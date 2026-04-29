//! REALITY-wrapped SOCKS5 client speaking the **full AnyTLS protocol**.
//!
//! Architecture:
//!
//! - All session-level concerns (cmdSettings/cmdServerSettings, cmdSYN/
//!   cmdSYNACK, cmdPSH/cmdFIN, cmdWaste padding scheme, idle session pool,
//!   stream multiplexing) are owned by `anytls::proxy::session::Client`.
//!   We only provide a `dial_out` callback that returns a fresh
//!   `Box<dyn AsyncReadWrite>` carrier on demand.
//! - Each carrier = one REALITY-protected TCP connection. The blocking
//!   rustls handshake runs on `std::net::TcpStream` via
//!   `rustls_util::StreamOwned`, then is bridged into a tokio
//!   `DuplexStream` so anytls can drive it asynchronously.
//! - Idle anytls sessions are reused for subsequent SOCKS requests
//!   (`Client::create_stream` picks an idle session under the
//!   `MAX_STREAMS_PER_SESSION` limit, otherwise dials a new one).
//! - SOCKS5 supports `CONNECT` (TCP) and `UDP ASSOCIATE` (anytls UoT
//!   Datagram mode, see `anytls::uot`).

use anytls_real::async_bridge;

use anyhow::{Context, Result, anyhow, bail};
use anytls::AsyncReadWrite;
use anytls::core::PaddingFactory;
use anytls::proxy::session::{Client, Stream as AnytlsStream};
use anytls::runtime::DefaultPaddingFactory;
use anytls::uot::{
    UotMode, UotRequest, uot_encode_packet, uot_get_packet_from_stream, uot_sentinel_destination,
};
use clap::Parser;
use core::net::SocketAddr;
use core::time::Duration;
use rustls::ClientConfig;
use rustls::Connection;
use rustls::RootCertStore;
use rustls::client::danger::{
    HandshakeSignatureValid, PeerVerified, ServerIdentity, ServerVerifier,
    SignatureVerificationInput,
};
use rustls::crypto::SignatureScheme;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls_aws_lc_rs as provider;
use rustls_util::{StreamOwned, complete_io};
use sha2::{Digest, Sha256};
use socks5_impl::protocol::{Address, Reply};
use socks5_impl::server::auth::NoAuth;
use socks5_impl::server::connection::{
    ClientConnection as SocksClientConnection, IncomingConnection, associate, connect,
};
use socks5_impl::server::{AssociatedUdpSocket, Server, UdpAssociate};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const MAX_UDP_RELAY_PACKET_SIZE: usize = 65_535;

#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// Path to the grouped client config (`.toml` or `.json`).
    #[arg(long)]
    config: PathBuf,

    /// Log filter (off/error/warn/info/debug/trace or env-style spec).
    #[arg(long, default_value = "info")]
    log: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientConfigFile {
    #[serde(default)]
    reality: Option<ClientRealityConfigFile>,
    #[serde(default)]
    anytls: Option<ClientAnytlsConfigFile>,
    #[serde(default)]
    client: Option<ClientRuntimeConfigFile>,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientRealityConfigFile {
    #[serde(default)]
    public_key: Option<String>,
    #[serde(default)]
    short_id: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    server_name: Option<String>,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientAnytlsConfigFile {
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    idle_check_secs: Option<u64>,
    #[serde(default)]
    idle_timeout_secs: Option<u64>,
    #[serde(default)]
    min_idle_sessions: Option<usize>,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientRuntimeConfigFile {
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    server_addr: Option<String>,
    #[serde(default)]
    ca_file: Option<PathBuf>,
    #[serde(default)]
    insecure: Option<bool>,
}

#[derive(Clone, Debug)]
struct RealityClientConfigResolved {
    listen: String,
    server_addr: String,
    ca_file: Option<PathBuf>,
    insecure: bool,
    password: String,
    idle_check_secs: u64,
    idle_timeout_secs: u64,
    min_idle_sessions: usize,
    public_key: String,
    short_id: String,
    version: String,
    server_name: String,
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerVerifier for NoCertificateVerification {
    fn verify_identity(
        &self,
        _identity: &ServerIdentity<'_>,
    ) -> core::result::Result<PeerVerified, rustls::Error> {
        Ok(PeerVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _input: &SignatureVerificationInput<'_>,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _input: &SignatureVerificationInput<'_>,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }

    fn request_ocsp_response(&self) -> bool {
        false
    }

    fn hash_config(&self, _: &mut dyn core::hash::Hasher) {}
}

#[derive(Clone)]
struct DialCtx {
    server_addr: String,
    tls_config: Arc<ClientConfig>,
    server_name: String,
    password_sha256: [u8; 32],
    padding: Arc<tokio::sync::RwLock<PaddingFactory>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(args.log.clone()))
        .init();

    let resolved = resolve_client_config(&args.config)?;
    let tls_config = Arc::new(build_client_config(&resolved)?);
    let server_addr = resolved.server_addr.clone();
    let server_name = resolved.server_name.clone();
    let padding = DefaultPaddingFactory::load();

    let dial_ctx = Arc::new(DialCtx {
        server_addr: server_addr.clone(),
        tls_config,
        server_name: server_name.clone(),
        password_sha256: Sha256::digest(resolved.password.as_bytes()).into(),
        padding: padding.clone(),
    });

    // anytls Client owns the session pool and stream multiplexer. On every
    // `create_stream()` it picks an idle session (under
    // `MAX_STREAMS_PER_SESSION`) or invokes `dial_out` to build a new one.
    let dial_ctx_for_dial = dial_ctx.clone();
    let anytls_client = Arc::new(Client::new(
        Box::new(move || {
            let ctx = dial_ctx_for_dial.clone();
            Box::pin(async move { dial_carrier(ctx).await })
        }),
        padding,
        Duration::from_secs(resolved.idle_check_secs),
        Duration::from_secs(resolved.idle_timeout_secs),
        resolved.min_idle_sessions,
    ));

    log::info!(
        "REALITY+anytls client: SOCKS5 {} -> {} (sni={})",
        resolved.listen,
        server_addr,
        server_name
    );

    let listen: SocketAddr = resolved
        .listen
        .parse()
        .context("parse --listen")?;
    let socks_server = Server::bind(listen, Arc::new(NoAuth)).await?;

    loop {
        let (incoming, peer_addr) = socks_server.accept().await?;
        let anytls_client = anytls_client.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_socks(incoming, anytls_client).await {
                log::warn!("SOCKS peer {peer_addr} failed: {error:#}");
            }
        });
    }
}

/// One-shot REALITY+TLS+anytls-auth dialer. Returns a fresh transport
/// `Box<dyn AsyncReadWrite>` ready to be wrapped in a brand-new anytls
/// session. Called by `Client` whenever the idle-session pool is empty.
async fn dial_carrier(ctx: Arc<DialCtx>) -> std::io::Result<Box<dyn AsyncReadWrite>> {
    // 1) Plain TCP connect.
    let tokio_tcp = TcpStream::connect(&ctx.server_addr).await?;
    tokio_tcp.set_nodelay(true).ok();
    let std_tcp = tokio_tcp.into_std()?;

    // 2) Blocking REALITY rustls handshake on a worker thread (our forked
    //    rustls cannot use tokio-rustls).
    let tls_config = ctx.tls_config.clone();
    let server_name = ctx.server_name.clone();
    let tls = tokio::task::spawn_blocking(move || -> std::io::Result<_> {
        std_tcp.set_nonblocking(false)?;
        let server_name = ServerName::try_from(server_name)
            .map_err(|err| std::io::Error::other(format!("invalid sni: {err}")))?;
        let mut conn = tls_config
            .connect(server_name)
            .build()
            .map_err(|err| std::io::Error::other(format!("rustls build: {err}")))?;
        let mut sock = std_tcp;
        while conn.is_handshaking() {
            complete_io(&mut sock, &mut conn)
                .map_err(|err| std::io::Error::other(format!("reality handshake: {err}")))?;
        }
        Ok(StreamOwned::new(conn, sock))
    })
    .await
    .map_err(|err| std::io::Error::other(format!("join handshake task: {err}")))??;

    // 3) Bridge blocking TLS into an async duplex carrier.
    let mut bridge = async_bridge::into_async(tls)
        .map_err(|err| std::io::Error::other(format!("async bridge: {err}")))?;

    // 4) Send anytls auth header:
    //    sha256(password) || u16be(padding_len) || padding_len zero bytes
    let padding_factory = ctx.padding.read().await;
    let padding_sizes = padding_factory.generate_record_payload_sizes(0);
    drop(padding_factory);
    let padding_len: u16 = padding_sizes
        .first()
        .copied()
        .map(|v| u16::try_from(v).unwrap_or(0))
        .unwrap_or(0);

    let mut auth = Vec::with_capacity(34 + padding_len as usize);
    auth.extend_from_slice(&ctx.password_sha256);
    auth.extend_from_slice(&padding_len.to_be_bytes());
    if padding_len > 0 {
        auth.resize(auth.len() + padding_len as usize, 0);
    }
    bridge.write_all(&auth).await?;

    Ok(Box::new(bridge) as Box<dyn AsyncReadWrite>)
}

async fn handle_socks(incoming: IncomingConnection<()>, client: Arc<Client>) -> Result<()> {
    let (authenticated, _) = incoming.authenticate().await?;
    let request = authenticated.wait_request().await?;

    match request {
        SocksClientConnection::Connect(connect_req, target) => {
            handle_tcp_connect(connect_req, target, &client).await
        }
        SocksClientConnection::UdpAssociate(associate_req, _) => {
            handle_udp_associate(associate_req, &client).await
        }
        SocksClientConnection::Bind(_, _) => bail!("SOCKS BIND is not supported"),
    }
}

async fn handle_tcp_connect(
    connect_req: connect::Connect<connect::NeedReply>,
    target: Address,
    client: &Client,
) -> Result<()> {
    let bind_addr = Address::from(connect_req.local_addr()?);

    // Open the anytls stream *before* confirming success to the SOCKS client.
    let stream = match client.create_stream().await {
        Ok(s) => s,
        Err(err) => {
            let _ = client.close().await;
            if let Ok(mut failed) = connect_req
                .reply(Reply::GeneralFailure, Address::unspecified())
                .await
            {
                let _ = failed.shutdown().await;
            }
            return Err(err.into());
        }
    };

    // First user payload on this stream: target address in SOCKS5 SocksAddr
    // format. Becomes the data of the first cmdPSH frame.
    let addr_bytes: Vec<u8> = target.clone().into();
    if let Err(err) = stream.write(&addr_bytes).await {
        let _ = stream.close().await;
        let _ = client.close().await;
        if let Ok(mut failed) = connect_req
            .reply(Reply::GeneralFailure, Address::unspecified())
            .await
        {
            let _ = failed.shutdown().await;
        }
        return Err(err.into());
    }

    // Stream is open and the address is en-route; now confirm success to the
    // local SOCKS client.
    let ready = connect_req
        .reply(Reply::Succeeded, bind_addr)
        .await?;

    let (mut local_read, mut local_write) = ready.into_split();
    let stream_w = stream.clone();
    let stream_r = stream.clone();

    let l2r = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if stream_w.write(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = stream_w.close().await;
    });

    let r2l = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match stream_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if local_write
                        .write_all(&buf[..n])
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = local_write.shutdown().await;
    });

    let _ = tokio::join!(l2r, r2l);
    let _ = stream.close().await;
    log::debug!("tcp tunnel to {target} closed");
    Ok(())
}

async fn handle_udp_associate(
    associate_req: UdpAssociate<associate::NeedReply>,
    client: &Client,
) -> Result<()> {
    let listen_ip = associate_req.local_addr()?.ip();
    let udp = match UdpSocket::bind(SocketAddr::from((listen_ip, 0))).await {
        Ok(socket) => socket,
        Err(err) => {
            let mut reply = associate_req
                .reply(Reply::GeneralFailure, Address::unspecified())
                .await?;
            reply.shutdown().await?;
            return Err(err.into());
        }
    };
    let listen_addr = udp.local_addr()?;

    let stream = match client.create_stream().await {
        Ok(s) => s,
        Err(err) => {
            let _ = client.close().await;
            let mut reply = associate_req
                .reply(Reply::GeneralFailure, Address::unspecified())
                .await?;
            reply.shutdown().await?;
            return Err(err.into());
        }
    };

    // Mark this stream as a UoT stream:
    //   sentinel address (SocksAddr) + UotRequest{Datagram, unspecified}
    if let Err(err) = setup_uot_request(&stream).await {
        let _ = stream.close().await;
        let _ = client.close().await;
        let mut reply = associate_req
            .reply(Reply::GeneralFailure, Address::unspecified())
            .await?;
        reply.shutdown().await?;
        return Err(err);
    }

    let mut reply = associate_req
        .reply(Reply::Succeeded, Address::from(listen_addr))
        .await?;
    let listen_udp = Arc::new(AssociatedUdpSocket::from((udp, MAX_UDP_RELAY_PACKET_SIZE)));
    // Pin the UDP association to the first sender; ignore packets from other sources.
    let incoming_addr = Arc::new(tokio::sync::Mutex::new(Option::<SocketAddr>::None));
    let stream_writer = stream.clone();
    let mut stream_reader = AnytlsStreamReader::new(stream.clone());

    let result: Result<()> = loop {
        tokio::select! {
            res = listen_udp.recv_from() => {
                let (pkt, frag, destination, src_addr) = res?;
                if frag != 0 {
                    break Err(anyhow!("SOCKS UDP fragmentation is not supported"));
                }
                let mut guard = incoming_addr.lock().await;
                match *guard {
                    None => *guard = Some(src_addr),
                    Some(pinned) if pinned != src_addr => {
                        log::debug!("UDP ASSOCIATE: dropping packet from {src_addr} (pinned to {pinned})");
                        drop(guard);
                        continue;
                    }
                    Some(_) => {}
                }
                drop(guard);
                let frame = uot_encode_packet(UotMode::Datagram, Some(&destination), &pkt)?;
                stream_writer.write(&frame).await?;
            }
            res = uot_get_packet_from_stream(UotMode::Datagram, &mut stream_reader) => {
                let (source, payload) = res?;
                let Some(incoming) = *incoming_addr.lock().await else {
                    continue;
                };
                let source = source.ok_or_else(|| anyhow!("UoT datagram missing source"))?;
                listen_udp.send_to(&payload, 0, source, incoming).await?;
            }
            res = reply.wait_until_closed() => {
                res?;
                break Ok(());
            }
        }
    };

    let _ = stream.close().await;
    let _ = reply.shutdown().await;
    result
}

async fn setup_uot_request(stream: &Arc<AnytlsStream>) -> Result<()> {
    let sentinel: Vec<u8> = uot_sentinel_destination().into();
    stream.write(&sentinel).await?;
    let request_bytes: Vec<u8> = UotRequest::new(UotMode::Datagram, Address::unspecified()).into();
    stream.write(&request_bytes).await?;
    Ok(())
}

// === helpers ===

fn resolve_client_config(config_path: &Path) -> Result<RealityClientConfigResolved> {
    let file_config = load_client_config_file(config_path)?;
    let reality = file_config
        .reality
        .as_ref()
        .ok_or_else(|| anyhow!("client config requires a [reality] section"))?;
    let anytls = file_config
        .anytls
        .as_ref()
        .ok_or_else(|| anyhow!("client config requires an [anytls] section"))?;
    let client = file_config
        .client
        .as_ref()
        .ok_or_else(|| anyhow!("client config requires a [client] section"))?;

    let listen = client
        .listen
        .clone()
        .unwrap_or_else(|| "127.0.0.1:1080".to_string());
    let server_addr = client
        .server_addr
        .clone()
        .ok_or_else(|| anyhow!("client.serverAddr must be set in config"))?;
    let mut ca_file = client.ca_file.clone();
    let insecure = client.insecure.unwrap_or(false);
    if insecure && ca_file.is_some() {
        // If insecure mode is requested we must not attempt to load the CA file
        // (verification is disabled). Clear the ca_file so load_root_store
        // won't try to open a missing file and will use system roots instead.
        log::debug!("'insecure = true' set in client config; ignoring provided ca_file");
        ca_file = None;
    }

    let password = anytls
        .password
        .clone()
        .ok_or_else(|| anyhow!("anytls.password must be set in config"))?;
    if password.is_empty() {
        bail!("anytls.password must not be empty");
    }

    let idle_check_secs = anytls.idle_check_secs.unwrap_or(30);
    let idle_timeout_secs = anytls.idle_timeout_secs.unwrap_or(30);
    // Keep the idle floor at zero by default so timed-out sessions are not
    // preserved indefinitely. Users can opt back in via config if they want
    // a warm pool.
    let min_idle_sessions = anytls.min_idle_sessions.unwrap_or(0);

    let short_id = reality
        .short_id
        .clone()
        .ok_or_else(|| anyhow!("reality.shortId must be set in config"))?;
    let public_key = reality
        .public_key
        .clone()
        .ok_or_else(|| anyhow!("reality.publicKey must be set in config"))?;
    let version = reality
        .version
        .clone()
        .ok_or_else(|| anyhow!("reality.version must be set in config"))?;
    let server_name = reality
        .server_name
        .clone()
        .ok_or_else(|| anyhow!("reality.serverName must be set in config"))?;

    Ok(RealityClientConfigResolved {
        listen,
        server_addr,
        ca_file,
        insecure,
        password,
        idle_check_secs,
        idle_timeout_secs,
        min_idle_sessions,
        short_id,
        public_key,
        version,
        server_name,
    })
}

fn build_client_config(args: &RealityClientConfigResolved) -> Result<ClientConfig> {
    let provider = provider::reality::default_x25519_tls13_reality_provider();
    let root_store = load_root_store(args.ca_file.as_deref())?;

    let mut config = ClientConfig::builder(Arc::new(provider))
        .with_root_certificates(root_store)
        .with_no_client_auth()?;

    if args.insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification));
    }

    provider::reality::install_reality_session_id_generator_from_xray_fields(
        &mut config,
        parse_reality_version(&args.version),
        &args.short_id,
        &args.public_key,
    )?;

    Ok(config)
}

fn load_root_store(ca_file: Option<&Path>) -> Result<RootCertStore> {
    let mut root_store = RootCertStore::empty();

    if let Some(ca_file) = ca_file {
        let certs = CertificateDer::pem_file_iter(ca_file)
            .context("open CA file")?
            .collect::<core::result::Result<Vec<_>, _>>()
            .context("read CA certificates")?;
        for cert in certs {
            root_store.add(cert)?;
        }
    } else {
        root_store.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );
    }

    Ok(root_store)
}

fn load_client_config_file(path: &Path) -> Result<ClientConfigFile> {
    let contents = std::fs::read_to_string(path)?;
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
    {
        "json" => Ok(serde_json::from_str(&contents)?),
        "toml" => Ok(toml::from_str(&contents)?),
        _ => bail!("unsupported REALITY config format: {}", path.display()),
    }
}

fn parse_reality_version(version: &str) -> [u8; 3] {
    let version = version.trim();
    assert_eq!(version.len(), 6, "REALITY version must be 6 hex digits");
    let mut parsed = [0u8; 3];
    for (index, chunk) in version
        .as_bytes()
        .chunks_exact(2)
        .enumerate()
    {
        parsed[index] = parse_hex_byte(chunk[0], chunk[1]);
    }
    parsed
}

fn parse_hex_byte(high: u8, low: u8) -> u8 {
    (parse_hex_nibble(high) << 4) | parse_hex_nibble(low)
}

fn parse_hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("REALITY version must contain only hexadecimal digits"),
    }
}

// === AsyncRead adapter for AnytlsStream (so UoT helpers can drive it) ===

struct AnytlsStreamReader {
    inner: Arc<AnytlsStream>,
    #[allow(clippy::type_complexity)]
    read_fut: Option<
        core::pin::Pin<
            Box<dyn core::future::Future<Output = std::io::Result<(Vec<u8>, usize)>> + Send>,
        >,
    >,
}

impl AnytlsStreamReader {
    fn new(inner: Arc<AnytlsStream>) -> Self {
        Self {
            inner,
            read_fut: None,
        }
    }
}

impl AsyncRead for AnytlsStreamReader {
    fn poll_read(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        loop {
            if let Some(fut) = self.read_fut.as_mut() {
                match fut.as_mut().poll(cx) {
                    core::task::Poll::Ready(Ok((v, n))) => {
                        self.read_fut = None;
                        buf.put_slice(&v[..n]);
                        return core::task::Poll::Ready(Ok(()));
                    }
                    core::task::Poll::Ready(Err(e)) => {
                        self.read_fut = None;
                        return core::task::Poll::Ready(Err(e));
                    }
                    core::task::Poll::Pending => return core::task::Poll::Pending,
                }
            }

            let remaining = buf.remaining();
            if remaining == 0 {
                return core::task::Poll::Ready(Ok(()));
            }

            let inner = self.inner.clone();
            self.read_fut = Some(Box::pin(async move {
                let mut v = vec![0u8; remaining];
                let n = inner.read(&mut v).await?;
                Ok::<(Vec<u8>, usize), std::io::Error>((v, n))
            }));
        }
    }
}
