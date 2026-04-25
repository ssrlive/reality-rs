//! REALITY-wrapped server speaking the **full AnyTLS protocol**.
//!
//! For each inbound TCP:
//! 1. REALITY rustls handshake on a blocking worker thread.
//! 2. Bridge into an async `DuplexStream`.
//! 3. Read anytls auth header `sha256(password) || u16be(pad_len) || pad`.
//! 4. Hand the carrier to `anytls::proxy::session::new_server_session` and
//!    drive its `run()` loop. The library handles cmdSettings,
//!    cmdServerSettings, cmdSYN/cmdSYNACK, cmdPSH/cmdFIN, cmdWaste etc.
//! 5. For each opened anytls stream: read a SOCKS5-style `Address` (the
//!    proxy target). If it is the AnyTLS UoT sentinel, follow with a
//!    `UotRequest` and run a UDP-over-TCP relay. Otherwise dial the
//!    address and bidirectionally relay between the upstream socket and
//!    the anytls stream.
//!
//! Note: anytls's protocol mandates that clients implement session reuse
//! and that the server be tolerant of any number of streams per session.
//! We do nothing special on the server side for that — if a client opens
//! many streams over one session, this server still serves them all.

mod async_bridge;

use anyhow::{Context, Result, bail};
use anytls::core::PaddingFactory;
use anytls::proxy::session::{Session, Stream as AnytlsStream, new_server_session};
use anytls::runtime::DefaultPaddingFactory;
use anytls::uot::{
    UotMode, UotRequest, uot_encode_packet, uot_get_packet_from_stream,
    uot_get_request_from_stream, uot_is_sentinel_destination,
};
use clap::Parser;
use core::hash::Hasher;
use rustls::Connection;
use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls::crypto::Identity;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHelloVerifier, RealityClientHello};
use rustls_aws_lc_rs as provider;
use rustls_util::{StreamOwned, complete_io};
use sha2::{Digest, Sha256};
use socks5_impl::protocol::{Address, AsyncStreamOperation};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream as TokioTcpStream, UdpSocket};

#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    #[arg(long, default_value = "[::]:443")]
    listen: String,

    #[arg(long)]
    cert: PathBuf,

    #[arg(long)]
    key: PathBuf,

    #[arg(long)]
    reality_config: Option<PathBuf>,

    #[arg(long, requires_all = ["reality_private_key", "reality_version"])]
    reality_short_id: Option<String>,

    #[arg(long, requires_all = ["reality_short_id", "reality_version"])]
    reality_private_key: Option<String>,

    #[arg(long, requires_all = ["reality_short_id", "reality_private_key"])]
    reality_version: Option<String>,

    #[arg(long = "reality-server-name")]
    reality_server_name: Vec<String>,

    /// AnyTLS shared password.
    #[arg(long, env = "ANYTLS_PASSWORD")]
    password: String,

    /// Log filter (off/error/warn/info/debug/trace or env-style spec).
    #[arg(long, default_value = "info")]
    log: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RealityDocument<T> {
    reality: T,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RealityServerConfigFile {
    private_key: String,
    short_id: String,
    version: String,
    #[serde(default)]
    server_names: Vec<String>,
}

#[derive(Clone, Debug)]
struct RealityServerConfigResolved {
    private_key: String,
    short_id: String,
    version: String,
    server_names: Vec<String>,
}

#[derive(Debug)]
struct ExampleRealityVerifier {
    inner: Arc<dyn ClientHelloVerifier>,
    server_names: Vec<String>,
}

impl ClientHelloVerifier for ExampleRealityVerifier {
    fn verify_client_hello(
        &self,
        client_hello: &RealityClientHello<'_>,
    ) -> core::result::Result<(), rustls::Error> {
        if !self.server_names.is_empty() {
            let server_name = client_hello
                .server_name()
                .map(|name| name.as_ref())
                .ok_or_else(|| rustls::Error::General("REALITY verifier requires SNI".into()))?;

            if !self
                .server_names
                .iter()
                .any(|allowed| allowed == server_name)
            {
                return Err(rustls::Error::General(
                    "REALITY verifier rejected an unexpected server_name".into(),
                ));
            }
        }

        self.inner
            .verify_client_hello(client_hello)
    }

    fn hash_config(&self, h: &mut dyn Hasher) {
        h.write_usize(self.server_names.len());
        for name in &self.server_names {
            h.write(name.as_bytes());
        }
        self.inner.hash_config(h);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(args.log.clone()))
        .init();

    if args.password.is_empty() {
        bail!("anytls password must not be empty (set --password or ANYTLS_PASSWORD)");
    }

    let reality = resolve_reality_config(&args)?;
    let tls_config = Arc::new(build_server_config(&args, &reality)?);
    let password_sha256: [u8; 32] = Sha256::digest(args.password.as_bytes()).into();
    let padding = DefaultPaddingFactory::load();

    let listener = TcpListener::bind(&args.listen).await?;
    log::info!("REALITY+anytls server listening on {}", args.listen);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let tls_config = tls_config.clone();
        let padding = padding.clone();
        tokio::spawn(async move {
            if let Err(error) =
                handle_connection(stream, tls_config, password_sha256, padding).await
            {
                log::warn!("REALITY client {peer_addr} failed: {error:#}");
            }
        });
    }
}

async fn handle_connection(
    stream: TokioTcpStream,
    config: Arc<ServerConfig>,
    password_sha256: [u8; 32],
    padding: Arc<tokio::sync::RwLock<PaddingFactory>>,
) -> Result<()> {
    stream.set_nodelay(true).ok();
    let std_stream = stream.into_std()?;

    // 1) REALITY blocking handshake on a worker thread.
    let tls = tokio::task::spawn_blocking(
        move || -> Result<StreamOwned<ServerConnection, std::net::TcpStream>> {
            let mut sock = std_stream;
            sock.set_nonblocking(false)?;
            let mut conn = ServerConnection::new(config)?;
            while conn.is_handshaking() {
                complete_io(&mut sock, &mut conn).context("complete REALITY handshake")?;
            }
            Ok(StreamOwned::new(conn, sock))
        },
    )
    .await??;

    // 2) Bridge into async.
    let mut bridge = async_bridge::into_async(tls)?;

    // 3) Read anytls auth: 32 sha256(password) + u16be padding_len + padding.
    let mut auth = [0u8; 34];
    bridge
        .read_exact(&mut auth)
        .await
        .context("read anytls auth header")?;
    if auth[..32] != password_sha256[..] {
        log::debug!("anytls auth failed for an inbound REALITY peer");
        return Ok(());
    }
    let padding_len = u16::from_be_bytes([auth[32], auth[33]]);
    if padding_len > 0 {
        let mut padding_buf = vec![0u8; padding_len as usize];
        bridge
            .read_exact(&mut padding_buf)
            .await
            .context("read anytls padding")?;
    }

    // 4) Hand the carrier to anytls and run the session loop.
    let session = new_server_session(
        Box::new(bridge),
        Box::new(|stream: Arc<AnytlsStream>| {
            tokio::spawn(async move {
                if let Err(error) = handle_stream(stream).await {
                    log::debug!("stream error: {error:#}");
                }
            });
        }),
        padding,
    )
    .await;

    let session: Session = session;
    if let Err(error) = session.run().await {
        log::debug!("anytls session ended: {error}");
    }
    Ok(())
}

async fn handle_stream(stream: Arc<AnytlsStream>) -> Result<()> {
    let mut reader = AnytlsStreamReader::new(stream.clone());
    let destination = Address::retrieve_from_async_stream(&mut reader).await?;

    if uot_is_sentinel_destination(&destination) {
        let request = uot_get_request_from_stream(&mut reader).await?;
        return match request.mode {
            UotMode::Connected => handle_uot_connected(stream, &mut reader, &request).await,
            UotMode::Datagram => handle_uot_datagram(stream, &mut reader).await,
        };
    }

    handle_tcp_stream(stream, destination).await
}

async fn handle_tcp_stream(stream: Arc<AnytlsStream>, destination: Address) -> Result<()> {
    let dst = destination.to_string();
    let mut outbound = match TokioTcpStream::connect(&dst).await {
        Ok(s) => s,
        Err(err) => {
            log::debug!("connect upstream {dst} failed: {err}");
            stream
                .handshake_failure(&err.to_string())
                .await?;
            stream.close().await?;
            return Err(err.into());
        }
    };
    outbound.set_nodelay(true).ok();
    stream.handshake_success().await?;

    let (stream_read, stream_write) = stream.split_ref();
    let (mut up_read, mut up_write) = outbound.split();

    let s2u = async {
        use tokio::io::AsyncWriteExt;
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match stream_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if up_write
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
        let _ = up_write.shutdown().await;
        Ok::<(), std::io::Error>(())
    };

    let u2s = async {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match up_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if stream_write
                        .write(&buf[..n])
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = stream_write.close().await;
        Ok::<(), std::io::Error>(())
    };

    let _ = tokio::join!(s2u, u2s);
    Ok(())
}

async fn handle_uot_datagram(
    stream: Arc<AnytlsStream>,
    reader: &mut AnytlsStreamReader,
) -> Result<()> {
    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    stream.handshake_success().await?;
    let mut buf = vec![0u8; 65_535];

    let result: Result<()> = async {
        loop {
            tokio::select! {
                res = uot_get_packet_from_stream(UotMode::Datagram, reader) => {
                    let (destination, payload) = res?;
                    let dst = destination
                        .ok_or_else(|| anyhow::anyhow!("UoT datagram missing destination"))?;
                    udp.send_to(&payload, dst.to_string()).await?;
                }
                res = udp.recv_from(&mut buf) => {
                    let (n, source) = res?;
                    let frame = uot_encode_packet(
                        UotMode::Datagram,
                        Some(&Address::from(source)),
                        &buf[..n],
                    )?;
                    stream.write(&frame).await?;
                }
            }
        }
    }
    .await;

    let _ = stream.close().await;
    result
}

async fn handle_uot_connected(
    stream: Arc<AnytlsStream>,
    reader: &mut AnytlsStreamReader,
    request: &UotRequest,
) -> Result<()> {
    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    let dst = request.destination.to_string();
    if let Err(err) = udp.connect(&dst).await {
        stream
            .handshake_failure(&err.to_string())
            .await?;
        stream.close().await?;
        return Err(err.into());
    }
    stream.handshake_success().await?;
    let mut buf = vec![0u8; 65_535];

    let result: Result<()> = async {
        loop {
            tokio::select! {
                res = uot_get_packet_from_stream(UotMode::Connected, reader) => {
                    let (_, payload) = res?;
                    udp.send(&payload).await?;
                }
                res = udp.recv(&mut buf) => {
                    let n = res?;
                    let frame = uot_encode_packet(UotMode::Connected, None, &buf[..n])?;
                    stream.write(&frame).await?;
                }
            }
        }
    }
    .await;

    let _ = stream.close().await;
    result
}

// === helpers ===

fn resolve_reality_config(args: &Args) -> Result<RealityServerConfigResolved> {
    let file_config = if let Some(path) = args.reality_config.as_deref() {
        Some(load_reality_document::<RealityServerConfigFile>(path)?.reality)
    } else {
        None
    };

    let short_id = args
        .reality_short_id
        .clone()
        .or_else(|| {
            file_config
                .as_ref()
                .map(|c| c.short_id.clone())
        });
    let private_key = args
        .reality_private_key
        .clone()
        .or_else(|| {
            file_config
                .as_ref()
                .map(|c| c.private_key.clone())
        });
    let version = args
        .reality_version
        .clone()
        .or_else(|| {
            file_config
                .as_ref()
                .map(|c| c.version.clone())
        });
    let server_names = if args.reality_server_name.is_empty() {
        file_config
            .as_ref()
            .map(|c| c.server_names.clone())
            .unwrap_or_default()
    } else {
        args.reality_server_name.clone()
    };

    match (short_id, private_key, version) {
        (Some(s), Some(p), Some(v)) => Ok(RealityServerConfigResolved {
            short_id: s,
            private_key: p,
            version: v,
            server_names,
        }),
        _ => bail!(
            "REALITY server requires short_id, private_key, and version via CLI or --reality-config"
        ),
    }
}

fn build_server_config(args: &Args, reality: &RealityServerConfigResolved) -> Result<ServerConfig> {
    let certs = CertificateDer::pem_file_iter(&args.cert)
        .context("open certificate file")?
        .collect::<core::result::Result<Vec<_>, _>>()
        .context("read certificate chain")?;
    let private_key = PrivateKeyDer::from_pem_file(&args.key).context("read private key")?;

    let provider = provider::reality::default_x25519_tls13_reality_provider();
    let mut config = ServerConfig::builder(Arc::new(provider))
        .with_no_client_auth()
        .with_single_cert(Arc::new(Identity::from_cert_chain(certs)?), private_key)?;

    let inner = provider::reality::RealityServerVerifierConfig::from_xray_fields(
        parse_reality_version(&reality.version),
        &reality.short_id,
        &reality.private_key,
    )?
    .build_verifier()?;
    config
        .dangerous()
        .set_reality_client_hello_verifier(Some(Arc::new(ExampleRealityVerifier {
            inner,
            server_names: reality.server_names.clone(),
        })));

    Ok(config)
}

fn load_reality_document<T>(path: &Path) -> Result<RealityDocument<T>>
where
    T: serde::de::DeserializeOwned,
{
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

// === AsyncRead adapter for AnytlsStream ===

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

#[allow(dead_code)]
fn _force_connection_in_scope(c: &ServerConnection) -> bool {
    Connection::is_handshaking(c)
}
