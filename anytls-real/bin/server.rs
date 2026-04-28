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

use anytls_real::async_bridge;

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{Context, Result, bail};
use anytls::core::PaddingFactory;
use anytls::proxy::session::{Session, Stream as AnytlsStream, new_server_session};
use anytls::runtime::DefaultPaddingFactory;
use anytls::uot::{
    UotMode, UotRequest, uot_encode_packet, uot_get_packet_from_stream,
    uot_get_request_from_stream, uot_is_sentinel_destination,
};
use aws_lc_rs::agreement;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use clap::Parser;
use core::hash::Hasher;
use core::time::Duration;
use hkdf::Hkdf;
use rustls::ClientConfig;
use rustls::ClientConnection;
use rustls::Connection;
use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls::crypto::Identity;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ClientHelloVerifier, RealityClientHello};
use rustls_aws_lc_rs as provider;
use rustls_util::{StreamOwned, complete_io};
use sha2::{Digest, Sha256};
use socks5_impl::protocol::{Address, AsyncStreamOperation};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream as TokioTcpStream, UdpSocket};

#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// Path to the grouped server config (`.toml` or `.json`).
    #[arg(long)]
    config: PathBuf,

    /// Log filter (off/error/warn/info/debug/trace or env-style spec).
    #[arg(long, default_value = "info")]
    log: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerConfigFile {
    #[serde(default)]
    reality: Option<ServerRealityConfigFile>,
    #[serde(default)]
    anytls: Option<ServerAnytlsConfigFile>,
    #[serde(default)]
    server: Option<ServerRuntimeConfigFile>,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerRealityConfigFile {
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    short_id: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    server_names: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerAnytlsConfigFile {
    #[serde(default)]
    password: Option<String>,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerRuntimeConfigFile {
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    cert: Option<PathBuf>,
    #[serde(default)]
    key: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct ServerConfigResolved {
    listen: String,
    cert: PathBuf,
    key: PathBuf,
    password: String,
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

    let resolved = resolve_server_config(&args.config)?;
    let tls_config = Arc::new(build_server_config(&resolved)?);
    let upstream_tls_config = Arc::new(build_upstream_tls_config()?);
    let allowed_server_names = Arc::new(resolved.server_names.clone());
    let plain_tls_config = Arc::new(build_plain_server_config(&resolved)?);
    let password_sha256: [u8; 32] = Sha256::digest(resolved.password.as_bytes()).into();
    let padding = DefaultPaddingFactory::load();
    let reality_private_key = Arc::new(parse_reality_private_key(&resolved.private_key)?);
    let reality_short_id = Arc::new(parse_reality_short_id_fixed(&resolved.short_id)?);
    let reality_version = parse_reality_version(&resolved.version);

    let listener = TcpListener::bind(&resolved.listen).await?;
    log::info!("REALITY+anytls server listening on {}", resolved.listen);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let tls_config = tls_config.clone();
        let upstream_tls_config = upstream_tls_config.clone();
        let allowed_server_names = allowed_server_names.clone();
        let plain_tls_config = plain_tls_config.clone();
        let padding = padding.clone();
        let reality_private_key = reality_private_key.clone();
        let reality_short_id = reality_short_id.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(
                stream,
                tls_config,
                upstream_tls_config,
                allowed_server_names,
                plain_tls_config,
                password_sha256,
                padding,
                reality_private_key,
                reality_short_id,
                reality_version,
            )
            .await
            {
                log::warn!("REALITY client {peer_addr} failed: {error:#}");
            }
        });
    }
}

async fn handle_connection(
    stream: TokioTcpStream,
    reality_config: Arc<ServerConfig>,
    upstream_tls_config: Arc<ClientConfig>,
    allowed_server_names: Arc<Vec<String>>,
    plain_tls_config: Arc<ServerConfig>,
    password_sha256: [u8; 32],
    padding: Arc<tokio::sync::RwLock<PaddingFactory>>,
    reality_private_key: Arc<Vec<u8>>,
    reality_short_id: Arc<[u8; 8]>,
    reality_version: [u8; 3],
) -> Result<()> {
    stream.set_nodelay(true).ok();
    let std_stream = stream.into_std()?;
    std_stream.set_nonblocking(false)?;

    let is_reality = is_reality_client_hello(
        &std_stream,
        reality_private_key.as_slice(),
        reality_short_id.as_slice(),
        &reality_version,
    )?;
    if !is_reality {
        return handle_plain_tls_connection(
            std_stream,
            plain_tls_config,
            upstream_tls_config,
            allowed_server_names,
        )
        .await;
    }

    // 1) REALITY blocking handshake on a worker thread.
    let tls = tokio::task::spawn_blocking(
        move || -> Result<StreamOwned<ServerConnection, std::net::TcpStream>> {
            let mut sock = std_stream;
            sock.set_nonblocking(false)?;
            let mut conn = ServerConnection::new(reality_config)?;
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

fn resolve_server_config(config_path: &Path) -> Result<ServerConfigResolved> {
    let file_config = load_server_config_file(config_path)?;
    let reality = file_config
        .reality
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("server config requires a [reality] section"))?;
    let anytls = file_config
        .anytls
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("server config requires an [anytls] section"))?;
    let server = file_config
        .server
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("server config requires a [server] section"))?;

    let listen = server
        .listen
        .clone()
        .unwrap_or_else(|| "[::]:443".to_string());
    let cert = server
        .cert
        .clone()
        .ok_or_else(|| anyhow::anyhow!("server.cert must be set in config"))?;
    let key = server
        .key
        .clone()
        .ok_or_else(|| anyhow::anyhow!("server.key must be set in config"))?;
    let password = anytls
        .password
        .clone()
        .ok_or_else(|| anyhow::anyhow!("anytls.password must be set in config"))?;
    if password.is_empty() {
        bail!("anytls.password must not be empty");
    }

    let short_id = reality
        .short_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("reality.shortId must be set in config"))?;
    let private_key = reality
        .private_key
        .clone()
        .ok_or_else(|| anyhow::anyhow!("reality.privateKey must be set in config"))?;
    let version = reality
        .version
        .clone()
        .ok_or_else(|| anyhow::anyhow!("reality.version must be set in config"))?;

    let server_names = reality
        .server_names
        .clone()
        .unwrap_or_default();

    Ok(ServerConfigResolved {
        listen,
        cert,
        key,
        password,
        private_key,
        short_id,
        version,
        server_names,
    })
}

fn build_server_config(reality: &ServerConfigResolved) -> Result<ServerConfig> {
    let certs = CertificateDer::pem_file_iter(&reality.cert)
        .context("open certificate file")?
        .collect::<core::result::Result<Vec<_>, _>>()
        .context("read certificate chain")?;
    let private_key = PrivateKeyDer::from_pem_file(&reality.key).context("read private key")?;

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

fn build_plain_server_config(reality: &ServerConfigResolved) -> Result<ServerConfig> {
    let certs = CertificateDer::pem_file_iter(&reality.cert)
        .context("open certificate file")?
        .collect::<core::result::Result<Vec<_>, _>>()
        .context("read certificate chain")?;
    let private_key = PrivateKeyDer::from_pem_file(&reality.key).context("read private key")?;

    let config = ServerConfig::builder(Arc::new(provider::DEFAULT_PROVIDER))
        .with_no_client_auth()
        .with_single_cert(Arc::new(Identity::from_cert_chain(certs)?), private_key)?;

    Ok(config)
}

fn is_reality_client_hello(
    stream: &std::net::TcpStream,
    server_private_key: &[u8],
    short_id: &[u8],
    version: &[u8; 3],
) -> Result<bool> {
    stream
        .set_nonblocking(false)
        .context("set socket blocking for ClientHello peek")?;

    let mut buf = vec![0u8; 2048];
    let mut available = 0;

    loop {
        let n = stream
            .peek(&mut buf[available..])
            .context("peek ClientHello")?;
        if n == 0 {
            return Ok(false);
        }
        available += n;

        if available < 5 {
            continue;
        }

        let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        let needed = 5 + record_len;
        if available < needed {
            if needed > buf.len() {
                buf.resize(needed, 0);
            }
            continue;
        }

        let Ok(parsed) = parse_client_hello(&buf[..needed]) else {
            return Ok(false);
        };

        let private_key =
            agreement::PrivateKey::from_private_key(&agreement::X25519, server_private_key)
                .context("parse REALITY private key bytes")?;
        let peer_public = agreement::UnparsedPublicKey::new(&agreement::X25519, &parsed.key_share);
        let reality_key = agreement::agree(
            &private_key,
            peer_public,
            aws_lc_rs::error::Unspecified,
            |secret| Ok::<Vec<u8>, aws_lc_rs::error::Unspecified>(Vec::from(secret)),
        )
        .map_err(|_| anyhow::anyhow!("failed to compute REALITY shared secret"))?;

        let hk = Hkdf::<Sha256>::new(Some(&parsed.random[..20]), &reality_key);
        let mut sealing_key = [0u8; 32];
        hk.expand(b"REALITY", &mut sealing_key)
            .context("derive REALITY sealing key")?;

        let cipher = Aes256Gcm::new(&sealing_key.into());
        let mut decrypted = parsed.session_id.to_vec();
        let nonce = Nonce::from_slice(&parsed.random[20..32]);
        if cipher
            .decrypt_in_place(nonce, &parsed.raw_client_hello, &mut decrypted)
            .is_err()
        {
            return Ok(false);
        }

        if decrypted.len() != 16 || decrypted[3] != 0 {
            return Ok(false);
        }
        if &decrypted[..3] != version.as_slice() {
            return Ok(false);
        }
        if &decrypted[8..16] != short_id {
            return Ok(false);
        }

        return Ok(true);
    }
}

struct ParsedClientHello {
    random: [u8; 32],
    session_id: [u8; 32],
    raw_client_hello: Vec<u8>,
    key_share: Vec<u8>,
}

fn parse_client_hello(bytes: &[u8]) -> Result<ParsedClientHello> {
    if bytes.len() < 9 || bytes[0] != 22 {
        bail!("not a TLS record")
    }

    let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    if bytes.len() < 5 + record_len || record_len < 4 {
        bail!("truncated TLS record")
    }

    let handshake = &bytes[5..5 + record_len];
    if handshake[0] != 1 {
        bail!("not a ClientHello")
    }

    let handshake_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | (handshake[3] as usize);
    if handshake_len + 4 > handshake.len() {
        bail!("truncated ClientHello")
    }

    let body = &handshake[4..4 + handshake_len];
    if body.len() < 35 {
        bail!("ClientHello body too short")
    }

    let mut offset = 0;
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[offset + 2..offset + 34]);
    offset += 34;

    let session_id_len = body[offset] as usize;
    if session_id_len != 32 {
        bail!("not a REALITY-style session_id")
    }
    offset += 1;

    let session_id_offset = offset;
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&body[offset..offset + 32]);
    offset += 32;

    let cipher_suites_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;
    if offset + 1 > body.len() {
        bail!("truncated ClientHello after cipher suites")
    }
    let compression_len = body[offset] as usize;
    offset += 1 + compression_len;
    if offset + 2 > body.len() {
        bail!("truncated ClientHello after compression")
    }

    let extensions_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset += 2;
    if offset + extensions_len > body.len() {
        bail!("truncated ClientHello extensions")
    }

    let mut key_share = None;
    let extensions_end = offset + extensions_len;
    while offset + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let ext_len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        offset += 4;
        if offset + ext_len > extensions_end {
            break;
        }
        if ext_type == 0x0033 {
            if ext_len < 6 {
                bail!("invalid key_share extension")
            }
            let client_shares_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
            if client_shares_len + 2 != ext_len {
                bail!("invalid key_share length")
            }
            let group = u16::from_be_bytes([body[offset + 2], body[offset + 3]]);
            let share_len = u16::from_be_bytes([body[offset + 4], body[offset + 5]]) as usize;
            if group != 0x001d || share_len + 6 != ext_len {
                bail!("unsupported key_share for REALITY")
            }
            key_share = Some(body[offset + 6..offset + 6 + share_len].to_vec());
            break;
        }
        offset += ext_len;
    }

    let key_share = key_share.ok_or_else(|| anyhow::anyhow!("missing X25519 key_share"))?;
    let mut raw_client_hello = handshake.to_vec();
    let raw_session_id_offset = 4 + 2 + 32 + 1 + session_id_offset - 35;
    raw_client_hello[raw_session_id_offset..raw_session_id_offset + 32].fill(0);

    Ok(ParsedClientHello {
        random,
        session_id,
        raw_client_hello,
        key_share,
    })
}

async fn handle_plain_tls_connection(
    mut stream: std::net::TcpStream,
    config: Arc<ServerConfig>,
    upstream_tls_config: Arc<ClientConfig>,
    allowed_server_names: Arc<Vec<String>>,
) -> Result<()> {
    stream.set_nonblocking(false)?;
    let mut conn = ServerConnection::new(config)?;
    while conn.is_handshaking() {
        complete_io(&mut stream, &mut conn).context("complete plain TLS handshake")?;
    }

    let mut tls = StreamOwned::new(conn, stream);

    let server_name = match tls.conn.server_name() {
        Some(name) => name.as_ref().to_string(),
        None => {
            tls.conn.send_close_notify();
            while tls.conn.wants_write() {
                complete_io(&mut tls.sock, &mut tls.conn)
                    .context("flush plain TLS rejection close_notify")?;
            }
            return Ok(());
        }
    };

    if !allowed_server_names.is_empty()
        && !allowed_server_names
            .iter()
            .any(|allowed| allowed == &server_name)
    {
        log::debug!("rejecting plain TLS probe for unexpected SNI: {server_name}");
        tls.conn.send_close_notify();
        while tls.conn.wants_write() {
            complete_io(&mut tls.sock, &mut tls.conn)
                .context("flush plain TLS rejection close_notify")?;
        }
        return Ok(());
    }

    proxy_plain_tls_connection(tls, upstream_tls_config, server_name).await
}

async fn proxy_plain_tls_connection(
    client_tls: StreamOwned<ServerConnection, std::net::TcpStream>,
    upstream_tls_config: Arc<ClientConfig>,
    server_name: String,
) -> Result<()> {
    tokio::task::spawn_blocking(move || -> Result<()> {
        let upstream_host = server_name;
        let server_name =
            ServerName::try_from(upstream_host.clone()).context("parse SNI server_name")?;
        let upstream_sock = std::net::TcpStream::connect((upstream_host.as_str(), 443))
            .with_context(|| format!("connect upstream {}:443", upstream_host))?;
        upstream_sock.set_nodelay(true).ok();
        upstream_sock.set_nonblocking(false)?;

        let mut upstream_conn = upstream_tls_config
            .connect(server_name)
            .build()
            .context("create upstream TLS client")?;
        let mut upstream_sock = upstream_sock;
        while upstream_conn.is_handshaking() {
            complete_io(&mut upstream_sock, &mut upstream_conn)
                .context("complete upstream TLS handshake")?;
        }

        let upstream_tls = StreamOwned::new(upstream_conn, upstream_sock);
        relay_tls_streams(client_tls, upstream_tls)
    })
    .await??;

    Ok(())
}

fn relay_tls_streams(
    mut client_tls: StreamOwned<ServerConnection, std::net::TcpStream>,
    mut upstream_tls: StreamOwned<ClientConnection, std::net::TcpStream>,
) -> Result<()> {
    client_tls.sock.set_nonblocking(true)?;
    upstream_tls
        .sock
        .set_nonblocking(true)?;

    let mut client_to_upstream = Vec::with_capacity(16 * 1024);
    let mut upstream_to_client = Vec::with_capacity(16 * 1024);
    let mut buf = vec![0u8; 16 * 1024];
    let mut client_closed = false;
    let mut upstream_closed = false;

    loop {
        let mut progressed = false;

        if !client_closed && client_to_upstream.len() < 256 * 1024 {
            match client_tls.read(&mut buf) {
                Ok(0) => {
                    client_closed = true;
                    upstream_tls.conn.send_close_notify();
                    progressed = true;
                }
                Ok(n) => {
                    client_to_upstream.extend_from_slice(&buf[..n]);
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }

        if !client_to_upstream.is_empty() {
            match upstream_tls.write(&client_to_upstream) {
                Ok(0) => upstream_closed = true,
                Ok(n) => {
                    client_to_upstream.drain(..n);
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            let _ = upstream_tls.flush();
        }

        if !upstream_closed && upstream_to_client.len() < 256 * 1024 {
            match upstream_tls.read(&mut buf) {
                Ok(0) => {
                    upstream_closed = true;
                    client_tls.conn.send_close_notify();
                    progressed = true;
                }
                Ok(n) => {
                    upstream_to_client.extend_from_slice(&buf[..n]);
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }

        if !upstream_to_client.is_empty() {
            match client_tls.write(&upstream_to_client) {
                Ok(0) => client_closed = true,
                Ok(n) => {
                    upstream_to_client.drain(..n);
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            let _ = client_tls.flush();
        }

        if client_tls.conn.wants_write() {
            let _ = complete_io(&mut client_tls.sock, &mut client_tls.conn);
            progressed = true;
        }
        if upstream_tls.conn.wants_write() {
            let _ = complete_io(&mut upstream_tls.sock, &mut upstream_tls.conn);
            progressed = true;
        }

        if (client_closed || upstream_closed)
            && client_to_upstream.is_empty()
            && upstream_to_client.is_empty()
        {
            break;
        }

        if !progressed {
            thread::sleep(Duration::from_millis(1));
        }
    }

    client_tls.conn.send_close_notify();
    upstream_tls.conn.send_close_notify();
    let _ = client_tls.flush();
    let _ = upstream_tls.flush();
    Ok(())
}

fn build_upstream_tls_config() -> Result<ClientConfig> {
    let root_store = rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );

    Ok(ClientConfig::builder(Arc::new(provider::DEFAULT_PROVIDER))
        .with_root_certificates(root_store)
        .with_no_client_auth()?)
}

fn load_server_config_file(path: &Path) -> Result<ServerConfigFile> {
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

fn parse_reality_private_key(private_key: &str) -> Result<Vec<u8>> {
    let key = private_key.trim();
    let decoded = URL_SAFE_NO_PAD
        .decode(key.as_bytes())
        .or_else(|_| STANDARD_NO_PAD.decode(key.as_bytes()))
        .or_else(|_| URL_SAFE.decode(key.as_bytes()))
        .or_else(|_| STANDARD.decode(key.as_bytes()))
        .context("parse REALITY private key")?;

    if decoded.len() != 32 {
        bail!("REALITY private_key must decode to 32 bytes")
    }
    Ok(decoded)
}

fn parse_reality_short_id_fixed(short_id: &str) -> Result<[u8; 8]> {
    let raw = decode_hex(short_id.trim())?;
    if raw.len() > 8 {
        bail!("REALITY short_id must be at most 8 bytes")
    }

    let mut fixed = [0u8; 8];
    fixed[..raw.len()].copy_from_slice(&raw);
    Ok(fixed)
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    let input = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if !input.len().is_multiple_of(2) {
        bail!("REALITY short_id hex string must contain an even number of digits")
    }

    let mut bytes = Vec::with_capacity(input.len() / 2);
    for chunk in input.as_bytes().chunks_exact(2) {
        bytes.push(parse_hex_byte(chunk[0], chunk[1]));
    }
    Ok(bytes)
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
