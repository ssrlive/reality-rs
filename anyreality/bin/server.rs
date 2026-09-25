#![allow(clippy::std_instead_of_core)]

//! REALITY-wrapped server speaking the **full AnyTLS protocol**.
//!
//! For each inbound TCP:
//! 1. REALITY rustls handshake on a blocking worker thread.
//! 2. Bridge into an async `DuplexStream`.
//! 3. Read anytls auth header `sha256(password) || u16be(pad_len) || pad`.
//! 4. Hand the carrier to `anytls::proxy::session::new_server_session` and
//!    drive its `run()` loop. The library handles cmdSettings,
//!    cmdServerSettings, cmdSYN/cmdSYNACK, cmdPSH/cmdFIN, cmdWaste etc.
//! 5. For each opened anytls session: read a SOCKS5-style `Address` (the
//!    proxy target). If it is the AnyTLS UoT sentinel, follow with a
//!    `UotRequest` and run a UDP-over-TCP relay. Otherwise dial the
//!    address and bidirectionally relay between the upstream socket and
//!    the anytls session.
//!
//! Each inbound AnyTLS logical stream is handled in its own task, so an
//! upstream relay that is still draining cannot block later multiplexed
//! streams on the same carrier.

use anyreality::{AnytlsStreamReader, async_bridge};

use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{Context, Result, bail};
use anytls::{
    DEFAULT_SCHEME, PaddingFactory, Session, Stream as AnytlsStream, UotMode, UotRequest, uot_get_request_from_stream,
    uot_is_sentinel_destination,
};
use aws_lc_rs::agreement;
use aws_lc_rs::encoding::{AsBigEndian, Curve25519SeedBin};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use clap::Parser;
use core::hash::Hasher;
use core::time::Duration;
use hkdf::Hkdf;
use rustls::Connection;
use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls::crypto::SelectedCredential;
use rustls::server::{ClientHello, ClientHelloVerifier, RealityClientHello, ServerCredentialResolver};
use rustls_aws_lc_rs as provider;
use rustls_util::{StreamOwned, complete_io};
use sha2::{Digest, Sha256};
use socks5_impl::protocol::{Address, AsyncStreamOperation};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream as TokioTcpStream, UdpSocket};

const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const CLIENT_HELLO_MAX_WIRE_SIZE: usize = 128 * 1024;
const DEFAULT_MAX_STREAMS_PER_SESSION: usize = 128;
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
static NEXT_SESSION_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);

#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// Path to the grouped server config (`.toml` or `.json`).
    /// Optional — not required when using `--gen-reality-keys`.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Generate an X25519 REALITY keypair (prints privateKey base64url and shortId hex) and exit
    #[arg(short, long)]
    gen_reality_keys: bool,

    /// Log filter (off/error/warn/info/debug/trace or env-style spec).
    #[arg(short, long, value_name = "LEVEL", default_value = "info")]
    log: log::LevelFilter,
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
}

#[derive(Clone, Debug)]
struct ServerConfigResolved {
    listen: String,
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

#[derive(Debug)]
struct RejectCredentialResolver;

impl ServerCredentialResolver for RejectCredentialResolver {
    fn resolve(&self, _client_hello: &ClientHello<'_>) -> Result<SelectedCredential, rustls::Error> {
        Err(rustls::Error::NoSuitableCertificate)
    }
}

impl ClientHelloVerifier for ExampleRealityVerifier {
    fn verify_client_hello(&self, client_hello: &RealityClientHello<'_>) -> core::result::Result<(), rustls::Error> {
        if !self.server_names.is_empty() {
            let server_name = client_hello
                .server_name()
                .map(|name| name.as_ref())
                .ok_or_else(|| rustls::Error::General("REALITY verifier requires SNI".into()))?;

            if !self.server_names.iter().any(|allowed| allowed == server_name) {
                return Err(rustls::Error::General("REALITY verifier rejected an unexpected server_name".into()));
            }
        }

        self.inner.verify_client_hello(client_hello)
    }

    fn reality_auth_key(&self, client_hello: &RealityClientHello<'_>) -> core::result::Result<Option<[u8; 32]>, rustls::Error> {
        self.inner.reality_auth_key(client_hello)
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
    let log = args.log.to_string();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log)).init();

    if args.gen_reality_keys {
        if args.config.is_some() {
            bail!("--gen-reality-keys must not be used together with --config");
        }
        generate_reality_keypair()?;
        return Ok(());
    }

    let config_path = args.config.as_ref().ok_or_else(|| anyhow::anyhow!("--config is required"))?;
    let resolved = resolve_server_config(config_path)?;
    let tls_config = Arc::new(build_server_config(&resolved)?);
    let allowed_server_names = Arc::new(resolved.server_names.clone());
    let password_sha256: [u8; 32] = Sha256::digest(resolved.password.as_bytes()).into();
    let padding = Arc::new(tokio::sync::RwLock::new(
        PaddingFactory::new(DEFAULT_SCHEME).expect("valid default padding scheme"),
    ));
    let reality_private_key = Arc::new(parse_reality_private_key(&resolved.private_key)?);
    let reality_short_id = Arc::new(parse_reality_short_id_fixed(&resolved.short_id)?);
    let reality_version = parse_reality_version(&resolved.version);

    let listener = TcpListener::bind(&resolved.listen).await?;
    log::info!("REALITY+anytls server listening on {}", resolved.listen);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let tls_config = tls_config.clone();
        let allowed_server_names = allowed_server_names.clone();
        let padding = padding.clone();
        let reality_private_key = reality_private_key.clone();
        let reality_short_id = reality_short_id.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(
                stream,
                tls_config,
                allowed_server_names,
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
    allowed_server_names: Arc<Vec<String>>,
    password_sha256: [u8; 32],
    padding: Arc<tokio::sync::RwLock<PaddingFactory>>,
    reality_private_key: Arc<Vec<u8>>,
    reality_short_id: Arc<[u8; 8]>,
    reality_version: [u8; 3],
) -> Result<()> {
    stream.set_nodelay(true).ok();
    let peer_addr = stream.peer_addr()?;
    let std_stream = stream.into_std()?;
    std_stream.set_nonblocking(false)?;

    // ClientHello sniffing performs blocking socket reads for up to
    // CLIENT_HELLO_TIMEOUT. Run it on the blocking pool so a slow or probing
    // connection can never pin an async worker thread; otherwise a handful of
    // scanners on this port would freeze every live carrier's SYNACK traffic.
    let detect_key = reality_private_key.clone();
    let detect_short_id = reality_short_id.clone();
    let (is_reality, std_stream) = tokio::task::spawn_blocking(move || -> Result<(bool, std::net::TcpStream)> {
        let is_reality = is_reality_client_hello(&std_stream, detect_key.as_slice(), detect_short_id.as_slice(), &reality_version)?;
        Ok((is_reality, std_stream))
    })
    .await??;
    if !is_reality {
        return handle_raw_tls_fallback(std_stream, allowed_server_names).await;
    }

    // 1) REALITY blocking handshake on a worker thread.
    let tls = tokio::task::spawn_blocking(move || -> Result<StreamOwned<ServerConnection, std::net::TcpStream>> {
        let mut sock = std_stream;
        sock.set_nonblocking(false)?;
        let mut conn = ServerConnection::new(reality_config)?;
        while conn.is_handshaking() {
            complete_io(&mut sock, &mut conn).context("complete REALITY handshake")?;
        }
        Ok(StreamOwned::new(conn, sock))
    })
    .await??;

    // 2) Bridge into async.
    let mut bridge = async_bridge::into_async(tls)?;

    // 3) Read anytls auth: 32 sha256(password) + u16be padding_len + padding.
    let mut auth = [0u8; 34];
    bridge.read_exact(&mut auth).await.context("read anytls auth header")?;
    if auth[..32] != password_sha256[..] {
        log::debug!("anytls auth failed for an inbound REALITY peer");
        return Ok(());
    }
    let padding_len = u16::from_be_bytes([auth[32], auth[33]]);
    let mut padding_buf = vec![0u8; padding_len as usize];
    if padding_len > 0 {
        bridge.read_exact(&mut padding_buf).await.context("read anytls padding")?;
    }
    if padding_buf.len() >= 36
        && let Some(client_id) = std::str::from_utf8(&padding_buf[..36])
            .ok()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
    {
        log::info!("anytls client id: {client_id}");
    }

    // 4) Hand the carrier to anytls and run the session loop.
    let session = Session::new_server(
        NEXT_SESSION_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        Box::new(bridge),
        padding,
        DEFAULT_MAX_STREAMS_PER_SESSION,
    );
    let session_id = session.id();

    log::debug!("session={} peer={peer_addr} stage=authenticated_session", session_id);
    if let Err(error) = session.run().await {
        log::debug!("session={} peer={peer_addr} stage=session_ended reason={error}", session_id);
        return Ok(());
    }
    loop {
        match session.accept_stream().await {
            Ok(stream) => {
                tokio::spawn(async move {
                    let stream = Arc::new(stream);
                    let stream_id = stream.id();
                    if let Err(error) = handle_stream(stream.clone()).await {
                        log::warn!("session={session_id} stream={stream_id} stage=stream_failed reason={error:#}");
                    }
                });
            }
            Err(error) if !session.is_closed() => {
                log::debug!("session={session_id} peer={peer_addr} stage=stream_rejected reason={error}");
            }
            Err(error) => {
                log::debug!("session={session_id} peer={peer_addr} stage=session_ended reason={error}");
                break;
            }
        }
    }
    Ok(())
}

async fn handle_stream(stream: Arc<AnytlsStream>) -> Result<()> {
    // Acknowledge the stream immediately so the client's SYNACK watchdog is
    // satisfied within one RTT. SYNACK must not be gated on reading the target
    // address or dialing upstream: multiplex reader head-of-line delays and
    // slow upstream connects would otherwise push the SYNACK past the client
    // deadline and abort an otherwise healthy stream.
    stream.handshake_success().await?;
    log::debug!(
        "session={} stream={} stage=target_read_start",
        stream.session_id().unwrap_or_default(),
        stream.id()
    );
    let mut reader = AnytlsStreamReader::new(stream.clone());
    let destination = match Address::retrieve_from_async_stream(&mut reader).await {
        Ok(destination) => destination,
        Err(error) if is_error_of_session_broken(&error) => {
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    log::debug!(
        "session={} stream={} stage=target_read_complete target={destination}",
        stream.session_id().unwrap_or_default(),
        stream.id()
    );
    if uot_is_sentinel_destination(&destination) {
        let request = uot_get_request_from_stream(&mut reader).await?;
        match request.mode {
            UotMode::Connected => handle_uot_connected(stream, &mut reader, &request).await,
            UotMode::Datagram => handle_uot_datagram(stream, &mut reader).await,
        }
    } else {
        handle_tcp_stream(stream, destination, &mut reader).await
    }
}

async fn handle_tcp_stream(stream: Arc<AnytlsStream>, destination: Address, reader: &mut AnytlsStreamReader) -> Result<()> {
    let dst = destination.to_string();
    let started = tokio::time::Instant::now();
    log::debug!(
        "session={} stream={} stage=upstream_connect_start target={dst}",
        stream.session_id().unwrap_or_default(),
        stream.id()
    );
    let outbound = match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TokioTcpStream::connect(&dst)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            log::debug!(
                "session={} stream={} stage=upstream_connect_failed elapsed_ms={} target={dst} reason={err}",
                stream.session_id().unwrap_or_default(),
                stream.id(),
                started.elapsed().as_millis()
            );
            // SYNACK was already sent on accept; the upstream is simply dead,
            // so close the stream instead of emitting a duplicate SYNACK.
            stream.shutdown_write().await?;
            return Err(err.into());
        }
        Err(_) => {
            let err = std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("connect upstream {dst} timed out after {}s", UPSTREAM_CONNECT_TIMEOUT.as_secs()),
            );
            log::debug!(
                "session={} stream={} stage=upstream_connect_timeout elapsed_ms={} reason={err}",
                stream.session_id().unwrap_or_default(),
                stream.id(),
                started.elapsed().as_millis()
            );
            // SYNACK was already sent on accept; just close on timeout.
            stream.shutdown_write().await?;
            return Err(err.into());
        }
    };
    log::debug!(
        "session={} stream={} stage=upstream_connect_complete elapsed_ms={}",
        stream.session_id().unwrap_or_default(),
        stream.id(),
        started.elapsed().as_millis()
    );
    outbound.set_nodelay(true).ok();

    anyreality::relay_tcp(outbound, stream, reader).await?;
    Ok(())
}

async fn handle_uot_datagram(stream: Arc<AnytlsStream>, reader: &mut AnytlsStreamReader) -> Result<()> {
    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    let result = anyreality::relay_uot(&udp, &stream, reader, UotMode::Datagram).await;

    if result.is_err() {
        let _ = stream.shutdown_write().await;
    }
    result.map_err(Into::into)
}

async fn handle_uot_connected(stream: Arc<AnytlsStream>, reader: &mut AnytlsStreamReader, request: &UotRequest) -> Result<()> {
    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    let dst = request.destination.to_string();
    if let Err(err) = udp.connect(&dst).await {
        // SYNACK was already sent on accept; close on connect failure.
        stream.shutdown_write().await?;
        return Err(err.into());
    }
    let result = anyreality::relay_uot(&udp, &stream, reader, UotMode::Connected).await;

    if result.is_err() {
        let _ = stream.shutdown_write().await;
    }
    result.map_err(Into::into)
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

    let listen = server.listen.clone().unwrap_or_else(|| "[::]:443".to_string());
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
        .ok_or_else(|| anyhow::anyhow!("reality.serverNames must be set for fallback"))?;
    if server_names.is_empty() {
        bail!("reality.serverNames must not be empty for fallback");
    }

    Ok(ServerConfigResolved {
        listen,
        password,
        private_key,
        short_id,
        version,
        server_names,
    })
}

fn build_server_config(reality: &ServerConfigResolved) -> Result<ServerConfig> {
    let provider = provider::reality::default_x25519_tls13_reality_provider();
    let mut config = ServerConfig::builder(Arc::new(provider))
        .with_no_client_auth()
        .with_server_credential_resolver(Arc::new(RejectCredentialResolver))?;

    let reality_config = provider::reality::RealityServerVerifierConfig::from_xray_fields(
        parse_reality_version(&reality.version),
        &reality.short_id,
        &reality.private_key,
    )?;
    reality_config.install_into(&mut config)?;
    let verifier = reality_config.build_verifier()?;
    config
        .dangerous()
        .set_reality_client_hello_verifier(Some(Arc::new(ExampleRealityVerifier {
            inner: verifier,
            server_names: reality.server_names.clone(),
        })));

    Ok(config)
}

fn is_reality_client_hello(
    tcp_stream: &std::net::TcpStream,
    server_private_key: &[u8],
    short_id: &[u8],
    version: &[u8; 3],
) -> Result<bool> {
    tcp_stream
        .set_nonblocking(false)
        .context("set socket blocking for ClientHello peek")?;
    tcp_stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .context("set ClientHello peek timeout")?;

    let mut buf = vec![0u8; 2048];
    let deadline = Instant::now() + CLIENT_HELLO_TIMEOUT;

    loop {
        if Instant::now() >= deadline {
            bail!("timed out waiting for ClientHello")
        }
        let available = match tcp_stream.peek(&mut buf) {
            Ok(available) => available,
            // A SO_RCVTIMEO timeout surfaces as TimedOut or WouldBlock (EAGAIN
            // on Linux); both mean "no data yet", so keep waiting until the
            // deadline instead of failing an otherwise valid slow client.
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut || error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(error) => return Err(error).context("peek ClientHello"),
        };
        if available == 0 {
            return Ok(false);
        }

        let Some(handshake) = collect_client_hello(&buf[..available])? else {
            if buf.len() == CLIENT_HELLO_MAX_WIRE_SIZE {
                bail!("ClientHello exceeds maximum size")
            }
            buf.resize((buf.len() * 2).min(CLIENT_HELLO_MAX_WIRE_SIZE), 0);
            thread::sleep(Duration::from_millis(1));
            continue;
        };

        let Ok(parsed) = parse_client_hello(&handshake) else {
            return Ok(false);
        };
        if parsed.session_id.len() != 32 {
            return Ok(false);
        }

        let private_key =
            agreement::PrivateKey::from_private_key(&agreement::X25519, server_private_key).context("parse REALITY private key bytes")?;
        if parsed.key_share.is_empty() {
            return Ok(false);
        }
        let peer_public = agreement::UnparsedPublicKey::new(&agreement::X25519, &parsed.key_share);
        let reality_key = agreement::agree(&private_key, peer_public, aws_lc_rs::error::Unspecified, |secret| {
            Ok::<Vec<u8>, aws_lc_rs::error::Unspecified>(Vec::from(secret))
        })
        .map_err(|_| anyhow::anyhow!("failed to compute REALITY shared secret"))?;

        let hk = Hkdf::<Sha256>::new(Some(&parsed.random[..20]), &reality_key);
        let mut sealing_key = [0u8; 32];
        hk.expand(b"REALITY", &mut sealing_key).context("derive REALITY sealing key")?;

        let cipher = Aes256Gcm::new(&sealing_key.into());
        let mut decrypted = parsed.session_id.clone();
        let nonce = Nonce::try_from(&parsed.random[20..32])?;
        if cipher.decrypt_in_place(&nonce, &parsed.raw_client_hello, &mut decrypted).is_err() {
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
    session_id: Vec<u8>,
    raw_client_hello: Vec<u8>,
    key_share: Vec<u8>,
    server_name: Option<String>,
}

fn collect_client_hello(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut offset = 0;
    let mut handshake = Vec::new();
    let mut expected_len = None;

    while offset < bytes.len() {
        if bytes.len() - offset < 5 {
            return Ok(None);
        }
        let header = &bytes[offset..offset + 5];
        offset += 5;
        if header[0] != 22 {
            bail!("not a handshake record")
        }
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if bytes.len() - offset < record_len {
            return Ok(None);
        }
        let payload = &bytes[offset..offset + record_len];
        offset += record_len;
        handshake.extend_from_slice(payload);

        if expected_len.is_none() && handshake.len() >= 4 {
            if handshake[0] != 1 {
                bail!("not a ClientHello")
            }
            let client_hello_len = ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | handshake[3] as usize;
            let total_len = client_hello_len
                .checked_add(4)
                .ok_or_else(|| anyhow::anyhow!("ClientHello length overflow"))?;
            if total_len > CLIENT_HELLO_MAX_WIRE_SIZE {
                bail!("ClientHello exceeds maximum size")
            }
            expected_len = Some(total_len);
        }

        if let Some(expected_len) = expected_len
            && handshake.len() >= expected_len
        {
            handshake.truncate(expected_len);
            return Ok(Some(handshake));
        }
    }

    Ok(None)
}

fn parse_client_hello(bytes: &[u8]) -> Result<ParsedClientHello> {
    if bytes.len() < 4 || bytes[0] != 1 {
        bail!("not a ClientHello")
    }

    let handshake_len = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | (bytes[3] as usize);
    if handshake_len < 34 || handshake_len + 4 > bytes.len() {
        bail!("truncated ClientHello")
    }

    let body = &bytes[4..4 + handshake_len];
    let mut offset = 2;
    let mut random = [0u8; 32];
    let random_end = offset + 32;
    random.copy_from_slice(
        body.get(offset..random_end)
            .ok_or_else(|| anyhow::anyhow!("truncated ClientHello random"))?,
    );
    offset = random_end;

    let session_id_len = *body.get(offset).ok_or_else(|| anyhow::anyhow!("missing session ID length"))? as usize;
    offset += 1;

    let session_id_offset = offset;
    let session_id_end = offset + session_id_len;
    let session_id = body
        .get(offset..session_id_end)
        .ok_or_else(|| anyhow::anyhow!("truncated session ID"))?
        .to_vec();
    offset = session_id_end;

    let cipher_suites_len = read_u16(body, &mut offset, "cipher suites length")?;
    take_bytes(body, &mut offset, cipher_suites_len, "cipher suites")?;
    let compression_len = *body
        .get(offset)
        .ok_or_else(|| anyhow::anyhow!("missing compression methods length"))? as usize;
    offset += 1 + compression_len;
    if offset > body.len() {
        bail!("truncated ClientHello after compression")
    }

    let extensions_len = read_u16(body, &mut offset, "extensions length")?;
    let extensions = take_bytes(body, &mut offset, extensions_len, "extensions")?;

    let mut extension_offset = 0;
    let mut server_name = None;
    let mut key_share = None;
    while extension_offset < extensions.len() {
        let ext_type = read_u16(extensions, &mut extension_offset, "extension type")?;
        let ext_len = read_u16(extensions, &mut extension_offset, "extension length")?;
        let extension = take_bytes(extensions, &mut extension_offset, ext_len, "extension")?;
        if ext_type == 0x0000 {
            server_name = parse_server_name(extension)?;
        }
        if ext_type == 0x0033 {
            key_share = parse_x25519_key_share(extension)?;
        }
    }

    let key_share = key_share.unwrap_or_default();
    let mut raw_client_hello = bytes.to_vec();
    let raw_session_id_end = 4 + session_id_offset + session_id_len;
    raw_client_hello
        .get_mut(4 + session_id_offset..raw_session_id_end)
        .ok_or_else(|| anyhow::anyhow!("invalid session ID offset"))?
        .fill(0);

    Ok(ParsedClientHello {
        random,
        session_id,
        raw_client_hello,
        key_share,
        server_name,
    })
}

fn read_u16(bytes: &[u8], offset: &mut usize, field: &str) -> Result<usize> {
    let value = take_bytes(bytes, offset, 2, field)?;
    Ok(u16::from_be_bytes([value[0], value[1]]) as usize)
}

fn take_bytes<'a>(bytes: &'a [u8], offset: &mut usize, length: usize, field: &str) -> Result<&'a [u8]> {
    let end = offset.checked_add(length).ok_or_else(|| anyhow::anyhow!("ClientHello overflow"))?;
    let value = bytes
        .get(*offset..end)
        .ok_or_else(|| anyhow::anyhow!("truncated ClientHello {field}"))?;
    *offset = end;
    Ok(value)
}

fn parse_server_name(extension: &[u8]) -> Result<Option<String>> {
    let mut offset = 0;
    let names_len = read_u16(extension, &mut offset, "server name list length")?;
    let names = take_bytes(extension, &mut offset, names_len, "server name list")?;
    let mut name_offset = 0;
    while name_offset < names.len() {
        let name_type = *names
            .get(name_offset)
            .ok_or_else(|| anyhow::anyhow!("truncated server name type"))?;
        name_offset += 1;
        let name_len = read_u16(names, &mut name_offset, "server name length")?;
        let name = take_bytes(names, &mut name_offset, name_len, "server name")?;
        if name_type == 0 {
            return Ok(Some(std::str::from_utf8(name)?.to_ascii_lowercase()));
        }
    }
    Ok(None)
}

fn parse_x25519_key_share(extension: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut offset = 0;
    let shares_len = read_u16(extension, &mut offset, "key share list length")?;
    let shares = take_bytes(extension, &mut offset, shares_len, "key share list")?;
    let mut share_offset = 0;
    while share_offset < shares.len() {
        let group = read_u16(shares, &mut share_offset, "key share group")?;
        let share_len = read_u16(shares, &mut share_offset, "key share length")?;
        let share = take_bytes(shares, &mut share_offset, share_len, "key share")?;
        if group == 0x001d {
            return Ok(Some(share.to_vec()));
        }
    }
    Ok(None)
}

fn generate_reality_keypair() -> Result<()> {
    // Generate an X25519 private key and derive public, then print Xray-style fields.
    let priv_key = agreement::PrivateKey::generate(&agreement::X25519).context("generate X25519 private key")?;
    let pub_key = priv_key.compute_public_key().context("compute public key")?;

    // Extract raw private seed bytes (32 bytes)
    let raw_priv: Curve25519SeedBin<'_> = priv_key.as_be_bytes().context("extract private key bytes")?;
    let priv_bytes = raw_priv.as_ref();

    // base64url no-padding privateKey (Xray style)
    let private_b64url = URL_SAFE_NO_PAD.encode(priv_bytes);

    // shortId = first 8 bytes of SHA256(public_key)
    let digest = Sha256::digest(pub_key.as_ref());
    let short_id = &digest[..8];
    let mut shorthex = String::with_capacity(16);
    for b in short_id {
        use core::fmt::Write;
        write!(&mut shorthex, "{:02x}", b).ok();
    }

    // publicKey: base64url no padding (Xray-style) for client config
    let public_b64url = URL_SAFE_NO_PAD.encode(pub_key.as_ref());

    println!("privateKey: {}", private_b64url);
    println!("publicKey: {}", public_b64url);
    println!("shortId: {}", shorthex);
    Ok(())
}

async fn handle_raw_tls_fallback(tcp_client: std::net::TcpStream, allowed_server_names: Arc<Vec<String>>) -> Result<()> {
    // The SNI sniff also does blocking reads for up to CLIENT_HELLO_TIMEOUT;
    // keep it on the blocking pool so it never occupies an async worker thread.
    let (server_name, tcp_client) = tokio::task::spawn_blocking(move || -> Result<(String, std::net::TcpStream)> {
        tcp_client.set_read_timeout(Some(Duration::from_secs(1)))?;
        let mut buffer = vec![0u8; 2048];
        let deadline = Instant::now() + CLIENT_HELLO_TIMEOUT;
        let handshake = loop {
            if Instant::now() >= deadline {
                bail!("timed out waiting for fallback ClientHello");
            }
            let available = match tcp_client.peek(&mut buffer) {
                Ok(available) => available,
                // Timeout on a slow client shows up as TimedOut or
                // WouldBlock (EAGAIN on Linux); keep waiting either way.
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut || error.kind() == std::io::ErrorKind::WouldBlock => 0,
                Err(error) => return Err(error.into()),
            };
            let Some(handshake) = collect_client_hello(&buffer[..available])? else {
                if buffer.len() == CLIENT_HELLO_MAX_WIRE_SIZE {
                    bail!("ClientHello exceeds maximum size");
                }
                buffer.resize((buffer.len() * 2).min(CLIENT_HELLO_MAX_WIRE_SIZE), 0);
                thread::sleep(Duration::from_millis(1));
                continue;
            };
            break handshake;
        };
        let parsed = parse_client_hello(&handshake)?;
        let server_name = parsed.server_name.ok_or_else(|| anyhow::anyhow!("fallback requires SNI"))?;
        Ok((server_name, tcp_client))
    })
    .await??;

    if !allowed_server_names.iter().any(|allowed| allowed == &server_name) {
        bail!("fallback rejected unexpected SNI: {server_name}");
    }

    tcp_client.set_nonblocking(true)?;
    let client = TokioTcpStream::from_std(tcp_client)?;
    let mut upstream = TokioTcpStream::connect((server_name.as_str(), 443)).await?;
    let mut client = client;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

fn load_server_config_file(path: &Path) -> Result<ServerConfigFile> {
    let contents = std::fs::read_to_string(path)?;
    match path.extension().and_then(|ext| ext.to_str()).unwrap_or_default() {
        "json" => Ok(serde_json::from_str(&contents)?),
        "toml" => Ok(toml::from_str(&contents)?),
        _ => bail!("unsupported REALITY config format: {}", path.display()),
    }
}

fn parse_reality_version(version: &str) -> [u8; 3] {
    let version = version.trim();
    assert_eq!(version.len(), 6, "REALITY version must be 6 hex digits");
    let mut parsed = [0u8; 3];
    for (index, chunk) in version.as_bytes().as_chunks::<2>().0.iter().enumerate() {
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
    let input = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value);
    if !input.len().is_multiple_of(2) {
        bail!("REALITY short_id hex string must contain an even number of digits")
    }

    let mut bytes = Vec::with_capacity(input.len() / 2);
    for chunk in input.as_bytes().as_chunks::<2>().0 {
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

fn is_error_of_session_broken(error: &std::io::Error) -> bool {
    use std::io::ErrorKind::{BrokenPipe, UnexpectedEof};
    matches!(error.kind(), UnexpectedEof | BrokenPipe)
}

#[cfg(test)]
mod tests {
    use super::{collect_client_hello, parse_client_hello};

    #[test]
    fn malformed_client_hello_returns_error_without_panicking() {
        let inputs = [
            vec![22, 3, 3, 0, 4, 1, 0, 0, 0],
            vec![22, 3, 3, 0, 39, 1, 0, 0, 35, 3, 3],
            vec![22, 3, 3, 0, 42, 1, 0, 0, 38, 3, 3, 0, 0, 0, 0],
        ];

        for input in inputs {
            let result = std::panic::catch_unwind(|| parse_client_hello(&input));
            assert!(result.is_ok(), "parser panicked for malformed input");
            assert!(result.unwrap().is_err());
        }
    }

    #[test]
    fn fragmented_client_hello_is_collected_and_parsed() {
        let mut handshake = vec![1, 0, 0, 75, 3, 3];
        handshake.extend([0u8; 32]);
        handshake.push(32);
        handshake.extend([0u8; 32]);
        handshake.extend([0, 2, 0x13, 0x01, 1, 0, 0, 0]);

        let split = 2;
        let mut records = vec![22, 3, 3, 0, split as u8];
        records.extend_from_slice(&handshake[..split]);
        records.extend([22, 3, 3, 0, (handshake.len() - split) as u8]);
        records.extend_from_slice(&handshake[split..]);

        let collected = collect_client_hello(&records)
            .unwrap()
            .expect("fragmented ClientHello should be complete");
        assert_eq!(collected, handshake);
        assert!(parse_client_hello(&collected).is_ok());
    }
}
