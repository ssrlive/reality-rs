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

use anyreality::async_bridge;

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
use rustls::Connection;
use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls::crypto::SelectedCredential;
use rustls::server::{
    ClientHello, ClientHelloVerifier, RealityClientHello, RealityClientHelloProbe, RealityServerHelloAction, ServerCredentialResolver,
};
use rustls_aws_lc_rs as provider;
use rustls_util::{StreamOwned, complete_io};
use sha2::{Digest, Sha256};
use socks5_impl::protocol::{Address, AsyncStreamOperation};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream as TokioTcpStream, UdpSocket};

const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const CLIENT_HELLO_MAX_WIRE_SIZE: usize = 128 * 1024;
const SERVER_HELLO_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const REALITY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const ANYTLS_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_INBOUND_CARRIERS: usize = 128;
const MAX_ACTIVE_STREAMS: usize = 512;
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
    short_ids: Option<Vec<String>>,
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
    listen: Option<SocketAddr>,
}

#[derive(Clone, Debug)]
struct ServerConfigResolved {
    listen: SocketAddr,
    password: String,
    private_key: String,
    short_ids: Vec<Vec<u8>>,
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

    fn verify_client_hello_probe(&self, probe: &RealityClientHelloProbe) -> core::result::Result<bool, rustls::Error> {
        self.inner.verify_client_hello_probe(probe)
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
    let (tls_config, reality_probe_verifier) = build_server_config(&resolved)?;
    let tls_config = Arc::new(tls_config);
    let allowed_server_names = Arc::new(resolved.server_names.clone());
    let password_sha256: [u8; 32] = Sha256::digest(resolved.password.as_bytes()).into();
    let padding = Arc::new(tokio::sync::RwLock::new(
        PaddingFactory::new(DEFAULT_SCHEME).expect("valid default padding scheme"),
    ));
    let listener = TcpListener::bind(&resolved.listen).await?;
    let carrier_slots = Arc::new(tokio::sync::Semaphore::new(MAX_INBOUND_CARRIERS));
    let stream_slots = Arc::new(tokio::sync::Semaphore::new(MAX_ACTIVE_STREAMS));
    log::info!("REALITY+anytls server listening on {}", resolved.listen);

    loop {
        let carrier_permit = carrier_slots.clone().acquire_owned().await?;
        let (stream, peer_addr) = listener.accept().await?;
        let tls_config = tls_config.clone();
        let allowed_server_names = allowed_server_names.clone();
        let padding = padding.clone();
        let reality_probe_verifier = reality_probe_verifier.clone();
        let stream_slots = stream_slots.clone();
        tokio::spawn(async move {
            let _carrier_permit = carrier_permit;
            if let Err(error) = handle_connection(
                stream,
                tls_config,
                allowed_server_names,
                reality_probe_verifier,
                password_sha256,
                padding,
                stream_slots,
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
    reality_probe_verifier: Arc<dyn ClientHelloVerifier>,
    password_sha256: [u8; 32],
    padding: Arc<tokio::sync::RwLock<PaddingFactory>>,
    stream_slots: Arc<tokio::sync::Semaphore>,
) -> Result<()> {
    stream.set_nodelay(true).ok();
    let peer_addr = stream.peer_addr()?;
    let std_stream = stream.into_std()?;
    std_stream.set_nonblocking(false)?;

    // ClientHello sniffing performs blocking socket reads for up to
    // CLIENT_HELLO_TIMEOUT. Run it on the blocking pool so a slow or probing
    // connection can never pin an async worker thread; otherwise a handful of
    // scanners on this port would freeze every live carrier's SYNACK traffic.
    let detect_verifier = reality_probe_verifier.clone();
    let (client_hello, std_stream) =
        tokio::task::spawn_blocking(move || -> Result<(Option<RealityClientHelloProbe>, std::net::TcpStream)> {
            let client_hello = is_reality_client_hello(&std_stream, detect_verifier.as_ref())?;
            Ok((client_hello, std_stream))
        })
        .await??;
    let Some(client_hello) = client_hello else {
        return handle_raw_tls_fallback(std_stream, allowed_server_names).await;
    };
    let allowed_names_for_probe = allowed_server_names.clone();
    let server_hello_action = tokio::task::spawn_blocking(move || {
        client_hello.fetch_server_hello_or_fallback(&allowed_names_for_probe, |server_name, client_hello| {
            let destination = format!("{server_name}:443");
            probe_server_hello(&destination, client_hello).map_err(|error| rustls::Error::General(error.to_string()))
        })
    })
    .await?;
    let server_hello_template = match server_hello_action {
        RealityServerHelloAction::UseTemplate(template) => template,
        RealityServerHelloAction::Fallback { server_name, probe_error } => {
            if let Some(error) = probe_error {
                log::debug!(
                    "REALITY ServerHello probe failed for {:?}: {error}; falling back to target",
                    server_name
                );
            }
            return handle_raw_tls_fallback(std_stream, allowed_server_names).await;
        }
        _ => return handle_raw_tls_fallback(std_stream, allowed_server_names).await,
    };

    // 1) REALITY blocking handshake on a worker thread.
    let tls = tokio::task::spawn_blocking(move || -> Result<StreamOwned<ServerConnection, std::net::TcpStream>> {
        let mut sock = std_stream;
        sock.set_nonblocking(false)?;
        sock.set_read_timeout(Some(REALITY_HANDSHAKE_TIMEOUT))?;
        sock.set_write_timeout(Some(REALITY_HANDSHAKE_TIMEOUT))?;
        let mut conn = ServerConnection::new(reality_config)?;
        conn.set_reality_server_hello_template(&server_hello_template)
            .context("install SNI target ServerHello template")?;
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
    let padding_buf = tokio::time::timeout(ANYTLS_AUTH_TIMEOUT, async {
        bridge.read_exact(&mut auth).await?;
        let padding_len = u16::from_be_bytes([auth[32], auth[33]]);
        let mut padding_buf = vec![0u8; padding_len as usize];
        if padding_len > 0 {
            bridge.read_exact(&mut padding_buf).await?;
        }
        Ok::<_, std::io::Error>(padding_buf)
    })
    .await
    .context("timed out waiting for anytls auth")??;
    if auth[..32] != password_sha256[..] {
        log::debug!("anytls auth failed for an inbound REALITY peer");
        return Ok(());
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
        anytls::DEFAULT_MAX_SESSION_AGE,
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
                let Ok(stream_permit) = stream_slots.clone().try_acquire_owned() else {
                    log::debug!("session={session_id} stream={} rejected: active stream limit reached", stream.id());
                    if stream.handshake_success().await.is_ok() {
                        let _ = stream.shutdown_write_by_send_fin_to_remote().await;
                    }
                    continue;
                };
                tokio::spawn(async move {
                    let _stream_permit = stream_permit;
                    let stream_id = stream.id();
                    if let Err(error) = handle_stream(stream).await {
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

async fn handle_stream(stream: AnytlsStream) -> Result<()> {
    let mut io = anytls::StreamIo::new(stream);
    let stream = io.stream();
    let session_id = stream.session_id();
    let stream_id = stream.id();
    // Acknowledge the stream immediately so the client's SYNACK watchdog is
    // satisfied within one RTT. SYNACK must not be gated on reading the target
    // address or dialing upstream: multiplex reader head-of-line delays and
    // slow upstream connects would otherwise push the SYNACK past the client
    // deadline and abort an otherwise healthy stream.
    if let Err(error) = stream.handshake_success().await {
        if is_error_of_session_broken(&error) {
            log::debug!("session={session_id} stream={stream_id} peer disconnected before SYNACK: {error}",);
            return Ok(());
        }
        return Err(error.into());
    }
    log::debug!("session={session_id} stream={} stage=target_read_start", stream.id());
    let destination = match Address::retrieve_from_async_stream(&mut io).await {
        Ok(destination) => destination,
        Err(error) if is_error_of_session_broken(&error) => {
            log::debug!("session={session_id} stream={stream_id} peer disconnected while sending target: {error}",);
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    log::debug!("session={session_id} stream={stream_id} stage=target_read_complete target={destination}",);
    if uot_is_sentinel_destination(&destination) {
        let request = match uot_get_request_from_stream(&mut io).await {
            Ok(request) => request,
            Err(error) if is_error_of_session_broken(&error) => {
                log::debug!("session={session_id} stream={stream_id} peer disconnected while sending UoT request: {error}",);
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        match request.mode {
            UotMode::Connected => handle_uot_connected(stream, &mut io, &request).await,
            UotMode::Datagram => handle_uot_datagram(stream, &mut io).await,
        }
    } else {
        handle_tcp_stream(&mut io, &stream, destination).await
    }
}

async fn handle_tcp_stream(io: &mut anytls::StreamIo, stream: &Arc<AnytlsStream>, destination: Address) -> Result<()> {
    let session_id = stream.session_id();
    let stream_id = stream.id();

    let dst = destination.to_string();
    let started = tokio::time::Instant::now();
    log::debug!("session={session_id} stream={stream_id} stage=upstream_connect_start target={dst}",);
    let mut outbound = match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TokioTcpStream::connect(&dst)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            log::debug!(
                "session={session_id} stream={stream_id} stage=upstream_connect_failed elapsed_ms={} target={dst} reason={err}",
                started.elapsed().as_millis()
            );
            // SYNACK was already sent on accept; the upstream is simply dead,
            // so close the stream instead of emitting a duplicate SYNACK.
            stream.shutdown_write_by_send_fin_to_remote().await?;
            return Err(err.into());
        }
        Err(_) => {
            let err = std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("connect upstream {dst} timed out after {}s", UPSTREAM_CONNECT_TIMEOUT.as_secs()),
            );
            log::debug!(
                "session={session_id} stream={stream_id} stage=upstream_connect_timeout elapsed_ms={} reason={err}",
                started.elapsed().as_millis()
            );
            // SYNACK was already sent on accept; just close on timeout.
            stream.shutdown_write_by_send_fin_to_remote().await?;
            return Err(err.into());
        }
    };
    log::debug!(
        "session={session_id} stream={stream_id} stage=upstream_connect_complete elapsed_ms={}",
        started.elapsed().as_millis()
    );
    outbound.set_nodelay(true).ok();

    match anytls::relay::copy_bidirectional(io, &mut outbound).await {
        Ok(_) => {}
        Err(error) if error.is_peer_disconnect() => {
            log::debug!("session={session_id} stream={stream_id} peer disconnected during TCP relay to {dst}: {error}",);
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

async fn handle_uot_datagram(stream: Arc<AnytlsStream>, reader: &mut anytls::StreamIo) -> Result<()> {
    let session_id = stream.session_id();
    let stream_id = stream.id();

    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    let result = anyreality::relay_uot_with_peer_identity(&udp, &stream, reader, UotMode::Datagram).await;

    if result.is_err() {
        let _ = stream.shutdown_write_by_send_fin_to_remote().await;
    }
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.is_peer_disconnect() => {
            log::debug!("session={session_id} stream={stream_id} peer disconnected during UoT relay: {error}",);
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

async fn handle_uot_connected(stream: Arc<AnytlsStream>, reader: &mut anytls::StreamIo, request: &UotRequest) -> Result<()> {
    let session_id = stream.session_id();
    let stream_id = stream.id();

    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    let dst = request.destination.to_string();
    if let Err(err) = udp.connect(&dst).await {
        // SYNACK was already sent on accept; close on connect failure.
        stream.shutdown_write_by_send_fin_to_remote().await?;
        return Err(err.into());
    }
    let result = anyreality::relay_uot_with_peer_identity(&udp, &stream, reader, UotMode::Connected).await;

    if result.is_err() {
        let _ = stream.shutdown_write_by_send_fin_to_remote().await;
    }
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.is_peer_disconnect() => {
            log::debug!("session={session_id} stream={stream_id} peer disconnected during connected UoT relay to {dst}: {error}",);
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
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

    let listen = server.listen.unwrap_or_else(|| "[::]:443".parse::<SocketAddr>().unwrap());
    let password = anytls
        .password
        .clone()
        .ok_or_else(|| anyhow::anyhow!("anytls.password must be set in config"))?;
    if password.is_empty() {
        bail!("anytls.password must not be empty");
    }

    let short_ids = parse_server_short_ids(reality)?;
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
        short_ids,
        version,
        server_names,
    })
}

fn build_server_config(reality: &ServerConfigResolved) -> Result<(ServerConfig, Arc<dyn ClientHelloVerifier>)> {
    let provider = provider::reality::default_x25519_tls13_reality_provider();
    let mut config = ServerConfig::builder(Arc::new(provider))
        .with_no_client_auth()
        .with_server_credential_resolver(Arc::new(RejectCredentialResolver))?;

    let reality_config = provider::reality::RealityServerVerifierConfig::new(
        parse_reality_version(&reality.version),
        &reality.short_ids[0],
        parse_reality_private_key(&reality.private_key)?,
    )
    .with_short_ids(reality.short_ids.clone());
    reality_config.install_into(&mut config)?;
    let verifier = reality_config.build_verifier()?;
    config
        .dangerous()
        .set_reality_client_hello_verifier(Some(Arc::new(ExampleRealityVerifier {
            inner: verifier.clone(),
            server_names: reality.server_names.clone(),
        })));

    Ok((config, verifier))
}

fn is_reality_client_hello(
    tcp_stream: &std::net::TcpStream,
    verifier: &dyn ClientHelloVerifier,
) -> Result<Option<RealityClientHelloProbe>> {
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
            return Ok(None);
        }

        let Some(client_hello) = RealityClientHelloProbe::from_tls_records(&buf[..available])? else {
            if buf.len() == CLIENT_HELLO_MAX_WIRE_SIZE {
                bail!("ClientHello exceeds maximum size")
            }
            buf.resize((buf.len() * 2).min(CLIENT_HELLO_MAX_WIRE_SIZE), 0);
            thread::sleep(Duration::from_millis(1));
            continue;
        };

        if verifier.verify_client_hello_probe(&client_hello)? {
            return Ok(Some(client_hello));
        }
        log::debug!("REALITY ClientHello preflight rejected; passing the connection through to its SNI target");
        return Ok(None);
    }
}

fn probe_server_hello(destination: &str, client_hello: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind::InvalidData, ErrorKind::InvalidInput};
    let mut last_error = None;
    use std::net::ToSocketAddrs;
    for address in destination.to_socket_addrs()? {
        match std::net::TcpStream::connect_timeout(&address, SERVER_HELLO_PROBE_TIMEOUT) {
            Ok(mut stream) => {
                stream.set_read_timeout(Some(SERVER_HELLO_PROBE_TIMEOUT))?;
                stream.set_write_timeout(Some(SERVER_HELLO_PROBE_TIMEOUT))?;
                stream.write_all(client_hello)?;

                let mut record_header = [0u8; 5];
                stream.read_exact(&mut record_header)?;
                let record_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
                if !(4..=18_432).contains(&record_len) {
                    return Err(Error::new(InvalidData, "destination sent an invalid TLS handshake record length"));
                }
                let mut payload = vec![0u8; record_len];
                stream.read_exact(&mut payload)?;
                let mut record = Vec::with_capacity(record_header.len() + payload.len());
                record.extend_from_slice(&record_header);
                record.extend_from_slice(&payload);
                return Ok(record);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| Error::new(InvalidInput, format!("can't resolve ServerHello probe destination {destination}"))))
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
    let (client_hello, tcp_client) = tokio::task::spawn_blocking(move || -> Result<(RealityClientHelloProbe, std::net::TcpStream)> {
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
            let Some(client_hello) = RealityClientHelloProbe::from_tls_records(&buffer[..available])? else {
                if buffer.len() == CLIENT_HELLO_MAX_WIRE_SIZE {
                    bail!("ClientHello exceeds maximum size");
                }
                buffer.resize((buffer.len() * 2).min(CLIENT_HELLO_MAX_WIRE_SIZE), 0);
                thread::sleep(Duration::from_millis(1));
                continue;
            };
            break client_hello;
        };
        Ok((handshake, tcp_client))
    })
    .await??;

    let server_name = client_hello
        .server_name_if_allowed(&allowed_server_names)
        .ok_or_else(|| match client_hello.server_name() {
            Some(server_name) => anyhow::anyhow!("fallback rejected unexpected SNI: {server_name}"),
            None => anyhow::anyhow!("fallback requires SNI"),
        })?;
    let server_name = server_name.to_string();

    tcp_client.set_nonblocking(true)?;
    let client = TokioTcpStream::from_std(tcp_client)?;
    let mut upstream = TokioTcpStream::connect((server_name.as_str(), 443)).await?;
    let mut client = client;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

fn load_server_config_file(path: &Path) -> Result<ServerConfigFile> {
    let contents = std::fs::read_to_string(path)?;
    if let Ok(config) = serde_json::from_str(&contents) {
        Ok(config)
    } else if let Ok(config) = toml::from_str(&contents) {
        Ok(config)
    } else {
        bail!("unsupported REALITY config format: {}", path.display());
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

fn parse_server_short_ids(reality: &ServerRealityConfigFile) -> Result<Vec<Vec<u8>>> {
    let configured_short_ids = reality
        .short_ids
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("reality.shortIds must be set in config"))?;

    if configured_short_ids.is_empty() {
        bail!("reality.shortIds must not be empty");
    }

    configured_short_ids
        .iter()
        .map(|short_id| {
            let short_id = decode_hex(short_id.trim())?;
            if short_id.len() > 8 {
                bail!("each REALITY short_id must be at most 8 bytes");
            }
            Ok(short_id)
        })
        .collect()
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    let input = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value);
    if !input.len().is_multiple_of(2) {
        bail!("REALITY short_id hex string must contain an even number of digits")
    }
    if !input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("REALITY short_id must contain only hexadecimal digits")
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
    error.kind() == std::io::ErrorKind::UnexpectedEof || anytls::relay::is_peer_disconnect(error)
}

#[cfg(test)]
mod tests {
    use super::{ServerRealityConfigFile, parse_server_short_ids, probe_server_hello};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn server_short_ids_accepts_toml_and_json_arrays() {
        let array: ServerRealityConfigFile = toml::from_str("shortIds = [\"aabbcc\", \"1122\"]").unwrap();
        assert_eq!(
            parse_server_short_ids(&array).unwrap(),
            vec![vec![0xaa, 0xbb, 0xcc], vec![0x11, 0x22]]
        );

        let json: ServerRealityConfigFile = serde_json::from_str(r#"{"shortIds":["aabbcc","1122"]}"#).unwrap();
        assert_eq!(
            parse_server_short_ids(&json).unwrap(),
            vec![vec![0xaa, 0xbb, 0xcc], vec![0x11, 0x22]]
        );
    }

    #[test]
    fn server_short_ids_rejects_missing_or_invalid_config() {
        let missing: ServerRealityConfigFile = toml::from_str("").unwrap();
        assert!(parse_server_short_ids(&missing).is_err());

        let legacy: ServerRealityConfigFile = toml::from_str("shortId = \"aabbcc\"").unwrap();
        assert!(parse_server_short_ids(&legacy).is_err());

        let empty: ServerRealityConfigFile = toml::from_str("shortIds = []").unwrap();
        assert!(parse_server_short_ids(&empty).is_err());

        let too_long: ServerRealityConfigFile = toml::from_str("shortIds = [\"001122334455667788\"]").unwrap();
        assert!(parse_server_short_ids(&too_long).is_err());

        let invalid_hex: ServerRealityConfigFile = toml::from_str("shortIds = [\"zz\"]").unwrap();
        assert!(parse_server_short_ids(&invalid_hex).is_err());
    }

    #[test]
    fn server_hello_probe_preserves_client_hello_wire_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client_hello = vec![22, 3, 3, 0, 4, 1, 0, 0, 0];
        let expected_client_hello = client_hello.clone();
        let server_hello_record = [22, 3, 3, 0, 8, 2, 0, 0, 4, 0, 0, 0, 0];
        let expected_server_hello = server_hello_record.to_vec();

        let target = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = vec![0; expected_client_hello.len()];
            stream.read_exact(&mut received).unwrap();
            assert_eq!(received, expected_client_hello);
            stream.write_all(&server_hello_record).unwrap();
        });

        let template = probe_server_hello(&address.to_string(), &client_hello).unwrap();
        target.join().unwrap();
        assert_eq!(template, expected_server_hello);
    }
}
