#![allow(clippy::std_instead_of_core)]

//! REALITY-wrapped SOCKS5 client speaking the **full AnyTLS protocol**.
//!
//! Architecture:
//!
//! - All session-level concerns (cmdSettings/cmdServerSettings, cmdSYN/
//!   cmdSYNACK, cmdPSH/cmdFIN, cmdWaste padding scheme, idle session pool)
//!   are owned by `anytls::proxy::session::Client`.
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

use anyreality::async_bridge;

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
use rustls::client::{ClientHelloProfile, Resumption};
use rustls::pki_types::ServerName;
use rustls_aws_lc_rs as provider;
use rustls_util::{StreamOwned, complete_io};
use sha2::{Digest, Sha256};
use socks5_impl::protocol::{Address, Reply};
use socks5_impl::server::auth::NoAuth;
use socks5_impl::server::connection::{
    ClientConnection as SocksClientConnection, IncomingConnection, associate, connect,
};
use socks5_impl::server::{AssociatedUdpSocket, UdpAssociate};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader,
};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const MAX_UDP_RELAY_PACKET_SIZE: usize = 65_535;
const DEFAULT_MAX_STREAMS_PER_SESSION: usize = 8;

#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// Path to the grouped client config (`.toml` or `.json`).
    #[arg(long)]
    config: PathBuf,

    /// Log filter (off/error/warn/info/debug/trace or env-style spec).
    #[arg(long, default_value = "info")]
    log: log::LevelFilter,
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
    #[serde(default)]
    client_hello_profile: Option<String>,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientAnytlsConfigFile {
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    client_id: Option<uuid::Uuid>,
    #[serde(default)]
    idle_check_secs: Option<u64>,
    #[serde(default)]
    idle_timeout_secs: Option<u64>,
    #[serde(default)]
    min_idle_sessions: Option<usize>,
    #[serde(default)]
    max_streams_per_session: Option<usize>,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientRuntimeConfigFile {
    #[serde(default)]
    listen: Option<SocketAddr>,
    #[serde(default)]
    server_addr: Option<String>,
    #[serde(default)]
    probe_proxy: Option<SocketAddr>,
}

#[derive(Clone, Debug)]
struct RealityClientConfigResolved {
    listen: SocketAddr,
    server_addr: String,
    probe_proxy: Option<SocketAddr>,
    password: String,
    client_id: Option<uuid::Uuid>,
    idle_check_secs: u64,
    idle_timeout_secs: u64,
    min_idle_sessions: usize,
    max_streams_per_session: usize,
    public_key: String,
    short_id: String,
    version: String,
    server_name: String,
    client_hello_profile: ClientHelloProfile,
}

#[derive(Clone)]
struct DialCtx {
    server_addr: String,
    probe_proxy: Option<SocketAddr>,
    tls_config: Arc<ClientConfig>,
    server_name: String,
    password_sha256: [u8; 32],
    client_id: Option<uuid::Uuid>,
    padding: Arc<tokio::sync::RwLock<PaddingFactory>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let log = args.log.to_string();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log)).init();

    let resolved = resolve_client_config(&args.config)?;
    let tls_config = Arc::new(build_client_config(&resolved)?);
    let server_addr = resolved.server_addr.clone();
    let server_name = resolved.server_name.clone();
    let padding = DefaultPaddingFactory::load();

    let dial_ctx = Arc::new(DialCtx {
        server_addr: server_addr.clone(),
        probe_proxy: resolved.probe_proxy,
        tls_config,
        server_name: server_name.clone(),
        password_sha256: Sha256::digest(resolved.password.as_bytes()).into(),
        client_id: resolved.client_id,
        padding: padding.clone(),
    });

    // anytls Client owns the session pool. On every `create_stream()` it
    // picks an idle session or invokes `dial_out` to build a new one.
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
        resolved.max_streams_per_session,
    ));

    log::info!(
        "REALITY+anytls client: mixed SOCKS5/HTTP {} -> {} (sni={})",
        resolved.listen,
        server_addr,
        server_name
    );

    let listen: SocketAddr = resolved.listen;
    let listener = TcpListener::bind(listen).await?;
    let auth = Arc::new(NoAuth);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let anytls_client = anytls_client.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            let mut first_byte = [0u8; 1];
            let result = match stream.peek(&mut first_byte).await {
                Ok(0) => Ok(()),
                Ok(_) if first_byte[0] == 0x05 => {
                    handle_socks(IncomingConnection::new(stream, auth), anytls_client).await
                }
                Ok(_) => handle_http_connect(stream, anytls_client).await,
                Err(error) => Err(error.into()),
            };
            if let Err(error) = result {
                log::warn!("Proxy peer {peer_addr} failed: {error:#}");
            }
        });
    }
}

/// One-shot REALITY+TLS+anytls-auth dialer. Returns a fresh transport
/// `Box<dyn AsyncReadWrite>` ready to be wrapped in a brand-new anytls
/// session. Called by `Client` whenever the idle-session pool is empty.
async fn dial_carrier(ctx: Arc<DialCtx>) -> std::io::Result<Box<dyn AsyncReadWrite>> {
    // 1) Plain TCP connect, optionally via an HTTP CONNECT probe proxy.
    let tokio_tcp = if let Some(proxy_addr) = ctx.probe_proxy {
        log::info!("Connecting to REALITY server via probe proxy at {proxy_addr}");
        connect_via_probe_proxy(proxy_addr, &ctx.server_addr).await?
    } else {
        TcpStream::connect(&ctx.server_addr).await?
    };
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

    let client_id_bytes = ctx
        .client_id
        .map(|client_id| client_id.to_string().into_bytes())
        .unwrap_or_default();
    let padding_len = padding_len.max(client_id_bytes.len() as u16);

    let mut auth = Vec::with_capacity(34 + padding_len as usize);
    auth.extend_from_slice(&ctx.password_sha256);
    auth.extend_from_slice(&padding_len.to_be_bytes());
    if padding_len > 0 {
        let start = auth.len();
        auth.resize(start + padding_len as usize, 0);
        auth[start..start + client_id_bytes.len()].copy_from_slice(&client_id_bytes);
    }
    bridge.write_all(&auth).await?;

    Ok(Box::new(bridge) as Box<dyn AsyncReadWrite>)
}

async fn connect_via_probe_proxy(
    proxy_addr: SocketAddr,
    target: &str,
) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream.set_nodelay(true)?;

    let connect_request = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    );
    stream
        .write_all(connect_request.as_bytes())
        .await?;

    let mut reader = TokioBufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .await?;
    if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200") {
        return Err(std::io::Error::other(format!(
            "HTTP proxy CONNECT failed: {}",
            status_line.trim_end()
        )));
    }

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    let stream = reader.into_inner();
    stream.set_nodelay(true)?;
    Ok(stream)
}

async fn handle_socks(incoming: IncomingConnection, client: Arc<Client>) -> Result<()> {
    let authenticated = incoming.authenticate().await?;
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

async fn handle_http_connect(mut stream: TcpStream, client: Arc<Client>) -> Result<()> {
    let mut request = Vec::new();
    let read_headers = async {
        loop {
            let mut byte = [0u8; 1];
            let count = stream.read(&mut byte).await?;
            if count == 0 {
                bail!("HTTP proxy client closed before sending headers");
            }
            request.push(byte[0]);
            if request.len() > 16 * 1024 {
                bail!("HTTP proxy request headers are too large");
            }
            if request.ends_with(b"\r\n\r\n") || request.ends_with(b"\n\n") {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::time::timeout(Duration::from_secs(10), read_headers)
        .await
        .context("HTTP proxy header timeout")??;

    let text = std::str::from_utf8(&request).context("HTTP proxy request is not UTF-8")?;
    let request_line = text
        .lines()
        .next()
        .ok_or_else(|| anyhow!("HTTP proxy request is empty"))?;
    let mut fields = request_line.split_whitespace();
    let method = fields.next().unwrap_or_default();
    let target = fields.next().unwrap_or_default();
    if !method.eq_ignore_ascii_case("CONNECT") {
        stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
            .await?;
        return Ok(());
    }
    let target = Address::try_from(target).context("invalid HTTP CONNECT target")?;

    let session = client.create_stream().await?;
    if let Err(err) = session
        .write(&Vec::<u8>::from(target.clone()))
        .await
    {
        let _ = session.terminate().await;
        return Err(err.into());
    }
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let (mut local_read, mut local_write) = stream.into_split();
    let session_w = session.clone();
    let session_r = session.clone();
    let l2r = tokio::spawn(async move {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            match local_read.read(&mut buffer).await {
                Ok(0) => {
                    let _ = finish_logical_stream(&session_w).await;
                    break;
                }
                Ok(count) => {
                    if session_w
                        .write(&buffer[..count])
                        .await
                        .is_err()
                    {
                        let _ = session_w.terminate().await;
                        break;
                    }
                }
                Err(_) => {
                    let _ = session_w.terminate().await;
                    break;
                }
            }
        }
    });
    let r2l = tokio::spawn(async move {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            match session_r.read(&mut buffer).await {
                Ok(0) => break,
                Ok(count)
                    if local_write
                        .write_all(&buffer[..count])
                        .await
                        .is_err() =>
                {
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let _ = local_write.shutdown().await;
    });
    let _ = tokio::join!(l2r, r2l);
    Ok(())
}

async fn handle_tcp_connect(
    connect_req: connect::Connect<connect::NeedReply>,
    target: Address,
    client: &Client,
) -> Result<()> {
    let bind_addr = Address::from(connect_req.local_addr()?);

    // Open the anytls stream before reporting success to the SOCKS client.
    let session = match client.create_stream().await {
        Ok(s) => s,
        Err(err) => {
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
    if let Err(err) = session.write(&addr_bytes).await {
        let _ = session.terminate().await;
        if let Ok(mut failed) = connect_req
            .reply(Reply::GeneralFailure, Address::unspecified())
            .await
        {
            let _ = failed.shutdown().await;
        }
        return Err(err.into());
    }

    // The target address is queued; report success and let the stream watchdog
    // handle a missing v2 SYNACK.
    let ready = connect_req
        .reply(Reply::Succeeded, bind_addr)
        .await?;

    let (mut local_read, mut local_write) = ready.into_split();
    let session_w = session.clone();
    let session_r = session.clone();

    let l2r = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        let mut err = None;
        let mut local_eof = false;
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    local_eof = true;
                    break;
                }
                Ok(n) => {
                    if let Err(e) = session_w.write(&buf[..n]).await {
                        err = Some(e);
                        break;
                    }
                }
                Err(e) => {
                    if is_nonfatal_local_disconnect(&e) {
                        log::trace!("tcp tunnel local->proxy closed: {e}");
                        local_eof = true;
                    } else {
                        err = Some(e);
                    }
                    break;
                }
            }
        }
        if let Some(e) = err {
            let _ = session_w.terminate().await;
            log::debug!("tcp tunnel local->proxy error: {e}");
        } else if local_eof {
            let _ = finish_logical_stream(&session_w).await;
        }
    });

    let r2l = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match session_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if local_write
                        .write_all(&buf[..n])
                        .await
                        .is_err()
                    {
                        let _ = finish_logical_stream(&session_r).await;
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = local_write.shutdown().await;
    });

    let _ = tokio::join!(l2r, r2l);
    log::trace!("tcp tunnel to {target} closed");
    Ok(())
}

async fn finish_logical_stream(session: &Arc<AnytlsStream>) -> std::io::Result<()> {
    session.close().await
}

fn is_nonfatal_local_disconnect(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof
    )
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

    let session = match client.create_stream().await {
        Ok(s) => s,
        Err(err) => {
            let mut reply = associate_req
                .reply(Reply::GeneralFailure, Address::unspecified())
                .await?;
            reply.shutdown().await?;
            return Err(err.into());
        }
    };

    // Mark this stream as a UoT stream:
    //   sentinel address (SocksAddr) + UotRequest{Datagram, unspecified}
    if let Err(err) = setup_uot_request(&session).await {
        let _ = session.terminate().await;
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
    let session_writer = session.clone();
    let mut session_reader = AnytlsStreamReader::new(session.clone());

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
                session_writer.write(&frame).await?;
            }
            res = uot_get_packet_from_stream(UotMode::Datagram, &mut session_reader) => {
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

    if result.is_ok() {
        let _ = session.close().await;
    } else {
        let _ = session.terminate().await;
    }
    let _ = reply.shutdown().await;
    result
}

async fn setup_uot_request(session: &Arc<AnytlsStream>) -> Result<()> {
    let sentinel: Vec<u8> = uot_sentinel_destination().into();
    session.write(&sentinel).await?;
    let request_bytes: Vec<u8> = UotRequest::new(UotMode::Datagram, Address::unspecified()).into();
    session.write(&request_bytes).await?;
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
        .unwrap_or_else(|| "127.0.0.1:1080".parse().unwrap());
    let server_addr = client
        .server_addr
        .clone()
        .ok_or_else(|| anyhow!("client.serverAddr must be set in config"))?;
    let password = anytls
        .password
        .clone()
        .ok_or_else(|| anyhow!("anytls.password must be set in config"))?;
    if password.is_empty() {
        bail!("anytls.password must not be empty");
    }

    let client_id = anytls.client_id;

    let idle_check_secs = anytls.idle_check_secs.unwrap_or(30);
    let idle_timeout_secs = anytls.idle_timeout_secs.unwrap_or(30);
    // Keep the idle floor at zero by default so timed-out sessions are not
    // preserved indefinitely. Users can opt back in via config if they want
    // a warm pool.
    let min_idle_sessions = anytls.min_idle_sessions.unwrap_or(0);
    let max_streams_per_session = anytls
        .max_streams_per_session
        .unwrap_or(DEFAULT_MAX_STREAMS_PER_SESSION)
        .max(1);

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
    let client_hello_profile = match reality.client_hello_profile.as_deref() {
        None | Some("default") => ClientHelloProfile::Default,
        Some("chrome") => ClientHelloProfile::Chrome,
        Some("firefox") => ClientHelloProfile::Firefox,
        Some("safari") => ClientHelloProfile::Safari,
        Some(value) => bail!("unsupported reality.clientHelloProfile: {value}"),
    };

    Ok(RealityClientConfigResolved {
        listen,
        server_addr,
        probe_proxy: client.probe_proxy,
        password,
        client_id,
        idle_check_secs,
        idle_timeout_secs,
        min_idle_sessions,
        max_streams_per_session,
        short_id,
        public_key,
        version,
        server_name,
        client_hello_profile,
    })
}

fn build_client_config(args: &RealityClientConfigResolved) -> Result<ClientConfig> {
    let root_store = load_root_store();
    let mut config = provider::reality::build_reality_client_config_from_xray_fields(
        parse_reality_version(&args.version),
        &args.short_id,
        &args.public_key,
        root_store,
    )?;

    // REALITY carriers are short-lived and heavily concurrent here; disabling
    // TLS resumption avoids resumed handshakes tearing down some fresh
    // carriers under burst load.
    config.resumption = Resumption::disabled();
    config.client_hello_profile = args.client_hello_profile;

    Ok(config)
}

fn load_root_store() -> RootCertStore {
    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );
    root_store
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
        .as_chunks::<2>()
        .0
        .iter()
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

// === AsyncRead adapter for AnytlsSession (so UoT helpers can drive it) ===

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
                v.truncate(n);
                Ok::<(Vec<u8>, usize), std::io::Error>((v, n))
            }));
        }
    }
}
