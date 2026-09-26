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

use anyreality::{AnytlsStreamReader, async_bridge};

use anyhow::{Context, Result, anyhow, bail};
use anytls::{
    AsyncReadWrite, Client, DEFAULT_SCHEME, PaddingFactory, Stream as AnytlsStream, UotMode, UotRequest, uot_encode_packet,
    uot_get_packet_from_stream, uot_sentinel_destination,
};
use clap::Parser;
use core::net::SocketAddr;
use core::time::Duration;
use rustls::Connection;
use rustls::client::{ClientHelloProfile, Resumption};
use rustls_aws_lc_rs as provider;
use rustls_util::{StreamOwned, complete_io};
use sha2::{Digest, Sha256};
use socks5_impl::protocol::{Address, Reply};
use socks5_impl::server::auth::NoAuth;
use socks5_impl::server::connection::{ClientConnection as SocksClientConnection, IncomingConnection, associate, connect};
use socks5_impl::server::{AssociatedUdpSocket, UdpAssociate};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const MAX_UDP_RELAY_PACKET_SIZE: usize = 65_535;
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:1080";
const DEFAULT_IDLE_CHECK_SECS: u64 = 30;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MIN_IDLE_SESSIONS: usize = 5;
const DEFAULT_MAX_STREAMS_PER_SESSION: usize = 8;
const DEFAULT_CLIENT_HELLO_PROFILE: &str = "default";
const DEFAULT_HTTP_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_HTTP_HEADER_LIMIT: usize = 16 * 1024;
const DEFAULT_PADDING_LEN: usize = 0;

#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// Path to the grouped client config (`.toml` or `.json`).
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,

    /// Log filter (off/error/warn/info/debug/trace or env-style spec).
    #[arg(short, long, value_name = "LEVEL", default_value = DEFAULT_LOG_LEVEL)]
    log: log::LevelFilter,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientConfigFile {
    #[serde(default)]
    reality: Option<ClientRealityConfig>,
    #[serde(default)]
    anytls: Option<ClientAnytlsConfig>,
    #[serde(default)]
    client: Option<ClientRuntimeConfig>,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientRealityConfig {
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
struct ClientAnytlsConfig {
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
struct ClientRuntimeConfig {
    #[serde(default)]
    listen: Option<SocketAddr>,
    #[serde(default)]
    server_addr: Option<String>,
    #[serde(default)]
    probe_proxy: Option<SocketAddr>,
}

#[derive(Clone)]
struct DialCtx {
    server_addr: String,
    probe_proxy: Option<SocketAddr>,
    tls_config: Arc<rustls::ClientConfig>,
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
    let reality = resolved.reality.as_ref().expect("validated reality config");
    let anytls = resolved.anytls.as_ref().expect("validated anytls config");
    let client = resolved.client.as_ref().expect("validated client config");
    let tls_config = Arc::new(build_rustls_client_config(reality)?);
    let listen = client.listen.expect("validated client listen address");
    let server_addr = client.server_addr.clone().expect("validated client server address");
    let server_name = reality.server_name.clone().expect("validated reality server name");
    let padding = Arc::new(tokio::sync::RwLock::new(
        PaddingFactory::new(DEFAULT_SCHEME).expect("valid default padding scheme"),
    ));

    let password_sha256 = Sha256::digest(anytls.password.as_deref().expect("validated anytls password").as_bytes()).into();

    let dial_ctx = Arc::new(DialCtx {
        server_addr: server_addr.clone(),
        probe_proxy: client.probe_proxy,
        tls_config,
        server_name: server_name.clone(),
        password_sha256,
        client_id: anytls.client_id,
        padding: padding.clone(),
    });

    // anytls Client owns the session pool. On every `create_stream()` it
    // picks an idle session or invokes `dial_out` to build a new one.
    let dial_ctx_for_dial = dial_ctx.clone();
    let anytls_client = Client::new(
        Arc::new(move || {
            let ctx = dial_ctx_for_dial.clone();
            Box::pin(async move { dial_carrier(ctx).await })
        }),
        padding,
        Duration::from_secs(anytls.idle_timeout_secs.unwrap()),
        anytls.max_streams_per_session.unwrap(),
        Duration::ZERO,
    );

    log::info!(
        "REALITY+anytls client: mixed SOCKS5/HTTP {} -> {} (sni={})",
        listen,
        server_addr,
        server_name
    );

    let listener = TcpListener::bind(listen).await?;
    let auth = Arc::new(NoAuth);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let anytls_client = anytls_client.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            let result = match detect_local_proxy_protocol(&stream).await {
                Ok(None) => Ok(()),
                Ok(Some(LocalProxyProtocol::Socks5)) => handle_socks(IncomingConnection::new(stream, auth), anytls_client).await,
                Ok(Some(LocalProxyProtocol::Http)) => handle_http_connect(stream, anytls_client).await,
                Err(error) if is_peer_disconnect(&error) => {
                    log::debug!("Proxy peer {peer_addr} disconnected during protocol detection: {error}");
                    Ok(())
                }
                Err(error) => Err(error),
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
        let server_name =
            rustls::pki_types::ServerName::try_from(server_name).map_err(|err| std::io::Error::other(format!("invalid sni: {err}")))?;
        let mut conn = tls_config
            .connect(server_name)
            .build()
            .map_err(|err| std::io::Error::other(format!("rustls build: {err}")))?;
        let mut sock = std_tcp;
        while conn.is_handshaking() {
            complete_io(&mut sock, &mut conn).map_err(|err| std::io::Error::other(format!("reality handshake: {err}")))?;
        }
        Ok(StreamOwned::new(conn, sock))
    })
    .await
    .map_err(|err| std::io::Error::other(format!("join handshake task: {err}")))??;

    // 3) Bridge blocking TLS into an async duplex carrier.
    let mut bridge = async_bridge::into_async(tls).map_err(|err| std::io::Error::other(format!("async bridge: {err}")))?;

    // 4) Send anytls auth header:
    //    sha256(password) || u16be(padding_len) || padding_len zero bytes
    let padding_factory = ctx.padding.read().await;
    let padding_sizes = padding_factory.generate_record_payload_sizes(0);
    drop(padding_factory);
    let padding_len: u16 = padding_sizes
        .first()
        .copied()
        .map(|v| u16::try_from(v).unwrap_or(DEFAULT_PADDING_LEN as u16))
        .unwrap_or(DEFAULT_PADDING_LEN as u16);

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

async fn connect_via_probe_proxy(proxy_addr: SocketAddr, target: &str) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream.set_nodelay(true)?;

    let connect_request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: Keep-Alive\r\n\r\n");
    stream.write_all(connect_request.as_bytes()).await?;

    let mut reader = TokioBufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;
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
        SocksClientConnection::Connect(connect_req, target) => handle_tcp_connect(connect_req, target, &client).await,
        SocksClientConnection::UdpAssociate(associate_req, _) => handle_udp_associate(associate_req, &client).await,
        SocksClientConnection::Bind(_, _) => bail!("SOCKS BIND is not supported"),
    }
}

async fn handle_http_connect(mut tcp_stream: TcpStream, client: Arc<Client>) -> Result<()> {
    let mut request = Vec::new();
    let read_headers = async {
        loop {
            let mut byte = [0u8; 1];
            let count = tcp_stream.read(&mut byte).await?;
            if count == 0 {
                bail!("HTTP proxy client closed before sending headers");
            }
            request.push(byte[0]);
            if request.len() > DEFAULT_HTTP_HEADER_LIMIT {
                bail!("HTTP proxy request headers are too large");
            }
            if request.ends_with(b"\r\n\r\n") || request.ends_with(b"\n\n") {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::time::timeout(DEFAULT_HTTP_HEADER_TIMEOUT, read_headers)
        .await
        .with_context(|| http_header_timeout_context(&request))??;

    let text = std::str::from_utf8(&request).context("HTTP proxy request is not UTF-8")?;
    let request_line = text.lines().next().ok_or_else(|| anyhow!("HTTP proxy request is empty"))?;
    let mut fields = request_line.split_whitespace();
    let method = fields.next().unwrap_or_default();
    let target = fields.next().unwrap_or_default();
    if !method.eq_ignore_ascii_case("CONNECT") {
        tcp_stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
            .await?;
        return Ok(());
    }
    let target = Address::try_from(target).context("invalid HTTP CONNECT target")?;

    let mut remote = anytls::StreamIo::new(client.create_stream().await?);
    let stream = remote.stream();
    let session_id = stream.session_id().unwrap_or_default();
    let stream_id = stream.id();
    log::debug!(
        "session={session_id} stream={stream_id} stage=target_submit protocol=http-connect peer={:?} target={target}",
        tcp_stream.peer_addr()
    );
    remote.write_all(&Vec::<u8>::from(target.clone())).await?;
    if let Err(error) = tcp_stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await {
        return Err(error.into());
    }
    match anytls::relay::copy_bidirectional(&mut tcp_stream, &mut remote).await {
        Ok(_) => {}
        Err(error) if error.is_peer_disconnect() => {
            log::debug!("Proxy peer disconnected during HTTP CONNECT relay: {error}");
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

async fn handle_tcp_connect(connect_req: connect::Connect<connect::NeedReply>, target: Address, client: &Arc<Client>) -> Result<()> {
    let bind_addr = Address::from(connect_req.local_addr()?);

    // Open the anytls stream before reporting success to the SOCKS client.
    let stream = match client.create_stream().await {
        Ok(stream) => stream,
        Err(err) => {
            if let Ok(mut failed) = connect_req.reply(Reply::GeneralFailure, Address::unspecified()).await {
                let _ = failed.shutdown().await;
            }
            return Err(err.into());
        }
    };
    let mut remote = anytls::StreamIo::new(stream);
    let stream = remote.stream();
    let session_id = stream.session_id().unwrap_or_default();
    let stream_id = stream.id();

    // First user payload on this stream: target address in SOCKS5 SocksAddr
    // format. Becomes the data of the first cmdPSH frame.
    log::debug!("session={session_id} stream={stream_id} stage=target_submit protocol=socks5 target={target}",);
    let addr_bytes: Vec<u8> = target.clone().into();
    if let Err(err) = remote.write_all(&addr_bytes).await {
        if let Ok(mut failed) = connect_req.reply(Reply::GeneralFailure, Address::unspecified()).await {
            let _ = failed.shutdown().await;
        }
        return Err(err.into());
    }

    let mut ready = match connect_req.reply(Reply::Succeeded, bind_addr).await {
        Ok(ready) => ready,
        Err(error) => {
            return Err(error.into());
        }
    };
    match anytls::relay::copy_bidirectional(&mut ready, &mut remote).await {
        Ok(_) => {}
        Err(error) if error.is_peer_disconnect() => {
            log::debug!("Proxy peer disconnected during SOCKS5 relay to {target}: {error}");
        }
        Err(error) => return Err(error.into()),
    }
    log::trace!("tcp tunnel to {target} closed");
    Ok(())
}

fn is_peer_disconnect(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(anytls::relay::is_peer_disconnect)
    })
}

#[derive(Debug, PartialEq)]
enum LocalProxyProtocol {
    Socks5,
    Http,
}

async fn detect_local_proxy_protocol(stream: &TcpStream) -> Result<Option<LocalProxyProtocol>> {
    let mut first_byte = [0u8; 1];
    if stream.peek(&mut first_byte).await? == 0 {
        return Ok(None);
    }
    match first_byte[0] {
        0x05 => Ok(Some(LocalProxyProtocol::Socks5)),
        byte if byte.is_ascii_alphabetic() => Ok(Some(LocalProxyProtocol::Http)),
        0x04 => bail!("SOCKS4 is not supported; configure this application to use SOCKS5 or HTTP CONNECT"),
        0x16 => bail!("TLS handshake prefix on plaintext proxy port; use HTTP CONNECT or SOCKS5, not an HTTPS proxy"),
        byte => bail!("unsupported local proxy protocol (first_byte=0x{byte:02x}); expected SOCKS5 or HTTP CONNECT"),
    }
}

fn http_header_timeout_context(request: &[u8]) -> String {
    let prefix = if request.starts_with(b"\x16\x03") {
        "tls-handshake"
    } else if request.starts_with(b"CONNECT ") {
        "http-connect"
    } else if request.first().is_some_and(u8::is_ascii_alphabetic) {
        "ascii-method-or-other"
    } else if request.is_empty() {
        "empty"
    } else {
        "binary-or-other"
    };
    format!(
        "HTTP proxy header timeout (received_bytes={}, prefix={prefix}, request_line_complete={})",
        request.len(),
        request.contains(&b'\n')
    )
}

#[cfg(test)]
mod http_diagnostic_tests {
    use super::*;

    #[tokio::test]
    async fn local_protocol_detection_preserves_supported_prefixes_and_rejects_binary() {
        for (prefix, expected) in [
            (0x05, Some(LocalProxyProtocol::Socks5)),
            (b'C', Some(LocalProxyProtocol::Http)),
            (0x04, None),
            (0x16, None),
            (0x00, None),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut sender = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
            let (receiver, _) = listener.accept().await.unwrap();
            let mut payload = [0u8; 26];
            payload[0] = prefix;
            sender.write_all(&payload).await.unwrap();
            let result = tokio::time::timeout(Duration::from_secs(1), detect_local_proxy_protocol(&receiver))
                .await
                .expect("protocol detection must not wait for HTTP headers");
            if let Some(expected) = expected {
                assert_eq!(result.unwrap(), Some(expected));
                let mut byte = [0u8; 1];
                receiver.peek(&mut byte).await.unwrap();
                assert_eq!(byte[0], prefix);
            } else {
                let message = result.unwrap_err().to_string();
                assert!(!message.contains("header timeout"));
                match prefix {
                    0x04 => assert!(message.starts_with("SOCKS4 is not supported")),
                    0x16 => assert!(message.starts_with("TLS handshake prefix")),
                    _ => assert!(message.contains("first_byte=0x00")),
                }
            }
        }
    }

    #[test]
    fn header_timeout_diagnostics_do_not_expose_request_contents() {
        let request = b"CONNECT private.example:443 HTTP/1.1\r\nProxy-Authorization: secret";
        let message = http_header_timeout_context(request);
        assert!(message.contains(&format!("received_bytes={}", request.len())));
        assert!(message.contains("prefix=http-connect"));
        assert!(message.contains("request_line_complete=true"));
        assert!(!message.contains("private.example"));
        assert!(!message.contains("secret"));
        assert!(http_header_timeout_context(b"\x16\x03\x01").contains("prefix=tls-handshake"));
        assert!(http_header_timeout_context(b"GET ").contains("prefix=ascii-method-or-other"));
        assert!(http_header_timeout_context(b"\x04").contains("prefix=binary-or-other"));
        assert!(http_header_timeout_context(b"").contains("prefix=empty"));
        assert!(http_header_timeout_context(b"CONNECT ").contains("request_line_complete=false"));
    }
}

async fn handle_udp_associate(associate_req: UdpAssociate<associate::NeedReply>, client: &Arc<Client>) -> Result<()> {
    let listen_ip = associate_req.local_addr()?.ip();
    let udp = match UdpSocket::bind(SocketAddr::from((listen_ip, 0))).await {
        Ok(socket) => socket,
        Err(err) => {
            let mut reply = associate_req.reply(Reply::GeneralFailure, Address::unspecified()).await?;
            reply.shutdown().await?;
            return Err(err.into());
        }
    };
    let listen_addr = udp.local_addr()?;

    let stream = match client.create_stream().await {
        Ok(s) => Arc::new(s),
        Err(err) => {
            let mut reply = associate_req.reply(Reply::GeneralFailure, Address::unspecified()).await?;
            reply.shutdown().await?;
            return Err(err.into());
        }
    };
    let session_id = stream.session_id().unwrap_or_default();
    let stream_id = stream.id();

    // Mark this stream as a UoT stream:
    //   sentinel address (SocksAddr) + UotRequest{Datagram, unspecified}
    log::debug!("session={session_id} stream={stream_id} stage=target_submit protocol=uot",);
    if let Err(err) = setup_uot_request(&stream).await {
        let mut reply = associate_req.reply(Reply::GeneralFailure, Address::unspecified()).await?;
        reply.shutdown().await?;
        return Err(err);
    }
    let mut reply = associate_req.reply(Reply::Succeeded, Address::from(listen_addr)).await?;
    let listen_udp = Arc::new(AssociatedUdpSocket::from((udp, MAX_UDP_RELAY_PACKET_SIZE)));
    // Pin the UDP association to the first sender; ignore packets from other sources.
    let incoming_addr = Arc::new(tokio::sync::Mutex::new(Option::<SocketAddr>::None));
    let session_writer = stream.clone();
    let mut session_reader = AnytlsStreamReader::new(stream.clone());

    let result: Result<()> = {
        let upload = async {
            loop {
                let (pkt, frag, destination, src_addr) = listen_udp.recv_from().await?;
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
        };
        let download = async {
            loop {
                let (source, payload) = uot_get_packet_from_stream(UotMode::Datagram, &mut session_reader).await?;
                let Some(incoming) = *incoming_addr.lock().await else {
                    continue;
                };
                let source = source.ok_or_else(|| anyhow!("UoT datagram missing source"))?;
                listen_udp.send_to(&payload, 0, source, incoming).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        };
        tokio::select! {
            result = upload => result,
            result = download => result,
            res = reply.wait_until_closed() => {
                res.map_err(Into::into)
            }
        }
    };

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

fn resolve_client_config(config_path: &Path) -> Result<ClientConfigFile> {
    let mut file_config = load_client_config_file(config_path)?;
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

    client
        .server_addr
        .as_ref()
        .ok_or_else(|| anyhow!("client.serverAddr must be set in config"))?;
    let password = anytls
        .password
        .as_deref()
        .ok_or_else(|| anyhow!("anytls.password must be set in config"))?;
    if password.is_empty() {
        bail!("anytls.password must not be empty");
    }

    // Keep a small warm pool by default so the first proxied requests avoid
    // paying the full carrier setup cost.
    reality
        .short_id
        .as_ref()
        .ok_or_else(|| anyhow!("reality.shortId must be set in config"))?;
    reality
        .public_key
        .as_ref()
        .ok_or_else(|| anyhow!("reality.publicKey must be set in config"))?;
    reality
        .version
        .as_ref()
        .ok_or_else(|| anyhow!("reality.version must be set in config"))?;
    reality
        .server_name
        .as_ref()
        .ok_or_else(|| anyhow!("reality.serverName must be set in config"))?;
    match reality.client_hello_profile.as_deref() {
        None | Some(DEFAULT_CLIENT_HELLO_PROFILE) => ClientHelloProfile::Default,
        Some("chrome") => ClientHelloProfile::Chrome,
        Some("firefox") => ClientHelloProfile::Firefox,
        Some("safari") => ClientHelloProfile::Safari,
        Some(value) => bail!("unsupported reality.clientHelloProfile: {value}"),
    };

    if let Some(client) = file_config.client.as_mut() {
        client.listen.get_or_insert_with(|| DEFAULT_LISTEN_ADDR.parse().unwrap());
    }
    if let Some(anytls) = file_config.anytls.as_mut() {
        anytls.idle_check_secs.get_or_insert(DEFAULT_IDLE_CHECK_SECS);
        anytls.idle_timeout_secs.get_or_insert(DEFAULT_IDLE_TIMEOUT_SECS);
        anytls.min_idle_sessions.get_or_insert(DEFAULT_MIN_IDLE_SESSIONS);
        anytls.max_streams_per_session.get_or_insert(DEFAULT_MAX_STREAMS_PER_SESSION);
        if let Some(max_streams) = anytls.max_streams_per_session.as_mut() {
            *max_streams = (*max_streams).max(1);
        }
    }

    Ok(file_config)
}

fn build_rustls_client_config(args: &ClientRealityConfig) -> Result<rustls::ClientConfig> {
    let root_store = load_root_store();
    let mut config = provider::reality::build_reality_client_config_from_xray_fields(
        parse_reality_version(
            args.version
                .as_deref()
                .ok_or_else(|| anyhow!("reality.version must be set in config"))?,
        ),
        args.short_id
            .as_deref()
            .ok_or_else(|| anyhow!("reality.shortId must be set in config"))?,
        args.public_key
            .as_deref()
            .ok_or_else(|| anyhow!("reality.publicKey must be set in config"))?,
        root_store,
    )?;

    // REALITY carriers are short-lived and heavily concurrent here; disabling
    // TLS resumption avoids resumed handshakes tearing down some fresh
    // carriers under burst load.
    config.resumption = Resumption::disabled();
    config.client_hello_profile = match args.client_hello_profile.as_deref() {
        None | Some(DEFAULT_CLIENT_HELLO_PROFILE) => ClientHelloProfile::Default,
        Some("chrome") => ClientHelloProfile::Chrome,
        Some("firefox") => ClientHelloProfile::Firefox,
        Some("safari") => ClientHelloProfile::Safari,
        Some(value) => bail!("unsupported reality.clientHelloProfile: {value}"),
    };

    Ok(config)
}

fn load_root_store() -> rustls::RootCertStore {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    root_store
}

fn load_client_config_file(path: &Path) -> Result<ClientConfigFile> {
    let contents = std::fs::read_to_string(path)?;
    if let Ok(config) = serde_json::from_str(&contents) {
        return Ok(config);
    }
    if let Ok(config) = toml::from_str(&contents) {
        return Ok(config);
    }
    bail!("unsupported REALITY config format: {}", path.display());
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
