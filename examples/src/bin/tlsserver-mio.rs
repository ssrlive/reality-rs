//! This is an example server that uses rustls for TLS, and [mio] for I/O.
//!
//! It uses command line flags to demonstrate configuring a TLS server that may:
//!  * Specify supported TLS protocol versions
//!  * Customize cipher suite selection
//!  * Perform optional or mandatory client certificate authentication
//!  * Check client certificates for revocation status with CRLs
//!  * Support session tickets
//!  * Staple an OCSP response
//!  * Gate incoming TLS1.3 client hellos with REALITY verifier parameters
//!
//! See `--help` output for more details.
//!
//! You may set the `SSLKEYLOGFILE` env var when using this example to write a
//! log file with key material (insecure) for debugging purposes. See [`rustls::KeyLog`]
//! for more information.
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.
//!
//! [mio]: https://docs.rs/mio/latest/mio/

use core::hash::Hasher;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream as StdTcpStream;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fs, net};

#[path = "../common/reality_config.rs"]
mod reality_config;

use clap::{Parser, Subcommand};
use log::{debug, error};
use mio::net::{TcpListener, TcpStream};
use rustls::crypto::kx::NamedGroup;
use rustls::crypto::{CryptoProvider, Identity};
use rustls::enums::{ApplicationProtocol, ProtocolVersion};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::{
    Acceptor, ClientHelloVerifier, NoServerSessionStorage, RealityClientHello, WebPkiClientVerifier,
};
use rustls::{Connection, RootCertStore, ServerConfig, ServerConnection};
use rustls_aws_lc_rs as provider;
use rustls_util::KeyLogFile;

use reality_config::{RealityFallbackRuleConfig, RealityServerConfig, load_reality_document};

// Token for our listening socket.
const LISTENER: mio::Token = mio::Token(0);

// Which mode the server operates in.
#[derive(Clone, Debug, Subcommand)]
enum ServerMode {
    /// Write back received bytes
    Echo,

    /// Do one read, then write a bodged HTTP response and
    /// cleanly close the connection.
    Http,

    /// Forward traffic to/from given port on localhost.
    Forward { port: u16 },
}

/// This binds together a TCP listening socket, some outstanding
/// connections, and a TLS server configuration.
struct TlsServer {
    server: TcpListener,
    connections: HashMap<mio::Token, OpenConnection>,
    next_id: usize,
    tls_config: Arc<ServerConfig>,
    mode: ServerMode,
    reality_server_names: Vec<String>, // Added field for reality server names
    reality_fallback_target: Option<FallbackTarget>,
    reality_fallback_rules: Vec<FallbackRule>,
    reality_probe_matcher: Option<RealityProbeMatcher>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FallbackTarget {
    address: String,
    port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FallbackMatcher {
    server_names: Vec<String>,
    alpns: Vec<String>,
    named_groups: Vec<String>,
}

impl FallbackMatcher {
    fn is_empty(&self) -> bool {
        self.server_names.is_empty() && self.alpns.is_empty() && self.named_groups.is_empty()
    }

    fn matches(&self, input: &ClientHelloFallbackInput<'_>) -> bool {
        let server_name_matches = if self.server_names.is_empty() {
            true
        } else {
            input.server_name.is_some_and(|value| {
                self.server_names
                    .iter()
                    .any(|allowed| allowed == value)
            })
        };

        if !server_name_matches {
            return false;
        }

        let alpn_matches = if self.alpns.is_empty() {
            true
        } else {
            input.alpns.is_some_and(|offered| {
                self.alpns.iter().any(|allowed| {
                    offered
                        .iter()
                        .any(|proto| proto.as_slice() == allowed.as_bytes())
                })
            })
        };

        if !alpn_matches {
            return false;
        }

        if self.named_groups.is_empty() {
            true
        } else {
            input
                .named_groups
                .is_some_and(|offered| {
                    self.named_groups.iter().any(|allowed| {
                        offered
                            .iter()
                            .any(|group| format!("{:?}", group).eq_ignore_ascii_case(allowed))
                    })
                })
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FallbackRule {
    matcher: FallbackMatcher,
    target: FallbackTarget,
}

#[derive(Clone, Copy, Debug)]
struct ClientHelloFallbackInput<'a> {
    server_name: Option<&'a str>,
    alpns: Option<&'a [Vec<u8>]>,
    named_groups: Option<&'a [NamedGroup]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RealityProbeMatcher {
    version_prefix: [u8; 4],
    short_id_prefix: [u8; 8],
}

impl TlsServer {
    fn new(
        server: TcpListener,
        mode: ServerMode,
        cfg: Arc<ServerConfig>,
        reality_server_names: Vec<String>, // Added parameter for reality server names
        reality_fallback_target: Option<FallbackTarget>,
        reality_fallback_rules: Vec<FallbackRule>,
        reality_probe_matcher: Option<RealityProbeMatcher>,
    ) -> Self {
        Self {
            server,
            connections: HashMap::new(),
            next_id: 2,
            tls_config: cfg,
            mode,
            reality_server_names, // Initialize reality server names
            reality_fallback_target,
            reality_fallback_rules,
            reality_probe_matcher,
        }
    }

    fn accept(&mut self, registry: &mio::Registry) -> Result<(), io::Error> {
        loop {
            match self.server.accept() {
                Ok((socket, addr)) => {
                    debug!("Accepting new connection from {addr:?}");

                    let mode = self.mode.clone();

                    let token = mio::Token(self.next_id);
                    self.next_id += 1;

                    let mut connection = OpenConnection::new(
                        socket,
                        token,
                        mode,
                        self.tls_config.clone(),
                        self.reality_server_names.clone(), // Pass reality server names to connection
                        self.reality_fallback_target.clone(),
                        self.reality_fallback_rules.clone(),
                        self.reality_probe_matcher.clone(),
                    );
                    connection.register(registry);
                    self.connections
                        .insert(token, connection);
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => {
                    println!("encountered error while accepting connection; err={err:?}");
                    return Err(err);
                }
            }
        }
    }

    fn conn_event(&mut self, registry: &mio::Registry, event: &mio::event::Event) {
        let token = event.token();

        if self.connections.contains_key(&token) {
            self.connections
                .get_mut(&token)
                .unwrap()
                .ready(registry, event);

            if self.connections[&token].is_closed() {
                self.connections.remove(&token);
            }
        }
    }
}

enum ConnectionState {
    Accepting {
        acceptor: Acceptor,
        buffered: Vec<u8>,
    },
    Tls(ServerConnection),
    Passthrough,
}

/// This is a connection which has been accepted by the server,
/// and is currently being served.
///
/// It has a TCP-level stream, a TLS-level connection state, and some
/// other state/metadata.
struct OpenConnection {
    socket: TcpStream,
    token: mio::Token,
    closing: bool,
    closed: bool,
    mode: ServerMode,
    state: ConnectionState,
    tls_config: Arc<ServerConfig>,
    reality_fallback_target: Option<FallbackTarget>,
    reality_fallback_rules: Vec<FallbackRule>,
    reality_probe_matcher: Option<RealityProbeMatcher>,
    back: Option<TcpStream>,
    front_send_buf: Vec<u8>,
    back_send_buf: Vec<u8>,
    reality_server_names: Vec<String>, // Added field for reality server names
    sent_http_response: bool,
}

fn connect_local_backend(port: u16) -> io::Result<StdTcpStream> {
    let ipv6 = net::SocketAddr::V6(net::SocketAddrV6::new(net::Ipv6Addr::LOCALHOST, port, 0, 0));
    let ipv4 = net::SocketAddr::V4(net::SocketAddrV4::new(
        net::Ipv4Addr::new(127, 0, 0, 1),
        port,
    ));
    StdTcpStream::connect([ipv6, ipv4].as_slice())
}

fn connect_fallback_backend(target: &FallbackTarget) -> io::Result<StdTcpStream> {
    let addrs = (target.address.as_str(), target.port)
        .to_socket_addrs()?
        .collect::<Vec<_>>();

    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "could not resolve fallback target {}:{}",
                target.address, target.port
            ),
        ));
    }

    StdTcpStream::connect(addrs.as_slice())
}

fn open_back_port(port: u16) -> TcpStream {
    let stream = connect_local_backend(port).unwrap();
    stream.set_nonblocking(true).unwrap();
    TcpStream::from_std(stream)
}

/// Open a plaintext TCP-level connection for forwarded connections.
fn open_back(mode: &ServerMode) -> Option<TcpStream> {
    match *mode {
        ServerMode::Forward { port } => Some(open_back_port(port)),
        _ => None,
    }
}

/// This used to be conveniently exposed by mio: map EWOULDBLOCK
/// errors to something less-errory.
fn try_read(r: io::Result<usize>) -> io::Result<Option<usize>> {
    match r {
        Ok(len) => Ok(Some(len)),
        Err(e) => {
            if e.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

impl OpenConnection {
    fn new(
        socket: TcpStream,
        token: mio::Token,
        mode: ServerMode,
        tls_config: Arc<ServerConfig>,
        reality_server_names: Vec<String>, // Added parameter for reality server names
        reality_fallback_target: Option<FallbackTarget>,
        reality_fallback_rules: Vec<FallbackRule>,
        reality_probe_matcher: Option<RealityProbeMatcher>,
    ) -> Self {
        let state = if reality_fallback_target.is_some() {
            ConnectionState::Accepting {
                acceptor: Acceptor::default(),
                buffered: Vec::new(),
            }
        } else {
            ConnectionState::Tls(ServerConnection::new(tls_config.clone()).unwrap())
        };
        let back = if reality_fallback_target.is_some() {
            None
        } else {
            open_back(&mode)
        };
        Self {
            socket,
            token,
            closing: false,
            closed: false,
            mode,
            state,
            tls_config,
            reality_fallback_target,
            reality_fallback_rules,
            reality_probe_matcher,
            back,
            front_send_buf: Vec::new(),
            back_send_buf: Vec::new(),
            reality_server_names,
            sent_http_response: false,
        }
    }

    /// We're a connection, and we have something to do.
    fn ready(&mut self, registry: &mio::Registry, ev: &mio::event::Event) {
        // If we're readable: read some TLS.  Then
        // see if that yielded new plaintext.  Then
        // see if the backend is readable too.
        if ev.is_readable() {
            match self.state {
                ConnectionState::Accepting { .. } => self.do_accept_read(registry),
                ConnectionState::Tls(_) => {
                    self.do_tls_read();
                    self.try_plain_read();
                    self.try_back_read_tls();
                }
                ConnectionState::Passthrough => {
                    self.try_front_read_passthrough();
                    self.try_back_read_passthrough();
                }
            }
        }

        if ev.is_writable() {
            match self.state {
                ConnectionState::Tls(_) => self.do_tls_write_and_handle_error(),
                ConnectionState::Passthrough => self.flush_passthrough_writes(),
                ConnectionState::Accepting { .. } => {}
            }
        }

        if self.closing {
            let _ = self
                .socket
                .shutdown(net::Shutdown::Both);
            self.close_back();
            self.closed = true;
            self.deregister(registry);
        } else {
            self.reregister(registry);
        }
    }

    fn tls_conn(&self) -> Option<&ServerConnection> {
        match &self.state {
            ConnectionState::Tls(conn) => Some(conn),
            _ => None,
        }
    }

    fn tls_conn_mut(&mut self) -> Option<&mut ServerConnection> {
        match &mut self.state {
            ConnectionState::Tls(conn) => Some(conn),
            _ => None,
        }
    }

    /// Close the backend connection for forwarded sessions.
    fn close_back(&mut self) {
        if let Some(back) = self.back.take() {
            back.shutdown(net::Shutdown::Both)
                .unwrap();
        }
    }

    fn do_accept_read(&mut self, registry: &mio::Registry) {
        let mut buf = [0u8; 4096];

        loop {
            match self.socket.read(&mut buf) {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return,
                Err(err) => {
                    error!("acceptor read error {err:?}");
                    self.closing = true;
                    return;
                }
                Ok(0) => {
                    debug!("eof while reading client hello");
                    self.closing = true;
                    return;
                }
                Ok(len) => {
                    let mut incoming = &buf[..len];
                    if let ConnectionState::Accepting { acceptor, buffered } = &mut self.state {
                        buffered.extend_from_slice(&buf[..len]);
                        if let Err(err) = acceptor.read_tls(&mut incoming) {
                            error!("acceptor buffering error {err:?}");
                            self.closing = true;
                            return;
                        }
                    }

                    match self.try_finish_accept(registry) {
                        AcceptProgress::NeedMore => continue,
                        AcceptProgress::Ready
                        | AcceptProgress::Fallback
                        | AcceptProgress::Closed => {
                            return;
                        }
                    }
                }
            }
        }
    }

    fn try_finish_accept(&mut self, registry: &mio::Registry) -> AcceptProgress {
        let accept_result = match &mut self.state {
            ConnectionState::Accepting { acceptor, .. } => acceptor.accept(),
            _ => return AcceptProgress::Ready,
        };

        match accept_result {
            Ok(None) => AcceptProgress::NeedMore,
            Ok(Some(accepted)) => {
                if let Some(target) = self.fallback_target_for_client_hello(accepted.client_hello())
                {
                    debug!("routing client hello to REALITY fallback backend");
                    if let Some(buffered) = self.take_accept_buffer() {
                        match self.start_fallback(registry, buffered, target) {
                            Ok(()) => {
                                debug!("forwarding non-REALITY probe to fallback backend");
                                return AcceptProgress::Fallback;
                            }
                            Err(err) => {
                                error!("failed to connect/write REALITY fallback backend: {err:?}");
                            }
                        }
                    }

                    self.closing = true;
                    return AcceptProgress::Closed;
                }

                match self.start_tls_from_accept_buffer() {
                    Ok(()) => {
                        if self
                            .tls_conn()
                            .is_some_and(ServerConnection::wants_write)
                        {
                            self.do_tls_write_and_handle_error();
                        }
                        AcceptProgress::Ready
                    }
                    Err(err) => {
                        error!("cannot start TLS from accepted client hello: {err:?}");
                        self.closing = true;
                        AcceptProgress::Closed
                    }
                }
            }
            Err((err, mut alert)) => {
                error!("client hello parse failed: {err:?}");
                let _ = alert.write_all(&mut self.socket);
                self.closing = true;
                AcceptProgress::Closed
            }
        }
    }

    fn take_accept_buffer(&mut self) -> Option<Vec<u8>> {
        match &mut self.state {
            ConnectionState::Accepting { buffered, .. } => Some(core::mem::take(buffered)),
            _ => None,
        }
    }

    fn accept_buffer(&self) -> Option<&[u8]> {
        match &self.state {
            ConnectionState::Accepting { buffered, .. } => Some(buffered.as_slice()),
            _ => None,
        }
    }

    fn fallback_target_for_client_hello(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<FallbackTarget> {
        let alpn_protocols = client_hello.alpn().map(|protocols| {
            protocols
                .map(|proto| proto.to_vec())
                .collect::<Vec<_>>()
        });
        let offered_alpns = alpn_protocols
            .as_ref()
            .map(|protocols| display_alpns(protocols));
        let offered_named_groups = client_hello
            .named_groups()
            .map(display_named_groups);
        let matcher_input = ClientHelloFallbackInput {
            server_name: client_hello
                .server_name()
                .map(|name| name.as_ref()),
            alpns: alpn_protocols.as_deref(),
            named_groups: client_hello.named_groups(),
        };
        let selected_target = select_fallback_target(
            &matcher_input,
            &self.reality_fallback_rules,
            self.reality_fallback_target.clone(),
        );
        debug!(
            "fallback decision inputs: target={:?} allowlist={:?} sni={:?} alpn={:?} named_groups={:?} rules={:?}",
            selected_target,
            self.reality_server_names,
            client_hello
                .server_name()
                .map(|name| name.as_ref()),
            offered_alpns,
            offered_named_groups,
            self.reality_fallback_rules,
        );
        let selected_target = selected_target?;

        if self.reality_server_names.is_empty() {
            return None;
        }

        let Some(server_name) = client_hello
            .server_name()
            .map(|name| name.as_ref())
        else {
            return Some(selected_target);
        };

        if !self
            .reality_server_names
            .iter()
            .any(|allowed| allowed == server_name)
        {
            return Some(selected_target);
        }

        let matcher = self.reality_probe_matcher.as_ref()?;
        let Some(session_id) = self
            .accept_buffer()
            .and_then(client_hello_session_id)
        else {
            return Some(selected_target);
        };

        (!session_id_matches_reality(session_id, matcher)).then_some(selected_target)
    }

    fn start_tls_from_accept_buffer(&mut self) -> Result<(), rustls::Error> {
        let buffered = self
            .take_accept_buffer()
            .unwrap_or_default();
        let mut conn = ServerConnection::new(self.tls_config.clone())?;
        let mut incoming = buffered.as_slice();
        conn.read_tls(&mut incoming)
            .map_err(|err| rustls::Error::General(err.to_string()))?;
        conn.process_new_packets()?;
        self.state = ConnectionState::Tls(conn);
        Ok(())
    }

    fn start_fallback(
        &mut self,
        registry: &mio::Registry,
        buffered: Vec<u8>,
        target: FallbackTarget,
    ) -> io::Result<()> {
        let mut back = connect_fallback_backend(&target)?;
        back.write_all(&buffered)?;
        back.set_nonblocking(true)?;
        let mut back = TcpStream::from_std(back);
        registry
            .register(&mut back, self.token, mio::Interest::READABLE)
            .unwrap();
        self.back = Some(back);
        self.state = ConnectionState::Passthrough;
        Ok(())
    }

    fn do_tls_read(&mut self) {
        // Read some TLS data.
        let read_result = match &mut self.state {
            ConnectionState::Tls(conn) => conn.read_tls(&mut self.socket),
            _ => return,
        };

        match read_result {
            Err(err) => {
                if let io::ErrorKind::WouldBlock = err.kind() {
                    return;
                }

                error!("read error {err:?}");
                self.closing = true;
                return;
            }
            Ok(0) => {
                debug!("eof");
                self.closing = true;
                return;
            }
            Ok(_) => {}
        };

        // Process newly-received TLS messages.
        if let ConnectionState::Tls(conn) = &mut self.state {
            if let Err(err) = conn.process_new_packets() {
                error!("cannot process packet: {err:?}");

                // last gasp write to send any alerts
                self.do_tls_write_and_handle_error();

                self.closing = true;
            }
        }
    }

    fn try_plain_read(&mut self) {
        let Some(tls_conn) = self.tls_conn_mut() else {
            return;
        };

        // Read and process all available plaintext.
        if let Ok(io_state) = tls_conn.process_new_packets() {
            if let Some(mut early_data) = tls_conn.early_data() {
                let mut buf = Vec::new();
                early_data
                    .read_to_end(&mut buf)
                    .unwrap();

                if !buf.is_empty() {
                    debug!("early data read {:?}", buf.len());
                    self.incoming_plaintext(&buf);
                    return;
                }
            }

            if io_state.plaintext_bytes_to_read() > 0 {
                let mut buf = vec![0u8; io_state.plaintext_bytes_to_read()];

                tls_conn
                    .reader()
                    .read_exact(&mut buf)
                    .unwrap();

                debug!("plaintext read {:?}", buf.len());
                self.incoming_plaintext(&buf);
            }
        }
    }

    fn try_back_read_tls(&mut self) {
        if self.back.is_none() {
            return;
        }

        // Try a non-blocking read.
        let mut buf = [0u8; 1024];
        let back = self.back.as_mut().unwrap();
        let rc = try_read(back.read(&mut buf));

        if rc.is_err() {
            error!("backend read failed: {rc:?}");
            self.closing = true;
            return;
        }

        let maybe_len = rc.unwrap();

        // If we have a successful but empty read, that's an EOF.
        // Otherwise, we shove the data into the TLS session.
        match maybe_len {
            Some(0) => {
                debug!("back eof");
                self.closing = true;
            }
            Some(len) => {
                self.tls_conn_mut()
                    .unwrap()
                    .writer()
                    .write_all(&buf[..len])
                    .unwrap();
            }
            None => {}
        };
    }

    fn try_front_read_passthrough(&mut self) {
        let mut buf = [0u8; 1024];
        let rc = try_read(self.socket.read(&mut buf));
        if rc.is_err() {
            error!("front read failed: {rc:?}");
            self.closing = true;
            return;
        }

        match rc.unwrap() {
            Some(0) => {
                debug!("front eof");
                self.closing = true;
            }
            Some(len) => {
                self.back_send_buf
                    .extend_from_slice(&buf[..len]);
                if !self.flush_back_send_buf() {
                    self.closing = true;
                }
            }
            None => {}
        }
    }

    fn try_back_read_passthrough(&mut self) {
        if self.back.is_none() {
            return;
        }

        let mut buf = [0u8; 1024];
        let back = self.back.as_mut().unwrap();
        let rc = try_read(back.read(&mut buf));

        if rc.is_err() {
            error!("fallback backend read failed: {rc:?}");
            self.closing = true;
            return;
        }

        match rc.unwrap() {
            Some(0) => {
                debug!("fallback backend eof");
                self.closing = true;
            }
            Some(len) => {
                self.front_send_buf
                    .extend_from_slice(&buf[..len]);
                if !self.flush_front_send_buf() {
                    self.closing = true;
                }
            }
            None => {}
        }
    }

    fn flush_passthrough_writes(&mut self) {
        if !self.flush_front_send_buf() || !self.flush_back_send_buf() {
            self.closing = true;
        }
    }

    fn flush_front_send_buf(&mut self) -> bool {
        while !self.front_send_buf.is_empty() {
            match self.socket.write(&self.front_send_buf) {
                Ok(0) => {
                    debug!("front write eof");
                    return false;
                }
                Ok(len) => {
                    self.front_send_buf.drain(..len);
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return true,
                Err(err) => {
                    error!("front write failed: {err:?}");
                    return false;
                }
            }
        }

        true
    }

    fn flush_back_send_buf(&mut self) -> bool {
        let Some(back) = self.back.as_mut() else {
            return false;
        };

        while !self.back_send_buf.is_empty() {
            match back.write(&self.back_send_buf) {
                Ok(0) => {
                    debug!("fallback backend write eof");
                    return false;
                }
                Ok(len) => {
                    self.back_send_buf.drain(..len);
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return true,
                Err(err) => {
                    error!("fallback backend write failed: {err:?}");
                    return false;
                }
            }
        }

        true
    }

    /// Process some amount of received plaintext.
    fn incoming_plaintext(&mut self, buf: &[u8]) {
        match self.mode {
            ServerMode::Echo => {
                self.tls_conn_mut()
                    .unwrap()
                    .writer()
                    .write_all(buf)
                    .unwrap();
            }
            ServerMode::Http => {
                self.send_http_response_once();
            }
            ServerMode::Forward { .. } => {
                self.back
                    .as_mut()
                    .unwrap()
                    .write_all(buf)
                    .unwrap();
            }
        }
    }

    fn send_http_response_once(&mut self) {
        let response =
            b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello world from rustls tlsserver\r\n";
        if !self.sent_http_response {
            self.tls_conn_mut()
                .unwrap()
                .writer()
                .write_all(response)
                .unwrap();
            self.sent_http_response = true;
            self.tls_conn_mut()
                .unwrap()
                .send_close_notify();
        }
    }

    fn tls_write(&mut self) -> io::Result<usize> {
        match &mut self.state {
            ConnectionState::Tls(conn) => conn.write_tls(&mut self.socket),
            _ => Ok(0),
        }
    }

    fn do_tls_write_and_handle_error(&mut self) {
        let rc = self.tls_write();
        if rc.is_err() {
            error!("write failed {rc:?}");
            self.closing = true;
        }
    }

    fn register(&mut self, registry: &mio::Registry) {
        let event_set = self.front_event_set();
        let back_event_set = self.back_event_set();
        registry
            .register(&mut self.socket, self.token, event_set)
            .unwrap();

        if let Some(back) = &mut self.back {
            registry
                .register(back, self.token, back_event_set)
                .unwrap();
        }
    }

    fn reregister(&mut self, registry: &mio::Registry) {
        let event_set = self.front_event_set();
        let back_event_set = self.back_event_set();
        registry
            .reregister(&mut self.socket, self.token, event_set)
            .unwrap();

        if let Some(back) = self.back.as_mut() {
            registry
                .reregister(back, self.token, back_event_set)
                .unwrap();
        }
    }

    fn deregister(&mut self, registry: &mio::Registry) {
        registry
            .deregister(&mut self.socket)
            .unwrap();

        if let Some(back) = self.back.as_mut() {
            registry.deregister(back).unwrap();
        }
    }

    /// What IO events we're currently waiting for,
    /// based on wants_read/wants_write.
    fn front_event_set(&self) -> mio::Interest {
        if matches!(self.state, ConnectionState::Passthrough) {
            return if self.front_send_buf.is_empty() {
                mio::Interest::READABLE
            } else {
                mio::Interest::READABLE | mio::Interest::WRITABLE
            };
        }

        let Some(tls_conn) = self.tls_conn() else {
            return mio::Interest::READABLE;
        };

        let rd = tls_conn.wants_read();
        let wr = tls_conn.wants_write();

        if rd && wr {
            mio::Interest::READABLE | mio::Interest::WRITABLE
        } else if wr {
            mio::Interest::WRITABLE
        } else {
            mio::Interest::READABLE
        }
    }

    fn back_event_set(&self) -> mio::Interest {
        if self.back_send_buf.is_empty() {
            mio::Interest::READABLE
        } else {
            mio::Interest::READABLE | mio::Interest::WRITABLE
        }
    }

    fn is_closed(&self) -> bool {
        self.closed
    }
}

/// Runs a TLS server on :PORT. The default PORT is 443.
///
/// `echo` mode means the server echoes received data on each connection.
///
/// `http` mode means the server blindly sends a HTTP response on each connection.
///
/// `forward` means the server forwards plaintext to a connection made to `localhost:fport`.
///
/// `--certs` names the full certificate chain, `--key` provides the private key.
#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    mode: ServerMode,
    /// Listen on port.
    #[clap(short, long, default_value = "443")]
    port: u16,
    /// Emit log output.
    #[clap(short, long)]
    verbose: bool,
    /// Disable default TLS version list, and use the given versions instead.
    #[clap(long)]
    protover: Vec<String>,
    /// Disable default cipher suite list, and use the given suites instead.
    #[clap(long)]
    suite: Vec<String>,
    /// Negotiate the given protocols using ALPN.
    #[clap(long)]
    proto: Vec<Vec<u8>>,
    /// Read server certificates from the given file. This should contain PEM-format certificates
    /// in the right order (the first certificate should certify the end entity, matching the
    /// private key, the last should be a root CA).
    #[clap(long)]
    certs: PathBuf,
    /// Perform client certificate revocation checking using the DER-encoded CRLs from the given
    /// files.
    #[clap(long)]
    crl: Vec<PathBuf>,
    /// Read private key from the given file. This should be a private key in PEM format.
    #[clap(long)]
    key: PathBuf,
    /// Read DER-encoded OCSP response from the given file and staple to certificate.
    #[clap(long)]
    ocsp: Option<PathBuf>,
    /// Enable client authentication, and accept certificates signed by those roots provided in
    /// the given file.
    #[clap(long)]
    auth: Option<PathBuf>,
    /// Send a fatal alert if the client does not complete client authentication.
    #[clap(long)]
    require_auth: bool,
    /// Disable stateful session resumption.
    #[clap(long)]
    no_resumption: bool,
    /// Support tickets (stateless resumption).
    #[clap(long)]
    tickets: bool,
    /// Support receiving this many bytes with 0-RTT.
    #[clap(long, default_value = "0")]
    max_early_data: u32,
    /// Load REALITY fields from a JSON or TOML file.
    #[clap(long)]
    reality_config: Option<PathBuf>,
    /// Enable REALITY using this Xray-style short_id hex value.
    #[clap(long, requires_all = ["reality_private_key", "reality_version"])]
    reality_short_id: Option<String>,
    /// Enable REALITY using this Xray-style private_key base64/base64url value.
    #[clap(long, requires_all = ["reality_short_id", "reality_version"])]
    reality_private_key: Option<String>,
    /// REALITY version encoded as 6 hex digits, for example 010203.
    #[clap(long, requires_all = ["reality_short_id", "reality_private_key"])]
    reality_version: Option<String>,
    /// Accept this SNI for REALITY handshakes. May be repeated.
    #[clap(long = "reality-server-name")]
    reality_server_name: Vec<String>,
    /// Forward rejected REALITY handshakes as raw TCP to ADDRESS:PORT.
    #[clap(long)]
    reality_fallback_address: Option<String>,
    /// Forward rejected REALITY handshakes as raw TCP to ADDRESS:PORT.
    #[clap(long)]
    reality_fallback_port: Option<u16>,
}

impl Args {
    fn validate(&self, reality: Option<&RealityServerConfig>) -> Result<(), String> {
        let fallback_target = effective_reality_fallback_target(self, reality);

        if reality.is_none() {
            if fallback_target.is_some() || self.reality_fallback_address.is_some() {
                return Err("REALITY fallback requires REALITY mode".into());
            }
            return Ok(());
        }

        if fallback_target.is_none()
            && (self.reality_fallback_address.is_some()
                || reality
                    .and_then(|config| config.fallback_address.as_ref())
                    .is_some())
        {
            return Err("REALITY fallback address requires a fallback port".into());
        }

        if fallback_target.is_some() && matches!(self.mode, ServerMode::Forward { .. }) {
            return Err("REALITY fallback is not supported with forward mode".into());
        }

        if matches!(fallback_target, Some(FallbackTarget { port: 0, .. })) {
            return Err("REALITY fallback port must be non-zero".into());
        }

        validate_reality_fallback_rules(reality)?;

        let versions = lookup_versions(&self.protover);
        if !versions.is_empty() && versions.as_slice() != [ProtocolVersion::TLSv1_3] {
            return Err("REALITY mode requires TLS1.3".into());
        }

        Ok(())
    }

    fn provider(
        &self,
        reality: Option<&RealityServerConfig>,
    ) -> (Vec<ProtocolVersion>, CryptoProvider) {
        let (versions, provider) = if reality.is_some() {
            (
                vec![ProtocolVersion::TLSv1_3],
                provider::reality::default_x25519_tls13_reality_provider(),
            )
        } else {
            match lookup_versions(&self.protover).as_slice() {
                versions @ [ProtocolVersion::TLSv1_2] => {
                    (versions.to_vec(), provider::DEFAULT_TLS12_PROVIDER)
                }
                versions @ [ProtocolVersion::TLSv1_3] => {
                    (versions.to_vec(), provider::DEFAULT_TLS13_PROVIDER)
                }
                _ => (
                    vec![ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3],
                    provider::DEFAULT_PROVIDER,
                ),
            }
        };

        let provider = match self.suite.as_slice() {
            [] => provider,
            _ => filter_suites(provider, &self.suite),
        };

        (versions, provider)
    }
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
    ) -> Result<(), rustls::Error> {
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

/// Alter `provider` to reduce the set of ciphersuites to just `suites`
fn filter_suites(mut provider: CryptoProvider, suites: &[String]) -> CryptoProvider {
    // first, check `suites` all name known suites, and will have some effect
    let known_suites = provider
        .tls12_cipher_suites
        .iter()
        .map(|cs| cs.common.suite)
        .chain(
            provider
                .tls13_cipher_suites
                .iter()
                .map(|cs| cs.common.suite),
        )
        .map(|cs| format!("{:?}", cs).to_lowercase())
        .collect::<Vec<String>>();

    for s in suites {
        if !known_suites.contains(&s.to_lowercase()) {
            panic!(
                "unsupported ciphersuite '{s}'; should be one of {known_suites}",
                known_suites = known_suites.join(", ")
            );
        }
    }

    // now discard non-named suites
    provider
        .tls12_cipher_suites
        .to_mut()
        .retain(|cs| {
            let name = format!("{:?}", cs.common.suite).to_lowercase();
            suites
                .iter()
                .any(|s| s.to_lowercase() == name)
        });
    provider
        .tls13_cipher_suites
        .to_mut()
        .retain(|cs| {
            let name = format!("{:?}", cs.common.suite).to_lowercase();
            suites
                .iter()
                .any(|s| s.to_lowercase() == name)
        });

    provider
}

/// Make a vector of protocol versions named in `versions`
fn lookup_versions(versions: &[String]) -> Vec<ProtocolVersion> {
    let mut out = Vec::new();

    for vname in versions {
        let version = match vname.as_ref() {
            "1.2" => ProtocolVersion::TLSv1_2,
            "1.3" => ProtocolVersion::TLSv1_3,
            _ => panic!("cannot look up version '{vname}', valid are '1.2' and '1.3'"),
        };
        if !out.contains(&version) {
            out.push(version);
        }
    }

    out
}

fn load_certs(filename: &Path) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_file_iter(filename)
        .expect("cannot open certificate file")
        .map(|result| result.unwrap())
        .collect()
}

fn load_private_key(filename: &Path) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_file(filename).expect("cannot read private key file")
}

fn load_ocsp(filename: Option<&Path>) -> Vec<u8> {
    let mut ret = Vec::new();

    if let Some(name) = filename {
        fs::File::open(name)
            .expect("cannot open ocsp file")
            .read_to_end(&mut ret)
            .unwrap();
    }

    ret
}

fn load_crls(
    filenames: impl Iterator<Item = impl AsRef<Path>>,
) -> Vec<CertificateRevocationListDer<'static>> {
    filenames
        .map(|filename| {
            CertificateRevocationListDer::from_pem_file(filename).expect("cannot read CRL file")
        })
        .collect()
}

fn resolve_reality_config(
    args: &Args,
) -> Result<Option<RealityServerConfig>, Box<dyn core::error::Error>> {
    let file_config = if let Some(path) = args.reality_config.as_deref() {
        Some(load_reality_document::<RealityServerConfig>(path)?.reality)
    } else {
        None
    };

    let short_id = args
        .reality_short_id
        .clone()
        .or_else(|| {
            file_config
                .as_ref()
                .map(|config| config.short_id.clone())
        });
    let private_key = args
        .reality_private_key
        .clone()
        .or_else(|| {
            file_config
                .as_ref()
                .map(|config| config.private_key.clone())
        });
    let version = args
        .reality_version
        .clone()
        .or_else(|| {
            file_config
                .as_ref()
                .map(|config| config.version.clone())
        });
    let server_names = if args.reality_server_name.is_empty() {
        file_config
            .as_ref()
            .map(|config| config.server_names.clone())
            .unwrap_or_default()
    } else {
        args.reality_server_name.clone()
    };
    let fallback_address = args
        .reality_fallback_address
        .clone()
        .or_else(|| {
            file_config
                .as_ref()
                .and_then(|config| config.fallback_address.clone())
        });
    let fallback_port = args.reality_fallback_port.or_else(|| {
        file_config
            .as_ref()
            .and_then(|config| config.fallback_port)
    });

    match (short_id, private_key, version) {
        (None, None, None) => Ok(None),
        (Some(short_id), Some(private_key), Some(version)) => Ok(Some(RealityServerConfig {
            short_id,
            private_key,
            version,
            server_names,
            fallback_address,
            fallback_port,
            fallback_rules: file_config
                .as_ref()
                .map(|config| config.fallback_rules.clone())
                .unwrap_or_default(),
        })),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "REALITY requires short_id, private_key, and version via CLI flags or --reality-config",
        )
        .into()),
    }
}

fn effective_reality_fallback_target(
    args: &Args,
    reality: Option<&RealityServerConfig>,
) -> Option<FallbackTarget> {
    let port = args
        .reality_fallback_port
        .or_else(|| reality.and_then(|config| config.fallback_port))?;
    let address = args
        .reality_fallback_address
        .clone()
        .or_else(|| reality.and_then(|config| config.fallback_address.clone()))
        .unwrap_or_else(|| "localhost".to_string());

    Some(FallbackTarget { address, port })
}

fn effective_reality_fallback_rules(reality: Option<&RealityServerConfig>) -> Vec<FallbackRule> {
    reality
        .map(|config| {
            config
                .fallback_rules
                .iter()
                .map(fallback_rule_from_config)
                .collect()
        })
        .unwrap_or_default()
}

fn validate_reality_fallback_rules(reality: Option<&RealityServerConfig>) -> Result<(), String> {
    let Some(reality) = reality else {
        return Ok(());
    };

    for (index, rule) in reality
        .fallback_rules
        .iter()
        .enumerate()
    {
        let matcher = FallbackMatcher {
            server_names: rule.server_names.clone(),
            alpns: rule.alpns.clone(),
            named_groups: rule.named_groups.clone(),
        };

        if matcher.is_empty() {
            return Err(format!(
                "REALITY fallback rule #{index} requires at least one server_name, alpn, or named_group match"
            ));
        }

        if rule.fallback_port == 0 {
            return Err(format!(
                "REALITY fallback rule #{index} requires a non-zero fallback port"
            ));
        }
    }

    Ok(())
}

fn display_alpns(alpns: &[Vec<u8>]) -> Vec<String> {
    alpns
        .iter()
        .map(|proto| String::from_utf8_lossy(proto).into_owned())
        .collect()
}

fn display_named_groups(named_groups: &[NamedGroup]) -> Vec<String> {
    named_groups
        .iter()
        .map(|group| format!("{:?}", group).to_lowercase())
        .collect()
}

fn fallback_rule_from_config(rule: &RealityFallbackRuleConfig) -> FallbackRule {
    FallbackRule {
        matcher: FallbackMatcher {
            server_names: rule.server_names.clone(),
            alpns: rule.alpns.clone(),
            named_groups: rule.named_groups.clone(),
        },
        target: FallbackTarget {
            address: rule.fallback_address.clone(),
            port: rule.fallback_port,
        },
    }
}

fn select_fallback_target(
    input: &ClientHelloFallbackInput<'_>,
    rules: &[FallbackRule],
    default_target: Option<FallbackTarget>,
) -> Option<FallbackTarget> {
    for rule in rules {
        if rule.matcher.matches(input) {
            return Some(rule.target.clone());
        }
    }

    default_target
}

fn effective_reality_probe_matcher(
    reality: Option<&RealityServerConfig>,
) -> Option<RealityProbeMatcher> {
    let reality = reality?;
    Some(RealityProbeMatcher {
        version_prefix: reality_version_prefix(&reality.version)?,
        short_id_prefix: parse_reality_short_id_prefix(&reality.short_id)?,
    })
}

fn reality_version_prefix(version: &str) -> Option<[u8; 4]> {
    let parsed = parse_reality_version_checked(version)?;
    Some([parsed[0], parsed[1], parsed[2], 0])
}

fn parse_reality_short_id_prefix(short_id: &str) -> Option<[u8; 8]> {
    let short_id = short_id.trim();
    if short_id.len() > 16 || !short_id.len().is_multiple_of(2) {
        return None;
    }

    let mut parsed = [0u8; 8];
    for (index, chunk) in short_id
        .as_bytes()
        .chunks_exact(2)
        .enumerate()
    {
        parsed[index] = parse_hex_byte_checked(chunk[0], chunk[1])?;
    }

    Some(parsed)
}

fn client_hello_session_id(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 5 || buf[0] != 22 {
        return None;
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record = buf.get(5..5 + record_len)?;
    if record.len() < 4 || record[0] != 1 {
        return None;
    }

    let hello_len = ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | record[3] as usize;
    let hello = record.get(4..4 + hello_len)?;
    let session_id_len = *hello.get(34)? as usize;
    hello.get(35..35 + session_id_len)
}

fn session_id_matches_reality(session_id: &[u8], matcher: &RealityProbeMatcher) -> bool {
    session_id.len() == 32
        && session_id[..4] == matcher.version_prefix
        && session_id[8..16] == matcher.short_id_prefix
}

fn make_config(args: &Args, reality: Option<&RealityServerConfig>) -> Arc<ServerConfig> {
    let (versions, provider) = args.provider(reality);
    let client_auth = if let Some(auth) = &args.auth {
        let roots = load_certs(auth);
        let mut client_auth_roots = RootCertStore::empty();
        for root in roots {
            client_auth_roots.add(root).unwrap();
        }
        let crls = load_crls(args.crl.iter());
        if args.require_auth {
            Arc::new(
                WebPkiClientVerifier::builder(client_auth_roots.into(), &provider)
                    .with_crls(crls)
                    .build()
                    .unwrap(),
            )
        } else {
            Arc::new(
                WebPkiClientVerifier::builder(client_auth_roots.into(), &provider)
                    .with_crls(crls)
                    .allow_unauthenticated()
                    .build()
                    .unwrap(),
            )
        }
    } else {
        WebPkiClientVerifier::no_client_auth()
    };

    let certs = load_certs(&args.certs);
    let privkey = load_private_key(&args.key);
    let ocsp = load_ocsp(args.ocsp.as_deref());

    let mut config = ServerConfig::builder(provider.into())
        .with_client_cert_verifier(client_auth)
        .with_single_cert_with_ocsp(
            Arc::new(Identity::from_cert_chain(certs).unwrap()),
            privkey,
            Arc::from(ocsp),
        )
        .expect("bad certificates/private key");

    config.key_log = Arc::new(KeyLogFile::new());

    if args.no_resumption {
        config.session_storage = Arc::new(NoServerSessionStorage {});
    }

    if args.tickets {
        config.ticketer = Some(
            provider::DEFAULT_PROVIDER
                .ticketer_factory
                .ticketer()
                .unwrap(),
        );
    }

    if args.max_early_data > 0 {
        if !versions.contains(&ProtocolVersion::TLSv1_3) {
            panic!("Early data is only available for servers supporting TLS1.3");
        }
        if args.no_resumption {
            panic!("Early data requires resumption.");
        }
        if args.tickets {
            panic!("Early data is not supported for stateless resumption (--tickets).");
        }
        config.max_early_data_size = args.max_early_data;
    }

    config.alpn_protocols = args
        .proto
        .iter()
        .map(|bytes| ApplicationProtocol::from(bytes.as_slice()).to_owned())
        .collect();

    if let Some(reality) = reality {
        let inner = provider::reality::RealityServerVerifierConfig::from_xray_fields(
            parse_reality_version(&reality.version),
            &reality.short_id,
            &reality.private_key,
        )
        .and_then(|config| config.build_verifier())
        .expect("bad REALITY verifier parameters");
        config
            .dangerous()
            .set_reality_client_hello_verifier(Some(Arc::new(ExampleRealityVerifier {
                inner,
                server_names: reality.server_names.clone(),
            })));
    }

    Arc::new(config)
}

fn parse_reality_version(version: &str) -> [u8; 3] {
    parse_reality_version_checked(version)
        .expect("REALITY version must be exactly 6 hex digits, for example 010203")
}

fn parse_reality_version_checked(version: &str) -> Option<[u8; 3]> {
    let version = version.trim();
    if version.len() != 6 {
        return None;
    }

    let mut parsed = [0u8; 3];
    for (index, chunk) in version
        .as_bytes()
        .chunks_exact(2)
        .enumerate()
    {
        parsed[index] = parse_hex_byte_checked(chunk[0], chunk[1])?;
    }
    Some(parsed)
}

fn parse_hex_byte_checked(high: u8, low: u8) -> Option<u8> {
    Some((parse_hex_nibble_checked(high)? << 4) | parse_hex_nibble_checked(low)?)
}

fn parse_hex_nibble_checked(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn main() {
    let args = Args::parse();
    let reality = resolve_reality_config(&args).unwrap();
    args.validate(reality.as_ref()).unwrap();
    if args.verbose {
        env_logger::Builder::new()
            .parse_filters("trace")
            .init();
    }

    if !args.crl.is_empty() && args.auth.is_none() {
        println!("--crl can only be provided with --auth enabled");
        return;
    }

    let mut addr: net::SocketAddr = "[::]:443".parse().unwrap();
    addr.set_port(args.port);

    let config = make_config(&args, reality.as_ref());

    let mut listener = TcpListener::bind(addr).expect("cannot listen on port");
    println!("listening on {addr}");
    let mut poll = mio::Poll::new().unwrap();
    poll.registry()
        .register(&mut listener, LISTENER, mio::Interest::READABLE)
        .unwrap();
    let fallback_target = effective_reality_fallback_target(&args, reality.as_ref());
    let fallback_rules = effective_reality_fallback_rules(reality.as_ref());
    let reality_probe_matcher = effective_reality_probe_matcher(reality.as_ref());

    let mut tlsserv = TlsServer::new(
        listener,
        args.mode,
        config,
        reality
            .as_ref()
            .map(|config| config.server_names.clone())
            .unwrap_or_default(),
        fallback_target,
        fallback_rules,
        reality_probe_matcher,
    );

    let mut events = mio::Events::with_capacity(256);
    loop {
        match poll.poll(&mut events, None) {
            Ok(_) => {}
            // Polling can be interrupted (e.g. by a debugger) - retry if so.
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                panic!("poll failed: {e:?}")
            }
        }

        for event in events.iter() {
            match event.token() {
                LISTENER => {
                    tlsserv
                        .accept(poll.registry())
                        .expect("error accepting socket");
                }
                _ => tlsserv.conn_event(poll.registry(), event),
            }
        }
    }
}

enum AcceptProgress {
    NeedMore,
    Ready,
    Fallback,
    Closed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args(mode: ServerMode) -> Args {
        Args {
            mode,
            port: 443,
            verbose: false,
            protover: vec!["1.3".to_string()],
            suite: vec![],
            proto: vec![],
            certs: PathBuf::from("cert.pem"),
            crl: vec![],
            key: PathBuf::from("key.pem"),
            ocsp: None,
            auth: None,
            require_auth: false,
            no_resumption: false,
            tickets: false,
            max_early_data: 0,
            reality_config: None,
            reality_short_id: None,
            reality_private_key: None,
            reality_version: None,
            reality_server_name: vec![],
            reality_fallback_address: None,
            reality_fallback_port: None,
        }
    }

    fn test_cert_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("bogo")
            .join("keys")
            .join(name)
    }

    fn test_config_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("config")
            .join(name)
    }

    #[test]
    fn parse_reality_version_hex() {
        assert_eq!(parse_reality_version("010203"), [1, 2, 3]);
        assert_eq!(parse_reality_version("a0B1c2"), [0xa0, 0xb1, 0xc2]);
    }

    #[test]
    fn client_hello_session_id_extracts_session_id() {
        let session_id = [0x5a; 32];
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(session_id.len() as u8);
        body.extend_from_slice(&session_id);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x00]);

        let mut handshake = vec![1u8, 0, 0, body.len() as u8];
        handshake.extend_from_slice(&body);
        let mut record = vec![22u8, 0x03, 0x01, 0, handshake.len() as u8];
        record.extend_from_slice(&handshake);

        assert_eq!(
            client_hello_session_id(&record),
            Some(session_id.as_slice())
        );
    }

    #[test]
    fn session_id_matches_reality_checks_version_and_short_id_prefix() {
        let matcher = RealityProbeMatcher {
            version_prefix: [1, 2, 3, 0],
            short_id_prefix: [0xaa, 0xbb, 0xcc, 0, 0, 0, 0, 0],
        };
        let mut session_id = [0u8; 32];
        session_id[..4].copy_from_slice(&matcher.version_prefix);
        session_id[8..16].copy_from_slice(&matcher.short_id_prefix);

        assert!(session_id_matches_reality(&session_id, &matcher));

        session_id[8] = 0;
        assert!(!session_id_matches_reality(&session_id, &matcher));
    }

    #[test]
    fn select_fallback_target_prefers_matching_rule() {
        let rules = vec![FallbackRule {
            matcher: FallbackMatcher {
                server_names: vec!["decoy.example".to_string()],
                alpns: vec![],
                named_groups: vec![],
            },
            target: FallbackTarget {
                address: "127.0.0.1".to_string(),
                port: 9555,
            },
        }];

        assert_eq!(
            select_fallback_target(
                &ClientHelloFallbackInput {
                    server_name: Some("decoy.example"),
                    alpns: None,
                    named_groups: None,
                },
                &rules,
                Some(FallbackTarget {
                    address: "::1".to_string(),
                    port: 9446,
                })
            ),
            Some(FallbackTarget {
                address: "127.0.0.1".to_string(),
                port: 9555,
            })
        );
    }

    #[test]
    fn select_fallback_target_uses_default_when_no_rule_matches() {
        let rules = vec![FallbackRule {
            matcher: FallbackMatcher {
                server_names: vec!["decoy.example".to_string()],
                alpns: vec![],
                named_groups: vec![],
            },
            target: FallbackTarget {
                address: "127.0.0.1".to_string(),
                port: 9555,
            },
        }];

        assert_eq!(
            select_fallback_target(
                &ClientHelloFallbackInput {
                    server_name: Some("other.example"),
                    alpns: None,
                    named_groups: None,
                },
                &rules,
                Some(FallbackTarget {
                    address: "::1".to_string(),
                    port: 9446,
                })
            ),
            Some(FallbackTarget {
                address: "::1".to_string(),
                port: 9446,
            })
        );
    }

    #[test]
    fn select_fallback_target_requires_matching_alpn_when_configured() {
        let rules = vec![FallbackRule {
            matcher: FallbackMatcher {
                server_names: vec!["decoy.example".to_string()],
                alpns: vec!["http/1.1".to_string()],
                named_groups: vec![],
            },
            target: FallbackTarget {
                address: "::1".to_string(),
                port: 9447,
            },
        }];

        assert_eq!(
            select_fallback_target(
                &ClientHelloFallbackInput {
                    server_name: Some("decoy.example"),
                    alpns: Some(&[b"http/1.1".to_vec()]),
                    named_groups: None,
                },
                &rules,
                Some(FallbackTarget {
                    address: "::1".to_string(),
                    port: 9446,
                })
            ),
            Some(FallbackTarget {
                address: "::1".to_string(),
                port: 9447,
            })
        );

        assert_eq!(
            select_fallback_target(
                &ClientHelloFallbackInput {
                    server_name: Some("decoy.example"),
                    alpns: Some(&[b"h2".to_vec()]),
                    named_groups: None,
                },
                &rules,
                Some(FallbackTarget {
                    address: "::1".to_string(),
                    port: 9446,
                })
            ),
            Some(FallbackTarget {
                address: "::1".to_string(),
                port: 9446,
            })
        );
    }

    #[test]
    fn select_fallback_target_requires_matching_named_group_when_configured() {
        let rules = vec![FallbackRule {
            matcher: FallbackMatcher {
                server_names: vec!["decoy.example".to_string()],
                alpns: vec![],
                named_groups: vec!["x25519".to_string()],
            },
            target: FallbackTarget {
                address: "::1".to_string(),
                port: 9447,
            },
        }];

        assert_eq!(
            select_fallback_target(
                &ClientHelloFallbackInput {
                    server_name: Some("decoy.example"),
                    alpns: None,
                    named_groups: Some(&[NamedGroup::X25519]),
                },
                &rules,
                Some(FallbackTarget {
                    address: "::1".to_string(),
                    port: 9446,
                })
            ),
            Some(FallbackTarget {
                address: "::1".to_string(),
                port: 9447,
            })
        );

        assert_eq!(
            select_fallback_target(
                &ClientHelloFallbackInput {
                    server_name: Some("decoy.example"),
                    alpns: None,
                    named_groups: Some(&[NamedGroup::secp256r1]),
                },
                &rules,
                Some(FallbackTarget {
                    address: "::1".to_string(),
                    port: 9446,
                })
            ),
            Some(FallbackTarget {
                address: "::1".to_string(),
                port: 9446,
            })
        );
    }

    #[test]
    fn validate_rejects_reality_with_tls12() {
        let args = Args {
            protover: vec!["1.2".to_string()],
            reality_short_id: Some("aabbcc".to_string()),
            reality_private_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
            reality_version: Some("010203".to_string()),
            ..base_args(ServerMode::Http)
        };

        let reality = resolve_reality_config(&args).unwrap();
        assert_eq!(
            args.validate(reality.as_ref())
                .unwrap_err(),
            "REALITY mode requires TLS1.3"
        );
    }

    #[test]
    fn make_config_supports_reality_arguments() {
        let args = Args {
            certs: PathBuf::from("../bogo/keys/cert.pem"),
            key: PathBuf::from("../bogo/keys/key.pem"),
            reality_short_id: Some("aabbcc".to_string()),
            reality_private_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
            reality_version: Some("010203".to_string()),
            reality_server_name: vec!["test".to_string()],
            ..base_args(ServerMode::Http)
        };

        let reality = resolve_reality_config(&args).unwrap();
        let config = make_config(&args, reality.as_ref());
        assert!(Arc::strong_count(&config) >= 1);
    }

    #[test]
    fn resolve_reality_supports_toml_file() {
        let args = Args {
            certs: test_cert_path("cert.pem"),
            key: test_cert_path("key.pem"),
            reality_config: Some(test_config_path("reality-server.toml")),
            ..base_args(ServerMode::Http)
        };

        let reality = resolve_reality_config(&args)
            .unwrap()
            .unwrap();
        assert_eq!(reality.server_names, vec!["test"]);
        assert_eq!(reality.fallback_address.as_deref(), Some("::1"));
        assert_eq!(reality.fallback_port, Some(9446));
        assert_eq!(reality.fallback_rules.len(), 1);
        assert_eq!(reality.fallback_rules[0].alpns, vec!["http/1.1"]);
        assert_eq!(reality.fallback_rules[0].named_groups, vec!["x25519"]);
    }

    #[test]
    fn resolve_reality_prefers_cli_fallback_target() {
        let args = Args {
            certs: test_cert_path("cert.pem"),
            key: test_cert_path("key.pem"),
            reality_config: Some(test_config_path("reality-server.toml")),
            reality_fallback_address: Some("127.0.0.1".to_string()),
            reality_fallback_port: Some(9555),
            ..base_args(ServerMode::Http)
        };

        let reality = resolve_reality_config(&args)
            .unwrap()
            .unwrap();
        assert_eq!(reality.fallback_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(reality.fallback_port, Some(9555));
    }

    #[test]
    fn validate_rejects_fallback_address_without_port() {
        let args = Args {
            reality_short_id: Some("aabbcc".to_string()),
            reality_private_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
            reality_version: Some("010203".to_string()),
            reality_fallback_address: Some("::1".to_string()),
            ..base_args(ServerMode::Http)
        };

        let reality = resolve_reality_config(&args).unwrap();
        assert_eq!(
            args.validate(reality.as_ref())
                .unwrap_err(),
            "REALITY fallback address requires a fallback port"
        );
    }

    #[test]
    fn validate_rejects_fallback_without_reality() {
        let args = Args {
            reality_fallback_port: Some(8443),
            ..base_args(ServerMode::Http)
        };

        assert_eq!(
            args.validate(None).unwrap_err(),
            "REALITY fallback requires REALITY mode"
        );
    }

    #[test]
    fn validate_rejects_fallback_with_forward_mode() {
        let args = Args {
            reality_short_id: Some("aabbcc".to_string()),
            reality_private_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
            reality_version: Some("010203".to_string()),
            reality_fallback_port: Some(8443),
            ..base_args(ServerMode::Forward { port: 9000 })
        };

        let reality = resolve_reality_config(&args).unwrap();
        assert_eq!(
            args.validate(reality.as_ref())
                .unwrap_err(),
            "REALITY fallback is not supported with forward mode"
        );
    }

    #[test]
    fn validate_rejects_zero_global_fallback_port() {
        let args = Args {
            reality_short_id: Some("aabbcc".to_string()),
            reality_private_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
            reality_version: Some("010203".to_string()),
            reality_fallback_port: Some(0),
            ..base_args(ServerMode::Http)
        };

        let reality = resolve_reality_config(&args).unwrap();
        assert_eq!(
            args.validate(reality.as_ref())
                .unwrap_err(),
            "REALITY fallback port must be non-zero"
        );
    }

    #[test]
    fn validate_rejects_fallback_rule_without_matchers() {
        let args = Args {
            certs: test_cert_path("cert.pem"),
            key: test_cert_path("key.pem"),
            reality_short_id: Some("aabbcc".to_string()),
            reality_private_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
            reality_version: Some("010203".to_string()),
            ..base_args(ServerMode::Http)
        };
        let reality = RealityServerConfig {
            short_id: "aabbcc".to_string(),
            private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            version: "010203".to_string(),
            server_names: vec!["test".to_string()],
            fallback_address: Some("::1".to_string()),
            fallback_port: Some(9446),
            fallback_rules: vec![RealityFallbackRuleConfig {
                server_names: vec![],
                alpns: vec![],
                named_groups: vec![],
                fallback_address: "::1".to_string(),
                fallback_port: 9447,
            }],
        };

        assert_eq!(
            args.validate(Some(&reality))
                .unwrap_err(),
            "REALITY fallback rule #0 requires at least one server_name, alpn, or named_group match"
        );
    }

    #[test]
    fn validate_rejects_fallback_rule_with_zero_port() {
        let args = Args {
            certs: test_cert_path("cert.pem"),
            key: test_cert_path("key.pem"),
            reality_short_id: Some("aabbcc".to_string()),
            reality_private_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
            reality_version: Some("010203".to_string()),
            ..base_args(ServerMode::Http)
        };
        let reality = RealityServerConfig {
            short_id: "aabbcc".to_string(),
            private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            version: "010203".to_string(),
            server_names: vec!["test".to_string()],
            fallback_address: Some("::1".to_string()),
            fallback_port: Some(9446),
            fallback_rules: vec![RealityFallbackRuleConfig {
                server_names: vec!["decoy.example".to_string()],
                alpns: vec![],
                named_groups: vec![],
                fallback_address: "::1".to_string(),
                fallback_port: 0,
            }],
        };

        assert_eq!(
            args.validate(Some(&reality))
                .unwrap_err(),
            "REALITY fallback rule #0 requires a non-zero fallback port"
        );
    }
}
