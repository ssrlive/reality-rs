use anyhow::{Context, Result, bail};
use clap::Parser;
use rustls::ClientConfig;
use rustls::Connection;
use rustls::RootCertStore;
use rustls::client::ClientConnection;
use rustls::client::danger::{
    HandshakeSignatureValid, PeerVerified, ServerIdentity, ServerVerifier,
    SignatureVerificationInput,
};
use rustls::crypto::SignatureScheme;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls_aws_lc_rs as provider;
use rustls_util::{StreamOwned, complete_io};
use socks5_impl::protocol::{Address, Reply};
use socks5_impl::server::Server;
use socks5_impl::server::auth::NoAuth;
use socks5_impl::server::connection::ClientConnection as SocksClientConnection;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:1080")]
    listen: String,

    #[arg(long)]
    server_addr: String,

    #[arg(long)]
    server_name: Option<String>,

    #[arg(long)]
    reality_config: Option<PathBuf>,

    #[arg(long, requires_all = ["reality_public_key", "reality_version"])]
    reality_short_id: Option<String>,

    #[arg(long, requires_all = ["reality_short_id", "reality_version"])]
    reality_public_key: Option<String>,

    #[arg(long, requires_all = ["reality_short_id", "reality_public_key"])]
    reality_version: Option<String>,

    #[arg(long)]
    ca_file: Option<PathBuf>,

    #[arg(long)]
    insecure: bool,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RealityDocument<T> {
    reality: T,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RealityClientConfigFile {
    public_key: String,
    short_id: String,
    version: String,
    #[serde(default)]
    server_name: Option<String>,
}

#[derive(Clone, Debug)]
struct RealityClientConfigResolved {
    public_key: String,
    short_id: String,
    version: String,
    server_name: String,
}

#[derive(Clone, Debug)]
struct TunnelTarget {
    host: String,
    port: u16,
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerVerifier for NoCertificateVerification {
    fn verify_identity(
        &self,
        _identity: &ServerIdentity<'_>,
    ) -> std::result::Result<PeerVerified, rustls::Error> {
        Ok(PeerVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _input: &SignatureVerificationInput<'_>,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _input: &SignatureVerificationInput<'_>,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
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

    fn hash_config(&self, _: &mut dyn std::hash::Hasher) {}
}

struct EstablishedTlsClient {
    tls_stream: StreamOwned<ClientConnection, std::net::TcpStream>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let reality = resolve_reality_config(&args)?;
    let tls_server_name = reality.server_name.clone();
    let tls_config = Arc::new(build_client_config(&args, &reality)?);
    let socks_server = Server::bind(args.listen.parse()?, Arc::new(NoAuth)).await?;

    loop {
        let (incoming, peer_addr) = socks_server.accept().await?;
        let tls_config = Arc::clone(&tls_config);
        let server_addr = args.server_addr.clone();
        let tls_server_name = tls_server_name.clone();

        tokio::spawn(async move {
            if let Err(error) =
                handle_connection(incoming, tls_config, server_addr, tls_server_name).await
            {
                eprintln!("SOCKS peer {peer_addr} failed: {error:#}");
            }
        });
    }
}

async fn handle_connection(
    incoming: socks5_impl::server::connection::IncomingConnection<()>,
    tls_config: Arc<ClientConfig>,
    server_addr: String,
    tls_server_name: String,
) -> Result<()> {
    let (authenticated, _) = incoming.authenticate().await?;

    match authenticated.wait_request().await? {
        SocksClientConnection::Connect(connect, address) => {
            let target = decode_address(&address)?;
            let established = tokio::task::spawn_blocking({
                let tls_config = Arc::clone(&tls_config);
                let server_addr = server_addr.clone();
                let tls_server_name = tls_server_name.clone();
                let target = target.clone();
                move || establish_tls_client(tls_config, &server_addr, &tls_server_name, &target)
            })
            .await??;

            let bind_addr = Address::from(connect.local_addr()?);
            let connect = connect
                .reply(Reply::Succeeded, bind_addr)
                .await?;
            let local_stream: TcpStream = connect.into();
            let local_stream = local_stream.into_std()?;

            tokio::task::spawn_blocking(move || relay_tls_client(local_stream, established))
                .await??;
            Ok(())
        }
        SocksClientConnection::Bind(bind, _) => {
            let _ = bind;
            bail!("SOCKS BIND is not supported")
        }
        SocksClientConnection::UdpAssociate(associate, _) => {
            let _ = associate;
            bail!("SOCKS UDP ASSOCIATE is not supported")
        }
    }
}

fn resolve_reality_config(args: &Args) -> Result<RealityClientConfigResolved> {
    let file_config = if let Some(path) = args.reality_config.as_deref() {
        Some(load_reality_document::<RealityClientConfigFile>(path)?.reality)
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
    let public_key = args
        .reality_public_key
        .clone()
        .or_else(|| {
            file_config
                .as_ref()
                .map(|config| config.public_key.clone())
        });
    let version = args
        .reality_version
        .clone()
        .or_else(|| {
            file_config
                .as_ref()
                .map(|config| config.version.clone())
        });
    let server_name = args.server_name.clone().or_else(|| {
        file_config
            .as_ref()
            .and_then(|config| config.server_name.clone())
    });

    match (short_id, public_key, version, server_name) {
        (Some(short_id), Some(public_key), Some(version), Some(server_name)) => {
            Ok(RealityClientConfigResolved {
                short_id,
                public_key,
                version,
                server_name,
            })
        }
        _ => bail!(
            "REALITY client requires short_id, public_key, version, and server_name via CLI or --reality-config"
        ),
    }
}

fn build_client_config(args: &Args, reality: &RealityClientConfigResolved) -> Result<ClientConfig> {
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
        parse_reality_version(&reality.version),
        &reality.short_id,
        &reality.public_key,
    )?;

    Ok(config)
}

fn load_root_store(ca_file: Option<&Path>) -> Result<RootCertStore> {
    let mut root_store = RootCertStore::empty();

    if let Some(ca_file) = ca_file {
        let certs = CertificateDer::pem_file_iter(ca_file)
            .context("open CA file")?
            .collect::<std::result::Result<Vec<_>, _>>()
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

fn decode_address(address: &Address) -> Result<TunnelTarget> {
    Ok(TunnelTarget {
        host: address.domain(),
        port: address.port(),
    })
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

fn establish_tls_client(
    tls_config: Arc<ClientConfig>,
    server_addr: &str,
    tls_server_name: &str,
    target: &TunnelTarget,
) -> Result<EstablishedTlsClient> {
    let mut upstream = std::net::TcpStream::connect(server_addr)
        .with_context(|| format!("connect REALITY server {server_addr}"))?;
    upstream.set_nodelay(true)?;

    let server_name = ServerName::try_from(tls_server_name.to_owned())?;
    let mut conn = tls_config
        .connect(server_name)
        .build()?;
    while conn.is_handshaking() {
        complete_io(&mut upstream, &mut conn).context("complete REALITY handshake")?;
    }

    let mut tls_stream = StreamOwned::new(conn, upstream);
    write_target_header_blocking(&mut tls_stream, target).context("write tunnel target header")?;
    tls_stream.sock.set_nonblocking(true)?;

    Ok(EstablishedTlsClient { tls_stream })
}

fn relay_tls_client(
    local_stream: std::net::TcpStream,
    established: EstablishedTlsClient,
) -> Result<()> {
    relay_plain_and_tls(local_stream, established.tls_stream)
}

fn relay_plain_and_tls<C>(
    mut plain_stream: std::net::TcpStream,
    mut tls_stream: StreamOwned<C, std::net::TcpStream>,
) -> Result<()>
where
    C: Connection,
{
    plain_stream.set_nonblocking(true)?;
    tls_stream.sock.set_nonblocking(true)?;

    let mut plain_to_tls = Vec::new();
    let mut tls_to_plain = Vec::new();
    let mut plain_closed = false;
    let mut tls_closed = false;
    let mut buf = [0u8; 16 * 1024];

    loop {
        let mut progressed = false;

        if !plain_closed && plain_to_tls.len() < 128 * 1024 {
            match plain_stream.read(&mut buf) {
                Ok(0) => {
                    plain_closed = true;
                    tls_stream.conn.send_close_notify();
                    progressed = true;
                }
                Ok(read) => {
                    plain_to_tls.extend_from_slice(&buf[..read]);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }

        if !plain_to_tls.is_empty() {
            match tls_stream.write(&plain_to_tls) {
                Ok(written) => {
                    plain_to_tls.drain(..written);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            let _ = tls_stream.flush();
        }

        if !tls_closed && tls_to_plain.len() < 128 * 1024 {
            match tls_stream.read(&mut buf) {
                Ok(0) => {
                    tls_closed = true;
                    progressed = true;
                }
                Ok(read) => {
                    tls_to_plain.extend_from_slice(&buf[..read]);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }

        if !tls_to_plain.is_empty() {
            match plain_stream.write(&tls_to_plain) {
                Ok(written) => {
                    tls_to_plain.drain(..written);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }

        if (plain_closed || tls_closed) && plain_to_tls.is_empty() && tls_to_plain.is_empty() {
            break;
        }

        if !progressed {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    Ok(())
}

fn write_target_header_blocking<W>(writer: &mut W, target: &TunnelTarget) -> Result<()>
where
    W: Write,
{
    writer.write_all(b"RLY1")?;

    if let Ok(ipv4) = target
        .host
        .parse::<std::net::Ipv4Addr>()
    {
        writer.write_all(&[1])?;
        writer.write_all(&ipv4.octets())?;
    } else if let Ok(ipv6) = target
        .host
        .parse::<std::net::Ipv6Addr>()
    {
        writer.write_all(&[4])?;
        writer.write_all(&ipv6.octets())?;
    } else {
        let host = target.host.as_bytes();
        if host.len() > u8::MAX as usize {
            bail!("target host is too long")
        }
        writer.write_all(&[3, host.len() as u8])?;
        writer.write_all(host)?;
    }

    writer.write_all(&target.port.to_be_bytes())?;
    writer.flush()?;
    Ok(())
}
