use anyhow::{Context, Result, bail};
use clap::Parser;
use rustls::Connection;
use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls::crypto::Identity;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHelloVerifier, RealityClientHello};
use rustls_aws_lc_rs as provider;
use rustls_util::{StreamOwned, complete_io};
use std::hash::Hasher;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

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

#[derive(Clone, Debug)]
struct TunnelTarget {
    host: String,
    port: u16,
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
    ) -> std::result::Result<(), rustls::Error> {
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
    let reality = resolve_reality_config(&args)?;
    let config = Arc::new(build_server_config(&args, &reality)?);
    let listener = TcpListener::bind(&args.listen).await?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let config = Arc::clone(&config);

        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, config).await {
                eprintln!("REALITY client {peer_addr} failed: {error:#}");
            }
        });
    }
}

async fn handle_connection(stream: TcpStream, config: Arc<ServerConfig>) -> Result<()> {
    let stream = stream.into_std()?;
    tokio::task::spawn_blocking(move || handle_connection_blocking(stream, config)).await??;
    Ok(())
}

fn handle_connection_blocking(
    stream: std::net::TcpStream,
    config: Arc<ServerConfig>,
) -> Result<()> {
    let mut stream = stream;
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    let mut conn = ServerConnection::new(config)?;
    while conn.is_handshaking() {
        complete_io(&mut stream, &mut conn).context("complete REALITY handshake")?;
    }

    let mut tls_stream = StreamOwned::new(conn, stream);
    let target =
        read_target_header_blocking(&mut tls_stream).context("read tunnel target header")?;
    let upstream = std::net::TcpStream::connect((target.host.as_str(), target.port))
        .with_context(|| format!("connect upstream {}:{}", target.host, target.port))?;
    upstream.set_nodelay(true)?;

    relay_plain_and_tls(upstream, tls_stream).context("relay tunnel traffic")
}

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

    match (short_id, private_key, version) {
        (Some(short_id), Some(private_key), Some(version)) => Ok(RealityServerConfigResolved {
            private_key,
            short_id,
            version,
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
        .collect::<std::result::Result<Vec<_>, _>>()
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

fn read_target_header_blocking<R>(reader: &mut R) -> Result<TunnelTarget>
where
    R: Read,
{
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != b"RLY1" {
        bail!("invalid tunnel header magic")
    }

    let mut address_type = [0u8; 1];
    reader.read_exact(&mut address_type)?;
    let host = match address_type[0] {
        1 => {
            let mut octets = [0u8; 4];
            reader.read_exact(&mut octets)?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        3 => {
            let mut length = [0u8; 1];
            reader.read_exact(&mut length)?;
            let mut bytes = vec![0u8; length[0] as usize];
            reader.read_exact(&mut bytes)?;
            String::from_utf8(bytes).context("target host is not valid UTF-8")?
        }
        4 => {
            let mut octets = [0u8; 16];
            reader.read_exact(&mut octets)?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        other => bail!("unsupported tunnel address type: {other}"),
    };

    let mut port = [0u8; 2];
    reader.read_exact(&mut port)?;
    Ok(TunnelTarget {
        host,
        port: u16::from_be_bytes(port),
    })
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
