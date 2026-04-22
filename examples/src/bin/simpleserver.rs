//! This is the simplest possible server using rustls that does something useful:
//! it accepts the default configuration, loads a server certificate and private key,
//! and then accepts a single client connection.
//!
//! Usage: cargo r --bin simpleserver -- --cert <path/to/cert.pem> --key <path/to/privatekey.pem>
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use core::error::Error as StdError;
use core::hash::Hasher;
use std::io;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;

#[path = "../common/reality_config.rs"]
mod reality_config;

use clap::Parser;
use rustls::crypto::Identity;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHelloVerifier, RealityClientHello};
use rustls::{ServerConfig, ServerConnection};
use rustls_aws_lc_rs as provider;
use rustls_util::Stream;

use reality_config::{RealityServerConfig, load_reality_document};

#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    #[arg(long)]
    cert: PathBuf,

    #[arg(long)]
    key: PathBuf,

    #[arg(long, default_value_t = 4443)]
    port: u16,

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

impl Args {
    fn validate(&self, reality: Option<&RealityServerConfig>) -> Result<(), String> {
        if reality.is_none() {
            return Ok(());
        }

        if self.port == 0 {
            return Err("REALITY mode requires a concrete listening port".into());
        }

        Ok(())
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

fn resolve_reality_config(args: &Args) -> Result<Option<RealityServerConfig>, Box<dyn StdError>> {
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

    match (short_id, private_key, version) {
        (None, None, None) => Ok(None),
        (Some(short_id), Some(private_key), Some(version)) => Ok(Some(RealityServerConfig {
            short_id,
            private_key,
            version,
            server_names,
            fallback_address: file_config
                .as_ref()
                .and_then(|config| config.fallback_address.clone()),
            fallback_port: file_config
                .as_ref()
                .and_then(|config| config.fallback_port),
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

fn build_config(
    args: &Args,
    reality: Option<&RealityServerConfig>,
) -> Result<ServerConfig, Box<dyn StdError>> {
    let certs = CertificateDer::pem_file_iter(&args.cert)
        .unwrap()
        .map(|cert| cert.unwrap())
        .collect();
    let private_key = PrivateKeyDer::from_pem_file(&args.key).unwrap();

    let provider = if reality.is_some() {
        provider::reality::default_x25519_tls13_reality_provider()
    } else {
        provider::DEFAULT_PROVIDER
    };

    let mut config = ServerConfig::builder(Arc::new(provider))
        .with_no_client_auth()
        .with_single_cert(Arc::new(Identity::from_cert_chain(certs)?), private_key)?;

    if let Some(reality) = reality {
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
    }

    Ok(config)
}

fn parse_reality_version(version: &str) -> [u8; 3] {
    let version = version.trim();
    assert_eq!(
        version.len(),
        6,
        "REALITY version must be exactly 6 hex digits, for example 010203"
    );

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

fn main() -> Result<(), Box<dyn StdError>> {
    let args = Args::parse();
    let reality = resolve_reality_config(&args)?;
    args.validate(reality.as_ref())?;

    let config = build_config(&args, reality.as_ref())?;

    let listener = TcpListener::bind(format!("[::]:{}", args.port)).unwrap();
    let (mut tcp_stream, _) = listener.accept()?;
    let mut conn = ServerConnection::new(Arc::new(config))?;
    let mut tls_stream = Stream::new(&mut conn, &mut tcp_stream);

    tls_stream.write_all(b"Hello from the server")?;
    tls_stream.flush()?;
    let mut buf = [0; 64];
    let len = tls_stream.read(&mut buf)?;
    println!("Received message from client: {:?}", &buf[..len]);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn build_config_supports_plain_tls() {
        let args = Args {
            cert: test_cert_path("cert.pem"),
            key: test_cert_path("key.pem"),
            port: 4443,
            reality_config: None,
            reality_short_id: None,
            reality_private_key: None,
            reality_version: None,
            reality_server_name: vec![],
        };

        let reality = resolve_reality_config(&args).unwrap();
        let config = build_config(&args, reality.as_ref()).unwrap();
        assert!(
            !config
                .crypto_provider()
                .tls12_cipher_suites
                .is_empty()
        );
    }

    #[test]
    fn build_config_supports_reality_arguments() {
        let args = Args {
            cert: test_cert_path("cert.pem"),
            key: test_cert_path("key.pem"),
            port: 4443,
            reality_config: None,
            reality_short_id: Some("aabbcc".to_string()),
            reality_private_key: Some("SMGC8zRkH_w4ZggVwiEJOdkeY1jWMZLCet5Qf2i-SmM".to_string()),
            reality_version: Some("010203".to_string()),
            reality_server_name: vec!["test".to_string()],
        };

        let reality = resolve_reality_config(&args).unwrap();
        let config = build_config(&args, reality.as_ref()).unwrap();
        assert!(
            config
                .crypto_provider()
                .tls12_cipher_suites
                .is_empty()
        );
    }

    #[test]
    fn resolve_reality_supports_toml_file() {
        let args = Args {
            cert: test_cert_path("cert.pem"),
            key: test_cert_path("key.pem"),
            port: 4443,
            reality_config: Some(test_config_path("reality-server.toml")),
            reality_short_id: None,
            reality_private_key: None,
            reality_version: None,
            reality_server_name: vec![],
        };

        let reality = resolve_reality_config(&args)
            .unwrap()
            .unwrap();
        assert_eq!(reality.short_id, "aabbcc");
        assert_eq!(reality.version, "010203");
        assert_eq!(reality.server_names, vec!["test"]);
        assert_eq!(reality.fallback_address.as_deref(), Some("::1"));
        assert_eq!(reality.fallback_port, Some(9446));
        assert_eq!(reality.fallback_rules.len(), 1);
        assert_eq!(reality.fallback_rules[0].alpns, vec!["http/1.1"]);
        assert_eq!(reality.fallback_rules[0].named_groups, vec!["x25519"]);
    }
}
