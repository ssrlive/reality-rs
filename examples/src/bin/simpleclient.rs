//! This is the simplest possible client using rustls that does something useful:
//! it accepts the default configuration, loads some root certs, and then connects
//! to rust-lang.org and issues a basic HTTP request.  The response is printed to stdout.
//!
//! It can also be switched into a REALITY-oriented client mode by supplying
//! Xray-style `short_id`, `public_key`, and `version` fields.
//!
//! It makes use of rustls::Stream to treat the underlying TLS connection as a basic
//! bi-directional stream -- the underlying IO is performed transparently.
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use clap::Parser;
use std::io::{Read, Write, stdout};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};
use rustls_util::{KeyLogFile, Stream};

#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    #[arg(long, default_value = "www.rust-lang.org")]
    host: String,

    #[arg(long, default_value_t = 443)]
    port: u16,

    #[arg(long, default_value = "/")]
    path: String,

    #[arg(long)]
    reality_short_id: Option<String>,

    #[arg(long)]
    reality_public_key: Option<String>,

    #[arg(long)]
    reality_version: Option<String>,
}

fn main() {
    let args = Args::parse();

    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let mut config = build_client_config(&args, root_store);

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(KeyLogFile::new());

    let server_name = rustls::pki_types::ServerName::try_from(args.host.as_str())
        .unwrap()
        .to_owned();
    let mut conn = Arc::new(config)
        .connect(server_name)
        .build()
        .unwrap();
    let mut sock = TcpStream::connect((args.host.as_str(), args.port)).unwrap();
    let mut tls = Stream::new(&mut conn, &mut sock);
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
        args.path, args.host
    );
    tls.write_all(request.as_bytes())
        .unwrap();
    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}

fn build_client_config(args: &Args, root_store: RootCertStore) -> ClientConfig {
    let reality = match (
        args.reality_short_id.as_deref(),
        args.reality_public_key.as_deref(),
        args.reality_version.as_deref(),
    ) {
        (None, None, None) => None,
        (Some(short_id), Some(public_key), Some(version)) => Some((short_id, public_key, version)),
        _ => panic!(
            "REALITY mode requires --reality-short-id, --reality-public-key, and --reality-version together"
        ),
    };

    match reality {
        Some((short_id, public_key, version)) => {
            rustls_aws_lc_rs::reality::build_reality_client_config_from_xray_fields(
                parse_reality_version(version),
                short_id,
                public_key,
                root_store,
            )
            .unwrap()
        }
        None => ClientConfig::builder(rustls_aws_lc_rs::DEFAULT_PROVIDER.into())
            .with_root_certificates(root_store)
            .with_no_client_auth()
            .unwrap(),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reality_version_hex() {
        assert_eq!(parse_reality_version("010203"), [1, 2, 3]);
        assert_eq!(parse_reality_version("a0B1c2"), [0xa0, 0xb1, 0xc2]);
    }
}
