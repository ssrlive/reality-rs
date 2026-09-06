use alloc::borrow::Cow;
use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use core::convert::TryFrom;
use core::fmt;
use core::hash::Hasher;
use core::time::Duration;

use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement;
use aws_lc_rs::hmac as aws_hmac;
use pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::client::danger::{
    HandshakeSignatureValid, PeerVerified, RealitySessionIdGenerator, RealitySessionIdSealer,
    SealingRealitySessionIdGenerator, ServerIdentity, ServerVerifier,
};
use rustls::client::{ParsedCertificate, verify_server_name};
use rustls::crypto::Identity;
use rustls::crypto::tls13::{Hkdf, HkdfUsingHmac};
use rustls::crypto::{
    CryptoProvider,
    kx::{NamedGroup, SupportedKxGroup},
};
use rustls::crypto::{SelectedCredential, SignatureScheme};
use rustls::error::{ApiMisuse, Error};
use rustls::server::{
    ClientHello, ClientHelloVerifier, RealityClientHello, ServerConfig, ServerCredentialResolver,
};
use rustls::time_provider::{DefaultTimeProvider, TimeProvider};
use rustls::{ClientConfig, RootCertStore};
use subtle::ConstantTimeEq;

static REALITY_X25519_KX_GROUPS: &[&dyn SupportedKxGroup] = &[crate::kx_group::X25519];
const REALITY_X25519_PUBLIC_KEY_LEN: usize = 32;
const REALITY_X25519_PRIVATE_KEY_LEN: usize = 32;
const DEFAULT_REALITY_MAX_TIME_SKEW: Duration = Duration::from_secs(30);

/// A server credential resolver that emits a per-connection REALITY certificate.
#[derive(Debug)]
pub struct RealityServerCredentialResolver {
    fallback: Arc<dyn ServerCredentialResolver>,
    provider: Arc<CryptoProvider>,
}

/// A server verifier that recognizes REALITY's HMAC-authenticated Ed25519 certificates.
#[derive(Debug)]
pub struct RealityServerVerifier {
    fallback: Arc<dyn ServerVerifier>,
}

impl RealityServerCredentialResolver {
    /// Wraps the normal resolver. Connections without a verified AuthKey use it unchanged.
    pub fn new(fallback: Arc<dyn ServerCredentialResolver>, provider: Arc<CryptoProvider>) -> Self {
        Self { fallback, provider }
    }
}

impl ServerCredentialResolver for RealityServerCredentialResolver {
    fn resolve(&self, client_hello: &ClientHello<'_>) -> Result<SelectedCredential, Error> {
        let Some(auth_key) = client_hello.reality_auth_key() else {
            return self.fallback.resolve(client_hello);
        };

        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|_| Error::General("failed to generate REALITY Ed25519 key".into()))?;
        let public_key: [u8; 32] = key_pair
            .public_key_raw()
            .try_into()
            .map_err(|_| Error::General("unexpected Ed25519 public key length".into()))?;
        let server_name = client_hello
            .server_name()
            .ok_or(Error::NoSuitableCertificate)?;
        let params = rcgen::CertificateParams::new(vec![server_name.as_ref().to_string()])
            .map_err(|_| {
                Error::General("failed to create REALITY certificate parameters".into())
            })?;
        let certificate = params
            .self_signed(&key_pair)
            .map_err(|_| Error::General("failed to create REALITY certificate".into()))?;
        let mut cert_der = certificate.der().to_vec();
        let signature = reality_certificate_signature(auth_key, &public_key);
        replace_outer_signature(&mut cert_der, &signature)?;

        let identity = Arc::new(Identity::from_cert_chain(vec![CertificateDer::from(
            cert_der,
        )])?);
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let signing_key = self
            .provider
            .key_provider
            .load_private_key(private_key)?;
        let signer = signing_key
            .choose_scheme(client_hello.signature_schemes())
            .ok_or(Error::NoSuitableCertificate)?;
        Ok(SelectedCredential::new(identity, signer))
    }
}

impl RealityServerVerifier {
    /// Wraps the normal verifier. Non-REALITY or non-Ed25519 certificates use it unchanged.
    pub fn new(fallback: Arc<dyn ServerVerifier>) -> Self {
        Self { fallback }
    }
}

impl ServerVerifier for RealityServerVerifier {
    fn verify_identity(&self, identity: &ServerIdentity<'_>) -> Result<PeerVerified, Error> {
        let Some(auth_key) = identity.reality_auth_key else {
            return self.fallback.verify_identity(identity);
        };
        let Identity::X509(certificates) = identity.identity else {
            return self.fallback.verify_identity(identity);
        };
        let Some((public_key, signature)) = reality_certificate_fields(&certificates.end_entity)?
        else {
            return self.fallback.verify_identity(identity);
        };
        if !verify_reality_certificate_signature(auth_key, &public_key, &signature) {
            return Err(Error::General(
                "REALITY certificate signature mismatch".into(),
            ));
        }
        let parsed = ParsedCertificate::try_from(&certificates.end_entity)?;
        verify_server_name(&parsed, identity.server_name)?;
        Ok(PeerVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        input: &rustls::client::danger::SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.fallback
            .verify_tls12_signature(input)
    }

    fn verify_tls13_signature(
        &self,
        input: &rustls::client::danger::SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.fallback
            .verify_tls13_signature(input)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.fallback.supported_verify_schemes()
    }
    fn request_ocsp_response(&self) -> bool {
        self.fallback.request_ocsp_response()
    }
    fn hash_config(&self, h: &mut dyn Hasher) {
        self.fallback.hash_config(h);
        h.write(b"reality-server-verifier");
    }
}

fn der_tlv(input: &[u8], offset: &mut usize) -> Result<(u8, usize, usize), Error> {
    let tag = *input
        .get(*offset)
        .ok_or_else(|| Error::General("malformed REALITY certificate".into()))?;
    *offset += 1;
    let first = *input
        .get(*offset)
        .ok_or_else(|| Error::General("malformed REALITY certificate".into()))?;
    *offset += 1;
    let length = if first & 0x80 == 0 {
        first as usize
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return Err(Error::General(
                "malformed REALITY certificate length".into(),
            ));
        }
        let mut length = 0;
        for _ in 0..count {
            length = (length << 8)
                | *input
                    .get(*offset)
                    .ok_or_else(|| Error::General("malformed REALITY certificate length".into()))?
                    as usize;
            *offset += 1;
        }
        length
    };
    let start = *offset;
    let end = start
        .checked_add(length)
        .ok_or_else(|| Error::General("malformed REALITY certificate length".into()))?;
    if end > input.len() {
        return Err(Error::General("malformed REALITY certificate".into()));
    }
    *offset = end;
    Ok((tag, start, end))
}

fn replace_outer_signature(cert: &mut [u8], signature: &[u8; 64]) -> Result<(), Error> {
    let mut offset = 0;
    let (tag, start, end) = der_tlv(cert, &mut offset)?;
    if tag != 0x30 || end != cert.len() {
        return Err(Error::General("malformed REALITY certificate".into()));
    }
    offset = start;
    let (_, _, _) = der_tlv(cert, &mut offset)?;
    let (_, _, _) = der_tlv(cert, &mut offset)?;
    let (tag, value, end) = der_tlv(cert, &mut offset)?;
    if tag != 0x03 || end - value != 65 || cert[value] != 0 {
        return Err(Error::General(
            "unexpected REALITY certificate signature".into(),
        ));
    }
    cert[value + 1..end].copy_from_slice(signature);
    let _ = start;
    Ok(())
}

#[allow(clippy::type_complexity)]
fn reality_certificate_fields(
    cert: &CertificateDer<'_>,
) -> Result<Option<([u8; 32], Vec<u8>)>, Error> {
    let der = cert.as_ref();
    let mut outer = 0;
    let (tag, cert_start, cert_end) = der_tlv(der, &mut outer)?;
    if tag != 0x30 {
        return Err(Error::General("malformed REALITY certificate".into()));
    }
    let mut cert = cert_start;
    let (_, tbs_start, tbs_end) = der_tlv(der, &mut cert)?;
    if cert_end != der.len() {
        return Err(Error::General("malformed REALITY certificate".into()));
    }
    let mut tbs = tbs_start;
    outer = tbs_end;
    let _ = der_tlv(der, &mut outer)?;
    let (sig_tag, sig_start, sig_end) = der_tlv(der, &mut outer)?;
    if sig_tag != 0x03 || sig_end - sig_start != 65 || der[sig_start] != 0 {
        // Only REALITY's temporary Ed25519 certificate has a 64-byte outer
        // signature. Ordinary certificates use other signature formats and
        // must be delegated to the configured TLS verifier.
        return Ok(None);
    }
    let first_start = tbs;
    let (first_tag, _, _) = der_tlv(der, &mut tbs)?;
    if first_tag != 0xa0 {
        tbs = first_start;
    }
    for _ in 0..5 {
        let (_, _, end) = der_tlv(der, &mut tbs)?;
        tbs = end;
    }
    let (spki_tag, spki_start, spki_end) = der_tlv(der, &mut tbs)?;
    if spki_tag != 0x30 || spki_end > tbs_end {
        return Ok(None);
    }
    let mut spki = spki_start;
    let (alg_tag, alg_start, alg_end) = der_tlv(der, &mut spki)?;
    if alg_tag != 0x30 || &der[alg_start..alg_end] != b"\x06\x03\x2b\x65\x70" {
        return Err(Error::General(format!(
            "algorithm shape tag={alg_tag:#x} bytes={:02x?}",
            &der[alg_start..alg_end]
        )));
    }
    let (key_tag, key_start, key_end) = der_tlv(der, &mut spki)?;
    if key_tag != 0x03 || key_end - key_start != 33 || der[key_start] != 0 {
        return Err(Error::General(format!(
            "key shape tag={key_tag:#x} len={} unused={}",
            key_end - key_start,
            der[key_start]
        )));
    }
    Ok(Some((
        der[key_start + 1..key_end]
            .try_into()
            .unwrap(),
        der[sig_start + 1..sig_end].to_vec(),
    )))
}

/// Derives the per-connection REALITY authentication key.
///
/// This is deliberately stateless: callers must provide the ECDH result and the
/// ClientHello random for the same handshake. The result is HKDF-SHA256 with the
/// first 20 random bytes as salt and `REALITY` as the info value.
pub fn derive_reality_auth_key(ecdh: &[u8], client_random: &[u8; 32]) -> Result<[u8; 32], Error> {
    if ecdh.is_empty() {
        return Err(Error::General(
            "REALITY ECDH secret must not be empty".into(),
        ));
    }

    let expander = HkdfUsingHmac(&crate::hmac::HMAC_SHA256)
        .extract_from_secret(Some(&client_random[..20]), ecdh);
    let mut auth_key = [0u8; 32];
    expander
        .expand_slice(&[b"REALITY"], &mut auth_key)
        .map_err(|_| Error::Unreachable("REALITY AuthKey output length rejected"))?;
    Ok(auth_key)
}

/// Computes the XTLS REALITY temporary-certificate signature.
///
/// The certificate's Ed25519 public key is the HMAC message and the per-connection
/// AuthKey is the HMAC-SHA512 key. This returns the 64-byte X.509 signature value.
pub fn reality_certificate_signature(
    auth_key: &[u8; 32],
    ed25519_public_key: &[u8; 32],
) -> [u8; 64] {
    let key = aws_hmac::Key::new(aws_hmac::HMAC_SHA512, auth_key);
    let tag = aws_hmac::sign(&key, ed25519_public_key);
    tag.as_ref()
        .try_into()
        .expect("HMAC-SHA512 has a 64-byte tag")
}

/// Verifies an XTLS REALITY temporary-certificate signature in constant time.
pub fn verify_reality_certificate_signature(
    auth_key: &[u8; 32],
    ed25519_public_key: &[u8; 32],
    signature: &[u8],
) -> bool {
    if signature.len() != 64 {
        return false;
    }

    reality_certificate_signature(auth_key, ed25519_public_key)
        .as_ref()
        .ct_eq(signature)
        .unwrap_u8()
        == 1
}

/// Xray-compatible REALITY sealer using AES-256-GCM from aws-lc-rs.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct Aes256GcmRealitySessionIdSealer;

/// Business-level configuration for installing REALITY session ID sealing on a client.
#[derive(Debug, Clone)]
pub struct RealitySessionIdConfig {
    version: [u8; 3],
    short_id: Vec<u8>,
    server_public_key: Vec<u8>,
    time_provider: Arc<dyn TimeProvider>,
}

/// Business-level configuration for installing REALITY session ID verification on a server.
#[derive(Debug, Clone)]
pub struct RealityServerVerifierConfig {
    version: [u8; 3],
    short_ids: Vec<Vec<u8>>,
    server_private_key: Vec<u8>,
    time_provider: Arc<dyn TimeProvider>,
    max_time_skew: Duration,
}

/// aws-lc-rs backed REALITY verifier for incoming TLS 1.3 client hellos.
pub struct AwsLcRsRealityClientHelloVerifier {
    version: [u8; 3],
    short_ids: Vec<[u8; 8]>,
    short_id_lens: Vec<usize>,
    server_private_key: Vec<u8>,
    time_provider: Arc<dyn TimeProvider>,
    max_time_skew: Duration,
}

impl fmt::Debug for AwsLcRsRealityClientHelloVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsLcRsRealityClientHelloVerifier")
            .field("version", &self.version)
            .field("short_id_count", &self.short_ids.len())
            .field("server_private_key_len", &self.server_private_key.len())
            .field("max_time_skew", &self.max_time_skew)
            .finish()
    }
}

impl RealitySessionIdSealer for Aes256GcmRealitySessionIdSealer {
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8; 16],
    ) -> Result<[u8; 32], Error> {
        if key.len() != 32 {
            return Err(Error::General(
                "REALITY AES-256-GCM sealer requires a 32-byte key".into(),
            ));
        }

        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key)
            .map_err(|_| Error::General("failed to initialize REALITY AES-256-GCM key".into()))?;
        let nonce = Nonce::assume_unique_for_key(*nonce);
        let mut in_out = plaintext.to_vec();
        LessSafeKey::new(unbound_key)
            .seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
            .map_err(super::unspecified_err)?;

        <[u8; 32]>::try_from(in_out.as_slice()).map_err(|_| {
            Error::General("REALITY AES-256-GCM output had an unexpected length".into())
        })
    }
}

impl RealitySessionIdConfig {
    /// Creates a REALITY config using the default wall-clock time provider.
    pub fn new(version: [u8; 3], short_id: impl AsRef<[u8]>, server_public_key: Vec<u8>) -> Self {
        Self {
            version,
            short_id: short_id.as_ref().to_vec(),
            server_public_key,
            time_provider: Arc::new(DefaultTimeProvider),
        }
    }

    /// Creates a REALITY config from Xray-style text fields.
    ///
    /// `short_id_hex` is parsed as hexadecimal bytes and `server_public_key_base64`
    /// accepts both padded/unpadded base64 and URL-safe base64.
    pub fn from_text_fields(
        version: [u8; 3],
        short_id_hex: &str,
        server_public_key_base64: &str,
    ) -> Result<Self, Error> {
        Ok(Self::new(
            version,
            decode_hex(short_id_hex, "REALITY short_id")?,
            decode_base64(server_public_key_base64, "REALITY server_public_key")?,
        ))
    }

    /// Creates a REALITY config from Xray-style field names.
    ///
    /// `short_id` is parsed as hexadecimal bytes and `public_key`
    /// accepts both padded/unpadded base64 and URL-safe base64.
    pub fn from_xray_fields(
        version: [u8; 3],
        short_id: &str,
        public_key: &str,
    ) -> Result<Self, Error> {
        Self::from_text_fields(version, short_id, public_key)
    }

    /// Replaces the time provider used to encode the REALITY timestamp field.
    pub fn with_time_provider(mut self, time_provider: Arc<dyn TimeProvider>) -> Self {
        self.time_provider = time_provider;
        self
    }

    /// Validates that this configuration is usable for the current X25519-only REALITY path.
    pub fn validate(&self) -> Result<(), Error> {
        if self.short_id.len() > 8 {
            return Err(Error::ApiMisuse(ApiMisuse::RealityShortIdTooLong {
                actual: self.short_id.len(),
                maximum: 8,
            }));
        }

        if self.server_public_key.len() != REALITY_X25519_PUBLIC_KEY_LEN {
            return Err(Error::General(format!(
                "REALITY public_key must be {REALITY_X25519_PUBLIC_KEY_LEN} bytes for X25519"
            )));
        }

        Ok(())
    }

    /// Builds a REALITY session ID generator from this configuration.
    pub fn build_generator(&self) -> Result<Arc<dyn RealitySessionIdGenerator>, Error> {
        self.validate()?;
        Ok(Arc::new(SealingRealitySessionIdGenerator::new(
            self.version,
            &self.short_id,
            self.server_public_key.clone(),
            self.time_provider.clone(),
            &crate::hmac::HMAC_SHA256,
            Arc::new(Aes256GcmRealitySessionIdSealer),
        )?))
    }

    /// Installs this REALITY configuration onto a client config.
    pub fn install_into(&self, config: &mut ClientConfig) -> Result<(), Error> {
        config
            .dangerous()
            .set_reality_session_id_generator(Some(self.build_generator()?));
        Ok(())
    }

    /// Builds a TLS1.3-only, X25519-pinned client config with this REALITY configuration installed.
    ///
    /// The returned config uses webpki root verification and no client authentication.
    pub fn build_client_config(
        &self,
        root_store: impl Into<Arc<RootCertStore>>,
    ) -> Result<ClientConfig, Error> {
        let provider = Arc::new(default_x25519_tls13_reality_provider());
        let root_store = root_store.into();
        let fallback = rustls::client::WebPkiServerVerifier::new_without_revocation(
            root_store.clone(),
            provider.signature_verification_algorithms,
        );
        let mut config = ClientConfig::builder(provider)
            .with_root_certificates(root_store)
            .with_no_client_auth()?;
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(RealityServerVerifier::new(Arc::new(fallback))));
        self.install_into(&mut config)?;
        Ok(config)
    }

    /// Builds a ready-to-use REALITY client config from Xray-style text fields.
    pub fn build_client_config_from_xray_fields(
        version: [u8; 3],
        short_id: &str,
        public_key: &str,
        root_store: impl Into<Arc<RootCertStore>>,
    ) -> Result<ClientConfig, Error> {
        Self::from_xray_fields(version, short_id, public_key)?.build_client_config(root_store)
    }
}

impl RealityServerVerifierConfig {
    /// Creates a REALITY server verifier config using the default wall-clock time provider.
    pub fn new(version: [u8; 3], short_id: impl AsRef<[u8]>, server_private_key: Vec<u8>) -> Self {
        Self {
            version,
            short_ids: vec![short_id.as_ref().to_vec()],
            server_private_key,
            time_provider: Arc::new(DefaultTimeProvider),
            max_time_skew: DEFAULT_REALITY_MAX_TIME_SKEW,
        }
    }

    /// Creates a REALITY server verifier config from Xray-style text fields.
    ///
    /// `short_id_hex` is parsed as hexadecimal bytes and `server_private_key_base64`
    /// accepts both padded/unpadded base64 and URL-safe base64.
    pub fn from_text_fields(
        version: [u8; 3],
        short_id_hex: &str,
        server_private_key_base64: &str,
    ) -> Result<Self, Error> {
        Ok(Self::new(
            version,
            decode_hex(short_id_hex, "REALITY short_id")?,
            decode_base64(server_private_key_base64, "REALITY server_private_key")?,
        ))
    }

    /// Creates a REALITY server verifier config from Xray-style field names.
    pub fn from_xray_fields(
        version: [u8; 3],
        short_id: &str,
        private_key: &str,
    ) -> Result<Self, Error> {
        Self::from_text_fields(version, short_id, private_key)
    }

    /// Replaces the time provider used to validate the REALITY timestamp field.
    pub fn with_time_provider(mut self, time_provider: Arc<dyn TimeProvider>) -> Self {
        self.time_provider = time_provider;
        self
    }

    /// Replaces the maximum accepted absolute timestamp skew.
    pub fn with_max_time_skew(mut self, max_time_skew: Duration) -> Self {
        self.max_time_skew = max_time_skew;
        self
    }

    /// Replaces the accepted Short ID with the configured Xray `shortIds` list.
    pub fn with_short_ids<I, S>(mut self, short_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        self.short_ids = short_ids
            .into_iter()
            .map(|short_id| short_id.as_ref().to_vec())
            .collect();
        self
    }

    /// Validates that this configuration is usable for the current X25519-only REALITY path.
    pub fn validate(&self) -> Result<(), Error> {
        if self.short_ids.is_empty() {
            return Err(Error::General(
                "REALITY requires at least one short_id".into(),
            ));
        }
        for short_id in &self.short_ids {
            if short_id.len() > 8 {
                return Err(Error::ApiMisuse(ApiMisuse::RealityShortIdTooLong {
                    actual: short_id.len(),
                    maximum: 8,
                }));
            }
        }

        if self.server_private_key.len() != REALITY_X25519_PRIVATE_KEY_LEN {
            return Err(Error::General(format!(
                "REALITY private_key must be {REALITY_X25519_PRIVATE_KEY_LEN} bytes for X25519"
            )));
        }

        Ok(())
    }

    /// Builds a REALITY client hello verifier from this configuration.
    pub fn build_verifier(&self) -> Result<Arc<dyn ClientHelloVerifier>, Error> {
        self.validate()?;

        let mut fixed_short_ids = Vec::with_capacity(self.short_ids.len());
        let mut short_id_lens = Vec::with_capacity(self.short_ids.len());
        for short_id in &self.short_ids {
            let mut fixed_short_id = [0u8; 8];
            fixed_short_id[..short_id.len()].copy_from_slice(short_id);
            fixed_short_ids.push(fixed_short_id);
            short_id_lens.push(short_id.len());
        }
        Ok(Arc::new(AwsLcRsRealityClientHelloVerifier {
            version: self.version,
            short_ids: fixed_short_ids,
            short_id_lens,
            server_private_key: self.server_private_key.clone(),
            time_provider: self.time_provider.clone(),
            max_time_skew: self.max_time_skew,
        }))
    }

    /// Installs this REALITY configuration onto a server config.
    pub fn install_into(&self, config: &mut ServerConfig) -> Result<(), Error> {
        let fallback = config.cert_resolver.clone();
        config.cert_resolver = Arc::new(RealityServerCredentialResolver::new(
            fallback,
            config.crypto_provider().clone(),
        ));
        config
            .dangerous()
            .set_reality_client_hello_verifier(Some(self.build_verifier()?));
        Ok(())
    }
}

impl AwsLcRsRealityClientHelloVerifier {
    fn verify_header(&self, client_hello: &RealityClientHello<'_>) -> Result<(), Error> {
        if client_hello.version().0 != 0x0304 {
            return Err(Error::General(
                "REALITY server verifier requires TLS1.3 client hellos".into(),
            ));
        }

        let raw_client_hello = client_hello
            .raw_client_hello()
            .ok_or_else(|| {
                Error::General(
                    "REALITY server verifier requires a 32-byte session_id snapshot".into(),
                )
            })?;
        let client_key_share = client_hello
            .key_share(NamedGroup::X25519)
            .ok_or_else(|| {
                Error::General("REALITY server verifier requires an X25519 key_share".into())
            })?;
        let session_id = <[u8; 32]>::try_from(client_hello.session_id()).map_err(|_| {
            Error::General("REALITY server verifier requires a 32-byte session_id".into())
        })?;

        let reality_key = agreement::agree(
            &agreement::PrivateKey::from_private_key(&agreement::X25519, &self.server_private_key)
                .map_err(|_| Error::General("failed to parse REALITY X25519 private key".into()))?,
            agreement::UnparsedPublicKey::new(&agreement::X25519, client_key_share),
            aws_lc_rs::error::Unspecified,
            |secret| Ok::<Vec<u8>, aws_lc_rs::error::Unspecified>(Vec::from(secret)),
        )
        .map_err(super::unspecified_err)?;

        let sealing_key = derive_reality_auth_key(&reality_key, client_hello.client_random())?;

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&client_hello.client_random()[20..32]);

        let mut decrypted = session_id.to_vec();
        let plaintext = LessSafeKey::new(
            UnboundKey::new(&aead::AES_256_GCM, &sealing_key).map_err(|_| {
                Error::General("failed to initialize REALITY AES-256-GCM key".into())
            })?,
        )
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(raw_client_hello),
            &mut decrypted,
        )
        .map_err(super::unspecified_err)?;

        if plaintext.len() != 16 {
            return Err(Error::General(
                "REALITY server verifier decrypted an unexpected plaintext length".into(),
            ));
        }

        if plaintext[3] != 0 {
            return Err(Error::General(
                "REALITY server verifier rejected a non-zero reserved byte".into(),
            ));
        }

        if plaintext[..3]
            .ct_eq(&self.version)
            .unwrap_u8()
            != 1
        {
            return Err(Error::General(
                "REALITY server verifier rejected an unexpected version tag".into(),
            ));
        }

        let short_id_matches = self
            .short_ids
            .iter()
            .zip(&self.short_id_lens)
            .any(|(short_id, short_id_len)| {
                plaintext[8..16]
                    .ct_eq(short_id)
                    .unwrap_u8()
                    == 1
                    && plaintext[8 + *short_id_len..16]
                        .ct_eq(&short_id[*short_id_len..])
                        .unwrap_u8()
                        == 1
            });
        if !short_id_matches {
            return Err(Error::General(
                "REALITY server verifier rejected an unexpected short_id".into(),
            ));
        }

        let timestamp = u32::from_be_bytes(plaintext[4..8].try_into().unwrap()) as u64;
        let current_time = self
            .time_provider
            .current_time()
            .ok_or(Error::FailedToGetCurrentTime)?
            .as_secs();
        if current_time.abs_diff(timestamp) > self.max_time_skew.as_secs() {
            return Err(Error::General(
                "REALITY server verifier rejected a stale timestamp".into(),
            ));
        }

        Ok(())
    }
}

impl ClientHelloVerifier for AwsLcRsRealityClientHelloVerifier {
    fn verify_client_hello(&self, client_hello: &RealityClientHello<'_>) -> Result<(), Error> {
        self.verify_header(client_hello)
    }

    fn reality_auth_key(
        &self,
        client_hello: &RealityClientHello<'_>,
    ) -> Result<Option<[u8; 32]>, Error> {
        let client_key_share = client_hello
            .key_share(NamedGroup::X25519)
            .ok_or_else(|| Error::General("REALITY requires an X25519 key_share".into()))?;
        let reality_key = agreement::agree(
            &agreement::PrivateKey::from_private_key(&agreement::X25519, &self.server_private_key)
                .map_err(|_| Error::General("failed to parse REALITY X25519 private key".into()))?,
            agreement::UnparsedPublicKey::new(&agreement::X25519, client_key_share),
            aws_lc_rs::error::Unspecified,
            |secret| Ok::<Vec<u8>, aws_lc_rs::error::Unspecified>(Vec::from(secret)),
        )
        .map_err(super::unspecified_err)?;
        Ok(Some(derive_reality_auth_key(
            &reality_key,
            client_hello.client_random(),
        )?))
    }

    fn hash_config(&self, h: &mut dyn Hasher) {
        h.write(&self.version);
        h.write_usize(self.short_ids.len());
        for (short_id, short_id_len) in self
            .short_ids
            .iter()
            .zip(&self.short_id_lens)
        {
            h.write(&[*short_id_len as u8]);
            h.write(&short_id[..*short_id_len]);
        }
        h.write(&(self.server_private_key.len() as u64).to_be_bytes());
        h.write(&self.server_private_key);
        h.write(
            &self
                .max_time_skew
                .as_secs()
                .to_be_bytes(),
        );
    }
}

/// Returns a TLS1.3-only aws-lc-rs provider pinned to X25519 for REALITY client hellos.
///
/// REALITY session ID sealing currently relies on the 32-byte X25519 shared secret shape.
pub fn default_x25519_tls13_reality_provider() -> CryptoProvider {
    let mut provider = crate::DEFAULT_TLS13_PROVIDER.clone();
    provider.kx_groups = Cow::Borrowed(REALITY_X25519_KX_GROUPS);
    provider
}

/// Builds an aws-lc-rs backed REALITY session ID generator using HKDF-SHA256 and AES-256-GCM.
pub fn new_reality_session_id_generator(
    version: [u8; 3],
    short_id: &[u8],
    server_public_key: Vec<u8>,
    time_provider: Arc<dyn TimeProvider>,
) -> Result<Arc<dyn RealitySessionIdGenerator>, Error> {
    RealitySessionIdConfig::new(version, short_id, server_public_key)
        .with_time_provider(time_provider)
        .build_generator()
}

/// Installs an aws-lc-rs backed REALITY session ID generator onto a client config.
pub fn install_reality_session_id_generator(
    config: &mut ClientConfig,
    version: [u8; 3],
    short_id: &[u8],
    server_public_key: Vec<u8>,
    time_provider: Arc<dyn TimeProvider>,
) -> Result<(), Error> {
    RealitySessionIdConfig::new(version, short_id, server_public_key)
        .with_time_provider(time_provider)
        .install_into(config)
}

/// Installs a REALITY session ID generator from Xray-style text fields onto a client config.
pub fn install_reality_session_id_generator_from_xray_fields(
    config: &mut ClientConfig,
    version: [u8; 3],
    short_id: &str,
    public_key: &str,
) -> Result<(), Error> {
    RealitySessionIdConfig::from_xray_fields(version, short_id, public_key)?.install_into(config)
}

/// Builds a ready-to-use REALITY client config from binary fields.
pub fn build_reality_client_config(
    version: [u8; 3],
    short_id: &[u8],
    server_public_key: Vec<u8>,
    root_store: impl Into<Arc<RootCertStore>>,
) -> Result<ClientConfig, Error> {
    RealitySessionIdConfig::new(version, short_id, server_public_key)
        .build_client_config(root_store)
}

/// Builds a ready-to-use REALITY client config from Xray-style text fields.
pub fn build_reality_client_config_from_xray_fields(
    version: [u8; 3],
    short_id: &str,
    public_key: &str,
    root_store: impl Into<Arc<RootCertStore>>,
) -> Result<ClientConfig, Error> {
    RealitySessionIdConfig::build_client_config_from_xray_fields(
        version, short_id, public_key, root_store,
    )
}

/// Builds an aws-lc-rs backed REALITY client hello verifier using X25519, HKDF-SHA256, and AES-256-GCM.
pub fn new_reality_client_hello_verifier(
    version: [u8; 3],
    short_id: &[u8],
    server_private_key: Vec<u8>,
    time_provider: Arc<dyn TimeProvider>,
) -> Result<Arc<dyn ClientHelloVerifier>, Error> {
    RealityServerVerifierConfig::new(version, short_id, server_private_key)
        .with_time_provider(time_provider)
        .build_verifier()
}

/// Installs an aws-lc-rs backed REALITY client hello verifier onto a server config.
pub fn install_reality_client_hello_verifier(
    config: &mut ServerConfig,
    version: [u8; 3],
    short_id: &[u8],
    server_private_key: Vec<u8>,
    time_provider: Arc<dyn TimeProvider>,
) -> Result<(), Error> {
    RealityServerVerifierConfig::new(version, short_id, server_private_key)
        .with_time_provider(time_provider)
        .install_into(config)
}

/// Installs a REALITY client hello verifier from Xray-style text fields onto a server config.
pub fn install_reality_client_hello_verifier_from_xray_fields(
    config: &mut ServerConfig,
    version: [u8; 3],
    short_id: &str,
    private_key: &str,
) -> Result<(), Error> {
    RealityServerVerifierConfig::from_xray_fields(version, short_id, private_key)?
        .install_into(config)
}

fn decode_hex(input: &str, field_name: &str) -> Result<Vec<u8>, Error> {
    let input = input.trim();
    if input.len() % 2 != 0 {
        return Err(Error::General(format!(
            "{field_name} must contain an even number of hex digits"
        )));
    }

    let mut output = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let high = decode_hex_nibble(bytes[index], field_name)?;
        let low = decode_hex_nibble(bytes[index + 1], field_name)?;
        output.push((high << 4) | low);
        index += 2;
    }
    Ok(output)
}

fn decode_hex_nibble(byte: u8, field_name: &str) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::General(format!(
            "{field_name} contains a non-hex character"
        ))),
    }
}

fn decode_base64(input: &str, field_name: &str) -> Result<Vec<u8>, Error> {
    let input = input.trim().trim_end_matches('=');
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let remainder = input.len() % 4;
    if remainder == 1 {
        return Err(Error::General(format!("{field_name} is not valid base64")));
    }

    let mut output = Vec::with_capacity((input.len() * 3) / 4 + 3);
    let bytes = input.as_bytes();
    let mut index = 0;
    while index + 4 <= bytes.len() {
        let a = decode_base64_char(bytes[index], field_name)?;
        let b = decode_base64_char(bytes[index + 1], field_name)?;
        let c = decode_base64_char(bytes[index + 2], field_name)?;
        let d = decode_base64_char(bytes[index + 3], field_name)?;
        output.push((a << 2) | (b >> 4));
        output.push((b << 4) | (c >> 2));
        output.push((c << 6) | d);
        index += 4;
    }

    match bytes.len() - index {
        0 => {}
        2 => {
            let a = decode_base64_char(bytes[index], field_name)?;
            let b = decode_base64_char(bytes[index + 1], field_name)?;
            output.push((a << 2) | (b >> 4));
        }
        3 => {
            let a = decode_base64_char(bytes[index], field_name)?;
            let b = decode_base64_char(bytes[index + 1], field_name)?;
            let c = decode_base64_char(bytes[index + 2], field_name)?;
            output.push((a << 2) | (b >> 4));
            output.push((b << 4) | (c >> 2));
        }
        _ => {
            return Err(Error::General(format!("{field_name} is not valid base64")));
        }
    }

    Ok(output)
}

fn decode_base64_char(byte: u8, field_name: &str) -> Result<u8, Error> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' | b'-' => Ok(62),
        b'/' | b'_' => Ok(63),
        _ => Err(Error::General(format!(
            "{field_name} contains a non-base64 character"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec;
    use aws_lc_rs::agreement;
    use aws_lc_rs::encoding::{AsBigEndian, Curve25519SeedBin};
    use core::time::Duration;
    use pki_types::pem::PemObject;
    use pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
    use rustls::client::danger::{
        HandshakeSignatureValid, PeerVerified, ServerIdentity, ServerVerifier,
        SignatureVerificationInput,
    };
    use rustls::crypto::Identity;
    use rustls::crypto::kx::NamedGroup;
    use rustls::crypto::tls13::{Hkdf, HkdfUsingHmac};
    use rustls::server::ServerConnection;
    use rustls::{Connection, RootCertStore, ServerConfig};
    use rustls_test::{ErrorFromPeer, bytes_for, do_handshake, do_handshake_until_error};
    use std::eprintln;

    #[derive(Debug)]
    struct FixedTimeProvider(UnixTime);

    #[derive(Debug)]
    struct RejectingVerifier;

    impl ServerVerifier for RejectingVerifier {
        fn verify_identity(&self, _: &ServerIdentity<'_>) -> Result<PeerVerified, Error> {
            Err(Error::General("standard verifier fallback".into()))
        }

        fn verify_tls12_signature(
            &self,
            _: &SignatureVerificationInput<'_>,
        ) -> Result<HandshakeSignatureValid, Error> {
            Err(Error::General("unused test verifier".into()))
        }

        fn verify_tls13_signature(
            &self,
            _: &SignatureVerificationInput<'_>,
        ) -> Result<HandshakeSignatureValid, Error> {
            Err(Error::General("unused test verifier".into()))
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }
        fn request_ocsp_response(&self) -> bool {
            false
        }
        fn hash_config(&self, _: &mut dyn Hasher) {}
    }

    impl TimeProvider for FixedTimeProvider {
        fn current_time(&self) -> Option<UnixTime> {
            Some(self.0)
        }
    }

    fn first_client_hello_bytes(config: ClientConfig) -> Vec<u8> {
        let mut conn = Arc::new(config)
            .connect(ServerName::try_from("localhost").unwrap())
            .build()
            .unwrap();
        let mut bytes = Vec::new();
        conn.write_tls(&mut bytes).unwrap();
        bytes
    }

    fn client_hello_session_id(bytes: &[u8]) -> [u8; 32] {
        assert!(bytes.len() >= 76);
        assert_eq!(bytes[0], 22);
        assert_eq!(bytes[5], 1);
        assert_eq!(bytes[43], 32);

        bytes[44..76].try_into().unwrap()
    }

    struct ParsedClientHello {
        random: [u8; 32],
        session_id: [u8; 32],
        raw_client_hello: Vec<u8>,
        key_share: Vec<u8>,
    }

    fn parse_client_hello(bytes: &[u8]) -> ParsedClientHello {
        assert!(bytes.len() >= 9);
        assert_eq!(bytes[0], 22);

        let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        let handshake = &bytes[5..5 + record_len];
        assert_eq!(handshake[0], 1);

        let handshake_len = ((handshake[1] as usize) << 16)
            | ((handshake[2] as usize) << 8)
            | handshake[3] as usize;
        let body = &handshake[4..4 + handshake_len];

        let mut offset = 0;
        offset += 2;

        let mut random = [0u8; 32];
        random.copy_from_slice(&body[offset..offset + 32]);
        offset += 32;

        let session_id_len = body[offset] as usize;
        offset += 1;
        assert_eq!(session_id_len, 32);
        let session_id_offset = offset;

        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&body[offset..offset + session_id_len]);
        offset += session_id_len;

        let cipher_suites_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        offset += 2 + cipher_suites_len;

        let compression_methods_len = body[offset] as usize;
        offset += 1 + compression_methods_len;

        let extensions_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        offset += 2;
        let extensions_end = offset + extensions_len;

        let mut key_share = None;
        while offset < extensions_end {
            let extension_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
            let extension_len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
            offset += 4;
            let extension = &body[offset..offset + extension_len];
            offset += extension_len;

            if extension_type != 0x0033 {
                continue;
            }

            let client_shares_len = u16::from_be_bytes([extension[0], extension[1]]) as usize;
            assert_eq!(client_shares_len + 2, extension.len());
            let share_group = u16::from_be_bytes([extension[2], extension[3]]);
            assert_eq!(share_group, 0x001d);
            let share_len = u16::from_be_bytes([extension[4], extension[5]]) as usize;
            key_share = Some(extension[6..6 + share_len].to_vec());
        }

        let mut raw_client_hello = handshake.to_vec();
        let raw_session_id_offset = 4 + 2 + 32 + 1 + session_id_offset - 35;
        raw_client_hello[raw_session_id_offset..raw_session_id_offset + 32].fill(0);

        ParsedClientHello {
            random,
            session_id,
            raw_client_hello,
            key_share: key_share.expect("missing key_share extension"),
        }
    }

    #[test]
    fn aes256_gcm_reality_sealer_rejects_non_32_byte_key() {
        let err = Aes256GcmRealitySessionIdSealer
            .seal(&[0u8; 31], &[0u8; 12], &[], &[0u8; 16])
            .unwrap_err();

        assert!(matches!(err, Error::General(_)));
    }

    #[test]
    fn reality_auth_key_uses_the_connection_random() {
        let ecdh = [0x11; 32];
        let random_a = [0x22; 32];
        let mut random_b = random_a;
        random_b[0] ^= 1;
        let mut random_c = random_a;
        random_c[20] ^= 1;

        let auth_key_a = derive_reality_auth_key(&ecdh, &random_a).unwrap();
        assert_eq!(
            auth_key_a,
            derive_reality_auth_key(&ecdh, &random_a).unwrap()
        );
        assert_ne!(
            auth_key_a,
            derive_reality_auth_key(&ecdh, &random_b).unwrap()
        );
        assert_eq!(
            auth_key_a,
            derive_reality_auth_key(&ecdh, &random_c).unwrap()
        );
    }

    #[test]
    fn reality_certificate_hmac_accepts_only_the_matching_auth_key() {
        let auth_key = derive_reality_auth_key(&[0x11; 32], &[0x22; 32]).unwrap();
        let wrong_auth_key = derive_reality_auth_key(&[0x33; 32], &[0x22; 32]).unwrap();
        let public_key = [0x44; 32];
        let signature = reality_certificate_signature(&auth_key, &public_key);

        assert!(verify_reality_certificate_signature(
            &auth_key,
            &public_key,
            &signature,
        ));
        assert!(!verify_reality_certificate_signature(
            &wrong_auth_key,
            &public_key,
            &signature,
        ));
    }

    #[test]
    fn reality_certificate_hmac_rejects_modified_or_short_signatures() {
        let auth_key = [0x11; 32];
        let public_key = [0x22; 32];
        let mut signature = reality_certificate_signature(&auth_key, &public_key);
        signature[0] ^= 1;

        assert!(!verify_reality_certificate_signature(
            &auth_key,
            &public_key,
            &signature,
        ));
        assert!(!verify_reality_certificate_signature(
            &auth_key,
            &public_key,
            &signature[..63],
        ));
    }

    #[test]
    fn ordinary_p256_certificate_is_not_treated_as_reality_certificate() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let certificate = params.self_signed(&key_pair).unwrap();

        let fields =
            reality_certificate_fields(&CertificateDer::from(certificate.der().to_vec())).unwrap();

        assert!(fields.is_none());
    }

    #[test]
    fn reality_server_verifier_accepts_authenticated_ed25519_certificate() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let certificate = params.self_signed(&key_pair).unwrap();
        let mut cert_der = certificate.der().to_vec();
        let auth_key = [0x11; 32];
        let public_key: [u8; 32] = key_pair
            .public_key_raw()
            .try_into()
            .unwrap();
        let signature = reality_certificate_signature(&auth_key, &public_key);
        replace_outer_signature(&mut cert_der, &signature).unwrap();
        eprintln!("cert prefix: {:02x?}", &cert_der[..80]);
        let fields = reality_certificate_fields(&CertificateDer::from(cert_der.clone())).unwrap();
        assert!(fields.is_some(), "Ed25519 certificate was not recognized");

        let identity = Identity::from_cert_chain(vec![CertificateDer::from(cert_der)]).unwrap();
        let server_name = ServerName::try_from("localhost").unwrap();
        let fallback = Arc::new(RejectingVerifier);
        let verifier = RealityServerVerifier::new(fallback);
        assert!(
            verifier
                .verify_identity(
                    &ServerIdentity::new(&identity, &server_name, UnixTime::now(),)
                        .with_reality_auth_key(&auth_key)
                )
                .is_ok()
        );

        let wrong_auth_key = [0x22; 32];
        assert!(
            verifier
                .verify_identity(
                    &ServerIdentity::new(&identity, &server_name, UnixTime::now(),)
                        .with_reality_auth_key(&wrong_auth_key)
                )
                .is_err()
        );

        let other_server_name = ServerName::try_from("example.com").unwrap();
        assert!(
            verifier
                .verify_identity(
                    &ServerIdentity::new(&identity, &other_server_name, UnixTime::now(),)
                        .with_reality_auth_key(&auth_key)
                )
                .is_err()
        );
    }

    #[test]
    fn install_helper_sets_a_sealed_client_hello_session_id() {
        let server_private_key = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let server_public_key = server_private_key
            .compute_public_key()
            .unwrap();

        let mut config = ClientConfig::builder(Arc::new(default_x25519_tls13_reality_provider()))
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth()
            .unwrap();
        install_reality_session_id_generator(
            &mut config,
            [1, 2, 3],
            &[0xaa, 0xbb, 0xcc],
            server_public_key.as_ref().to_vec(),
            Arc::new(FixedTimeProvider(UnixTime::since_unix_epoch(
                Duration::from_secs(0x01020304),
            ))),
        )
        .unwrap();

        let session_id = client_hello_session_id(&first_client_hello_bytes(config));

        assert_ne!(session_id, [0u8; 32]);
        assert_ne!(session_id[..3], [1, 2, 3]);
        assert_ne!(
            session_id,
            [
                1, 2, 3, 0, 1, 2, 3, 4, 0xaa, 0xbb, 0xcc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn config_object_installs_a_sealed_client_hello_session_id() {
        let server_private_key = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let server_public_key = server_private_key
            .compute_public_key()
            .unwrap();

        let mut config = ClientConfig::builder(Arc::new(default_x25519_tls13_reality_provider()))
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth()
            .unwrap();
        RealitySessionIdConfig::new(
            [1, 2, 3],
            [0xaa, 0xbb, 0xcc],
            server_public_key.as_ref().to_vec(),
        )
        .with_time_provider(Arc::new(FixedTimeProvider(UnixTime::since_unix_epoch(
            Duration::from_secs(0x01020304),
        ))))
        .install_into(&mut config)
        .unwrap();

        let session_id = client_hello_session_id(&first_client_hello_bytes(config));

        assert_ne!(session_id, [0u8; 32]);
        assert_ne!(session_id[..3], [1, 2, 3]);
    }

    #[test]
    fn config_object_builds_reality_client_config() {
        let server_private_key = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let server_public_key = server_private_key
            .compute_public_key()
            .unwrap();

        let config = RealitySessionIdConfig::new(
            [1, 2, 3],
            [0xaa, 0xbb, 0xcc],
            server_public_key.as_ref().to_vec(),
        )
        .with_time_provider(Arc::new(FixedTimeProvider(UnixTime::since_unix_epoch(
            Duration::from_secs(0x01020304),
        ))))
        .build_client_config(RootCertStore::empty())
        .unwrap();

        let parsed = parse_client_hello(&first_client_hello_bytes(config));

        assert_ne!(parsed.session_id, [0u8; 32]);
        assert_eq!(parsed.key_share.len(), 32);
    }

    #[test]
    fn text_fields_build_reality_client_config() {
        let server_private_key = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let server_public_key = server_private_key
            .compute_public_key()
            .unwrap();
        let public_key_b64url = encode_base64url_unpadded(server_public_key.as_ref());

        let config =
            RealitySessionIdConfig::from_text_fields([1, 2, 3], "aabbcc", &public_key_b64url)
                .unwrap()
                .with_time_provider(Arc::new(FixedTimeProvider(UnixTime::since_unix_epoch(
                    Duration::from_secs(0x01020304),
                ))))
                .build_client_config(RootCertStore::empty())
                .unwrap();

        let parsed = parse_client_hello(&first_client_hello_bytes(config));

        assert_ne!(parsed.session_id, [0u8; 32]);
        assert_eq!(parsed.key_share.len(), 32);
    }

    #[test]
    fn server_verifier_accepts_multiple_short_id_configurations() {
        let server_private_key = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let config = RealityServerVerifierConfig::new(
            [1, 2, 3],
            [0xaa, 0xbb, 0xcc],
            x25519_private_key_bytes(&server_private_key),
        )
        .with_short_ids([vec![0xaa, 0xbb, 0xcc], vec![0x11, 0x22]])
        .build_verifier();

        assert!(config.is_ok());
    }

    #[test]
    fn server_verifier_rejects_empty_short_id_list() {
        let server_private_key = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let result = RealityServerVerifierConfig::new(
            [1, 2, 3],
            [0xaa, 0xbb, 0xcc],
            x25519_private_key_bytes(&server_private_key),
        )
        .with_short_ids(core::iter::empty::<Vec<u8>>())
        .build_verifier();

        assert!(matches!(result, Err(Error::General(_))));
    }

    #[test]
    fn xray_fields_build_reality_client_config() {
        let server_private_key = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let server_public_key = server_private_key
            .compute_public_key()
            .unwrap();
        let public_key_b64url = encode_base64url_unpadded(server_public_key.as_ref());

        let config = RealitySessionIdConfig::build_client_config_from_xray_fields(
            [1, 2, 3],
            "aabbcc",
            &public_key_b64url,
            RootCertStore::empty(),
        )
        .unwrap();

        let parsed = parse_client_hello(&first_client_hello_bytes(config));

        assert_ne!(parsed.session_id, [0u8; 32]);
        assert_eq!(parsed.key_share.len(), 32);
    }

    #[test]
    fn module_level_builder_builds_reality_client_config() {
        let server_private_key = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let server_public_key = server_private_key
            .compute_public_key()
            .unwrap();

        let config = build_reality_client_config(
            [1, 2, 3],
            &[0xaa, 0xbb, 0xcc],
            server_public_key.as_ref().to_vec(),
            RootCertStore::empty(),
        )
        .unwrap();

        let parsed = parse_client_hello(&first_client_hello_bytes(config));

        assert_ne!(parsed.session_id, [0u8; 32]);
        assert_eq!(parsed.key_share.len(), 32);
    }

    #[test]
    fn config_rejects_non_x25519_public_key_length() {
        let err = RealitySessionIdConfig::new([1, 2, 3], [0xaa, 0xbb, 0xcc], vec![0u8; 31])
            .build_generator()
            .unwrap_err();

        match err {
            Error::General(message) => {
                assert!(message.contains("32 bytes"));
                assert!(message.contains("X25519"));
            }
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn xray_fields_reject_invalid_public_key_text() {
        let err = RealitySessionIdConfig::from_xray_fields([1, 2, 3], "aabbcc", "***").unwrap_err();

        match err {
            Error::General(message) => {
                assert!(message.contains("server_public_key"));
                assert!(message.contains("base64"));
            }
            other => panic!("unexpected error {other:?}"),
        }
    }

    fn encode_base64url_unpadded(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        let mut output = String::with_capacity((bytes.len() * 4).div_ceil(3));
        let mut index = 0;
        while index + 3 <= bytes.len() {
            let a = bytes[index];
            let b = bytes[index + 1];
            let c = bytes[index + 2];
            output.push(ALPHABET[(a >> 2) as usize] as char);
            output.push(ALPHABET[((a & 0x03) << 4 | (b >> 4)) as usize] as char);
            output.push(ALPHABET[((b & 0x0f) << 2 | (c >> 6)) as usize] as char);
            output.push(ALPHABET[(c & 0x3f) as usize] as char);
            index += 3;
        }

        match bytes.len() - index {
            0 => {}
            1 => {
                let a = bytes[index];
                output.push(ALPHABET[(a >> 2) as usize] as char);
                output.push(ALPHABET[((a & 0x03) << 4) as usize] as char);
            }
            2 => {
                let a = bytes[index];
                let b = bytes[index + 1];
                output.push(ALPHABET[(a >> 2) as usize] as char);
                output.push(ALPHABET[((a & 0x03) << 4 | (b >> 4)) as usize] as char);
                output.push(ALPHABET[((b & 0x0f) << 2) as usize] as char);
            }
            _ => unreachable!(),
        }

        output
    }

    fn x25519_private_key_bytes(private_key: &agreement::PrivateKey) -> Vec<u8> {
        let raw_private_key: Curve25519SeedBin<'_> = private_key.as_be_bytes().unwrap();
        raw_private_key.as_ref().to_vec()
    }

    fn test_root_store() -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(bytes_for("rsa-2048", "ca.der")))
            .unwrap();
        roots
    }

    fn test_server_identity() -> Arc<Identity<'static>> {
        Arc::new(
            Identity::from_cert_chain(
                CertificateDer::pem_slice_iter(bytes_for("rsa-2048", "end.fullchain"))
                    .map(|result| result.unwrap())
                    .collect(),
            )
            .unwrap(),
        )
    }

    fn test_server_key() -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_reader(&mut bytes_for("rsa-2048", "end.key")).unwrap()
    }

    fn test_reality_server_config(
        version: [u8; 3],
        short_id: &[u8],
        server_private_key: Vec<u8>,
        time_provider: Arc<dyn TimeProvider>,
    ) -> ServerConfig {
        let mut config = ServerConfig::builder(Arc::new(default_x25519_tls13_reality_provider()))
            .with_no_client_auth()
            .with_single_cert(test_server_identity(), test_server_key())
            .unwrap();
        RealityServerVerifierConfig::new(version, short_id, server_private_key)
            .with_time_provider(time_provider)
            .install_into(&mut config)
            .unwrap();
        config
    }

    #[test]
    fn installed_helper_session_id_decrypts_to_expected_header() {
        let server_private_key = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let server_public_key = server_private_key
            .compute_public_key()
            .unwrap();

        let mut config = ClientConfig::builder(Arc::new(default_x25519_tls13_reality_provider()))
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth()
            .unwrap();
        install_reality_session_id_generator(
            &mut config,
            [1, 2, 3],
            &[0xaa, 0xbb, 0xcc],
            server_public_key.as_ref().to_vec(),
            Arc::new(FixedTimeProvider(UnixTime::since_unix_epoch(
                Duration::from_secs(0x01020304),
            ))),
        )
        .unwrap();

        let parsed = parse_client_hello(&first_client_hello_bytes(config));

        let peer_key = agreement::UnparsedPublicKey::new(&agreement::X25519, &parsed.key_share);
        let reality_key = agreement::agree(&server_private_key, peer_key, (), |secret| {
            Ok::<Vec<u8>, ()>(Vec::from(secret))
        })
        .unwrap();
        let expander = HkdfUsingHmac(&crate::hmac::HMAC_SHA256)
            .extract_from_secret(Some(&parsed.random[..20]), &reality_key);
        let mut sealing_key = vec![0u8; reality_key.len()];
        expander
            .expand_slice(&[b"REALITY"], &mut sealing_key)
            .unwrap();

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&parsed.random[20..32]);
        let mut decrypted = parsed.session_id.to_vec();
        let plaintext =
            LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &sealing_key).unwrap())
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(parsed.raw_client_hello.as_slice()),
                    &mut decrypted,
                )
                .unwrap();

        assert_eq!(
            plaintext,
            &[1, 2, 3, 0, 1, 2, 3, 4, 0xaa, 0xbb, 0xcc, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn default_reality_provider_pins_x25519() {
        let provider = default_x25519_tls13_reality_provider();

        assert!(provider.tls12_cipher_suites.is_empty());
        assert_eq!(provider.kx_groups.len(), 1);
        assert_eq!(provider.kx_groups[0].name(), NamedGroup::X25519);
    }

    #[test]
    fn installed_server_verifier_accepts_matching_reality_handshake() {
        let server_private_key = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let server_public_key = server_private_key
            .compute_public_key()
            .unwrap();
        let fixed_time = Arc::new(FixedTimeProvider(UnixTime::since_unix_epoch(
            Duration::from_secs(0x01020304),
        )));

        let client_config = RealitySessionIdConfig::new(
            [1, 2, 3],
            [0xaa, 0xbb, 0xcc],
            server_public_key.as_ref().to_vec(),
        )
        .with_time_provider(fixed_time.clone())
        .build_client_config(test_root_store())
        .unwrap();
        let server_config = test_reality_server_config(
            [1, 2, 3],
            &[0xaa, 0xbb, 0xcc],
            x25519_private_key_bytes(&server_private_key),
            fixed_time,
        );

        let mut client = Arc::new(client_config)
            .connect(ServerName::try_from("example.com").unwrap())
            .build()
            .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        do_handshake(&mut client, &mut server);
    }

    #[test]
    fn installed_server_verifier_rejects_wrong_short_id() {
        let server_private_key = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        let server_public_key = server_private_key
            .compute_public_key()
            .unwrap();
        let fixed_time = Arc::new(FixedTimeProvider(UnixTime::since_unix_epoch(
            Duration::from_secs(0x01020304),
        )));

        let client_config = RealitySessionIdConfig::new(
            [1, 2, 3],
            [0xaa, 0xbb, 0xcc],
            server_public_key.as_ref().to_vec(),
        )
        .with_time_provider(fixed_time.clone())
        .build_client_config(test_root_store())
        .unwrap();
        let server_config = test_reality_server_config(
            [1, 2, 3],
            &[0xde, 0xad, 0xbe, 0xef],
            x25519_private_key_bytes(&server_private_key),
            fixed_time,
        );

        let mut client = Arc::new(client_config)
            .connect(ServerName::try_from("localhost").unwrap())
            .build()
            .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server).unwrap_err();
        assert!(matches!(
            err,
            ErrorFromPeer::Server(Error::General(message)) if message.contains("short_id")
        ));
    }
}
