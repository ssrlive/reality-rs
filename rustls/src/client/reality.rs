use alloc::vec;
use alloc::vec::Vec;

use core::any::Any;
use core::convert::TryFrom;
use core::fmt;
use core::hash::{Hash, Hasher};

use pki_types::ServerName;

use super::config::{ClientHelloCallback, ClientHelloCallbackContext};
use crate::DynHasher;
use crate::crypto::hmac;
use crate::crypto::kx::ActiveKeyExchange;
use crate::crypto::tls13::{Hkdf, HkdfUsingHmac};
use crate::error::{ApiMisuse, Error};
use crate::sync::Arc;
use crate::time_provider::TimeProvider;

/// Generates the 32-byte session ID used by a REALITY-style client hello.
pub trait RealitySessionIdGenerator: fmt::Debug + Send + Sync + Any {
    /// Derive the session ID for the outgoing `ClientHello`.
    fn generate_session_id(&self, hello: &RealityClientHello<'_>) -> Result<[u8; 32], Error>;

    /// Include generator configuration in the client config hash.
    fn hash_config(&self, _h: &mut dyn Hasher) {}
}

/// Seals a 16-byte REALITY header into the 32-byte session ID ciphertext placed on the wire.
pub trait RealitySessionIdSealer: fmt::Debug + Send + Sync + Any {
    /// Seal the provided 16-byte plaintext header using the derived key, nonce, and raw client hello.
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8; 16],
    ) -> Result<[u8; 32], Error>;

    /// Include sealer configuration in the client config hash.
    fn hash_config(&self, _h: &mut dyn Hasher) {}
}

/// REALITY-specific view of a pending client hello.
pub struct RealityClientHello<'a> {
    server_name: &'a ServerName<'static>,
    client_random: &'a [u8; 32],
    active_key_exchange: &'a dyn ActiveKeyExchange,
    raw_client_hello: Option<&'a [u8]>,
    is_retry: bool,
}

impl<'a> RealityClientHello<'a> {
    pub(crate) fn new(
        server_name: &'a ServerName<'static>,
        client_random: &'a [u8; 32],
        active_key_exchange: &'a dyn ActiveKeyExchange,
        raw_client_hello: Option<&'a [u8]>,
        is_retry: bool,
    ) -> Self {
        Self {
            server_name,
            client_random,
            active_key_exchange,
            raw_client_hello,
            is_retry,
        }
    }

    /// Returns the server name associated with this connection attempt.
    pub fn server_name(&self) -> &ServerName<'static> {
        self.server_name
    }

    /// Returns the client random that will be sent in this hello.
    pub fn client_random(&self) -> &[u8; 32] {
        self.client_random
    }

    /// Returns the in-progress key exchange for this hello.
    pub fn active_key_exchange(&self) -> &dyn ActiveKeyExchange {
        self.active_key_exchange
    }

    /// Returns a pre-encoded `ClientHello` snapshot with a zero-filled 32-byte session ID placeholder.
    pub fn raw_client_hello(&self) -> Option<&[u8]> {
        self.raw_client_hello
    }

    /// Optionally derives a REALITY-specific shared key for the given server static public key.
    pub fn extract_reality_key(&self, server_pub_key: &[u8]) -> Option<Vec<u8>> {
        self.active_key_exchange
            .extract_reality_key(server_pub_key)
    }

    /// Returns whether this hello is being emitted after a `HelloRetryRequest`.
    pub fn is_retry(&self) -> bool {
        self.is_retry
    }
}

#[derive(Debug)]
pub(crate) struct RealityClientHelloCallback {
    generator: Arc<dyn RealitySessionIdGenerator>,
}

/// A minimal REALITY session ID generator that writes the plaintext header layout used before sealing.
///
/// This does not perform AEAD sealing. It is intended as the bridge between the current hook point and
/// a later full REALITY implementation that uses [`RealityClientHello::raw_client_hello()`] and
/// [`RealityClientHello::extract_reality_key()`].
#[derive(Debug)]
pub struct PlaintextRealitySessionIdGenerator {
    version: [u8; 3],
    short_id: [u8; 8],
    short_id_len: usize,
    time_provider: Arc<dyn TimeProvider>,
}

/// A REALITY session ID generator that derives a sealing key with HKDF and delegates AEAD sealing.
pub struct SealingRealitySessionIdGenerator {
    version: [u8; 3],
    short_id: [u8; 8],
    short_id_len: usize,
    time_provider: Arc<dyn TimeProvider>,
    server_public_key: Vec<u8>,
    hmac: &'static dyn hmac::Hmac,
    sealer: Arc<dyn RealitySessionIdSealer>,
}

impl fmt::Debug for SealingRealitySessionIdGenerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealingRealitySessionIdGenerator")
            .field("version", &self.version)
            .field("short_id_len", &self.short_id_len)
            .field("server_public_key_len", &self.server_public_key.len())
            .finish()
    }
}

impl PlaintextRealitySessionIdGenerator {
    /// Creates a generator with the provided 3-byte version tag and short ID.
    pub fn new(
        version: [u8; 3],
        short_id: &[u8],
        time_provider: Arc<dyn TimeProvider>,
    ) -> Result<Self, Error> {
        if short_id.len() > 8 {
            return Err(Error::ApiMisuse(ApiMisuse::RealityShortIdTooLong {
                actual: short_id.len(),
                maximum: 8,
            }));
        }

        let mut fixed_short_id = [0u8; 8];
        fixed_short_id[..short_id.len()].copy_from_slice(short_id);
        Ok(Self {
            version,
            short_id: fixed_short_id,
            short_id_len: short_id.len(),
            time_provider,
        })
    }
}

impl SealingRealitySessionIdGenerator {
    /// Creates a REALITY sealing generator.
    ///
    /// `hmac` should be an implementation of HMAC-SHA256 to match Xray/REALITY.
    pub fn new(
        version: [u8; 3],
        short_id: &[u8],
        server_public_key: Vec<u8>,
        time_provider: Arc<dyn TimeProvider>,
        hmac: &'static dyn hmac::Hmac,
        sealer: Arc<dyn RealitySessionIdSealer>,
    ) -> Result<Self, Error> {
        if short_id.len() > 8 {
            return Err(Error::ApiMisuse(ApiMisuse::RealityShortIdTooLong {
                actual: short_id.len(),
                maximum: 8,
            }));
        }

        let mut fixed_short_id = [0u8; 8];
        fixed_short_id[..short_id.len()].copy_from_slice(short_id);
        Ok(Self {
            version,
            short_id: fixed_short_id,
            short_id_len: short_id.len(),
            time_provider,
            server_public_key,
            hmac,
            sealer,
        })
    }
}

impl RealitySessionIdGenerator for PlaintextRealitySessionIdGenerator {
    fn generate_session_id(&self, hello: &RealityClientHello<'_>) -> Result<[u8; 32], Error> {
        let current_time = self
            .time_provider
            .current_time()
            .ok_or(Error::FailedToGetCurrentTime)?;
        let mut session_id = [0u8; 32];
        session_id[..3].copy_from_slice(&self.version);
        session_id[3] = 0;
        let timestamp = u32::try_from(current_time.as_secs()).unwrap_or(u32::MAX);
        session_id[4..8].copy_from_slice(&timestamp.to_be_bytes());
        session_id[8..8 + self.short_id_len].copy_from_slice(&self.short_id[..self.short_id_len]);

        let _ = hello.raw_client_hello();
        Ok(session_id)
    }

    fn hash_config(&self, h: &mut dyn Hasher) {
        h.write(&self.version);
        h.write(&[self.short_id_len as u8]);
        h.write(&self.short_id[..self.short_id_len]);
    }
}

impl RealitySessionIdGenerator for SealingRealitySessionIdGenerator {
    fn generate_session_id(&self, hello: &RealityClientHello<'_>) -> Result<[u8; 32], Error> {
        let raw_client_hello = hello
            .raw_client_hello()
            .ok_or(Error::ApiMisuse(
                ApiMisuse::RealitySealingGeneratorRequiresRawClientHello,
            ))?;
        let reality_key = hello
            .extract_reality_key(&self.server_public_key)
            .ok_or(Error::ApiMisuse(
                ApiMisuse::RealitySealingGeneratorRequiresRealityKey,
            ))?;

        let current_time = self
            .time_provider
            .current_time()
            .ok_or(Error::FailedToGetCurrentTime)?;
        let mut header = [0u8; 16];
        header[..3].copy_from_slice(&self.version);
        header[3] = 0;
        let timestamp = u32::try_from(current_time.as_secs()).unwrap_or(u32::MAX);
        header[4..8].copy_from_slice(&timestamp.to_be_bytes());
        header[8..8 + self.short_id_len].copy_from_slice(&self.short_id[..self.short_id_len]);

        let expander = HkdfUsingHmac(self.hmac)
            .extract_from_secret(Some(&hello.client_random()[..20]), &reality_key);
        let mut sealing_key = vec![0u8; reality_key.len()];
        expander
            .expand_slice(&[b"REALITY"], &mut sealing_key)
            .map_err(|_| Error::Unreachable("REALITY HKDF output length rejected"))?;

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&hello.client_random()[20..32]);

        self.sealer
            .seal(&sealing_key, &nonce, raw_client_hello, &header)
    }

    fn hash_config(&self, h: &mut dyn Hasher) {
        h.write(&self.version);
        h.write(&[self.short_id_len as u8]);
        h.write(&self.short_id[..self.short_id_len]);
        h.write(&(self.server_public_key.len() as u64).to_be_bytes());
        h.write(&self.server_public_key);
        h.write(&(self.hmac.hash_output_len() as u64).to_be_bytes());
        self.sealer
            .type_id()
            .hash(&mut DynHasher(h));
        self.sealer.hash_config(h);
    }
}

impl RealityClientHelloCallback {
    pub(crate) fn new(generator: Arc<dyn RealitySessionIdGenerator>) -> Self {
        Self { generator }
    }
}

impl ClientHelloCallback for RealityClientHelloCallback {
    fn modify_client_hello(&self, hello: &mut ClientHelloCallbackContext<'_>) -> Result<(), Error> {
        let Some(active_key_exchange) = hello.active_key_exchange() else {
            return Err(Error::ApiMisuse(
                ApiMisuse::RealitySessionIdGeneratorRequiresKeyShare,
            ));
        };

        let reality_hello = RealityClientHello::new(
            hello.server_name(),
            hello.client_random(),
            active_key_exchange,
            hello.raw_client_hello(),
            hello.is_retry(),
        );
        let session_id = self
            .generator
            .generate_session_id(&reality_hello)?;
        hello.set_session_id(&session_id)
    }

    fn hash_config(&self, h: &mut dyn Hasher) {
        self.generator
            .type_id()
            .hash(&mut DynHasher(h));
        self.generator.hash_config(h);
    }
}
