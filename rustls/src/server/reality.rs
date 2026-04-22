use alloc::vec::Vec;

use core::fmt;

use pki_types::DnsName;

use super::hs::ClientHelloInput;
use crate::crypto::kx::NamedGroup;
use crate::enums::ProtocolVersion;
use crate::error::Error;
use crate::msgs::MessagePayload;

/// REALITY-specific view of an incoming client hello.
pub struct RealityClientHello<'a> {
    input: &'a ClientHelloInput<'a>,
    sni: Option<&'a DnsName<'static>>,
    version: ProtocolVersion,
    raw_client_hello: Option<Vec<u8>>,
}

impl fmt::Debug for RealityClientHello<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityClientHello")
            .field("version", &self.version)
            .field("has_sni", &self.sni.is_some())
            .field(
                "session_id_len",
                &self
                    .input
                    .client_hello
                    .session_id
                    .as_ref()
                    .len(),
            )
            .field("has_raw_client_hello", &self.raw_client_hello.is_some())
            .finish()
    }
}

impl<'a> RealityClientHello<'a> {
    pub(crate) fn new(
        input: &'a ClientHelloInput<'a>,
        sni: Option<&'a DnsName<'static>>,
        version: ProtocolVersion,
    ) -> Result<Self, Error> {
        let raw_client_hello = zero_session_id_client_hello(input)?;
        Ok(Self {
            input,
            sni,
            version,
            raw_client_hello,
        })
    }

    /// Returns the negotiated TLS version path being processed.
    pub fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the validated SNI, if one was accepted.
    pub fn server_name(&self) -> Option<&DnsName<'_>> {
        self.sni
            .map(|name| name as &DnsName<'_>)
    }

    /// Returns the client random from the incoming hello.
    pub fn client_random(&self) -> &[u8; 32] {
        &self.input.client_hello.random.0
    }

    /// Returns the raw incoming session ID bytes.
    pub fn session_id(&self) -> &[u8] {
        self.input
            .client_hello
            .session_id
            .as_ref()
    }

    /// Returns a pre-encoded client hello with the session ID bytes zeroed in place.
    pub fn raw_client_hello(&self) -> Option<&[u8]> {
        self.raw_client_hello.as_deref()
    }

    /// Returns the offered key share for the requested group, if present.
    pub fn key_share(&self, group: NamedGroup) -> Option<&[u8]> {
        self.input
            .client_hello
            .key_shares
            .as_ref()?
            .iter()
            .find(|share| share.group == group)
            .map(|share| share.payload.bytes())
    }
}

fn zero_session_id_client_hello(input: &ClientHelloInput<'_>) -> Result<Option<Vec<u8>>, Error> {
    if input
        .client_hello
        .session_id
        .as_ref()
        .len()
        != 32
    {
        return Ok(None);
    }

    let MessagePayload::Handshake { encoded, .. } = &input.message.payload else {
        return Err(Error::Unreachable(
            "server REALITY hook invoked on non-ClientHello",
        ));
    };

    let mut raw_client_hello = encoded.bytes().to_vec();
    raw_client_hello[39..71].fill(0);
    Ok(Some(raw_client_hello))
}
