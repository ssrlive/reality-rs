use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use core::fmt;

use pki_types::DnsName;

use super::hs::ClientHelloInput;
use crate::crypto::kx::NamedGroup;
use crate::enums::ProtocolVersion;
use crate::error::Error;
use crate::msgs::MessagePayload;

const MAX_REALITY_CLIENT_HELLO_WIRE_SIZE: usize = 128 * 1024;

/// A complete TLS ClientHello collected from one or more handshake records.
///
/// The original record bytes are retained for REALITY's decoy ServerHello
/// probe. The parsed handshake fields are also available for verification.
#[derive(Debug)]
#[non_exhaustive]
pub struct RealityClientHelloProbe {
    handshake: Vec<u8>,
    wire: Vec<u8>,
    random: [u8; 32],
    session_id: Vec<u8>,
    raw_client_hello: Vec<u8>,
    x25519_key_share: Vec<u8>,
    server_name: Option<String>,
}

/// The protocol-level outcome after trying to obtain the SNI target's ServerHello.
#[derive(Debug)]
#[non_exhaustive]
pub enum RealityServerHelloAction {
    /// Continue the REALITY handshake using this unframed ServerHello template.
    UseTemplate(Vec<u8>),
    /// Pass the untouched client connection through to its SNI target.
    Fallback {
        /// Parsed SNI, if the ClientHello contained one.
        server_name: Option<String>,
        /// Why a target ServerHello could not be used, if a probe was attempted.
        probe_error: Option<Error>,
    },
}

impl RealityClientHelloProbe {
    /// Collects and parses a complete ClientHello from TLS handshake records.
    ///
    /// Returns `Ok(None)` while the supplied bytes contain only a partial
    /// record or handshake. `Err` indicates malformed TLS or ClientHello data.
    pub fn from_tls_records(bytes: &[u8]) -> Result<Option<Self>, Error> {
        let mut offset = 0;
        let mut handshake = Vec::new();
        let mut expected_len = None;

        while offset < bytes.len() {
            if bytes.len() - offset < 5 {
                return Ok(None);
            }
            let header = &bytes[offset..offset + 5];
            offset += 5;
            if header[0] != 22 {
                return Err(reality_parse_error("not a handshake record"));
            }
            let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            if bytes.len() - offset < record_len {
                return Ok(None);
            }
            handshake.extend_from_slice(&bytes[offset..offset + record_len]);
            offset += record_len;

            if expected_len.is_none() && handshake.len() >= 4 {
                if handshake[0] != 1 {
                    return Err(reality_parse_error("not a ClientHello"));
                }
                let client_hello_len = ((handshake[1] as usize) << 16)
                    | ((handshake[2] as usize) << 8)
                    | handshake[3] as usize;
                let total_len = client_hello_len
                    .checked_add(4)
                    .ok_or_else(|| reality_parse_error("ClientHello length overflow"))?;
                if total_len > MAX_REALITY_CLIENT_HELLO_WIRE_SIZE {
                    return Err(reality_parse_error("ClientHello exceeds maximum size"));
                }
                expected_len = Some(total_len);
            }

            if let Some(expected_len) = expected_len {
                if handshake.len() >= expected_len {
                    handshake.truncate(expected_len);
                    let parsed = parse_reality_client_hello(&handshake)?;
                    return Ok(Some(Self {
                        handshake,
                        wire: bytes[..offset].to_vec(),
                        random: parsed.random,
                        session_id: parsed.session_id,
                        raw_client_hello: parsed.raw_client_hello,
                        x25519_key_share: parsed.x25519_key_share,
                        server_name: parsed.server_name,
                    }));
                }
            }
        }

        Ok(None)
    }

    /// Returns the encoded ClientHello handshake message, without TLS records.
    pub fn handshake(&self) -> &[u8] {
        &self.handshake
    }

    /// Returns the original TLS record bytes containing the ClientHello.
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// Returns the ClientHello random.
    pub fn random(&self) -> &[u8; 32] {
        &self.random
    }

    /// Returns the raw ClientHello session ID.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Returns the ClientHello encoding with session ID bytes zeroed.
    pub fn raw_client_hello(&self) -> &[u8] {
        &self.raw_client_hello
    }

    /// Returns the X25519 key share, if one was offered.
    pub fn x25519_key_share(&self) -> &[u8] {
        &self.x25519_key_share
    }

    /// Returns the normalized SNI, if present.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// Returns the ClientHello SNI only when it matches a configured target.
    pub fn server_name_if_allowed<'a>(
        &'a self,
        allowed_server_names: &[String],
    ) -> Option<&'a str> {
        let server_name = self.server_name()?;
        allowed_server_names
            .iter()
            .any(|allowed| allowed == server_name)
            .then_some(server_name)
    }

    /// Obtains and validates the SNI target's ServerHello for this ClientHello.
    ///
    /// The callback owns target connection and I/O. It is called only when the
    /// ClientHello contains an allowlisted SNI, and must return one complete
    /// TLS record. The result explicitly selects either the template or the
    /// protocol's direct SNI fallback path.
    pub fn fetch_server_hello_or_fallback<F>(
        &self,
        allowed_server_names: &[String],
        fetch_server_hello: F,
    ) -> RealityServerHelloAction
    where
        F: FnOnce(&str, &[u8]) -> Result<Vec<u8>, Error>,
    {
        let Some(server_name) = self.server_name_if_allowed(allowed_server_names) else {
            return RealityServerHelloAction::Fallback {
                server_name: self.server_name.clone(),
                probe_error: None,
            };
        };
        match fetch_server_hello(server_name, self.wire())
            .and_then(|record| Self::parse_server_hello_record(&record).map(<[u8]>::to_vec))
        {
            Ok(template) => RealityServerHelloAction::UseTemplate(template),
            Err(probe_error) => RealityServerHelloAction::Fallback {
                server_name: Some(server_name.to_string()),
                probe_error: Some(probe_error),
            },
        }
    }

    /// Validates one TLS record containing a ServerHello and returns its
    /// encoded handshake message without the record header.
    pub fn parse_server_hello_record(record: &[u8]) -> Result<&[u8], Error> {
        if record.len() < 5 {
            return Err(reality_parse_error("truncated TLS record header"));
        }
        if record[0] != 22 {
            return Err(reality_parse_error(
                "destination did not send a TLS handshake record",
            ));
        }
        let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        if !(4..=18_432).contains(&record_len) {
            return Err(reality_parse_error(
                "destination sent an invalid TLS handshake record length",
            ));
        }
        if record.len() < 5 + record_len {
            return Err(reality_parse_error("truncated TLS handshake record"));
        }

        let payload = &record[5..5 + record_len];
        if payload[0] != 2 {
            return Err(reality_parse_error(
                "destination did not send ServerHello first",
            ));
        }
        let handshake_len =
            ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | payload[3] as usize;
        let server_hello_len = handshake_len
            .checked_add(4)
            .ok_or_else(|| reality_parse_error("invalid ServerHello length"))?;
        if server_hello_len > payload.len() {
            return Err(reality_parse_error(
                "destination split ServerHello across TLS records",
            ));
        }
        Ok(&payload[..server_hello_len])
    }
}

struct ParsedRealityClientHello {
    random: [u8; 32],
    session_id: Vec<u8>,
    raw_client_hello: Vec<u8>,
    x25519_key_share: Vec<u8>,
    server_name: Option<String>,
}

fn parse_reality_client_hello(bytes: &[u8]) -> Result<ParsedRealityClientHello, Error> {
    if bytes.len() < 4 || bytes[0] != 1 {
        return Err(reality_parse_error("not a ClientHello"));
    }

    let handshake_len =
        ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | bytes[3] as usize;
    if handshake_len < 34 || handshake_len + 4 > bytes.len() {
        return Err(reality_parse_error("truncated ClientHello"));
    }

    let body = &bytes[4..4 + handshake_len];
    let mut offset = 2;
    let mut random = [0u8; 32];
    random.copy_from_slice(reality_take_bytes(
        body,
        &mut offset,
        32,
        "ClientHello random",
    )?);

    let session_id_len = *body
        .get(offset)
        .ok_or_else(|| reality_parse_error("missing session ID length"))?
        as usize;
    offset += 1;
    let session_id_offset = offset;
    let session_id = reality_take_bytes(body, &mut offset, session_id_len, "session ID")?.to_vec();

    let cipher_suites_len = reality_read_u16(body, &mut offset, "cipher suites length")?;
    reality_take_bytes(body, &mut offset, cipher_suites_len, "cipher suites")?;
    let compression_len = *body
        .get(offset)
        .ok_or_else(|| reality_parse_error("missing compression methods length"))?
        as usize;
    offset += 1 + compression_len;
    if offset > body.len() {
        return Err(reality_parse_error(
            "truncated ClientHello after compression",
        ));
    }

    let extensions_len = reality_read_u16(body, &mut offset, "extensions length")?;
    let extensions = reality_take_bytes(body, &mut offset, extensions_len, "extensions")?;
    let mut extension_offset = 0;
    let mut server_name = None;
    let mut x25519_key_share = None;
    while extension_offset < extensions.len() {
        let ext_type = reality_read_u16(extensions, &mut extension_offset, "extension type")?;
        let ext_len = reality_read_u16(extensions, &mut extension_offset, "extension length")?;
        let extension =
            reality_take_bytes(extensions, &mut extension_offset, ext_len, "extension")?;
        if ext_type == 0x0000 {
            server_name = parse_reality_server_name(extension)?;
        } else if ext_type == 0x0033 {
            x25519_key_share = parse_reality_x25519_key_share(extension)?;
        }
    }

    let mut raw_client_hello = bytes.to_vec();
    let raw_session_id_end = 4 + session_id_offset + session_id_len;
    raw_client_hello
        .get_mut(4 + session_id_offset..raw_session_id_end)
        .ok_or_else(|| reality_parse_error("invalid session ID offset"))?
        .fill(0);

    Ok(ParsedRealityClientHello {
        random,
        session_id,
        raw_client_hello,
        x25519_key_share: x25519_key_share.unwrap_or_default(),
        server_name,
    })
}

fn reality_read_u16(bytes: &[u8], offset: &mut usize, field: &str) -> Result<usize, Error> {
    let value = reality_take_bytes(bytes, offset, 2, field)?;
    Ok(u16::from_be_bytes([value[0], value[1]]) as usize)
}

fn reality_take_bytes<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
    field: &str,
) -> Result<&'a [u8], Error> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| reality_parse_error("ClientHello length overflow"))?;
    let value = bytes
        .get(*offset..end)
        .ok_or_else(|| reality_parse_error(&format!("truncated ClientHello {field}")))?;
    *offset = end;
    Ok(value)
}

fn parse_reality_server_name(extension: &[u8]) -> Result<Option<String>, Error> {
    let mut offset = 0;
    let names_len = reality_read_u16(extension, &mut offset, "server name list length")?;
    let names = reality_take_bytes(extension, &mut offset, names_len, "server name list")?;
    let mut name_offset = 0;
    while name_offset < names.len() {
        let name_type = *names
            .get(name_offset)
            .ok_or_else(|| reality_parse_error("truncated server name type"))?;
        name_offset += 1;
        let name_len = reality_read_u16(names, &mut name_offset, "server name length")?;
        let name = reality_take_bytes(names, &mut name_offset, name_len, "server name")?;
        if name_type == 0 {
            let name = core::str::from_utf8(name)
                .map_err(|_| reality_parse_error("server name is not valid UTF-8"))?;
            return Ok(Some(name.to_ascii_lowercase()));
        }
    }
    Ok(None)
}

fn parse_reality_x25519_key_share(extension: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let mut offset = 0;
    let shares_len = reality_read_u16(extension, &mut offset, "key share list length")?;
    let shares = reality_take_bytes(extension, &mut offset, shares_len, "key share list")?;
    let mut share_offset = 0;
    while share_offset < shares.len() {
        let group = reality_read_u16(shares, &mut share_offset, "key share group")?;
        let share_len = reality_read_u16(shares, &mut share_offset, "key share length")?;
        let share = reality_take_bytes(shares, &mut share_offset, share_len, "key share")?;
        if group == 0x001d {
            return Ok(Some(share.to_vec()));
        }
    }
    Ok(None)
}

fn reality_parse_error(message: &str) -> Error {
    Error::General(message.into())
}

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

#[cfg(test)]
mod tests {
    use super::{RealityClientHelloProbe, RealityServerHelloAction};
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    fn client_hello_with_sni(server_name: &str) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.push(0);
        body.extend([0, 2, 0x13, 0x01, 1, 0]);

        let mut server_name_list = Vec::new();
        server_name_list.extend_from_slice(&((server_name.len() + 3) as u16).to_be_bytes());
        server_name_list.push(0);
        server_name_list.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        server_name_list.extend_from_slice(server_name.as_bytes());

        let mut extensions = vec![0, 0];
        extensions.extend_from_slice(&(server_name_list.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&server_name_list);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![1];
        handshake.extend_from_slice(&[
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&body);

        let mut record = vec![22, 3, 3];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn malformed_client_hello_records_return_errors_without_panicking() {
        let inputs = [
            vec![22, 3, 3, 0, 4, 1, 0, 0, 0],
            vec![23, 3, 3, 0, 0],
            vec![22, 3, 3, 0, 4, 2, 0, 0, 0],
        ];

        for input in inputs {
            let result =
                std::panic::catch_unwind(|| RealityClientHelloProbe::from_tls_records(&input));
            assert!(result.is_ok(), "parser panicked for malformed input");
            assert!(result.unwrap().is_err());
        }
    }

    #[test]
    fn fragmented_client_hello_is_collected_and_parsed() {
        let mut handshake = vec![1, 0, 0, 75, 3, 3];
        handshake.extend([0u8; 32]);
        handshake.push(32);
        handshake.extend([0u8; 32]);
        handshake.extend([0, 2, 0x13, 0x01, 1, 0, 0, 0]);

        let split = 2;
        let mut records = vec![22, 3, 3, 0, split as u8];
        records.extend_from_slice(&handshake[..split]);
        records.extend([22, 3, 3, 0, (handshake.len() - split) as u8]);
        records.extend_from_slice(&handshake[split..]);

        let parsed = RealityClientHelloProbe::from_tls_records(&records)
            .unwrap()
            .expect("fragmented ClientHello should be complete");
        assert_eq!(parsed.handshake(), handshake);
        assert_eq!(parsed.wire(), records);
        assert_eq!(parsed.session_id().len(), 32);
        assert!(parsed.x25519_key_share().is_empty());
    }

    #[test]
    fn server_hello_record_is_validated_and_unframed() {
        let record = [22, 3, 3, 0, 8, 2, 0, 0, 4, 0, 0, 0, 0];
        assert_eq!(
            RealityClientHelloProbe::parse_server_hello_record(&record).unwrap(),
            &[2, 0, 0, 4, 0, 0, 0, 0]
        );
        assert!(
            RealityClientHelloProbe::parse_server_hello_record(&[23, 3, 3, 0, 4, 2, 0, 0, 0])
                .is_err()
        );
    }

    #[test]
    fn server_hello_fetch_uses_only_allowlisted_sni_and_original_client_hello() {
        let client_hello = client_hello_with_sni("decoy.example");
        let probe = RealityClientHelloProbe::from_tls_records(&client_hello)
            .unwrap()
            .unwrap();
        let allowed = vec![String::from("decoy.example")];
        let server_hello_record = [22, 3, 3, 0, 8, 2, 0, 0, 4, 0, 0, 0, 0];

        let action = probe.fetch_server_hello_or_fallback(&allowed, |server_name, wire| {
            assert_eq!(server_name, "decoy.example");
            assert_eq!(wire, client_hello);
            Ok(server_hello_record.to_vec())
        });
        let RealityServerHelloAction::UseTemplate(template) = action else {
            panic!("allowlisted SNI should use its target ServerHello");
        };
        assert_eq!(template, &[2, 0, 0, 4, 0, 0, 0, 0]);

        let unallowed = [String::from("other.example")];
        assert!(matches!(
            probe.fetch_server_hello_or_fallback(&unallowed, |_, _| panic!(
                "unallowlisted SNI was probed"
            )),
            RealityServerHelloAction::Fallback {
                server_name: Some(_),
                probe_error: None,
            }
        ));

        assert!(matches!(
            probe.fetch_server_hello_or_fallback(&allowed, |_, _| {
                Err(crate::Error::General(String::from("probe failed")))
            }),
            RealityServerHelloAction::Fallback {
                server_name: Some(_),
                probe_error: Some(_),
            }
        ));
    }
}
