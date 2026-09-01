use crate::{
    finished_verify_data, hybrid_server_share, KeySchedule, RecordKeys, TlsError, Transcript,
    TLS_AES_128_GCM_SHA256, X25519_MLKEM768,
};
use mrml_crypto::{rsa_pss_sha256_sign, x25519_public, x25519_shared};
use mrml_runtime::{Shared, TcpStream, Text, Vector};

pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
pub const MAX_TLS13_SIGNATURE_BYTES: usize = 512;

/// Use-only TLS 1.3 CertificateVerify signing boundary. Implementations receive
/// only the current handshake transcript digest. The implementation must bind
/// the fixed TLS 1.3 server CertificateVerify context before signing and never
/// exposes private-key bytes.
pub trait TlsServerSigningKey: Send + Sync {
    fn signature_scheme(&self) -> u16;
    fn sign_certificate_verify_transcript(
        &self,
        transcript_digest: &[u8; 32],
        output: &mut [u8; MAX_TLS13_SIGNATURE_BYTES],
    ) -> Result<usize, TlsError>;
}

fn u16_push(out: &mut Vector<u8>, n: usize) -> Result<(), TlsError> {
    if n > u16::MAX as usize {
        return Err(TlsError::Handshake);
    }
    out.try_extend_from_slice(&(n as u16).to_be_bytes())
        .map_err(|_| TlsError::AllocationFailed)
}
fn u24_push(out: &mut Vector<u8>, n: usize) -> Result<(), TlsError> {
    if n > 0xff_ffff {
        return Err(TlsError::Handshake);
    }
    out.try_extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8])
        .map_err(|_| TlsError::AllocationFailed)
}
fn handshake(kind: u8, body: &[u8]) -> Result<Vector<u8>, TlsError> {
    let mut out = Vector::new();
    out.try_push(kind).map_err(|_| TlsError::AllocationFailed)?;
    u24_push(&mut out, body.len())?;
    out.try_extend_from_slice(body)
        .map_err(|_| TlsError::AllocationFailed)?;
    Ok(out)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        let end = self.at.checked_add(n).ok_or(TlsError::Handshake)?;
        let out = self.bytes.get(self.at..end).ok_or(TlsError::Handshake)?;
        self.at = end;
        Ok(out)
    }
    fn byte(&mut self) -> Result<u8, TlsError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, TlsError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Result<usize, TlsError> {
        let b = self.take(3)?;
        Ok((b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize)
    }
    fn done(&self) -> bool {
        self.at == self.bytes.len()
    }
}

fn der_length(c: &mut Cursor<'_>) -> Result<usize, TlsError> {
    let first = c.byte()?;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 4 {
        return Err(TlsError::Certificate);
    }
    let mut n = 0usize;
    for b in c.take(count)? {
        n = n
            .checked_mul(256)
            .and_then(|v| v.checked_add(*b as usize))
            .ok_or(TlsError::Certificate)?;
    }
    Ok(n)
}
fn der<'a>(c: &mut Cursor<'a>, tag: u8) -> Result<&'a [u8], TlsError> {
    if c.byte()? != tag {
        return Err(TlsError::Certificate);
    }
    let n = der_length(c)?;
    c.take(n).map_err(|_| TlsError::Certificate)
}
fn integer<'a>(c: &mut Cursor<'a>) -> Result<&'a [u8], TlsError> {
    let mut v = der(c, 2)?;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    Ok(v)
}

fn base64_value(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
fn pem_blocks(input: &[u8], label: &[u8]) -> Result<Vector<Vector<u8>>, TlsError> {
    let mut begin = Vector::new();
    begin
        .try_extend_from_slice(b"-----BEGIN ")
        .map_err(|_| TlsError::AllocationFailed)?;
    begin
        .try_extend_from_slice(label)
        .map_err(|_| TlsError::AllocationFailed)?;
    begin
        .try_extend_from_slice(b"-----")
        .map_err(|_| TlsError::AllocationFailed)?;
    let mut end = Vector::new();
    end.try_extend_from_slice(b"-----END ")
        .map_err(|_| TlsError::AllocationFailed)?;
    end.try_extend_from_slice(label)
        .map_err(|_| TlsError::AllocationFailed)?;
    end.try_extend_from_slice(b"-----")
        .map_err(|_| TlsError::AllocationFailed)?;
    let mut blocks = Vector::new();
    let mut at = 0;
    while let Some(p) = input[at..]
        .windows(begin.len())
        .position(|w| w == &begin[..])
    {
        let start = at + p + begin.len();
        let stop = input[start..]
            .windows(end.len())
            .position(|w| w == &end[..])
            .ok_or(TlsError::Certificate)?
            + start;
        let mut out = Vector::new();
        let mut bits = 0u32;
        let mut count = 0u8;
        let mut padded = false;
        for &b in &input[start..stop] {
            if b.is_ascii_whitespace() {
                continue;
            }
            if b == b'=' {
                padded = true;
                continue;
            }
            if padded {
                return Err(TlsError::Certificate);
            }
            if let Some(v) = base64_value(b) {
                bits = (bits << 6) | v as u32;
                count += 1;
                if count == 4 {
                    out.try_extend_from_slice(&[(bits >> 16) as u8, (bits >> 8) as u8, bits as u8])
                        .map_err(|_| TlsError::AllocationFailed)?;
                    bits = 0;
                    count = 0;
                }
            } else {
                return Err(TlsError::Certificate);
            }
        }
        if count == 2 {
            out.try_push((bits >> 4) as u8)
                .map_err(|_| TlsError::AllocationFailed)?;
        } else if count == 3 {
            out.try_extend_from_slice(&[(bits >> 10) as u8, (bits >> 2) as u8])
                .map_err(|_| TlsError::AllocationFailed)?;
        } else if count != 0 {
            return Err(TlsError::Certificate);
        }
        blocks
            .try_push(out)
            .map_err(|_| TlsError::AllocationFailed)?;
        at = stop + end.len();
    }
    Ok(blocks)
}

pub struct TlsServerConfig {
    certificates: Vector<Vector<u8>>,
    modulus: Vector<u8>,
    private_exponent: Vector<u8>,
    protocols: Vector<Text>,
    ocsp_response: Option<Vector<u8>>,
    signing_key: Option<Shared<dyn TlsServerSigningKey>>,
    required_server_name: Option<Text>,
}
impl Drop for TlsServerConfig {
    fn drop(&mut self) {
        self.private_exponent.fill(0);
    }
}
impl TlsServerConfig {
    pub fn from_pem(certificate_pem: &[u8], private_key_pem: &[u8]) -> Result<Self, TlsError> {
        if certificate_pem.len() > 1024 * 1024 || private_key_pem.len() > 64 * 1024 {
            return Err(TlsError::Certificate);
        }
        let certificates = pem_blocks(certificate_pem, b"CERTIFICATE")?;
        if certificates.is_empty()
            || certificates.len() > 8
            || certificates
                .iter()
                .any(|certificate| certificate.len() > 64 * 1024)
        {
            return Err(TlsError::Certificate);
        }
        let pkcs8 = pem_blocks(private_key_pem, b"PRIVATE KEY")?;
        let pkcs1 = pem_blocks(private_key_pem, b"RSA PRIVATE KEY")?;
        let raw = if let Some(v) = pkcs1.first() {
            &v[..]
        } else if let Some(v) = pkcs8.first() {
            let mut top = Cursor::new(v);
            let seq = der(&mut top, 0x30)?;
            let mut s = Cursor::new(seq);
            integer(&mut s)?;
            der(&mut s, 0x30)?;
            der(&mut s, 0x04)?
        } else {
            return Err(TlsError::Certificate);
        };
        let mut top = Cursor::new(raw);
        let seq = der(&mut top, 0x30)?;
        let mut s = Cursor::new(seq);
        integer(&mut s)?;
        let modulus = integer(&mut s)?;
        integer(&mut s)?;
        let private_exponent = integer(&mut s)?;
        if !(256..=512).contains(&modulus.len()) || private_exponent.is_empty() {
            return Err(TlsError::Certificate);
        }
        let mut n = Vector::new();
        n.try_extend_from_slice(modulus)
            .map_err(|_| TlsError::AllocationFailed)?;
        let mut d = Vector::new();
        d.try_extend_from_slice(private_exponent)
            .map_err(|_| TlsError::AllocationFailed)?;
        Ok(Self {
            certificates,
            modulus: n,
            private_exponent: d,
            protocols: Vector::new(),
            ocsp_response: None,
            signing_key: None,
            required_server_name: None,
        })
    }
    pub fn from_der_chain(certificates: &[&[u8]]) -> Result<Self, TlsError> {
        if certificates.is_empty()
            || certificates.len() > 8
            || certificates
                .iter()
                .any(|certificate| certificate.is_empty() || certificate.len() > 64 * 1024)
        {
            return Err(TlsError::Certificate);
        }
        let mut owned = Vector::new();
        for certificate in certificates {
            let mut der = Vector::new();
            der.try_extend_from_slice(certificate)
                .map_err(|_| TlsError::AllocationFailed)?;
            owned
                .try_push(der)
                .map_err(|_| TlsError::AllocationFailed)?;
        }
        Ok(Self {
            certificates: owned,
            modulus: Vector::new(),
            private_exponent: Vector::new(),
            protocols: Vector::new(),
            ocsp_response: None,
            signing_key: None,
            required_server_name: None,
        })
    }
    pub fn with_signing_key<S: TlsServerSigningKey + 'static>(mut self, signer: S) -> Self {
        self.signing_key = Some(Shared::new(signer));
        self
    }
    pub fn require_server_name(mut self, name: &str) -> Result<Self, TlsError> {
        if name.is_empty()
            || name.len() > 253
            || !name.is_ascii()
            || name.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return Err(TlsError::Handshake);
        }
        self.required_server_name = Some(
            Text::try_from_str(name)
                .map_err(|_| TlsError::AllocationFailed)?
                .to_ascii_lowercase(),
        );
        Ok(self)
    }
    pub fn with_protocols(mut self, protocols: &[&str]) -> Result<Self, TlsError> {
        for protocol in protocols {
            if protocol.is_empty() || protocol.len() > u8::MAX as usize || !protocol.is_ascii() {
                return Err(TlsError::Handshake);
            }
            self.protocols
                .try_push(Text::try_from_str(protocol).map_err(|_| TlsError::AllocationFailed)?)
                .map_err(|_| TlsError::AllocationFailed)?;
        }
        Ok(self)
    }
    pub fn with_ocsp_response(mut self, response: &[u8]) -> Result<Self, TlsError> {
        if response.is_empty() || response.len() > 64 * 1024 {
            return Err(TlsError::Certificate);
        }
        let mut owned = Vector::new();
        owned
            .try_extend_from_slice(response)
            .map_err(|_| TlsError::AllocationFailed)?;
        self.ocsp_response = Some(owned);
        Ok(self)
    }

    /// Select the public gitd production signing policy.
    ///
    /// The current first-party RSA private operation has not yet established
    /// blinding, fixed-shape timing, post-sign verification, and bounded signer
    /// concurrency. Public gitd therefore fails closed rather than exposing it.
    /// A future constant-time signer adapter can replace this gate without
    /// weakening the experimental loopback server profile.
    pub fn for_public_gitd(self) -> Result<Self, TlsError> {
        let _ = self;
        Err(TlsError::Certificate)
    }
}

fn sign_certificate_verify(
    config: &TlsServerConfig,
    transcript_digest: &[u8; 32],
) -> Result<(u16, Vector<u8>), TlsError> {
    if let Some(signer) = &config.signing_key {
        let scheme = signer.signature_scheme();
        if scheme != ECDSA_SECP256R1_SHA256 {
            return Err(TlsError::Certificate);
        }
        let mut bounded = [0; MAX_TLS13_SIGNATURE_BYTES];
        let written = signer.sign_certificate_verify_transcript(transcript_digest, &mut bounded)?;
        if written == 0 || written > bounded.len() {
            bounded.fill(0);
            return Err(TlsError::AuthenticationFailed);
        }
        let mut signature = Vector::new();
        signature
            .try_extend_from_slice(&bounded[..written])
            .map_err(|_| TlsError::AllocationFailed)?;
        bounded.fill(0);
        return Ok((scheme, signature));
    }
    if config.modulus.is_empty() || config.private_exponent.is_empty() {
        return Err(TlsError::Certificate);
    }
    let mut salt = [0; 32];
    mrml_runtime::fill_random(&mut salt).map_err(|_| TlsError::AuthenticationFailed)?;
    let mut signed = Vector::new();
    signed
        .try_extend_from_slice(&[0x20; 64])
        .map_err(|_| TlsError::AllocationFailed)?;
    signed
        .try_extend_from_slice(b"TLS 1.3, server CertificateVerify\0")
        .map_err(|_| TlsError::AllocationFailed)?;
    signed
        .try_extend_from_slice(transcript_digest)
        .map_err(|_| TlsError::AllocationFailed)?;
    let mut signature = Vector::new();
    signature
        .try_resize(config.modulus.len(), 0)
        .map_err(|_| TlsError::AllocationFailed)?;
    rsa_pss_sha256_sign(
        &config.modulus,
        &config.private_exponent,
        &signed,
        &salt,
        &mut signature,
    )
    .map_err(|_| TlsError::AuthenticationFailed)?;
    salt.fill(0);
    Ok((RSA_PSS_RSAE_SHA256, signature))
}

fn record(stream: &mut TcpStream) -> Result<Vector<u8>, TlsError> {
    let mut h = [0; 5];
    stream.read_exact(&mut h).map_err(|_| TlsError::Io)?;
    if h[1] != 3 || !(1..=3).contains(&h[2]) {
        return Err(TlsError::InvalidRecord);
    }
    let n = u16::from_be_bytes([h[3], h[4]]) as usize;
    if n > 16640 {
        return Err(TlsError::InvalidRecord);
    }
    let mut out = Vector::new();
    out.try_extend_from_slice(&h)
        .map_err(|_| TlsError::AllocationFailed)?;
    out.try_resize(5 + n, 0)
        .map_err(|_| TlsError::AllocationFailed)?;
    stream.read_exact(&mut out[5..]).map_err(|_| TlsError::Io)?;
    Ok(out)
}
fn send_plain(stream: &mut TcpStream, msg: &[u8]) -> Result<(), TlsError> {
    let h = [22, 3, 3, (msg.len() >> 8) as u8, msg.len() as u8];
    stream.write_all(&h).map_err(|_| TlsError::Io)?;
    stream.write_all(msg).map_err(|_| TlsError::Io)
}

fn compatibility_change_cipher_spec(record: &[u8]) -> Result<bool, TlsError> {
    if record.first() != Some(&20) {
        return Ok(false);
    }
    if record.len() != 6 || record[1..] != [3, 3, 0, 1, 1] {
        return Err(TlsError::InvalidRecord);
    }
    Ok(true)
}
fn client_offer(
    msg: &[u8],
) -> Result<
    (
        &[u8],
        u16,
        &[u8],
        Vector<Text>,
        Option<Vector<u8>>,
        bool,
        Option<Text>,
    ),
    TlsError,
> {
    let mut c = Cursor::new(msg);
    if c.byte()? != 1 || c.u24()? != msg.len() - 4 || c.take(2)? != [3, 3] {
        return Err(TlsError::Handshake);
    }
    c.take(32)?;
    let sid = c.byte()? as usize;
    let session = c.take(sid)?;
    let suites = c.u16()? as usize;
    let offered = c.take(suites)?;
    if !offered
        .chunks_exact(2)
        .any(|x| x == TLS_AES_128_GCM_SHA256.to_be_bytes())
    {
        return Err(TlsError::Handshake);
    }
    let compression = c.byte()? as usize;
    c.take(compression)?;
    let elen = c.u16()? as usize;
    let mut e = Cursor::new(c.take(elen)?);
    if !c.done() {
        return Err(TlsError::Handshake);
    }
    let mut hybrid_share = None;
    let mut x25519_share = None;
    let mut protocols = Vector::new();
    let mut transport_parameters = None;
    let mut status_requested = false;
    let mut server_name = None;
    while !e.done() {
        let kind = e.u16()?;
        let n = e.u16()? as usize;
        let value = e.take(n)?;
        if kind == 0 {
            if server_name.is_some() {
                return Err(TlsError::Handshake);
            }
            let mut list = Cursor::new(value);
            let total = list.u16()? as usize;
            let mut names = Cursor::new(list.take(total)?);
            if !list.done() || names.byte()? != 0 {
                return Err(TlsError::Handshake);
            }
            let length = names.u16()? as usize;
            let bytes = names.take(length)?;
            if !names.done() || bytes.is_empty() || bytes.len() > 253 || !bytes.is_ascii() {
                return Err(TlsError::Handshake);
            }
            let name = core::str::from_utf8(bytes).map_err(|_| TlsError::Handshake)?;
            server_name = Some(
                Text::try_from_str(name)
                    .map_err(|_| TlsError::AllocationFailed)?
                    .to_ascii_lowercase(),
            );
        } else if kind == 51 {
            let mut k = Cursor::new(value);
            let total = k.u16()? as usize;
            let mut shares = Cursor::new(k.take(total)?);
            while !shares.done() {
                let group = shares.u16()?;
                let len = shares.u16()? as usize;
                let share = shares.take(len)?;
                if group == X25519_MLKEM768 && len == 1216 {
                    hybrid_share = Some(share);
                } else if group == 0x1d && len == 32 {
                    x25519_share = Some(share);
                }
            }
        } else if kind == 16 {
            let mut list = Cursor::new(value);
            let total = list.u16()? as usize;
            let mut names = Cursor::new(list.take(total)?);
            if !list.done() {
                return Err(TlsError::Handshake);
            }
            while !names.done() {
                let length = names.byte()? as usize;
                let bytes = names.take(length)?;
                let protocol = core::str::from_utf8(bytes).map_err(|_| TlsError::Handshake)?;
                protocols
                    .try_push(Text::try_from_str(protocol).map_err(|_| TlsError::AllocationFailed)?)
                    .map_err(|_| TlsError::AllocationFailed)?;
            }
        } else if kind == 5 {
            if status_requested || value != [1, 0, 0, 0, 0] {
                return Err(TlsError::Handshake);
            }
            status_requested = true;
        } else if kind == 57 {
            if transport_parameters.is_some() || value.len() > 4096 {
                return Err(TlsError::Handshake);
            }
            let mut owned = Vector::new();
            owned
                .try_extend_from_slice(value)
                .map_err(|_| TlsError::AllocationFailed)?;
            transport_parameters = Some(owned);
        }
    }
    let (group, share) = hybrid_share
        .map(|share| (X25519_MLKEM768, share))
        .or_else(|| x25519_share.map(|share| (0x1d, share)))
        .ok_or(TlsError::Handshake)?;
    Ok((
        session,
        group,
        share,
        protocols,
        transport_parameters,
        status_requested,
        server_name,
    ))
}

fn require_configured_server_name(
    config: &TlsServerConfig,
    offered: Option<&str>,
) -> Result<(), TlsError> {
    match (&config.required_server_name, offered) {
        (None, _) => Ok(()),
        (Some(required), Some(offered)) if required.eq_ignore_ascii_case(offered) => Ok(()),
        _ => Err(TlsError::Handshake),
    }
}

pub struct QuicTlsServerFlight {
    pub server_hello: Vector<u8>,
    pub handshake_messages: Vector<Vector<u8>>,
    pub client_handshake_secret: [u8; 32],
    pub server_handshake_secret: [u8; 32],
    pub client_application_secret: [u8; 32],
    pub server_application_secret: [u8; 32],
    pub peer_transport_parameters: Vector<u8>,
}

pub struct QuicTlsServerHandshake {
    expected_client_finished: [u8; 32],
    complete: bool,
}

impl QuicTlsServerHandshake {
    pub fn accept(
        client_hello: &[u8],
        transport_parameters: &[u8],
        config: &TlsServerConfig,
    ) -> Result<(Self, QuicTlsServerFlight), TlsError> {
        if transport_parameters.len() > 4096 || config.ocsp_response.is_none() {
            return Err(TlsError::Handshake);
        }
        let (
            session,
            group,
            share,
            protocols,
            peer_transport_parameters,
            status_requested,
            server_name,
        ) = client_offer(client_hello)?;
        require_configured_server_name(config, server_name.as_deref())?;
        if !session.is_empty() || !protocols.iter().any(|protocol| protocol == "h3") {
            return Err(TlsError::Handshake);
        }
        let peer_transport_parameters = peer_transport_parameters.ok_or(TlsError::Handshake)?;
        let (server_share, mut shared) = if group == X25519_MLKEM768 {
            let (public, secret) = hybrid_server_share(share)?;
            let mut shared = Vector::new();
            shared
                .try_extend_from_slice(&secret)
                .map_err(|_| TlsError::AllocationFailed)?;
            (public, shared)
        } else {
            let peer: [u8; 32] = share.try_into().map_err(|_| TlsError::Handshake)?;
            let mut scalar = [0; 32];
            mrml_runtime::fill_random(&mut scalar).map_err(|_| TlsError::AuthenticationFailed)?;
            let public = x25519_public(scalar);
            let secret = x25519_shared(scalar, peer).ok_or(TlsError::AuthenticationFailed)?;
            scalar.fill(0);
            let mut public_bytes = Vector::new();
            public_bytes
                .try_extend_from_slice(&public)
                .map_err(|_| TlsError::AllocationFailed)?;
            let mut shared = Vector::new();
            shared
                .try_extend_from_slice(&secret)
                .map_err(|_| TlsError::AllocationFailed)?;
            (public_bytes, shared)
        };
        let mut random = [0; 32];
        mrml_runtime::fill_random(&mut random).map_err(|_| TlsError::AuthenticationFailed)?;
        let mut body = Vector::new();
        body.try_extend_from_slice(&[3, 3])
            .map_err(|_| TlsError::AllocationFailed)?;
        body.try_extend_from_slice(&random)
            .map_err(|_| TlsError::AllocationFailed)?;
        body.try_push(session.len() as u8)
            .map_err(|_| TlsError::AllocationFailed)?;
        body.try_extend_from_slice(session)
            .map_err(|_| TlsError::AllocationFailed)?;
        u16_push(&mut body, TLS_AES_128_GCM_SHA256 as usize)?;
        body.try_push(0).map_err(|_| TlsError::AllocationFailed)?;
        let mut hello_extensions = Vector::new();
        u16_push(&mut hello_extensions, 43)?;
        u16_push(&mut hello_extensions, 2)?;
        hello_extensions
            .try_extend_from_slice(&[3, 4])
            .map_err(|_| TlsError::AllocationFailed)?;
        u16_push(&mut hello_extensions, 51)?;
        u16_push(&mut hello_extensions, 4 + server_share.len())?;
        u16_push(&mut hello_extensions, group as usize)?;
        u16_push(&mut hello_extensions, server_share.len())?;
        hello_extensions
            .try_extend_from_slice(&server_share)
            .map_err(|_| TlsError::AllocationFailed)?;
        u16_push(&mut body, hello_extensions.len())?;
        body.try_extend_from_slice(&hello_extensions)
            .map_err(|_| TlsError::AllocationFailed)?;
        let server_hello = handshake(2, &body)?;

        let mut transcript = Transcript::new();
        transcript.update(client_hello);
        transcript.update(&server_hello);
        let mut schedule = KeySchedule::new();
        schedule.mix_shared_secret(&shared);
        shared.fill(0);
        let client_hs = schedule.traffic_secret(false, &transcript.hash());
        let server_hs = schedule.traffic_secret(true, &transcript.hash());

        let mut encrypted_extensions = Vector::new();
        let mut alpn = Vector::new();
        alpn.try_extend_from_slice(&[0, 3, 2, b'h', b'3'])
            .map_err(|_| TlsError::AllocationFailed)?;
        u16_push(&mut encrypted_extensions, 16)?;
        u16_push(&mut encrypted_extensions, alpn.len())?;
        encrypted_extensions
            .try_extend_from_slice(&alpn)
            .map_err(|_| TlsError::AllocationFailed)?;
        u16_push(&mut encrypted_extensions, 57)?;
        u16_push(&mut encrypted_extensions, transport_parameters.len())?;
        encrypted_extensions
            .try_extend_from_slice(transport_parameters)
            .map_err(|_| TlsError::AllocationFailed)?;
        let mut encrypted_extensions_body = Vector::new();
        u16_push(&mut encrypted_extensions_body, encrypted_extensions.len())?;
        encrypted_extensions_body
            .try_extend_from_slice(&encrypted_extensions)
            .map_err(|_| TlsError::AllocationFailed)?;
        let extensions = handshake(8, &encrypted_extensions_body)?;
        transcript.update(&extensions);

        let mut certificate_body = Vector::new();
        certificate_body
            .try_push(0)
            .map_err(|_| TlsError::AllocationFailed)?;
        let mut certificate_list = Vector::new();
        for (index, certificate) in config.certificates.iter().enumerate() {
            u24_push(&mut certificate_list, certificate.len())?;
            certificate_list
                .try_extend_from_slice(certificate)
                .map_err(|_| TlsError::AllocationFailed)?;
            if index == 0 && status_requested {
                let response = config.ocsp_response.as_ref().ok_or(TlsError::Certificate)?;
                let mut status = Vector::new();
                status.try_push(1).map_err(|_| TlsError::AllocationFailed)?;
                u24_push(&mut status, response.len())?;
                status
                    .try_extend_from_slice(response)
                    .map_err(|_| TlsError::AllocationFailed)?;
                u16_push(&mut certificate_list, 4 + status.len())?;
                u16_push(&mut certificate_list, 5)?;
                u16_push(&mut certificate_list, status.len())?;
                certificate_list
                    .try_extend_from_slice(&status)
                    .map_err(|_| TlsError::AllocationFailed)?;
            } else {
                u16_push(&mut certificate_list, 0)?;
            }
        }
        u24_push(&mut certificate_body, certificate_list.len())?;
        certificate_body
            .try_extend_from_slice(&certificate_list)
            .map_err(|_| TlsError::AllocationFailed)?;
        let certificate = handshake(11, &certificate_body)?;
        transcript.update(&certificate);

        let (signature_scheme, signature) = sign_certificate_verify(config, &transcript.hash())?;
        let mut verify_body = Vector::new();
        u16_push(&mut verify_body, signature_scheme as usize)?;
        u16_push(&mut verify_body, signature.len())?;
        verify_body
            .try_extend_from_slice(&signature)
            .map_err(|_| TlsError::AllocationFailed)?;
        let certificate_verify = handshake(15, &verify_body)?;
        transcript.update(&certificate_verify);
        let finished = handshake(20, &finished_verify_data(&server_hs, &transcript.hash()))?;
        transcript.update(&finished);
        let hash = transcript.hash();
        schedule.finish_handshake();
        let client_application_secret = schedule.application_traffic_secret(false, &hash);
        let server_application_secret = schedule.application_traffic_secret(true, &hash);
        let expected_client_finished = finished_verify_data(&client_hs, &hash);
        let mut handshake_messages = Vector::new();
        for message in [extensions, certificate, certificate_verify, finished] {
            handshake_messages
                .try_push(message)
                .map_err(|_| TlsError::AllocationFailed)?;
        }
        Ok((
            Self {
                expected_client_finished,
                complete: false,
            },
            QuicTlsServerFlight {
                server_hello,
                handshake_messages,
                client_handshake_secret: client_hs,
                server_handshake_secret: server_hs,
                client_application_secret,
                server_application_secret,
                peer_transport_parameters,
            },
        ))
    }

    pub fn receive_client_finished(&mut self, message: &[u8]) -> Result<(), TlsError> {
        if self.complete || message.len() != 36 || message[0] != 20 || message[1..4] != [0, 0, 32] {
            return Err(TlsError::Handshake);
        }
        if self
            .expected_client_finished
            .iter()
            .zip(&message[4..])
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            != 0
        {
            return Err(TlsError::AuthenticationFailed);
        }
        self.complete = true;
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

pub struct TlsServerStream {
    stream: TcpStream,
    read_keys: RecordKeys,
    write_keys: RecordKeys,
    pending: Vector<u8>,
    at: usize,
    negotiated_protocol: Option<Text>,
}
impl TlsServerStream {
    pub fn accept(mut stream: TcpStream, config: &TlsServerConfig) -> Result<Self, TlsError> {
        stream
            .set_read_timeout_millis(30_000)
            .map_err(|_| TlsError::Io)?;
        stream
            .set_write_timeout_millis(30_000)
            .map_err(|_| TlsError::Io)?;
        let first = record(&mut stream)?;
        if first[0] != 22 {
            return Err(TlsError::Handshake);
        }
        let client_hello = &first[5..];
        let (session, group, share, offered_protocols, _, status_requested, server_name) =
            client_offer(client_hello)?;
        require_configured_server_name(config, server_name.as_deref())?;
        let negotiated_protocol = if config.protocols.is_empty() {
            None
        } else {
            config
                .protocols
                .iter()
                .find(|wanted| offered_protocols.iter().any(|offered| offered == *wanted))
                .cloned()
                .ok_or(TlsError::Handshake)?
                .into()
        };
        let (server_share, mut shared) = if group == X25519_MLKEM768 {
            let (public, secret) = hybrid_server_share(share)?;
            let mut shared = Vector::new();
            shared
                .try_extend_from_slice(&secret)
                .map_err(|_| TlsError::AllocationFailed)?;
            (public, shared)
        } else {
            let peer: [u8; 32] = share.try_into().map_err(|_| TlsError::Handshake)?;
            let mut scalar = [0; 32];
            mrml_runtime::fill_random(&mut scalar).map_err(|_| TlsError::AuthenticationFailed)?;
            let public = x25519_public(scalar);
            let secret = x25519_shared(scalar, peer).ok_or(TlsError::AuthenticationFailed)?;
            scalar.fill(0);
            let mut public_bytes = Vector::new();
            public_bytes
                .try_extend_from_slice(&public)
                .map_err(|_| TlsError::AllocationFailed)?;
            let mut shared = Vector::new();
            shared
                .try_extend_from_slice(&secret)
                .map_err(|_| TlsError::AllocationFailed)?;
            (public_bytes, shared)
        };
        let mut random = [0; 32];
        mrml_runtime::fill_random(&mut random).map_err(|_| TlsError::AuthenticationFailed)?;
        let mut body = Vector::new();
        body.try_extend_from_slice(&[3, 3])
            .map_err(|_| TlsError::AllocationFailed)?;
        body.try_extend_from_slice(&random)
            .map_err(|_| TlsError::AllocationFailed)?;
        body.try_push(session.len() as u8)
            .map_err(|_| TlsError::AllocationFailed)?;
        body.try_extend_from_slice(session)
            .map_err(|_| TlsError::AllocationFailed)?;
        u16_push(&mut body, TLS_AES_128_GCM_SHA256 as usize)?;
        body.try_push(0).map_err(|_| TlsError::AllocationFailed)?;
        let mut ext = Vector::new();
        u16_push(&mut ext, 43)?;
        u16_push(&mut ext, 2)?;
        ext.try_extend_from_slice(&[3, 4])
            .map_err(|_| TlsError::AllocationFailed)?;
        u16_push(&mut ext, 51)?;
        u16_push(&mut ext, 4 + server_share.len())?;
        u16_push(&mut ext, group as usize)?;
        u16_push(&mut ext, server_share.len())?;
        ext.try_extend_from_slice(&server_share)
            .map_err(|_| TlsError::AllocationFailed)?;
        u16_push(&mut body, ext.len())?;
        body.try_extend_from_slice(&ext)
            .map_err(|_| TlsError::AllocationFailed)?;
        let server_hello = handshake(2, &body)?;
        send_plain(&mut stream, &server_hello)?;
        let mut transcript = Transcript::new();
        transcript.update(client_hello);
        transcript.update(&server_hello);
        let mut schedule = KeySchedule::new();
        schedule.mix_shared_secret(&shared);
        shared.fill(0);
        let client_hs = schedule.traffic_secret(false, &transcript.hash());
        let server_hs = schedule.traffic_secret(true, &transcript.hash());
        let mut read_hs = RecordKeys::from_traffic_secret(&client_hs);
        let mut write_hs = RecordKeys::from_traffic_secret(&server_hs);
        let mut extension_body = Vector::new();
        if let Some(protocol) = &negotiated_protocol {
            let mut value = Vector::new();
            u16_push(&mut value, protocol.len() + 1)?;
            value
                .try_push(protocol.len() as u8)
                .map_err(|_| TlsError::AllocationFailed)?;
            value
                .try_extend_from_slice(protocol.as_bytes())
                .map_err(|_| TlsError::AllocationFailed)?;
            u16_push(&mut extension_body, 16)?;
            u16_push(&mut extension_body, value.len())?;
            extension_body
                .try_extend_from_slice(&value)
                .map_err(|_| TlsError::AllocationFailed)?;
        }
        let mut extension_message = Vector::new();
        u16_push(&mut extension_message, extension_body.len())?;
        extension_message
            .try_extend_from_slice(&extension_body)
            .map_err(|_| TlsError::AllocationFailed)?;
        let extensions = handshake(8, &extension_message)?;
        transcript.update(&extensions);
        let mut cert_body = Vector::new();
        cert_body
            .try_push(0)
            .map_err(|_| TlsError::AllocationFailed)?;
        let mut list = Vector::new();
        for (certificate_index, cert) in config.certificates.iter().enumerate() {
            u24_push(&mut list, cert.len())?;
            list.try_extend_from_slice(cert)
                .map_err(|_| TlsError::AllocationFailed)?;
            if certificate_index == 0 && status_requested {
                if let Some(response) = &config.ocsp_response {
                    let mut status = Vector::new();
                    status.try_push(1).map_err(|_| TlsError::AllocationFailed)?;
                    u24_push(&mut status, response.len())?;
                    status
                        .try_extend_from_slice(response)
                        .map_err(|_| TlsError::AllocationFailed)?;
                    u16_push(&mut list, 4 + status.len())?;
                    u16_push(&mut list, 5)?;
                    u16_push(&mut list, status.len())?;
                    list.try_extend_from_slice(&status)
                        .map_err(|_| TlsError::AllocationFailed)?;
                } else {
                    u16_push(&mut list, 0)?;
                }
            } else {
                u16_push(&mut list, 0)?;
            }
        }
        u24_push(&mut cert_body, list.len())?;
        cert_body
            .try_extend_from_slice(&list)
            .map_err(|_| TlsError::AllocationFailed)?;
        let certificate = handshake(11, &cert_body)?;
        transcript.update(&certificate);
        let (signature_scheme, signature) = sign_certificate_verify(config, &transcript.hash())?;
        let mut verify_body = Vector::new();
        u16_push(&mut verify_body, signature_scheme as usize)?;
        u16_push(&mut verify_body, signature.len())?;
        verify_body
            .try_extend_from_slice(&signature)
            .map_err(|_| TlsError::AllocationFailed)?;
        let certificate_verify = handshake(15, &verify_body)?;
        transcript.update(&certificate_verify);
        let finished = handshake(20, &finished_verify_data(&server_hs, &transcript.hash()))?;
        transcript.update(&finished);
        for msg in [
            &extensions[..],
            &certificate[..],
            &certificate_verify[..],
            &finished[..],
        ] {
            for chunk in msg.chunks(1 << 14) {
                let mut protected = Vector::new();
                write_hs.seal(22, chunk, &mut protected)?;
                stream.write_all(&protected).map_err(|_| TlsError::Io)?;
            }
        }
        let hash = transcript.hash();
        schedule.finish_handshake();
        let incoming = loop {
            let incoming = record(&mut stream)?;
            if compatibility_change_cipher_spec(&incoming)? {
                continue;
            }
            if incoming[0] != 23 {
                return Err(TlsError::Handshake);
            }
            break incoming;
        };
        let mut plain = Vector::new();
        let content_type = read_hs.open(&incoming, &mut plain)?;
        if content_type != 22 || plain.len() != 36 || plain[0] != 20 {
            return Err(TlsError::Handshake);
        }
        let expected = finished_verify_data(&client_hs, &hash);
        let mut difference = 0;
        for (a, b) in expected.iter().zip(&plain[4..]) {
            difference |= a ^ b
        }
        if difference != 0 {
            return Err(TlsError::AuthenticationFailed);
        }
        Ok(Self {
            stream,
            read_keys: RecordKeys::from_traffic_secret(
                &schedule.application_traffic_secret(false, &hash),
            ),
            write_keys: RecordKeys::from_traffic_secret(
                &schedule.application_traffic_secret(true, &hash),
            ),
            pending: Vector::new(),
            at: 0,
            negotiated_protocol,
        })
    }
    pub fn negotiated_protocol(&self) -> Option<&str> {
        self.negotiated_protocol.as_deref()
    }
    pub fn write_all(&mut self, data: &[u8]) -> Result<(), TlsError> {
        for chunk in data.chunks(1 << 14) {
            let mut out = Vector::new();
            self.write_keys.seal(23, chunk, &mut out)?;
            self.stream.write_all(&out).map_err(|_| TlsError::Io)?;
        }
        Ok(())
    }
    pub fn read(&mut self, out: &mut [u8]) -> Result<usize, TlsError> {
        if self.at < self.pending.len() {
            let n = out.len().min(self.pending.len() - self.at);
            out[..n].copy_from_slice(&self.pending[self.at..self.at + n]);
            self.at += n;
            return Ok(n);
        }
        loop {
            let record = record(&mut self.stream)?;
            let mut plain = Vector::new();
            let kind = self.read_keys.open(&record, &mut plain)?;
            if kind == 21 {
                return Ok(0);
            }
            if kind == 23 {
                let n = out.len().min(plain.len());
                out[..n].copy_from_slice(&plain[..n]);
                self.pending = plain;
                self.at = n;
                return Ok(n);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    struct UseOnlySigner {
        called: AtomicBool,
        scheme: u16,
    }

    impl TlsServerSigningKey for UseOnlySigner {
        fn signature_scheme(&self) -> u16 {
            self.scheme
        }
        fn sign_certificate_verify_transcript(
            &self,
            digest: &[u8; 32],
            output: &mut [u8; MAX_TLS13_SIGNATURE_BYTES],
        ) -> Result<usize, TlsError> {
            assert_ne!(digest, &[0; 32]);
            self.called.store(true, Ordering::Release);
            output[..8].copy_from_slice(b"bounded!");
            Ok(8)
        }
    }

    #[test]
    fn external_p256_route_receives_only_context_digest() {
        let config = TlsServerConfig::from_der_chain(&[b"certificate"])
            .unwrap()
            .with_signing_key(UseOnlySigner {
                called: AtomicBool::new(false),
                scheme: ECDSA_SECP256R1_SHA256,
            });
        let (scheme, signature) = sign_certificate_verify(&config, &[7; 32]).unwrap();
        assert_eq!(scheme, ECDSA_SECP256R1_SHA256);
        assert_eq!(&signature[..], b"bounded!");
        assert!(config.signing_key.as_ref().unwrap().signature_scheme() == scheme);
        let invalid = TlsServerConfig::from_der_chain(&[b"certificate"])
            .unwrap()
            .with_signing_key(UseOnlySigner {
                called: AtomicBool::new(false),
                scheme: RSA_PSS_RSAE_SHA256,
            });
        assert!(matches!(
            sign_certificate_verify(&invalid, &[7; 32]),
            Err(TlsError::Certificate)
        ));
    }

    #[test]
    fn exact_sni_policy_never_falls_back() {
        let config = TlsServerConfig::from_der_chain(&[b"certificate"])
            .unwrap()
            .require_server_name("Git.Example")
            .unwrap();
        assert_eq!(
            require_configured_server_name(&config, Some("git.example")),
            Ok(())
        );
        assert_eq!(
            require_configured_server_name(&config, Some("other.example")),
            Err(TlsError::Handshake)
        );
        assert_eq!(
            require_configured_server_name(&config, None),
            Err(TlsError::Handshake)
        );
        assert!(TlsServerConfig::from_der_chain(&[b"certificate"])
            .unwrap()
            .require_server_name("bad_name")
            .is_err());
    }

    #[test]
    fn public_gitd_rsa_private_signing_fails_closed() {
        let config = TlsServerConfig {
            certificates: Vector::new(),
            modulus: [3].into(),
            private_exponent: [1].into(),
            protocols: Vector::new(),
            ocsp_response: None,
            signing_key: None,
            required_server_name: None,
        };
        assert!(matches!(
            config.for_public_gitd(),
            Err(TlsError::Certificate)
        ));
    }

    #[test]
    fn compatibility_ccs_is_exact_and_bounded() {
        assert!(compatibility_change_cipher_spec(&[20, 3, 3, 0, 1, 1]).unwrap());
        assert!(!compatibility_change_cipher_spec(&[23, 3, 3, 0, 1, 1]).unwrap());
        assert!(compatibility_change_cipher_spec(&[20, 3, 3, 0, 2, 1, 1]).is_err());
        assert!(compatibility_change_cipher_spec(&[20, 3, 1, 0, 1, 1]).is_err());
        assert!(compatibility_change_cipher_spec(&[20, 3, 3, 0, 1, 2]).is_err());
    }
    use crate::TlsClientStream;
    use mrml_runtime::{environment_variable, read_file, TcpListener};

    #[test]
    fn pem_decoder_rejects_non_base64_and_trailing_data() {
        assert!(pem_blocks(
            b"-----BEGIN CERTIFICATE-----\nYWJj!\n-----END CERTIFICATE-----",
            b"CERTIFICATE"
        )
        .is_err());
        assert!(pem_blocks(
            b"-----BEGIN CERTIFICATE-----\nYQ==Y\n-----END CERTIFICATE-----",
            b"CERTIFICATE"
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn server_pss_signature_verifies_with_openssl_when_configured() {
        let Some(openssl) = environment_variable("MRML_TLS_OPENSSL") else {
            return;
        };
        let Some(cert_path) = environment_variable("MRML_TLS_SERVER_TEST_CERT") else {
            return;
        };
        let Some(key_path) = environment_variable("MRML_TLS_SERVER_TEST_KEY") else {
            return;
        };
        let config = TlsServerConfig::from_pem(
            &read_file(&cert_path).unwrap(),
            &read_file(&key_path).unwrap(),
        )
        .unwrap();
        let message = b"MRML TLS RSA-PSS interoperability probe";
        let mut salt = [0x5a; 32];
        let mut signature = Vector::new();
        signature.try_resize(config.modulus.len(), 0).unwrap();
        rsa_pss_sha256_sign(
            &config.modulus,
            &config.private_exponent,
            message,
            &salt,
            &mut signature,
        )
        .unwrap();
        salt.fill(0);
        let stem = mrml_runtime::mrml_format!("/tmp/mrml-tls-pss-{}", mrml_runtime::process_id());
        let message_path = mrml_runtime::mrml_format!("{stem}.message");
        let signature_path = mrml_runtime::mrml_format!("{stem}.signature");
        let public_path = mrml_runtime::mrml_format!("{stem}.public.pem");
        mrml_runtime::write_file(&message_path, message).unwrap();
        mrml_runtime::write_file(&signature_path, &signature).unwrap();
        let public = mrml_runtime::Command::new(&openssl)
            .args(["x509", "-pubkey", "-noout", "-in"])
            .arg(&cert_path)
            .args(["-out"])
            .arg(&public_path)
            .output()
            .unwrap();
        assert!(public.status.success());
        let verified = mrml_runtime::Command::new(&openssl)
            .args([
                "dgst",
                "-sha256",
                "-sigopt",
                "rsa_padding_mode:pss",
                "-sigopt",
                "rsa_pss_saltlen:32",
                "-verify",
            ])
            .arg(&public_path)
            .args(["-signature"])
            .arg(&signature_path)
            .arg(&message_path)
            .output()
            .unwrap();
        assert!(
            verified.status.success(),
            "OpenSSL rejected MRML RSA-PSS: {}",
            core::str::from_utf8(&verified.stderr).unwrap_or("non-UTF-8 error")
        );
        mrml_runtime::remove_file(&message_path).unwrap();
        mrml_runtime::remove_file(&signature_path).unwrap();
        mrml_runtime::remove_file(&public_path).unwrap();
    }

    #[test]
    fn authenticated_hybrid_client_server_interoperate_when_configured() {
        if !crate::experimental_feature_enabled("MRML_TLS_EXPERIMENTAL_SERVER")
            || !crate::experimental_feature_enabled("MRML_TLS_EXPERIMENTAL_HYBRID")
        {
            return;
        }
        let Some(cert_path) = environment_variable("MRML_TLS_SERVER_TEST_CERT") else {
            return;
        };
        let Some(key_path) = environment_variable("MRML_TLS_SERVER_TEST_KEY") else {
            return;
        };
        let cert = read_file(&cert_path).unwrap();
        let key = read_file(&key_path).unwrap();
        let config = mrml_runtime::Shared::new(TlsServerConfig::from_pem(&cert, &key).unwrap());
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        assert!(mrml_runtime::spawn_detached(move || {
            let socket = listener.accept().unwrap();
            let mut tls = TlsServerStream::accept(socket, &config).unwrap();
            let mut request = [0; 4];
            assert_eq!(tls.read(&mut request).unwrap(), 4);
            assert_eq!(&request, b"ping");
            tls.write_all(b"pong").unwrap();
        })
        .is_ok());
        let mut client = TlsClientStream::connect("localhost", port).unwrap();
        assert_eq!(client.negotiated_group(), X25519_MLKEM768);
        client.write_all(b"ping").unwrap();
        let mut response = [0; 4];
        assert_eq!(client.read(&mut response).unwrap(), 4);
        assert_eq!(&response, b"pong");
    }
}
