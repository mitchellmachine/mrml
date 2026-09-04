use crate::{
    HybridClientSecret, KeySchedule, RecordKeys, TLS_AES_128_GCM_SHA256, TlsError, Transcript,
    X25519_MLKEM768, finished_verify_data, hybrid_client_share, verify_server_chain,
};
use mrml_crypto::{x25519_public, x25519_shared};
use mrml_runtime::{TcpStream, Text, Vector};

fn push_u16(out: &mut Vector<u8>, value: usize) -> Result<(), TlsError> {
    if value > u16::MAX as usize {
        return Err(TlsError::Handshake);
    }
    out.try_extend_from_slice(&(value as u16).to_be_bytes())
        .map_err(|_| TlsError::AllocationFailed)
}
fn push_u24(out: &mut Vector<u8>, value: usize) -> Result<(), TlsError> {
    if value > 0xff_ffff {
        return Err(TlsError::Handshake);
    }
    out.try_extend_from_slice(&[(value >> 16) as u8, (value >> 8) as u8, value as u8])
        .map_err(|_| TlsError::AllocationFailed)
}
fn extension(out: &mut Vector<u8>, kind: u16, value: &[u8]) -> Result<(), TlsError> {
    push_u16(out, kind as usize)?;
    push_u16(out, value.len())?;
    out.try_extend_from_slice(value)
        .map_err(|_| TlsError::AllocationFailed)
}

fn client_hello(
    host: &str,
    protocols: &[&str],
    quic_transport_parameters: Option<&[u8]>,
) -> Result<(Vector<u8>, Option<HybridClientSecret>, [u8; 32]), TlsError> {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return Err(TlsError::Handshake);
    }
    let hybrid_enabled = true;
    let (share, secret) = if hybrid_enabled {
        let (share, secret) = hybrid_client_share()?;
        (share, Some(secret))
    } else {
        (Vector::new(), None)
    };
    let mut fallback = [0u8; 32];
    mrml_runtime::fill_random(&mut fallback).map_err(|_| TlsError::AuthenticationFailed)?;
    let fallback_public = x25519_public(fallback);
    let mut random = [0u8; 32];
    let mut session = [0u8; 32];
    mrml_runtime::fill_random(&mut random).map_err(|_| TlsError::AuthenticationFailed)?;
    let quic = quic_transport_parameters.is_some();
    if !quic {
        mrml_runtime::fill_random(&mut session).map_err(|_| TlsError::AuthenticationFailed)?;
    }
    let mut extensions = Vector::new();
    let mut sni = Vector::new();
    push_u16(&mut sni, host.len() + 3)?;
    sni.try_push(0).map_err(|_| TlsError::AllocationFailed)?;
    push_u16(&mut sni, host.len())?;
    sni.try_extend_from_slice(host.as_bytes())
        .map_err(|_| TlsError::AllocationFailed)?;
    extension(&mut extensions, 0, &sni)?;
    if !protocols.is_empty() {
        let mut names = Vector::new();
        for protocol in protocols {
            if protocol.is_empty() || protocol.len() > u8::MAX as usize || !protocol.is_ascii() {
                return Err(TlsError::Handshake);
            }
            names
                .try_push(protocol.len() as u8)
                .map_err(|_| TlsError::AllocationFailed)?;
            names
                .try_extend_from_slice(protocol.as_bytes())
                .map_err(|_| TlsError::AllocationFailed)?;
        }
        let mut alpn = Vector::new();
        push_u16(&mut alpn, names.len())?;
        alpn.try_extend_from_slice(&names)
            .map_err(|_| TlsError::AllocationFailed)?;
        extension(&mut extensions, 16, &alpn)?;
    }
    // Request a TLS 1.3 stapled OCSP response for the leaf certificate.
    extension(&mut extensions, 5, &[1, 0, 0, 0, 0])?;
    if let Some(parameters) = quic_transport_parameters {
        if parameters.len() > 4096 {
            return Err(TlsError::Handshake);
        }
        extension(&mut extensions, 57, parameters)?;
    }
    extension(&mut extensions, 43, &[2, 3, 4])?;
    extension(&mut extensions, 13, &[0, 8, 4, 3, 5, 3, 8, 4, 4, 1])?;
    extension(&mut extensions, 50, &[0, 8, 4, 3, 5, 3, 8, 4, 4, 1])?;
    if hybrid_enabled {
        extension(&mut extensions, 10, &[0, 4, 0x11, 0xec, 0, 0x1d])?;
    } else {
        extension(&mut extensions, 10, &[0, 2, 0, 0x1d])?;
    }
    let mut key_share = Vector::new();
    let key_share_bytes = if hybrid_enabled {
        4usize
            .checked_add(share.len())
            .and_then(|length| length.checked_add(4 + fallback_public.len()))
            .ok_or(TlsError::Handshake)?
    } else {
        4 + fallback_public.len()
    };
    push_u16(&mut key_share, key_share_bytes)?;
    if hybrid_enabled {
        push_u16(&mut key_share, X25519_MLKEM768 as usize)?;
        push_u16(&mut key_share, share.len())?;
        key_share
            .try_extend_from_slice(&share)
            .map_err(|_| TlsError::AllocationFailed)?;
    }
    push_u16(&mut key_share, 0x1d)?;
    push_u16(&mut key_share, 32)?;
    key_share
        .try_extend_from_slice(&fallback_public)
        .map_err(|_| TlsError::AllocationFailed)?;
    extension(&mut extensions, 51, &key_share)?;
    let mut body = Vector::new();
    body.try_extend_from_slice(&[3, 3])
        .map_err(|_| TlsError::AllocationFailed)?;
    body.try_extend_from_slice(&random)
        .map_err(|_| TlsError::AllocationFailed)?;
    let session_length = if quic { 0 } else { session.len() };
    body.try_push(session_length as u8)
        .map_err(|_| TlsError::AllocationFailed)?;
    body.try_extend_from_slice(&session[..session_length])
        .map_err(|_| TlsError::AllocationFailed)?;
    push_u16(&mut body, 2)?;
    push_u16(&mut body, TLS_AES_128_GCM_SHA256 as usize)?;
    body.try_extend_from_slice(&[1, 0])
        .map_err(|_| TlsError::AllocationFailed)?;
    push_u16(&mut body, extensions.len())?;
    body.try_extend_from_slice(&extensions)
        .map_err(|_| TlsError::AllocationFailed)?;
    let mut handshake = Vector::new();
    handshake
        .try_push(1)
        .map_err(|_| TlsError::AllocationFailed)?;
    push_u24(&mut handshake, body.len())?;
    handshake
        .try_extend_from_slice(&body)
        .map_err(|_| TlsError::AllocationFailed)?;
    Ok((handshake, secret, fallback))
}

fn encrypted_extensions(message: &[u8], offered: &[&str]) -> Result<Option<Text>, TlsError> {
    let mut cursor = Cursor::new(message);
    if cursor.u8()? != 8 || cursor.u24()? != message.len() - 4 {
        return Err(TlsError::Handshake);
    }
    let total = cursor.u16()? as usize;
    let mut extensions = Cursor::new(cursor.take(total)?);
    if !cursor.done() {
        return Err(TlsError::Handshake);
    }
    let mut selected = None;
    while !extensions.done() {
        let kind = extensions.u16()?;
        let length = extensions.u16()? as usize;
        let value = extensions.take(length)?;
        if kind == 16 {
            if selected.is_some() {
                return Err(TlsError::Handshake);
            }
            let mut a = Cursor::new(value);
            let list = a.u16()? as usize;
            if list != value.len() - 2 {
                return Err(TlsError::Handshake);
            }
            let n = a.u8()? as usize;
            let bytes = a.take(n)?;
            if !a.done() {
                return Err(TlsError::Handshake);
            }
            let protocol = core::str::from_utf8(bytes).map_err(|_| TlsError::Handshake)?;
            if !offered.contains(&protocol) {
                return Err(TlsError::Handshake);
            }
            selected = Some(Text::try_from_str(protocol).map_err(|_| TlsError::AllocationFailed)?);
        }
    }
    if !offered.is_empty() && selected.is_none() {
        return Err(TlsError::Handshake);
    }
    Ok(selected)
}

fn record(stream: &mut TcpStream) -> Result<(u8, Vector<u8>), TlsError> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).map_err(|_| TlsError::Io)?;
    if header[1..3] != [3, 3] {
        return Err(TlsError::InvalidRecord);
    }
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    if length > 16640 {
        return Err(TlsError::InvalidRecord);
    }
    let mut body = Vector::new();
    body.try_resize(length, 0)
        .map_err(|_| TlsError::AllocationFailed)?;
    stream.read_exact(&mut body).map_err(|_| TlsError::Io)?;
    Ok((header[0], body))
}
fn send_plain_handshake(stream: &mut TcpStream, message: &[u8]) -> Result<(), TlsError> {
    if message.len() > u16::MAX as usize {
        return Err(TlsError::Handshake);
    }
    let header = [22, 3, 1, (message.len() >> 8) as u8, message.len() as u8];
    stream.write_all(&header).map_err(|_| TlsError::Io)?;
    stream.write_all(message).map_err(|_| TlsError::Io)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        let end = self.position.checked_add(n).ok_or(TlsError::Handshake)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(TlsError::Handshake)?;
        self.position = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, TlsError> {
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
        self.position == self.bytes.len()
    }
}

fn server_share(message: &[u8]) -> Result<(u16, &[u8]), TlsError> {
    let mut c = Cursor::new(message);
    if c.u8()? != 2 {
        return Err(TlsError::Handshake);
    }
    let len = c.u24()?;
    if len != message.len() - 4 {
        return Err(TlsError::Handshake);
    }
    if c.take(2)? != [3, 3] {
        return Err(TlsError::Handshake);
    }
    c.take(32)?;
    let sid = c.u8()? as usize;
    c.take(sid)?;
    if c.u16() != Ok(TLS_AES_128_GCM_SHA256) || c.u8()? != 0 {
        return Err(TlsError::Handshake);
    }
    let ext_len = c.u16()? as usize;
    let mut e = Cursor::new(c.take(ext_len)?);
    if !c.done() {
        return Err(TlsError::Handshake);
    }
    let mut version = false;
    let mut share = None;
    while !e.done() {
        let kind = e.u16()?;
        let value_len = e.u16()? as usize;
        let value = e.take(value_len)?;
        match kind {
            43 if value == [3, 4] => version = true,
            51 => {
                let mut k = Cursor::new(value);
                let group = k.u16()?;
                let length = k.u16()? as usize;
                let bytes = k.take(length)?;
                if !k.done() || !matches!((group, length), (X25519_MLKEM768, 1120) | (0x1d, 32)) {
                    return Err(TlsError::Handshake);
                }
                share = Some((group, bytes))
            }
            _ => {}
        }
    }
    if !version {
        return Err(TlsError::Handshake);
    }
    share.ok_or(TlsError::Handshake)
}

fn handshake_message(buffer: &mut Vector<u8>) -> Result<Option<Vector<u8>>, TlsError> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    let len = (buffer[1] as usize) << 16 | (buffer[2] as usize) << 8 | buffer[3] as usize;
    if len > 0xff_ffff {
        return Err(TlsError::Handshake);
    }
    if buffer.len() < 4 + len {
        return Ok(None);
    }
    let mut result = Vector::new();
    result
        .try_extend_from_slice(&buffer[..4 + len])
        .map_err(|_| TlsError::AllocationFailed)?;
    let consumed = 4 + len;
    let remaining = buffer.len() - consumed;
    buffer.copy_within(consumed.., 0);
    buffer.truncate(remaining);
    Ok(Some(result))
}

fn certificate_chain(
    message: &[u8],
    storage: &mut Vector<Vector<u8>>,
    stapled_ocsp: &mut Option<Vector<u8>>,
) -> Result<(), TlsError> {
    let mut c = Cursor::new(message);
    if c.u8()? != 11 {
        return Err(TlsError::Handshake);
    }
    let length = c.u24()?;
    if length != message.len() - 4 {
        return Err(TlsError::Handshake);
    }
    let context = c.u8()? as usize;
    if context != 0 {
        c.take(context)?;
        return Err(TlsError::Handshake);
    }
    let list_len = c.u24()?;
    let list = c.take(list_len)?;
    if !c.done() {
        return Err(TlsError::Handshake);
    }
    let mut entries = Cursor::new(list);
    while !entries.done() {
        let der_len = entries.u24()?;
        if storage.len() >= 8 || der_len > 64 * 1024 {
            return Err(TlsError::Certificate);
        }
        let der = entries.take(der_len)?;
        let mut owned = Vector::new();
        owned
            .try_extend_from_slice(der)
            .map_err(|_| TlsError::AllocationFailed)?;
        storage
            .try_push(owned)
            .map_err(|_| TlsError::AllocationFailed)?;
        let ext = entries.u16()? as usize;
        let mut extensions = Cursor::new(entries.take(ext)?);
        while !extensions.done() {
            let kind = extensions.u16()?;
            let length = extensions.u16()? as usize;
            let value = extensions.take(length)?;
            if kind == 5 {
                if storage.len() != 1 || stapled_ocsp.is_some() {
                    return Err(TlsError::Certificate);
                }
                let mut status = Cursor::new(value);
                if status.u8()? != 1 {
                    return Err(TlsError::Certificate);
                }
                let response_length = status.u24()?;
                let response = status.take(response_length)?;
                if !status.done() || response.is_empty() || response.len() > 64 * 1024 {
                    return Err(TlsError::Certificate);
                }
                let mut owned = Vector::new();
                owned
                    .try_extend_from_slice(response)
                    .map_err(|_| TlsError::AllocationFailed)?;
                *stapled_ocsp = Some(owned);
            }
        }
    }
    if storage.is_empty() {
        Err(TlsError::Certificate)
    } else {
        Ok(())
    }
}

fn verify_certificate_message(
    message: &[u8],
    transcript_hash: &[u8; 32],
    leaf: &crate::Certificate<'_>,
) -> Result<(), TlsError> {
    let mut c = Cursor::new(message);
    if c.u8()? != 15 {
        return Err(TlsError::Handshake);
    }
    let len = c.u24()?;
    if len != message.len() - 4 {
        return Err(TlsError::Handshake);
    }
    let scheme = c.u16()?;
    let signature_len = c.u16()? as usize;
    let signature = c.take(signature_len)?;
    if !c.done() {
        return Err(TlsError::Handshake);
    }
    let mut signed = Vector::new();
    signed
        .try_extend_from_slice(&[0x20; 64])
        .map_err(|_| TlsError::AllocationFailed)?;
    signed
        .try_extend_from_slice(b"TLS 1.3, server CertificateVerify\0")
        .map_err(|_| TlsError::AllocationFailed)?;
    signed
        .try_extend_from_slice(transcript_hash)
        .map_err(|_| TlsError::AllocationFailed)?;
    match scheme {
        0x0403 => leaf.verify_tls_ecdsa(&signed, signature),
        0x0503 => leaf.verify_tls_ecdsa_p384(&signed, signature),
        0x0804 => leaf.verify_tls_pss(&signed, signature),
        _ => return Err(TlsError::Handshake),
    }
    .map_err(|_| TlsError::AuthenticationFailed)
}

pub struct QuicHandshakeSecrets {
    pub client: [u8; 32],
    pub server: [u8; 32],
}
pub struct QuicApplicationSecrets {
    pub client: [u8; 32],
    pub server: [u8; 32],
    pub peer_transport_parameters: Vector<u8>,
    pub client_finished: Vector<u8>,
}
pub struct QuicTlsClientHandshake {
    host: Text,
    transcript: Transcript,
    schedule: Option<KeySchedule>,
    hybrid: Option<HybridClientSecret>,
    fallback: [u8; 32],
    client_hs: [u8; 32],
    server_hs: [u8; 32],
    certificates: Vector<Vector<u8>>,
    stapled_ocsp: Option<Vector<u8>>,
    peer_transport_parameters: Option<Vector<u8>>,
    got_extensions: bool,
    got_certificate: bool,
    got_verify: bool,
}
impl QuicTlsClientHandshake {
    pub fn new(host: &str, transport_parameters: &[u8]) -> Result<(Self, Vector<u8>), TlsError> {
        let (hello, hybrid, fallback) = client_hello(host, &["h3"], Some(transport_parameters))?;
        let mut transcript = Transcript::new();
        transcript.update(&hello);
        Ok((
            Self {
                host: Text::try_from_str(host).map_err(|_| TlsError::AllocationFailed)?,
                transcript,
                schedule: None,
                hybrid,
                fallback,
                client_hs: [0; 32],
                server_hs: [0; 32],
                certificates: Vector::new(),
                stapled_ocsp: None,
                peer_transport_parameters: None,
                got_extensions: false,
                got_certificate: false,
                got_verify: false,
            },
            hello,
        ))
    }
    pub fn receive_server_hello(
        &mut self,
        message: &[u8],
    ) -> Result<QuicHandshakeSecrets, TlsError> {
        if self.schedule.is_some() {
            return Err(TlsError::Handshake);
        }
        let (group, server_key) = server_share(message)?;
        let mut shared = Vector::new();
        if group == X25519_MLKEM768 {
            shared
                .try_extend_from_slice(
                    &self
                        .hybrid
                        .take()
                        .ok_or(TlsError::Handshake)?
                        .complete(server_key)?,
                )
                .map_err(|_| TlsError::AllocationFailed)?
        } else {
            let peer: [u8; 32] = server_key.try_into().map_err(|_| TlsError::Handshake)?;
            shared
                .try_extend_from_slice(
                    &x25519_shared(self.fallback, peer).ok_or(TlsError::AuthenticationFailed)?,
                )
                .map_err(|_| TlsError::AllocationFailed)?
        }
        self.fallback.fill(0);
        self.transcript.update(message);
        let mut schedule = KeySchedule::new();
        schedule.mix_shared_secret(&shared);
        shared.fill(0);
        self.client_hs = schedule.traffic_secret(false, &self.transcript.hash());
        self.server_hs = schedule.traffic_secret(true, &self.transcript.hash());
        self.schedule = Some(schedule);
        Ok(QuicHandshakeSecrets {
            client: self.client_hs,
            server: self.server_hs,
        })
    }
    pub fn receive_handshake(
        &mut self,
        message: &[u8],
    ) -> Result<Option<QuicApplicationSecrets>, TlsError> {
        if self.schedule.is_none() {
            return Err(TlsError::Handshake);
        }
        match message.first().copied() {
            Some(8) => {
                if self.got_extensions {
                    return Err(TlsError::Handshake);
                }
                self.peer_transport_parameters = Some(quic_extensions(message)?);
                self.got_extensions = true;
                self.transcript.update(message);
                Ok(None)
            }
            Some(11) => {
                if !self.got_extensions || self.got_certificate {
                    return Err(TlsError::Handshake);
                }
                certificate_chain(message, &mut self.certificates, &mut self.stapled_ocsp)?;
                let refs: Vector<&[u8]> = self.certificates.iter().map(|v| &v[..]).collect();
                verify_server_chain(&self.host, &refs).map_err(|error| match error {
                    crate::CertificateError::UnsupportedAlgorithm => TlsError::Handshake,
                    crate::CertificateError::InvalidSignature => TlsError::AuthenticationFailed,
                    crate::CertificateError::Malformed => TlsError::InvalidRecord,
                    _ => TlsError::Certificate,
                })?;
                let leaf = crate::Certificate::parse(&self.certificates[0])
                    .map_err(|_| TlsError::Certificate)?;
                let issuer = crate::Certificate::parse(
                    self.certificates.get(1).ok_or(TlsError::Certificate)?,
                )
                .map_err(|_| TlsError::Certificate)?;
                if let Some(response) = self.stapled_ocsp.as_deref() {
                    crate::verify_stapled_ocsp(
                        response,
                        &leaf,
                        &issuer,
                        mrml_runtime::unix_time_seconds().ok_or(TlsError::Certificate)?,
                    )
                    .map_err(|_| TlsError::AuthenticationFailed)?;
                }
                self.got_certificate = true;
                self.transcript.update(message);
                Ok(None)
            }
            Some(15) => {
                if !self.got_certificate || self.got_verify {
                    return Err(TlsError::Handshake);
                }
                let leaf = crate::Certificate::parse(&self.certificates[0])
                    .map_err(|_| TlsError::Certificate)?;
                verify_certificate_message(message, &self.transcript.hash(), &leaf)?;
                self.got_verify = true;
                self.transcript.update(message);
                Ok(None)
            }
            Some(20) => {
                if !self.got_verify {
                    return Err(TlsError::Handshake);
                }
                let mut cursor = Cursor::new(message);
                cursor.u8()?;
                if cursor.u24()? != 32 {
                    return Err(TlsError::Handshake);
                }
                let received = cursor.take(32)?;
                if !cursor.done() {
                    return Err(TlsError::Handshake);
                }
                let expected = finished_verify_data(&self.server_hs, &self.transcript.hash());
                if expected
                    .iter()
                    .zip(received)
                    .fold(0u8, |difference, (a, b)| difference | (a ^ b))
                    != 0
                {
                    return Err(TlsError::AuthenticationFailed);
                }
                self.transcript.update(message);
                let schedule = self.schedule.as_mut().ok_or(TlsError::Handshake)?;
                schedule.finish_handshake();
                let hash = self.transcript.hash();
                let client = schedule.application_traffic_secret(false, &hash);
                let server = schedule.application_traffic_secret(true, &hash);
                let verify = finished_verify_data(&self.client_hs, &self.transcript.hash());
                let mut client_finished = Vector::new();
                client_finished
                    .try_push(20)
                    .map_err(|_| TlsError::AllocationFailed)?;
                push_u24(&mut client_finished, 32)?;
                client_finished
                    .try_extend_from_slice(&verify)
                    .map_err(|_| TlsError::AllocationFailed)?;
                Ok(Some(QuicApplicationSecrets {
                    client,
                    server,
                    peer_transport_parameters: self
                        .peer_transport_parameters
                        .take()
                        .ok_or(TlsError::Handshake)?,
                    client_finished,
                }))
            }
            _ => Err(TlsError::Handshake),
        }
    }
}
fn quic_extensions(message: &[u8]) -> Result<Vector<u8>, TlsError> {
    let mut cursor = Cursor::new(message);
    if cursor.u8()? != 8 || cursor.u24()? != message.len() - 4 {
        return Err(TlsError::Handshake);
    }
    let total = cursor.u16()? as usize;
    let mut extensions = Cursor::new(cursor.take(total)?);
    if !cursor.done() {
        return Err(TlsError::Handshake);
    }
    let mut alpn = false;
    let mut parameters = None;
    while !extensions.done() {
        let kind = extensions.u16()?;
        let length = extensions.u16()? as usize;
        let value = extensions.take(length)?;
        match kind {
            16 => {
                let mut a = Cursor::new(value);
                if a.u16()? != 3 || a.u8()? != 2 || a.take(2)? != b"h3" || !a.done() {
                    return Err(TlsError::Handshake);
                }
                alpn = true
            }
            57 => {
                if parameters.is_some() || value.len() > 4096 {
                    return Err(TlsError::Handshake);
                }
                let mut owned = Vector::new();
                owned
                    .try_extend_from_slice(value)
                    .map_err(|_| TlsError::AllocationFailed)?;
                parameters = Some(owned)
            }
            _ => {}
        }
    }
    if !alpn {
        return Err(TlsError::Handshake);
    }
    parameters.ok_or(TlsError::Handshake)
}

pub struct TlsClientStream {
    stream: TcpStream,
    read_keys: RecordKeys,
    write_keys: RecordKeys,
    pending: Vector<u8>,
    pending_position: usize,
    negotiated_group: u16,
    negotiated_protocol: Option<Text>,
    read_secret: [u8; 32],
    write_secret: [u8; 32],
}
impl TlsClientStream {
    pub fn connect(host: &str, port: u16) -> Result<Self, TlsError> {
        let address = TcpStream::resolve_host(host).map_err(|_| TlsError::Io)?;
        Self::connect_resolved(host, address, port)
    }

    /// Connect to an exact IPv4 address while authenticating `host` with TLS.
    pub fn connect_resolved(host: &str, address: [u8; 4], port: u16) -> Result<Self, TlsError> {
        Self::connect_resolved_with_alpn(host, address, port, &[])
    }
    pub fn connect_with_alpn(host: &str, port: u16, protocols: &[&str]) -> Result<Self, TlsError> {
        let address = TcpStream::resolve_host(host).map_err(|_| TlsError::Io)?;
        Self::connect_resolved_with_alpn(host, address, port, protocols)
    }
    pub fn connect_resolved_with_alpn(
        host: &str,
        address: [u8; 4],
        port: u16,
        protocols: &[&str],
    ) -> Result<Self, TlsError> {
        Self::connect_resolved_with_policy(host, address, port, protocols, None)
    }

    pub fn connect_resolved_for_acme_tls_alpn01(
        host: &str,
        address: [u8; 4],
        port: u16,
        key_authorization_digest: [u8; 32],
    ) -> Result<Self, TlsError> {
        Self::connect_resolved_with_policy(
            host,
            address,
            port,
            &["acme-tls/1"],
            Some(key_authorization_digest),
        )
    }

    fn connect_resolved_with_policy(
        host: &str,
        address: [u8; 4],
        port: u16,
        protocols: &[&str],
        acme_tls_alpn01_digest: Option<[u8; 32]>,
    ) -> Result<Self, TlsError> {
        let mut stream = TcpStream::connect(address, port).map_err(|_| TlsError::Io)?;
        stream.set_no_delay(true).map_err(|_| TlsError::Io)?;
        stream
            .set_read_timeout_millis(30_000)
            .map_err(|_| TlsError::Io)?;
        stream
            .set_write_timeout_millis(30_000)
            .map_err(|_| TlsError::Io)?;
        let (client_hello, hybrid, mut fallback) = client_hello(host, protocols, None)?;
        send_plain_handshake(&mut stream, &client_hello)?;
        let (mut kind, mut server_hello) = record(&mut stream)?;
        while kind == 20 {
            (kind, server_hello) = record(&mut stream)?;
        }
        if kind != 22 {
            return Err(TlsError::Handshake);
        }
        let (group, server_key) = server_share(&server_hello)?;
        let mut shared = Vector::new();
        if group == X25519_MLKEM768 {
            shared
                .try_extend_from_slice(&hybrid.ok_or(TlsError::Handshake)?.complete(server_key)?)
                .map_err(|_| TlsError::AllocationFailed)?;
        } else {
            let peer: [u8; 32] = server_key.try_into().map_err(|_| TlsError::Handshake)?;
            let secret = x25519_shared(fallback, peer).ok_or(TlsError::AuthenticationFailed)?;
            shared
                .try_extend_from_slice(&secret)
                .map_err(|_| TlsError::AllocationFailed)?;
        }
        fallback.fill(0);
        let mut transcript = Transcript::new();
        transcript.update(&client_hello);
        transcript.update(&server_hello);
        let mut schedule = KeySchedule::new();
        schedule.mix_shared_secret(&shared);
        shared.fill(0);
        let client_hs = schedule.traffic_secret(false, &transcript.hash());
        let server_hs = schedule.traffic_secret(true, &transcript.hash());
        let mut read_hs = RecordKeys::from_traffic_secret(&server_hs);
        let mut write_hs = RecordKeys::from_traffic_secret(&client_hs);
        let mut handshakes = Vector::new();
        let mut certificates = Vector::new();
        let mut got_extensions = false;
        let mut got_certificate = false;
        let mut got_verify = false;
        let mut negotiated_protocol = None;
        let mut stapled_ocsp = None;
        loop {
            let (kind, encrypted) = record(&mut stream)?;
            if kind == 20 {
                continue;
            }
            if kind != 23 {
                return Err(TlsError::Handshake);
            }
            let mut complete = Vector::new();
            complete
                .try_extend_from_slice(&[
                    23,
                    3,
                    3,
                    (encrypted.len() >> 8) as u8,
                    encrypted.len() as u8,
                ])
                .map_err(|_| TlsError::AllocationFailed)?;
            complete
                .try_extend_from_slice(&encrypted)
                .map_err(|_| TlsError::AllocationFailed)?;
            let mut plain = Vector::new();
            if read_hs
                .open(&complete, &mut plain)
                .map_err(|_| TlsError::InvalidRecord)?
                != 22
            {
                return Err(TlsError::Handshake);
            }
            handshakes
                .try_extend_from_slice(&plain)
                .map_err(|_| TlsError::AllocationFailed)?;
            if handshakes.len() > 1024 * 1024 {
                return Err(TlsError::Handshake);
            }
            while let Some(message) = handshake_message(&mut handshakes)? {
                match message[0] {
                    8 => {
                        if got_extensions {
                            return Err(TlsError::Handshake);
                        }
                        negotiated_protocol = encrypted_extensions(&message, protocols)?;
                        got_extensions = true;
                        transcript.update(&message)
                    }
                    11 => {
                        if !got_extensions || got_certificate {
                            return Err(TlsError::Handshake);
                        }
                        certificate_chain(&message, &mut certificates, &mut stapled_ocsp)?;
                        let leaf = crate::Certificate::parse(&certificates[0])
                            .map_err(|_| TlsError::Certificate)?;
                        if let Some(digest) = acme_tls_alpn01_digest.as_ref() {
                            if certificates.len() != 1
                                || negotiated_protocol.as_deref() != Some("acme-tls/1")
                            {
                                return Err(TlsError::Certificate);
                            }
                            leaf.require_tls_alpn01(host, digest)
                                .map_err(|_| TlsError::Certificate)?;
                        } else {
                            let refs: Vector<&[u8]> = certificates.iter().map(|v| &v[..]).collect();
                            verify_server_chain(host, &refs).map_err(|_| TlsError::Certificate)?;
                            let issuer = crate::Certificate::parse(
                                certificates.get(1).ok_or(TlsError::Certificate)?,
                            )
                            .map_err(|_| TlsError::Certificate)?;
                            let now =
                                mrml_runtime::unix_time_seconds().ok_or(TlsError::Certificate)?;
                            if let Some(response) = stapled_ocsp.as_deref() {
                                crate::verify_stapled_ocsp(response, &leaf, &issuer, now)
                                    .map_err(|_| TlsError::Certificate)?;
                            }
                        }
                        got_certificate = true;
                        transcript.update(&message)
                    }
                    15 => {
                        if !got_certificate || got_verify {
                            return Err(TlsError::Handshake);
                        }
                        let leaf = crate::Certificate::parse(&certificates[0])
                            .map_err(|_| TlsError::Certificate)?;
                        verify_certificate_message(&message, &transcript.hash(), &leaf)?;
                        got_verify = true;
                        transcript.update(&message)
                    }
                    20 => {
                        if !got_verify {
                            return Err(TlsError::Handshake);
                        }
                        let mut f = Cursor::new(&message);
                        f.u8()?;
                        if f.u24()? != 32 {
                            return Err(TlsError::Handshake);
                        }
                        let expected = finished_verify_data(&server_hs, &transcript.hash());
                        let received = f.take(32)?;
                        let mut difference = 0u8;
                        for (a, b) in expected.iter().zip(received) {
                            difference |= a ^ b;
                        }
                        if difference != 0 {
                            return Err(TlsError::AuthenticationFailed);
                        }
                        transcript.update(&message);
                        schedule.finish_handshake();
                        let application_hash = transcript.hash();
                        let read_secret =
                            schedule.application_traffic_secret(true, &application_hash);
                        let write_secret =
                            schedule.application_traffic_secret(false, &application_hash);
                        let read_keys = RecordKeys::from_traffic_secret(&read_secret);
                        let write_keys = RecordKeys::from_traffic_secret(&write_secret);
                        let verify = finished_verify_data(&client_hs, &transcript.hash());
                        let mut finished = Vector::new();
                        finished
                            .try_push(20)
                            .map_err(|_| TlsError::AllocationFailed)?;
                        push_u24(&mut finished, 32)?;
                        finished
                            .try_extend_from_slice(&verify)
                            .map_err(|_| TlsError::AllocationFailed)?;
                        let mut protected = Vector::new();
                        write_hs.seal(22, &finished, &mut protected)?;
                        stream.write_all(&protected).map_err(|_| TlsError::Io)?;
                        return Ok(Self {
                            stream,
                            read_keys,
                            write_keys,
                            pending: Vector::new(),
                            pending_position: 0,
                            negotiated_group: group,
                            negotiated_protocol,
                            read_secret,
                            write_secret,
                        });
                    }
                    _ => return Err(TlsError::Handshake),
                }
            }
        }
    }
    pub fn write_all(&mut self, data: &[u8]) -> Result<(), TlsError> {
        for chunk in data.chunks(1 << 14) {
            let mut record = Vector::new();
            self.write_keys.seal(23, chunk, &mut record)?;
            self.stream.write_all(&record).map_err(|_| TlsError::Io)?;
        }
        Ok(())
    }
    /// Change the timeout for an established application-data channel. TLS
    /// handshakes retain their independent 30-second timeout; callers must
    /// select an explicit bounded value for longer-running protocols.
    pub fn set_application_io_timeout_millis(
        &self,
        timeout_millis: u64,
    ) -> Result<(), TlsError> {
        if !(1_000..=900_000).contains(&timeout_millis) {
            return Err(TlsError::Io);
        }
        self.stream
            .set_read_timeout_millis(timeout_millis)
            .and_then(|_| self.stream.set_write_timeout_millis(timeout_millis))
            .map_err(|_| TlsError::Io)
    }
    pub const fn negotiated_group(&self) -> u16 {
        self.negotiated_group
    }
    pub fn negotiated_protocol(&self) -> Option<&str> {
        self.negotiated_protocol.as_deref()
    }
    pub fn read(&mut self, output: &mut [u8]) -> Result<usize, TlsError> {
        if self.pending_position < self.pending.len() {
            let n = output.len().min(self.pending.len() - self.pending_position);
            output[..n]
                .copy_from_slice(&self.pending[self.pending_position..self.pending_position + n]);
            self.pending_position += n;
            if self.pending_position == self.pending.len() {
                self.pending.clear();
                self.pending_position = 0;
            }
            return Ok(n);
        }
        loop {
            let (kind, body) = record(&mut self.stream)?;
            if kind != 23 {
                return Err(TlsError::InvalidRecord);
            }
            let mut complete = Vector::new();
            complete
                .try_extend_from_slice(&[23, 3, 3, (body.len() >> 8) as u8, body.len() as u8])
                .map_err(|_| TlsError::AllocationFailed)?;
            complete
                .try_extend_from_slice(&body)
                .map_err(|_| TlsError::AllocationFailed)?;
            let inner = self.read_keys.open(&complete, &mut self.pending)?;
            match inner {
                23 => return self.read(output),
                21 => {
                    self.pending.clear();
                    return Ok(0);
                }
                22 => {
                    let mut at = 0;
                    while at < self.pending.len() {
                        if self.pending.len() - at < 4 {
                            return Err(TlsError::Handshake);
                        }
                        let length = ((self.pending[at + 1] as usize) << 16)
                            | ((self.pending[at + 2] as usize) << 8)
                            | self.pending[at + 3] as usize;
                        let end = at.checked_add(4 + length).ok_or(TlsError::Handshake)?;
                        if end > self.pending.len() {
                            return Err(TlsError::Handshake);
                        }
                        if self.pending[at] == 24 {
                            if length != 1 || self.pending[at + 4] > 1 {
                                return Err(TlsError::Handshake);
                            }
                            crate::update_application_traffic_secret(&mut self.read_secret)?;
                            self.read_keys = RecordKeys::from_traffic_secret(&self.read_secret);
                            if self.pending[at + 4] == 1 {
                                let mut response = Vector::new();
                                self.write_keys.seal(22, &[24, 0, 0, 1, 0], &mut response)?;
                                self.stream.write_all(&response).map_err(|_| TlsError::Io)?;
                                crate::update_application_traffic_secret(&mut self.write_secret)?;
                                self.write_keys =
                                    RecordKeys::from_traffic_secret(&self.write_secret);
                            }
                        } else if self.pending[at] != 4 {
                            return Err(TlsError::Handshake);
                        }
                        at = end;
                    }
                    self.pending.clear();
                    continue;
                }
                _ => return Err(TlsError::InvalidRecord),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hybrid_share_is_advertised_before_x25519() {
        let (hello, hybrid, _) = client_hello("example.com", &["h2", "http/1.1"], None).unwrap();
        assert!(hybrid.is_some());
        assert!(hello.len() > 32);
        let hybrid_position = hello
            .windows(2)
            .position(|bytes| bytes == X25519_MLKEM768.to_be_bytes())
            .unwrap();
        let x25519_position = hello
            .windows(2)
            .rposition(|bytes| bytes == [0, 0x1d])
            .unwrap();
        assert!(hybrid_position < x25519_position);
    }
    #[test]
    fn encrypted_extensions_require_an_offered_alpn() {
        let message = [8, 0, 0, 10, 0, 8, 0, 16, 0, 4, 0, 2, 1, b'h'];
        assert_eq!(
            encrypted_extensions(&message, &["h2"]),
            Err(TlsError::Handshake)
        );
        let message = [8, 0, 0, 11, 0, 9, 0, 16, 0, 5, 0, 3, 2, b'h', b'2'];
        assert_eq!(
            encrypted_extensions(&message, &["h2"]).unwrap().as_deref(),
            Some("h2")
        );
    }
    #[test]
    fn quic_extensions_require_h3_and_transport_parameters() {
        let message = [
            8, 0, 0, 17, 0, 15, 0, 16, 0, 5, 0, 3, 2, b'h', b'3', 0, 57, 0, 2, 0xaa, 0xbb,
        ];
        assert_eq!(&quic_extensions(&message).unwrap()[..], &[0xaa, 0xbb]);
        let (_, hello) = QuicTlsClientHandshake::new("example.com", &[1, 2, 3]).unwrap();
        assert_eq!(hello[38], 0, "QUIC must disable TLS compatibility mode");
        assert!(
            hello
                .windows(7)
                .any(|window| window == [0, 57, 0, 3, 1, 2, 3])
        );
        let (tcp_hello, _, _) = client_hello("example.com", &["h2"], None).unwrap();
        assert_eq!(tcp_hello[38], 32);
    }

    #[test]
    fn live_authenticated_handshake_when_configured() {
        let Some(host) = mrml_runtime::environment_variable("MRML_TLS_LIVE_HOST") else {
            return;
        };
        let port = mrml_runtime::environment_variable("MRML_TLS_LIVE_PORT")
            .and_then(|p| p.parse().ok())
            .unwrap_or(443);
        let mut tls = TlsClientStream::connect(&host, port).unwrap();
        if mrml_runtime::environment_variable("MRML_TLS_REQUIRE_HYBRID").is_some() {
            assert_eq!(tls.negotiated_group(), X25519_MLKEM768);
        }
        tls.write_all(b"HEAD / HTTP/1.1\r\n").unwrap();
        tls.write_all(mrml_runtime::mrml_format!("Host: {}\r\n", host).as_bytes())
            .unwrap();
        tls.write_all(b"Connection: close\r\n\r\n").unwrap();
        let mut response = [0u8; 64];
        let read = tls.read(&mut response).unwrap();
        assert!(read >= 12);
        assert_eq!(&response[..5], b"HTTP/");
    }
}
