use crate::{
    Header, HttpError, QuicClientConnection, QuicConnection, QuicFrame, QuicServerListener,
    QuicStreamAssembler, QuicVersion, RequestHead, ResponseBodySink, ResponseHead, valid_header,
    valid_value,
};
use mrml_runtime::{JoinHandle, Receiver, Sender, Vector};
use mrml_tls::TlsServerConfig;
const MAX_FRAME: usize = 1024 * 1024;
const QPACK_STATIC: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3FrameKind {
    Data,
    Headers,
    Settings,
    GoAway,
    Unknown(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3StreamPhase {
    ExpectHeaders,
    Body,
    Trailers,
    Finished,
}

pub struct Http3RequestStreamState {
    phase: Http3StreamPhase,
}
impl Http3RequestStreamState {
    pub const fn new() -> Self {
        Self {
            phase: Http3StreamPhase::ExpectHeaders,
        }
    }
    pub fn receive(&mut self, frame: &Http3Frame, finished: bool) -> Result<(), HttpError> {
        self.phase = match (self.phase, frame.kind) {
            (Http3StreamPhase::ExpectHeaders, Http3FrameKind::Headers) => Http3StreamPhase::Body,
            (Http3StreamPhase::Body, Http3FrameKind::Data) => Http3StreamPhase::Body,
            (Http3StreamPhase::Body, Http3FrameKind::Headers) => Http3StreamPhase::Trailers,
            (Http3StreamPhase::Trailers, Http3FrameKind::Headers | Http3FrameKind::Data)
            | (Http3StreamPhase::Finished, _) => return Err(HttpError::InvalidResponse),
            (_, Http3FrameKind::Settings | Http3FrameKind::GoAway) => {
                return Err(HttpError::InvalidResponse);
            }
            (phase, Http3FrameKind::Unknown(_)) => phase,
            _ => return Err(HttpError::InvalidResponse),
        };
        if finished {
            if self.phase == Http3StreamPhase::ExpectHeaders {
                return Err(HttpError::InvalidResponse);
            }
            self.phase = Http3StreamPhase::Finished;
        }
        Ok(())
    }
    pub fn phase(&self) -> Http3StreamPhase {
        self.phase
    }
    fn finish(&mut self) -> Result<(), HttpError> {
        if self.phase == Http3StreamPhase::ExpectHeaders {
            return Err(HttpError::InvalidResponse);
        }
        self.phase = Http3StreamPhase::Finished;
        Ok(())
    }
}
impl Default for Http3RequestStreamState {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Http3ConnectionState {
    control_stream: Option<u64>,
    encoder_stream: Option<u64>,
    decoder_stream: Option<u64>,
    settings_received: bool,
    goaway: Option<u64>,
}
impl Http3ConnectionState {
    pub const fn new() -> Self {
        Self {
            control_stream: None,
            encoder_stream: None,
            decoder_stream: None,
            settings_received: false,
            goaway: None,
        }
    }
    pub fn open_peer_unidirectional_stream(
        &mut self,
        stream_id: u64,
        stream_type: u64,
    ) -> Result<(), HttpError> {
        let slot = match stream_type {
            0 => &mut self.control_stream,
            2 => &mut self.encoder_stream,
            3 => &mut self.decoder_stream,
            1 => return Err(HttpError::InvalidResponse),
            _ => return Ok(()),
        };
        if slot.replace(stream_id).is_some() {
            return Err(HttpError::InvalidResponse);
        }
        Ok(())
    }
    pub fn receive_control_frame(&mut self, frame: &Http3Frame) -> Result<(), HttpError> {
        if !self.settings_received && frame.kind != Http3FrameKind::Settings {
            return Err(HttpError::InvalidResponse);
        }
        match frame.kind {
            Http3FrameKind::Settings => {
                if self.settings_received {
                    return Err(HttpError::InvalidResponse);
                }
                validate_settings(&frame.payload)?;
                self.settings_received = true;
            }
            Http3FrameKind::GoAway => {
                let mut at = 0;
                let id = read_varint(&frame.payload, &mut at)?;
                if at != frame.payload.len() || self.goaway.is_some_and(|previous| id > previous) {
                    return Err(HttpError::InvalidResponse);
                }
                self.goaway = Some(id);
            }
            Http3FrameKind::Data | Http3FrameKind::Headers => {
                return Err(HttpError::InvalidResponse);
            }
            Http3FrameKind::Unknown(_) => {}
        }
        Ok(())
    }
    pub fn settings_received(&self) -> bool {
        self.settings_received
    }
}
impl Default for Http3ConnectionState {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_settings(payload: &[u8]) -> Result<(), HttpError> {
    let mut at = 0;
    let mut seen = Vector::new();
    while at < payload.len() {
        let identifier = read_varint(payload, &mut at)?;
        let value = read_varint(payload, &mut at)?;
        if seen.contains(&identifier) || matches!(identifier, 2..=5) {
            return Err(HttpError::InvalidResponse);
        }
        seen.try_push(identifier)
            .map_err(|_| HttpError::Allocation)?;
        let _ = value;
    }
    Ok(())
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http3Frame {
    pub kind: Http3FrameKind,
    pub payload: Vector<u8>,
}
fn varint(out: &mut Vector<u8>, v: u64) -> Result<(), HttpError> {
    if v < (1 << 6) {
        out.try_push(v as u8).map_err(|_| HttpError::Allocation)
    } else if v < (1 << 14) {
        out.try_extend_from_slice(&((v as u16) | 0x4000).to_be_bytes())
            .map_err(|_| HttpError::Allocation)
    } else if v < (1 << 30) {
        out.try_extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes())
            .map_err(|_| HttpError::Allocation)
    } else if v < (1 << 62) {
        out.try_extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes())
            .map_err(|_| HttpError::Allocation)
    } else {
        Err(HttpError::BodyTooLarge)
    }
}
fn read_varint(input: &[u8], at: &mut usize) -> Result<u64, HttpError> {
    if *at >= input.len() {
        return Err(HttpError::InvalidResponse);
    }
    let n = 1usize << ((input[*at] >> 6) as usize);
    if input.len() - *at < n {
        return Err(HttpError::InvalidResponse);
    }
    let mut v = (input[*at] & 0x3f) as u64;
    for b in &input[*at + 1..*at + n] {
        v = (v << 8) | *b as u64
    }
    *at += n;
    Ok(v)
}
impl Http3Frame {
    pub fn encode(&self) -> Result<Vector<u8>, HttpError> {
        if self.payload.len() > MAX_FRAME {
            return Err(HttpError::BodyTooLarge);
        }
        let ty = match self.kind {
            Http3FrameKind::Data => 0,
            Http3FrameKind::Headers => 1,
            Http3FrameKind::Settings => 4,
            Http3FrameKind::GoAway => 7,
            Http3FrameKind::Unknown(v) => v,
        };
        let mut o = Vector::new();
        varint(&mut o, ty)?;
        varint(&mut o, self.payload.len() as u64)?;
        o.try_extend_from_slice(&self.payload)
            .map_err(|_| HttpError::Allocation)?;
        Ok(o)
    }
    pub fn decode(input: &[u8]) -> Result<(Self, usize), HttpError> {
        let mut at = 0;
        let ty = read_varint(input, &mut at)?;
        let n = read_varint(input, &mut at)?;
        let n = usize::try_from(n).map_err(|_| HttpError::BodyTooLarge)?;
        if n > MAX_FRAME || input.len() - at < n {
            return Err(HttpError::InvalidResponse);
        }
        let kind = match ty {
            0 => Http3FrameKind::Data,
            1 => Http3FrameKind::Headers,
            4 => Http3FrameKind::Settings,
            7 => Http3FrameKind::GoAway,
            v => Http3FrameKind::Unknown(v),
        };
        let mut payload = Vector::new();
        payload
            .try_extend_from_slice(&input[at..at + n])
            .map_err(|_| HttpError::Allocation)?;
        Ok((Self { kind, payload }, at + n))
    }
}

fn partial_varint(input: &[u8], at: &mut usize) -> Result<Option<u64>, HttpError> {
    let Some(first) = input.get(*at).copied() else {
        return Ok(None);
    };
    let length = 1usize << ((first >> 6) as usize);
    if input.len() - *at < length {
        return Ok(None);
    }
    let mut value = (first & 0x3f) as u64;
    for byte in &input[*at + 1..*at + length] {
        value = (value << 8) | *byte as u64;
    }
    *at += length;
    Ok(Some(value))
}

fn complete_frame_length(input: &[u8]) -> Result<Option<usize>, HttpError> {
    let mut at = 0;
    if partial_varint(input, &mut at)?.is_none() {
        return Ok(None);
    }
    let Some(payload) = partial_varint(input, &mut at)? else {
        return Ok(None);
    };
    let payload = usize::try_from(payload).map_err(|_| HttpError::BodyTooLarge)?;
    if payload > MAX_FRAME {
        return Err(HttpError::BodyTooLarge);
    }
    let total = at.checked_add(payload).ok_or(HttpError::BodyTooLarge)?;
    Ok((input.len() >= total).then_some(total))
}
fn qstr(out: &mut Vector<u8>, s: &str) -> Result<(), HttpError> {
    if s.len() > 127 {
        return Err(HttpError::HeaderTooLarge);
    }
    out.try_push(s.len() as u8)
        .map_err(|_| HttpError::Allocation)?;
    out.try_extend_from_slice(s.as_bytes())
        .map_err(|_| HttpError::Allocation)
}
fn qread_string(input: &[u8], at: &mut usize) -> Result<mrml_runtime::Text, HttpError> {
    if *at >= input.len() {
        return Err(HttpError::InvalidResponse);
    }
    let huffman = input[*at] & 0x80 != 0;
    let length = qread_int(input, at, 7)?;
    let end = at.checked_add(length).ok_or(HttpError::InvalidResponse)?;
    if end > input.len() {
        return Err(HttpError::InvalidResponse);
    }
    let decoded = if huffman {
        Some(crate::huffman::decode(&input[*at..end], MAX_FRAME)?)
    } else {
        None
    };
    let value = core::str::from_utf8(decoded.as_deref().unwrap_or(&input[*at..end]))
        .map_err(|_| HttpError::InvalidResponse)?;
    *at = end;
    mrml_runtime::Text::try_from_str(value).map_err(|_| HttpError::Allocation)
}
fn qint(out: &mut Vector<u8>, prefix: u8, bits: u8, mut value: usize) -> Result<(), HttpError> {
    let max = (1usize << bits) - 1;
    if value < max {
        out.try_push(prefix | value as u8)
            .map_err(|_| HttpError::Allocation)?;
        return Ok(());
    }
    out.try_push(prefix | max as u8)
        .map_err(|_| HttpError::Allocation)?;
    value -= max;
    while value >= 128 {
        out.try_push((value as u8 & 0x7f) | 0x80)
            .map_err(|_| HttpError::Allocation)?;
        value >>= 7;
    }
    out.try_push(value as u8)
        .map_err(|_| HttpError::Allocation)
        .map(|_| ())
}
fn qread_int(input: &[u8], at: &mut usize, bits: u8) -> Result<usize, HttpError> {
    if *at >= input.len() {
        return Err(HttpError::InvalidResponse);
    }
    let first = input[*at];
    *at += 1;
    let max = (1usize << bits) - 1;
    let mut value = first as usize & max;
    if value < max {
        return Ok(value);
    }
    let mut shift = 0;
    loop {
        if *at >= input.len() || shift > 56 {
            return Err(HttpError::InvalidResponse);
        }
        let byte = input[*at];
        *at += 1;
        value = value
            .checked_add(
                ((byte & 0x7f) as usize)
                    .checked_shl(shift)
                    .ok_or(HttpError::InvalidResponse)?,
            )
            .ok_or(HttpError::InvalidResponse)?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}
fn qblock(fields: &[(&str, &str)]) -> Result<Vector<u8>, HttpError> {
    let mut o = Vector::new();
    o.try_extend_from_slice(&[0, 0])
        .map_err(|_| HttpError::Allocation)?;
    for (n, v) in fields {
        if !valid_field_name(n) || n.bytes().any(|b| b.is_ascii_uppercase()) || !valid_value(v) {
            return Err(HttpError::InvalidUrl);
        }
        if let Some(index) = QPACK_STATIC.iter().position(|entry| *entry == (*n, *v)) {
            qint(&mut o, 0xc0, 6, index)?;
            continue;
        }
        if let Some(index) = QPACK_STATIC.iter().position(|entry| entry.0 == *n) {
            qint(&mut o, 0x50, 4, index)?;
        } else {
            qint(&mut o, 0x20, 3, n.len())?;
            o.try_extend_from_slice(n.as_bytes())
                .map_err(|_| HttpError::Allocation)?;
        }
        qstr(&mut o, v)?
    }
    Ok(o)
}
fn valid_field_name(name: &str) -> bool {
    valid_header(name) || name.strip_prefix(':').is_some_and(valid_header)
}
fn qdecode(input: &[u8]) -> Result<Vector<Header>, HttpError> {
    if input.len() < 2 {
        return Err(HttpError::InvalidResponse);
    }
    let mut at = 0;
    if qread_int(input, &mut at, 8)? != 0 {
        return Err(HttpError::InvalidResponse);
    }
    let sign = input.get(at).ok_or(HttpError::InvalidResponse)? & 0x80 != 0;
    if sign || qread_int(input, &mut at, 7)? != 0 {
        return Err(HttpError::InvalidResponse);
    }
    let mut o = Vector::new();
    while at < input.len() {
        let b = input[at];
        let (name, value) = if b & 0x80 != 0 {
            if b & 0x40 == 0 {
                return Err(HttpError::InvalidResponse);
            }
            let index = qread_int(input, &mut at, 6)?;
            let &(name, value) = QPACK_STATIC.get(index).ok_or(HttpError::InvalidResponse)?;
            (name.into(), value.into())
        } else if b & 0xc0 == 0x40 {
            if b & 0x10 == 0 {
                return Err(HttpError::InvalidResponse);
            }
            let index = qread_int(input, &mut at, 4)?;
            let name: mrml_runtime::Text = QPACK_STATIC
                .get(index)
                .ok_or(HttpError::InvalidResponse)?
                .0
                .into();
            (name, qread_string(input, &mut at)?)
        } else if b & 0xe0 == 0x20 {
            let huffman_name = b & 0x08 != 0;
            let length = qread_int(input, &mut at, 3)?;
            if length == 0 || input.len() - at < length {
                return Err(HttpError::InvalidResponse);
            }
            let decoded = if huffman_name {
                Some(crate::huffman::decode(&input[at..at + length], MAX_FRAME)?)
            } else {
                None
            };
            let name = core::str::from_utf8(decoded.as_deref().unwrap_or(&input[at..at + length]))
                .map_err(|_| HttpError::InvalidResponse)?;
            let name = mrml_runtime::Text::try_from_str(name).map_err(|_| HttpError::Allocation)?;
            at += length;
            (name, qread_string(input, &mut at)?)
        } else {
            return Err(HttpError::InvalidResponse);
        };
        if !valid_field_name(&name) || !valid_value(&value) {
            return Err(HttpError::InvalidResponse);
        }
        o.try_push(Header { name, value })
            .map_err(|_| HttpError::Allocation)?
    }
    Ok(o)
}
fn take(h: &mut Vector<Header>, n: &str) -> Result<mrml_runtime::Text, HttpError> {
    let p = h
        .iter()
        .position(|x| x.name == n)
        .ok_or(HttpError::InvalidResponse)?;
    if h.iter().filter(|x| x.name == n).count() != 1 {
        return Err(HttpError::InvalidResponse);
    }
    Ok(h.remove(p).value)
}
pub struct Http3Client;
impl Http3Client {
    pub const fn new() -> Self {
        Self
    }
    pub fn control_stream(&self) -> Result<Vector<u8>, HttpError> {
        let mut o = Vector::new();
        varint(&mut o, 0)?;
        o.try_extend_from_slice(
            &Http3Frame {
                kind: Http3FrameKind::Settings,
                payload: Vector::new(),
            }
            .encode()?,
        )
        .map_err(|_| HttpError::Allocation)?;
        Ok(o)
    }
    pub fn critical_streams(&self) -> Result<[Vector<u8>; 3], HttpError> {
        Ok([self.control_stream()?, [2].into(), [3].into()])
    }
    pub fn request(
        &self,
        method: &str,
        scheme: &str,
        authority: &str,
        target: &str,
        headers: &[(&str, &str)],
    ) -> Result<Vector<u8>, HttpError> {
        let mut f = Vector::new();
        for p in [
            (":method", method),
            (":scheme", scheme),
            (":authority", authority),
            (":path", target),
        ] {
            f.try_push(p).map_err(|_| HttpError::Allocation)?
        }
        for p in headers {
            f.try_push(*p).map_err(|_| HttpError::Allocation)?
        }
        Http3Frame {
            kind: Http3FrameKind::Headers,
            payload: qblock(&f)?,
        }
        .encode()
    }
    pub fn request_with_control_body(
        &self,
        method: &str,
        scheme: &str,
        authority: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Vector<u8>, HttpError> {
        if body.len() > 4096 {
            return Err(HttpError::BodyTooLarge);
        }
        let mut wire = self.request(method, scheme, authority, target, headers)?;
        if !body.is_empty() {
            let mut payload = Vector::new();
            payload
                .try_extend_from_slice(body)
                .map_err(|_| HttpError::Allocation)?;
            wire.try_extend_from_slice(
                &Http3Frame {
                    kind: Http3FrameKind::Data,
                    payload,
                }
                .encode()?,
            )
            .map_err(|_| HttpError::Allocation)?;
        }
        Ok(wire)
    }
    pub fn response(&self, frame: &Http3Frame) -> Result<ResponseHead, HttpError> {
        if frame.kind != Http3FrameKind::Headers {
            return Err(HttpError::InvalidResponse);
        }
        let mut h = qdecode(&frame.payload)?;
        let status: u16 = take(&mut h, ":status")?
            .parse()
            .map_err(|_| HttpError::InvalidResponse)?;
        if !(100..=599).contains(&status) || h.iter().any(|x| x.name.starts_with(':')) {
            return Err(HttpError::InvalidResponse);
        }
        Ok(ResponseHead { status, headers: h })
    }
}
impl Default for Http3Client {
    fn default() -> Self {
        Self::new()
    }
}
pub struct Http3Server;
impl Http3Server {
    pub const fn new() -> Self {
        Self
    }
    pub fn control_stream(&self) -> Result<Vector<u8>, HttpError> {
        Http3Client::new().control_stream()
    }
    pub fn request(&self, frame: &Http3Frame) -> Result<RequestHead, HttpError> {
        if frame.kind != Http3FrameKind::Headers {
            return Err(HttpError::InvalidResponse);
        }
        let mut h = qdecode(&frame.payload)?;
        let method = take(&mut h, ":method")?;
        let scheme = take(&mut h, ":scheme")?;
        let authority = take(&mut h, ":authority")?;
        let target = take(&mut h, ":path")?;
        if h.iter().any(|x| x.name.starts_with(':')) {
            return Err(HttpError::InvalidResponse);
        }
        Ok(RequestHead {
            method,
            scheme,
            authority,
            target,
            headers: h,
        })
    }
    pub fn response(&self, status: u16, headers: &[(&str, &str)]) -> Result<Vector<u8>, HttpError> {
        if !(100..=599).contains(&status) {
            return Err(HttpError::InvalidUrl);
        }
        let s = mrml_runtime::mrml_format!("{}", status);
        let mut f = Vector::new();
        f.try_push((":status", s.as_str()))
            .map_err(|_| HttpError::Allocation)?;
        for p in headers {
            f.try_push(*p).map_err(|_| HttpError::Allocation)?
        }
        Http3Frame {
            kind: Http3FrameKind::Headers,
            payload: qblock(&f)?,
        }
        .encode()
    }
}
impl Default for Http3Server {
    fn default() -> Self {
        Self::new()
    }
}

fn quic_error(_: crate::QuicError) -> HttpError {
    HttpError::Io
}
fn stream_frame(id: u64, offset: u64, fin: bool, data: &[u8]) -> Result<QuicFrame, HttpError> {
    let mut owned = Vector::new();
    owned
        .try_extend_from_slice(data)
        .map_err(|_| HttpError::Allocation)?;
    Ok(QuicFrame::Stream {
        id,
        offset,
        fin,
        data: owned,
    })
}
fn send_critical_streams(connection: &mut QuicConnection) -> Result<(), HttpError> {
    let mut frames = Vector::new();
    for bytes in Http3Client::new().critical_streams()? {
        let id = connection.open_uni_stream().map_err(quic_error)?;
        frames
            .try_push(stream_frame(id, 0, false, &bytes)?)
            .map_err(|_| HttpError::Allocation)?;
    }
    connection.send_frames(&frames).map_err(quic_error)
}
fn receive_control_data(
    state: &mut Http3ConnectionState,
    id: u64,
    data: &[u8],
) -> Result<(), HttpError> {
    let mut at = 0;
    let stream_type = read_varint(data, &mut at)?;
    state.open_peer_unidirectional_stream(id, stream_type)?;
    if stream_type == 0 {
        while at < data.len() {
            let (frame, used) = Http3Frame::decode(&data[at..])?;
            state.receive_control_frame(&frame)?;
            at += used;
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http3Response {
    pub status: u16,
    pub headers: Vector<Header>,
    pub body: Vector<u8>,
}

pub struct Http3ClientConnection {
    connection: QuicConnection,
    protocol: Http3Client,
    state: Http3ConnectionState,
}
struct LimitedBody {
    bytes: Vector<u8>,
    limit: usize,
}
impl ResponseBodySink for LimitedBody {
    fn write(&mut self, bytes: &[u8]) -> Result<(), HttpError> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|length| length > self.limit)
        {
            return Err(HttpError::BodyTooLarge);
        }
        self.bytes
            .try_extend_from_slice(bytes)
            .map_err(|_| HttpError::Allocation)
    }
}
impl Http3ClientConnection {
    pub fn connect(host: &str, port: u16) -> Result<Self, HttpError> {
        Self::connect_version(host, port, QuicVersion::V1)
    }
    pub fn connect_v2(host: &str, port: u16) -> Result<Self, HttpError> {
        Self::connect_version(host, port, QuicVersion::V2)
    }
    pub fn connect_version(host: &str, port: u16, version: QuicVersion) -> Result<Self, HttpError> {
        let mut connection =
            QuicClientConnection::connect_version(host, port, version).map_err(quic_error)?;
        send_critical_streams(&mut connection)?;
        Ok(Self {
            connection,
            protocol: Http3Client::new(),
            state: Http3ConnectionState::new(),
        })
    }
    pub fn connect_resolved(
        host: &str,
        address: [u8; 4],
        port: u16,
        version: QuicVersion,
    ) -> Result<Self, HttpError> {
        let mut connection = QuicClientConnection::connect_resolved(host, address, port, version)
            .map_err(quic_error)?;
        send_critical_streams(&mut connection)?;
        Ok(Self {
            connection,
            protocol: Http3Client::new(),
            state: Http3ConnectionState::new(),
        })
    }
    pub fn request(
        &mut self,
        method: &str,
        authority: &str,
        target: &str,
        headers: &[(&str, &str)],
    ) -> Result<Http3Response, HttpError> {
        self.request_control_with_body(method, authority, target, headers, &[])
    }

    /// Send one deliberately small request body in the initial request-stream
    /// packet. This is for bounded control-plane commands, not pack transfer;
    /// bulk callers must use the flow-controlled streaming path.
    pub fn request_control_with_body(
        &mut self,
        method: &str,
        authority: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Http3Response, HttpError> {
        let mut output = LimitedBody {
            bytes: Vector::new(),
            limit: 16 * 1024 * 1024,
        };
        let head = self.request_control_with_body_to(
            method,
            authority,
            target,
            headers,
            body,
            &mut output,
        )?;
        Ok(Http3Response {
            status: head.status,
            headers: head.headers,
            body: output.bytes,
        })
    }

    pub fn request_control_with_body_to(
        &mut self,
        method: &str,
        authority: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        output: &mut dyn ResponseBodySink,
    ) -> Result<ResponseHead, HttpError> {
        let id = self.connection.open_bidi_stream().map_err(quic_error)?;
        let request = self
            .protocol
            .request_with_control_body(method, "https", authority, target, headers, body)?;
        self.connection
            .send_frames(&[stream_frame(id, 0, true, &request)?])
            .map_err(quic_error)?;
        let mut stream = QuicStreamAssembler::new(MAX_FRAME + 64 * 1024);
        let mut head = None;
        loop {
            for frame in self.connection.receive_frames().map_err(quic_error)? {
                if let QuicFrame::Stream {
                    id: received,
                    offset,
                    fin,
                    data,
                } = frame
                {
                    if received & 3 == 3 {
                        if offset != 0 || fin {
                            return Err(HttpError::InvalidResponse);
                        }
                        receive_control_data(&mut self.state, received, &data)?;
                    } else if received == id {
                        stream.insert(offset, &data, fin).map_err(quic_error)?;
                    }
                }
            }
            while let Some(used) = complete_frame_length(stream.contiguous())? {
                let (frame, decoded) = Http3Frame::decode(&stream.contiguous()[..used])?;
                if decoded != used {
                    return Err(HttpError::InvalidResponse);
                }
                match frame.kind {
                    Http3FrameKind::Headers if head.is_none() => {
                        head = Some(self.protocol.response(&frame)?)
                    }
                    Http3FrameKind::Data if head.is_some() => {
                        output.write(&frame.payload)?;
                    }
                    Http3FrameKind::Unknown(_) => {}
                    _ => return Err(HttpError::InvalidResponse),
                }
                stream.consume(used).map_err(quic_error)?;
            }
            if stream.is_finished() {
                if !stream.contiguous().is_empty() {
                    return Err(HttpError::InvalidResponse);
                }
                return head.ok_or(HttpError::InvalidResponse);
            }
        }
    }
}

pub struct Http3ServerConnection {
    connection: QuicConnection,
    protocol: Http3Server,
    state: Http3ConnectionState,
    unidirectional: Vector<IncomingHttp3Stream>,
    requests: Vector<IncomingHttp3Stream>,
    completed_requests: Vector<u64>,
    ready_request: Option<(u64, RequestHead)>,
    response_stream: Option<u64>,
    response_offset: u64,
}

/// A response encoded away from the authoritative QUIC connection owner.
/// Packet numbers, recovery state, congestion control, and UDP I/O are not
/// present here and therefore cannot be raced by workers.
pub struct PreparedHttp3Response {
    stream_id: u64,
    frames: Vector<QuicFrame>,
}

struct Http3ResponseJob {
    stream_id: u64,
    status: u16,
    headers: Vector<Header>,
    body: Vector<u8>,
}

/// Bounded CPU worker pool for independent HTTP/3 response preparation.
///
/// The application may submit work from its request dispatcher. The single
/// QUIC owner must call `receive` and then `respond_prepared`; bounded queues
/// apply backpressure instead of allowing unbounded per-stream allocation.
pub struct Http3WorkerPool {
    jobs: Option<Sender<Http3ResponseJob>>,
    completed: Option<Receiver<Result<PreparedHttp3Response, HttpError>>>,
    workers: Vector<JoinHandle>,
}

impl Http3WorkerPool {
    pub fn new(worker_count: usize, queue_capacity: usize) -> Result<Self, HttpError> {
        if worker_count == 0 || worker_count > 64 || queue_capacity == 0 || queue_capacity > 4096 {
            return Err(HttpError::InvalidUrl);
        }
        let (jobs, receiver) = mrml_runtime::blocking_channel(queue_capacity);
        let (completed_sender, completed) = mrml_runtime::blocking_channel(queue_capacity);
        let mut workers = Vector::new();
        for _ in 0..worker_count {
            let receiver = receiver.clone();
            let completed_sender = completed_sender.clone();
            let worker = mrml_runtime::spawn_joinable(move || {
                while let Ok(job) = receiver.recv() {
                    let result = prepare_response(job);
                    if completed_sender.send(result).is_err() {
                        break;
                    }
                }
            })
            .map_err(|_| HttpError::Allocation)?;
            workers
                .try_push(worker)
                .map_err(|_| HttpError::Allocation)?;
        }
        Ok(Self {
            jobs: Some(jobs),
            completed: Some(completed),
            workers,
        })
    }

    pub fn for_available_cpus(queue_capacity: usize) -> Result<Self, HttpError> {
        Self::new(
            mrml_runtime::available_parallelism().clamp(1, 64),
            queue_capacity,
        )
    }

    pub fn submit(
        &self,
        stream_id: u64,
        status: u16,
        headers: &[Header],
        body: &[u8],
    ) -> Result<(), HttpError> {
        if stream_id & 3 != 0 || body.len() > 16 * 1024 * 1024 {
            return Err(HttpError::BodyTooLarge);
        }
        let mut owned_headers = Vector::new();
        for header in headers {
            owned_headers
                .try_push(header.clone())
                .map_err(|_| HttpError::Allocation)?;
        }
        let mut owned_body = Vector::new();
        owned_body
            .try_extend_from_slice(body)
            .map_err(|_| HttpError::Allocation)?;
        self.jobs
            .as_ref()
            .ok_or(HttpError::Io)?
            .send(Http3ResponseJob {
                stream_id,
                status,
                headers: owned_headers,
                body: owned_body,
            })
            .map_err(|_| HttpError::Io)
    }

    pub fn receive(&self) -> Result<PreparedHttp3Response, HttpError> {
        self.completed
            .as_ref()
            .ok_or(HttpError::Io)?
            .recv()
            .map_err(|_| HttpError::Io)?
    }
}

impl Drop for Http3WorkerPool {
    fn drop(&mut self) {
        self.jobs.take();
        self.completed.take();
        while let Some(worker) = self.workers.pop() {
            let _ = worker.join();
        }
    }
}

fn prepare_response(job: Http3ResponseJob) -> Result<PreparedHttp3Response, HttpError> {
    if !(100..=599).contains(&job.status) {
        return Err(HttpError::InvalidUrl);
    }
    let status = mrml_runtime::mrml_format!("{}", job.status);
    let mut fields: Vector<(&str, &str)> = Vector::new();
    fields
        .try_push((":status", status.as_str()))
        .map_err(|_| HttpError::Allocation)?;
    for header in &job.headers {
        if !valid_header(&header.name) || !valid_value(&header.value) {
            return Err(HttpError::InvalidUrl);
        }
        fields
            .try_push((header.name.as_str(), header.value.as_str()))
            .map_err(|_| HttpError::Allocation)?;
    }
    let headers = Http3Frame {
        kind: Http3FrameKind::Headers,
        payload: qblock(&fields)?,
    }
    .encode()?;
    let mut frames = Vector::new();
    frames
        .try_push(stream_frame(
            job.stream_id,
            0,
            job.body.is_empty(),
            &headers,
        )?)
        .map_err(|_| HttpError::Allocation)?;
    let mut offset = headers.len() as u64;
    for (index, chunk) in job.body.chunks(800).enumerate() {
        let mut payload = Vector::new();
        payload
            .try_extend_from_slice(chunk)
            .map_err(|_| HttpError::Allocation)?;
        let bytes = Http3Frame {
            kind: Http3FrameKind::Data,
            payload,
        }
        .encode()?;
        let fin = (index + 1) * 800 >= job.body.len();
        frames
            .try_push(stream_frame(job.stream_id, offset, fin, &bytes)?)
            .map_err(|_| HttpError::Allocation)?;
        offset = offset
            .checked_add(bytes.len() as u64)
            .ok_or(HttpError::BodyTooLarge)?;
    }
    Ok(PreparedHttp3Response {
        stream_id: job.stream_id,
        frames,
    })
}

struct IncomingHttp3Stream {
    id: u64,
    bytes: QuicStreamAssembler,
    parsed: usize,
    stream_type: Option<u64>,
    request_state: Http3RequestStreamState,
    head: Option<RequestHead>,
    head_delivered: bool,
    pending_body: Vector<u8>,
    body_finished: bool,
}

const MAX_ACTIVE_HTTP3_STREAMS: usize = 256;
const MAX_COMPLETED_HTTP3_STREAMS: usize = 1024;
const MAX_PENDING_HTTP3_BODY: usize = 64 * 1024;

fn complete_varint(input: &[u8], at: usize) -> Result<Option<(u64, usize)>, HttpError> {
    let Some(first) = input.get(at) else {
        return Ok(None);
    };
    let width = 1usize << (first >> 6);
    if input.len().saturating_sub(at) < width {
        return Ok(None);
    }
    let mut end = at;
    let value = read_varint(input, &mut end)?;
    Ok(Some((value, end)))
}

fn complete_http3_frame(input: &[u8]) -> Result<Option<(Http3Frame, usize)>, HttpError> {
    let Some((_, after_kind)) = complete_varint(input, 0)? else {
        return Ok(None);
    };
    let Some((length, after_length)) = complete_varint(input, after_kind)? else {
        return Ok(None);
    };
    let length = usize::try_from(length).map_err(|_| HttpError::BodyTooLarge)?;
    let total = after_length
        .checked_add(length)
        .ok_or(HttpError::BodyTooLarge)?;
    if total > MAX_FRAME || input.len() < total {
        return if total > MAX_FRAME {
            Err(HttpError::BodyTooLarge)
        } else {
            Ok(None)
        };
    }
    let (frame, used) = Http3Frame::decode(&input[..total])?;
    Ok(Some((frame, used)))
}

fn copy_http3_pending_body(
    stream: &mut IncomingHttp3Stream,
    output: &mut [u8],
) -> Result<usize, HttpError> {
    let count = output.len().min(stream.pending_body.len());
    output[..count].copy_from_slice(&stream.pending_body[..count]);
    let remaining = stream.pending_body.len() - count;
    stream.pending_body.copy_within(count.., 0);
    stream.pending_body.truncate(remaining);
    Ok(count)
}

impl Http3ServerConnection {
    pub fn accept(
        listener: QuicServerListener,
        config: &TlsServerConfig,
    ) -> Result<Self, HttpError> {
        let mut connection = listener.accept(config).map_err(quic_error)?;
        send_critical_streams(&mut connection)?;
        Ok(Self {
            connection,
            protocol: Http3Server::new(),
            state: Http3ConnectionState::new(),
            unidirectional: Vector::new(),
            requests: Vector::new(),
            completed_requests: Vector::new(),
            ready_request: None,
            response_stream: None,
            response_offset: 0,
        })
    }
    pub fn next_request(&mut self) -> Result<(u64, RequestHead), HttpError> {
        if self.state.settings_received()
            && let Some(request) = self.ready_request.take()
        {
            if let Some(stream) = self
                .requests
                .iter_mut()
                .find(|stream| stream.id == request.0)
            {
                stream.head_delivered = true;
            }
            return Ok(request);
        }
        loop {
            for frame in self.connection.receive_frames().map_err(quic_error)? {
                if let QuicFrame::Stream {
                    id,
                    offset,
                    fin,
                    data,
                } = frame
                {
                    if id & 3 == 2 {
                        let index = if let Some(index) = self
                            .unidirectional
                            .iter()
                            .position(|stream| stream.id == id)
                        {
                            index
                        } else {
                            if self.unidirectional.len() + self.requests.len()
                                >= MAX_ACTIVE_HTTP3_STREAMS
                            {
                                return Err(HttpError::BodyTooLarge);
                            }
                            self.unidirectional
                                .try_push(IncomingHttp3Stream {
                                    id,
                                    bytes: QuicStreamAssembler::new(1024 * 1024),
                                    parsed: 0,
                                    stream_type: None,
                                    request_state: Http3RequestStreamState::new(),
                                    head: None,
                                    head_delivered: false,
                                    pending_body: Vector::new(),
                                    body_finished: false,
                                })
                                .map_err(|_| HttpError::Allocation)?;
                            self.unidirectional.len() - 1
                        };
                        let stream = &mut self.unidirectional[index];
                        stream
                            .bytes
                            .insert(offset, &data, fin)
                            .map_err(quic_error)?;
                        if stream.stream_type.is_none() {
                            let Some((stream_type, used)) =
                                complete_varint(stream.bytes.contiguous(), 0)?
                            else {
                                continue;
                            };
                            self.state
                                .open_peer_unidirectional_stream(id, stream_type)?;
                            stream.stream_type = Some(stream_type);
                            stream.parsed = used;
                        }
                        if stream.stream_type == Some(0) {
                            loop {
                                let Some((control, used)) = complete_http3_frame(
                                    &stream.bytes.contiguous()[stream.parsed..],
                                )?
                                else {
                                    break;
                                };
                                self.state.receive_control_frame(&control)?;
                                stream.parsed += used;
                            }
                        } else if matches!(stream.stream_type, Some(2) | Some(3))
                            && stream.parsed < stream.bytes.contiguous().len()
                        {
                            return Err(HttpError::InvalidResponse);
                        }
                        if self.state.settings_received()
                            && let Some(request) = self.ready_request.take()
                        {
                            if let Some(stream) = self
                                .requests
                                .iter_mut()
                                .find(|stream| stream.id == request.0)
                            {
                                stream.head_delivered = true;
                            }
                            return Ok(request);
                        }
                    } else if id & 3 == 0 {
                        if self.completed_requests.contains(&id) {
                            return Err(HttpError::InvalidResponse);
                        }
                        let index = if let Some(index) =
                            self.requests.iter().position(|stream| stream.id == id)
                        {
                            index
                        } else {
                            if self.unidirectional.len() + self.requests.len()
                                >= MAX_ACTIVE_HTTP3_STREAMS
                            {
                                return Err(HttpError::BodyTooLarge);
                            }
                            self.requests
                                .try_push(IncomingHttp3Stream {
                                    id,
                                    bytes: QuicStreamAssembler::new(MAX_FRAME + 16),
                                    parsed: 0,
                                    stream_type: None,
                                    request_state: Http3RequestStreamState::new(),
                                    head: None,
                                    head_delivered: false,
                                    pending_body: Vector::new(),
                                    body_finished: false,
                                })
                                .map_err(|_| HttpError::Allocation)?;
                            self.requests.len() - 1
                        };
                        let stream = &mut self.requests[index];
                        stream
                            .bytes
                            .insert(offset, &data, fin)
                            .map_err(quic_error)?;
                        while stream.parsed < stream.bytes.contiguous().len() {
                            let Some((request_frame, used)) =
                                complete_http3_frame(&stream.bytes.contiguous()[stream.parsed..])?
                            else {
                                break;
                            };
                            stream.parsed += used;
                            let finished = stream.bytes.is_finished()
                                && stream.parsed == stream.bytes.contiguous().len();
                            stream.request_state.receive(&request_frame, finished)?;
                            if request_frame.kind == Http3FrameKind::Headers
                                && stream.head.is_none()
                            {
                                stream.head = Some(self.protocol.request(&request_frame)?);
                            } else if request_frame.kind == Http3FrameKind::Data {
                                if request_frame.payload.len()
                                    > MAX_PENDING_HTTP3_BODY
                                        .saturating_sub(stream.pending_body.len())
                                {
                                    return Err(HttpError::BodyTooLarge);
                                }
                                stream
                                    .pending_body
                                    .try_extend_from_slice(&request_frame.payload)
                                    .map_err(|_| HttpError::Allocation)?;
                            }
                        }
                        let finished = stream.bytes.is_finished()
                            && stream.parsed == stream.bytes.contiguous().len();
                        if stream.parsed != 0 {
                            stream.bytes.consume(stream.parsed).map_err(quic_error)?;
                            stream.parsed = 0;
                        }
                        if stream.bytes.is_finished() && !finished {
                            return Err(HttpError::InvalidResponse);
                        }
                        if finished {
                            if stream.request_state.phase() != Http3StreamPhase::Finished {
                                stream.request_state.finish()?;
                            }
                            stream.body_finished = true;
                        }
                        if !stream.head_delivered
                            && let Some(head) = stream.head.clone()
                        {
                            let request = (id, head);
                            if self.state.settings_received() {
                                stream.head_delivered = true;
                                return Ok(request);
                            }
                            if self.ready_request.replace(request).is_some() {
                                return Err(HttpError::BodyTooLarge);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Read DATA for the request whose headers were returned by
    /// `next_request`, retaining at most a bounded pending body window.
    /// This sequential transport path rejects a second request stream while
    /// the selected request body is active rather than silently discarding it.
    pub fn read_request_data(&mut self, id: u64, output: &mut [u8]) -> Result<usize, HttpError> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            let index = self
                .requests
                .iter()
                .position(|stream| stream.id == id && stream.head_delivered)
                .ok_or(HttpError::InvalidResponse)?;
            if !self.requests[index].pending_body.is_empty() {
                return copy_http3_pending_body(&mut self.requests[index], output);
            }
            if self.requests[index].body_finished {
                self.complete_request(index)?;
                return Ok(0);
            }
            for frame in self.connection.receive_frames().map_err(quic_error)? {
                let QuicFrame::Stream {
                    id: frame_id,
                    offset,
                    fin,
                    data,
                } = frame
                else {
                    continue;
                };
                if frame_id == id {
                    self.receive_active_request_data(index, offset, fin, &data)?;
                } else if frame_id & 3 == 2 {
                    self.receive_control_stream_data(frame_id, offset, fin, &data)?;
                } else if frame_id & 3 == 0 {
                    return Err(HttpError::InvalidResponse);
                }
            }
        }
    }

    pub fn request_body_complete(&self, id: u64) -> Result<bool, HttpError> {
        self.requests
            .iter()
            .find(|stream| stream.id == id && stream.head_delivered)
            .map(|stream| stream.body_finished && stream.pending_body.is_empty())
            .ok_or(HttpError::InvalidResponse)
    }

    fn receive_active_request_data(
        &mut self,
        index: usize,
        offset: u64,
        fin: bool,
        data: &[u8],
    ) -> Result<(), HttpError> {
        let stream = &mut self.requests[index];
        stream.bytes.insert(offset, data, fin).map_err(quic_error)?;
        while stream.parsed < stream.bytes.contiguous().len() {
            let Some((frame, used)) =
                complete_http3_frame(&stream.bytes.contiguous()[stream.parsed..])?
            else {
                break;
            };
            stream.parsed += used;
            let finished =
                stream.bytes.is_finished() && stream.parsed == stream.bytes.contiguous().len();
            stream.request_state.receive(&frame, finished)?;
            if frame.kind != Http3FrameKind::Data
                || frame.payload.len()
                    > MAX_PENDING_HTTP3_BODY.saturating_sub(stream.pending_body.len())
            {
                return Err(if frame.kind == Http3FrameKind::Data {
                    HttpError::BodyTooLarge
                } else {
                    HttpError::InvalidResponse
                });
            }
            stream
                .pending_body
                .try_extend_from_slice(&frame.payload)
                .map_err(|_| HttpError::Allocation)?;
        }
        let finished =
            stream.bytes.is_finished() && stream.parsed == stream.bytes.contiguous().len();
        if stream.parsed != 0 {
            stream.bytes.consume(stream.parsed).map_err(quic_error)?;
            stream.parsed = 0;
        }
        if stream.bytes.is_finished() && !finished {
            return Err(HttpError::InvalidResponse);
        }
        if finished {
            if stream.request_state.phase() != Http3StreamPhase::Finished {
                stream.request_state.finish()?;
            }
            stream.body_finished = true;
        }
        Ok(())
    }

    fn receive_control_stream_data(
        &mut self,
        id: u64,
        offset: u64,
        fin: bool,
        data: &[u8],
    ) -> Result<(), HttpError> {
        let index = self
            .unidirectional
            .iter()
            .position(|stream| stream.id == id)
            .ok_or(HttpError::InvalidResponse)?;
        let stream = &mut self.unidirectional[index];
        stream.bytes.insert(offset, data, fin).map_err(quic_error)?;
        if stream.stream_type == Some(0) {
            while stream.parsed < stream.bytes.contiguous().len() {
                let Some((control, used)) =
                    complete_http3_frame(&stream.bytes.contiguous()[stream.parsed..])?
                else {
                    break;
                };
                self.state.receive_control_frame(&control)?;
                stream.parsed += used;
            }
            if stream.parsed != 0 {
                stream.bytes.consume(stream.parsed).map_err(quic_error)?;
                stream.parsed = 0;
            }
            Ok(())
        } else if data.is_empty() {
            Ok(())
        } else {
            Err(HttpError::InvalidResponse)
        }
    }

    fn complete_request(&mut self, index: usize) -> Result<(), HttpError> {
        let id = self.requests[index].id;
        self.requests.remove(index);
        if self.completed_requests.len() >= MAX_COMPLETED_HTTP3_STREAMS {
            return Err(HttpError::BodyTooLarge);
        }
        self.completed_requests
            .try_push(id)
            .map_err(|_| HttpError::Allocation)
    }

    pub fn respond(
        &mut self,
        id: u64,
        status: u16,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<(), HttpError> {
        self.respond_head(id, status, headers, body.is_empty())?;
        if !body.is_empty() {
            self.respond_data(id, body, true)?;
        }
        Ok(())
    }

    pub fn respond_head(
        &mut self,
        id: u64,
        status: u16,
        headers: &[(&str, &str)],
        end_stream: bool,
    ) -> Result<(), HttpError> {
        if self.response_stream.is_some() || id & 3 != 0 {
            return Err(HttpError::InvalidResponse);
        }
        let headers = self.protocol.response(status, headers)?;
        self.connection
            .send_frames(&[stream_frame(id, 0, end_stream, &headers)?])
            .map_err(quic_error)?;
        if !end_stream {
            self.response_stream = Some(id);
            self.response_offset = headers.len() as u64;
        }
        Ok(())
    }

    pub fn respond_data(
        &mut self,
        id: u64,
        body: &[u8],
        end_stream: bool,
    ) -> Result<(), HttpError> {
        if self.response_stream != Some(id) {
            return Err(HttpError::InvalidResponse);
        }
        if body.is_empty() {
            return if end_stream {
                self.finish_response(id)
            } else {
                Ok(())
            };
        }
        for (index, chunk) in body.chunks(800).enumerate() {
            let mut payload = Vector::new();
            payload
                .try_extend_from_slice(chunk)
                .map_err(|_| HttpError::Allocation)?;
            let bytes = Http3Frame {
                kind: Http3FrameKind::Data,
                payload,
            }
            .encode()?;
            let fin = end_stream && (index + 1) * 800 >= body.len();
            self.connection
                .send_frames(&[stream_frame(id, self.response_offset, fin, &bytes)?])
                .map_err(quic_error)?;
            self.response_offset = self
                .response_offset
                .checked_add(bytes.len() as u64)
                .ok_or(HttpError::BodyTooLarge)?;
        }
        if end_stream {
            self.response_stream = None;
            self.response_offset = 0;
        }
        Ok(())
    }

    pub fn finish_response(&mut self, id: u64) -> Result<(), HttpError> {
        if self.response_stream != Some(id) {
            return Err(HttpError::InvalidResponse);
        }
        self.connection
            .send_frames(&[stream_frame(id, self.response_offset, true, &[])?])
            .map_err(quic_error)?;
        self.response_stream = None;
        self.response_offset = 0;
        Ok(())
    }

    pub fn respond_prepared(&mut self, response: PreparedHttp3Response) -> Result<(), HttpError> {
        if self.response_stream.is_some()
            || response.stream_id & 3 != 0
            || response.frames.iter().any(
                |frame| !matches!(frame, QuicFrame::Stream { id, .. } if *id == response.stream_id),
            )
        {
            return Err(HttpError::InvalidResponse);
        }
        for frame in response.frames {
            self.connection.send_frames(&[frame]).map_err(quic_error)?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_request_body_is_consumed_in_caller_sized_slices() {
        let mut stream = IncomingHttp3Stream {
            id: 0,
            bytes: QuicStreamAssembler::new(MAX_FRAME + 16),
            parsed: 0,
            stream_type: None,
            request_state: Http3RequestStreamState::new(),
            head: None,
            head_delivered: true,
            pending_body: [b'a', b'b', b'c', b'd', b'e', b'f'].into(),
            body_finished: true,
        };
        let mut output = [0; 4];
        assert_eq!(copy_http3_pending_body(&mut stream, &mut output), Ok(4));
        assert_eq!(&output, b"abcd");
        assert_eq!(&stream.pending_body[..], b"ef");
        assert_eq!(copy_http3_pending_body(&mut stream, &mut output), Ok(2));
        assert!(stream.pending_body.is_empty());
    }
    #[test]
    fn client_server_round_trip() {
        let c = Http3Client::new();
        let wire = c
            .request("GET", "https", "x", "/", &[("accept", "x")])
            .unwrap();
        let (f, n) = Http3Frame::decode(&wire).unwrap();
        assert_eq!(n, wire.len());
        assert_eq!(Http3Server::new().request(&f).unwrap().method, "GET");
        let wire = Http3Server::new().response(200, &[]).unwrap();
        let (f, _) = Http3Frame::decode(&wire).unwrap();
        assert_eq!(c.response(&f).unwrap().status, 200)
    }
    #[test]
    fn control_request_body_is_exact_and_bounded() {
        let client = Http3Client::new();
        let wire = client
            .request_with_control_body("POST", "https", "x", "/git", &[], b"0000")
            .unwrap();
        let (headers, used) = Http3Frame::decode(&wire).unwrap();
        assert_eq!(headers.kind, Http3FrameKind::Headers);
        let (data, consumed) = Http3Frame::decode(&wire[used..]).unwrap();
        assert_eq!(data.kind, Http3FrameKind::Data);
        assert_eq!(&data.payload[..], b"0000");
        assert_eq!(used + consumed, wire.len());
        assert_eq!(
            client.request_with_control_body("POST", "https", "x", "/", &[], &[0; 4097]),
            Err(HttpError::BodyTooLarge)
        );
    }
    #[test]
    fn partial_frame_length_waits_for_fragmented_header_and_payload() {
        let wire = Http3Frame {
            kind: Http3FrameKind::Data,
            payload: [7; 80].into(),
        }
        .encode()
        .unwrap();
        for end in 0..wire.len() {
            assert_eq!(complete_frame_length(&wire[..end]).unwrap(), None);
        }
        assert_eq!(complete_frame_length(&wire).unwrap(), Some(wire.len()));
        let oversized = [0, 0x80, 0x10, 0, 1];
        assert_eq!(
            complete_frame_length(&oversized),
            Err(HttpError::BodyTooLarge)
        );
    }
    #[test]
    fn bounded_workers_prepare_independent_streams() {
        let pool = Http3WorkerPool::new(2, 2).unwrap();
        pool.submit(0, 200, &[], b"first").unwrap();
        pool.submit(4, 204, &[], b"").unwrap();
        let first = pool.receive().unwrap();
        let second = pool.receive().unwrap();
        assert_ne!(first.stream_id, second.stream_id);
        assert!([0, 4].contains(&first.stream_id));
        assert!([0, 4].contains(&second.stream_id));
        assert!(!first.frames.is_empty());
        assert!(!second.frames.is_empty());
    }
    #[test]
    fn worker_pool_drop_retires_workers_with_undrained_results() {
        let pool = Http3WorkerPool::new(1, 1).unwrap();
        pool.submit(0, 200, &[], b"queued").unwrap();
        drop(pool);
    }
    #[test]
    fn varint_boundaries() {
        for v in [0, 63, 64, 16383, 16384, (1 << 30) - 1] {
            let mut o = Vector::new();
            varint(&mut o, v).unwrap();
            let mut at = 0;
            assert_eq!(read_varint(&o, &mut at).unwrap(), v);
            assert_eq!(at, o.len())
        }
    }
    #[test]
    fn decodes_rfc_static_name_reference() {
        let block = [
            0x00, 0x00, 0x51, 0x0b, b'/', b'i', b'n', b'd', b'e', b'x', b'.', b'h', b't', b'm',
            b'l',
        ];
        let fields = qdecode(&block).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, ":path");
        assert_eq!(fields[0].value, "/index.html");
    }
    #[test]
    fn enforces_critical_streams_settings_and_request_order() {
        let mut connection = Http3ConnectionState::new();
        connection.open_peer_unidirectional_stream(3, 0).unwrap();
        assert!(connection.open_peer_unidirectional_stream(7, 0).is_err());
        assert!(
            connection
                .receive_control_frame(&Http3Frame {
                    kind: Http3FrameKind::GoAway,
                    payload: [0].into(),
                })
                .is_err()
        );
        connection
            .receive_control_frame(&Http3Frame {
                kind: Http3FrameKind::Settings,
                payload: [1, 0, 7, 0].into(),
            })
            .unwrap();
        assert!(connection.settings_received());
        assert!(
            connection
                .receive_control_frame(&Http3Frame {
                    kind: Http3FrameKind::Settings,
                    payload: Vector::new(),
                })
                .is_err()
        );
        let headers = Http3Frame {
            kind: Http3FrameKind::Headers,
            payload: Vector::new(),
        };
        let data = Http3Frame {
            kind: Http3FrameKind::Data,
            payload: Vector::new(),
        };
        let mut request = Http3RequestStreamState::new();
        assert!(request.receive(&data, false).is_err());
        request.receive(&headers, false).unwrap();
        request.receive(&data, true).unwrap();
        assert_eq!(request.phase(), Http3StreamPhase::Finished);
        assert!(request.receive(&data, false).is_err());
    }

    #[test]
    fn live_http3_get_when_configured() {
        let Some(host) = mrml_runtime::environment_variable("MRML_HTTP3_LIVE_HOST") else {
            return;
        };
        let mut quic = QuicClientConnection::connect(&host, 443).unwrap();
        send_critical_streams(&mut quic).unwrap();
        let mut connection = Http3ClientConnection {
            connection: quic,
            protocol: Http3Client::new(),
            state: Http3ConnectionState::new(),
        };
        let response = connection
            .request("GET", &host, "/", &[("user-agent", "mrml-http/1")])
            .unwrap();
        assert!((100..=599).contains(&response.status));
    }

    #[test]
    fn authenticated_loopback_when_configured() {
        let Some(certificate_path) = mrml_runtime::environment_variable("MRML_HTTP3_LOOPBACK_CERT")
        else {
            return;
        };
        let Some(issuer_path) = mrml_runtime::environment_variable("MRML_HTTP3_LOOPBACK_ISSUER")
        else {
            return;
        };
        let Some(key_path) = mrml_runtime::environment_variable("MRML_HTTP3_LOOPBACK_KEY") else {
            return;
        };
        let Some(ocsp_path) = mrml_runtime::environment_variable("MRML_HTTP3_LOOPBACK_OCSP") else {
            return;
        };
        let mut chain = mrml_runtime::read_file(&certificate_path).unwrap();
        chain
            .try_extend_from_slice(&mrml_runtime::read_file(&issuer_path).unwrap())
            .unwrap();
        let key = mrml_runtime::read_file(&key_path).unwrap();
        let ocsp = mrml_runtime::read_file(&ocsp_path).unwrap();
        let config = TlsServerConfig::from_pem(&chain, &key)
            .unwrap()
            .with_protocols(&["h3"])
            .unwrap()
            .with_ocsp_response(&ocsp)
            .unwrap();
        let listener = QuicServerListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let server_error = mrml_runtime::Shared::new(mrml_runtime::SpinMutex::new(None));
        let worker_error = server_error.clone();
        let Ok(worker) = mrml_runtime::spawn_joinable(move || {
            let mut server = match Http3ServerConnection::accept(listener, &config) {
                Ok(server) => server,
                Err(error) => {
                    *worker_error.lock() = Some(error);
                    return;
                }
            };
            let (id, request) = server.next_request().unwrap();
            assert_eq!(request.method, "GET");
            assert_eq!(request.target, "/loopback");
            server.respond(id, 200, &[], b"http3 loopback").unwrap();
        }) else {
            panic!("failed to start HTTP/3 loopback server");
        };
        let test_v2 =
            mrml_runtime::environment_variable("MRML_HTTP3_LOOPBACK_V2").as_deref() == Some("1");
        if let Some(curl) =
            mrml_runtime::environment_variable("MRML_HTTP3_CURL").filter(|_| !test_v2)
        {
            let endpoint = mrml_runtime::mrml_format!("localhost:{port}:127.0.0.1");
            let url = mrml_runtime::mrml_format!("https://localhost:{port}/loopback");
            let output = mrml_runtime::Command::new(&curl)
                .args([
                    "--http3-only",
                    "--silent",
                    "--show-error",
                    "--noproxy",
                    "*",
                    "--cacert",
                ])
                .arg(&issuer_path)
                .args(["--resolve"])
                .arg(&endpoint)
                .arg(&url)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "curl failed: {}",
                core::str::from_utf8(&output.stderr).unwrap_or("non-UTF-8 error")
            );
            assert_eq!(&output.stdout[..], b"http3 loopback");
        } else {
            let mut client = if test_v2 {
                let mut connection = QuicClientConnection::connect_resolved(
                    "localhost",
                    [127, 0, 0, 1],
                    port,
                    QuicVersion::V2,
                )
                .unwrap_or_else(|error| panic!("QUIC v2 handshake failed: {error:?}"));
                assert_eq!(connection.version(), QuicVersion::V2);
                send_critical_streams(&mut connection)
                    .unwrap_or_else(|error| panic!("QUIC v2 critical streams failed: {error:?}"));
                Ok(Http3ClientConnection {
                    connection,
                    protocol: Http3Client::new(),
                    state: Http3ConnectionState::new(),
                })
            } else {
                Http3ClientConnection::connect_resolved(
                    "localhost",
                    [127, 0, 0, 1],
                    port,
                    QuicVersion::V1,
                )
            }
            .unwrap_or_else(|error| {
                let started = mrml_runtime::Instant::now();
                while server_error.lock().is_none()
                    && started.elapsed() < core::time::Duration::from_secs(2)
                {
                    mrml_runtime::yield_now();
                }
                panic!(
                    "HTTP/3 client failed: {error:?}; server: {:?}",
                    *server_error.lock()
                )
            });
            let response = client
                .request("GET", "localhost", "/loopback", &[])
                .unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(&response.body[..], b"http3 loopback");
        }
        assert!(worker.join());
    }
}
