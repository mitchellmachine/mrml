use crate::{
    valid_header, valid_value, Header, HttpError, QuicClientConnection, QuicConnection, QuicFrame,
    QuicServerListener, QuicStreamAssembler, RequestHead, ResponseHead,
};
use mrml_runtime::Vector;
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
                return Err(HttpError::InvalidResponse)
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
                return Err(HttpError::InvalidResponse)
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
impl Http3ClientConnection {
    pub fn connect(host: &str, port: u16) -> Result<Self, HttpError> {
        let mut connection = QuicClientConnection::connect(host, port).map_err(quic_error)?;
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
        let id = self.connection.open_bidi_stream().map_err(quic_error)?;
        let request = self
            .protocol
            .request(method, "https", authority, target, headers)?;
        self.connection
            .send_frames(&[stream_frame(id, 0, true, &request)?])
            .map_err(quic_error)?;
        let mut stream = QuicStreamAssembler::new(16 * 1024 * 1024);
        let mut parsed = 0;
        let mut head = None;
        let mut body = Vector::new();
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
            while parsed < stream.contiguous().len() {
                let (frame, used) = Http3Frame::decode(&stream.contiguous()[parsed..])?;
                parsed += used;
                match frame.kind {
                    Http3FrameKind::Headers if head.is_none() => {
                        head = Some(self.protocol.response(&frame)?)
                    }
                    Http3FrameKind::Data if head.is_some() => {
                        if body.len() + frame.payload.len() > 16 * 1024 * 1024 {
                            return Err(HttpError::BodyTooLarge);
                        }
                        body.try_extend_from_slice(&frame.payload)
                            .map_err(|_| HttpError::Allocation)?;
                    }
                    Http3FrameKind::Unknown(_) => {}
                    _ => return Err(HttpError::InvalidResponse),
                }
            }
            if stream.is_finished() {
                let head = head.ok_or(HttpError::InvalidResponse)?;
                return Ok(Http3Response {
                    status: head.status,
                    headers: head.headers,
                    body,
                });
            }
        }
    }
}

pub struct Http3ServerConnection {
    connection: QuicConnection,
    protocol: Http3Server,
    state: Http3ConnectionState,
}

struct IncomingHttp3Stream {
    id: u64,
    bytes: QuicStreamAssembler,
    parsed: usize,
    stream_type: Option<u64>,
}

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
        })
    }
    pub fn next_request(&mut self) -> Result<(u64, RequestHead), HttpError> {
        let mut unidirectional: Vector<IncomingHttp3Stream> = Vector::new();
        let mut requests: Vector<IncomingHttp3Stream> = Vector::new();
        let mut ready_request: Option<(u64, RequestHead)> = None;
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
                        let index = if let Some(index) =
                            unidirectional.iter().position(|stream| stream.id == id)
                        {
                            index
                        } else {
                            unidirectional
                                .try_push(IncomingHttp3Stream {
                                    id,
                                    bytes: QuicStreamAssembler::new(1024 * 1024),
                                    parsed: 0,
                                    stream_type: None,
                                })
                                .map_err(|_| HttpError::Allocation)?;
                            unidirectional.len() - 1
                        };
                        let stream = &mut unidirectional[index];
                        stream.bytes.insert(offset, &data, fin).map_err(quic_error)?;
                        if stream.stream_type.is_none() {
                            let Some((stream_type, used)) =
                                complete_varint(stream.bytes.contiguous(), 0)?
                            else {
                                continue;
                            };
                            self.state.open_peer_unidirectional_stream(id, stream_type)?;
                            stream.stream_type = Some(stream_type);
                            stream.parsed = used;
                        }
                        if stream.stream_type == Some(0) {
                            loop {
                                let Some((control, used)) = complete_http3_frame(
                                    &stream.bytes.contiguous()[stream.parsed..],
                                )? else {
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
                            && let Some(request) = ready_request.take()
                        {
                            return Ok(request);
                        }
                    } else if id & 3 == 0 {
                        let index = if let Some(index) =
                            requests.iter().position(|stream| stream.id == id)
                        {
                            index
                        } else {
                            requests
                                .try_push(IncomingHttp3Stream {
                                    id,
                                    bytes: QuicStreamAssembler::new(16 * 1024 * 1024),
                                    parsed: 0,
                                    stream_type: None,
                                })
                                .map_err(|_| HttpError::Allocation)?;
                            requests.len() - 1
                        };
                        let stream = &mut requests[index];
                        stream.bytes.insert(offset, &data, fin).map_err(quic_error)?;
                        if !stream.bytes.is_finished() {
                            continue;
                        }
                        let mut request_state = Http3RequestStreamState::new();
                        let mut head = None;
                        while stream.parsed < stream.bytes.contiguous().len() {
                            let Some((request_frame, used)) = complete_http3_frame(
                                &stream.bytes.contiguous()[stream.parsed..],
                            )? else {
                                return Err(HttpError::InvalidResponse);
                            };
                            stream.parsed += used;
                            let finished = stream.parsed == stream.bytes.contiguous().len();
                            request_state.receive(&request_frame, finished)?;
                            if request_frame.kind == Http3FrameKind::Headers && head.is_none() {
                                head = Some(self.protocol.request(&request_frame)?);
                            }
                        }
                        let request = (id, head.ok_or(HttpError::InvalidResponse)?);
                        if self.state.settings_received() {
                            return Ok(request);
                        }
                        ready_request = Some(request);
                    }
                }
            }
        }
    }
    pub fn respond(
        &mut self,
        id: u64,
        status: u16,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<(), HttpError> {
        let headers = self.protocol.response(status, headers)?;
        let mut offset = headers.len() as u64;
        self.connection
            .send_frames(&[stream_frame(id, 0, body.is_empty(), &headers)?])
            .map_err(quic_error)?;
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
            let fin = (index + 1) * 800 >= body.len();
            self.connection
                .send_frames(&[stream_frame(id, offset, fin, &bytes)?])
                .map_err(quic_error)?;
            offset = offset
                .checked_add(bytes.len() as u64)
                .ok_or(HttpError::BodyTooLarge)?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
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
        assert!(connection
            .receive_control_frame(&Http3Frame {
                kind: Http3FrameKind::GoAway,
                payload: [0].into(),
            })
            .is_err());
        connection
            .receive_control_frame(&Http3Frame {
                kind: Http3FrameKind::Settings,
                payload: [1, 0, 7, 0].into(),
            })
            .unwrap();
        assert!(connection.settings_received());
        assert!(connection
            .receive_control_frame(&Http3Frame {
                kind: Http3FrameKind::Settings,
                payload: Vector::new(),
            })
            .is_err());
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
        let Some(certificate_path) =
            mrml_runtime::environment_variable("MRML_HTTP3_LOOPBACK_CERT")
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
        let Ok(worker) = mrml_runtime::spawn_joinable(move || {
            let mut server = Http3ServerConnection::accept(listener, &config).unwrap();
            let (id, request) = server.next_request().unwrap();
            assert_eq!(request.method, "GET");
            assert_eq!(request.target, "/loopback");
            server.respond(id, 200, &[], b"http3 loopback").unwrap();
        }) else {
            panic!("failed to start HTTP/3 loopback server");
        };
        if let Some(curl) = mrml_runtime::environment_variable("MRML_HTTP3_CURL") {
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
            let mut client = Http3ClientConnection::connect("localhost", port).unwrap();
            let response = client.request("GET", "localhost", "/loopback", &[]).unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(&response.body[..], b"http3 loopback");
        }
        assert!(worker.join());
    }
}
