use mrml_runtime::{Text, Vector};
use mrml_tls::{TlsClientStream, TlsError, TlsServerStream};

use crate::{
    Header, HttpError, RequestBodySource, RequestHead, ResponseBodySink, ResponseHead,
    read_request_body_chunk, valid_header, valid_value,
};

pub const HTTP2_CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_FRAME: usize = 16 * 1024;
const ESTABLISHED_HTTP2_IO_TIMEOUT_MILLIS: u64 = 15 * 60 * 1_000;
const HPACK_STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http2FrameKind {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    GoAway,
    WindowUpdate,
    Continuation,
    Unknown(u8),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http2Frame {
    pub kind: Http2FrameKind,
    pub flags: u8,
    pub stream_id: u32,
    pub payload: Vector<u8>,
}

impl Http2Frame {
    pub fn encode(&self) -> Result<Vector<u8>, HttpError> {
        if self.payload.len() > MAX_FRAME || self.stream_id > 0x7fff_ffff {
            return Err(HttpError::BodyTooLarge);
        }
        let ty = match self.kind {
            Http2FrameKind::Data => 0,
            Http2FrameKind::Headers => 1,
            Http2FrameKind::Priority => 2,
            Http2FrameKind::RstStream => 3,
            Http2FrameKind::Settings => 4,
            Http2FrameKind::PushPromise => 5,
            Http2FrameKind::Ping => 6,
            Http2FrameKind::GoAway => 7,
            Http2FrameKind::WindowUpdate => 8,
            Http2FrameKind::Continuation => 9,
            Http2FrameKind::Unknown(v) => v,
        };
        if matches!(
            self.kind,
            Http2FrameKind::Settings | Http2FrameKind::Ping | Http2FrameKind::GoAway
        ) && self.stream_id != 0
        {
            return Err(HttpError::InvalidResponse);
        }
        if matches!(
            self.kind,
            Http2FrameKind::Data
                | Http2FrameKind::Headers
                | Http2FrameKind::Priority
                | Http2FrameKind::RstStream
                | Http2FrameKind::PushPromise
                | Http2FrameKind::Continuation
        ) && self.stream_id == 0
        {
            return Err(HttpError::InvalidResponse);
        }
        let n = self.payload.len();
        let mut out = Vector::new();
        out.try_extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8, ty, self.flags])
            .map_err(|_| HttpError::Allocation)?;
        out.try_extend_from_slice(&self.stream_id.to_be_bytes())
            .map_err(|_| HttpError::Allocation)?;
        out.try_extend_from_slice(&self.payload)
            .map_err(|_| HttpError::Allocation)?;
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<(Self, usize), HttpError> {
        if input.len() < 9 {
            return Err(HttpError::InvalidResponse);
        }
        let n = ((input[0] as usize) << 16) | ((input[1] as usize) << 8) | input[2] as usize;
        if n > MAX_FRAME || input.len() < 9 + n || input[5] & 0x80 != 0 {
            return Err(HttpError::InvalidResponse);
        }
        let stream_id = u32::from_be_bytes([input[5], input[6], input[7], input[8]]);
        let kind = match input[3] {
            0 => Http2FrameKind::Data,
            1 => Http2FrameKind::Headers,
            2 => Http2FrameKind::Priority,
            3 => Http2FrameKind::RstStream,
            4 => Http2FrameKind::Settings,
            5 => Http2FrameKind::PushPromise,
            6 => Http2FrameKind::Ping,
            7 => Http2FrameKind::GoAway,
            8 => Http2FrameKind::WindowUpdate,
            9 => Http2FrameKind::Continuation,
            v => Http2FrameKind::Unknown(v),
        };
        if matches!(
            kind,
            Http2FrameKind::Settings | Http2FrameKind::Ping | Http2FrameKind::GoAway
        ) && stream_id != 0
        {
            return Err(HttpError::InvalidResponse);
        }
        if matches!(
            kind,
            Http2FrameKind::Data
                | Http2FrameKind::Headers
                | Http2FrameKind::Priority
                | Http2FrameKind::RstStream
                | Http2FrameKind::PushPromise
                | Http2FrameKind::Continuation
        ) && stream_id == 0
        {
            return Err(HttpError::InvalidResponse);
        }
        if (kind == Http2FrameKind::Ping && n != 8)
            || (kind == Http2FrameKind::RstStream && n != 4)
            || (kind == Http2FrameKind::Priority && n != 5)
            || (kind == Http2FrameKind::Settings && input[4] & 1 != 0 && n != 0)
            || (kind == Http2FrameKind::Settings && n % 6 != 0)
            || (kind == Http2FrameKind::WindowUpdate && n != 4)
        {
            return Err(HttpError::InvalidResponse);
        }
        let mut payload = Vector::new();
        payload
            .try_extend_from_slice(&input[9..9 + n])
            .map_err(|_| HttpError::Allocation)?;
        Ok((
            Self {
                kind,
                flags: input[4],
                stream_id,
                payload,
            },
            9 + n,
        ))
    }
}

pub struct Http2ConnectionState {
    settings_received: bool,
    continuation_stream: Option<u32>,
    last_peer_stream: u32,
    connection_window: u32,
}
impl Http2ConnectionState {
    pub const fn new() -> Self {
        Self {
            settings_received: false,
            continuation_stream: None,
            last_peer_stream: 0,
            connection_window: 65_535,
        }
    }
    pub fn receive(&mut self, frame: &Http2Frame) -> Result<(), HttpError> {
        if let Some(stream) = self.continuation_stream {
            if frame.kind != Http2FrameKind::Continuation || frame.stream_id != stream {
                return Err(HttpError::InvalidResponse);
            }
        } else if frame.kind == Http2FrameKind::Continuation {
            return Err(HttpError::InvalidResponse);
        }
        match frame.kind {
            Http2FrameKind::Settings => {
                if frame.flags & 1 == 0 {
                    validate_settings(&frame.payload)?;
                    self.settings_received = true;
                }
            }
            Http2FrameKind::Headers | Http2FrameKind::PushPromise => {
                if frame.flags & 4 == 0 {
                    self.continuation_stream = Some(frame.stream_id);
                }
                self.last_peer_stream = self.last_peer_stream.max(frame.stream_id);
            }
            Http2FrameKind::Continuation if frame.flags & 4 != 0 => {
                self.continuation_stream = None;
            }
            Http2FrameKind::WindowUpdate => {
                validate_window_update(frame)?;
                let increment = u32::from_be_bytes([
                    frame.payload[0],
                    frame.payload[1],
                    frame.payload[2],
                    frame.payload[3],
                ]) & 0x7fff_ffff;
                if increment == 0 {
                    return Err(HttpError::InvalidResponse);
                }
                if frame.stream_id == 0 {
                    self.connection_window = self
                        .connection_window
                        .checked_add(increment)
                        .filter(|value| *value <= 0x7fff_ffff)
                        .ok_or(HttpError::InvalidResponse)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    pub fn settings_received(&self) -> bool {
        self.settings_received
    }
}
impl Default for Http2ConnectionState {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_settings(payload: &[u8]) -> Result<(), HttpError> {
    if payload.len() % 6 != 0 {
        return Err(HttpError::InvalidResponse);
    }
    let mut seen = Vector::new();
    for setting in payload.chunks_exact(6) {
        let identifier = u16::from_be_bytes([setting[0], setting[1]]);
        let value = u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]);
        if seen.contains(&identifier) {
            return Err(HttpError::InvalidResponse);
        }
        seen.try_push(identifier)
            .map_err(|_| HttpError::Allocation)?;
        match identifier {
            2 if value > 1 => return Err(HttpError::InvalidResponse),
            4 if value > 0x7fff_ffff => return Err(HttpError::InvalidResponse),
            5 if !(16_384..=16_777_215).contains(&value) => return Err(HttpError::InvalidResponse),
            _ => {}
        }
    }
    Ok(())
}

fn peer_send_settings(payload: &[u8]) -> Result<(Option<i64>, Option<usize>), HttpError> {
    validate_settings(payload)?;
    let mut window = None;
    let mut maximum_frame = None;
    for setting in payload.chunks_exact(6) {
        let identifier = u16::from_be_bytes([setting[0], setting[1]]);
        let value = u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]);
        match identifier {
            4 => window = Some(i64::from(value)),
            5 => maximum_frame = Some(value as usize),
            _ => {}
        }
    }
    Ok((window, maximum_frame))
}

fn validate_window_update(frame: &Http2Frame) -> Result<(), HttpError> {
    if frame.flags != 0 || frame.payload.len() != 4 {
        return Err(HttpError::InvalidResponse);
    }
    let increment = u32::from_be_bytes([
        frame.payload[0],
        frame.payload[1],
        frame.payload[2],
        frame.payload[3],
    ]) & 0x7fff_ffff;
    if increment == 0 {
        return Err(HttpError::InvalidResponse);
    }
    Ok(())
}

fn integer(out: &mut Vector<u8>, prefix: u8, bits: u8, mut value: usize) -> Result<(), HttpError> {
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
fn string(out: &mut Vector<u8>, value: &str) -> Result<(), HttpError> {
    integer(out, 0, 7, value.len())?;
    out.try_extend_from_slice(value.as_bytes())
        .map_err(|_| HttpError::Allocation)
}
fn literal(out: &mut Vector<u8>, name: &str, value: &str) -> Result<(), HttpError> {
    if !valid_field_name(name)
        || !valid_value(value)
        || name.bytes().any(|b| b.is_ascii_uppercase())
    {
        return Err(HttpError::InvalidUrl);
    }
    if let Some(index) = HPACK_STATIC
        .iter()
        .position(|entry| *entry == (name, value))
    {
        return integer(out, 0x80, 7, index + 1);
    }
    if let Some(index) = HPACK_STATIC.iter().position(|entry| entry.0 == name) {
        integer(out, 0, 4, index + 1)?;
    } else {
        out.try_push(0).map_err(|_| HttpError::Allocation)?;
        string(out, name)?;
    }
    string(out, value)
}
fn valid_field_name(name: &str) -> bool {
    valid_header(name) || name.strip_prefix(':').is_some_and(valid_header)
}
fn decode_int(input: &[u8], at: &mut usize, bits: u8) -> Result<usize, HttpError> {
    if *at >= input.len() {
        return Err(HttpError::InvalidResponse);
    }
    let first = input[*at];
    *at += 1;
    let max = (1usize << bits) - 1;
    let mut value = (first as usize) & max;
    if value < max {
        return Ok(value);
    }
    let mut shift = 0;
    loop {
        if *at >= input.len() || shift > 56 {
            return Err(HttpError::InvalidResponse);
        }
        let b = input[*at];
        *at += 1;
        value = value
            .checked_add(
                ((b & 0x7f) as usize)
                    .checked_shl(shift)
                    .ok_or(HttpError::InvalidResponse)?,
            )
            .ok_or(HttpError::InvalidResponse)?;
        if b & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}
fn decode_string(input: &[u8], at: &mut usize) -> Result<Text, HttpError> {
    if *at >= input.len() {
        return Err(HttpError::InvalidResponse);
    }
    let huffman = input[*at] & 0x80 != 0;
    let n = decode_int(input, at, 7)?;
    let end = at.checked_add(n).ok_or(HttpError::InvalidResponse)?;
    if end > input.len() {
        return Err(HttpError::InvalidResponse);
    }
    let decoded = if huffman {
        Some(crate::huffman::decode(&input[*at..end], MAX_FRAME)?)
    } else {
        None
    };
    let bytes = decoded.as_deref().unwrap_or(&input[*at..end]);
    let s = core::str::from_utf8(bytes).map_err(|_| HttpError::InvalidResponse)?;
    *at = end;
    Text::try_from_str(s).map_err(|_| HttpError::Allocation)
}
fn decode_block(input: &[u8]) -> Result<Vector<Header>, HttpError> {
    let mut at = 0;
    let mut out = Vector::new();
    let mut allow_size_update = true;
    while at < input.len() {
        let first = input[at];
        if first & 0xe0 == 0x20 {
            if !allow_size_update || decode_int(input, &mut at, 5)? != 0 {
                return Err(HttpError::InvalidResponse);
            }
            continue;
        }
        allow_size_update = false;
        if first & 0x80 != 0 {
            let index = decode_int(input, &mut at, 7)?;
            let (name, value) = *HPACK_STATIC
                .get(index.checked_sub(1).ok_or(HttpError::InvalidResponse)?)
                .ok_or(HttpError::InvalidResponse)?;
            out.try_push(Header {
                name: name.into(),
                value: value.into(),
            })
            .map_err(|_| HttpError::Allocation)?;
            continue;
        }
        let bits = if first & 0x40 != 0 { 6 } else { 4 };
        let index = decode_int(input, &mut at, bits)?;
        let name = if index == 0 {
            decode_string(input, &mut at)?
        } else {
            HPACK_STATIC
                .get(index - 1)
                .ok_or(HttpError::InvalidResponse)?
                .0
                .into()
        };
        let value = decode_string(input, &mut at)?;
        if !valid_field_name(&name)
            || name.bytes().any(|b| b.is_ascii_uppercase())
            || !valid_value(&value)
        {
            return Err(HttpError::InvalidResponse);
        }
        out.try_push(Header { name, value })
            .map_err(|_| HttpError::Allocation)?;
    }
    Ok(out)
}
fn block(fields: &[(&str, &str)]) -> Result<Vector<u8>, HttpError> {
    let mut out = Vector::new();
    for (n, v) in fields {
        literal(&mut out, n, v)?
    }
    Ok(out)
}

pub struct Http2Client {
    next_stream: u32,
}
impl Http2Client {
    pub const fn new() -> Self {
        Self { next_stream: 1 }
    }
    pub fn connection_bytes(&self) -> Result<Vector<u8>, HttpError> {
        let mut out = Vector::new();
        out.try_extend_from_slice(HTTP2_CLIENT_PREFACE)
            .map_err(|_| HttpError::Allocation)?;
        out.try_extend_from_slice(
            &Http2Frame {
                kind: Http2FrameKind::Settings,
                flags: 0,
                stream_id: 0,
                payload: [0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0].into(),
            }
            .encode()?,
        )
        .map_err(|_| HttpError::Allocation)?;
        Ok(out)
    }
    pub fn request(
        &mut self,
        method: &str,
        scheme: &str,
        authority: &str,
        target: &str,
        headers: &[(&str, &str)],
        end_stream: bool,
    ) -> Result<(u32, Vector<u8>), HttpError> {
        let id = self.next_stream;
        self.next_stream = self
            .next_stream
            .checked_add(2)
            .filter(|v| *v <= 0x7fff_ffff)
            .ok_or(HttpError::BodyTooLarge)?;
        let mut fields = Vector::new();
        for pair in [
            (":method", method),
            (":scheme", scheme),
            (":authority", authority),
            (":path", target),
        ] {
            fields.try_push(pair).map_err(|_| HttpError::Allocation)?
        }
        for pair in headers {
            fields.try_push(*pair).map_err(|_| HttpError::Allocation)?
        }
        let payload = block(&fields)?;
        let frame = Http2Frame {
            kind: Http2FrameKind::Headers,
            flags: 0x4 | if end_stream { 1 } else { 0 },
            stream_id: id,
            payload,
        };
        Ok((id, frame.encode()?))
    }
    pub fn response(&self, frame: &Http2Frame) -> Result<ResponseHead, HttpError> {
        decode_response(frame)
    }
}
impl Default for Http2Client {
    fn default() -> Self {
        Self::new()
    }
}
pub struct Http2Server;
impl Http2Server {
    pub const fn new() -> Self {
        Self
    }
    pub fn settings(&self) -> Result<Vector<u8>, HttpError> {
        Http2Frame {
            kind: Http2FrameKind::Settings,
            flags: 0,
            stream_id: 0,
            payload: Vector::new(),
        }
        .encode()
    }
    pub fn request(&self, frame: &Http2Frame) -> Result<RequestHead, HttpError> {
        if frame.kind != Http2FrameKind::Headers
            || frame.flags & 4 == 0
            || frame.stream_id == 0
            || frame.stream_id % 2 == 0
        {
            return Err(HttpError::InvalidResponse);
        }
        let mut h = decode_block(&frame.payload)?;
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
    pub fn response(
        &self,
        stream_id: u32,
        status: u16,
        headers: &[(&str, &str)],
        end_stream: bool,
    ) -> Result<Vector<u8>, HttpError> {
        if !(100..=599).contains(&status) {
            return Err(HttpError::InvalidUrl);
        }
        let status_text = mrml_runtime::mrml_format!("{}", status);
        let mut fields = Vector::new();
        fields
            .try_push((":status", status_text.as_str()))
            .map_err(|_| HttpError::Allocation)?;
        for p in headers {
            fields.try_push(*p).map_err(|_| HttpError::Allocation)?
        }
        Http2Frame {
            kind: Http2FrameKind::Headers,
            flags: 4 | if end_stream { 1 } else { 0 },
            stream_id,
            payload: block(&fields)?,
        }
        .encode()
    }
}
impl Default for Http2Server {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http2Response {
    pub status: u16,
    pub headers: Vector<Header>,
    pub body: Vector<u8>,
}

fn tls_read_exact_client(stream: &mut TlsClientStream, out: &mut [u8]) -> Result<(), HttpError> {
    let mut at = 0;
    while at < out.len() {
        let count = stream.read(&mut out[at..]).map_err(map_tls_read_error)?;
        if count == 0 {
            return Err(HttpError::Io);
        }
        at += count;
    }
    Ok(())
}
fn map_tls_read_error(error: TlsError) -> HttpError {
    match error {
        TlsError::InvalidRecord | TlsError::SequenceExhausted => HttpError::TlsRecord,
        TlsError::AuthenticationFailed => HttpError::TlsAuthentication,
        TlsError::Handshake => HttpError::TlsHandshake,
        TlsError::Certificate => HttpError::TlsCertificate,
        TlsError::Io => HttpError::TlsTransport,
        TlsError::AllocationFailed => HttpError::Allocation,
    }
}
fn tls_read_exact_server(stream: &mut TlsServerStream, out: &mut [u8]) -> Result<(), HttpError> {
    let mut at = 0;
    while at < out.len() {
        let count = stream.read(&mut out[at..]).map_err(|_| HttpError::Tls)?;
        if count == 0 {
            return Err(HttpError::Io);
        }
        at += count;
    }
    Ok(())
}
fn read_client_frame(stream: &mut TlsClientStream) -> Result<Http2Frame, HttpError> {
    let mut header = [0; 9];
    tls_read_exact_client(stream, &mut header)?;
    let length = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
    if length > MAX_FRAME {
        return Err(HttpError::BodyTooLarge);
    }
    let mut wire = Vector::new();
    wire.try_extend_from_slice(&header)
        .map_err(|_| HttpError::Allocation)?;
    wire.try_resize(9 + length, 0)
        .map_err(|_| HttpError::Allocation)?;
    tls_read_exact_client(stream, &mut wire[9..])?;
    Http2Frame::decode(&wire).map(|value| value.0)
}
fn read_server_frame(stream: &mut TlsServerStream) -> Result<Http2Frame, HttpError> {
    let mut header = [0; 9];
    tls_read_exact_server(stream, &mut header)?;
    let length = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
    if length > MAX_FRAME {
        return Err(HttpError::BodyTooLarge);
    }
    let mut wire = Vector::new();
    wire.try_extend_from_slice(&header)
        .map_err(|_| HttpError::Allocation)?;
    wire.try_resize(9 + length, 0)
        .map_err(|_| HttpError::Allocation)?;
    tls_read_exact_server(stream, &mut wire[9..])?;
    Http2Frame::decode(&wire).map(|value| value.0)
}

pub struct Http2ClientConnection {
    stream: TlsClientStream,
    protocol: Http2Client,
    send_connection_window: i64,
    send_stream_window: i64,
    peer_initial_stream_window: i64,
    peer_maximum_frame: usize,
    pending_response_frames: Vector<Http2Frame>,
}
struct LimitedBody {
    bytes: Vector<u8>,
    limit: usize,
}
struct SliceBodySource<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl RequestBodySource for SliceBodySource<'_> {
    fn remaining(&self) -> u64 {
        (self.bytes.len() - self.offset) as u64
    }
    fn read(&mut self, output: &mut [u8]) -> Result<usize, HttpError> {
        let count = output.len().min(self.bytes.len() - self.offset);
        output[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
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
impl Http2ClientConnection {
    pub fn connect(host: &str, port: u16) -> Result<Self, HttpError> {
        let mut stream = TlsClientStream::connect_with_alpn(host, port, &["h2"])
            .map_err(map_tls_read_error)?;
        if stream.negotiated_protocol() != Some("h2") {
            return Err(HttpError::Tls);
        }
        let protocol = Http2Client::new();
        stream
            .write_all(&protocol.connection_bytes()?)
            .map_err(map_tls_read_error)?;
        let settings = read_client_frame(&mut stream)?;
        if settings.kind != Http2FrameKind::Settings || settings.flags != 0 {
            return Err(HttpError::InvalidResponse);
        }
        let (initial_window, maximum_frame) = peer_send_settings(&settings.payload)?;
        stream
            .write_all(
                &Http2Frame {
                    kind: Http2FrameKind::Settings,
                    flags: 1,
                    stream_id: 0,
                    payload: Vector::new(),
                }
                .encode()?,
            )
            .map_err(map_tls_read_error)?;
        stream
            .set_application_io_timeout_millis(ESTABLISHED_HTTP2_IO_TIMEOUT_MILLIS)
            .map_err(map_tls_read_error)?;
        let initial_window = initial_window.unwrap_or(65_535);
        Ok(Self {
            stream,
            protocol,
            send_connection_window: 65_535,
            send_stream_window: initial_window,
            peer_initial_stream_window: initial_window,
            peer_maximum_frame: maximum_frame.unwrap_or(16_384),
            pending_response_frames: Vector::new(),
        })
    }
    pub fn request(
        &mut self,
        method: &str,
        authority: &str,
        target: &str,
        headers: &[(&str, &str)],
    ) -> Result<Http2Response, HttpError> {
        self.request_with_body(method, authority, target, headers, &[])
    }
    pub fn request_with_body(
        &mut self,
        method: &str,
        authority: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Http2Response, HttpError> {
        let mut output = LimitedBody {
            bytes: Vector::new(),
            limit: 16 * 1024 * 1024,
        };
        let head =
            self.request_with_body_to(method, authority, target, headers, body, &mut output)?;
        Ok(Http2Response {
            status: head.status,
            headers: head.headers,
            body: output.bytes,
        })
    }
    pub fn request_with_body_to(
        &mut self,
        method: &str,
        authority: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        output: &mut dyn ResponseBodySink,
    ) -> Result<ResponseHead, HttpError> {
        if body.len() > 16 * 1024 * 1024 {
            return Err(HttpError::BodyTooLarge);
        }
        let mut source = SliceBodySource {
            bytes: body,
            offset: 0,
        };
        self.request_streaming_body_to(method, authority, target, headers, &mut source, output)
    }

    pub fn request_streaming_body_to(
        &mut self,
        method: &str,
        authority: &str,
        target: &str,
        headers: &[(&str, &str)],
        source: &mut dyn RequestBodySource,
        output: &mut dyn ResponseBodySink,
    ) -> Result<ResponseHead, HttpError> {
        self.send_stream_window = self.peer_initial_stream_window;
        let mut remaining = source.remaining();
        let (stream_id, request) =
            self.protocol
                .request(method, "https", authority, target, headers, remaining == 0)?;
        self.stream
            .write_all(&request)
            .map_err(map_tls_read_error)?;
        let mut chunk = [0u8; 16 * 1024];
        while remaining != 0 {
            while self.send_connection_window <= 0 || self.send_stream_window <= 0 {
                if self.receive_send_control(stream_id)? {
                    return self.receive_response(stream_id, output);
                }
            }
            let maximum = chunk
                .len()
                .min(self.peer_maximum_frame)
                .min(self.send_connection_window as usize)
                .min(self.send_stream_window as usize)
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            let count = read_request_body_chunk(source, &mut chunk[..maximum], remaining)?;
            remaining -= count as u64;
            let mut payload = Vector::new();
            payload
                .try_extend_from_slice(&chunk[..count])
                .map_err(|_| HttpError::Allocation)?;
            self.stream
                .write_all(
                    &Http2Frame {
                        kind: Http2FrameKind::Data,
                        flags: if remaining == 0 { 1 } else { 0 },
                        stream_id,
                        payload,
                    }
                    .encode()?,
                )
                .map_err(map_tls_read_error)?;
            self.send_connection_window -= count as i64;
            self.send_stream_window -= count as i64;
        }
        self.receive_response(stream_id, output)
    }

    fn receive_send_control(&mut self, stream_id: u32) -> Result<bool, HttpError> {
        let frame = read_client_frame(&mut self.stream)?;
        match frame.kind {
            Http2FrameKind::Settings => self.accept_peer_settings(&frame).map(|()| false),
            Http2FrameKind::WindowUpdate => self
                .accept_send_window_update(&frame, stream_id)
                .map(|()| false),
            Http2FrameKind::Ping if frame.flags & 1 == 0 && frame.payload.len() == 8 => {
                self.stream
                    .write_all(&Http2Frame { flags: 1, ..frame }.encode()?)
                    .map_err(map_tls_read_error)?;
                Ok(false)
            }
            Http2FrameKind::Headers if frame.stream_id == stream_id => {
                if self.pending_response_frames.len() >= 4 {
                    return Err(HttpError::BodyTooLarge);
                }
                let response_ended = response_frame_ends_upload(&frame);
                self.pending_response_frames
                    .try_push(frame)
                    .map_err(|_| HttpError::Allocation)?;
                // A server may send its response head before it has consumed
                // the request body. Preserve that head, but continue servicing
                // upload flow control unless the response is already final.
                Ok(response_ended)
            }
            Http2FrameKind::Data if frame.stream_id == stream_id => {
                if self.pending_response_frames.len() >= 4 {
                    return Err(HttpError::BodyTooLarge);
                }
                self.pending_response_frames
                    .try_push(frame)
                    .map_err(|_| HttpError::Allocation)?;
                Ok(true)
            }
            Http2FrameKind::GoAway => Err(HttpError::Io),
            _ => Ok(false),
        }
    }

    fn accept_peer_settings(&mut self, frame: &Http2Frame) -> Result<(), HttpError> {
        if frame.stream_id != 0 {
            return Err(HttpError::InvalidResponse);
        }
        if frame.flags & 1 != 0 {
            return if frame.payload.is_empty() {
                Ok(())
            } else {
                Err(HttpError::InvalidResponse)
            };
        }
        let (initial_window, maximum_frame) = peer_send_settings(&frame.payload)?;
        if let Some(initial_window) = initial_window {
            let delta = initial_window - self.peer_initial_stream_window;
            self.send_stream_window = self
                .send_stream_window
                .checked_add(delta)
                .filter(|window| *window >= -0x7fff_ffff && *window <= 0x7fff_ffff)
                .ok_or(HttpError::InvalidResponse)?;
            self.peer_initial_stream_window = initial_window;
        }
        if let Some(maximum_frame) = maximum_frame {
            self.peer_maximum_frame = maximum_frame;
        }
        self.stream
            .write_all(
                &Http2Frame {
                    kind: Http2FrameKind::Settings,
                    flags: 1,
                    stream_id: 0,
                    payload: Vector::new(),
                }
                .encode()?,
            )
            .map_err(map_tls_read_error)
    }

    fn accept_send_window_update(
        &mut self,
        frame: &Http2Frame,
        stream_id: u32,
    ) -> Result<(), HttpError> {
        validate_window_update(frame)?;
        if frame.stream_id != 0 && frame.stream_id != stream_id {
            return Err(HttpError::InvalidResponse);
        }
        let increment = i64::from(
            u32::from_be_bytes([
                frame.payload[0],
                frame.payload[1],
                frame.payload[2],
                frame.payload[3],
            ]) & 0x7fff_ffff,
        );
        let window = if frame.stream_id == 0 {
            &mut self.send_connection_window
        } else {
            &mut self.send_stream_window
        };
        *window = window
            .checked_add(increment)
            .filter(|value| *value <= 0x7fff_ffff)
            .ok_or(HttpError::InvalidResponse)?;
        Ok(())
    }

    fn receive_response(
        &mut self,
        stream_id: u32,
        output: &mut dyn ResponseBodySink,
    ) -> Result<ResponseHead, HttpError> {
        let mut head = None;
        loop {
            let frame = if self.pending_response_frames.is_empty() {
                read_client_frame(&mut self.stream)?
            } else {
                self.pending_response_frames.remove(0)
            };
            match frame.kind {
                Http2FrameKind::Settings => self.accept_peer_settings(&frame)?,
                Http2FrameKind::WindowUpdate => {
                    self.accept_send_window_update(&frame, stream_id)?
                }
                Http2FrameKind::Ping if frame.flags & 1 == 0 && frame.payload.len() == 8 => {
                    self.stream
                        .write_all(&Http2Frame { flags: 1, ..frame }.encode()?)
                        .map_err(map_tls_read_error)?;
                }
                Http2FrameKind::Headers if frame.stream_id == stream_id => {
                    if head.is_some() {
                        return Err(HttpError::InvalidResponse);
                    }
                    head = Some(self.protocol.response(&frame)?);
                    if frame.flags & 1 != 0 {
                        break;
                    }
                }
                Http2FrameKind::Data if frame.stream_id == stream_id => {
                    if head.is_none() {
                        return Err(HttpError::InvalidResponse);
                    }
                    let consumed =
                        u32::try_from(frame.payload.len()).map_err(|_| HttpError::BodyTooLarge)?;
                    output.write(&frame.payload)?;
                    if consumed != 0 {
                        for target in [0, stream_id] {
                            self.stream
                                .write_all(
                                    &Http2Frame {
                                        kind: Http2FrameKind::WindowUpdate,
                                        flags: 0,
                                        stream_id: target,
                                        payload: consumed.to_be_bytes().into(),
                                    }
                                    .encode()?,
                                )
                                .map_err(map_tls_read_error)?;
                        }
                    }
                    if frame.flags & 1 != 0 {
                        break;
                    }
                }
                Http2FrameKind::GoAway => return Err(HttpError::Io),
                _ => {}
            }
        }
        head.ok_or(HttpError::InvalidResponse)
    }
}

fn response_frame_ends_upload(frame: &Http2Frame) -> bool {
    matches!(frame.kind, Http2FrameKind::Headers) && frame.flags & 1 != 0
}

pub struct Http2ServerConnection {
    stream: TlsServerStream,
    protocol: Http2Server,
    request_stream: Option<u32>,
    request_ended: bool,
    pending_request_data: Vector<u8>,
    pending_request_offset: usize,
    pending_request_end: bool,
    send_connection_window: i64,
    send_stream_window: i64,
    peer_initial_stream_window: i64,
    peer_maximum_frame: usize,
}
impl Http2ServerConnection {
    pub fn accept(mut stream: TlsServerStream) -> Result<Self, HttpError> {
        if stream.negotiated_protocol() != Some("h2") {
            return Err(HttpError::Tls);
        }
        let mut preface = [0; 24];
        tls_read_exact_server(&mut stream, &mut preface)?;
        if &preface != HTTP2_CLIENT_PREFACE {
            return Err(HttpError::InvalidResponse);
        }
        let first = read_server_frame(&mut stream)?;
        if first.kind != Http2FrameKind::Settings || first.flags != 0 {
            return Err(HttpError::InvalidResponse);
        }
        let (initial_window, maximum_frame) = peer_send_settings(&first.payload)?;
        let protocol = Http2Server::new();
        stream
            .write_all(&protocol.settings()?)
            .map_err(|_| HttpError::Tls)?;
        stream
            .write_all(
                &Http2Frame {
                    kind: Http2FrameKind::Settings,
                    flags: 1,
                    stream_id: 0,
                    payload: Vector::new(),
                }
                .encode()?,
            )
            .map_err(|_| HttpError::Tls)?;
        Ok(Self {
            stream,
            protocol,
            request_stream: None,
            request_ended: false,
            pending_request_data: Vector::new(),
            pending_request_offset: 0,
            pending_request_end: false,
            send_connection_window: 65_535,
            send_stream_window: initial_window.unwrap_or(65_535),
            peer_initial_stream_window: initial_window.unwrap_or(65_535),
            peer_maximum_frame: maximum_frame.unwrap_or(MAX_FRAME),
        })
    }
    pub fn next_request(&mut self) -> Result<(u32, RequestHead), HttpError> {
        if self.request_stream.is_some() && !self.request_ended {
            return Err(HttpError::InvalidResponse);
        }
        self.request_stream = None;
        self.request_ended = false;
        loop {
            let frame = read_server_frame(&mut self.stream)?;
            match frame.kind {
                Http2FrameKind::Headers => {
                    let id = frame.stream_id;
                    let request = self.protocol.request(&frame)?;
                    self.request_stream = Some(id);
                    self.request_ended = frame.flags & 1 != 0;
                    self.send_stream_window = self.peer_initial_stream_window;
                    return Ok((id, request));
                }
                Http2FrameKind::Settings => self.accept_peer_settings(&frame)?,
                Http2FrameKind::Ping if frame.flags & 1 == 0 && frame.payload.len() == 8 => {
                    self.stream
                        .write_all(&Http2Frame { flags: 1, ..frame }.encode()?)
                        .map_err(|_| HttpError::Tls)?;
                }
                Http2FrameKind::WindowUpdate => self.accept_window_update(&frame)?,
                _ => return Err(HttpError::InvalidResponse),
            }
        }
    }
    /// Read request DATA from the active stream without buffering more than
    /// one protocol frame. A zero result means the peer sent END_STREAM.
    pub fn read_request_data(
        &mut self,
        stream_id: u32,
        output: &mut [u8],
    ) -> Result<usize, HttpError> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.request_stream != Some(stream_id) {
            return Err(HttpError::InvalidResponse);
        }
        if self.pending_request_offset < self.pending_request_data.len() {
            return self.copy_pending_request_data(stream_id, output);
        }
        if self.request_ended {
            return Ok(0);
        }
        loop {
            let frame = read_server_frame(&mut self.stream)?;
            match frame.kind {
                Http2FrameKind::Data if frame.stream_id == stream_id && frame.flags & !1 == 0 => {
                    self.pending_request_data = frame.payload;
                    self.pending_request_offset = 0;
                    self.pending_request_end = frame.flags & 1 != 0;
                    if self.pending_request_data.is_empty() {
                        if self.pending_request_end {
                            self.request_ended = true;
                            return Ok(0);
                        }
                        continue;
                    }
                    return self.copy_pending_request_data(stream_id, output);
                }
                Http2FrameKind::Ping if frame.flags & 1 == 0 && frame.payload.len() == 8 => {
                    self.stream
                        .write_all(&Http2Frame { flags: 1, ..frame }.encode()?)
                        .map_err(|_| HttpError::Tls)?;
                }
                Http2FrameKind::Settings => self.accept_peer_settings(&frame)?,
                Http2FrameKind::WindowUpdate => self.accept_window_update(&frame)?,
                Http2FrameKind::RstStream
                    if frame.stream_id == stream_id && frame.payload.len() == 4 =>
                {
                    return Err(HttpError::Io);
                }
                _ => return Err(HttpError::InvalidResponse),
            }
        }
    }
    pub fn request_body_complete(&self, stream_id: u32) -> Result<bool, HttpError> {
        if self.request_stream != Some(stream_id) {
            return Err(HttpError::InvalidResponse);
        }
        Ok(self.request_ended && self.pending_request_offset == self.pending_request_data.len())
    }
    fn copy_pending_request_data(
        &mut self,
        stream_id: u32,
        output: &mut [u8],
    ) -> Result<usize, HttpError> {
        let remaining = &self.pending_request_data[self.pending_request_offset..];
        let count = remaining.len().min(output.len());
        output[..count].copy_from_slice(&remaining[..count]);
        self.pending_request_offset += count;
        if self.pending_request_offset == self.pending_request_data.len() {
            self.pending_request_data.clear();
            self.pending_request_offset = 0;
            if self.pending_request_end {
                self.request_ended = true;
                self.pending_request_end = false;
            }
        }
        self.acknowledge_request_bytes(stream_id, count as u32)?;
        Ok(count)
    }
    fn acknowledge_request_bytes(&mut self, stream_id: u32, count: u32) -> Result<(), HttpError> {
        if count == 0 {
            return Ok(());
        }
        for target in [0, stream_id] {
            self.stream
                .write_all(
                    &Http2Frame {
                        kind: Http2FrameKind::WindowUpdate,
                        flags: 0,
                        stream_id: target,
                        payload: count.to_be_bytes().into(),
                    }
                    .encode()?,
                )
                .map_err(|_| HttpError::Tls)?;
        }
        Ok(())
    }
    fn accept_peer_settings(&mut self, frame: &Http2Frame) -> Result<(), HttpError> {
        if frame.stream_id != 0 {
            return Err(HttpError::InvalidResponse);
        }
        if frame.flags & 1 != 0 {
            return if frame.flags == 1 && frame.payload.is_empty() {
                Ok(())
            } else {
                Err(HttpError::InvalidResponse)
            };
        }
        if frame.flags != 0 {
            return Err(HttpError::InvalidResponse);
        }
        let (initial_window, maximum_frame) = peer_send_settings(&frame.payload)?;
        if let Some(initial_window) = initial_window {
            let delta = initial_window - self.peer_initial_stream_window;
            self.send_stream_window = self
                .send_stream_window
                .checked_add(delta)
                .filter(|window| *window >= -0x7fff_ffff && *window <= 0x7fff_ffff)
                .ok_or(HttpError::InvalidResponse)?;
            self.peer_initial_stream_window = initial_window;
        }
        if let Some(maximum_frame) = maximum_frame {
            self.peer_maximum_frame = maximum_frame;
        }
        self.stream
            .write_all(
                &Http2Frame {
                    kind: Http2FrameKind::Settings,
                    flags: 1,
                    stream_id: 0,
                    payload: Vector::new(),
                }
                .encode()?,
            )
            .map_err(|_| HttpError::Tls)
    }
    fn accept_window_update(&mut self, frame: &Http2Frame) -> Result<(), HttpError> {
        validate_window_update(frame)?;
        let increment = i64::from(
            u32::from_be_bytes([
                frame.payload[0],
                frame.payload[1],
                frame.payload[2],
                frame.payload[3],
            ]) & 0x7fff_ffff,
        );
        let window = if frame.stream_id == 0 {
            &mut self.send_connection_window
        } else if self.request_stream == Some(frame.stream_id) {
            &mut self.send_stream_window
        } else {
            return Err(HttpError::InvalidResponse);
        };
        *window = window
            .checked_add(increment)
            .filter(|value| *value <= 0x7fff_ffff)
            .ok_or(HttpError::InvalidResponse)?;
        Ok(())
    }
    pub fn respond(
        &mut self,
        stream_id: u32,
        status: u16,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<(), HttpError> {
        self.respond_head(stream_id, status, headers, body.is_empty())?;
        for chunk in body.chunks(MAX_FRAME) {
            self.respond_data(stream_id, chunk, false)?;
        }
        if !body.is_empty() {
            self.finish_response(stream_id)?;
        }
        Ok(())
    }
    /// Send response headers before any response body bytes.
    pub fn respond_head(
        &mut self,
        stream_id: u32,
        status: u16,
        headers: &[(&str, &str)],
        end_stream: bool,
    ) -> Result<(), HttpError> {
        self.stream
            .write_all(
                &self
                    .protocol
                    .response(stream_id, status, headers, end_stream)?,
            )
            .map_err(|_| HttpError::Tls)
    }
    /// Send one bounded response DATA fragment. Larger caller buffers are
    /// split into protocol-sized frames without collecting the whole body.
    pub fn respond_data(
        &mut self,
        stream_id: u32,
        bytes: &[u8],
        end_stream: bool,
    ) -> Result<(), HttpError> {
        if bytes.is_empty() {
            if end_stream {
                return self.finish_response(stream_id);
            }
            return Ok(());
        }
        if self.request_stream != Some(stream_id) {
            return Err(HttpError::InvalidResponse);
        }
        let mut at = 0usize;
        while at < bytes.len() {
            while self.send_connection_window <= 0 || self.send_stream_window <= 0 {
                self.await_send_capacity(stream_id)?;
            }
            let count = (bytes.len() - at)
                .min(MAX_FRAME)
                .min(self.peer_maximum_frame)
                .min(self.send_connection_window as usize)
                .min(self.send_stream_window as usize);
            let chunk = &bytes[at..at + count];
            let mut payload = Vector::new();
            payload
                .try_extend_from_slice(chunk)
                .map_err(|_| HttpError::Allocation)?;
            self.stream
                .write_all(
                    &Http2Frame {
                        kind: Http2FrameKind::Data,
                        flags: if end_stream && at + count == bytes.len() {
                            1
                        } else {
                            0
                        },
                        stream_id,
                        payload,
                    }
                    .encode()?,
                )
                .map_err(|_| HttpError::Tls)?;
            self.send_connection_window -= count as i64;
            self.send_stream_window -= count as i64;
            at += count;
        }
        Ok(())
    }
    fn await_send_capacity(&mut self, stream_id: u32) -> Result<(), HttpError> {
        let frame = read_server_frame(&mut self.stream)?;
        match frame.kind {
            Http2FrameKind::WindowUpdate => self.accept_window_update(&frame),
            Http2FrameKind::Settings => self.accept_peer_settings(&frame),
            Http2FrameKind::Ping if frame.flags & 1 == 0 && frame.payload.len() == 8 => self
                .stream
                .write_all(&Http2Frame { flags: 1, ..frame }.encode()?)
                .map_err(|_| HttpError::Tls),
            Http2FrameKind::Data
                if frame.stream_id == stream_id
                    && frame.flags & !1 == 0
                    && self.pending_request_data.is_empty()
                    && !self.request_ended =>
            {
                self.pending_request_data = frame.payload;
                self.pending_request_offset = 0;
                self.pending_request_end = frame.flags & 1 != 0;
                if self.pending_request_data.is_empty() && self.pending_request_end {
                    self.request_ended = true;
                    self.pending_request_end = false;
                }
                Ok(())
            }
            Http2FrameKind::RstStream
                if frame.stream_id == stream_id && frame.payload.len() == 4 =>
            {
                Err(HttpError::Io)
            }
            _ => Err(HttpError::InvalidResponse),
        }
    }
    /// Close a response body without manufacturing application bytes.
    pub fn finish_response(&mut self, stream_id: u32) -> Result<(), HttpError> {
        self.stream
            .write_all(
                &Http2Frame {
                    kind: Http2FrameKind::Data,
                    flags: 1,
                    stream_id,
                    payload: Vector::new(),
                }
                .encode()?,
            )
            .map_err(|_| HttpError::Tls)
    }
    /// Abort one stream after its response has started. The caller supplies an
    /// RFC 9113 error code; connection-wide failures remain the listener's
    /// responsibility.
    pub fn reset_stream(&mut self, stream_id: u32, error_code: u32) -> Result<(), HttpError> {
        if stream_id == 0 || stream_id > 0x7fff_ffff {
            return Err(HttpError::InvalidResponse);
        }
        self.stream
            .write_all(
                &Http2Frame {
                    kind: Http2FrameKind::RstStream,
                    flags: 0,
                    stream_id,
                    payload: error_code.to_be_bytes().into(),
                }
                .encode()?,
            )
            .map_err(|_| HttpError::Tls)
    }
}
fn take(headers: &mut Vector<Header>, name: &str) -> Result<Text, HttpError> {
    let pos = headers
        .iter()
        .position(|h| h.name == name)
        .ok_or(HttpError::InvalidResponse)?;
    if headers.iter().filter(|h| h.name == name).count() != 1 {
        return Err(HttpError::InvalidResponse);
    }
    Ok(headers.remove(pos).value)
}
fn decode_response(frame: &Http2Frame) -> Result<ResponseHead, HttpError> {
    if frame.kind != Http2FrameKind::Headers || frame.flags & 4 == 0 {
        return Err(HttpError::InvalidResponse);
    }
    let mut h = decode_block(&frame.payload)?;
    let status: u16 = take(&mut h, ":status")?
        .parse()
        .map_err(|_| HttpError::InvalidResponse)?;
    if !(100..=599).contains(&status) || h.iter().any(|x| x.name.starts_with(':')) {
        return Err(HttpError::InvalidResponse);
    }
    Ok(ResponseHead { status, headers: h })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_runtime::TcpListener;
    use mrml_tls::TlsServerConfig;
    #[test]
    fn client_server_round_trip() {
        let mut c = Http2Client::new();
        let (id, wire) = c
            .request(
                "GET",
                "https",
                "example.com",
                "/x",
                &[("accept", "text/plain")],
                true,
            )
            .unwrap();
        let (f, n) = Http2Frame::decode(&wire).unwrap();
        assert_eq!(n, wire.len());
        let r = Http2Server::new().request(&f).unwrap();
        assert_eq!(r.target, "/x");
        let wire = Http2Server::new()
            .response(id, 204, &[("cache-control", "no-store")], true)
            .unwrap();
        let (f, _) = Http2Frame::decode(&wire).unwrap();
        assert_eq!(c.response(&f).unwrap().status, 204)
    }
    #[test]
    fn rejects_oversize_and_uppercase() {
        let payload = [0u8; 16385];
        let f = Http2Frame {
            kind: Http2FrameKind::Data,
            flags: 0,
            stream_id: 1,
            payload: payload.into(),
        };
        assert_eq!(f.encode(), Err(HttpError::BodyTooLarge));
        assert!(
            Http2Client::new()
                .request("GET", "https", "x", "/", &[("Bad", "x")], true)
                .is_err()
        )
    }
    #[test]
    fn decodes_rfc_huffman_and_static_index_request() {
        let payload: Vector<u8> = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ]
        .into();
        let request = Http2Server::new()
            .request(&Http2Frame {
                kind: Http2FrameKind::Headers,
                flags: 5,
                stream_id: 1,
                payload,
            })
            .unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.scheme, "http");
        assert_eq!(request.authority, "www.example.com");
        assert_eq!(request.target, "/");
    }
    #[test]
    fn request_wire_matches_independent_h2_probe() {
        let connection = Http2Client::new().connection_bytes().unwrap();
        let mut expected_connection = Vector::new();
        expected_connection
            .try_extend_from_slice(HTTP2_CLIENT_PREFACE)
            .unwrap();
        expected_connection
            .try_extend_from_slice(&[
                0, 0, 12, 4, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0,
            ])
            .unwrap();
        assert_eq!(connection, expected_connection);
        let (_, wire) = Http2Client::new()
            .request(
                "GET",
                "https",
                "huggingface.co",
                "/",
                &[("user-agent", "mrml-http/1")],
                true,
            )
            .unwrap();
        let expected: Vector<u8> = [
            0x00, 0x00, 0x21, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01, 0x82, 0x87, 0x01, 0x0e, b'h',
            b'u', b'g', b'g', b'i', b'n', b'g', b'f', b'a', b'c', b'e', b'.', b'c', b'o', 0x84,
            0x0f, 0x2b, 0x0b, b'm', b'r', b'm', b'l', b'-', b'h', b't', b't', b'p', b'/', b'1',
        ]
        .into();
        assert_eq!(wire, expected);
    }
    #[test]
    fn validates_settings_continuations_and_window_updates() {
        assert_eq!(
            peer_send_settings(&[0, 4, 0, 1, 0, 0, 0, 5, 0, 0, 128, 0]),
            Ok((Some(65_536), Some(32_768)))
        );
        assert!(peer_send_settings(&[0, 4, 128, 0, 0, 0]).is_err());
        let mut state = Http2ConnectionState::new();
        state
            .receive(&Http2Frame {
                kind: Http2FrameKind::Settings,
                flags: 0,
                stream_id: 0,
                payload: [0, 5, 0, 0, 0x40, 0].into(),
            })
            .unwrap();
        assert!(state.settings_received());
        state
            .receive(&Http2Frame {
                kind: Http2FrameKind::Headers,
                flags: 0,
                stream_id: 1,
                payload: Vector::new(),
            })
            .unwrap();
        assert!(
            state
                .receive(&Http2Frame {
                    kind: Http2FrameKind::Data,
                    flags: 0,
                    stream_id: 1,
                    payload: Vector::new(),
                })
                .is_err()
        );
        state
            .receive(&Http2Frame {
                kind: Http2FrameKind::Continuation,
                flags: 4,
                stream_id: 1,
                payload: Vector::new(),
            })
            .unwrap();
        assert!(
            state
                .receive(&Http2Frame {
                    kind: Http2FrameKind::WindowUpdate,
                    flags: 0,
                    stream_id: 0,
                    payload: [0, 0, 0, 0].into(),
                })
                .is_err()
        );
        assert!(
            state
                .receive(&Http2Frame {
                    kind: Http2FrameKind::WindowUpdate,
                    flags: 0,
                    stream_id: 0,
                    payload: Vector::new(),
                })
                .is_err()
        );
    }

    #[test]
    fn nonfinal_response_head_does_not_end_request_upload() {
        let nonfinal = Http2Frame {
            kind: Http2FrameKind::Headers,
            flags: 4,
            stream_id: 1,
            payload: Vector::new(),
        };
        let final_head = Http2Frame { flags: 5, ..nonfinal.clone() };
        assert!(!response_frame_ends_upload(&nonfinal));
        assert!(response_frame_ends_upload(&final_head));
    }

    #[test]
    fn live_http2_get_when_configured() {
        let Some(host) = mrml_runtime::environment_variable("MRML_HTTP2_LIVE_HOST") else {
            return;
        };
        let mut connection = Http2ClientConnection::connect(&host, 443).unwrap();
        let response = connection
            .request("GET", &host, "/", &[("user-agent", "mrml-http/1")])
            .unwrap();
        assert!((100..=599).contains(&response.status));
    }

    #[test]
    fn authenticated_loopback_when_configured() {
        let Some(certificate_path) = mrml_runtime::environment_variable("MRML_HTTP2_LOOPBACK_CERT")
        else {
            return;
        };
        let Some(issuer_path) = mrml_runtime::environment_variable("MRML_HTTP2_LOOPBACK_ISSUER")
        else {
            return;
        };
        let Some(key_path) = mrml_runtime::environment_variable("MRML_HTTP2_LOOPBACK_KEY") else {
            return;
        };
        let Some(ocsp_path) = mrml_runtime::environment_variable("MRML_HTTP2_LOOPBACK_OCSP") else {
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
            .with_protocols(&["h2"])
            .unwrap()
            .with_ocsp_response(&ocsp)
            .unwrap();
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let Ok(worker) = mrml_runtime::spawn_joinable(move || {
            let socket = listener.accept().unwrap();
            let tls = TlsServerStream::accept(socket, &config).unwrap();
            let mut server = Http2ServerConnection::accept(tls).unwrap();
            let (id, request) = server.next_request().unwrap();
            assert_eq!(request.target, "/loopback");
            let mut request_body = Vector::new();
            let mut chunk = [0; 3];
            loop {
                let count = server.read_request_data(id, &mut chunk).unwrap();
                if count == 0 {
                    break;
                }
                request_body.try_extend_from_slice(&chunk[..count]).unwrap();
            }
            if request.method == "POST" {
                assert_eq!(&request_body[..], b"request body");
            } else {
                assert_eq!(request.method, "GET");
                assert!(request_body.is_empty());
            }
            server.respond_head(id, 200, &[], false).unwrap();
            server.respond_data(id, b"http2 ", false).unwrap();
            server.respond_data(id, b"loopback", false).unwrap();
            server.finish_response(id).unwrap();
            let _ = server.next_request();
        }) else {
            panic!("failed to start HTTP/2 loopback server");
        };
        if let Some(curl) = mrml_runtime::environment_variable("MRML_HTTP2_CURL") {
            let endpoint = mrml_runtime::mrml_format!("localhost:{port}:127.0.0.1");
            let url = mrml_runtime::mrml_format!("https://localhost:{port}/loopback");
            let output = mrml_runtime::Command::new(&curl)
                .args([
                    "--http2",
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
            assert!(worker.join(), "MRML HTTP/2 server failed");
            assert!(
                output.status.success(),
                "curl failed: {}",
                core::str::from_utf8(&output.stderr).unwrap_or("non-UTF-8 error")
            );
            assert_eq!(&output.stdout[..], b"http2 loopback");
            return;
        } else {
            let mut client = Http2ClientConnection::connect("localhost", port).unwrap();
            let response = client
                .request_with_body("POST", "localhost", "/loopback", &[], b"request body")
                .unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(&response.body[..], b"http2 loopback");
        }
        assert!(worker.join());
    }
}
