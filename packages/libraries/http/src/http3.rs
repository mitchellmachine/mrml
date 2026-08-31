use crate::{valid_header, valid_value, Header, HttpError, RequestHead, ResponseHead};
use mrml_runtime::Vector;
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
}
