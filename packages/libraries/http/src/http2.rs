use mrml_runtime::{Text, Vector};

use crate::{Header, HttpError, RequestHead, ResponseHead, valid_header, valid_value};

pub const HTTP2_CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_FRAME: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http2FrameKind {
    Data,
    Headers,
    Settings,
    Ping,
    GoAway,
    WindowUpdate,
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
            Http2FrameKind::Settings => 4,
            Http2FrameKind::Ping => 6,
            Http2FrameKind::GoAway => 7,
            Http2FrameKind::WindowUpdate => 8,
            Http2FrameKind::Unknown(v) => v,
        };
        if matches!(
            self.kind,
            Http2FrameKind::Settings | Http2FrameKind::Ping | Http2FrameKind::GoAway
        ) && self.stream_id != 0
        {
            return Err(HttpError::InvalidResponse);
        }
        if matches!(self.kind, Http2FrameKind::Data | Http2FrameKind::Headers)
            && self.stream_id == 0
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
            4 => Http2FrameKind::Settings,
            6 => Http2FrameKind::Ping,
            7 => Http2FrameKind::GoAway,
            8 => Http2FrameKind::WindowUpdate,
            v => Http2FrameKind::Unknown(v),
        };
        if matches!(
            kind,
            Http2FrameKind::Settings | Http2FrameKind::Ping | Http2FrameKind::GoAway
        ) && stream_id != 0
        {
            return Err(HttpError::InvalidResponse);
        }
        if matches!(kind, Http2FrameKind::Data | Http2FrameKind::Headers) && stream_id == 0 {
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
    out.try_push(0).map_err(|_| HttpError::Allocation)?;
    string(out, name)?;
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
    if *at >= input.len() || input[*at] & 0x80 != 0 {
        return Err(HttpError::InvalidResponse);
    }
    let n = decode_int(input, at, 7)?;
    let end = at.checked_add(n).ok_or(HttpError::InvalidResponse)?;
    if end > input.len() {
        return Err(HttpError::InvalidResponse);
    }
    let s = core::str::from_utf8(&input[*at..end]).map_err(|_| HttpError::InvalidResponse)?;
    *at = end;
    Text::try_from_str(s).map_err(|_| HttpError::Allocation)
}
fn decode_block(input: &[u8]) -> Result<Vector<Header>, HttpError> {
    let mut at = 0;
    let mut out = Vector::new();
    while at < input.len() {
        if input[at] != 0 {
            return Err(HttpError::InvalidResponse);
        }
        at += 1;
        let name = decode_string(input, &mut at)?;
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
                payload: Vector::new(),
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
}
