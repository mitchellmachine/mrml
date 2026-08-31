use crate::{Header, HttpError, RequestHead, ResponseHead, valid_header, valid_value};
use mrml_runtime::Vector;
const MAX_FRAME: usize = 1024 * 1024;
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
        qint(&mut o, 0x20, 3, n.len())?;
        o.try_extend_from_slice(n.as_bytes())
            .map_err(|_| HttpError::Allocation)?;
        qstr(&mut o, v)?
    }
    Ok(o)
}
fn valid_field_name(name: &str) -> bool {
    valid_header(name) || name.strip_prefix(':').is_some_and(valid_header)
}
fn qdecode(input: &[u8]) -> Result<Vector<Header>, HttpError> {
    if input.len() < 2 || input[0] != 0 || input[1] != 0 {
        return Err(HttpError::InvalidResponse);
    }
    let mut at = 2;
    let mut o = Vector::new();
    while at < input.len() {
        let b = input[at];
        if b & 0xf8 != 0x20 {
            return Err(HttpError::InvalidResponse);
        }
        let nl = qread_int(input, &mut at, 3)?;
        if nl == 0 || input.len() - at < nl {
            return Err(HttpError::InvalidResponse);
        }
        let name =
            core::str::from_utf8(&input[at..at + nl]).map_err(|_| HttpError::InvalidResponse)?;
        at += nl;
        if at >= input.len() || input[at] & 0x80 != 0 {
            return Err(HttpError::InvalidResponse);
        }
        let vl = input[at] as usize;
        at += 1;
        if input.len() - at < vl {
            return Err(HttpError::InvalidResponse);
        }
        let value =
            core::str::from_utf8(&input[at..at + vl]).map_err(|_| HttpError::InvalidResponse)?;
        at += vl;
        if !valid_field_name(name) || !valid_value(value) {
            return Err(HttpError::InvalidResponse);
        }
        o.try_push(Header {
            name: name.into(),
            value: value.into(),
        })
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
}
