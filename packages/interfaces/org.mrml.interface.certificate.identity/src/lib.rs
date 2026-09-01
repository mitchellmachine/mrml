#![no_std]
//! Capability-scoped exact TLS identity publication; descriptors identify but do not authorize.
#[path = "../1.rs"]
mod generated;
pub use generated::*;
pub const HEALTH_HEALTHY: u32 = 1;
pub const HEALTH_WARNING: u32 = 2;
pub const HEALTH_CRITICAL: u32 = 3;
pub const HEALTH_EXPIRED: u32 = 4;

pub const ABI_CALL_HEADER_BYTES: usize = 72;
pub const DESCRIBE_REQUEST_BYTES: usize = 120;
pub const READ_CHAIN_REQUEST_BYTES: usize = 120;
pub const REQUEST_SIGNING_ROUTE_REQUEST_BYTES: usize = 128;
pub const POLL_GENERATION_REQUEST_BYTES: usize = 96;
pub const RESPONSE_BYTES: usize = 24;
const MAGIC: [u8; 8] = *b"MRMLCALL";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidHeader,
    InvalidRequest,
    InvalidResponse,
}

pub fn encode_describe_request(
    r: DescribeRequest,
) -> Result<[u8; DESCRIBE_REQUEST_BYTES], ProtocolError> {
    valid_io(r.identity, r.output, 2048)?;
    let mut b = [0; DESCRIBE_REQUEST_BYTES];
    header(&mut b, OP_DESCRIBE, 48)?;
    put_r(&mut b, 72, r.identity);
    put64(&mut b, 88, r.observed_generation);
    put_w(&mut b, 96, r.output);
    Ok(b)
}
pub fn decode_describe_request(
    b: &[u8; DESCRIBE_REQUEST_BYTES],
    m: u64,
) -> Result<DescribeRequest, ProtocolError> {
    check(b, OP_DESCRIBE, 48)?;
    if b[112..120] != [0; 8] {
        return Err(ProtocolError::InvalidHeader);
    }
    let r = DescribeRequest {
        identity: get_r(b, 72, m)?,
        observed_generation: get64(b, 88),
        output: get_w(b, 96, m)?,
    };
    valid_io(r.identity, r.output, 2048)?;
    Ok(r)
}
pub fn encode_read_chain_request(
    r: ReadChainRequest,
) -> Result<[u8; READ_CHAIN_REQUEST_BYTES], ProtocolError> {
    valid_io(r.identity, r.output, 16384)?;
    let mut b = [0; READ_CHAIN_REQUEST_BYTES];
    header(&mut b, OP_READ_CHAIN, 48)?;
    put_r(&mut b, 72, r.identity);
    put64(&mut b, 88, r.generation);
    put32(&mut b, 96, r.certificate_index);
    put_w(&mut b, 104, r.output);
    Ok(b)
}
pub fn decode_read_chain_request(
    b: &[u8; READ_CHAIN_REQUEST_BYTES],
    m: u64,
) -> Result<ReadChainRequest, ProtocolError> {
    check(b, OP_READ_CHAIN, 48)?;
    if b[100..104] != [0; 4] {
        return Err(ProtocolError::InvalidHeader);
    }
    let r = ReadChainRequest {
        identity: get_r(b, 72, m)?,
        generation: get64(b, 88),
        certificate_index: get32(b, 96),
        output: get_w(b, 104, m)?,
    };
    valid_io(r.identity, r.output, 16384)?;
    Ok(r)
}
pub fn encode_request_signing_route_request(
    r: RequestSigningRouteRequest,
) -> Result<[u8; REQUEST_SIGNING_ROUTE_REQUEST_BYTES], ProtocolError> {
    if !r.validate()
        || r.identity.length() == 0
        || r.key_identity.length() != 32
        || r.output.length() == 0
        || overlap(r.identity, r.output)
        || overlap(r.key_identity, r.output)
    {
        return Err(ProtocolError::InvalidRequest);
    }
    let mut b = [0; REQUEST_SIGNING_ROUTE_REQUEST_BYTES];
    header(&mut b, OP_REQUEST_SIGNING_ROUTE, 56)?;
    put_r(&mut b, 72, r.identity);
    put64(&mut b, 88, r.generation);
    put_r(&mut b, 96, r.key_identity);
    put_w(&mut b, 112, r.output);
    Ok(b)
}
pub fn decode_request_signing_route_request(
    b: &[u8; REQUEST_SIGNING_ROUTE_REQUEST_BYTES],
    m: u64,
) -> Result<RequestSigningRouteRequest, ProtocolError> {
    check(b, OP_REQUEST_SIGNING_ROUTE, 56)?;
    let r = RequestSigningRouteRequest {
        identity: get_r(b, 72, m)?,
        generation: get64(b, 88),
        key_identity: get_r(b, 96, m)?,
        output: get_w(b, 112, m)?,
    };
    encode_request_signing_route_request(r).map(|_| r)
}
pub fn encode_poll_generation_request(
    r: PollGenerationRequest,
) -> Result<[u8; POLL_GENERATION_REQUEST_BYTES], ProtocolError> {
    if !r.validate() || r.identity.length() == 0 {
        return Err(ProtocolError::InvalidRequest);
    }
    let mut b = [0; POLL_GENERATION_REQUEST_BYTES];
    header(&mut b, OP_POLL_GENERATION, 24)?;
    put_r(&mut b, 72, r.identity);
    put64(&mut b, 88, r.observed_generation);
    Ok(b)
}
pub fn decode_poll_generation_request(
    b: &[u8; POLL_GENERATION_REQUEST_BYTES],
    m: u64,
) -> Result<PollGenerationRequest, ProtocolError> {
    check(b, OP_POLL_GENERATION, 24)?;
    let r = PollGenerationRequest {
        identity: get_r(b, 72, m)?,
        observed_generation: get64(b, 88),
    };
    encode_poll_generation_request(r).map(|_| r)
}

macro_rules! response_codec {($enc:ident,$dec:ident,$ok:ty,$err:ty,$a:ident,$z:ident,$ctor:path,$max:expr,$zmax:expr,$($n:literal=>$e:ident),+)=>{
pub fn $enc(result:Result<$ok,$err>)->[u8;RESPONSE_BYTES]{match result{Ok(v)=>response(0,v.$a as u64,v.$z as u64),Err(e)=>response(e as u32,0,0)}}
pub fn $dec(b:&[u8;RESPONSE_BYTES],limit:u64)->Result<Result<$ok,$err>,ProtocolError>{let(s,a,z)=decode_response(b)?;if s==0{return if a!=0&&a<=limit&&a<=$max&&z!=0&&z<=$zmax{Ok(Ok($ctor(a,z)))}else{Err(ProtocolError::InvalidResponse)}}let e=match s{$($n=><$err>::$e,)+_=>return Err(ProtocolError::InvalidResponse)};if a!=0||z!=0{return Err(ProtocolError::InvalidResponse)}Ok(Err(e))}}
}
fn describe_ok(a: u64, z: u64) -> DescribeResponse {
    DescribeResponse {
        written: a,
        current_generation: z,
    }
}
fn chain_ok(a: u64, z: u64) -> ReadChainResponse {
    ReadChainResponse {
        written: a,
        certificate_count: z as u32,
    }
}
fn route_ok(a: u64, z: u64) -> RequestSigningRouteResponse {
    RequestSigningRouteResponse {
        written: a,
        route_generation: z,
    }
}
response_codec!(encode_describe_response,decode_describe_response,DescribeResponse,DescribeError,written,current_generation,describe_ok,2048,u64::MAX,1=>InvalidRequest,2=>IdentityUnavailable,3=>PermissionDenied,4=>OutputTooSmall);
response_codec!(encode_read_chain_response,decode_read_chain_response,ReadChainResponse,ReadChainError,written,certificate_count,chain_ok,16384,u32::MAX as u64,1=>InvalidRequest,2=>StaleIdentity,3=>PermissionDenied,4=>OutputTooSmall);
response_codec!(encode_request_signing_route_response,decode_request_signing_route_response,RequestSigningRouteResponse,RequestSigningRouteError,written,route_generation,route_ok,64,u64::MAX,1=>InvalidRequest,2=>StaleIdentity,3=>PermissionDenied,4=>RouteUnavailable,5=>OutputTooSmall);
pub fn encode_poll_generation_response(
    r: Result<PollGenerationResponse, PollGenerationError>,
) -> [u8; RESPONSE_BYTES] {
    match r {
        Ok(v) => response(0, v.current_generation, v.health as u64),
        Err(e) => response(e as u32, 0, 0),
    }
}
pub fn decode_poll_generation_response(
    b: &[u8; RESPONSE_BYTES],
) -> Result<Result<PollGenerationResponse, PollGenerationError>, ProtocolError> {
    let (s, g, h) = decode_response(b)?;
    if s == 0 {
        return if g != 0
            && (HEALTH_HEALTHY..=HEALTH_EXPIRED).contains(&(h as u32))
            && h <= u32::MAX as u64
        {
            Ok(Ok(PollGenerationResponse {
                current_generation: g,
                health: h as u32,
            }))
        } else {
            Err(ProtocolError::InvalidResponse)
        };
    }
    let e = match s {
        1 => PollGenerationError::InvalidRequest,
        2 => PollGenerationError::IdentityUnavailable,
        3 => PollGenerationError::PermissionDenied,
        _ => return Err(ProtocolError::InvalidResponse),
    };
    if g != 0 || h != 0 {
        return Err(ProtocolError::InvalidResponse);
    }
    Ok(Err(e))
}

fn valid_io(r: BorrowedReadView, w: BorrowedWriteView, max: u64) -> Result<(), ProtocolError> {
    if r.length() == 0 || r.length() > 16 || w.length() == 0 || w.length() > max || overlap(r, w) {
        Err(ProtocolError::InvalidRequest)
    } else {
        Ok(())
    }
}
fn overlap(r: BorrowedReadView, w: BorrowedWriteView) -> bool {
    r.offset() < w.offset().saturating_add(w.length())
        && w.offset() < r.offset().saturating_add(r.length())
}
fn header<const N: usize>(b: &mut [u8; N], op: u32, p: u64) -> Result<(), ProtocolError> {
    if N != 72 + p as usize {
        return Err(ProtocolError::InvalidRequest);
    }
    b[..8].copy_from_slice(&MAGIC);
    b[8..10].copy_from_slice(&1u16.to_le_bytes());
    b[16..48].copy_from_slice(&INTERFACE_FINGERPRINT);
    put32(b, 48, INTERFACE_GENERATION);
    put32(b, 52, op);
    put64(b, 56, p);
    put64(b, 64, RESPONSE_BYTES as u64);
    Ok(())
}
fn check(b: &[u8], op: u32, p: u64) -> Result<(), ProtocolError> {
    if b.len() != 72 + p as usize
        || b[..8] != MAGIC
        || u16::from_le_bytes(b[8..10].try_into().unwrap()) != 1
        || b[10..16] != [0; 6]
        || b[16..48] != INTERFACE_FINGERPRINT
        || get32(b, 48) != INTERFACE_GENERATION
        || get32(b, 52) != op
        || get64(b, 56) != p
        || get64(b, 64) != RESPONSE_BYTES as u64
    {
        Err(ProtocolError::InvalidHeader)
    } else {
        Ok(())
    }
}
fn response(s: u32, a: u64, z: u64) -> [u8; RESPONSE_BYTES] {
    let mut b = [0; RESPONSE_BYTES];
    put32(&mut b, 0, s);
    put64(&mut b, 8, a);
    put64(&mut b, 16, z);
    b
}
fn decode_response(b: &[u8; RESPONSE_BYTES]) -> Result<(u32, u64, u64), ProtocolError> {
    if b[4..8] != [0; 4] {
        Err(ProtocolError::InvalidResponse)
    } else {
        Ok((get32(b, 0), get64(b, 8), get64(b, 16)))
    }
}
fn put_r(b: &mut [u8], o: usize, v: BorrowedReadView) {
    put64(b, o, v.offset());
    put64(b, o + 8, v.length())
}
fn put_w(b: &mut [u8], o: usize, v: BorrowedWriteView) {
    put64(b, o, v.offset());
    put64(b, o + 8, v.length())
}
fn get_r(b: &[u8], o: usize, m: u64) -> Result<BorrowedReadView, ProtocolError> {
    BorrowedReadView::within(get64(b, o), get64(b, o + 8), m).ok_or(ProtocolError::InvalidRequest)
}
fn get_w(b: &[u8], o: usize, m: u64) -> Result<BorrowedWriteView, ProtocolError> {
    BorrowedWriteView::within(get64(b, o), get64(b, o + 8), m).ok_or(ProtocolError::InvalidRequest)
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes())
}
fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes())
}
fn get32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn get64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codecs_round_trip_and_reject_overlap() {
        let r = RequestSigningRouteRequest {
            identity: BorrowedReadView::within(0, 16, 256).unwrap(),
            generation: 7,
            key_identity: BorrowedReadView::within(16, 32, 256).unwrap(),
            output: BorrowedWriteView::within(48, 64, 256).unwrap(),
        };
        let b = encode_request_signing_route_request(r).unwrap();
        assert_eq!(decode_request_signing_route_request(&b, 256), Ok(r));
        assert_eq!(
            decode_poll_generation_response(&encode_poll_generation_response(Ok(
                PollGenerationResponse {
                    current_generation: 8,
                    health: HEALTH_HEALTHY
                }
            ))),
            Ok(Ok(PollGenerationResponse {
                current_generation: 8,
                health: HEALTH_HEALTHY
            }))
        );
        assert_eq!(
            encode_request_signing_route_request(RequestSigningRouteRequest {
                output: BorrowedWriteView::within(32, 64, 256).unwrap(),
                ..r
            }),
            Err(ProtocolError::InvalidRequest)
        );
    }
}
