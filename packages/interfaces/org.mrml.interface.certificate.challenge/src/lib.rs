#![no_std]
//! Exact generation-bound HTTP-01, TLS-ALPN-01, and DNS-01 publication lifecycle.
#[path = "../1.rs"]
mod generated;
pub use generated::*;
pub const CHALLENGE_HTTP01: u32 = 1;
pub const CHALLENGE_TLS_ALPN01: u32 = 2;
pub const CHALLENGE_DNS01: u32 = 3;
pub const PUBLICATION_PREPARED: u32 = 1;
pub const PUBLICATION_ACTIVE: u32 = 2;
pub const PUBLICATION_REMOVAL_PREPARED: u32 = 3;
pub const PUBLICATION_REMOVAL_UNCERTAIN: u32 = 4;
pub const PUBLICATION_REMOVED: u32 = 5;
pub const ABI_CALL_HEADER_BYTES: usize = 72;
pub const PREPARE_REQUEST_BYTES: usize = 208;
pub const RECEIPT_REQUEST_BYTES: usize = 88;
pub const RESPONSE_BYTES: usize = 24;
const MAGIC: [u8; 8] = *b"MRMLCALL";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidHeader,
    InvalidRequest,
    InvalidResponse,
}

pub fn encode_prepare_request(
    r: PrepareRequest,
) -> Result<[u8; PREPARE_REQUEST_BYTES], ProtocolError> {
    validate_prepare(&r)?;
    let mut b = [0; PREPARE_REQUEST_BYTES];
    header(&mut b, OP_PREPARE, 136)?;
    put32(&mut b, 72, r.challenge_kind);
    put64(&mut b, 80, r.challenge_generation);
    put_r(&mut b, 88, r.order_digest);
    put_r(&mut b, 104, r.authorization_digest);
    put_r(&mut b, 120, r.identifier);
    put_r(&mut b, 136, r.token);
    put_r(&mut b, 152, r.key_authorization_digest);
    put64(&mut b, 168, r.not_before);
    put64(&mut b, 176, r.expires);
    put64(&mut b, 184, r.policy_generation);
    put_w(&mut b, 192, r.output);
    Ok(b)
}
pub fn decode_prepare_request(
    b: &[u8; PREPARE_REQUEST_BYTES],
    m: u64,
) -> Result<PrepareRequest, ProtocolError> {
    check(b, OP_PREPARE, 136)?;
    if b[76..80] != [0; 4] {
        return Err(ProtocolError::InvalidHeader);
    }
    let r = PrepareRequest {
        challenge_kind: get32(b, 72),
        challenge_generation: get64(b, 80),
        order_digest: get_r(b, 88, m)?,
        authorization_digest: get_r(b, 104, m)?,
        identifier: get_r(b, 120, m)?,
        token: get_r(b, 136, m)?,
        key_authorization_digest: get_r(b, 152, m)?,
        not_before: get64(b, 168),
        expires: get64(b, 176),
        policy_generation: get64(b, 184),
        output: get_w(b, 192, m)?,
    };
    validate_prepare(&r)?;
    Ok(r)
}

macro_rules! receipt_codec {
    ($enc:ident,$dec:ident,$ty:ty,$ctor:path,$op:ident) => {
        pub fn $enc(r: $ty) -> Result<[u8; RECEIPT_REQUEST_BYTES], ProtocolError> {
            if !r.validate() || r.receipt.length() == 0 {
                return Err(ProtocolError::InvalidRequest);
            }
            let mut b = [0; RECEIPT_REQUEST_BYTES];
            header(&mut b, $op, 16)?;
            put_r(&mut b, 72, r.receipt);
            Ok(b)
        }
        pub fn $dec(b: &[u8; RECEIPT_REQUEST_BYTES], m: u64) -> Result<$ty, ProtocolError> {
            check(b, $op, 16)?;
            let r = $ctor(get_r(b, 72, m)?);
            $enc(r).map(|_| r)
        }
    };
}
fn activate_request(receipt: BorrowedReadView) -> ActivateRequest {
    ActivateRequest { receipt }
}
fn prepare_removal_request(receipt: BorrowedReadView) -> PrepareRemovalRequest {
    PrepareRemovalRequest { receipt }
}
fn commit_removal_request(receipt: BorrowedReadView) -> CommitRemovalRequest {
    CommitRemovalRequest { receipt }
}
fn authoritative_request(receipt: BorrowedReadView) -> AuthoritativeStateRequest {
    AuthoritativeStateRequest { receipt }
}
receipt_codec!(
    encode_activate_request,
    decode_activate_request,
    ActivateRequest,
    activate_request,
    OP_ACTIVATE
);
receipt_codec!(
    encode_prepare_removal_request,
    decode_prepare_removal_request,
    PrepareRemovalRequest,
    prepare_removal_request,
    OP_PREPARE_REMOVAL
);
receipt_codec!(
    encode_commit_removal_request,
    decode_commit_removal_request,
    CommitRemovalRequest,
    commit_removal_request,
    OP_COMMIT_REMOVAL
);
receipt_codec!(
    encode_authoritative_state_request,
    decode_authoritative_state_request,
    AuthoritativeStateRequest,
    authoritative_request,
    OP_AUTHORITATIVE_STATE
);

pub fn encode_prepare_response(r: Result<PrepareResponse, PrepareError>) -> [u8; RESPONSE_BYTES] {
    match r {
        Ok(v) => response(0, v.written, v.publisher_generation),
        Err(e) => response(e as u32, 0, 0),
    }
}
pub fn decode_prepare_response(
    b: &[u8; RESPONSE_BYTES],
    limit: u64,
) -> Result<Result<PrepareResponse, PrepareError>, ProtocolError> {
    let (s, w, g) = decode_response(b)?;
    if s == 0 {
        return if w != 0 && w <= limit && w <= 128 && g != 0 {
            Ok(Ok(PrepareResponse {
                written: w,
                publisher_generation: g,
            }))
        } else {
            Err(ProtocolError::InvalidResponse)
        };
    }
    let e = match s {
        1 => PrepareError::InvalidRequest,
        2 => PrepareError::StaleGeneration,
        3 => PrepareError::PermissionDenied,
        4 => PrepareError::Capacity,
        5 => PrepareError::OutputTooSmall,
        _ => return Err(ProtocolError::InvalidResponse),
    };
    error_tail(w, g, e)
}
macro_rules! generation_response{($enc:ident,$dec:ident,$ok:ty,$err:ty,$($n:literal=>$e:ident),+)=>{pub fn $enc(r:Result<$ok,$err>)->[u8;RESPONSE_BYTES]{match r{Ok(g)=>response(0,g,0),Err(e)=>response(e as u32,0,0)}}pub fn $dec(b:&[u8;RESPONSE_BYTES])->Result<Result<$ok,$err>,ProtocolError>{let(s,g,z)=decode_response(b)?;if s==0{return if g!=0&&z==0{Ok(Ok(g))}else{Err(ProtocolError::InvalidResponse)}}let e=match s{$($n=><$err>::$e,)+_=>return Err(ProtocolError::InvalidResponse)};error_tail(g,z,e)}}}
generation_response!(encode_activate_response,decode_activate_response,ActivateResponse,ActivateError,1=>InvalidRequest,2=>StaleGeneration,3=>PermissionDenied,4=>PublicationFailed);
generation_response!(encode_prepare_removal_response,decode_prepare_removal_response,PrepareRemovalResponse,PrepareRemovalError,1=>InvalidRequest,2=>StaleGeneration,3=>PermissionDenied);
generation_response!(encode_commit_removal_response,decode_commit_removal_response,CommitRemovalResponse,CommitRemovalError,1=>InvalidRequest,2=>StaleGeneration,3=>PermissionDenied,4=>RemovalUncertain);
pub fn encode_authoritative_state_response(
    r: Result<AuthoritativeStateResponse, AuthoritativeStateError>,
) -> [u8; RESPONSE_BYTES] {
    match r {
        Ok(v) => response(0, v.state as u64, v.publisher_generation),
        Err(e) => response(e as u32, 0, 0),
    }
}
pub fn decode_authoritative_state_response(
    b: &[u8; RESPONSE_BYTES],
) -> Result<Result<AuthoritativeStateResponse, AuthoritativeStateError>, ProtocolError> {
    let (s, state, g) = decode_response(b)?;
    if s == 0 {
        return if (PUBLICATION_PREPARED as u64..=PUBLICATION_REMOVED as u64).contains(&state)
            && g != 0
        {
            Ok(Ok(AuthoritativeStateResponse {
                state: state as u32,
                publisher_generation: g,
            }))
        } else {
            Err(ProtocolError::InvalidResponse)
        };
    }
    let e = match s {
        1 => AuthoritativeStateError::InvalidRequest,
        2 => AuthoritativeStateError::UnknownReceipt,
        3 => AuthoritativeStateError::PermissionDenied,
        _ => return Err(ProtocolError::InvalidResponse),
    };
    error_tail(state, g, e)
}

fn validate_prepare(r: &PrepareRequest) -> Result<(), ProtocolError> {
    let reads = [
        r.order_digest,
        r.authorization_digest,
        r.identifier,
        r.token,
        r.key_authorization_digest,
    ];
    if !r.validate()
        || !(CHALLENGE_HTTP01..=CHALLENGE_DNS01).contains(&r.challenge_kind)
        || r.challenge_generation == 0
        || r.order_digest.length() != 32
        || r.authorization_digest.length() != 32
        || r.identifier.length() == 0
        || r.token.length() == 0
        || r.key_authorization_digest.length() != 32
        || r.not_before >= r.expires
        || r.policy_generation == 0
        || r.output.length() == 0
        || reads.iter().any(|v| overlap(*v, r.output))
    {
        Err(ProtocolError::InvalidRequest)
    } else {
        Ok(())
    }
}
fn overlap(r: BorrowedReadView, w: BorrowedWriteView) -> bool {
    r.offset() < w.offset().saturating_add(w.length())
        && w.offset() < r.offset().saturating_add(r.length())
}
fn error_tail<T>(a: u64, z: u64, e: T) -> Result<Result<T::Output, T>, ProtocolError>
where
    T: ErrorOutput,
{
    if a == 0 && z == 0 {
        Ok(Err(e))
    } else {
        Err(ProtocolError::InvalidResponse)
    }
}
trait ErrorOutput {
    type Output;
}
impl ErrorOutput for PrepareError {
    type Output = PrepareResponse;
}
impl ErrorOutput for ActivateError {
    type Output = ActivateResponse;
}
impl ErrorOutput for PrepareRemovalError {
    type Output = PrepareRemovalResponse;
}
impl ErrorOutput for CommitRemovalError {
    type Output = CommitRemovalResponse;
}
impl ErrorOutput for AuthoritativeStateError {
    type Output = AuthoritativeStateResponse;
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
    fn challenge_frames_round_trip_and_reject_overlap() {
        let request = PrepareRequest {
            challenge_kind: CHALLENGE_DNS01,
            challenge_generation: 7,
            order_digest: BorrowedReadView::within(0, 32, 1024).unwrap(),
            authorization_digest: BorrowedReadView::within(32, 32, 1024).unwrap(),
            identifier: BorrowedReadView::within(64, 11, 1024).unwrap(),
            token: BorrowedReadView::within(75, 12, 1024).unwrap(),
            key_authorization_digest: BorrowedReadView::within(87, 32, 1024).unwrap(),
            not_before: 10,
            expires: 20,
            policy_generation: 3,
            output: BorrowedWriteView::within(128, 128, 1024).unwrap(),
        };
        let encoded = encode_prepare_request(request).unwrap();
        assert_eq!(decode_prepare_request(&encoded, 1024), Ok(request));
        let receipt = ActivateRequest {
            receipt: BorrowedReadView::within(0, 64, 128).unwrap(),
        };
        assert_eq!(
            decode_activate_request(&encode_activate_request(receipt).unwrap(), 128),
            Ok(receipt)
        );
        let state = AuthoritativeStateResponse {
            state: PUBLICATION_REMOVED,
            publisher_generation: 9,
        };
        assert_eq!(
            decode_authoritative_state_response(&encode_authoritative_state_response(Ok(state))),
            Ok(Ok(state))
        );
        assert_eq!(
            encode_prepare_request(PrepareRequest {
                output: BorrowedWriteView::within(100, 128, 1024).unwrap(),
                ..request
            }),
            Err(ProtocolError::InvalidRequest)
        );
        let mut corrupt = encoded;
        corrupt[10] = 1;
        assert_eq!(
            decode_prepare_request(&corrupt, 1024),
            Err(ProtocolError::InvalidHeader)
        );
    }
}
