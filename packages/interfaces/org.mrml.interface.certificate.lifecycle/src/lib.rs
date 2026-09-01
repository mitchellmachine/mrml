#![no_std]
//! Owner-authorized certificate lifecycle administration; the route capability authorizes.
#[path = "../1.rs"]
mod generated;
pub use generated::*;
pub const BACKUP_CREATE: u32 = 1;
pub const BACKUP_VERIFY: u32 = 2;
pub const RESTORE_VERIFY_ONLY: u32 = 3;
pub const RESTORE_COMMIT: u32 = 4;
pub const SCOPE_ACCOUNT: u32 = 1;
pub const SCOPE_IDENTITY: u32 = 2;
pub const SCOPE_CHALLENGE: u32 = 3;
pub const SCOPE_BACKUP: u32 = 4;
pub const ACCOUNT_CREATE: u32 = 1;
pub const ACCOUNT_RECOVER: u32 = 2;
pub const ACCOUNT_UPDATE: u32 = 3;
pub const ACCOUNT_ROLLOVER: u32 = 4;
pub const ACCOUNT_DEACTIVATE: u32 = 5;
pub const ACCOUNT_ACCEPT_TERMS: u32 = 6;
pub const IDENTITY_OBTAIN: u32 = 1;
pub const IDENTITY_RENEW: u32 = 2;
pub const IDENTITY_REPLACE: u32 = 3;
pub const IDENTITY_REVOKE: u32 = 4;
pub const ABI_CALL_HEADER_BYTES: usize = 72;
pub const STATUS_REQUEST_BYTES: usize = 112;
pub const ACCOUNT_OPERATION_REQUEST_BYTES: usize = 120;
pub const IDENTITY_OPERATION_REQUEST_BYTES: usize = 136;
pub const BACKUP_OPERATION_REQUEST_BYTES: usize = 120;
pub const RESPONSE_BYTES: usize = 24;
const MAGIC: [u8; 8] = *b"MRMLCALL";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidHeader,
    InvalidRequest,
    InvalidResponse,
}
pub fn encode_status_request(
    r: StatusRequest,
) -> Result<[u8; STATUS_REQUEST_BYTES], ProtocolError> {
    if !r.validate()
        || !(SCOPE_ACCOUNT..=SCOPE_BACKUP).contains(&r.scope)
        || r.object_identity.length() == 0
        || r.output.length() == 0
        || overlap(r.object_identity, r.output)
    {
        return Err(ProtocolError::InvalidRequest);
    }
    let mut b = [0; STATUS_REQUEST_BYTES];
    header(&mut b, OP_STATUS, 40)?;
    put32(&mut b, 72, r.scope);
    put_r(&mut b, 80, r.object_identity);
    put_w(&mut b, 96, r.output);
    Ok(b)
}
pub fn decode_status_request(
    b: &[u8; STATUS_REQUEST_BYTES],
    m: u64,
) -> Result<StatusRequest, ProtocolError> {
    check(b, OP_STATUS, 40)?;
    if b[76..80] != [0; 4] {
        return Err(ProtocolError::InvalidHeader);
    }
    let r = StatusRequest {
        scope: get32(b, 72),
        object_identity: get_r(b, 80, m)?,
        output: get_w(b, 96, m)?,
    };
    encode_status_request(r).map(|_| r)
}
pub fn encode_account_operation_request(
    r: AccountOperationRequest,
) -> Result<[u8; ACCOUNT_OPERATION_REQUEST_BYTES], ProtocolError> {
    valid_operation(
        r.operation,
        ACCOUNT_CREATE,
        ACCOUNT_ACCEPT_TERMS,
        r.policy_generation,
        r.request,
        r.output,
        4096,
        4096,
    )?;
    let mut b = [0; ACCOUNT_OPERATION_REQUEST_BYTES];
    header(&mut b, OP_ACCOUNT_OPERATION, 48)?;
    put32(&mut b, 72, r.operation);
    put64(&mut b, 80, r.policy_generation);
    put_r(&mut b, 88, r.request);
    put_w(&mut b, 104, r.output);
    Ok(b)
}
pub fn decode_account_operation_request(
    b: &[u8; ACCOUNT_OPERATION_REQUEST_BYTES],
    m: u64,
) -> Result<AccountOperationRequest, ProtocolError> {
    check(b, OP_ACCOUNT_OPERATION, 48)?;
    if b[76..80] != [0; 4] {
        return Err(ProtocolError::InvalidHeader);
    }
    let r = AccountOperationRequest {
        operation: get32(b, 72),
        policy_generation: get64(b, 80),
        request: get_r(b, 88, m)?,
        output: get_w(b, 104, m)?,
    };
    encode_account_operation_request(r).map(|_| r)
}
pub fn encode_identity_operation_request(
    r: IdentityOperationRequest,
) -> Result<[u8; IDENTITY_OPERATION_REQUEST_BYTES], ProtocolError> {
    if !r.validate() || r.identity.length() == 0 {
        return Err(ProtocolError::InvalidRequest);
    }
    valid_operation(
        r.operation,
        IDENTITY_OBTAIN,
        IDENTITY_REVOKE,
        r.policy_generation,
        r.request,
        r.output,
        8192,
        8192,
    )?;
    if overlap(r.identity, r.output) {
        return Err(ProtocolError::InvalidRequest);
    }
    let mut b = [0; IDENTITY_OPERATION_REQUEST_BYTES];
    header(&mut b, OP_IDENTITY_OPERATION, 64)?;
    put32(&mut b, 72, r.operation);
    put_r(&mut b, 80, r.identity);
    put64(&mut b, 96, r.policy_generation);
    put_r(&mut b, 104, r.request);
    put_w(&mut b, 120, r.output);
    Ok(b)
}
pub fn decode_identity_operation_request(
    b: &[u8; IDENTITY_OPERATION_REQUEST_BYTES],
    m: u64,
) -> Result<IdentityOperationRequest, ProtocolError> {
    check(b, OP_IDENTITY_OPERATION, 64)?;
    if b[76..80] != [0; 4] {
        return Err(ProtocolError::InvalidHeader);
    }
    let r = IdentityOperationRequest {
        operation: get32(b, 72),
        identity: get_r(b, 80, m)?,
        policy_generation: get64(b, 96),
        request: get_r(b, 104, m)?,
        output: get_w(b, 120, m)?,
    };
    encode_identity_operation_request(r).map(|_| r)
}
pub fn encode_backup_operation_request(
    r: BackupOperationRequest,
) -> Result<[u8; BACKUP_OPERATION_REQUEST_BYTES], ProtocolError> {
    valid_operation(
        r.operation,
        BACKUP_CREATE,
        RESTORE_COMMIT,
        r.policy_generation,
        r.request,
        r.output,
        4096,
        8192,
    )?;
    let mut b = [0; BACKUP_OPERATION_REQUEST_BYTES];
    header(&mut b, OP_BACKUP_OPERATION, 48)?;
    put32(&mut b, 72, r.operation);
    put64(&mut b, 80, r.policy_generation);
    put_r(&mut b, 88, r.request);
    put_w(&mut b, 104, r.output);
    Ok(b)
}
pub fn decode_backup_operation_request(
    b: &[u8; BACKUP_OPERATION_REQUEST_BYTES],
    m: u64,
) -> Result<BackupOperationRequest, ProtocolError> {
    check(b, OP_BACKUP_OPERATION, 48)?;
    if b[76..80] != [0; 4] {
        return Err(ProtocolError::InvalidHeader);
    }
    let r = BackupOperationRequest {
        operation: get32(b, 72),
        policy_generation: get64(b, 80),
        request: get_r(b, 88, m)?,
        output: get_w(b, 104, m)?,
    };
    encode_backup_operation_request(r).map(|_| r)
}
macro_rules! response_codec{($enc:ident,$dec:ident,$ok:ty,$err:ty,$field:ident,$max:expr,$($n:literal=>$e:ident),+)=>{pub fn $enc(r:Result<$ok,$err>)->[u8;RESPONSE_BYTES]{match r{Ok(v)=>response(0,v.written,v.$field),Err(e)=>response(e as u32,0,0)}}pub fn $dec(b:&[u8;RESPONSE_BYTES],limit:u64)->Result<Result<$ok,$err>,ProtocolError>{let(s,w,g)=decode_response(b)?;if s==0{return if w!=0&&w<=limit&&w<=$max&&g!=0{Ok(Ok(<$ok>::new(w,g)))}else{Err(ProtocolError::InvalidResponse)}}let e=match s{$($n=><$err>::$e,)+_=>return Err(ProtocolError::InvalidResponse)};if w!=0||g!=0{return Err(ProtocolError::InvalidResponse)}Ok(Err(e))}}}
trait NewResponse {
    fn new(w: u64, g: u64) -> Self;
}
impl NewResponse for StatusResponse {
    fn new(w: u64, g: u64) -> Self {
        Self {
            written: w,
            state_generation: g,
        }
    }
}
impl NewResponse for AccountOperationResponse {
    fn new(w: u64, g: u64) -> Self {
        Self {
            written: w,
            account_generation: g,
        }
    }
}
impl NewResponse for IdentityOperationResponse {
    fn new(w: u64, g: u64) -> Self {
        Self {
            written: w,
            identity_generation: g,
        }
    }
}
impl NewResponse for BackupOperationResponse {
    fn new(w: u64, g: u64) -> Self {
        Self {
            written: w,
            backup_generation: g,
        }
    }
}
response_codec!(encode_status_response,decode_status_response,StatusResponse,StatusError,state_generation,8192,1=>InvalidRequest,2=>PermissionDenied,3=>NotFound,4=>OutputTooSmall);
response_codec!(encode_account_operation_response,decode_account_operation_response,AccountOperationResponse,AccountOperationError,account_generation,4096,1=>InvalidRequest,2=>StalePolicy,3=>PermissionDenied,4=>OwnerAuthorizationRequired,5=>OperationFailed);
response_codec!(encode_identity_operation_response,decode_identity_operation_response,IdentityOperationResponse,IdentityOperationError,identity_generation,8192,1=>InvalidRequest,2=>StalePolicy,3=>PermissionDenied,4=>OwnerAuthorizationRequired,5=>OperationFailed);
response_codec!(encode_backup_operation_response,decode_backup_operation_response,BackupOperationResponse,BackupOperationError,backup_generation,8192,1=>InvalidRequest,2=>StalePolicy,3=>PermissionDenied,4=>OwnerAuthorizationRequired,5=>OperationFailed);
fn valid_operation(
    op: u32,
    min: u32,
    max: u32,
    policy: u64,
    r: BorrowedReadView,
    w: BorrowedWriteView,
    rmax: u64,
    wmax: u64,
) -> Result<(), ProtocolError> {
    if !(min..=max).contains(&op)
        || policy == 0
        || r.length() > rmax
        || w.length() == 0
        || w.length() > wmax
        || overlap(r, w)
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
fn response(s: u32, w: u64, g: u64) -> [u8; RESPONSE_BYTES] {
    let mut b = [0; RESPONSE_BYTES];
    put32(&mut b, 0, s);
    put64(&mut b, 8, w);
    put64(&mut b, 16, g);
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
    fn lifecycle_frames_round_trip_and_bind_owner_operations() {
        let account = AccountOperationRequest {
            operation: ACCOUNT_ROLLOVER,
            policy_generation: 7,
            request: BorrowedReadView::within(0, 64, 512).unwrap(),
            output: BorrowedWriteView::within(64, 128, 512).unwrap(),
        };
        assert_eq!(
            decode_account_operation_request(
                &encode_account_operation_request(account).unwrap(),
                512
            ),
            Ok(account)
        );
        let identity = IdentityOperationRequest {
            operation: IDENTITY_RENEW,
            identity: BorrowedReadView::within(0, 16, 512).unwrap(),
            policy_generation: 8,
            request: BorrowedReadView::within(16, 32, 512).unwrap(),
            output: BorrowedWriteView::within(48, 128, 512).unwrap(),
        };
        assert_eq!(
            decode_identity_operation_request(
                &encode_identity_operation_request(identity).unwrap(),
                512
            ),
            Ok(identity)
        );
        let response = IdentityOperationResponse {
            written: 32,
            identity_generation: 9,
        };
        assert_eq!(
            decode_identity_operation_response(
                &encode_identity_operation_response(Ok(response)),
                128
            ),
            Ok(Ok(response))
        );
        assert_eq!(
            encode_account_operation_request(AccountOperationRequest {
                operation: 99,
                ..account
            }),
            Err(ProtocolError::InvalidRequest)
        );
        assert_eq!(
            encode_identity_operation_request(IdentityOperationRequest {
                output: BorrowedWriteView::within(32, 128, 512).unwrap(),
                ..identity
            }),
            Err(ProtocolError::InvalidRequest)
        );
    }
}
