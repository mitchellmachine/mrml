#![no_std]
//! Generation-bound, use-only certificate signing. The route capability authorizes;
//! identity and key fields only bind the selected route and never grant authority.
#[path = "../1.rs"]
mod generated;
pub use generated::*;
pub const PURPOSE_ACME_ACCOUNT_JWS: u32 = 1;
pub const PURPOSE_PKCS10: u32 = 2;
pub const PURPOSE_TLS13_CERTIFICATE_VERIFY: u32 = 3;
pub const PURPOSE_TLS_ALPN01_CERTIFICATE: u32 = 4;

pub const ABI_CALL_HEADER_BYTES: usize = 72;
pub const DESCRIBE_PUBLIC_KEY_REQUEST_BYTES: usize = 144;
pub const SIGN_REQUEST_BYTES: usize = 176;
pub const RESPONSE_BYTES: usize = 24;
const ABI_MAGIC: [u8; 8] = *b"MRMLCALL";
const ABI_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidHeader,
    InvalidRequest,
    InvalidResponse,
}

pub fn encode_describe_public_key_request(
    request: DescribePublicKeyRequest,
) -> Result<[u8; DESCRIBE_PUBLIC_KEY_REQUEST_BYTES], ProtocolError> {
    validate_describe(&request)?;
    let mut bytes = [0; DESCRIBE_PUBLIC_KEY_REQUEST_BYTES];
    encode_header(&mut bytes, OP_DESCRIBE_PUBLIC_KEY, 72)?;
    write_view(&mut bytes, 72, request.identity);
    write_u64(&mut bytes, 88, request.identity_generation);
    write_view(&mut bytes, 96, request.key_identity);
    write_u64(&mut bytes, 112, request.route_generation);
    write_write_view(&mut bytes, 120, request.output);
    Ok(bytes)
}

pub fn decode_describe_public_key_request(
    bytes: &[u8; DESCRIBE_PUBLIC_KEY_REQUEST_BYTES],
    memory_length: u64,
) -> Result<DescribePublicKeyRequest, ProtocolError> {
    validate_header(bytes, OP_DESCRIBE_PUBLIC_KEY, 72)?;
    let request = DescribePublicKeyRequest {
        identity: read_view(bytes, 72, memory_length)?,
        identity_generation: read_u64(bytes, 88),
        key_identity: read_view(bytes, 96, memory_length)?,
        route_generation: read_u64(bytes, 112),
        output: read_write_view(bytes, 120, memory_length)?,
    };
    if bytes[136..144] != [0; 8] {
        return Err(ProtocolError::InvalidHeader);
    }
    validate_describe(&request)?;
    Ok(request)
}

pub fn encode_sign_request(
    request: SignRequest,
) -> Result<[u8; SIGN_REQUEST_BYTES], ProtocolError> {
    validate_sign(&request)?;
    let mut bytes = [0; SIGN_REQUEST_BYTES];
    encode_header(&mut bytes, OP_SIGN, 104)?;
    write_u32(&mut bytes, 72, request.purpose);
    write_view(&mut bytes, 80, request.identity);
    write_u64(&mut bytes, 96, request.identity_generation);
    write_view(&mut bytes, 104, request.key_identity);
    write_u64(&mut bytes, 120, request.route_generation);
    write_view(&mut bytes, 128, request.approved_digest);
    write_write_view(&mut bytes, 144, request.output);
    Ok(bytes)
}

pub fn decode_sign_request(
    bytes: &[u8; SIGN_REQUEST_BYTES],
    memory_length: u64,
) -> Result<SignRequest, ProtocolError> {
    validate_header(bytes, OP_SIGN, 104)?;
    if bytes[76..80] != [0; 4] || bytes[160..176] != [0; 16] {
        return Err(ProtocolError::InvalidHeader);
    }
    let request = SignRequest {
        purpose: read_u32(bytes, 72),
        identity: read_view(bytes, 80, memory_length)?,
        identity_generation: read_u64(bytes, 96),
        key_identity: read_view(bytes, 104, memory_length)?,
        route_generation: read_u64(bytes, 120),
        approved_digest: read_view(bytes, 128, memory_length)?,
        output: read_write_view(bytes, 144, memory_length)?,
    };
    validate_sign(&request)?;
    Ok(request)
}

pub fn encode_describe_public_key_response(
    result: Result<DescribePublicKeyResponse, DescribePublicKeyError>,
) -> [u8; RESPONSE_BYTES] {
    match result {
        Ok(value) => encode_response(0, value.written, value.key_generation),
        Err(error) => encode_response(error as u32, 0, 0),
    }
}

pub fn decode_describe_public_key_response(
    bytes: &[u8; RESPONSE_BYTES],
    output_length: u64,
) -> Result<Result<DescribePublicKeyResponse, DescribePublicKeyError>, ProtocolError> {
    let (status, written, generation) = decode_response(bytes)?;
    if status == 0 {
        return if written != 0 && written <= output_length && written <= 65 && generation != 0 {
            Ok(Ok(DescribePublicKeyResponse {
                written,
                key_generation: generation,
            }))
        } else {
            Err(ProtocolError::InvalidResponse)
        };
    }
    let error = match status {
        1 => DescribePublicKeyError::InvalidRequest,
        2 => DescribePublicKeyError::StaleIdentity,
        3 => DescribePublicKeyError::StaleKey,
        4 => DescribePublicKeyError::PermissionDenied,
        5 => DescribePublicKeyError::OutputTooSmall,
        6 => DescribePublicKeyError::KeyUnavailable,
        _ => return Err(ProtocolError::InvalidResponse),
    };
    if written != 0 || generation != 0 {
        return Err(ProtocolError::InvalidResponse);
    }
    Ok(Err(error))
}

pub fn encode_sign_response(result: Result<SignResponse, SignError>) -> [u8; RESPONSE_BYTES] {
    match result {
        Ok(value) => encode_response(0, value.written, value.signature_generation),
        Err(error) => encode_response(error as u32, 0, 0),
    }
}

pub fn decode_sign_response(
    bytes: &[u8; RESPONSE_BYTES],
    output_length: u64,
) -> Result<Result<SignResponse, SignError>, ProtocolError> {
    let (status, written, generation) = decode_response(bytes)?;
    if status == 0 {
        return if written != 0 && written <= output_length && written <= 72 && generation != 0 {
            Ok(Ok(SignResponse {
                written,
                signature_generation: generation,
            }))
        } else {
            Err(ProtocolError::InvalidResponse)
        };
    }
    let error = match status {
        1 => SignError::InvalidRequest,
        2 => SignError::StaleIdentity,
        3 => SignError::StaleKey,
        4 => SignError::PermissionDenied,
        5 => SignError::UnsupportedPurpose,
        6 => SignError::OutputTooSmall,
        7 => SignError::SigningFailed,
        _ => return Err(ProtocolError::InvalidResponse),
    };
    if written != 0 || generation != 0 {
        return Err(ProtocolError::InvalidResponse);
    }
    Ok(Err(error))
}

fn validate_describe(request: &DescribePublicKeyRequest) -> Result<(), ProtocolError> {
    if !request.validate()
        || request.identity.length() == 0
        || request.key_identity.length() != 32
        || request.output.length() == 0
        || overlaps(request.identity, request.output)
        || overlaps(request.key_identity, request.output)
    {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(())
}

fn validate_sign(request: &SignRequest) -> Result<(), ProtocolError> {
    if !request.validate()
        || !(PURPOSE_ACME_ACCOUNT_JWS..=PURPOSE_TLS_ALPN01_CERTIFICATE).contains(&request.purpose)
        || request.identity.length() == 0
        || request.key_identity.length() != 32
        || request.approved_digest.length() != 32
        || request.output.length() == 0
        || overlaps(request.identity, request.output)
        || overlaps(request.key_identity, request.output)
        || overlaps(request.approved_digest, request.output)
    {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(())
}

fn overlaps(read: BorrowedReadView, write: BorrowedWriteView) -> bool {
    let read_end = read.offset().checked_add(read.length()).unwrap_or(u64::MAX);
    let write_end = write
        .offset()
        .checked_add(write.length())
        .unwrap_or(u64::MAX);
    read.offset() < write_end && write.offset() < read_end
}

fn encode_header<const N: usize>(
    bytes: &mut [u8; N],
    operation: u32,
    payload: u64,
) -> Result<(), ProtocolError> {
    if N != ABI_CALL_HEADER_BYTES + payload as usize {
        return Err(ProtocolError::InvalidRequest);
    }
    bytes[0..8].copy_from_slice(&ABI_MAGIC);
    bytes[8..10].copy_from_slice(&ABI_SCHEMA_VERSION.to_le_bytes());
    bytes[16..48].copy_from_slice(&INTERFACE_FINGERPRINT);
    write_u32(bytes, 48, INTERFACE_GENERATION);
    write_u32(bytes, 52, operation);
    write_u64(bytes, 56, payload);
    write_u64(bytes, 64, RESPONSE_BYTES as u64);
    Ok(())
}

fn validate_header(bytes: &[u8], operation: u32, payload: u64) -> Result<(), ProtocolError> {
    if bytes.len() != ABI_CALL_HEADER_BYTES + payload as usize
        || bytes[0..8] != ABI_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != ABI_SCHEMA_VERSION
        || bytes[10..16] != [0; 6]
        || bytes[16..48] != INTERFACE_FINGERPRINT
        || read_u32(bytes, 48) != INTERFACE_GENERATION
        || read_u32(bytes, 52) != operation
        || read_u64(bytes, 56) != payload
        || read_u64(bytes, 64) != RESPONSE_BYTES as u64
    {
        return Err(ProtocolError::InvalidHeader);
    }
    Ok(())
}

fn encode_response(status: u32, first: u64, second: u64) -> [u8; RESPONSE_BYTES] {
    let mut bytes = [0; RESPONSE_BYTES];
    write_u32(&mut bytes, 0, status);
    write_u64(&mut bytes, 8, first);
    write_u64(&mut bytes, 16, second);
    bytes
}
fn decode_response(bytes: &[u8; RESPONSE_BYTES]) -> Result<(u32, u64, u64), ProtocolError> {
    if bytes[4..8] != [0; 4] {
        return Err(ProtocolError::InvalidResponse);
    }
    Ok((read_u32(bytes, 0), read_u64(bytes, 8), read_u64(bytes, 16)))
}
fn write_view(bytes: &mut [u8], offset: usize, view: BorrowedReadView) {
    write_u64(bytes, offset, view.offset());
    write_u64(bytes, offset + 8, view.length());
}
fn write_write_view(bytes: &mut [u8], offset: usize, view: BorrowedWriteView) {
    write_u64(bytes, offset, view.offset());
    write_u64(bytes, offset + 8, view.length());
}
fn read_view(bytes: &[u8], offset: usize, length: u64) -> Result<BorrowedReadView, ProtocolError> {
    BorrowedReadView::within(read_u64(bytes, offset), read_u64(bytes, offset + 8), length)
        .ok_or(ProtocolError::InvalidRequest)
}
fn read_write_view(
    bytes: &[u8],
    offset: usize,
    length: u64,
) -> Result<BorrowedWriteView, ProtocolError> {
    BorrowedWriteView::within(read_u64(bytes, offset), read_u64(bytes, offset + 8), length)
        .ok_or(ProtocolError::InvalidRequest)
}
fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signing_codec_round_trips_and_rejects_hostile_views() {
        let request = SignRequest {
            purpose: PURPOSE_TLS13_CERTIFICATE_VERIFY,
            identity: BorrowedReadView::within(0, 16, 256).unwrap(),
            identity_generation: 7,
            key_identity: BorrowedReadView::within(16, 32, 256).unwrap(),
            route_generation: 9,
            approved_digest: BorrowedReadView::within(48, 32, 256).unwrap(),
            output: BorrowedWriteView::within(80, 72, 256).unwrap(),
        };
        let bytes = encode_sign_request(request).unwrap();
        assert_eq!(decode_sign_request(&bytes, 256), Ok(request));
        assert_eq!(
            decode_sign_response(
                &encode_sign_response(Ok(SignResponse {
                    written: 64,
                    signature_generation: 11
                })),
                72
            ),
            Ok(Ok(SignResponse {
                written: 64,
                signature_generation: 11
            }))
        );
        let overlapping = SignRequest {
            output: BorrowedWriteView::within(64, 72, 256).unwrap(),
            ..request
        };
        assert_eq!(
            encode_sign_request(overlapping),
            Err(ProtocolError::InvalidRequest)
        );
        let mut corrupt = bytes;
        corrupt[10] = 1;
        assert_eq!(
            decode_sign_request(&corrupt, 256),
            Err(ProtocolError::InvalidHeader)
        );
    }
}
