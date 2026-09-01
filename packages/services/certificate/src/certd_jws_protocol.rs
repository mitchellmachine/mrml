use crate::{AcmeJwsOperation, ConstrainedAcmeJwsRequest};
use mrml_acme::{AcmeUrl, ReplayNonce};

const MAGIC: &[u8; 8] = b"MRMLJWS1";
pub const CERTD_JWS_REQUEST_HEADER_BYTES: usize = 52;
pub const MAX_CERTD_JWS_PAYLOAD_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertdJwsProtocolError {
    OutputTooSmall,
    InvalidFrame,
    InvalidOperation,
    InvalidGeneration,
    InvalidIdentity,
    InvalidUrl,
    InvalidNonce,
    PayloadTooLarge,
}

pub fn encode_certd_jws_request(
    request: &ConstrainedAcmeJwsRequest<'_>,
    output: &mut [u8],
) -> Result<usize, CertdJwsProtocolError> {
    if request.directory_generation == 0 || request.account_generation == 0 {
        return Err(CertdJwsProtocolError::InvalidGeneration);
    }
    if request.account_identity == [0; 16] {
        return Err(CertdJwsProtocolError::InvalidIdentity);
    }
    if request.payload.len() > MAX_CERTD_JWS_PAYLOAD_BYTES {
        return Err(CertdJwsProtocolError::PayloadTooLarge);
    }
    let protected = request.protected_url.as_str().as_bytes();
    let nonce = request.nonce.as_str().as_bytes();
    let account = request
        .account_url
        .as_ref()
        .map(AcmeUrl::as_str)
        .unwrap_or("")
        .as_bytes();
    let length = CERTD_JWS_REQUEST_HEADER_BYTES
        .checked_add(protected.len())
        .and_then(|value| value.checked_add(nonce.len()))
        .and_then(|value| value.checked_add(account.len()))
        .and_then(|value| value.checked_add(request.payload.len()))
        .ok_or(CertdJwsProtocolError::PayloadTooLarge)?;
    if output.len() < length
        || protected.len() > u16::MAX as usize
        || nonce.len() > u16::MAX as usize
        || account.len() > u16::MAX as usize
    {
        return Err(CertdJwsProtocolError::OutputTooSmall);
    }
    output[..length].fill(0);
    output[..8].copy_from_slice(MAGIC);
    output[8] = request.operation as u8;
    output[9] = u8::from(request.account_url.is_some());
    output[12..20].copy_from_slice(&request.directory_generation.to_be_bytes());
    output[20..28].copy_from_slice(&request.account_generation.to_be_bytes());
    output[28..44].copy_from_slice(&request.account_identity);
    output[44..46].copy_from_slice(&(protected.len() as u16).to_be_bytes());
    output[46..48].copy_from_slice(&(nonce.len() as u16).to_be_bytes());
    output[48..50].copy_from_slice(&(account.len() as u16).to_be_bytes());
    output[50..52].copy_from_slice(&(request.payload.len() as u16).to_be_bytes());
    let mut cursor = CERTD_JWS_REQUEST_HEADER_BYTES;
    for bytes in [protected, nonce, account, request.payload] {
        output[cursor..cursor + bytes.len()].copy_from_slice(bytes);
        cursor += bytes.len();
    }
    Ok(length)
}

pub fn decode_certd_jws_request(
    input: &[u8],
    allow_test_http: bool,
) -> Result<ConstrainedAcmeJwsRequest<'_>, CertdJwsProtocolError> {
    if input.len() < CERTD_JWS_REQUEST_HEADER_BYTES
        || &input[..8] != MAGIC
        || input[10..12] != [0; 2]
    {
        return Err(CertdJwsProtocolError::InvalidFrame);
    }
    let operation =
        AcmeJwsOperation::from_u8(input[8]).ok_or(CertdJwsProtocolError::InvalidOperation)?;
    let has_account = match input[9] {
        0 => false,
        1 => true,
        _ => return Err(CertdJwsProtocolError::InvalidFrame),
    };
    let directory_generation = read_u64(&input[12..20])?;
    let account_generation = read_u64(&input[20..28])?;
    if directory_generation == 0 || account_generation == 0 {
        return Err(CertdJwsProtocolError::InvalidGeneration);
    }
    let account_identity: [u8; 16] = input[28..44]
        .try_into()
        .map_err(|_| CertdJwsProtocolError::InvalidFrame)?;
    if account_identity == [0; 16] {
        return Err(CertdJwsProtocolError::InvalidIdentity);
    }
    let lengths = [
        read_u16(&input[44..46])?,
        read_u16(&input[46..48])?,
        read_u16(&input[48..50])?,
        read_u16(&input[50..52])?,
    ];
    if lengths[3] > MAX_CERTD_JWS_PAYLOAD_BYTES
        || lengths
            .iter()
            .try_fold(CERTD_JWS_REQUEST_HEADER_BYTES, |sum, value| {
                sum.checked_add(*value)
            })
            != Some(input.len())
        || has_account != (lengths[2] != 0)
    {
        return Err(CertdJwsProtocolError::InvalidFrame);
    }
    let mut cursor = CERTD_JWS_REQUEST_HEADER_BYTES;
    let protected = text(input, &mut cursor, lengths[0])?;
    let nonce = text(input, &mut cursor, lengths[1])?;
    let account = text(input, &mut cursor, lengths[2])?;
    let payload = &input[cursor..cursor + lengths[3]];
    Ok(ConstrainedAcmeJwsRequest {
        operation,
        directory_generation,
        account_generation,
        account_identity,
        protected_url: AcmeUrl::parse(protected, allow_test_http)
            .map_err(|_| CertdJwsProtocolError::InvalidUrl)?,
        nonce: ReplayNonce::parse(nonce).map_err(|_| CertdJwsProtocolError::InvalidNonce)?,
        account_url: if has_account {
            Some(
                AcmeUrl::parse(account, allow_test_http)
                    .map_err(|_| CertdJwsProtocolError::InvalidUrl)?,
            )
        } else {
            None
        },
        payload,
    })
}

fn text<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a str, CertdJwsProtocolError> {
    let end = cursor
        .checked_add(length)
        .ok_or(CertdJwsProtocolError::InvalidFrame)?;
    let bytes = input
        .get(*cursor..end)
        .ok_or(CertdJwsProtocolError::InvalidFrame)?;
    *cursor = end;
    core::str::from_utf8(bytes).map_err(|_| CertdJwsProtocolError::InvalidFrame)
}
fn read_u16(input: &[u8]) -> Result<usize, CertdJwsProtocolError> {
    Ok(usize::from(u16::from_be_bytes(
        input
            .try_into()
            .map_err(|_| CertdJwsProtocolError::InvalidFrame)?,
    )))
}
fn read_u64(input: &[u8]) -> Result<u64, CertdJwsProtocolError> {
    Ok(u64::from_be_bytes(
        input
            .try_into()
            .map_err(|_| CertdJwsProtocolError::InvalidFrame)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_request_round_trips_and_mutation_fails() {
        let request = ConstrainedAcmeJwsRequest {
            operation: AcmeJwsOperation::NewOrder,
            directory_generation: 2,
            account_generation: 3,
            account_identity: [4; 16],
            protected_url: AcmeUrl::parse("https://ca.example/new-order", false).unwrap(),
            nonce: ReplayNonce::parse("nonce-1").unwrap(),
            account_url: Some(AcmeUrl::parse("https://ca.example/acct/1", false).unwrap()),
            payload: b"{}",
        };
        let mut encoded = [0u8; 512];
        let length = encode_certd_jws_request(&request, &mut encoded).unwrap();
        let decoded = decode_certd_jws_request(&encoded[..length], false).unwrap();
        assert_eq!(decoded.operation, request.operation);
        assert_eq!(
            decoded.protected_url.as_str(),
            request.protected_url.as_str()
        );
        assert_eq!(decoded.payload, b"{}");
        encoded[10] = 1;
        assert_eq!(
            decode_certd_jws_request(&encoded[..length], false).err(),
            Some(CertdJwsProtocolError::InvalidFrame)
        );
    }
}
