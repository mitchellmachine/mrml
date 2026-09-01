pub const CERTD_ACCOUNT_KEY_REQUEST_BYTES: usize = 32;
pub const CERTD_TLS_KEY_REQUEST_BYTES: usize = 64;
pub const CERTD_P256_PUBLIC_KEY_BYTES: usize = 65;
pub const CERTD_TLS_KEY_RESPONSE_BYTES: usize = 97;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertdAccountKeyRequest {
    pub account_identity: [u8; 16],
    pub directory_generation: u64,
    pub account_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertdTlsKeyRequest {
    pub identity: [u8; 16],
    pub key_generation: u64,
    pub policy_generation: u64,
    pub identifier_set_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertdKeyProtocolError {
    InvalidLength,
    InvalidIdentity,
    InvalidGeneration,
    InvalidDigest,
    InvalidPublicKey,
}

pub fn encode_certd_account_key_request(
    request: CertdAccountKeyRequest,
) -> Result<[u8; CERTD_ACCOUNT_KEY_REQUEST_BYTES], CertdKeyProtocolError> {
    validate_account(request)?;
    let mut output = [0u8; CERTD_ACCOUNT_KEY_REQUEST_BYTES];
    output[..16].copy_from_slice(&request.account_identity);
    output[16..24].copy_from_slice(&request.directory_generation.to_be_bytes());
    output[24..32].copy_from_slice(&request.account_generation.to_be_bytes());
    Ok(output)
}

pub fn decode_certd_account_key_request(
    input: &[u8],
) -> Result<CertdAccountKeyRequest, CertdKeyProtocolError> {
    if input.len() != CERTD_ACCOUNT_KEY_REQUEST_BYTES {
        return Err(CertdKeyProtocolError::InvalidLength);
    }
    let request = CertdAccountKeyRequest {
        account_identity: input[..16]
            .try_into()
            .map_err(|_| CertdKeyProtocolError::InvalidLength)?,
        directory_generation: read_u64(&input[16..24])?,
        account_generation: read_u64(&input[24..32])?,
    };
    validate_account(request)?;
    Ok(request)
}

pub fn encode_certd_tls_key_request(
    request: CertdTlsKeyRequest,
) -> Result<[u8; CERTD_TLS_KEY_REQUEST_BYTES], CertdKeyProtocolError> {
    validate_tls(request)?;
    let mut output = [0u8; CERTD_TLS_KEY_REQUEST_BYTES];
    output[..16].copy_from_slice(&request.identity);
    output[16..24].copy_from_slice(&request.key_generation.to_be_bytes());
    output[24..32].copy_from_slice(&request.policy_generation.to_be_bytes());
    output[32..64].copy_from_slice(&request.identifier_set_digest);
    Ok(output)
}

pub fn decode_certd_tls_key_request(
    input: &[u8],
) -> Result<CertdTlsKeyRequest, CertdKeyProtocolError> {
    if input.len() != CERTD_TLS_KEY_REQUEST_BYTES {
        return Err(CertdKeyProtocolError::InvalidLength);
    }
    let request = CertdTlsKeyRequest {
        identity: input[..16]
            .try_into()
            .map_err(|_| CertdKeyProtocolError::InvalidLength)?,
        key_generation: read_u64(&input[16..24])?,
        policy_generation: read_u64(&input[24..32])?,
        identifier_set_digest: input[32..64]
            .try_into()
            .map_err(|_| CertdKeyProtocolError::InvalidLength)?,
    };
    validate_tls(request)?;
    Ok(request)
}

pub fn encode_certd_tls_key_response(
    public_key: [u8; CERTD_P256_PUBLIC_KEY_BYTES],
    key_identity: [u8; 32],
) -> Result<[u8; CERTD_TLS_KEY_RESPONSE_BYTES], CertdKeyProtocolError> {
    if public_key[0] != 4 || key_identity == [0; 32] {
        return Err(CertdKeyProtocolError::InvalidPublicKey);
    }
    let mut output = [0u8; CERTD_TLS_KEY_RESPONSE_BYTES];
    output[..CERTD_P256_PUBLIC_KEY_BYTES].copy_from_slice(&public_key);
    output[CERTD_P256_PUBLIC_KEY_BYTES..].copy_from_slice(&key_identity);
    Ok(output)
}

fn validate_account(request: CertdAccountKeyRequest) -> Result<(), CertdKeyProtocolError> {
    if request.account_identity == [0; 16] {
        return Err(CertdKeyProtocolError::InvalidIdentity);
    }
    if request.directory_generation == 0 || request.account_generation == 0 {
        return Err(CertdKeyProtocolError::InvalidGeneration);
    }
    Ok(())
}

fn validate_tls(request: CertdTlsKeyRequest) -> Result<(), CertdKeyProtocolError> {
    if request.identity == [0; 16] {
        return Err(CertdKeyProtocolError::InvalidIdentity);
    }
    if request.key_generation == 0 || request.policy_generation == 0 {
        return Err(CertdKeyProtocolError::InvalidGeneration);
    }
    if request.identifier_set_digest == [0; 32] {
        return Err(CertdKeyProtocolError::InvalidDigest);
    }
    Ok(())
}

fn read_u64(input: &[u8]) -> Result<u64, CertdKeyProtocolError> {
    Ok(u64::from_be_bytes(
        input
            .try_into()
            .map_err(|_| CertdKeyProtocolError::InvalidLength)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_account_and_tls_requests_round_trip() {
        let account = CertdAccountKeyRequest {
            account_identity: [1; 16],
            directory_generation: 2,
            account_generation: 3,
        };
        let encoded = encode_certd_account_key_request(account).unwrap();
        assert_eq!(decode_certd_account_key_request(&encoded), Ok(account));
        let tls = CertdTlsKeyRequest {
            identity: [4; 16],
            key_generation: 5,
            policy_generation: 6,
            identifier_set_digest: [7; 32],
        };
        let encoded = encode_certd_tls_key_request(tls).unwrap();
        assert_eq!(decode_certd_tls_key_request(&encoded), Ok(tls));
    }

    #[test]
    fn truncation_zero_bindings_and_invalid_public_keys_fail_closed() {
        assert_eq!(
            decode_certd_account_key_request(&[0; 31]),
            Err(CertdKeyProtocolError::InvalidLength)
        );
        assert_eq!(
            decode_certd_tls_key_request(&[0; CERTD_TLS_KEY_REQUEST_BYTES]),
            Err(CertdKeyProtocolError::InvalidIdentity)
        );
        assert_eq!(
            encode_certd_tls_key_response([0; 65], [1; 32]),
            Err(CertdKeyProtocolError::InvalidPublicKey)
        );
    }
}
