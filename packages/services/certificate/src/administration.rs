use crate::CertificateLifecycleSupplementalProvider;
use mrml_crypto::Sha256;
use mrml_interface_certificate_lifecycle_v1 as abi;

pub const ADMINISTRATION_HEADER_BYTES: usize = 128;
pub const MAX_ADMINISTRATION_PAYLOAD_BYTES: usize = 3968;
const MAGIC: &[u8; 8] = b"MRMLADM1";
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AdministrationClass {
    Account = 1,
    Identity = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdministrationRequest<'a> {
    pub class: AdministrationClass,
    pub operation: u32,
    pub request_generation: u64,
    pub policy_generation: u64,
    pub identity: [u8; 16],
    pub owner_authorization_digest: [u8; 32],
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdministrationCodecError {
    InvalidClass,
    InvalidOperation,
    InvalidGeneration,
    InvalidIdentity,
    MissingOwnerAuthorization,
    PayloadLimit,
    OutputTooSmall,
    InvalidEncoding,
    DigestMismatch,
}

pub fn encode_administration_request(
    request: AdministrationRequest<'_>,
    output: &mut [u8],
) -> Result<usize, AdministrationCodecError> {
    validate_request(request)?;
    let written = ADMINISTRATION_HEADER_BYTES
        .checked_add(request.payload.len())
        .ok_or(AdministrationCodecError::PayloadLimit)?;
    if output.len() < written {
        return Err(AdministrationCodecError::OutputTooSmall);
    }
    output[..written].fill(0);
    output[..8].copy_from_slice(MAGIC);
    output[8..10].copy_from_slice(&VERSION.to_be_bytes());
    output[10] = request.class as u8;
    output[12..16].copy_from_slice(&request.operation.to_be_bytes());
    output[16..24].copy_from_slice(&request.request_generation.to_be_bytes());
    output[24..32].copy_from_slice(&request.policy_generation.to_be_bytes());
    output[32..48].copy_from_slice(&request.identity);
    output[48..80].copy_from_slice(&request.owner_authorization_digest);
    output[80..112].copy_from_slice(&Sha256::digest(request.payload));
    output[112..116].copy_from_slice(&(request.payload.len() as u32).to_be_bytes());
    output[ADMINISTRATION_HEADER_BYTES..written].copy_from_slice(request.payload);
    Ok(written)
}

pub fn decode_administration_request(
    input: &[u8],
) -> Result<AdministrationRequest<'_>, AdministrationCodecError> {
    if input.len() < ADMINISTRATION_HEADER_BYTES
        || &input[..8] != MAGIC
        || u16::from_be_bytes([input[8], input[9]]) != VERSION
        || input[11] != 0
        || input[116..ADMINISTRATION_HEADER_BYTES] != [0; 12]
    {
        return Err(AdministrationCodecError::InvalidEncoding);
    }
    let class = match input[10] {
        1 => AdministrationClass::Account,
        2 => AdministrationClass::Identity,
        _ => return Err(AdministrationCodecError::InvalidClass),
    };
    let payload_length = u32::from_be_bytes(
        input[112..116]
            .try_into()
            .map_err(|_| AdministrationCodecError::InvalidEncoding)?,
    ) as usize;
    if payload_length == 0
        || payload_length > MAX_ADMINISTRATION_PAYLOAD_BYTES
        || ADMINISTRATION_HEADER_BYTES.checked_add(payload_length) != Some(input.len())
    {
        return Err(AdministrationCodecError::PayloadLimit);
    }
    let payload = &input[ADMINISTRATION_HEADER_BYTES..];
    let expected_digest: [u8; 32] = input[80..112]
        .try_into()
        .map_err(|_| AdministrationCodecError::InvalidEncoding)?;
    if Sha256::digest(payload) != expected_digest {
        return Err(AdministrationCodecError::DigestMismatch);
    }
    let request = AdministrationRequest {
        class,
        operation: u32::from_be_bytes(
            input[12..16]
                .try_into()
                .map_err(|_| AdministrationCodecError::InvalidEncoding)?,
        ),
        request_generation: u64::from_be_bytes(
            input[16..24]
                .try_into()
                .map_err(|_| AdministrationCodecError::InvalidEncoding)?,
        ),
        policy_generation: u64::from_be_bytes(
            input[24..32]
                .try_into()
                .map_err(|_| AdministrationCodecError::InvalidEncoding)?,
        ),
        identity: input[32..48]
            .try_into()
            .map_err(|_| AdministrationCodecError::InvalidEncoding)?,
        owner_authorization_digest: input[48..80]
            .try_into()
            .map_err(|_| AdministrationCodecError::InvalidEncoding)?,
        payload,
    };
    validate_request(request)?;
    Ok(request)
}

fn validate_request(request: AdministrationRequest<'_>) -> Result<(), AdministrationCodecError> {
    if request.request_generation == 0 || request.policy_generation == 0 {
        return Err(AdministrationCodecError::InvalidGeneration);
    }
    if request.owner_authorization_digest == [0; 32] {
        return Err(AdministrationCodecError::MissingOwnerAuthorization);
    }
    if request.payload.is_empty() || request.payload.len() > MAX_ADMINISTRATION_PAYLOAD_BYTES {
        return Err(AdministrationCodecError::PayloadLimit);
    }
    let operation_valid = match request.class {
        AdministrationClass::Account => matches!(
            request.operation,
            abi::ACCOUNT_CREATE
                | abi::ACCOUNT_RECOVER
                | abi::ACCOUNT_UPDATE
                | abi::ACCOUNT_ROLLOVER
                | abi::ACCOUNT_DEACTIVATE
                | abi::ACCOUNT_ACCEPT_TERMS
        ),
        AdministrationClass::Identity => matches!(
            request.operation,
            abi::IDENTITY_OBTAIN
                | abi::IDENTITY_RENEW
                | abi::IDENTITY_REPLACE
                | abi::IDENTITY_REVOKE
        ),
    };
    if !operation_valid {
        return Err(AdministrationCodecError::InvalidOperation);
    }
    match request.class {
        AdministrationClass::Account if request.identity != [0; 16] => {
            Err(AdministrationCodecError::InvalidIdentity)
        }
        AdministrationClass::Identity if request.identity == [0; 16] => {
            Err(AdministrationCodecError::InvalidIdentity)
        }
        _ => Ok(()),
    }
}

pub struct CanonicalAdministrationProvider<P> {
    inner: P,
}

impl<P> CanonicalAdministrationProvider<P> {
    pub const fn new(inner: P) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> P {
        self.inner
    }
}

impl<P: CertificateLifecycleSupplementalProvider> CertificateLifecycleSupplementalProvider
    for CanonicalAdministrationProvider<P>
{
    fn status_other(
        &mut self,
        scope: u32,
        object_identity: &[u8],
        output: &mut [u8],
    ) -> Result<abi::StatusResponse, abi::StatusError> {
        self.inner.status_other(scope, object_identity, output)
    }

    fn account_operation(
        &mut self,
        operation: u32,
        policy_generation: u64,
        request: &[u8],
        output: &mut [u8],
    ) -> Result<abi::AccountOperationResponse, abi::AccountOperationError> {
        let decoded = decode_administration_request(request)
            .map_err(|_| abi::AccountOperationError::InvalidRequest)?;
        if decoded.class != AdministrationClass::Account
            || decoded.operation != operation
            || decoded.policy_generation != policy_generation
        {
            return Err(abi::AccountOperationError::InvalidRequest);
        }
        self.inner
            .account_operation(operation, policy_generation, decoded.payload, output)
    }

    fn identity_operation(
        &mut self,
        operation: u32,
        identity: &[u8],
        policy_generation: u64,
        request: &[u8],
        output: &mut [u8],
    ) -> Result<abi::IdentityOperationResponse, abi::IdentityOperationError> {
        let decoded = decode_administration_request(request)
            .map_err(|_| abi::IdentityOperationError::InvalidRequest)?;
        if decoded.class != AdministrationClass::Identity
            || decoded.operation != operation
            || decoded.policy_generation != policy_generation
            || decoded.identity.as_slice() != identity
        {
            return Err(abi::IdentityOperationError::InvalidRequest);
        }
        self.inner.identity_operation(
            operation,
            identity,
            policy_generation,
            decoded.payload,
            output,
        )
    }

    fn backup_operation(
        &mut self,
        operation: u32,
        policy_generation: u64,
        request: &[u8],
        output: &mut [u8],
    ) -> Result<abi::BackupOperationResponse, abi::BackupOperationError> {
        self.inner
            .backup_operation(operation, policy_generation, request, output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request<'a>(
        class: AdministrationClass,
        operation: u32,
        payload: &'a [u8],
    ) -> AdministrationRequest<'a> {
        AdministrationRequest {
            class,
            operation,
            request_generation: 11,
            policy_generation: 7,
            identity: if class == AdministrationClass::Identity {
                [9; 16]
            } else {
                [0; 16]
            },
            owner_authorization_digest: [0xa5; 32],
            payload,
        }
    }

    #[test]
    fn canonical_request_round_trips_and_rejects_mutation_or_trailing_data() {
        let expected = request(
            AdministrationClass::Identity,
            abi::IDENTITY_RENEW,
            b"renew-exact",
        );
        let mut encoded = [0u8; 256];
        let written = encode_administration_request(expected, &mut encoded).unwrap();
        assert_eq!(
            decode_administration_request(&encoded[..written]).unwrap(),
            expected
        );
        for index in [0usize, 8, 10, 11, 80, 112, 116, 127, written - 1] {
            let mut changed = encoded;
            changed[index] ^= 1;
            assert!(decode_administration_request(&changed[..written]).is_err());
        }
        encoded[written] = 0;
        assert!(decode_administration_request(&encoded[..=written]).is_err());
    }

    #[test]
    fn class_operation_identity_and_authorization_are_fail_closed() {
        let mut encoded = [0u8; 256];
        let mut value = request(AdministrationClass::Account, abi::ACCOUNT_UPDATE, b"update");
        value.identity = [1; 16];
        assert_eq!(
            encode_administration_request(value, &mut encoded),
            Err(AdministrationCodecError::InvalidIdentity)
        );
        value.identity = [0; 16];
        value.operation = u32::MAX;
        assert_eq!(
            encode_administration_request(value, &mut encoded),
            Err(AdministrationCodecError::InvalidOperation)
        );
        value.operation = abi::ACCOUNT_UPDATE;
        value.owner_authorization_digest = [0; 32];
        assert_eq!(
            encode_administration_request(value, &mut encoded),
            Err(AdministrationCodecError::MissingOwnerAuthorization)
        );
    }

    struct Inner {
        account_calls: u8,
        identity_calls: u8,
    }

    impl CertificateLifecycleSupplementalProvider for Inner {
        fn status_other(
            &mut self,
            _: u32,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<abi::StatusResponse, abi::StatusError> {
            Err(abi::StatusError::NotFound)
        }
        fn account_operation(
            &mut self,
            _: u32,
            _: u64,
            request: &[u8],
            output: &mut [u8],
        ) -> Result<abi::AccountOperationResponse, abi::AccountOperationError> {
            assert_eq!(request, b"account-payload");
            self.account_calls += 1;
            output[0] = 1;
            Ok(abi::AccountOperationResponse {
                written: 1,
                account_generation: 12,
            })
        }
        fn identity_operation(
            &mut self,
            _: u32,
            identity: &[u8],
            _: u64,
            request: &[u8],
            output: &mut [u8],
        ) -> Result<abi::IdentityOperationResponse, abi::IdentityOperationError> {
            assert_eq!(identity, [9; 16]);
            assert_eq!(request, b"identity-payload");
            self.identity_calls += 1;
            output[0] = 2;
            Ok(abi::IdentityOperationResponse {
                written: 1,
                identity_generation: 12,
            })
        }
        fn backup_operation(
            &mut self,
            _: u32,
            _: u64,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<abi::BackupOperationResponse, abi::BackupOperationError> {
            Err(abi::BackupOperationError::OperationFailed)
        }
    }

    #[test]
    fn provider_unwraps_only_exact_outer_operation_policy_and_identity() {
        let mut account = [0u8; 256];
        let account_len = encode_administration_request(
            request(
                AdministrationClass::Account,
                abi::ACCOUNT_UPDATE,
                b"account-payload",
            ),
            &mut account,
        )
        .unwrap();
        let mut identity = [0u8; 256];
        let identity_len = encode_administration_request(
            request(
                AdministrationClass::Identity,
                abi::IDENTITY_RENEW,
                b"identity-payload",
            ),
            &mut identity,
        )
        .unwrap();
        let mut provider = CanonicalAdministrationProvider::new(Inner {
            account_calls: 0,
            identity_calls: 0,
        });
        let mut output = [0u8; 8];
        assert!(
            provider
                .account_operation(abi::ACCOUNT_UPDATE, 7, &account[..account_len], &mut output)
                .is_ok()
        );
        assert_eq!(
            provider.account_operation(
                abi::ACCOUNT_CREATE,
                7,
                &account[..account_len],
                &mut output
            ),
            Err(abi::AccountOperationError::InvalidRequest)
        );
        assert!(
            provider
                .identity_operation(
                    abi::IDENTITY_RENEW,
                    &[9; 16],
                    7,
                    &identity[..identity_len],
                    &mut output
                )
                .is_ok()
        );
        assert_eq!(
            provider.identity_operation(
                abi::IDENTITY_RENEW,
                &[8; 16],
                7,
                &identity[..identity_len],
                &mut output
            ),
            Err(abi::IdentityOperationError::InvalidRequest)
        );
        let inner = provider.into_inner();
        assert_eq!((inner.account_calls, inner.identity_calls), (1, 1));
    }
}
