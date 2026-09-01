use crate::{
    CertificateLifecycleProvider, CertificateManager, TlsIdentityId, encode_managed_identity_status,
};
use mrml_interface_certificate_lifecycle_v1 as abi;

pub trait CertificateLifecycleSupplementalProvider {
    fn status_other(
        &mut self,
        scope: u32,
        object_identity: &[u8],
        output: &mut [u8],
    ) -> Result<abi::StatusResponse, abi::StatusError>;
    fn account_operation(
        &mut self,
        operation: u32,
        policy_generation: u64,
        request: &[u8],
        output: &mut [u8],
    ) -> Result<abi::AccountOperationResponse, abi::AccountOperationError>;
    fn identity_operation(
        &mut self,
        operation: u32,
        identity: &[u8],
        policy_generation: u64,
        request: &[u8],
        output: &mut [u8],
    ) -> Result<abi::IdentityOperationResponse, abi::IdentityOperationError>;
    fn backup_operation(
        &mut self,
        operation: u32,
        policy_generation: u64,
        request: &[u8],
        output: &mut [u8],
    ) -> Result<abi::BackupOperationResponse, abi::BackupOperationError>;
}

pub struct CatalogLifecycleProvider<'a, P> {
    catalog: &'a CertificateManager,
    supplemental: &'a mut P,
}

impl<'a, P> CatalogLifecycleProvider<'a, P> {
    pub fn new(catalog: &'a CertificateManager, supplemental: &'a mut P) -> Self {
        Self {
            catalog,
            supplemental,
        }
    }
}

impl<P: CertificateLifecycleSupplementalProvider> CertificateLifecycleProvider
    for CatalogLifecycleProvider<'_, P>
{
    fn status(
        &mut self,
        scope: u32,
        object_identity: &[u8],
        output: &mut [u8],
    ) -> Result<abi::StatusResponse, abi::StatusError> {
        if scope != abi::SCOPE_IDENTITY {
            return self
                .supplemental
                .status_other(scope, object_identity, output);
        }
        let identity: [u8; 16] = object_identity
            .try_into()
            .map_err(|_| abi::StatusError::InvalidRequest)?;
        let status = self
            .catalog
            .status(TlsIdentityId(identity))
            .map_err(|_| abi::StatusError::NotFound)?;
        let written = encode_managed_identity_status(status, output)
            .map_err(|_| abi::StatusError::OutputTooSmall)?;
        let state_generation = status
            .active
            .map(|descriptor| descriptor.generation)
            .unwrap_or(status.policy_generation);
        Ok(abi::StatusResponse {
            written: written as u64,
            state_generation,
        })
    }

    fn account_operation(
        &mut self,
        operation: u32,
        policy_generation: u64,
        request: &[u8],
        output: &mut [u8],
    ) -> Result<abi::AccountOperationResponse, abi::AccountOperationError> {
        self.supplemental
            .account_operation(operation, policy_generation, request, output)
    }

    fn identity_operation(
        &mut self,
        operation: u32,
        identity: &[u8],
        policy_generation: u64,
        request: &[u8],
        output: &mut [u8],
    ) -> Result<abi::IdentityOperationResponse, abi::IdentityOperationError> {
        self.supplemental.identity_operation(
            operation,
            identity,
            policy_generation,
            request,
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
        self.supplemental
            .backup_operation(operation, policy_generation, request, output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MAX_MANAGED_STATUS_BYTES, decode_managed_identity_status};

    struct Supplemental;
    impl CertificateLifecycleSupplementalProvider for Supplemental {
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
            _: &[u8],
            _: &mut [u8],
        ) -> Result<abi::AccountOperationResponse, abi::AccountOperationError> {
            Err(abi::AccountOperationError::OperationFailed)
        }
        fn identity_operation(
            &mut self,
            _: u32,
            _: &[u8],
            _: u64,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<abi::IdentityOperationResponse, abi::IdentityOperationError> {
            Err(abi::IdentityOperationError::OperationFailed)
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
    fn exact_identity_status_uses_canonical_catalog_payload() {
        let identity = TlsIdentityId([9; 16]);
        let mut catalog = CertificateManager::new();
        catalog.enroll(identity, 7).unwrap();
        let mut supplemental = Supplemental;
        let mut provider = CatalogLifecycleProvider::new(&catalog, &mut supplemental);
        let mut output = [0u8; MAX_MANAGED_STATUS_BYTES];
        let response = provider
            .status(abi::SCOPE_IDENTITY, &identity.0, &mut output)
            .unwrap();
        assert_eq!(response.state_generation, 7);
        let status = decode_managed_identity_status(&output[..response.written as usize]).unwrap();
        assert!(status.identity == identity);
        assert_eq!(status.policy_generation, 7);
        assert!(status.active.is_none());
    }

    #[test]
    fn malformed_or_unknown_identity_never_reaches_other_scope_provider() {
        let catalog = CertificateManager::new();
        let mut supplemental = Supplemental;
        let mut provider = CatalogLifecycleProvider::new(&catalog, &mut supplemental);
        let mut output = [0u8; 64];
        assert!(matches!(
            provider.status(abi::SCOPE_IDENTITY, &[1; 15], &mut output),
            Err(abi::StatusError::InvalidRequest)
        ));
        assert!(matches!(
            provider.status(abi::SCOPE_IDENTITY, &[1; 16], &mut output),
            Err(abi::StatusError::NotFound)
        ));
    }
}
