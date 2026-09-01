//! Protected receive authority adapter over a narrow authenticated RPC.

use crate::{
    AuditReceiptAuthority, CandidateRefTransaction, GitdCoreError, HistoryVerificationError,
    ObjectId, ProtectedCommitVerifier, ProtectedHistoryContext, ProtectedReceiveAuthority,
    ProtectedReceiveAuthorization, VerifiedCommitProof, VerifiedLegacyCommitProof,
    encode_authority_commit, encode_authority_receipt, encode_authority_receive,
    encode_authority_ref_transaction,
};

pub const AUTHORITY_OP_AUTHORIZE_RECEIVE: u8 = 2;
pub const AUTHORITY_OP_AUTHORIZE_REF_TRANSACTION: u8 = 3;
pub const AUTHORITY_OP_VERIFY_COMMIT: u8 = 4;
pub const AUTHORITY_OP_SIGN_RECEIPT: u8 = 6;
pub const AUTHORITY_OP_VERIFY_RECEIPT: u8 = 7;
const MAX_AUTHORITY_RESULT_BYTES: usize = 1024;

/// Transport-only capability. Implementations must authenticate the peer,
/// request, response, operation, and request identifier before returning.
pub trait ProtectedAuthorityRpc {
    fn call(&mut self, operation: u8, request: &[u8], response: &mut [u8]) -> Result<usize, ()>;

    fn signer_identity(&self) -> [u8; 64];
}

pub struct RemoteProtectedReceiveAuthority<T> {
    transport: T,
}

impl<T: ProtectedAuthorityRpc> RemoteProtectedReceiveAuthority<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    fn empty_response(&mut self, operation: u8, request: &[u8]) -> Result<(), GitdCoreError> {
        let mut response = [0u8; MAX_AUTHORITY_RESULT_BYTES];
        let length = self
            .transport
            .call(operation, request, &mut response)
            .map_err(|_| GitdCoreError::Authorization)?;
        if length != 0 {
            return Err(GitdCoreError::Authorization);
        }
        Ok(())
    }
}

impl<T: ProtectedAuthorityRpc> ProtectedReceiveAuthority for RemoteProtectedReceiveAuthority<T> {
    fn authorize_receive(
        &mut self,
        request: &ProtectedReceiveAuthorization,
    ) -> Result<(), GitdCoreError> {
        let encoded = encode_authority_receive(request)?;
        self.empty_response(AUTHORITY_OP_AUTHORIZE_RECEIVE, &encoded)
    }

    fn authorize_ref_transaction(
        &mut self,
        transaction: &CandidateRefTransaction,
        policy_digest: [u8; 64],
    ) -> Result<(), GitdCoreError> {
        let encoded = encode_authority_ref_transaction(transaction, policy_digest)?;
        self.empty_response(AUTHORITY_OP_AUTHORIZE_REF_TRANSACTION, &encoded)
    }
}

impl<T: ProtectedAuthorityRpc> ProtectedCommitVerifier for RemoteProtectedReceiveAuthority<T> {
    fn verify_commit(
        &mut self,
        context: ProtectedHistoryContext<'_>,
        commit: ObjectId,
        exact_contents: &[u8],
    ) -> Result<VerifiedCommitProof, HistoryVerificationError> {
        let encoded = encode_authority_commit(context, commit, exact_contents)
            .map_err(|_| HistoryVerificationError::Signature)?;
        self.empty_response(AUTHORITY_OP_VERIFY_COMMIT, &encoded)
            .map_err(|_| HistoryVerificationError::Signature)?;
        Ok(VerifiedCommitProof {
            commit,
            repository: context.repository.clone(),
            repository_generation: context.repository_generation,
            trust_generation: context.trust_generation,
            revocation_generation: context.revocation_generation,
            purpose: context.purpose,
            object_format: context.object_format,
        })
    }

    fn verify_legacy_commit(
        &mut self,
        _: ProtectedHistoryContext<'_>,
        _: ObjectId,
        _: &[u8],
    ) -> Result<VerifiedLegacyCommitProof, HistoryVerificationError> {
        Err(HistoryVerificationError::Signature)
    }
}

impl<T: ProtectedAuthorityRpc> AuditReceiptAuthority for RemoteProtectedReceiveAuthority<T> {
    fn signer_identity(&self) -> [u8; 64] {
        self.transport.signer_identity()
    }

    fn sign(&mut self, transcript: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        let request = encode_authority_receipt(transcript, &[]).map_err(|_| ())?;
        let mut response = [0u8; MAX_AUTHORITY_RESULT_BYTES];
        let length = self
            .transport
            .call(AUTHORITY_OP_SIGN_RECEIPT, &request, &mut response)?;
        if length == 0 || length > output.len() {
            return Err(());
        }
        output[..length].copy_from_slice(&response[..length]);
        Ok(length)
    }

    fn verify(&mut self, transcript: &[u8], signature: &[u8]) -> Result<(), ()> {
        let request = encode_authority_receipt(transcript, signature).map_err(|_| ())?;
        let mut response = [0u8; MAX_AUTHORITY_RESULT_BYTES];
        let length = self
            .transport
            .call(AUTHORITY_OP_VERIFY_RECEIPT, &request, &mut response)?;
        if length != 0 {
            return Err(());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ObjectFormat, RepositoryGeneration, RepositoryIdentity, RevocationGeneration,
        SignaturePurpose, TrustGeneration, parse_authority_commit, parse_authority_receive,
    };
    use mrml_runtime::Vector;

    struct ExactRpc {
        allow: bool,
        calls: Vector<u8>,
    }

    impl ProtectedAuthorityRpc for ExactRpc {
        fn call(
            &mut self,
            operation: u8,
            request: &[u8],
            response: &mut [u8],
        ) -> Result<usize, ()> {
            self.calls.push(operation);
            if !self.allow {
                return Err(());
            }
            match operation {
                AUTHORITY_OP_AUTHORIZE_RECEIVE => {
                    parse_authority_receive(request).map_err(|_| ())?;
                    Ok(0)
                }
                AUTHORITY_OP_VERIFY_COMMIT => {
                    parse_authority_commit(request).map_err(|_| ())?;
                    Ok(0)
                }
                AUTHORITY_OP_SIGN_RECEIPT => {
                    response[..32].fill(0x55);
                    Ok(32)
                }
                AUTHORITY_OP_VERIFY_RECEIPT => Ok(0),
                _ => Ok(0),
            }
        }

        fn signer_identity(&self) -> [u8; 64] {
            [0x44; 64]
        }
    }

    #[test]
    fn authenticated_success_mints_exact_proof_and_denial_never_does() {
        let repository = RepositoryIdentity::parse("owner/protected").unwrap();
        let context = ProtectedHistoryContext {
            repository: &repository,
            repository_generation: RepositoryGeneration(3),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(8),
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha256,
        };
        let commit = ObjectId::from_bytes(ObjectFormat::Sha256, &[7; 32]).unwrap();
        let mut allowed = RemoteProtectedReceiveAuthority::new(ExactRpc {
            allow: true,
            calls: Vector::new(),
        });
        assert!(
            allowed
                .verify_commit(context, commit, b"commit bytes")
                .is_ok()
        );
        let mut signature = [0u8; 64];
        assert_eq!(allowed.sign(b"receipt", &mut signature), Ok(32));
        assert_eq!(&signature[..32], &[0x55; 32]);
        assert_eq!(allowed.verify(b"receipt", &signature[..32]), Ok(()));

        let mut denied = RemoteProtectedReceiveAuthority::new(ExactRpc {
            allow: false,
            calls: Vector::new(),
        });
        assert_eq!(
            denied.verify_commit(context, commit, b"commit bytes"),
            Err(HistoryVerificationError::Signature)
        );
    }
}
