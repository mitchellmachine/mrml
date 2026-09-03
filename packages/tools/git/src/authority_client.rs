//! Protected receive authority adapter over a narrow authenticated RPC.

use crate::{
    encode_authority_candidate, encode_authority_commit, encode_authority_proof_install,
    encode_authority_receipt, encode_authority_receive, encode_authority_ref_transaction,
    parse_authority_candidate_record, AuditReceiptAuthority, AuthorityCandidateContext,
    AuthorityCandidateRecord, CandidateRefTransaction, DetachedCommitProofRecord, GitdCoreError,
    HistoryVerificationError, ObjectId, ProtectedCommitVerifier, ProtectedHistoryContext,
    ProtectedReceiveAuthority, ProtectedReceiveAuthorization, VerifiedCommitProof,
    VerifiedLegacyCommitProof,
};

pub const AUTHORITY_OP_AUTHORIZE_RECEIVE: u8 = 2;
pub const AUTHORITY_OP_AUTHORIZE_REF_TRANSACTION: u8 = 3;
pub const AUTHORITY_OP_VERIFY_COMMIT: u8 = 4;
pub const AUTHORITY_OP_SIGN_RECEIPT: u8 = 6;
pub const AUTHORITY_OP_VERIFY_RECEIPT: u8 = 7;
pub const AUTHORITY_OP_INSTALL_PROOF: u8 = 8;
pub const AUTHORITY_OP_BEGIN_CANDIDATE: u8 = 9;
pub const AUTHORITY_OP_SEAL_CANDIDATE_PROOF_SET: u8 = 10;
pub const AUTHORITY_OP_AUTHORIZE_CANDIDATE: u8 = 11;
pub const AUTHORITY_OP_START_CANDIDATE_ACTIVATION: u8 = 12;
pub const AUTHORITY_OP_COMMIT_CANDIDATE: u8 = 13;
pub const AUTHORITY_OP_ABORT_CANDIDATE: u8 = 14;
pub const AUTHORITY_OP_QUERY_CANDIDATE: u8 = 15;
pub const AUTHORITY_OP_PERSIST_CANDIDATE_RECEIPT: u8 = 16;
pub const AUTHORITY_OP_COMPLETE_CANDIDATE: u8 = 17;
const MAX_AUTHORITY_RESULT_BYTES: usize = 1024;

/// Transport-only capability. Implementations must authenticate the peer,
/// request, response, operation, and request identifier before returning.
pub trait ProtectedAuthorityRpc {
    fn call(&mut self, operation: u8, request: &[u8], response: &mut [u8]) -> Result<usize, ()>;

    fn signer_identity(&self) -> [u8; 64];
}

pub struct RemoteProtectedReceiveAuthority<T> {
    transport: T,
    pending_proofs: mrml_runtime::Vector<DetachedCommitProofRecord>,
}

impl<T: ProtectedAuthorityRpc> RemoteProtectedReceiveAuthority<T> {
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            pending_proofs: mrml_runtime::Vector::new(),
        }
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

    pub fn install_commit_proof(
        &mut self,
        context: ProtectedHistoryContext<'_>,
        commit: ObjectId,
        exact_contents: &[u8],
        proof: &DetachedCommitProofRecord,
    ) -> Result<(), GitdCoreError> {
        let encoded = encode_authority_proof_install(context, commit, exact_contents, proof)?;
        self.empty_response(AUTHORITY_OP_INSTALL_PROOF, &encoded)
    }

    pub fn begin_candidate(
        &mut self,
        context: &AuthorityCandidateContext,
    ) -> Result<(), GitdCoreError> {
        self.candidate_transition(AUTHORITY_OP_BEGIN_CANDIDATE, context)
    }

    pub fn seal_candidate_proof_set(
        &mut self,
        context: &AuthorityCandidateContext,
    ) -> Result<(), GitdCoreError> {
        self.candidate_transition(AUTHORITY_OP_SEAL_CANDIDATE_PROOF_SET, context)
    }

    pub fn authorize_candidate(
        &mut self,
        context: &AuthorityCandidateContext,
    ) -> Result<(), GitdCoreError> {
        self.candidate_transition(AUTHORITY_OP_AUTHORIZE_CANDIDATE, context)
    }

    pub fn start_candidate_activation(
        &mut self,
        context: &AuthorityCandidateContext,
    ) -> Result<(), GitdCoreError> {
        self.candidate_transition(AUTHORITY_OP_START_CANDIDATE_ACTIVATION, context)
    }

    pub fn commit_candidate(
        &mut self,
        context: &AuthorityCandidateContext,
    ) -> Result<(), GitdCoreError> {
        self.candidate_transition(AUTHORITY_OP_COMMIT_CANDIDATE, context)
    }

    pub fn abort_candidate(
        &mut self,
        context: &AuthorityCandidateContext,
    ) -> Result<(), GitdCoreError> {
        self.candidate_transition(AUTHORITY_OP_ABORT_CANDIDATE, context)
    }

    pub fn persist_candidate_receipt(
        &mut self,
        context: &AuthorityCandidateContext,
    ) -> Result<(), GitdCoreError> {
        self.candidate_transition(AUTHORITY_OP_PERSIST_CANDIDATE_RECEIPT, context)
    }

    pub fn complete_candidate(
        &mut self,
        context: &AuthorityCandidateContext,
    ) -> Result<(), GitdCoreError> {
        self.candidate_transition(AUTHORITY_OP_COMPLETE_CANDIDATE, context)
    }

    pub fn query_candidate(
        &mut self,
        context: &AuthorityCandidateContext,
    ) -> Result<AuthorityCandidateRecord, GitdCoreError> {
        let encoded = encode_authority_candidate(context)?;
        let mut response = [0u8; MAX_AUTHORITY_RESULT_BYTES];
        let length = self
            .transport
            .call(AUTHORITY_OP_QUERY_CANDIDATE, &encoded, &mut response)
            .map_err(|_| GitdCoreError::Authorization)?;
        let record = parse_authority_candidate_record(&response[..length])?;
        (record.context == *context)
            .then_some(record)
            .ok_or(GitdCoreError::Authorization)
    }

    fn candidate_transition(
        &mut self,
        operation: u8,
        context: &AuthorityCandidateContext,
    ) -> Result<(), GitdCoreError> {
        let encoded = encode_authority_candidate(context)?;
        self.empty_response(operation, &encoded)
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
    fn begin_receive_proofs(
        &mut self,
        proofs: &[DetachedCommitProofRecord],
    ) -> Result<(), GitdCoreError> {
        // This method is the explicit boundary of a new serialized receive.
        // Discard proof state left by an earlier receive that failed before its
        // completion hook; proofs are commit-bound and must never leak across
        // receive transactions or leave the worker permanently unavailable.
        self.pending_proofs.clear();
        if proofs.is_empty()
            || proofs.len() > crate::MAX_DETACHED_COMMIT_PROOFS
            || !proofs
                .windows(2)
                .all(|pair| pair[0].commit() < pair[1].commit())
        {
            return Err(GitdCoreError::Authorization);
        }
        self.pending_proofs
            .try_extend_from_slice(proofs)
            .map_err(|_| GitdCoreError::Resource)
    }

    fn verify_commit(
        &mut self,
        context: ProtectedHistoryContext<'_>,
        commit: ObjectId,
        exact_contents: &[u8],
    ) -> Result<VerifiedCommitProof, HistoryVerificationError> {
        let index = self
            .pending_proofs
            .binary_search_by_key(&commit, DetachedCommitProofRecord::commit)
            .map_err(|_| HistoryVerificationError::Signature)?;
        let proof = self.pending_proofs.remove(index);
        self.install_commit_proof(context, commit, exact_contents, &proof)
            .map_err(|_| HistoryVerificationError::Signature)?;
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

    fn finish_receive_proofs(&mut self) -> Result<(), GitdCoreError> {
        if self.pending_proofs.is_empty() {
            Ok(())
        } else {
            self.pending_proofs.clear();
            Err(GitdCoreError::Authorization)
        }
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
        encode_authority_candidate_record, parse_authority_candidate, parse_authority_commit,
        parse_authority_proof_install, parse_authority_receive, AuthorityCandidateStatus,
        ObjectFormat, QuarantineTransactionId, RepositoryGeneration, RepositoryIdentity,
        RevocationGeneration, SignaturePurpose, TrustGeneration,
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
                AUTHORITY_OP_INSTALL_PROOF => {
                    parse_authority_proof_install(request).map_err(|_| ())?;
                    Ok(0)
                }
                AUTHORITY_OP_BEGIN_CANDIDATE
                | AUTHORITY_OP_SEAL_CANDIDATE_PROOF_SET
                | AUTHORITY_OP_AUTHORIZE_CANDIDATE
                | AUTHORITY_OP_START_CANDIDATE_ACTIVATION
                | AUTHORITY_OP_COMMIT_CANDIDATE
                | AUTHORITY_OP_ABORT_CANDIDATE
                | AUTHORITY_OP_PERSIST_CANDIDATE_RECEIPT
                | AUTHORITY_OP_COMPLETE_CANDIDATE => {
                    parse_authority_candidate(request).map_err(|_| ())?;
                    Ok(0)
                }
                AUTHORITY_OP_QUERY_CANDIDATE => {
                    let context = parse_authority_candidate(request).map_err(|_| ())?;
                    let encoded = encode_authority_candidate_record(&AuthorityCandidateRecord {
                        context,
                        status: AuthorityCandidateStatus::Receiving,
                    })
                    .map_err(|_| ())?;
                    response[..encoded.len()].copy_from_slice(&encoded);
                    Ok(encoded.len())
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
        let proof = DetachedCommitProofRecord::new(
            commit,
            &[3; 64],
            &[4; mrml_crypto::ML_DSA_65_SIGNATURE_BYTES],
        )
        .unwrap();
        allowed
            .begin_receive_proofs(core::slice::from_ref(&proof))
            .unwrap();
        assert!(allowed
            .verify_commit(context, commit, b"commit bytes")
            .is_ok());
        assert_eq!(allowed.finish_receive_proofs(), Ok(()));
        let mut signature = [0u8; 64];
        assert_eq!(allowed.sign(b"receipt", &mut signature), Ok(32));
        assert_eq!(&signature[..32], &[0x55; 32]);
        assert_eq!(allowed.verify(b"receipt", &signature[..32]), Ok(()));
        let candidate = AuthorityCandidateContext {
            id: QuarantineTransactionId([9; 16]),
            repository: repository.clone(),
            current_generation: RepositoryGeneration(3),
            next_generation: RepositoryGeneration(4),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(8),
            policy_digest: [1; 64],
            ref_update_digest: [2; 64],
            introduced_commit_set_digest: [3; 64],
            arrival_pack_digest: [4; 64],
            proof_set_digest: [5; 64],
            activation_digest: [6; 64],
        };
        allowed.begin_candidate(&candidate).unwrap();
        assert_eq!(
            allowed.query_candidate(&candidate).unwrap().status,
            AuthorityCandidateStatus::Receiving
        );

        let mut denied = RemoteProtectedReceiveAuthority::new(ExactRpc {
            allow: false,
            calls: Vector::new(),
        });
        denied
            .begin_receive_proofs(core::slice::from_ref(&proof))
            .unwrap();
        assert_eq!(
            denied.verify_commit(context, commit, b"commit bytes"),
            Err(HistoryVerificationError::Signature)
        );
    }

    #[test]
    fn receive_proof_batch_rejects_missing_and_unused_records() {
        let repository = RepositoryIdentity::parse("owner/protected").unwrap();
        let context = ProtectedHistoryContext {
            repository: &repository,
            repository_generation: RepositoryGeneration(3),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(8),
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha256,
        };
        let first = ObjectId::from_bytes(ObjectFormat::Sha256, &[7; 32]).unwrap();
        let second = ObjectId::from_bytes(ObjectFormat::Sha256, &[8; 32]).unwrap();
        let first_proof = DetachedCommitProofRecord::new(
            first,
            &[3; 64],
            &[4; mrml_crypto::ML_DSA_65_SIGNATURE_BYTES],
        )
        .unwrap();
        let second_proof = DetachedCommitProofRecord::new(
            second,
            &[5; 64],
            &[6; mrml_crypto::ML_DSA_65_SIGNATURE_BYTES],
        )
        .unwrap();
        let mut authority = RemoteProtectedReceiveAuthority::new(ExactRpc {
            allow: true,
            calls: Vector::new(),
        });
        authority
            .begin_receive_proofs(&[first_proof, second_proof.clone()])
            .unwrap();
        assert_eq!(
            authority.verify_commit(context, first, b"first commit bytes"),
            Ok(VerifiedCommitProof {
                commit: first,
                repository: repository.clone(),
                repository_generation: RepositoryGeneration(3),
                trust_generation: TrustGeneration(4),
                revocation_generation: RevocationGeneration(8),
                purpose: SignaturePurpose::GitCommit,
                object_format: ObjectFormat::Sha256,
            })
        );
        assert_eq!(
            authority.finish_receive_proofs(),
            Err(GitdCoreError::Authorization)
        );
        assert_eq!(
            authority.verify_commit(context, second, b"second commit bytes"),
            Err(HistoryVerificationError::Signature)
        );
        authority
            .begin_receive_proofs(core::slice::from_ref(&second_proof))
            .unwrap();
        assert_eq!(
            authority.verify_commit(context, second, b"second commit bytes"),
            Ok(VerifiedCommitProof {
                commit: second,
                repository,
                repository_generation: RepositoryGeneration(3),
                trust_generation: TrustGeneration(4),
                revocation_generation: RevocationGeneration(8),
                purpose: SignaturePurpose::GitCommit,
                object_format: ObjectFormat::Sha256,
            })
        );
        assert_eq!(authority.finish_receive_proofs(), Ok(()));
    }
}
