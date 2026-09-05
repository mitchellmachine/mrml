//! Exact shared identities and states for protected receive candidates.

use crate::{
    DetachedCommitProofRecord, GitdCoreError, ObjectFormat, ObjectId, QuarantineTransactionId,
    RepositoryGeneration, RepositoryIdentity, RevocationGeneration, TrustGeneration,
    VerifiedRefTransaction,
};
use mrml_crypto::Sha3_512;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum AuthorityCandidateStatus {
    Receiving = 1,
    ProofsSealed = 2,
    Authorized = 3,
    ActivationStarted = 4,
    Activated = 5,
    ReceiptPersisted = 6,
    Completed = 7,
    Aborted = 8,
}

impl AuthorityCandidateStatus {
    pub const fn from_code(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Receiving,
            2 => Self::ProofsSealed,
            3 => Self::Authorized,
            4 => Self::ActivationStarted,
            5 => Self::Activated,
            6 => Self::ReceiptPersisted,
            7 => Self::Completed,
            8 => Self::Aborted,
            _ => return None,
        })
    }

    pub fn permits(self, next: Self) -> bool {
        next == Self::Aborted
            && matches!(
                self,
                Self::Receiving | Self::ProofsSealed | Self::Authorized | Self::ActivationStarted
            )
            || matches!(
                (self, next),
                (Self::Receiving, Self::ProofsSealed)
                    | (Self::ProofsSealed, Self::Authorized)
                    | (Self::Authorized, Self::ActivationStarted)
                    | (Self::ActivationStarted, Self::Activated)
                    | (Self::Activated, Self::ReceiptPersisted)
                    | (Self::ReceiptPersisted, Self::Completed)
            )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityCandidateContext {
    pub id: QuarantineTransactionId,
    pub repository: RepositoryIdentity,
    pub current_generation: RepositoryGeneration,
    pub next_generation: RepositoryGeneration,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    pub policy_digest: [u8; 64],
    pub ref_update_digest: [u8; 64],
    pub introduced_commit_set_digest: [u8; 64],
    pub arrival_pack_digest: [u8; 64],
    pub proof_set_digest: [u8; 64],
    pub activation_digest: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityCandidateRecord {
    pub context: AuthorityCandidateContext,
    pub status: AuthorityCandidateStatus,
}

pub fn candidate_ref_update_digest(
    transaction: &VerifiedRefTransaction,
) -> Result<[u8; 64], GitdCoreError> {
    if transaction.updates().is_empty() {
        return Err(GitdCoreError::Authorization);
    }
    let mut hash = Sha3_512::new();
    hash.update(b"MRML git candidate ref updates v1\0");
    hash.update(
        &u16::try_from(transaction.updates().len())
            .map_err(|_| GitdCoreError::Resource)?
            .to_be_bytes(),
    );
    for update in transaction.updates() {
        let name = update.name().as_str().as_bytes();
        hash.update(
            &u16::try_from(name.len())
                .map_err(|_| GitdCoreError::Resource)?
                .to_be_bytes(),
        );
        hash.update(name);
        hash_optional_object(&mut hash, update.expected_old())?;
        hash_optional_object(&mut hash, update.proposed_new())?;
    }
    Ok(hash.finalize())
}

pub fn candidate_proof_set_digest(
    proofs: &[DetachedCommitProofRecord],
) -> Result<[u8; 64], GitdCoreError> {
    if proofs.is_empty()
        || proofs.len() > crate::MAX_DETACHED_COMMIT_PROOFS
        || !proofs
            .windows(2)
            .all(|pair| pair[0].commit() < pair[1].commit())
    {
        return Err(GitdCoreError::Authorization);
    }
    let mut hash = Sha3_512::new();
    hash.update(b"MRML git candidate proof set v1\0");
    hash.update(
        &u32::try_from(proofs.len())
            .map_err(|_| GitdCoreError::Resource)?
            .to_be_bytes(),
    );
    for proof in proofs {
        hash.update(&[2]);
        hash.update(proof.commit().as_bytes());
        hash.update(
            &u32::try_from(proof.openpgp_signature().len())
                .map_err(|_| GitdCoreError::Resource)?
                .to_be_bytes(),
        );
        hash.update(proof.openpgp_signature());
        hash.update(
            &u32::try_from(proof.ml_dsa_signature().len())
                .map_err(|_| GitdCoreError::Resource)?
                .to_be_bytes(),
        );
        hash.update(proof.ml_dsa_signature());
    }
    Ok(hash.finalize())
}

#[allow(clippy::too_many_arguments)]
pub fn candidate_arrival_pack_digest(
    format: ObjectFormat,
    pack_checksum: ObjectId,
    index_checksum: ObjectId,
    pack_bytes: u64,
    index_bytes: u64,
    object_count: u32,
    expanded_bytes: u64,
) -> Result<[u8; 64], GitdCoreError> {
    if format != ObjectFormat::Sha256
        || pack_checksum.format() != format
        || index_checksum.format() != format
        || pack_checksum.is_zero()
        || index_checksum.is_zero()
        || pack_bytes == 0
        || index_bytes == 0
        || object_count == 0
        || expanded_bytes == 0
    {
        return Err(GitdCoreError::Authorization);
    }
    let mut hash = Sha3_512::new();
    hash.update(b"MRML git candidate arrival pack v1\0");
    hash.update(&[2]);
    hash.update(pack_checksum.as_bytes());
    hash.update(index_checksum.as_bytes());
    hash.update(&pack_bytes.to_be_bytes());
    hash.update(&index_bytes.to_be_bytes());
    hash.update(&object_count.to_be_bytes());
    hash.update(&expanded_bytes.to_be_bytes());
    Ok(hash.finalize())
}

pub fn candidate_activation_digest(authenticated_receipt_transcript: &[u8]) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(b"MRML git candidate activation evidence v1\0");
    hash.update(authenticated_receipt_transcript);
    hash.finalize()
}

fn hash_optional_object(
    hash: &mut Sha3_512,
    object: Option<ObjectId>,
) -> Result<(), GitdCoreError> {
    match object {
        Some(object) if object.format() == ObjectFormat::Sha256 && !object.is_zero() => {
            hash.update(&[1, 2]);
            hash.update(object.as_bytes());
            Ok(())
        }
        Some(_) => Err(GitdCoreError::Authorization),
        None => {
            hash.update(&[0]);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CandidateRefTransaction, CandidateRefUpdate, FullRefName, HistoryVerificationLimits,
        ProtectedHistoryContext, RevocationGeneration, SignaturePurpose, TrustGeneration,
        VerifiedCommitProof, build_verified_fast_forward_transaction,
        verify_protected_introduced_history,
    };
    use mrml_runtime::Vector;

    fn id(byte: u8) -> ObjectId {
        ObjectId::from_bytes(ObjectFormat::Sha256, &[byte; 32]).unwrap()
    }

    #[test]
    fn all_candidate_digests_are_exact_ordered_and_domain_separated() {
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let context = ProtectedHistoryContext {
            repository: &repository,
            repository_generation: RepositoryGeneration(3),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(5),
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha256,
        };
        let range = verify_protected_introduced_history(
            context,
            id(1),
            id(2),
            HistoryVerificationLimits::default(),
            |commit| {
                if commit == id(2) {
                    Ok([id(1)].into())
                } else {
                    Ok(Vector::new())
                }
            },
            |commit| {
                Ok(VerifiedCommitProof {
                    commit,
                    repository: repository.clone(),
                    repository_generation: RepositoryGeneration(3),
                    trust_generation: TrustGeneration(4),
                    revocation_generation: RevocationGeneration(5),
                    purpose: SignaturePurpose::GitCommit,
                    object_format: ObjectFormat::Sha256,
                })
            },
        )
        .unwrap();
        let verified = build_verified_fast_forward_transaction(
            CandidateRefTransaction {
                repository,
                repository_generation: RepositoryGeneration(3),
                trust_generation: TrustGeneration(4),
                revocation_generation: RevocationGeneration(5),
                updates: [CandidateRefUpdate {
                    name: FullRefName::parse("refs/heads/main").unwrap(),
                    expected_old: Some(id(1)),
                    proposed_new: Some(id(2)),
                }]
                .into(),
            },
            &[range],
        )
        .unwrap();
        let ref_digest = candidate_ref_update_digest(&verified).unwrap();
        assert_ne!(ref_digest, verified.introduced_commit_set_digest());
        let proof = DetachedCommitProofRecord::new(
            id(2),
            &[7; 64],
            &[8; mrml_crypto::ML_DSA_65_SIGNATURE_BYTES],
        )
        .unwrap();
        let proof_digest = candidate_proof_set_digest(core::slice::from_ref(&proof)).unwrap();
        assert_ne!(proof_digest, ref_digest);
        let arrival =
            candidate_arrival_pack_digest(ObjectFormat::Sha256, id(9), id(10), 100, 80, 1, 40)
                .unwrap();
        assert_ne!(arrival, proof_digest);
        assert_ne!(candidate_activation_digest(b"receipt"), arrival);
    }
}
