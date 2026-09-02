//! Bounded detached hybrid proofs for protected commit admission.

use mrml_crypto::{ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES};
use mrml_openpgp::{PublicKeyV6, MAX_OPENPGP_SIGNATURE_BYTES};
use mrml_runtime::Vector;

use crate::{
    bind_verified_commit_proof, verify_hybrid_signature, DurableDetachedCommitProofDirectory,
    GitObjectType, HistoryVerificationError, HybridTrustPolicy, HybridVerificationRequest,
    ObjectId, ProtectedCommitVerifier, ProtectedHistoryContext, VerifiedCommitProof,
};

pub const MAX_DETACHED_COMMIT_PROOFS: usize = 5_000;

/// Untrusted stored detached signatures for one exact commit ID. Authentication
/// happens only when [`DetachedHybridCommitVerifier`] verifies both signatures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetachedCommitProofRecord {
    commit: ObjectId,
    openpgp_signature: Vector<u8>,
    ml_dsa_signature: Vector<u8>,
}

/// Verification-only adapter backed by the durable, exact-context proof
/// directory. The directory contains untrusted signatures, while this adapter
/// obtains verification authority only from its injected public policy state.
pub struct DurableDetachedHybridCommitVerifier<'a> {
    store: &'a DurableDetachedCommitProofDirectory,
    policy: &'a HybridTrustPolicy,
    openpgp_key: &'a PublicKeyV6,
    ml_dsa_key: &'a [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
    openpgp_scratch: &'a mut [u8],
}

impl<'a> DurableDetachedHybridCommitVerifier<'a> {
    pub fn new(
        store: &'a DurableDetachedCommitProofDirectory,
        policy: &'a HybridTrustPolicy,
        openpgp_key: &'a PublicKeyV6,
        ml_dsa_key: &'a [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
        openpgp_scratch: &'a mut [u8],
    ) -> Result<Self, HistoryVerificationError> {
        if openpgp_scratch.len() < MAX_OPENPGP_SIGNATURE_BYTES {
            return Err(HistoryVerificationError::Resource);
        }
        Ok(Self {
            store,
            policy,
            openpgp_key,
            ml_dsa_key,
            openpgp_scratch,
        })
    }
}

impl ProtectedCommitVerifier for DurableDetachedHybridCommitVerifier<'_> {
    fn verify_commit(
        &mut self,
        context: ProtectedHistoryContext<'_>,
        commit: ObjectId,
        exact_contents: &[u8],
    ) -> Result<VerifiedCommitProof, HistoryVerificationError> {
        let record = self
            .store
            .lookup(context, commit)
            .map_err(|_| HistoryVerificationError::Signature)?
            .ok_or(HistoryVerificationError::Signature)?;
        let request = HybridVerificationRequest {
            repository: context.repository,
            object_format: context.object_format,
            object_type: GitObjectType::Commit,
            purpose: context.purpose,
            trust_generation: context.trust_generation,
            revocation_generation: context.revocation_generation,
            payload: exact_contents,
            openpgp_signature: record.openpgp_signature(),
            ml_dsa_signature: record.ml_dsa_signature(),
        };
        let signature = verify_hybrid_signature(
            self.policy,
            self.openpgp_key,
            self.ml_dsa_key,
            &request,
            self.openpgp_scratch,
        )
        .map_err(|_| HistoryVerificationError::Signature)?;
        bind_verified_commit_proof(&signature, commit, exact_contents, context)
            .map_err(|_| HistoryVerificationError::Signature)
    }
}

impl DetachedCommitProofRecord {
    pub fn new(
        commit: ObjectId,
        openpgp_signature: &[u8],
        ml_dsa_signature: &[u8],
    ) -> Result<Self, HistoryVerificationError> {
        if commit.is_zero()
            || openpgp_signature.is_empty()
            || openpgp_signature.len() > MAX_OPENPGP_SIGNATURE_BYTES
            || ml_dsa_signature.len() != ML_DSA_65_SIGNATURE_BYTES
        {
            return Err(HistoryVerificationError::Signature);
        }
        let mut openpgp = Vector::with_capacity(openpgp_signature.len())
            .map_err(|_| HistoryVerificationError::Resource)?;
        openpgp
            .try_extend_from_slice(openpgp_signature)
            .map_err(|_| HistoryVerificationError::Resource)?;
        let mut ml_dsa = Vector::with_capacity(ml_dsa_signature.len())
            .map_err(|_| HistoryVerificationError::Resource)?;
        ml_dsa
            .try_extend_from_slice(ml_dsa_signature)
            .map_err(|_| HistoryVerificationError::Resource)?;
        Ok(Self {
            commit,
            openpgp_signature: openpgp,
            ml_dsa_signature: ml_dsa,
        })
    }

    pub const fn commit(&self) -> ObjectId {
        self.commit
    }

    pub fn openpgp_signature(&self) -> &[u8] {
        &self.openpgp_signature
    }

    pub fn ml_dsa_signature(&self) -> &[u8] {
        &self.ml_dsa_signature
    }
}

/// Fixed-capacity proof store. Records must be strictly ordered by exact object
/// ID, making duplicate or ambiguous proof selection impossible.
pub struct DetachedCommitProofStore {
    records: Vector<DetachedCommitProofRecord>,
}

impl DetachedCommitProofStore {
    pub fn new(
        records: Vector<DetachedCommitProofRecord>,
    ) -> Result<Self, HistoryVerificationError> {
        if records.is_empty()
            || records.len() > MAX_DETACHED_COMMIT_PROOFS
            || !records
                .windows(2)
                .all(|pair| pair[0].commit < pair[1].commit)
        {
            return Err(HistoryVerificationError::Resource);
        }
        Ok(Self { records })
    }

    fn exact(
        &self,
        commit: ObjectId,
    ) -> Result<&DetachedCommitProofRecord, HistoryVerificationError> {
        self.records
            .binary_search_by_key(&commit, |record| record.commit)
            .ok()
            .map(|index| &self.records[index])
            .ok_or(HistoryVerificationError::Signature)
    }
}

/// Concrete verification-only adapter for detached hybrid commit proofs.
pub struct DetachedHybridCommitVerifier<'a> {
    store: &'a DetachedCommitProofStore,
    policy: &'a HybridTrustPolicy,
    openpgp_key: &'a PublicKeyV6,
    ml_dsa_key: &'a [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
    openpgp_scratch: &'a mut [u8],
}

impl<'a> DetachedHybridCommitVerifier<'a> {
    pub fn new(
        store: &'a DetachedCommitProofStore,
        policy: &'a HybridTrustPolicy,
        openpgp_key: &'a PublicKeyV6,
        ml_dsa_key: &'a [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
        openpgp_scratch: &'a mut [u8],
    ) -> Result<Self, HistoryVerificationError> {
        if openpgp_scratch.len() < MAX_OPENPGP_SIGNATURE_BYTES {
            return Err(HistoryVerificationError::Resource);
        }
        Ok(Self {
            store,
            policy,
            openpgp_key,
            ml_dsa_key,
            openpgp_scratch,
        })
    }
}

impl ProtectedCommitVerifier for DetachedHybridCommitVerifier<'_> {
    fn verify_commit(
        &mut self,
        context: ProtectedHistoryContext<'_>,
        commit: ObjectId,
        exact_contents: &[u8],
    ) -> Result<VerifiedCommitProof, HistoryVerificationError> {
        let record = self.store.exact(commit)?;
        let request = HybridVerificationRequest {
            repository: context.repository,
            object_format: context.object_format,
            object_type: GitObjectType::Commit,
            purpose: context.purpose,
            trust_generation: context.trust_generation,
            revocation_generation: context.revocation_generation,
            payload: exact_contents,
            openpgp_signature: &record.openpgp_signature,
            ml_dsa_signature: &record.ml_dsa_signature,
        };
        let signature = verify_hybrid_signature(
            self.policy,
            self.openpgp_key,
            self.ml_dsa_key,
            &request,
            self.openpgp_scratch,
        )
        .map_err(|_| HistoryVerificationError::Signature)?;
        bind_verified_commit_proof(&signature, commit, exact_contents, context)
            .map_err(|_| HistoryVerificationError::Signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        canonical_hybrid_transcript, encode_loose_object_with_format, AuthorizedHybridPair,
        ObjectFormat, ObjectKind, RepositoryGeneration, RepositoryIdentity, RevocationGeneration,
        SignaturePurpose, TrustGeneration,
    };
    use mrml_crypto::{ml_dsa_65_keygen, ml_dsa_65_sign, ML_DSA_65_SECRET_KEY_BYTES};
    use mrml_openpgp::{sign_detached_v6_ascii_with_salt, DigestAlgorithm, SigningKeyV6};

    #[test]
    fn exact_detached_record_authenticates_bytes_and_context() {
        let repository = RepositoryIdentity::parse("owner/protected").unwrap();
        let contents =
            b"tree 0123456789012345678901234567890123456789012345678901234567890123\n\nmessage\n";
        let commit =
            encode_loose_object_with_format(ObjectFormat::Sha256, ObjectKind::Commit, contents).0;
        let signing = SigningKeyV6::from_seed([7; 32], 1_700_000_000).unwrap();
        let public = signing.public_key();
        let mut ml_public = [0; ML_DSA_65_PUBLIC_KEY_BYTES];
        let mut ml_secret = [0; ML_DSA_65_SECRET_KEY_BYTES];
        ml_dsa_65_keygen(&[9; 32], &mut ml_public, &mut ml_secret).unwrap();
        let pair = AuthorizedHybridPair::bind(&public, &ml_public);
        let transcript = canonical_hybrid_transcript(
            &repository,
            ObjectFormat::Sha256,
            GitObjectType::Commit,
            SignaturePurpose::GitCommit,
            TrustGeneration(4),
            pair,
            contents,
        )
        .unwrap();
        let mut openpgp = [0; MAX_OPENPGP_SIGNATURE_BYTES];
        let openpgp_len = sign_detached_v6_ascii_with_salt(
            &signing,
            &transcript,
            DigestAlgorithm::Sha512,
            1_700_000_001,
            &[11; 32],
            &mut openpgp,
        )
        .unwrap();
        let mut ml_dsa = [0; ML_DSA_65_SIGNATURE_BYTES];
        ml_dsa_65_sign(
            &ml_secret,
            b"mrml.git.hybrid.v1",
            &transcript,
            &[13; 32],
            &mut ml_dsa,
        )
        .unwrap();
        let record =
            DetachedCommitProofRecord::new(commit, &openpgp[..openpgp_len], &ml_dsa).unwrap();
        let store = DetachedCommitProofStore::new([record.clone()].into()).unwrap();
        let policy = HybridTrustPolicy {
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(8),
            authorized_pair: pair,
            validation_time: Some(1_700_000_002),
            openpgp_not_after: None,
            enforce_signature_expiration: true,
        };
        let context = ProtectedHistoryContext {
            repository: &repository,
            repository_generation: RepositoryGeneration(3),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(8),
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha256,
        };
        let mut scratch = [0; MAX_OPENPGP_SIGNATURE_BYTES];
        let mut verifier =
            DetachedHybridCommitVerifier::new(&store, &policy, &public, &ml_public, &mut scratch)
                .unwrap();
        assert!(verifier.verify_commit(context, commit, contents).is_ok());
        assert_eq!(
            verifier.verify_commit(context, commit, b"different"),
            Err(HistoryVerificationError::Signature)
        );
        assert_eq!(
            verifier.verify_commit(context, ObjectId::Sha256([99; 32]), contents),
            Err(HistoryVerificationError::Signature)
        );

        #[cfg(unix)]
        {
            let root = mrml_runtime::join_path(
                &mrml_runtime::temporary_directory(),
                &mrml_runtime::mrml_format!("mrml-durable-verifier-{}", mrml_runtime::process_id()),
            );
            let directory = DurableDetachedCommitProofDirectory::open(&root).unwrap();
            directory.insert(context, &record).unwrap();
            let mut durable_scratch = [0; MAX_OPENPGP_SIGNATURE_BYTES];
            let mut durable = DurableDetachedHybridCommitVerifier::new(
                &directory,
                &policy,
                &public,
                &ml_public,
                &mut durable_scratch,
            )
            .unwrap();
            assert!(durable.verify_commit(context, commit, contents).is_ok());
            assert_eq!(
                durable.verify_commit(context, commit, b"substituted"),
                Err(HistoryVerificationError::Signature)
            );
        }
    }

    #[test]
    fn proof_store_rejects_duplicates_oversize_and_wrong_signature_width() {
        let commit = ObjectId::Sha256([1; 32]);
        assert!(DetachedCommitProofRecord::new(commit, &[1], &[2]).is_err());
        assert!(DetachedCommitProofRecord::new(
            commit,
            &[1; MAX_OPENPGP_SIGNATURE_BYTES + 1],
            &[2; ML_DSA_65_SIGNATURE_BYTES],
        )
        .is_err());
        let record =
            DetachedCommitProofRecord::new(commit, &[1], &[2; ML_DSA_65_SIGNATURE_BYTES]).unwrap();
        assert!(DetachedCommitProofStore::new([record.clone(), record].into()).is_err());
    }
}
