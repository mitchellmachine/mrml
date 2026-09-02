//! Capability-scoped client proof construction for protected pushes.

use mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES;
use mrml_openpgp::{MAX_OPENPGP_SIGNATURE_BYTES, PublicKeyV6};
use mrml_runtime::Vector;

use crate::{
    DetachedCommitProofRecord, GitObjectType, HistoryVerificationError, HistoryVerificationLimits,
    HybridTrustPolicy, HybridVerificationRequest, ObjectId, ObjectKind, ProtectedHistoryContext,
    Repository, VerifiedCommitProof, bind_verified_commit_proof,
    verify_hybrid_signature, verify_protected_introduced_history,
};

pub struct ProtectedCommitSigningRequest<'a> {
    pub context: ProtectedHistoryContext<'a>,
    pub commit: ObjectId,
    pub exact_contents: &'a [u8],
}

pub struct HybridCommitSignatures {
    openpgp: Vector<u8>,
    ml_dsa: Vector<u8>,
}

impl HybridCommitSignatures {
    pub fn new(openpgp: &[u8], ml_dsa: &[u8]) -> Result<Self, HistoryVerificationError> {
        if openpgp.is_empty()
            || openpgp.len() > MAX_OPENPGP_SIGNATURE_BYTES
            || ml_dsa.len() != mrml_crypto::ML_DSA_65_SIGNATURE_BYTES
        {
            return Err(HistoryVerificationError::Signature);
        }
        let mut value = Self {
            openpgp: Vector::new(),
            ml_dsa: Vector::new(),
        };
        value
            .openpgp
            .try_extend_from_slice(openpgp)
            .map_err(|_| HistoryVerificationError::Resource)?;
        value
            .ml_dsa
            .try_extend_from_slice(ml_dsa)
            .map_err(|_| HistoryVerificationError::Resource)?;
        Ok(value)
    }

    pub fn openpgp(&self) -> &[u8] {
        &self.openpgp
    }

    pub fn ml_dsa(&self) -> &[u8] {
        &self.ml_dsa
    }
}

/// Capability-bearing provider operation restricted to one canonical Git
/// commit request. Implementations must not expose key export or arbitrary
/// signing through this route.
pub trait HybridCommitSigningProvider {
    fn sign_git_commit(
        &mut self,
        request: ProtectedCommitSigningRequest<'_>,
    ) -> Result<HybridCommitSignatures, HistoryVerificationError>;
}

/// Client-side verifier around an isolated signing provider. Provider output
/// is untrusted until both algorithms verify under the exact pinned policy and
/// the resulting proof binds to the requested commit bytes.
pub struct CapabilityVerifiedProofSigner<'a, P> {
    provider: P,
    policy: HybridTrustPolicy,
    openpgp_key: &'a PublicKeyV6,
    ml_dsa_key: &'a [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
    openpgp_scratch: &'a mut [u8],
}

impl<'a, P: HybridCommitSigningProvider> CapabilityVerifiedProofSigner<'a, P> {
    pub fn new(
        provider: P,
        policy: HybridTrustPolicy,
        openpgp_key: &'a PublicKeyV6,
        ml_dsa_key: &'a [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
        openpgp_scratch: &'a mut [u8],
    ) -> Result<Self, HistoryVerificationError> {
        if openpgp_scratch.len() < MAX_OPENPGP_SIGNATURE_BYTES {
            return Err(HistoryVerificationError::Resource);
        }
        Ok(Self {
            provider,
            policy,
            openpgp_key,
            ml_dsa_key,
            openpgp_scratch,
        })
    }

    pub fn into_provider(self) -> P {
        self.provider
    }
}

impl<P: HybridCommitSigningProvider> ProtectedCommitProofSigner
    for CapabilityVerifiedProofSigner<'_, P>
{
    fn sign_commit(
        &mut self,
        context: ProtectedHistoryContext<'_>,
        commit: ObjectId,
        exact_contents: &[u8],
    ) -> Result<DetachedCommitProofRecord, HistoryVerificationError> {
        if context.trust_generation != self.policy.trust_generation
            || context.revocation_generation != self.policy.revocation_generation
            || context.purpose != crate::SignaturePurpose::GitCommit
            || context.object_format != crate::ObjectFormat::Sha256
        {
            return Err(HistoryVerificationError::Signature);
        }
        let signatures = self.provider.sign_git_commit(ProtectedCommitSigningRequest {
            context,
            commit,
            exact_contents,
        })?;
        let request = HybridVerificationRequest {
            repository: context.repository,
            object_format: context.object_format,
            object_type: GitObjectType::Commit,
            purpose: context.purpose,
            trust_generation: context.trust_generation,
            revocation_generation: context.revocation_generation,
            payload: exact_contents,
            openpgp_signature: &signatures.openpgp,
            ml_dsa_signature: &signatures.ml_dsa,
        };
        let mut verification_policy = self.policy;
        verification_policy.validation_time =
            Some(mrml_runtime::unix_time_seconds().ok_or(HistoryVerificationError::Signature)?);
        let verified = verify_hybrid_signature(
            &verification_policy,
            self.openpgp_key,
            self.ml_dsa_key,
            &request,
            self.openpgp_scratch,
        )
        .map_err(|_| HistoryVerificationError::Signature)?;
        bind_verified_commit_proof(&verified, commit, exact_contents, context)
            .map_err(|_| HistoryVerificationError::Signature)?;
        DetachedCommitProofRecord::new(commit, &signatures.openpgp, &signatures.ml_dsa)
    }
}

/// Narrow signing-use boundary for one exact protected Git commit. Providers
/// retain key custody and must bind both signatures to the canonical hybrid
/// transcript selected by this context. This interface grants no key lifecycle,
/// export, generic-message signing, or repository-write authority.
pub trait ProtectedCommitProofSigner {
    fn sign_commit(
        &mut self,
        context: ProtectedHistoryContext<'_>,
        commit: ObjectId,
        exact_contents: &[u8],
    ) -> Result<DetachedCommitProofRecord, HistoryVerificationError>;
}

/// Traverse the entire introduced history, including every merge-side parent,
/// and request one exact proof per commit. The returned records are sorted by
/// object ID for the canonical receive-wire encoding.
pub fn sign_protected_introduced_history(
    repository: &Repository,
    context: ProtectedHistoryContext<'_>,
    old: ObjectId,
    new: ObjectId,
    limits: HistoryVerificationLimits,
    signer: &mut dyn ProtectedCommitProofSigner,
) -> Result<Vector<DetachedCommitProofRecord>, HistoryVerificationError> {
    let mut proofs = Vector::new();
    verify_protected_introduced_history(
        context,
        old,
        new,
        limits,
        |id| {
            let commit = repository
                .read_commit(id)
                .map_err(|_| HistoryVerificationError::MissingCommit)?;
            if commit.parents.len() > usize::from(limits.max_parents_per_commit) {
                return Err(HistoryVerificationError::Resource);
            }
            Ok(commit.parents)
        },
        |id| {
            let object = repository
                .read_object(id)
                .map_err(|_| HistoryVerificationError::MissingCommit)?;
            if object.kind != ObjectKind::Commit {
                return Err(HistoryVerificationError::MissingCommit);
            }
            let proof = signer.sign_commit(context, id, &object.contents)?;
            if proof.commit() != id {
                return Err(HistoryVerificationError::Signature);
            }
            proofs
                .try_push(proof)
                .map_err(|_| HistoryVerificationError::Resource)?;
            Ok(VerifiedCommitProof {
                commit: id,
                repository: context.repository.clone(),
                repository_generation: context.repository_generation,
                trust_generation: context.trust_generation,
                revocation_generation: context.revocation_generation,
                purpose: context.purpose,
                object_format: context.object_format,
            })
        },
    )?;
    proofs.sort_unstable_by_key(DetachedCommitProofRecord::commit);
    if proofs.is_empty()
        || !proofs
            .windows(2)
            .all(|pair| pair[0].commit() < pair[1].commit())
    {
        return Err(HistoryVerificationError::Signature);
    }
    Ok(proofs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ObjectFormat, RepositoryGeneration, RepositoryIdentity, RevocationGeneration,
        SignaturePurpose, TrustGeneration,
    };

    struct RecordingSigner {
        commits: Vector<ObjectId>,
    }

    struct InvalidCapabilityProvider;

    impl HybridCommitSigningProvider for InvalidCapabilityProvider {
        fn sign_git_commit(
            &mut self,
            _: ProtectedCommitSigningRequest<'_>,
        ) -> Result<HybridCommitSignatures, HistoryVerificationError> {
            HybridCommitSignatures::new(
                &[3; 64],
                &[4; mrml_crypto::ML_DSA_65_SIGNATURE_BYTES],
            )
        }
    }

    impl ProtectedCommitProofSigner for RecordingSigner {
        fn sign_commit(
            &mut self,
            _: ProtectedHistoryContext<'_>,
            commit: ObjectId,
            _: &[u8],
        ) -> Result<DetachedCommitProofRecord, HistoryVerificationError> {
            self.commits.push(commit);
            DetachedCommitProofRecord::new(
                commit,
                &[3; 64],
                &[4; mrml_crypto::ML_DSA_65_SIGNATURE_BYTES],
            )
        }
    }

    fn commit(repository: &Repository, parents: &[ObjectId], marker: &str) -> ObjectId {
        let tree = ObjectId::from_bytes(ObjectFormat::Sha256, &[9; 32]).unwrap();
        let mut contents = mrml_runtime::mrml_format!("tree {tree}\n");
        for parent in parents {
            contents.push_str(&mrml_runtime::mrml_format!("parent {parent}\n"));
        }
        contents.push_str(&mrml_runtime::mrml_format!(
            "author A <a@example.invalid> 1 +0000\ncommitter A <a@example.invalid> 1 +0000\n\n{marker}\n"
        ));
        repository
            .write_object(ObjectKind::Commit, contents.as_bytes())
            .unwrap()
    }


    #[test]
    fn signs_every_merge_side_commit_once_and_returns_canonical_order() {
        let root = mrml_runtime::join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-protected-push-{}", mrml_runtime::process_id()),
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        let repository = Repository::init_with_format(&root, ObjectFormat::Sha256).unwrap();
        let base = commit(&repository, &[], "base");
        let side = commit(&repository, &[base], "side");
        let merge = commit(&repository, &[base, side], "merge");
        let identity = RepositoryIdentity::parse("owner/project").unwrap();
        let mut signer = RecordingSigner {
            commits: Vector::new(),
        };
        let proofs = sign_protected_introduced_history(
            &repository,
            ProtectedHistoryContext {
                repository: &identity,
                repository_generation: RepositoryGeneration(2),
                trust_generation: TrustGeneration(3),
                revocation_generation: RevocationGeneration(4),
                purpose: SignaturePurpose::GitCommit,
                object_format: ObjectFormat::Sha256,
            },
            base,
            merge,
            HistoryVerificationLimits::default(),
            &mut signer,
        )
        .unwrap();
        assert_eq!(signer.commits.len(), 2);
        assert!(signer.commits.contains(&side));
        assert!(signer.commits.contains(&merge));
        assert!(!signer.commits.contains(&base));
        assert_eq!(proofs.len(), 2);
        assert!(proofs[0].commit() < proofs[1].commit());
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn capability_provider_output_is_independently_verified() {
        use mrml_crypto::{ML_DSA_65_SECRET_KEY_BYTES, ml_dsa_65_keygen};
        use mrml_openpgp::SigningKeyV6;

        let signing = SigningKeyV6::from_seed([7; 32], 1_700_000_000).unwrap();
        let openpgp = signing.public_key();
        let mut ml_public = [0; ML_DSA_65_PUBLIC_KEY_BYTES];
        let mut ml_secret = [0; ML_DSA_65_SECRET_KEY_BYTES];
        ml_dsa_65_keygen(&[8; 32], &mut ml_public, &mut ml_secret).unwrap();
        let policy = HybridTrustPolicy {
            trust_generation: TrustGeneration(3),
            revocation_generation: RevocationGeneration(4),
            authorized_pair: crate::AuthorizedHybridPair::bind(&openpgp, &ml_public),
            validation_time: Some(1_700_000_001),
            openpgp_not_after: None,
            enforce_signature_expiration: false,
        };
        let identity = RepositoryIdentity::parse("owner/project").unwrap();
        let context = ProtectedHistoryContext {
            repository: &identity,
            repository_generation: RepositoryGeneration(2),
            trust_generation: TrustGeneration(3),
            revocation_generation: RevocationGeneration(4),
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha256,
        };
        let commit = ObjectId::from_bytes(ObjectFormat::Sha256, &[9; 32]).unwrap();
        let mut scratch = [0; MAX_OPENPGP_SIGNATURE_BYTES];
        let mut provider = CapabilityVerifiedProofSigner::new(
            InvalidCapabilityProvider,
            policy,
            &openpgp,
            &ml_public,
            &mut scratch,
        )
        .unwrap();
        assert_eq!(
            provider.sign_commit(context, commit, b"exact commit bytes"),
            Err(HistoryVerificationError::Signature)
        );
        ml_secret.fill(0);
    }
}
