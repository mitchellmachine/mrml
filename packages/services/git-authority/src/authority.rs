use mrml_crypto::{
    ed25519_public, ed25519_sign, ed25519_verify, erase_secret_bytes, Sha3_512,
    ML_DSA_65_PUBLIC_KEY_BYTES,
};
use mrml_git::{
    bind_verified_commit_proof, parse_authority_commit, parse_authority_proof_install,
    parse_authority_receipt, parse_authority_receive, parse_authority_ref_transaction,
    verify_hybrid_signature, AuthorizedHybridPair, DurableDetachedCommitProofDirectory,
    DurableDetachedHybridCommitVerifier, GitObjectType, GitdCoreError, HybridVerificationRequest,
    LinuxDurableTrustPolicyStore, ProtectedCommitVerifier, ProtectedHistoryContext,
    RepositoryGeneration, SignaturePurpose, TrustPolicyState,
};
use mrml_openpgp::{PublicKeyV6, MAX_OPENPGP_SIGNATURE_BYTES};
use mrml_runtime::Vector;

use crate::AuthorityOperation;

const RECEIPT_DOMAIN: &[u8] = b"MRML git authority receipt signing v1";
const RECEIPT_SIGNATURE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityDispatchError {
    Malformed,
    Unauthorized,
    Unavailable,
    Resource,
}

pub struct ProductionAuthority {
    policy: LinuxDurableTrustPolicyStore,
    proofs: DurableDetachedCommitProofDirectory,
    openpgp_key: PublicKeyV6,
    ml_dsa_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
    receipt_key: [u8; 32],
    signer_identity: [u8; 64],
    validation_time: u64,
    repository_generation: RepositoryGeneration,
}

impl ProductionAuthority {
    pub fn new(
        policy: LinuxDurableTrustPolicyStore,
        proofs: DurableDetachedCommitProofDirectory,
        openpgp_key: PublicKeyV6,
        ml_dsa_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
        receipt_key: [u8; 32],
        validation_time: u64,
        repository_generation: RepositoryGeneration,
    ) -> Result<Self, AuthorityDispatchError> {
        if receipt_key == [0; 32] || validation_time == 0 || repository_generation.0 == 0 {
            return Err(AuthorityDispatchError::Unavailable);
        }
        let pair = AuthorizedHybridPair::bind(&openpgp_key, &ml_dsa_key);
        let current = policy
            .load()
            .map_err(|_| AuthorityDispatchError::Unavailable)?;
        current
            .active_verification_policy_at(pair, validation_time, true)
            .map_err(|_| AuthorityDispatchError::Unauthorized)?;
        let mut identity = Sha3_512::new();
        identity.update(b"MRML git receipt signer identity v1");
        identity.update(&ed25519_public(&receipt_key));
        let signer_identity = identity.finalize();
        Ok(Self {
            policy,
            proofs,
            openpgp_key,
            ml_dsa_key,
            receipt_key,
            signer_identity,
            validation_time,
            repository_generation,
        })
    }

    pub const fn signer_identity(&self) -> [u8; 64] {
        self.signer_identity
    }

    pub fn receipt_verification_key(&self) -> [u8; 32] {
        ed25519_public(&self.receipt_key)
    }

    pub fn set_validation_time(
        &mut self,
        validation_time: u64,
    ) -> Result<(), AuthorityDispatchError> {
        if validation_time == 0 {
            return Err(AuthorityDispatchError::Unavailable);
        }
        self.validation_time = validation_time;
        Ok(())
    }

    pub fn dispatch(
        &mut self,
        operation: AuthorityOperation,
        payload: &[u8],
    ) -> Result<Vector<u8>, AuthorityDispatchError> {
        match operation {
            AuthorityOperation::Health if payload.is_empty() => self.health(),
            AuthorityOperation::AuthorizeReceive => self.authorize_receive(payload),
            AuthorityOperation::AuthorizeRefTransaction => self.authorize_refs(payload),
            AuthorityOperation::VerifyCommit => self.verify_commit(payload),
            AuthorityOperation::VerifyLegacyCommit => Err(AuthorityDispatchError::Unauthorized),
            AuthorityOperation::SignReceipt => self.sign_receipt(payload),
            AuthorityOperation::VerifyReceipt => self.verify_receipt(payload),
            AuthorityOperation::InstallProof => self.install_proof(payload),
            AuthorityOperation::Health => Err(AuthorityDispatchError::Malformed),
        }
    }

    fn health(&self) -> Result<Vector<u8>, AuthorityDispatchError> {
        let policy = self
            .policy
            .load()
            .map_err(|_| AuthorityDispatchError::Unavailable)?;
        let pair = AuthorizedHybridPair::bind(&self.openpgp_key, &self.ml_dsa_key);
        policy
            .active_verification_policy_at(pair, self.validation_time, true)
            .map_err(|_| AuthorityDispatchError::Unavailable)?;
        let mut output = Vector::new();
        output
            .try_extend_from_slice(b"ready-v1")
            .map_err(|_| AuthorityDispatchError::Resource)?;
        Ok(output)
    }

    fn authorize_receive(&self, payload: &[u8]) -> Result<Vector<u8>, AuthorityDispatchError> {
        let request = parse_authority_receive(payload).map_err(map_git_error)?;
        let policy = self.current_policy()?;
        if request.repository != *policy.repository()
            || request.repository_generation != self.repository_generation
            || request.trust_generation != policy.generation()
            || request.revocation_generation != policy.revocation_generation()
            || request.policy_digest != policy.digest()
        {
            return Err(AuthorityDispatchError::Unauthorized);
        }
        Ok(Vector::new())
    }

    fn authorize_refs(&self, payload: &[u8]) -> Result<Vector<u8>, AuthorityDispatchError> {
        let request = parse_authority_ref_transaction(payload).map_err(map_git_error)?;
        let policy = self.current_policy()?;
        let transaction = &request.transaction;
        if transaction.repository != *policy.repository()
            || transaction.repository_generation != self.repository_generation
            || transaction.trust_generation != policy.generation()
            || transaction.revocation_generation != policy.revocation_generation()
            || request.policy_digest != policy.digest()
            || transaction.updates.iter().any(|update| {
                !policy.protects_ref(&update.name)
                    || update.expected_old.is_none()
                    || update.proposed_new.is_none()
            })
        {
            return Err(AuthorityDispatchError::Unauthorized);
        }
        Ok(Vector::new())
    }

    fn verify_commit(&mut self, payload: &[u8]) -> Result<Vector<u8>, AuthorityDispatchError> {
        let request = parse_authority_commit(payload).map_err(map_git_error)?;
        let policy = self.current_policy()?;
        if request.repository != *policy.repository()
            || request.trust_generation != policy.generation()
            || request.revocation_generation != policy.revocation_generation()
            || request.repository_generation != self.repository_generation
            || request.purpose != SignaturePurpose::GitCommit
        {
            return Err(AuthorityDispatchError::Unauthorized);
        }
        let pair = AuthorizedHybridPair::bind(&self.openpgp_key, &self.ml_dsa_key);
        let verification_policy = policy
            .active_verification_policy_at(pair, self.validation_time, true)
            .map_err(|_| AuthorityDispatchError::Unauthorized)?;
        let mut scratch = [0u8; MAX_OPENPGP_SIGNATURE_BYTES];
        let mut verifier = DurableDetachedHybridCommitVerifier::new(
            &self.proofs,
            &verification_policy,
            &self.openpgp_key,
            &self.ml_dsa_key,
            &mut scratch,
        )
        .map_err(|_| AuthorityDispatchError::Unavailable)?;
        let context = ProtectedHistoryContext {
            repository: &request.repository,
            repository_generation: request.repository_generation,
            trust_generation: request.trust_generation,
            revocation_generation: request.revocation_generation,
            purpose: request.purpose,
            object_format: request.object_format,
        };
        verifier
            .verify_commit(context, request.commit, &request.exact_contents)
            .map_err(|_| AuthorityDispatchError::Unauthorized)?;
        Ok(Vector::new())
    }

    fn install_proof(&mut self, payload: &[u8]) -> Result<Vector<u8>, AuthorityDispatchError> {
        let request = parse_authority_proof_install(payload).map_err(map_git_error)?;
        let policy = self.current_policy()?;
        if request.repository != *policy.repository()
            || request.repository_generation != self.repository_generation
            || request.trust_generation != policy.generation()
            || request.revocation_generation != policy.revocation_generation()
            || request.purpose != SignaturePurpose::GitCommit
        {
            return Err(AuthorityDispatchError::Unauthorized);
        }
        let pair = AuthorizedHybridPair::bind(&self.openpgp_key, &self.ml_dsa_key);
        let verification_policy = policy
            .active_verification_policy_at(pair, self.validation_time, true)
            .map_err(|_| AuthorityDispatchError::Unauthorized)?;
        let context = ProtectedHistoryContext {
            repository: &request.repository,
            repository_generation: request.repository_generation,
            trust_generation: request.trust_generation,
            revocation_generation: request.revocation_generation,
            purpose: request.purpose,
            object_format: request.object_format,
        };
        let signature = verify_hybrid_signature(
            &verification_policy,
            &self.openpgp_key,
            &self.ml_dsa_key,
            &HybridVerificationRequest {
                repository: &request.repository,
                object_format: request.object_format,
                object_type: GitObjectType::Commit,
                purpose: request.purpose,
                trust_generation: request.trust_generation,
                revocation_generation: request.revocation_generation,
                payload: &request.exact_contents,
                openpgp_signature: request.proof.openpgp_signature(),
                ml_dsa_signature: request.proof.ml_dsa_signature(),
            },
            &mut [0; MAX_OPENPGP_SIGNATURE_BYTES],
        )
        .map_err(|_| AuthorityDispatchError::Unauthorized)?;
        bind_verified_commit_proof(&signature, request.commit, &request.exact_contents, context)
            .map_err(|_| AuthorityDispatchError::Unauthorized)?;
        match self.proofs.insert(context, &request.proof) {
            Ok(()) => {}
            Err(mrml_git::DetachedCommitProofFileError::AlreadyExists) => {
                let mut scratch = [0; MAX_OPENPGP_SIGNATURE_BYTES];
                DurableDetachedHybridCommitVerifier::new(
                    &self.proofs,
                    &verification_policy,
                    &self.openpgp_key,
                    &self.ml_dsa_key,
                    &mut scratch,
                )
                .and_then(|mut verifier| {
                    verifier.verify_commit(context, request.commit, &request.exact_contents)
                })
                .map_err(|_| AuthorityDispatchError::Unauthorized)?;
            }
            Err(_) => return Err(AuthorityDispatchError::Unavailable),
        }
        Ok(Vector::new())
    }

    fn sign_receipt(&self, payload: &[u8]) -> Result<Vector<u8>, AuthorityDispatchError> {
        let request = parse_authority_receipt(payload).map_err(map_git_error)?;
        if !request.signature.is_empty() {
            return Err(AuthorityDispatchError::Malformed);
        }
        let transcript = receipt_signature_transcript(&request.transcript)?;
        let signature = ed25519_sign(&self.receipt_key, &transcript);
        let mut output = Vector::new();
        output
            .try_extend_from_slice(&signature)
            .map_err(|_| AuthorityDispatchError::Resource)?;
        Ok(output)
    }

    fn verify_receipt(&self, payload: &[u8]) -> Result<Vector<u8>, AuthorityDispatchError> {
        let request = parse_authority_receipt(payload).map_err(map_git_error)?;
        if request.signature.len() != RECEIPT_SIGNATURE_BYTES {
            return Err(AuthorityDispatchError::Unauthorized);
        }
        let signature: &[u8; RECEIPT_SIGNATURE_BYTES] = (&request.signature[..])
            .try_into()
            .map_err(|_| AuthorityDispatchError::Unauthorized)?;
        let transcript = receipt_signature_transcript(&request.transcript)?;
        if !ed25519_verify(&ed25519_public(&self.receipt_key), &transcript, signature) {
            return Err(AuthorityDispatchError::Unauthorized);
        }
        Ok(Vector::new())
    }

    fn current_policy(&self) -> Result<TrustPolicyState, AuthorityDispatchError> {
        self.policy
            .load()
            .map_err(|_| AuthorityDispatchError::Unavailable)
    }
}

fn receipt_signature_transcript(payload: &[u8]) -> Result<Vector<u8>, AuthorityDispatchError> {
    let length = u32::try_from(payload.len()).map_err(|_| AuthorityDispatchError::Resource)?;
    let mut output = Vector::new();
    output
        .try_extend_from_slice(RECEIPT_DOMAIN)
        .and_then(|_| output.try_extend_from_slice(&length.to_be_bytes()))
        .and_then(|_| output.try_extend_from_slice(payload))
        .map_err(|_| AuthorityDispatchError::Resource)?;
    Ok(output)
}

impl Drop for ProductionAuthority {
    fn drop(&mut self) {
        erase_secret_bytes(&mut self.receipt_key);
    }
}

fn map_git_error(error: GitdCoreError) -> AuthorityDispatchError {
    match error {
        GitdCoreError::Resource => AuthorityDispatchError::Resource,
        GitdCoreError::Authorization
        | GitdCoreError::Policy
        | GitdCoreError::Signature
        | GitdCoreError::StaleGeneration => AuthorityDispatchError::Unauthorized,
        _ => AuthorityDispatchError::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_crypto::{
        ml_dsa_65_keygen, ml_dsa_65_sign, ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
    };
    use mrml_git::{
        canonical_hybrid_transcript, encode_authority_commit, encode_authority_receipt,
        encode_authority_receive, encode_authority_ref_transaction,
        encode_loose_object_with_format, CandidateRefTransaction, CandidateRefUpdate,
        DetachedCommitProofRecord, FullRefName, GitObjectType, ObjectFormat, ObjectId, ObjectKind,
        PolicyPairStatus, ProtectedReceiveAuthorization, RepositoryGeneration, RepositoryIdentity,
        RevocationGeneration, TrustGeneration, TrustPolicyCandidate,
    };
    use mrml_openpgp::{
        sign_detached_v6_ascii_with_salt, DigestAlgorithm, SigningKeyV6,
        MAX_OPENPGP_SIGNATURE_BYTES,
    };
    use mrml_runtime::{join_path, Vector};

    #[test]
    fn exact_policy_refs_and_receipts_dispatch_fail_closed() {
        let root = join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-production-authority-{}", mrml_runtime::process_id()),
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        mrml_runtime::create_dir_all(&root).unwrap();
        let repository = RepositoryIdentity::parse("owner/protected").unwrap();
        let openpgp = SigningKeyV6::from_seed([7; 32], 1_700_000_000).unwrap();
        let public = openpgp.public_key();
        let mut ml_public = [0; ML_DSA_65_PUBLIC_KEY_BYTES];
        let mut ml_secret = [0; ML_DSA_65_SECRET_KEY_BYTES];
        ml_dsa_65_keygen(&[9; 32], &mut ml_public, &mut ml_secret).unwrap();
        let pair = AuthorizedHybridPair::bind(&public, &ml_public);
        let cutover = ObjectId::from_bytes(ObjectFormat::Sha256, &[5; 32]).unwrap();
        let policy = TrustPolicyState::establish(TrustPolicyCandidate {
            repository: repository.clone(),
            generation: TrustGeneration(4),
            previous_policy_digest: [0; 64],
            revocation_generation: RevocationGeneration(8),
            protected_refs: [FullRefName::parse("refs/heads/main").unwrap()].into(),
            allow_sha1: false,
            allow_sha256: true,
            hybrid_required: true,
            legacy_checkpoint: None,
            hybrid_cutover: Some(cutover),
            emergency_policy_digest: None,
            active_pairs: [pair].into(),
            pair_statuses: [
                PolicyPairStatus::new(pair, 1_700_000_000, 1_800_000_000, None).unwrap(),
            ]
            .into(),
            legacy_v4_statuses: Vector::new(),
            revoked_legacy_v4: Vector::new(),
            revoked_openpgp: Vector::new(),
            revoked_ml_dsa: Vector::new(),
        })
        .unwrap();
        let policy_store =
            LinuxDurableTrustPolicyStore::create(&join_path(&root, "policy"), &policy).unwrap();
        let proofs =
            DurableDetachedCommitProofDirectory::open(&join_path(&root, "proofs")).unwrap();
        let contents =
            b"tree 0123456789012345678901234567890123456789012345678901234567890123\n\nmessage\n";
        let commit =
            encode_loose_object_with_format(ObjectFormat::Sha256, ObjectKind::Commit, contents).0;
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
        let mut openpgp_signature = [0; MAX_OPENPGP_SIGNATURE_BYTES];
        let openpgp_length = sign_detached_v6_ascii_with_salt(
            &openpgp,
            &transcript,
            DigestAlgorithm::Sha512,
            1_700_000_001,
            &[11; 32],
            &mut openpgp_signature,
        )
        .unwrap();
        let mut ml_signature = [0; ML_DSA_65_SIGNATURE_BYTES];
        ml_dsa_65_sign(
            &ml_secret,
            b"mrml.git.hybrid.v1",
            &transcript,
            &[13; 32],
            &mut ml_signature,
        )
        .unwrap();
        erase_secret_bytes(&mut ml_secret);
        let context = ProtectedHistoryContext {
            repository: &repository,
            repository_generation: RepositoryGeneration(3),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(8),
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha256,
        };
        let proof = DetachedCommitProofRecord::new(
            commit,
            &openpgp_signature[..openpgp_length],
            &ml_signature,
        )
        .unwrap();
        let mut authority = ProductionAuthority::new(
            policy_store,
            proofs,
            public,
            ml_public,
            [0x33; 32],
            1_700_000_002,
            RepositoryGeneration(3),
        )
        .unwrap();
        let receive = ProtectedReceiveAuthorization {
            repository: repository.clone(),
            repository_generation: RepositoryGeneration(3),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(8),
            policy_digest: policy.digest(),
        };
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::InstallProof,
                &mrml_git::encode_authority_proof_install(context, commit, contents, &proof)
                    .unwrap()
            ),
            Ok(Vector::new())
        );
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::InstallProof,
                &mrml_git::encode_authority_proof_install(context, commit, b"substituted", &proof)
                    .unwrap()
            ),
            Err(AuthorityDispatchError::Unauthorized)
        );
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::AuthorizeReceive,
                &encode_authority_receive(&receive).unwrap()
            ),
            Ok(Vector::new())
        );
        let mut wrong = receive.clone();
        wrong.policy_digest[0] ^= 1;
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::AuthorizeReceive,
                &encode_authority_receive(&wrong).unwrap()
            ),
            Err(AuthorityDispatchError::Unauthorized)
        );
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::VerifyCommit,
                &encode_authority_commit(context, commit, contents).unwrap()
            ),
            Ok(Vector::new())
        );
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::VerifyCommit,
                &encode_authority_commit(context, commit, b"substituted").unwrap()
            ),
            Err(AuthorityDispatchError::Unauthorized)
        );
        let transaction = CandidateRefTransaction {
            repository,
            repository_generation: RepositoryGeneration(3),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(8),
            updates: [CandidateRefUpdate {
                name: FullRefName::parse("refs/heads/main").unwrap(),
                expected_old: Some(cutover),
                proposed_new: Some(ObjectId::from_bytes(ObjectFormat::Sha256, &[6; 32]).unwrap()),
            }]
            .into(),
        };
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::AuthorizeRefTransaction,
                &encode_authority_ref_transaction(&transaction, policy.digest()).unwrap()
            ),
            Ok(Vector::new())
        );
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::AuthorizeRefTransaction,
                &encode_authority_ref_transaction(&transaction, [0; 64]).unwrap()
            ),
            Err(AuthorityDispatchError::Unauthorized)
        );
        let sign_request = encode_authority_receipt(b"receipt transcript", &[]).unwrap();
        let signature = authority
            .dispatch(AuthorityOperation::SignReceipt, &sign_request)
            .unwrap();
        assert_eq!(signature.len(), RECEIPT_SIGNATURE_BYTES);
        let signature_array: &[u8; RECEIPT_SIGNATURE_BYTES] =
            (&signature[..]).try_into().unwrap();
        assert!(ed25519_verify(
            &authority.receipt_verification_key(),
            &receipt_signature_transcript(b"receipt transcript").unwrap(),
            signature_array
        ));
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::VerifyReceipt,
                &encode_authority_receipt(b"receipt transcript", &signature).unwrap()
            ),
            Ok(Vector::new())
        );
        let mut tampered = signature.clone();
        tampered[0] ^= 1;
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::VerifyReceipt,
                &encode_authority_receipt(b"receipt transcript", &tampered).unwrap()
            ),
            Err(AuthorityDispatchError::Unauthorized)
        );
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
