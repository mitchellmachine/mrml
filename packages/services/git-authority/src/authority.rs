use mrml_crypto::{ML_DSA_65_PUBLIC_KEY_BYTES, Sha3_512, erase_secret_bytes, hmac_sha256};
use mrml_git::{
    AuthorizedHybridPair, DurableDetachedCommitProofDirectory, DurableDetachedHybridCommitVerifier,
    GitdCoreError, LinuxDurableTrustPolicyStore, ProtectedCommitVerifier, ProtectedHistoryContext,
    RepositoryGeneration, SignaturePurpose, TrustPolicyState, parse_authority_commit,
    parse_authority_receipt, parse_authority_receive, parse_authority_ref_transaction,
};
use mrml_openpgp::{MAX_OPENPGP_SIGNATURE_BYTES, PublicKeyV6};
use mrml_runtime::Vector;

use crate::AuthorityOperation;

const RECEIPT_DOMAIN: &[u8] = b"MRML git authority receipt signing v1";

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
        identity.update(&receipt_key);
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
            AuthorityOperation::Health => Err(AuthorityDispatchError::Malformed),
        }
    }

    fn health(&self) -> Result<Vector<u8>, AuthorityDispatchError> {
        self.policy
            .load()
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

    fn sign_receipt(&self, payload: &[u8]) -> Result<Vector<u8>, AuthorityDispatchError> {
        let request = parse_authority_receipt(payload).map_err(map_git_error)?;
        if !request.signature.is_empty() {
            return Err(AuthorityDispatchError::Malformed);
        }
        let signature = hmac_sha256(&self.receipt_key, &[RECEIPT_DOMAIN, &request.transcript]);
        let mut output = Vector::new();
        output
            .try_extend_from_slice(&signature)
            .map_err(|_| AuthorityDispatchError::Resource)?;
        Ok(output)
    }

    fn verify_receipt(&self, payload: &[u8]) -> Result<Vector<u8>, AuthorityDispatchError> {
        let request = parse_authority_receipt(payload).map_err(map_git_error)?;
        if request.signature.len() != 32 {
            return Err(AuthorityDispatchError::Unauthorized);
        }
        let expected = hmac_sha256(&self.receipt_key, &[RECEIPT_DOMAIN, &request.transcript]);
        let mut difference = 0u8;
        for index in 0..expected.len() {
            difference |= expected[index] ^ request.signature[index];
        }
        if difference != 0 {
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
        ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES, ml_dsa_65_keygen, ml_dsa_65_sign,
    };
    use mrml_git::{
        CandidateRefTransaction, CandidateRefUpdate, DetachedCommitProofRecord, FullRefName,
        GitObjectType, ObjectFormat, ObjectId, ObjectKind, PolicyPairStatus,
        ProtectedReceiveAuthorization, RepositoryGeneration, RepositoryIdentity,
        RevocationGeneration, TrustGeneration, TrustPolicyCandidate, canonical_hybrid_transcript,
        encode_authority_commit, encode_authority_receipt, encode_authority_receive,
        encode_authority_ref_transaction, encode_loose_object_with_format,
    };
    use mrml_openpgp::{
        DigestAlgorithm, MAX_OPENPGP_SIGNATURE_BYTES, SigningKeyV6,
        sign_detached_v6_ascii_with_salt,
    };
    use mrml_runtime::{Vector, join_path};

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
        proofs
            .insert(
                context,
                &DetachedCommitProofRecord::new(
                    commit,
                    &openpgp_signature[..openpgp_length],
                    &ml_signature,
                )
                .unwrap(),
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
        assert_eq!(signature.len(), 32);
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
