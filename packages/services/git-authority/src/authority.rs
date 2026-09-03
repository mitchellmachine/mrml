use mrml_crypto::{
    ed25519_public, ed25519_sign, ed25519_verify, erase_secret_bytes, Sha3_512,
    ML_DSA_65_PUBLIC_KEY_BYTES,
};
use mrml_git::{
    authority_receipt_signature_transcript, bind_verified_commit_proof,
    candidate_activation_digest,
    encode_authority_candidate_record, parse_authority_candidate, parse_authority_candidate_lookup,
    parse_authority_candidate_proof, parse_authority_commit, parse_authority_proof_install,
    parse_authority_receipt, parse_authority_receive, parse_authority_ref_transaction,
    parse_authenticated_audit_receipt_transcript,
    verify_hybrid_signature, AuthorizedHybridPair, DurableDetachedCommitProofDirectory,
    DurableDetachedHybridCommitVerifier, GitObjectType, GitdCoreError, HybridVerificationRequest,
    LinuxDurableTrustPolicyStore, ProtectedCommitVerifier, ProtectedHistoryContext,
    RepositoryGeneration, RepositoryIdentity, SignaturePurpose, TrustPolicyState,
};
use mrml_openpgp::{PublicKeyV6, MAX_OPENPGP_SIGNATURE_BYTES};
use mrml_runtime::Vector;
use std::sync::Mutex;

use crate::{
    AuthorityCandidateContext, AuthorityCandidateStatus, AuthorityGenerationStore,
    AuthorityOperation, CandidateStoreError, GenerationStoreError, LinuxAuthorityCandidateStore,
    MemoryAuthorityGenerationStore,
};

const RECEIPT_SIGNATURE_BYTES: usize = 64;
const MAX_AUTHORITY_REPOSITORIES: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityDispatchError {
    Malformed,
    Unauthorized,
    Unavailable,
    Resource,
}

fn authority_request_repository(
    operation: AuthorityOperation,
    payload: &[u8],
) -> Result<RepositoryIdentity, AuthorityDispatchError> {
    let repository = match operation {
        AuthorityOperation::AuthorizeReceive => {
            parse_authority_receive(payload).map_err(map_git_error)?.repository
        }
        AuthorityOperation::AuthorizeRefTransaction => {
            parse_authority_ref_transaction(payload)
                .map_err(map_git_error)?
                .transaction
                .repository
        }
        AuthorityOperation::VerifyCommit => {
            parse_authority_commit(payload).map_err(map_git_error)?.repository
        }
        AuthorityOperation::InstallProof | AuthorityOperation::VerifyProof => {
            parse_authority_proof_install(payload)
                .map_err(map_git_error)?
                .repository
        }
        AuthorityOperation::InstallCandidateProof => {
            let request = parse_authority_candidate_proof(payload).map_err(map_git_error)?;
            if request.candidate.repository != request.proof.repository {
                return Err(AuthorityDispatchError::Unauthorized);
            }
            request.candidate.repository
        }
        AuthorityOperation::QueryCandidateById => {
            parse_authority_candidate_lookup(payload)
                .map_err(map_git_error)?
                .repository
        }
        AuthorityOperation::BeginCandidate
        | AuthorityOperation::SealCandidateProofSet
        | AuthorityOperation::AuthorizeCandidate
        | AuthorityOperation::StartCandidateActivation
        | AuthorityOperation::CommitCandidate
        | AuthorityOperation::AbortCandidate
        | AuthorityOperation::QueryCandidate
        | AuthorityOperation::PersistCandidateReceipt
        | AuthorityOperation::CompleteCandidate => {
            parse_authority_candidate(payload).map_err(map_git_error)?.repository
        }
        AuthorityOperation::SignReceipt | AuthorityOperation::VerifyReceipt => {
            let request = parse_authority_receipt(payload).map_err(map_git_error)?;
            parse_authenticated_audit_receipt_transcript(&request.transcript)
                .map_err(|_| AuthorityDispatchError::Malformed)?
                .repository
        }
        AuthorityOperation::Health | AuthorityOperation::VerifyLegacyCommit => {
            return Err(AuthorityDispatchError::Unauthorized);
        }
    };
    Ok(repository)
}

pub struct ProductionAuthority {
    policy: LinuxDurableTrustPolicyStore,
    proofs: DurableDetachedCommitProofDirectory,
    openpgp_key: PublicKeyV6,
    ml_dsa_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
    receipt_key: [u8; 32],
    signer_identity: [u8; 64],
    validation_time: u64,
    generations: Box<dyn AuthorityGenerationStore>,
    candidates: Option<LinuxAuthorityCandidateStore>,
}

pub struct ProductionAuthorityCatalog {
    authorities: Vector<(RepositoryIdentity, Mutex<ProductionAuthority>)>,
}

impl ProductionAuthorityCatalog {
    pub fn new(
        authorities: Vector<(RepositoryIdentity, ProductionAuthority)>,
    ) -> Result<Self, AuthorityDispatchError> {
        if authorities.is_empty() || authorities.len() > MAX_AUTHORITY_REPOSITORIES {
            return Err(AuthorityDispatchError::Resource);
        }
        let mut indexed = Vector::new();
        indexed
            .try_reserve_exact(authorities.len())
            .map_err(|_| AuthorityDispatchError::Resource)?;
        for (repository, authority) in authorities {
            if authority.repository()? != repository
                || indexed
                    .last()
                    .is_some_and(|(previous, _)| previous >= &repository)
            {
                return Err(AuthorityDispatchError::Unauthorized);
            }
            indexed.push((repository, Mutex::new(authority)));
        }
        Ok(Self {
            authorities: indexed,
        })
    }

    pub fn dispatch(
        &self,
        operation: AuthorityOperation,
        payload: &[u8],
        validation_time: u64,
    ) -> Result<Vector<u8>, AuthorityDispatchError> {
        if operation == AuthorityOperation::Health {
            if !payload.is_empty() {
                return Err(AuthorityDispatchError::Malformed);
            }
            for (_, authority) in &self.authorities {
                let mut authority = authority
                    .try_lock()
                    .map_err(|_| AuthorityDispatchError::Unavailable)?;
                authority.set_validation_time(validation_time)?;
                authority.dispatch(operation, payload)?;
            }
            return Ok((*b"ready-v1").into());
        }
        let repository = authority_request_repository(operation, payload)?;
        let index = self
            .authorities
            .binary_search_by(|(candidate, _)| candidate.cmp(&repository))
            .map_err(|_| AuthorityDispatchError::Unauthorized)?;
        let mut authority = self.authorities[index]
            .1
            .try_lock()
            .map_err(|_| AuthorityDispatchError::Unavailable)?;
        authority.set_validation_time(validation_time)?;
        authority.dispatch(operation, payload)
    }
}

impl ProductionAuthority {
    pub fn repository(&self) -> Result<RepositoryIdentity, AuthorityDispatchError> {
        self.current_policy().map(|policy| policy.repository().clone())
    }
    pub fn new(
        policy: LinuxDurableTrustPolicyStore,
        proofs: DurableDetachedCommitProofDirectory,
        openpgp_key: PublicKeyV6,
        ml_dsa_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
        receipt_key: [u8; 32],
        validation_time: u64,
        repository_generation: RepositoryGeneration,
    ) -> Result<Self, AuthorityDispatchError> {
        let repository = policy
            .load()
            .map_err(|_| AuthorityDispatchError::Unavailable)?
            .repository()
            .clone();
        Self::new_with_generation_store(
            policy,
            proofs,
            openpgp_key,
            ml_dsa_key,
            receipt_key,
            validation_time,
            Box::new(MemoryAuthorityGenerationStore::new(
                repository,
                repository_generation,
            )),
        )
    }

    pub fn new_with_generation_store(
        policy: LinuxDurableTrustPolicyStore,
        proofs: DurableDetachedCommitProofDirectory,
        openpgp_key: PublicKeyV6,
        ml_dsa_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
        receipt_key: [u8; 32],
        validation_time: u64,
        generations: Box<dyn AuthorityGenerationStore>,
    ) -> Result<Self, AuthorityDispatchError> {
        Self::new_with_stores(
            policy,
            proofs,
            openpgp_key,
            ml_dsa_key,
            receipt_key,
            validation_time,
            generations,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_stores(
        policy: LinuxDurableTrustPolicyStore,
        proofs: DurableDetachedCommitProofDirectory,
        openpgp_key: PublicKeyV6,
        ml_dsa_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
        receipt_key: [u8; 32],
        validation_time: u64,
        generations: Box<dyn AuthorityGenerationStore>,
        candidates: Option<LinuxAuthorityCandidateStore>,
    ) -> Result<Self, AuthorityDispatchError> {
        if receipt_key == [0; 32] || validation_time == 0 {
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
            generations,
            candidates,
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
            AuthorityOperation::VerifyProof => self.verify_proof(payload),
            AuthorityOperation::InstallCandidateProof => self.install_candidate_proof(payload),
            AuthorityOperation::QueryCandidateById => self.query_candidate_by_id(payload),
            AuthorityOperation::BeginCandidate => self.begin_candidate(payload),
            AuthorityOperation::SealCandidateProofSet => self.seal_candidate_proofs(payload),
            AuthorityOperation::AuthorizeCandidate => self.transition_candidate(
                payload,
                AuthorityCandidateStatus::ProofsSealed,
                AuthorityCandidateStatus::Authorized,
            ),
            AuthorityOperation::StartCandidateActivation => self.transition_candidate(
                payload,
                AuthorityCandidateStatus::Authorized,
                AuthorityCandidateStatus::ActivationStarted,
            ),
            AuthorityOperation::CommitCandidate => self.commit_candidate(payload),
            AuthorityOperation::AbortCandidate => self.abort_candidate(payload),
            AuthorityOperation::QueryCandidate => self.query_candidate(payload),
            AuthorityOperation::PersistCandidateReceipt => self.transition_candidate(
                payload,
                AuthorityCandidateStatus::Activated,
                AuthorityCandidateStatus::ReceiptPersisted,
            ),
            AuthorityOperation::CompleteCandidate => self.transition_candidate(
                payload,
                AuthorityCandidateStatus::ReceiptPersisted,
                AuthorityCandidateStatus::Completed,
            ),
            AuthorityOperation::Health => Err(AuthorityDispatchError::Malformed),
        }
    }

    fn policy_checked_candidate_context(
        &self,
        payload: &[u8],
    ) -> Result<AuthorityCandidateContext, AuthorityDispatchError> {
        let context = parse_authority_candidate(payload).map_err(map_git_error)?;
        let policy = self.current_policy()?;
        if context.repository != *policy.repository()
            || context.current_generation.0.checked_add(1) != Some(context.next_generation.0)
            || context.trust_generation != policy.generation()
            || context.revocation_generation != policy.revocation_generation()
            || context.policy_digest != policy.digest()
        {
            return Err(AuthorityDispatchError::Unauthorized);
        }
        Ok(context)
    }

    fn candidate_store(&self) -> Result<&LinuxAuthorityCandidateStore, AuthorityDispatchError> {
        self.candidates
            .as_ref()
            .ok_or(AuthorityDispatchError::Unavailable)
    }

    fn begin_candidate(&self, payload: &[u8]) -> Result<Vector<u8>, AuthorityDispatchError> {
        let context = self.policy_checked_candidate_context(payload)?;
        if self.current_generation(&context.repository)? != context.current_generation {
            return Err(AuthorityDispatchError::Unauthorized);
        }
        self.candidate_store()?
            .begin(context)
            .map_err(map_candidate_error)?;
        Ok(Vector::new())
    }

    fn transition_candidate(
        &self,
        payload: &[u8],
        expected: AuthorityCandidateStatus,
        next: AuthorityCandidateStatus,
    ) -> Result<Vector<u8>, AuthorityDispatchError> {
        let context = self.policy_checked_candidate_context(payload)?;
        let required_generation = if matches!(
            expected,
            AuthorityCandidateStatus::Activated | AuthorityCandidateStatus::ReceiptPersisted
        ) {
            context.next_generation
        } else {
            context.current_generation
        };
        if self.current_generation(&context.repository)? != required_generation {
            return Err(AuthorityDispatchError::Unauthorized);
        }
        self.candidate_store()?
            .transition(&context, expected, next)
            .map_err(map_candidate_error)?;
        Ok(Vector::new())
    }

    fn commit_candidate(&mut self, payload: &[u8]) -> Result<Vector<u8>, AuthorityDispatchError> {
        let context = self.policy_checked_candidate_context(payload)?;
        let record = self
            .candidate_store()?
            .query(context.id)
            .map_err(map_candidate_error)?;
        if record.context != context {
            return Err(AuthorityDispatchError::Unauthorized);
        }
        let generation = self.current_generation(&context.repository)?;
        match (record.status, generation) {
            (AuthorityCandidateStatus::ActivationStarted, current)
                if current == context.current_generation =>
            {
                self.candidate_store()?
                    .transition(
                        &context,
                        AuthorityCandidateStatus::ActivationStarted,
                        AuthorityCandidateStatus::Activated,
                    )
                    .map_err(map_candidate_error)?;
                self.generations
                    .commit_next(
                        &context.repository,
                        context.current_generation,
                        context.next_generation,
                    )
                    .map_err(map_generation_error)?;
            }
            (AuthorityCandidateStatus::Activated, current)
                if current == context.current_generation =>
            {
                // Recovery after the activated journal record was synced but
                // before the repository-generation replacement completed.
                self.generations
                    .commit_next(
                        &context.repository,
                        context.current_generation,
                        context.next_generation,
                    )
                    .map_err(map_generation_error)?;
            }
            (AuthorityCandidateStatus::Activated, current)
                if current == context.next_generation => {}
            _ => return Err(AuthorityDispatchError::Unauthorized),
        }
        Ok(Vector::new())
    }

    fn abort_candidate(&self, payload: &[u8]) -> Result<Vector<u8>, AuthorityDispatchError> {
        let context = parse_authority_candidate(payload).map_err(map_git_error)?;
        let current = self
            .candidate_store()?
            .query(context.id)
            .map_err(map_candidate_error)?;
        if current.context != context {
            return Err(AuthorityDispatchError::Unauthorized);
        }
        if current.status == AuthorityCandidateStatus::Aborted {
            return Ok(Vector::new());
        }
        self.candidate_store()?
            .transition(&context, current.status, AuthorityCandidateStatus::Aborted)
            .map_err(map_candidate_error)?;
        Ok(Vector::new())
    }

    fn query_candidate(&self, payload: &[u8]) -> Result<Vector<u8>, AuthorityDispatchError> {
        let context = parse_authority_candidate(payload).map_err(map_git_error)?;
        let record = self
            .candidate_store()?
            .query(context.id)
            .map_err(map_candidate_error)?;
        if record.context != context {
            return Err(AuthorityDispatchError::Unauthorized);
        }
        encode_authority_candidate_record(&record).map_err(map_git_error)
    }

    fn query_candidate_by_id(
        &self,
        payload: &[u8],
    ) -> Result<Vector<u8>, AuthorityDispatchError> {
        let lookup = parse_authority_candidate_lookup(payload).map_err(map_git_error)?;
        let policy = self.current_policy()?;
        if lookup.repository != *policy.repository() {
            return Err(AuthorityDispatchError::Unauthorized);
        }
        let record = self
            .candidate_store()?
            .query(lookup.id)
            .map_err(map_candidate_error)?;
        if record.context.repository != lookup.repository {
            return Err(AuthorityDispatchError::Unauthorized);
        }
        encode_authority_candidate_record(&record).map_err(map_git_error)
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
            || request.repository_generation != self.current_generation(policy.repository())?
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
            || transaction.repository_generation != self.current_generation(policy.repository())?
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
            || request.repository_generation != self.current_generation(policy.repository())?
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
        if self.candidates.is_some() {
            return Err(AuthorityDispatchError::Unauthorized);
        }
        let request = parse_authority_proof_install(payload).map_err(map_git_error)?;
        self.verify_proof_request(&request)?;
        let context = ProtectedHistoryContext {
            repository: &request.repository,
            repository_generation: request.repository_generation,
            trust_generation: request.trust_generation,
            revocation_generation: request.revocation_generation,
            purpose: request.purpose,
            object_format: request.object_format,
        };
        match self.proofs.insert(context, &request.proof) {
            Ok(()) => {}
            Err(mrml_git::DetachedCommitProofFileError::AlreadyExists) => {
                self.verify_installed_proof(&request)?;
            }
            Err(_) => return Err(AuthorityDispatchError::Unavailable),
        }
        Ok(Vector::new())
    }

    fn verify_proof(&self, payload: &[u8]) -> Result<Vector<u8>, AuthorityDispatchError> {
        let request = parse_authority_proof_install(payload).map_err(map_git_error)?;
        self.verify_proof_request(&request)?;
        Ok(Vector::new())
    }

    fn install_candidate_proof(
        &self,
        payload: &[u8],
    ) -> Result<Vector<u8>, AuthorityDispatchError> {
        let request = parse_authority_candidate_proof(payload).map_err(map_git_error)?;
        let encoded_candidate = mrml_git::encode_authority_candidate(&request.candidate)
            .map_err(map_git_error)?;
        let candidate = self.policy_checked_candidate_context(&encoded_candidate)?;
        self.verify_proof_request(&request.proof)?;
        let proof_context = ProtectedHistoryContext {
            repository: &request.proof.repository,
            repository_generation: request.proof.repository_generation,
            trust_generation: request.proof.trust_generation,
            revocation_generation: request.proof.revocation_generation,
            purpose: request.proof.purpose,
            object_format: request.proof.object_format,
        };
        self.candidate_store()?
            .install_proof(&candidate, proof_context, &request.proof.proof)
            .map_err(map_candidate_error)?;
        Ok(Vector::new())
    }

    fn seal_candidate_proofs(
        &self,
        payload: &[u8],
    ) -> Result<Vector<u8>, AuthorityDispatchError> {
        let context = self.policy_checked_candidate_context(payload)?;
        self.candidate_store()?
            .seal_proofs(&context)
            .map_err(map_candidate_error)?;
        self.transition_candidate(
            payload,
            AuthorityCandidateStatus::Receiving,
            AuthorityCandidateStatus::ProofsSealed,
        )
    }

    fn verify_proof_request(
        &self,
        request: &mrml_git::AuthorityProofInstallRequest,
    ) -> Result<(), AuthorityDispatchError> {
        let policy = self.current_policy()?;
        if request.repository != *policy.repository()
            || request.repository_generation != self.current_generation(policy.repository())?
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
        Ok(())
    }

    fn verify_installed_proof(
        &self,
        request: &mrml_git::AuthorityProofInstallRequest,
    ) -> Result<(), AuthorityDispatchError> {
        let policy = self.current_policy()?;
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
        Ok(())
    }

    fn sign_receipt(&mut self, payload: &[u8]) -> Result<Vector<u8>, AuthorityDispatchError> {
        let request = parse_authority_receipt(payload).map_err(map_git_error)?;
        if !request.signature.is_empty() {
            return Err(AuthorityDispatchError::Malformed);
        }
        let receipt = parse_authenticated_audit_receipt_transcript(&request.transcript)
            .map_err(|_| AuthorityDispatchError::Malformed)?;
        let policy = self.current_policy()?;
        let current = self.current_generation(policy.repository())?;
        if receipt.repository != *policy.repository()
            || receipt.trust_generation != policy.generation()
            || receipt.revocation_generation != policy.revocation_generation()
        {
            return Err(AuthorityDispatchError::Unauthorized);
        }
        let candidate = if let Some(candidates) = &self.candidates {
            let record = candidates
                .query(receipt.transaction)
                .map_err(map_candidate_error)?;
            if record.context.repository != receipt.repository
                || record.context.current_generation != receipt.repository_generation
                || record.context.next_generation != receipt.activated_repository_generation
                || record.context.trust_generation != receipt.trust_generation
                || record.context.revocation_generation != receipt.revocation_generation
                || record.context.policy_digest != policy.digest()
                || record.context.activation_digest != candidate_activation_digest(&request.transcript)
                || current != record.context.next_generation
                || !matches!(
                    record.status,
                    AuthorityCandidateStatus::Activated
                        | AuthorityCandidateStatus::ReceiptPersisted
                )
            {
                return Err(AuthorityDispatchError::Unauthorized);
            }
            Some(record)
        } else {
            if receipt.repository_generation != current
                || receipt.activated_repository_generation.0
                    != current
                        .0
                        .checked_add(1)
                        .ok_or(AuthorityDispatchError::Resource)?
            {
                return Err(AuthorityDispatchError::Unauthorized);
            }
            None
        };
        let transcript = authority_receipt_signature_transcript(&request.transcript)
            .map_err(|_| AuthorityDispatchError::Resource)?;
        let signature = ed25519_sign(&self.receipt_key, &transcript);
        if let Some(record) = candidate {
            if record.status == AuthorityCandidateStatus::Activated {
                self.candidate_store()?
                    .transition(
                        &record.context,
                        AuthorityCandidateStatus::Activated,
                        AuthorityCandidateStatus::ReceiptPersisted,
                    )
                    .map_err(map_candidate_error)?;
            }
        } else {
            self.generations
                .commit_next(
                    policy.repository(),
                    current,
                    receipt.activated_repository_generation,
                )
                .map_err(map_generation_error)?;
        }
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
        let transcript = authority_receipt_signature_transcript(&request.transcript)
            .map_err(|_| AuthorityDispatchError::Resource)?;
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

    fn current_generation(
        &self,
        repository: &mrml_git::RepositoryIdentity,
    ) -> Result<RepositoryGeneration, AuthorityDispatchError> {
        self.generations
            .current(repository)
            .map_err(map_generation_error)
    }
}

fn map_generation_error(error: GenerationStoreError) -> AuthorityDispatchError {
    match error {
        GenerationStoreError::Stale | GenerationStoreError::Invalid => {
            AuthorityDispatchError::Unauthorized
        }
        GenerationStoreError::Unavailable => AuthorityDispatchError::Unavailable,
    }
}

fn map_candidate_error(error: CandidateStoreError) -> AuthorityDispatchError {
    match error {
        CandidateStoreError::AlreadyExists
        | CandidateStoreError::Invalid
        | CandidateStoreError::Missing
        | CandidateStoreError::Stale => AuthorityDispatchError::Unauthorized,
        CandidateStoreError::Unavailable => AuthorityDispatchError::Unavailable,
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
        ml_dsa_65_keygen, ml_dsa_65_sign, ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
    };
    use mrml_git::{
        authenticated_audit_receipt_transcript, candidate_proof_set_digest,
        canonical_hybrid_transcript,
        encode_audit_receipt, encode_authority_candidate, encode_authority_commit,
        encode_authority_receipt, encode_authority_receive, encode_authority_ref_transaction,
        encode_loose_object_with_format, parse_authority_candidate_record, AuditReceipt,
        AuthorityCandidateContext, AuthorityCandidateStatus, CandidateRefTransaction,
        CandidateRefUpdate, DetachedCommitProofRecord, FullRefName, GitObjectType, ObjectFormat,
        ObjectId, ObjectKind, PolicyPairStatus, ProtectedReceiveAuthorization,
        QuarantineTransactionId, RepositoryGeneration, RepositoryIdentity, RevocationGeneration,
        TrustGeneration, TrustPolicyCandidate,
    };
    use mrml_openpgp::{
        sign_detached_v6_ascii_with_salt, DigestAlgorithm, SigningKeyV6,
        MAX_OPENPGP_SIGNATURE_BYTES,
    };
    use mrml_runtime::{join_path, Vector};
    use std::os::unix::fs::MetadataExt;

    fn catalog_authority(
        root: &str,
        repository: &str,
        seed: u8,
    ) -> (ProductionAuthority, TrustPolicyState) {
        mrml_runtime::create_dir_all(root).unwrap();
        let repository = RepositoryIdentity::parse(repository).unwrap();
        let openpgp = SigningKeyV6::from_seed([seed; 32], 1_700_000_000).unwrap();
        let public = openpgp.public_key();
        let mut ml_public = [0; ML_DSA_65_PUBLIC_KEY_BYTES];
        let mut ml_secret = [0; ML_DSA_65_SECRET_KEY_BYTES];
        ml_dsa_65_keygen(&[seed.wrapping_add(1); 32], &mut ml_public, &mut ml_secret).unwrap();
        let pair = AuthorizedHybridPair::bind(&public, &ml_public);
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
            hybrid_cutover: Some(ObjectId::from_bytes(ObjectFormat::Sha256, &[seed; 32]).unwrap()),
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
            LinuxDurableTrustPolicyStore::create(&join_path(root, "policy"), &policy).unwrap();
        let proofs = DurableDetachedCommitProofDirectory::open(&join_path(root, "proofs")).unwrap();
        let authority = ProductionAuthority::new_with_generation_store(
            policy_store,
            proofs,
            public,
            ml_public,
            [seed.wrapping_add(2); 32],
            1_700_000_002,
            Box::new(MemoryAuthorityGenerationStore::new(
                repository,
                RepositoryGeneration(3),
            )),
        )
        .unwrap();
        erase_secret_bytes(&mut ml_secret);
        (authority, policy)
    }

    #[test]
    fn catalog_routes_exact_repositories_and_isolates_stalled_locks() {
        let root = join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-authority-catalog-{}", mrml_runtime::process_id()),
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        let first_root = join_path(&root, "first");
        let second_root = join_path(&root, "second");
        let (first, first_policy) = catalog_authority(&first_root, "owner/first", 0x31);
        let (second, second_policy) = catalog_authority(&second_root, "owner/second", 0x41);
        let catalog = std::sync::Arc::new(
            ProductionAuthorityCatalog::new(
                [
                    (RepositoryIdentity::parse("owner/first").unwrap(), first),
                    (RepositoryIdentity::parse("owner/second").unwrap(), second),
                ]
                .into(),
            )
            .unwrap(),
        );
        let receive = |repository: &str, policy: &TrustPolicyState| {
            encode_authority_receive(&ProtectedReceiveAuthorization {
                repository: RepositoryIdentity::parse(repository).unwrap(),
                repository_generation: RepositoryGeneration(3),
                trust_generation: TrustGeneration(4),
                revocation_generation: RevocationGeneration(8),
                policy_digest: policy.digest(),
            })
            .unwrap()
        };
        let first_request = receive("owner/first", &first_policy);
        let second_request = receive("owner/second", &second_policy);
        assert_eq!(
            catalog.dispatch(
                AuthorityOperation::AuthorizeReceive,
                &first_request,
                1_700_000_003,
            ),
            Ok(Vector::new())
        );
        assert_eq!(
            catalog.dispatch(
                AuthorityOperation::AuthorizeReceive,
                &second_request,
                1_700_000_003,
            ),
            Ok(Vector::new())
        );

        let first_guard = catalog.authorities[0].1.lock().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let second_catalog = catalog.clone();
        let second_worker = std::thread::spawn(move || {
            sender
                .send(second_catalog.dispatch(
                    AuthorityOperation::AuthorizeReceive,
                    &second_request,
                    1_700_000_004,
                ))
                .unwrap();
        });
        assert_eq!(
            receiver.recv_timeout(std::time::Duration::from_secs(1)),
            Ok(Ok(Vector::new()))
        );
        second_worker.join().unwrap();

        let (sender, receiver) = std::sync::mpsc::channel();
        let first_catalog = catalog.clone();
        let first_worker = std::thread::spawn(move || {
            sender
                .send(first_catalog.dispatch(
                    AuthorityOperation::AuthorizeReceive,
                    &first_request,
                    1_700_000_004,
                ))
                .unwrap();
        });
        assert_eq!(
            receiver.recv_timeout(std::time::Duration::from_secs(1)),
            Ok(Err(AuthorityDispatchError::Unavailable))
        );
        drop(first_guard);
        first_worker.join().unwrap();
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

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
        let candidate_root = join_path(&root, "candidates");
        mrml_runtime::create_dir_all(&candidate_root).unwrap();
        let candidate_owner = std::fs::metadata(&*candidate_root).unwrap().uid();
        let candidate_store =
            LinuxAuthorityCandidateStore::open(&candidate_root, candidate_owner).unwrap();
        let mut authority = ProductionAuthority::new_with_stores(
            policy_store,
            proofs,
            public,
            ml_public,
            [0x33; 32],
            1_700_000_002,
            Box::new(MemoryAuthorityGenerationStore::new(
                repository.clone(),
                RepositoryGeneration(3),
            )),
            Some(candidate_store),
        )
        .unwrap();
        let receive = ProtectedReceiveAuthorization {
            repository: repository.clone(),
            repository_generation: RepositoryGeneration(3),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(8),
            policy_digest: policy.digest(),
        };
        let encoded_proof =
            mrml_git::encode_authority_proof_install(context, commit, contents, &proof).unwrap();
        assert_eq!(
            authority.dispatch(AuthorityOperation::VerifyProof, &encoded_proof),
            Ok(Vector::new())
        );
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::VerifyCommit,
                &encode_authority_commit(context, commit, contents).unwrap()
            ),
            Err(AuthorityDispatchError::Unauthorized)
        );
        assert_eq!(
            authority.dispatch(AuthorityOperation::InstallProof, &encoded_proof),
            Err(AuthorityDispatchError::Unauthorized)
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
            Err(AuthorityDispatchError::Unauthorized)
        );
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::VerifyCommit,
                &encode_authority_commit(context, commit, b"substituted").unwrap()
            ),
            Err(AuthorityDispatchError::Unauthorized)
        );
        let transaction = CandidateRefTransaction {
            repository: repository.clone(),
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
        let candidate = AuthorityCandidateContext {
            id: QuarantineTransactionId([30; 16]),
            repository: transaction.repository.clone(),
            current_generation: RepositoryGeneration(3),
            next_generation: RepositoryGeneration(4),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(8),
            policy_digest: policy.digest(),
            ref_update_digest: [1; 64],
            introduced_commit_set_digest: [2; 64],
            arrival_pack_digest: [3; 64],
            proof_set_digest: candidate_proof_set_digest(core::slice::from_ref(&proof)).unwrap(),
            activation_digest: [5; 64],
        };
        let candidate_request = encode_authority_candidate(&candidate).unwrap();
        assert_eq!(
            authority.dispatch(AuthorityOperation::BeginCandidate, &candidate_request),
            Ok(Vector::new())
        );
        assert_eq!(
            parse_authority_candidate_record(
                &authority
                    .dispatch(AuthorityOperation::QueryCandidate, &candidate_request)
                    .unwrap()
            )
            .unwrap()
            .status,
            AuthorityCandidateStatus::Receiving
        );
        assert_eq!(
            parse_authority_candidate_record(
                &authority
                    .dispatch(
                        AuthorityOperation::QueryCandidateById,
                        &mrml_git::encode_authority_candidate_lookup(
                            &candidate.repository,
                            candidate.id,
                        )
                        .unwrap(),
                    )
                    .unwrap(),
            )
            .unwrap()
            .context,
            candidate
        );
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::InstallCandidateProof,
                &mrml_git::encode_authority_candidate_proof(
                    &candidate,
                    context,
                    commit,
                    contents,
                    &proof,
                )
                .unwrap()
            ),
            Ok(Vector::new())
        );
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::SealCandidateProofSet,
                &candidate_request
            ),
            Ok(Vector::new())
        );
        assert_eq!(
            authority.dispatch(AuthorityOperation::AuthorizeCandidate, &candidate_request),
            Ok(Vector::new())
        );
        assert_eq!(
            authority.dispatch(AuthorityOperation::AbortCandidate, &candidate_request),
            Ok(Vector::new())
        );
        assert_eq!(
            authority.dispatch(AuthorityOperation::AbortCandidate, &candidate_request),
            Ok(Vector::new())
        );
        assert_eq!(
            parse_authority_candidate_record(
                &authority
                    .dispatch(AuthorityOperation::QueryCandidate, &candidate_request)
                    .unwrap()
            )
            .unwrap()
            .status,
            AuthorityCandidateStatus::Aborted
        );
        let receipt = AuditReceipt {
            transaction: QuarantineTransactionId([31; 16]),
            repository: transaction.repository.clone(),
            repository_generation: RepositoryGeneration(3),
            activated_repository_generation: RepositoryGeneration(4),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(8),
            updates: [(
                transaction.updates[0].name.clone(),
                transaction.updates[0].expected_old.unwrap(),
                transaction.updates[0].proposed_new.unwrap(),
            )]
            .into(),
        };
        let canonical_receipt = encode_audit_receipt(&receipt).unwrap();
        let receipt_transcript =
            authenticated_audit_receipt_transcript(&canonical_receipt).unwrap();
        let receipt_candidate = AuthorityCandidateContext {
            id: receipt.transaction,
            repository: receipt.repository.clone(),
            current_generation: receipt.repository_generation,
            next_generation: receipt.activated_repository_generation,
            trust_generation: receipt.trust_generation,
            revocation_generation: receipt.revocation_generation,
            policy_digest: policy.digest(),
            ref_update_digest: [11; 64],
            introduced_commit_set_digest: [12; 64],
            arrival_pack_digest: [13; 64],
            proof_set_digest: candidate_proof_set_digest(core::slice::from_ref(&proof)).unwrap(),
            activation_digest: candidate_activation_digest(&receipt_transcript),
        };
        let receipt_candidate_request = encode_authority_candidate(&receipt_candidate).unwrap();
        assert_eq!(
            authority.dispatch(AuthorityOperation::BeginCandidate, &receipt_candidate_request),
            Ok(Vector::new())
        );
        let receipt_proof_context = ProtectedHistoryContext {
            repository: &repository,
            repository_generation: receipt.repository_generation,
            trust_generation: receipt.trust_generation,
            revocation_generation: receipt.revocation_generation,
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha256,
        };
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::InstallCandidateProof,
                &mrml_git::encode_authority_candidate_proof(
                    &receipt_candidate,
                    receipt_proof_context,
                    commit,
                    contents,
                    &proof,
                )
                .unwrap()
            ),
            Ok(Vector::new())
        );
        for operation in [
            AuthorityOperation::SealCandidateProofSet,
            AuthorityOperation::AuthorizeCandidate,
            AuthorityOperation::StartCandidateActivation,
            AuthorityOperation::CommitCandidate,
        ] {
            assert_eq!(
                authority.dispatch(operation, &receipt_candidate_request),
                Ok(Vector::new())
            );
        }
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::CommitCandidate,
                &receipt_candidate_request
            ),
            Ok(Vector::new())
        );
        let sign_request = encode_authority_receipt(&receipt_transcript, &[]).unwrap();
        let signature = authority
            .dispatch(AuthorityOperation::SignReceipt, &sign_request)
            .unwrap();
        assert_eq!(signature.len(), RECEIPT_SIGNATURE_BYTES);
        assert_eq!(
            authority.dispatch(AuthorityOperation::SignReceipt, &sign_request),
            Ok(signature.clone())
        );
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::CompleteCandidate,
                &receipt_candidate_request
            ),
            Ok(Vector::new())
        );
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::AuthorizeReceive,
                &encode_authority_receive(&receive).unwrap()
            ),
            Err(AuthorityDispatchError::Unauthorized)
        );
        let mut next_receive = receive.clone();
        next_receive.repository_generation = RepositoryGeneration(4);
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::AuthorizeReceive,
                &encode_authority_receive(&next_receive).unwrap()
            ),
            Ok(Vector::new())
        );
        let signature_array: &[u8; RECEIPT_SIGNATURE_BYTES] =
            (&signature[..]).try_into().unwrap();
        assert!(ed25519_verify(
            &authority.receipt_verification_key(),
            &authority_receipt_signature_transcript(&receipt_transcript).unwrap(),
            signature_array
        ));
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::VerifyReceipt,
                &encode_authority_receipt(&receipt_transcript, &signature).unwrap()
            ),
            Ok(Vector::new())
        );
        let mut tampered = signature.clone();
        tampered[0] ^= 1;
        assert_eq!(
            authority.dispatch(
                AuthorityOperation::VerifyReceipt,
                &encode_authority_receipt(&receipt_transcript, &tampered).unwrap()
            ),
            Err(AuthorityDispatchError::Unauthorized)
        );
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
