//! Bounded receive-pack composition for an injected edge transport.

use crate::receive_backend::prepare_authority_classified_receive;
use crate::{
    ActiveRefState, AuditReceiptAuthority, AuthenticatedReceiveStore, BoundedRead, BoundedWrite,
    GitdCoreError, HistoryVerificationLimits, LinuxDurableReceiveStore, ProtectedCommitVerifier,
    QuarantineLimits, QuarantineTransactionId, Repository, RepositoryGeneration,
    RepositoryIdentity, RevocationGeneration, SmartGitRequest, SmartGitResponse, TrustGeneration,
    TrustPolicyState, WorkBudget, finish_prepared_protected_receive,
    prepare_policy_classified_receive, prepare_protected_receive,
};

/// Exact public context presented to the capability-bearing protected Git
/// service. It contains no secret key material and cannot itself authorize a
/// receive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedReceiveAuthorization {
    pub repository: RepositoryIdentity,
    pub repository_generation: RepositoryGeneration,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    pub policy_digest: [u8; 64],
}

/// Narrow injected service authority for a production protected receive.
/// Implementations may keep signing keys and key-policy databases isolated;
/// this API exposes only exact-context authorization, commit verification, and
/// purpose-separated receipt signing.
pub trait ProtectedReceiveAuthority: ProtectedCommitVerifier + AuditReceiptAuthority {
    fn authorize_receive(
        &mut self,
        request: &ProtectedReceiveAuthorization,
    ) -> Result<(), GitdCoreError>;

    fn authorize_ref_transaction(
        &mut self,
        transaction: &crate::CandidateRefTransaction,
        policy_digest: [u8; 64],
    ) -> Result<(), GitdCoreError>;
}

struct AuthorityVerifier<'a> {
    authority: &'a mut dyn ProtectedReceiveAuthority,
    policy_digest: [u8; 64],
}

impl ProtectedCommitVerifier for AuthorityVerifier<'_> {
    fn begin_receive_proofs(
        &mut self,
        proofs: &[crate::DetachedCommitProofRecord],
    ) -> Result<(), GitdCoreError> {
        self.authority.begin_receive_proofs(proofs)
    }

    fn authorize_transaction(
        &mut self,
        transaction: &crate::CandidateRefTransaction,
    ) -> Result<(), GitdCoreError> {
        self.authority
            .authorize_ref_transaction(transaction, self.policy_digest)
    }

    fn verify_commit(
        &mut self,
        context: crate::ProtectedHistoryContext<'_>,
        commit: crate::ObjectId,
        exact_contents: &[u8],
    ) -> Result<crate::VerifiedCommitProof, crate::HistoryVerificationError> {
        self.authority
            .verify_commit(context, commit, exact_contents)
    }

    fn verify_legacy_commit(
        &mut self,
        context: crate::ProtectedHistoryContext<'_>,
        commit: crate::ObjectId,
        exact_contents: &[u8],
    ) -> Result<crate::VerifiedLegacyCommitProof, crate::HistoryVerificationError> {
        self.authority
            .verify_legacy_commit(context, commit, exact_contents)
    }

    fn finish_receive_proofs(&mut self) -> Result<(), GitdCoreError> {
        self.authority.finish_receive_proofs()
    }
}

/// Exact per-request authority and resource envelope supplied by a gitd edge.
/// Verification and receipt-signing implementations are injected separately;
/// this value contains no private key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivePackCore {
    pub request: SmartGitRequest,
    pub transaction: QuarantineTransactionId,
    pub quarantine_limits: QuarantineLimits,
    pub history_limits: HistoryVerificationLimits,
    pub ordinary_free_bytes: u64,
    pub work_budget: WorkBudget,
}

impl ReceivePackCore {
    /// Production composition using one injected capability-bearing authority.
    /// Authorization is checked before any request byte is consumed or
    /// quarantine state is created. The same authority then verifies every
    /// introduced commit and authenticates the final durable receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_authority(
        &self,
        active: &ActiveRefState,
        active_objects: &Repository,
        store: &mut LinuxDurableReceiveStore,
        policy: &TrustPolicyState,
        signed_receipts_path: &str,
        authority: &mut dyn ProtectedReceiveAuthority,
        input: &mut dyn BoundedRead,
        output: &mut dyn BoundedWrite,
    ) -> Result<SmartGitResponse, GitdCoreError> {
        if self.request.repository != active.repository
            || self.request.repository_generation != active.repository_generation
            || self.request.object_format != active.object_format
            || policy.repository() != &active.repository
            || policy.generation() != active.trust_generation
            || policy.revocation_generation() != active.revocation_generation
        {
            return Err(GitdCoreError::Authorization);
        }
        authority.authorize_receive(&ProtectedReceiveAuthorization {
            repository: active.repository.clone(),
            repository_generation: active.repository_generation,
            trust_generation: active.trust_generation,
            revocation_generation: active.revocation_generation,
            policy_digest: policy.digest(),
        })?;
        let prepared = prepare_authority_classified_receive(
            self.request.clone(),
            active,
            active_objects,
            store,
            &mut AuthorityVerifier {
                authority,
                policy_digest: policy.digest(),
            },
            policy,
            self.transaction,
            self.quarantine_limits,
            self.history_limits,
            self.ordinary_free_bytes,
            input,
            self.work_budget,
        )?;
        self.finish(prepared, store, signed_receipts_path, authority, output)
    }

    /// Parses, quarantines, verifies, durably activates, and reports one atomic
    /// protected receive. Every authority-bearing dependency is injected.
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        &self,
        active: &ActiveRefState,
        active_objects: &Repository,
        store: &mut LinuxDurableReceiveStore,
        verifier: &mut dyn ProtectedCommitVerifier,
        signed_receipts_path: &str,
        receipt_authority: &mut dyn AuditReceiptAuthority,
        input: &mut dyn BoundedRead,
        output: &mut dyn BoundedWrite,
    ) -> Result<SmartGitResponse, GitdCoreError> {
        let prepared = prepare_protected_receive(
            self.request.clone(),
            active,
            active_objects,
            store,
            verifier,
            self.transaction,
            self.quarantine_limits,
            self.history_limits,
            self.ordinary_free_bytes,
            input,
            self.work_budget,
        )?;
        self.finish(
            prepared,
            store,
            signed_receipts_path,
            receipt_authority,
            output,
        )
    }

    /// Policy-classified variant preserving the same bounded composition.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_policy_classified(
        &self,
        active: &ActiveRefState,
        active_objects: &Repository,
        store: &mut LinuxDurableReceiveStore,
        verifier: &mut dyn ProtectedCommitVerifier,
        policy: &TrustPolicyState,
        signed_receipts_path: &str,
        receipt_authority: &mut dyn AuditReceiptAuthority,
        input: &mut dyn BoundedRead,
        output: &mut dyn BoundedWrite,
    ) -> Result<SmartGitResponse, GitdCoreError> {
        let prepared = prepare_policy_classified_receive(
            self.request.clone(),
            active,
            active_objects,
            store,
            verifier,
            policy,
            self.transaction,
            self.quarantine_limits,
            self.history_limits,
            self.ordinary_free_bytes,
            input,
            self.work_budget,
        )?;
        self.finish(
            prepared,
            store,
            signed_receipts_path,
            receipt_authority,
            output,
        )
    }

    fn finish(
        &self,
        prepared: crate::PreparedProtectedReceive,
        store: &mut LinuxDurableReceiveStore,
        signed_receipts_path: &str,
        receipt_authority: &mut dyn AuditReceiptAuthority,
        output: &mut dyn BoundedWrite,
    ) -> Result<SmartGitResponse, GitdCoreError> {
        let mut authenticated =
            AuthenticatedReceiveStore::new(store, signed_receipts_path, receipt_authority)
                .map_err(|_| GitdCoreError::Storage)?;
        finish_prepared_protected_receive(prepared, &mut authenticated, output, self.work_budget)
    }
}
