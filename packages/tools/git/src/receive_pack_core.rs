//! Bounded receive-pack composition for an injected edge transport.

use crate::{
    ActiveRefState, AuditReceiptAuthority, AuthenticatedReceiveStore, BoundedRead, BoundedWrite,
    GitdCoreError, HistoryVerificationLimits, LinuxDurableReceiveStore, ProtectedCommitVerifier,
    QuarantineLimits, QuarantineTransactionId, Repository, SmartGitRequest, SmartGitResponse,
    TrustPolicyState, WorkBudget, finish_prepared_protected_receive,
    prepare_policy_classified_receive, prepare_protected_receive,
};

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
        finish_prepared_protected_receive(
            prepared,
            &mut authenticated,
            output,
            self.work_budget,
        )
    }
}

