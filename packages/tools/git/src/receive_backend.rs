//! Protected receive preparation before signed audit-receipt activation.

use mrml_runtime::Vector;

use crate::{
    authenticated_audit_receipt_transcript, build_verified_fast_forward_transaction,
    candidate_activation_digest, candidate_arrival_pack_digest, candidate_proof_set_digest,
    candidate_ref_update_digest, durably_activate_verified_receive, encode_audit_receipt,
    expected_audit_receipt, read_receive_pack_commands, reserve_push_disk_before_body,
    verify_conventional_introduced_history, verify_policy_classified_history,
    verify_protected_introduced_history, write_receive_pack_report, ActiveRefState, AuditReceipt,
    AuthenticatedReceiveStore, BoundedWrite, DurableReceiveError, DurableReceiveStore,
    GitdCoreError, HistoryVerificationError, HistoryVerificationLimits, LinuxDurableReceiveStore,
    Object, ObjectFormat, ObjectId, ObjectKind, ProtectedHistoryContext, ProtocolBudget, QuarantineLimits,
    QuarantineTransaction, QuarantineTransactionId, ReceivePackRequest, ReceiveRefStatus,
    Repository, SignaturePurpose, SmartGitOperation, SmartGitRequest, SmartGitResponse,
    TrustPolicyState, VerifiedCommitProof, VerifiedLegacyCommitProof, VerifiedRefTransaction,
    AuthorityCandidateContext, WorkBudget,
};
use crate::pack_set::AuthenticatedPackIndexSummary;

/// Verification-only authority. Implementations receive public policy/key state
/// and exact commit bytes; no signing key belongs at this boundary.
pub trait ProtectedCommitVerifier {
    /// Begin one receive's bounded detached-proof set. Implementations that do
    /// not support proof installation reject non-empty sets by default.
    fn begin_receive_proofs(
        &mut self,
        proofs: &[crate::DetachedCommitProofRecord],
    ) -> Result<(), GitdCoreError> {
        if proofs.is_empty() {
            Ok(())
        } else {
            Err(GitdCoreError::Authorization)
        }
    }

    /// Optional exact ref-transaction authorization used by the production
    /// authority composition after command parsing and before pack admission.
    fn authorize_transaction(
        &mut self,
        _: &crate::CandidateRefTransaction,
    ) -> Result<(), GitdCoreError> {
        Err(GitdCoreError::Authorization)
    }

    fn verify_commit(
        &mut self,
        context: ProtectedHistoryContext<'_>,
        commit: ObjectId,
        exact_contents: &[u8],
    ) -> Result<VerifiedCommitProof, HistoryVerificationError>;

    fn verify_legacy_commit(
        &mut self,
        _: ProtectedHistoryContext<'_>,
        _: ObjectId,
        _: &[u8],
    ) -> Result<VerifiedLegacyCommitProof, HistoryVerificationError> {
        Err(HistoryVerificationError::Signature)
    }

    /// Complete proof consumption before a verified transaction can be
    /// constructed. Any unused supplied proof fails closed.
    fn finish_receive_proofs(&mut self) -> Result<(), GitdCoreError> {
        Ok(())
    }
}

/// Opaque preparation result. It cannot activate refs; the signed audit-receipt
/// authority and durable activation gate consume it in the subsequent phase.
pub struct PreparedProtectedReceive {
    request: ReceivePackRequest,
    transaction: QuarantineTransaction,
    verified: VerifiedRefTransaction,
    pack_summary: AuthenticatedPackIndexSummary,
    protocol_budget: ProtocolBudget,
}

impl PreparedProtectedReceive {
    pub fn request(&self) -> &ReceivePackRequest {
        &self.request
    }

    pub fn transaction(&self) -> &QuarantineTransaction {
        &self.transaction
    }

    pub fn verified(&self) -> &VerifiedRefTransaction {
        &self.verified
    }

    pub fn candidate_context(
        &self,
        policy_digest: [u8; 64],
    ) -> Result<AuthorityCandidateContext, GitdCoreError> {
        if policy_digest == [0; 64] {
            return Err(GitdCoreError::Authorization);
        }
        let expanded_bytes = self
            .transaction
            .validated_expanded_bytes()
            .ok_or(GitdCoreError::ObjectValidation)?;
        let receipt = expected_audit_receipt(self.transaction.id(), &self.verified)
            .map_err(map_durable_error)?;
        let receipt_bytes =
            encode_audit_receipt(&receipt).map_err(|_| GitdCoreError::Policy)?;
        let receipt_transcript = authenticated_audit_receipt_transcript(&receipt_bytes)
            .map_err(|_| GitdCoreError::Policy)?;
        Ok(AuthorityCandidateContext {
            id: self.transaction.id(),
            repository: self.verified.repository().clone(),
            current_generation: self.verified.repository_generation(),
            next_generation: receipt.activated_repository_generation,
            trust_generation: self.verified.trust_generation(),
            revocation_generation: self.verified.revocation_generation(),
            policy_digest,
            ref_update_digest: candidate_ref_update_digest(&self.verified)?,
            introduced_commit_set_digest: self.verified.introduced_commit_set_digest(),
            arrival_pack_digest: candidate_arrival_pack_digest(
                ObjectFormat::Sha256,
                self.pack_summary.pack_checksum,
                self.pack_summary.index_checksum,
                self.pack_summary.pack_bytes,
                self.pack_summary.index_bytes,
                self.pack_summary.object_count,
                expanded_bytes,
            )?,
            proof_set_digest: candidate_proof_set_digest(&self.request.proofs)?,
            activation_digest: candidate_activation_digest(&receipt_transcript),
        })
    }

    pub const fn protocol_budget(&self) -> ProtocolBudget {
        self.protocol_budget
    }

    pub(crate) fn install_candidate_proofs(
        &self,
        store: &LinuxDurableReceiveStore,
        active_objects: &Repository,
        authority: &mut dyn crate::ProtectedReceiveAuthority,
        candidate: &AuthorityCandidateContext,
    ) -> Result<(), GitdCoreError> {
        if candidate.introduced_commit_set_digest
            != self.verified.introduced_commit_set_digest()
            || candidate.proof_set_digest != candidate_proof_set_digest(&self.request.proofs)?
        {
            return Err(GitdCoreError::Authorization);
        }
        let context = ProtectedHistoryContext {
            repository: self.verified.repository(),
            repository_generation: self.verified.repository_generation(),
            trust_generation: self.verified.trust_generation(),
            revocation_generation: self.verified.revocation_generation(),
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha256,
        };
        for proof in &self.request.proofs {
            let commit = proof.commit();
            if self.verified.introduced_commits().binary_search(&commit).is_err() {
                return Err(GitdCoreError::Authorization);
            }
            let object = received_or_active(store, self.transaction.id(), active_objects, commit)
                .map_err(map_history_error)?;
            if object.kind != ObjectKind::Commit {
                return Err(GitdCoreError::ObjectValidation);
            }
            authority.install_candidate_proof(
                candidate,
                context,
                commit,
                &object.contents,
                proof,
            )?;
        }
        Ok(())
    }
}

/// Activate an already verified protected receive through the only durable
/// store in this crate that authenticates its audit receipt. Consuming the
/// opaque preparation prevents replaying one authorization in-process.
pub fn activate_prepared_protected_receive(
    mut prepared: PreparedProtectedReceive,
    store: &mut AuthenticatedReceiveStore<'_>,
) -> Result<AuditReceipt, GitdCoreError> {
    durably_activate_verified_receive(&mut prepared.transaction, &prepared.verified, store)
        .map_err(map_durable_error)
}

/// Complete activation and emit the negotiated receive-pack result. Once
/// activation succeeds, any output failure is reported as `UncertainCommit`:
/// the caller must not retry as though refs were unchanged.
pub fn finish_prepared_protected_receive(
    prepared: PreparedProtectedReceive,
    store: &mut AuthenticatedReceiveStore<'_>,
    output: &mut dyn BoundedWrite,
    initial_budget: WorkBudget,
) -> Result<SmartGitResponse, GitdCoreError> {
    finish_prepared_receive(prepared, store, output, initial_budget)
}

/// Complete a conventional receive using the repository store's
/// checksum-protected audit receipt. No protected-history or receipt-signing
/// authority is involved in this profile.
pub fn finish_prepared_conventional_receive(
    prepared: PreparedProtectedReceive,
    store: &mut LinuxDurableReceiveStore,
    output: &mut dyn BoundedWrite,
    initial_budget: WorkBudget,
) -> Result<SmartGitResponse, GitdCoreError> {
    finish_prepared_receive(prepared, store, output, initial_budget)
}

fn finish_prepared_receive(
    mut prepared: PreparedProtectedReceive,
    store: &mut dyn DurableReceiveStore,
    output: &mut dyn BoundedWrite,
    initial_budget: WorkBudget,
) -> Result<SmartGitResponse, GitdCoreError> {
    let request = prepared.request.clone();
    let mut protocol = prepared.protocol_budget;
    let receipt =
        durably_activate_verified_receive(&mut prepared.transaction, &prepared.verified, store)
            .map_err(map_durable_error)?;
    let mut statuses = Vector::new();
    statuses
        .try_reserve_exact(request.candidate.updates.len())
        .map_err(|_| GitdCoreError::UncertainCommit)?;
    for update in &request.candidate.updates {
        statuses.push(ReceiveRefStatus {
            name: update.name.clone(),
            error: None,
        });
    }
    let authenticated_receipt = if request.mrml_receipt_v1 {
        Some(
            store
                .authenticated_audit_receipt(receipt.transaction)
                .ok_or(GitdCoreError::UncertainCommit)?,
        )
    } else {
        None
    };
    write_receive_pack_report(
        output,
        &request,
        None,
        &statuses,
        authenticated_receipt,
        &mut protocol,
    )
        .map_err(|_| GitdCoreError::UncertainCommit)?;
    Ok(SmartGitResponse {
        repository_generation: receipt.activated_repository_generation,
        bytes_read: initial_budget
            .max_input_bytes
            .checked_sub(protocol.input_remaining())
            .ok_or(GitdCoreError::UncertainCommit)?,
        bytes_written: initial_budget
            .max_output_bytes
            .checked_sub(protocol.output_remaining())
            .ok_or(GitdCoreError::UncertainCommit)?,
        refs_activated: true,
    })
}

/// Prepare a conventional fast-forward receive after edge authentication and
/// repository authorization. Every introduced commit and pack object is still
/// traversed and bounded, but commit contents are not signature authority.
#[allow(clippy::too_many_arguments)]
pub fn prepare_conventional_receive(
    smart_request: SmartGitRequest,
    active: &ActiveRefState,
    active_objects: &Repository,
    store: &LinuxDurableReceiveStore,
    transaction_id: QuarantineTransactionId,
    quarantine_limits: QuarantineLimits,
    history_limits: HistoryVerificationLimits,
    ordinary_free_bytes: u64,
    input: &mut dyn crate::BoundedRead,
    work_budget: WorkBudget,
) -> Result<PreparedProtectedReceive, GitdCoreError> {
    prepare_receive_internal(
        smart_request,
        active,
        active_objects,
        store,
        None,
        None,
        false,
        transaction_id,
        quarantine_limits,
        history_limits,
        ordinary_free_bytes,
        input,
        work_budget,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_protected_receive(
    smart_request: SmartGitRequest,
    active: &ActiveRefState,
    active_objects: &Repository,
    store: &LinuxDurableReceiveStore,
    verifier: &mut dyn ProtectedCommitVerifier,
    transaction_id: QuarantineTransactionId,
    quarantine_limits: QuarantineLimits,
    history_limits: HistoryVerificationLimits,
    ordinary_free_bytes: u64,
    input: &mut dyn crate::BoundedRead,
    work_budget: WorkBudget,
) -> Result<PreparedProtectedReceive, GitdCoreError> {
    prepare_receive_internal(
        smart_request,
        active,
        active_objects,
        store,
        Some(verifier),
        None,
        false,
        transaction_id,
        quarantine_limits,
        history_limits,
        ordinary_free_bytes,
        input,
        work_budget,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_policy_classified_receive(
    smart_request: SmartGitRequest,
    active: &ActiveRefState,
    active_objects: &Repository,
    store: &LinuxDurableReceiveStore,
    verifier: &mut dyn ProtectedCommitVerifier,
    policy: &TrustPolicyState,
    transaction_id: QuarantineTransactionId,
    quarantine_limits: QuarantineLimits,
    history_limits: HistoryVerificationLimits,
    ordinary_free_bytes: u64,
    input: &mut dyn crate::BoundedRead,
    work_budget: WorkBudget,
) -> Result<PreparedProtectedReceive, GitdCoreError> {
    prepare_receive_internal(
        smart_request,
        active,
        active_objects,
        store,
        Some(verifier),
        Some(policy),
        false,
        transaction_id,
        quarantine_limits,
        history_limits,
        ordinary_free_bytes,
        input,
        work_budget,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_authority_classified_receive(
    smart_request: SmartGitRequest,
    active: &ActiveRefState,
    active_objects: &Repository,
    store: &LinuxDurableReceiveStore,
    verifier: &mut dyn ProtectedCommitVerifier,
    policy: &TrustPolicyState,
    transaction_id: QuarantineTransactionId,
    quarantine_limits: QuarantineLimits,
    history_limits: HistoryVerificationLimits,
    ordinary_free_bytes: u64,
    input: &mut dyn crate::BoundedRead,
    work_budget: WorkBudget,
) -> Result<PreparedProtectedReceive, GitdCoreError> {
    prepare_receive_internal(
        smart_request,
        active,
        active_objects,
        store,
        Some(verifier),
        Some(policy),
        true,
        transaction_id,
        quarantine_limits,
        history_limits,
        ordinary_free_bytes,
        input,
        work_budget,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_receive_internal(
    smart_request: SmartGitRequest,
    active: &ActiveRefState,
    active_objects: &Repository,
    store: &LinuxDurableReceiveStore,
    mut verifier: Option<&mut dyn ProtectedCommitVerifier>,
    policy: Option<&TrustPolicyState>,
    require_transaction_authorization: bool,
    transaction_id: QuarantineTransactionId,
    quarantine_limits: QuarantineLimits,
    history_limits: HistoryVerificationLimits,
    ordinary_free_bytes: u64,
    input: &mut dyn crate::BoundedRead,
    work_budget: WorkBudget,
) -> Result<PreparedProtectedReceive, GitdCoreError> {
    if smart_request.operation != SmartGitOperation::ReceivePack
        || smart_request.repository != active.repository
        || smart_request.repository_generation != active.repository_generation
        || smart_request.object_format != active.object_format
        || active.object_format != active_objects.object_format()
    {
        return Err(GitdCoreError::StaleGeneration);
    }
    if work_budget.max_input_bytes == 0
        || work_budget.max_output_bytes == 0
        || work_budget.max_memory_bytes == 0
        || work_budget.max_work_units == 0
    {
        return Err(GitdCoreError::Resource);
    }
    let mut protocol_budget = ProtocolBudget::new(work_budget);
    let request = read_receive_pack_commands(
        input,
        active.repository.clone(),
        active.repository_generation,
        active.trust_generation,
        active.revocation_generation,
        active.object_format,
        false,
        &mut protocol_budget,
    )?;
    if !request.atomic || !request.report_status_v2 || request.delete_refs {
        return Err(GitdCoreError::Unsupported);
    }
    match verifier.as_deref_mut() {
        Some(verifier) => verifier.begin_receive_proofs(&request.proofs)?,
        None if !request.proofs.is_empty() => return Err(GitdCoreError::Unsupported),
        None => {}
    }
    if require_transaction_authorization {
        verifier
            .as_deref_mut()
            .ok_or(GitdCoreError::Authorization)?
            .authorize_transaction(&request.candidate)?;
    }
    for update in &request.candidate.updates {
        let old = update.expected_old.ok_or(GitdCoreError::Unsupported)?;
        let new = update.proposed_new.ok_or(GitdCoreError::Unsupported)?;
        let active_old = active
            .refs
            .iter()
            .find(|(name, _)| name == &update.name)
            .map(|(_, id)| *id)
            .ok_or(GitdCoreError::Authorization)?;
        if old != active_old
            || old.format() != active.object_format
            || new.format() != active.object_format
        {
            return Err(GitdCoreError::StaleGeneration);
        }
    }

    let body_bytes = input.remaining();
    if body_bytes > protocol_budget.input_remaining()
        || body_bytes > protocol_budget.work_remaining()
    {
        return Err(GitdCoreError::Resource);
    }
    let mut effective_limits = quarantine_limits;
    effective_limits.max_individual_object_bytes = effective_limits
        .max_individual_object_bytes
        .min(work_budget.max_memory_bytes);
    let validation_fixed_work = body_bytes.checked_mul(2).ok_or(GitdCoreError::Resource)?;
    let validation_available = protocol_budget
        .work_remaining()
        .checked_sub(body_bytes)
        .and_then(|value| value.checked_sub(validation_fixed_work))
        .ok_or(GitdCoreError::Resource)?;
    effective_limits.max_expanded_object_bytes = effective_limits
        .max_expanded_object_bytes
        .min(validation_available);
    let reservation = reserve_push_disk_before_body(
        effective_limits,
        active.object_format,
        body_bytes,
        u16::try_from(request.candidate.updates.len()).map_err(|_| GitdCoreError::Resource)?,
        ordinary_free_bytes,
    )
    .map_err(|_| GitdCoreError::Resource)?;
    let mut transaction = QuarantineTransaction::begin(
        transaction_id,
        active.repository.clone(),
        active.repository_generation,
        active.trust_generation,
        active.revocation_generation,
        reservation,
    )
    .map_err(|_| GitdCoreError::Policy)?;
    store.receive_pack_body(&mut transaction, input)?;
    protocol_budget.consume_external_input(body_bytes)?;
    let mut tips = Vector::new();
    tips.try_reserve_exact(request.candidate.updates.len())
        .map_err(|_| GitdCoreError::Resource)?;
    for update in &request.candidate.updates {
        tips.push(update.proposed_new.ok_or(GitdCoreError::Unsupported)?);
    }
    let pack_summary = store.validate_received_pack_with_active_bases(
        &mut transaction,
        &tips,
        active,
        active_objects,
    )?;
    let validation_work = validation_fixed_work
        .checked_add(
            transaction
                .validated_expanded_bytes()
                .ok_or(GitdCoreError::ObjectValidation)?,
        )
        .ok_or(GitdCoreError::Resource)?;
    protocol_budget.consume_external_work(validation_work)?;

    let context = ProtectedHistoryContext {
        repository: &active.repository,
        repository_generation: active.repository_generation,
        trust_generation: active.trust_generation,
        revocation_generation: active.revocation_generation,
        purpose: SignaturePurpose::GitCommit,
        object_format: active.object_format,
    };
    let mut ranges = Vector::new();
    for update in &request.candidate.updates {
        let old = update.expected_old.ok_or(GitdCoreError::Unsupported)?;
        let new = update.proposed_new.ok_or(GitdCoreError::Unsupported)?;
        let read_parents = |id| {
            let object = received_or_active(store, transaction_id, active_objects, id)?;
            if object.kind != ObjectKind::Commit {
                return Err(HistoryVerificationError::MissingCommit);
            }
            crate::Commit::parse_with_format(&object.contents, active.object_format)
                .map(|commit| commit.parents)
                .map_err(|_| HistoryVerificationError::MissingCommit)
        };
        let range = if verifier.is_none() {
            verify_conventional_introduced_history(context, old, new, history_limits, read_parents)
        } else if let Some(policy) = policy {
            let verifier = core::cell::RefCell::new(
                verifier
                    .as_deref_mut()
                    .ok_or(GitdCoreError::Authorization)?,
            );
            verify_policy_classified_history(
                policy,
                context,
                old,
                new,
                history_limits,
                read_parents,
                |id| {
                    let object = received_or_active(store, transaction_id, active_objects, id)?;
                    if object.kind != ObjectKind::Commit {
                        return Err(HistoryVerificationError::MissingCommit);
                    }
                    verifier
                        .borrow_mut()
                        .verify_commit(context, id, &object.contents)
                },
                |id| {
                    let object = received_or_active(store, transaction_id, active_objects, id)?;
                    if object.kind != ObjectKind::Commit {
                        return Err(HistoryVerificationError::MissingCommit);
                    }
                    verifier
                        .borrow_mut()
                        .verify_legacy_commit(context, id, &object.contents)
                },
            )
        } else {
            let verifier = core::cell::RefCell::new(
                verifier
                    .as_deref_mut()
                    .ok_or(GitdCoreError::Authorization)?,
            );
            verify_protected_introduced_history(
                context,
                old,
                new,
                history_limits,
                read_parents,
                |id| {
                    let object = received_or_active(store, transaction_id, active_objects, id)?;
                    if object.kind != ObjectKind::Commit {
                        return Err(HistoryVerificationError::MissingCommit);
                    }
                    verifier
                        .borrow_mut()
                        .verify_commit(context, id, &object.contents)
                },
            )
        }
        .map_err(map_history_error)?;
        ranges.push(range);
    }
    if let Some(verifier) = verifier.as_deref_mut() {
        verifier.finish_receive_proofs()?;
    }
    let verified = build_verified_fast_forward_transaction(request.candidate.clone(), &ranges)?;
    transaction
        .history_verified(&verified)
        .map_err(|_| GitdCoreError::Policy)?;
    Ok(PreparedProtectedReceive {
        request,
        transaction,
        verified,
        pack_summary,
        protocol_budget,
    })
}

fn received_or_active(
    store: &LinuxDurableReceiveStore,
    transaction: QuarantineTransactionId,
    active: &Repository,
    id: ObjectId,
) -> Result<Object, HistoryVerificationError> {
    store
        .read_quarantined_object(transaction, id, crate::DEFAULT_MAX_INDIVIDUAL_OBJECT_BYTES)
        .or_else(|_| {
            store.read_active_arrival_object(id, crate::DEFAULT_MAX_INDIVIDUAL_OBJECT_BYTES)
        })
        .or_else(|_| {
            active
                .read_object(id)
                .map_err(|_| GitdCoreError::ObjectValidation)
        })
        .map_err(|_| HistoryVerificationError::MissingCommit)
}

fn map_history_error(error: HistoryVerificationError) -> GitdCoreError {
    match error {
        HistoryVerificationError::MissingCommit
        | HistoryVerificationError::ObjectFormatMismatch => GitdCoreError::ObjectValidation,
        HistoryVerificationError::Cycle | HistoryVerificationError::NotFastForward => {
            GitdCoreError::Ancestry
        }
        HistoryVerificationError::Signature => GitdCoreError::Signature,
        HistoryVerificationError::Resource => GitdCoreError::Resource,
    }
}

fn map_durable_error(error: DurableReceiveError) -> GitdCoreError {
    match error {
        DurableReceiveError::InvalidState => GitdCoreError::Policy,
        DurableReceiveError::StaleAuthority => GitdCoreError::StaleGeneration,
        DurableReceiveError::Aborted(_) => GitdCoreError::Storage,
        DurableReceiveError::Uncertain(_) => GitdCoreError::UncertainCommit,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use mrml_crypto::Sha256;
    use mrml_runtime::{join_path, Shared, Text, Vector};

    use super::*;
    use crate::{
        encode_pack_with_format, ActiveRefFile, FullRefName, ObjectFormat, PackGeneration,
        PackObject, PackSetLimits, RepositoryGeneration, RepositoryIdentity, RevocationGeneration,
        TrustGeneration,
    };

    struct Reader {
        bytes: Vector<u8>,
        offset: usize,
    }

    impl crate::BoundedRead for Reader {
        fn remaining(&self) -> u64 {
            (self.bytes.len() - self.offset) as u64
        }

        fn read(&mut self, output: &mut [u8]) -> Result<usize, GitdCoreError> {
            let count = output.len().min(11).min(self.bytes.len() - self.offset);
            output[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Ok(count)
        }
    }

    struct Writer {
        bytes: Vector<u8>,
        remaining: u64,
    }

    impl crate::BoundedWrite for Writer {
        fn remaining(&self) -> u64 {
            self.remaining
        }

        fn write(&mut self, input: &[u8]) -> Result<(), GitdCoreError> {
            if input.len() as u64 > self.remaining {
                return Err(GitdCoreError::Resource);
            }
            self.bytes
                .try_extend_from_slice(input)
                .map_err(|_| GitdCoreError::Resource)?;
            self.remaining -= input.len() as u64;
            Ok(())
        }
    }

    struct ExactVerifier {
        repository: RepositoryIdentity,
        generation: RepositoryGeneration,
        trust: TrustGeneration,
        revocations: RevocationGeneration,
        expected: ObjectId,
    }

    impl ProtectedCommitVerifier for ExactVerifier {
        fn verify_commit(
            &mut self,
            context: ProtectedHistoryContext<'_>,
            commit: ObjectId,
            _: &[u8],
        ) -> Result<VerifiedCommitProof, HistoryVerificationError> {
            if commit != self.expected || context.repository != &self.repository {
                return Err(HistoryVerificationError::Signature);
            }
            Ok(VerifiedCommitProof {
                commit,
                repository: self.repository.clone(),
                repository_generation: self.generation,
                trust_generation: self.trust,
                revocation_generation: self.revocations,
                purpose: SignaturePurpose::GitCommit,
                object_format: ObjectFormat::Sha256,
            })
        }
    }

    struct ReceiptAuthority;

    impl crate::AuditReceiptAuthority for ReceiptAuthority {
        fn signer_identity(&self) -> [u8; 64] {
            [23u8; 64]
        }

        fn sign(&mut self, transcript: &[u8], output: &mut [u8]) -> Result<usize, ()> {
            let signature = Sha256::digest(transcript);
            output
                .get_mut(..signature.len())
                .ok_or(())?
                .copy_from_slice(&signature);
            Ok(signature.len())
        }

        fn verify(&mut self, transcript: &[u8], signature: &[u8]) -> Result<(), ()> {
            (Sha256::digest(transcript).as_slice() == signature)
                .then_some(())
                .ok_or(())
        }
    }

    fn append_packet(output: &mut Vector<u8>, payload: &[u8]) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let length = payload.len() + 4;
        output.extend([
            HEX[(length >> 12) & 15],
            HEX[(length >> 8) & 15],
            HEX[(length >> 4) & 15],
            HEX[length & 15],
        ]);
        output.extend(payload.iter().copied());
    }

    fn encode_pack_header(kind: u8, mut size: usize, output: &mut Vector<u8>) {
        let mut first = ((kind & 7) << 4) | (size as u8 & 15);
        size >>= 4;
        if size != 0 {
            first |= 0x80;
        }
        output.push(first);
        while size != 0 {
            let mut byte = (size & 0x7f) as u8;
            size >>= 7;
            if size != 0 {
                byte |= 0x80;
            }
            output.push(byte);
        }
    }

    fn encode_delta_size(mut size: usize, output: &mut Vector<u8>) {
        loop {
            let mut byte = (size & 0x7f) as u8;
            size >>= 7;
            if size != 0 {
                byte |= 0x80;
            }
            output.push(byte);
            if size == 0 {
                return;
            }
        }
    }

    fn thin_ref_delta_pack(base: ObjectId, base_bytes: &[u8], result: &[u8]) -> Vector<u8> {
        let mut delta = Vector::new();
        encode_delta_size(base_bytes.len(), &mut delta);
        encode_delta_size(result.len(), &mut delta);
        for chunk in result.chunks(127) {
            delta.push(chunk.len() as u8);
            delta.extend(chunk.iter().copied());
        }
        let mut pack = Vector::from(*b"PACK");
        pack.extend(2u32.to_be_bytes());
        pack.extend(1u32.to_be_bytes());
        encode_pack_header(7, delta.len(), &mut pack);
        pack.extend(base.as_bytes().iter().copied());
        pack.extend(crate::deflate::encode_zlib(&delta));
        let checksum = ObjectFormat::Sha256.hash_bytes(&pack);
        pack.extend(checksum.as_bytes().iter().copied());
        pack
    }

    struct ConcurrentBodyReader {
        bytes: Vector<u8>,
        offset: usize,
        body_offset: usize,
        body_started: bool,
        bodies_ready: Shared<AtomicUsize>,
    }

    impl crate::BoundedRead for ConcurrentBodyReader {
        fn remaining(&self) -> u64 {
            (self.bytes.len() - self.offset) as u64
        }

        fn read(&mut self, output: &mut [u8]) -> Result<usize, GitdCoreError> {
            if self.offset >= self.body_offset && !self.body_started {
                self.body_started = true;
                self.bodies_ready.fetch_add(1, Ordering::AcqRel);
                while self.bodies_ready.load(Ordering::Acquire) != 2 {
                    mrml_runtime::yield_now();
                }
            }
            let count = output.len().min(11).min(self.bytes.len() - self.offset);
            output[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Ok(count)
        }
    }

    fn path(root: &str, child: &str) -> Text {
        join_path(root, child)
    }

    #[test]
    fn prepares_exact_protected_fast_forward_without_activating_refs() {
        let root = join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-receive-prepare-{}", mrml_runtime::process_id()),
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        mrml_runtime::create_dir_all(&root).unwrap();
        let repository_path = path(&root, "repository");
        let repository =
            Repository::init_with_format(&repository_path, ObjectFormat::Sha256).unwrap();
        let tree = repository.write_object(ObjectKind::Tree, &[]).unwrap();
        let old_contents = mrml_runtime::mrml_format!(
            "tree {}\nauthor Owner <owner@example.invalid> 1 +0000\n\nold\n",
            tree.to_hex()
        );
        let old = repository
            .write_object(ObjectKind::Commit, old_contents.as_bytes())
            .unwrap();
        let new_contents = mrml_runtime::mrml_format!(
            "tree {}\nparent {}\nauthor Owner <owner@example.invalid> 2 +0000\n\nnew\n",
            tree.to_hex(),
            old.to_hex()
        );
        let (new, _) = crate::encode_loose_object_with_format(
            ObjectFormat::Sha256,
            ObjectKind::Commit,
            new_contents.as_bytes(),
        );
        let mut new_bytes = Vector::new();
        new_bytes.extend(new_contents.as_bytes().iter().copied());
        let pack = encode_pack_with_format(
            &[PackObject {
                id: new,
                kind: ObjectKind::Commit,
                contents: new_bytes,
            }],
            ObjectFormat::Sha256,
        )
        .unwrap();
        let identity = RepositoryIdentity::parse("owner/repository").unwrap();
        let initial_manifest = crate::pack_set::build_pack_set_manifest(
            identity.clone(),
            RepositoryGeneration(7),
            PackGeneration(1),
            ObjectFormat::Sha256,
            Vector::new(),
            PackSetLimits {
                max_packs: 65_536,
                max_objects: 10_000_000,
                max_pack_bytes: 8 * 1024 * 1024 * 1024 * 1024,
                max_index_bytes: 16 * 1024 * 1024 * 1024,
                max_work_units: 16 * 1024 * 1024 * 1024 * 1024,
            },
        )
        .unwrap();
        let active = ActiveRefState {
            repository: identity.clone(),
            repository_generation: RepositoryGeneration(7),
            trust_generation: TrustGeneration(8),
            revocation_generation: RevocationGeneration(9),
            pack_generation: PackGeneration(1),
            pack_set_digest: initial_manifest.digest().unwrap(),
            object_format: ObjectFormat::Sha256,
            default_branch: FullRefName::parse("refs/heads/main").unwrap(),
            refs: [(FullRefName::parse("refs/heads/main").unwrap(), old)].into(),
        };
        let refs = path(&root, "refs");
        ActiveRefFile::initialize_with_pack_set(&refs, &active, &initial_manifest).unwrap();
        let store = LinuxDurableReceiveStore::open(
            &path(&root, "journals"),
            &path(&root, "packs"),
            &refs,
            &path(&root, "receipts"),
            ObjectFormat::Sha256,
            1024 * 1024,
        )
        .unwrap();
        let command = mrml_runtime::mrml_format!(
            "{} {} refs/heads/main\0report-status-v2 atomic object-format=sha256\n",
            old.to_hex(),
            new.to_hex()
        );
        let mut bytes = Vector::new();
        append_packet(&mut bytes, command.as_bytes());
        bytes.extend(*b"0000");
        bytes.extend(pack.iter().copied());
        let command_bytes = bytes.len() - pack.len();
        let mut unauthorized_input = Reader {
            bytes: bytes.clone(),
            offset: 0,
        };
        let mut unauthorized_verifier = ExactVerifier {
            repository: identity.clone(),
            generation: RepositoryGeneration(7),
            trust: TrustGeneration(8),
            revocations: RevocationGeneration(9),
            expected: new,
        };
        assert!(matches!(
            prepare_receive_internal(
                SmartGitRequest {
                    repository: identity.clone(),
                    repository_generation: RepositoryGeneration(7),
                    operation: SmartGitOperation::ReceivePack,
                    object_format: ObjectFormat::Sha256,
                },
                &active,
                &repository,
                &store,
                Some(&mut unauthorized_verifier),
                None,
                true,
                QuarantineTransactionId([30u8; 16]),
                QuarantineLimits {
                    max_incoming_pack_bytes: 1024 * 1024,
                    max_expanded_object_bytes: 1024 * 1024,
                    max_individual_object_bytes: 1024 * 1024,
                    max_objects: 16,
                    max_refs: 4,
                    minimum_free_space_bytes: 0,
                },
                HistoryVerificationLimits::default(),
                16 * 1024 * 1024,
                &mut unauthorized_input,
                WorkBudget {
                    max_input_bytes: 2 * 1024 * 1024,
                    max_output_bytes: 1024 * 1024,
                    max_memory_bytes: 1024 * 1024,
                    max_work_units: 8 * 1024 * 1024,
                },
            ),
            Err(GitdCoreError::Authorization)
        ));
        assert_eq!(unauthorized_input.offset, command_bytes);
        assert_eq!(
            unauthorized_input.bytes.len() - unauthorized_input.offset,
            pack.len()
        );

        let mut input = Reader { bytes, offset: 0 };
        let mut verifier = ExactVerifier {
            repository: identity.clone(),
            generation: RepositoryGeneration(7),
            trust: TrustGeneration(8),
            revocations: RevocationGeneration(9),
            expected: new,
        };
        let work_budget = WorkBudget {
            max_input_bytes: 2 * 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            max_memory_bytes: 1024 * 1024,
            max_work_units: 8 * 1024 * 1024,
        };
        let core = crate::ReceivePackCore {
            request: SmartGitRequest {
                repository: identity.clone(),
                repository_generation: RepositoryGeneration(7),
                operation: SmartGitOperation::ReceivePack,
                object_format: ObjectFormat::Sha256,
            },
            transaction: QuarantineTransactionId([31u8; 16]),
            quarantine_limits: QuarantineLimits {
                max_incoming_pack_bytes: 1024 * 1024,
                max_expanded_object_bytes: 1024 * 1024,
                max_individual_object_bytes: 1024 * 1024,
                max_objects: 16,
                max_refs: 4,
                minimum_free_space_bytes: 0,
            },
            history_limits: HistoryVerificationLimits::default(),
            ordinary_free_bytes: 16 * 1024 * 1024,
            work_budget,
        };

        let signed_receipts = path(&root, "signed-receipts");
        let mut store = store;
        let mut authority = ReceiptAuthority;
        let mut output = Writer {
            bytes: Vector::new(),
            remaining: work_budget.max_output_bytes,
        };
        let response = core
            .execute(
                &active,
                &repository,
                &mut store,
                &mut verifier,
                &signed_receipts,
                &mut authority,
                &mut input,
                &mut output,
            )
            .unwrap();
        let activated = store.active_refs().load().unwrap();
        assert_eq!(activated.repository_generation, RepositoryGeneration(8));
        assert_eq!(activated.refs[0].1, new);
        assert_eq!(response.repository_generation, RepositoryGeneration(8));
        assert!(response.refs_activated);
        assert!(output.bytes.ends_with(b"0000"));
        let signed = crate::AuthenticatedAuditReceiptDirectory::open(&signed_receipts)
            .unwrap()
            .load(QuarantineTransactionId([31u8; 16]), &mut authority)
            .unwrap();
        assert_eq!(
            signed.receipt.activated_repository_generation,
            RepositoryGeneration(8)
        );

        // A later receive must traverse the prior commit through the selected
        // arrival manifest; the baseline repository intentionally lacks it.
        let newer_contents = mrml_runtime::mrml_format!(
            "tree {}\nparent {}\nauthor Owner <owner@example.invalid> 3 +0000\n\nnewer\n",
            tree.to_hex(),
            new.to_hex()
        );
        let (newer, _) = crate::encode_loose_object_with_format(
            ObjectFormat::Sha256,
            ObjectKind::Commit,
            newer_contents.as_bytes(),
        );
        let mut newer_bytes = Vector::new();
        newer_bytes.extend(newer_contents.as_bytes().iter().copied());
        let newer_pack = encode_pack_with_format(
            &[PackObject {
                id: newer,
                kind: ObjectKind::Commit,
                contents: newer_bytes,
            }],
            ObjectFormat::Sha256,
        )
        .unwrap();
        let command = mrml_runtime::mrml_format!(
            "{} {} refs/heads/main\0report-status-v2 atomic object-format=sha256\n",
            new.to_hex(),
            newer.to_hex()
        );
        let mut bytes = Vector::new();
        append_packet(&mut bytes, command.as_bytes());
        bytes.extend(*b"0000");
        bytes.extend(newer_pack.iter().copied());
        let mut input = Reader { bytes, offset: 0 };
        let active = store.active_refs().load().unwrap();
        let mut verifier = ExactVerifier {
            repository: active.repository.clone(),
            generation: RepositoryGeneration(8),
            trust: TrustGeneration(8),
            revocations: RevocationGeneration(9),
            expected: newer,
        };
        let core = crate::ReceivePackCore {
            request: SmartGitRequest {
                repository: active.repository.clone(),
                repository_generation: RepositoryGeneration(8),
                operation: SmartGitOperation::ReceivePack,
                object_format: ObjectFormat::Sha256,
            },
            transaction: QuarantineTransactionId([32; 16]),
            quarantine_limits: QuarantineLimits {
                max_incoming_pack_bytes: 1024 * 1024,
                max_expanded_object_bytes: 1024 * 1024,
                max_individual_object_bytes: 1024 * 1024,
                max_objects: 16,
                max_refs: 4,
                minimum_free_space_bytes: 0,
            },
            history_limits: HistoryVerificationLimits::default(),
            ordinary_free_bytes: 16 * 1024 * 1024,
            work_budget,
        };
        let before_failed = store.active_refs().load().unwrap();
        let mut malformed = Reader {
            bytes: Vector::from(*b"0003"),
            offset: 0,
        };
        let mut failed_output = Writer {
            bytes: Vector::new(),
            remaining: work_budget.max_output_bytes,
        };
        assert!(
            core.execute(
                &active,
                &repository,
                &mut store,
                &mut verifier,
                &signed_receipts,
                &mut authority,
                &mut malformed,
                &mut failed_output,
            )
            .is_err()
        );
        assert_eq!(store.active_refs().load().unwrap(), before_failed);

        let prepared_later = prepare_protected_receive(
            core.request,
            &active,
            &repository,
            &store,
            &mut verifier,
            core.transaction,
            core.quarantine_limits,
            core.history_limits,
            core.ordinary_free_bytes,
            &mut input,
            core.work_budget,
        )
        .unwrap();
        assert_eq!(
            prepared_later.verified().updates()[0].proposed_new(),
            Some(newer)
        );
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn concurrent_thin_receives_share_selected_base_and_only_one_activates() {
        let root = join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!(
                "mrml-concurrent-thin-receive-{}",
                mrml_runtime::process_id()
            ),
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        mrml_runtime::create_dir_all(&root).unwrap();
        let repository_path = path(&root, "repository");
        let repository =
            Repository::init_with_format(&repository_path, ObjectFormat::Sha256).unwrap();
        let tree = repository.write_object(ObjectKind::Tree, &[]).unwrap();
        let old_contents = mrml_runtime::mrml_format!(
            "tree {}\nauthor Owner <owner@example.invalid> 1 +0000\n\nselected base\n",
            tree.to_hex()
        );
        let (old, _) = crate::encode_loose_object_with_format(
            ObjectFormat::Sha256,
            ObjectKind::Commit,
            old_contents.as_bytes(),
        );
        // The old tip/base is deliberately absent from the baseline repository
        // and available only through the selected arrival manifest.
        assert!(repository.read_object(old).is_err());

        let identity = RepositoryIdentity::parse("owner/concurrent").unwrap();
        let packs = path(&root, "packs");
        let arrivals =
            crate::ArrivalPackStore::open(&packs, ObjectFormat::Sha256, 1024 * 1024).unwrap();
        let seed_id = QuarantineTransactionId([40; 16]);
        let mut old_bytes = Vector::new();
        old_bytes.extend(old_contents.as_bytes().iter().copied());
        let seed_pack = encode_pack_with_format(
            &[PackObject {
                id: old,
                kind: ObjectKind::Commit,
                contents: old_bytes,
            }],
            ObjectFormat::Sha256,
        )
        .unwrap();
        let seed_summary = arrivals
            .stage_compacted_pack(seed_id, &seed_pack, &[old])
            .unwrap();
        arrivals.install(seed_id, 1).unwrap();
        let limits = PackSetLimits {
            max_packs: 65_536,
            max_objects: 10_000_000,
            max_pack_bytes: 8 * 1024 * 1024 * 1024 * 1024,
            max_index_bytes: 16 * 1024 * 1024 * 1024,
            max_work_units: 16 * 1024 * 1024 * 1024 * 1024,
        };
        let initial_manifest = crate::pack_set::build_pack_set_manifest(
            identity.clone(),
            RepositoryGeneration(7),
            PackGeneration(1),
            ObjectFormat::Sha256,
            Vector::from([seed_summary]),
            limits,
        )
        .unwrap();
        let active = ActiveRefState {
            repository: identity.clone(),
            repository_generation: RepositoryGeneration(7),
            trust_generation: TrustGeneration(8),
            revocation_generation: RevocationGeneration(9),
            pack_generation: PackGeneration(1),
            pack_set_digest: initial_manifest.digest().unwrap(),
            object_format: ObjectFormat::Sha256,
            default_branch: FullRefName::parse("refs/heads/main").unwrap(),
            refs: [(FullRefName::parse("refs/heads/main").unwrap(), old)].into(),
        };
        let refs = path(&root, "refs");
        ActiveRefFile::initialize_with_pack_set(&refs, &active, &initial_manifest).unwrap();

        let bodies_ready = Shared::new(AtomicUsize::new(0));
        let successes = Shared::new(AtomicUsize::new(0));
        let rejected = Shared::new(AtomicUsize::new(0));
        let unexpected = Shared::new(AtomicUsize::new(0));
        let mut workers = Vector::new();
        let mut candidate_ids = Vector::new();
        for (index, message) in ["candidate alpha", "candidate beta"].iter().enumerate() {
            let new_contents = mrml_runtime::mrml_format!(
                "tree {}\nparent {}\nauthor Owner <owner@example.invalid> {} +0000\n\n{}\n",
                tree.to_hex(),
                old.to_hex(),
                index + 2,
                message
            );
            let (new, _) = crate::encode_loose_object_with_format(
                ObjectFormat::Sha256,
                ObjectKind::Commit,
                new_contents.as_bytes(),
            );
            candidate_ids.push(new);
            let thin = thin_ref_delta_pack(old, old_contents.as_bytes(), new_contents.as_bytes());
            let command = mrml_runtime::mrml_format!(
                "{} {} refs/heads/main\0report-status-v2 atomic object-format=sha256\n",
                old.to_hex(),
                new.to_hex()
            );
            let mut bytes = Vector::new();
            append_packet(&mut bytes, command.as_bytes());
            bytes.extend(*b"0000");
            let body_offset = bytes.len();
            bytes.extend(thin.iter().copied());

            let worker_root = root.clone();
            let worker_repository = repository_path.clone();
            let worker_identity = identity.clone();
            let worker_active = active.clone();
            let worker_ready = bodies_ready.clone();
            let worker_successes = successes.clone();
            let worker_rejected = rejected.clone();
            let worker_unexpected = unexpected.clone();
            let worker = mrml_runtime::spawn_joinable(move || {
                let active_objects = Repository::discover(&worker_repository).unwrap();
                let mut store = LinuxDurableReceiveStore::open(
                    &path(&worker_root, "journals"),
                    &path(&worker_root, "packs"),
                    &path(&worker_root, "refs"),
                    &path(&worker_root, "receipts"),
                    ObjectFormat::Sha256,
                    1024 * 1024,
                )
                .unwrap();
                let budget = WorkBudget {
                    max_input_bytes: 2 * 1024 * 1024,
                    max_output_bytes: 1024 * 1024,
                    max_memory_bytes: 1024 * 1024,
                    max_work_units: 8 * 1024 * 1024,
                };
                let core = crate::ReceivePackCore {
                    request: SmartGitRequest {
                        repository: worker_identity.clone(),
                        repository_generation: RepositoryGeneration(7),
                        operation: SmartGitOperation::ReceivePack,
                        object_format: ObjectFormat::Sha256,
                    },
                    transaction: QuarantineTransactionId([41 + index as u8; 16]),
                    quarantine_limits: QuarantineLimits {
                        max_incoming_pack_bytes: 1024 * 1024,
                        max_expanded_object_bytes: 1024 * 1024,
                        max_individual_object_bytes: 1024 * 1024,
                        max_objects: 16,
                        max_refs: 4,
                        minimum_free_space_bytes: 0,
                    },
                    history_limits: HistoryVerificationLimits::default(),
                    ordinary_free_bytes: 16 * 1024 * 1024,
                    work_budget: budget,
                };
                let mut input = ConcurrentBodyReader {
                    bytes,
                    offset: 0,
                    body_offset,
                    body_started: false,
                    bodies_ready: worker_ready,
                };
                let mut output = Writer {
                    bytes: Vector::new(),
                    remaining: budget.max_output_bytes,
                };
                let mut verifier = ExactVerifier {
                    repository: worker_identity,
                    generation: RepositoryGeneration(7),
                    trust: TrustGeneration(8),
                    revocations: RevocationGeneration(9),
                    expected: new,
                };
                let mut authority = ReceiptAuthority;
                match core.execute(
                    &worker_active,
                    &active_objects,
                    &mut store,
                    &mut verifier,
                    &path(&worker_root, "signed-receipts"),
                    &mut authority,
                    &mut input,
                    &mut output,
                ) {
                    Ok(response) if response.refs_activated => {
                        worker_successes.fetch_add(1, Ordering::AcqRel);
                    }
                    Err(
                        GitdCoreError::StaleGeneration
                        | GitdCoreError::Storage
                        | GitdCoreError::UncertainCommit,
                    ) => {
                        worker_rejected.fetch_add(1, Ordering::AcqRel);
                    }
                    _ => {
                        worker_unexpected.fetch_add(1, Ordering::AcqRel);
                    }
                }
            })
            .unwrap_or_else(|_| panic!("failed to start concurrent thin receive"));
            workers.push(worker);
        }
        for worker in workers {
            assert!(worker.join());
        }
        assert_eq!(bodies_ready.load(Ordering::Acquire), 2);
        assert_eq!(successes.load(Ordering::Acquire), 1);
        assert_eq!(rejected.load(Ordering::Acquire), 1);
        assert_eq!(unexpected.load(Ordering::Acquire), 0);
        let reopened = LinuxDurableReceiveStore::open(
            &path(&root, "journals"),
            &packs,
            &refs,
            &path(&root, "receipts"),
            ObjectFormat::Sha256,
            1024 * 1024,
        )
        .unwrap();
        let final_state = reopened.active_refs().load().unwrap();
        assert_eq!(final_state.repository_generation, RepositoryGeneration(8));
        assert!(candidate_ids.contains(&final_state.refs[0].1));
        let winner = reopened
            .read_active_arrival_object(final_state.refs[0].1, 1024 * 1024)
            .unwrap();
        assert_eq!(winner.kind, ObjectKind::Commit);
        assert_eq!(
            &reopened
                .read_active_arrival_object(old, 1024 * 1024)
                .unwrap()
                .contents[..],
            old_contents.as_bytes()
        );
        let loser = *candidate_ids
            .iter()
            .find(|id| **id != final_state.refs[0].1)
            .unwrap();
        assert!(
            reopened
                .read_active_arrival_object(loser, 1024 * 1024)
                .is_err()
        );
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
