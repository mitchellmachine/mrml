//! Protected receive preparation before signed audit-receipt activation.

use mrml_runtime::Vector;

use crate::{
    ActiveRefState, GitdCoreError, HistoryVerificationError, HistoryVerificationLimits,
    LinuxDurableReceiveStore, Object, ObjectId, ObjectKind, ProtectedHistoryContext,
    ProtocolBudget, QuarantineLimits, QuarantineTransaction, QuarantineTransactionId,
    ReceivePackRequest, Repository, SignaturePurpose, SmartGitOperation, SmartGitRequest,
    VerifiedCommitProof, VerifiedRefTransaction, WorkBudget,
    build_verified_fast_forward_transaction, read_receive_pack_commands,
    reserve_push_disk_before_body, verify_protected_introduced_history,
};

/// Verification-only authority. Implementations receive public policy/key state
/// and exact commit bytes; no signing key belongs at this boundary.
pub trait ProtectedCommitVerifier {
    fn verify_commit(
        &mut self,
        context: ProtectedHistoryContext<'_>,
        commit: ObjectId,
        exact_contents: &[u8],
    ) -> Result<VerifiedCommitProof, HistoryVerificationError>;
}

/// Opaque preparation result. It cannot activate refs; the signed audit-receipt
/// authority and durable activation gate consume it in the subsequent phase.
pub struct PreparedProtectedReceive {
    request: ReceivePackRequest,
    transaction: QuarantineTransaction,
    verified: VerifiedRefTransaction,
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

    pub const fn protocol_budget(&self) -> ProtocolBudget {
        self.protocol_budget
    }
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
    store.validate_received_pack(&mut transaction, &tips)?;
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
        let range = verify_protected_introduced_history(
            context,
            old,
            new,
            history_limits,
            |id| {
                let object = received_or_active(store, transaction_id, active_objects, id)?;
                if object.kind != ObjectKind::Commit {
                    return Err(HistoryVerificationError::MissingCommit);
                }
                crate::Commit::parse_with_format(&object.contents, active.object_format)
                    .map(|commit| commit.parents)
                    .map_err(|_| HistoryVerificationError::MissingCommit)
            },
            |id| {
                let object = received_or_active(store, transaction_id, active_objects, id)?;
                if object.kind != ObjectKind::Commit {
                    return Err(HistoryVerificationError::MissingCommit);
                }
                verifier.verify_commit(context, id, &object.contents)
            },
        )
        .map_err(map_history_error)?;
        ranges.push(range);
    }
    let verified = build_verified_fast_forward_transaction(request.candidate.clone(), &ranges)?;
    transaction
        .history_verified(&verified)
        .map_err(|_| GitdCoreError::Policy)?;
    Ok(PreparedProtectedReceive {
        request,
        transaction,
        verified,
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

#[cfg(all(test, unix))]
mod tests {
    use mrml_runtime::{Text, Vector, join_path};

    use super::*;
    use crate::{
        ActiveRefFile, FullRefName, ObjectFormat, PackGeneration, PackObject, RepositoryGeneration,
        RepositoryIdentity, RevocationGeneration, TrustGeneration, encode_pack_with_format,
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
        let active = ActiveRefState {
            repository: identity.clone(),
            repository_generation: RepositoryGeneration(7),
            trust_generation: TrustGeneration(8),
            revocation_generation: RevocationGeneration(9),
            pack_generation: PackGeneration(1),
            object_format: ObjectFormat::Sha256,
            default_branch: FullRefName::parse("refs/heads/main").unwrap(),
            refs: [(FullRefName::parse("refs/heads/main").unwrap(), old)].into(),
        };
        let refs = path(&root, "refs");
        ActiveRefFile::initialize(&refs, &active).unwrap();
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
        let mut input = Reader { bytes, offset: 0 };
        let mut verifier = ExactVerifier {
            repository: identity.clone(),
            generation: RepositoryGeneration(7),
            trust: TrustGeneration(8),
            revocations: RevocationGeneration(9),
            expected: new,
        };
        let prepared = prepare_protected_receive(
            SmartGitRequest {
                repository: identity,
                repository_generation: RepositoryGeneration(7),
                operation: SmartGitOperation::ReceivePack,
                object_format: ObjectFormat::Sha256,
            },
            &active,
            &repository,
            &store,
            &mut verifier,
            QuarantineTransactionId([31u8; 16]),
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
            &mut input,
            WorkBudget {
                max_input_bytes: 2 * 1024 * 1024,
                max_output_bytes: 1024 * 1024,
                max_memory_bytes: 1024 * 1024,
                max_work_units: 8 * 1024 * 1024,
            },
        )
        .unwrap();
        assert_eq!(
            prepared.transaction().phase(),
            crate::QuarantinePhase::HistoryVerified
        );
        assert_eq!(prepared.verified().updates()[0].proposed_new(), Some(new));
        assert_eq!(store.active_refs().load().unwrap(), active);
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
