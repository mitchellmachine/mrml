//! Hosted-Linux composition of durable receive storage components.

use crate::{
    ActivationSnapshot, ActiveRefFile, ArrivalPackStore, AuditReceipt, AuditReceiptDirectory,
    ActiveRefState, BoundedRead, DurableFailure, DurableReceiveStore, GitdCoreError, Object,
    ObjectFormat, ObjectId, PackError, QuarantineTransaction, QuarantineTransactionId,
    ReceiveJournalDirectory, ReceiveJournalError, ReceiveJournalRecord, RecoveryAction, Repository,
    PackGeneration, PackSetLimits, VerifiedRefTransaction, classify_receive_recovery,
};
use crate::pack_set::{
    AuthenticatedPackIndexSummary, build_pack_set_manifest,
};

/// Concrete storage ordering backend. Receipt records are currently
/// checksum-protected but not signed, so protected-profile deployment must
/// remain disabled until an isolated receipt-signing authority wraps this
/// backend.
pub struct LinuxDurableReceiveStore {
    journals: ReceiveJournalDirectory,
    arrivals: ArrivalPackStore,
    refs: ActiveRefFile,
    receipts: AuditReceiptDirectory,
    pending: Option<(QuarantineTransactionId, u32)>,
    pending_summary: Option<AuthenticatedPackIndexSummary>,
}

const fn receive_pack_set_limits() -> PackSetLimits {
    PackSetLimits {
        max_packs: 65_536,
        max_objects: 10_000_000,
        max_pack_bytes: 8 * 1024 * 1024 * 1024 * 1024,
        max_index_bytes: 16 * 1024 * 1024 * 1024,
        max_work_units: 16 * 1024 * 1024 * 1024 * 1024,
    }
}

impl LinuxDurableReceiveStore {
    pub(crate) fn receive_pack_body(
        &self,
        transaction: &mut QuarantineTransaction,
        input: &mut dyn BoundedRead,
    ) -> Result<(), GitdCoreError> {
        self.arrivals.receive_pack_body(transaction, input)
    }

    pub(crate) fn validate_received_pack_with_active_bases(
        &self,
        transaction: &mut QuarantineTransaction,
        required_tips: &[ObjectId],
        expected_active: &ActiveRefState,
        active_objects: &Repository,
    ) -> Result<(), GitdCoreError> {
        if self
            .refs
            .load()
            .map_err(|_| GitdCoreError::Storage)?
            != *expected_active
            || active_objects.object_format() != expected_active.object_format
            || transaction.repository() != &expected_active.repository
            || transaction.repository_generation() != expected_active.repository_generation
        {
            return Err(GitdCoreError::StaleGeneration);
        }
        self.arrivals.validate_received_pack_with_bases(
            transaction,
            required_tips,
            |id, limit| {
                let object = match active_objects.read_object(id) {
                    Ok(object) => object,
                    Err(_) => return Ok(None),
                };
                if object.contents.len() as u64 > limit {
                    return Err(PackError::TooLarge);
                }
                Ok(Some((object.kind, object.contents)))
            },
        )
    }

    pub(crate) fn read_quarantined_object(
        &self,
        transaction: QuarantineTransactionId,
        id: ObjectId,
        max_bytes: u64,
    ) -> Result<Object, GitdCoreError> {
        self.arrivals
            .read_quarantined_object(transaction, id, max_bytes)
    }

    pub fn open(
        journals: &str,
        arrivals: &str,
        refs: &str,
        receipts: &str,
        format: ObjectFormat,
        max_pack_bytes: u64,
    ) -> Result<Self, DurableFailure> {
        Ok(Self {
            journals: ReceiveJournalDirectory::open(journals)?,
            arrivals: ArrivalPackStore::open(arrivals, format, max_pack_bytes)?,
            refs: ActiveRefFile::open(refs).map_err(|_| DurableFailure::VerifierCrash)?,
            receipts: AuditReceiptDirectory::open(receipts)?,
            pending: None,
            pending_summary: None,
        })
    }

    pub fn stage_pack(
        &self,
        transaction: &QuarantineTransaction,
        verified: &VerifiedRefTransaction,
        pack: &[u8],
    ) -> Result<(), DurableFailure> {
        if transaction.repository() != verified.repository()
            || transaction.repository_generation() != verified.repository_generation()
            || transaction.trust_generation() != verified.trust_generation()
            || transaction.revocation_generation() != verified.revocation_generation()
        {
            return Err(DurableFailure::VerifierCrash);
        }
        let mut tips = mrml_runtime::Vector::new();
        tips.try_reserve_exact(verified.updates().len())
            .map_err(|_| DurableFailure::DiskFull)?;
        for update in verified.updates() {
            tips.push(update.proposed_new().ok_or(DurableFailure::VerifierCrash)?);
        }
        self.arrivals.stage(transaction, &tips, pack)
    }

    pub fn active_refs(&self) -> &ActiveRefFile {
        &self.refs
    }

    pub fn receipts(&self) -> &AuditReceiptDirectory {
        &self.receipts
    }

    /// Re-reads the exact active ref generation for a durable journal. This is
    /// deliberately journal-driven: recovery never reconstructs a verified
    /// transaction or treats object IDs in the journal as fresh authority.
    pub fn recovery_snapshot(
        &self,
        journal: &ReceiveJournalRecord,
    ) -> Result<ActivationSnapshot, DurableFailure> {
        let state = self
            .refs
            .load()
            .map_err(|_| DurableFailure::VerifierCrash)?;
        if state.repository != journal.repository {
            return Err(DurableFailure::StaleLock);
        }
        let mut refs = mrml_runtime::Vector::new();
        refs.try_reserve_exact(journal.updates.len())
            .map_err(|_| DurableFailure::DiskFull)?;
        for update in &journal.updates {
            let value = state
                .refs
                .iter()
                .find(|(name, _)| name == &update.name)
                .map(|(_, id)| *id);
            refs.push((update.name.clone(), value));
        }
        Ok(ActivationSnapshot {
            repository_generation: state.repository_generation,
            trust_generation: state.trust_generation,
            revocation_generation: state.revocation_generation,
            refs,
        })
    }

    pub fn recovery_actions(
        &self,
    ) -> Result<mrml_runtime::Vector<(ReceiveJournalRecord, RecoveryAction)>, ReceiveJournalError>
    {
        let journals = self.journals.load_all()?;
        let mut actions = mrml_runtime::Vector::new();
        actions
            .try_reserve_exact(journals.len())
            .map_err(|_| ReceiveJournalError::Resource)?;
        for journal in journals {
            let snapshot = self
                .recovery_snapshot(&journal)
                .map_err(|_| ReceiveJournalError::Mismatch)?;
            let action = classify_receive_recovery(&journal, &snapshot);
            actions.push((journal, action));
        }
        Ok(actions)
    }

    /// Recovers only the post-activation receipt. Any pre-activation state
    /// still requires full history/policy re-verification; divergent state is
    /// never guessed. Existing byte-exact receipts make this idempotent.
    pub fn recover_audit_receipt(
        &self,
        journal: &ReceiveJournalRecord,
    ) -> Result<AuditReceipt, DurableFailure> {
        let snapshot = self.recovery_snapshot(journal)?;
        if classify_receive_recovery(journal, &snapshot) != RecoveryAction::RecoverAuditReceipt {
            return Err(DurableFailure::VerifierCrash);
        }
        let mut updates = mrml_runtime::Vector::new();
        updates
            .try_reserve_exact(journal.updates.len())
            .map_err(|_| DurableFailure::DiskFull)?;
        for update in &journal.updates {
            updates.push((
                update.name.clone(),
                update.expected_old,
                update.proposed_new,
            ));
        }
        updates.sort_unstable_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
        let receipt = AuditReceipt {
            transaction: journal.transaction,
            repository: journal.repository.clone(),
            repository_generation: journal.repository_generation,
            activated_repository_generation: snapshot.repository_generation,
            trust_generation: journal.trust_generation,
            revocation_generation: journal.revocation_generation,
            updates,
        };
        match self.receipts.load(journal.transaction) {
            Ok(existing) if existing == receipt => return Ok(receipt),
            Ok(_) => return Err(DurableFailure::AuditReceipt),
            Err(crate::AuditReceiptError::Malformed) => {}
            Err(_) => return Err(DurableFailure::AuditReceipt),
        }
        self.receipts.append(&receipt)?;
        Ok(receipt)
    }
}

impl DurableReceiveStore for LinuxDurableReceiveStore {
    fn persist_journal_and_fsync(
        &mut self,
        transaction: &QuarantineTransaction,
        verified: &VerifiedRefTransaction,
    ) -> Result<(), DurableFailure> {
        let identity = (
            transaction.id(),
            transaction
                .validated_object_count()
                .ok_or(DurableFailure::VerifierCrash)?,
        );
        if self.pending.is_some_and(|pending| pending != identity) {
            return Err(DurableFailure::StaleLock);
        }
        self.pending = Some(identity);
        self.journals.persist(transaction, verified)
    }

    fn install_arrival_pack_and_fsync(
        &mut self,
        transaction: QuarantineTransactionId,
    ) -> Result<(), DurableFailure> {
        let (pending, object_count) = self.pending.ok_or(DurableFailure::StaleLock)?;
        if pending != transaction {
            return Err(DurableFailure::StaleLock);
        }
        self.arrivals.install(transaction, object_count)
            ?;
        self.pending_summary = Some(
            self.arrivals
                .authenticated_installed_summary(transaction, object_count)?,
        );
        Ok(())
    }

    fn reread_activation_snapshot(
        &mut self,
        verified: &VerifiedRefTransaction,
    ) -> Result<ActivationSnapshot, DurableFailure> {
        self.refs.snapshot_for(verified)
    }

    fn activate_refs_atomically_and_fsync(
        &mut self,
        verified: &VerifiedRefTransaction,
    ) -> Result<(), DurableFailure> {
        let current = self
            .refs
            .load()
            .map_err(|_| DurableFailure::VerifierCrash)?;
        let limits = receive_pack_set_limits();
        let selected = self
            .refs
            .load_selected_pack_set(limits)
            .map_err(|_| DurableFailure::VerifierCrash)?;
        let pending = self
            .pending_summary
            .as_ref()
            .ok_or(DurableFailure::StaleLock)?;
        let mut summaries = mrml_runtime::Vector::new();
        summaries
            .try_reserve_exact(selected.entries().len().saturating_add(1))
            .map_err(|_| DurableFailure::DiskFull)?;
        for entry in selected.entries() {
            let mut object_ids = mrml_runtime::Vector::new();
            object_ids
                .try_extend_from_slice(entry.object_ids())
                .map_err(|_| DurableFailure::DiskFull)?;
            summaries.push(AuthenticatedPackIndexSummary {
                transaction: entry.transaction(),
                object_count: entry.object_count(),
                pack_checksum: entry.pack_checksum(),
                index_checksum: entry.index_checksum(),
                pack_bytes: entry.pack_bytes(),
                index_bytes: entry.index_bytes(),
                work_units: entry.work_units(),
                object_ids,
            });
        }
        summaries.push(pending.clone());
        summaries.sort_unstable_by(|left, right| left.transaction.cmp(&right.transaction));
        let manifest = build_pack_set_manifest(
            current.repository.clone(),
            crate::RepositoryGeneration(
                current
                    .repository_generation
                    .0
                    .checked_add(1)
                    .ok_or(DurableFailure::DiskFull)?,
            ),
            PackGeneration(
                current
                    .pack_generation
                    .0
                    .checked_add(1)
                    .ok_or(DurableFailure::DiskFull)?,
            ),
            current.object_format,
            summaries,
            limits,
        )
        .map_err(|_| DurableFailure::VerifierCrash)?;
        self.refs
            .activate_with_pack_set(verified, &manifest)
            .map(|_| ())
    }

    fn append_audit_receipt_and_fsync(
        &mut self,
        receipt: &AuditReceipt,
    ) -> Result<(), DurableFailure> {
        self.receipts.append(receipt)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use mrml_runtime::{Text, Vector, join_path};

    use super::*;
    use crate::{
        ActiveRefState, CandidateRefTransaction, CandidateRefUpdate, FullRefName,
        HistoryVerificationLimits, ObjectId, ObjectKind, PackGeneration, PackObject,
        PushStorageForecast, QuarantineLimits, QuarantinePhase, RecoveryAction,
        RepositoryGeneration, RepositoryIdentity, RevocationGeneration, TrustGeneration,
        build_verified_fast_forward_transaction, classify_receive_recovery,
        durably_activate_verified_receive, encode_pack_with_format, reserve_push_disk,
        verify_introduced_history,
    };

    fn path(root: &str, child: &str) -> Text {
        join_path(root, child)
    }

    #[test]
    fn complete_linux_receive_reopens_pack_refs_journal_and_receipt() {
        let root = join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-receive-store-{}", mrml_runtime::process_id()),
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        mrml_runtime::create_dir_all(&root).unwrap();
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let old = ObjectId::Sha256([1u8; 32]);
        let blob = PackObject {
            id: ObjectId::blob_with_format(ObjectFormat::Sha256, b"received"),
            kind: ObjectKind::Blob,
            contents: Vector::from(*b"received"),
        };
        let new = blob.id;
        let pack = encode_pack_with_format(&[blob], ObjectFormat::Sha256).unwrap();
        let range = verify_introduced_history(
            old,
            new,
            HistoryVerificationLimits::default(),
            |id| {
                Ok(if id == new {
                    [old].into()
                } else {
                    Vector::new()
                })
            },
            |_| Ok(()),
        )
        .unwrap();
        let verified = build_verified_fast_forward_transaction(
            CandidateRefTransaction {
                repository: repository.clone(),
                repository_generation: RepositoryGeneration(7),
                trust_generation: TrustGeneration(8),
                revocation_generation: RevocationGeneration(9),
                updates: [CandidateRefUpdate {
                    name: FullRefName::parse("refs/heads/main").unwrap(),
                    expected_old: Some(old),
                    proposed_new: Some(new),
                }]
                .into(),
            },
            &[range],
        )
        .unwrap();
        let reservation = reserve_push_disk(
            QuarantineLimits {
                minimum_free_space_bytes: 0,
                ..QuarantineLimits::default()
            },
            PushStorageForecast {
                incoming_pack_bytes: pack.len() as u64,
                expanded_object_bytes: 8,
                largest_object_bytes: 8,
                object_count: 1,
                ref_count: 1,
                arrival_index_bytes: 4096,
                staging_metadata_bytes: 4096,
                audit_receipt_bytes: 4096,
                ordinary_free_bytes: 1_000_000,
            },
        )
        .unwrap();
        let id = QuarantineTransactionId([14u8; 16]);
        let mut transaction = QuarantineTransaction::begin(
            id,
            repository.clone(),
            RepositoryGeneration(7),
            TrustGeneration(8),
            RevocationGeneration(9),
            reservation,
        )
        .unwrap();
        transaction.objects_quarantined(pack.len() as u64).unwrap();
        transaction.objects_validated(8, 1).unwrap();
        transaction.history_verified(&verified).unwrap();

        let ref_path = path(&root, "refs");
        let initial_manifest = build_pack_set_manifest(
            repository.clone(),
            RepositoryGeneration(7),
            PackGeneration(1),
            ObjectFormat::Sha256,
            mrml_runtime::Vector::new(),
            receive_pack_set_limits(),
        )
        .unwrap();
        ActiveRefFile::initialize_with_pack_set(
            &ref_path,
            &ActiveRefState {
                repository,
                repository_generation: RepositoryGeneration(7),
                trust_generation: TrustGeneration(8),
                revocation_generation: RevocationGeneration(9),
                pack_generation: PackGeneration(1),
                pack_set_digest: initial_manifest.digest().unwrap(),
                object_format: ObjectFormat::Sha256,
                default_branch: FullRefName::parse("refs/heads/main").unwrap(),
                refs: [(FullRefName::parse("refs/heads/main").unwrap(), old)].into(),
            },
            &initial_manifest,
        )
        .unwrap();
        let mut store = LinuxDurableReceiveStore::open(
            &path(&root, "journals"),
            &path(&root, "packs"),
            &ref_path,
            &path(&root, "receipts"),
            ObjectFormat::Sha256,
            1024 * 1024,
        )
        .unwrap();
        store.stage_pack(&transaction, &verified, &pack).unwrap();
        let receipt =
            durably_activate_verified_receive(&mut transaction, &verified, &mut store).unwrap();
        assert_eq!(transaction.phase(), QuarantinePhase::AuditReceiptAppended);
        let active = store.active_refs().load().unwrap();
        assert_eq!(active.refs[0].1, new);
        assert_eq!(active.pack_generation, PackGeneration(2));
        let selected = store
            .active_refs()
            .load_selected_pack_set(receive_pack_set_limits())
            .unwrap();
        assert_eq!(selected.entries().len(), 1);
        assert_eq!(selected.entries()[0].transaction(), id);
        assert_eq!(selected.entries()[0].object_ids(), &[new]);
        assert_eq!(store.receipts().load(id).unwrap(), receipt);
        let final_journal = ReceiveJournalDirectory::open(&path(&root, "journals"))
            .unwrap()
            .load(id)
            .unwrap();
        assert_eq!(final_journal.phase, QuarantinePhase::AuditReceiptAppended);
        assert_eq!(
            classify_receive_recovery(
                &final_journal,
                &store.active_refs().snapshot_for(&verified).unwrap(),
            ),
            RecoveryAction::MarkComplete
        );
        assert_eq!(
            store.recovery_actions().unwrap()[0].1,
            RecoveryAction::MarkComplete
        );
        let mut activated_journal = final_journal.clone();
        activated_journal.phase = QuarantinePhase::RefsAtomicallyActivated;
        let recovery_store = LinuxDurableReceiveStore::open(
            &path(&root, "journals"),
            &path(&root, "packs"),
            &ref_path,
            &path(&root, "recovery-receipts"),
            ObjectFormat::Sha256,
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(
            recovery_store
                .recover_audit_receipt(&activated_journal)
                .unwrap(),
            receipt
        );
        assert_eq!(
            recovery_store
                .recover_audit_receipt(&activated_journal)
                .unwrap(),
            receipt
        );
        ArrivalPackStore::open(&path(&root, "packs"), ObjectFormat::Sha256, 1024 * 1024)
            .unwrap()
            .verify_installed(id, 1)
            .unwrap();
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
