//! Hosted-Linux composition of durable receive storage components.

use crate::{
    ActivationSnapshot, ActiveRefFile, ArrivalPackStore, AuditReceipt, AuditReceiptDirectory,
    DurableFailure, DurableReceiveStore, ObjectFormat, QuarantineTransaction,
    QuarantineTransactionId, ReceiveJournalDirectory, VerifiedRefTransaction,
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
}

impl LinuxDurableReceiveStore {
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
}

impl DurableReceiveStore for LinuxDurableReceiveStore {
    fn persist_journal_and_fsync(
        &mut self,
        transaction: &QuarantineTransaction,
        verified: &VerifiedRefTransaction,
    ) -> Result<(), DurableFailure> {
        let identity = (transaction.id(), transaction.reservation().object_count());
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
        self.refs.activate(verified).map(|_| ())
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
        PushStorageForecast, QuarantineLimits, QuarantinePhase, RepositoryGeneration,
        RepositoryIdentity, RevocationGeneration, TrustGeneration,
        build_verified_fast_forward_transaction, durably_activate_verified_receive,
        encode_pack_with_format, reserve_push_disk, verify_introduced_history,
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
        ActiveRefFile::initialize(
            &ref_path,
            &ActiveRefState {
                repository,
                repository_generation: RepositoryGeneration(7),
                trust_generation: TrustGeneration(8),
                revocation_generation: RevocationGeneration(9),
                pack_generation: PackGeneration(1),
                object_format: ObjectFormat::Sha256,
                default_branch: FullRefName::parse("refs/heads/main").unwrap(),
                refs: [(FullRefName::parse("refs/heads/main").unwrap(), old)].into(),
            },
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
        assert_eq!(store.active_refs().load().unwrap().refs[0].1, new);
        assert_eq!(store.receipts().load(id).unwrap(), receipt);
        assert_eq!(
            ReceiveJournalDirectory::open(&path(&root, "journals"))
                .unwrap()
                .load(id)
                .unwrap()
                .phase,
            QuarantinePhase::AuditReceiptAppended
        );
        ArrivalPackStore::open(&path(&root, "packs"), ObjectFormat::Sha256, 1024 * 1024)
            .unwrap()
            .verify_installed(id, 1)
            .unwrap();
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
