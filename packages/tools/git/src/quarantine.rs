//! Storage-neutral quarantine admission and ordered receive lifecycle.

use crate::{
    ObjectFormat, RepositoryGeneration, RepositoryIdentity, RevocationGeneration, TrustGeneration,
    VerifiedRefTransaction,
};

pub const DEFAULT_MAX_INCOMING_PACK_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_EXPANDED_OBJECT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_INDIVIDUAL_OBJECT_BYTES: u64 = 128 * 1024 * 1024;
pub const DEFAULT_MAX_OBJECTS_PER_PUSH: u32 = 1_000_000;
pub const DEFAULT_MINIMUM_FREE_SPACE_BYTES: u64 = 40 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QuarantineTransactionId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuarantineLimits {
    pub max_incoming_pack_bytes: u64,
    pub max_expanded_object_bytes: u64,
    pub max_individual_object_bytes: u64,
    pub max_objects: u32,
    pub max_refs: u16,
    pub minimum_free_space_bytes: u64,
}

impl Default for QuarantineLimits {
    fn default() -> Self {
        Self {
            max_incoming_pack_bytes: DEFAULT_MAX_INCOMING_PACK_BYTES,
            max_expanded_object_bytes: DEFAULT_MAX_EXPANDED_OBJECT_BYTES,
            max_individual_object_bytes: DEFAULT_MAX_INDIVIDUAL_OBJECT_BYTES,
            max_objects: DEFAULT_MAX_OBJECTS_PER_PUSH,
            max_refs: 32,
            minimum_free_space_bytes: DEFAULT_MINIMUM_FREE_SPACE_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PushStorageForecast {
    pub incoming_pack_bytes: u64,
    pub expanded_object_bytes: u64,
    pub largest_object_bytes: u64,
    pub object_count: u32,
    pub ref_count: u16,
    pub arrival_index_bytes: u64,
    pub staging_metadata_bytes: u64,
    pub audit_receipt_bytes: u64,
    pub ordinary_free_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PushDiskReservation {
    required_bytes: u64,
    incoming_pack_bytes: u64,
    expanded_object_bytes: u64,
    individual_object_bytes: u64,
    object_count: u32,
    ref_count: u16,
}

impl PushDiskReservation {
    pub const fn required_bytes(self) -> u64 {
        self.required_bytes
    }

    pub const fn incoming_pack_bytes(self) -> u64 {
        self.incoming_pack_bytes
    }

    pub const fn object_count(self) -> u32 {
        self.object_count
    }

    pub const fn expanded_object_bytes(self) -> u64 {
        self.expanded_object_bytes
    }

    pub const fn individual_object_bytes(self) -> u64 {
        self.individual_object_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuarantinePhase {
    CandidateReceived,
    ObjectsQuarantined,
    ObjectsValidated,
    HistoryVerified,
    RefUpdatesPrepared,
    ObjectsDurablyInstalled,
    RefsAtomicallyActivated,
    AuditReceiptAppended,
    Aborted,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableFailure {
    DiskFull,
    ShortWrite,
    Fsync,
    Rename,
    StaleLock,
    VerifierCrash,
    AuditReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuarantineError {
    ResourceLimit,
    InsufficientSpace,
    ArithmeticOverflow,
    InvalidTransition,
    StaleGeneration,
    PolicyMismatch,
    CountMismatch,
    Terminal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationSnapshot {
    pub repository_generation: RepositoryGeneration,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    pub refs: mrml_runtime::Vector<(crate::FullRefName, Option<crate::ObjectId>)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditReceipt {
    pub transaction: QuarantineTransactionId,
    pub repository: RepositoryIdentity,
    pub repository_generation: RepositoryGeneration,
    pub activated_repository_generation: RepositoryGeneration,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    pub updates: mrml_runtime::Vector<(crate::FullRefName, crate::ObjectId, crate::ObjectId)>,
}

/// Storage authority used only after history has produced a private verified
/// transaction. Each successful method includes the durability guarantee in
/// its name; implementations must not return success before that guarantee is
/// true.
pub trait DurableReceiveStore {
    fn persist_journal_and_fsync(
        &mut self,
        transaction: &QuarantineTransaction,
        verified: &VerifiedRefTransaction,
    ) -> Result<(), DurableFailure>;
    fn install_arrival_pack_and_fsync(
        &mut self,
        transaction: QuarantineTransactionId,
    ) -> Result<(), DurableFailure>;
    fn reread_activation_snapshot(
        &mut self,
        verified: &VerifiedRefTransaction,
    ) -> Result<ActivationSnapshot, DurableFailure>;
    fn activate_refs_atomically_and_fsync(
        &mut self,
        verified: &VerifiedRefTransaction,
    ) -> Result<(), DurableFailure>;
    fn append_audit_receipt_and_fsync(
        &mut self,
        receipt: &AuditReceipt,
    ) -> Result<(), DurableFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableReceiveError {
    InvalidState,
    StaleAuthority,
    Aborted(DurableFailure),
    Uncertain(DurableFailure),
}

pub fn reserve_push_disk(
    limits: QuarantineLimits,
    forecast: PushStorageForecast,
) -> Result<PushDiskReservation, QuarantineError> {
    if forecast.incoming_pack_bytes == 0
        || forecast.incoming_pack_bytes > limits.max_incoming_pack_bytes
        || forecast.expanded_object_bytes > limits.max_expanded_object_bytes
        || forecast.largest_object_bytes > limits.max_individual_object_bytes
        || forecast.object_count == 0
        || forecast.object_count > limits.max_objects
        || forecast.ref_count == 0
        || forecast.ref_count > limits.max_refs
    {
        return Err(QuarantineError::ResourceLimit);
    }
    // The conservative peak includes the incoming quarantine bytes, expanded
    // validation material, a separately durable immutable arrival pack, its
    // index, transaction metadata, receipt, and the mandatory ordinary reserve.
    let required_bytes = forecast
        .incoming_pack_bytes
        .checked_add(forecast.expanded_object_bytes)
        .and_then(|value| value.checked_add(forecast.incoming_pack_bytes))
        .and_then(|value| value.checked_add(forecast.arrival_index_bytes))
        .and_then(|value| value.checked_add(forecast.staging_metadata_bytes))
        .and_then(|value| value.checked_add(forecast.audit_receipt_bytes))
        .and_then(|value| value.checked_add(limits.minimum_free_space_bytes))
        .ok_or(QuarantineError::ArithmeticOverflow)?;
    if forecast.ordinary_free_bytes < required_bytes {
        return Err(QuarantineError::InsufficientSpace);
    }
    Ok(PushDiskReservation {
        required_bytes,
        incoming_pack_bytes: forecast.incoming_pack_bytes,
        expanded_object_bytes: forecast.expanded_object_bytes,
        individual_object_bytes: forecast.largest_object_bytes,
        object_count: forecast.object_count,
        ref_count: forecast.ref_count,
    })
}

/// Reserves a conservative receive envelope before any pack-body byte is
/// consumed. Git's wire protocol does not declare expanded size or object
/// count ahead of the pack header, so this uses the configured maxima; the
/// later validation phase binds the actual nonzero count and expanded bytes.
pub fn reserve_push_disk_before_body(
    limits: QuarantineLimits,
    format: ObjectFormat,
    incoming_pack_bytes: u64,
    ref_count: u16,
    ordinary_free_bytes: u64,
) -> Result<PushDiskReservation, QuarantineError> {
    let per_object_index = u64::try_from(format.hash_len())
        .map_err(|_| QuarantineError::ArithmeticOverflow)?
        .checked_add(16)
        .ok_or(QuarantineError::ArithmeticOverflow)?;
    let arrival_index_bytes = 8u64
        .checked_add(256 * 4)
        .and_then(|value| value.checked_add(u64::from(limits.max_objects) * per_object_index))
        .and_then(|value| value.checked_add((format.hash_len() * 2) as u64))
        .ok_or(QuarantineError::ArithmeticOverflow)?;
    reserve_push_disk(
        limits,
        PushStorageForecast {
            incoming_pack_bytes,
            expanded_object_bytes: limits.max_expanded_object_bytes,
            largest_object_bytes: limits.max_individual_object_bytes,
            object_count: limits.max_objects,
            ref_count,
            arrival_index_bytes,
            staging_metadata_bytes: 1024 * 1024,
            audit_receipt_bytes: 64 * 1024,
            ordinary_free_bytes,
        },
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineTransaction {
    id: QuarantineTransactionId,
    repository: RepositoryIdentity,
    repository_generation: RepositoryGeneration,
    trust_generation: TrustGeneration,
    revocation_generation: RevocationGeneration,
    reservation: PushDiskReservation,
    validated_object_count: Option<u32>,
    validated_expanded_bytes: Option<u64>,
    phase: QuarantinePhase,
    failure: Option<DurableFailure>,
}

impl QuarantineTransaction {
    pub fn begin(
        id: QuarantineTransactionId,
        repository: RepositoryIdentity,
        repository_generation: RepositoryGeneration,
        trust_generation: TrustGeneration,
        revocation_generation: RevocationGeneration,
        reservation: PushDiskReservation,
    ) -> Result<Self, QuarantineError> {
        if id.0 == [0u8; 16]
            || repository_generation.0 == 0
            || trust_generation.0 == 0
            || revocation_generation.0 == 0
        {
            return Err(QuarantineError::StaleGeneration);
        }
        Ok(Self {
            id,
            repository,
            repository_generation,
            trust_generation,
            revocation_generation,
            reservation,
            validated_object_count: None,
            validated_expanded_bytes: None,
            phase: QuarantinePhase::CandidateReceived,
            failure: None,
        })
    }

    pub const fn phase(&self) -> QuarantinePhase {
        self.phase
    }

    pub const fn id(&self) -> QuarantineTransactionId {
        self.id
    }

    pub fn repository(&self) -> &RepositoryIdentity {
        &self.repository
    }

    pub const fn repository_generation(&self) -> RepositoryGeneration {
        self.repository_generation
    }

    pub const fn trust_generation(&self) -> TrustGeneration {
        self.trust_generation
    }

    pub const fn revocation_generation(&self) -> RevocationGeneration {
        self.revocation_generation
    }

    pub const fn reservation(&self) -> PushDiskReservation {
        self.reservation
    }

    pub const fn validated_object_count(&self) -> Option<u32> {
        self.validated_object_count
    }

    pub const fn validated_expanded_bytes(&self) -> Option<u64> {
        self.validated_expanded_bytes
    }

    pub const fn failure(&self) -> Option<DurableFailure> {
        self.failure
    }

    pub fn objects_quarantined(&mut self, bytes_written: u64) -> Result<(), QuarantineError> {
        if bytes_written != self.reservation.incoming_pack_bytes {
            return Err(QuarantineError::CountMismatch);
        }
        self.advance(
            QuarantinePhase::CandidateReceived,
            QuarantinePhase::ObjectsQuarantined,
        )
    }

    pub fn objects_validated(
        &mut self,
        expanded_bytes: u64,
        object_count: u32,
    ) -> Result<(), QuarantineError> {
        if expanded_bytes > self.reservation.expanded_object_bytes
            || object_count == 0
            || object_count > self.reservation.object_count
        {
            return Err(QuarantineError::CountMismatch);
        }
        self.advance(
            QuarantinePhase::ObjectsQuarantined,
            QuarantinePhase::ObjectsValidated,
        )?;
        self.validated_object_count = Some(object_count);
        self.validated_expanded_bytes = Some(expanded_bytes);
        Ok(())
    }

    pub fn history_verified(
        &mut self,
        verified: &VerifiedRefTransaction,
    ) -> Result<(), QuarantineError> {
        if verified.repository() != &self.repository
            || verified.repository_generation() != self.repository_generation
            || verified.trust_generation() != self.trust_generation
            || verified.revocation_generation() != self.revocation_generation
        {
            return Err(QuarantineError::PolicyMismatch);
        }
        if verified.updates().len() != usize::from(self.reservation.ref_count) {
            return Err(QuarantineError::CountMismatch);
        }
        self.advance(
            QuarantinePhase::ObjectsValidated,
            QuarantinePhase::HistoryVerified,
        )
    }

    pub fn ref_updates_prepared(&mut self) -> Result<(), QuarantineError> {
        self.advance(
            QuarantinePhase::HistoryVerified,
            QuarantinePhase::RefUpdatesPrepared,
        )
    }

    pub fn objects_durably_installed(&mut self) -> Result<(), QuarantineError> {
        self.advance(
            QuarantinePhase::RefUpdatesPrepared,
            QuarantinePhase::ObjectsDurablyInstalled,
        )
    }

    pub fn refs_atomically_activated(&mut self) -> Result<(), QuarantineError> {
        self.advance(
            QuarantinePhase::ObjectsDurablyInstalled,
            QuarantinePhase::RefsAtomicallyActivated,
        )
    }

    pub fn audit_receipt_appended(&mut self) -> Result<(), QuarantineError> {
        self.advance(
            QuarantinePhase::RefsAtomicallyActivated,
            QuarantinePhase::AuditReceiptAppended,
        )
    }

    pub fn fail(&mut self, failure: DurableFailure) -> Result<(), QuarantineError> {
        if matches!(
            self.phase,
            QuarantinePhase::Aborted | QuarantinePhase::Uncertain
        ) {
            return Err(QuarantineError::Terminal);
        }
        self.failure = Some(failure);
        self.phase = if matches!(
            self.phase,
            QuarantinePhase::ObjectsDurablyInstalled
                | QuarantinePhase::RefsAtomicallyActivated
                | QuarantinePhase::AuditReceiptAppended
        ) || failure == DurableFailure::AuditReceipt
        {
            QuarantinePhase::Uncertain
        } else {
            QuarantinePhase::Aborted
        };
        Ok(())
    }

    fn advance(
        &mut self,
        expected: QuarantinePhase,
        next: QuarantinePhase,
    ) -> Result<(), QuarantineError> {
        if self.phase != expected {
            return Err(QuarantineError::InvalidTransition);
        }
        self.phase = next;
        Ok(())
    }
}

fn record_failure(
    transaction: &mut QuarantineTransaction,
    verified: &VerifiedRefTransaction,
    store: &mut dyn DurableReceiveStore,
    failure: DurableFailure,
) -> DurableReceiveError {
    let _ = transaction.fail(failure);
    let _ = store.persist_journal_and_fsync(transaction, verified);
    if transaction.phase() == QuarantinePhase::Uncertain {
        DurableReceiveError::Uncertain(failure)
    } else {
        DurableReceiveError::Aborted(failure)
    }
}

pub fn durably_activate_verified_receive(
    transaction: &mut QuarantineTransaction,
    verified: &VerifiedRefTransaction,
    store: &mut dyn DurableReceiveStore,
) -> Result<AuditReceipt, DurableReceiveError> {
    transaction
        .ref_updates_prepared()
        .map_err(|_| DurableReceiveError::InvalidState)?;
    if let Err(failure) = store.persist_journal_and_fsync(transaction, verified) {
        return Err(record_failure(transaction, verified, store, failure));
    }
    if let Err(failure) = store.install_arrival_pack_and_fsync(transaction.id()) {
        return Err(record_failure(transaction, verified, store, failure));
    }
    transaction
        .objects_durably_installed()
        .map_err(|_| DurableReceiveError::InvalidState)?;
    if let Err(failure) = store.persist_journal_and_fsync(transaction, verified) {
        return Err(record_failure(transaction, verified, store, failure));
    }

    let snapshot = match store.reread_activation_snapshot(verified) {
        Ok(snapshot) => snapshot,
        Err(failure) => return Err(record_failure(transaction, verified, store, failure)),
    };
    let exact_generations = snapshot.repository_generation == verified.repository_generation()
        && snapshot.trust_generation == verified.trust_generation()
        && snapshot.revocation_generation == verified.revocation_generation();
    let exact_refs = snapshot.refs.len() == verified.updates().len()
        && verified.updates().iter().all(|update| {
            snapshot
                .refs
                .iter()
                .any(|(name, value)| name == update.name() && *value == update.expected_old())
        });
    if !exact_generations || !exact_refs {
        let _ = record_failure(transaction, verified, store, DurableFailure::StaleLock);
        return Err(DurableReceiveError::StaleAuthority);
    }
    if let Err(failure) = store.activate_refs_atomically_and_fsync(verified) {
        return Err(record_failure(transaction, verified, store, failure));
    }
    transaction
        .refs_atomically_activated()
        .map_err(|_| DurableReceiveError::InvalidState)?;
    if let Err(failure) = store.persist_journal_and_fsync(transaction, verified) {
        return Err(record_failure(transaction, verified, store, failure));
    }

    let mut updates = mrml_runtime::Vector::new();
    for update in verified.updates() {
        let old = update
            .expected_old()
            .ok_or(DurableReceiveError::InvalidState)?;
        let new = update
            .proposed_new()
            .ok_or(DurableReceiveError::InvalidState)?;
        updates.push((update.name().clone(), old, new));
    }
    updates.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let activated_repository_generation = RepositoryGeneration(
        verified
            .repository_generation()
            .0
            .checked_add(1)
            .ok_or(DurableReceiveError::InvalidState)?,
    );
    let receipt = AuditReceipt {
        transaction: transaction.id(),
        repository: verified.repository().clone(),
        repository_generation: verified.repository_generation(),
        activated_repository_generation,
        trust_generation: verified.trust_generation(),
        revocation_generation: verified.revocation_generation(),
        updates,
    };
    if let Err(failure) = store.append_audit_receipt_and_fsync(&receipt) {
        return Err(record_failure(transaction, verified, store, failure));
    }
    transaction
        .audit_receipt_appended()
        .map_err(|_| DurableReceiveError::InvalidState)?;
    if let Err(failure) = store.persist_journal_and_fsync(transaction, verified) {
        return Err(record_failure(transaction, verified, store, failure));
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CandidateRefTransaction, CandidateRefUpdate, FullRefName, HistoryVerificationLimits,
        ObjectId, build_verified_fast_forward_transaction, verify_introduced_history,
    };
    use mrml_runtime::Vector;

    struct MockDurableStore {
        snapshot: ActivationSnapshot,
        phases: Vector<QuarantinePhase>,
        install_count: u8,
        activation_count: u8,
        receipt_count: u8,
        journal_failure_at: Option<QuarantinePhase>,
        install_failure: Option<DurableFailure>,
        snapshot_failure: Option<DurableFailure>,
        activation_failure: Option<DurableFailure>,
        receipt_failure: Option<DurableFailure>,
    }

    impl DurableReceiveStore for MockDurableStore {
        fn persist_journal_and_fsync(
            &mut self,
            transaction: &QuarantineTransaction,
            _: &VerifiedRefTransaction,
        ) -> Result<(), DurableFailure> {
            self.phases.push(transaction.phase());
            if self.journal_failure_at == Some(transaction.phase()) {
                Err(DurableFailure::Fsync)
            } else {
                Ok(())
            }
        }

        fn install_arrival_pack_and_fsync(
            &mut self,
            _: QuarantineTransactionId,
        ) -> Result<(), DurableFailure> {
            self.install_count += 1;
            self.install_failure.map_or(Ok(()), Err)
        }

        fn reread_activation_snapshot(
            &mut self,
            _: &VerifiedRefTransaction,
        ) -> Result<ActivationSnapshot, DurableFailure> {
            self.snapshot_failure
                .map_or_else(|| Ok(self.snapshot.clone()), Err)
        }

        fn activate_refs_atomically_and_fsync(
            &mut self,
            _: &VerifiedRefTransaction,
        ) -> Result<(), DurableFailure> {
            self.activation_count += 1;
            self.activation_failure.map_or(Ok(()), Err)
        }

        fn append_audit_receipt_and_fsync(
            &mut self,
            _: &AuditReceipt,
        ) -> Result<(), DurableFailure> {
            self.receipt_count += 1;
            self.receipt_failure.map_or(Ok(()), Err)
        }
    }

    fn reservation(ref_count: u16) -> PushDiskReservation {
        reserve_push_disk(
            QuarantineLimits::default(),
            PushStorageForecast {
                incoming_pack_bytes: 1024,
                expanded_object_bytes: 4096,
                largest_object_bytes: 2048,
                object_count: 2,
                ref_count,
                arrival_index_bytes: 512,
                staging_metadata_bytes: 256,
                audit_receipt_bytes: 128,
                ordinary_free_bytes: DEFAULT_MINIMUM_FREE_SPACE_BYTES + 10_000,
            },
        )
        .unwrap()
    }

    #[test]
    fn reservation_is_conservative_and_rejects_before_body() {
        let reserved = reservation(1);
        assert_eq!(
            reserved.required_bytes(),
            DEFAULT_MINIMUM_FREE_SPACE_BYTES + 1024 + 4096 + 1024 + 512 + 256 + 128
        );
        let mut forecast = PushStorageForecast {
            incoming_pack_bytes: DEFAULT_MAX_INCOMING_PACK_BYTES + 1,
            expanded_object_bytes: 1,
            largest_object_bytes: 1,
            object_count: 1,
            ref_count: 1,
            arrival_index_bytes: 1,
            staging_metadata_bytes: 1,
            audit_receipt_bytes: 1,
            ordinary_free_bytes: u64::MAX,
        };
        assert_eq!(
            reserve_push_disk(QuarantineLimits::default(), forecast),
            Err(QuarantineError::ResourceLimit)
        );
        forecast.incoming_pack_bytes = DEFAULT_MAX_INCOMING_PACK_BYTES;
        forecast.ordinary_free_bytes = u64::MAX;
        let maximum = reserve_push_disk(QuarantineLimits::default(), forecast).unwrap();
        assert_eq!(
            maximum.incoming_pack_bytes(),
            DEFAULT_MAX_INCOMING_PACK_BYTES
        );
        forecast.incoming_pack_bytes = 1;
        forecast.ordinary_free_bytes = 1;
        assert_eq!(
            reserve_push_disk(QuarantineLimits::default(), forecast),
            Err(QuarantineError::InsufficientSpace)
        );

        let limits = QuarantineLimits {
            max_incoming_pack_bytes: 4096,
            max_expanded_object_bytes: 8192,
            max_individual_object_bytes: 2048,
            max_objects: 16,
            minimum_free_space_bytes: 0,
            ..QuarantineLimits::default()
        };
        let prebody =
            reserve_push_disk_before_body(limits, ObjectFormat::Sha256, 1024, 2, 10_000_000)
                .unwrap();
        assert_eq!(prebody.incoming_pack_bytes(), 1024);
        assert_eq!(prebody.object_count(), 16);
    }

    #[test]
    fn validated_pack_binds_actual_count_within_prebody_reservation() {
        let mut transaction = QuarantineTransaction::begin(
            QuarantineTransactionId([21u8; 16]),
            RepositoryIdentity::parse("owner/repository").unwrap(),
            RepositoryGeneration(1),
            TrustGeneration(1),
            RevocationGeneration(1),
            reservation(1),
        )
        .unwrap();
        transaction.objects_quarantined(1024).unwrap();
        transaction.objects_validated(2048, 1).unwrap();
        assert_eq!(transaction.validated_object_count(), Some(1));
    }

    #[test]
    fn lifecycle_binds_verified_transaction_and_models_uncertainty() {
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let old = ObjectId::Sha1([1u8; 20]);
        let new = ObjectId::Sha1([2u8; 20]);
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
                repository_generation: RepositoryGeneration(3),
                trust_generation: TrustGeneration(4),
                revocation_generation: RevocationGeneration(5),
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
        let mut transaction = QuarantineTransaction::begin(
            QuarantineTransactionId([7u8; 16]),
            repository,
            RepositoryGeneration(3),
            TrustGeneration(4),
            RevocationGeneration(5),
            reservation(1),
        )
        .unwrap();
        assert_eq!(
            transaction.ref_updates_prepared(),
            Err(QuarantineError::InvalidTransition)
        );
        transaction.objects_quarantined(1024).unwrap();
        transaction.objects_validated(4096, 2).unwrap();
        transaction.history_verified(&verified).unwrap();
        transaction.ref_updates_prepared().unwrap();
        transaction.objects_durably_installed().unwrap();
        transaction.fail(DurableFailure::Fsync).unwrap();
        assert_eq!(transaction.phase(), QuarantinePhase::Uncertain);
        assert_eq!(transaction.failure(), Some(DurableFailure::Fsync));
    }

    fn ready_receive() -> (QuarantineTransaction, VerifiedRefTransaction, ObjectId) {
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let old = ObjectId::Sha1([1u8; 20]);
        let new = ObjectId::Sha1([2u8; 20]);
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
                repository_generation: RepositoryGeneration(3),
                trust_generation: TrustGeneration(4),
                revocation_generation: RevocationGeneration(5),
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
        let mut transaction = QuarantineTransaction::begin(
            QuarantineTransactionId([8u8; 16]),
            repository,
            RepositoryGeneration(3),
            TrustGeneration(4),
            RevocationGeneration(5),
            reservation(1),
        )
        .unwrap();
        transaction.objects_quarantined(1024).unwrap();
        transaction.objects_validated(4096, 2).unwrap();
        transaction.history_verified(&verified).unwrap();
        (transaction, verified, old)
    }

    fn store_for(verified: &VerifiedRefTransaction, old: ObjectId) -> MockDurableStore {
        MockDurableStore {
            snapshot: ActivationSnapshot {
                repository_generation: verified.repository_generation(),
                trust_generation: verified.trust_generation(),
                revocation_generation: verified.revocation_generation(),
                refs: [(verified.updates()[0].name().clone(), Some(old))].into(),
            },
            phases: Vector::new(),
            install_count: 0,
            activation_count: 0,
            receipt_count: 0,
            journal_failure_at: None,
            install_failure: None,
            snapshot_failure: None,
            activation_failure: None,
            receipt_failure: None,
        }
    }

    #[test]
    fn durable_receive_orders_install_reread_atomic_activation_and_receipt() {
        let (mut transaction, verified, old) = ready_receive();
        let mut store = store_for(&verified, old);
        let receipt =
            durably_activate_verified_receive(&mut transaction, &verified, &mut store).unwrap();
        assert_eq!(transaction.phase(), QuarantinePhase::AuditReceiptAppended);
        assert_eq!(store.install_count, 1);
        assert_eq!(store.activation_count, 1);
        assert_eq!(store.receipt_count, 1);
        assert_eq!(receipt.updates[0].1, old);
        assert_eq!(
            &*store.phases,
            &[
                QuarantinePhase::RefUpdatesPrepared,
                QuarantinePhase::ObjectsDurablyInstalled,
                QuarantinePhase::RefsAtomicallyActivated,
                QuarantinePhase::AuditReceiptAppended,
            ]
        );
    }

    #[test]
    fn stale_reread_never_calls_activation_and_activation_failure_is_uncertain() {
        let (mut transaction, verified, old) = ready_receive();
        let mut stale = store_for(&verified, old);
        stale.snapshot.refs[0].1 = Some(ObjectId::Sha1([9u8; 20]));
        assert_eq!(
            durably_activate_verified_receive(&mut transaction, &verified, &mut stale),
            Err(DurableReceiveError::StaleAuthority)
        );
        assert_eq!(stale.activation_count, 0);
        assert_eq!(transaction.phase(), QuarantinePhase::Uncertain);

        let (mut transaction, verified, old) = ready_receive();
        let mut failing = store_for(&verified, old);
        failing.activation_failure = Some(DurableFailure::Fsync);
        assert_eq!(
            durably_activate_verified_receive(&mut transaction, &verified, &mut failing),
            Err(DurableReceiveError::Uncertain(DurableFailure::Fsync))
        );
        assert_eq!(transaction.phase(), QuarantinePhase::Uncertain);
        assert_eq!(failing.receipt_count, 0);

        let (mut transaction, verified, old) = ready_receive();
        let mut receipt_failure = store_for(&verified, old);
        receipt_failure.receipt_failure = Some(DurableFailure::AuditReceipt);
        assert_eq!(
            durably_activate_verified_receive(&mut transaction, &verified, &mut receipt_failure),
            Err(DurableReceiveError::Uncertain(DurableFailure::AuditReceipt))
        );
        assert_eq!(receipt_failure.activation_count, 1);
        assert_eq!(transaction.phase(), QuarantinePhase::Uncertain);
    }

    #[test]
    fn every_durable_boundary_failure_is_classified_without_false_success() {
        let cases = [
            (
                Some(QuarantinePhase::RefUpdatesPrepared),
                None,
                None,
                DurableReceiveError::Aborted(DurableFailure::Fsync),
                0,
            ),
            (
                None,
                Some(DurableFailure::DiskFull),
                None,
                DurableReceiveError::Aborted(DurableFailure::DiskFull),
                0,
            ),
            (
                Some(QuarantinePhase::ObjectsDurablyInstalled),
                None,
                None,
                DurableReceiveError::Uncertain(DurableFailure::Fsync),
                0,
            ),
            (
                None,
                None,
                Some(DurableFailure::VerifierCrash),
                DurableReceiveError::Uncertain(DurableFailure::VerifierCrash),
                0,
            ),
            (
                Some(QuarantinePhase::RefsAtomicallyActivated),
                None,
                None,
                DurableReceiveError::Uncertain(DurableFailure::Fsync),
                1,
            ),
            (
                Some(QuarantinePhase::AuditReceiptAppended),
                None,
                None,
                DurableReceiveError::Uncertain(DurableFailure::Fsync),
                1,
            ),
        ];
        for (journal_failure_at, install_failure, snapshot_failure, expected, activations) in cases {
            let (mut transaction, verified, old) = ready_receive();
            let mut store = store_for(&verified, old);
            store.journal_failure_at = journal_failure_at;
            store.install_failure = install_failure;
            store.snapshot_failure = snapshot_failure;
            assert_eq!(
                durably_activate_verified_receive(&mut transaction, &verified, &mut store),
                Err(expected)
            );
            assert_eq!(store.activation_count, activations);
            assert!(matches!(
                transaction.phase(),
                QuarantinePhase::Aborted | QuarantinePhase::Uncertain
            ));
        }
    }
}
