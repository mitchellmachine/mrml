//! Storage-neutral quarantine admission and ordered receive lifecycle.

use crate::{
    RepositoryGeneration, RepositoryIdentity, RevocationGeneration, TrustGeneration,
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
        object_count: forecast.object_count,
        ref_count: forecast.ref_count,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineTransaction {
    id: QuarantineTransactionId,
    repository: RepositoryIdentity,
    repository_generation: RepositoryGeneration,
    trust_generation: TrustGeneration,
    revocation_generation: RevocationGeneration,
    reservation: PushDiskReservation,
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
            phase: QuarantinePhase::CandidateReceived,
            failure: None,
        })
    }

    pub const fn phase(&self) -> QuarantinePhase {
        self.phase
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
            || object_count != self.reservation.object_count
        {
            return Err(QuarantineError::CountMismatch);
        }
        self.advance(
            QuarantinePhase::ObjectsQuarantined,
            QuarantinePhase::ObjectsValidated,
        )
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
            QuarantinePhase::AuditReceiptAppended
                | QuarantinePhase::Aborted
                | QuarantinePhase::Uncertain
        ) {
            return Err(QuarantineError::Terminal);
        }
        self.failure = Some(failure);
        self.phase = if matches!(
            self.phase,
            QuarantinePhase::ObjectsDurablyInstalled | QuarantinePhase::RefsAtomicallyActivated
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CandidateRefTransaction, CandidateRefUpdate, FullRefName, HistoryVerificationLimits,
        ObjectId, build_verified_fast_forward_transaction, verify_introduced_history,
    };
    use mrml_runtime::Vector;

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
        forecast.incoming_pack_bytes = 1;
        forecast.ordinary_free_bytes = 1;
        assert_eq!(
            reserve_push_disk(QuarantineLimits::default(), forecast),
            Err(QuarantineError::InsufficientSpace)
        );
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
}
