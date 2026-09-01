use crate::{
    DurableAuthenticator, DurableError, DurableNamespace, DurableObjectId, DurableRecord,
    DurableRecordKind, DurableStateStore, DurableTransaction, ExpiryHealth, RenewalLease,
    RenewalSchedule, RenewalSource, TransactionState,
};
use mrml_acme::AriCertificateId;

const RENEWAL_PAYLOAD_MAGIC: &[u8; 8] = b"MRMLRENU";
pub const RENEWAL_PAYLOAD_VERSION: u16 = 1;
const SCHEDULE_BYTES: usize = 174;
const RENEWAL_PAYLOAD_BYTES: usize = 416;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DurableRenewalStage {
    LeaseAcquired = 1,
    ReplacementStaged = 2,
    ActivationUncertain = 3,
    Active = 4,
    Aborted = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenewalJournalError {
    Durable(DurableError),
    InvalidStage,
    ReceiptMismatch,
    Malformed,
    NotCommitted,
}

impl From<DurableError> for RenewalJournalError {
    fn from(value: DurableError) -> Self {
        Self::Durable(value)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RenewalJournal {
    pub stage: DurableRenewalStage,
    pub lease: RenewalLease,
    pub previous: RenewalSchedule,
    pub replacement: Option<RenewalSchedule>,
    pub record_generation: u64,
}

pub trait RenewalCheckpointSink {
    fn persist(&mut self, journal: RenewalJournal) -> Result<RenewalJournal, RenewalJournalError>;
}

pub struct DurableRenewalCheckpointSink<'a, A, S> {
    object: DurableObjectId,
    authenticator: &'a mut A,
    store: &'a mut S,
}

impl<'a, A, S> DurableRenewalCheckpointSink<'a, A, S> {
    pub fn new(object: DurableObjectId, authenticator: &'a mut A, store: &'a mut S) -> Self {
        Self {
            object,
            authenticator,
            store,
        }
    }
}

impl<A: DurableAuthenticator, S: DurableStateStore> RenewalCheckpointSink
    for DurableRenewalCheckpointSink<'_, A, S>
{
    fn persist(
        &mut self,
        mut journal: RenewalJournal,
    ) -> Result<RenewalJournal, RenewalJournalError> {
        let mut transaction =
            journal.prepare_persist(self.object, self.authenticator, self.store)?;
        if commit_or_resolve_renewal(&mut journal, &mut transaction, self.store)?
            != TransactionState::Committed
        {
            return Err(RenewalJournalError::NotCommitted);
        }
        Ok(journal)
    }
}

impl RenewalJournal {
    pub fn lease_acquired(
        lease: RenewalLease,
        previous: RenewalSchedule,
        record_generation: u64,
    ) -> Result<Self, RenewalJournalError> {
        validate_lease_schedule(lease, previous)?;
        Ok(Self {
            stage: DurableRenewalStage::LeaseAcquired,
            lease,
            previous,
            replacement: None,
            record_generation,
        })
    }

    pub fn replacement_staged(
        mut self,
        replacement: RenewalSchedule,
    ) -> Result<Self, RenewalJournalError> {
        if self.stage != DurableRenewalStage::LeaseAcquired
            || replacement.identity != self.lease.identity
            || replacement.policy_generation != self.lease.policy_generation
            || replacement.identity_generation
                != self
                    .lease
                    .identity_generation
                    .checked_add(1)
                    .ok_or(RenewalJournalError::Malformed)?
            || replacement.certificate_id == self.previous.certificate_id
            || replacement.not_after_unix <= self.previous.not_after_unix
        {
            return Err(RenewalJournalError::ReceiptMismatch);
        }
        self.stage = DurableRenewalStage::ReplacementStaged;
        self.replacement = Some(replacement);
        Ok(self)
    }

    pub fn activation_uncertain(mut self) -> Result<Self, RenewalJournalError> {
        if self.stage != DurableRenewalStage::ReplacementStaged || self.replacement.is_none() {
            return Err(RenewalJournalError::InvalidStage);
        }
        self.stage = DurableRenewalStage::ActivationUncertain;
        Ok(self)
    }

    pub fn active(mut self) -> Result<Self, RenewalJournalError> {
        if !matches!(
            self.stage,
            DurableRenewalStage::ReplacementStaged | DurableRenewalStage::ActivationUncertain
        ) || self.replacement.is_none()
        {
            return Err(RenewalJournalError::InvalidStage);
        }
        self.stage = DurableRenewalStage::Active;
        Ok(self)
    }

    pub fn aborted(mut self) -> Result<Self, RenewalJournalError> {
        if matches!(
            self.stage,
            DurableRenewalStage::ActivationUncertain
                | DurableRenewalStage::Active
                | DurableRenewalStage::Aborted
        ) {
            return Err(RenewalJournalError::InvalidStage);
        }
        self.stage = DurableRenewalStage::Aborted;
        Ok(self)
    }

    pub fn authenticated_record(
        &self,
        object: DurableObjectId,
        authenticator: &mut impl DurableAuthenticator,
    ) -> Result<DurableRecord, RenewalJournalError> {
        let mut payload = [0; RENEWAL_PAYLOAD_BYTES];
        self.encode_payload(&mut payload);
        Ok(DurableRecord::prepare(
            DurableNamespace::PublicState,
            DurableRecordKind::RenewalTransaction,
            object,
            self.record_generation,
            &payload,
            authenticator,
        )?)
    }

    pub fn prepare_persist(
        &self,
        object: DurableObjectId,
        authenticator: &mut impl DurableAuthenticator,
        store: &mut impl DurableStateStore,
    ) -> Result<DurableTransaction, RenewalJournalError> {
        let record = self.authenticated_record(object, authenticator)?;
        Ok(DurableTransaction::prepare(&record, store)?)
    }

    pub fn recover(
        encoded_record: &[u8],
        expected_object: DurableObjectId,
        authenticator: &mut impl DurableAuthenticator,
    ) -> Result<Self, RenewalJournalError> {
        let record = DurableRecord::decode(encoded_record, authenticator)?;
        if record.namespace != DurableNamespace::PublicState
            || record.kind != DurableRecordKind::RenewalTransaction
            || record.object != expected_object
        {
            return Err(RenewalJournalError::Malformed);
        }
        let mut journal = Self::decode_payload(record.payload())?;
        journal.record_generation = record.generation;
        Ok(journal)
    }

    fn encode_payload(&self, output: &mut [u8; RENEWAL_PAYLOAD_BYTES]) {
        output[..8].copy_from_slice(RENEWAL_PAYLOAD_MAGIC);
        output[8..10].copy_from_slice(&RENEWAL_PAYLOAD_VERSION.to_be_bytes());
        output[10] = self.stage as u8;
        output[11..19].copy_from_slice(&self.record_generation.to_be_bytes());
        encode_lease(self.lease, &mut output[19..67]);
        encode_schedule(self.previous, &mut output[67..241]);
        if let Some(replacement) = self.replacement {
            output[241] = 1;
            encode_schedule(replacement, &mut output[242..416]);
        }
    }

    fn decode_payload(input: &[u8]) -> Result<Self, RenewalJournalError> {
        if input.len() != RENEWAL_PAYLOAD_BYTES
            || input[..8] != *RENEWAL_PAYLOAD_MAGIC
            || read_u16(&input[8..10])? != RENEWAL_PAYLOAD_VERSION
        {
            return Err(RenewalJournalError::Malformed);
        }
        let stage = match input[10] {
            1 => DurableRenewalStage::LeaseAcquired,
            2 => DurableRenewalStage::ReplacementStaged,
            3 => DurableRenewalStage::ActivationUncertain,
            4 => DurableRenewalStage::Active,
            5 => DurableRenewalStage::Aborted,
            _ => return Err(RenewalJournalError::Malformed),
        };
        let record_generation = read_u64(&input[11..19])?;
        let lease = decode_lease(&input[19..67])?;
        let previous = decode_schedule(&input[67..241])?;
        let replacement = match input[241] {
            0 if input[242..416].iter().all(|byte| *byte == 0) => None,
            1 => Some(decode_schedule(&input[242..416])?),
            _ => return Err(RenewalJournalError::Malformed),
        };
        validate_lease_schedule(lease, previous)?;
        let journal = Self {
            stage,
            lease,
            previous,
            replacement,
            record_generation,
        };
        match (stage, replacement) {
            (DurableRenewalStage::LeaseAcquired, None) => Ok(journal),
            (DurableRenewalStage::Aborted, None) => Ok(journal),
            (DurableRenewalStage::ReplacementStaged, Some(replacement))
            | (DurableRenewalStage::ActivationUncertain, Some(replacement))
            | (DurableRenewalStage::Active, Some(replacement)) => {
                let staged = Self::lease_acquired(lease, previous, record_generation)?
                    .replacement_staged(replacement)?;
                if staged.replacement == journal.replacement {
                    Ok(journal)
                } else {
                    Err(RenewalJournalError::Malformed)
                }
            }
            (DurableRenewalStage::Aborted, Some(replacement)) => {
                Self::lease_acquired(lease, previous, record_generation)?
                    .replacement_staged(replacement)?;
                Ok(journal)
            }
            _ => Err(RenewalJournalError::Malformed),
        }
    }
}

pub fn commit_or_resolve_renewal(
    journal: &mut RenewalJournal,
    transaction: &mut DurableTransaction,
    store: &mut impl DurableStateStore,
) -> Result<TransactionState, RenewalJournalError> {
    let state = match transaction.commit(store) {
        Ok(_) => TransactionState::Committed,
        Err(DurableError::CommitUncertain) => transaction.resolve(store)?,
        Err(error) => return Err(error.into()),
    };
    if state == TransactionState::Committed {
        journal.record_generation =
            journal
                .record_generation
                .checked_add(1)
                .ok_or(RenewalJournalError::Durable(
                    DurableError::ArithmeticOverflow,
                ))?;
    }
    Ok(state)
}

fn validate_lease_schedule(
    lease: RenewalLease,
    schedule: RenewalSchedule,
) -> Result<(), RenewalJournalError> {
    if lease.identity != schedule.identity
        || lease.identity_generation != schedule.identity_generation
        || lease.policy_generation != schedule.policy_generation
        || lease.lease_generation == 0
        || lease.expires_at_unix == 0
    {
        return Err(RenewalJournalError::ReceiptMismatch);
    }
    Ok(())
}

fn encode_lease(lease: RenewalLease, output: &mut [u8]) {
    output[..16].copy_from_slice(&lease.identity.0);
    output[16..24].copy_from_slice(&lease.identity_generation.to_be_bytes());
    output[24..32].copy_from_slice(&lease.policy_generation.to_be_bytes());
    output[32..40].copy_from_slice(&lease.lease_generation.to_be_bytes());
    output[40..48].copy_from_slice(&lease.expires_at_unix.to_be_bytes());
}

fn decode_lease(input: &[u8]) -> Result<RenewalLease, RenewalJournalError> {
    let mut identity = [0; 16];
    identity.copy_from_slice(&input[..16]);
    Ok(RenewalLease {
        identity: crate::TlsIdentityId(identity),
        identity_generation: read_u64(&input[16..24])?,
        policy_generation: read_u64(&input[24..32])?,
        lease_generation: read_u64(&input[32..40])?,
        expires_at_unix: read_u64(&input[40..48])?,
    })
}

fn encode_schedule(schedule: RenewalSchedule, output: &mut [u8]) {
    output.fill(0);
    output[..16].copy_from_slice(&schedule.identity.0);
    output[16..24].copy_from_slice(&schedule.identity_generation.to_be_bytes());
    output[24..32].copy_from_slice(&schedule.policy_generation.to_be_bytes());
    let certificate_id = schedule.certificate_id.as_str().as_bytes();
    output[32] = certificate_id.len() as u8;
    output[33..33 + certificate_id.len()].copy_from_slice(certificate_id);
    output[147] = match schedule.source {
        RenewalSource::Ari => 1,
        RenewalSource::LifetimeFallback => 2,
    };
    output[148..156].copy_from_slice(&schedule.renew_at_unix.to_be_bytes());
    output[156..164].copy_from_slice(&schedule.requery_ari_at_unix.to_be_bytes());
    output[164..172].copy_from_slice(&schedule.not_after_unix.to_be_bytes());
    output[172] = schedule.failure_count;
    output[173] = match schedule.health {
        ExpiryHealth::Healthy => 1,
        ExpiryHealth::Warning => 2,
        ExpiryHealth::Critical => 3,
        ExpiryHealth::Expired => 4,
    };
}

fn decode_schedule(input: &[u8]) -> Result<RenewalSchedule, RenewalJournalError> {
    if input.len() != SCHEDULE_BYTES {
        return Err(RenewalJournalError::Malformed);
    }
    let mut identity = [0; 16];
    identity.copy_from_slice(&input[..16]);
    let certificate_len = usize::from(input[32]);
    if certificate_len == 0
        || certificate_len > 114
        || input[33 + certificate_len..147]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(RenewalJournalError::Malformed);
    }
    let certificate_id = core::str::from_utf8(&input[33..33 + certificate_len])
        .map_err(|_| RenewalJournalError::Malformed)
        .and_then(|value| {
            AriCertificateId::parse(value).map_err(|_| RenewalJournalError::Malformed)
        })?;
    let source = match input[147] {
        1 => RenewalSource::Ari,
        2 => RenewalSource::LifetimeFallback,
        _ => return Err(RenewalJournalError::Malformed),
    };
    let health = match input[173] {
        1 => ExpiryHealth::Healthy,
        2 => ExpiryHealth::Warning,
        3 => ExpiryHealth::Critical,
        4 => ExpiryHealth::Expired,
        _ => return Err(RenewalJournalError::Malformed),
    };
    Ok(RenewalSchedule {
        identity: crate::TlsIdentityId(identity),
        identity_generation: read_u64(&input[16..24])?,
        policy_generation: read_u64(&input[24..32])?,
        certificate_id,
        source,
        renew_at_unix: read_u64(&input[148..156])?,
        requery_ari_at_unix: read_u64(&input[156..164])?,
        not_after_unix: read_u64(&input[164..172])?,
        failure_count: input[172],
        health,
    })
}

fn read_u16(input: &[u8]) -> Result<u16, RenewalJournalError> {
    Ok(u16::from_be_bytes(
        input
            .try_into()
            .map_err(|_| RenewalJournalError::Malformed)?,
    ))
}

fn read_u64(input: &[u8]) -> Result<u64, RenewalJournalError> {
    Ok(u64::from_be_bytes(
        input
            .try_into()
            .map_err(|_| RenewalJournalError::Malformed)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommittedStoreReceipt, MAX_DURABLE_RECORD_BYTES, PreparedStoreReceipt};
    use mrml_crypto::hmac_sha256;

    struct Auth([u8; 32]);
    impl DurableAuthenticator for Auth {
        fn authenticate(&mut self, record: &[u8]) -> Result<[u8; 32], DurableError> {
            Ok(hmac_sha256(&self.0, &[record]))
        }
        fn verify(&mut self, record: &[u8], tag: &[u8; 32]) -> Result<bool, DurableError> {
            Ok(hmac_sha256(&self.0, &[record]) == *tag)
        }
    }

    struct UncertainStore {
        prepared: Option<PreparedStoreReceipt>,
    }
    impl DurableStateStore for UncertainStore {
        fn prepare(
            &mut self,
            record: &DurableRecord,
        ) -> Result<PreparedStoreReceipt, DurableError> {
            let receipt = PreparedStoreReceipt {
                namespace: record.namespace,
                object: record.object,
                previous_generation: record.previous_generation,
                generation: record.generation,
                payload_digest: record.payload_digest,
                store_generation: 11,
            };
            self.prepared = Some(receipt);
            Ok(receipt)
        }
        fn commit(
            &mut self,
            _: PreparedStoreReceipt,
        ) -> Result<CommittedStoreReceipt, DurableError> {
            Err(DurableError::CommitUncertain)
        }
        fn authoritative(
            &mut self,
            namespace: DurableNamespace,
            object: DurableObjectId,
        ) -> Result<Option<CommittedStoreReceipt>, DurableError> {
            Ok(self
                .prepared
                .filter(|receipt| receipt.namespace == namespace && receipt.object == object)
                .map(|receipt| CommittedStoreReceipt {
                    namespace: receipt.namespace,
                    object: receipt.object,
                    generation: receipt.generation,
                    payload_digest: receipt.payload_digest,
                    store_generation: receipt.store_generation,
                }))
        }
    }

    fn schedule(generation: u64, not_after: u64, id: u8) -> RenewalSchedule {
        RenewalSchedule {
            identity: crate::TlsIdentityId([1; 16]),
            identity_generation: generation,
            policy_generation: 3,
            certificate_id: AriCertificateId::derive(&[id], &[0, id]).unwrap(),
            source: if generation == 1 {
                RenewalSource::Ari
            } else {
                RenewalSource::LifetimeFallback
            },
            renew_at_unix: 100 + generation,
            requery_ari_at_unix: 90 + generation,
            not_after_unix: not_after,
            failure_count: generation as u8,
            health: ExpiryHealth::Warning,
        }
    }

    #[test]
    fn every_restart_boundary_round_trips_as_one_authenticated_generation() {
        let previous = schedule(1, 1_000, 1);
        let replacement = schedule(2, 2_000, 2);
        let lease = RenewalLease {
            identity: previous.identity,
            identity_generation: 1,
            policy_generation: 3,
            lease_generation: 4,
            expires_at_unix: 500,
        };
        let leased = RenewalJournal::lease_acquired(lease, previous, 0).unwrap();
        let staged = leased.replacement_staged(replacement).unwrap();
        let uncertain = staged.activation_uncertain().unwrap();
        let active = uncertain.active().unwrap();
        let aborted_before_issue = leased.aborted().unwrap();
        let aborted_candidate = staged.aborted().unwrap();
        let object = DurableObjectId([7; 16]);
        for expected in [
            leased,
            staged,
            uncertain,
            active,
            aborted_before_issue,
            aborted_candidate,
        ] {
            let mut auth = Auth([9; 32]);
            let record = expected.authenticated_record(object, &mut auth).unwrap();
            let mut encoded = [0; MAX_DURABLE_RECORD_BYTES];
            let written = record.encode(&mut encoded).unwrap();
            let recovered =
                RenewalJournal::recover(&encoded[..written], object, &mut auth).unwrap();
            assert_eq!(recovered.stage, expected.stage);
            assert!(recovered.lease == expected.lease);
            assert!(recovered.previous == expected.previous);
            assert!(recovered.replacement == expected.replacement);
            assert_eq!(recovered.record_generation, 1);
        }
    }

    #[test]
    fn mutation_wrong_object_and_skipped_stage_fail_closed() {
        let previous = schedule(1, 1_000, 1);
        let replacement = schedule(2, 2_000, 2);
        let lease = RenewalLease {
            identity: previous.identity,
            identity_generation: 1,
            policy_generation: 3,
            lease_generation: 4,
            expires_at_unix: 500,
        };
        let journal = RenewalJournal::lease_acquired(lease, previous, 0)
            .unwrap()
            .replacement_staged(replacement)
            .unwrap();
        assert!(matches!(
            RenewalJournal::lease_acquired(lease, previous, 0)
                .unwrap()
                .activation_uncertain(),
            Err(RenewalJournalError::InvalidStage)
        ));
        let object = DurableObjectId([7; 16]);
        let mut auth = Auth([9; 32]);
        let record = journal.authenticated_record(object, &mut auth).unwrap();
        let mut encoded = [0; MAX_DURABLE_RECORD_BYTES];
        let written = record.encode(&mut encoded).unwrap();
        assert!(matches!(
            RenewalJournal::recover(&encoded[..written], DurableObjectId([8; 16]), &mut auth),
            Err(RenewalJournalError::Malformed)
        ));
        encoded[120] ^= 1;
        assert!(matches!(
            RenewalJournal::recover(&encoded[..written], object, &mut auth),
            Err(RenewalJournalError::Durable(
                DurableError::AuthenticationFailed | DurableError::Malformed
            ))
        ));
    }

    #[test]
    fn uncertain_store_commit_is_resolved_before_generation_advances() {
        let previous = schedule(1, 1_000, 1);
        let lease = RenewalLease {
            identity: previous.identity,
            identity_generation: 1,
            policy_generation: 3,
            lease_generation: 4,
            expires_at_unix: 500,
        };
        let mut journal = RenewalJournal::lease_acquired(lease, previous, 0).unwrap();
        let mut auth = Auth([9; 32]);
        let mut store = UncertainStore { prepared: None };
        let mut transaction = journal
            .prepare_persist(DurableObjectId([7; 16]), &mut auth, &mut store)
            .unwrap();
        assert_eq!(
            commit_or_resolve_renewal(&mut journal, &mut transaction, &mut store).unwrap(),
            TransactionState::Committed
        );
        assert_eq!(journal.record_generation, 1);
    }
}
