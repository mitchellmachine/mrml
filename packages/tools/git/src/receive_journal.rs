//! Canonical bounded receive journal records and crash-recovery classification.

use mrml_crypto::Sha256;
use mrml_runtime::Vector;

use crate::{
    ActivationSnapshot, DurableFailure, FullRefName, GitdCoreError, ObjectFormat, ObjectId,
    QuarantinePhase, QuarantineTransaction, QuarantineTransactionId, RepositoryGeneration,
    RepositoryIdentity, RevocationGeneration, TrustGeneration, VerifiedRefTransaction,
};

const MAGIC: &[u8; 8] = b"MRGJNL01";
const DIGEST_BYTES: usize = 32;
pub const MAX_RECEIVE_JOURNAL_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalRefUpdate {
    pub name: FullRefName,
    pub expected_old: ObjectId,
    pub proposed_new: ObjectId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveJournalRecord {
    pub transaction: QuarantineTransactionId,
    pub repository: RepositoryIdentity,
    pub repository_generation: RepositoryGeneration,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    pub phase: QuarantinePhase,
    pub failure: Option<DurableFailure>,
    pub updates: Vector<JournalRefUpdate>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveJournalError {
    Resource,
    Malformed,
    Integrity,
    Mismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    /// No ref can have changed; remove inaccessible quarantine/staging state.
    DiscardBeforeActivation,
    /// Objects exist but refs are still old. Re-run all generation, ancestry,
    /// signature and policy verification before constructing new typestate.
    ReverifyBeforeActivation,
    /// Every ref is already new; append/recover the auditable receipt.
    RecoverAuditReceipt,
    /// Receipt was durable and refs are exactly new; mark journal complete.
    MarkComplete,
    /// Live authority/ref state is neither the exact old nor exact new set.
    ManualUncertain,
}

pub fn encode_receive_journal(
    transaction: &QuarantineTransaction,
    verified: &VerifiedRefTransaction,
) -> Result<Vector<u8>, ReceiveJournalError> {
    if transaction.repository() != verified.repository()
        || transaction.repository_generation() != verified.repository_generation()
        || transaction.trust_generation() != verified.trust_generation()
        || transaction.revocation_generation() != verified.revocation_generation()
        || verified.updates().is_empty()
        || verified.updates().len() > crate::MAX_REFS_PER_TRANSACTION
    {
        return Err(ReceiveJournalError::Mismatch);
    }
    let mut output = Vector::new();
    append(&mut output, MAGIC)?;
    append(&mut output, &transaction.id().0)?;
    let repository = transaction.repository().as_str().as_bytes();
    append_u16(&mut output, repository.len())?;
    append(&mut output, repository)?;
    append_u64(&mut output, transaction.repository_generation().0)?;
    append_u64(&mut output, transaction.trust_generation().0)?;
    append_u64(&mut output, transaction.revocation_generation().0)?;
    append(&mut output, &[encode_phase(transaction.phase())])?;
    append(
        &mut output,
        &[transaction.failure().map(encode_failure).unwrap_or(0)],
    )?;
    append_u16(&mut output, verified.updates().len())?;
    for update in verified.updates() {
        let old = update.expected_old().ok_or(ReceiveJournalError::Mismatch)?;
        let new = update.proposed_new().ok_or(ReceiveJournalError::Mismatch)?;
        if old.format() != new.format()
            || old == ObjectId::zero(old.format())
            || new == ObjectId::zero(new.format())
        {
            return Err(ReceiveJournalError::Mismatch);
        }
        append_u16(&mut output, update.name().as_str().len())?;
        append(&mut output, update.name().as_str().as_bytes())?;
        append(&mut output, &[encode_format(old.format())])?;
        append(&mut output, old.as_bytes())?;
        append(&mut output, new.as_bytes())?;
    }
    if output
        .len()
        .checked_add(DIGEST_BYTES)
        .ok_or(ReceiveJournalError::Resource)?
        > MAX_RECEIVE_JOURNAL_BYTES
    {
        return Err(ReceiveJournalError::Resource);
    }
    let digest = Sha256::digest(&output);
    append(&mut output, &digest)?;
    Ok(output)
}

pub fn parse_receive_journal(input: &[u8]) -> Result<ReceiveJournalRecord, ReceiveJournalError> {
    if input.len() < MAGIC.len() + DIGEST_BYTES || input.len() > MAX_RECEIVE_JOURNAL_BYTES {
        return Err(ReceiveJournalError::Malformed);
    }
    let authenticated_len = input.len() - DIGEST_BYTES;
    if Sha256::digest(&input[..authenticated_len]) != input[authenticated_len..] {
        return Err(ReceiveJournalError::Integrity);
    }
    let mut cursor = Cursor::new(&input[..authenticated_len]);
    if cursor.take(MAGIC.len())? != MAGIC {
        return Err(ReceiveJournalError::Malformed);
    }
    let mut transaction = [0u8; 16];
    transaction.copy_from_slice(cursor.take(16)?);
    if transaction == [0u8; 16] {
        return Err(ReceiveJournalError::Malformed);
    }
    let repository_len = usize::from(cursor.u16()?);
    let repository = core::str::from_utf8(cursor.take(repository_len)?)
        .map_err(|_| ReceiveJournalError::Malformed)?;
    let repository = RepositoryIdentity::parse(repository).map_err(map_identifier)?;
    let repository_generation = nonzero_generation(cursor.u64()?)?;
    let trust_generation = nonzero_generation(cursor.u64()?)?;
    let revocation_generation = nonzero_generation(cursor.u64()?)?;
    let phase = decode_phase(cursor.u8()?)?;
    let failure = decode_failure(cursor.u8()?)?;
    if matches!(phase, QuarantinePhase::Aborted | QuarantinePhase::Uncertain) != failure.is_some() {
        return Err(ReceiveJournalError::Malformed);
    }
    let count = usize::from(cursor.u16()?);
    if count == 0 || count > crate::MAX_REFS_PER_TRANSACTION {
        return Err(ReceiveJournalError::Malformed);
    }
    let mut updates = Vector::new();
    updates
        .try_reserve_exact(count)
        .map_err(|_| ReceiveJournalError::Resource)?;
    for _ in 0..count {
        let name_len = usize::from(cursor.u16()?);
        let name = core::str::from_utf8(cursor.take(name_len)?)
            .map_err(|_| ReceiveJournalError::Malformed)?;
        let name = FullRefName::parse(name).map_err(map_identifier)?;
        if updates
            .iter()
            .any(|update: &JournalRefUpdate| update.name == name)
        {
            return Err(ReceiveJournalError::Malformed);
        }
        let format = decode_format(cursor.u8()?)?;
        let old = ObjectId::from_bytes(format, cursor.take(format.hash_len())?)
            .ok_or(ReceiveJournalError::Malformed)?;
        let new = ObjectId::from_bytes(format, cursor.take(format.hash_len())?)
            .ok_or(ReceiveJournalError::Malformed)?;
        if old == ObjectId::zero(format) || new == ObjectId::zero(format) {
            return Err(ReceiveJournalError::Malformed);
        }
        updates.push(JournalRefUpdate {
            name,
            expected_old: old,
            proposed_new: new,
        });
    }
    if !cursor.is_empty() {
        return Err(ReceiveJournalError::Malformed);
    }
    Ok(ReceiveJournalRecord {
        transaction: QuarantineTransactionId(transaction),
        repository,
        repository_generation: RepositoryGeneration(repository_generation),
        trust_generation: TrustGeneration(trust_generation),
        revocation_generation: RevocationGeneration(revocation_generation),
        phase,
        failure,
        updates,
    })
}

pub fn classify_receive_recovery(
    journal: &ReceiveJournalRecord,
    live: &ActivationSnapshot,
) -> RecoveryAction {
    let generations_match = live.repository_generation == journal.repository_generation
        && live.trust_generation == journal.trust_generation
        && live.revocation_generation == journal.revocation_generation;
    let exact_old = exact_refs(journal, live, false);
    let exact_new = exact_refs(journal, live, true);
    match journal.phase {
        QuarantinePhase::CandidateReceived
        | QuarantinePhase::ObjectsQuarantined
        | QuarantinePhase::ObjectsValidated
        | QuarantinePhase::HistoryVerified
        | QuarantinePhase::RefUpdatesPrepared
        | QuarantinePhase::Aborted => RecoveryAction::DiscardBeforeActivation,
        QuarantinePhase::ObjectsDurablyInstalled if generations_match && exact_old => {
            RecoveryAction::ReverifyBeforeActivation
        }
        QuarantinePhase::ObjectsDurablyInstalled
        | QuarantinePhase::RefsAtomicallyActivated
        | QuarantinePhase::Uncertain
            if generations_match && exact_new =>
        {
            RecoveryAction::RecoverAuditReceipt
        }
        QuarantinePhase::AuditReceiptAppended if generations_match && exact_new => {
            RecoveryAction::MarkComplete
        }
        _ => RecoveryAction::ManualUncertain,
    }
}

fn exact_refs(journal: &ReceiveJournalRecord, live: &ActivationSnapshot, new: bool) -> bool {
    live.refs.len() == journal.updates.len()
        && journal.updates.iter().all(|update| {
            let expected = if new {
                update.proposed_new
            } else {
                update.expected_old
            };
            live.refs
                .iter()
                .any(|(name, value)| name == &update.name && *value == Some(expected))
        })
}

fn append(output: &mut Vector<u8>, bytes: &[u8]) -> Result<(), ReceiveJournalError> {
    if output
        .len()
        .checked_add(bytes.len())
        .ok_or(ReceiveJournalError::Resource)?
        > MAX_RECEIVE_JOURNAL_BYTES
    {
        return Err(ReceiveJournalError::Resource);
    }
    output
        .try_extend_from_slice(bytes)
        .map_err(|_| ReceiveJournalError::Resource)
}

fn append_u16(output: &mut Vector<u8>, value: usize) -> Result<(), ReceiveJournalError> {
    append(
        output,
        &u16::try_from(value)
            .map_err(|_| ReceiveJournalError::Resource)?
            .to_be_bytes(),
    )
}

fn append_u64(output: &mut Vector<u8>, value: u64) -> Result<(), ReceiveJournalError> {
    append(output, &value.to_be_bytes())
}

fn encode_format(format: ObjectFormat) -> u8 {
    match format {
        ObjectFormat::Sha1 => 1,
        ObjectFormat::Sha256 => 2,
    }
}
fn decode_format(value: u8) -> Result<ObjectFormat, ReceiveJournalError> {
    match value {
        1 => Ok(ObjectFormat::Sha1),
        2 => Ok(ObjectFormat::Sha256),
        _ => Err(ReceiveJournalError::Malformed),
    }
}

fn encode_phase(phase: QuarantinePhase) -> u8 {
    match phase {
        QuarantinePhase::CandidateReceived => 1,
        QuarantinePhase::ObjectsQuarantined => 2,
        QuarantinePhase::ObjectsValidated => 3,
        QuarantinePhase::HistoryVerified => 4,
        QuarantinePhase::RefUpdatesPrepared => 5,
        QuarantinePhase::ObjectsDurablyInstalled => 6,
        QuarantinePhase::RefsAtomicallyActivated => 7,
        QuarantinePhase::AuditReceiptAppended => 8,
        QuarantinePhase::Aborted => 9,
        QuarantinePhase::Uncertain => 10,
    }
}
fn decode_phase(value: u8) -> Result<QuarantinePhase, ReceiveJournalError> {
    match value {
        1 => Ok(QuarantinePhase::CandidateReceived),
        2 => Ok(QuarantinePhase::ObjectsQuarantined),
        3 => Ok(QuarantinePhase::ObjectsValidated),
        4 => Ok(QuarantinePhase::HistoryVerified),
        5 => Ok(QuarantinePhase::RefUpdatesPrepared),
        6 => Ok(QuarantinePhase::ObjectsDurablyInstalled),
        7 => Ok(QuarantinePhase::RefsAtomicallyActivated),
        8 => Ok(QuarantinePhase::AuditReceiptAppended),
        9 => Ok(QuarantinePhase::Aborted),
        10 => Ok(QuarantinePhase::Uncertain),
        _ => Err(ReceiveJournalError::Malformed),
    }
}
fn encode_failure(failure: DurableFailure) -> u8 {
    match failure {
        DurableFailure::DiskFull => 1,
        DurableFailure::ShortWrite => 2,
        DurableFailure::Fsync => 3,
        DurableFailure::Rename => 4,
        DurableFailure::StaleLock => 5,
        DurableFailure::VerifierCrash => 6,
        DurableFailure::AuditReceipt => 7,
    }
}
fn decode_failure(value: u8) -> Result<Option<DurableFailure>, ReceiveJournalError> {
    match value {
        0 => Ok(None),
        1 => Ok(Some(DurableFailure::DiskFull)),
        2 => Ok(Some(DurableFailure::ShortWrite)),
        3 => Ok(Some(DurableFailure::Fsync)),
        4 => Ok(Some(DurableFailure::Rename)),
        5 => Ok(Some(DurableFailure::StaleLock)),
        6 => Ok(Some(DurableFailure::VerifierCrash)),
        7 => Ok(Some(DurableFailure::AuditReceipt)),
        _ => Err(ReceiveJournalError::Malformed),
    }
}
fn nonzero_generation(value: u64) -> Result<u64, ReceiveJournalError> {
    if value == 0 {
        Err(ReceiveJournalError::Malformed)
    } else {
        Ok(value)
    }
}
fn map_identifier(_: GitdCoreError) -> ReceiveJournalError {
    ReceiveJournalError::Malformed
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], ReceiveJournalError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(ReceiveJournalError::Malformed)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ReceiveJournalError::Malformed)?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, ReceiveJournalError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ReceiveJournalError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| ReceiveJournalError::Malformed)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, ReceiveJournalError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ReceiveJournalError::Malformed)?,
        ))
    }
    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CandidateRefTransaction, CandidateRefUpdate, HistoryVerificationLimits,
        PushStorageForecast, QuarantineLimits, build_verified_fast_forward_transaction,
        reserve_push_disk, verify_introduced_history,
    };

    fn fixture() -> (
        QuarantineTransaction,
        VerifiedRefTransaction,
        ObjectId,
        ObjectId,
    ) {
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let old = ObjectId::Sha256([1u8; 32]);
        let new = ObjectId::Sha256([2u8; 32]);
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
        let reservation = reserve_push_disk(
            QuarantineLimits {
                minimum_free_space_bytes: 0,
                ..QuarantineLimits::default()
            },
            PushStorageForecast {
                incoming_pack_bytes: 10,
                expanded_object_bytes: 20,
                largest_object_bytes: 20,
                object_count: 1,
                ref_count: 1,
                arrival_index_bytes: 10,
                staging_metadata_bytes: 10,
                audit_receipt_bytes: 10,
                ordinary_free_bytes: 100,
            },
        )
        .unwrap();
        let mut transaction = QuarantineTransaction::begin(
            QuarantineTransactionId([9u8; 16]),
            repository,
            RepositoryGeneration(3),
            TrustGeneration(4),
            RevocationGeneration(5),
            reservation,
        )
        .unwrap();
        transaction.objects_quarantined(10).unwrap();
        transaction.objects_validated(20, 1).unwrap();
        transaction.history_verified(&verified).unwrap();
        transaction.ref_updates_prepared().unwrap();
        transaction.objects_durably_installed().unwrap();
        (transaction, verified, old, new)
    }

    fn snapshot(verified: &VerifiedRefTransaction, value: ObjectId) -> ActivationSnapshot {
        ActivationSnapshot {
            repository_generation: verified.repository_generation(),
            trust_generation: verified.trust_generation(),
            revocation_generation: verified.revocation_generation(),
            refs: [(verified.updates()[0].name().clone(), Some(value))].into(),
        }
    }

    #[test]
    fn canonical_journal_round_trips_and_detects_torn_or_tampered_records() {
        let (transaction, verified, _, _) = fixture();
        let encoded = encode_receive_journal(&transaction, &verified).unwrap();
        let parsed = parse_receive_journal(&encoded).unwrap();
        assert_eq!(parsed.phase, QuarantinePhase::ObjectsDurablyInstalled);
        assert_eq!(parsed.updates.len(), 1);
        assert_eq!(
            encode_receive_journal(&transaction, &verified).unwrap(),
            encoded
        );

        let mut tampered = encoded.clone();
        tampered[20] ^= 1;
        assert_eq!(
            parse_receive_journal(&tampered),
            Err(ReceiveJournalError::Integrity)
        );
        assert!(parse_receive_journal(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            parse_receive_journal(&trailing),
            Err(ReceiveJournalError::Integrity)
        );
    }

    #[test]
    fn recovery_never_guesses_between_old_new_and_divergent_ref_states() {
        let (mut transaction, verified, old, new) = fixture();
        let installed =
            parse_receive_journal(&encode_receive_journal(&transaction, &verified).unwrap())
                .unwrap();
        assert_eq!(
            classify_receive_recovery(&installed, &snapshot(&verified, old)),
            RecoveryAction::ReverifyBeforeActivation
        );
        assert_eq!(
            classify_receive_recovery(&installed, &snapshot(&verified, new)),
            RecoveryAction::RecoverAuditReceipt
        );
        assert_eq!(
            classify_receive_recovery(
                &installed,
                &snapshot(&verified, ObjectId::Sha256([7u8; 32]))
            ),
            RecoveryAction::ManualUncertain
        );

        transaction.refs_atomically_activated().unwrap();
        transaction.audit_receipt_appended().unwrap();
        let completed =
            parse_receive_journal(&encode_receive_journal(&transaction, &verified).unwrap())
                .unwrap();
        assert_eq!(
            classify_receive_recovery(&completed, &snapshot(&verified, new)),
            RecoveryAction::MarkComplete
        );
        let mut stale = snapshot(&verified, new);
        stale.trust_generation = TrustGeneration(99);
        assert_eq!(
            classify_receive_recovery(&completed, &stale),
            RecoveryAction::ManualUncertain
        );
    }
}
