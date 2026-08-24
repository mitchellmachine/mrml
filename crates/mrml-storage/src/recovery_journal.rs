use core::cell::RefCell;

use mrml_crypto::Sha3_256;

use crate::{AUTHORITY_RECOVERY_STATE_BYTES, AuthorityRecoveryStateStore};

pub const RECOVERY_JOURNAL_SLOT_BYTES: usize = 112;
const JOURNAL_MAGIC: [u8; 8] = *b"MRJRNL01";
const JOURNAL_DIGEST_OFFSET: usize = 80;

/// Authenticated durable primitives for a two-slot recovery-state journal.
///
/// # Safety
///
/// Both slot numbers must identify distinct, fixed, owner-provisioned storage
/// objects in the same authenticated monotonic domain as the counter. Reads
/// must return the exact durable bytes for the named slot. A successful slot
/// write must be durable and read-verified before returning. Counter advance
/// must be serialized, compare against `expected`, advance exactly once, and be
/// power-loss atomic. Backend uncertainty must be returned as an error and must
/// never be reported as a definite old state.
pub unsafe trait RecoveryJournalBackend {
    type Error;

    fn read_counter(&mut self) -> Result<u64, Self::Error>;

    fn read_slot(
        &mut self,
        slot: u8,
        output: &mut [u8; RECOVERY_JOURNAL_SLOT_BYTES],
    ) -> Result<(), Self::Error>;

    fn write_and_verify_slot(
        &mut self,
        slot: u8,
        input: &[u8; RECOVERY_JOURNAL_SLOT_BYTES],
    ) -> Result<(), Self::Error>;

    fn increment_counter(&mut self, expected: u64) -> Result<u64, Self::Error>;
}

/// Two-slot authenticated journal whose monotonic counter is the only
/// publication point. The inactive successor is durable before the counter can
/// select it.
pub struct AuthenticatedRecoveryJournal<B> {
    backend: RefCell<B>,
}

impl<B> AuthenticatedRecoveryJournal<B> {
    pub const fn new(backend: B) -> Self {
        Self {
            backend: RefCell::new(backend),
        }
    }

    pub fn into_backend(self) -> B {
        self.backend.into_inner()
    }
}

impl<B: RecoveryJournalBackend> AuthorityRecoveryStateStore for AuthenticatedRecoveryJournal<B> {
    type Error = RecoveryJournalError<B::Error>;

    fn load_authenticated(
        &self,
        output: &mut [u8; AUTHORITY_RECOVERY_STATE_BYTES],
    ) -> Result<(), Self::Error> {
        let mut backend = self
            .backend
            .try_borrow_mut()
            .map_err(|_| RecoveryJournalError::Busy)?;
        let (_, state) = load_current(&mut *backend)?;
        output.copy_from_slice(&state);
        Ok(())
    }

    fn compare_and_store(
        &mut self,
        expected: &[u8; AUTHORITY_RECOVERY_STATE_BYTES],
        replacement: &[u8; AUTHORITY_RECOVERY_STATE_BYTES],
    ) -> Result<(), Self::Error> {
        let backend = self.backend.get_mut();
        let (sequence, current) = load_current(backend)?;
        if current != *expected {
            return Err(RecoveryJournalError::Conflict);
        }
        let next = sequence
            .checked_add(1)
            .ok_or(RecoveryJournalError::SequenceExhausted)?;
        let slot = slot_for(next);
        let encoded = encode_slot(next, replacement);
        backend
            .write_and_verify_slot(slot, &encoded)
            .map_err(RecoveryJournalError::Backend)?;
        let advanced = backend
            .increment_counter(sequence)
            .map_err(RecoveryJournalError::Backend)?;
        if advanced != next {
            return Err(RecoveryJournalError::CounterMismatch);
        }
        let (committed_sequence, committed) = load_current(backend)?;
        if committed_sequence != next || committed != *replacement {
            return Err(RecoveryJournalError::CounterMismatch);
        }
        Ok(())
    }
}

fn load_current<B: RecoveryJournalBackend>(
    backend: &mut B,
) -> Result<(u64, [u8; AUTHORITY_RECOVERY_STATE_BYTES]), RecoveryJournalError<B::Error>> {
    let sequence = backend
        .read_counter()
        .map_err(RecoveryJournalError::Backend)?;
    let mut encoded = [0; RECOVERY_JOURNAL_SLOT_BYTES];
    backend
        .read_slot(slot_for(sequence), &mut encoded)
        .map_err(RecoveryJournalError::Backend)?;
    decode_slot(sequence, &encoded)
}

const fn slot_for(sequence: u64) -> u8 {
    (sequence & 1) as u8
}

fn encode_slot(
    sequence: u64,
    state: &[u8; AUTHORITY_RECOVERY_STATE_BYTES],
) -> [u8; RECOVERY_JOURNAL_SLOT_BYTES] {
    let mut output = [0; RECOVERY_JOURNAL_SLOT_BYTES];
    output[..8].copy_from_slice(&JOURNAL_MAGIC);
    output[8..16].copy_from_slice(&sequence.to_le_bytes());
    output[16..JOURNAL_DIGEST_OFFSET].copy_from_slice(state);
    let digest = digest(&output[..JOURNAL_DIGEST_OFFSET]);
    output[JOURNAL_DIGEST_OFFSET..].copy_from_slice(&digest);
    output
}

fn decode_slot<E>(
    expected_sequence: u64,
    input: &[u8; RECOVERY_JOURNAL_SLOT_BYTES],
) -> Result<(u64, [u8; AUTHORITY_RECOVERY_STATE_BYTES]), RecoveryJournalError<E>> {
    if input[..8] != JOURNAL_MAGIC {
        return Err(RecoveryJournalError::MalformedSlot);
    }
    let sequence = u64::from_le_bytes(input[8..16].try_into().unwrap());
    if sequence != expected_sequence
        || input[JOURNAL_DIGEST_OFFSET..] != digest(&input[..JOURNAL_DIGEST_OFFSET])
    {
        return Err(RecoveryJournalError::MalformedSlot);
    }
    Ok((
        sequence,
        input[16..JOURNAL_DIGEST_OFFSET].try_into().unwrap(),
    ))
}

fn digest(input: &[u8]) -> [u8; 32] {
    let mut digest = Sha3_256::new();
    digest.update(input);
    digest.finalize()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryJournalError<E> {
    Busy,
    Conflict,
    SequenceExhausted,
    MalformedSlot,
    CounterMismatch,
    Backend(E),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum BackendError {
        Write,
        Increment,
        Read,
    }

    struct Backend {
        counter: u64,
        slots: [[u8; RECOVERY_JOURNAL_SLOT_BYTES]; 2],
        fail_write: bool,
        fail_increment_before_commit: bool,
        fail_increment_after_commit: bool,
        fail_read: bool,
    }

    impl Backend {
        fn new(state: [u8; AUTHORITY_RECOVERY_STATE_BYTES]) -> Self {
            let mut slots = [[0; RECOVERY_JOURNAL_SLOT_BYTES]; 2];
            slots[0] = encode_slot(0, &state);
            Self {
                counter: 0,
                slots,
                fail_write: false,
                fail_increment_before_commit: false,
                fail_increment_after_commit: false,
                fail_read: false,
            }
        }
    }

    // SAFETY: this deterministic backend models two distinct exact durable
    // slots and one serialized monotonic counter for protocol tests.
    unsafe impl RecoveryJournalBackend for Backend {
        type Error = BackendError;

        fn read_counter(&mut self) -> Result<u64, Self::Error> {
            if self.fail_read {
                Err(BackendError::Read)
            } else {
                Ok(self.counter)
            }
        }

        fn read_slot(
            &mut self,
            slot: u8,
            output: &mut [u8; RECOVERY_JOURNAL_SLOT_BYTES],
        ) -> Result<(), Self::Error> {
            if self.fail_read {
                return Err(BackendError::Read);
            }
            output.copy_from_slice(&self.slots[usize::from(slot)]);
            Ok(())
        }

        fn write_and_verify_slot(
            &mut self,
            slot: u8,
            input: &[u8; RECOVERY_JOURNAL_SLOT_BYTES],
        ) -> Result<(), Self::Error> {
            if self.fail_write {
                return Err(BackendError::Write);
            }
            self.slots[usize::from(slot)].copy_from_slice(input);
            Ok(())
        }

        fn increment_counter(&mut self, expected: u64) -> Result<u64, Self::Error> {
            if self.counter != expected || self.fail_increment_before_commit {
                return Err(BackendError::Increment);
            }
            self.counter = self.counter.checked_add(1).ok_or(BackendError::Increment)?;
            if self.fail_increment_after_commit {
                Err(BackendError::Increment)
            } else {
                Ok(self.counter)
            }
        }
    }

    fn state(marker: u8) -> [u8; AUTHORITY_RECOVERY_STATE_BYTES] {
        [marker; AUTHORITY_RECOVERY_STATE_BYTES]
    }

    #[test]
    fn publishes_inactive_slot_only_through_counter_advance() {
        let old = state(1);
        let new = state(2);
        let mut journal = AuthenticatedRecoveryJournal::new(Backend::new(old));
        journal.compare_and_store(&old, &new).unwrap();
        let mut loaded = state(0);
        journal.load_authenticated(&mut loaded).unwrap();
        assert_eq!(loaded, new);
        let backend = journal.into_backend();
        assert_eq!(backend.counter, 1);
        assert_eq!(
            decode_slot::<BackendError>(1, &backend.slots[1]).unwrap().1,
            new
        );
    }

    #[test]
    fn failed_inactive_write_leaves_old_slot_selected() {
        let old = state(3);
        let new = state(4);
        let mut backend = Backend::new(old);
        backend.fail_write = true;
        let mut journal = AuthenticatedRecoveryJournal::new(backend);
        assert_eq!(
            journal.compare_and_store(&old, &new),
            Err(RecoveryJournalError::Backend(BackendError::Write))
        );
        let mut backend = journal.into_backend();
        backend.fail_write = false;
        let journal = AuthenticatedRecoveryJournal::new(backend);
        let mut loaded = state(0);
        journal.load_authenticated(&mut loaded).unwrap();
        assert_eq!(loaded, old);
    }

    #[test]
    fn committed_but_uncertain_increment_never_replays_old_expected_state() {
        let old = state(5);
        let new = state(6);
        let mut backend = Backend::new(old);
        backend.fail_increment_after_commit = true;
        let mut journal = AuthenticatedRecoveryJournal::new(backend);
        assert_eq!(
            journal.compare_and_store(&old, &new),
            Err(RecoveryJournalError::Backend(BackendError::Increment))
        );
        let mut backend = journal.into_backend();
        backend.fail_increment_after_commit = false;
        let mut journal = AuthenticatedRecoveryJournal::new(backend);
        let mut loaded = state(0);
        journal.load_authenticated(&mut loaded).unwrap();
        assert_eq!(loaded, new);
        assert_eq!(
            journal.compare_and_store(&old, &state(7)),
            Err(RecoveryJournalError::Conflict)
        );
    }

    #[test]
    fn uncommitted_inactive_slot_is_ignored_after_increment_failure() {
        let old = state(11);
        let new = state(12);
        let mut backend = Backend::new(old);
        backend.fail_increment_before_commit = true;
        let mut journal = AuthenticatedRecoveryJournal::new(backend);
        assert_eq!(
            journal.compare_and_store(&old, &new),
            Err(RecoveryJournalError::Backend(BackendError::Increment))
        );
        let mut backend = journal.into_backend();
        backend.fail_increment_before_commit = false;
        let journal = AuthenticatedRecoveryJournal::new(backend);
        let mut loaded = state(0);
        journal.load_authenticated(&mut loaded).unwrap();
        assert_eq!(loaded, old);
    }

    #[test]
    fn rejects_stale_corrupt_and_conflicting_slots() {
        let old = state(8);
        let mut backend = Backend::new(old);
        backend.slots[0][8] = 1;
        let journal = AuthenticatedRecoveryJournal::new(backend);
        let mut loaded = state(0);
        assert_eq!(
            journal.load_authenticated(&mut loaded),
            Err(RecoveryJournalError::MalformedSlot)
        );

        let mut journal = AuthenticatedRecoveryJournal::new(Backend::new(old));
        assert_eq!(
            journal.compare_and_store(&state(9), &state(10)),
            Err(RecoveryJournalError::Conflict)
        );

        let mut backend = Backend::new(old);
        backend.counter = u64::MAX;
        backend.slots[1] = encode_slot(u64::MAX, &old);
        let mut journal = AuthenticatedRecoveryJournal::new(backend);
        assert_eq!(
            journal.compare_and_store(&old, &state(10)),
            Err(RecoveryJournalError::SequenceExhausted)
        );

        let mut backend = Backend::new(old);
        backend.fail_read = true;
        let journal = AuthenticatedRecoveryJournal::new(backend);
        assert_eq!(
            journal.load_authenticated(&mut loaded),
            Err(RecoveryJournalError::Backend(BackendError::Read))
        );
    }
}
