use core::cell::RefCell;

use mrml_crypto::Sha3_256;
use mrml_kernel::{BOOTSTRAP_STATE_BYTES, MonotonicStateStore};

pub const RELEASE_STATE_JOURNAL_SLOT_BYTES: usize = 136;
const JOURNAL_MAGIC: [u8; 8] = *b"MRLSTJ01";
const JOURNAL_DIGEST_OFFSET: usize = 16 + BOOTSTRAP_STATE_BYTES;

/// Authenticated durable primitives dedicated to release bootstrap state.
///
/// # Safety
///
/// Both slots must be distinct fixed owner-provisioned objects in the same
/// authenticated monotonic domain as the counter. Exact reads and successful
/// writes must refer to those objects; writes must be durable and read-verified.
/// Counter advancement must be serialized, compare `expected`, advance exactly
/// once, and be power-loss atomic. Uncertainty must be returned as an error and
/// must never be reported as definite old state.
pub unsafe trait ReleaseStateJournalBackend {
    type Error;

    fn read_counter(&mut self) -> Result<u64, Self::Error>;

    fn read_slot(
        &mut self,
        slot: u8,
        output: &mut [u8; RELEASE_STATE_JOURNAL_SLOT_BYTES],
    ) -> Result<(), Self::Error>;

    fn write_and_verify_slot(
        &mut self,
        slot: u8,
        input: &[u8; RELEASE_STATE_JOURNAL_SLOT_BYTES],
    ) -> Result<(), Self::Error>;

    fn increment_counter(&mut self, expected: u64) -> Result<u64, Self::Error>;
}

/// Two-slot journal whose authenticated monotonic counter is the sole
/// publication point for one canonical 88-byte release bootstrap state.
pub struct AuthenticatedReleaseStateJournal<B> {
    backend: RefCell<B>,
}

impl<B> AuthenticatedReleaseStateJournal<B> {
    pub const fn new(backend: B) -> Self {
        Self {
            backend: RefCell::new(backend),
        }
    }

    pub fn into_backend(self) -> B {
        self.backend.into_inner()
    }
}

impl<B: ReleaseStateJournalBackend> MonotonicStateStore for AuthenticatedReleaseStateJournal<B> {
    fn load_authenticated(
        &self,
        output: &mut [u8; BOOTSTRAP_STATE_BYTES],
    ) -> Result<(), mrml_kernel::ArtifactError> {
        let mut backend = self
            .backend
            .try_borrow_mut()
            .map_err(|_| mrml_kernel::ArtifactError::StateConflict)?;
        let (_, state) = load_current(&mut *backend)
            .map_err(|_| mrml_kernel::ArtifactError::UnauthenticatedBootstrapState)?;
        output.copy_from_slice(&state);
        Ok(())
    }

    fn compare_and_store(
        &mut self,
        expected: &[u8; BOOTSTRAP_STATE_BYTES],
        replacement: &[u8; BOOTSTRAP_STATE_BYTES],
    ) -> Result<(), mrml_kernel::ArtifactError> {
        let backend = self.backend.get_mut();
        let (sequence, current) = load_current(backend)
            .map_err(|_| mrml_kernel::ArtifactError::UnauthenticatedBootstrapState)?;
        if current != *expected {
            return Err(mrml_kernel::ArtifactError::StateConflict);
        }
        let next = sequence
            .checked_add(1)
            .ok_or(mrml_kernel::ArtifactError::VersionExhausted)?;
        let encoded = encode_slot(next, replacement);
        backend
            .write_and_verify_slot(slot_for(next), &encoded)
            .map_err(|_| mrml_kernel::ArtifactError::StateStorageFailure)?;
        let advanced = backend
            .increment_counter(sequence)
            .map_err(|_| mrml_kernel::ArtifactError::StateStorageFailure)?;
        if advanced != next {
            return Err(mrml_kernel::ArtifactError::StateStorageFailure);
        }
        let (committed_sequence, committed) = load_current(backend)
            .map_err(|_| mrml_kernel::ArtifactError::UnauthenticatedBootstrapState)?;
        if committed_sequence != next || committed != *replacement {
            return Err(mrml_kernel::ArtifactError::StateStorageFailure);
        }
        Ok(())
    }
}

fn load_current<B: ReleaseStateJournalBackend>(
    backend: &mut B,
) -> Result<(u64, [u8; BOOTSTRAP_STATE_BYTES]), ReleaseStateJournalError<B::Error>> {
    let sequence = backend
        .read_counter()
        .map_err(ReleaseStateJournalError::Backend)?;
    let mut encoded = [0; RELEASE_STATE_JOURNAL_SLOT_BYTES];
    backend
        .read_slot(slot_for(sequence), &mut encoded)
        .map_err(ReleaseStateJournalError::Backend)?;
    decode_slot(sequence, &encoded)
}

const fn slot_for(sequence: u64) -> u8 {
    (sequence & 1) as u8
}

fn encode_slot(
    sequence: u64,
    state: &[u8; BOOTSTRAP_STATE_BYTES],
) -> [u8; RELEASE_STATE_JOURNAL_SLOT_BYTES] {
    let mut output = [0; RELEASE_STATE_JOURNAL_SLOT_BYTES];
    output[..8].copy_from_slice(&JOURNAL_MAGIC);
    output[8..16].copy_from_slice(&sequence.to_le_bytes());
    output[16..JOURNAL_DIGEST_OFFSET].copy_from_slice(state);
    let digest = Sha3_256::digest(&output[..JOURNAL_DIGEST_OFFSET]);
    output[JOURNAL_DIGEST_OFFSET..].copy_from_slice(&digest);
    output
}

fn decode_slot<E>(
    expected_sequence: u64,
    input: &[u8; RELEASE_STATE_JOURNAL_SLOT_BYTES],
) -> Result<(u64, [u8; BOOTSTRAP_STATE_BYTES]), ReleaseStateJournalError<E>> {
    if input[..8] != JOURNAL_MAGIC {
        return Err(ReleaseStateJournalError::MalformedSlot);
    }
    let sequence = u64::from_le_bytes(input[8..16].try_into().unwrap());
    if sequence != expected_sequence
        || input[JOURNAL_DIGEST_OFFSET..] != Sha3_256::digest(&input[..JOURNAL_DIGEST_OFFSET])
    {
        return Err(ReleaseStateJournalError::MalformedSlot);
    }
    Ok((
        sequence,
        input[16..JOURNAL_DIGEST_OFFSET].try_into().unwrap(),
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseStateJournalError<E> {
    MalformedSlot,
    Backend(E),
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_kernel::BootstrapState;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum BackendError {
        Write,
        Increment,
        Read,
    }

    struct Backend {
        counter: u64,
        slots: [[u8; RELEASE_STATE_JOURNAL_SLOT_BYTES]; 2],
        fail_write: bool,
        fail_increment_before_commit: bool,
        fail_increment_after_commit: bool,
        fail_read: bool,
    }

    impl Backend {
        fn new(state: [u8; BOOTSTRAP_STATE_BYTES]) -> Self {
            let mut slots = [[0; RELEASE_STATE_JOURNAL_SLOT_BYTES]; 2];
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

    // SAFETY: the model supplies two distinct exact durable slots and one
    // serialized power-loss-atomic monotonic counter.
    unsafe impl ReleaseStateJournalBackend for Backend {
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
            output: &mut [u8; RELEASE_STATE_JOURNAL_SLOT_BYTES],
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
            input: &[u8; RELEASE_STATE_JOURNAL_SLOT_BYTES],
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

    fn state(root: u8, release: u64) -> [u8; BOOTSTRAP_STATE_BYTES] {
        BootstrapState::genesis([root; 64], release).encode()
    }

    #[test]
    fn publishes_exact_release_state_only_after_counter_advance() {
        let old = state(1, 7);
        let new = state(2, 8);
        let mut journal = AuthenticatedReleaseStateJournal::new(Backend::new(old));
        journal.compare_and_store(&old, &new).unwrap();
        let mut loaded = [0; BOOTSTRAP_STATE_BYTES];
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
    fn stale_root_with_same_release_floor_conflicts() {
        let old = state(3, 9);
        let mut journal = AuthenticatedReleaseStateJournal::new(Backend::new(old));
        assert_eq!(
            journal.compare_and_store(&state(4, 9), &state(5, 10)),
            Err(mrml_kernel::ArtifactError::StateConflict)
        );
        assert_eq!(journal.into_backend().counter, 0);
    }

    #[test]
    fn failed_write_or_precommit_increment_preserves_old_selection() {
        for fail_write in [true, false] {
            let old = state(6, 11);
            let new = state(7, 12);
            let mut backend = Backend::new(old);
            backend.fail_write = fail_write;
            backend.fail_increment_before_commit = !fail_write;
            let mut journal = AuthenticatedReleaseStateJournal::new(backend);
            assert_eq!(
                journal.compare_and_store(&old, &new),
                Err(mrml_kernel::ArtifactError::StateStorageFailure)
            );
            let mut backend = journal.into_backend();
            backend.fail_write = false;
            backend.fail_increment_before_commit = false;
            let journal = AuthenticatedReleaseStateJournal::new(backend);
            let mut loaded = [0; BOOTSTRAP_STATE_BYTES];
            journal.load_authenticated(&mut loaded).unwrap();
            assert_eq!(loaded, old);
        }
    }

    #[test]
    fn committed_but_uncertain_advance_never_replays_old_expected_state() {
        let old = state(8, 13);
        let new = state(9, 14);
        let mut backend = Backend::new(old);
        backend.fail_increment_after_commit = true;
        let mut journal = AuthenticatedReleaseStateJournal::new(backend);
        assert_eq!(
            journal.compare_and_store(&old, &new),
            Err(mrml_kernel::ArtifactError::StateStorageFailure)
        );
        let mut backend = journal.into_backend();
        backend.fail_increment_after_commit = false;
        let mut journal = AuthenticatedReleaseStateJournal::new(backend);
        let mut loaded = [0; BOOTSTRAP_STATE_BYTES];
        journal.load_authenticated(&mut loaded).unwrap();
        assert_eq!(loaded, new);
        assert_eq!(
            journal.compare_and_store(&old, &state(10, 15)),
            Err(mrml_kernel::ArtifactError::StateConflict)
        );
    }

    #[test]
    fn corruption_read_failure_and_sequence_exhaustion_fail_closed() {
        let old = state(11, 16);
        let mut corrupt = Backend::new(old);
        corrupt.slots[0][16] ^= 1;
        let journal = AuthenticatedReleaseStateJournal::new(corrupt);
        let mut loaded = [0; BOOTSTRAP_STATE_BYTES];
        assert_eq!(
            journal.load_authenticated(&mut loaded),
            Err(mrml_kernel::ArtifactError::UnauthenticatedBootstrapState)
        );

        let mut unreadable = Backend::new(old);
        unreadable.fail_read = true;
        let journal = AuthenticatedReleaseStateJournal::new(unreadable);
        assert_eq!(
            journal.load_authenticated(&mut loaded),
            Err(mrml_kernel::ArtifactError::UnauthenticatedBootstrapState)
        );

        let mut exhausted = Backend::new(old);
        exhausted.counter = u64::MAX;
        exhausted.slots[1] = encode_slot(u64::MAX, &old);
        let mut journal = AuthenticatedReleaseStateJournal::new(exhausted);
        assert_eq!(
            journal.compare_and_store(&old, &state(12, 17)),
            Err(mrml_kernel::ArtifactError::VersionExhausted)
        );
    }
}
