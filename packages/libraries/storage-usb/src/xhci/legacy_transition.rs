//! Pure validation for a bounded xHCI legacy ownership observation sequence.
//! Successful validation is not a lease, permission to write MMIO, or proof
//! that firmware I/O, DMA, and interrupts have been shut down.
use super::{Error, LegacyOwnership, LegacySample, sample_legacy_ownership};

const SEMAPHORES: u32 = (1 << 16) | (1 << 24);
const OBSERVATIONS: u8 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyTransitionError {
    InvalidInitialOwner,
    ChangedLease,
    ChangedCapability,
    RequestLost,
    Timeout,
}

pub struct LegacyOwnershipSequence {
    generation: u64,
    initial: LegacySample,
    first_acknowledgment: bool,
    remaining: u8,
}

/// Two matching ownership polls have been observed. This value proves no
/// live state: the caller must still revalidate the exact retained lease
/// and all non-ownership prerequisites while consuming the result.
pub struct LegacyOwnershipAcknowledgment {
    generation: u64,
    expected: LegacySample,
}

impl LegacyOwnershipSequence {
    /// Samples the already bounded BAR through the existing read-only walker.
    pub fn observe_initial<E>(
        generation: u64,
        bar_bytes: u32,
        read: impl FnMut(u32) -> Result<u32, E>,
    ) -> Result<Result<Self, LegacyTransitionError>, Error<E>> {
        sample_legacy_ownership(bar_bytes, read).map(|sample| Self::begin(generation, sample))
    }

    pub(super) fn begin(
        generation: u64,
        initial: LegacySample,
    ) -> Result<Self, LegacyTransitionError> {
        if generation == 0 {
            return Err(LegacyTransitionError::ChangedLease);
        }
        if initial.ownership != LegacyOwnership::Firmware || initial.capability.is_none() {
            return Err(LegacyTransitionError::InvalidInitialOwner);
        }
        Ok(Self {
            generation,
            initial,
            first_acknowledgment: false,
            remaining: OBSERVATIONS,
        })
    }

    /// A continuation must come from the next fresh sample on the same
    /// retained lease. Each successful call consumes one observation.
    pub fn observe<E>(
        self,
        generation: u64,
        bar_bytes: u32,
        read: impl FnMut(u32) -> Result<u32, E>,
    ) -> Result<Result<LegacyOwnershipPoll, LegacyTransitionError>, Error<E>> {
        sample_legacy_ownership(bar_bytes, read).map(|sample| self.poll(generation, sample))
    }

    pub(super) fn poll(
        mut self,
        generation: u64,
        live: LegacySample,
    ) -> Result<LegacyOwnershipPoll, LegacyTransitionError> {
        if generation != self.generation {
            return Err(LegacyTransitionError::ChangedLease);
        }
        let identity = |sample: LegacySample| {
            (
                sample.hcc1,
                sample
                    .capability
                    .map(|(offset, value)| (offset, value & !SEMAPHORES)),
            )
        };
        if identity(live) != identity(self.initial) {
            return Err(LegacyTransitionError::ChangedCapability);
        }
        match live.ownership {
            LegacyOwnership::OperatingSystem if self.first_acknowledgment => {
                return Ok(LegacyOwnershipPoll::Acknowledged(
                    LegacyOwnershipAcknowledgment {
                        generation,
                        expected: live,
                    },
                ));
            }
            LegacyOwnership::OperatingSystem => self.first_acknowledgment = true,
            LegacyOwnership::Contended if !self.first_acknowledgment => (),
            _ => return Err(LegacyTransitionError::RequestLost),
        }
        self.remaining -= 1;
        if self.remaining == 0 {
            return Err(LegacyTransitionError::Timeout);
        }
        Ok(LegacyOwnershipPoll::Pending(self))
    }
}

pub enum LegacyOwnershipPoll {
    Pending(LegacyOwnershipSequence),
    Acknowledged(LegacyOwnershipAcknowledgment),
}

impl LegacyOwnershipAcknowledgment {
    /// Read and compare at the final boundary. An unreliable read or any
    /// drift consumes this acknowledgment rather than permitting replay.
    pub fn revalidate<E>(
        self,
        generation: u64,
        bar_bytes: u32,
        read: impl FnMut(u32) -> Result<u32, E>,
    ) -> Result<Result<u64, LegacyTransitionError>, Error<E>> {
        sample_legacy_ownership(bar_bytes, read).map(|sample| self.finish(generation, sample))
    }

    pub(super) fn finish(
        self,
        generation: u64,
        live: LegacySample,
    ) -> Result<u64, LegacyTransitionError> {
        if generation != self.generation {
            return Err(LegacyTransitionError::ChangedLease);
        }
        if live.ownership != LegacyOwnership::OperatingSystem {
            return Err(LegacyTransitionError::RequestLost);
        }
        if live != self.expected {
            return Err(LegacyTransitionError::ChangedCapability);
        }
        Ok(generation)
    }
}
