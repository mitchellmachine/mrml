//! Linear shutdown ownership for one assigned xHCI controller.
use super::{Controller, Error, Platform};
use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerRetirementPending {
    Halt,
    Revocation,
}

enum ControllerRetirementState<P: RevocablePlatform> {
    Running(Controller<P>),
    Halting(StopFailure<P>),
    Revoking(RevocationFailure<P>),
    Complete,
}

/// Owns exactly one controller after its I/O view has been withdrawn. The
/// supervisor can retry this object but cannot recover the old I/O path or
/// substitute a newer controller. The backend retains quarantine on drop.
#[must_use]
pub struct ControllerRetirement<P: RevocablePlatform> {
    state: ControllerRetirementState<P>,
}

impl<P: RevocablePlatform> ControllerRetirement<P> {
    pub fn new(controller: Controller<P>) -> Self {
        Self {
            state: ControllerRetirementState::Running(controller),
        }
    }

    pub fn withdraw(&mut self, ticks: u32) -> Result<(), ControllerRetirementPending> {
        use ControllerRetirementState as State;
        let state = core::mem::replace(&mut self.state, State::Complete);
        let halted = match state {
            State::Running(controller) => controller.stop(ticks),
            State::Halting(pending) => pending.retry(ticks),
            State::Revoking(pending) => return self.record_revocation(pending.retry()),
            State::Complete => return Ok(()),
        };
        match halted {
            Ok(halted) => self.record_revocation(halted.revoke()),
            Err(pending) => {
                self.state = State::Halting(pending);
                Err(ControllerRetirementPending::Halt)
            }
        }
    }

    fn record_revocation(
        &mut self,
        result: Result<(), RevocationFailure<P>>,
    ) -> Result<(), ControllerRetirementPending> {
        match result {
            Ok(()) => Ok(()),
            Err(pending) => {
                self.state = ControllerRetirementState::Revoking(pending);
                Err(ControllerRetirementPending::Revocation)
            }
        }
    }
}

/// Privileged assignment owner that can withdraw all resources for the same
/// generation. Discovery and controller halt do not perform PCI or IOMMU
/// operations themselves.
pub trait RevocablePlatform: Platform {
    /// On success, bus mastering is disabled and read back, device DMA is
    /// revoked and invalidated, reusable DMA memory is scrubbed, and the
    /// exact MMIO mapping is withdrawn. Retry must resume the exact pending
    /// withdrawal; it must not reacquire authority or operate on a new owner.
    /// On uncertainty the assignment and all not-yet-safe resources remain
    /// quarantined, including if the backend is dropped.
    fn revoke_after_halt(&mut self) -> Result<(), Self::Error>;
}

/// Failed startup returns the original owner, or an owner restricted to
/// shutdown if programming may have begun.
#[must_use]
pub enum StartFailure<P: Platform> {
    Untouched { error: Error<P::Error>, platform: P },
    Programming(StopFailure<P>),
}

impl<P: Platform> StartFailure<P> {
    pub fn error(&self) -> &Error<P::Error> {
        match self {
            Self::Untouched { error, .. } => error,
            Self::Programming(failure) => failure.error(),
        }
    }
}

impl<P: Platform> fmt::Debug for StartFailure<P>
where
    P::Error: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StartFailure").field(self.error()).finish()
    }
}

/// Live ownership is retained when halt cannot be established. Only shutdown
/// can be retried, not I/O or initialization.
#[must_use]
pub struct StopFailure<P: Platform> {
    error: Error<P::Error>,
    controller: Controller<P>,
}

impl<P: Platform> StopFailure<P> {
    pub(super) fn new(error: Error<P::Error>, controller: Controller<P>) -> Self {
        Self { error, controller }
    }

    pub fn error(&self) -> &Error<P::Error> {
        &self.error
    }

    pub fn retry(self, ticks: u32) -> Result<Halted<P>, Self> {
        self.controller.stop(ticks)
    }
}

impl<P: Platform> fmt::Debug for StopFailure<P>
where
    P::Error: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StopFailure").field(self.error()).finish()
    }
}

/// The xHCI halt was confirmed. This is not yet proof that the mapping can
/// be reused: the backend must still disable and revoke the device's access.
#[must_use]
pub struct Halted<P: Platform> {
    platform: P,
}

impl<P: Platform> Halted<P> {
    pub(super) fn new(platform: P) -> Self {
        Self { platform }
    }
}

impl<P: RevocablePlatform> Halted<P> {
    pub fn revoke(mut self) -> Result<(), RevocationFailure<P>> {
        match self.platform.revoke_after_halt() {
            Ok(()) => Ok(()),
            Err(error) => Err(RevocationFailure {
                halted: self,
                error,
            }),
        }
    }
}

#[must_use]
pub struct RevocationFailure<P: RevocablePlatform> {
    halted: Halted<P>,
    error: P::Error,
}

impl<P: RevocablePlatform> RevocationFailure<P> {
    pub fn error(&self) -> &P::Error {
        &self.error
    }

    pub fn retry(self) -> Result<(), Self> {
        self.halted.revoke()
    }
}

impl<P: RevocablePlatform> fmt::Debug for RevocationFailure<P>
where
    P::Error: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RevocationFailure")
            .field(self.error())
            .finish()
    }
}
