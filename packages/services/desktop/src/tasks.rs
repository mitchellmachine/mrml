//! Capability-checked management of an exact supervised MicroVM instance.
//! The host supervisor, not the desktop, owns the backend and installation policy.

use core::num::NonZeroU64;
use mrml_kernel::{Capability, CapabilitySpace, ObjectId, Rights};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Instance {
    pub domain: ObjectId,
    pub generation: NonZeroU64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Starting,
    Running,
    Stopping,
    Stopped,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Row {
    pub instance: Instance,
    pub status: Status,
    /// The supervisor marks its substrate and critical guests as protected.
    pub protected: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Stop,
    Restart,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Denied,
    Stale,
    Protected,
    NotReady,
    CleanupUncertain,
    LaunchFailed,
    InvalidSuccessor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopResult {
    /// Routing, VCPUs, device access, and outstanding resource leases are gone.
    Quiesced,
    /// Operations must remain blocked until supervisor cleanup is verified.
    Uncertain,
}

/// Implemented only by the trusted supervisor. Snapshots come from live
/// records, never from the browser, guest, or a task-manager list row.
pub trait Supervisor {
    fn registry_object(&self) -> ObjectId;
    fn inspect(&self, visitor: &mut dyn FnMut(Row));
    fn current(&self, domain: ObjectId) -> Option<Row>;
    /// Stop new routing before stopping the guest. If incomplete, keep a
    /// quarantined record. Return Stale if the expected instance changed.
    fn stop_exact(&mut self, expected: Instance) -> Result<StopResult, Error>;
    /// Use the approved launch configuration, never a guest-supplied image.
    /// Recheck that this exact predecessor is stopped and cannot resume.
    fn start_successor(&mut self, stopped: Instance) -> Result<Instance, Error>;
}

fn authorize<const N: usize>(
    caps: &CapabilitySpace<N>,
    cap: Capability,
    right: Rights,
    object: ObjectId,
) -> Result<(), Error> {
    (object.0 != 0 && caps.authorize_exact(cap, right) == Ok(object))
        .then_some(())
        .ok_or(Error::Denied)
}

/// List authority is distinct from each instance's control authority. The
/// desktop paints the projection and need not hold any control capability.
pub fn inspect<const N: usize>(
    supervisor: &impl Supervisor,
    caps: &CapabilitySpace<N>,
    inspector: Capability,
    visitor: &mut dyn FnMut(Row),
) -> Result<(), Error> {
    authorize(
        caps,
        inspector,
        Rights::INSPECT,
        supervisor.registry_object(),
    )?;
    supervisor.inspect(visitor);
    Ok(())
}

pub fn request<const N: usize>(
    supervisor: &mut impl Supervisor,
    caps: &CapabilitySpace<N>,
    control: Capability,
    instance: Instance,
    action: Action,
) -> Result<Option<Instance>, Error> {
    authorize(caps, control, Rights::CONTROL, instance.domain)?;
    let row = supervisor
        .current(instance.domain)
        .filter(|row| row.instance == instance)
        .ok_or(Error::Stale)?;
    if row.protected {
        return Err(Error::Protected);
    }
    match row.status {
        Status::Running => {
            if supervisor.stop_exact(instance)? != StopResult::Quiesced {
                return Err(Error::CleanupUncertain);
            }
        }
        Status::Stopped if action == Action::Restart => {}
        _ => return Err(Error::NotReady),
    }
    if action == Action::Stop {
        return Ok(None);
    }
    let successor = supervisor.start_successor(instance)?;
    if successor.domain != instance.domain || successor.generation <= instance.generation {
        return Err(Error::InvalidSuccessor);
    }
    Ok(Some(successor))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        row: Row,
        uncertain: bool,
        stops: u32,
        starts: u32,
    }

    impl Supervisor for Fixture {
        fn registry_object(&self) -> ObjectId {
            ObjectId(2)
        }
        fn inspect(&self, visitor: &mut dyn FnMut(Row)) {
            visitor(self.row);
        }
        fn current(&self, domain: ObjectId) -> Option<Row> {
            (self.row.instance.domain == domain).then_some(self.row)
        }
        fn stop_exact(&mut self, expected: Instance) -> Result<StopResult, Error> {
            assert_eq!(expected, self.row.instance);
            self.stops += 1;
            if self.uncertain {
                self.row.status = Status::Quarantined;
                Ok(StopResult::Uncertain)
            } else {
                self.row.status = Status::Stopped;
                Ok(StopResult::Quiesced)
            }
        }
        fn start_successor(&mut self, expected: Instance) -> Result<Instance, Error> {
            assert_eq!(expected, self.row.instance);
            assert_eq!(self.row.status, Status::Stopped);
            self.starts += 1;
            self.row.instance.generation = NonZeroU64::new(expected.generation.get() + 1).unwrap();
            self.row.status = Status::Running;
            Ok(self.row.instance)
        }
    }

    fn fixture() -> Fixture {
        Fixture {
            row: Row {
                instance: Instance {
                    domain: ObjectId(1),
                    generation: NonZeroU64::MIN,
                },
                status: Status::Running,
                protected: false,
            },
            uncertain: false,
            stops: 0,
            starts: 0,
        }
    }

    #[test]
    fn lists_status_without_authorizing_stop() {
        let mut supervisor = fixture();
        let registry = ObjectId(2);
        let mut caps = CapabilitySpace::<2>::new();
        let view = caps.insert(registry, Rights::INSPECT).unwrap();
        let stop = caps
            .insert(supervisor.row.instance.domain, Rights::CONTROL)
            .unwrap();
        let mut row = None;
        inspect(&supervisor, &caps, view, &mut |item| row = Some(item)).unwrap();
        assert_eq!(row.unwrap().status, Status::Running);
        assert_eq!(
            inspect(&supervisor, &caps, stop, &mut |_| panic!()),
            Err(Error::Denied)
        );
        assert_eq!(
            request(
                &mut supervisor,
                &caps,
                view,
                row.unwrap().instance,
                Action::Stop
            ),
            Err(Error::Denied)
        );
        assert_eq!(
            request(
                &mut supervisor,
                &caps,
                stop,
                row.unwrap().instance,
                Action::Stop
            ),
            Ok(None)
        );
        assert_eq!(supervisor.row.status, Status::Stopped);
    }

    #[test]
    fn restart_waits_for_teardown_and_cannot_stop_the_successor_with_an_old_row() {
        let mut supervisor = fixture();
        let original = supervisor.row.instance;
        let mut caps = CapabilitySpace::<1>::new();
        let cap = caps.insert(original.domain, Rights::CONTROL).unwrap();
        let next = request(&mut supervisor, &caps, cap, original, Action::Restart)
            .unwrap()
            .unwrap();
        assert!(next.generation > original.generation);
        assert_eq!(
            request(&mut supervisor, &caps, cap, original, Action::Stop),
            Err(Error::Stale)
        );
        assert_eq!((supervisor.stops, supervisor.starts), (1, 1));
        caps.revoke(cap).unwrap();
        assert_eq!(
            request(&mut supervisor, &caps, cap, next, Action::Stop),
            Err(Error::Denied)
        );
    }

    #[test]
    fn protects_critical_guests_and_never_restarts_an_uncertain_guest() {
        let mut supervisor = fixture();
        let original = supervisor.row.instance;
        let mut caps = CapabilitySpace::<1>::new();
        let cap = caps.insert(original.domain, Rights::CONTROL).unwrap();
        supervisor.row.protected = true;
        assert_eq!(
            request(&mut supervisor, &caps, cap, original, Action::Stop),
            Err(Error::Protected)
        );
        assert_eq!(supervisor.stops, 0);
        supervisor.row.protected = false;
        supervisor.uncertain = true;
        assert_eq!(
            request(&mut supervisor, &caps, cap, original, Action::Restart),
            Err(Error::CleanupUncertain)
        );
        assert_eq!(supervisor.row.status, Status::Quarantined);
        assert_eq!(
            request(&mut supervisor, &caps, cap, original, Action::Restart),
            Err(Error::NotReady)
        );
        assert_eq!((supervisor.stops, supervisor.starts), (1, 0));
    }
}
