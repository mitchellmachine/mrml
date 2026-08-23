use core::array;

use crate::arch::x86_64::{TrapDisposition, UserContext};
use crate::{
    Capability, CapabilityError, CapabilitySpace, FaultRetirement, ObjectId, Priority,
    ScheduleOutcome, TaskId, TaskRuntime, TaskRuntimeError, TaskTermination,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceId {
    slot: u32,
    generation: u32,
}

impl ServiceId {
    pub const fn token(self) -> u64 {
        ((self.generation as u64) << 32) | self.slot as u64
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceState {
    Running,
    Exited,
    Faulted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    Full,
    InvalidService,
    InvalidObject,
    TaskMismatch,
    StillRunning,
    GenerationExhausted,
    InvalidRestartPolicy,
    RestartLimit,
    RestartBackoff { eligible_at: u64 },
    TimeExhausted,
    CleanupRequired,
    InvalidCleanupTicket,
    Unauthorized(CapabilityError),
    Runtime(TaskRuntimeError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartPolicy {
    maximum_restarts: u32,
    base_backoff_ticks: u64,
    maximum_backoff_ticks: u64,
}

impl RestartPolicy {
    pub const ONCE_IMMEDIATE: Self = Self {
        maximum_restarts: 1,
        base_backoff_ticks: 0,
        maximum_backoff_ticks: 0,
    };

    pub const fn new(
        maximum_restarts: u32,
        base_backoff_ticks: u64,
        maximum_backoff_ticks: u64,
    ) -> Result<Self, ServiceError> {
        if maximum_restarts == 0 || maximum_backoff_ticks < base_backoff_ticks {
            return Err(ServiceError::InvalidRestartPolicy);
        }
        Ok(Self {
            maximum_restarts,
            base_backoff_ticks,
            maximum_backoff_ticks,
        })
    }

    fn delay(self, completed_restarts: u32) -> u64 {
        let shift = completed_restarts.min(63);
        self.base_backoff_ticks
            .saturating_mul(1u64 << shift)
            .min(self.maximum_backoff_ticks)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceRetirement {
    pub service: ServiceId,
    pub task: TaskId,
    pub next: ScheduleOutcome,
    pub cleanup: ServiceCleanupTicket,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceFault {
    pub service: ServiceId,
    pub retirement: FaultRetirement,
    pub cleanup: ServiceCleanupTicket,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceRecovery {
    pub retired: ServiceId,
    pub replacement: ServiceId,
    pub task: TaskId,
    pub next: ScheduleOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceRecoveryError<E> {
    Retirement(ServiceError),
    Cleanup {
        service: ServiceId,
        error: ServiceCleanupError<E>,
    },
    Restart {
        service: ServiceId,
        error: ServiceError,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceCleanupTicket {
    service: ServiceId,
    task: TaskId,
    context: UserContext,
}

impl ServiceCleanupTicket {
    pub const fn service(self) -> ServiceId {
        self.service
    }
    pub const fn task(self) -> TaskId {
        self.task
    }
    pub const fn context(self) -> UserContext {
        self.context
    }
}

pub trait ServiceAddressSpaceEraser {
    type Error;
    fn erase(&mut self, task: TaskId, context: UserContext) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceCleanupError<E> {
    Service(ServiceError),
    Eraser(E),
}

#[derive(Clone, Copy)]
struct ServiceSlot {
    generation: u32,
    object: ObjectId,
    task: Option<TaskId>,
    state: ServiceState,
    occupied: bool,
    restart_policy: RestartPolicy,
    completed_restarts: u32,
    next_restart_tick: u64,
    cleanup: Option<ServiceCleanupTicket>,
}

impl ServiceSlot {
    const EMPTY: Self = Self {
        generation: 1,
        object: ObjectId(0),
        task: None,
        state: ServiceState::Exited,
        occupied: false,
        restart_policy: RestartPolicy::ONCE_IMMEDIATE,
        completed_restarts: 0,
        next_restart_tick: 0,
        cleanup: None,
    };
}

/// Fixed-capacity owner of service-to-task identity. A stopped or faulted
/// instance can restart only through CONTROL authority for its exact object and
/// a freshly supplied context. Restart advances the service generation, making
/// every handle to the retired instance permanently stale.
pub struct ServiceSupervisor<const SERVICES: usize> {
    slots: [ServiceSlot; SERVICES],
}

impl<const SERVICES: usize> ServiceSupervisor<SERVICES> {
    pub fn new() -> Self {
        Self {
            slots: array::from_fn(|_| ServiceSlot::EMPTY),
        }
    }

    pub fn register(&mut self, object: ObjectId, task: TaskId) -> Result<ServiceId, ServiceError> {
        self.register_with_policy(object, task, RestartPolicy::ONCE_IMMEDIATE)
    }

    pub fn register_with_policy(
        &mut self,
        object: ObjectId,
        task: TaskId,
        restart_policy: RestartPolicy,
    ) -> Result<ServiceId, ServiceError> {
        if object.0 == 0 {
            return Err(ServiceError::InvalidObject);
        }
        let (slot, entry) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, entry)| !entry.occupied)
            .ok_or(ServiceError::Full)?;
        entry.object = object;
        entry.task = Some(task);
        entry.state = ServiceState::Running;
        entry.occupied = true;
        entry.restart_policy = restart_policy;
        entry.completed_restarts = 0;
        entry.next_restart_tick = 0;
        entry.cleanup = None;
        Ok(ServiceId {
            slot: slot as u32,
            generation: entry.generation,
        })
    }

    pub fn state(&self, service: ServiceId) -> Result<ServiceState, ServiceError> {
        Ok(self.slot(service)?.state)
    }

    pub fn task(&self, service: ServiceId) -> Result<Option<TaskId>, ServiceError> {
        Ok(self.slot(service)?.task)
    }

    pub fn pending_cleanup(
        &self,
        service: ServiceId,
    ) -> Result<Option<ServiceCleanupTicket>, ServiceError> {
        Ok(self.slot(service)?.cleanup)
    }

    pub fn exit_current<const TASKS: usize, const CAPS: usize>(
        &mut self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
    ) -> Result<ServiceRetirement, ServiceError> {
        self.exit_current_at(runtime, 0)
    }

    pub fn exit_current_at<const TASKS: usize, const CAPS: usize>(
        &mut self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        now: u64,
    ) -> Result<ServiceRetirement, ServiceError> {
        let current = runtime
            .current()
            .ok_or(ServiceError::Runtime(TaskRuntimeError::NoCurrentTask))?;
        let slot = self.running_task_slot(current)?;
        let service = self.id(slot);
        let next_restart_tick = self.restart_deadline(slot, now)?;
        let (TaskTermination { task, next }, context) = runtime
            .terminate_current_with_context()
            .map_err(ServiceError::Runtime)?;
        if task != current {
            return Err(ServiceError::TaskMismatch);
        }
        self.slots[slot].task = None;
        self.slots[slot].state = ServiceState::Exited;
        let cleanup = ServiceCleanupTicket {
            service,
            task,
            context,
        };
        self.slots[slot].cleanup = Some(cleanup);
        self.slots[slot].next_restart_tick = next_restart_tick;
        Ok(ServiceRetirement {
            service,
            task,
            next,
            cleanup,
        })
    }

    pub fn fault_current<const TASKS: usize, const CAPS: usize>(
        &mut self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        disposition: TrapDisposition,
    ) -> Result<ServiceFault, ServiceError> {
        self.fault_current_at(runtime, disposition, 0)
    }

    pub fn fault_current_at<const TASKS: usize, const CAPS: usize>(
        &mut self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        disposition: TrapDisposition,
        now: u64,
    ) -> Result<ServiceFault, ServiceError> {
        let current = runtime
            .current()
            .ok_or(ServiceError::Runtime(TaskRuntimeError::NoCurrentTask))?;
        let slot = self.running_task_slot(current)?;
        let service = self.id(slot);
        let next_restart_tick = self.restart_deadline(slot, now)?;
        let retirement = runtime
            .terminate_current_fault(disposition)
            .map_err(ServiceError::Runtime)?;
        if retirement.task != current {
            return Err(ServiceError::TaskMismatch);
        }
        self.slots[slot].task = None;
        self.slots[slot].state = ServiceState::Faulted;
        let cleanup = ServiceCleanupTicket {
            service,
            task: retirement.task,
            context: retirement.context,
        };
        self.slots[slot].cleanup = Some(cleanup);
        self.slots[slot].next_restart_tick = next_restart_tick;
        Ok(ServiceFault {
            service,
            retirement,
            cleanup,
        })
    }

    pub fn complete_cleanup<E: ServiceAddressSpaceEraser>(
        &mut self,
        ticket: ServiceCleanupTicket,
        eraser: &mut E,
    ) -> Result<(), ServiceCleanupError<E::Error>> {
        let slot = ticket.service.slot as usize;
        let entry = self
            .slot(ticket.service)
            .map_err(ServiceCleanupError::Service)?;
        if entry.cleanup != Some(ticket) {
            return Err(ServiceCleanupError::Service(
                ServiceError::InvalidCleanupTicket,
            ));
        }
        eraser
            .erase(ticket.task, ticket.context)
            .map_err(ServiceCleanupError::Eraser)?;
        self.slots[slot].cleanup = None;
        Ok(())
    }

    /// Retires a recoverable user fault, completes all caller-supplied cleanup,
    /// and creates one fresh service generation from the caller's independently
    /// validated context before returning control to the dispatch loop. The
    /// retired context is used only to bind cleanup. A successful call does not
    /// expose the scheduler outcome until cleanup and restart have both
    /// succeeded; failures retain a typed stopped-service state for explicit
    /// retry or fail-stop handling.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_current_fault<
        E: ServiceAddressSpaceEraser,
        const TASKS: usize,
        const CAPS: usize,
        const MANAGEMENT_CAPS: usize,
    >(
        &mut self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        disposition: TrapDisposition,
        now: u64,
        eraser: &mut E,
        management: &CapabilitySpace<MANAGEMENT_CAPS>,
        control: Capability,
        priority: Priority,
        fresh_context: UserContext,
    ) -> Result<ServiceRecovery, ServiceRecoveryError<E::Error>> {
        let fault = self
            .fault_current_at(runtime, disposition, now)
            .map_err(ServiceRecoveryError::Retirement)?;
        self.complete_cleanup(fault.cleanup, eraser)
            .map_err(|error| ServiceRecoveryError::Cleanup {
                service: fault.service,
                error,
            })?;
        let replacement = self
            .restart_at(
                fault.service,
                management,
                control,
                runtime,
                priority,
                fresh_context,
                now,
            )
            .map_err(|error| ServiceRecoveryError::Restart {
                service: fault.service,
                error,
            })?;
        let task = self
            .task(replacement)
            .map_err(|error| ServiceRecoveryError::Restart {
                service: fault.service,
                error,
            })?
            .ok_or(ServiceRecoveryError::Restart {
                service: fault.service,
                error: ServiceError::TaskMismatch,
            })?;
        Ok(ServiceRecovery {
            retired: fault.service,
            replacement,
            task,
            next: fault.retirement.next,
        })
    }

    pub fn restart<const TASKS: usize, const CAPS: usize, const MANAGEMENT_CAPS: usize>(
        &mut self,
        service: ServiceId,
        management: &CapabilitySpace<MANAGEMENT_CAPS>,
        control: Capability,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        priority: Priority,
        fresh_context: UserContext,
    ) -> Result<ServiceId, ServiceError> {
        self.restart_at(
            service,
            management,
            control,
            runtime,
            priority,
            fresh_context,
            0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn restart_at<const TASKS: usize, const CAPS: usize, const MANAGEMENT_CAPS: usize>(
        &mut self,
        service: ServiceId,
        management: &CapabilitySpace<MANAGEMENT_CAPS>,
        control: Capability,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        priority: Priority,
        fresh_context: UserContext,
        now: u64,
    ) -> Result<ServiceId, ServiceError> {
        let slot = service.slot as usize;
        let entry = self.slot(service)?;
        if entry.state == ServiceState::Running || entry.task.is_some() {
            return Err(ServiceError::StillRunning);
        }
        let authorized = management
            .authorize(control, crate::Rights::CONTROL)
            .map_err(ServiceError::Unauthorized)?;
        if authorized != entry.object {
            return Err(ServiceError::Unauthorized(
                CapabilityError::PermissionDenied,
            ));
        }
        if entry.cleanup.is_some() {
            return Err(ServiceError::CleanupRequired);
        }
        if entry.completed_restarts >= entry.restart_policy.maximum_restarts {
            return Err(ServiceError::RestartLimit);
        }
        if now < entry.next_restart_tick {
            return Err(ServiceError::RestartBackoff {
                eligible_at: entry.next_restart_tick,
            });
        }
        let generation = entry
            .generation
            .checked_add(1)
            .filter(|generation| *generation != 0)
            .ok_or(ServiceError::GenerationExhausted)?;
        let task = runtime
            .create(priority, fresh_context)
            .map_err(ServiceError::Runtime)?;
        self.slots[slot].generation = generation;
        self.slots[slot].task = Some(task);
        self.slots[slot].state = ServiceState::Running;
        self.slots[slot].completed_restarts += 1;
        Ok(ServiceId {
            slot: slot as u32,
            generation,
        })
    }

    fn restart_deadline(&self, slot: usize, now: u64) -> Result<u64, ServiceError> {
        if self.slots[slot].completed_restarts >= self.slots[slot].restart_policy.maximum_restarts {
            return Ok(u64::MAX);
        }
        let delay = self.slots[slot]
            .restart_policy
            .delay(self.slots[slot].completed_restarts);
        now.checked_add(delay).ok_or(ServiceError::TimeExhausted)
    }

    fn slot(&self, service: ServiceId) -> Result<&ServiceSlot, ServiceError> {
        self.slots
            .get(service.slot as usize)
            .filter(|entry| entry.occupied && entry.generation == service.generation)
            .ok_or(ServiceError::InvalidService)
    }

    fn running_task_slot(&self, task: TaskId) -> Result<usize, ServiceError> {
        self.slots
            .iter()
            .position(|entry| {
                entry.occupied && entry.state == ServiceState::Running && entry.task == Some(task)
            })
            .ok_or(ServiceError::TaskMismatch)
    }

    fn id(&self, slot: usize) -> ServiceId {
        ServiceId {
            slot: slot as u32,
            generation: self.slots[slot].generation,
        }
    }
}

impl<const SERVICES: usize> Default for ServiceSupervisor<SERVICES> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ControlEvent, Endpoint, PeerDeathReason, PhysAddr, Rights};

    fn context(root: u64, entry: u64) -> UserContext {
        UserContext::new(PhysAddr::new(root).unwrap(), entry, 0x7000_0000).unwrap()
    }

    #[derive(Default)]
    struct TestEraser {
        fail: bool,
        erased: Option<(TaskId, UserContext)>,
    }

    impl ServiceAddressSpaceEraser for TestEraser {
        type Error = ();
        fn erase(&mut self, task: TaskId, context: UserContext) -> Result<(), Self::Error> {
            if self.fail {
                return Err(());
            }
            self.erased = Some((task, context));
            Ok(())
        }
    }

    fn complete<const N: usize>(
        supervisor: &mut ServiceSupervisor<N>,
        ticket: ServiceCleanupTicket,
    ) {
        supervisor
            .complete_cleanup(ticket, &mut TestEraser::default())
            .unwrap();
    }

    #[test]
    fn clean_exit_revokes_task_and_restart_requires_exact_control() {
        let object = ObjectId(0x51);
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        runtime.start();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let old = supervisor.register(object, task).unwrap();
        let retired = supervisor.exit_current(&mut runtime).unwrap();
        assert_eq!(retired.service, old);
        assert_eq!(supervisor.state(old), Ok(ServiceState::Exited));
        assert_eq!(runtime.context(task), Err(TaskRuntimeError::MissingTask));

        let mut management = CapabilitySpace::<2>::new();
        let wrong = management.insert(ObjectId(0x52), Rights::CONTROL).unwrap();
        assert_eq!(
            supervisor.restart(
                old,
                &management,
                wrong,
                &mut runtime,
                Priority::NORMAL,
                context(0x30_0000, 0x50_0000),
            ),
            Err(ServiceError::Unauthorized(
                CapabilityError::PermissionDenied
            ))
        );
        let control = management.insert(object, Rights::CONTROL).unwrap();
        assert_eq!(
            supervisor.restart(
                old,
                &management,
                control,
                &mut runtime,
                Priority::RESPONSIVE,
                context(0x30_0000, 0x50_0000),
            ),
            Err(ServiceError::CleanupRequired)
        );
        complete(&mut supervisor, retired.cleanup);
        let replacement = supervisor
            .restart(
                old,
                &management,
                control,
                &mut runtime,
                Priority::RESPONSIVE,
                context(0x30_0000, 0x50_0000),
            )
            .unwrap();
        assert_ne!(replacement, old);
        assert_eq!(supervisor.state(old), Err(ServiceError::InvalidService));
        assert_eq!(supervisor.state(replacement), Ok(ServiceState::Running));
        assert!(supervisor.task(replacement).unwrap().is_some());
    }

    #[test]
    fn faulted_service_needs_fresh_generation_to_restart() {
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        runtime.start();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let service = supervisor.register(ObjectId(7), task).unwrap();
        let fault = supervisor
            .fault_current(
                &mut runtime,
                TrapDisposition::TerminateUser {
                    vector: 6,
                    address: None,
                },
            )
            .unwrap();
        assert_eq!(fault.service, service);
        assert_eq!(supervisor.state(service), Ok(ServiceState::Faulted));
        complete(&mut supervisor, fault.cleanup);
    }

    #[test]
    fn restart_policy_enforces_authority_backoff_and_budget() {
        assert_eq!(
            RestartPolicy::new(0, 1, 1),
            Err(ServiceError::InvalidRestartPolicy)
        );
        assert_eq!(
            RestartPolicy::new(1, 2, 1),
            Err(ServiceError::InvalidRestartPolicy)
        );
        assert_eq!(
            RestartPolicy::new(2, u64::MAX - 1, u64::MAX)
                .unwrap()
                .delay(1),
            u64::MAX
        );
        let object = ObjectId(0x61);
        let policy = RestartPolicy::new(2, 10, 15).unwrap();
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        runtime.start();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let first = supervisor
            .register_with_policy(object, task, policy)
            .unwrap();
        let retirement = supervisor.exit_current_at(&mut runtime, 100).unwrap();
        complete(&mut supervisor, retirement.cleanup);

        let mut management = CapabilitySpace::<2>::new();
        let wrong = management.insert(ObjectId(0x62), Rights::CONTROL).unwrap();
        let control = management.insert(object, Rights::CONTROL).unwrap();
        assert_eq!(
            supervisor.restart_at(
                first,
                &management,
                wrong,
                &mut runtime,
                Priority::NORMAL,
                context(0x30_0000, 0x50_0000),
                101,
            ),
            Err(ServiceError::Unauthorized(
                CapabilityError::PermissionDenied
            ))
        );
        assert_eq!(
            supervisor.restart_at(
                first,
                &management,
                control,
                &mut runtime,
                Priority::NORMAL,
                context(0x30_0000, 0x50_0000),
                109,
            ),
            Err(ServiceError::RestartBackoff { eligible_at: 110 })
        );
        let second = supervisor
            .restart_at(
                first,
                &management,
                control,
                &mut runtime,
                Priority::NORMAL,
                context(0x30_0000, 0x50_0000),
                110,
            )
            .unwrap();
        assert!(matches!(runtime.start(), ScheduleOutcome::Switch { .. }));
        let fault = supervisor
            .fault_current_at(
                &mut runtime,
                TrapDisposition::TerminateUser {
                    vector: 6,
                    address: None,
                },
                200,
            )
            .unwrap();
        complete(&mut supervisor, fault.cleanup);
        assert_eq!(
            supervisor.restart_at(
                second,
                &management,
                control,
                &mut runtime,
                Priority::NORMAL,
                context(0x40_0000, 0x60_0000),
                214,
            ),
            Err(ServiceError::RestartBackoff { eligible_at: 215 })
        );
        let third = supervisor
            .restart_at(
                second,
                &management,
                control,
                &mut runtime,
                Priority::NORMAL,
                context(0x40_0000, 0x60_0000),
                215,
            )
            .unwrap();
        assert!(matches!(runtime.start(), ScheduleOutcome::Switch { .. }));
        let retirement = supervisor.exit_current_at(&mut runtime, 300).unwrap();
        complete(&mut supervisor, retirement.cleanup);
        assert_eq!(
            supervisor.restart_at(
                third,
                &management,
                control,
                &mut runtime,
                Priority::NORMAL,
                context(0x50_0000, 0x70_0000),
                u64::MAX,
            ),
            Err(ServiceError::RestartLimit)
        );
    }

    #[test]
    fn cleanup_is_exact_one_use_and_failure_keeps_restart_blocked() {
        let object = ObjectId(0x71);
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        runtime.start();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let service = supervisor.register(object, task).unwrap();
        let retirement = supervisor.exit_current(&mut runtime).unwrap();

        let mut eraser = TestEraser {
            fail: true,
            erased: None,
        };
        assert_eq!(
            supervisor.complete_cleanup(retirement.cleanup, &mut eraser),
            Err(ServiceCleanupError::Eraser(()))
        );
        let mut management = CapabilitySpace::<1>::new();
        let control = management.insert(object, Rights::CONTROL).unwrap();
        assert_eq!(
            supervisor.restart(
                service,
                &management,
                control,
                &mut runtime,
                Priority::NORMAL,
                context(0x30_0000, 0x50_0000),
            ),
            Err(ServiceError::CleanupRequired)
        );

        eraser.fail = false;
        supervisor
            .complete_cleanup(retirement.cleanup, &mut eraser)
            .unwrap();
        assert_eq!(eraser.erased, Some((task, retirement.cleanup.context())));
        assert_eq!(
            supervisor.complete_cleanup(retirement.cleanup, &mut eraser),
            Err(ServiceCleanupError::Service(
                ServiceError::InvalidCleanupTicket
            ))
        );
    }

    #[test]
    fn recovery_withholds_peer_resume_until_cleanup_and_fresh_generation() {
        let object = ObjectId(0x75);
        let endpoint_object = ObjectId(0x76);
        let mut runtime = TaskRuntime::<3, 2>::new(1_000, 1).unwrap();
        let faulted = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let observer = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let faulted_endpoint = runtime
            .capabilities_mut(faulted)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let observer_endpoint = runtime
            .capabilities_mut(observer)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        runtime
            .connect_control_peers(
                faulted,
                observer,
                &Endpoint::new(endpoint_object),
                faulted_endpoint,
                observer_endpoint,
            )
            .unwrap();
        assert!(matches!(runtime.start(), ScheduleOutcome::Switch { to, .. } if to == faulted));
        let retired_context = context(0x20_0000, 0x41_0000);
        *runtime.context_mut(faulted).unwrap() = retired_context;
        let fresh_context = context(0x20_0000, 0x40_0000);
        let mut supervisor = ServiceSupervisor::<1>::new();
        let retired = supervisor.register(object, faulted).unwrap();
        let mut management = CapabilitySpace::<1>::new();
        let control = management.insert(object, Rights::CONTROL).unwrap();
        let mut eraser = TestEraser::default();

        let recovery = supervisor
            .recover_current_fault(
                &mut runtime,
                TrapDisposition::TerminateUser {
                    vector: 14,
                    address: Some(0xdead),
                },
                0,
                &mut eraser,
                &management,
                control,
                Priority::NORMAL,
                fresh_context,
            )
            .unwrap();

        assert_eq!(recovery.retired, retired);
        assert_ne!(recovery.replacement, retired);
        assert_ne!(recovery.task, faulted);
        assert!(matches!(recovery.next, ScheduleOutcome::Switch { to, .. } if to == observer));
        assert_eq!(runtime.current(), Some(observer));
        assert_eq!(eraser.erased, Some((faulted, retired_context)));
        assert_eq!(runtime.context(recovery.task), Ok(&fresh_context));
        let ControlEvent::PeerDied(death) = runtime.receive_control(observer).unwrap() else {
            panic!("expected typed peer death");
        };
        assert_eq!(death.peer(), faulted);
        assert_eq!(
            death.reason(),
            PeerDeathReason::Faulted {
                vector: 14,
                address: Some(0xdead),
            }
        );
        assert_eq!(supervisor.state(retired), Err(ServiceError::InvalidService));
        assert_eq!(
            supervisor.state(recovery.replacement),
            Ok(ServiceState::Running)
        );
    }

    #[test]
    fn recovery_failure_retains_exact_cleanup_ticket_for_retry() {
        let object = ObjectId(0x77);
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        runtime.start();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let service = supervisor.register(object, task).unwrap();
        let mut management = CapabilitySpace::<1>::new();
        let control = management.insert(object, Rights::CONTROL).unwrap();
        let mut eraser = TestEraser {
            fail: true,
            erased: None,
        };

        let error = supervisor
            .recover_current_fault(
                &mut runtime,
                TrapDisposition::TerminateUser {
                    vector: 6,
                    address: None,
                },
                0,
                &mut eraser,
                &management,
                control,
                Priority::NORMAL,
                context(0x20_0000, 0x40_0000),
            )
            .unwrap_err();
        let ServiceRecoveryError::Cleanup {
            service: failed_service,
            error: ServiceCleanupError::Eraser(()),
        } = error
        else {
            panic!("expected retained cleanup failure");
        };
        assert_eq!(failed_service, service);
        assert_eq!(supervisor.state(service), Ok(ServiceState::Faulted));
        let cleanup = supervisor.pending_cleanup(service).unwrap().unwrap();
        assert_eq!(
            supervisor.restart(
                service,
                &management,
                control,
                &mut runtime,
                Priority::NORMAL,
                cleanup.context(),
            ),
            Err(ServiceError::CleanupRequired)
        );

        eraser.fail = false;
        supervisor.complete_cleanup(cleanup, &mut eraser).unwrap();
        assert!(
            supervisor
                .restart(
                    service,
                    &management,
                    control,
                    &mut runtime,
                    Priority::NORMAL,
                    cleanup.context(),
                )
                .is_ok()
        );
    }

    #[test]
    fn recovery_restart_rejection_leaves_clean_stopped_service_retryable() {
        let object = ObjectId(0x78);
        let saved = context(0x20_0000, 0x40_0000);
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime.create(Priority::NORMAL, saved).unwrap();
        runtime.start();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let service = supervisor.register(object, task).unwrap();
        let mut management = CapabilitySpace::<2>::new();
        let wrong = management.insert(ObjectId(0x79), Rights::CONTROL).unwrap();
        let control = management.insert(object, Rights::CONTROL).unwrap();
        let mut eraser = TestEraser::default();

        assert_eq!(
            supervisor.recover_current_fault(
                &mut runtime,
                TrapDisposition::TerminateUser {
                    vector: 6,
                    address: None,
                },
                0,
                &mut eraser,
                &management,
                wrong,
                Priority::NORMAL,
                saved,
            ),
            Err(ServiceRecoveryError::Restart {
                service,
                error: ServiceError::Unauthorized(CapabilityError::PermissionDenied),
            })
        );
        assert_eq!(supervisor.state(service), Ok(ServiceState::Faulted));
        assert_eq!(supervisor.pending_cleanup(service), Ok(None));
        assert!(
            supervisor
                .restart(
                    service,
                    &management,
                    control,
                    &mut runtime,
                    Priority::NORMAL,
                    saved,
                )
                .is_ok()
        );
    }

    #[test]
    fn retirement_time_overflow_is_rejected_before_revocation() {
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        runtime.start();
        let mut supervisor = ServiceSupervisor::<1>::new();
        supervisor
            .register_with_policy(ObjectId(7), task, RestartPolicy::new(1, 10, 10).unwrap())
            .unwrap();
        assert_eq!(
            supervisor.exit_current_at(&mut runtime, u64::MAX - 5),
            Err(ServiceError::TimeExhausted)
        );
        assert!(runtime.context(task).is_ok());
        assert_eq!(runtime.current(), Some(task));
    }
}
