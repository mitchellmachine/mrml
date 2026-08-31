use core::array;
use core::mem::size_of;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::x86_64::{TrapDisposition, UserContext};
use crate::device_service::{
    validate_current_native_device_service_retirement_state,
    validate_native_device_service_retirement_state,
};
use crate::task_runtime::FrozenTask;
use crate::{
    Capability, CapabilityError, CapabilitySpace, DeadlineReceiveCancellation,
    DeadlineReceiveCancellationEscrow, DeadlineReceiveSyscallError, DeadlineReceiveSyscallExecutor,
    FaultRetirement, MemoryBackingKind, MemoryObjectId, MemoryPoolId, MemoryPoolTable,
    MemoryResourceError, NativeDeviceServiceRetirement, NativeDeviceServiceRetirementError,
    NativeDeviceServiceTask, ObjectId, PAGE_SIZE, Priority, Rights, TaskId,
    TaskProtocolViolation, TaskRuntime, TaskRuntimeError, TaskTermination,
    TaskTerminationDispatch, TaskTerminationDispatchError, TaskViolationRetirement,
    retire_current_native_device_service_task,
};

#[cfg(test)]
use crate::ScheduleOutcome;

static NEXT_SERVICE_SUPERVISOR_IDENTITY: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceId {
    slot: u32,
    generation: u32,
}

impl ServiceId {
    pub const fn token(self) -> u64 {
        ((self.generation as u64) << 32) | self.slot as u64
    }

    /// Reconstructs an untrusted opaque service handle. Callers gain no
    /// authority until the supervisor validates its generation and the
    /// operation's independently supplied capability.
    pub const fn from_token(token: u64) -> Self {
        Self {
            slot: token as u32,
            generation: (token >> 32) as u32,
        }
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
    ObjectAlreadyRegistered,
    TaskMismatch,
    TaskAlreadyRegistered,
    StillRunning,
    GenerationExhausted,
    InvalidRestartPolicy,
    RestartLimit,
    RestartBackoff { eligible_at: u64 },
    TimeExhausted,
    CleanupRequired,
    ConstructedLifecycleRequired,
    InvalidCleanupTicket,
    Unauthorized(CapabilityError),
    Runtime(TaskRuntimeError),
    Dispatch(TaskTerminationDispatchError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceDeadlineCancellationError {
    Service(ServiceError),
    Deadline(DeadlineReceiveSyscallError),
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

    pub const fn maximum_restarts(self) -> u32 {
        self.maximum_restarts
    }

    pub const fn base_backoff_ticks(self) -> u64 {
        self.base_backoff_ticks
    }

    pub const fn maximum_backoff_ticks(self) -> u64 {
        self.maximum_backoff_ticks
    }

    fn delay(self, completed_restarts: u32) -> u64 {
        let shift = completed_restarts.min(63);
        self.base_backoff_ticks
            .saturating_mul(1u64 << shift)
            .min(self.maximum_backoff_ticks)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ServiceRetirement {
    pub service: ServiceId,
    pub task: TaskId,
    pub cleanup: ServiceCleanupTicket,
    pub dispatch: TaskTerminationDispatch,
}

/// A supervisor-bound constructed service whose task has stopped but whose
/// address space has not yet been erased. Successor dispatch is withheld by
/// the retained termination owner.
#[derive(Debug)]
pub struct SupervisedConstructedServiceRetirement {
    binding: SupervisedServiceTask,
    termination: TaskTermination,
    cleanup: ServiceCleanupTicket,
}

impl SupervisedConstructedServiceRetirement {
    pub const fn service(&self) -> ServiceId {
        self.binding.service
    }

    pub const fn task(&self) -> TaskId {
        self.binding.task
    }

    pub const fn cleanup(&self) -> ServiceCleanupTicket {
        self.cleanup
    }
}

#[derive(Debug)]
pub struct SupervisedConstructedServiceCleanupFailure<E> {
    error: ServiceCleanupError<E>,
    retirement: SupervisedConstructedServiceRetirement,
}

impl<E> SupervisedConstructedServiceCleanupFailure<E> {
    pub const fn error(&self) -> &ServiceCleanupError<E> {
        &self.error
    }

    pub fn into_retirement(self) -> SupervisedConstructedServiceRetirement {
        self.retirement
    }
}

#[derive(Debug)]
pub struct CleanedSupervisedConstructedService {
    binding: SupervisedServiceTask,
    termination: TaskTermination,
}

impl CleanedSupervisedConstructedService {
    pub const fn service(&self) -> ServiceId {
        self.binding.service
    }

    pub const fn task(&self) -> TaskId {
        self.binding.task
    }

    pub fn dispatch<const TASKS: usize, const CAPS: usize>(
        self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
    ) -> Result<TaskTerminationDispatch, SupervisedConstructedServiceDispatchFailure> {
        match runtime.dispatch_after_termination(self.termination) {
            Ok(dispatch) => Ok(dispatch),
            Err(error) => Err(SupervisedConstructedServiceDispatchFailure {
                error,
                cleaned: self,
            }),
        }
    }
}

#[derive(Debug)]
pub struct SupervisedConstructedServiceDispatchFailure {
    error: TaskTerminationDispatchError,
    cleaned: CleanedSupervisedConstructedService,
}

impl SupervisedConstructedServiceDispatchFailure {
    pub const fn error(&self) -> TaskTerminationDispatchError {
        self.error
    }

    pub fn into_cleaned(self) -> CleanedSupervisedConstructedService {
        self.cleaned
    }
}

/// Exact supervisor, service generation, and runtime task binding minted by
/// constructed-task publication. The binding identifies lifecycle state but
/// grants no authority independently of the supervisor and live runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupervisedServiceTask {
    supervisor: u64,
    service: ServiceId,
    task: TaskId,
}

impl SupervisedServiceTask {
    pub const fn service(self) -> ServiceId {
        self.service
    }

    pub const fn task(self) -> TaskId {
        self.task
    }
}

/// Exact constructed-service execution freeze. The runtime retains the task's
/// complete domain and capabilities, but no successor is scheduler-visible
/// until device quiescence consumes this owner into retirement.
pub struct SupervisedNativeDeviceServiceFreeze<const N: usize> {
    binding: SupervisedServiceTask,
    native: NativeDeviceServiceTask<N>,
    frozen: FrozenTask,
}

impl<const N: usize> SupervisedNativeDeviceServiceFreeze<N> {
    pub const fn service(&self) -> ServiceId {
        self.binding.service
    }

    pub const fn task(&self) -> TaskId {
        self.binding.task
    }
}

pub struct SupervisedNativeDeviceServiceFrozenRetirementError<const N: usize> {
    error: SupervisedNativeDeviceServiceRetirementError,
    frozen: SupervisedNativeDeviceServiceFreeze<N>,
}

impl<const N: usize> SupervisedNativeDeviceServiceFrozenRetirementError<N> {
    pub const fn error(&self) -> SupervisedNativeDeviceServiceRetirementError {
        self.error
    }

    pub fn into_frozen(self) -> SupervisedNativeDeviceServiceFreeze<N> {
        self.frozen
    }
}

/// A stopped native device-service whose successor dispatch remains withheld.
/// Device-specific owners must retain this state until DMA and mapping cleanup
/// have completed.
pub struct SupervisedNativeDeviceServiceRetirement<const N: usize> {
    binding: SupervisedServiceTask,
    termination: TaskTermination,
    native: NativeDeviceServiceRetirement<N>,
    cleanup: ServiceCleanupTicket,
}

impl<const N: usize> SupervisedNativeDeviceServiceRetirement<N> {
    pub const fn service(&self) -> ServiceId {
        self.binding.service
    }

    pub const fn task(&self) -> TaskId {
        self.binding.task
    }

    pub const fn native(&self) -> NativeDeviceServiceRetirement<N> {
        self.native
    }

    pub fn dispatch<const TASKS: usize, const CAPS: usize>(
        self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
    ) -> Result<SupervisedNativeDeviceServiceDispatch<N>, SupervisedNativeDeviceServiceDispatchError<N>> {
        if !self.native.task().belongs_to_runtime(runtime) {
            return Err(SupervisedNativeDeviceServiceDispatchError {
                error: TaskTerminationDispatchError::RetirementRuntimeMismatch,
                retirement: self,
            });
        }
        let Self {
            binding,
            termination,
            native,
            cleanup,
        } = self;
        match runtime.dispatch_after_termination(termination) {
            Ok(dispatch) => Ok(SupervisedNativeDeviceServiceDispatch {
                binding,
                native,
                cleanup,
                dispatch,
            }),
            Err(error) => Err(SupervisedNativeDeviceServiceDispatchError {
                error,
                retirement: Self {
                    binding,
                    termination,
                    native,
                    cleanup,
                },
            }),
        }
    }
}

pub struct SupervisedNativeDeviceServiceDispatch<const N: usize> {
    binding: SupervisedServiceTask,
    native: NativeDeviceServiceRetirement<N>,
    cleanup: ServiceCleanupTicket,
    dispatch: TaskTerminationDispatch,
}

impl<const N: usize> SupervisedNativeDeviceServiceDispatch<N> {
    pub const fn service(&self) -> ServiceId {
        self.binding.service
    }

    pub const fn task(&self) -> TaskId {
        self.binding.task
    }

    pub const fn cleanup(&self) -> ServiceCleanupTicket {
        self.cleanup
    }

    pub const fn native(&self) -> NativeDeviceServiceRetirement<N> {
        self.native
    }

    pub const fn dispatch(&self) -> &TaskTerminationDispatch {
        &self.dispatch
    }

    pub fn into_parts(
        self,
    ) -> (
        SupervisedServiceTask,
        NativeDeviceServiceRetirement<N>,
        ServiceCleanupTicket,
        TaskTerminationDispatch,
    ) {
        (self.binding, self.native, self.cleanup, self.dispatch)
    }
}

pub struct SupervisedNativeDeviceServiceDispatchError<const N: usize> {
    error: TaskTerminationDispatchError,
    retirement: SupervisedNativeDeviceServiceRetirement<N>,
}

impl<const N: usize> SupervisedNativeDeviceServiceDispatchError<N> {
    pub const fn error(&self) -> TaskTerminationDispatchError {
        self.error
    }

    pub fn into_retirement(self) -> SupervisedNativeDeviceServiceRetirement<N> {
        self.retirement
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisedNativeDeviceServiceRetirementError {
    Service(ServiceError),
    Native(NativeDeviceServiceRetirementError),
}

#[derive(Debug, Eq, PartialEq)]
pub struct ServiceFault {
    pub service: ServiceId,
    pub retirement: FaultRetirement,
    pub cleanup: ServiceCleanupTicket,
    pub dispatch: TaskTerminationDispatch,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ServiceViolation {
    pub service: ServiceId,
    pub retirement: TaskViolationRetirement,
    pub cleanup: ServiceCleanupTicket,
    pub dispatch: TaskTerminationDispatch,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ServiceRecovery {
    pub retired: ServiceId,
    pub replacement: ServiceId,
    pub task: TaskId,
    pub dispatch: TaskTerminationDispatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceRestartCommit {
    service: ServiceId,
    task: TaskId,
}

impl ServiceRestartCommit {
    pub const fn service(self) -> ServiceId {
        self.service
    }

    pub const fn task(self) -> TaskId {
        self.task
    }
}

/// One-use registration decision bound to one exact vacant supervisor slot.
/// The plan carries no capability and cannot authorize any other lifecycle
/// operation. Commit rechecks the slot generation and vacancy before mutation.
#[derive(Debug, Eq, PartialEq)]
pub struct ServiceRegistrationPlan {
    slot: u32,
    generation: u32,
    object: ObjectId,
    task: TaskId,
    restart_policy: RestartPolicy,
}

impl ServiceRegistrationPlan {
    pub const fn object(&self) -> ObjectId {
        self.object
    }

    pub const fn task(&self) -> TaskId {
        self.task
    }
}

/// A one-use, supervisor-created restart decision. Untrusted requests select
/// only the service and capability; trusted kernel code supplies the launch
/// context, priority, and observed time before host reprovisioning begins.
#[derive(Debug, Eq, PartialEq)]
pub struct ServiceRestartPlan {
    service: ServiceId,
    object: ObjectId,
    control: Capability,
    policy_generation: u32,
    priority: Priority,
    context: UserContext,
    now: u64,
}

impl ServiceRestartPlan {
    pub const fn service(&self) -> ServiceId {
        self.service
    }

    pub const fn object(&self) -> ObjectId {
        self.object
    }
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

struct CurrentServiceRetirementPlan {
    slot: usize,
    service: ServiceId,
    task: TaskId,
    next_restart_tick: u64,
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
    runtime: Option<u64>,
    launch_class: ServiceLaunchClass,
    state: ServiceState,
    occupied: bool,
    restart_policy: RestartPolicy,
    policy_generation: u32,
    completed_restarts: u32,
    next_restart_tick: u64,
    cleanup: Option<ServiceCleanupTicket>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceLaunchClass {
    Ordinary,
    Constructed,
}

impl ServiceSlot {
    const EMPTY: Self = Self {
        generation: 1,
        object: ObjectId(0),
        task: None,
        runtime: None,
        launch_class: ServiceLaunchClass::Ordinary,
        state: ServiceState::Exited,
        occupied: false,
        restart_policy: RestartPolicy::ONCE_IMMEDIATE,
        policy_generation: 1,
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
    identity: Option<u64>,
    slots: [ServiceSlot; SERVICES],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountedServiceSupervisorError {
    Memory(MemoryResourceError),
    Arithmetic,
}

impl From<MemoryResourceError> for AccountedServiceSupervisorError {
    fn from(value: MemoryResourceError) -> Self {
        Self::Memory(value)
    }
}

/// Fixed-capacity lifecycle, cleanup, policy, and restart state committed to
/// one exact memory pool before publication.
pub struct AccountedServiceSupervisor<const SERVICES: usize> {
    supervisor: ServiceSupervisor<SERVICES>,
    charge: MemoryObjectId,
    charge_capability: Capability,
    committed_pages: u64,
}

impl<const SERVICES: usize> AccountedServiceSupervisor<SERVICES> {
    pub fn new<const POOLS: usize, const OBJECTS: usize, const AUTHORITIES: usize>(
        pool: MemoryPoolId,
        pool_capability: Capability,
        memory: &mut MemoryPoolTable<POOLS, OBJECTS>,
        authorities: &mut CapabilitySpace<AUTHORITIES>,
    ) -> Result<Self, AccountedServiceSupervisorError> {
        let committed_pages = Self::required_pages()?;
        let (charge, charge_capability) = memory.allocate_object(
            pool,
            pool_capability,
            committed_pages,
            MemoryBackingKind::Anonymous,
            Rights::CONTROL,
            authorities,
        )?;
        Ok(Self {
            supervisor: ServiceSupervisor::new(),
            charge,
            charge_capability,
            committed_pages,
        })
    }

    pub fn required_pages() -> Result<u64, AccountedServiceSupervisorError> {
        let bytes = u64::try_from(size_of::<Self>())
            .map_err(|_| AccountedServiceSupervisorError::Arithmetic)?;
        bytes
            .checked_add(PAGE_SIZE - 1)
            .map(|rounded| rounded / PAGE_SIZE)
            .filter(|pages| *pages != 0)
            .ok_or(AccountedServiceSupervisorError::Arithmetic)
    }

    pub const fn charge(&self) -> MemoryObjectId {
        self.charge
    }

    pub const fn committed_pages(&self) -> u64 {
        self.committed_pages
    }

    /// Consumes the supervisor and returns its commitment only after every
    /// dependent lifecycle authority has been retired externally.
    ///
    /// Failure returns the complete still-accounted supervisor.
    ///
    /// # Safety
    ///
    /// No running/stopped task, cleanup ticket, prepared registration/restart,
    /// peer, recovery path, or external policy state may depend on any slot or
    /// generation in this supervisor.
    #[allow(clippy::result_large_err)]
    pub unsafe fn release<const POOLS: usize, const OBJECTS: usize, const AUTHORITIES: usize>(
        self,
        memory: &mut MemoryPoolTable<POOLS, OBJECTS>,
        authorities: &mut CapabilitySpace<AUTHORITIES>,
    ) -> Result<u64, (Self, MemoryResourceError)> {
        match memory.release_object(self.charge, self.charge_capability, authorities) {
            Ok(pages) => Ok(pages),
            Err(error) => Err((self, error)),
        }
    }
}

impl<const SERVICES: usize> Deref for AccountedServiceSupervisor<SERVICES> {
    type Target = ServiceSupervisor<SERVICES>;

    fn deref(&self) -> &Self::Target {
        &self.supervisor
    }
}

impl<const SERVICES: usize> DerefMut for AccountedServiceSupervisor<SERVICES> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.supervisor
    }
}

impl<const SERVICES: usize> ServiceSupervisor<SERVICES> {
    pub fn new() -> Self {
        Self {
            identity: None,
            slots: array::from_fn(|_| ServiceSlot::EMPTY),
        }
    }

    pub fn register(&mut self, object: ObjectId, task: TaskId) -> Result<ServiceId, ServiceError> {
        self.register_with_policy(object, task, RestartPolicy::ONCE_IMMEDIATE)
    }

    /// Registers an already-runnable task only after binding its exact runtime
    /// identity. Runtime lifecycle and wait-cancellation operations reject the
    /// older unbound registration form.
    pub fn register_in_runtime<const TASKS: usize, const CAPS: usize>(
        &mut self,
        object: ObjectId,
        task: TaskId,
        runtime: &TaskRuntime<TASKS, CAPS>,
    ) -> Result<ServiceId, ServiceError> {
        self.register_with_policy_in_runtime(
            object,
            task,
            RestartPolicy::ONCE_IMMEDIATE,
            runtime,
        )
    }

    pub fn register_with_policy_in_runtime<const TASKS: usize, const CAPS: usize>(
        &mut self,
        object: ObjectId,
        task: TaskId,
        restart_policy: RestartPolicy,
        runtime: &TaskRuntime<TASKS, CAPS>,
    ) -> Result<ServiceId, ServiceError> {
        let plan = self.plan_registration_in_runtime(object, task, restart_policy, runtime)?;
        self.commit_registration_with_runtime(plan, runtime)
    }

    /// Creates and publishes one supervised task as a single kernel-owned
    /// transition. Slot and object validation complete before task creation,
    /// and no caller can mutate the reservation between creation and publish.
    pub fn launch<const TASKS: usize, const CAPS: usize>(
        &mut self,
        object: ObjectId,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        priority: Priority,
        context: UserContext,
    ) -> Result<(ServiceId, TaskId), ServiceError> {
        if object.0 == 0 {
            return Err(ServiceError::InvalidObject);
        }
        let slot = self
            .slots
            .iter()
            .position(|entry| !entry.occupied)
            .ok_or(ServiceError::Full)?;
        if self
            .slots
            .iter()
            .any(|entry| entry.occupied && entry.object == object)
        {
            return Err(ServiceError::ObjectAlreadyRegistered);
        }
        let generation = self.slots[slot].generation;
        let task = runtime
            .create(priority, context)
            .map_err(ServiceError::Runtime)?;
        let entry = &mut self.slots[slot];
        debug_assert!(!entry.occupied && entry.generation == generation);
        entry.object = object;
        entry.task = Some(task);
        entry.runtime = Some(runtime.identity());
        entry.launch_class = ServiceLaunchClass::Ordinary;
        entry.state = ServiceState::Running;
        entry.occupied = true;
        entry.restart_policy = RestartPolicy::ONCE_IMMEDIATE;
        entry.policy_generation = 1;
        entry.completed_restarts = 0;
        entry.next_restart_tick = 0;
        entry.cleanup = None;
        Ok((
            ServiceId {
                slot: slot as u32,
                generation,
            },
            task,
        ))
    }

    pub fn register_with_policy(
        &mut self,
        object: ObjectId,
        task: TaskId,
        restart_policy: RestartPolicy,
    ) -> Result<ServiceId, ServiceError> {
        let plan = self.plan_registration(object, task, restart_policy)?;
        self.commit_registration(plan)
    }

    pub fn plan_registration(
        &self,
        object: ObjectId,
        task: TaskId,
        restart_policy: RestartPolicy,
    ) -> Result<ServiceRegistrationPlan, ServiceError> {
        self.plan_registration_for_runtime(object, task, restart_policy, None)
    }

    pub fn plan_registration_in_runtime<const TASKS: usize, const CAPS: usize>(
        &self,
        object: ObjectId,
        task: TaskId,
        restart_policy: RestartPolicy,
        runtime: &TaskRuntime<TASKS, CAPS>,
    ) -> Result<ServiceRegistrationPlan, ServiceError> {
        self.plan_registration_for_runtime(
            object,
            task,
            restart_policy,
            Some(runtime.identity()),
        )
    }

    fn plan_registration_for_runtime(
        &self,
        object: ObjectId,
        task: TaskId,
        restart_policy: RestartPolicy,
        runtime: Option<u64>,
    ) -> Result<ServiceRegistrationPlan, ServiceError> {
        if object.0 == 0 {
            return Err(ServiceError::InvalidObject);
        }
        let (slot, entry) = self
            .slots
            .iter()
            .enumerate()
            .find(|(_, entry)| !entry.occupied)
            .ok_or(ServiceError::Full)?;
        if self
            .slots
            .iter()
            .any(|entry| Self::task_binding_conflicts(entry, task, runtime))
        {
            return Err(ServiceError::TaskAlreadyRegistered);
        }
        if self
            .slots
            .iter()
            .any(|entry| entry.occupied && entry.object == object)
        {
            return Err(ServiceError::ObjectAlreadyRegistered);
        }
        Ok(ServiceRegistrationPlan {
            slot: slot as u32,
            generation: entry.generation,
            object,
            task,
            restart_policy,
        })
    }

    pub fn commit_registration(
        &mut self,
        plan: ServiceRegistrationPlan,
    ) -> Result<ServiceId, ServiceError> {
        self.validate_registration_plan(&plan, None)?;
        Ok(self.commit_registration_prevalidated(
            plan,
            None,
            ServiceLaunchClass::Ordinary,
        ))
    }

    /// Publishes a prepared registration only while its exact task generation
    /// remains live in the supplied runtime. Recovery and other delayed
    /// publication paths must use this entry rather than trusting the
    /// prepare-time task identity.
    pub fn commit_registration_with_runtime<const TASKS: usize, const CAPS: usize>(
        &mut self,
        plan: ServiceRegistrationPlan,
        runtime: &TaskRuntime<TASKS, CAPS>,
    ) -> Result<ServiceId, ServiceError> {
        runtime.context(plan.task).map_err(ServiceError::Runtime)?;
        if runtime
            .construction_pending(plan.task)
            .map_err(ServiceError::Runtime)?
        {
            return Err(ServiceError::Runtime(
                TaskRuntimeError::ConstructionPending,
            ));
        }
        self.validate_registration_plan(&plan, Some(runtime.identity()))?;
        Ok(self.commit_registration_prevalidated(
            plan,
            Some(runtime.identity()),
            ServiceLaunchClass::Ordinary,
        ))
    }

    /// Registers an already-complete construction target and makes it runnable
    /// as one kernel-owned transition. Every fallible supervisor and scheduler
    /// check completes before the supervisor slot is published; the exact task
    /// is woken only after that publication.
    ///
    /// # Safety
    ///
    /// `task` must identify the fully constructed task owned by `runtime`, and
    /// `object` must be the lifecycle object authenticated by the same typed
    /// construction owner. Ordinary exclusive references provide the operation's
    /// serialization; any lower-level interrupt access must obey the same Rust
    /// aliasing contract as every other mutation of these owners.
    pub unsafe fn register_and_activate_constructed<
        const TASKS: usize,
        const CAPS: usize,
    >(
        &mut self,
        object: ObjectId,
        task: TaskId,
        restart_policy: RestartPolicy,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
    ) -> Result<SupervisedServiceTask, ServiceError> {
        let runtime_identity = runtime.identity();
        let registration = self.plan_registration_for_runtime(
            object,
            task,
            restart_policy,
            Some(runtime_identity),
        )?;
        self.validate_registration_plan(&registration, Some(runtime_identity))?;
        let activation = runtime
            .prepare_constructed_task_activation(task)
            .map_err(ServiceError::Runtime)?;
        let supervisor = self.ensure_identity()?;

        let service = self.commit_registration_prevalidated(
            registration,
            Some(runtime_identity),
            ServiceLaunchClass::Constructed,
        );
        activation.commit();
        Ok(SupervisedServiceTask {
            supervisor,
            service,
            task,
        })
    }

    fn ensure_identity(&mut self) -> Result<u64, ServiceError> {
        if let Some(identity) = self.identity {
            return Ok(identity);
        }
        let identity = allocate_service_supervisor_identity(&NEXT_SERVICE_SUPERVISOR_IDENTITY)?;
        self.identity = Some(identity);
        Ok(identity)
    }

    fn validate_registration_plan(
        &self,
        plan: &ServiceRegistrationPlan,
        runtime: Option<u64>,
    ) -> Result<(), ServiceError> {
        let entry = self
            .slots
            .get(plan.slot as usize)
            .ok_or(ServiceError::InvalidService)?;
        if entry.occupied || entry.generation != plan.generation {
            return Err(ServiceError::InvalidService);
        }
        if self
            .slots
            .iter()
            .any(|entry| Self::task_binding_conflicts(entry, plan.task, runtime))
        {
            return Err(ServiceError::TaskAlreadyRegistered);
        }
        if self
            .slots
            .iter()
            .any(|entry| entry.occupied && entry.object == plan.object)
        {
            return Err(ServiceError::ObjectAlreadyRegistered);
        }
        Ok(())
    }

    fn task_binding_conflicts(
        entry: &ServiceSlot,
        task: TaskId,
        runtime: Option<u64>,
    ) -> bool {
        if !entry.occupied || entry.task != Some(task) {
            return false;
        }
        match (entry.runtime, runtime) {
            (Some(existing), Some(requested)) => existing == requested,
            _ => true,
        }
    }

    fn commit_registration_prevalidated(
        &mut self,
        plan: ServiceRegistrationPlan,
        runtime: Option<u64>,
        launch_class: ServiceLaunchClass,
    ) -> ServiceId {
        let entry = &mut self.slots[plan.slot as usize];
        debug_assert!(!entry.occupied && entry.generation == plan.generation);
        entry.object = plan.object;
        entry.task = Some(plan.task);
        entry.runtime = runtime;
        entry.launch_class = launch_class;
        entry.state = ServiceState::Running;
        entry.occupied = true;
        entry.restart_policy = plan.restart_policy;
        entry.policy_generation = 1;
        entry.completed_restarts = 0;
        entry.next_restart_tick = 0;
        entry.cleanup = None;
        ServiceId {
            slot: plan.slot,
            generation: entry.generation,
        }
    }

    pub fn state(&self, service: ServiceId) -> Result<ServiceState, ServiceError> {
        Ok(self.slot(service)?.state)
    }

    /// Returns lifecycle state only when the caller holds exact READ authority
    /// for this service object. Public supervision protocols must use this
    /// path rather than treating a service token as introspection authority.
    pub fn state_authorized<const MANAGEMENT_CAPS: usize>(
        &self,
        service: ServiceId,
        management: &CapabilitySpace<MANAGEMENT_CAPS>,
        authority: Capability,
    ) -> Result<ServiceState, ServiceError> {
        let entry = self.slot(service)?;
        let object = management
            .authorize_exact(authority, crate::Rights::READ)
            .map_err(ServiceError::Unauthorized)?;
        if object != entry.object {
            return Err(ServiceError::Unauthorized(
                CapabilityError::PermissionDenied,
            ));
        }
        Ok(entry.state)
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

    /// Replaces restart policy only through exact service CONTROL authority.
    /// Consumed restart budget and an already-computed eligibility deadline are
    /// retained; replacement cannot manufacture retries or shorten a pending
    /// backoff. Advancing the policy generation invalidates every restart plan
    /// prepared under the prior policy.
    pub fn replace_restart_policy<const MANAGEMENT_CAPS: usize>(
        &mut self,
        service: ServiceId,
        management: &CapabilitySpace<MANAGEMENT_CAPS>,
        control: Capability,
        restart_policy: RestartPolicy,
    ) -> Result<(), ServiceError> {
        let entry = self.slot(service)?;
        let authorized = management
            .authorize_exact(control, crate::Rights::CONTROL)
            .map_err(ServiceError::Unauthorized)?;
        if authorized != entry.object {
            return Err(ServiceError::Unauthorized(
                CapabilityError::PermissionDenied,
            ));
        }
        let next_policy_generation = entry
            .policy_generation
            .checked_add(1)
            .filter(|generation| *generation != 0)
            .ok_or(ServiceError::GenerationExhausted)?;
        let slot = service.slot as usize;
        self.slots[slot].restart_policy = restart_policy;
        self.slots[slot].policy_generation = next_policy_generation;
        Ok(())
    }

    /// Cancels one exact suspended deadline receive only when the manager also
    /// holds exact CONTROL authority for the token's live service instance.
    pub fn cancel_deadline_receive<
        const TASKS: usize,
        const CAPS: usize,
        const MANAGEMENT_CAPS: usize,
    >(
        &self,
        service: ServiceId,
        management: &CapabilitySpace<MANAGEMENT_CAPS>,
        control: Capability,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        executor: &mut DeadlineReceiveSyscallExecutor<TASKS>,
        cancellation: DeadlineReceiveCancellation,
    ) -> Result<(), ServiceDeadlineCancellationError> {
        let entry = self
            .slot(service)
            .map_err(ServiceDeadlineCancellationError::Service)?;
        let authorized = management
            .authorize_exact(control, Rights::CONTROL)
            .map_err(ServiceError::Unauthorized)
            .map_err(ServiceDeadlineCancellationError::Service)?;
        if authorized != entry.object {
            return Err(ServiceDeadlineCancellationError::Service(
                ServiceError::Unauthorized(CapabilityError::PermissionDenied),
            ));
        }
        let task = self
            .running_task_in_runtime(service, runtime.identity())
            .map_err(ServiceDeadlineCancellationError::Service)?;
        if task != cancellation.task() {
            return Err(ServiceDeadlineCancellationError::Service(
                ServiceError::TaskMismatch,
            ));
        }
        executor
            .cancel(runtime, cancellation)
            .map_err(ServiceDeadlineCancellationError::Deadline)
    }

    /// Resolves the opaque wait token only after exact service CONTROL
    /// authorization, then consumes both the executor owner and escrow entry.
    pub fn cancel_escrowed_deadline_receive<
        const TASKS: usize,
        const CAPS: usize,
        const MANAGEMENT_CAPS: usize,
    >(
        &self,
        service: ServiceId,
        management: &CapabilitySpace<MANAGEMENT_CAPS>,
        control: Capability,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        executor: &mut DeadlineReceiveSyscallExecutor<TASKS>,
        escrow: &mut DeadlineReceiveCancellationEscrow<TASKS>,
    ) -> Result<(), ServiceDeadlineCancellationError> {
        executor
            .validate_escrow(escrow)
            .map_err(ServiceDeadlineCancellationError::Deadline)?;
        let entry = self
            .slot(service)
            .map_err(ServiceDeadlineCancellationError::Service)?;
        let authorized = management
            .authorize_exact(control, Rights::CONTROL)
            .map_err(ServiceError::Unauthorized)
            .map_err(ServiceDeadlineCancellationError::Service)?;
        if authorized != entry.object {
            return Err(ServiceDeadlineCancellationError::Service(
                ServiceError::Unauthorized(CapabilityError::PermissionDenied),
            ));
        }
        let task = self
            .running_task_in_runtime(service, runtime.identity())
            .map_err(ServiceDeadlineCancellationError::Service)?;
        let cancellation = escrow
            .get(task)
            .map_err(ServiceDeadlineCancellationError::Deadline)?;
        executor
            .cancel(runtime, cancellation)
            .map_err(ServiceDeadlineCancellationError::Deadline)?;
        escrow
            .retire(cancellation)
            .expect("successful exact cancellation preserves its prevalidated escrow owner");
        executor
            .validate_escrow(escrow)
            .map_err(ServiceDeadlineCancellationError::Deadline)?;
        Ok(())
    }

    /// Request-bound variant for syscall dispatchers. The requester must hold
    /// an exact task-local CONTROL handle for the live service object; the
    /// service token and escrowed wait remain independent matching inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn cancel_escrowed_deadline_receive_for_requester<const TASKS: usize, const CAPS: usize>(
        &self,
        service: ServiceId,
        requester: TaskId,
        control: Capability,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        executor: &mut DeadlineReceiveSyscallExecutor<TASKS>,
        escrow: &mut DeadlineReceiveCancellationEscrow<TASKS>,
    ) -> Result<(), ServiceDeadlineCancellationError> {
        executor
            .validate_escrow(escrow)
            .map_err(ServiceDeadlineCancellationError::Deadline)?;
        let entry = self
            .slot(service)
            .map_err(ServiceDeadlineCancellationError::Service)?;
        runtime
            .authorize_capability_exact(requester, control, Rights::CONTROL, entry.object)
            .map_err(ServiceError::Runtime)
            .map_err(ServiceDeadlineCancellationError::Service)?;
        let task = self
            .running_task_in_runtime(service, runtime.identity())
            .map_err(ServiceDeadlineCancellationError::Service)?;
        let cancellation = escrow
            .get(task)
            .map_err(ServiceDeadlineCancellationError::Deadline)?;
        executor
            .cancel(runtime, cancellation)
            .map_err(ServiceDeadlineCancellationError::Deadline)?;
        escrow
            .retire(cancellation)
            .expect("successful requester cancellation preserves its escrow owner");
        executor
            .validate_escrow(escrow)
            .map_err(ServiceDeadlineCancellationError::Deadline)?;
        Ok(())
    }

    pub fn exit_current<const TASKS: usize, const CAPS: usize>(
        &mut self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
    ) -> Result<ServiceRetirement, ServiceError> {
        self.exit_current_at(runtime, 0)
    }

    /// Stops the exact current constructed service while retaining its
    /// termination until supervisor-bound address-space cleanup completes.
    pub fn retire_current_constructed_service<
        const TASKS: usize,
        const CAPS: usize,
    >(
        &mut self,
        binding: SupervisedServiceTask,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
    ) -> Result<SupervisedConstructedServiceRetirement, ServiceError> {
        if runtime.current() != Some(binding.task) {
            return Err(ServiceError::TaskMismatch);
        }
        let plan = self.prepare_bound_current_retirement(binding, runtime.identity(), 0)?;
        let (termination, context) = runtime
            .terminate_current_with_context()
            .map_err(ServiceError::Runtime)?;
        let cleanup = ServiceCleanupTicket {
            service: plan.service,
            task: plan.task,
            context,
        };
        self.commit_current_retirement(plan, ServiceState::Exited, cleanup);
        Ok(SupervisedConstructedServiceRetirement {
            binding,
            termination,
            cleanup,
        })
    }

    /// Removes the exact current constructed service from scheduler execution
    /// while retaining its domain and authority for device-specific quiescence.
    /// No successor can dispatch until the freeze is retired.
    pub fn freeze_current_native_device_service<
        const N: usize,
        const TASKS: usize,
        const CAPS: usize,
    >(
        &self,
        binding: SupervisedServiceTask,
        task: NativeDeviceServiceTask<N>,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
    ) -> Result<SupervisedNativeDeviceServiceFreeze<N>, SupervisedNativeDeviceServiceRetirementError>
    {
        if task.task() != binding.task {
            return Err(SupervisedNativeDeviceServiceRetirementError::Service(
                ServiceError::TaskMismatch,
            ));
        }
        self.bound_running_slot(binding, runtime.identity())
            .map_err(SupervisedNativeDeviceServiceRetirementError::Service)?;
        validate_current_native_device_service_retirement_state(task, runtime)
            .map_err(SupervisedNativeDeviceServiceRetirementError::Native)?;
        let frozen = runtime
            .freeze_current_for_device_quiescence(task.task())
            .map_err(NativeDeviceServiceRetirementError::Runtime)
            .map_err(SupervisedNativeDeviceServiceRetirementError::Native)?;
        Ok(SupervisedNativeDeviceServiceFreeze {
            binding,
            native: task,
            frozen,
        })
    }

    /// Retires an exact execution freeze after device/DMA quiescence.
    ///
    /// # Safety
    ///
    /// The caller must prove that the device represented by `frozen` has
    /// stopped accepting work, completed or failed closed every in-flight
    /// command, and revoked device/DMA access. The returned retirement owner
    /// must be retained and must not be dispatched until every service mapping
    /// has been withdrawn and the exact supervisor cleanup ticket has completed.
    /// On error the returned frozen owner must remain frozen and be retried or
    /// fail-stopped.
    pub unsafe fn retire_frozen_native_device_service<
        const N: usize,
        const TASKS: usize,
        const CAPS: usize,
    >(
        &mut self,
        frozen: SupervisedNativeDeviceServiceFreeze<N>,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
    ) -> Result<
        SupervisedNativeDeviceServiceRetirement<N>,
        SupervisedNativeDeviceServiceFrozenRetirementError<N>,
    > {
        // SAFETY: this wrapper preserves the caller's device-quiescence proof.
        unsafe { self.retire_frozen_native_device_service_at(frozen, runtime, 0) }
    }

    /// Timed variant of [`Self::retire_frozen_native_device_service`].
    ///
    /// # Safety
    ///
    /// The same device-quiescence, mapping-withdrawal, exact-cleanup,
    /// delayed-dispatch, and fail-stop obligations apply.
    pub unsafe fn retire_frozen_native_device_service_at<
        const N: usize,
        const TASKS: usize,
        const CAPS: usize,
    >(
        &mut self,
        frozen: SupervisedNativeDeviceServiceFreeze<N>,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        now: u64,
    ) -> Result<
        SupervisedNativeDeviceServiceRetirement<N>,
        SupervisedNativeDeviceServiceFrozenRetirementError<N>,
    > {
        let result = (|| {
            let plan = self
                .prepare_bound_current_retirement(frozen.binding, runtime.identity(), now)
                .map_err(SupervisedNativeDeviceServiceRetirementError::Service)?;
            let context = validate_native_device_service_retirement_state(frozen.native, runtime)
                .map_err(SupervisedNativeDeviceServiceRetirementError::Native)?;
            let (termination, retired_context) = runtime
                .terminate_frozen_with_context(&frozen.frozen)
                .map_err(NativeDeviceServiceRetirementError::Runtime)
                .map_err(SupervisedNativeDeviceServiceRetirementError::Native)?;
            debug_assert_eq!(context, retired_context);
            let cleanup = ServiceCleanupTicket {
                service: plan.service,
                task: plan.task,
                context: retired_context,
            };
            self.commit_current_retirement(plan, ServiceState::Exited, cleanup);
            Ok(SupervisedNativeDeviceServiceRetirement {
                binding: frozen.binding,
                termination,
                native: NativeDeviceServiceRetirement::from_task_and_context(
                    frozen.native,
                    retired_context,
                ),
                cleanup,
            })
        })();
        result.map_err(|error| SupervisedNativeDeviceServiceFrozenRetirementError {
            error,
            frozen,
        })
    }

    /// Retires one exact supervised native device service while withholding
    /// successor dispatch for device-specific DMA and mapping cleanup.
    ///
    /// # Safety
    ///
    /// The caller must prove that the device represented by `task` has stopped
    /// accepting work, has completed or failed closed every in-flight command,
    /// and has revoked device/DMA access. The returned owner must not be
    /// dispatched until every service mapping has also been withdrawn.
    pub unsafe fn retire_current_native_device_service<
        const N: usize,
        const TASKS: usize,
        const CAPS: usize,
    >(
        &mut self,
        binding: SupervisedServiceTask,
        task: NativeDeviceServiceTask<N>,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
    ) -> Result<SupervisedNativeDeviceServiceRetirement<N>, SupervisedNativeDeviceServiceRetirementError>
    {
        // SAFETY: the caller supplies the same device-quiescence proof required
        // by this wrapper; exact supervisor/runtime/root checks precede mutation.
        unsafe { self.retire_current_native_device_service_at(binding, task, runtime, 0) }
    }

    /// Timed variant of [`Self::retire_current_native_device_service`].
    ///
    /// # Safety
    ///
    /// The same device-quiescence and delayed-dispatch obligations apply.
    pub unsafe fn retire_current_native_device_service_at<
        const N: usize,
        const TASKS: usize,
        const CAPS: usize,
    >(
        &mut self,
        binding: SupervisedServiceTask,
        task: NativeDeviceServiceTask<N>,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        now: u64,
    ) -> Result<SupervisedNativeDeviceServiceRetirement<N>, SupervisedNativeDeviceServiceRetirementError>
    {
        if task.task() != binding.task {
            return Err(SupervisedNativeDeviceServiceRetirementError::Service(
                ServiceError::TaskMismatch,
            ));
        }
        let plan = self
            .prepare_bound_current_retirement(binding, runtime.identity(), now)
            .map_err(SupervisedNativeDeviceServiceRetirementError::Service)?;
        // SAFETY: the caller proved device quiescence. The exact bound service,
        // runtime, current task, and native page-table root are all revalidated
        // before the runtime retirement commits.
        let (termination, native) = unsafe {
            retire_current_native_device_service_task(task, runtime)
        }
        .map_err(SupervisedNativeDeviceServiceRetirementError::Native)?;
        let cleanup = ServiceCleanupTicket {
            service: plan.service,
            task: plan.task,
            context: native.context(),
        };
        self.commit_current_retirement(plan, ServiceState::Exited, cleanup);
        Ok(SupervisedNativeDeviceServiceRetirement {
            binding,
            termination,
            native,
            cleanup,
        })
    }

    pub fn exit_current_at<const TASKS: usize, const CAPS: usize>(
        &mut self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        now: u64,
    ) -> Result<ServiceRetirement, ServiceError> {
        let current = runtime
            .current()
            .ok_or(ServiceError::Runtime(TaskRuntimeError::NoCurrentTask))?;
        let plan = self.prepare_current_retirement(current, runtime.identity(), now)?;
        let (termination, context) = runtime
            .terminate_current_with_context()
            .map_err(ServiceError::Runtime)?;
        let dispatch = runtime
            .dispatch_after_termination(termination)
            .map_err(ServiceError::Dispatch)?;
        let cleanup = ServiceCleanupTicket {
            service: plan.service,
            task: plan.task,
            context,
        };
        self.commit_current_retirement(plan, ServiceState::Exited, cleanup);
        Ok(ServiceRetirement {
            service: cleanup.service,
            task: cleanup.task,
            cleanup,
            dispatch,
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
        let plan = self.prepare_current_retirement(current, runtime.identity(), now)?;
        let retirement = runtime
            .terminate_current_fault(disposition)
            .map_err(ServiceError::Runtime)?;
        let dispatch = runtime
            .dispatch_after_fault(retirement)
            .map_err(ServiceError::Dispatch)?;
        let cleanup = ServiceCleanupTicket {
            service: plan.service,
            task: plan.task,
            context: retirement.context,
        };
        self.commit_current_retirement(plan, ServiceState::Faulted, cleanup);
        Ok(ServiceFault {
            service: cleanup.service,
            retirement,
            cleanup,
            dispatch,
        })
    }

    pub fn violate_current<const TASKS: usize, const CAPS: usize>(
        &mut self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        violation: TaskProtocolViolation,
    ) -> Result<ServiceViolation, ServiceError> {
        self.violate_current_at(runtime, violation, 0)
    }

    pub fn violate_current_at<const TASKS: usize, const CAPS: usize>(
        &mut self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        violation: TaskProtocolViolation,
        now: u64,
    ) -> Result<ServiceViolation, ServiceError> {
        let current = runtime
            .current()
            .ok_or(ServiceError::Runtime(TaskRuntimeError::NoCurrentTask))?;
        let plan = self.prepare_current_retirement(current, runtime.identity(), now)?;
        let retirement = runtime
            .terminate_current_violation(violation)
            .map_err(ServiceError::Runtime)?;
        let dispatch = runtime
            .dispatch_after_violation(retirement)
            .map_err(ServiceError::Dispatch)?;
        let cleanup = ServiceCleanupTicket {
            service: plan.service,
            task: plan.task,
            context: retirement.context,
        };
        self.commit_current_retirement(plan, ServiceState::Faulted, cleanup);
        Ok(ServiceViolation {
            service: cleanup.service,
            retirement,
            cleanup,
            dispatch,
        })
    }

    fn prepare_current_retirement(
        &self,
        task: TaskId,
        runtime: u64,
        now: u64,
    ) -> Result<CurrentServiceRetirementPlan, ServiceError> {
        let slot = self.running_task_slot(task, runtime)?;
        if self.slots[slot].launch_class == ServiceLaunchClass::Constructed {
            return Err(ServiceError::ConstructedLifecycleRequired);
        }
        Ok(CurrentServiceRetirementPlan {
            slot,
            service: self.id(slot),
            task,
            next_restart_tick: self.restart_deadline(slot, now)?,
        })
    }

    fn prepare_bound_current_retirement(
        &self,
        binding: SupervisedServiceTask,
        runtime: u64,
        now: u64,
    ) -> Result<CurrentServiceRetirementPlan, ServiceError> {
        let slot = self.bound_running_slot(binding, runtime)?;
        Ok(CurrentServiceRetirementPlan {
            slot,
            service: binding.service,
            task: binding.task,
            next_restart_tick: self.restart_deadline(slot, now)?,
        })
    }

    fn bound_running_slot(
        &self,
        binding: SupervisedServiceTask,
        runtime: u64,
    ) -> Result<usize, ServiceError> {
        if self.identity != Some(binding.supervisor) {
            return Err(ServiceError::InvalidService);
        }
        let entry = self.slot(binding.service)?;
        if entry.launch_class != ServiceLaunchClass::Constructed
            || entry.state != ServiceState::Running
            || entry.task != Some(binding.task)
            || entry.runtime != Some(runtime)
        {
            return Err(ServiceError::TaskMismatch);
        }
        Ok(binding.service.slot as usize)
    }

    fn commit_current_retirement(
        &mut self,
        plan: CurrentServiceRetirementPlan,
        state: ServiceState,
        cleanup: ServiceCleanupTicket,
    ) {
        let entry = &mut self.slots[plan.slot];
        entry.task = None;
        entry.runtime = None;
        entry.state = state;
        entry.cleanup = Some(cleanup);
        entry.next_restart_tick = plan.next_restart_tick;
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
        if entry.launch_class == ServiceLaunchClass::Constructed {
            return Err(ServiceCleanupError::Service(
                ServiceError::ConstructedLifecycleRequired,
            ));
        }
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

    /// Erases one exact constructed-service address space while preserving the
    /// retained retirement on every validation or backend failure.
    pub fn complete_constructed_service_cleanup<E: ServiceAddressSpaceEraser>(
        &mut self,
        retirement: SupervisedConstructedServiceRetirement,
        eraser: &mut E,
    ) -> Result<CleanedSupervisedConstructedService, SupervisedConstructedServiceCleanupFailure<E::Error>>
    {
        let result = (|| {
            if self.identity != Some(retirement.binding.supervisor) {
                return Err(ServiceCleanupError::Service(ServiceError::InvalidService));
            }
            let ticket = retirement.cleanup;
            let slot = ticket.service.slot as usize;
            let entry = self
                .slot(ticket.service)
                .map_err(ServiceCleanupError::Service)?;
            if entry.launch_class != ServiceLaunchClass::Constructed
                || retirement.binding.service != ticket.service
                || retirement.binding.task != ticket.task
                || entry.cleanup != Some(ticket)
            {
                return Err(ServiceCleanupError::Service(
                    ServiceError::InvalidCleanupTicket,
                ));
            }
            eraser
                .erase(ticket.task, ticket.context)
                .map_err(ServiceCleanupError::Eraser)?;
            self.slots[slot].cleanup = None;
            Ok(CleanedSupervisedConstructedService {
                binding: retirement.binding,
                termination: retirement.termination,
            })
        })();
        result.map_err(|error| SupervisedConstructedServiceCleanupFailure {
            error,
            retirement,
        })
    }

    /// Completes cleanup only for the exact supervisor-bound constructed
    /// service retirement. A copied generic ticket cannot cross supervisor
    /// identity.
    ///
    /// # Safety
    ///
    /// The caller must prove that device/DMA authority and every service CPU
    /// mapping have been withdrawn before address-space erasure is attempted,
    /// and that an `Ok` result from `eraser` means the exact retired address
    /// space can no longer be entered or addressed. The caller must retain the
    /// retirement owner and withhold dispatch until this method succeeds.
    pub unsafe fn complete_supervised_native_device_service_cleanup<
        E: ServiceAddressSpaceEraser,
        const N: usize,
    >(
        &mut self,
        retirement: &SupervisedNativeDeviceServiceRetirement<N>,
        eraser: &mut E,
    ) -> Result<(), ServiceCleanupError<E::Error>> {
        if self.identity != Some(retirement.binding.supervisor) {
            return Err(ServiceCleanupError::Service(ServiceError::InvalidService));
        }
        let ticket = retirement.cleanup;
        let slot = ticket.service.slot as usize;
        let entry = self
            .slot(ticket.service)
            .map_err(ServiceCleanupError::Service)?;
        if entry.launch_class != ServiceLaunchClass::Constructed
            || retirement.binding.service != ticket.service
            || retirement.binding.task != ticket.task
            || entry.cleanup != Some(ticket)
        {
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
        let plan = self
            .prepare_restart_at(
                fault.service,
                management,
                control,
                priority,
                fresh_context,
                now,
            )
            .map_err(|error| ServiceRecoveryError::Restart {
                service: fault.service,
                error,
            })?;
        let replacement = self
            .commit_restart_with_task(plan, management, runtime)
            .map_err(|error| ServiceRecoveryError::Restart {
                service: fault.service,
                error,
            })?;
        Ok(ServiceRecovery {
            retired: fault.service,
            replacement: replacement.service(),
            task: replacement.task(),
            dispatch: fault.dispatch,
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
        let plan =
            self.prepare_restart_at(service, management, control, priority, fresh_context, now)?;
        self.commit_restart(plan, management, runtime)
    }

    /// Authorizes and snapshots a restart without mutating lifecycle state.
    /// The returned plan can cross a trusted host-reprovisioning boundary; the
    /// commit path revalidates every lifecycle and generation condition.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_restart_at<const MANAGEMENT_CAPS: usize>(
        &self,
        service: ServiceId,
        management: &CapabilitySpace<MANAGEMENT_CAPS>,
        control: Capability,
        priority: Priority,
        fresh_context: UserContext,
        now: u64,
    ) -> Result<ServiceRestartPlan, ServiceError> {
        let entry = self.slot(service)?;
        if entry.launch_class == ServiceLaunchClass::Constructed {
            return Err(ServiceError::ConstructedLifecycleRequired);
        }
        if entry.state == ServiceState::Running || entry.task.is_some() {
            return Err(ServiceError::StillRunning);
        }
        let authorized = management
            .authorize_exact(control, crate::Rights::CONTROL)
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
        Ok(ServiceRestartPlan {
            service,
            object: entry.object,
            control,
            policy_generation: entry.policy_generation,
            priority,
            context: fresh_context,
            now,
        })
    }

    /// Consumes an authorized plan only after trusted reprovisioning. Reuse,
    /// generation drift, new cleanup state, backoff drift, and policy changes
    /// all fail before a task is created or supervisor state is changed.
    pub fn commit_restart<const TASKS: usize, const CAPS: usize, const MANAGEMENT_CAPS: usize>(
        &mut self,
        plan: ServiceRestartPlan,
        management: &CapabilitySpace<MANAGEMENT_CAPS>,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
    ) -> Result<ServiceId, ServiceError> {
        self.commit_restart_with_task(plan, management, runtime)
            .map(ServiceRestartCommit::service)
    }

    pub fn commit_restart_with_task<
        const TASKS: usize,
        const CAPS: usize,
        const MANAGEMENT_CAPS: usize,
    >(
        &mut self,
        plan: ServiceRestartPlan,
        management: &CapabilitySpace<MANAGEMENT_CAPS>,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
    ) -> Result<ServiceRestartCommit, ServiceError> {
        let authorized = management
            .authorize_exact(plan.control, crate::Rights::CONTROL)
            .map_err(ServiceError::Unauthorized)?;
        if authorized != plan.object {
            return Err(ServiceError::Unauthorized(
                CapabilityError::PermissionDenied,
            ));
        }
        self.commit_restart_authorized(plan, runtime)
    }

    pub fn commit_restart_with_task_for_requester<const TASKS: usize, const CAPS: usize>(
        &mut self,
        plan: ServiceRestartPlan,
        requester: TaskId,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
    ) -> Result<ServiceRestartCommit, ServiceError> {
        runtime
            .authorize_capability_exact(
                requester,
                plan.control,
                crate::Rights::CONTROL,
                plan.object,
            )
            .map_err(ServiceError::Runtime)?;
        self.commit_restart_authorized(plan, runtime)
    }

    fn commit_restart_authorized<const TASKS: usize, const CAPS: usize>(
        &mut self,
        plan: ServiceRestartPlan,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
    ) -> Result<ServiceRestartCommit, ServiceError> {
        let service = plan.service;
        let slot = service.slot as usize;
        let entry = self.restartable_entry(service, plan.now)?;
        if entry.object != plan.object {
            return Err(ServiceError::InvalidObject);
        }
        if entry.policy_generation != plan.policy_generation {
            return Err(ServiceError::InvalidRestartPolicy);
        }
        let generation = entry
            .generation
            .checked_add(1)
            .filter(|generation| *generation != 0)
            .ok_or(ServiceError::GenerationExhausted)?;
        let task = runtime
            .create(plan.priority, plan.context)
            .map_err(ServiceError::Runtime)?;
        self.slots[slot].generation = generation;
        self.slots[slot].task = Some(task);
        self.slots[slot].runtime = Some(runtime.identity());
        self.slots[slot].state = ServiceState::Running;
        self.slots[slot].completed_restarts += 1;
        Ok(ServiceRestartCommit {
            service: ServiceId {
                slot: slot as u32,
                generation,
            },
            task,
        })
    }

    fn restartable_entry(
        &self,
        service: ServiceId,
        now: u64,
    ) -> Result<&ServiceSlot, ServiceError> {
        let entry = self.slot(service)?;
        if entry.launch_class == ServiceLaunchClass::Constructed {
            return Err(ServiceError::ConstructedLifecycleRequired);
        }
        if entry.state == ServiceState::Running || entry.task.is_some() {
            return Err(ServiceError::StillRunning);
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
        Ok(entry)
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

    fn running_task_slot(&self, task: TaskId, runtime: u64) -> Result<usize, ServiceError> {
        let mut matches = self.slots.iter().enumerate().filter_map(|(slot, entry)| {
            (entry.occupied
                && entry.state == ServiceState::Running
                && entry.task == Some(task)
                && entry.runtime == Some(runtime))
            .then_some(slot)
        });
        let slot = matches.next().ok_or(ServiceError::TaskMismatch)?;
        if matches.next().is_some() {
            return Err(ServiceError::TaskMismatch);
        }
        Ok(slot)
    }

    fn running_task_in_runtime(
        &self,
        service: ServiceId,
        runtime: u64,
    ) -> Result<TaskId, ServiceError> {
        let entry = self.slot(service)?;
        if entry.state != ServiceState::Running || entry.runtime != Some(runtime) {
            return Err(ServiceError::TaskMismatch);
        }
        entry.task.ok_or(ServiceError::TaskMismatch)
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

fn allocate_service_supervisor_identity(counter: &AtomicU64) -> Result<u64, ServiceError> {
    counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |identity| {
            identity.checked_add(1)
        })
        .map_err(|_| ServiceError::GenerationExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ControlEvent, DeviceServiceLaunchAttachment, Endpoint, IsolationPlacement,
        IsolationServiceSpec, PeerDeathReason, PhysAddr, Rights, TotalMicrovmClass,
        prepare_native_device_service_task,
    };

    fn context(root: u64, entry: u64) -> UserContext {
        UserContext::new(PhysAddr::new(root).unwrap(), entry, 0x7000_0000).unwrap()
    }

    const MEMORY_POOL_RIGHTS: Rights = Rights::ALLOCATE.union(Rights::INSPECT);

    #[test]
    fn accounted_supervisor_charges_complete_lifecycle_state_before_registration() {
        let pages = AccountedServiceSupervisor::<2>::required_pages().unwrap();
        let mut memory = MemoryPoolTable::<1, 1>::new(29).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = memory
            .create_root(pages, 1, 0, MEMORY_POOL_RIGHTS, &mut authorities)
            .unwrap();
        let mut supervisor = AccountedServiceSupervisor::<2>::new(
            pool,
            pool_capability,
            &mut memory,
            &mut authorities,
        )
        .unwrap();
        assert_eq!(supervisor.committed_pages(), pages);
        assert_eq!(memory.object_pool(supervisor.charge()), Ok(pool));
        let mut runtime = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let service = supervisor.register(ObjectId(0x90), task).unwrap();
        assert_eq!(supervisor.state(service), Ok(ServiceState::Running));
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            pages
        );
    }

    #[test]
    fn supervisor_exhaustion_does_not_publish_and_empty_release_returns_charge() {
        let large_pages = AccountedServiceSupervisor::<64>::required_pages().unwrap();
        assert!(large_pages > 1);
        let mut exhausted_memory = MemoryPoolTable::<1, 1>::new(30).unwrap();
        let mut exhausted_authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = exhausted_memory
            .create_root(
                large_pages - 1,
                1,
                0,
                MEMORY_POOL_RIGHTS,
                &mut exhausted_authorities,
            )
            .unwrap();
        assert!(matches!(
            AccountedServiceSupervisor::<64>::new(
                pool,
                pool_capability,
                &mut exhausted_memory,
                &mut exhausted_authorities,
            ),
            Err(AccountedServiceSupervisorError::Memory(
                MemoryResourceError::PoolExhausted
            ))
        ));
        assert_eq!(
            exhausted_memory
                .usage(pool, pool_capability, &exhausted_authorities)
                .unwrap()
                .committed_pages(),
            0
        );

        let pages = AccountedServiceSupervisor::<1>::required_pages().unwrap();
        let mut memory = MemoryPoolTable::<1, 1>::new(31).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = memory
            .create_root(pages, 1, 0, MEMORY_POOL_RIGHTS, &mut authorities)
            .unwrap();
        let supervisor = AccountedServiceSupervisor::<1>::new(
            pool,
            pool_capability,
            &mut memory,
            &mut authorities,
        )
        .unwrap();
        assert!(matches!(
            unsafe { supervisor.release(&mut memory, &mut authorities) },
            Ok(released) if released == pages
        ));
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            0
        );
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

    fn constructed_native_service_pair() -> (
        TaskRuntime<3, 4>,
        TaskId,
        NativeDeviceServiceTask<1>,
        NativeDeviceServiceTask<1>,
        ObjectId,
    ) {
        let object = ObjectId(0xd0);
        let spec = IsolationServiceSpec::new(
            object,
            ObjectId(0xd5),
            1,
            2,
            3,
            4,
            TotalMicrovmClass::MicrovmEligible,
            IsolationPlacement::NativeService,
        )
        .unwrap();
        let mut runtime = TaskRuntime::<3, 4>::new(1_000, 1).unwrap();
        let source = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let first_target = runtime
            .create_for_construction(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let second_target = runtime
            .create_for_construction(Priority::NORMAL, context(0x40_0000, 0x60_0000))
            .unwrap();
        let endpoint = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0xd1), Rights::SIGNAL.union(Rights::DELEGATE))
            .unwrap();
        let launch_data = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0xd2), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let authority = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0xd3), Rights::CONTROL.union(Rights::DELEGATE))
            .unwrap();
        let attachment = DeviceServiceLaunchAttachment::new(
            spec,
            5,
            ObjectId(0xd2),
            6,
            64,
            launch_data,
            [(ObjectId(0xd3), authority, Rights::CONTROL)],
            runtime.capabilities(source).unwrap(),
        )
        .unwrap();
        let prepare = |runtime: &mut TaskRuntime<3, 4>, target| {
            prepare_native_device_service_task(
                runtime,
                source,
                target,
                spec,
                attachment,
                ObjectId(0xd1),
                endpoint,
                source,
                ObjectId(0xd4),
            )
            .unwrap()
        };
        let first = prepare(&mut runtime, first_target);
        let second = prepare(&mut runtime, second_target);
        (runtime, source, first, second, object)
    }

    #[test]
    fn constructed_service_retirement_withholds_dispatch_until_exact_cleanup() {
        let (mut runtime, source, native, _, object) = constructed_native_service_pair();
        let mut supervisor = ServiceSupervisor::<1>::new();
        // SAFETY: `native` retains the complete construction owner and the
        // lifecycle object comes from that same admitted service spec.
        let binding = unsafe {
            supervisor.register_and_activate_constructed(
                object,
                native.task(),
                RestartPolicy::ONCE_IMMEDIATE,
                &mut runtime,
            )
        }
        .unwrap();
        assert!(matches!(
            runtime.start(),
            ScheduleOutcome::Switch { to, .. } if to == source
        ));
        assert!(matches!(
            runtime.yield_current().unwrap(),
            ScheduleOutcome::Switch { to, .. } if to == native.task()
        ));

        let retirement = supervisor
            .retire_current_constructed_service(binding, &mut runtime)
            .unwrap();
        assert_eq!(retirement.service(), binding.service());
        assert_eq!(retirement.task(), native.task());
        assert_eq!(supervisor.state(binding.service()), Ok(ServiceState::Exited));
        assert_eq!(
            supervisor.pending_cleanup(binding.service()),
            Ok(Some(retirement.cleanup()))
        );
        // The scheduler may select the successor internally, but the caller
        // receives no executable dispatch context until cleanup consumes the
        // retained termination below.
        assert_eq!(runtime.current(), Some(source));

        let mut rejecting = TestEraser {
            fail: true,
            erased: None,
        };
        let failure = supervisor
            .complete_constructed_service_cleanup(retirement, &mut rejecting)
            .unwrap_err();
        assert_eq!(failure.error(), &ServiceCleanupError::Eraser(()));
        assert!(supervisor
            .pending_cleanup(binding.service())
            .unwrap()
            .is_some());

        let mut eraser = TestEraser::default();
        let cleaned = supervisor
            .complete_constructed_service_cleanup(failure.into_retirement(), &mut eraser)
            .unwrap();
        assert_eq!(cleaned.service(), binding.service());
        assert_eq!(cleaned.task(), native.task());
        assert_eq!(supervisor.pending_cleanup(binding.service()), Ok(None));
        assert_eq!(eraser.erased.map(|(task, _)| task), Some(native.task()));
        let dispatch = cleaned.dispatch(&mut runtime).unwrap();
        assert_eq!(dispatch.user().map(|(task, _)| task), Some(source));
    }

    #[test]
    fn supervised_native_lifecycle_rejects_binding_runtime_and_cleanup_collisions() {
        let (mut runtime, source, native, mismatched, object) =
            constructed_native_service_pair();
        let mut supervisor = ServiceSupervisor::<1>::new();
        // SAFETY: `native` is the fully constructed task owner for this exact
        // runtime and `object` is derived from the same admitted service spec.
        let binding = unsafe {
            supervisor.register_and_activate_constructed(
                object,
                native.task(),
                RestartPolicy::ONCE_IMMEDIATE,
                &mut runtime,
            )
        }
        .unwrap();
        let service = binding.service();
        assert!(matches!(
            runtime.start(),
            ScheduleOutcome::Switch { to, .. } if to == source
        ));
        assert!(matches!(
            runtime.yield_current().unwrap(),
            ScheduleOutcome::Switch { to, .. } if to == native.task()
        ));

        // SAFETY: neither constructed task has any attached device, DMA, or
        // mapping state, so the direct API's quiescence precondition is
        // vacuously satisfied. The mismatched pair must still be rejected.
        assert!(matches!(
            unsafe {
                supervisor.retire_current_native_device_service(
                    binding,
                    mismatched,
                    &mut runtime,
                )
            },
            Err(SupervisedNativeDeviceServiceRetirementError::Service(
                ServiceError::TaskMismatch,
            ))
        ));
        assert_eq!(runtime.current(), Some(native.task()));
        assert_eq!(supervisor.state(service), Ok(ServiceState::Running));
        assert_eq!(supervisor.pending_cleanup(service), Ok(None));

        let frozen = supervisor
            .freeze_current_native_device_service(binding, native, &mut runtime)
            .unwrap();
        // SAFETY: the fixture has no attached device, DMA, or mapping state;
        // cleanup and dispatch remain withheld by the retained owner below.
        let retirement = unsafe {
            supervisor.retire_frozen_native_device_service(frozen, &mut runtime)
        }
        .unwrap_or_else(|_| panic!("exact frozen fixture must retire"));
        let cleanup = supervisor
            .pending_cleanup(service)
            .unwrap()
            .expect("constructed retirement must retain cleanup");

        let (mut other_runtime, other_source, other_native, _, other_object) =
            constructed_native_service_pair();
        assert_eq!(object, other_object);
        assert_eq!(native.task(), other_native.task());
        let mut other_supervisor = ServiceSupervisor::<1>::new();
        // SAFETY: the second fixture independently proves the same complete
        // construction contract for its distinct runtime.
        let other_binding = unsafe {
            other_supervisor.register_and_activate_constructed(
                other_object,
                other_native.task(),
                RestartPolicy::ONCE_IMMEDIATE,
                &mut other_runtime,
            )
        }
        .unwrap();
        let other_service = other_binding.service();
        assert_eq!(service, other_service);
        assert!(matches!(
            other_runtime.start(),
            ScheduleOutcome::Switch { to, .. } if to == other_source
        ));
        assert!(matches!(
            other_runtime.yield_current().unwrap(),
            ScheduleOutcome::Switch { to, .. } if to == other_native.task()
        ));
        let other_frozen = other_supervisor
            .freeze_current_native_device_service(
                other_binding,
                other_native,
                &mut other_runtime,
            )
            .unwrap();
        // SAFETY: the second fixture has the same vacuous device/DMA/mapping
        // quiescence proof and its retirement remains retained below.
        let other_retirement = unsafe {
            other_supervisor
                .retire_frozen_native_device_service(other_frozen, &mut other_runtime)
        }
        .unwrap_or_else(|_| panic!("second exact frozen fixture must retire"));
        let other_cleanup = other_supervisor
            .pending_cleanup(other_service)
            .unwrap()
            .expect("second supervisor must retain cleanup");
        assert_eq!(cleanup, other_cleanup);

        let mut generic_eraser = TestEraser::default();
        assert_eq!(
            supervisor.complete_cleanup(cleanup, &mut generic_eraser),
            Err(ServiceCleanupError::Service(
                ServiceError::ConstructedLifecycleRequired,
            ))
        );
        assert_eq!(generic_eraser.erased, None);

        let mut wrong_eraser = TestEraser::default();
        // SAFETY: both fixtures have no device or mapping state, and the model
        // eraser is the authoritative exact-erasure boundary for this test.
        assert_eq!(
            unsafe {
                other_supervisor.complete_supervised_native_device_service_cleanup(
                    &retirement,
                    &mut wrong_eraser,
                )
            },
            Err(ServiceCleanupError::Service(ServiceError::InvalidService))
        );
        assert_eq!(wrong_eraser.erased, None);
        assert_eq!(supervisor.pending_cleanup(service), Ok(Some(cleanup)));
        assert_eq!(
            other_supervisor.pending_cleanup(other_service),
            Ok(Some(other_cleanup))
        );

        let mut eraser = TestEraser::default();
        // SAFETY: the fixture has no device or mapping state and this model
        // eraser truthfully retires the exact removed task context.
        unsafe {
            supervisor.complete_supervised_native_device_service_cleanup(
                &retirement,
                &mut eraser,
            )
        }
        .unwrap();
        assert_eq!(eraser.erased, Some((native.task(), cleanup.context())));
        let mut management = CapabilitySpace::<1>::new();
        let control = management.insert(object, Rights::CONTROL).unwrap();
        assert!(matches!(
            supervisor.prepare_restart_at(
                service,
                &management,
                control,
                Priority::NORMAL,
                cleanup.context(),
                0,
            ),
            Err(ServiceError::ConstructedLifecycleRequired)
        ));

        let retirement = match retirement.dispatch(&mut other_runtime) {
            Ok(_) => panic!("another runtime must not consume the retirement"),
            Err(error) => {
                assert_eq!(
                    error.error(),
                    TaskTerminationDispatchError::RetirementRuntimeMismatch
                );
                error.into_retirement()
            }
        };

        let mut other_eraser = TestEraser::default();
        // SAFETY: the second fixture has no device or mapping state and this
        // model eraser truthfully retires its exact removed task context.
        unsafe {
            other_supervisor.complete_supervised_native_device_service_cleanup(
                &other_retirement,
                &mut other_eraser,
            )
        }
        .unwrap();
        let other_dispatch = other_retirement
            .dispatch(&mut other_runtime)
            .unwrap_or_else(|_| panic!("second runtime must consume its own retirement"));
        assert_eq!(
            other_dispatch.dispatch().user().map(|(task, _)| task),
            Some(other_source)
        );
        let dispatch = retirement
            .dispatch(&mut runtime)
            .unwrap_or_else(|_| panic!("originating runtime must consume retirement"));
        assert_eq!(
            dispatch.dispatch().user().map(|(task, _)| task),
            Some(source)
        );
    }

    #[test]
    fn atomic_launch_preflights_slot_before_creating_task() {
        let mut unavailable_runtime = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let mut unavailable = ServiceSupervisor::<0>::new();
        assert!(matches!(
            unavailable.launch(
                ObjectId(0x51),
                &mut unavailable_runtime,
                Priority::NORMAL,
                context(0x20_0000, 0x40_0000),
            ),
            Err(ServiceError::Full)
        ));
        assert_eq!(unavailable_runtime.current(), None);

        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let mut supervisor = ServiceSupervisor::<2>::new();
        let (service, task) = supervisor
            .launch(
                ObjectId(0x51),
                &mut runtime,
                Priority::NORMAL,
                context(0x20_0000, 0x40_0000),
            )
            .unwrap();
        assert_eq!(supervisor.task(service), Ok(Some(task)));
        assert_eq!(supervisor.state(service), Ok(ServiceState::Running));
        assert!(matches!(
            supervisor.launch(
                ObjectId(0x51),
                &mut runtime,
                Priority::NORMAL,
                context(0x30_0000, 0x50_0000),
            ),
            Err(ServiceError::ObjectAlreadyRegistered)
        ));
        assert_eq!(runtime.load().occupied(), 1);
        let _ = runtime.start();
        assert_eq!(runtime.current(), Some(task));
    }

    #[test]
    fn runtime_registration_distinguishes_equal_task_tokens_by_runtime() {
        let mut first_runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let first_task = first_runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let mut second_runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let second_task = second_runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        assert_eq!(first_task, second_task);

        let mut supervisor = ServiceSupervisor::<3>::new();
        let first = supervisor
            .register_in_runtime(ObjectId(0x53), first_task, &first_runtime)
            .unwrap();
        let second = supervisor
            .register_in_runtime(ObjectId(0x54), second_task, &second_runtime)
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(supervisor.task(first), Ok(Some(first_task)));
        assert_eq!(supervisor.task(second), Ok(Some(second_task)));
        assert_eq!(supervisor.state(first), Ok(ServiceState::Running));
        assert_eq!(supervisor.state(second), Ok(ServiceState::Running));

        assert_eq!(
            supervisor.register_in_runtime(ObjectId(0x55), first_task, &first_runtime),
            Err(ServiceError::TaskAlreadyRegistered)
        );
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
        let old = supervisor.register_in_runtime(object, task, &runtime).unwrap();
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
        let service = supervisor
            .register_in_runtime(ObjectId(7), task, &runtime)
            .unwrap();
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
    fn protocol_violating_service_becomes_faulted_with_exact_cleanup() {
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task_context = context(0x20_0000, 0x40_0000);
        let task = runtime.create(Priority::NORMAL, task_context).unwrap();
        runtime.start();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let service = supervisor
            .register_in_runtime(ObjectId(8), task, &runtime)
            .unwrap();

        let violation = supervisor
            .violate_current(
                &mut runtime,
                TaskProtocolViolation::InvalidUserReturn(crate::UserReturnError::InvalidStack),
            )
            .unwrap();

        assert_eq!(violation.service, service);
        assert_eq!(violation.retirement.task, task);
        assert_eq!(violation.retirement.context, task_context);
        assert_eq!(
            violation.retirement.violation,
            TaskProtocolViolation::InvalidUserReturn(crate::UserReturnError::InvalidStack)
        );
        assert!(violation.dispatch.is_idle());
        assert_eq!(supervisor.state(service), Ok(ServiceState::Faulted));
        assert_eq!(
            supervisor.pending_cleanup(service),
            Ok(Some(violation.cleanup))
        );
        complete(&mut supervisor, violation.cleanup);
        assert_eq!(supervisor.pending_cleanup(service), Ok(None));
    }

    #[test]
    fn registration_plan_rechecks_exact_vacant_slot_before_commit() {
        let object = ObjectId(0x60);
        let policy = RestartPolicy::new(2, 5, 20).unwrap();
        let task = TaskId::from_token((7u64 << 32) | 1);
        let competing_task = TaskId::from_token((7u64 << 32) | 2);
        let mut supervisor = ServiceSupervisor::<1>::new();
        assert_eq!(
            supervisor.plan_registration(ObjectId(0), task, policy),
            Err(ServiceError::InvalidObject)
        );
        let stale = supervisor.plan_registration(object, task, policy).unwrap();
        assert_eq!((stale.object(), stale.task()), (object, task));
        supervisor.register(ObjectId(0x61), competing_task).unwrap();
        assert_eq!(
            supervisor.commit_registration(stale),
            Err(ServiceError::InvalidService)
        );

        let mut supervisor = ServiceSupervisor::<1>::new();
        let plan = supervisor.plan_registration(object, task, policy).unwrap();
        let service = supervisor.commit_registration(plan).unwrap();
        assert_eq!(supervisor.task(service), Ok(Some(task)));
        assert_eq!(supervisor.state(service), Ok(ServiceState::Running));
        assert_eq!(
            supervisor.plan_registration(ObjectId(0x62), task, policy),
            Err(ServiceError::Full)
        );
    }

    #[test]
    fn runtime_registration_commit_rejects_retired_task_generation() {
        let object = ObjectId(0x62);
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let plan = supervisor
            .plan_registration(object, task, RestartPolicy::ONCE_IMMEDIATE)
            .unwrap();
        runtime.detach_domain(task).unwrap();

        assert!(matches!(
            supervisor.commit_registration_with_runtime(plan, &runtime),
            Err(ServiceError::Runtime(_))
        ));
        assert!(!supervisor.slots[0].occupied);

        let replacement = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        assert_ne!(replacement, task);
        let plan = supervisor
            .plan_registration(object, replacement, RestartPolicy::ONCE_IMMEDIATE)
            .unwrap();
        let service = supervisor
            .commit_registration_with_runtime(plan, &runtime)
            .unwrap();
        assert_eq!(supervisor.task(service), Ok(Some(replacement)));
    }

    #[test]
    fn runtime_registration_rejects_construction_pending_task_before_publication() {
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime
            .create_for_construction(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let plan = supervisor
            .plan_registration(ObjectId(0x65), task, RestartPolicy::ONCE_IMMEDIATE)
            .unwrap();

        assert_eq!(
            supervisor.commit_registration_with_runtime(plan, &runtime),
            Err(ServiceError::Runtime(
                TaskRuntimeError::ConstructionPending
            ))
        );
        assert!(!supervisor.slots[0].occupied);
        assert_eq!(runtime.construction_pending(task), Ok(true));
        assert_eq!(runtime.load().runnable(), 0);
    }

    #[test]
    fn constructed_activation_publishes_running_service_before_one_wake() {
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime
            .create_for_construction(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let mut supervisor = ServiceSupervisor::<2>::new();
        let before = runtime.load();

        assert_eq!(
            unsafe {
                supervisor.register_and_activate_constructed(
                    ObjectId(0),
                    task,
                    RestartPolicy::ONCE_IMMEDIATE,
                    &mut runtime,
                )
            },
            Err(ServiceError::InvalidObject)
        );
        assert_eq!(runtime.construction_pending(task), Ok(true));
        assert_eq!(runtime.load(), before);
        assert!(!supervisor.slots[0].occupied);

        let binding = unsafe {
            supervisor
                .register_and_activate_constructed(
                    ObjectId(0x66),
                    task,
                    RestartPolicy::ONCE_IMMEDIATE,
                    &mut runtime,
                )
                .unwrap()
        };
        let service = binding.service();
        assert_eq!(binding.task(), task);
        assert_eq!(supervisor.task(service), Ok(Some(task)));
        assert_eq!(supervisor.state(service), Ok(ServiceState::Running));
        assert_eq!(runtime.construction_pending(task), Ok(false));
        assert_eq!(runtime.load().runnable(), before.runnable() + 1);
        assert_eq!(
            runtime.start(),
            ScheduleOutcome::Switch {
                from: None,
                to: task,
            }
        );

        let runnable = runtime.load();
        assert_eq!(
            unsafe {
                supervisor.register_and_activate_constructed(
                    ObjectId(0x66),
                    task,
                    RestartPolicy::ONCE_IMMEDIATE,
                    &mut runtime,
                )
            },
            Err(ServiceError::TaskAlreadyRegistered)
        );
        assert_eq!(runtime.load(), runnable);
        assert!(!supervisor.slots[1].occupied);
    }

    #[test]
    fn supervisor_identity_allocation_exhausts_without_wrapping() {
        let counter = AtomicU64::new(u64::MAX - 1);
        assert_eq!(
            allocate_service_supervisor_identity(&counter),
            Ok(u64::MAX - 1)
        );
        assert_eq!(
            allocate_service_supervisor_identity(&counter),
            Err(ServiceError::GenerationExhausted)
        );
    }

    #[test]
    fn constructed_activation_denials_leave_both_owners_unchanged() {
        let mut runtime = TaskRuntime::<2, 0>::new(1_000, 1).unwrap();
        let source = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let target = runtime
            .create_for_construction(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let before = runtime.load();
        let mut full = ServiceSupervisor::<1>::new();
        let existing = full.register(ObjectId(0x67), source).unwrap();

        assert_eq!(
            unsafe {
                full.register_and_activate_constructed(
                    ObjectId(0x68),
                    target,
                    RestartPolicy::ONCE_IMMEDIATE,
                    &mut runtime,
                )
            },
            Err(ServiceError::Full)
        );
        assert_eq!(full.task(existing), Ok(Some(source)));
        assert_eq!(runtime.construction_pending(target), Ok(true));
        assert_eq!(runtime.load(), before);

        let mut supervisor = ServiceSupervisor::<1>::new();
        let ordinary_before = runtime.load();
        assert_eq!(
            unsafe {
                supervisor.register_and_activate_constructed(
                    ObjectId(0x68),
                    source,
                    RestartPolicy::ONCE_IMMEDIATE,
                    &mut runtime,
                )
            },
            Err(ServiceError::Runtime(
                TaskRuntimeError::NotConstructionTarget
            ))
        );
        assert!(!supervisor.slots[0].occupied);
        assert_eq!(runtime.load(), ordinary_before);
        assert_eq!(runtime.construction_pending(target), Ok(true));
    }

    #[test]
    fn supervised_task_rejects_lifecycle_exit_from_same_token_runtime() {
        let mut owner = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let owner_task = owner
            .create_for_construction(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let mut other = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let other_task = other
            .create_for_construction(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        assert_eq!(owner_task, other_task);
        let mut supervisor = ServiceSupervisor::<1>::new();
        let binding = unsafe {
            supervisor
                .register_and_activate_constructed(
                    ObjectId(0x6a),
                    owner_task,
                    RestartPolicy::ONCE_IMMEDIATE,
                    &mut owner,
                )
                .unwrap()
        };
        let service = binding.service();
        let other_activation = other
            .prepare_constructed_task_activation(other_task)
            .unwrap();
        other_activation.commit();
        assert!(matches!(
            other.start(),
            ScheduleOutcome::Switch { to, .. } if to == other_task
        ));
        let other_before = other.load();

        assert_eq!(
            supervisor.exit_current(&mut other),
            Err(ServiceError::TaskMismatch)
        );
        assert_eq!(other.current(), Some(other_task));
        assert_eq!(other.load(), other_before);
        assert_eq!(supervisor.state(service), Ok(ServiceState::Running));

        assert!(matches!(
            owner.start(),
            ScheduleOutcome::Switch { to, .. } if to == owner_task
        ));
        assert_eq!(
            supervisor.exit_current(&mut owner),
            Err(ServiceError::ConstructedLifecycleRequired)
        );
        assert_eq!(owner.current(), Some(owner_task));
        assert_eq!(supervisor.state(service), Ok(ServiceState::Running));
    }

    #[test]
    fn runtime_bound_deadline_cancellation_rejects_same_token_runtime() {
        let object = ObjectId(0x6b);
        let mut owner = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let owner_task = owner
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let service = supervisor
            .register_in_runtime(object, owner_task, &owner)
            .unwrap();

        let mut other = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let other_task = other
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        assert_eq!(owner_task, other_task);
        assert!(matches!(other.start(), ScheduleOutcome::Switch { .. }));
        let mut executor = DeadlineReceiveSyscallExecutor::new();
        let cancellation = match executor
            .start(&mut other, crate::ReceiveTimeout::new(3).unwrap())
            .unwrap()
        {
            crate::DeadlineReceiveStart::Blocked { cancellation, .. } => cancellation,
            _ => panic!("expected suspended receive"),
        };
        let mut management = CapabilitySpace::<1>::new();
        let control = management.insert(object, Rights::CONTROL).unwrap();

        assert_eq!(
            supervisor.cancel_deadline_receive(
                service,
                &management,
                control,
                &mut other,
                &mut executor,
                cancellation,
            ),
            Err(ServiceDeadlineCancellationError::Service(
                ServiceError::TaskMismatch
            ))
        );
        assert!(executor.has_pending(other_task).unwrap());
        assert_eq!(supervisor.task(service), Ok(Some(owner_task)));
    }

    #[test]
    fn pending_retirement_blocks_constructed_activation_before_registration() {
        let mut runtime = TaskRuntime::<2, 0>::new(1_000, 1).unwrap();
        let source = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let target = runtime
            .create_for_construction(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        assert!(matches!(
            runtime.start(),
            ScheduleOutcome::Switch { to, .. } if to == source
        ));
        runtime.terminate_current().unwrap();
        let before = runtime.load();
        let mut supervisor = ServiceSupervisor::<1>::new();

        assert_eq!(
            unsafe {
                supervisor.register_and_activate_constructed(
                    ObjectId(0x69),
                    target,
                    RestartPolicy::ONCE_IMMEDIATE,
                    &mut runtime,
                )
            },
            Err(ServiceError::Runtime(
                TaskRuntimeError::RetirementDispatchPending
            ))
        );
        assert!(!supervisor.slots[0].occupied);
        assert_eq!(runtime.construction_pending(target), Ok(true));
        assert_eq!(runtime.load(), before);
    }

    #[test]
    fn registration_rejects_duplicate_task_and_object_before_publication() {
        let task = TaskId::from_token((9u64 << 32) | 1);
        let unrelated = TaskId::from_token((9u64 << 32) | 2);
        let policy = RestartPolicy::ONCE_IMMEDIATE;
        let mut supervisor = ServiceSupervisor::<2>::new();
        supervisor.register(ObjectId(0x63), unrelated).unwrap();
        assert_eq!(
            supervisor.plan_registration(ObjectId(0x63), task, policy),
            Err(ServiceError::ObjectAlreadyRegistered)
        );
        let plan = supervisor
            .plan_registration(ObjectId(0x64), task, policy)
            .unwrap();
        supervisor.slots[0].object = ObjectId(0x64);

        assert_eq!(
            supervisor.commit_registration(plan),
            Err(ServiceError::ObjectAlreadyRegistered)
        );
        assert!(!supervisor.slots[1].occupied);
        supervisor.slots[0].object = ObjectId(0x63);
        let plan = supervisor
            .plan_registration(ObjectId(0x64), task, policy)
            .unwrap();
        supervisor.slots[0].task = Some(task);

        assert_eq!(
            supervisor.commit_registration(plan),
            Err(ServiceError::TaskAlreadyRegistered)
        );
        assert!(!supervisor.slots[1].occupied);
        assert_eq!(
            supervisor.plan_registration(ObjectId(0x64), task, policy),
            Err(ServiceError::TaskAlreadyRegistered)
        );
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
            .register_with_policy_in_runtime(object, task, policy, &runtime)
            .unwrap();
        let retirement = supervisor.exit_current_at(&mut runtime, 100).unwrap();
        runtime
            .consume_idle_dispatch(retirement.dispatch)
            .expect("single-service exit must select idle");
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
        runtime
            .consume_idle_dispatch(fault.dispatch)
            .expect("single-service fault must select idle");
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
    fn prepared_restart_revalidates_after_reprovisioning_boundary() {
        let object = ObjectId(0x81);
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        runtime.start();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let service = supervisor.register_in_runtime(object, task, &runtime).unwrap();
        let retirement = supervisor.exit_current(&mut runtime).unwrap();
        complete(&mut supervisor, retirement.cleanup);
        let mut management = CapabilitySpace::<2>::new();
        let control = management.insert(object, Rights::CONTROL).unwrap();
        let overbroad = management
            .insert(object, Rights::CONTROL.union(Rights::READ))
            .unwrap();
        let fresh = context(0x30_0000, 0x50_0000);
        assert_eq!(
            supervisor.prepare_restart_at(
                service,
                &management,
                overbroad,
                Priority::RESPONSIVE,
                fresh,
                0,
            ),
            Err(ServiceError::Unauthorized(
                CapabilityError::PermissionDenied
            ))
        );
        let plan = supervisor
            .prepare_restart_at(
                service,
                &management,
                control,
                Priority::RESPONSIVE,
                fresh,
                0,
            )
            .unwrap();
        assert_eq!(plan.service(), service);
        assert_eq!(plan.object(), object);

        management.revoke(control).unwrap();
        assert_eq!(
            supervisor.commit_restart(plan, &management, &mut runtime),
            Err(ServiceError::Unauthorized(CapabilityError::Invalid))
        );
        assert_eq!(supervisor.state(service), Ok(ServiceState::Exited));
        assert!(runtime.current().is_none());
        let replacement_control = management.insert(object, Rights::CONTROL).unwrap();
        let plan = supervisor
            .prepare_restart_at(
                service,
                &management,
                replacement_control,
                Priority::RESPONSIVE,
                fresh,
                0,
            )
            .unwrap();

        let replacement = supervisor
            .commit_restart_with_task(plan, &management, &mut runtime)
            .unwrap();
        assert_ne!(replacement.service(), service);
        assert_eq!(runtime.context(replacement.task()), Ok(&fresh));
        assert_eq!(
            supervisor.task(replacement.service()),
            Ok(Some(replacement.task()))
        );
        assert_eq!(
            supervisor.prepare_restart_at(
                service,
                &management,
                replacement_control,
                Priority::RESPONSIVE,
                fresh,
                0,
            ),
            Err(ServiceError::InvalidService)
        );
    }

    #[test]
    fn prepared_restart_does_not_bypass_cleanup_or_object_binding() {
        let object = ObjectId(0x82);
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        runtime.start();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let service = supervisor.register_in_runtime(object, task, &runtime).unwrap();
        let retirement = supervisor.exit_current(&mut runtime).unwrap();
        let mut management = CapabilitySpace::<1>::new();
        let control = management.insert(object, Rights::CONTROL).unwrap();
        assert_eq!(
            supervisor.prepare_restart_at(
                service,
                &management,
                control,
                Priority::NORMAL,
                context(0x30_0000, 0x50_0000),
                0,
            ),
            Err(ServiceError::CleanupRequired)
        );
        complete(&mut supervisor, retirement.cleanup);
        let mut plan = supervisor
            .prepare_restart_at(
                service,
                &management,
                control,
                Priority::NORMAL,
                context(0x30_0000, 0x50_0000),
                0,
            )
            .unwrap();
        plan.object = ObjectId(0x83);
        management.revoke(control).unwrap();
        plan.control = management.insert(ObjectId(0x83), Rights::CONTROL).unwrap();
        assert_eq!(
            supervisor.commit_restart(plan, &management, &mut runtime),
            Err(ServiceError::InvalidObject)
        );
        assert_eq!(supervisor.state(service), Ok(ServiceState::Exited));
        assert!(runtime.current().is_none());
    }

    #[test]
    fn task_local_restart_commit_revalidates_live_requester_control() {
        let object = ObjectId(0x8a);
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let service_task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let requester = runtime
            .create(Priority::BACKGROUND, context(0x30_0000, 0x50_0000))
            .unwrap();
        let control = runtime
            .capabilities_mut(requester)
            .unwrap()
            .insert(object, Rights::CONTROL)
            .unwrap();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let service = supervisor
            .register_in_runtime(object, service_task, &runtime)
            .unwrap();
        assert!(matches!(runtime.start(), ScheduleOutcome::Switch { .. }));
        let retirement = supervisor.exit_current(&mut runtime).unwrap();
        complete(&mut supervisor, retirement.cleanup);
        let plan = supervisor
            .prepare_restart_at(
                service,
                runtime.capabilities(requester).unwrap(),
                control,
                Priority::NORMAL,
                context(0x40_0000, 0x60_0000),
                0,
            )
            .unwrap();
        runtime.revoke_capability(requester, control).unwrap();
        assert_eq!(
            supervisor.commit_restart_with_task_for_requester(plan, requester, &mut runtime),
            Err(ServiceError::Runtime(TaskRuntimeError::Ipc(
                crate::IpcError::Unauthorized
            )))
        );
        assert_eq!(supervisor.state(service), Ok(ServiceState::Exited));
        assert_eq!(supervisor.task(service), Ok(None));
    }

    #[test]
    fn policy_replacement_requires_control_invalidates_plans_and_preserves_history() {
        let object = ObjectId(0x84);
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        runtime.start();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let service = supervisor
            .register_with_policy_in_runtime(
                object,
                task,
                RestartPolicy::new(2, 10, 10).unwrap(),
                &runtime,
            )
            .unwrap();
        let retirement = supervisor.exit_current_at(&mut runtime, 100).unwrap();
        runtime
            .consume_idle_dispatch(retirement.dispatch)
            .expect("single-service exit must select idle");
        complete(&mut supervisor, retirement.cleanup);

        let mut management = CapabilitySpace::<3>::new();
        let wrong = management.insert(ObjectId(0x85), Rights::CONTROL).unwrap();
        let control = management.insert(object, Rights::CONTROL).unwrap();
        let overbroad = management
            .insert(object, Rights::CONTROL.union(Rights::READ))
            .unwrap();
        let fresh = context(0x30_0000, 0x50_0000);
        let stale_plan = supervisor
            .prepare_restart_at(service, &management, control, Priority::NORMAL, fresh, 110)
            .unwrap();
        assert_eq!(
            supervisor.replace_restart_policy(
                service,
                &management,
                wrong,
                RestartPolicy::new(3, 0, 0).unwrap(),
            ),
            Err(ServiceError::Unauthorized(
                CapabilityError::PermissionDenied
            ))
        );
        assert_eq!(
            supervisor.replace_restart_policy(
                service,
                &management,
                overbroad,
                RestartPolicy::new(3, 0, 0).unwrap(),
            ),
            Err(ServiceError::Unauthorized(
                CapabilityError::PermissionDenied
            ))
        );
        supervisor
            .replace_restart_policy(
                service,
                &management,
                control,
                RestartPolicy::new(3, 0, 0).unwrap(),
            )
            .unwrap();
        assert_eq!(
            supervisor.commit_restart(stale_plan, &management, &mut runtime),
            Err(ServiceError::InvalidRestartPolicy)
        );
        assert_eq!(
            supervisor.restart_at(
                service,
                &management,
                control,
                &mut runtime,
                Priority::NORMAL,
                fresh,
                109,
            ),
            Err(ServiceError::RestartBackoff { eligible_at: 110 })
        );
        let replacement = supervisor
            .restart_at(
                service,
                &management,
                control,
                &mut runtime,
                Priority::NORMAL,
                fresh,
                110,
            )
            .unwrap();
        assert!(matches!(runtime.start(), ScheduleOutcome::Switch { .. }));
        let retirement = supervisor.exit_current_at(&mut runtime, 200).unwrap();
        runtime
            .consume_idle_dispatch(retirement.dispatch)
            .expect("single-service exit must select idle");
        complete(&mut supervisor, retirement.cleanup);
        supervisor
            .replace_restart_policy(
                replacement,
                &management,
                control,
                RestartPolicy::new(1, 0, 0).unwrap(),
            )
            .unwrap();
        assert_eq!(
            supervisor.restart_at(
                replacement,
                &management,
                control,
                &mut runtime,
                Priority::NORMAL,
                context(0x40_0000, 0x60_0000),
                200,
            ),
            Err(ServiceError::RestartLimit)
        );
    }

    #[test]
    fn policy_generation_exhaustion_preserves_policy_and_restart_plan() {
        let object = ObjectId(0x86);
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        runtime.start();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let service = supervisor.register_in_runtime(object, task, &runtime).unwrap();
        let retirement = supervisor.exit_current(&mut runtime).unwrap();
        complete(&mut supervisor, retirement.cleanup);
        supervisor.slots[service.slot as usize].policy_generation = u32::MAX;
        let mut management = CapabilitySpace::<1>::new();
        let control = management.insert(object, Rights::CONTROL).unwrap();
        let plan = supervisor
            .prepare_restart_at(
                service,
                &management,
                control,
                Priority::NORMAL,
                context(0x30_0000, 0x50_0000),
                0,
            )
            .unwrap();
        assert_eq!(
            supervisor.replace_restart_policy(
                service,
                &management,
                control,
                RestartPolicy::new(2, 0, 0).unwrap(),
            ),
            Err(ServiceError::GenerationExhausted)
        );
        assert!(
            supervisor
                .commit_restart(plan, &management, &mut runtime)
                .is_ok()
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
        let service = supervisor.register_in_runtime(object, task, &runtime).unwrap();
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
        let retired = supervisor
            .register_in_runtime(object, faulted, &runtime)
            .unwrap();
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
        assert_eq!(
            recovery.dispatch.user().map(|(task, _)| task),
            Some(observer)
        );
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
        let service = supervisor.register_in_runtime(object, task, &runtime).unwrap();
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
        let service = supervisor.register_in_runtime(object, task, &runtime).unwrap();
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
            .register_with_policy_in_runtime(
                ObjectId(7),
                task,
                RestartPolicy::new(1, 10, 10).unwrap(),
                &runtime,
            )
            .unwrap();
        assert_eq!(
            supervisor.exit_current_at(&mut runtime, u64::MAX - 5),
            Err(ServiceError::TimeExhausted)
        );
        assert!(runtime.context(task).is_ok());
        assert_eq!(runtime.current(), Some(task));
    }

    #[test]
    fn public_state_query_requires_exact_read_authority() {
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let object = ObjectId(0x7a);
        let mut supervisor = ServiceSupervisor::<1>::new();
        let service = supervisor.register(object, task).unwrap();
        let mut management = CapabilitySpace::<4>::new();
        let read = management.insert(object, Rights::READ).unwrap();
        let wrong = management.insert(ObjectId(0x7b), Rights::READ).unwrap();
        let control_only = management.insert(object, Rights::CONTROL).unwrap();
        let overbroad = management
            .insert(object, Rights::READ.union(Rights::CONTROL))
            .unwrap();
        assert_eq!(
            supervisor.state_authorized(service, &management, read),
            Ok(ServiceState::Running)
        );
        assert_eq!(
            supervisor.state_authorized(service, &management, wrong),
            Err(ServiceError::Unauthorized(
                CapabilityError::PermissionDenied
            ))
        );
        assert_eq!(
            supervisor.state_authorized(service, &management, control_only),
            Err(ServiceError::Unauthorized(
                CapabilityError::PermissionDenied
            ))
        );
        assert_eq!(
            supervisor.state_authorized(service, &management, overbroad),
            Err(ServiceError::Unauthorized(
                CapabilityError::PermissionDenied
            ))
        );
        management.revoke(read).unwrap();
        assert_eq!(
            supervisor.state_authorized(service, &management, read),
            Err(ServiceError::Unauthorized(CapabilityError::Invalid))
        );
    }

    #[test]
    fn deadline_cancellation_requires_both_exact_service_control_and_wait_owner() {
        let receiver_object = ObjectId(0x7c);
        let sender_object = ObjectId(0x7d);
        let mut runtime = TaskRuntime::<2, 0>::new(1_000, 1).unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let mut supervisor = ServiceSupervisor::<2>::new();
        let receiver_service = supervisor
            .register_in_runtime(receiver_object, receiver, &runtime)
            .unwrap();
        let sender_service = supervisor
            .register_in_runtime(sender_object, sender, &runtime)
            .unwrap();
        let mut management = CapabilitySpace::<2>::new();
        let receiver_control = management.insert(receiver_object, Rights::CONTROL).unwrap();
        let sender_control = management.insert(sender_object, Rights::CONTROL).unwrap();
        runtime.start();
        let mut executor = DeadlineReceiveSyscallExecutor::new();
        let cancellation = match executor
            .start(&mut runtime, crate::ReceiveTimeout::new(3).unwrap())
            .unwrap()
        {
            crate::DeadlineReceiveStart::Blocked {
                scheduling: ScheduleOutcome::Switch { to, .. },
                cancellation,
            } if to == sender => cancellation,
            _ => panic!("expected blocked supervised deadline receive"),
        };

        assert_eq!(
            supervisor.cancel_deadline_receive(
                receiver_service,
                &management,
                sender_control,
                &mut runtime,
                &mut executor,
                cancellation,
            ),
            Err(ServiceDeadlineCancellationError::Service(
                ServiceError::Unauthorized(CapabilityError::PermissionDenied)
            ))
        );
        assert_eq!(
            supervisor.cancel_deadline_receive(
                sender_service,
                &management,
                sender_control,
                &mut runtime,
                &mut executor,
                cancellation,
            ),
            Err(ServiceDeadlineCancellationError::Service(
                ServiceError::TaskMismatch
            ))
        );
        assert!(executor.has_pending(receiver).unwrap());
        assert_eq!(
            supervisor.cancel_deadline_receive(
                receiver_service,
                &management,
                receiver_control,
                &mut runtime,
                &mut executor,
                cancellation,
            ),
            Ok(())
        );
        assert_eq!(
            runtime.context(receiver).unwrap().rax,
            crate::SyscallCompletionStatus::Cancelled.code()
        );
        assert_eq!(
            supervisor.cancel_deadline_receive(
                receiver_service,
                &management,
                receiver_control,
                &mut runtime,
                &mut executor,
                cancellation,
            ),
            Err(ServiceDeadlineCancellationError::Deadline(
                DeadlineReceiveSyscallError::OwnerMismatch
            ))
        );
    }

    #[test]
    fn supervised_escrow_resolves_only_after_control_authorization() {
        let object = ObjectId(0x7e);
        let mut runtime = TaskRuntime::<2, 2>::new(1_000, 1).unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let service = supervisor
            .register_in_runtime(object, receiver, &runtime)
            .unwrap();
        let mut management = CapabilitySpace::<2>::new();
        let control = management.insert(object, Rights::CONTROL).unwrap();
        let wrong = management.insert(ObjectId(0x7f), Rights::CONTROL).unwrap();
        let requester_control = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(object, Rights::CONTROL)
            .unwrap();
        let requester_overbroad = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(object, Rights::CONTROL.union(Rights::READ))
            .unwrap();
        runtime.start();
        let mut executor = DeadlineReceiveSyscallExecutor::new();
        let cancellation = match executor
            .start(&mut runtime, crate::ReceiveTimeout::new(3).unwrap())
            .unwrap()
        {
            crate::DeadlineReceiveStart::Blocked {
                scheduling: ScheduleOutcome::Switch { to, .. },
                cancellation,
            } if to == sender => cancellation,
            _ => panic!("expected escrowed supervised deadline receive"),
        };
        let mut escrow = DeadlineReceiveCancellationEscrow::new();
        assert_eq!(
            supervisor.cancel_escrowed_deadline_receive(
                service,
                &management,
                control,
                &mut runtime,
                &mut executor,
                &mut escrow,
            ),
            Err(ServiceDeadlineCancellationError::Deadline(
                DeadlineReceiveSyscallError::OwnerMismatch
            ))
        );
        assert!(executor.has_pending(receiver).unwrap());
        escrow.retain(cancellation).unwrap();

        assert_eq!(
            supervisor.cancel_escrowed_deadline_receive(
                service,
                &management,
                wrong,
                &mut runtime,
                &mut executor,
                &mut escrow,
            ),
            Err(ServiceDeadlineCancellationError::Service(
                ServiceError::Unauthorized(CapabilityError::PermissionDenied)
            ))
        );
        assert_eq!(escrow.get(receiver), Ok(cancellation));
        assert_eq!(
            supervisor.cancel_escrowed_deadline_receive(
                service,
                &management,
                control,
                &mut runtime,
                &mut executor,
                &mut escrow,
            ),
            Ok(())
        );
        assert_eq!(
            escrow.get(receiver),
            Err(DeadlineReceiveSyscallError::OwnerMismatch)
        );
        assert_eq!(
            supervisor.cancel_escrowed_deadline_receive(
                service,
                &management,
                control,
                &mut runtime,
                &mut executor,
                &mut escrow,
            ),
            Err(ServiceDeadlineCancellationError::Deadline(
                DeadlineReceiveSyscallError::OwnerMismatch
            ))
        );

        assert!(matches!(
            runtime.yield_current().unwrap(),
            ScheduleOutcome::Switch { to, .. } if to == receiver
        ));
        let requester_cancellation = match executor
            .start(&mut runtime, crate::ReceiveTimeout::new(3).unwrap())
            .unwrap()
        {
            crate::DeadlineReceiveStart::Blocked { cancellation, .. } => cancellation,
            _ => panic!("expected second escrowed deadline receive"),
        };
        escrow.retain(requester_cancellation).unwrap();
        assert!(matches!(
            supervisor.cancel_escrowed_deadline_receive_for_requester(
                service,
                sender,
                requester_overbroad,
                &mut runtime,
                &mut executor,
                &mut escrow,
            ),
            Err(ServiceDeadlineCancellationError::Service(
                ServiceError::Runtime(_)
            ))
        ));
        assert_eq!(escrow.get(receiver), Ok(requester_cancellation));
        assert_eq!(
            supervisor.cancel_escrowed_deadline_receive_for_requester(
                service,
                sender,
                requester_control,
                &mut runtime,
                &mut executor,
                &mut escrow,
            ),
            Ok(())
        );
    }
}
