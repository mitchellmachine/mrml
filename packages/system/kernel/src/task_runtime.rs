use core::array;
use core::mem::size_of;
use core::ops::{Deref, DerefMut};

use crate::arch::x86_64::{
    InstalledEntryStack, TrapDisposition, UserContext, enter_user_context_on_stack,
};
use crate::capability::CapabilityRevocationPlan;
use crate::ipc::EndpointSendPlan;
use crate::scheduler::WakePlan;
use crate::{
    BalancePolicyError, BalanceTarget, Capability, CapabilitySpace, DetachedTask, Endpoint,
    IpcError, KernelScheduleError, KernelScheduler, MemoryBackingKind, MemoryObjectId,
    MemoryPoolId, MemoryPoolTable, MemoryResourceError, Message, ObjectId, OwnershipMailbox,
    PAGE_SIZE, PeriodicBalancer, Priority, Rights, ScheduleOutcome, SchedulerLoad, TaskId,
    TaskMigration, UserReturnError,
};

pub const TASK_INBOX_MESSAGES: usize = 2;
pub const TASK_CONTROL_PEERS: usize = 8;
pub const MAX_TASK_DELEGATIONS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskRuntimeError {
    Full,
    MissingTask,
    NoCurrentTask,
    AddressSpaceMismatch,
    NonRecoverableFault,
    Scheduler(KernelScheduleError),
    IntegrityFailure,
    SameTaskIpc,
    Ipc(IpcError),
    InboxFull,
    InboxEmpty,
    ReceiveCapacity,
    PeerTableFull,
    ActiveControlPeers,
    ActiveDelegations,
    DelegationTableFull,
    ConstructionTargetNotPristine,
    RetirementDispatchPending,
}

impl TaskRuntimeError {
    pub const fn is_precommit_send_denial(self) -> bool {
        matches!(
            self,
            Self::MissingTask
                | Self::SameTaskIpc
                | Self::Ipc(
                    IpcError::PayloadTooLarge
                        | IpcError::TooManyCapabilities
                        | IpcError::Unauthorized
                        | IpcError::SequenceExhausted,
                )
                | Self::InboxFull
                | Self::DelegationTableFull
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountedTaskRuntimeError {
    Runtime(TaskRuntimeError),
    Memory(MemoryResourceError),
    Arithmetic,
}

impl From<TaskRuntimeError> for AccountedTaskRuntimeError {
    fn from(value: TaskRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

impl From<MemoryResourceError> for AccountedTaskRuntimeError {
    fn from(value: MemoryResourceError) -> Self {
        Self::Memory(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerDeathReason {
    Exited,
    Faulted { vector: u8, address: Option<u64> },
    ProtocolViolation(TaskProtocolViolation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskProtocolViolation {
    InvalidUserReturn(UserReturnError),
    BufferedReceiveMappingDrift,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerDeath {
    peer: TaskId,
    reason: PeerDeathReason,
}

impl PeerDeath {
    pub const fn peer(self) -> TaskId {
        self.peer
    }

    pub const fn reason(self) -> PeerDeathReason {
        self.reason
    }
}

pub struct ReceivedMessage {
    sender: TaskId,
    sequence: u64,
    message: Message,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuedMessageShape {
    payload_length: usize,
    capability_count: usize,
}

impl QueuedMessageShape {
    pub const fn payload_length(self) -> usize {
        self.payload_length
    }

    pub const fn capability_count(self) -> usize {
        self.capability_count
    }
}

impl ReceivedMessage {
    pub const fn sender(&self) -> TaskId {
        self.sender
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn message(&self) -> &Message {
        &self.message
    }

    pub fn into_message(self) -> Message {
        self.message
    }
}

// The message stays inline because this no-allocation kernel boundary cannot
// box it, and returning a borrowed inbox entry would prevent atomic dequeue.
#[allow(clippy::large_enum_variant)]
pub enum ControlEvent {
    Message(ReceivedMessage),
    PeerDied(PeerDeath),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultRetirement {
    pub task: TaskId,
    pub context: UserContext,
    pub vector: u8,
    pub address: Option<u64>,
    next: ScheduleOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskViolationRetirement {
    pub task: TaskId,
    pub context: UserContext,
    pub violation: TaskProtocolViolation,
    next: ScheduleOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskTermination {
    task: TaskId,
    next: ScheduleOutcome,
}

impl TaskTermination {
    pub const fn task(self) -> TaskId {
        self.task
    }

    pub const fn outcome(self) -> ScheduleOutcome {
        self.next
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingRetirement {
    Termination(TaskTermination),
    Fault(FaultRetirement),
    Violation(TaskViolationRetirement),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TaskTerminationDispatchTarget {
    Idle,
    User { task: TaskId, context: UserContext },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaskTerminationDispatchIdentity {
    source: TaskId,
    target: Option<TaskId>,
}

/// An opaque successor dispatch minted only after exact runtime validation.
///
/// Callers may inspect the selected target but cannot construct a replacement
/// proof from a task name or saved context.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "a validated dispatch must be explicitly consumed"]
pub struct TaskTerminationDispatch {
    identity: TaskTerminationDispatchIdentity,
    target: TaskTerminationDispatchTarget,
}

#[derive(Debug, Eq, PartialEq)]
pub struct TaskTerminationIdle {
    _private: (),
}

impl TaskTerminationDispatch {
    pub const fn is_idle(&self) -> bool {
        matches!(self.target, TaskTerminationDispatchTarget::Idle)
    }

    pub const fn user(&self) -> Option<(TaskId, UserContext)> {
        match self.target {
            TaskTerminationDispatchTarget::Idle => None,
            TaskTerminationDispatchTarget::User { task, context } => Some((task, context)),
        }
    }

    /// Borrows the selected successor context for trusted preparation while
    /// exact-matching this issued dispatch to its owning runtime and task.
    pub fn user_context_mut<'a, const TASKS: usize, const CAPS: usize>(
        &self,
        runtime: &'a mut TaskRuntime<TASKS, CAPS>,
        task: TaskId,
    ) -> Result<&'a mut UserContext, TaskTerminationDispatchError> {
        if self.identity.target != Some(task) {
            return Err(TaskTerminationDispatchError::CurrentMismatch);
        }
        runtime.context_mut_for_issued_dispatch(self.identity, task)
    }

    /// Refreshes the saved user context after trusted successor preparation,
    /// while exact-matching the scheduler-selected task again.
    pub fn refresh_from_runtime<const TASKS: usize, const CAPS: usize>(
        &mut self,
        runtime: &TaskRuntime<TASKS, CAPS>,
    ) -> Result<(), TaskTerminationDispatchError> {
        runtime.validate_issued_dispatch(self.identity)?;
        match &mut self.target {
            TaskTerminationDispatchTarget::Idle => {
                if runtime.current().is_some() {
                    return Err(TaskTerminationDispatchError::CurrentMismatch);
                }
            }
            TaskTerminationDispatchTarget::User { task, context } => {
                if runtime.current() != Some(*task) {
                    return Err(TaskTerminationDispatchError::CurrentMismatch);
                }
                *context = *runtime
                    .context(*task)
                    .map_err(TaskTerminationDispatchError::Runtime)?;
            }
        }
        Ok(())
    }

    /// Consumes this validated dispatch at the x86-64 context-transition
    /// boundary. An idle dispatch returns an opaque marker; a user dispatch
    /// does not return.
    ///
    /// # Safety
    ///
    /// The caller must satisfy every transition-stack, page-table, TSS, and
    /// interrupt exclusion requirement of [`enter_user_context_on_stack`].
    pub unsafe fn enter_user_on_stack<const TASKS: usize, const CAPS: usize>(
        self,
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        transition_stack: InstalledEntryStack,
    ) -> Result<TaskTerminationIdle, (Self, TaskTerminationDispatchError)> {
        if let Err(error) = runtime.consume_issued_dispatch(self.identity) {
            return Err((self, error));
        }
        match self.target {
            TaskTerminationDispatchTarget::Idle => Ok(TaskTerminationIdle { _private: () }),
            TaskTerminationDispatchTarget::User { context, .. } => unsafe {
                enter_user_context_on_stack(&context, transition_stack)
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskTerminationDispatchError {
    InvalidOutcome,
    WrongSource,
    CurrentMismatch,
    NoPendingTermination,
    TerminationMismatch,
    NoPendingFault,
    FaultMismatch,
    NoPendingViolation,
    ViolationMismatch,
    DispatchOutstanding,
    DispatchIdentityMismatch,
    Runtime(TaskRuntimeError),
}

struct TaskDomain<const CAPS: usize> {
    task: TaskId,
    context: UserContext,
    capabilities: CapabilitySpace<CAPS>,
    inbox: [Option<ReceivedMessage>; TASK_INBOX_MESSAGES],
    inbox_head: u8,
    inbox_tail: u8,
    inbox_count: u8,
    peers: [Option<TaskId>; TASK_CONTROL_PEERS],
    peer_deaths: [Option<PeerDeath>; TASK_CONTROL_PEERS],
}

#[derive(Clone, Copy)]
struct Delegation {
    source_task: TaskId,
    source: Capability,
    destination_task: TaskId,
    destination: Capability,
}

struct InboxDeliveryPlan {
    slot: usize,
    next_tail: u8,
    next_count: u8,
}

type DelegationSet = [Option<(TaskId, Capability)>; MAX_TASK_DELEGATIONS + 2];

#[derive(Clone, Copy)]
struct TrackedRevocationPlan {
    domain_slot: usize,
    capability: CapabilityRevocationPlan,
}

type TrackedRevocationSet = [Option<TrackedRevocationPlan>; MAX_TASK_DELEGATIONS + 2];

struct PeerDeathPublicationPlan {
    domain_slot: usize,
    relation_slot: usize,
    death_slot: usize,
    wake: WakePlan,
}

type PeerDeathPublicationSet = [Option<PeerDeathPublicationPlan>; TASK_CONTROL_PEERS];

pub struct DetachedTaskDomain<const CAPS: usize> {
    scheduling: DetachedTask,
    domain: TaskDomain<CAPS>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainBalanceError {
    Policy(BalancePolicyError),
    Runtime(TaskRuntimeError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainBalanceOutcome {
    Idle,
    Published(BalanceTarget),
    RetryPending(BalanceTarget),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerDomainBalanceOutcome {
    scheduling: ScheduleOutcome,
    balancing: DomainBalanceOutcome,
}

impl TimerDomainBalanceOutcome {
    pub const fn scheduling(self) -> ScheduleOutcome {
        self.scheduling
    }

    pub const fn balancing(self) -> DomainBalanceOutcome {
        self.balancing
    }
}

/// Couples periodic peer selection to linear complete-domain ownership. A full
/// destination mailbox retains the detached domain inside this controller and
/// retries it before considering another tick, so cadence cannot duplicate,
/// discard, or reorder migration tickets.
pub struct PeriodicDomainBalancer<const CPUS: usize, const CAPS: usize> {
    policy: PeriodicBalancer<CPUS>,
    pending: Option<(BalanceTarget, DetachedTaskDomain<CAPS>)>,
}

impl<const CPUS: usize, const CAPS: usize> PeriodicDomainBalancer<CPUS, CAPS> {
    pub const fn new(start_tick: u64, interval_ticks: u64) -> Result<Self, DomainBalanceError> {
        let policy = match PeriodicBalancer::new(start_tick, interval_ticks) {
            Ok(policy) => policy,
            Err(error) => return Err(DomainBalanceError::Policy(error)),
        };
        Ok(Self {
            policy,
            pending: None,
        })
    }

    pub fn pending_target(&self) -> Option<BalanceTarget> {
        self.pending.as_ref().map(|pending| pending.0)
    }

    pub fn poll_and_publish<const TASKS: usize>(
        &mut self,
        tick: u64,
        local_cpu: usize,
        loads: &[SchedulerLoad; CPUS],
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        mailboxes: &[&OwnershipMailbox<DetachedTaskDomain<CAPS>>; CPUS],
    ) -> Result<DomainBalanceOutcome, DomainBalanceError> {
        if let Some((target, ticket)) = self.pending.take() {
            return match mailboxes[target.cpu()].publish(ticket) {
                Ok(()) => Ok(DomainBalanceOutcome::Published(target)),
                Err((_, ticket)) => {
                    self.pending = Some((target, ticket));
                    Ok(DomainBalanceOutcome::RetryPending(target))
                }
            };
        }

        let Some(target) = self
            .policy
            .poll(tick, local_cpu, loads)
            .map_err(DomainBalanceError::Policy)?
        else {
            return Ok(DomainBalanceOutcome::Idle);
        };
        let Some(ticket) = runtime
            .detach_domain_for_rebalance(target.load())
            .map_err(DomainBalanceError::Runtime)?
        else {
            return Ok(DomainBalanceOutcome::Idle);
        };
        match mailboxes[target.cpu()].publish(ticket) {
            Ok(()) => Ok(DomainBalanceOutcome::Published(target)),
            Err((_, ticket)) => {
                self.pending = Some((target, ticket));
                Ok(DomainBalanceOutcome::RetryPending(target))
            }
        }
    }

    /// Accounts the hardware timer event before applying periodic migration
    /// policy. The caller's published local load must still match the runtime;
    /// a stale or forged snapshot fails before any domain is detached.
    pub fn timer_tick_and_publish<const TASKS: usize>(
        &mut self,
        local_cpu: usize,
        loads: &[SchedulerLoad; CPUS],
        runtime: &mut TaskRuntime<TASKS, CAPS>,
        mailboxes: &[&OwnershipMailbox<DetachedTaskDomain<CAPS>>; CPUS],
    ) -> Result<TimerDomainBalanceOutcome, DomainBalanceError> {
        if local_cpu >= CPUS || loads[local_cpu] != runtime.load() {
            return Err(DomainBalanceError::Runtime(
                TaskRuntimeError::IntegrityFailure,
            ));
        }
        let scheduling = runtime.timer_tick().map_err(DomainBalanceError::Runtime)?;
        let balancing =
            self.poll_and_publish(runtime.ticks(), local_cpu, loads, runtime, mailboxes)?;
        Ok(TimerDomainBalanceOutcome {
            scheduling,
            balancing,
        })
    }
}

/// Owns the scheduler-visible identity, saved context, and capability space as
/// one revocation domain. Fault retirement removes the domain before it asks
/// the scheduler for a replacement, so a stale task is never resumable with a
/// partially live authority set.
pub struct TaskRuntime<const TASKS: usize, const CAPS: usize> {
    scheduler: KernelScheduler<TASKS>,
    domains: [Option<TaskDomain<CAPS>>; TASKS],
    delegations: [Option<Delegation>; MAX_TASK_DELEGATIONS],
    pending_retirement: Option<PendingRetirement>,
    issued_dispatch: Option<TaskTerminationDispatchIdentity>,
}

/// A task runtime whose complete fixed-capacity kernel footprint has one exact
/// memory-pool commitment.
///
/// This accounts the scheduler, task/capability metadata, delegation table,
/// and every inline IPC inbox slot together. Per-message delivery does not
/// create another RAM charge because those slots already exist in this fixed
/// allocation. Consuming `release` is the only supported way to return the
/// commitment; a failed release returns the still-accounted runtime.
pub struct AccountedTaskRuntime<const TASKS: usize, const CAPS: usize> {
    runtime: TaskRuntime<TASKS, CAPS>,
    charge: MemoryObjectId,
    charge_capability: Capability,
    committed_pages: u64,
}

impl<const TASKS: usize, const CAPS: usize> AccountedTaskRuntime<TASKS, CAPS> {
    #[allow(clippy::too_many_arguments)]
    pub fn new<const POOLS: usize, const OBJECTS: usize, const AUTHORITIES: usize>(
        ticks_per_second: u32,
        quantum_ticks: u32,
        pool: MemoryPoolId,
        pool_capability: Capability,
        memory: &mut MemoryPoolTable<POOLS, OBJECTS>,
        authorities: &mut CapabilitySpace<AUTHORITIES>,
    ) -> Result<Self, AccountedTaskRuntimeError> {
        let runtime = TaskRuntime::new(ticks_per_second, quantum_ticks)?;
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
            runtime,
            charge,
            charge_capability,
            committed_pages,
        })
    }

    pub fn required_pages() -> Result<u64, AccountedTaskRuntimeError> {
        let bytes =
            u64::try_from(size_of::<Self>()).map_err(|_| AccountedTaskRuntimeError::Arithmetic)?;
        bytes
            .checked_add(PAGE_SIZE - 1)
            .map(|rounded| rounded / PAGE_SIZE)
            .filter(|pages| *pages != 0)
            .ok_or(AccountedTaskRuntimeError::Arithmetic)
    }

    pub const fn charge(&self) -> MemoryObjectId {
        self.charge
    }

    pub const fn committed_pages(&self) -> u64 {
        self.committed_pages
    }

    #[allow(clippy::result_large_err)]
    pub fn release<const POOLS: usize, const OBJECTS: usize, const AUTHORITIES: usize>(
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

impl<const TASKS: usize, const CAPS: usize> Deref for AccountedTaskRuntime<TASKS, CAPS> {
    type Target = TaskRuntime<TASKS, CAPS>;

    fn deref(&self) -> &Self::Target {
        &self.runtime
    }
}

impl<const TASKS: usize, const CAPS: usize> DerefMut for AccountedTaskRuntime<TASKS, CAPS> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.runtime
    }
}

impl<const TASKS: usize, const CAPS: usize> TaskRuntime<TASKS, CAPS> {
    pub fn new(ticks_per_second: u32, quantum_ticks: u32) -> Result<Self, TaskRuntimeError> {
        let scheduler = KernelScheduler::new(ticks_per_second, quantum_ticks)
            .map_err(TaskRuntimeError::Scheduler)?;
        Ok(Self {
            scheduler,
            domains: array::from_fn(|_| None),
            delegations: [None; MAX_TASK_DELEGATIONS],
            pending_retirement: None,
            issued_dispatch: None,
        })
    }

    pub fn create(
        &mut self,
        priority: Priority,
        context: UserContext,
    ) -> Result<TaskId, TaskRuntimeError> {
        let slot = self
            .domains
            .iter()
            .position(Option::is_none)
            .ok_or(TaskRuntimeError::Full)?;
        let task = self
            .scheduler
            .create(priority)
            .map_err(TaskRuntimeError::Scheduler)?;
        self.domains[slot] = Some(TaskDomain {
            task,
            context,
            capabilities: CapabilitySpace::new(),
            inbox: array::from_fn(|_| None),
            inbox_head: 0,
            inbox_tail: 0,
            inbox_count: 0,
            peers: [None; TASK_CONTROL_PEERS],
            peer_deaths: [None; TASK_CONTROL_PEERS],
        });
        Ok(task)
    }

    pub fn start(&mut self) -> ScheduleOutcome {
        if self.issued_dispatch.is_some() {
            return self
                .current()
                .map_or(ScheduleOutcome::Idle, ScheduleOutcome::Continue);
        }
        self.scheduler.start()
    }

    pub const fn ticks(&self) -> u64 {
        self.scheduler.ticks()
    }

    pub fn load(&self) -> SchedulerLoad {
        self.scheduler.load()
    }

    pub fn timer_tick(&mut self) -> Result<ScheduleOutcome, TaskRuntimeError> {
        self.ensure_scheduler_mutable()?;
        self.scheduler
            .timer_tick()
            .map_err(TaskRuntimeError::Scheduler)
    }

    /// Accounts one timer tick and atomically installs the interrupted CPL3
    /// context into the domain that was current at interrupt entry.
    pub fn preempt_current(
        &mut self,
        interrupted: UserContext,
    ) -> Result<ScheduleOutcome, TaskRuntimeError> {
        self.ensure_scheduler_mutable()?;
        let current = self
            .scheduler
            .current()
            .ok_or(TaskRuntimeError::NoCurrentTask)?;
        let slot = self.domain_slot(current)?;
        if !self.scheduler.contains(current) {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        if self.domains[slot]
            .as_ref()
            .ok_or(TaskRuntimeError::IntegrityFailure)?
            .context
            .page_table()
            != interrupted.page_table()
        {
            return Err(TaskRuntimeError::AddressSpaceMismatch);
        }
        let outcome = self
            .scheduler
            .timer_tick()
            .map_err(TaskRuntimeError::Scheduler)?;
        self.domains[slot]
            .as_mut()
            .expect("preemption preserves the prevalidated domain slot")
            .context = interrupted;
        Ok(outcome)
    }

    pub fn yield_current(&mut self) -> Result<ScheduleOutcome, TaskRuntimeError> {
        self.ensure_scheduler_mutable()?;
        self.scheduler
            .yield_current()
            .map_err(TaskRuntimeError::Scheduler)
    }

    pub fn context(&self, task: TaskId) -> Result<&UserContext, TaskRuntimeError> {
        let slot = self.domain_slot(task)?;
        if !self.scheduler.contains(task) {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        self.domains[slot]
            .as_ref()
            .map(|domain| &domain.context)
            .ok_or(TaskRuntimeError::IntegrityFailure)
    }

    pub fn context_mut(&mut self, task: TaskId) -> Result<&mut UserContext, TaskRuntimeError> {
        self.ensure_scheduler_mutable()?;
        self.context_mut_unfrozen(task)
    }

    fn context_mut_unfrozen(&mut self, task: TaskId) -> Result<&mut UserContext, TaskRuntimeError> {
        let slot = self.domain_slot(task)?;
        if !self.scheduler.contains(task) {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        self.domains[slot]
            .as_mut()
            .map(|domain| &mut domain.context)
            .ok_or(TaskRuntimeError::IntegrityFailure)
    }

    fn context_mut_for_issued_dispatch(
        &mut self,
        identity: TaskTerminationDispatchIdentity,
        task: TaskId,
    ) -> Result<&mut UserContext, TaskTerminationDispatchError> {
        self.validate_issued_dispatch(identity)?;
        if self.current() != Some(task) || identity.target != Some(task) {
            return Err(TaskTerminationDispatchError::CurrentMismatch);
        }
        self.context_mut_unfrozen(task)
            .map_err(TaskTerminationDispatchError::Runtime)
    }

    pub const fn current(&self) -> Option<TaskId> {
        self.scheduler.current()
    }

    /// Retires a non-current scheduler identity and removes its complete user
    /// revocation domain as one linear object. On scheduler rejection the
    /// untouched domain is restored to its exact slot.
    pub fn detach_domain(
        &mut self,
        task: TaskId,
    ) -> Result<DetachedTaskDomain<CAPS>, TaskRuntimeError> {
        self.ensure_scheduler_mutable()?;
        let slot = self.domain_slot(task)?;
        if self.domains[slot].as_ref().is_some_and(|domain| {
            domain.peers.iter().any(Option::is_some)
                || domain.peer_deaths.iter().any(Option::is_some)
        }) {
            return Err(TaskRuntimeError::ActiveControlPeers);
        }
        if self
            .delegations
            .iter()
            .flatten()
            .any(|delegation| delegation.source_task == task || delegation.destination_task == task)
        {
            return Err(TaskRuntimeError::ActiveDelegations);
        }
        let domain = self.domains[slot]
            .take()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        match self.scheduler.detach(task) {
            Ok(scheduling) => Ok(DetachedTaskDomain { scheduling, domain }),
            Err(error) => {
                self.domains[slot] = Some(domain);
                Err(TaskRuntimeError::Scheduler(error))
            }
        }
    }

    pub fn detach_domain_for_rebalance(
        &mut self,
        destination: SchedulerLoad,
    ) -> Result<Option<DetachedTaskDomain<CAPS>>, TaskRuntimeError> {
        self.ensure_scheduler_mutable()?;
        let Some(candidate) = self
            .scheduler
            .rebalance_candidate(destination)
            .map_err(TaskRuntimeError::Scheduler)?
        else {
            return Ok(None);
        };
        self.domain_slot(candidate)
            .map_err(|_| TaskRuntimeError::IntegrityFailure)?;
        self.detach_domain(candidate).map(Some)
    }

    /// Admits a complete migrated user domain under a fresh local scheduler
    /// identity. Capacity failure returns context, capabilities, inbox, and
    /// scheduling ticket together so authority cannot be orphaned.
    pub fn attach_domain(
        &mut self,
        ticket: &mut Option<DetachedTaskDomain<CAPS>>,
    ) -> Result<TaskMigration, TaskRuntimeError> {
        self.ensure_scheduler_mutable()?;
        let Some(slot) = self.domains.iter().position(Option::is_none) else {
            return Err(TaskRuntimeError::Full);
        };
        let task = ticket.take().ok_or(TaskRuntimeError::MissingTask)?;
        let DetachedTaskDomain {
            scheduling,
            mut domain,
        } = task;
        let migration = match self.scheduler.attach(scheduling) {
            Ok(migration) => migration,
            Err(error) => {
                let schedule_error = error.error();
                *ticket = Some(DetachedTaskDomain {
                    scheduling: error.into_task(),
                    domain,
                });
                return Err(TaskRuntimeError::Scheduler(schedule_error));
            }
        };
        domain.task = migration.destination();
        self.domains[slot] = Some(domain);
        Ok(migration)
    }

    pub fn capabilities_mut(
        &mut self,
        task: TaskId,
    ) -> Result<&mut CapabilitySpace<CAPS>, TaskRuntimeError> {
        let slot = self.domain_slot(task)?;
        if !self.scheduler.contains(task) {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        self.domains[slot]
            .as_mut()
            .map(|domain| &mut domain.capabilities)
            .ok_or(TaskRuntimeError::IntegrityFailure)
    }

    pub fn capabilities(&self, task: TaskId) -> Result<&CapabilitySpace<CAPS>, TaskRuntimeError> {
        let slot = self.domain_slot(task)?;
        if !self.scheduler.contains(task) {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        self.domains[slot]
            .as_ref()
            .map(|domain| &domain.capabilities)
            .ok_or(TaskRuntimeError::IntegrityFailure)
    }

    /// Resolves one opaque task-local handle against its exact generation,
    /// requested rights, and expected object without exposing capability-space
    /// contents to userspace.
    pub fn authorize_capability(
        &self,
        task: TaskId,
        capability: Capability,
        rights: Rights,
        expected: ObjectId,
    ) -> Result<(), TaskRuntimeError> {
        let object = self
            .capabilities(task)?
            .authorize(capability, rights)
            .map_err(|error| TaskRuntimeError::Ipc(error.into()))?;
        if object != expected {
            return Err(TaskRuntimeError::Ipc(IpcError::Unauthorized));
        }
        Ok(())
    }

    /// Resolves one task-local handle only when its authority is exactly the
    /// requested rights set. This rejects otherwise-valid overbroad handles at
    /// narrow boot and service boundaries.
    pub fn authorize_capability_exact(
        &self,
        task: TaskId,
        capability: Capability,
        rights: Rights,
        expected: ObjectId,
    ) -> Result<(), TaskRuntimeError> {
        let object = self
            .capabilities(task)?
            .authorize_exact(capability, rights)
            .map_err(|error| TaskRuntimeError::Ipc(error.into()))?;
        if object != expected {
            return Err(TaskRuntimeError::Ipc(IpcError::Unauthorized));
        }
        Ok(())
    }

    /// Revokes one exact capability and every capability transitively derived
    /// from it through this runtime's IPC transfer path. Descendants are
    /// removed before the source handle, so no surviving task can observe a
    /// live child after explicit revocation completes.
    pub fn revoke_capability(
        &mut self,
        task: TaskId,
        capability: Capability,
    ) -> Result<(), TaskRuntimeError> {
        self.capabilities(task)?
            .describe(capability)
            .map_err(|error| TaskRuntimeError::Ipc(error.into()))?;
        let descendants = self.delegation_descendants(task, capability)?;
        let plan = self.prepare_tracked_revocation(&descendants.0, 0)?;
        self.commit_tracked_revocation(plan);
        self.remove_tracked(&descendants.0);
        Ok(())
    }

    /// Atomically revokes two distinct roots and every tracked descendant.
    /// Complete generation and graph validation precedes all capability-space
    /// mutation, so a stale second root cannot partially revoke the first.
    pub fn revoke_capability_pair(
        &mut self,
        task: TaskId,
        first: Capability,
        second: Capability,
    ) -> Result<(), TaskRuntimeError> {
        if first == second {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        self.capabilities(task)?
            .describe(first)
            .map_err(|error| TaskRuntimeError::Ipc(error.into()))?;
        self.capabilities(task)?
            .describe(second)
            .map_err(|error| TaskRuntimeError::Ipc(error.into()))?;
        let first_tree = self.delegation_descendants(task, first)?.0;
        let second_tree = self.delegation_descendants(task, second)?.0;
        let mut tracked: DelegationSet = [None; MAX_TASK_DELEGATIONS + 2];
        let mut count = 0usize;
        for item in first_tree.into_iter().chain(second_tree).flatten() {
            if tracked[..count].contains(&Some(item)) {
                continue;
            }
            let slot = tracked
                .get_mut(count)
                .ok_or(TaskRuntimeError::IntegrityFailure)?;
            *slot = Some(item);
            count += 1;
        }
        let plan = self.prepare_tracked_revocation(&tracked, 0)?;
        self.commit_tracked_revocation(plan);
        self.remove_tracked(&tracked);
        Ok(())
    }

    fn delegation_descendants(
        &self,
        task: TaskId,
        capability: Capability,
    ) -> Result<(DelegationSet, usize), TaskRuntimeError> {
        let mut tracked = [None; MAX_TASK_DELEGATIONS + 2];
        tracked[0] = Some((task, capability));
        let mut count = 1usize;
        let mut changed = true;
        while changed {
            changed = false;
            for edge in self.delegations.iter().flatten().copied() {
                if tracked[..count].contains(&Some((edge.source_task, edge.source)))
                    && !tracked[..count].contains(&Some((edge.destination_task, edge.destination)))
                {
                    let slot = tracked
                        .get_mut(count)
                        .ok_or(TaskRuntimeError::IntegrityFailure)?;
                    *slot = Some((edge.destination_task, edge.destination));
                    count += 1;
                    changed = true;
                }
            }
        }
        Ok((tracked, count))
    }

    fn prepare_tracked_revocation(
        &self,
        tracked: &DelegationSet,
        start: usize,
    ) -> Result<TrackedRevocationSet, TaskRuntimeError> {
        // Validate the complete exact-generation set before changing any
        // destination space. A stale graph edge is an integrity failure, but
        // cannot otherwise leave a partially revoked descendant tree.
        let mut plan: TrackedRevocationSet = array::from_fn(|_| None);
        let mut plan_count = 0usize;
        for (task, capability) in tracked[start..].iter().flatten().copied() {
            let domain_slot = self.domain_slot(task)?;
            if !self.scheduler.contains(task) {
                return Err(TaskRuntimeError::IntegrityFailure);
            }
            let capability = self.domains[domain_slot]
                .as_ref()
                .ok_or(TaskRuntimeError::IntegrityFailure)?
                .capabilities
                .prepare_revoke(capability)
                .map_err(|_| TaskRuntimeError::IntegrityFailure)?;
            if plan[..plan_count]
                .iter()
                .flatten()
                .any(|prior| prior.domain_slot == domain_slot && prior.capability == capability)
            {
                return Err(TaskRuntimeError::IntegrityFailure);
            }
            plan[plan_count] = Some(TrackedRevocationPlan {
                domain_slot,
                capability,
            });
            plan_count += 1;
        }
        Ok(plan)
    }

    fn commit_tracked_revocation(&mut self, plan: TrackedRevocationSet) {
        for revocation in plan.into_iter().flatten() {
            self.domains[revocation.domain_slot]
                .as_mut()
                .expect("runtime preserves every prepared revocation domain")
                .capabilities
                .commit_revoke(revocation.capability);
        }
    }

    fn remove_tracked(&mut self, tracked: &DelegationSet) {
        for edge in &mut self.delegations {
            if edge.is_some_and(|edge| {
                tracked.contains(&Some((edge.source_task, edge.source)))
                    || tracked.contains(&Some((edge.destination_task, edge.destination)))
            }) {
                *edge = None;
            }
        }
    }

    fn revoke_task_delegations(&mut self, task: TaskId) -> Result<(), TaskRuntimeError> {
        self.validate_delegation_graph()?;
        let mut descendants = [None; MAX_TASK_DELEGATIONS + 2];
        let mut count = 0usize;
        for edge in self.delegations.iter().flatten().copied() {
            if edge.source_task == task
                && !descendants[..count].contains(&Some((edge.destination_task, edge.destination)))
            {
                descendants[count] = Some((edge.destination_task, edge.destination));
                count += 1;
            }
        }
        let mut changed = true;
        while changed {
            changed = false;
            for edge in self.delegations.iter().flatten().copied() {
                if descendants[..count].contains(&Some((edge.source_task, edge.source)))
                    && !descendants[..count]
                        .contains(&Some((edge.destination_task, edge.destination)))
                {
                    let slot = descendants
                        .get_mut(count)
                        .ok_or(TaskRuntimeError::IntegrityFailure)?;
                    *slot = Some((edge.destination_task, edge.destination));
                    count += 1;
                    changed = true;
                }
            }
        }
        let plan = self.prepare_tracked_revocation(&descendants, 0)?;
        self.commit_tracked_revocation(plan);
        self.remove_tracked(&descendants);
        for edge in &mut self.delegations {
            if edge.is_some_and(|edge| edge.source_task == task || edge.destination_task == task) {
                *edge = None;
            }
        }
        Ok(())
    }

    pub fn terminate_current_fault(
        &mut self,
        disposition: TrapDisposition,
    ) -> Result<FaultRetirement, TaskRuntimeError> {
        self.ensure_no_pending_retirement()?;
        self.ensure_no_issued_retirement()?;
        let (vector, address) = match disposition {
            TrapDisposition::TerminateUser { vector, address } => (vector, address),
            TrapDisposition::HaltKernel { .. } => {
                return Err(TaskRuntimeError::NonRecoverableFault);
            }
        };
        let current = self
            .scheduler
            .current()
            .ok_or(TaskRuntimeError::NoCurrentTask)?;
        let slot = self
            .domain_slot(current)
            .map_err(|_| TaskRuntimeError::IntegrityFailure)?;
        let termination_plan = self
            .scheduler
            .prepare_current_termination()
            .map_err(TaskRuntimeError::Scheduler)?;

        let peer_plan = self.prepare_peer_death_publication(
            self.domains[slot]
                .as_ref()
                .ok_or(TaskRuntimeError::IntegrityFailure)?,
        )?;
        self.revoke_task_delegations(current)?;

        // Taking the complete domain first revokes the saved context and every
        // task-local capability before scheduler selection can expose `next`.
        let domain = self.domains[slot]
            .take()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        self.commit_peer_death_publication(
            peer_plan,
            domain.task,
            PeerDeathReason::Faulted { vector, address },
        );
        let next = self.scheduler.commit_current_termination(termination_plan);
        let retirement = FaultRetirement {
            task: current,
            context: domain.context,
            vector,
            address,
            next,
        };
        self.pending_retirement = Some(PendingRetirement::Fault(retirement));
        Ok(retirement)
    }

    /// Retires a userspace domain for a kernel-recognized protocol violation.
    ///
    /// Protocol violations are distinct from hardware exceptions: the exact
    /// saved domain and its authority are revoked before peers or a replacement
    /// can observe the typed reason.
    pub fn terminate_current_violation(
        &mut self,
        violation: TaskProtocolViolation,
    ) -> Result<TaskViolationRetirement, TaskRuntimeError> {
        self.ensure_no_pending_retirement()?;
        self.ensure_no_issued_retirement()?;
        let current = self
            .scheduler
            .current()
            .ok_or(TaskRuntimeError::NoCurrentTask)?;
        let slot = self
            .domain_slot(current)
            .map_err(|_| TaskRuntimeError::IntegrityFailure)?;
        let termination_plan = self
            .scheduler
            .prepare_current_termination()
            .map_err(TaskRuntimeError::Scheduler)?;

        let peer_plan = self.prepare_peer_death_publication(
            self.domains[slot]
                .as_ref()
                .ok_or(TaskRuntimeError::IntegrityFailure)?,
        )?;
        self.revoke_task_delegations(current)?;
        let domain = self.domains[slot]
            .take()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        self.commit_peer_death_publication(
            peer_plan,
            domain.task,
            PeerDeathReason::ProtocolViolation(violation),
        );
        let next = self.scheduler.commit_current_termination(termination_plan);
        let retirement = TaskViolationRetirement {
            task: current,
            context: domain.context,
            violation,
            next,
        };
        self.pending_retirement = Some(PendingRetirement::Violation(retirement));
        Ok(retirement)
    }

    /// Removes the current task's complete revocation domain for a voluntary
    /// exit before selecting a replacement. No context or authority from the
    /// removed domain is returned to its caller.
    pub fn terminate_current(&mut self) -> Result<TaskTermination, TaskRuntimeError> {
        self.terminate_current_with_context()
            .map(|(termination, _)| termination)
    }

    /// Exact-matches a voluntary termination outcome to the scheduler's
    /// selected successor before disclosing the context that a privileged
    /// caller may install. Caller-provided or stale outcomes are data only.
    pub fn dispatch_after_termination(
        &mut self,
        termination: TaskTermination,
    ) -> Result<TaskTerminationDispatch, TaskTerminationDispatchError> {
        self.ensure_no_issued_dispatch()?;
        let target = self.validate_dispatch_target(termination.task, termination.next)?;
        self.consume_pending_termination(termination)?;
        Ok(self.issue_dispatch(termination.task, target))
    }

    /// Exact-matches a fault retirement to the runtime's one pending fault
    /// transition before disclosing its selected successor context.
    pub fn dispatch_after_fault(
        &mut self,
        retirement: FaultRetirement,
    ) -> Result<TaskTerminationDispatch, TaskTerminationDispatchError> {
        self.ensure_no_issued_dispatch()?;
        let target = self.validate_dispatch_target(retirement.task, retirement.next)?;
        match self.pending_retirement {
            Some(PendingRetirement::Fault(pending)) if pending == retirement => {}
            Some(PendingRetirement::Fault(_)) => {
                return Err(TaskTerminationDispatchError::FaultMismatch);
            }
            _ => return Err(TaskTerminationDispatchError::NoPendingFault),
        }
        self.pending_retirement = None;
        Ok(self.issue_dispatch(retirement.task, target))
    }

    /// Exact-matches a protocol-violation retirement to the runtime's one
    /// pending violation transition before disclosing its successor context.
    pub fn dispatch_after_violation(
        &mut self,
        retirement: TaskViolationRetirement,
    ) -> Result<TaskTerminationDispatch, TaskTerminationDispatchError> {
        self.ensure_no_issued_dispatch()?;
        let target = self.validate_dispatch_target(retirement.task, retirement.next)?;
        match self.pending_retirement {
            Some(PendingRetirement::Violation(pending)) if pending == retirement => {}
            Some(PendingRetirement::Violation(_)) => {
                return Err(TaskTerminationDispatchError::ViolationMismatch);
            }
            _ => return Err(TaskTerminationDispatchError::NoPendingViolation),
        }
        self.pending_retirement = None;
        Ok(self.issue_dispatch(retirement.task, target))
    }

    fn issue_dispatch(
        &mut self,
        source: TaskId,
        target: TaskTerminationDispatchTarget,
    ) -> TaskTerminationDispatch {
        let identity = TaskTerminationDispatchIdentity {
            source,
            target: match target {
                TaskTerminationDispatchTarget::Idle => None,
                TaskTerminationDispatchTarget::User { task, .. } => Some(task),
            },
        };
        self.issued_dispatch = Some(identity);
        TaskTerminationDispatch { identity, target }
    }

    fn ensure_no_issued_dispatch(&self) -> Result<(), TaskTerminationDispatchError> {
        if self.issued_dispatch.is_some() {
            Err(TaskTerminationDispatchError::DispatchOutstanding)
        } else {
            Ok(())
        }
    }

    fn validate_issued_dispatch(
        &self,
        identity: TaskTerminationDispatchIdentity,
    ) -> Result<(), TaskTerminationDispatchError> {
        if self.issued_dispatch == Some(identity) {
            Ok(())
        } else {
            Err(TaskTerminationDispatchError::DispatchIdentityMismatch)
        }
    }

    fn consume_issued_dispatch(
        &mut self,
        identity: TaskTerminationDispatchIdentity,
    ) -> Result<(), TaskTerminationDispatchError> {
        self.validate_issued_dispatch(identity)?;
        self.issued_dispatch = None;
        Ok(())
    }

    pub fn consume_idle_dispatch(
        &mut self,
        dispatch: TaskTerminationDispatch,
    ) -> Result<TaskTerminationIdle, TaskTerminationDispatch> {
        if !dispatch.is_idle() || self.consume_issued_dispatch(dispatch.identity).is_err() {
            return Err(dispatch);
        }
        Ok(TaskTerminationIdle { _private: () })
    }

    fn validate_dispatch_target(
        &self,
        source: TaskId,
        outcome: ScheduleOutcome,
    ) -> Result<TaskTerminationDispatchTarget, TaskTerminationDispatchError> {
        match outcome {
            ScheduleOutcome::Idle => {
                if self.current().is_some() {
                    return Err(TaskTerminationDispatchError::CurrentMismatch);
                }
                Ok(TaskTerminationDispatchTarget::Idle)
            }
            ScheduleOutcome::Switch {
                from: Some(from),
                to,
            } => {
                if from != source {
                    return Err(TaskTerminationDispatchError::WrongSource);
                }
                if self.current() != Some(to) {
                    return Err(TaskTerminationDispatchError::CurrentMismatch);
                }
                let context = *self
                    .context(to)
                    .map_err(TaskTerminationDispatchError::Runtime)?;
                Ok(TaskTerminationDispatchTarget::User { task: to, context })
            }
            ScheduleOutcome::Continue(_) | ScheduleOutcome::Switch { from: None, .. } => {
                Err(TaskTerminationDispatchError::InvalidOutcome)
            }
        }
    }

    fn consume_pending_termination(
        &mut self,
        termination: TaskTermination,
    ) -> Result<(), TaskTerminationDispatchError> {
        match self.pending_retirement {
            Some(PendingRetirement::Termination(pending)) if pending == termination => {}
            Some(PendingRetirement::Termination(_)) => {
                return Err(TaskTerminationDispatchError::TerminationMismatch);
            }
            _ => return Err(TaskTerminationDispatchError::NoPendingTermination),
        }
        self.pending_retirement = None;
        Ok(())
    }

    fn ensure_no_pending_retirement(&self) -> Result<(), TaskRuntimeError> {
        if self.pending_retirement.is_some() {
            Err(TaskRuntimeError::RetirementDispatchPending)
        } else {
            Ok(())
        }
    }

    fn ensure_scheduler_mutable(&self) -> Result<(), TaskRuntimeError> {
        if self.pending_retirement.is_some() || self.issued_dispatch.is_some() {
            Err(TaskRuntimeError::RetirementDispatchPending)
        } else {
            Ok(())
        }
    }

    fn ensure_no_issued_retirement(&self) -> Result<(), TaskRuntimeError> {
        if self.issued_dispatch.is_some() {
            Err(TaskRuntimeError::RetirementDispatchPending)
        } else {
            Ok(())
        }
    }

    pub(crate) fn terminate_current_with_context(
        &mut self,
    ) -> Result<(TaskTermination, UserContext), TaskRuntimeError> {
        if self.pending_retirement.is_some() || self.issued_dispatch.is_some() {
            return Err(TaskRuntimeError::RetirementDispatchPending);
        }
        let current = self
            .scheduler
            .current()
            .ok_or(TaskRuntimeError::NoCurrentTask)?;
        let slot = self
            .domain_slot(current)
            .map_err(|_| TaskRuntimeError::IntegrityFailure)?;
        let termination_plan = self
            .scheduler
            .prepare_current_termination()
            .map_err(TaskRuntimeError::Scheduler)?;
        let peer_plan = self.prepare_peer_death_publication(
            self.domains[slot]
                .as_ref()
                .ok_or(TaskRuntimeError::IntegrityFailure)?,
        )?;
        self.revoke_task_delegations(current)?;
        let domain = self.domains[slot]
            .take()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        self.commit_peer_death_publication(peer_plan, domain.task, PeerDeathReason::Exited);
        let next = self.scheduler.commit_current_termination(termination_plan);
        let termination = TaskTermination {
            task: current,
            next,
        };
        self.pending_retirement = Some(PendingRetirement::Termination(termination));
        Ok((termination, domain.context))
    }

    /// Atomically derives a bounded capability set into a fresh task domain for
    /// kernel-owned construction and records every parent/child edge for
    /// transitive revocation.
    ///
    /// This is not an IPC shortcut: it accepts no payload or endpoint and only
    /// an otherwise pristine destination domain. Source handles must carry
    /// `DELEGATE`; the requested rights become the exact target handles.
    pub fn project_capabilities_for_construction(
        &mut self,
        source_task: TaskId,
        target_task: TaskId,
        requested: &[(Capability, Rights)],
    ) -> Result<Message, TaskRuntimeError> {
        if source_task == target_task {
            return Err(TaskRuntimeError::SameTaskIpc);
        }
        if requested.is_empty() {
            return Err(TaskRuntimeError::Ipc(IpcError::CapabilityShape));
        }
        Message::validate_shape(0, requested.len()).map_err(TaskRuntimeError::Ipc)?;
        if !self.scheduler.contains(source_task) || !self.scheduler.contains(target_task) {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        let source_slot = self
            .domain_slot(source_task)
            .map_err(|_| TaskRuntimeError::IntegrityFailure)?;
        let target_slot = self
            .domain_slot(target_task)
            .map_err(|_| TaskRuntimeError::IntegrityFailure)?;
        let source = self.domains[source_slot]
            .as_ref()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        source
            .capabilities
            .validate_derivations(requested)
            .map_err(IpcError::from)
            .map_err(TaskRuntimeError::Ipc)?;
        let target = self.domains[target_slot]
            .as_ref()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        if !target.capabilities.is_empty()
            || target.inbox_count != 0
            || target.peers.iter().any(Option::is_some)
            || target.peer_deaths.iter().any(Option::is_some)
            || self.delegations.iter().flatten().any(|delegation| {
                delegation.source_task == target_task || delegation.destination_task == target_task
            })
        {
            return Err(TaskRuntimeError::ConstructionTargetNotPristine);
        }
        target
            .capabilities
            .validate_derivation_capacity(requested.len())
            .map_err(IpcError::from)
            .map_err(TaskRuntimeError::Ipc)?;
        let delegation_slots = self.prepare_delegation_slots(requested.len())?;
        self.validate_delegation_graph()?;
        let (source, target) = two_domains_mut(&mut self.domains, source_slot, target_slot)
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        let message = Message::transfer(
            &[],
            requested,
            &source.capabilities,
            &mut target.capabilities,
        )
        .map_err(TaskRuntimeError::Ipc)?;
        for (((source, _), destination), slot) in requested
            .iter()
            .zip(message.capabilities())
            .zip(delegation_slots)
        {
            self.delegations[slot] = Some(Delegation {
                source_task,
                source: *source,
                destination_task: target_task,
                destination,
            });
        }
        Ok(message)
    }

    /// Atomically attenuates a bounded capability set inside one live domain
    /// while recording the same revocation ancestry used for IPC projections.
    /// This is the kernel-owned path for splitting a broad construction root
    /// into narrow source handles before a fresh target domain is populated.
    pub fn derive_capabilities_for_construction_source(
        &mut self,
        task: TaskId,
        requested: &[(Capability, Rights)],
    ) -> Result<Message, TaskRuntimeError> {
        if requested.is_empty() {
            return Err(TaskRuntimeError::Ipc(IpcError::CapabilityShape));
        }
        Message::validate_shape(0, requested.len()).map_err(TaskRuntimeError::Ipc)?;
        if !self.scheduler.contains(task) {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        let slot = self
            .domain_slot(task)
            .map_err(|_| TaskRuntimeError::IntegrityFailure)?;
        let domain = self.domains[slot]
            .as_ref()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        domain
            .capabilities
            .validate_derivations(requested)
            .map_err(IpcError::from)
            .map_err(TaskRuntimeError::Ipc)?;
        domain
            .capabilities
            .validate_derivation_capacity(requested.len())
            .map_err(IpcError::from)
            .map_err(TaskRuntimeError::Ipc)?;
        let delegation_slots = self.prepare_delegation_slots(requested.len())?;
        self.validate_delegation_graph()?;
        let mut derived = [None; crate::MAX_CAPABILITIES];
        self.domains[slot]
            .as_mut()
            .expect("validated live domain remains present")
            .capabilities
            .derive_local_batch(requested, &mut derived[..requested.len()])
            .expect("complete local derivation was preflighted");
        let message = Message::from_derived_capabilities(&derived[..requested.len()])
            .expect("preflighted derived capability shape is canonical");
        for (((source, _), destination), edge_slot) in requested
            .iter()
            .zip(message.capabilities())
            .zip(delegation_slots)
        {
            self.delegations[edge_slot] = Some(Delegation {
                source_task: task,
                source: *source,
                destination_task: task,
                destination,
            });
        }
        Ok(message)
    }

    /// Transfers a message and attenuated capabilities between two distinct
    /// task domains. Endpoint authority and sequence capacity are reserved
    /// before receiver capability state changes.
    pub fn send_ipc(
        &mut self,
        sender: TaskId,
        receiver: TaskId,
        endpoint: &mut Endpoint,
        endpoint_capability: Capability,
        payload: &[u8],
        requested: &[(Capability, Rights)],
    ) -> Result<(u64, Message), TaskRuntimeError> {
        if sender == receiver {
            return Err(TaskRuntimeError::SameTaskIpc);
        }
        if !self.scheduler.contains(sender) {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        let sender_slot = self
            .domain_slot(sender)
            .map_err(|_| TaskRuntimeError::IntegrityFailure)?;
        let send_plan = endpoint
            .prepare_send(
                &self.domains[sender_slot]
                    .as_ref()
                    .ok_or(TaskRuntimeError::IntegrityFailure)?
                    .capabilities,
                endpoint_capability,
            )
            .map_err(TaskRuntimeError::Ipc)?;
        self.send_ipc_prepared(
            sender,
            receiver,
            endpoint,
            endpoint_capability,
            send_plan,
            payload,
            requested,
        )
    }

    fn send_ipc_prepared(
        &mut self,
        sender: TaskId,
        receiver: TaskId,
        endpoint: &mut Endpoint,
        endpoint_capability: Capability,
        send_plan: EndpointSendPlan,
        payload: &[u8],
        requested: &[(Capability, Rights)],
    ) -> Result<(u64, Message), TaskRuntimeError> {
        Message::validate_shape(payload.len(), requested.len()).map_err(TaskRuntimeError::Ipc)?;
        if !self.scheduler.contains(sender) {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        let sender_slot = self
            .domain_slot(sender)
            .map_err(|_| TaskRuntimeError::IntegrityFailure)?;
        self.domains[sender_slot]
            .as_ref()
            .ok_or(TaskRuntimeError::IntegrityFailure)?
            .capabilities
            .validate_derivations(requested)
            .map_err(IpcError::from)
            .map_err(TaskRuntimeError::Ipc)?;
        if !self.scheduler.contains(receiver) {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        let receiver_slot = self
            .domain_slot(receiver)
            .map_err(|_| TaskRuntimeError::IntegrityFailure)?;
        self.domains[receiver_slot]
            .as_ref()
            .ok_or(TaskRuntimeError::IntegrityFailure)?
            .capabilities
            .validate_derivation_capacity(requested.len())
            .map_err(IpcError::from)
            .map_err(TaskRuntimeError::Ipc)?;
        let delegation_slots = self.prepare_delegation_slots(requested.len())?;
        self.validate_delegation_graph()?;
        let (source, destination) = two_domains_mut(&mut self.domains, sender_slot, receiver_slot)
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        let delegations = &mut self.delegations;
        let (sequence, message) = endpoint
            .commit_send_with(send_plan, endpoint_capability, || {
                let message = Message::transfer(
                    payload,
                    requested,
                    &source.capabilities,
                    &mut destination.capabilities,
                )?;
                for (((source, _), destination), slot) in requested
                    .iter()
                    .zip(message.capabilities())
                    .zip(delegation_slots)
                {
                    delegations[slot] = Some(Delegation {
                        source_task: sender,
                        source: *source,
                        destination_task: receiver,
                        destination,
                    });
                }
                Ok(message)
            })
            .map_err(|error| match error {
                IpcError::InvalidSequencePlan => TaskRuntimeError::IntegrityFailure,
                error => TaskRuntimeError::Ipc(error),
            })?;
        Ok((sequence, message))
    }

    /// Delivers into the receiver's bounded kernel-owned inbox and makes a
    /// blocked receiver runnable. Capacity is checked before endpoint sequence
    /// or capability state changes.
    pub fn deliver_ipc(
        &mut self,
        sender: TaskId,
        receiver: TaskId,
        endpoint: &mut Endpoint,
        endpoint_capability: Capability,
        payload: &[u8],
        requested: &[(Capability, Rights)],
    ) -> Result<u64, TaskRuntimeError> {
        if !self.scheduler.contains(sender) {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        let sender_slot = self
            .domain_slot(sender)
            .map_err(|_| TaskRuntimeError::IntegrityFailure)?;
        let send_plan = endpoint
            .prepare_send(
                &self.domains[sender_slot]
                    .as_ref()
                    .ok_or(TaskRuntimeError::IntegrityFailure)?
                    .capabilities,
                endpoint_capability,
            )
            .map_err(TaskRuntimeError::Ipc)?;
        if sender == receiver {
            return Err(TaskRuntimeError::SameTaskIpc);
        }
        Message::validate_shape(payload.len(), requested.len()).map_err(TaskRuntimeError::Ipc)?;
        self.domains[sender_slot]
            .as_ref()
            .ok_or(TaskRuntimeError::IntegrityFailure)?
            .capabilities
            .validate_derivations(requested)
            .map_err(IpcError::from)
            .map_err(TaskRuntimeError::Ipc)?;
        let receiver_slot = self.domain_slot(receiver)?;
        if !self.scheduler.contains(receiver) {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        self.domains[receiver_slot]
            .as_ref()
            .ok_or(TaskRuntimeError::IntegrityFailure)?
            .capabilities
            .validate_derivation_capacity(requested.len())
            .map_err(IpcError::from)
            .map_err(TaskRuntimeError::Ipc)?;
        let _ = self.prepare_delegation_slots(requested.len())?;
        let inbox_plan = self.prepare_inbox_delivery(receiver_slot)?;
        let wake_plan = self
            .scheduler
            .prepare_wake(receiver)
            .map_err(TaskRuntimeError::Scheduler)?;
        let (sequence, message) = self.send_ipc_prepared(
            sender,
            receiver,
            endpoint,
            endpoint_capability,
            send_plan,
            payload,
            requested,
        )?;
        let domain = self.domains[receiver_slot]
            .as_mut()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        domain.inbox[inbox_plan.slot] = Some(ReceivedMessage {
            sender,
            sequence,
            message,
        });
        domain.inbox_tail = inbox_plan.next_tail;
        domain.inbox_count = inbox_plan.next_count;
        self.scheduler.commit_wake(wake_plan);
        Ok(sequence)
    }

    pub fn receive_ipc(&mut self, task: TaskId) -> Result<Message, TaskRuntimeError> {
        let slot = self.domain_slot(task)?;
        if !self.scheduler.contains(task) {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        let domain = self.domains[slot]
            .as_mut()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        Self::validate_inbox_state(domain)?;
        if domain.inbox_count == 0 {
            return Err(TaskRuntimeError::InboxEmpty);
        }
        let head = usize::from(domain.inbox_head);
        let message = domain.inbox[head]
            .take()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        domain.inbox_head = ((head + 1) % TASK_INBOX_MESSAGES) as u8;
        domain.inbox_count -= 1;
        Ok(message.into_message())
    }

    /// Consumes the next message only when both caller-supplied output
    /// capacities cover its complete bounded shape.
    pub fn receive_ipc_bounded(
        &mut self,
        task: TaskId,
        payload_capacity: usize,
        capability_capacity: usize,
    ) -> Result<Message, TaskRuntimeError> {
        let shape = self.peek_ipc_shape(task)?;
        if shape.payload_length > payload_capacity || shape.capability_count > capability_capacity {
            return Err(TaskRuntimeError::ReceiveCapacity);
        }
        self.receive_ipc(task)
    }

    /// Returns only the bounded shape of the next queued message without
    /// exposing its contents, capabilities, or consuming the inbox entry.
    pub fn peek_ipc_shape(&self, task: TaskId) -> Result<QueuedMessageShape, TaskRuntimeError> {
        let slot = self.domain_slot(task)?;
        if !self.scheduler.contains(task) {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        let domain = self.domains[slot]
            .as_ref()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        Self::validate_inbox_state(domain)?;
        if domain.inbox_count == 0 {
            return Err(TaskRuntimeError::InboxEmpty);
        }
        let head = usize::from(domain.inbox_head);
        let message = domain.inbox[head]
            .as_ref()
            .ok_or(TaskRuntimeError::IntegrityFailure)?
            .message();
        Ok(QueuedMessageShape {
            payload_length: message.payload().len(),
            capability_count: message.capability_count(),
        })
    }

    fn validate_inbox_state(domain: &TaskDomain<CAPS>) -> Result<(), TaskRuntimeError> {
        let count = usize::from(domain.inbox_count);
        let head = usize::from(domain.inbox_head);
        let tail = usize::from(domain.inbox_tail);
        if count > TASK_INBOX_MESSAGES
            || head >= TASK_INBOX_MESSAGES
            || tail >= TASK_INBOX_MESSAGES
            || tail != (head + count) % TASK_INBOX_MESSAGES
        {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        for offset in 0..TASK_INBOX_MESSAGES {
            let slot = (head + offset) % TASK_INBOX_MESSAGES;
            if domain.inbox[slot].is_some() != (offset < count) {
                return Err(TaskRuntimeError::IntegrityFailure);
            }
        }
        Ok(())
    }

    fn prepare_inbox_delivery(
        &self,
        receiver_slot: usize,
    ) -> Result<InboxDeliveryPlan, TaskRuntimeError> {
        let domain = self.domains[receiver_slot]
            .as_ref()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        Self::validate_inbox_state(domain)?;
        if usize::from(domain.inbox_count) == TASK_INBOX_MESSAGES {
            return Err(TaskRuntimeError::InboxFull);
        }
        let slot = usize::from(domain.inbox_tail);
        Ok(InboxDeliveryPlan {
            slot,
            next_tail: ((slot + 1) % TASK_INBOX_MESSAGES) as u8,
            next_count: domain.inbox_count + 1,
        })
    }

    /// Links two live domains for typed lifecycle notification. The relation is
    /// symmetric, bounded, and exact-generation; it is committed only after
    /// both peer tables have capacity. Linked domains cannot migrate until the
    /// relation and any pending death result have been consumed.
    pub fn connect_control_peers(
        &mut self,
        first: TaskId,
        second: TaskId,
        endpoint: &Endpoint,
        first_capability: Capability,
        second_capability: Capability,
    ) -> Result<(), TaskRuntimeError> {
        if first == second {
            return Err(TaskRuntimeError::SameTaskIpc);
        }
        if !self.scheduler.contains(first) || !self.scheduler.contains(second) {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        let first_slot = self.domain_slot(first)?;
        let second_slot = self.domain_slot(second)?;
        self.validate_control_topology(
            self.domains[first_slot]
                .as_ref()
                .ok_or(TaskRuntimeError::IntegrityFailure)?,
        )?;
        self.validate_control_topology(
            self.domains[second_slot]
                .as_ref()
                .ok_or(TaskRuntimeError::IntegrityFailure)?,
        )?;
        let (first_domain, second_domain) =
            two_domains_mut(&mut self.domains, first_slot, second_slot)
                .ok_or(TaskRuntimeError::IntegrityFailure)?;
        endpoint
            .authorize_member(&first_domain.capabilities, first_capability)
            .map_err(TaskRuntimeError::Ipc)?;
        endpoint
            .authorize_member(&second_domain.capabilities, second_capability)
            .map_err(TaskRuntimeError::Ipc)?;
        let first_has = first_domain.peers.contains(&Some(second));
        let second_has = second_domain.peers.contains(&Some(first));
        if first_has != second_has {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        if first_has {
            return Ok(());
        }
        let first_used = first_domain.peers.iter().flatten().count()
            + first_domain.peer_deaths.iter().flatten().count();
        let second_used = second_domain.peers.iter().flatten().count()
            + second_domain.peer_deaths.iter().flatten().count();
        if first_used == TASK_CONTROL_PEERS || second_used == TASK_CONTROL_PEERS {
            return Err(TaskRuntimeError::PeerTableFull);
        }
        let first_peer_slot = first_domain
            .peers
            .iter()
            .position(Option::is_none)
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        let second_peer_slot = second_domain
            .peers
            .iter()
            .position(Option::is_none)
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        first_domain.peers[first_peer_slot] = Some(second);
        second_domain.peers[second_peer_slot] = Some(first);
        Ok(())
    }

    pub fn receive_control(&mut self, task: TaskId) -> Result<ControlEvent, TaskRuntimeError> {
        let slot = self.domain_slot(task)?;
        if !self.scheduler.contains(task) {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        self.validate_control_topology(
            self.domains[slot]
                .as_ref()
                .ok_or(TaskRuntimeError::IntegrityFailure)?,
        )?;
        let domain = self.domains[slot]
            .as_mut()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        Self::validate_inbox_state(domain)?;
        if let Some(death) = domain.peer_deaths.iter_mut().find_map(Option::take) {
            return Ok(ControlEvent::PeerDied(death));
        }
        if domain.inbox_count == 0 {
            return Err(TaskRuntimeError::InboxEmpty);
        }
        let head = usize::from(domain.inbox_head);
        let message = domain.inbox[head]
            .take()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        domain.inbox_head = ((head + 1) % TASK_INBOX_MESSAGES) as u8;
        domain.inbox_count -= 1;
        Ok(ControlEvent::Message(message))
    }

    pub fn receive_control_or_block_current(
        &mut self,
    ) -> Result<Result<ControlEvent, ScheduleOutcome>, TaskRuntimeError> {
        let current = self
            .scheduler
            .current()
            .ok_or(TaskRuntimeError::NoCurrentTask)?;
        match self.receive_control(current) {
            Ok(event) => Ok(Ok(event)),
            Err(TaskRuntimeError::InboxEmpty) => self
                .scheduler
                .block_current()
                .map(Err)
                .map_err(TaskRuntimeError::Scheduler),
            Err(error) => Err(error),
        }
    }

    fn domain_slot(&self, task: TaskId) -> Result<usize, TaskRuntimeError> {
        let mut matches = self
            .domains
            .iter()
            .enumerate()
            .filter_map(|(slot, domain)| {
                domain
                    .as_ref()
                    .is_some_and(|domain| domain.task == task)
                    .then_some(slot)
            });
        let slot = matches.next().ok_or(TaskRuntimeError::MissingTask)?;
        if matches.next().is_some() {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        Ok(slot)
    }

    fn prepare_peer_death_publication(
        &self,
        retired: &TaskDomain<CAPS>,
    ) -> Result<PeerDeathPublicationSet, TaskRuntimeError> {
        Self::validate_control_state(retired)?;
        let mut plan = array::from_fn(|_| None);
        let mut count = 0usize;
        for (index, peer) in retired.peers.iter().enumerate() {
            let Some(peer) = *peer else {
                continue;
            };
            if retired.peers[..index].contains(&Some(peer)) {
                return Err(TaskRuntimeError::IntegrityFailure);
            }
            if !self.scheduler.contains(peer) {
                return Err(TaskRuntimeError::IntegrityFailure);
            }
            let domain_slot = self.domain_slot(peer)?;
            let domain = self.domains[domain_slot]
                .as_ref()
                .ok_or(TaskRuntimeError::IntegrityFailure)?;
            Self::validate_control_state(domain)?;
            let mut relations = domain
                .peers
                .iter()
                .enumerate()
                .filter_map(|(slot, candidate)| (*candidate == Some(retired.task)).then_some(slot));
            let relation_slot = relations.next().ok_or(TaskRuntimeError::IntegrityFailure)?;
            if relations.next().is_some() {
                return Err(TaskRuntimeError::IntegrityFailure);
            }
            let death_slot = domain
                .peer_deaths
                .iter()
                .position(Option::is_none)
                .ok_or(TaskRuntimeError::IntegrityFailure)?;
            let wake = self
                .scheduler
                .prepare_wake(peer)
                .map_err(TaskRuntimeError::Scheduler)?;
            plan[count] = Some(PeerDeathPublicationPlan {
                domain_slot,
                relation_slot,
                death_slot,
                wake,
            });
            count += 1;
        }
        Ok(plan)
    }

    fn commit_peer_death_publication(
        &mut self,
        plan: PeerDeathPublicationSet,
        retired: TaskId,
        reason: PeerDeathReason,
    ) {
        for publication in plan.into_iter().flatten() {
            let domain = self.domains[publication.domain_slot]
                .as_mut()
                .expect("runtime preserves every prepared peer domain");
            let relation = &mut domain.peers[publication.relation_slot];
            assert_eq!(*relation, Some(retired));
            *relation = None;
            let death_slot = &mut domain.peer_deaths[publication.death_slot];
            assert!(death_slot.is_none());
            *death_slot = Some(PeerDeath {
                peer: retired,
                reason,
            });
            self.scheduler.commit_wake(publication.wake);
        }
    }

    fn validate_control_state(domain: &TaskDomain<CAPS>) -> Result<(), TaskRuntimeError> {
        let peers = domain.peers.iter().flatten().count();
        let deaths = domain.peer_deaths.iter().flatten().count();
        if peers + deaths > TASK_CONTROL_PEERS {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        for (index, peer) in domain.peers.iter().enumerate() {
            let Some(peer) = *peer else {
                continue;
            };
            if domain.peers[..index].contains(&Some(peer))
                || domain
                    .peer_deaths
                    .iter()
                    .flatten()
                    .any(|death| death.peer == peer)
            {
                return Err(TaskRuntimeError::IntegrityFailure);
            }
        }
        for (index, death) in domain.peer_deaths.iter().enumerate() {
            let Some(death) = *death else {
                continue;
            };
            if domain.peer_deaths[..index]
                .iter()
                .flatten()
                .any(|prior| prior.peer == death.peer)
            {
                return Err(TaskRuntimeError::IntegrityFailure);
            }
        }
        Ok(())
    }

    fn validate_control_topology(&self, domain: &TaskDomain<CAPS>) -> Result<(), TaskRuntimeError> {
        Self::validate_control_state(domain)?;
        for death in domain.peer_deaths.iter().flatten() {
            if death.peer == domain.task
                || self.scheduler.contains(death.peer)
                || !matches!(
                    self.domain_slot(death.peer),
                    Err(TaskRuntimeError::MissingTask)
                )
            {
                return Err(TaskRuntimeError::IntegrityFailure);
            }
        }
        for peer in domain.peers.iter().flatten().copied() {
            if !self.scheduler.contains(peer) {
                return Err(TaskRuntimeError::IntegrityFailure);
            }
            let slot = self.domain_slot(peer)?;
            let peer_domain = self.domains[slot]
                .as_ref()
                .ok_or(TaskRuntimeError::IntegrityFailure)?;
            Self::validate_control_state(peer_domain)?;
            if peer_domain
                .peers
                .iter()
                .filter(|candidate| **candidate == Some(domain.task))
                .count()
                != 1
            {
                return Err(TaskRuntimeError::IntegrityFailure);
            }
        }
        Ok(())
    }

    fn prepare_delegation_slots(
        &self,
        requested: usize,
    ) -> Result<[usize; crate::MAX_CAPABILITIES], TaskRuntimeError> {
        if requested > crate::MAX_CAPABILITIES {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        let mut slots = [0; crate::MAX_CAPABILITIES];
        let mut count = 0;
        for (index, edge) in self.delegations.iter().enumerate() {
            if edge.is_some() || count == requested {
                continue;
            }
            slots[count] = index;
            count += 1;
        }
        if count != requested {
            return Err(TaskRuntimeError::DelegationTableFull);
        }
        Ok(slots)
    }

    fn validate_delegation_graph(&self) -> Result<(), TaskRuntimeError> {
        let mut parents = [None; MAX_TASK_DELEGATIONS];
        for (index, edge) in self.delegations.iter().enumerate() {
            let Some(edge) = *edge else {
                continue;
            };
            if !self.scheduler.contains(edge.source_task)
                || !self.scheduler.contains(edge.destination_task)
                || self.delegations[..index].iter().flatten().any(|prior| {
                    prior.destination_task == edge.destination_task
                        && prior.destination == edge.destination
                })
            {
                return Err(TaskRuntimeError::IntegrityFailure);
            }
            let (source_object, source_rights) = self
                .capabilities(edge.source_task)?
                .describe(edge.source)
                .map_err(|_| TaskRuntimeError::IntegrityFailure)?;
            let (destination_object, destination_rights) = self
                .capabilities(edge.destination_task)?
                .describe(edge.destination)
                .map_err(|_| TaskRuntimeError::IntegrityFailure)?;
            if source_object != destination_object
                || !source_rights.contains(Rights::DELEGATE)
                || !source_rights.contains(destination_rights)
            {
                return Err(TaskRuntimeError::IntegrityFailure);
            }
            parents[index] = self.delegations.iter().position(|candidate| {
                candidate.is_some_and(|candidate| {
                    (candidate.destination_task, candidate.destination)
                        == (edge.source_task, edge.source)
                })
            });
        }
        for (index, edge) in self.delegations.iter().enumerate() {
            if edge.is_none() {
                continue;
            }
            let mut ancestor = Some(index);
            for _ in 0..MAX_TASK_DELEGATIONS {
                let Some(current) = ancestor else {
                    break;
                };
                ancestor = parents[current];
            }
            if ancestor.is_some() {
                return Err(TaskRuntimeError::IntegrityFailure);
            }
        }
        Ok(())
    }

    pub fn receive_or_block_current(
        &mut self,
    ) -> Result<Result<Message, ScheduleOutcome>, TaskRuntimeError> {
        let current = self
            .scheduler
            .current()
            .ok_or(TaskRuntimeError::NoCurrentTask)?;
        match self.receive_ipc(current) {
            Ok(message) => Ok(Ok(message)),
            Err(TaskRuntimeError::InboxEmpty) => self
                .scheduler
                .block_current()
                .map(Err)
                .map_err(TaskRuntimeError::Scheduler),
            Err(error) => Err(error),
        }
    }
}

fn two_domains_mut<const TASKS: usize, const CAPS: usize>(
    domains: &mut [Option<TaskDomain<CAPS>>; TASKS],
    first: usize,
    second: usize,
) -> Option<(&mut TaskDomain<CAPS>, &mut TaskDomain<CAPS>)> {
    if first == second || first >= TASKS || second >= TASKS {
        return None;
    }
    if first < second {
        let (left, right) = domains.split_at_mut(second);
        Some((left[first].as_mut()?, right[0].as_mut()?))
    } else {
        let (left, right) = domains.split_at_mut(first);
        Some((right[0].as_mut()?, left[second].as_mut()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapabilityError, ObjectId, OwnershipMailbox, PhysAddr, Rights};

    fn context(root: u64, entry: u64) -> UserContext {
        UserContext::new(PhysAddr::new(root).unwrap(), entry, 0x0000_7000_0000_0000).unwrap()
    }

    const KERNEL_POOL_RIGHTS: Rights = Rights::ALLOCATE.union(Rights::INSPECT);

    #[test]
    fn send_denial_classification_excludes_integrity_and_unrelated_failures() {
        for error in [
            TaskRuntimeError::MissingTask,
            TaskRuntimeError::SameTaskIpc,
            TaskRuntimeError::Ipc(IpcError::Unauthorized),
            TaskRuntimeError::InboxFull,
            TaskRuntimeError::DelegationTableFull,
        ] {
            assert!(error.is_precommit_send_denial());
        }
        for error in [
            TaskRuntimeError::Full,
            TaskRuntimeError::NoCurrentTask,
            TaskRuntimeError::AddressSpaceMismatch,
            TaskRuntimeError::IntegrityFailure,
            TaskRuntimeError::ActiveDelegations,
            TaskRuntimeError::Ipc(IpcError::InvalidSequencePlan),
            TaskRuntimeError::Ipc(IpcError::Malformed),
            TaskRuntimeError::Ipc(IpcError::Replay),
            TaskRuntimeError::Ipc(IpcError::CapabilityShape),
            TaskRuntimeError::Ipc(IpcError::BufferTooSmall),
        ] {
            assert!(!error.is_precommit_send_denial());
        }
    }

    #[test]
    fn accounted_runtime_charges_complete_fixed_ipc_footprint_until_release() {
        let pages = AccountedTaskRuntime::<2, 4>::required_pages().unwrap();
        let mut memory = MemoryPoolTable::<1, 1>::new(21).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = memory
            .create_root(pages, 1, 0, KERNEL_POOL_RIGHTS, &mut authorities)
            .unwrap();
        let mut runtime = AccountedTaskRuntime::<2, 4>::new(
            1_000,
            1,
            pool,
            pool_capability,
            &mut memory,
            &mut authorities,
        )
        .unwrap();
        assert_eq!(runtime.committed_pages(), pages);
        assert_eq!(memory.object_pool(runtime.charge()), Ok(pool));
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .object_pages(),
            pages
        );
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_object = ObjectId(0x100);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let mut endpoint = Endpoint::new(endpoint_object);
        runtime
            .deliver_ipc(
                sender,
                receiver,
                &mut endpoint,
                endpoint_capability,
                b"first",
                &[],
            )
            .unwrap();
        runtime
            .deliver_ipc(
                sender,
                receiver,
                &mut endpoint,
                endpoint_capability,
                b"second",
                &[],
            )
            .unwrap();
        assert_eq!(
            runtime.deliver_ipc(
                sender,
                receiver,
                &mut endpoint,
                endpoint_capability,
                b"full",
                &[],
            ),
            Err(TaskRuntimeError::InboxFull)
        );
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            pages
        );
        assert!(matches!(
            runtime.release(&mut memory, &mut authorities),
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

    #[test]
    fn insufficient_runtime_commitment_fails_without_publishing_or_charging() {
        let pages = AccountedTaskRuntime::<1, 2>::required_pages().unwrap();
        assert!(pages > 1);
        let mut memory = MemoryPoolTable::<1, 1>::new(22).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = memory
            .create_root(pages - 1, 1, 0, KERNEL_POOL_RIGHTS, &mut authorities)
            .unwrap();
        assert!(matches!(
            AccountedTaskRuntime::<1, 2>::new(
                1_000,
                1,
                pool,
                pool_capability,
                &mut memory,
                &mut authorities,
            ),
            Err(AccountedTaskRuntimeError::Memory(
                MemoryResourceError::PoolExhausted
            ))
        ));
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            0
        );
    }

    #[test]
    fn failed_runtime_release_returns_the_live_runtime_and_retains_its_charge() {
        let pages = AccountedTaskRuntime::<1, 2>::required_pages().unwrap();
        let mut memory = MemoryPoolTable::<1, 1>::new(23).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = memory
            .create_root(pages, 1, 0, KERNEL_POOL_RIGHTS, &mut authorities)
            .unwrap();
        let runtime = AccountedTaskRuntime::<1, 2>::new(
            1_000,
            1,
            pool,
            pool_capability,
            &mut memory,
            &mut authorities,
        )
        .unwrap();
        authorities.revoke(runtime.charge_capability).unwrap();
        let retained = match runtime.release(&mut memory, &mut authorities) {
            Err((runtime, MemoryResourceError::Capability(CapabilityError::Invalid))) => runtime,
            _ => panic!("revoked charge authority must fail closed"),
        };
        assert_eq!(retained.committed_pages(), pages);
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            pages
        );
    }

    #[test]
    fn user_fault_revokes_domain_before_selecting_replacement() {
        let mut runtime = TaskRuntime::<2, 3>::new(1_000, 1).unwrap();
        let faulted = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let replacement = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let stale_capability = runtime
            .capabilities_mut(faulted)
            .unwrap()
            .insert(ObjectId(7), Rights::READ)
            .unwrap();
        assert_eq!(
            runtime.start(),
            ScheduleOutcome::Switch {
                from: None,
                to: faulted
            }
        );

        let retired = runtime
            .terminate_current_fault(TrapDisposition::TerminateUser {
                vector: 6,
                address: None,
            })
            .unwrap();
        assert_eq!(retired.task, faulted);
        assert_eq!(retired.vector, 6);
        assert_eq!(
            retired.next,
            ScheduleOutcome::Switch {
                from: Some(faulted),
                to: replacement
            }
        );
        assert_eq!(runtime.context(faulted), Err(TaskRuntimeError::MissingTask));
        assert_eq!(
            runtime.capabilities_mut(faulted).map(|_| ()),
            Err(TaskRuntimeError::MissingTask)
        );
        let _ = stale_capability;
        assert_eq!(
            runtime.context(replacement).unwrap().instruction_pointer(),
            0x50_0000
        );
        assert_eq!(
            runtime.timer_tick(),
            Err(TaskRuntimeError::RetirementDispatchPending)
        );
        assert_eq!(
            runtime.context_mut(replacement).map(|_| ()),
            Err(TaskRuntimeError::RetirementDispatchPending)
        );
        assert_eq!(
            runtime.dispatch_after_fault(FaultRetirement {
                vector: 13,
                ..retired
            }),
            Err(TaskTerminationDispatchError::FaultMismatch)
        );
        let dispatch = runtime.dispatch_after_fault(retired).unwrap();
        assert_eq!(
            dispatch.user(),
            Some((replacement, context(0x30_0000, 0x50_0000)))
        );
        assert_eq!(
            runtime.dispatch_after_fault(retired),
            Err(TaskTerminationDispatchError::DispatchOutstanding)
        );
    }

    #[test]
    fn kernel_fault_cannot_retire_a_user_domain() {
        let mut runtime = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        runtime.start();
        assert_eq!(
            runtime.terminate_current_fault(TrapDisposition::HaltKernel { vector: 13 }),
            Err(TaskRuntimeError::NonRecoverableFault)
        );
        assert!(runtime.context(task).is_ok());
    }

    #[test]
    fn voluntary_exit_revokes_domain_before_switching() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let exiting = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let replacement = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let capability = runtime
            .capabilities_mut(exiting)
            .unwrap()
            .insert(ObjectId(17), Rights::READ)
            .unwrap();
        assert!(matches!(
            runtime.start(),
            ScheduleOutcome::Switch { to, .. } if to == exiting
        ));
        let terminated = runtime.terminate_current().unwrap();
        assert_eq!(terminated.task, exiting);
        assert_eq!(
            terminated.next,
            ScheduleOutcome::Switch {
                from: Some(exiting),
                to: replacement,
            }
        );
        assert_eq!(
            runtime.terminate_current(),
            Err(TaskRuntimeError::RetirementDispatchPending)
        );
        assert_eq!(
            runtime.yield_current(),
            Err(TaskRuntimeError::RetirementDispatchPending)
        );
        assert_eq!(
            runtime.timer_tick(),
            Err(TaskRuntimeError::RetirementDispatchPending)
        );
        assert_eq!(
            runtime.preempt_current(context(0x30_0000, 0x50_0000)),
            Err(TaskRuntimeError::RetirementDispatchPending)
        );
        assert!(matches!(
            runtime.detach_domain(replacement),
            Err(TaskRuntimeError::RetirementDispatchPending)
        ));
        let load = runtime.load();
        assert!(matches!(
            runtime.detach_domain_for_rebalance(load),
            Err(TaskRuntimeError::RetirementDispatchPending)
        ));
        let mut migration = None;
        assert!(matches!(
            runtime.attach_domain(&mut migration),
            Err(TaskRuntimeError::RetirementDispatchPending)
        ));
        assert_eq!(
            runtime.context_mut(replacement).map(|_| ()),
            Err(TaskRuntimeError::RetirementDispatchPending)
        );
        assert_eq!(
            runtime.dispatch_after_termination(TaskTermination {
                task: exiting,
                next: ScheduleOutcome::Continue(replacement),
            }),
            Err(TaskTerminationDispatchError::InvalidOutcome)
        );
        assert_eq!(
            runtime.dispatch_after_termination(TaskTermination {
                task: exiting,
                next: ScheduleOutcome::Switch {
                    from: Some(replacement),
                    to: replacement,
                },
            }),
            Err(TaskTerminationDispatchError::WrongSource)
        );
        assert_eq!(
            runtime.dispatch_after_termination(TaskTermination {
                task: exiting,
                next: ScheduleOutcome::Switch {
                    from: Some(exiting),
                    to: exiting,
                },
            }),
            Err(TaskTerminationDispatchError::CurrentMismatch)
        );
        assert_eq!(
            runtime.dispatch_after_termination(TaskTermination {
                task: replacement,
                next: ScheduleOutcome::Switch {
                    from: Some(replacement),
                    to: replacement,
                },
            }),
            Err(TaskTerminationDispatchError::TerminationMismatch)
        );
        let issued = runtime.dispatch_after_termination(terminated).unwrap();
        let mut dispatch = match runtime.consume_idle_dispatch(issued) {
            Err(dispatch) => dispatch,
            Ok(_) => panic!("user dispatch must not consume as idle"),
        };
        assert!(!dispatch.is_idle());
        assert_eq!(
            dispatch.user(),
            Some((replacement, context(0x30_0000, 0x50_0000)))
        );
        assert_eq!(
            runtime.dispatch_after_termination(terminated),
            Err(TaskTerminationDispatchError::DispatchOutstanding)
        );
        assert_eq!(
            runtime.timer_tick(),
            Err(TaskRuntimeError::RetirementDispatchPending)
        );
        assert_eq!(
            runtime.yield_current(),
            Err(TaskRuntimeError::RetirementDispatchPending)
        );
        assert_eq!(
            runtime.preempt_current(context(0x30_0000, 0x50_0000)),
            Err(TaskRuntimeError::RetirementDispatchPending)
        );
        assert_eq!(
            runtime.terminate_current(),
            Err(TaskRuntimeError::RetirementDispatchPending)
        );
        assert_eq!(
            runtime.context_mut(replacement).map(|_| ()),
            Err(TaskRuntimeError::RetirementDispatchPending)
        );
        let mut other_runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        assert_eq!(
            dispatch
                .user_context_mut(&mut other_runtime, replacement)
                .map(|_| ()),
            Err(TaskTerminationDispatchError::DispatchIdentityMismatch)
        );
        assert_eq!(
            dispatch.user_context_mut(&mut runtime, exiting).map(|_| ()),
            Err(TaskTerminationDispatchError::CurrentMismatch)
        );
        let refreshed = context(0x30_0000, 0x51_0000);
        *dispatch
            .user_context_mut(&mut runtime, replacement)
            .unwrap() = refreshed;
        dispatch.refresh_from_runtime(&runtime).unwrap();
        assert_eq!(dispatch.user(), Some((replacement, refreshed)));
        assert_eq!(runtime.context(exiting), Err(TaskRuntimeError::MissingTask));
        assert_eq!(
            runtime.capabilities_mut(exiting).map(|_| ()),
            Err(TaskRuntimeError::MissingTask)
        );
        let _ = capability;
    }

    #[test]
    fn termination_dispatch_exact_matches_idle_runtime_state() {
        let mut runtime = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        runtime.start();
        assert_eq!(
            runtime.dispatch_after_termination(TaskTermination {
                task,
                next: ScheduleOutcome::Idle,
            }),
            Err(TaskTerminationDispatchError::CurrentMismatch)
        );
        let termination = runtime.terminate_current().unwrap();
        assert_eq!(termination.next, ScheduleOutcome::Idle);
        let dispatch = runtime.dispatch_after_termination(termination).unwrap();
        assert!(dispatch.is_idle());
        assert_eq!(dispatch.user(), None);
        let replacement = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        assert_eq!(runtime.start(), ScheduleOutcome::Idle);
        assert_eq!(runtime.current(), None);
        let mut other_runtime = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let dispatch = other_runtime
            .consume_idle_dispatch(dispatch)
            .expect_err("another runtime must not consume the issued dispatch");
        assert_eq!(
            runtime.consume_idle_dispatch(dispatch),
            Ok(TaskTerminationIdle { _private: () })
        );
        assert_eq!(
            runtime.dispatch_after_termination(termination),
            Err(TaskTerminationDispatchError::NoPendingTermination)
        );
        assert_eq!(
            runtime.start(),
            ScheduleOutcome::Switch {
                from: None,
                to: replacement,
            }
        );
    }

    #[test]
    fn timer_preemption_saves_only_the_current_address_space() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let first = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let second = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        runtime.start();
        assert_eq!(
            runtime.preempt_current(context(0x30_0000, 0x60_0000)),
            Err(TaskRuntimeError::AddressSpaceMismatch)
        );
        assert_eq!(runtime.ticks(), 0);
        let saved = context(0x20_0000, 0x60_0000);
        assert_eq!(
            runtime.preempt_current(saved),
            Ok(ScheduleOutcome::Switch {
                from: Some(first),
                to: second,
            })
        );
        assert_eq!(
            runtime.context(first).unwrap().instruction_pointer(),
            0x60_0000
        );
    }

    #[test]
    fn ipc_transfer_is_attenuated_and_authorization_denial_is_preflighted() {
        let mut runtime = TaskRuntime::<2, 3>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_object = ObjectId(91);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let delegated = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(ObjectId(7), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let mut endpoint = Endpoint::new(endpoint_object);
        let (sequence, message) = runtime
            .send_ipc(
                sender,
                receiver,
                &mut endpoint,
                endpoint_capability,
                b"read",
                &[(delegated, Rights::READ)],
            )
            .unwrap();
        assert_eq!(sequence, 1);
        assert_eq!(message.payload(), b"read");
        let received = message.capabilities().next().unwrap();
        assert_eq!(
            runtime
                .capabilities_mut(receiver)
                .unwrap()
                .authorize(received, Rights::READ),
            Ok(ObjectId(7))
        );

        let wrong_endpoint = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(ObjectId(92), Rights::SIGNAL)
            .unwrap();
        assert_eq!(
            runtime
                .send_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    wrong_endpoint,
                    b"denied",
                    &[(delegated, Rights::READ)],
                )
                .err(),
            Some(TaskRuntimeError::Ipc(IpcError::Unauthorized))
        );
        // One original received capability plus two free slots proves the
        // denied transfer did not consume receiver authority space.
        let receiver_space = runtime.capabilities_mut(receiver).unwrap();
        assert!(receiver_space.insert(ObjectId(8), Rights::READ).is_ok());
        assert!(receiver_space.insert(ObjectId(9), Rights::READ).is_ok());
        assert_eq!(
            runtime
                .send_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    b"next",
                    &[],
                )
                .unwrap()
                .0,
            2
        );
    }

    #[test]
    fn construction_projection_is_exact_atomic_and_transitively_revocable() {
        let mut runtime = TaskRuntime::<2, 4>::new(1_000, 1).unwrap();
        let source = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let target = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let data = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0x80), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let endpoint = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0x81), Rights::SIGNAL.union(Rights::DELEGATE))
            .unwrap();
        let projection = runtime
            .project_capabilities_for_construction(
                source,
                target,
                &[(data, Rights::READ), (endpoint, Rights::SIGNAL)],
            )
            .unwrap();
        assert!(projection.payload().is_empty());
        assert_eq!(projection.capability_count(), 2);
        let mut capabilities = projection.capabilities();
        let target_data = capabilities.next().unwrap();
        let target_endpoint = capabilities.next().unwrap();
        assert_eq!(capabilities.next(), None);
        assert_eq!(
            runtime
                .capabilities(target)
                .unwrap()
                .authorize_exact(target_data, Rights::READ),
            Ok(ObjectId(0x80))
        );
        assert_eq!(
            runtime
                .capabilities(target)
                .unwrap()
                .authorize_exact(target_endpoint, Rights::SIGNAL),
            Ok(ObjectId(0x81))
        );
        runtime.revoke_capability(source, data).unwrap();
        assert_eq!(
            runtime
                .capabilities(target)
                .unwrap()
                .authorize(target_data, Rights::READ),
            Err(crate::CapabilityError::Invalid)
        );
        assert_eq!(
            runtime
                .capabilities(target)
                .unwrap()
                .authorize_exact(target_endpoint, Rights::SIGNAL),
            Ok(ObjectId(0x81))
        );
    }

    #[test]
    fn construction_source_split_tracks_local_and_cross_domain_descendants() {
        let mut runtime = TaskRuntime::<2, 5>::new(1_000, 1).unwrap();
        let source = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let target = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let root_rights = Rights::MAP
            .union(Rights::READ)
            .union(Rights::WRITE)
            .union(Rights::DELEGATE);
        let root = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0xa0), root_rights)
            .unwrap();
        let local_read_rights = Rights::MAP.union(Rights::READ).union(Rights::DELEGATE);
        let provider_write_rights = Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE);
        let split = runtime
            .derive_capabilities_for_construction_source(
                source,
                &[(root, local_read_rights), (root, provider_write_rights)],
            )
            .unwrap();
        let mut split_handles = split.capabilities();
        let local_read = split_handles.next().unwrap();
        let provider_write = split_handles.next().unwrap();
        assert_eq!(split_handles.next(), None);
        assert_eq!(
            runtime
                .capabilities(source)
                .unwrap()
                .authorize_exact(local_read, local_read_rights),
            Ok(ObjectId(0xa0))
        );
        assert_eq!(
            runtime
                .capabilities(source)
                .unwrap()
                .authorize_exact(provider_write, provider_write_rights),
            Ok(ObjectId(0xa0))
        );
        let projection = runtime
            .project_capabilities_for_construction(
                source,
                target,
                &[
                    (local_read, Rights::MAP.union(Rights::READ)),
                    (provider_write, provider_write_rights),
                ],
            )
            .unwrap();
        let mut projected_handles = projection.capabilities();
        let projected = [
            projected_handles.next().unwrap(),
            projected_handles.next().unwrap(),
        ];
        assert_eq!(projected_handles.next(), None);
        let stale_provider_write =
            Capability::from_token(provider_write.token().wrapping_add(1_u64 << 32));
        assert!(
            runtime
                .revoke_capability_pair(source, local_read, stale_provider_write)
                .is_err()
        );
        assert_eq!(
            runtime
                .capabilities(source)
                .unwrap()
                .authorize(local_read, Rights::READ),
            Ok(ObjectId(0xa0))
        );
        assert_eq!(
            runtime
                .capabilities(target)
                .unwrap()
                .authorize(projected[0], Rights::READ),
            Ok(ObjectId(0xa0))
        );
        runtime
            .revoke_capability_pair(source, local_read, provider_write)
            .unwrap();
        for (task, capability, rights) in [
            (source, local_read, Rights::READ),
            (source, provider_write, Rights::WRITE),
            (target, projected[0], Rights::READ),
            (target, projected[1], Rights::WRITE),
        ] {
            assert_eq!(
                runtime
                    .capabilities(task)
                    .unwrap()
                    .authorize(capability, rights),
                Err(crate::CapabilityError::Invalid)
            );
        }
        assert_eq!(
            runtime
                .capabilities(source)
                .unwrap()
                .authorize_exact(root, root_rights),
            Ok(ObjectId(0xa0))
        );
    }

    #[test]
    fn construction_source_split_preflights_complete_batch_without_partial_handles() {
        let mut runtime = TaskRuntime::<1, 4>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let root = runtime
            .capabilities_mut(task)
            .unwrap()
            .insert(
                ObjectId(0xa0),
                Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE),
            )
            .unwrap();
        let nondelegable = runtime
            .capabilities_mut(task)
            .unwrap()
            .insert(ObjectId(0xa1), Rights::READ)
            .unwrap();
        assert_eq!(
            runtime
                .derive_capabilities_for_construction_source(
                    task,
                    &[(root, Rights::READ), (nondelegable, Rights::READ)],
                )
                .err(),
            Some(TaskRuntimeError::Ipc(IpcError::Unauthorized))
        );
        let capabilities = runtime.capabilities_mut(task).unwrap();
        assert!(capabilities.insert(ObjectId(0xb0), Rights::READ).is_ok());
        assert!(capabilities.insert(ObjectId(0xb1), Rights::WRITE).is_ok());
    }

    #[test]
    fn construction_projection_rejects_nonpristine_or_overbroad_targets_without_partial_authority()
    {
        let mut runtime = TaskRuntime::<3, 3>::new(1_000, 1).unwrap();
        let source = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let clean = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let occupied = runtime
            .create(Priority::NORMAL, context(0x40_0000, 0x60_0000))
            .unwrap();
        let data = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0x80), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        runtime
            .capabilities_mut(occupied)
            .unwrap()
            .insert(ObjectId(0x99), Rights::READ)
            .unwrap();
        assert_eq!(
            runtime
                .project_capabilities_for_construction(source, occupied, &[(data, Rights::READ)],)
                .err(),
            Some(TaskRuntimeError::ConstructionTargetNotPristine)
        );
        assert_eq!(
            runtime
                .project_capabilities_for_construction(source, clean, &[(data, Rights::WRITE)],)
                .err(),
            Some(TaskRuntimeError::Ipc(IpcError::Unauthorized))
        );
        let projection = runtime
            .project_capabilities_for_construction(source, clean, &[(data, Rights::READ)])
            .unwrap();
        let projected = projection.capabilities().next().unwrap();
        assert_eq!(
            runtime
                .capabilities(clean)
                .unwrap()
                .authorize_exact(projected, Rights::READ),
            Ok(ObjectId(0x80))
        );
    }

    #[test]
    fn denied_transfer_leaves_no_delegation_that_blocks_migration() {
        let mut runtime = TaskRuntime::<2, 2>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let wrong_endpoint = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(ObjectId(0x80), Rights::SIGNAL)
            .unwrap();
        let delegated = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(ObjectId(0x81), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let mut endpoint = Endpoint::new(ObjectId(0x82));

        assert_eq!(
            runtime
                .send_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    wrong_endpoint,
                    &[],
                    &[(delegated, Rights::READ)],
                )
                .err(),
            Some(TaskRuntimeError::Ipc(IpcError::Unauthorized))
        );
        assert!(runtime.detach_domain(receiver).is_ok());
    }

    #[test]
    fn delegation_capacity_is_preflighted_and_reusable_after_revocation() {
        const RECEIVERS: usize = MAX_TASK_DELEGATIONS / 8;
        let mut runtime = TaskRuntime::<{ RECEIVERS + 2 }, 8>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let endpoint_object = ObjectId(0x85);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let root = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(ObjectId(0x86), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let mut receivers = [None; RECEIVERS + 1];
        for (index, slot) in receivers.iter_mut().enumerate() {
            *slot = Some(
                runtime
                    .create(
                        Priority::NORMAL,
                        context(0x30_0000 + index as u64 * 0x1000, 0x50_0000),
                    )
                    .unwrap(),
            );
        }
        let requested = [(root, Rights::READ); 8];
        let mut endpoint = Endpoint::new(endpoint_object);
        let mut first_derived = None;
        for receiver in receivers[..RECEIVERS].iter().flatten().copied() {
            let (_, message) = runtime
                .send_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    &[],
                    &requested,
                )
                .unwrap();
            if first_derived.is_none() {
                first_derived = message.capabilities().next();
            }
        }
        let spare = receivers[RECEIVERS].unwrap();
        assert_eq!(
            runtime
                .send_ipc(
                    sender,
                    spare,
                    &mut endpoint,
                    endpoint_capability,
                    &[],
                    &[(root, Rights::READ)],
                )
                .err(),
            Some(TaskRuntimeError::DelegationTableFull)
        );

        let first_receiver = receivers[0].unwrap();
        runtime
            .revoke_capability(first_receiver, first_derived.unwrap())
            .unwrap();
        assert!(
            runtime
                .send_ipc(
                    sender,
                    spare,
                    &mut endpoint,
                    endpoint_capability,
                    &[],
                    &[(root, Rights::READ)],
                )
                .is_ok()
        );
    }

    #[test]
    fn delegation_capacity_denial_precedes_graph_inspection() {
        let mut runtime = TaskRuntime::<2, 3>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_object = ObjectId(0x87);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let root = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(ObjectId(0x88), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let mut endpoint = Endpoint::new(endpoint_object);
        runtime
            .send_ipc(
                sender,
                receiver,
                &mut endpoint,
                endpoint_capability,
                b"first",
                &[(root, Rights::READ)],
            )
            .unwrap();
        let edge = runtime
            .delegations
            .iter()
            .flatten()
            .copied()
            .next()
            .unwrap();
        runtime.delegations.fill(Some(edge));

        assert_eq!(
            runtime
                .send_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    b"full",
                    &[(root, Rights::READ)],
                )
                .err(),
            Some(TaskRuntimeError::DelegationTableFull)
        );

        runtime.delegations.fill(None);
        runtime.delegations[0] = Some(edge);
        assert_eq!(
            runtime
                .send_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    b"second",
                    &[(root, Rights::READ)],
                )
                .unwrap()
                .0,
            2
        );

        for payload in [b"one".as_slice(), b"two".as_slice()] {
            runtime
                .deliver_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    payload,
                    &[],
                )
                .unwrap();
        }
        let valid_edges = runtime.delegations;
        runtime.delegations.fill(Some(edge));
        assert_eq!(
            runtime.deliver_ipc(
                sender,
                receiver,
                &mut endpoint,
                endpoint_capability,
                b"queued-full",
                &[(root, Rights::READ)],
            ),
            Err(TaskRuntimeError::DelegationTableFull)
        );
        runtime.delegations = valid_edges;
        runtime.receive_ipc(receiver).unwrap();
        assert_eq!(
            runtime
                .deliver_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    b"queued",
                    &[(root, Rights::READ)],
                )
                .unwrap(),
            5
        );
    }

    #[test]
    fn delegation_slot_plan_selects_exact_fragmented_capacity() {
        let mut runtime = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let capability = Capability::from_token(1);
        let occupied = Delegation {
            source_task: task,
            source: capability,
            destination_task: task,
            destination: capability,
        };
        runtime.delegations[1] = Some(occupied);
        runtime.delegations[3] = Some(occupied);

        let slots = runtime.prepare_delegation_slots(3).unwrap();
        assert_eq!(&slots[..3], &[0, 2, 4]);
        assert_eq!(
            runtime.prepare_delegation_slots(crate::MAX_CAPABILITIES + 1),
            Err(TaskRuntimeError::IntegrityFailure)
        );
    }

    #[test]
    fn explicit_revocation_removes_transitive_ipc_descendants() {
        let mut runtime = TaskRuntime::<3, 4>::new(1_000, 1).unwrap();
        let source_task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let middle_task = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let leaf_task = runtime
            .create(Priority::NORMAL, context(0x40_0000, 0x60_0000))
            .unwrap();
        let endpoint_object = ObjectId(0x90);
        let source_endpoint = runtime
            .capabilities_mut(source_task)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let middle_endpoint = runtime
            .capabilities_mut(middle_task)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let root = runtime
            .capabilities_mut(source_task)
            .unwrap()
            .insert(
                ObjectId(0x91),
                Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE),
            )
            .unwrap();
        let mut endpoint = Endpoint::new(endpoint_object);
        let (_, middle_message) = runtime
            .send_ipc(
                source_task,
                middle_task,
                &mut endpoint,
                source_endpoint,
                &[],
                &[(root, Rights::READ.union(Rights::DELEGATE))],
            )
            .unwrap();
        let middle = middle_message.capabilities().next().unwrap();
        let (_, leaf_message) = runtime
            .send_ipc(
                middle_task,
                leaf_task,
                &mut endpoint,
                middle_endpoint,
                &[],
                &[(middle, Rights::READ)],
            )
            .unwrap();
        let leaf = leaf_message.capabilities().next().unwrap();

        runtime.revoke_capability(source_task, root).unwrap();

        assert!(
            runtime
                .capabilities_mut(middle_task)
                .unwrap()
                .authorize(middle, Rights::READ)
                .is_err()
        );
        assert!(
            runtime
                .capabilities_mut(leaf_task)
                .unwrap()
                .authorize(leaf, Rights::READ)
                .is_err()
        );
    }

    #[test]
    fn tracked_revocation_rejects_duplicate_target_before_mutation() {
        let mut runtime = TaskRuntime::<1, 2>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let capability = runtime
            .capabilities_mut(task)
            .unwrap()
            .insert(ObjectId(0x92), Rights::READ)
            .unwrap();
        let mut tracked = [None; MAX_TASK_DELEGATIONS + 2];
        tracked[0] = Some((task, capability));
        tracked[1] = Some((task, capability));

        assert!(matches!(
            runtime.prepare_tracked_revocation(&tracked, 0),
            Err(TaskRuntimeError::IntegrityFailure)
        ));
        assert_eq!(
            runtime
                .capabilities(task)
                .unwrap()
                .authorize(capability, Rights::READ),
            Ok(ObjectId(0x92))
        );
    }

    #[test]
    fn intermediate_revocation_preserves_root_and_blocks_migration_until_cleanup() {
        let mut runtime = TaskRuntime::<3, 3>::new(1_000, 1).unwrap();
        let source_task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let middle_task = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let leaf_task = runtime
            .create(Priority::NORMAL, context(0x40_0000, 0x60_0000))
            .unwrap();
        let endpoint_object = ObjectId(0xa0);
        let source_endpoint = runtime
            .capabilities_mut(source_task)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let middle_endpoint = runtime
            .capabilities_mut(middle_task)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let root = runtime
            .capabilities_mut(source_task)
            .unwrap()
            .insert(ObjectId(0xa1), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let mut endpoint = Endpoint::new(endpoint_object);
        let (_, message) = runtime
            .send_ipc(
                source_task,
                middle_task,
                &mut endpoint,
                source_endpoint,
                &[],
                &[(root, Rights::READ.union(Rights::DELEGATE))],
            )
            .unwrap();
        let middle = message.capabilities().next().unwrap();
        let (_, message) = runtime
            .send_ipc(
                middle_task,
                leaf_task,
                &mut endpoint,
                middle_endpoint,
                &[],
                &[(middle, Rights::READ)],
            )
            .unwrap();
        let leaf = message.capabilities().next().unwrap();
        assert_eq!(
            runtime.detach_domain(middle_task).err(),
            Some(TaskRuntimeError::ActiveDelegations)
        );

        runtime.revoke_capability(middle_task, middle).unwrap();

        assert_eq!(
            runtime
                .capabilities_mut(source_task)
                .unwrap()
                .authorize(root, Rights::READ),
            Ok(ObjectId(0xa1))
        );
        assert!(
            runtime
                .capabilities_mut(leaf_task)
                .unwrap()
                .authorize(leaf, Rights::READ)
                .is_err()
        );
        assert!(runtime.detach_domain(middle_task).is_ok());
    }

    #[test]
    fn task_death_revokes_transitive_descendants_before_replacement_runs() {
        let mut runtime = TaskRuntime::<3, 4>::new(1_000, 1).unwrap();
        let source_task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let middle_task = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let leaf_task = runtime
            .create(Priority::NORMAL, context(0x40_0000, 0x60_0000))
            .unwrap();
        let endpoint_object = ObjectId(0xb0);
        let source_endpoint = runtime
            .capabilities_mut(source_task)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let middle_endpoint = runtime
            .capabilities_mut(middle_task)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let root = runtime
            .capabilities_mut(source_task)
            .unwrap()
            .insert(ObjectId(0xb1), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let unrelated = runtime
            .capabilities_mut(leaf_task)
            .unwrap()
            .insert(ObjectId(0xb2), Rights::READ)
            .unwrap();
        let mut endpoint = Endpoint::new(endpoint_object);
        let (_, message) = runtime
            .send_ipc(
                source_task,
                middle_task,
                &mut endpoint,
                source_endpoint,
                &[],
                &[(root, Rights::READ.union(Rights::DELEGATE))],
            )
            .unwrap();
        let middle = message.capabilities().next().unwrap();
        let (_, message) = runtime
            .send_ipc(
                middle_task,
                leaf_task,
                &mut endpoint,
                middle_endpoint,
                &[],
                &[(middle, Rights::READ)],
            )
            .unwrap();
        let leaf = message.capabilities().next().unwrap();
        assert!(matches!(runtime.start(), ScheduleOutcome::Switch { to, .. } if to == source_task));

        let termination = runtime.terminate_current().unwrap();

        assert!(
            matches!(termination.next, ScheduleOutcome::Switch { to, .. } if to == middle_task)
        );
        assert!(
            runtime
                .capabilities_mut(middle_task)
                .unwrap()
                .authorize(middle, Rights::READ)
                .is_err()
        );
        assert!(
            runtime
                .capabilities_mut(leaf_task)
                .unwrap()
                .authorize(leaf, Rights::READ)
                .is_err()
        );
        assert_eq!(
            runtime
                .capabilities_mut(leaf_task)
                .unwrap()
                .authorize(unrelated, Rights::READ),
            Ok(ObjectId(0xb2))
        );
    }

    #[test]
    fn task_death_preflights_all_delegation_roots_before_revocation() {
        let mut runtime = TaskRuntime::<3, 4>::new(1_000, 1).unwrap();
        let source = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let first = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let second = runtime
            .create(Priority::NORMAL, context(0x40_0000, 0x60_0000))
            .unwrap();
        let endpoint_object = ObjectId(0xb3);
        let endpoint_capability = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let first_root = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0xb4), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let second_root = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0xb5), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let mut endpoint = Endpoint::new(endpoint_object);
        let (_, first_message) = runtime
            .send_ipc(
                source,
                first,
                &mut endpoint,
                endpoint_capability,
                &[],
                &[(first_root, Rights::READ)],
            )
            .unwrap();
        let first_derived = first_message.capabilities().next().unwrap();
        let (_, second_message) = runtime
            .send_ipc(
                source,
                second,
                &mut endpoint,
                endpoint_capability,
                &[],
                &[(second_root, Rights::READ)],
            )
            .unwrap();
        let second_derived = second_message.capabilities().next().unwrap();
        runtime
            .capabilities_mut(second)
            .unwrap()
            .revoke(second_derived)
            .unwrap();
        assert!(matches!(runtime.start(), ScheduleOutcome::Switch { to, .. } if to == source));

        assert_eq!(
            runtime.terminate_current_violation(TaskProtocolViolation::InvalidUserReturn(
                UserReturnError::InvalidStack,
            )),
            Err(TaskRuntimeError::IntegrityFailure)
        );
        assert_eq!(runtime.current(), Some(source));
        assert!(runtime.context(source).is_ok());
        assert_eq!(
            runtime
                .capabilities_mut(first)
                .unwrap()
                .authorize(first_derived, Rights::READ),
            Ok(ObjectId(0xb4))
        );
    }

    #[test]
    fn empty_receive_blocks_and_delivery_wakes_without_overwriting() {
        let mut runtime = TaskRuntime::<2, 2>::new(1_000, 1).unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let object = ObjectId(44);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let mut endpoint = Endpoint::new(object);
        assert_eq!(
            runtime.start(),
            ScheduleOutcome::Switch {
                from: None,
                to: receiver
            }
        );
        assert!(matches!(
            runtime.receive_or_block_current(),
            Ok(Err(ScheduleOutcome::Switch { to, .. })) if to == sender
        ));
        assert_eq!(
            runtime
                .deliver_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    b"one",
                    &[],
                )
                .unwrap(),
            1
        );
        runtime
            .deliver_ipc(
                sender,
                receiver,
                &mut endpoint,
                endpoint_capability,
                b"two",
                &[],
            )
            .unwrap();
        assert_eq!(
            runtime
                .deliver_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    b"three",
                    &[],
                )
                .err(),
            Some(TaskRuntimeError::InboxFull)
        );
        assert_eq!(
            runtime.peek_ipc_shape(receiver).unwrap(),
            QueuedMessageShape {
                payload_length: 3,
                capability_count: 0,
            }
        );
        assert!(matches!(
            runtime.receive_ipc_bounded(receiver, 2, 0),
            Err(TaskRuntimeError::ReceiveCapacity)
        ));
        assert_eq!(
            runtime.peek_ipc_shape(receiver).unwrap(),
            QueuedMessageShape {
                payload_length: 3,
                capability_count: 0,
            }
        );
        assert_eq!(
            runtime
                .receive_ipc_bounded(receiver, 3, 0)
                .unwrap()
                .payload(),
            b"one"
        );
        assert_eq!(
            runtime.peek_ipc_shape(receiver).unwrap(),
            QueuedMessageShape {
                payload_length: 3,
                capability_count: 0,
            }
        );
        assert_eq!(runtime.receive_ipc(receiver).unwrap().payload(), b"two");
        assert_eq!(
            runtime.receive_ipc(receiver).err(),
            Some(TaskRuntimeError::InboxEmpty)
        );
        assert_eq!(
            runtime.peek_ipc_shape(receiver),
            Err(TaskRuntimeError::InboxEmpty)
        );
    }

    #[test]
    fn unauthorized_delivery_cannot_observe_full_receiver_inbox() {
        let mut runtime = TaskRuntime::<2, 3>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_object = ObjectId(0x56);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let wrong_endpoint = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(ObjectId(0x57), Rights::SIGNAL)
            .unwrap();
        let stale_delegation = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(ObjectId(0x58), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        runtime
            .capabilities_mut(sender)
            .unwrap()
            .revoke(stale_delegation)
            .unwrap();
        let mut endpoint = Endpoint::new(endpoint_object);
        for payload in [b"one".as_slice(), b"two".as_slice()] {
            runtime
                .deliver_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    payload,
                    &[],
                )
                .unwrap();
        }

        assert_eq!(
            runtime.deliver_ipc(
                sender,
                receiver,
                &mut endpoint,
                wrong_endpoint,
                b"probe",
                &[],
            ),
            Err(TaskRuntimeError::Ipc(IpcError::Unauthorized))
        );
        let oversized = [0; crate::MAX_INLINE_PAYLOAD + 1];
        assert_eq!(
            runtime.deliver_ipc(
                sender,
                receiver,
                &mut endpoint,
                endpoint_capability,
                &oversized,
                &[],
            ),
            Err(TaskRuntimeError::Ipc(IpcError::PayloadTooLarge))
        );
        assert_eq!(
            runtime
                .deliver_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    b"stale",
                    &[(stale_delegation, Rights::READ)],
                )
                .err(),
            Some(TaskRuntimeError::Ipc(IpcError::Unauthorized))
        );
        let delegated = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(ObjectId(0x60), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        for object in 0x61..0x64 {
            runtime
                .capabilities_mut(receiver)
                .unwrap()
                .insert(ObjectId(object), Rights::READ)
                .unwrap();
        }
        assert_eq!(
            runtime
                .deliver_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    b"no-capacity",
                    &[(delegated, Rights::READ)],
                )
                .err(),
            Some(TaskRuntimeError::Ipc(IpcError::Unauthorized))
        );
        runtime.receive_ipc(receiver).unwrap();
        assert_eq!(
            runtime
                .deliver_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    b"three",
                    &[],
                )
                .unwrap(),
            3
        );
    }

    #[test]
    fn unauthorized_delivery_cannot_probe_missing_receiver_identity() {
        let mut runtime = TaskRuntime::<1, 2>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let endpoint_object = ObjectId(0x59);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let wrong_endpoint = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(ObjectId(0x5a), Rights::SIGNAL)
            .unwrap();
        let missing = TaskId::from_token((1u64 << 32) | 7);
        let mut endpoint = Endpoint::new(endpoint_object);

        assert_eq!(
            runtime.deliver_ipc(
                sender,
                missing,
                &mut endpoint,
                wrong_endpoint,
                b"probe",
                &[],
            ),
            Err(TaskRuntimeError::Ipc(IpcError::Unauthorized))
        );
        assert_eq!(
            runtime.deliver_ipc(
                sender,
                missing,
                &mut endpoint,
                endpoint_capability,
                b"authorized",
                &[],
            ),
            Err(TaskRuntimeError::MissingTask)
        );
    }

    #[test]
    fn invalid_delegation_cannot_probe_direct_receiver_identity() {
        let mut runtime = TaskRuntime::<2, 2>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_object = ObjectId(0x5d);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let stale = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(ObjectId(0x5e), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        runtime
            .capabilities_mut(sender)
            .unwrap()
            .revoke(stale)
            .unwrap();
        let missing = TaskId::from_token((1u64 << 32) | 7);
        let mut endpoint = Endpoint::new(endpoint_object);

        assert_eq!(
            runtime
                .send_ipc(
                    sender,
                    missing,
                    &mut endpoint,
                    endpoint_capability,
                    b"probe",
                    &[(stale, Rights::READ)],
                )
                .err(),
            Some(TaskRuntimeError::Ipc(IpcError::Unauthorized))
        );
        assert_eq!(
            runtime
                .send_ipc(
                    sender,
                    missing,
                    &mut endpoint,
                    endpoint_capability,
                    b"authorized",
                    &[],
                )
                .err(),
            Some(TaskRuntimeError::IntegrityFailure)
        );
        assert_eq!(
            runtime
                .send_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    b"valid",
                    &[],
                )
                .unwrap()
                .0,
            1
        );
    }

    #[test]
    fn self_delivery_is_rejected_before_receiver_inbox_inspection() {
        let mut runtime = TaskRuntime::<2, 2>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_object = ObjectId(0x5b);
        let sender_endpoint = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let receiver_endpoint = runtime
            .capabilities_mut(receiver)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let wrong_endpoint = runtime
            .capabilities_mut(receiver)
            .unwrap()
            .insert(ObjectId(0x5c), Rights::SIGNAL)
            .unwrap();
        let mut endpoint = Endpoint::new(endpoint_object);
        for payload in [b"one".as_slice(), b"two".as_slice()] {
            runtime
                .deliver_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    sender_endpoint,
                    payload,
                    &[],
                )
                .unwrap();
        }

        assert_eq!(
            runtime.deliver_ipc(
                receiver,
                receiver,
                &mut endpoint,
                wrong_endpoint,
                b"unauthorized",
                &[],
            ),
            Err(TaskRuntimeError::Ipc(IpcError::Unauthorized))
        );
        assert_eq!(
            runtime.deliver_ipc(
                receiver,
                receiver,
                &mut endpoint,
                receiver_endpoint,
                b"self",
                &[],
            ),
            Err(TaskRuntimeError::SameTaskIpc)
        );
        assert_eq!(
            runtime.peek_ipc_shape(receiver).unwrap(),
            QueuedMessageShape {
                payload_length: 3,
                capability_count: 0,
            }
        );
    }

    #[test]
    fn bounded_receive_retains_derived_capability_until_capacity_fits() {
        let mut runtime = TaskRuntime::<2, 3>::new(1_000, 1).unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_object = ObjectId(0x45);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let delegated_object = ObjectId(0x46);
        let root = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(delegated_object, Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        runtime
            .deliver_ipc(
                sender,
                receiver,
                &mut Endpoint::new(endpoint_object),
                endpoint_capability,
                b"x",
                &[(root, Rights::READ)],
            )
            .unwrap();

        assert!(matches!(
            runtime.receive_ipc_bounded(receiver, 1, 0),
            Err(TaskRuntimeError::ReceiveCapacity)
        ));
        assert_eq!(
            runtime.peek_ipc_shape(receiver).unwrap(),
            QueuedMessageShape {
                payload_length: 1,
                capability_count: 1,
            }
        );
        let message = runtime.receive_ipc_bounded(receiver, 1, 1).unwrap();
        let derived = message.capabilities().next().unwrap();
        assert_eq!(
            runtime
                .capabilities_mut(receiver)
                .unwrap()
                .authorize(derived, Rights::READ),
            Ok(delegated_object)
        );
    }

    #[test]
    fn delivery_rejects_unscheduled_receiver_before_enqueue() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let object = ObjectId(0x47);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        assert!(matches!(runtime.start(), ScheduleOutcome::Switch { to, .. } if to == sender));
        runtime.scheduler.detach(receiver).unwrap();

        assert_eq!(
            runtime.deliver_ipc(
                sender,
                receiver,
                &mut Endpoint::new(object),
                endpoint_capability,
                b"not-enqueued",
                &[],
            ),
            Err(TaskRuntimeError::IntegrityFailure)
        );
        assert_eq!(
            runtime.peek_ipc_shape(receiver),
            Err(TaskRuntimeError::IntegrityFailure)
        );
        let slot = runtime.domain_slot(receiver).unwrap();
        assert_eq!(runtime.domains[slot].as_ref().unwrap().inbox_count, 0);
    }

    #[test]
    fn delivery_rejects_unscheduled_sender_before_authority_transfer() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let object = ObjectId(0x49);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        assert!(matches!(runtime.start(), ScheduleOutcome::Switch { to, .. } if to == receiver));
        runtime.scheduler.detach(sender).unwrap();

        assert_eq!(
            runtime.deliver_ipc(
                sender,
                receiver,
                &mut Endpoint::new(object),
                endpoint_capability,
                b"not-transferred",
                &[],
            ),
            Err(TaskRuntimeError::IntegrityFailure)
        );
        assert_eq!(
            runtime.peek_ipc_shape(receiver),
            Err(TaskRuntimeError::InboxEmpty)
        );
    }

    #[test]
    fn direct_transfer_rejects_unscheduled_endpoint_before_authorization() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let object = ObjectId(0x4a);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        runtime.scheduler.detach(receiver).unwrap();

        assert!(matches!(
            runtime.send_ipc(
                sender,
                receiver,
                &mut Endpoint::new(object),
                endpoint_capability,
                b"not-transferred",
                &[],
            ),
            Err(TaskRuntimeError::IntegrityFailure)
        ));
    }

    #[test]
    fn receive_boundaries_reject_unscheduled_domain_without_consuming_message() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let object = ObjectId(0x4d);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        runtime
            .deliver_ipc(
                sender,
                receiver,
                &mut Endpoint::new(object),
                endpoint_capability,
                b"retained",
                &[],
            )
            .unwrap();
        runtime.scheduler.detach(receiver).unwrap();

        assert_eq!(
            runtime.peek_ipc_shape(receiver),
            Err(TaskRuntimeError::IntegrityFailure)
        );
        assert_eq!(
            runtime.receive_ipc(receiver).err(),
            Some(TaskRuntimeError::IntegrityFailure)
        );
        assert!(matches!(
            runtime.receive_control(receiver),
            Err(TaskRuntimeError::IntegrityFailure)
        ));
        assert!(matches!(
            runtime.capabilities(receiver),
            Err(TaskRuntimeError::IntegrityFailure)
        ));
        assert!(matches!(
            runtime.capabilities_mut(receiver),
            Err(TaskRuntimeError::IntegrityFailure)
        ));
        assert!(matches!(
            runtime.context(receiver),
            Err(TaskRuntimeError::IntegrityFailure)
        ));
        assert!(matches!(
            runtime.context_mut(receiver),
            Err(TaskRuntimeError::IntegrityFailure)
        ));
        assert_eq!(
            runtime.authorize_capability(
                receiver,
                Capability::from_token(1),
                Rights::READ,
                ObjectId(1),
            ),
            Err(TaskRuntimeError::IntegrityFailure)
        );
        let slot = runtime.domain_slot(receiver).unwrap();
        assert_eq!(runtime.domains[slot].as_ref().unwrap().inbox_count, 1);
    }

    #[test]
    fn duplicate_domain_identity_fails_before_task_resource_access() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let first = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let second = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_object = ObjectId(0x55);
        let endpoint_capability = runtime
            .capabilities_mut(first)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let second_slot = runtime.domain_slot(second).unwrap();
        runtime.domains[second_slot].as_mut().unwrap().task = first;

        assert!(matches!(
            runtime.context(first),
            Err(TaskRuntimeError::IntegrityFailure)
        ));
        assert!(matches!(
            runtime.capabilities_mut(first),
            Err(TaskRuntimeError::IntegrityFailure)
        ));
        assert_eq!(
            runtime.detach_domain(first).err(),
            Some(TaskRuntimeError::IntegrityFailure)
        );
        assert_eq!(
            runtime
                .send_ipc(
                    first,
                    second,
                    &mut Endpoint::new(endpoint_object),
                    endpoint_capability,
                    b"rejected",
                    &[],
                )
                .err(),
            Some(TaskRuntimeError::IntegrityFailure)
        );
        assert!(runtime.scheduler.contains(first));
        assert!(runtime.scheduler.contains(second));
    }

    #[test]
    fn direct_transfer_rejects_stale_delegation_before_sequence_mutation() {
        let mut runtime = TaskRuntime::<2, 3>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_object = ObjectId(0x4b);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let root = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(ObjectId(0x4c), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let mut endpoint = Endpoint::new(endpoint_object);
        let (sequence, message) = runtime
            .send_ipc(
                sender,
                receiver,
                &mut endpoint,
                endpoint_capability,
                b"first",
                &[(root, Rights::READ)],
            )
            .unwrap();
        assert_eq!(sequence, 1);
        let derived = message.capabilities().next().unwrap();
        runtime
            .capabilities_mut(receiver)
            .unwrap()
            .revoke(derived)
            .unwrap();

        assert!(matches!(
            runtime.send_ipc(
                sender,
                receiver,
                &mut endpoint,
                endpoint_capability,
                b"rejected",
                &[],
            ),
            Err(TaskRuntimeError::IntegrityFailure)
        ));
        runtime.delegations.fill(None);
        assert_eq!(
            runtime
                .send_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    b"second",
                    &[],
                )
                .unwrap()
                .0,
            2
        );
    }

    #[test]
    fn direct_transfer_rejects_semantically_substituted_delegation_edge() {
        let mut runtime = TaskRuntime::<2, 3>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_object = ObjectId(0x4f);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let root = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(ObjectId(0x50), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let wrong_endpoint = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(ObjectId(0x58), Rights::SIGNAL)
            .unwrap();
        let mut endpoint = Endpoint::new(endpoint_object);
        let (_, message) = runtime
            .send_ipc(
                sender,
                receiver,
                &mut endpoint,
                endpoint_capability,
                b"first",
                &[(root, Rights::READ)],
            )
            .unwrap();
        let derived = message.capabilities().next().unwrap();
        let unrelated = runtime
            .capabilities_mut(receiver)
            .unwrap()
            .insert(ObjectId(0x51), Rights::READ)
            .unwrap();
        let edge = runtime.delegations.iter_mut().flatten().next().unwrap();
        edge.destination = unrelated;

        assert_eq!(
            runtime
                .send_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    wrong_endpoint,
                    b"unauthorized",
                    &[],
                )
                .err(),
            Some(TaskRuntimeError::Ipc(IpcError::Unauthorized))
        );
        assert_eq!(
            runtime
                .send_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    b"rejected",
                    &[],
                )
                .err(),
            Some(TaskRuntimeError::IntegrityFailure)
        );
        runtime
            .delegations
            .iter_mut()
            .flatten()
            .next()
            .unwrap()
            .destination = derived;
        assert_eq!(
            runtime
                .send_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    b"second",
                    &[],
                )
                .unwrap()
                .0,
            2
        );
    }

    #[test]
    fn direct_transfer_rejects_delegation_cycle_before_sequence_mutation() {
        let mut runtime = TaskRuntime::<2, 3>::new(1_000, 1).unwrap();
        let first = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let second = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_object = ObjectId(0x53);
        let first_endpoint = runtime
            .capabilities_mut(first)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let second_endpoint = runtime
            .capabilities_mut(second)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let root = runtime
            .capabilities_mut(first)
            .unwrap()
            .insert(ObjectId(0x54), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let mut endpoint = Endpoint::new(endpoint_object);
        let (_, first_message) = runtime
            .send_ipc(
                first,
                second,
                &mut endpoint,
                first_endpoint,
                b"first",
                &[(root, Rights::READ.union(Rights::DELEGATE))],
            )
            .unwrap();
        let intermediate = first_message.capabilities().next().unwrap();
        let (_, second_message) = runtime
            .send_ipc(
                second,
                first,
                &mut endpoint,
                second_endpoint,
                b"second",
                &[(intermediate, Rights::READ)],
            )
            .unwrap();
        let leaf = second_message.capabilities().next().unwrap();
        let edge = runtime
            .delegations
            .iter_mut()
            .flatten()
            .find(|edge| edge.destination_task == first && edge.destination == leaf)
            .unwrap();
        edge.destination = root;

        assert_eq!(
            runtime
                .send_ipc(
                    first,
                    second,
                    &mut endpoint,
                    first_endpoint,
                    b"rejected",
                    &[],
                )
                .err(),
            Some(TaskRuntimeError::IntegrityFailure)
        );
        runtime
            .delegations
            .iter_mut()
            .flatten()
            .find(|edge| edge.destination_task == first && edge.destination == root)
            .unwrap()
            .destination = leaf;
        assert_eq!(
            runtime
                .send_ipc(first, second, &mut endpoint, first_endpoint, b"third", &[],)
                .unwrap()
                .0,
            3
        );
    }

    #[test]
    fn delivery_rejects_corrupt_inbox_before_endpoint_sequence_changes() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let object = ObjectId(0x48);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let mut endpoint = Endpoint::new(object);
        assert_eq!(
            runtime
                .deliver_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    b"first",
                    &[],
                )
                .unwrap(),
            1
        );
        let receiver_slot = runtime.domain_slot(receiver).unwrap();
        runtime.domains[receiver_slot].as_mut().unwrap().inbox_count = 0;
        assert_eq!(
            runtime.deliver_ipc(
                sender,
                receiver,
                &mut endpoint,
                endpoint_capability,
                b"rejected",
                &[],
            ),
            Err(TaskRuntimeError::IntegrityFailure)
        );
        runtime.domains[receiver_slot].as_mut().unwrap().inbox_count = 1;
        assert_eq!(runtime.receive_ipc(receiver).unwrap().payload(), b"first");
        assert_eq!(
            runtime
                .deliver_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    b"second",
                    &[],
                )
                .unwrap(),
            2
        );
    }

    #[test]
    fn inbox_validator_exhaustively_matches_exact_circular_topology() {
        let mut runtime = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let slot = runtime.domain_slot(task).unwrap();

        for count in 0..=3usize {
            for head in 0..=2usize {
                for tail in 0..=2usize {
                    for occupied in 0..4usize {
                        let domain = runtime.domains[slot].as_mut().unwrap();
                        domain.inbox_count = count as u8;
                        domain.inbox_head = head as u8;
                        domain.inbox_tail = tail as u8;
                        for index in 0..TASK_INBOX_MESSAGES {
                            domain.inbox[index] =
                                ((occupied >> index) & 1 == 1).then(|| ReceivedMessage {
                                    sender: task,
                                    sequence: 1,
                                    message: Message::new(b"x", &[]).unwrap(),
                                });
                        }
                        let valid = count <= TASK_INBOX_MESSAGES
                            && head < TASK_INBOX_MESSAGES
                            && tail < TASK_INBOX_MESSAGES
                            && tail == (head + count) % TASK_INBOX_MESSAGES
                            && (0..TASK_INBOX_MESSAGES).all(|offset| {
                                let index = (head + offset) % TASK_INBOX_MESSAGES;
                                ((occupied >> index) & 1 == 1) == (offset < count)
                            });
                        assert_eq!(
                            TaskRuntime::<1, 1>::validate_inbox_state(domain).is_ok(),
                            valid,
                            "count={count} head={head} tail={tail} occupied={occupied:02b}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn multi_client_messages_bind_sender_and_endpoint_sequence() {
        let mut runtime = TaskRuntime::<3, 1>::new(1_000, 1).unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let first = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let second = runtime
            .create(Priority::NORMAL, context(0x40_0000, 0x60_0000))
            .unwrap();
        let object = ObjectId(0x71);
        let first_capability = runtime
            .capabilities_mut(first)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let second_capability = runtime
            .capabilities_mut(second)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let mut endpoint = Endpoint::new(object);

        runtime
            .deliver_ipc(first, receiver, &mut endpoint, first_capability, b"a", &[])
            .unwrap();
        runtime
            .deliver_ipc(
                second,
                receiver,
                &mut endpoint,
                second_capability,
                b"b",
                &[],
            )
            .unwrap();

        let ControlEvent::Message(first_message) = runtime.receive_control(receiver).unwrap()
        else {
            panic!("expected first message");
        };
        assert_eq!(first_message.sender(), first);
        assert_eq!(first_message.sequence(), 1);
        assert_eq!(first_message.message().payload(), b"a");
        runtime
            .deliver_ipc(first, receiver, &mut endpoint, first_capability, b"c", &[])
            .unwrap();
        let ControlEvent::Message(second_message) = runtime.receive_control(receiver).unwrap()
        else {
            panic!("expected second message");
        };
        assert_eq!(second_message.sender(), second);
        assert_eq!(second_message.sequence(), 2);
        assert_eq!(second_message.message().payload(), b"b");
        let ControlEvent::Message(third_message) = runtime.receive_control(receiver).unwrap()
        else {
            panic!("expected wrapped third message");
        };
        assert_eq!(third_message.sender(), first);
        assert_eq!(third_message.sequence(), 3);
        assert_eq!(third_message.message().payload(), b"c");
    }

    #[test]
    fn control_receive_rejects_corrupt_inbox_before_consuming_peer_death() {
        let mut runtime = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let slot = runtime.domain_slot(task).unwrap();
        let domain = runtime.domains[slot].as_mut().unwrap();
        domain.inbox_count = 1;
        domain.peer_deaths[0] = Some(PeerDeath {
            peer: task,
            reason: PeerDeathReason::Exited,
        });

        assert!(matches!(
            runtime.receive_control(task),
            Err(TaskRuntimeError::IntegrityFailure)
        ));
        assert!(runtime.domains[slot].as_ref().unwrap().peer_deaths[0].is_some());
    }

    #[test]
    fn control_receive_rejects_duplicate_peer_death_without_consuming_either() {
        let mut runtime = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let slot = runtime.domain_slot(task).unwrap();
        let duplicate = PeerDeath {
            peer: task,
            reason: PeerDeathReason::Exited,
        };
        runtime.domains[slot].as_mut().unwrap().peer_deaths[..2].fill(Some(duplicate));

        assert!(matches!(
            runtime.receive_control(task),
            Err(TaskRuntimeError::IntegrityFailure)
        ));
        assert_eq!(
            runtime.domains[slot]
                .as_ref()
                .unwrap()
                .peer_deaths
                .iter()
                .flatten()
                .count(),
            2
        );
    }

    #[test]
    fn control_receive_rejects_unscheduled_live_peer_without_unlinking() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let first = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let second = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let object = ObjectId(0x52);
        let first_capability = runtime
            .capabilities_mut(first)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let second_capability = runtime
            .capabilities_mut(second)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        runtime
            .connect_control_peers(
                first,
                second,
                &Endpoint::new(object),
                first_capability,
                second_capability,
            )
            .unwrap();
        runtime.scheduler.detach(second).unwrap();

        assert!(matches!(
            runtime.receive_control(first),
            Err(TaskRuntimeError::IntegrityFailure)
        ));
        let first_slot = runtime.domain_slot(first).unwrap();
        let second_slot = runtime.domain_slot(second).unwrap();
        assert!(
            runtime.domains[first_slot]
                .as_ref()
                .unwrap()
                .peers
                .contains(&Some(second))
        );
        assert!(
            runtime.domains[second_slot]
                .as_ref()
                .unwrap()
                .peers
                .contains(&Some(first))
        );
    }

    #[test]
    fn control_receive_rejects_death_for_still_live_identity() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let observer = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let live = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let slot = runtime.domain_slot(observer).unwrap();
        runtime.domains[slot].as_mut().unwrap().peer_deaths[0] = Some(PeerDeath {
            peer: live,
            reason: PeerDeathReason::Exited,
        });

        assert!(matches!(
            runtime.receive_control(observer),
            Err(TaskRuntimeError::IntegrityFailure)
        ));
        assert!(runtime.domains[slot].as_ref().unwrap().peer_deaths[0].is_some());
        assert!(runtime.scheduler.contains(live));
    }

    #[test]
    fn fault_retirement_wakes_peer_with_typed_death_and_preserves_unrelated_domain() {
        let mut runtime = TaskRuntime::<3, 1>::new(1_000, 1).unwrap();
        let observer = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let faulted = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let unrelated = runtime
            .create(Priority::NORMAL, context(0x40_0000, 0x60_0000))
            .unwrap();
        let object = ObjectId(0x72);
        let observer_capability = runtime
            .capabilities_mut(observer)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let faulted_capability = runtime
            .capabilities_mut(faulted)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let endpoint = Endpoint::new(object);
        runtime
            .connect_control_peers(
                observer,
                faulted,
                &endpoint,
                observer_capability,
                faulted_capability,
            )
            .unwrap();
        assert!(matches!(runtime.start(), ScheduleOutcome::Switch { to, .. } if to == observer));
        assert!(matches!(
            runtime.receive_control_or_block_current(),
            Ok(Err(ScheduleOutcome::Switch { to, .. })) if to == faulted
        ));

        let retirement = runtime
            .terminate_current_fault(TrapDisposition::TerminateUser {
                vector: 14,
                address: Some(0x1234),
            })
            .unwrap();
        assert!(matches!(retirement.next, ScheduleOutcome::Switch { .. }));
        let ControlEvent::PeerDied(death) = runtime.receive_control(observer).unwrap() else {
            panic!("expected peer death");
        };
        assert_eq!(death.peer(), faulted);
        assert_eq!(
            death.reason(),
            PeerDeathReason::Faulted {
                vector: 14,
                address: Some(0x1234),
            }
        );
        assert_eq!(runtime.context(faulted), Err(TaskRuntimeError::MissingTask));
        assert!(runtime.context(unrelated).is_ok());
    }

    #[test]
    fn fault_death_wakeup_precedes_replacement_selection() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let observer = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let faulted = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let object = ObjectId(0x74);
        let observer_capability = runtime
            .capabilities_mut(observer)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let faulted_capability = runtime
            .capabilities_mut(faulted)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        runtime
            .connect_control_peers(
                observer,
                faulted,
                &Endpoint::new(object),
                observer_capability,
                faulted_capability,
            )
            .unwrap();
        assert!(matches!(runtime.start(), ScheduleOutcome::Switch { to, .. } if to == observer));
        assert!(matches!(
            runtime.receive_control_or_block_current(),
            Ok(Err(ScheduleOutcome::Switch { to, .. })) if to == faulted
        ));
        let retirement = runtime
            .terminate_current_fault(TrapDisposition::TerminateUser {
                vector: 3,
                address: None,
            })
            .unwrap();
        assert!(matches!(retirement.next, ScheduleOutcome::Switch { to, .. } if to == observer));
    }

    #[test]
    fn protocol_violation_revokes_domain_and_wakes_peer_with_typed_reason() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let observer_context = context(0x20_0000, 0x40_0000);
        let violated_context = context(0x30_0000, 0x50_0000);
        let observer = runtime.create(Priority::NORMAL, observer_context).unwrap();
        let violated = runtime.create(Priority::NORMAL, violated_context).unwrap();
        let object = ObjectId(0x75);
        let observer_capability = runtime
            .capabilities_mut(observer)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let violated_capability = runtime
            .capabilities_mut(violated)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        runtime
            .connect_control_peers(
                observer,
                violated,
                &Endpoint::new(object),
                observer_capability,
                violated_capability,
            )
            .unwrap();
        assert!(matches!(runtime.start(), ScheduleOutcome::Switch { to, .. } if to == observer));
        assert!(matches!(
            runtime.receive_control_or_block_current(),
            Ok(Err(ScheduleOutcome::Switch { to, .. })) if to == violated
        ));

        let retirement = runtime
            .terminate_current_violation(TaskProtocolViolation::InvalidUserReturn(
                UserReturnError::InvalidStack,
            ))
            .unwrap();
        assert_eq!(retirement.task, violated);
        assert_eq!(retirement.context, violated_context);
        assert_eq!(
            retirement.violation,
            TaskProtocolViolation::InvalidUserReturn(UserReturnError::InvalidStack)
        );
        assert!(matches!(retirement.next, ScheduleOutcome::Switch { to, .. } if to == observer));
        assert_eq!(
            runtime.context(violated),
            Err(TaskRuntimeError::MissingTask)
        );
        let ControlEvent::PeerDied(death) = runtime.receive_control(observer).unwrap() else {
            panic!("expected protocol-violation peer death");
        };
        assert_eq!(death.peer(), violated);
        assert_eq!(
            death.reason(),
            PeerDeathReason::ProtocolViolation(TaskProtocolViolation::InvalidUserReturn(
                UserReturnError::InvalidStack,
            ))
        );
        assert_eq!(
            runtime.timer_tick(),
            Err(TaskRuntimeError::RetirementDispatchPending)
        );
        assert_eq!(
            runtime.dispatch_after_violation(TaskViolationRetirement {
                violation: TaskProtocolViolation::BufferedReceiveMappingDrift,
                ..retirement
            }),
            Err(TaskTerminationDispatchError::ViolationMismatch)
        );
        let dispatch = runtime.dispatch_after_violation(retirement).unwrap();
        assert_eq!(dispatch.user(), Some((observer, observer_context)));
        assert_eq!(
            runtime.dispatch_after_violation(retirement),
            Err(TaskTerminationDispatchError::DispatchOutstanding)
        );
    }

    #[test]
    fn buffered_receive_mapping_drift_is_a_distinct_scoped_violation() {
        let mut runtime = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let saved = context(0x20_0000, 0x40_0000);
        let task = runtime.create(Priority::NORMAL, saved).unwrap();
        assert!(matches!(runtime.start(), ScheduleOutcome::Switch { to, .. } if to == task));

        let retirement = runtime
            .terminate_current_violation(TaskProtocolViolation::BufferedReceiveMappingDrift)
            .unwrap();
        assert_eq!(retirement.task, task);
        assert_eq!(retirement.context, saved);
        assert_eq!(
            retirement.violation,
            TaskProtocolViolation::BufferedReceiveMappingDrift
        );
        assert_eq!(retirement.next, ScheduleOutcome::Idle);
        assert_eq!(runtime.context(task), Err(TaskRuntimeError::MissingTask));
        assert!(
            runtime
                .dispatch_after_violation(retirement)
                .unwrap()
                .is_idle()
        );
    }

    #[test]
    fn protocol_violation_rejects_corrupt_peer_graph_before_retirement() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let observer = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let violated_context = context(0x30_0000, 0x50_0000);
        let violated = runtime.create(Priority::NORMAL, violated_context).unwrap();
        let object = ObjectId(0x76);
        let observer_capability = runtime
            .capabilities_mut(observer)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let violated_capability = runtime
            .capabilities_mut(violated)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        runtime
            .connect_control_peers(
                observer,
                violated,
                &Endpoint::new(object),
                observer_capability,
                violated_capability,
            )
            .unwrap();
        assert!(matches!(runtime.start(), ScheduleOutcome::Switch { to, .. } if to == observer));
        assert!(matches!(
            runtime.receive_control_or_block_current(),
            Ok(Err(ScheduleOutcome::Switch { to, .. })) if to == violated
        ));

        let observer_slot = runtime.domain_slot(observer).unwrap();
        runtime.domains[observer_slot]
            .as_mut()
            .unwrap()
            .peers
            .fill(None);
        assert_eq!(
            runtime.terminate_current_violation(TaskProtocolViolation::InvalidUserReturn(
                UserReturnError::InvalidStack,
            )),
            Err(TaskRuntimeError::IntegrityFailure)
        );
        assert_eq!(runtime.current(), Some(violated));
        assert_eq!(runtime.context(violated).copied(), Ok(violated_context));
        assert!(matches!(
            runtime.receive_control(observer),
            Err(TaskRuntimeError::InboxEmpty)
        ));

        runtime.domains[observer_slot].as_mut().unwrap().peers[0] = Some(violated);
        let violated_slot = runtime.domain_slot(violated).unwrap();
        runtime.domains[violated_slot].as_mut().unwrap().peers[1] = Some(observer);
        assert_eq!(
            runtime.terminate_current_violation(TaskProtocolViolation::InvalidUserReturn(
                UserReturnError::InvalidStack,
            )),
            Err(TaskRuntimeError::IntegrityFailure)
        );
        assert_eq!(runtime.current(), Some(violated));
        assert_eq!(runtime.context(violated).copied(), Ok(violated_context));
        assert!(runtime.domains[observer_slot].as_ref().unwrap().peer_deaths[0].is_none());
    }

    #[test]
    fn protocol_violation_rejects_unscheduled_peer_before_retirement() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let observer = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let violated_context = context(0x30_0000, 0x50_0000);
        let violated = runtime.create(Priority::NORMAL, violated_context).unwrap();
        let object = ObjectId(0x77);
        let observer_capability = runtime
            .capabilities_mut(observer)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let violated_capability = runtime
            .capabilities_mut(violated)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        runtime
            .connect_control_peers(
                observer,
                violated,
                &Endpoint::new(object),
                observer_capability,
                violated_capability,
            )
            .unwrap();
        assert!(matches!(runtime.start(), ScheduleOutcome::Switch { to, .. } if to == observer));
        assert!(matches!(
            runtime.receive_control_or_block_current(),
            Ok(Err(ScheduleOutcome::Switch { to, .. })) if to == violated
        ));

        runtime.scheduler.detach(observer).unwrap();
        assert_eq!(
            runtime.terminate_current_violation(TaskProtocolViolation::InvalidUserReturn(
                UserReturnError::InvalidStack,
            )),
            Err(TaskRuntimeError::IntegrityFailure)
        );
        assert_eq!(runtime.current(), Some(violated));
        assert_eq!(runtime.context(violated).copied(), Ok(violated_context));
        let observer_slot = runtime.domain_slot(observer).unwrap();
        assert!(
            runtime.domains[observer_slot]
                .as_ref()
                .unwrap()
                .peers
                .contains(&Some(violated))
        );
        assert!(runtime.domains[observer_slot].as_ref().unwrap().peer_deaths[0].is_none());
    }

    #[test]
    fn live_control_relation_blocks_domain_migration() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let first = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let second = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let object = ObjectId(0x73);
        let first_capability = runtime
            .capabilities_mut(first)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let second_capability = runtime
            .capabilities_mut(second)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let endpoint = Endpoint::new(object);
        runtime
            .connect_control_peers(
                first,
                second,
                &endpoint,
                first_capability,
                second_capability,
            )
            .unwrap();
        assert!(matches!(
            runtime.detach_domain(first),
            Err(TaskRuntimeError::ActiveControlPeers)
        ));
        assert!(runtime.context(first).is_ok());
        assert!(runtime.context(second).is_ok());
    }

    #[test]
    fn control_connection_rejects_unscheduled_peer_before_publication() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let first = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let second = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let object = ObjectId(0x78);
        let first_capability = runtime
            .capabilities_mut(first)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let second_capability = runtime
            .capabilities_mut(second)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        runtime.scheduler.detach(second).unwrap();

        assert_eq!(
            runtime.connect_control_peers(
                first,
                second,
                &Endpoint::new(object),
                first_capability,
                second_capability,
            ),
            Err(TaskRuntimeError::IntegrityFailure)
        );
        assert!(
            runtime.domains[runtime.domain_slot(first).unwrap()]
                .as_ref()
                .unwrap()
                .peers
                .iter()
                .all(Option::is_none)
        );
        assert!(
            runtime.domains[runtime.domain_slot(second).unwrap()]
                .as_ref()
                .unwrap()
                .peers
                .iter()
                .all(Option::is_none)
        );
    }

    #[test]
    fn control_relation_requires_exact_endpoint_authority_before_mutation() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let first = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let second = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let first_capability = runtime
            .capabilities_mut(first)
            .unwrap()
            .insert(ObjectId(0x74), Rights::SIGNAL)
            .unwrap();
        let wrong_capability = runtime
            .capabilities_mut(second)
            .unwrap()
            .insert(ObjectId(0x75), Rights::SIGNAL)
            .unwrap();
        let endpoint = Endpoint::new(ObjectId(0x74));
        assert_eq!(
            runtime.connect_control_peers(
                first,
                second,
                &endpoint,
                first_capability,
                wrong_capability,
            ),
            Err(TaskRuntimeError::Ipc(IpcError::Unauthorized))
        );
        assert!(runtime.detach_domain(first).is_ok());
        assert!(runtime.detach_domain(second).is_ok());
    }

    #[test]
    fn migration_moves_context_authority_and_inbox_as_one_domain() {
        let mut source = TaskRuntime::<2, 2>::new(1_000, 1).unwrap();
        let mut destination = TaskRuntime::<2, 2>::new(1_000, 1).unwrap();
        let sender = source
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let migrated = source
            .create(Priority::RESPONSIVE, context(0x30_0000, 0x50_0000))
            .unwrap();
        let retained_capability = source
            .capabilities_mut(migrated)
            .unwrap()
            .insert(ObjectId(77), Rights::READ)
            .unwrap();
        let endpoint_object = ObjectId(88);
        let endpoint_capability = source
            .capabilities_mut(sender)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let mut endpoint = Endpoint::new(endpoint_object);
        source
            .deliver_ipc(
                sender,
                migrated,
                &mut endpoint,
                endpoint_capability,
                b"migrate",
                &[],
            )
            .unwrap();
        assert!(matches!(source.start(), ScheduleOutcome::Switch { to, .. } if to == sender));

        let mut ticket = Some(source.detach_domain(migrated).unwrap());
        assert_eq!(source.context(migrated), Err(TaskRuntimeError::MissingTask));
        let migration = destination.attach_domain(&mut ticket).unwrap();
        assert!(ticket.is_none());
        let admitted = migration.destination();
        assert_eq!(
            destination.context(admitted).unwrap().instruction_pointer(),
            0x50_0000
        );
        assert_eq!(
            destination
                .capabilities_mut(admitted)
                .unwrap()
                .authorize(retained_capability, Rights::READ),
            Ok(ObjectId(77))
        );
        assert_eq!(
            destination.receive_ipc(admitted).unwrap().payload(),
            b"migrate"
        );
    }

    #[test]
    fn full_runtime_returns_the_complete_domain_for_retry() {
        let mut source = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let mut full = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let mut fallback = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let task = source
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        full.create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();

        let mut ticket = Some(source.detach_domain(task).unwrap());
        assert_eq!(full.attach_domain(&mut ticket), Err(TaskRuntimeError::Full));
        assert!(ticket.is_some());
        let migration = fallback.attach_domain(&mut ticket).unwrap();
        assert!(ticket.is_none());
        assert_eq!(
            fallback
                .context(migration.destination())
                .unwrap()
                .page_table(),
            PhysAddr::new(0x20_0000).unwrap()
        );
    }

    #[test]
    fn task_authorization_is_exact_and_detail_free() {
        let mut runtime = TaskRuntime::<1, 2>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let capability = runtime
            .capabilities_mut(task)
            .unwrap()
            .insert(ObjectId(7), Rights::READ)
            .unwrap();
        assert_eq!(
            runtime.authorize_capability(task, capability, Rights::READ, ObjectId(7)),
            Ok(())
        );
        assert_eq!(
            runtime.authorize_capability(task, capability, Rights::WRITE, ObjectId(7)),
            Err(TaskRuntimeError::Ipc(IpcError::Unauthorized))
        );
        assert_eq!(
            runtime.authorize_capability(task, capability, Rights::READ, ObjectId(8)),
            Err(TaskRuntimeError::Ipc(IpcError::Unauthorized))
        );

        let overbroad = runtime
            .capabilities_mut(task)
            .unwrap()
            .insert(ObjectId(7), Rights::READ.union(Rights::WRITE))
            .unwrap();
        assert_eq!(
            runtime.authorize_capability(task, overbroad, Rights::READ, ObjectId(7)),
            Ok(())
        );
        assert_eq!(
            runtime.authorize_capability_exact(task, overbroad, Rights::READ, ObjectId(7)),
            Err(TaskRuntimeError::Ipc(IpcError::Unauthorized))
        );
        assert_eq!(
            runtime.authorize_capability_exact(task, capability, Rights::READ, ObjectId(7)),
            Ok(())
        );
    }

    #[test]
    fn running_domain_cannot_detach_and_remains_fully_live() {
        let mut runtime = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let capability = runtime
            .capabilities_mut(task)
            .unwrap()
            .insert(ObjectId(7), Rights::READ)
            .unwrap();
        runtime.start();

        assert!(matches!(
            runtime.detach_domain(task),
            Err(TaskRuntimeError::Scheduler(
                KernelScheduleError::CurrentTaskCannotMigrate
            ))
        ));
        assert_eq!(runtime.current(), Some(task));
        assert_eq!(
            runtime
                .capabilities_mut(task)
                .unwrap()
                .authorize(capability, Rights::READ),
            Ok(ObjectId(7))
        );
        assert_eq!(
            runtime.context(task).unwrap().instruction_pointer(),
            0x40_0000
        );
    }

    #[test]
    fn complete_domain_crosses_typed_linear_mailbox() {
        let mut source = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let mut destination = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let task = source
            .create(Priority::RESPONSIVE, context(0x20_0000, 0x40_0000))
            .unwrap();
        let mailbox = OwnershipMailbox::new();
        mailbox
            .publish(source.detach_domain(task).unwrap())
            .ok()
            .unwrap();

        let mut ticket = mailbox.take();
        let migration = destination.attach_domain(&mut ticket).unwrap();
        assert!(ticket.is_none());
        assert_eq!(migration.source(), task);
        assert_eq!(migration.priority(), Priority::RESPONSIVE);
        assert_eq!(
            destination
                .context(migration.destination())
                .unwrap()
                .page_table(),
            PhysAddr::new(0x20_0000).unwrap()
        );
        assert!(mailbox.take().is_none());
    }

    #[test]
    fn runtime_rebalance_selects_only_an_identity_with_a_complete_domain() {
        let mut source = TaskRuntime::<3, 1>::new(1_000, 1).unwrap();
        let mut destination = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let current = source
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        source
            .create(Priority::RESPONSIVE, context(0x30_0000, 0x50_0000))
            .unwrap();
        source
            .create(Priority::BACKGROUND, context(0x40_0000, 0x60_0000))
            .unwrap();
        destination
            .create(Priority::NORMAL, context(0x50_0000, 0x70_0000))
            .unwrap();
        source.start();

        let mut ticket = source
            .detach_domain_for_rebalance(destination.scheduler.load())
            .unwrap();
        let migration = destination.attach_domain(&mut ticket).unwrap();
        assert_ne!(migration.source(), current);
        assert_eq!(migration.priority(), Priority::RESPONSIVE);
        assert_eq!(
            destination
                .context(migration.destination())
                .unwrap()
                .instruction_pointer(),
            0x50_0000
        );
    }

    #[test]
    fn periodic_domain_balancer_retries_linear_ticket_before_new_work() {
        let mut source = TaskRuntime::<3, 1>::new(1_000, 1).unwrap();
        let current = source
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let migrating = source
            .create(Priority::RESPONSIVE, context(0x30_0000, 0x50_0000))
            .unwrap();
        let capability = source
            .capabilities_mut(migrating)
            .unwrap()
            .insert(ObjectId(19), Rights::READ)
            .unwrap();
        source
            .create(Priority::BACKGROUND, context(0x40_0000, 0x60_0000))
            .unwrap();
        assert!(matches!(source.start(), ScheduleOutcome::Switch { to, .. } if to == current));

        let mut blocker = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let blocker_task = blocker
            .create(Priority::NORMAL, context(0x50_0000, 0x70_0000))
            .unwrap();
        let local_mailbox = OwnershipMailbox::new();
        let remote_mailbox = OwnershipMailbox::new();
        remote_mailbox
            .publish(blocker.detach_domain(blocker_task).unwrap())
            .ok()
            .unwrap();
        let mailboxes = [&local_mailbox, &remote_mailbox];
        let loads = [source.load(), SchedulerLoad::new(0, 0, 3).unwrap()];
        let mut balancer = PeriodicDomainBalancer::<2, 1>::new(0, 1).unwrap();

        assert!(matches!(
            balancer
                .poll_and_publish(1, 0, &loads, &mut source, &mailboxes)
                .unwrap(),
            DomainBalanceOutcome::RetryPending(target) if target.cpu() == 1
        ));
        assert_eq!(balancer.pending_target().unwrap().cpu(), 1);
        assert_eq!(source.load().runnable(), 2);

        let _occupied = remote_mailbox.take().unwrap();
        assert!(matches!(
            balancer
                .poll_and_publish(2, 0, &loads, &mut source, &mailboxes)
                .unwrap(),
            DomainBalanceOutcome::Published(target) if target.cpu() == 1
        ));
        assert!(balancer.pending_target().is_none());

        let mut destination = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let mut ticket = remote_mailbox.take();
        let migration = destination.attach_domain(&mut ticket).unwrap();
        assert_eq!(migration.source(), migrating);
        assert_eq!(
            destination
                .context(migration.destination())
                .unwrap()
                .page_table(),
            PhysAddr::new(0x30_0000).unwrap()
        );
        assert_eq!(
            destination
                .capabilities_mut(migration.destination())
                .unwrap()
                .authorize(capability, Rights::READ),
            Ok(ObjectId(19))
        );
    }

    #[test]
    fn periodic_domain_balancer_rejects_invalid_cadence() {
        assert!(matches!(
            PeriodicDomainBalancer::<1, 0>::new(0, 1),
            Err(DomainBalanceError::Policy(
                BalancePolicyError::InvalidCpuCount
            ))
        ));
        assert!(matches!(
            PeriodicDomainBalancer::<2, 0>::new(0, 0),
            Err(DomainBalanceError::Policy(
                BalancePolicyError::InvalidInterval
            ))
        ));
    }

    #[test]
    fn hardware_ticks_drive_domain_balancing_only_at_cadence() {
        let mut source = TaskRuntime::<3, 0>::new(1_000, 10).unwrap();
        let current = source
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        source
            .create(Priority::RESPONSIVE, context(0x30_0000, 0x50_0000))
            .unwrap();
        source
            .create(Priority::BACKGROUND, context(0x40_0000, 0x60_0000))
            .unwrap();
        source.start();
        let local_mailbox = OwnershipMailbox::new();
        let remote_mailbox = OwnershipMailbox::new();
        let mailboxes = [&local_mailbox, &remote_mailbox];
        let loads = [source.load(), SchedulerLoad::new(0, 0, 3).unwrap()];
        let mut balancer = PeriodicDomainBalancer::<2, 0>::new(0, 2).unwrap();

        let first = balancer
            .timer_tick_and_publish(0, &loads, &mut source, &mailboxes)
            .unwrap();
        assert_eq!(first.scheduling(), ScheduleOutcome::Continue(current));
        assert_eq!(first.balancing(), DomainBalanceOutcome::Idle);
        assert!(remote_mailbox.take().is_none());

        let second = balancer
            .timer_tick_and_publish(0, &loads, &mut source, &mailboxes)
            .unwrap();
        assert_eq!(second.scheduling(), ScheduleOutcome::Continue(current));
        assert!(matches!(
            second.balancing(),
            DomainBalanceOutcome::Published(target) if target.cpu() == 1
        ));
        assert!(remote_mailbox.take().is_some());

        let stale_loads = [loads[0], SchedulerLoad::new(0, 0, 3).unwrap()];
        assert_eq!(
            balancer.timer_tick_and_publish(0, &stale_loads, &mut source, &mailboxes),
            Err(DomainBalanceError::Runtime(
                TaskRuntimeError::IntegrityFailure
            ))
        );
        assert_eq!(source.ticks(), 2);
    }
}
