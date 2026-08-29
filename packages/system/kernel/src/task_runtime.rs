use core::array;
use core::mem::size_of;
use core::ops::{Deref, DerefMut};

use crate::arch::x86_64::{TrapDisposition, UserContext};
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
    PeerTableFull,
    ActiveControlPeers,
    ActiveDelegations,
    DelegationTableFull,
}

impl TaskRuntimeError {
    pub const fn is_precommit_send_denial(self) -> bool {
        matches!(
            self,
            Self::MissingTask
                | Self::SameTaskIpc
                | Self::Ipc(_)
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
    pub next: ScheduleOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskViolationRetirement {
    pub task: TaskId,
    pub context: UserContext,
    pub violation: TaskProtocolViolation,
    pub next: ScheduleOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskTermination {
    pub task: TaskId,
    pub next: ScheduleOutcome,
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

type DelegationSet = [Option<(TaskId, Capability)>; MAX_TASK_DELEGATIONS + 1];

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
        self.scheduler.start()
    }

    pub const fn ticks(&self) -> u64 {
        self.scheduler.ticks()
    }

    pub fn load(&self) -> SchedulerLoad {
        self.scheduler.load()
    }

    pub fn timer_tick(&mut self) -> Result<ScheduleOutcome, TaskRuntimeError> {
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
        let current = self
            .scheduler
            .current()
            .ok_or(TaskRuntimeError::NoCurrentTask)?;
        let domain = self
            .domain(current)
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        if domain.context.page_table() != interrupted.page_table() {
            return Err(TaskRuntimeError::AddressSpaceMismatch);
        }
        let outcome = self
            .scheduler
            .timer_tick()
            .map_err(TaskRuntimeError::Scheduler)?;
        *self.context_mut(current)? = interrupted;
        Ok(outcome)
    }

    pub fn yield_current(&mut self) -> Result<ScheduleOutcome, TaskRuntimeError> {
        self.scheduler
            .yield_current()
            .map_err(TaskRuntimeError::Scheduler)
    }

    pub fn context(&self, task: TaskId) -> Result<&UserContext, TaskRuntimeError> {
        self.domain(task)
            .map(|domain| &domain.context)
            .ok_or(TaskRuntimeError::MissingTask)
    }

    pub fn context_mut(&mut self, task: TaskId) -> Result<&mut UserContext, TaskRuntimeError> {
        self.domains
            .iter_mut()
            .flatten()
            .find(|domain| domain.task == task)
            .map(|domain| &mut domain.context)
            .ok_or(TaskRuntimeError::MissingTask)
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
        let slot = self
            .domains
            .iter()
            .position(|domain| domain.as_ref().is_some_and(|domain| domain.task == task))
            .ok_or(TaskRuntimeError::MissingTask)?;
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
        let Some(candidate) = self
            .scheduler
            .rebalance_candidate(destination)
            .map_err(TaskRuntimeError::Scheduler)?
        else {
            return Ok(None);
        };
        if self.domain(candidate).is_none() {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        self.detach_domain(candidate).map(Some)
    }

    /// Admits a complete migrated user domain under a fresh local scheduler
    /// identity. Capacity failure returns context, capabilities, inbox, and
    /// scheduling ticket together so authority cannot be orphaned.
    pub fn attach_domain(
        &mut self,
        ticket: &mut Option<DetachedTaskDomain<CAPS>>,
    ) -> Result<TaskMigration, TaskRuntimeError> {
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
        self.domains
            .iter_mut()
            .flatten()
            .find(|domain| domain.task == task)
            .map(|domain| &mut domain.capabilities)
            .ok_or(TaskRuntimeError::MissingTask)
    }

    pub fn capabilities(&self, task: TaskId) -> Result<&CapabilitySpace<CAPS>, TaskRuntimeError> {
        self.domains
            .iter()
            .flatten()
            .find(|domain| domain.task == task)
            .map(|domain| &domain.capabilities)
            .ok_or(TaskRuntimeError::MissingTask)
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
            .domains
            .iter()
            .flatten()
            .find(|domain| domain.task == task)
            .ok_or(TaskRuntimeError::MissingTask)?
            .capabilities
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
            .domains
            .iter()
            .flatten()
            .find(|domain| domain.task == task)
            .ok_or(TaskRuntimeError::MissingTask)?
            .capabilities
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
        self.capabilities_mut(task)?
            .authorize(capability, Rights::NONE)
            .map_err(|error| TaskRuntimeError::Ipc(error.into()))?;
        let descendants = self.delegation_descendants(task, capability)?;
        self.revoke_tracked(&descendants.0, 1)?;
        self.capabilities_mut(task)?
            .revoke(capability)
            .map_err(|_| TaskRuntimeError::IntegrityFailure)?;
        self.remove_tracked(&descendants.0);
        Ok(())
    }

    fn delegation_descendants(
        &self,
        task: TaskId,
        capability: Capability,
    ) -> Result<(DelegationSet, usize), TaskRuntimeError> {
        let mut tracked = [None; MAX_TASK_DELEGATIONS + 1];
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

    fn revoke_tracked(
        &mut self,
        tracked: &DelegationSet,
        start: usize,
    ) -> Result<(), TaskRuntimeError> {
        // Validate the complete exact-generation set before changing any
        // destination space. A stale graph edge is an integrity failure, but
        // cannot otherwise leave a partially revoked descendant tree.
        for (task, capability) in tracked[start..].iter().flatten().copied() {
            self.capabilities_mut(task)?
                .authorize(capability, Rights::NONE)
                .map_err(|_| TaskRuntimeError::IntegrityFailure)?;
        }
        for (task, capability) in tracked[start..].iter().flatten().copied() {
            self.capabilities_mut(task)?
                .revoke(capability)
                .map_err(|_| TaskRuntimeError::IntegrityFailure)?;
        }
        Ok(())
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
        let mut descendants = [None; MAX_TASK_DELEGATIONS + 1];
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
        self.revoke_tracked(&descendants, 0)?;
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
            .domains
            .iter()
            .position(|domain| domain.as_ref().is_some_and(|domain| domain.task == current))
            .ok_or(TaskRuntimeError::IntegrityFailure)?;

        self.validate_peer_death_publication(
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
        self.publish_peer_death(&domain, PeerDeathReason::Faulted { vector, address })?;
        let next = self
            .scheduler
            .terminate_current()
            .map_err(TaskRuntimeError::Scheduler)?;
        Ok(FaultRetirement {
            task: current,
            context: domain.context,
            vector,
            address,
            next,
        })
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
        let current = self
            .scheduler
            .current()
            .ok_or(TaskRuntimeError::NoCurrentTask)?;
        let slot = self
            .domains
            .iter()
            .position(|domain| domain.as_ref().is_some_and(|domain| domain.task == current))
            .ok_or(TaskRuntimeError::IntegrityFailure)?;

        self.validate_peer_death_publication(
            self.domains[slot]
                .as_ref()
                .ok_or(TaskRuntimeError::IntegrityFailure)?,
        )?;
        self.revoke_task_delegations(current)?;
        let domain = self.domains[slot]
            .take()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        self.publish_peer_death(&domain, PeerDeathReason::ProtocolViolation(violation))?;
        let next = self
            .scheduler
            .terminate_current()
            .map_err(TaskRuntimeError::Scheduler)?;
        Ok(TaskViolationRetirement {
            task: current,
            context: domain.context,
            violation,
            next,
        })
    }

    /// Removes the current task's complete revocation domain for a voluntary
    /// exit before selecting a replacement. No context or authority from the
    /// removed domain is returned to its caller.
    pub fn terminate_current(&mut self) -> Result<TaskTermination, TaskRuntimeError> {
        self.terminate_current_with_context()
            .map(|(termination, _)| termination)
    }

    pub(crate) fn terminate_current_with_context(
        &mut self,
    ) -> Result<(TaskTermination, UserContext), TaskRuntimeError> {
        let current = self
            .scheduler
            .current()
            .ok_or(TaskRuntimeError::NoCurrentTask)?;
        let slot = self
            .domains
            .iter()
            .position(|domain| domain.as_ref().is_some_and(|domain| domain.task == current))
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        self.validate_peer_death_publication(
            self.domains[slot]
                .as_ref()
                .ok_or(TaskRuntimeError::IntegrityFailure)?,
        )?;
        self.revoke_task_delegations(current)?;
        let domain = self.domains[slot]
            .take()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        self.publish_peer_death(&domain, PeerDeathReason::Exited)?;
        let next = self
            .scheduler
            .terminate_current()
            .map_err(TaskRuntimeError::Scheduler)?;
        Ok((
            TaskTermination {
                task: current,
                next,
            },
            domain.context,
        ))
    }

    /// Transfers a message and attenuated capabilities between two distinct
    /// task domains. Tentative receiver capabilities are revoked if endpoint
    /// authorization fails, so an unsuccessful send cannot grant authority.
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
        if self
            .delegations
            .iter()
            .filter(|edge| edge.is_none())
            .count()
            < requested.len()
        {
            return Err(TaskRuntimeError::DelegationTableFull);
        }
        let sender_slot = self
            .domains
            .iter()
            .position(|domain| domain.as_ref().is_some_and(|domain| domain.task == sender))
            .ok_or(TaskRuntimeError::MissingTask)?;
        let receiver_slot = self
            .domains
            .iter()
            .position(|domain| {
                domain
                    .as_ref()
                    .is_some_and(|domain| domain.task == receiver)
            })
            .ok_or(TaskRuntimeError::MissingTask)?;
        let (source, destination) = two_domains_mut(&mut self.domains, sender_slot, receiver_slot)
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        let message = Message::transfer(
            payload,
            requested,
            &source.capabilities,
            &mut destination.capabilities,
        )
        .map_err(TaskRuntimeError::Ipc)?;
        for ((source, _), destination) in requested.iter().zip(message.capabilities()) {
            let slot = self
                .delegations
                .iter_mut()
                .find(|edge| edge.is_none())
                .ok_or(TaskRuntimeError::IntegrityFailure)?;
            *slot = Some(Delegation {
                source_task: sender,
                source: *source,
                destination_task: receiver,
                destination,
            });
        }
        match endpoint.authorize_send(&source.capabilities, endpoint_capability, &message) {
            Ok(sequence) => Ok((sequence, message)),
            Err(error) => {
                for capability in message.capabilities() {
                    if destination.capabilities.revoke(capability).is_err() {
                        return Err(TaskRuntimeError::IntegrityFailure);
                    }
                    for edge in &mut self.delegations {
                        if edge.is_some_and(|edge| {
                            edge.destination_task == receiver && edge.destination == capability
                        }) {
                            *edge = None;
                        }
                    }
                }
                Err(TaskRuntimeError::Ipc(error))
            }
        }
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
        let receiver_slot = self
            .domains
            .iter()
            .position(|domain| {
                domain
                    .as_ref()
                    .is_some_and(|domain| domain.task == receiver)
            })
            .ok_or(TaskRuntimeError::MissingTask)?;
        if self.domains[receiver_slot]
            .as_ref()
            .is_none_or(|domain| usize::from(domain.inbox_count) == TASK_INBOX_MESSAGES)
        {
            return Err(TaskRuntimeError::InboxFull);
        }
        let (sequence, message) = self.send_ipc(
            sender,
            receiver,
            endpoint,
            endpoint_capability,
            payload,
            requested,
        )?;
        let domain = self.domains[receiver_slot]
            .as_mut()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
        let tail = usize::from(domain.inbox_tail);
        if domain.inbox[tail].is_some() {
            return Err(TaskRuntimeError::IntegrityFailure);
        }
        domain.inbox[tail] = Some(ReceivedMessage {
            sender,
            sequence,
            message,
        });
        domain.inbox_tail = ((tail + 1) % TASK_INBOX_MESSAGES) as u8;
        domain.inbox_count += 1;
        self.scheduler
            .wake(receiver)
            .map_err(TaskRuntimeError::Scheduler)?;
        Ok(sequence)
    }

    pub fn receive_ipc(&mut self, task: TaskId) -> Result<Message, TaskRuntimeError> {
        let domain = self
            .domains
            .iter_mut()
            .flatten()
            .find(|domain| domain.task == task)
            .ok_or(TaskRuntimeError::MissingTask)?;
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
        let first_slot = self.domain_slot(first)?;
        let second_slot = self.domain_slot(second)?;
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
        *first_domain
            .peers
            .iter_mut()
            .find(|peer| peer.is_none())
            .ok_or(TaskRuntimeError::IntegrityFailure)? = Some(second);
        *second_domain
            .peers
            .iter_mut()
            .find(|peer| peer.is_none())
            .ok_or(TaskRuntimeError::IntegrityFailure)? = Some(first);
        Ok(())
    }

    pub fn receive_control(&mut self, task: TaskId) -> Result<ControlEvent, TaskRuntimeError> {
        let slot = self.domain_slot(task)?;
        let domain = self.domains[slot]
            .as_mut()
            .ok_or(TaskRuntimeError::IntegrityFailure)?;
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
        self.domains
            .iter()
            .position(|domain| domain.as_ref().is_some_and(|domain| domain.task == task))
            .ok_or(TaskRuntimeError::MissingTask)
    }

    fn publish_peer_death(
        &mut self,
        retired: &TaskDomain<CAPS>,
        reason: PeerDeathReason,
    ) -> Result<(), TaskRuntimeError> {
        for peer in retired.peers.iter().flatten().copied() {
            let slot = self.domain_slot(peer)?;
            let domain = self.domains[slot]
                .as_mut()
                .ok_or(TaskRuntimeError::IntegrityFailure)?;
            let relation = domain
                .peers
                .iter_mut()
                .find(|candidate| **candidate == Some(retired.task))
                .ok_or(TaskRuntimeError::IntegrityFailure)?;
            *relation = None;
            let death_slot = domain
                .peer_deaths
                .iter_mut()
                .find(|death| death.is_none())
                .ok_or(TaskRuntimeError::IntegrityFailure)?;
            *death_slot = Some(PeerDeath {
                peer: retired.task,
                reason,
            });
            self.scheduler
                .wake(peer)
                .map_err(TaskRuntimeError::Scheduler)?;
        }
        Ok(())
    }

    fn validate_peer_death_publication(
        &self,
        retired: &TaskDomain<CAPS>,
    ) -> Result<(), TaskRuntimeError> {
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
            let slot = self.domain_slot(peer)?;
            let domain = self.domains[slot]
                .as_ref()
                .ok_or(TaskRuntimeError::IntegrityFailure)?;
            if domain
                .peers
                .iter()
                .filter(|candidate| **candidate == Some(retired.task))
                .count()
                != 1
                || !domain.peer_deaths.iter().any(Option::is_none)
            {
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

    fn domain(&self, task: TaskId) -> Option<&TaskDomain<CAPS>> {
        self.domains
            .iter()
            .flatten()
            .find(|domain| domain.task == task)
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
        let mut runtime = TaskRuntime::<2, 2>::new(1_000, 1).unwrap();
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
        assert_eq!(runtime.context(exiting), Err(TaskRuntimeError::MissingTask));
        assert_eq!(
            runtime.capabilities_mut(exiting).map(|_| ()),
            Err(TaskRuntimeError::MissingTask)
        );
        let _ = capability;
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
    fn ipc_transfer_is_attenuated_and_authorization_failure_rolls_back() {
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
        // tentative denied transfer did not consume receiver authority space.
        let receiver_space = runtime.capabilities_mut(receiver).unwrap();
        assert!(receiver_space.insert(ObjectId(8), Rights::READ).is_ok());
        assert!(receiver_space.insert(ObjectId(9), Rights::READ).is_ok());
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
        assert_eq!(runtime.receive_ipc(receiver).unwrap().payload(), b"one");
        assert_eq!(runtime.receive_ipc(receiver).unwrap().payload(), b"two");
        assert_eq!(
            runtime.receive_ipc(receiver).err(),
            Some(TaskRuntimeError::InboxEmpty)
        );
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
        let ControlEvent::Message(second_message) = runtime.receive_control(receiver).unwrap()
        else {
            panic!("expected second message");
        };
        assert_eq!(second_message.sender(), second);
        assert_eq!(second_message.sequence(), 2);
        assert_eq!(second_message.message().payload(), b"b");
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
        let mut runtime = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
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
