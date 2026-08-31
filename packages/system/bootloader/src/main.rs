#![no_std]
#![no_main]

#[cfg(all(feature = "ahci-service-manager-probe", not(feature = "service-probe")))]
compile_error!("ahci-service-manager-probe requires service-probe");

#[cfg(all(
    feature = "ahci-service-manager-probe",
    feature = "component-service-probe"
))]
compile_error!("ahci-service-manager-probe requires the direct TaskRuntime service probe");

#[cfg(all(
    feature = "deadline-receive-cancel-denied-probe",
    feature = "deadline-receive-cancel-replay-probe"
))]
compile_error!("deadline receive cancellation denial and replay probes are mutually exclusive");

#[cfg(feature = "vmx-root-probe")]
mod vmx_probe;

#[cfg(not(feature = "fault-probe"))]
use core::arch::x86_64::{__cpuid, __cpuid_count};
use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
#[cfg(any(feature = "smp-scheduler-probe", feature = "smp-ipi-probe"))]
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
#[cfg(feature = "production-policy")]
use mrml_kernel::BootPolicy;
#[cfg(any(feature = "block-service-probe", feature = "component-service-probe"))]
use mrml_kernel::GuestMappingRevoker;
#[cfg(any(feature = "timer-probe", feature = "smp-scheduler-probe"))]
use mrml_kernel::KernelScheduler;
#[cfg(all(feature = "smp-ipi-probe", not(feature = "smp-periodic-balance-probe")))]
use mrml_kernel::PeriodicBalancer;
#[cfg(feature = "service-probe")]
use mrml_kernel::SharedBufferUserCopy;
#[cfg(any(
    feature = "application-probe",
    feature = "user-probe",
    feature = "service-probe",
    feature = "smp-service-migration-probe"
))]
use mrml_kernel::SyscallRequest;
#[cfg(any(
    feature = "application-probe",
    feature = "user-probe",
    feature = "service-probe",
    feature = "preemption-probe",
    feature = "service-preemption-probe",
    feature = "smp-ipi-probe"
))]
use mrml_kernel::TaskRuntime;
use mrml_kernel::UserCallFrame;
#[cfg(feature = "smp-ipi-probe")]
use mrml_kernel::arch::x86_64::LocalApicController;
#[cfg(any(
    feature = "timer-probe",
    feature = "deadline-receive-probe",
    feature = "preemption-probe",
    feature = "service-preemption-probe",
    feature = "smp-scheduler-probe",
    feature = "smp-ipi-probe"
))]
use mrml_kernel::arch::x86_64::LocalApicTimer;
#[cfg(any(
    feature = "application-probe",
    feature = "uefi-service-preemption-probe",
    feature = "ahci-service-manager-probe"
))]
use mrml_kernel::arch::x86_64::PreallocatedPageTableStore;
#[cfg(feature = "uefi-service-preemption-probe")]
use mrml_kernel::arch::x86_64::ServiceAddressSpace;
#[cfg(any(
    feature = "timer-probe",
    feature = "deadline-receive-probe",
    feature = "preemption-probe",
    feature = "service-preemption-probe",
    feature = "smp-scheduler-probe",
    feature = "smp-periodic-balance-probe"
))]
use mrml_kernel::arch::x86_64::TimerDivide;
#[cfg(any(
    feature = "user-probe",
    feature = "service-probe",
    feature = "preemption-probe",
    feature = "service-preemption-probe"
))]
use mrml_kernel::arch::x86_64::TrapDisposition;
#[cfg(any(
    feature = "application-probe",
    feature = "user-probe",
    feature = "service-probe",
    feature = "preemption-probe",
    feature = "service-preemption-probe",
    feature = "smp-ipi-probe"
))]
use mrml_kernel::arch::x86_64::UserContext;
#[cfg(any(feature = "user-probe", feature = "preemption-probe"))]
use mrml_kernel::arch::x86_64::enter_user_context;
#[cfg(any(
    feature = "application-probe",
    feature = "service-probe",
    feature = "service-preemption-probe",
    feature = "smp-service-migration-probe"
))]
use mrml_kernel::arch::x86_64::enter_user_context_on_stack;
#[cfg(not(feature = "fault-probe"))]
use mrml_kernel::arch::x86_64::{
    ActiveApTrampolinePage, ActivePageTables, ApStartupTable, ApStartupTiming, ApTrampolineImage,
    ApTrampolinePage, ApicIpi, PerCpuPrivilegeStacks, X86CpuTopology,
};
#[cfg(feature = "service-probe")]
use mrml_kernel::arch::x86_64::{
    ActiveServiceMappingRevoker, ActiveTaskUserCopy, ActiveTaskUserCopyError,
    DirectActiveUserMemory, Mapping, PagePermissions, UserBufferAccess, VirtAddr,
};
use mrml_kernel::arch::x86_64::{
    ApOnlineTable, CpuDescriptorState, HardwareTrapFrame, MAX_X86_64_CPUS,
    PRIVILEGE_STACK_ARENA_PAGES, PrivilegeStackLayout,
};
#[cfg(feature = "application-probe")]
use mrml_kernel::arch::x86_64::{ApplicationAddressSpace, PageTableBuildError, ServiceSpaceError};
#[cfg(any(
    feature = "block-guest-driver-probe",
    feature = "pci-configuration-probe"
))]
use mrml_kernel::arch::x86_64::{NativeX86VirtualBlockPortIo, X86VirtualBlockGuestQueueTransport};
#[cfg(feature = "component-service-probe")]
use mrml_kernel::{
    AccountedServiceSupervisor, AccountedTaskRuntime, MemoryPoolId, MemoryPoolTable,
};
#[cfg(any(
    feature = "application-probe",
    feature = "uefi-service-preemption-probe"
))]
use mrml_kernel::{ArtifactKind, SignedArtifact, TrustRoot};
#[cfg(feature = "service-probe")]
use mrml_kernel::{
    BOOT_RECOVERY_SYSCALL_OPERATION, BootRecoveryDelivery, BootRecoverySyscallExecutor,
    BootRecoverySyscallRequest, CAPABILITY_TRANSFER_DESCRIPTOR_BYTES, Capability, CapabilitySpace,
    ControlEvent, DirectHostResourceMemory, GuestMemory, GuestRegion, HostResourceIoError,
    HostResourceTable, IpcError, IpcSharedBufferError, IpcSharedBufferIoError, MAX_CAPABILITIES,
    MAX_INLINE_PAYLOAD, PeerDeathReason, RestartPolicy, ServiceAddressSpaceEraser, ServiceError,
    ServiceId, ServiceResourceEraser, ServiceSupervisor, SharedAccess, SharedBindingError,
    SharedBufferSyscallError, SharedBufferSyscallExecutor, SharedEndpoint, SharedEndpointRequest,
    SharedMemoryBindings, TaskProtocolViolation, VmId, VmTable, decode_capability_transfers,
};
#[cfg(not(feature = "fault-probe"))]
use mrml_kernel::{
    BootHandoff, EarlyKernelContext, HANDOFF_HEADER_BYTES, MAX_HANDOFF_BYTES, MAX_HANDOFF_REGIONS,
    MemoryKind, MemoryRegion, PhysAddr,
};
#[cfg(all(
    not(feature = "fault-probe"),
    not(feature = "timer-probe"),
    not(feature = "preemption-probe"),
    not(feature = "service-preemption-probe"),
    not(feature = "application-probe"),
    not(feature = "user-probe"),
    not(feature = "service-probe")
))]
use mrml_kernel::{Color, FramebufferSurface};
#[cfg(feature = "smp-ipi-probe")]
use mrml_kernel::{DetachedTaskDomain, OwnershipMailbox, SchedulerLoad};
#[cfg(feature = "smp-periodic-balance-probe")]
use mrml_kernel::{DomainBalanceOutcome, PeriodicDomainBalancer};
#[cfg(any(feature = "user-probe", feature = "service-probe"))]
use mrml_kernel::{Endpoint, ObjectId, Rights};
#[cfg(all(not(feature = "fault-probe"), feature = "gpu-benchmark"))]
use mrml_kernel::{
    GPU_DOORBELL_PORT, GPU_QUEUE_MESSAGE_BYTES, GpuGuestCommandPublisher, GpuQueueIdentity,
    GpuQueueSender, GpuResourceResponse, GpuResourceResponseReceiver, GpuSharedRingIndices,
    ResourceCommand,
};
#[cfg(any(
    feature = "block-guest-driver-probe",
    feature = "pci-configuration-probe"
))]
use mrml_kernel::{PAGE_SIZE, VIRTUAL_BLOCK_CONFIGURATION_BYTES, VirtualBlockGuestDriver};
#[cfg(any(
    feature = "application-probe",
    feature = "timer-probe",
    feature = "deadline-receive-probe",
    feature = "preemption-probe",
    feature = "service-preemption-probe",
    feature = "user-probe",
    feature = "service-probe",
    feature = "smp-scheduler-probe",
    feature = "smp-ipi-probe"
))]
use mrml_kernel::{Priority, ScheduleOutcome};
#[cfg(any(
    feature = "block-guest-driver-probe",
    feature = "pci-configuration-probe"
))]
use mrml_kernel::{VIRTUAL_BLOCK_REQUEST_BYTES, VirtualBlockResumePage};

#[cfg(feature = "gpu-benchmark")]
const GPU_COMMAND_BASE: usize = 0x00b0_0000;
#[cfg(feature = "gpu-benchmark")]
const GPU_COMPLETION_BASE: usize = 0x00b0_1000;
#[cfg(feature = "gpu-benchmark")]
const GPU_BENCHMARK_ELEMENTS: u32 = 1 << 22;
#[cfg(feature = "gpu-benchmark")]
const GPU_BENCHMARK_ITERATIONS: u32 = 1_000;
#[cfg(any(
    feature = "block-guest-driver-probe",
    feature = "pci-configuration-probe"
))]
const BLOCK_CONFIGURATION_BASE: u64 = 0x0060_4000;
#[cfg(any(
    feature = "block-guest-driver-probe",
    feature = "pci-configuration-probe"
))]
const BLOCK_RESUME_BASE: u64 = 0x0060_5000;
#[cfg(any(
    feature = "block-guest-driver-probe",
    feature = "pci-configuration-probe"
))]
const BLOCK_PAYLOAD_BASE: u64 = 0x00a0_0000;
#[cfg(feature = "block-guest-driver-probe")]
const BLOCK_PROOF_PORT: u16 = 0x4d65;
#[cfg(feature = "block-guest-driver-probe")]
const BLOCK_PROBE_CYCLES: u32 = 8;
#[cfg(feature = "block-guest-driver-probe")]
const BLOCK_QUIESCE_CYCLE: u32 = BLOCK_PROBE_CYCLES / 2;
#[cfg(feature = "block-guest-driver-probe")]
const BLOCK_QUIESCE_REQUESTS: u32 = (BLOCK_QUIESCE_CYCLE - 1) * 4 + 2;
#[cfg(feature = "block-guest-driver-probe")]
const BLOCK_PROBE_OPERATIONS: u32 = BLOCK_PROBE_CYCLES * 4;
#[cfg(any(
    feature = "block-guest-driver-probe",
    feature = "pci-configuration-probe"
))]
const BLOCK_VECTOR: u8 = 48;
#[cfg(feature = "pci-configuration-probe")]
const PCI_PROOF_PORT: u16 = 0x4d66;
#[cfg(feature = "pci-configuration-probe")]
const PCI_WITHDRAW_PROOF_PORT: u16 = 0x4d67;
#[cfg(feature = "pci-configuration-probe")]
const PCI_TEST_SELECTOR: u32 = 0x8000_2000;
#[cfg(feature = "pci-configuration-probe")]
const PCI_TEST_CLASS_SELECTOR: u32 = PCI_TEST_SELECTOR + 8;
#[cfg(feature = "pci-configuration-probe")]
const PCI_TEST_BAR_SELECTOR: u32 = PCI_TEST_SELECTOR + 16;
#[cfg(feature = "pci-configuration-probe")]
const PCI_TEST_COMMAND_SELECTOR: u32 = PCI_TEST_SELECTOR + 4;
#[cfg(feature = "pci-configuration-probe")]
const PCI_TEST_MMIO_BASE: u64 = 0x00c0_0000;
#[cfg(feature = "pci-configuration-probe")]
const PCI_TEST_VENDOR_DEVICE: u32 = 0x5678_1234;
#[cfg(feature = "pci-configuration-probe")]
const PCI_TEST_CLASS: u32 = 0x0180_0001;
#[cfg(feature = "pci-configuration-probe")]
const PCI_BLOCK_PROBE_OPERATIONS: u32 = 5;
#[cfg(feature = "fault-probe")]
const EXCEPTION_PROBE_PORT: u16 = 0x4d53;
#[cfg(any(
    feature = "timer-probe",
    feature = "preemption-probe",
    feature = "service-preemption-probe"
))]
const TIMER_READY_PORT: u16 = 0x4d54;
#[cfg(feature = "timer-probe")]
const TIMER_TICK_PORT: u16 = 0x4d55;
#[cfg(any(
    feature = "timer-probe",
    feature = "deadline-receive-probe",
    feature = "preemption-probe",
    feature = "service-preemption-probe",
    feature = "smp-scheduler-probe",
    feature = "smp-periodic-balance-probe"
))]
const TIMER_VECTOR: u8 = 32;
#[cfg(feature = "smp-ipi-probe")]
const RESCHEDULE_VECTOR: u8 = 33;
#[cfg(feature = "user-probe")]
const USER_PROBE_PORT: u16 = 0x4d56;
#[cfg(feature = "user-probe")]
const USER_CALL_PROBE_PORT: u16 = 0x4d57;
#[cfg(feature = "application-probe")]
const APPLICATION_PROBE_PORT: u16 = 0x4d66;
#[cfg(feature = "service-probe")]
const SERVICE_PROBE_PORT: u16 = 0x4d58;
#[cfg(feature = "service-probe")]
const SERVICE_FRAME_PORT: u16 = 0x4d59;
#[cfg(feature = "service-probe")]
const SERVICE_CALL_PORT: u16 = 0x4d5a;
#[cfg(feature = "smp-probe")]
const SMP_PROBE_PORT: u16 = 0x4d5c;
#[cfg(any(
    feature = "whp-smp-probe",
    feature = "whp-smp-scheduler-probe",
    feature = "whp-smp-ipi-probe",
    feature = "whp-smp-service-migration-probe",
    feature = "whp-smp-periodic-balance-probe"
))]
const WHP_SMP_HANDSHAKE_PORT: u16 = 0x4d5d;
#[cfg(feature = "smp-scheduler-probe")]
const SMP_SCHEDULER_READY_PORT: u16 = 0x4d5e;
#[cfg(feature = "smp-scheduler-probe")]
const SMP_SCHEDULER_TICK_PORT: u16 = 0x4d5f;
#[cfg(feature = "smp-ipi-probe")]
const SMP_IPI_READY_PORT: u16 = 0x4d60;
#[cfg(all(
    feature = "smp-ipi-probe",
    not(feature = "smp-service-migration-probe"),
    not(feature = "smp-periodic-balance-probe")
))]
const SMP_IPI_PROOF_PORT: u16 = 0x4d61;
#[cfg(feature = "smp-service-migration-probe")]
const SMP_SERVICE_MIGRATION_PROOF_PORT: u16 = 0x4d62;
#[cfg(feature = "smp-periodic-balance-probe")]
const SMP_PERIODIC_APPLICATION_PORT: u16 = 0x4d63;
#[cfg(feature = "smp-periodic-balance-probe")]
const SMP_PERIODIC_BOOTSTRAP_PORT: u16 = 0x4d64;
#[cfg(any(
    feature = "service-probe",
    feature = "smp-service-migration-probe",
    all(
        feature = "service-preemption-probe",
        not(feature = "uefi-service-preemption-probe")
    )
))]
const SERVICE_ROOT: u64 = 0x00c0_0000;
#[cfg(feature = "service-probe")]
const SERVICE_B_ROOT: u64 = 0x00d0_0000;
#[cfg(any(
    feature = "service-restart-request-probe",
    feature = "deadline-receive-cancel-probe"
))]
const SERVICE_C_ROOT: u64 = 0x0140_0000;
#[cfg(any(
    feature = "smp-service-migration-probe",
    all(
        feature = "service-preemption-probe",
        not(feature = "uefi-service-preemption-probe")
    )
))]
const SERVICE_ENTRY: u64 = 0x0000_0001_4000_1000;
#[cfg(feature = "service-probe")]
const SERVICE_SHARED_PHYSICAL: u64 = 0x00f0_0000;
#[cfg(feature = "service-probe")]
const SERVICE_RESOURCE_VIRTUAL: u64 = 0x006f_f000;
#[cfg(feature = "service-probe")]
const SERVICE_PEER_RESOURCE_VIRTUAL: u64 = 0x006f_e000;
#[cfg(all(feature = "service-probe", not(feature = "block-service-probe")))]
#[cfg(any(
    feature = "service-probe",
    feature = "smp-service-migration-probe",
    all(
        feature = "service-preemption-probe",
        not(feature = "uefi-service-preemption-probe")
    )
))]
const SERVICE_STACK_TOP: u64 = 0x0070_8000;
#[cfg(feature = "block-service-probe")]
const SERVICE_STACK_TOP: u64 = 0x0080_0000;

static mut CPU0_DESCRIPTORS: CpuDescriptorState = CpuDescriptorState::empty(0);
struct ApDescriptorSlots([UnsafeCell<MaybeUninit<CpuDescriptorState>>; MAX_X86_64_CPUS]);
unsafe impl Sync for ApDescriptorSlots {}
// This storage is initialized independently by application processors after
// the image has been sealed. Force it into the writable PE data region;
// interior mutability alone is not a PE section-permission contract.
#[unsafe(link_section = ".data")]
static AP_DESCRIPTORS: ApDescriptorSlots =
    ApDescriptorSlots([const { UnsafeCell::new(MaybeUninit::uninit()) }; MAX_X86_64_CPUS]);
static AP_ONLINE: ApOnlineTable<MAX_X86_64_CPUS> = ApOnlineTable::empty();
#[cfg(any(feature = "smp-scheduler-probe", feature = "smp-ipi-probe"))]
struct ApSchedulerSlot {
    apic_id: AtomicU32,
    initialized: AtomicBool,
    #[cfg(feature = "smp-scheduler-probe")]
    scheduler: UnsafeCell<MaybeUninit<KernelScheduler<2>>>,
}
#[cfg(any(feature = "smp-scheduler-probe", feature = "smp-ipi-probe"))]
unsafe impl Sync for ApSchedulerSlot {}
#[cfg(any(feature = "smp-scheduler-probe", feature = "smp-ipi-probe"))]
impl ApSchedulerSlot {
    const fn empty() -> Self {
        Self {
            apic_id: AtomicU32::new(u32::MAX),
            initialized: AtomicBool::new(false),
            #[cfg(feature = "smp-scheduler-probe")]
            scheduler: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
}
#[cfg(any(feature = "smp-scheduler-probe", feature = "smp-ipi-probe"))]
struct ApSchedulerSlots([ApSchedulerSlot; MAX_X86_64_CPUS]);
#[cfg(any(feature = "smp-scheduler-probe", feature = "smp-ipi-probe"))]
unsafe impl Sync for ApSchedulerSlots {}
#[cfg(any(feature = "smp-scheduler-probe", feature = "smp-ipi-probe"))]
#[unsafe(link_section = ".data")]
static AP_SCHEDULERS: ApSchedulerSlots =
    ApSchedulerSlots([const { ApSchedulerSlot::empty() }; MAX_X86_64_CPUS]);
#[cfg(feature = "smp-ipi-probe")]
static AP_IPI_READY: [AtomicBool; MAX_X86_64_CPUS] =
    [const { AtomicBool::new(false) }; MAX_X86_64_CPUS];
#[cfg(feature = "smp-ipi-probe")]
static AP_RESCHEDULE_REQUEST: [AtomicBool; MAX_X86_64_CPUS] =
    [const { AtomicBool::new(false) }; MAX_X86_64_CPUS];
#[cfg(feature = "smp-ipi-probe")]
static AP_SCHEDULER_LOAD: [AtomicU32; MAX_X86_64_CPUS] =
    [const { AtomicU32::new(0) }; MAX_X86_64_CPUS];
#[cfg(all(feature = "smp-ipi-probe", not(feature = "smp-periodic-balance-probe")))]
struct SmpIpiRuntime(UnsafeCell<MaybeUninit<TaskRuntime<2, 1>>>);
#[cfg(feature = "smp-periodic-balance-probe")]
struct SmpIpiRuntime(UnsafeCell<MaybeUninit<TaskRuntime<3, 1>>>);
#[cfg(feature = "smp-ipi-probe")]
unsafe impl Sync for SmpIpiRuntime {}
#[cfg(feature = "smp-ipi-probe")]
#[unsafe(link_section = ".data")]
static SMP_IPI_RUNTIME: SmpIpiRuntime = SmpIpiRuntime(UnsafeCell::new(MaybeUninit::uninit()));
#[cfg(feature = "smp-ipi-probe")]
static SMP_MIGRATION_MAILBOX: OwnershipMailbox<DetachedTaskDomain<1>> = OwnershipMailbox::new();
#[cfg(feature = "smp-periodic-balance-probe")]
static SMP_LOCAL_MIGRATION_MAILBOX: OwnershipMailbox<DetachedTaskDomain<1>> =
    OwnershipMailbox::new();
#[cfg(feature = "smp-periodic-balance-probe")]
struct SmpPeriodicSource(UnsafeCell<MaybeUninit<TaskRuntime<5, 1>>>);
#[cfg(feature = "smp-periodic-balance-probe")]
unsafe impl Sync for SmpPeriodicSource {}
#[cfg(feature = "smp-periodic-balance-probe")]
#[unsafe(link_section = ".data")]
static SMP_PERIODIC_SOURCE: SmpPeriodicSource =
    SmpPeriodicSource(UnsafeCell::new(MaybeUninit::uninit()));
#[cfg(feature = "smp-periodic-balance-probe")]
struct SmpPeriodicPolicy(UnsafeCell<MaybeUninit<PeriodicDomainBalancer<2, 1>>>);
#[cfg(feature = "smp-periodic-balance-probe")]
unsafe impl Sync for SmpPeriodicPolicy {}
#[cfg(feature = "smp-periodic-balance-probe")]
#[unsafe(link_section = ".data")]
static SMP_PERIODIC_POLICY: SmpPeriodicPolicy =
    SmpPeriodicPolicy(UnsafeCell::new(MaybeUninit::uninit()));
#[cfg(feature = "smp-periodic-balance-probe")]
static SMP_PERIODIC_TARGET_CPU: AtomicU32 = AtomicU32::new(u32::MAX);
#[cfg(feature = "smp-periodic-balance-probe")]
static SMP_PERIODIC_TARGET_APIC: AtomicU32 = AtomicU32::new(u32::MAX);
#[cfg(feature = "smp-periodic-balance-probe")]
#[unsafe(link_section = ".data")]
static SMP_PERIODIC_ROUND: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "smp-periodic-balance-probe")]
#[unsafe(link_section = ".data")]
static SMP_PERIODIC_TIMER_TICK: AtomicU32 = AtomicU32::new(0);
#[cfg(not(feature = "fault-probe"))]
struct ApStartupWorkspace(UnsafeCell<MaybeUninit<ApStartupTable<MAX_X86_64_CPUS>>>);
#[cfg(not(feature = "fault-probe"))]
unsafe impl Sync for ApStartupWorkspace {}
#[cfg(not(feature = "fault-probe"))]
static AP_STARTUP_WORKSPACE: ApStartupWorkspace =
    ApStartupWorkspace(UnsafeCell::new(MaybeUninit::uninit()));
#[cfg(feature = "timer-probe")]
static mut TIMER_SCHEDULER: Option<KernelScheduler<1>> = None;
#[cfg(any(feature = "preemption-probe", feature = "service-preemption-probe"))]
static mut PREEMPTION_RUNTIME: Option<TaskRuntime<2, 0>> = None;
#[cfg(feature = "uefi-service-preemption-probe")]
static mut UEFI_SERVICE_RECOVERED: bool = false;
#[cfg(feature = "user-probe")]
static mut USER_RUNTIME: Option<TaskRuntime<2, 1>> = None;
#[cfg(feature = "user-probe")]
static mut USER_ENDPOINT: Option<Endpoint> = None;
#[cfg(feature = "application-probe")]
static mut APPLICATION_RUNTIME: Option<TaskRuntime<1, 0>> = None;
#[cfg(feature = "service-probe")]
const SERVICE_TASK_CAPACITY: usize = 3;
#[cfg(feature = "service-probe")]
const SERVICE_CAPABILITY_CAPACITY: usize = 9;
#[cfg(all(feature = "service-probe", not(feature = "component-service-probe")))]
static mut SERVICE_RUNTIME: Option<
    TaskRuntime<SERVICE_TASK_CAPACITY, SERVICE_CAPABILITY_CAPACITY>,
> = None;
#[cfg(feature = "component-service-probe")]
static mut SERVICE_RUNTIME: Option<
    AccountedTaskRuntime<SERVICE_TASK_CAPACITY, SERVICE_CAPABILITY_CAPACITY>,
> = None;
#[cfg(feature = "service-probe")]
static mut SERVICE_ENDPOINT: Option<Endpoint> = None;
#[cfg(all(feature = "service-probe", not(feature = "component-service-probe")))]
static mut SERVICE_SUPERVISOR: Option<ServiceSupervisor<SERVICE_TASK_CAPACITY>> = None;
#[cfg(feature = "component-service-probe")]
static mut SERVICE_SUPERVISOR: Option<AccountedServiceSupervisor<SERVICE_TASK_CAPACITY>> = None;
#[cfg(feature = "component-service-probe")]
static mut COMPONENT_SERVICE_MEMORY: Option<MemoryPoolTable<1, 2>> = None;
#[cfg(feature = "component-service-probe")]
static mut COMPONENT_SERVICE_MEMORY_AUTHORITIES: Option<CapabilitySpace<3>> = None;
#[cfg(feature = "component-service-probe")]
static mut COMPONENT_SERVICE_MEMORY_POOL: Option<(MemoryPoolId, Capability)> = None;
#[cfg(feature = "service-probe")]
static mut SERVICE_MANAGEMENT: Option<CapabilitySpace<3>> = None;
#[cfg(feature = "service-probe")]
static mut SERVICE_CONTROLS: Option<[Capability; 3]> = None;
#[cfg(feature = "service-probe")]
static mut SERVICE_IDS: Option<[ServiceId; 3]> = None;
#[cfg(feature = "service-probe")]
static mut SERVICE_RECEIVER_SIGNAL: Option<Capability> = None;
#[cfg(feature = "service-probe")]
static mut SERVICE_BOOT_RECOVERY: Option<BootRecoveryDelivery> = None;
#[cfg(feature = "service-probe")]
static mut SERVICE_RESTARTED: bool = false;
#[cfg(feature = "service-probe")]
static mut SERVICE_RESOURCE_VM_TABLE: Option<VmTable<1>> = None;
#[cfg(feature = "service-probe")]
static mut SERVICE_RESOURCE_VM: Option<VmId> = None;
#[cfg(feature = "service-probe")]
static mut SERVICE_RESOURCE_MEMORY: Option<GuestMemory<2>> = None;
#[cfg(feature = "service-probe")]
static mut SERVICE_RESOURCE_BINDINGS: Option<SharedMemoryBindings<4>> = None;
#[cfg(feature = "service-probe")]
static mut SERVICE_RESOURCES: Option<HostResourceTable<DirectHostResourceMemory, 1>> = None;
#[cfg(feature = "service-probe")]
static mut SERVICE_RESOURCE_SCRATCH: [u8; mrml_kernel::PAGE_SIZE as usize] =
    [0; mrml_kernel::PAGE_SIZE as usize];
#[cfg(feature = "service-probe")]
#[repr(C, align(4096))]
struct HostedServiceResourcePage([u8; mrml_kernel::PAGE_SIZE as usize]);
#[cfg(feature = "service-probe")]
static mut SERVICE_RESOURCE_PAGE: HostedServiceResourcePage =
    HostedServiceResourcePage([0; mrml_kernel::PAGE_SIZE as usize]);

#[cfg(feature = "service-probe")]
#[derive(Clone, Copy, Eq, PartialEq)]
struct PendingBufferReceive {
    task: mrml_kernel::TaskId,
    page_table: PhysAddr,
    payload_address: u64,
    payload_capacity: usize,
    capabilities_address: u64,
    capability_capacity: usize,
    wait: Option<mrml_kernel::BlockedReceive>,
}

#[cfg(feature = "service-probe")]
static mut SERVICE_PENDING_BUFFERS: [Option<PendingBufferReceive>; SERVICE_TASK_CAPACITY] =
    [None; SERVICE_TASK_CAPACITY];
#[cfg(feature = "service-probe")]
static mut SERVICE_PENDING_INLINE_WAITS: [Option<mrml_kernel::BlockedReceive>;
    SERVICE_TASK_CAPACITY] = [None; SERVICE_TASK_CAPACITY];
#[cfg(feature = "deadline-receive-probe")]
static mut SERVICE_DEADLINE_RECEIVES: Option<mrml_kernel::DeadlineReceiveSyscallExecutor<
    SERVICE_TASK_CAPACITY,
>> = None;
#[cfg(feature = "deadline-receive-probe")]
static mut SERVICE_DEADLINE_CANCELLATIONS: Option<mrml_kernel::DeadlineReceiveCancellationEscrow<
    SERVICE_TASK_CAPACITY,
>> = None;
#[cfg(feature = "buffer-drift-probe")]
static mut BUFFER_DRIFT_ARMED: bool = false;
#[cfg(feature = "service-probe")]
static mut SERVICE_SYSCALL_PAYLOAD: [u8; MAX_INLINE_PAYLOAD] = [0; MAX_INLINE_PAYLOAD];
#[cfg(feature = "service-probe")]
static mut SERVICE_SYSCALL_CAPABILITIES: [u8; MAX_CAPABILITIES
    * CAPABILITY_TRANSFER_DESCRIPTOR_BYTES] =
    [0; MAX_CAPABILITIES * CAPABILITY_TRANSFER_DESCRIPTOR_BYTES];

#[cfg(feature = "ahci-service-manager-probe")]
type BootAhciTeardownLease = mrml_storage_ahci::KernelAhciManagerTeardownLease<
    mrml_storage_ahci::AhciX86TeardownReacquisition<
        'static,
        mrml_storage_ahci::CurrentAhciX86ActiveMappingVerifier,
        ApStartupTiming,
    >,
>;

#[cfg(feature = "ahci-service-manager-probe")]
type BootAhciServiceManager = mrml_storage_ahci::KernelAhciServiceTeardownManager<
    'static,
    PreallocatedPageTableStore,
    BootAhciTeardownLease,
    1,
    4,
    4,
    SERVICE_TASK_CAPACITY,
    SERVICE_CAPABILITY_CAPACITY,
    { mrml_storage_ahci::AHCI_SERVICE_AUTHORITY_COUNT },
>;

#[cfg(feature = "ahci-service-manager-probe")]
static mut AHCI_SERVICE_MANAGER: BootAhciServiceManager = BootAhciServiceManager::empty();

#[cfg(feature = "service-probe")]
struct HostedServiceEraser;

#[cfg(any(feature = "block-service-probe", feature = "component-service-probe"))]
struct HostedUnmappedResourceRevoker;

#[cfg(any(feature = "block-service-probe", feature = "component-service-probe"))]
impl GuestMappingRevoker for HostedUnmappedResourceRevoker {
    type Error = ();

    fn revoke_guest_mapping(
        &mut self,
        _guest_address: u64,
        _bytes: u64,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(feature = "service-probe")]
impl ServiceAddressSpaceEraser for HostedServiceEraser {
    type Error = ();

    fn erase(
        &mut self,
        _task: mrml_kernel::TaskId,
        context: UserContext,
    ) -> Result<(), Self::Error> {
        let stage = if context.page_table().get() == SERVICE_ROOT {
            0x20u32
        } else if context.page_table().get() == SERVICE_B_ROOT {
            0x21u32
        } else {
            return Err(());
        };
        unsafe {
            asm!(
                "out dx, eax",
                in("dx") SERVICE_PROBE_PORT,
                in("eax") stage,
                options(nomem, nostack)
            )
        };
        Ok(())
    }
}

global_asm!(
    r#"
    .section .text
    .global mrml_exception_fail_stop
mrml_exception_fail_stop:
    cli
1:
    hlt
    jmp 1b

    .macro MRML_NO_ERROR vector
    .global mrml_exception_\vector
mrml_exception_\vector:
    push 0
    push \vector
    jmp mrml_exception_common
    .endm

    .macro MRML_ERROR vector
    .global mrml_exception_\vector
mrml_exception_\vector:
    push \vector
    jmp mrml_exception_common
    .endm

    MRML_NO_ERROR 0
    MRML_NO_ERROR 1
    MRML_NO_ERROR 2
    MRML_NO_ERROR 3
    MRML_NO_ERROR 4
    MRML_NO_ERROR 5
    MRML_NO_ERROR 6
    MRML_NO_ERROR 7
    MRML_ERROR 8
    MRML_NO_ERROR 9
    MRML_ERROR 10
    MRML_ERROR 11
    MRML_ERROR 12
    MRML_ERROR 13
    MRML_ERROR 14
    MRML_NO_ERROR 15
    MRML_NO_ERROR 16
    MRML_ERROR 17
    MRML_NO_ERROR 18
    MRML_NO_ERROR 19
    MRML_NO_ERROR 20
    MRML_ERROR 21
    MRML_NO_ERROR 22
    MRML_NO_ERROR 23
    MRML_NO_ERROR 24
    MRML_NO_ERROR 25
    MRML_NO_ERROR 26
    MRML_NO_ERROR 27
    MRML_NO_ERROR 28
    MRML_ERROR 29
    MRML_ERROR 30
    MRML_NO_ERROR 31

mrml_exception_common:
    cld
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rdi, rsp
    and rsp, -16
    call mrml_exception_dispatch
    ud2

    .global mrml_timer_interrupt
mrml_timer_interrupt:
    cld
    push 0
    push 32
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rdi, rsp
    and rsp, -16
    call mrml_timer_dispatch
    ud2

    .global mrml_reschedule_interrupt
mrml_reschedule_interrupt:
    cld
    push 0
    push 33
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rdi, rsp
    and rsp, -16
    call mrml_reschedule_dispatch
    ud2

    .global mrml_block_interrupt
mrml_block_interrupt:
    iretq

    .global mrml_user_probe
mrml_user_probe:
    int 0x80
    ud2
1:
    jmp 1b

    .global mrml_user_replacement_probe
mrml_user_replacement_probe:
    int3
2:
    jmp 2b

    .global mrml_preemption_spin
mrml_preemption_spin:
1:
    pause
    jmp 1b

    .global mrml_preemption_replacement
mrml_preemption_replacement:
    int3
3:
    pause
    jmp 3b

    .global mrml_user_call
mrml_user_call:
    cld
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rdi, rsp
    call mrml_user_call_dispatch
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    iretq
    ud2

    .section .rdata
    .balign 8
    .global mrml_exception_table
mrml_exception_table:
    .quad mrml_exception_0, mrml_exception_1, mrml_exception_2, mrml_exception_3
    .quad mrml_exception_4, mrml_exception_5, mrml_exception_6, mrml_exception_7
    .quad mrml_exception_8, mrml_exception_9, mrml_exception_10, mrml_exception_11
    .quad mrml_exception_12, mrml_exception_13, mrml_exception_14, mrml_exception_15
    .quad mrml_exception_16, mrml_exception_17, mrml_exception_18, mrml_exception_19
    .quad mrml_exception_20, mrml_exception_21, mrml_exception_22, mrml_exception_23
    .quad mrml_exception_24, mrml_exception_25, mrml_exception_26, mrml_exception_27
    .quad mrml_exception_28, mrml_exception_29, mrml_exception_30, mrml_exception_31
    "#
);

unsafe extern "C" {
    fn mrml_exception_fail_stop() -> !;
    #[cfg(any(
        feature = "timer-probe",
        feature = "deadline-receive-probe",
        feature = "preemption-probe",
        feature = "service-preemption-probe",
        feature = "smp-scheduler-probe",
        feature = "smp-periodic-balance-probe"
    ))]
    fn mrml_timer_interrupt() -> !;
    #[cfg(feature = "smp-ipi-probe")]
    fn mrml_reschedule_interrupt() -> !;
    #[cfg(any(
        feature = "block-guest-driver-probe",
        feature = "pci-configuration-probe"
    ))]
    fn mrml_block_interrupt() -> !;
    #[cfg(feature = "preemption-probe")]
    fn mrml_preemption_spin() -> !;
    #[cfg(feature = "preemption-probe")]
    fn mrml_preemption_replacement() -> !;
    #[cfg(feature = "user-probe")]
    fn mrml_user_probe() -> !;
    #[cfg(feature = "user-probe")]
    fn mrml_user_replacement_probe() -> !;
    #[cfg(feature = "user-probe")]
    fn mrml_user_call() -> !;
    #[cfg(all(
        any(
            feature = "application-probe",
            feature = "service-probe",
            feature = "smp-service-migration-probe"
        ),
        not(feature = "user-probe")
    ))]
    fn mrml_user_call() -> !;
    static mrml_exception_table: [u64; 32];
}

#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_user_call_dispatch(frame: *mut UserCallFrame) {
    #[cfg(feature = "application-probe")]
    unsafe {
        let frame = frame.as_mut().unwrap_or_else(|| halt());
        if frame.request().unwrap_or_else(|_| halt()) != SyscallRequest::Exit {
            halt();
        }
        let runtime = (*core::ptr::addr_of_mut!(APPLICATION_RUNTIME))
            .as_mut()
            .unwrap_or_else(|| halt());
        let current = runtime.current().unwrap_or_else(|| halt());
        let root = runtime
            .context(current)
            .unwrap_or_else(|_| halt())
            .page_table();
        *runtime.context_mut(current).unwrap_or_else(|_| halt()) =
            UserContext::from_user_call(root, frame).unwrap_or_else(|_| halt());
        if ActivePageTables::current()
            .unwrap_or_else(|_| halt())
            .root()
            != root
        {
            halt();
        }
        let terminated = runtime.terminate_current().unwrap_or_else(|_| halt());
        if terminated.task != current || terminated.next != ScheduleOutcome::Idle {
            halt();
        }
        asm!(
            "out dx, eax",
            in("dx") APPLICATION_PROBE_PORT,
            in("eax") 1u32,
            options(nomem, nostack)
        );
        halt();
    }
    #[cfg(feature = "user-probe")]
    unsafe {
        let frame = match frame.as_mut() {
            Some(frame) => frame,
            None => halt(),
        };
        let request = match frame.request() {
            Ok(request) => request,
            Err(_) => halt(),
        };
        let (endpoint_capability, receiver) = match &request {
            SyscallRequest::SendInline {
                endpoint, receiver, ..
            } => (*endpoint, *receiver),
            SyscallRequest::Yield
            | SyscallRequest::Receive
            | SyscallRequest::ReceiveFor { .. }
            | SyscallRequest::Exit
            | SyscallRequest::SendBuffer { .. }
            | SyscallRequest::ReceiveBuffer { .. }
            | SyscallRequest::AuthorizeCapability { .. }
            | SyscallRequest::ReleaseCapability { .. }
            | SyscallRequest::ReadSharedBuffer { .. }
            | SyscallRequest::WriteSharedBuffer { .. } => halt(),
        };
        let payload = request.payload();
        let runtime = match (*core::ptr::addr_of_mut!(USER_RUNTIME)).as_mut() {
            Some(runtime) => runtime,
            None => halt(),
        };
        let sender = match runtime.current() {
            Some(sender) => sender,
            None => halt(),
        };
        let endpoint = match (*core::ptr::addr_of_mut!(USER_ENDPOINT)).as_mut() {
            Some(endpoint) => endpoint,
            None => halt(),
        };
        let (sequence, message) = match runtime.send_ipc(
            sender,
            receiver,
            endpoint,
            endpoint_capability,
            payload,
            &[],
        ) {
            Ok(result) => result,
            Err(_) => halt(),
        };
        if sequence != 1 || message.payload() != b"ping" {
            halt();
        }
        frame.complete(sequence);
        asm!(
            "out dx, eax",
            in("dx") USER_CALL_PROBE_PORT,
            in("eax") sequence as u32,
            options(nomem, nostack)
        );
    }
    #[cfg(feature = "service-probe")]
    unsafe {
        let frame = match frame.as_mut() {
            Some(frame) => frame,
            None => halt(),
        };
        if frame.rax == BOOT_RECOVERY_SYSCALL_OPERATION {
            let request = match BootRecoverySyscallRequest::decode_frame(frame) {
                Ok(request) => request,
                Err(mrml_kernel::BootRecoverySyscallError::InvalidReturn(error)) => {
                    retire_service_protocol_violation(TaskProtocolViolation::InvalidUserReturn(
                        error,
                    ))
                }
                Err(_) => {
                    frame.complete_error();
                    return;
                }
            };
            let runtime = (*core::ptr::addr_of_mut!(SERVICE_RUNTIME))
                .as_mut()
                .unwrap_or_else(|| halt());
            let current = runtime.current().unwrap_or_else(|| halt());
            let root = runtime
                .context(current)
                .unwrap_or_else(|_| halt())
                .page_table();
            *runtime.context_mut(current).unwrap_or_else(|_| halt()) =
                UserContext::from_user_call(root, frame).unwrap_or_else(|_| halt());
            let active = ActivePageTables::current().unwrap_or_else(|_| halt());
            if active.root() != root {
                halt();
            }
            let delivery = (*core::ptr::addr_of_mut!(SERVICE_BOOT_RECOVERY))
                .as_mut()
                .unwrap_or_else(|| halt());
            let mut user = ActiveTaskUserCopy::new(&active, root, current, DirectActiveUserMemory);
            match BootRecoverySyscallExecutor::execute(
                request, runtime, current, delivery, &mut user,
            ) {
                Ok(()) => frame.complete(0),
                Err(mrml_kernel::BootRecoverySyscallError::UserValidation(
                    ActiveTaskUserCopyError::Buffer(_),
                ))
                | Err(mrml_kernel::BootRecoverySyscallError::Delivery(
                    mrml_kernel::BootRecoveryDeliveryError::WrongTask
                    | mrml_kernel::BootRecoveryDeliveryError::AlreadyDelivered
                    | mrml_kernel::BootRecoveryDeliveryError::Runtime(
                        mrml_kernel::TaskRuntimeError::Ipc(_),
                    ),
                )) => frame.complete_error(),
                Err(_) => halt(),
            }
            return;
        }
        let request = match frame.decode_request() {
            Ok(request) => request,
            Err(mrml_kernel::UserCallDecodeError::Return(error)) => {
                retire_service_protocol_violation(TaskProtocolViolation::InvalidUserReturn(error))
            }
            Err(mrml_kernel::UserCallDecodeError::Request(_)) => {
                frame.complete_error();
                return;
            }
        };
        let runtime = (*core::ptr::addr_of_mut!(SERVICE_RUNTIME))
            .as_mut()
            .unwrap_or_else(|| halt());
        let current = runtime.current().unwrap_or_else(|| halt());
        let root = runtime
            .context(current)
            .unwrap_or_else(|_| halt())
            .page_table();
        *runtime.context_mut(current).unwrap_or_else(|_| halt()) =
            UserContext::from_user_call(root, frame).unwrap_or_else(|_| halt());
        #[cfg(feature = "ahci-service-manager-probe")]
        if request == SyscallRequest::Exit {
            let manager = core::ptr::addr_of_mut!(AHCI_SERVICE_MANAGER)
                .as_mut()
                .unwrap_or_else(|| halt());
            if manager.active() && manager.task() == Some(current) {
                let supervisor = (*core::ptr::addr_of!(SERVICE_SUPERVISOR))
                    .as_ref()
                    .unwrap_or_else(|| halt());
                let routed = manager
                    .route_frame(frame, supervisor, runtime)
                    .unwrap_or_else(|_| halt());
                if routed.task() != current || manager.task() != Some(current) {
                    halt();
                }
                asm!(
                    "out dx, eax",
                    in("dx") SERVICE_PROBE_PORT,
                    in("eax") 0x32u32,
                    options(nomem, nostack)
                );
                halt();
            }
        }
        match request {
            SyscallRequest::ReceiveFor { timeout } => {
                #[cfg(feature = "deadline-receive-probe")]
                {
                    let executor = (*core::ptr::addr_of_mut!(SERVICE_DEADLINE_RECEIVES))
                        .as_mut()
                        .unwrap_or_else(|| halt());
                    let escrow = deadline_cancellation_escrow();
                    executor
                        .validate_escrow(escrow)
                        .unwrap_or_else(|_| halt());
                    match executor.start(runtime, timeout).unwrap_or_else(|_| halt()) {
                        mrml_kernel::DeadlineReceiveStart::Ready(message) => {
                            frame.complete_message(message.payload())
                        }
                        mrml_kernel::DeadlineReceiveStart::TimedOut => frame.complete_timeout(),
                        mrml_kernel::DeadlineReceiveStart::IncompatibleMessage => {
                            frame.complete_error()
                        }
                        mrml_kernel::DeadlineReceiveStart::Blocked {
                            scheduling: ScheduleOutcome::Switch { to, .. },
                            cancellation,
                        } => {
                            escrow
                                .retain(cancellation)
                                .unwrap_or_else(|_| halt());
                            executor
                                .validate_escrow(escrow)
                                .unwrap_or_else(|_| halt());
                            enter_service_task(runtime, to)
                        }
                        mrml_kernel::DeadlineReceiveStart::Blocked { .. } => halt(),
                    }
                }
                #[cfg(not(feature = "deadline-receive-probe"))]
                {
                    let _ = timeout;
                    frame.complete_error();
                }
            }
            SyscallRequest::CancelReceive {
                capability,
                service,
            } => {
                #[cfg(feature = "deadline-receive-probe")]
                {
                    let supervisor = (*core::ptr::addr_of!(SERVICE_SUPERVISOR))
                        .as_ref()
                        .unwrap_or_else(|| halt());
                    let executor = (*core::ptr::addr_of_mut!(SERVICE_DEADLINE_RECEIVES))
                        .as_mut()
                        .unwrap_or_else(|| halt());
                    let escrow = deadline_cancellation_escrow();
                    executor
                        .validate_escrow(escrow)
                        .unwrap_or_else(|_| halt());
                    let cancellation = supervisor.cancel_escrowed_deadline_receive_for_requester(
                        service,
                        current,
                        capability,
                        runtime,
                        executor,
                        escrow,
                    );
                    executor
                        .validate_escrow(escrow)
                        .unwrap_or_else(|_| halt());
                    match cancellation {
                        Ok(()) => frame.complete(0),
                        Err(
                            mrml_kernel::ServiceDeadlineCancellationError::Service(
                                mrml_kernel::ServiceError::InvalidService
                                | mrml_kernel::ServiceError::TaskMismatch
                                | mrml_kernel::ServiceError::Unauthorized(_)
                                | mrml_kernel::ServiceError::Runtime(
                                    mrml_kernel::TaskRuntimeError::Ipc(_),
                                ),
                            )
                            | mrml_kernel::ServiceDeadlineCancellationError::Deadline(
                                mrml_kernel::DeadlineReceiveSyscallError::OwnerMismatch,
                            ),
                        ) => frame.complete_error(),
                        Err(_) => halt(),
                    }
                }
                #[cfg(not(feature = "deadline-receive-probe"))]
                {
                    let _ = (capability, service);
                    frame.complete_error();
                }
            }
            SyscallRequest::Receive => {
                #[cfg(feature = "deadline-receive-probe")]
                frame.complete_error();
                #[cfg(not(feature = "deadline-receive-probe"))]
                match runtime
                    .receive_or_block_current()
                    .unwrap_or_else(|_| halt())
                {
                    Ok(message) => frame.complete_message(message.payload()),
                    Err(blocked) if matches!(blocked.outcome(), ScheduleOutcome::Switch { .. }) => {
                        let ScheduleOutcome::Switch { to, .. } = blocked.outcome() else {
                            halt()
                        };
                        insert_pending_inline_wait(blocked);
                        asm!(
                            "out dx, eax",
                            in("dx") SERVICE_CALL_PORT,
                            in("eax") 1u32,
                            options(nomem, nostack)
                        );
                        if core::ptr::addr_of!(SERVICE_RESTARTED).read()
                            && root.get() == SERVICE_B_ROOT
                            && !has_pending_buffer(current)
                        {
                            commit_pending_inline_wait(to);
                            let message = runtime.receive_ipc(to).unwrap_or_else(|_| halt());
                            runtime
                                .context_mut(to)
                                .unwrap_or_else(|_| halt())
                                .complete_message(message.payload());
                        }
                        enter_service_task(runtime, to)
                    }
                    _ => halt(),
                }
            },
            SyscallRequest::SendInline {
                endpoint,
                receiver,
                payload,
                length,
            } => {
                let endpoint_object = (*core::ptr::addr_of_mut!(SERVICE_ENDPOINT))
                    .as_mut()
                    .unwrap_or_else(|| halt());
                #[cfg(feature = "deadline-receive-probe")]
                let sequence = match deadline_deliver_ipc(
                    runtime,
                    current,
                    receiver,
                    endpoint_object,
                    endpoint,
                    &payload[..usize::from(length)],
                    &[],
                ) {
                    Ok(sequence) => sequence,
                    Err(mrml_kernel::DeadlineReceiveSyscallError::MessageShape) => {
                        frame.complete_error();
                        return;
                    }
                    Err(mrml_kernel::DeadlineReceiveSyscallError::Runtime(error))
                        if error.is_precommit_send_denial() =>
                    {
                        frame.complete_error();
                        return;
                    }
                    Err(_) => halt(),
                };
                #[cfg(not(feature = "deadline-receive-probe"))]
                let sequence = match runtime.deliver_ipc(
                    current,
                    receiver,
                    endpoint_object,
                    endpoint,
                    &payload[..usize::from(length)],
                    &[],
                ) {
                    Ok(sequence) => sequence,
                    Err(error) if error.is_precommit_send_denial() => {
                        frame.complete_error();
                        return;
                    }
                    Err(_) => halt(),
                };
                frame.complete(sequence);
                asm!(
                    "out dx, eax",
                    in("dx") SERVICE_CALL_PORT,
                    in("eax") 2u32,
                    options(nomem, nostack)
                );
            }
            SyscallRequest::SendBuffer {
                endpoint,
                receiver,
                payload_address,
                payload_length,
                capabilities_address,
                capability_count,
            } => {
                let payload_length = usize::from(payload_length);
                let payload_storage = &mut *core::ptr::addr_of_mut!(SERVICE_SYSCALL_PAYLOAD);
                payload_storage.fill(0);
                let payload = &mut payload_storage[..payload_length];
                if !try_copy_from_active_user(root, current, payload_address, payload) {
                    payload_storage.fill(0);
                    frame.complete_error();
                    return;
                }
                let capability_count = usize::from(capability_count);
                let descriptor_length = capability_count
                    .checked_mul(CAPABILITY_TRANSFER_DESCRIPTOR_BYTES)
                    .unwrap_or_else(|| halt());
                let descriptor_storage =
                    &mut *core::ptr::addr_of_mut!(SERVICE_SYSCALL_CAPABILITIES);
                descriptor_storage.fill(0);
                let descriptor_bytes = &mut descriptor_storage[..descriptor_length];
                if descriptor_length != 0
                    && !try_copy_from_active_user(
                        root,
                        current,
                        capabilities_address,
                        descriptor_bytes,
                    )
                {
                    payload_storage.fill(0);
                    descriptor_storage.fill(0);
                    frame.complete_error();
                    return;
                }
                let mut descriptors = [None; MAX_CAPABILITIES];
                if decode_capability_transfers(descriptor_bytes, capability_count, &mut descriptors)
                    .is_err()
                {
                    payload_storage.fill(0);
                    descriptor_storage.fill(0);
                    frame.complete_error();
                    return;
                }
                let mut requested = [(Capability::from_token(0), Rights::NONE); MAX_CAPABILITIES];
                for (slot, descriptor) in requested
                    .iter_mut()
                    .zip(descriptors[..capability_count].iter().flatten())
                {
                    *slot = (descriptor.capability, descriptor.rights);
                }
                descriptors.fill(None);
                descriptor_storage.fill(0);
                let endpoint_object = (*core::ptr::addr_of_mut!(SERVICE_ENDPOINT))
                    .as_mut()
                    .unwrap_or_else(|| halt());
                #[cfg(feature = "deadline-receive-probe")]
                let delivery = deadline_deliver_ipc(
                    runtime,
                    current,
                    receiver,
                    endpoint_object,
                    endpoint,
                    payload,
                    &requested[..capability_count],
                );
                #[cfg(not(feature = "deadline-receive-probe"))]
                let delivery = runtime.deliver_ipc(
                    current,
                    receiver,
                    endpoint_object,
                    endpoint,
                    payload,
                    &requested[..capability_count],
                );
                payload_storage.fill(0);
                requested.fill((Capability::from_token(0), Rights::NONE));
                let sequence = match delivery {
                    Ok(sequence) => sequence,
                    #[cfg(feature = "deadline-receive-probe")]
                    Err(mrml_kernel::DeadlineReceiveSyscallError::MessageShape) => {
                        frame.complete_error();
                        return;
                    }
                    #[cfg(feature = "deadline-receive-probe")]
                    Err(mrml_kernel::DeadlineReceiveSyscallError::Runtime(error))
                        if error.is_precommit_send_denial() =>
                    {
                        frame.complete_error();
                        return;
                    }
                    #[cfg(not(feature = "deadline-receive-probe"))]
                    Err(error) if error.is_precommit_send_denial() => {
                        frame.complete_error();
                        return;
                    }
                    Err(_) => halt(),
                };
                frame.complete(sequence);
                asm!(
                    "out dx, eax",
                    in("dx") SERVICE_CALL_PORT,
                    in("eax") 2u32,
                    options(nomem, nostack)
                );
            }
            SyscallRequest::ReceiveBuffer {
                payload_address,
                payload_capacity,
                capabilities_address,
                capability_capacity,
            } => {
                let pending = PendingBufferReceive {
                    task: current,
                    page_table: root,
                    payload_address,
                    payload_capacity: usize::from(payload_capacity),
                    capabilities_address,
                    capability_capacity: usize::from(capability_capacity),
                    wait: None,
                };
                if !active_receive_is_valid(root, pending) {
                    frame.complete_error();
                    return;
                }
                match runtime.receive_ipc_bounded(
                    current,
                    pending.payload_capacity,
                    pending.capability_capacity,
                ) {
                    Ok(message) => complete_buffer_current(root, pending, &message, frame),
                    Err(mrml_kernel::TaskRuntimeError::ReceiveCapacity) => {
                        frame.complete_error();
                    }
                    Err(mrml_kernel::TaskRuntimeError::InboxEmpty) => {
                        let pending_slot = pending_buffer_insert_slot(current);
                        match runtime
                            .receive_or_block_current()
                            .unwrap_or_else(|_| halt())
                        {
                            Ok(_) => halt(),
                            Err(blocked)
                                if matches!(blocked.outcome(), ScheduleOutcome::Switch { .. }) =>
                            {
                                let ScheduleOutcome::Switch { to, .. } = blocked.outcome() else {
                                    halt()
                                };
                                let pending = PendingBufferReceive {
                                    wait: Some(blocked),
                                    ..pending
                                };
                                insert_pending_buffer(pending_slot, pending);
                                asm!(
                                    "out dx, eax",
                                    in("dx") SERVICE_CALL_PORT,
                                    in("eax") 1u32,
                                    options(nomem, nostack)
                                );
                                enter_service_task(runtime, to)
                            }
                            _ => halt(),
                        }
                    }
                    Err(_) => halt(),
                }
            }
            SyscallRequest::AuthorizeCapability {
                capability,
                object,
                rights,
            } => {
                let authorized =
                    match runtime.authorize_capability_exact(current, capability, rights, object) {
                        Ok(()) => true,
                        Err(mrml_kernel::TaskRuntimeError::Ipc(_)) => false,
                        Err(_) => halt(),
                    };
                frame.complete_authorization(authorized);
            }
            SyscallRequest::ReleaseCapability { capability } => {
                let released = match runtime.revoke_capability(current, capability) {
                    Ok(()) => true,
                    Err(mrml_kernel::TaskRuntimeError::Ipc(_)) => false,
                    Err(_) => halt(),
                };
                frame.complete_authorization(released);
            }
            request @ (SyscallRequest::ReadSharedBuffer { .. }
            | SyscallRequest::WriteSharedBuffer { .. }) => {
                let active = ActivePageTables::current().unwrap_or_else(|_| halt());
                if active.root() != root {
                    halt();
                }
                let vm = (*core::ptr::addr_of!(SERVICE_RESOURCE_VM)).unwrap_or_else(|| halt());
                let memory = (*core::ptr::addr_of!(SERVICE_RESOURCE_MEMORY))
                    .as_ref()
                    .unwrap_or_else(|| halt());
                let bindings = (*core::ptr::addr_of!(SERVICE_RESOURCE_BINDINGS))
                    .as_ref()
                    .unwrap_or_else(|| halt());
                let resources = (*core::ptr::addr_of_mut!(SERVICE_RESOURCES))
                    .as_mut()
                    .unwrap_or_else(|| halt());
                let scratch = core::slice::from_raw_parts_mut(
                    core::ptr::addr_of_mut!(SERVICE_RESOURCE_SCRATCH).cast::<u8>(),
                    mrml_kernel::PAGE_SIZE as usize,
                );
                let mut user =
                    ActiveTaskUserCopy::new(&active, root, current, DirectActiveUserMemory);
                let result = SharedBufferSyscallExecutor::execute(
                    request, runtime, current, vm, bindings, memory, resources, &mut user, scratch,
                );
                match result {
                    Ok(()) => frame.complete(0),
                    Err(
                        SharedBufferSyscallError::ScratchTooSmall
                        | SharedBufferSyscallError::Authorization(
                            IpcSharedBufferError::Ipc(
                                IpcError::PayloadTooLarge
                                | IpcError::TooManyCapabilities
                                | IpcError::Unauthorized
                                | IpcError::BufferTooSmall
                                | IpcError::Malformed
                                | IpcError::Replay
                                | IpcError::CapabilityShape,
                            )
                            | IpcSharedBufferError::AccessMismatch
                            | IpcSharedBufferError::Binding(
                                SharedBindingError::MissingBinding
                                | SharedBindingError::AmbiguousBinding
                                | SharedBindingError::StaleBinding
                                | SharedBindingError::StaleMapping
                                | SharedBindingError::WrongVm
                                | SharedBindingError::WrongTask
                                | SharedBindingError::WrongMapping
                                | SharedBindingError::WrongObject
                                | SharedBindingError::AccessDenied
                                | SharedBindingError::ExecutableMapping
                                | SharedBindingError::ResourceMismatch
                                | SharedBindingError::Capability(_),
                            ),
                        )
                        | SharedBufferSyscallError::Buffer(
                            IpcSharedBufferIoError::Authorization(
                                IpcSharedBufferError::Ipc(
                                    IpcError::PayloadTooLarge
                                    | IpcError::TooManyCapabilities
                                    | IpcError::Unauthorized
                                    | IpcError::BufferTooSmall
                                    | IpcError::Malformed
                                    | IpcError::Replay
                                    | IpcError::CapabilityShape,
                                )
                                | IpcSharedBufferError::AccessMismatch
                                | IpcSharedBufferError::Binding(
                                    SharedBindingError::MissingBinding
                                    | SharedBindingError::AmbiguousBinding
                                    | SharedBindingError::StaleBinding
                                    | SharedBindingError::StaleMapping
                                    | SharedBindingError::WrongVm
                                    | SharedBindingError::WrongTask
                                    | SharedBindingError::WrongMapping
                                    | SharedBindingError::WrongObject
                                    | SharedBindingError::AccessDenied
                                    | SharedBindingError::ExecutableMapping
                                    | SharedBindingError::ResourceMismatch
                                    | SharedBindingError::Capability(_),
                                ),
                            )
                            | IpcSharedBufferIoError::Empty
                            | IpcSharedBufferIoError::OutOfRange
                            | IpcSharedBufferIoError::AccessDenied
                            | IpcSharedBufferIoError::Backend(
                                HostResourceIoError::Empty
                                | HostResourceIoError::OutOfRange
                                | HostResourceIoError::StaleHandle,
                            ),
                        )
                        | SharedBufferSyscallError::UserValidation(ActiveTaskUserCopyError::Buffer(
                            _,
                        )),
                    ) => frame.complete_error(),
                    Err(_) => halt(),
                }
            }
            SyscallRequest::QueryService {
                capability,
                service,
            } => {
                let supervisor = (*core::ptr::addr_of!(SERVICE_SUPERVISOR))
                    .as_ref()
                    .unwrap_or_else(|| halt());
                let capabilities = runtime.capabilities(current).unwrap_or_else(|_| halt());
                let state = match supervisor.state_authorized(service, capabilities, capability) {
                    Ok(state) => Some(state),
                    Err(
                        mrml_kernel::ServiceError::InvalidService
                        | mrml_kernel::ServiceError::Unauthorized(_),
                    ) => None,
                    Err(_) => halt(),
                };
                frame.complete_service_state(state);
            }
            SyscallRequest::RestartService {
                capability,
                service,
            } => {
                #[cfg(feature = "service-restart-request-probe")]
                {
                    let replacement =
                        restart_sender_from_request(runtime, current, capability, service);
                    frame.complete_service_restart(replacement);
                }
                #[cfg(not(feature = "service-restart-request-probe"))]
                {
                    let _ = (capability, service);
                    // A userspace request carries neither launch context nor time.
                    // Until an exact trusted reprovision plan is staged, restart
                    // remains unavailable rather than falling back to request data.
                    frame.complete_service_restart(None);
                }
            }
            SyscallRequest::ReplaceServicePolicy {
                capability,
                service,
                policy,
            } => {
                #[cfg(feature = "service-probe")]
                {
                    let supervisor = (*core::ptr::addr_of_mut!(SERVICE_SUPERVISOR))
                        .as_mut()
                        .unwrap_or_else(|| halt());
                    let replaced = match supervisor.replace_restart_policy(
                        service,
                        runtime.capabilities(current).unwrap_or_else(|_| halt()),
                        capability,
                        policy,
                    ) {
                        Ok(()) => true,
                        Err(
                            mrml_kernel::ServiceError::InvalidService
                            | mrml_kernel::ServiceError::Unauthorized(_),
                        ) => false,
                        Err(_) => halt(),
                    };
                    frame.complete_policy_replacement(replaced);
                }
                #[cfg(not(feature = "service-probe"))]
                {
                    let _ = (capability, service, policy);
                    frame.complete_policy_replacement(false);
                }
            }
            SyscallRequest::Yield => match runtime.yield_current().unwrap_or_else(|_| halt()) {
                ScheduleOutcome::Switch { to, .. } => {
                    #[cfg(feature = "deadline-receive-probe")]
                    {
                        let executor = (*core::ptr::addr_of!(SERVICE_DEADLINE_RECEIVES))
                            .as_ref()
                            .unwrap_or_else(|| halt());
                        if executor.has_pending(to).unwrap_or_else(|_| halt()) {
                            halt();
                        }
                    }
                    #[cfg(not(feature = "deadline-receive-probe"))]
                    if !has_pending_buffer(to) {
                        commit_pending_inline_wait(to);
                        let message = runtime.receive_ipc(to).unwrap_or_else(|_| halt());
                        runtime
                            .context_mut(to)
                            .unwrap_or_else(|_| halt())
                            .complete_message(message.payload());
                    }
                    asm!(
                        "out dx, eax",
                        in("dx") SERVICE_CALL_PORT,
                        in("eax") 3u32,
                        options(nomem, nostack)
                    );
                    enter_service_task(runtime, to)
                }
                _ => halt(),
            },
            SyscallRequest::Exit => {
                #[cfg(feature = "component-service-probe")]
                {
                    let supervisor = (*core::ptr::addr_of_mut!(SERVICE_SUPERVISOR))
                        .as_mut()
                        .unwrap_or_else(|| halt());
                    let terminated = supervisor.exit_current(runtime).unwrap_or_else(|_| halt());
                    if terminated.task != current || runtime.context(current).is_ok() {
                        halt();
                    }
                    complete_service_cleanup(supervisor, terminated.cleanup);
                    match terminated.dispatch.user().map(|(task, _)| task) {
                        Some(to) => enter_service_dispatch(runtime, to, terminated.dispatch),
                        None => {
                            let _ = runtime
                                .consume_idle_dispatch(terminated.dispatch)
                                .unwrap_or_else(|_| halt());
                            let ids = (*core::ptr::addr_of!(SERVICE_IDS)).unwrap_or_else(|| halt());
                            if ids[..2].iter().any(|service| {
                                supervisor.task(*service) != Ok(None)
                                    || supervisor.pending_cleanup(*service) != Ok(None)
                                    || supervisor.state(*service)
                                        != Ok(mrml_kernel::ServiceState::Exited)
                            }) {
                                halt();
                            }
                            release_component_service_accounting();
                            asm!(
                                "out dx, eax",
                                in("dx") SERVICE_PROBE_PORT,
                                in("eax") 0x40u32,
                                options(nomem, nostack)
                            );
                            halt();
                        }
                        _ => halt(),
                    }
                }
                #[cfg(all(
                    not(feature = "component-service-probe"),
                    feature = "block-service-probe"
                ))]
                {
                    let supervisor = (*core::ptr::addr_of_mut!(SERVICE_SUPERVISOR))
                        .as_mut()
                        .unwrap_or_else(|| halt());
                    let terminated = supervisor.exit_current(runtime).unwrap_or_else(|_| halt());
                    if terminated.task != current || runtime.context(current).is_ok() {
                        halt();
                    }
                    complete_service_cleanup(supervisor, terminated.cleanup);
                    match terminated.dispatch.user().map(|(task, _)| task) {
                        Some(to) => {
                            let ControlEvent::PeerDied(death) =
                                runtime.receive_control(to).unwrap_or_else(|_| halt())
                            else {
                                halt()
                            };
                            if death.peer() != current
                                || death.reason() != PeerDeathReason::Exited
                                || runtime.context(to).is_err()
                            {
                                halt();
                            }
                            asm!(
                                "out dx, eax",
                                in("dx") SERVICE_PROBE_PORT,
                                in("eax") 0x31u32,
                                options(nomem, nostack)
                            );
                            enter_service_dispatch(runtime, to, terminated.dispatch)
                        }
                        None => {
                            let _ = runtime
                                .consume_idle_dispatch(terminated.dispatch)
                                .unwrap_or_else(|_| halt());
                            let ids = (*core::ptr::addr_of!(SERVICE_IDS)).unwrap_or_else(|| halt());
                            if ids[..2].iter().any(|service| {
                                supervisor.task(*service) != Ok(None)
                                    || supervisor.pending_cleanup(*service) != Ok(None)
                                    || supervisor.state(*service)
                                        != Ok(mrml_kernel::ServiceState::Exited)
                            }) {
                                halt();
                            }
                            asm!(
                                "out dx, eax",
                                in("dx") SERVICE_PROBE_PORT,
                                in("eax") 0x30u32,
                                options(nomem, nostack)
                            );
                            halt();
                        }
                        _ => halt(),
                    }
                }
                #[cfg(feature = "deadline-receive-cancel-probe")]
                {
                    let supervisor = (*core::ptr::addr_of_mut!(SERVICE_SUPERVISOR))
                        .as_mut()
                        .unwrap_or_else(|| halt());
                    let ids = (*core::ptr::addr_of!(SERVICE_IDS)).unwrap_or_else(|| halt());
                    if supervisor.task(ids[2]) != Ok(Some(current)) {
                        halt();
                    }
                    let terminated = supervisor.exit_current(runtime).unwrap_or_else(|_| halt());
                    if terminated.task != current || runtime.context(current).is_ok() {
                        halt();
                    }
                    complete_service_cleanup(supervisor, terminated.cleanup);
                    if supervisor.task(ids[2]) != Ok(None)
                        || supervisor.pending_cleanup(ids[2]) != Ok(None)
                        || supervisor.state(ids[2]) != Ok(mrml_kernel::ServiceState::Exited)
                    {
                        halt();
                    }
                    match terminated.dispatch.user().map(|(task, _)| task) {
                        Some(to) => enter_service_dispatch(runtime, to, terminated.dispatch),
                        None => halt(),
                    }
                }
                #[cfg(not(any(
                    feature = "component-service-probe",
                    feature = "block-service-probe",
                    feature = "deadline-receive-cancel-probe"
                )))]
                {
                    let supervisor = (*core::ptr::addr_of_mut!(SERVICE_SUPERVISOR))
                        .as_mut()
                        .unwrap_or_else(|| halt());
                    let terminated = supervisor.exit_current(runtime).unwrap_or_else(|_| halt());
                    if terminated.task != current || runtime.context(current).is_ok() {
                        halt();
                    }
                    complete_service_cleanup(supervisor, terminated.cleanup);
                    match terminated.dispatch.user().map(|(task, _)| task) {
                        Some(to) => {
                            let ControlEvent::PeerDied(death) =
                                runtime.receive_control(to).unwrap_or_else(|_| halt())
                            else {
                                halt()
                            };
                            if death.peer() != current || death.reason() != PeerDeathReason::Exited
                            {
                                halt();
                            }
                            asm!(
                                "out dx, eax",
                                in("dx") SERVICE_PROBE_PORT,
                                in("eax") 0x22u32,
                                options(nomem, nostack)
                            );
                            asm!(
                                "out dx, eax",
                                in("dx") SERVICE_CALL_PORT,
                                in("eax") 3u32,
                                options(nomem, nostack)
                            );
                            enter_service_dispatch(runtime, to, terminated.dispatch)
                        }
                        #[cfg(any(
                            feature = "invalid-return-probe",
                            feature = "buffer-drift-probe"
                        ))]
                        None => {
                            let _ = runtime
                                .consume_idle_dispatch(terminated.dispatch)
                                .unwrap_or_else(|_| halt());
                            let ids = (*core::ptr::addr_of!(SERVICE_IDS)).unwrap_or_else(|| halt());
                            if supervisor.task(ids[0]) != Ok(None)
                                || supervisor.pending_cleanup(ids[0]) != Ok(None)
                                || supervisor.state(ids[0])
                                    != Ok(mrml_kernel::ServiceState::Faulted)
                                || supervisor.task(ids[1]) != Ok(None)
                                || supervisor.pending_cleanup(ids[1]) != Ok(None)
                                || supervisor.state(ids[1]) != Ok(mrml_kernel::ServiceState::Exited)
                            {
                                halt();
                            }
                            #[cfg(feature = "invalid-return-probe")]
                            service_restart_stage(0x27);
                            #[cfg(feature = "buffer-drift-probe")]
                            service_restart_stage(0x29);
                            halt();
                        }
                        _ => halt(),
                    }
                }
            }
        }
    }
    #[cfg(feature = "smp-service-migration-probe")]
    unsafe {
        let frame = frame.as_mut().unwrap_or_else(|| halt());
        if frame.request().unwrap_or_else(|_| halt()) != SyscallRequest::Receive {
            halt();
        }
        let runtime = (&mut *SMP_IPI_RUNTIME.0.get()).assume_init_mut();
        let task = runtime.current().unwrap_or_else(|| halt());
        let context = runtime.context(task).unwrap_or_else(|_| halt());
        if context.page_table() != PhysAddr::new(SERVICE_ROOT).unwrap_or_else(|_| halt()) {
            halt();
        }
        let apic_id = current_apic_id().unwrap_or_else(|| halt());
        let cpu = AP_SCHEDULERS
            .0
            .iter()
            .enumerate()
            .find(|(_, slot)| {
                slot.initialized.load(Ordering::Acquire)
                    && slot.apic_id.load(Ordering::Acquire) == apic_id
            })
            .map(|(cpu, _)| cpu)
            .unwrap_or_else(|| halt());
        asm!(
            "out dx, eax",
            in("dx") SMP_SERVICE_MIGRATION_PROOF_PORT,
            in("eax") ((cpu as u32) << 16) | task.token() as u32,
            options(nomem, nostack)
        );
        halt()
    }
    #[cfg(not(any(
        feature = "application-probe",
        feature = "user-probe",
        feature = "service-probe",
        feature = "smp-service-migration-probe"
    )))]
    let _ = frame;
}

#[cfg(feature = "smp-periodic-balance-probe")]
unsafe fn publish_periodic_balance_tick(expected_tick: u32) {
    smp_trace(0x80u8.saturating_add(expected_tick as u8));
    let target_cpu = SMP_PERIODIC_TARGET_CPU.load(Ordering::Acquire) as usize;
    let target_apic = SMP_PERIODIC_TARGET_APIC.load(Ordering::Acquire);
    if target_cpu != 1 || target_apic == u32::MAX {
        halt();
    }
    let remote = AP_SCHEDULER_LOAD[target_cpu].load(Ordering::Acquire);
    let remote_load = SchedulerLoad::new((remote >> 16) as usize, (remote & 0xffff) as usize, 3)
        .unwrap_or_else(|| halt());
    let runtime = unsafe { (&mut *SMP_PERIODIC_SOURCE.0.get()).assume_init_mut() };
    let loads = [runtime.load(), remote_load];
    let mailboxes = [&SMP_LOCAL_MIGRATION_MAILBOX, &SMP_MIGRATION_MAILBOX];
    let policy = unsafe { (&mut *SMP_PERIODIC_POLICY.0.get()).assume_init_mut() };
    let outcome = policy
        .timer_tick_and_publish(0, &loads, runtime, &mailboxes)
        .unwrap_or_else(|_| halt());
    smp_trace(0x82u8.saturating_add(expected_tick as u8));
    if runtime.ticks() != u64::from(expected_tick)
        || !matches!(
            outcome.balancing(),
            DomainBalanceOutcome::Published(target) if target.cpu() == target_cpu
        )
    {
        halt();
    }
    if AP_RESCHEDULE_REQUEST[target_cpu]
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        halt();
    }
    unsafe { ApicIpi::fixed(target_apic, RESCHEDULE_VECTOR).and_then(|ipi| ipi.send()) }
        .unwrap_or_else(|_| halt());
    smp_trace(0x84u8.saturating_add(expected_tick as u8));
    while SMP_PERIODIC_ROUND.load(Ordering::Acquire) < expected_tick {
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
    if SMP_PERIODIC_ROUND.load(Ordering::Acquire) != expected_tick
        || runtime.load().runnable() != 5 - expected_tick as usize
    {
        halt();
    }
    smp_trace(0x86u8.saturating_add(expected_tick as u8));
}

#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_timer_dispatch(frame: *const HardwareTrapFrame) -> ! {
    #[cfg(feature = "deadline-receive-probe")]
    unsafe {
        let frame = frame.as_ref().unwrap_or_else(|| halt());
        let normalized = frame.normalize(0, 0);
        if normalized.vector != u64::from(TIMER_VECTOR) || normalized.cs & 3 != 3 {
            halt();
        }
        let page_table: u64;
        asm!("mov {}, cr3", out(reg) page_table, options(nomem, nostack, preserves_flags));
        let interrupted = UserContext::from_external_interrupt(
            PhysAddr::new(page_table).unwrap_or_else(|_| halt()),
            &normalized,
            TIMER_VECTOR,
        )
        .unwrap_or_else(|_| halt());
        let runtime = (*core::ptr::addr_of_mut!(SERVICE_RUNTIME))
            .as_mut()
            .unwrap_or_else(|| halt());
        let current = runtime.current().unwrap_or_else(|| halt());
        *runtime.context_mut(current).unwrap_or_else(|_| halt()) = interrupted;
        let executor = (*core::ptr::addr_of_mut!(SERVICE_DEADLINE_RECEIVES))
            .as_mut()
            .unwrap_or_else(|| halt());
        let escrow = deadline_cancellation_escrow();
        executor
            .validate_escrow(escrow)
            .unwrap_or_else(|_| halt());
        let preview = runtime
            .preview_receive_expirations_on_next_tick()
            .unwrap_or_else(|_| halt());
        let mut cancellations = [None; SERVICE_TASK_CAPACITY];
        for (slot, expiration) in preview.iter().enumerate() {
            if let Some(expiration) = expiration {
                cancellations[slot] = Some(
                    escrow.get(expiration.task()).unwrap_or_else(|_| halt()),
                );
            }
        }
        let tick = executor.timer_tick(runtime).unwrap_or_else(|_| halt());
        for (expiration, cancellation) in tick.expired().iter().zip(cancellations) {
            match (expiration, cancellation) {
                (Some(expiration), Some(cancellation))
                    if cancellation.task() == expiration.task() =>
                {
                    escrow.retire(cancellation).unwrap_or_else(|_| halt());
                }
                (None, None) => {}
                _ => halt(),
            }
        }
        executor
            .validate_escrow(escrow)
            .unwrap_or_else(|_| halt());
        let next = match tick.scheduling() {
            ScheduleOutcome::Continue(task) => task,
            ScheduleOutcome::Switch { to, .. } => to,
            ScheduleOutcome::Idle => halt(),
        };
        let context = runtime
            .context(next)
            .map(|context| context as *const UserContext)
            .unwrap_or_else(|_| halt());
        LocalApicTimer::acknowledge();
        enter_service_probe_context(&*context)
    }
    #[cfg(feature = "smp-periodic-balance-probe")]
    unsafe {
        let frame = frame.as_ref().unwrap_or_else(|| halt());
        let normalized = frame.normalize(0, 0);
        if normalized.vector != u64::from(TIMER_VECTOR) || normalized.cs & 3 != 0 {
            halt();
        }
        let tick = SMP_PERIODIC_TIMER_TICK.fetch_add(1, Ordering::AcqRel) + 1;
        if tick > 2 {
            halt();
        }
        smp_trace(0x70u8.saturating_add(tick as u8));
        LocalApicTimer::acknowledge();
        asm!(
            "sti",
            "2:",
            "hlt",
            "jmp 2b",
            options(noreturn, nomem, nostack)
        );
    }
    #[cfg(feature = "smp-scheduler-probe")]
    unsafe {
        let _ = frame;
        let apic_id = current_apic_id().unwrap_or_else(|| halt());
        let mut owner = None;
        for (cpu, slot) in AP_SCHEDULERS.0.iter().enumerate() {
            if slot.initialized.load(Ordering::Acquire)
                && slot.apic_id.load(Ordering::Acquire) == apic_id
                && owner.replace((cpu, slot)).is_some()
            {
                halt();
            }
        }
        let (cpu, slot) = owner.unwrap_or_else(|| halt());
        let scheduler = (&mut *slot.scheduler.get()).assume_init_mut();
        if scheduler.timer_tick().is_err() || scheduler.ticks() != 1 {
            halt();
        }
        LocalApicTimer::acknowledge();
        asm!(
            "out dx, eax",
            in("dx") SMP_SCHEDULER_TICK_PORT,
            in("eax") ((cpu as u32) << 16) | scheduler.ticks() as u32,
            options(nomem, nostack)
        );
        halt();
    }
    #[cfg(feature = "timer-probe")]
    let _ = frame;
    #[cfg(feature = "timer-probe")]
    unsafe {
        let scheduler = match (*core::ptr::addr_of_mut!(TIMER_SCHEDULER)).as_mut() {
            Some(scheduler) => scheduler,
            None => halt(),
        };
        if scheduler.timer_tick().is_err() || scheduler.ticks() != 1 {
            halt();
        }
        LocalApicTimer::acknowledge();
        asm!(
            "out dx, eax",
            in("dx") TIMER_TICK_PORT,
            in("eax") 1u32,
            options(nomem, nostack)
        );
    }
    #[cfg(any(feature = "preemption-probe", feature = "service-preemption-probe"))]
    unsafe {
        let frame = frame.as_ref().unwrap_or_else(|| halt());
        let normalized = frame.normalize(0, 0);
        asm!(
            "out dx, eax",
            in("dx") 0x4d5bu16,
            in("eax") ((normalized.cs as u32 & 0xff) << 8) | normalized.vector as u32,
            options(nomem, nostack)
        );
        if normalized.vector != u64::from(TIMER_VECTOR) || normalized.cs & 3 != 3 {
            halt();
        }
        #[cfg(feature = "uefi-service-preemption-probe")]
        asm!("out dx, al", in("dx") 0xe9u16, in("al") 0x90u8, options(nomem, nostack));
        asm!("out dx, eax", in("dx") 0x4d5bu16, in("eax") 1u32, options(nomem, nostack));
        let page_table: u64;
        asm!("mov {}, cr3", out(reg) page_table, options(nomem, nostack, preserves_flags));
        #[cfg(feature = "uefi-service-preemption-probe")]
        uefi_service_trace(0x95);
        let page_table = PhysAddr::new(page_table).unwrap_or_else(|_| halt());
        #[cfg(feature = "uefi-service-preemption-probe")]
        {
            uefi_service_trace(0x96);
            uefi_service_trace(normalized.rflags as u8);
            uefi_service_trace((normalized.rflags >> 8) as u8);
            uefi_service_trace((normalized.rflags >> 16) as u8);
            uefi_service_trace((normalized.rflags >> 24) as u8);
        }
        let interrupted =
            match UserContext::from_external_interrupt(page_table, &normalized, TIMER_VECTOR) {
                Ok(context) => context,
                #[cfg(feature = "uefi-service-preemption-probe")]
                Err(error) => {
                    let stage = match error {
                        mrml_kernel::arch::x86_64::ContextError::KernelPageTable => 0xd0,
                        mrml_kernel::arch::x86_64::ContextError::InvalidEntry => 0xd1,
                        mrml_kernel::arch::x86_64::ContextError::InvalidStack => 0xd2,
                        mrml_kernel::arch::x86_64::ContextError::InvalidSelectors => 0xd3,
                        mrml_kernel::arch::x86_64::ContextError::InvalidFlags => 0xd4,
                        _ => 0xdf,
                    };
                    uefi_service_trace(stage);
                    halt()
                }
                #[cfg(not(feature = "uefi-service-preemption-probe"))]
                Err(_) => halt(),
            };
        #[cfg(feature = "uefi-service-preemption-probe")]
        uefi_service_trace(0x92);
        asm!("out dx, eax", in("dx") 0x4d5bu16, in("eax") 2u32, options(nomem, nostack));
        let runtime_pointer = core::ptr::addr_of_mut!(PREEMPTION_RUNTIME);
        let runtime = (*runtime_pointer).as_mut().unwrap_or_else(|| halt());
        #[cfg(feature = "uefi-service-preemption-probe")]
        if core::ptr::addr_of!(UEFI_SERVICE_RECOVERED).read() {
            let current = runtime.current().unwrap_or_else(|| halt());
            if runtime.preempt_current(interrupted) != Ok(ScheduleOutcome::Continue(current)) {
                halt();
            }
            LocalApicTimer::acknowledge();
            uefi_service_trace(0x9a);
            halt();
        }
        let next = match runtime.preempt_current(interrupted) {
            Ok(ScheduleOutcome::Switch { to, .. }) => to,
            _ => halt(),
        };
        #[cfg(feature = "uefi-service-preemption-probe")]
        uefi_service_trace(0x93);
        asm!("out dx, eax", in("dx") 0x4d5bu16, in("eax") 3u32, options(nomem, nostack));
        let context = runtime
            .context(next)
            .map(|context| context as *const UserContext)
            .unwrap_or_else(|_| halt());
        asm!("out dx, eax", in("dx") 0x4d5bu16, in("eax") 4u32, options(nomem, nostack));
        LocalApicTimer::acknowledge();
        #[cfg(feature = "uefi-service-preemption-probe")]
        uefi_service_trace(0x94);
        asm!("out dx, eax", in("dx") 0x4d5bu16, in("eax") 5u32, options(nomem, nostack));
        #[cfg(feature = "preemption-probe")]
        {
            enter_user_context(&*context)
        }
        #[cfg(feature = "service-preemption-probe")]
        {
            enter_service_preemption_context(&*context)
        }
    }
    #[cfg(not(any(
        feature = "preemption-probe",
        feature = "service-preemption-probe",
        feature = "deadline-receive-probe",
        feature = "smp-scheduler-probe",
        feature = "smp-periodic-balance-probe"
    )))]
    {
        #[cfg(not(feature = "timer-probe"))]
        let _ = frame;
        halt()
    }
}

#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_reschedule_dispatch(frame: *const HardwareTrapFrame) -> ! {
    #[cfg(feature = "smp-ipi-probe")]
    unsafe {
        #[cfg(feature = "smp-periodic-balance-probe")]
        smp_trace(0x76);
        let frame = frame.as_ref().unwrap_or_else(|| halt());
        let normalized = frame.normalize(0, 0);
        if normalized.vector != u64::from(RESCHEDULE_VECTOR) || normalized.cs & 3 != 0 {
            halt();
        }
        let apic_id = current_apic_id().unwrap_or_else(|| halt());
        let mut owner = None;
        for (cpu, slot) in AP_SCHEDULERS.0.iter().enumerate() {
            if slot.initialized.load(Ordering::Acquire)
                && slot.apic_id.load(Ordering::Acquire) == apic_id
                && owner.replace((cpu, slot)).is_some()
            {
                halt();
            }
        }
        let (cpu, _slot) = owner.unwrap_or_else(|| halt());
        if !AP_RESCHEDULE_REQUEST[cpu].swap(false, Ordering::AcqRel) {
            halt();
        }
        let runtime = (&mut *SMP_IPI_RUNTIME.0.get()).assume_init_mut();
        let mut ticket = SMP_MIGRATION_MAILBOX.take();
        let migration = runtime
            .attach_domain(&mut ticket)
            .unwrap_or_else(|_| halt());
        #[cfg(feature = "smp-periodic-balance-probe")]
        smp_trace(0x76u8.saturating_add(SMP_PERIODIC_ROUND.load(Ordering::Acquire) as u8));
        if ticket.is_some() {
            halt();
        }
        if migration.priority() != Priority::RESPONSIVE {
            halt();
        }
        let load = runtime.load();
        #[cfg(not(feature = "smp-periodic-balance-probe"))]
        if load.occupied() != 2 || load.runnable() != 2 {
            halt();
        }
        #[cfg(feature = "smp-periodic-balance-probe")]
        let round = SMP_PERIODIC_ROUND.fetch_add(1, Ordering::AcqRel) + 1;
        #[cfg(feature = "smp-periodic-balance-probe")]
        if round > 2
            || load.occupied() != round as usize + 1
            || load.runnable() != round as usize + 1
        {
            halt();
        }
        AP_SCHEDULER_LOAD[cpu].store(
            ((load.occupied() as u32) << 16) | load.runnable() as u32,
            Ordering::Release,
        );
        #[cfg(not(feature = "smp-periodic-balance-probe"))]
        let next = match runtime.yield_current().unwrap_or_else(|_| halt()) {
            ScheduleOutcome::Switch { to, .. } => to,
            _ => halt(),
        };
        #[cfg(feature = "smp-periodic-balance-probe")]
        let next = migration.destination();
        #[cfg(not(feature = "smp-periodic-balance-probe"))]
        if next != migration.destination() {
            halt();
        }
        let context = runtime.context(next).unwrap_or_else(|_| halt());
        #[cfg(not(feature = "smp-service-migration-probe"))]
        if context.instruction_pointer() != 0x0050_0000 {
            halt();
        }
        LocalApicTimer::acknowledge();
        #[cfg(feature = "smp-periodic-balance-probe")]
        {
            if round == 1 {
                asm!(
                    "sti",
                    "2:",
                    "hlt",
                    "jmp 2b",
                    options(noreturn, nomem, nostack)
                );
            }
            asm!(
                "out dx, eax",
                in("dx") SMP_PERIODIC_APPLICATION_PORT,
                in("eax") ((cpu as u32) << 16) | round,
                options(nomem, nostack)
            );
            halt();
        }
        #[cfg(feature = "smp-service-migration-probe")]
        {
            if context.instruction_pointer() != SERVICE_ENTRY
                || context.page_table() != PhysAddr::new(SERVICE_ROOT).unwrap_or_else(|_| halt())
            {
                halt();
            }
            let descriptor = AP_DESCRIPTORS.0.get(cpu).unwrap_or_else(|| halt()).get();
            let state = (&*descriptor).assume_init_ref();
            let transition_stack =
                CpuDescriptorState::entry_stack_top_from(state).unwrap_or_else(|_| halt());
            enter_user_context_on_stack(context, transition_stack)
        }
        #[cfg(all(
            not(feature = "smp-service-migration-probe"),
            not(feature = "smp-periodic-balance-probe")
        ))]
        asm!(
            "out dx, eax",
            in("dx") SMP_IPI_PROOF_PORT,
            in("eax") ((cpu as u32) << 16) | next.token() as u32,
            options(nomem, nostack)
        );
        #[cfg(all(
            not(feature = "smp-service-migration-probe"),
            not(feature = "smp-periodic-balance-probe")
        ))]
        halt();
    }
    #[cfg(not(feature = "smp-ipi-probe"))]
    {
        let _ = frame;
        halt()
    }
}

#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_exception_dispatch(frame: *const HardwareTrapFrame) -> ! {
    let frame = match unsafe { frame.as_ref() } {
        Some(frame) => frame,
        None => halt(),
    };
    let mut ss = 0u16;
    unsafe { asm!("mov {0:x}, ss", out(reg) ss, options(nomem, nostack, preserves_flags)) };
    let normalized = unsafe {
        frame.normalize(
            (frame as *const HardwareTrapFrame as u64)
                + core::mem::size_of::<HardwareTrapFrame>() as u64,
            u64::from(ss),
        )
    };
    let fault_address = if normalized.vector == 14 {
        let address: u64;
        unsafe { asm!("mov {}, cr2", out(reg) address, options(nomem, nostack, preserves_flags)) };
        Some(address)
    } else {
        None
    };
    #[cfg(feature = "service-probe")]
    unsafe {
        let proof = normalized.vector as u32
            | ((normalized.cs as u32 & 0xff) << 8)
            | ((normalized.ss as u32 & 0xff) << 16);
        asm!(
            "out dx, eax",
            in("dx") SERVICE_FRAME_PORT,
            in("eax") proof,
            options(nomem, nostack)
        );
    }
    let _disposition = match normalized.disposition(fault_address) {
        Ok(disposition) => disposition,
        Err(_) => halt(),
    };
    #[cfg(any(feature = "preemption-probe", feature = "service-preemption-probe"))]
    unsafe {
        let proof = if matches!(
            _disposition,
            TrapDisposition::TerminateUser {
                vector: 3,
                address: None
            }
        ) {
            6
        } else {
            0x8000 | normalized.vector as u32
        };
        asm!(
            "out dx, eax",
            in("dx") 0x4d5bu16,
            in("eax") proof,
            options(nomem, nostack)
        );
        if proof == 6 {
            #[cfg(feature = "uefi-service-preemption-probe")]
            {
                let runtime = (*core::ptr::addr_of_mut!(PREEMPTION_RUNTIME))
                    .as_mut()
                    .unwrap_or_else(|| halt());
                let retired = runtime
                    .terminate_current_fault(_disposition)
                    .unwrap_or_else(|_| halt());
                let dispatch = runtime
                    .dispatch_after_fault(retired)
                    .unwrap_or_else(|_| halt());
                let next = dispatch
                    .user()
                    .map(|(task, _)| task)
                    .filter(|_| retired.vector == 3 && retired.address.is_none())
                    .unwrap_or_else(|| halt());
                if runtime.context(retired.task).is_ok() {
                    halt();
                }
                core::ptr::addr_of_mut!(UEFI_SERVICE_RECOVERED).write(true);
                uefi_service_trace(0x91);
                if dispatch.user().map(|(task, _)| task) != Some(next) {
                    halt();
                }
                let transition_stack =
                    CpuDescriptorState::entry_stack_top_from(core::ptr::addr_of!(CPU0_DESCRIPTORS))
                        .unwrap_or_else(|_| halt());
                let _ = dispatch
                    .enter_user_on_stack(runtime, transition_stack)
                    .unwrap_or_else(|_| halt());
                halt()
            }
            #[cfg(not(feature = "uefi-service-preemption-probe"))]
            halt()
        }
    }
    #[cfg(feature = "fault-probe")]
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") EXCEPTION_PROBE_PORT,
            in("eax") normalized.vector as u32,
            options(nomem, nostack)
        )
    };
    #[cfg(feature = "user-probe")]
    if matches!(_disposition, TrapDisposition::TerminateUser { .. }) {
        let runtime = unsafe {
            match (*core::ptr::addr_of_mut!(USER_RUNTIME)).as_mut() {
                Some(runtime) => runtime,
                None => halt(),
            }
        };
        let retired = match runtime.terminate_current_fault(_disposition) {
            Ok(retired) => retired,
            Err(_) => halt(),
        };
        let dispatch = runtime
            .dispatch_after_fault(retired)
            .unwrap_or_else(|_| halt());
        match dispatch.user().map(|(task, _)| task) {
            Some(to) if retired.vector == 6 => {
                if dispatch.user().map(|(task, _)| task) != Some(to) {
                    halt();
                }
                let transition_stack = unsafe {
                    CpuDescriptorState::entry_stack_top_from(core::ptr::addr_of!(CPU0_DESCRIPTORS))
                        .unwrap_or_else(|_| halt())
                };
                let _ = unsafe { dispatch.enter_user_on_stack(runtime, transition_stack) }
                    .unwrap_or_else(|_| halt());
                halt();
            }
            None if retired.vector == 3 => {
                let _ = runtime
                    .consume_idle_dispatch(dispatch)
                    .unwrap_or_else(|_| halt());
            }
            _ => halt(),
        }
        unsafe {
            asm!(
                "out dx, eax",
                in("dx") USER_PROBE_PORT,
                in("eax") 3u32,
                options(nomem, nostack)
            )
        };
    }
    #[cfg(feature = "service-probe")]
    if _disposition
        == (TrapDisposition::TerminateUser {
            vector: 3,
            address: None,
        })
    {
        unsafe {
            let runtime = (*core::ptr::addr_of_mut!(SERVICE_RUNTIME))
                .as_mut()
                .unwrap_or_else(|| halt());
            let supervisor = (*core::ptr::addr_of_mut!(SERVICE_SUPERVISOR))
                .as_mut()
                .unwrap_or_else(|| halt());
            #[cfg(feature = "service-restart-request-probe")]
            {
                let current = runtime.current().unwrap_or_else(|| halt());
                let ids = (*core::ptr::addr_of!(SERVICE_IDS)).unwrap_or_else(|| halt());
                if supervisor.task(ids[2]) == Ok(Some(current)) {
                    if supervisor.state(ids[1]) != Ok(mrml_kernel::ServiceState::Running)
                        || ids[1].token() >> 32 <= 1
                    {
                        halt();
                    }
                    asm!(
                        "out dx, eax",
                        in("dx") SERVICE_PROBE_PORT,
                        in("eax") 0x25u32,
                        options(nomem, nostack)
                    );
                    halt();
                }
            }
            if core::ptr::addr_of!(SERVICE_RESTARTED).read() {
                let fault = supervisor
                    .fault_current(runtime, _disposition)
                    .unwrap_or_else(|_| halt());
                let peer = fault
                    .dispatch
                    .user()
                    .map(|(task, _)| task)
                    .unwrap_or_else(|| halt());
                complete_service_cleanup(supervisor, fault.cleanup);
                let ControlEvent::PeerDied(death) =
                    runtime.receive_control(peer).unwrap_or_else(|_| halt())
                else {
                    halt()
                };
                if death.peer() != fault.retirement.task
                    || death.reason()
                        != (PeerDeathReason::Faulted {
                            vector: 3,
                            address: None,
                        })
                    || runtime.context(peer).is_err()
                {
                    halt();
                }
                verify_restart_budget_exhausted(runtime, supervisor);
                asm!(
                    "out dx, eax",
                    in("dx") SERVICE_PROBE_PORT,
                    in("eax") 0x23u32,
                    options(nomem, nostack)
                );
                asm!(
                    "out dx, eax",
                    in("dx") SERVICE_PROBE_PORT,
                    in("eax") 4u32,
                    options(nomem, nostack)
                );
                halt();
            }
            let management = (*core::ptr::addr_of!(SERVICE_MANAGEMENT))
                .as_ref()
                .unwrap_or_else(|| halt());
            let controls = (*core::ptr::addr_of!(SERVICE_CONTROLS)).unwrap_or_else(|| halt());
            let mut fresh_context = UserContext::new(
                PhysAddr::new(SERVICE_ROOT).unwrap_or_else(|_| halt()),
                hosted_service_entry(),
                SERVICE_STACK_TOP,
            )
            .unwrap_or_else(|_| halt());
            fresh_context.r12 = 2;
            let fault = supervisor
                .fault_current_at(runtime, _disposition, 0)
                .unwrap_or_else(|_| halt());
            let _ = runtime
                .consume_idle_dispatch(fault.dispatch)
                .unwrap_or_else(|_| halt());
            complete_service_cleanup(supervisor, fault.cleanup);
            let replacement = supervisor
                .restart_at(
                    fault.service,
                    management,
                    controls[0],
                    runtime,
                    Priority::NORMAL,
                    fresh_context,
                    0,
                )
                .unwrap_or_else(|_| halt());
            asm!(
                "out dx, eax",
                in("dx") SERVICE_PROBE_PORT,
                in("eax") 3u32,
                options(nomem, nostack)
            );
            restart_service_pair(runtime, supervisor, replacement);
        };
    }
    halt()
}

#[cfg(feature = "fault-probe")]
#[used]
static RELOCATION_ANCHOR: unsafe extern "C" fn() -> ! = mrml_exception_fail_stop;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    halt()
}

/// Standalone PE32+ kernel entry. The loader calls this only after firmware
/// services have exited and after authenticating both this image and handoff.
///
/// # Safety
///
/// `bytes` must address exactly `length` readable bytes that remain mapped for
/// this non-returning call. The loader must already have installed the final
/// W^X image mappings, a writable kernel stack, and a read-only handoff mapping.
/// Both privilege-stack tops must be canonical, 16-byte aligned addresses in
/// distinct writable supervisor mappings whose guard pages are absent.
#[unsafe(export_name = "efi_main")]
pub unsafe extern "efiapi" fn kernel_entry(
    bytes: *const u8,
    length: usize,
    entry_stack_top: u64,
    double_fault_stack_top: u64,
) -> usize {
    unsafe { install_descriptor_tables(entry_stack_top, double_fault_stack_top) };
    #[cfg(feature = "fault-probe")]
    unsafe {
        let _ = (bytes, length);
        // Keep one absolute pointer live so the minimal diagnostic PE exercises
        // the same DIR64 high-half relocation path as the full kernel.
        let _ = core::ptr::addr_of!(RELOCATION_ANCHOR).read_volatile();
        asm!("ud2", options(noreturn));
    }
    #[cfg(not(feature = "fault-probe"))]
    unsafe {
        run_kernel(bytes, length)
    }
}

/// Relocated long-mode entry reached only by a sealed AP trampoline. The
/// trampoline uses the SysV register contract explicitly: CPU index in RDI,
/// startup generation in RSI, and the private stack-layout base in RDX.
///
/// # Safety
///
/// The BSP must have armed the exact CPU/generation pair, installed the shared
/// kernel CR3, and supplied the base of that CPU's exclusively owned, mapped
/// privilege-stack layout. The current RSP must be its early-stack top.
#[unsafe(export_name = "mrml_ap_entry")]
pub unsafe extern "sysv64" fn ap_kernel_entry(cpu: u64, generation: u64, stack_base: u64) -> ! {
    let cpu = usize::try_from(cpu)
        .ok()
        .filter(|cpu| *cpu < MAX_X86_64_CPUS)
        .unwrap_or_else(|| halt());
    let generation = u32::try_from(generation).unwrap_or_else(|_| halt());
    if !AP_ONLINE.matches_armed(cpu, generation) {
        halt();
    }
    let stacks = PrivilegeStackLayout::new(stack_base, PRIVILEGE_STACK_ARENA_PAGES)
        .unwrap_or_else(|_| halt());
    let slot = AP_DESCRIPTORS.0[cpu].get();
    unsafe { slot.write(MaybeUninit::new(CpuDescriptorState::empty(cpu as u16))) };
    let state = unsafe { (&mut *slot).assume_init_mut() };
    unsafe {
        install_descriptor_state(
            state,
            stacks.entry_top().unwrap_or_else(|_| halt()),
            stacks.double_fault_top().unwrap_or_else(|_| halt()),
        )
    };
    #[cfg(any(
        feature = "whp-smp-probe",
        feature = "whp-smp-scheduler-probe",
        feature = "whp-smp-ipi-probe",
        feature = "whp-smp-service-migration-probe",
        feature = "whp-smp-periodic-balance-probe"
    ))]
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") WHP_SMP_HANDSHAKE_PORT,
            in("eax") ((cpu as u32) << 16) | generation,
            options(nomem, nostack)
        )
    };
    if AP_ONLINE.acknowledge(cpu, generation).is_err() {
        halt();
    }
    #[cfg(feature = "smp-scheduler-probe")]
    unsafe {
        let mut scheduler = KernelScheduler::<2>::new(1_000, 1).unwrap_or_else(|_| halt());
        if scheduler.create(Priority::NORMAL).is_err()
            || !matches!(scheduler.start(), ScheduleOutcome::Switch { .. })
        {
            halt();
        }
        let apic_id = current_apic_id().unwrap_or_else(|| halt());
        let slot = AP_SCHEDULERS.0.get(cpu).unwrap_or_else(|| halt());
        if slot.initialized.load(Ordering::Acquire)
            || slot
                .apic_id
                .compare_exchange(u32::MAX, apic_id, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            halt();
        }
        (*slot.scheduler.get()).write(scheduler);
        slot.initialized.store(true, Ordering::Release);
        LocalApicTimer::periodic(TIMER_VECTOR, 100_000, TimerDivide::By16)
            .and_then(|timer| timer.enable())
            .unwrap_or_else(|_| halt());
        asm!(
            "out dx, eax",
            in("dx") SMP_SCHEDULER_READY_PORT,
            in("eax") ((cpu as u32) << 16) | generation,
            options(nomem, nostack)
        );
        asm!(
            "sti",
            "2:",
            "pause",
            "jmp 2b",
            options(noreturn, nomem, nostack)
        );
    }
    #[cfg(feature = "smp-ipi-probe")]
    unsafe {
        let page_table: u64;
        asm!("mov {}, cr3", out(reg) page_table, options(nomem, nostack, preserves_flags));
        let context = UserContext::new(
            PhysAddr::new(page_table).unwrap_or_else(|_| halt()),
            0x0040_0000,
            0x0000_7000_0000_0000,
        )
        .unwrap_or_else(|_| halt());
        #[cfg(not(feature = "smp-periodic-balance-probe"))]
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap_or_else(|_| halt());
        #[cfg(feature = "smp-periodic-balance-probe")]
        let mut runtime = TaskRuntime::<3, 1>::new(1_000, 1).unwrap_or_else(|_| halt());
        let first = runtime
            .create(Priority::NORMAL, context)
            .unwrap_or_else(|_| halt());
        if !matches!(runtime.start(), ScheduleOutcome::Switch { to, .. } if to == first)
            || first.token() as u32 != 0
        {
            halt();
        }
        let apic_id = current_apic_id().unwrap_or_else(|| halt());
        let slot = AP_SCHEDULERS.0.get(cpu).unwrap_or_else(|| halt());
        if slot.initialized.load(Ordering::Acquire)
            || slot
                .apic_id
                .compare_exchange(u32::MAX, apic_id, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            halt();
        }
        (*SMP_IPI_RUNTIME.0.get()).write(runtime);
        slot.initialized.store(true, Ordering::Release);
        AP_SCHEDULER_LOAD[cpu].store(0x0001_0001, Ordering::Release);
        LocalApicController::enable().unwrap_or_else(|_| halt());
        AP_IPI_READY[cpu].store(true, Ordering::Release);
        asm!(
            "out dx, eax",
            in("dx") SMP_IPI_READY_PORT,
            in("eax") ((cpu as u32) << 16) | generation,
            options(nomem, nostack)
        );
        #[cfg(feature = "smp-periodic-balance-probe")]
        {
            while SMP_PERIODIC_TARGET_APIC.load(Ordering::Acquire) == u32::MAX {
                core::sync::atomic::compiler_fence(Ordering::SeqCst);
            }
            LocalApicTimer::periodic(TIMER_VECTOR, 1_000_000, TimerDivide::By16)
                .and_then(|timer| timer.enable())
                .unwrap_or_else(|_| halt());
        }
        asm!(
            "sti",
            "2:",
            "pause",
            "jmp 2b",
            options(noreturn, nomem, nostack)
        );
    }
    #[cfg(feature = "smp-probe")]
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") SMP_PROBE_PORT,
            in("eax") ((cpu as u32) << 16) | generation,
            options(nomem, nostack)
        )
    };
    #[cfg(not(any(feature = "smp-scheduler-probe", feature = "smp-ipi-probe")))]
    halt()
}

#[cfg(not(feature = "fault-probe"))]
unsafe fn start_application_processors(topology: &X86CpuTopology, handoff: &BootHandoff) {
    smp_trace(0x10);
    let bsp_apic_id = current_apic_id().unwrap_or_else(|| halt());
    smp_trace(0x60u8.saturating_add(bsp_apic_id as u8));
    // The BSP is the sole writer during one-way early boot. Keeping the full
    // 256-CPU state table out of its guarded early stack leaves enough space
    // for the sealed trampoline image and nested topology parsing frame.
    let startup_storage = unsafe { &mut *AP_STARTUP_WORKSPACE.0.get() };
    let startup =
        ApStartupTable::<MAX_X86_64_CPUS>::initialize(startup_storage, topology, bsp_apic_id)
            .unwrap_or_else(|_| halt());
    smp_trace(0x11);
    let timing = ap_startup_timing().unwrap_or_else(|| halt());
    smp_trace(0x12);
    let root = unsafe { ActivePageTables::current() }
        .map(|tables| tables.root().get())
        .unwrap_or_else(|_| halt());
    let trampoline = handoff.ap_trampoline().unwrap_or_else(|| halt());
    let stack_base = handoff.ap_stack_arena().unwrap_or_else(|| halt());
    let stacks = PerCpuPrivilegeStacks::<MAX_X86_64_CPUS>::new(
        stack_base,
        stack_base,
        PRIVILEGE_STACK_ARENA_PAGES,
    )
    .unwrap_or_else(|_| halt());
    let mut page =
        unsafe { ActiveApTrampolinePage::current(trampoline) }.unwrap_or_else(|_| halt());
    smp_trace(0x13);

    for cpu in 0..topology.len() {
        let target = topology.cpu(cpu).unwrap_or_else(|_| halt());
        if target.apic_id() == bsp_apic_id {
            continue;
        }
        let token = startup.begin(cpu).unwrap_or_else(|_| halt());
        AP_ONLINE.arm(token).unwrap_or_else(|_| halt());
        smp_trace(0x20);
        let layout = stacks
            .cpu(cpu)
            .map(|slot| slot.virtual_layout())
            .unwrap_or_else(|_| halt());
        let image = ApTrampolineImage::new(
            trampoline,
            root,
            ap_kernel_entry as *const () as usize as u64,
            layout.early_top().unwrap_or_else(|_| halt()),
            cpu,
            token.generation(),
        )
        .unwrap_or_else(|_| halt());
        let installed = image.install(&mut page).unwrap_or_else(|_| halt());
        smp_trace(0x21);
        let destination = startup.destination(token).unwrap_or_else(|_| halt());
        unsafe { ApicIpi::init(destination).and_then(|ipi| ipi.send()) }.unwrap_or_else(|_| halt());
        smp_trace(0x22);
        timing.wait_after_init().unwrap_or_else(|_| halt());
        smp_trace(0x23);
        unsafe { ApicIpi::init_deassert(destination).and_then(|ipi| ipi.send()) }
            .unwrap_or_else(|_| halt());
        startup
            .startup_sent_with_image(token, installed)
            .unwrap_or_else(|_| halt());
        unsafe {
            ApicIpi::startup(destination, installed.startup_vector()).and_then(|ipi| ipi.send())
        }
        .unwrap_or_else(|_| halt());
        smp_trace(0x24);
        timing.wait_after_startup().unwrap_or_else(|_| halt());
        smp_trace(0x25);
        if !AP_ONLINE.is_online(token).unwrap_or_else(|_| halt()) {
            smp_trace(0x28);
            unsafe {
                ApicIpi::startup(destination, installed.startup_vector()).and_then(|ipi| ipi.send())
            }
            .unwrap_or_else(|_| halt());
            timing
                .wait_micros(ap_retry_timeout_micros())
                .unwrap_or_else(|_| halt());
            smp_trace(0x29);
        }
        if !AP_ONLINE.is_online(token).unwrap_or_else(|_| halt()) {
            smp_trace(0x2a);
            if AP_ONLINE.fail(token).is_ok() {
                startup.fail(token).unwrap_or_else(|_| halt());
                #[cfg(feature = "smp-probe")]
                unsafe {
                    asm!(
                        "out dx, eax",
                        in("dx") SMP_PROBE_PORT,
                        in("eax") 0xdead_0001u32,
                        options(nomem, nostack)
                    )
                };
                halt();
            }
            if !AP_ONLINE.is_online(token).unwrap_or_else(|_| halt()) {
                halt();
            }
        }
        smp_trace(0x2b);
        startup
            .acknowledge(token, destination)
            .unwrap_or_else(|_| halt());
        smp_trace(0x26);
        installed.rearm(&mut page).unwrap_or_else(|_| halt());
        smp_trace(0x27);
    }
    if !page.revoke_and_zero(trampoline) {
        halt();
    }
    smp_trace(0x30);
}

#[cfg(all(not(feature = "fault-probe"), feature = "smp-ipi-probe"))]
#[cfg(feature = "smp-periodic-balance-probe")]
unsafe fn initialize_periodic_balance_probe(
    topology_len: usize,
    cpu: usize,
    destination: u32,
    root: PhysAddr,
) {
    if topology_len != 2 || cpu != 1 {
        halt();
    }
    let mut source = TaskRuntime::<5, 1>::new(1_000, 10).unwrap_or_else(|_| halt());
    let first = source
        .create(
            Priority::NORMAL,
            UserContext::new(root, 0x0040_0000, 0x0000_7000_0000_0000).unwrap_or_else(|_| halt()),
        )
        .unwrap_or_else(|_| halt());
    for index in 0..4u64 {
        source
            .create(
                Priority::RESPONSIVE,
                UserContext::new(root, 0x0050_0000, 0x0000_7000_0000_1000 + index * 0x1000)
                    .unwrap_or_else(|_| halt()),
            )
            .unwrap_or_else(|_| halt());
    }
    if !matches!(source.start(), ScheduleOutcome::Switch { to, .. } if to == first) {
        halt();
    }
    unsafe { (*SMP_PERIODIC_SOURCE.0.get()).write(source) };
    unsafe {
        (*SMP_PERIODIC_POLICY.0.get())
            .write(PeriodicDomainBalancer::<2, 1>::new(0, 1).unwrap_or_else(|_| halt()))
    };
    SMP_PERIODIC_TARGET_CPU.store(cpu as u32, Ordering::Release);
    SMP_PERIODIC_TARGET_APIC.store(destination, Ordering::Release);
}

#[cfg(feature = "smp-periodic-balance-probe")]
unsafe fn run_periodic_balance_probe() -> ! {
    unsafe { LocalApicController::enable() }.unwrap_or_else(|_| halt());
    smp_trace(0x70);
    for expected_tick in 1..=2 {
        while SMP_PERIODIC_TIMER_TICK.load(Ordering::Acquire) < expected_tick {
            core::sync::atomic::compiler_fence(Ordering::SeqCst);
        }
        unsafe { publish_periodic_balance_tick(expected_tick) };
    }
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") SMP_PERIODIC_BOOTSTRAP_PORT,
            in("eax") 2u32,
            options(nomem, nostack)
        )
    };
    halt();
}

#[cfg(all(not(feature = "fault-probe"), feature = "smp-ipi-probe"))]
unsafe fn send_reschedule_probe(topology: &X86CpuTopology) {
    let bsp_apic_id = current_apic_id().unwrap_or_else(|| halt());
    let mut target = None;
    let mut bsp_cpu = None;
    for cpu in 0..topology.len() {
        let descriptor = topology.cpu(cpu).unwrap_or_else(|_| halt());
        if descriptor.apic_id() == bsp_apic_id {
            if bsp_cpu.replace(cpu).is_some() {
                halt();
            }
        } else if target.replace((cpu, descriptor.apic_id())).is_some() {
            halt();
        }
    }
    let (cpu, destination) = target.unwrap_or_else(|| halt());
    #[cfg(not(feature = "smp-periodic-balance-probe"))]
    let bsp_cpu = bsp_cpu.unwrap_or_else(|| halt());
    #[cfg(feature = "smp-periodic-balance-probe")]
    if bsp_cpu.is_none() {
        halt();
    }
    let timing = ap_startup_timing().unwrap_or_else(|| halt());
    for _ in 0..1_000 {
        if AP_IPI_READY[cpu].load(Ordering::Acquire) {
            break;
        }
        timing.wait_micros(100).unwrap_or_else(|_| halt());
    }
    if !AP_IPI_READY[cpu].load(Ordering::Acquire) {
        halt();
    }
    #[cfg(not(feature = "smp-periodic-balance-probe"))]
    let remote_load = {
        let remote = AP_SCHEDULER_LOAD[cpu].load(Ordering::Acquire);
        SchedulerLoad::new((remote >> 16) as usize, (remote & 0xffff) as usize, 2)
            .unwrap_or_else(|| halt())
    };
    let page_table: u64;
    unsafe { asm!("mov {}, cr3", out(reg) page_table, options(nomem, nostack, preserves_flags)) };
    let root = PhysAddr::new(page_table).unwrap_or_else(|_| halt());
    #[cfg(feature = "smp-periodic-balance-probe")]
    {
        unsafe {
            initialize_periodic_balance_probe(topology.len(), cpu, destination, root);
            run_periodic_balance_probe();
        }
    }
    #[cfg(not(feature = "smp-periodic-balance-probe"))]
    {
        let mut source = TaskRuntime::<3, 1>::new(1_000, 1).unwrap_or_else(|_| halt());
        let first = source
            .create(
                Priority::NORMAL,
                UserContext::new(root, 0x0040_0000, 0x0000_7000_0000_0000)
                    .unwrap_or_else(|_| halt()),
            )
            .unwrap_or_else(|_| halt());
        #[cfg(feature = "smp-service-migration-probe")]
        let responsive_context = UserContext::new(
            PhysAddr::new(SERVICE_ROOT).unwrap_or_else(|_| halt()),
            SERVICE_ENTRY,
            SERVICE_STACK_TOP,
        )
        .unwrap_or_else(|_| halt());
        #[cfg(not(feature = "smp-service-migration-probe"))]
        let responsive_context =
            UserContext::new(root, 0x0050_0000, 0x0000_7000_0000_1000).unwrap_or_else(|_| halt());
        source
            .create(Priority::RESPONSIVE, responsive_context)
            .unwrap_or_else(|_| halt());
        source
            .create(
                Priority::BACKGROUND,
                UserContext::new(root, 0x0060_0000, 0x0000_7000_0000_2000)
                    .unwrap_or_else(|_| halt()),
            )
            .unwrap_or_else(|_| halt());
        if !matches!(source.start(), ScheduleOutcome::Switch { to, .. } if to == first) {
            halt();
        }
        if topology.len() != 2 || bsp_cpu >= 2 || cpu >= 2 {
            halt();
        }
        let unavailable = SchedulerLoad::new(0, 0, 0).unwrap_or_else(|| halt());
        let mut loads = [unavailable; 2];
        loads[bsp_cpu] = source.load();
        loads[cpu] = remote_load;
        let mut policy = PeriodicBalancer::<2>::new(0, 1).unwrap_or_else(|_| halt());
        let selected = policy
            .poll(1, bsp_cpu, &loads)
            .unwrap_or_else(|_| halt())
            .unwrap_or_else(|| halt());
        if selected.cpu() != cpu || selected.load() != remote_load {
            halt();
        }
        let detached = source
            .detach_domain_for_rebalance(selected.load())
            .unwrap_or_else(|_| halt())
            .unwrap_or_else(|| halt());
        if source.load().runnable() != 2 || SMP_MIGRATION_MAILBOX.publish(detached).is_err() {
            halt();
        }
        if AP_RESCHEDULE_REQUEST[cpu]
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            halt();
        }
        unsafe { ApicIpi::fixed(destination, RESCHEDULE_VECTOR).and_then(|ipi| ipi.send()) }
            .unwrap_or_else(|_| halt());
        unsafe {
            asm!(
                "out dx, eax",
                in("dx") SMP_IPI_READY_PORT,
                in("eax") topology.len() as u32,
                options(nomem, nostack)
            )
        };
    }
}

#[cfg(not(feature = "fault-probe"))]
fn current_apic_id() -> Option<u32> {
    let maximum = __cpuid(0).eax;
    if maximum >= 0x0b {
        for level in 0..2 {
            let topology = __cpuid_count(0x0b, level);
            if topology.ebx & 0xffff != 0 {
                return Some(topology.edx);
            }
        }
    }
    (maximum >= 1).then(|| __cpuid(1).ebx >> 24)
}

#[cfg(not(feature = "fault-probe"))]
fn ap_startup_timing() -> Option<ApStartupTiming> {
    if let Ok(timing) = ApStartupTiming::detect() {
        return Some(timing);
    }
    #[cfg(feature = "emulated-ap-timing")]
    {
        let bytes = option_env!("MRML_EMULATED_TSC_HZ")?.as_bytes();
        if bytes.is_empty() || bytes.len() > 20 {
            return None;
        }
        let mut value = 0u64;
        for byte in bytes {
            if !byte.is_ascii_digit() {
                return None;
            }
            value = value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
        }
        ApStartupTiming::from_tsc_hz(value).ok()
    }
    #[cfg(not(feature = "emulated-ap-timing"))]
    None
}

#[cfg(all(not(feature = "fault-probe"), feature = "emulated-ap-timing"))]
const fn ap_retry_timeout_micros() -> u32 {
    // TCG vCPUs are host threads and can be descheduled well beyond the
    // architectural SIPI delay. This explicitly selected test profile keeps
    // production's hardware timeout unchanged.
    100_000
}

#[cfg(all(not(feature = "fault-probe"), not(feature = "emulated-ap-timing")))]
const fn ap_retry_timeout_micros() -> u32 {
    1_000
}

#[cfg(all(not(feature = "fault-probe"), feature = "ap-startup-trace"))]
fn smp_trace(stage: u8) {
    unsafe { asm!("out dx, al", in("dx") 0xe9u16, in("al") stage, options(nomem, nostack)) };
}

#[cfg(all(not(feature = "fault-probe"), not(feature = "ap-startup-trace")))]
const fn smp_trace(_: u8) {}

#[cfg(feature = "block-guest-driver-probe")]
unsafe fn run_block_guest_driver_probe() -> ! {
    let mut configuration = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
    for (offset, byte) in configuration.iter_mut().enumerate() {
        // SAFETY: the dedicated launch path maps this exact signed-device
        // configuration page read-only and keeps it live for the VM lifetime.
        *byte = unsafe { ((BLOCK_CONFIGURATION_BASE as *const u8).add(offset)).read_volatile() };
    }
    let decoded =
        mrml_kernel::VirtualBlockConfiguration::decode(&configuration).unwrap_or_else(|_| halt());
    let queue = decoded.queue();
    let request_published = unsafe { (queue.request_base() as *const u64).read_volatile() };
    let request_consumed = unsafe { ((queue.request_base() + 64) as *const u64).read_volatile() };
    let completion_published = unsafe { (queue.completion_base() as *const u64).read_volatile() };
    let completion_consumed =
        unsafe { ((queue.completion_base() + 64) as *const u64).read_volatile() };
    let mut resume_page = [0; PAGE_SIZE as usize];
    for (offset, byte) in resume_page.iter_mut().enumerate() {
        *byte = unsafe { ((BLOCK_RESUME_BASE as *const u8).add(offset)).read_volatile() };
    }
    let resume_state = VirtualBlockResumePage::decode_page(&resume_page).unwrap_or_else(|_| halt());
    if resume_state.configuration() != decoded
        || resume_state.request_producer() != request_published
        || resume_state.request_consumed() != request_consumed
        || resume_state.completion_published() != completion_published
        || resume_state.completion_consumer() != completion_consumed
    {
        halt();
    }
    let fresh = request_published == 0
        && request_consumed == 0
        && completion_published == 0
        && completion_consumed == 0
        && resume_state.last_admitted_request_id() == 0
        && resume_state.last_published_request_id() == 0;
    let recovering = request_published == u64::from(BLOCK_QUIESCE_REQUESTS)
        && request_consumed == u64::from(BLOCK_QUIESCE_REQUESTS)
        && completion_published == u64::from(BLOCK_QUIESCE_REQUESTS)
        && completion_consumed == u64::from(BLOCK_QUIESCE_REQUESTS - 2)
        && resume_state.last_admitted_request_id() == u64::from(BLOCK_QUIESCE_REQUESTS)
        && resume_state.last_published_request_id() == u64::from(BLOCK_QUIESCE_REQUESTS);
    if !fresh && !recovering {
        halt();
    }
    let mut requests = [[0; VIRTUAL_BLOCK_REQUEST_BYTES]; 2];
    for (slot, request) in requests.iter_mut().enumerate() {
        let base = queue.request_base() + 128 + slot as u64 * VIRTUAL_BLOCK_REQUEST_BYTES as u64;
        for (offset, byte) in request.iter_mut().enumerate() {
            *byte = unsafe { ((base as *const u8).add(offset)).read_volatile() };
        }
    }
    let mut driver = VirtualBlockGuestDriver::resume_from_page(
        &configuration,
        &resume_page,
        &requests,
        request_published,
        request_consumed,
        completion_published,
        completion_consumed,
    )
    .unwrap_or_else(|_| halt());
    let start_cycle = if recovering {
        BLOCK_QUIESCE_CYCLE - 1
    } else {
        0
    };
    // SAFETY: the launch builder identity-maps the exact configured request
    // and completion pages with their required directionality.
    let mut transport =
        unsafe { X86VirtualBlockGuestQueueTransport::new(NativeX86VirtualBlockPortIo) };

    unsafe { asm!("sti", options(nomem, nostack)) };
    for cycle in start_cycle..BLOCK_PROBE_CYCLES {
        let patterns = [0x40u8 + cycle as u8, 0x90u8 + cycle as u8];
        if !(recovering && cycle + 1 == BLOCK_QUIESCE_CYCLE) {
            for (block, value) in patterns.into_iter().enumerate() {
                let base = BLOCK_PAYLOAD_BASE + block as u64 * 4096;
                for offset in 0..4096usize {
                    unsafe { ((base as *mut u8).add(offset)).write_volatile(value) };
                }
            }
            for block in 0..2u64 {
                let write = driver
                    .prepare_write(block, 1, BLOCK_PAYLOAD_BASE + block * 4096, 4096)
                    .unwrap_or_else(|_| halt());
                driver
                    .publish_submission(&mut transport, write)
                    .unwrap_or_else(|_| halt());
            }
        }
        for _ in 0..2 {
            let write_completion = driver
                .prepare_completion_from_transport(&mut transport)
                .unwrap_or_else(|_| halt());
            if write_completion.status() != mrml_kernel::VirtualBlockCompletionStatus::Ok
                || write_completion.transferred() != 4096
            {
                halt();
            }
            driver
                .acknowledge_completion_with_transport(&mut transport, write_completion)
                .unwrap_or_else(|_| halt());
        }

        for offset in 0..8192usize {
            unsafe { ((BLOCK_PAYLOAD_BASE as *mut u8).add(offset)).write_volatile(0) };
        }
        for block in 0..2u64 {
            let read = driver
                .prepare_read(block, 1, BLOCK_PAYLOAD_BASE + block * 4096, 4096)
                .unwrap_or_else(|_| halt());
            driver
                .publish_submission(&mut transport, read)
                .unwrap_or_else(|_| halt());
        }
        for _ in 0..2 {
            let read_completion = driver
                .prepare_completion_from_transport(&mut transport)
                .unwrap_or_else(|_| halt());
            if read_completion.status() != mrml_kernel::VirtualBlockCompletionStatus::Ok
                || read_completion.transferred() != 4096
            {
                halt();
            }
            driver
                .acknowledge_completion_with_transport(&mut transport, read_completion)
                .unwrap_or_else(|_| halt());
        }
        for (block, value) in patterns.into_iter().enumerate() {
            let base = BLOCK_PAYLOAD_BASE + block as u64 * 4096;
            for offset in 0..4096usize {
                if unsafe { ((base as *const u8).add(offset)).read_volatile() } != value {
                    halt();
                }
            }
        }
    }
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") BLOCK_PROOF_PORT,
            in("eax") BLOCK_PROBE_OPERATIONS,
            options(nomem, nostack)
        )
    };
    halt()
}

#[cfg(feature = "pci-configuration-probe")]
unsafe fn run_pci_configuration_probe() -> ! {
    let mut restart_configuration = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
    for (offset, byte) in restart_configuration.iter_mut().enumerate() {
        *byte = unsafe { ((BLOCK_CONFIGURATION_BASE as *const u8).add(offset)).read_volatile() };
    }
    let decoded_restart = mrml_kernel::VirtualBlockConfiguration::decode(&restart_configuration)
        .unwrap_or_else(|_| halt());
    if decoded_restart.transport() != mrml_kernel::VirtualBlockTransport::MrmlSpecificPciMmio {
        halt();
    }
    let restart_queue = decoded_restart.queue();
    let request_published = unsafe { (restart_queue.request_base() as *const u64).read_volatile() };
    let request_consumed =
        unsafe { ((restart_queue.request_base() + 64) as *const u64).read_volatile() };
    let completion_published =
        unsafe { (restart_queue.completion_base() as *const u64).read_volatile() };
    let completion_consumed =
        unsafe { ((restart_queue.completion_base() + 64) as *const u64).read_volatile() };
    let mut restart_page = [0; PAGE_SIZE as usize];
    for (offset, byte) in restart_page.iter_mut().enumerate() {
        *byte = unsafe { ((BLOCK_RESUME_BASE as *const u8).add(offset)).read_volatile() };
    }
    let restart_state =
        VirtualBlockResumePage::decode_page(&restart_page).unwrap_or_else(|_| halt());
    if restart_state.configuration() != decoded_restart
        || restart_state.request_producer() != request_published
        || restart_state.request_consumed() != request_consumed
        || restart_state.completion_published() != completion_published
        || restart_state.completion_consumer() != completion_consumed
    {
        halt();
    }
    let fresh = request_published == 0
        && request_consumed == 0
        && completion_published == 0
        && completion_consumed == 0
        && restart_state.last_admitted_request_id() == 0
        && restart_state.last_published_request_id() == 0;
    let recovering = request_published == u64::from(PCI_BLOCK_PROBE_OPERATIONS)
        && request_consumed == u64::from(PCI_BLOCK_PROBE_OPERATIONS)
        && completion_published == u64::from(PCI_BLOCK_PROBE_OPERATIONS)
        && completion_consumed == u64::from(PCI_BLOCK_PROBE_OPERATIONS)
        && restart_state.last_admitted_request_id() == u64::from(PCI_BLOCK_PROBE_OPERATIONS)
        && restart_state.last_published_request_id() == u64::from(PCI_BLOCK_PROBE_OPERATIONS);
    if recovering {
        let mut requests = [[0; VIRTUAL_BLOCK_REQUEST_BYTES]; 2];
        for (slot, request) in requests.iter_mut().enumerate() {
            let base = restart_queue.request_base()
                + 128
                + slot as u64 * VIRTUAL_BLOCK_REQUEST_BYTES as u64;
            for (offset, byte) in request.iter_mut().enumerate() {
                *byte = unsafe { ((base as *const u8).add(offset)).read_volatile() };
            }
        }
        let _driver = VirtualBlockGuestDriver::resume_from_page(
            &restart_configuration,
            &restart_page,
            &requests,
            request_published,
            request_consumed,
            completion_published,
            completion_consumed,
        )
        .unwrap_or_else(|_| halt());
        unsafe {
            asm!(
                "out dx, eax",
                in("dx") PCI_PROOF_PORT,
                in("eax") PCI_BLOCK_PROBE_OPERATIONS,
                options(nomem, nostack)
            )
        };
        unsafe {
            asm!(
                "out dx, eax",
                in("dx") PCI_WITHDRAW_PROOF_PORT,
                in("eax") PCI_BLOCK_PROBE_OPERATIONS,
                options(nomem, nostack)
            )
        };
        halt();
    }
    if !fresh {
        halt();
    }
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") 0xcf8u16,
            in("eax") PCI_TEST_SELECTOR,
            options(nomem, nostack)
        )
    };
    let vendor_device: u32;
    unsafe {
        asm!(
            "in eax, dx",
            in("dx") 0xcfcu16,
            lateout("eax") vendor_device,
            options(nomem, nostack)
        )
    };
    if vendor_device != PCI_TEST_VENDOR_DEVICE {
        halt();
    }
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") 0xcf8u16,
            in("eax") PCI_TEST_CLASS_SELECTOR,
            options(nomem, nostack)
        )
    };
    let class: u32;
    unsafe {
        asm!(
            "in eax, dx",
            in("dx") 0xcfcu16,
            lateout("eax") class,
            options(nomem, nostack)
        )
    };
    if class != PCI_TEST_CLASS {
        halt();
    }
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") 0xcf8u16,
            in("eax") PCI_TEST_BAR_SELECTOR,
            options(nomem, nostack)
        );
        asm!(
            "out dx, eax",
            in("dx") 0xcfcu16,
            in("eax") PCI_TEST_MMIO_BASE as u32,
            options(nomem, nostack)
        );
        asm!(
            "out dx, eax",
            in("dx") 0xcf8u16,
            in("eax") PCI_TEST_COMMAND_SELECTOR,
            options(nomem, nostack)
        );
        asm!(
            "out dx, ax",
            in("dx") 0xcfcu16,
            in("ax") mrml_kernel::PCI_COMMAND_MEMORY_SPACE
                | mrml_kernel::PCI_COMMAND_INTERRUPT_DISABLE,
            options(nomem, nostack)
        );
    }

    let mut encoded_configuration = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
    for (offset, byte) in encoded_configuration.iter_mut().enumerate() {
        // SAFETY: the dedicated launch path maps this exact canonical page
        // read-only and keeps it live for the complete probe.
        *byte = unsafe { ((BLOCK_CONFIGURATION_BASE as *const u8).add(offset)).read_volatile() };
    }
    let configuration = mrml_kernel::VirtualBlockConfiguration::decode(&encoded_configuration)
        .unwrap_or_else(|_| halt());
    if configuration.transport() != mrml_kernel::VirtualBlockTransport::MrmlSpecificPciMmio {
        halt();
    }
    let queue = configuration.queue();
    let request_published = unsafe { (queue.request_base() as *const u64).read_volatile() };
    let request_consumed = unsafe { ((queue.request_base() + 64) as *const u64).read_volatile() };
    let completion_published = unsafe { (queue.completion_base() as *const u64).read_volatile() };
    let completion_consumed =
        unsafe { ((queue.completion_base() + 64) as *const u64).read_volatile() };
    let mut driver = VirtualBlockGuestDriver::discover(
        &encoded_configuration,
        request_published,
        request_consumed,
        completion_published,
        completion_consumed,
    )
    .unwrap_or_else(|_| halt());
    // SAFETY: the launch path maps the exact queue pages directionally and
    // installs a non-RAM trap leaf for this exact one-page BAR.
    let mut queue_transport = unsafe {
        X86VirtualBlockGuestQueueTransport::new_pci_mmio(
            NativeX86VirtualBlockPortIo,
            PCI_TEST_MMIO_BASE,
            PAGE_SIZE as u32,
        )
        .unwrap_or_else(|_| halt())
    };

    unsafe { asm!("sti", options(nomem, nostack)) };
    let patterns = [0x5au8, 0xa5u8];
    for (block, pattern) in patterns.into_iter().enumerate() {
        let base = BLOCK_PAYLOAD_BASE + block as u64 * PAGE_SIZE;
        for offset in 0..PAGE_SIZE as usize {
            unsafe { ((base as *mut u8).add(offset)).write_volatile(pattern) };
        }
        let submission = driver
            .prepare_write(block as u64, 1, base, PAGE_SIZE as u32)
            .unwrap_or_else(|_| halt());
        driver
            .publish_submission(&mut queue_transport, submission)
            .unwrap_or_else(|_| halt());
        if block == 0 {
            // Exercise conventional PCI interrupt masking: the completed
            // request remains pending until this exact function is unmasked.
            unsafe {
                asm!(
                    "out dx, ax",
                    in("dx") 0xcfcu16,
                    in("ax") mrml_kernel::PCI_COMMAND_MEMORY_SPACE,
                    options(nomem, nostack)
                )
            };
        }
    }
    for _ in 0..2 {
        let completion = driver
            .prepare_completion_from_transport(&mut queue_transport)
            .unwrap_or_else(|_| halt());
        if completion.status() != mrml_kernel::VirtualBlockCompletionStatus::Ok
            || completion.transferred() != PAGE_SIZE as u32
        {
            halt();
        }
        driver
            .acknowledge_completion_with_transport(&mut queue_transport, completion)
            .unwrap_or_else(|_| halt());
    }

    for offset in 0..(PAGE_SIZE as usize * 2) {
        unsafe { ((BLOCK_PAYLOAD_BASE as *mut u8).add(offset)).write_volatile(0) };
    }
    for block in 0..2u64 {
        let submission = driver
            .prepare_read(
                block,
                1,
                BLOCK_PAYLOAD_BASE + block * PAGE_SIZE,
                PAGE_SIZE as u32,
            )
            .unwrap_or_else(|_| halt());
        driver
            .publish_submission(&mut queue_transport, submission)
            .unwrap_or_else(|_| halt());
    }
    for _ in 0..2 {
        let completion = driver
            .prepare_completion_from_transport(&mut queue_transport)
            .unwrap_or_else(|_| halt());
        if completion.status() != mrml_kernel::VirtualBlockCompletionStatus::Ok
            || completion.transferred() != PAGE_SIZE as u32
        {
            halt();
        }
        driver
            .acknowledge_completion_with_transport(&mut queue_transport, completion)
            .unwrap_or_else(|_| halt());
    }
    let flush = driver.prepare_flush().unwrap_or_else(|_| halt());
    driver
        .publish_submission(&mut queue_transport, flush)
        .unwrap_or_else(|_| halt());
    let completion = driver
        .prepare_completion_from_transport(&mut queue_transport)
        .unwrap_or_else(|_| halt());
    if completion.status() != mrml_kernel::VirtualBlockCompletionStatus::Ok
        || completion.transferred() != 0
    {
        halt();
    }
    driver
        .acknowledge_completion_with_transport(&mut queue_transport, completion)
        .unwrap_or_else(|_| halt());
    for (block, pattern) in patterns.into_iter().enumerate() {
        let base = BLOCK_PAYLOAD_BASE + block as u64 * PAGE_SIZE;
        for offset in 0..PAGE_SIZE as usize {
            if unsafe { ((base as *const u8).add(offset)).read_volatile() } != pattern {
                halt();
            }
        }
    }
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") PCI_PROOF_PORT,
            in("eax") PCI_BLOCK_PROBE_OPERATIONS,
            options(nomem, nostack)
        )
    };
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") PCI_WITHDRAW_PROOF_PORT,
            in("eax") PCI_BLOCK_PROBE_OPERATIONS,
            options(nomem, nostack)
        )
    };
    halt()
}

#[cfg(not(feature = "fault-probe"))]
#[allow(unreachable_code)]
unsafe fn run_kernel(bytes: *const u8, length: usize) -> ! {
    smp_trace(0x01);
    if bytes.is_null() || !(HANDOFF_HEADER_BYTES..=MAX_HANDOFF_BYTES).contains(&length) {
        halt();
    }
    let encoded = unsafe { core::slice::from_raw_parts(bytes, length) };
    let placeholder = match MemoryRegion::new(
        match PhysAddr::new(0) {
            Ok(value) => value,
            Err(_) => halt(),
        },
        1,
        MemoryKind::Reserved,
    ) {
        Ok(value) => value,
        Err(_) => halt(),
    };
    let mut regions = [placeholder; MAX_HANDOFF_REGIONS];
    let mut region_count = 0usize;
    let handoff = match BootHandoff::decode(encoded, |region| {
        if region_count < regions.len() {
            regions[region_count] = region;
            region_count += 1;
        }
    }) {
        Ok(value) => value,
        Err(_) => halt(),
    };
    #[cfg(feature = "uefi-service-preemption-probe")]
    uefi_service_trace(0xc0);
    smp_trace(0x02);
    if region_count != handoff.region_count() {
        halt();
    }
    let early = EarlyKernelContext::from_handoff(&handoff, &regions[..region_count])
        .unwrap_or_else(|_| halt());
    #[cfg(feature = "pci-configuration-probe")]
    unsafe {
        run_pci_configuration_probe()
    }
    #[cfg(feature = "block-guest-driver-probe")]
    unsafe {
        run_block_guest_driver_probe()
    }
    #[cfg(feature = "vmx-root-probe")]
    if unsafe { vmx_probe::run() }.is_err() {
        halt();
    }
    if let Some(madt) = handoff.madt(encoded) {
        smp_trace(0x03);
        let topology = X86CpuTopology::parse_madt(madt).unwrap_or_else(|_| halt());
        smp_trace(0x40u8.saturating_add(topology.len() as u8));
        match (handoff.ap_trampoline(), handoff.ap_stack_arena()) {
            (Some(_), Some(base)) => {
                let stacks = PerCpuPrivilegeStacks::<MAX_X86_64_CPUS>::new(
                    base,
                    base,
                    PRIVILEGE_STACK_ARENA_PAGES,
                )
                .unwrap_or_else(|_| halt());
                for cpu in 0..topology.len() {
                    if stacks.cpu(cpu).is_err() {
                        halt();
                    }
                }
                if topology.len() > 1 {
                    smp_trace(0x04);
                    unsafe { start_application_processors(&topology, &handoff) };
                    smp_trace(0x05);
                    #[cfg(feature = "smp-ipi-probe")]
                    unsafe {
                        send_reschedule_probe(&topology)
                    };
                    #[cfg(feature = "smp-probe")]
                    unsafe {
                        asm!(
                            "out dx, eax",
                            in("dx") SMP_PROBE_PORT,
                            in("eax") topology.len() as u32,
                            options(nomem, nostack)
                        )
                    };
                    #[cfg(feature = "smp-scheduler-probe")]
                    unsafe {
                        asm!(
                            "out dx, eax",
                            in("dx") SMP_SCHEDULER_READY_PORT,
                            in("eax") topology.len() as u32,
                            options(nomem, nostack)
                        )
                    };
                }
            }
            (None, None) if topology.len() == 1 => {}
            _ => halt(),
        }
    }
    #[cfg(feature = "service-probe")]
    unsafe {
        run_service_probe(&handoff, |handoff| {
            let _ = handoff;
            let service_entry = hosted_service_entry();
            let mut context_a = UserContext::new(
                PhysAddr::new(SERVICE_ROOT).unwrap_or_else(|_| halt()),
                service_entry,
                SERVICE_STACK_TOP,
            )
            .unwrap_or_else(|_| halt());
            #[cfg(feature = "component-service-probe")]
            let service_b_entry = hosted_provider_entry();
            #[cfg(not(feature = "component-service-probe"))]
            let service_b_entry = service_entry + 0x200;
            let mut context_b = UserContext::new(
                PhysAddr::new(SERVICE_B_ROOT).unwrap_or_else(|_| halt()),
                service_b_entry,
                SERVICE_STACK_TOP,
            )
            .unwrap_or_else(|_| halt());
            context_a.r12 = 1;
            context_b.r12 = 1;
            let runtime_pointer = core::ptr::addr_of_mut!(SERVICE_RUNTIME);
            #[cfg(feature = "component-service-probe")]
            {
                let mut authorities = CapabilitySpace::<3>::new();
                let mut memory = MemoryPoolTable::<1, 2>::new(0x5444).unwrap_or_else(|_| halt());
                let runtime_pages =
                    AccountedTaskRuntime::<3, 9>::required_pages().unwrap_or_else(|_| halt());
                let supervisor_pages =
                    AccountedServiceSupervisor::<3>::required_pages().unwrap_or_else(|_| halt());
                let committed_pages = runtime_pages
                    .checked_add(supervisor_pages)
                    .unwrap_or_else(|| halt());
                let (pool, pool_capability) = memory
                    .create_root(
                        committed_pages,
                        2,
                        0,
                        Rights::ALLOCATE
                            .union(Rights::CONTROL)
                            .union(Rights::INSPECT),
                        &mut authorities,
                    )
                    .unwrap_or_else(|_| halt());
                let runtime = AccountedTaskRuntime::<3, 9>::new(
                    1_000,
                    1,
                    pool,
                    pool_capability,
                    &mut memory,
                    &mut authorities,
                )
                .unwrap_or_else(|_| halt());
                let supervisor = AccountedServiceSupervisor::<3>::new(
                    pool,
                    pool_capability,
                    &mut memory,
                    &mut authorities,
                )
                .unwrap_or_else(|_| halt());
                if runtime.committed_pages() != runtime_pages
                    || supervisor.committed_pages() != supervisor_pages
                    || memory
                        .usage(pool, pool_capability, &authorities)
                        .map(|usage| usage.object_pages())
                        != Ok(committed_pages)
                {
                    halt();
                }
                runtime_pointer.write(Some(runtime));
                core::ptr::addr_of_mut!(SERVICE_SUPERVISOR).write(Some(supervisor));
                core::ptr::addr_of_mut!(COMPONENT_SERVICE_MEMORY).write(Some(memory));
                core::ptr::addr_of_mut!(COMPONENT_SERVICE_MEMORY_AUTHORITIES)
                    .write(Some(authorities));
                core::ptr::addr_of_mut!(COMPONENT_SERVICE_MEMORY_POOL)
                    .write(Some((pool, pool_capability)));
            }
            #[cfg(not(feature = "component-service-probe"))]
            runtime_pointer.write(Some(
                TaskRuntime::<3, 9>::new(1_000, 1).unwrap_or_else(|_| halt()),
            ));
            let runtime = (*runtime_pointer).as_mut().unwrap_or_else(|| halt());
            let receiver = runtime
                .create(Priority::NORMAL, context_a)
                .unwrap_or_else(|_| halt());
            #[cfg(any(
                feature = "service-restart-request-probe",
                feature = "deadline-receive-cancel-probe"
            ))]
            let manager = runtime
                .create(
                    Priority::RESPONSIVE,
                    UserContext::new(
                        PhysAddr::new(SERVICE_C_ROOT).unwrap_or_else(|_| halt()),
                        service_entry + 0x400,
                        SERVICE_STACK_TOP,
                    )
                    .unwrap_or_else(|_| halt()),
                )
                .unwrap_or_else(|_| halt());
            let sender = runtime
                .create(Priority::NORMAL, context_b)
                .unwrap_or_else(|_| halt());
            #[cfg(feature = "component-service-probe")]
            let supervisor = (*core::ptr::addr_of_mut!(SERVICE_SUPERVISOR))
                .as_mut()
                .unwrap_or_else(|| halt());
            #[cfg(not(feature = "component-service-probe"))]
            let mut supervisor_storage = ServiceSupervisor::<3>::new();
            #[cfg(not(feature = "component-service-probe"))]
            let supervisor = &mut supervisor_storage;
            let service_a = supervisor
                .register_with_policy_in_runtime(
                    ObjectId(0xa0),
                    receiver,
                    RestartPolicy::ONCE_IMMEDIATE,
                    runtime,
                )
                .unwrap_or_else(|_| halt());
            let service_b = supervisor
                .register_with_policy_in_runtime(
                    ObjectId(0xa1),
                    sender,
                    RestartPolicy::ONCE_IMMEDIATE,
                    runtime,
                )
                .unwrap_or_else(|_| halt());
            #[cfg(any(
                feature = "service-restart-request-probe",
                feature = "deadline-receive-cancel-probe"
            ))]
            let service_c = supervisor
                .register_with_policy_in_runtime(
                    ObjectId(0xa2),
                    manager,
                    RestartPolicy::ONCE_IMMEDIATE,
                    runtime,
                )
                .unwrap_or_else(|_| halt());
            let mut management = CapabilitySpace::<3>::new();
            let control_a = management
                .insert(ObjectId(0xa0), Rights::CONTROL)
                .unwrap_or_else(|_| halt());
            let control_b = management
                .insert(ObjectId(0xa1), Rights::CONTROL)
                .unwrap_or_else(|_| halt());
            #[cfg(any(
                feature = "service-restart-request-probe",
                feature = "deadline-receive-cancel-probe"
            ))]
            let control_c = management
                .insert(ObjectId(0xa2), Rights::CONTROL)
                .unwrap_or_else(|_| halt());
            let endpoint_object = ObjectId(0x91);
            let receiver_capability = runtime
                .capabilities_mut(receiver)
                .and_then(|space| {
                    space
                        .insert(endpoint_object, Rights::SIGNAL)
                        .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
                })
                .unwrap_or_else(|_| halt());
            let recovery_capability = early.recovery_state().map(|_| {
                let object = ObjectId(0xa3);
                let capability = runtime
                    .capabilities_mut(receiver)
                    .and_then(|space| {
                        space
                            .insert(object, Rights::READ)
                            .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
                    })
                    .unwrap_or_else(|_| halt());
                let delivery = BootRecoveryDelivery::from_early(receiver, object, &early)
                    .unwrap_or_else(|_| halt());
                core::ptr::addr_of_mut!(SERVICE_BOOT_RECOVERY).write(Some(delivery));
                capability
            });
            #[cfg(feature = "block-service-probe")]
            let (resource_capabilities, sender_resources) =
                provision_service_resource(runtime, receiver, Some(sender));
            #[cfg(feature = "component-service-probe")]
            let (resource_capabilities, _) =
                provision_service_resource(runtime, receiver, Some(sender));
            #[cfg(not(any(feature = "block-service-probe", feature = "component-service-probe")))]
            let (resource_capabilities, _) = provision_service_resource(runtime, receiver, None);
            #[cfg(feature = "block-service-probe")]
            let [sender_write, sender_read, sender_transfer] =
                sender_resources.unwrap_or_else(|| halt());
            #[cfg(feature = "component-service-probe")]
            let resource_transfer = runtime
                .capabilities_mut(receiver)
                .and_then(|space| {
                    space
                        .insert(
                            ObjectId(0x94),
                            Rights::MAP
                                .union(Rights::READ)
                                .union(Rights::WRITE)
                                .union(Rights::DELEGATE),
                        )
                        .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
                })
                .unwrap_or_else(|_| halt());
            #[cfg(all(
                not(feature = "block-service-probe"),
                not(feature = "deadline-receive-cancel-probe")
            ))]
            let supervision_capability = runtime
                .capabilities_mut(sender)
                .and_then(|space| {
                    space
                        .insert(
                            ObjectId(0xa1),
                            Rights::READ.union(Rights::CONTROL).union(Rights::DELEGATE),
                        )
                        .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
                })
                .unwrap_or_else(|_| halt());
            #[cfg(feature = "deadline-receive-cancel-probe")]
            let deadline_receiver_authority = runtime
                .capabilities_mut(sender)
                .and_then(|space| {
                    space
                        .insert(
                            ObjectId(0xa0),
                            if cfg!(feature = "deadline-receive-cancel-denied-probe") {
                                Rights::READ.union(Rights::DELEGATE)
                            } else {
                                Rights::CONTROL.union(Rights::DELEGATE)
                            },
                        )
                        .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
                })
                .unwrap_or_else(|_| halt());
            let capability = runtime
                .capabilities_mut(sender)
                .and_then(|space| {
                    space
                        .insert(endpoint_object, Rights::SIGNAL)
                        .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
                })
                .unwrap_or_else(|_| halt());
            let root_capability = runtime
                .capabilities_mut(sender)
                .and_then(|space| {
                    space
                        .insert(
                            ObjectId(0x92),
                            Rights::READ.union(Rights::CONTROL).union(Rights::DELEGATE),
                        )
                        .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
                })
                .unwrap_or_else(|_| halt());
            #[cfg(not(feature = "component-service-probe"))]
            let setting_capability = runtime
                .capabilities_mut(sender)
                .and_then(|space| {
                    space
                        .insert(
                            ObjectId(0x93),
                            Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE),
                        )
                        .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
                })
                .unwrap_or_else(|_| halt());
            #[cfg(any(
                feature = "service-restart-request-probe",
                feature = "deadline-receive-cancel-probe"
            ))]
            let manager_signal = runtime
                .capabilities_mut(manager)
                .and_then(|space| {
                    space
                        .insert(endpoint_object, Rights::SIGNAL)
                        .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
                })
                .unwrap_or_else(|_| halt());
            #[cfg(feature = "service-restart-request-probe")]
            let manager_control = runtime
                .capabilities_mut(manager)
                .and_then(|space| {
                    space
                        .insert(ObjectId(0xa1), Rights::CONTROL.union(Rights::DELEGATE))
                        .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
                })
                .unwrap_or_else(|_| halt());
            let endpoint = Endpoint::new(endpoint_object);
            runtime
                .connect_control_peers(receiver, sender, &endpoint, receiver_capability, capability)
                .unwrap_or_else(|_| halt());
            let receiver_context = runtime.context_mut(receiver).unwrap_or_else(|_| halt());
            receiver_context.r13 = receiver_capability.token();
            receiver_context.r14 = sender.token();
            receiver_context.r15 = resource_capabilities[0].token();
            #[cfg(feature = "component-service-probe")]
            {
                receiver_context.r12 = 1;
                receiver_context.rbx = resource_transfer.token();
            }
            #[cfg(not(feature = "component-service-probe"))]
            {
                receiver_context.rbx = resource_capabilities[1].token();
            }
            receiver_context.r11 = recovery_capability.map_or(0, Capability::token);
            #[cfg(feature = "service-restart-request-probe")]
            {
                receiver_context.rbp = manager.token();
            }
            let sender_context = runtime.context_mut(sender).unwrap_or_else(|_| halt());
            sender_context.r13 = capability.token();
            #[cfg(not(feature = "deadline-receive-cancel-probe"))]
            {
                sender_context.r14 = receiver.token();
            }
            #[cfg(feature = "deadline-receive-cancel-probe")]
            {
                sender_context.r14 = manager.token();
            }
            #[cfg(feature = "component-service-probe")]
            {
                sender_context.r12 = 1;
            }
            #[cfg(not(feature = "block-service-probe"))]
            {
                sender_context.r15 = root_capability.token();
            }
            #[cfg(feature = "block-service-probe")]
            {
                sender_context.r15 = sender_write.token();
                sender_context.r11 = sender_read.token();
            }
            #[cfg(not(feature = "component-service-probe"))]
            {
                sender_context.rbx = setting_capability.token();
            }
            #[cfg(all(
                not(feature = "block-service-probe"),
                not(feature = "deadline-receive-cancel-probe")
            ))]
            {
                sender_context.rbp = supervision_capability.token();
            }
            #[cfg(feature = "deadline-receive-cancel-probe")]
            {
                sender_context.rbp = deadline_receiver_authority.token();
            }
            #[cfg(feature = "block-service-probe")]
            {
                sender_context.rbp = sender_transfer.token();
            }
            #[cfg(all(
                not(feature = "block-service-probe"),
                not(feature = "deadline-receive-cancel-probe")
            ))]
            {
                sender_context.r10 = service_b.token();
            }
            #[cfg(feature = "deadline-receive-cancel-probe")]
            {
                sender_context.r10 = service_a.token();
            }
            #[cfg(feature = "block-service-probe")]
            {
                sender_context.r10 = root_capability.token();
            }
            #[cfg(any(
                feature = "service-restart-request-probe",
                feature = "deadline-receive-cancel-probe"
            ))]
            {
                let manager_context = runtime.context_mut(manager).unwrap_or_else(|_| halt());
                manager_context.r13 = manager_signal.token();
                #[cfg(feature = "service-restart-request-probe")]
                {
                    manager_context.r14 = receiver.token();
                }
                #[cfg(feature = "deadline-receive-cancel-probe")]
                {
                    manager_context.r14 = sender.token();
                }
                #[cfg(feature = "service-restart-request-probe")]
                {
                    manager_context.r15 = manager_control.token();
                }
                #[cfg(feature = "service-restart-request-probe")]
                {
                    manager_context.rbx = service_b.token();
                }
            }
            if !matches!(runtime.start(), ScheduleOutcome::Switch { from: None, to } if to == receiver)
            {
                halt();
            }
            core::ptr::addr_of_mut!(SERVICE_ENDPOINT).write(Some(endpoint));
            #[cfg(not(feature = "component-service-probe"))]
            core::ptr::addr_of_mut!(SERVICE_SUPERVISOR).write(Some(supervisor_storage));
            core::ptr::addr_of_mut!(SERVICE_MANAGEMENT).write(Some(management));
            #[cfg(any(
                feature = "service-restart-request-probe",
                feature = "deadline-receive-cancel-probe"
            ))]
            {
                core::ptr::addr_of_mut!(SERVICE_CONTROLS)
                    .write(Some([control_a, control_b, control_c]));
                core::ptr::addr_of_mut!(SERVICE_IDS).write(Some([service_a, service_b, service_c]));
            }
            #[cfg(not(any(
                feature = "service-restart-request-probe",
                feature = "deadline-receive-cancel-probe"
            )))]
            {
                core::ptr::addr_of_mut!(SERVICE_CONTROLS)
                    .write(Some([control_a, control_b, control_a]));
                core::ptr::addr_of_mut!(SERVICE_IDS).write(Some([service_a, service_b, service_a]));
            }
            core::ptr::addr_of_mut!(SERVICE_RECEIVER_SIGNAL).write(Some(receiver_capability));
            #[cfg(feature = "deadline-receive-probe")]
            core::ptr::addr_of_mut!(SERVICE_DEADLINE_RECEIVES).write(Some(
                mrml_kernel::DeadlineReceiveSyscallExecutor::new(),
            ));
            #[cfg(feature = "deadline-receive-probe")]
            core::ptr::addr_of_mut!(SERVICE_DEADLINE_CANCELLATIONS).write(Some(
                mrml_kernel::DeadlineReceiveCancellationEscrow::new(),
            ));
            #[cfg(feature = "deadline-receive-probe")]
            LocalApicTimer::periodic(TIMER_VECTOR, 100_000, TimerDivide::By16)
                .and_then(|timer| timer.enable())
                .unwrap_or_else(|_| halt());
            let context = (*runtime_pointer)
                .as_ref()
                .and_then(|runtime| runtime.context(receiver).ok())
                .map(|context| context as *const UserContext)
                .unwrap_or_else(|| halt());
            enter_service_probe_context(&*context);
        });
    }
    #[cfg(feature = "user-probe")]
    unsafe {
        let user_stack: u64;
        let page_table: u64;
        asm!("mov {}, rsp", out(reg) user_stack, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) page_table, options(nomem, nostack, preserves_flags));
        let page_table = match PhysAddr::new(page_table) {
            Ok(page_table) => page_table,
            Err(_) => halt(),
        };
        let context = match UserContext::new(
            page_table,
            mrml_user_probe as *const () as usize as u64,
            user_stack & !0xf,
        ) {
            Ok(context) => context,
            Err(_) => halt(),
        };
        let replacement_context = match UserContext::new(
            page_table,
            mrml_user_replacement_probe as *const () as usize as u64,
            (user_stack & !0xf)
                .checked_sub(4096)
                .unwrap_or_else(|| halt()),
        ) {
            Ok(context) => context,
            Err(_) => halt(),
        };
        let mut runtime = match TaskRuntime::<2, 1>::new(1_000, 1) {
            Ok(runtime) => runtime,
            Err(_) => halt(),
        };
        let task = match runtime.create(Priority::NORMAL, context) {
            Ok(task) => task,
            Err(_) => halt(),
        };
        let replacement = match runtime.create(Priority::NORMAL, replacement_context) {
            Ok(task) => task,
            Err(_) => halt(),
        };
        let endpoint_object = ObjectId(0x81);
        let endpoint_capability = match runtime.capabilities_mut(task).and_then(|space| {
            space
                .insert(endpoint_object, Rights::SIGNAL)
                .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
        }) {
            Ok(capability) => capability,
            Err(_) => halt(),
        };
        let context = match runtime.context_mut(task) {
            Ok(context) => context,
            Err(_) => halt(),
        };
        context.rax = 1;
        context.rdi = endpoint_capability.token();
        context.rsi = replacement.token();
        context.rdx = 4;
        context.r10 = u64::from_le_bytes(*b"ping\0\0\0\0");
        core::ptr::addr_of_mut!(USER_ENDPOINT).write(Some(Endpoint::new(endpoint_object)));
        if !matches!(
            runtime.start(),
            ScheduleOutcome::Switch { from: None, to } if to == task
        ) {
            halt();
        }
        let runtime_pointer = core::ptr::addr_of_mut!(USER_RUNTIME);
        runtime_pointer.write(Some(runtime));
        let context_pointer = match (*runtime_pointer).as_ref() {
            Some(runtime) => match runtime.context(task) {
                Ok(context) => context as *const UserContext,
                Err(_) => halt(),
            },
            None => halt(),
        };
        enter_user_probe_context(&*context_pointer);
    }
    #[cfg(feature = "application-probe")]
    unsafe {
        application_probe_trace(1);
        let application = handoff.application().unwrap_or_else(|| halt());
        let artifact_length =
            usize::try_from(application.artifact_length()).unwrap_or_else(|_| halt());
        let artifact = core::slice::from_raw_parts(
            application.artifact_physical().get() as *const u8,
            artifact_length,
        );
        let signed = SignedArtifact::decode(artifact).unwrap_or_else(|_| halt());
        let verified = signed
            .verify_executable(
                &TrustRoot::new(
                    ArtifactKind::ApplicationImage,
                    embedded_application_root().unwrap_or_else(|| halt()),
                    embedded_application_minimum_version().unwrap_or_else(|| halt()),
                ),
                ArtifactKind::ApplicationImage,
            )
            .unwrap_or_else(|_| halt());
        application_probe_trace(2);
        let plan = ApplicationAddressSpace::<40>::from_handoff(application, &verified, &[])
            .unwrap_or_else(|_| halt());
        application_probe_trace(3);
        let store = PreallocatedPageTableStore::new(
            application.table_physical(),
            application.table_pages(),
        )
        .unwrap_or_else(|_| halt());
        let tables = match plan.build_page_tables_with_current_kernel(store) {
            Ok(tables) => tables,
            Err(error) => {
                let detail = match error {
                    ServiceSpaceError::Tables(PageTableBuildError::Storage) => 0x101,
                    ServiceSpaceError::Tables(PageTableBuildError::InvalidIntermediate) => 0x102,
                    ServiceSpaceError::Tables(PageTableBuildError::AlreadyMapped) => 0x103,
                    ServiceSpaceError::Tables(PageTableBuildError::NotMapped) => 0x104,
                    ServiceSpaceError::Tables(PageTableBuildError::MappingMismatch) => 0x105,
                    ServiceSpaceError::Tables(PageTableBuildError::AddressOverflow) => 0x106,
                    ServiceSpaceError::Tables(PageTableBuildError::Page(_)) => 0x107,
                    _ => 0x1ff,
                };
                application_probe_trace(detail);
                halt();
            }
        };
        application_probe_trace(4);
        let context = UserContext::new(tables.root(), plan.entry(), plan.stack_top())
            .unwrap_or_else(|_| halt());
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap_or_else(|_| halt());
        let task = runtime
            .create(Priority::NORMAL, context)
            .unwrap_or_else(|_| halt());
        if !matches!(runtime.start(), ScheduleOutcome::Switch { from: None, to } if to == task) {
            halt();
        }
        application_probe_trace(5);
        core::ptr::addr_of_mut!(APPLICATION_RUNTIME).write(Some(runtime));
        let context = (*core::ptr::addr_of!(APPLICATION_RUNTIME))
            .as_ref()
            .and_then(|runtime| runtime.context(task).ok())
            .map(|context| context as *const UserContext)
            .unwrap_or_else(|| halt());
        application_probe_trace(6);
        enter_application_probe_context(&*context);
    }
    #[cfg(feature = "service-preemption-probe")]
    unsafe {
        asm!("cli", options(nomem, nostack));
        #[cfg(feature = "uefi-service-preemption-probe")]
        let (service_root, service_entry, service_stack_top) = {
            let service = handoff.service().unwrap_or_else(|| halt());
            uefi_service_trace(0xc1);
            let artifact_length =
                usize::try_from(service.artifact_length()).unwrap_or_else(|_| halt());
            let artifact = core::slice::from_raw_parts(
                service.artifact_physical().get() as *const u8,
                artifact_length,
            );
            let signed = SignedArtifact::decode(artifact).unwrap_or_else(|_| halt());
            let verified = signed
                .verify_executable(
                    &TrustRoot::new(
                        ArtifactKind::ServiceImage,
                        embedded_service_root().unwrap_or_else(|| halt()),
                        embedded_service_minimum_version().unwrap_or_else(|| halt()),
                    ),
                    ArtifactKind::ServiceImage,
                )
                .unwrap_or_else(|_| halt());
            uefi_service_trace(0xc2);
            let plan = ServiceAddressSpace::<40>::from_handoff(service, &verified, &[])
                .unwrap_or_else(|_| halt());
            uefi_service_trace(0xc3);
            let store =
                PreallocatedPageTableStore::new(service.table_physical(), service.table_pages())
                    .unwrap_or_else(|_| halt());
            uefi_service_trace(0xc4);
            let tables = plan
                .build_page_tables_with_current_kernel(store)
                .unwrap_or_else(|_| halt());
            uefi_service_trace(0xc5);
            (tables.root(), plan.entry(), plan.stack_top())
        };
        #[cfg(not(feature = "uefi-service-preemption-probe"))]
        let (service_root, service_entry, service_stack_top) = (
            PhysAddr::new(SERVICE_ROOT).unwrap_or_else(|_| halt()),
            SERVICE_ENTRY,
            SERVICE_STACK_TOP,
        );
        let first_context = UserContext::new(service_root, service_entry, service_stack_top)
            .unwrap_or_else(|_| halt());
        #[cfg(feature = "uefi-service-preemption-probe")]
        uefi_service_trace(0xc6);
        let second_context = UserContext::new(
            service_root,
            service_entry.checked_add(0x80).unwrap_or_else(|| halt()),
            service_stack_top,
        )
        .unwrap_or_else(|_| halt());
        let mut runtime = TaskRuntime::<2, 0>::new(1_000, 1).unwrap_or_else(|_| halt());
        let first = runtime
            .create(Priority::NORMAL, first_context)
            .unwrap_or_else(|_| halt());
        runtime
            .create(Priority::NORMAL, second_context)
            .unwrap_or_else(|_| halt());
        if !matches!(runtime.start(), ScheduleOutcome::Switch { from: None, to } if to == first) {
            halt();
        }
        core::ptr::addr_of_mut!(PREEMPTION_RUNTIME).write(Some(runtime));
        LocalApicTimer::periodic(TIMER_VECTOR, 100_000, TimerDivide::By16)
            .and_then(|timer| timer.enable())
            .unwrap_or_else(|_| halt());
        let mut previous = LocalApicTimer::current_count();
        loop {
            let current = LocalApicTimer::current_count();
            if current > previous {
                break;
            }
            previous = current;
            core::hint::spin_loop();
        }
        asm!(
            "out dx, eax",
            in("dx") TIMER_READY_PORT,
            in("eax") 1u32,
            options(nomem, nostack)
        );
        let context = (*core::ptr::addr_of!(PREEMPTION_RUNTIME))
            .as_ref()
            .and_then(|runtime| runtime.context(first).ok())
            .map(|context| context as *const UserContext)
            .unwrap_or_else(|| halt());
        #[cfg(feature = "uefi-service-preemption-probe")]
        uefi_service_trace(0xc7);
        enter_service_preemption_context(&*context)
    }
    #[cfg(feature = "preemption-probe")]
    unsafe {
        asm!("cli", options(nomem, nostack));
        let user_stack: u64;
        let page_table: u64;
        asm!("mov {}, rsp", out(reg) user_stack, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) page_table, options(nomem, nostack, preserves_flags));
        let root = PhysAddr::new(page_table).unwrap_or_else(|_| halt());
        let first_context = UserContext::new(
            root,
            mrml_preemption_spin as *const () as usize as u64,
            user_stack & !0xf,
        )
        .unwrap_or_else(|_| halt());
        let second_context = UserContext::new(
            root,
            mrml_preemption_replacement as *const () as usize as u64,
            (user_stack & !0xf)
                .checked_sub(4096)
                .unwrap_or_else(|| halt()),
        )
        .unwrap_or_else(|_| halt());
        let mut runtime = TaskRuntime::<2, 0>::new(1_000, 1).unwrap_or_else(|_| halt());
        let first = runtime
            .create(Priority::NORMAL, first_context)
            .unwrap_or_else(|_| halt());
        runtime
            .create(Priority::NORMAL, second_context)
            .unwrap_or_else(|_| halt());
        if !matches!(runtime.start(), ScheduleOutcome::Switch { from: None, to } if to == first) {
            halt();
        }
        core::ptr::addr_of_mut!(PREEMPTION_RUNTIME).write(Some(runtime));
        LocalApicTimer::periodic(TIMER_VECTOR, 100_000, TimerDivide::By16)
            .and_then(|timer| timer.enable())
            .unwrap_or_else(|_| halt());
        let mut previous = LocalApicTimer::current_count();
        loop {
            let current = LocalApicTimer::current_count();
            if current > previous {
                break;
            }
            previous = current;
            core::hint::spin_loop();
        }
        asm!(
            "out dx, eax",
            in("dx") TIMER_READY_PORT,
            in("eax") 1u32,
            options(nomem, nostack)
        );
        let context = (*core::ptr::addr_of!(PREEMPTION_RUNTIME))
            .as_ref()
            .and_then(|runtime| runtime.context(first).ok())
            .map(|context| context as *const UserContext)
            .unwrap_or_else(|| halt());
        enter_user_context(&*context)
    }
    #[cfg(feature = "timer-probe")]
    unsafe {
        let mut scheduler = match KernelScheduler::<1>::new(1_000, 1) {
            Ok(scheduler) => scheduler,
            Err(_) => halt(),
        };
        if scheduler.create(Priority::NORMAL).is_err()
            || !matches!(scheduler.start(), ScheduleOutcome::Switch { .. })
        {
            halt();
        }
        core::ptr::addr_of_mut!(TIMER_SCHEDULER).write(Some(scheduler));
        let timer = LocalApicTimer::periodic(TIMER_VECTOR, 100_000, TimerDivide::By16)
            .unwrap_or_else(|_| halt());
        timer.enable().unwrap_or_else(|_| halt());
        asm!(
            "out dx, eax",
            in("dx") TIMER_READY_PORT,
            in("eax") 1u32,
            options(nomem, nostack)
        );
        let mut previous = LocalApicTimer::current_count();
        loop {
            let current = LocalApicTimer::current_count();
            if current > previous {
                break;
            }
            previous = current;
            core::hint::spin_loop();
        }
        asm!(
            "out dx, eax",
            "sti",
            "2:",
            "pause",
            "jmp 2b",
            in("dx") TIMER_READY_PORT,
            in("eax") 2u32,
            options(noreturn, nomem, nostack)
        );
    }
    #[cfg(all(
        not(feature = "timer-probe"),
        not(feature = "preemption-probe"),
        not(feature = "service-preemption-probe"),
        not(feature = "application-probe"),
        not(feature = "user-probe"),
        not(feature = "service-probe")
    ))]
    {
        #[cfg(feature = "production-policy")]
        {
            let minimum_version = match embedded_minimum_version() {
                Some(value) => value,
                None => halt(),
            };
            if BootPolicy::production(minimum_version)
                .validate(handoff.evidence())
                .is_err()
            {
                halt();
            }
        }
        let framebuffer = handoff.framebuffer();
        let framebuffer_bytes = unsafe {
            core::slice::from_raw_parts_mut(
                framebuffer.base().get() as *mut u8,
                framebuffer.byte_length() as usize,
            )
        };
        let mut surface = match FramebufferSurface::new(framebuffer, framebuffer_bytes) {
            Ok(value) => value,
            Err(_) => halt(),
        };
        if surface
            .fill_rectangle(
                0,
                0,
                framebuffer.width(),
                framebuffer.height(),
                Color {
                    red: 0x0b,
                    green: 0x3b,
                    blue: 0x5a,
                },
            )
            .is_err()
        {
            halt();
        }
        let _ = surface.fill_rectangle(
            0,
            0,
            framebuffer.width().min(96),
            framebuffer.height().min(12),
            Color {
                red: 0xff,
                green: 0xc8,
                blue: 0x57,
            },
        );
        #[cfg(feature = "gpu-benchmark")]
        if run_gpu_benchmark(handoff.evidence().entropy()).is_err() {
            halt();
        }
        #[cfg(feature = "gpu-benchmark")]
        let _ = surface.fill_rectangle(
            0,
            0,
            framebuffer.width().min(96),
            framebuffer.height().min(12),
            Color {
                red: 0x46,
                green: 0xe0,
                blue: 0x78,
            },
        );
        #[cfg(feature = "whp-gpu-benchmark")]
        unsafe {
            asm!("out dx, eax", in("dx") GPU_DOORBELL_PORT, in("eax") 2u32, options(nomem, nostack))
        };
    }
    halt()
}

#[cfg(all(not(feature = "fault-probe"), feature = "service-probe"))]
#[inline(never)]
fn run_service_probe(handoff: &BootHandoff, probe: impl FnOnce(&BootHandoff)) -> ! {
    probe(handoff);
    halt()
}

#[cfg(feature = "uefi-service-preemption-probe")]
fn embedded_service_root() -> Option<[u8; 64]> {
    let encoded = option_env!("MRML_SERVICE_ROOT_DIGEST_HEX")?.as_bytes();
    if encoded.len() != 128 {
        return None;
    }
    let mut digest = [0u8; 64];
    let mut index = 0usize;
    while index < digest.len() {
        digest[index] = hex_nibble(encoded[index * 2])?
            .checked_mul(16)?
            .checked_add(hex_nibble(encoded[index * 2 + 1])?)?;
        index += 1;
    }
    Some(digest)
}

#[cfg(feature = "application-probe")]
fn embedded_application_root() -> Option<[u8; 64]> {
    decode_digest(option_env!("MRML_APPLICATION_ROOT_DIGEST_HEX")?.as_bytes())
}

#[cfg(feature = "application-probe")]
fn decode_digest(encoded: &[u8]) -> Option<[u8; 64]> {
    if encoded.len() != 128 {
        return None;
    }
    let mut digest = [0u8; 64];
    let mut index = 0usize;
    while index < digest.len() {
        digest[index] = hex_nibble(encoded[index * 2])?
            .checked_mul(16)?
            .checked_add(hex_nibble(encoded[index * 2 + 1])?)?;
        index += 1;
    }
    Some(digest)
}

#[cfg(any(
    feature = "application-probe",
    feature = "uefi-service-preemption-probe"
))]
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(feature = "application-probe")]
fn embedded_application_minimum_version() -> Option<u64> {
    parse_nonzero_version(option_env!("MRML_APPLICATION_MIN_VERSION")?.as_bytes())
}

#[cfg(feature = "application-probe")]
fn parse_nonzero_version(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 20 {
        return None;
    }
    let mut value = 0u64;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((byte - b'0') as u64)?;
    }
    (value != 0).then_some(value)
}

#[cfg(feature = "uefi-service-preemption-probe")]
fn embedded_service_minimum_version() -> Option<u64> {
    let bytes = option_env!("MRML_SERVICE_MIN_VERSION")?.as_bytes();
    if bytes.is_empty() || bytes.len() > 20 {
        return None;
    }
    let mut value = 0u64;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((byte - b'0') as u64)?;
    }
    (value != 0).then_some(value)
}

#[cfg(feature = "uefi-service-preemption-probe")]
fn uefi_service_trace(stage: u8) {
    unsafe { asm!("out dx, al", in("dx") 0xe9u16, in("al") stage, options(nomem, nostack)) };
}

#[cfg(feature = "application-probe")]
unsafe fn enter_application_probe_context(context: &UserContext) -> ! {
    let transition_stack = unsafe {
        CpuDescriptorState::entry_stack_top_from(core::ptr::addr_of!(CPU0_DESCRIPTORS))
            .unwrap_or_else(|_| halt())
    };
    unsafe { enter_user_context_on_stack(context, transition_stack) }
}

#[cfg(feature = "application-probe")]
fn application_probe_trace(stage: u32) {
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") APPLICATION_PROBE_PORT,
            in("eax") 0xa000u32 | stage,
            options(nomem, nostack)
        )
    }
}

#[cfg(feature = "user-probe")]
unsafe fn enter_user_probe_context(context: &UserContext) {
    unsafe { enter_user_context(context) }
}

#[cfg(feature = "service-probe")]
unsafe fn enter_service_probe_context(context: &UserContext) -> ! {
    let transition_stack = unsafe {
        CpuDescriptorState::entry_stack_top_from(core::ptr::addr_of!(CPU0_DESCRIPTORS))
            .unwrap_or_else(|_| halt())
    };
    unsafe { enter_user_context_on_stack(context, transition_stack) }
}

#[cfg(feature = "service-probe")]
unsafe fn provision_service_resource(
    runtime: &mut TaskRuntime<SERVICE_TASK_CAPACITY, SERVICE_CAPABILITY_CAPACITY>,
    task: mrml_kernel::TaskId,
    peer: Option<mrml_kernel::TaskId>,
) -> ([Capability; 2], Option<[Capability; 3]>) {
    let resource_address = unsafe { core::ptr::addr_of_mut!(SERVICE_RESOURCE_PAGE.0) as u64 };
    let resource_physical = PhysAddr::new(0x00f0_1000).unwrap_or_else(|_| halt());
    let controller = runtime
        .capabilities_mut(task)
        .and_then(|space| {
            space
                .insert(
                    ObjectId(0x94),
                    Rights::MAP
                        .union(Rights::READ)
                        .union(Rights::WRITE)
                        .union(Rights::CONTROL),
                )
                .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
        })
        .unwrap_or_else(|_| halt());
    let write = runtime
        .capabilities_mut(task)
        .and_then(|space| {
            space
                .insert(
                    ObjectId(0x94),
                    Rights::MAP.union(Rights::READ).union(Rights::WRITE),
                )
                .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
        })
        .unwrap_or_else(|_| halt());
    let read = runtime
        .capabilities_mut(task)
        .and_then(|space| {
            space
                .insert(ObjectId(0x94), Rights::MAP.union(Rights::READ))
                .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
        })
        .unwrap_or_else(|_| halt());
    let peer_access = peer.map(|peer| {
        let local = runtime
            .capabilities_mut(peer)
            .and_then(|space| {
                space
                    .insert(
                        ObjectId(0x94),
                        Rights::MAP.union(Rights::READ).union(Rights::WRITE),
                    )
                    .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
            })
            .unwrap_or_else(|_| halt());
        let read = runtime
            .capabilities_mut(peer)
            .and_then(|space| {
                space
                    .insert(ObjectId(0x94), Rights::MAP.union(Rights::READ))
                    .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
            })
            .unwrap_or_else(|_| halt());
        let transfer = runtime
            .capabilities_mut(peer)
            .and_then(|space| {
                space
                    .insert(
                        ObjectId(0x94),
                        Rights::MAP
                            .union(Rights::READ)
                            .union(Rights::WRITE)
                            .union(Rights::DELEGATE),
                    )
                    .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
            })
            .unwrap_or_else(|_| halt());
        [local, read, transfer]
    });
    let vm_pointer = core::ptr::addr_of_mut!(SERVICE_RESOURCE_VM);
    if unsafe { (*vm_pointer).is_none() } {
        let mut table = VmTable::<1>::new();
        let vm = table.create(1).unwrap_or_else(|_| halt());
        unsafe {
            core::ptr::addr_of_mut!(SERVICE_RESOURCE_VM_TABLE).write(Some(table));
            vm_pointer.write(Some(vm));
        }
    }
    let vm = unsafe { (*vm_pointer).unwrap_or_else(|| halt()) };
    let memory_pointer = core::ptr::addr_of_mut!(SERVICE_RESOURCE_MEMORY);
    if unsafe { (*memory_pointer).is_none() } {
        unsafe { memory_pointer.write(Some(GuestMemory::new())) };
    }
    let memory = unsafe { (*memory_pointer).as_mut().unwrap_or_else(|| halt()) };
    let region = GuestRegion::new(SERVICE_RESOURCE_VIRTUAL, resource_physical, 1, true, false)
        .unwrap_or_else(|_| halt());
    let mapping = memory.map(region).unwrap_or_else(|_| halt());
    let resources_pointer = core::ptr::addr_of_mut!(SERVICE_RESOURCES);
    if unsafe { (*resources_pointer).is_none() } {
        unsafe { resources_pointer.write(Some(HostResourceTable::new(DirectHostResourceMemory))) };
    }
    let resources = unsafe { (*resources_pointer).as_mut().unwrap_or_else(|| halt()) };
    let handle = unsafe { resources.register(resource_address, mrml_kernel::PAGE_SIZE) }
        .unwrap_or_else(|_| halt());
    let bindings_pointer = core::ptr::addr_of_mut!(SERVICE_RESOURCE_BINDINGS);
    if unsafe { (*bindings_pointer).is_none() } {
        unsafe { bindings_pointer.write(Some(SharedMemoryBindings::new())) };
    }
    let bindings = unsafe { (*bindings_pointer).as_mut().unwrap_or_else(|| halt()) };
    let source_binding = bindings
        .bind(
            runtime.capabilities(task).unwrap_or_else(|_| halt()),
            write,
            memory,
            SharedEndpoint::for_task(vm, task, mapping, SharedAccess::ReadWrite),
            handle,
        )
        .unwrap_or_else(|_| halt());
    bindings
        .share(
            source_binding,
            runtime.capabilities(task).unwrap_or_else(|_| halt()),
            controller,
            SharedEndpointRequest::new(
                runtime.capabilities(task).unwrap_or_else(|_| halt()),
                read,
                memory,
                SharedEndpoint::for_task(vm, task, mapping, SharedAccess::ReadOnly),
            ),
        )
        .unwrap_or_else(|_| halt());
    if let (Some(peer), Some([peer_write, peer_read, _])) = (peer, peer_access) {
        let (_, peer_mapping) = bindings
            .share_alias(
                source_binding,
                runtime.capabilities(task).unwrap_or_else(|_| halt()),
                controller,
                runtime.capabilities(peer).unwrap_or_else(|_| halt()),
                peer_write,
                memory,
                vm,
                Some(peer),
                mapping,
                SERVICE_PEER_RESOURCE_VIRTUAL,
                SharedAccess::ReadWrite,
            )
            .unwrap_or_else(|_| halt());
        bindings
            .share(
                source_binding,
                runtime.capabilities(task).unwrap_or_else(|_| halt()),
                controller,
                SharedEndpointRequest::new(
                    runtime.capabilities(peer).unwrap_or_else(|_| halt()),
                    peer_read,
                    memory,
                    SharedEndpoint::for_task(vm, peer, peer_mapping, SharedAccess::ReadOnly),
                ),
            )
            .unwrap_or_else(|_| halt());
    }
    runtime
        .revoke_capability(task, controller)
        .unwrap_or_else(|_| halt());
    ([write, read], peer_access)
}

#[cfg(feature = "service-probe")]
unsafe fn service_resource_mapping(virtual_address: u64) -> Mapping {
    Mapping::new(
        VirtAddr::new(virtual_address).unwrap_or_else(|_| halt()),
        PhysAddr::new(0x00f0_1000).unwrap_or_else(|_| halt()),
        1,
        PagePermissions::USER_READ_WRITE,
    )
    .unwrap_or_else(|_| halt())
}

#[cfg(feature = "service-probe")]
unsafe fn retire_service_protocol_violation(violation: TaskProtocolViolation) -> ! {
    let runtime = unsafe {
        (*core::ptr::addr_of_mut!(SERVICE_RUNTIME))
            .as_mut()
            .unwrap_or_else(|| halt())
    };
    let current = runtime.current().unwrap_or_else(|| halt());
    if unsafe { has_pending_buffer(current) }
        || unsafe { pending_inline_wait_slot(current) }.is_some()
    {
        halt();
    }
    let supervisor = unsafe {
        (*core::ptr::addr_of_mut!(SERVICE_SUPERVISOR))
            .as_mut()
            .unwrap_or_else(|| halt())
    };
    let retired = supervisor
        .violate_current(runtime, violation)
        .unwrap_or_else(|_| halt());
    if retired.retirement.task != current
        || retired.retirement.violation != violation
        || runtime.context(current).is_ok()
    {
        halt();
    }
    unsafe { complete_service_cleanup(supervisor, retired.cleanup) };
    match retired.dispatch.user().map(|(task, _)| task) {
        Some(to) => {
            #[cfg(any(feature = "invalid-return-probe", feature = "buffer-drift-probe"))]
            {
                let ControlEvent::PeerDied(death) =
                    runtime.receive_control(to).unwrap_or_else(|_| halt())
                else {
                    halt()
                };
                if death.peer() != current
                    || death.reason() != PeerDeathReason::ProtocolViolation(violation)
                {
                    halt();
                }
                #[cfg(feature = "invalid-return-probe")]
                unsafe {
                    service_restart_stage(0x26)
                };
                #[cfg(feature = "buffer-drift-probe")]
                unsafe {
                    service_restart_stage(0x28)
                };
            }
            unsafe { enter_service_dispatch(runtime, to, retired.dispatch) }
        }
        None => {
            let _ = runtime
                .consume_idle_dispatch(retired.dispatch)
                .unwrap_or_else(|_| halt());
            halt()
        }
        _ => halt(),
    }
}

#[cfg(feature = "service-probe")]
unsafe fn complete_service_cleanup(
    supervisor: &mut ServiceSupervisor<SERVICE_TASK_CAPACITY>,
    ticket: mrml_kernel::ServiceCleanupTicket,
) {
    let root = ticket.context().page_table().get();
    #[cfg(any(feature = "block-service-probe", feature = "component-service-probe"))]
    if root == SERVICE_ROOT || root == SERVICE_B_ROOT {
        let resources = unsafe {
            (*core::ptr::addr_of_mut!(SERVICE_RESOURCES))
                .as_mut()
                .unwrap_or_else(|| halt())
        };
        let memory = unsafe {
            (*core::ptr::addr_of_mut!(SERVICE_RESOURCE_MEMORY))
                .as_mut()
                .unwrap_or_else(|| halt())
        };
        let bindings = unsafe {
            (*core::ptr::addr_of_mut!(SERVICE_RESOURCE_BINDINGS))
                .as_mut()
                .unwrap_or_else(|| halt())
        };
        let mut address_space = HostedServiceEraser;
        let mut revoker = HostedUnmappedResourceRevoker;
        let mut eraser = ServiceResourceEraser::new(
            &mut address_space,
            resources,
            &mut revoker,
            memory,
            bindings,
        );
        supervisor
            .complete_cleanup(ticket, &mut eraser)
            .unwrap_or_else(|_| halt());
        return;
    }
    #[cfg(any(feature = "block-service-probe", feature = "component-service-probe"))]
    let resource_virtual = if root == SERVICE_ROOT {
        Some(SERVICE_RESOURCE_VIRTUAL)
    } else if root == SERVICE_B_ROOT {
        Some(SERVICE_PEER_RESOURCE_VIRTUAL)
    } else {
        None
    };
    #[cfg(not(any(feature = "block-service-probe", feature = "component-service-probe")))]
    let resource_virtual = (root == SERVICE_ROOT).then_some(SERVICE_RESOURCE_VIRTUAL);
    let Some(resource_virtual) = resource_virtual else {
        supervisor
            .complete_cleanup(ticket, &mut HostedServiceEraser)
            .unwrap_or_else(|_| halt());
        return;
    };
    let mut active = unsafe { ActivePageTables::current() }.unwrap_or_else(|_| halt());
    let mut revoker = unsafe {
        ActiveServiceMappingRevoker::new(
            &mut active,
            PhysAddr::new(root).unwrap_or_else(|_| halt()),
            service_resource_mapping(resource_virtual),
        )
    }
    .unwrap_or_else(|_| halt());
    let resources = unsafe {
        (*core::ptr::addr_of_mut!(SERVICE_RESOURCES))
            .as_mut()
            .unwrap_or_else(|| halt())
    };
    let memory = unsafe {
        (*core::ptr::addr_of_mut!(SERVICE_RESOURCE_MEMORY))
            .as_mut()
            .unwrap_or_else(|| halt())
    };
    let bindings = unsafe {
        (*core::ptr::addr_of_mut!(SERVICE_RESOURCE_BINDINGS))
            .as_mut()
            .unwrap_or_else(|| halt())
    };
    let mut address_space = HostedServiceEraser;
    let mut eraser = ServiceResourceEraser::new(
        &mut address_space,
        resources,
        &mut revoker,
        memory,
        bindings,
    );
    supervisor
        .complete_cleanup(ticket, &mut eraser)
        .unwrap_or_else(|_| halt());
}

#[cfg(feature = "component-service-probe")]
unsafe fn release_component_service_accounting() {
    if unsafe { &*core::ptr::addr_of!(SERVICE_PENDING_BUFFERS) }
        .iter()
        .any(Option::is_some)
        || unsafe { &*core::ptr::addr_of!(SERVICE_PENDING_INLINE_WAITS) }
            .iter()
            .any(Option::is_some)
    {
        halt();
    }
    let runtime =
        unsafe { (*core::ptr::addr_of_mut!(SERVICE_RUNTIME)).take() }.unwrap_or_else(|| halt());
    let supervisor =
        unsafe { (*core::ptr::addr_of_mut!(SERVICE_SUPERVISOR)).take() }.unwrap_or_else(|| halt());
    let runtime_pages = runtime.committed_pages();
    let supervisor_pages = supervisor.committed_pages();
    let memory = unsafe {
        (*core::ptr::addr_of_mut!(COMPONENT_SERVICE_MEMORY))
            .as_mut()
            .unwrap_or_else(|| halt())
    };
    let authorities = unsafe {
        (*core::ptr::addr_of_mut!(COMPONENT_SERVICE_MEMORY_AUTHORITIES))
            .as_mut()
            .unwrap_or_else(|| halt())
    };
    let (pool, pool_capability) =
        unsafe { (*core::ptr::addr_of!(COMPONENT_SERVICE_MEMORY_POOL)).unwrap_or_else(|| halt()) };
    if !matches!(runtime.release(memory, authorities), Ok(pages) if pages == runtime_pages) {
        halt();
    }
    if !matches!(unsafe { supervisor.release(memory, authorities) }, Ok(pages) if pages == supervisor_pages)
    {
        halt();
    }
    if memory
        .usage(pool, pool_capability, authorities)
        .map(|usage| (usage.object_pages(), usage.active_mappings()))
        != Ok((0, 0))
    {
        halt();
    }
}

#[cfg(feature = "service-restart-request-probe")]
unsafe fn restart_sender_from_request(
    runtime: &mut TaskRuntime<SERVICE_TASK_CAPACITY, SERVICE_CAPABILITY_CAPACITY>,
    requester: mrml_kernel::TaskId,
    capability: Capability,
    service: ServiceId,
) -> Option<ServiceId> {
    let supervisor = unsafe {
        (*core::ptr::addr_of_mut!(SERVICE_SUPERVISOR))
            .as_mut()
            .unwrap_or_else(|| halt())
    };
    let mut context = UserContext::new(
        PhysAddr::new(SERVICE_B_ROOT).unwrap_or_else(|_| halt()),
        unsafe { hosted_service_entry() }
            .checked_add(0x200)
            .unwrap_or_else(|| halt()),
        SERVICE_STACK_TOP,
    )
    .unwrap_or_else(|_| halt());
    context.r12 = 2;
    let ids = unsafe {
        (*core::ptr::addr_of_mut!(SERVICE_IDS))
            .as_mut()
            .unwrap_or_else(|| halt())
    };
    if ids[1] != service {
        return None;
    }
    let plan = match supervisor.prepare_restart_at(
        service,
        runtime.capabilities(requester).unwrap_or_else(|_| halt()),
        capability,
        Priority::NORMAL,
        context,
        0,
    ) {
        Ok(plan) => plan,
        Err(
            mrml_kernel::ServiceError::InvalidService
            | mrml_kernel::ServiceError::StillRunning
            | mrml_kernel::ServiceError::RestartLimit
            | mrml_kernel::ServiceError::RestartBackoff { .. }
            | mrml_kernel::ServiceError::CleanupRequired
            | mrml_kernel::ServiceError::Unauthorized(_),
        ) => return None,
        Err(_) => halt(),
    };
    unsafe { service_restart_stage(0x24) };
    let replacement =
        match supervisor.commit_restart_with_task_for_requester(plan, requester, runtime) {
            Ok(replacement) => replacement,
            Err(
                mrml_kernel::ServiceError::InvalidService
                | mrml_kernel::ServiceError::StillRunning
                | mrml_kernel::ServiceError::RestartLimit
                | mrml_kernel::ServiceError::RestartBackoff { .. }
                | mrml_kernel::ServiceError::CleanupRequired
                | mrml_kernel::ServiceError::Runtime(mrml_kernel::TaskRuntimeError::Full)
                | mrml_kernel::ServiceError::Runtime(mrml_kernel::TaskRuntimeError::Ipc(_)),
            ) => return None,
            Err(_) => halt(),
        };
    let sender = replacement.task();
    let replacement = replacement.service();
    let endpoint = unsafe {
        (*core::ptr::addr_of!(SERVICE_ENDPOINT))
            .as_ref()
            .unwrap_or_else(|| halt())
    };
    let receiver_signal =
        unsafe { (*core::ptr::addr_of!(SERVICE_RECEIVER_SIGNAL)).unwrap_or_else(|| halt()) };
    let signal = runtime
        .capabilities_mut(sender)
        .unwrap_or_else(|_| halt())
        .insert(ObjectId(0x91), Rights::SIGNAL)
        .unwrap_or_else(|_| halt());
    let root = runtime
        .capabilities_mut(sender)
        .unwrap_or_else(|_| halt())
        .insert(ObjectId(0x92), Rights::CONTROL.union(Rights::DELEGATE))
        .unwrap_or_else(|_| halt());
    let setting = runtime
        .capabilities_mut(sender)
        .unwrap_or_else(|_| halt())
        .insert(
            ObjectId(0x93),
            Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE),
        )
        .unwrap_or_else(|_| halt());
    let supervision = runtime
        .capabilities_mut(sender)
        .unwrap_or_else(|_| halt())
        .insert(
            ObjectId(0xa1),
            Rights::READ.union(Rights::CONTROL).union(Rights::DELEGATE),
        )
        .unwrap_or_else(|_| halt());
    runtime
        .connect_control_peers(requester, sender, endpoint, receiver_signal, signal)
        .unwrap_or_else(|_| halt());
    let sender_context = runtime.context_mut(sender).unwrap_or_else(|_| halt());
    sender_context.r13 = signal.token();
    sender_context.r14 = requester.token();
    sender_context.r15 = root.token();
    sender_context.rbx = setting.token();
    sender_context.rbp = supervision.token();
    sender_context.r10 = replacement.token();
    ids[1] = replacement;
    Some(replacement)
}

#[cfg(feature = "service-probe")]
unsafe fn restart_service_pair(
    runtime: &mut TaskRuntime<SERVICE_TASK_CAPACITY, SERVICE_CAPABILITY_CAPACITY>,
    supervisor: &mut ServiceSupervisor<SERVICE_TASK_CAPACITY>,
    receiver_service: ServiceId,
) -> ! {
    let management = unsafe {
        (*core::ptr::addr_of!(SERVICE_MANAGEMENT))
            .as_ref()
            .unwrap_or_else(|| halt())
    };
    let controls = unsafe { (*core::ptr::addr_of!(SERVICE_CONTROLS)).unwrap_or_else(|| halt()) };
    let retired = unsafe { (*core::ptr::addr_of!(SERVICE_IDS)).unwrap_or_else(|| halt()) };
    let mut sender_context = UserContext::new(
        PhysAddr::new(SERVICE_B_ROOT).unwrap_or_else(|_| halt()),
        unsafe { hosted_service_entry() }
            .checked_add(0x200)
            .unwrap_or_else(|| halt()),
        SERVICE_STACK_TOP,
    )
    .unwrap_or_else(|_| halt());
    sender_context.r12 = 2;
    // Recovery has already created the receiver generation. Recreate the
    // sender, then explicitly yield to the receiver if the retained scheduler
    // cursor initially selects the sender. This preserves the proof that an
    // empty receive blocks before the replacement sender is allowed to run.
    let sender_service = supervisor
        .restart(
            retired[1],
            management,
            controls[1],
            runtime,
            Priority::NORMAL,
            sender_context,
        )
        .unwrap_or_else(|_| halt());
    unsafe { service_restart_stage(0x31) };
    if supervisor.state(receiver_service) != Ok(mrml_kernel::ServiceState::Running)
        || supervisor.pending_cleanup(receiver_service) != Ok(None)
    {
        halt();
    }
    unsafe { service_restart_stage(0x32) };
    let receiver = supervisor
        .task(receiver_service)
        .ok()
        .flatten()
        .unwrap_or_else(|| halt());
    let sender = supervisor
        .task(sender_service)
        .ok()
        .flatten()
        .unwrap_or_else(|| halt());
    unsafe { service_restart_stage(0x34) };
    let endpoint = unsafe {
        (*core::ptr::addr_of!(SERVICE_ENDPOINT))
            .as_ref()
            .unwrap_or_else(|| halt())
    };
    unsafe { service_restart_stage(0x35) };
    let receiver_capability = runtime
        .capabilities_mut(receiver)
        .and_then(|space| {
            space
                .insert(ObjectId(0x91), Rights::SIGNAL)
                .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
        })
        .unwrap_or_else(|_| halt());
    let (resource_capabilities, _) = unsafe { provision_service_resource(runtime, receiver, None) };
    let supervision_capability = runtime
        .capabilities_mut(sender)
        .and_then(|space| {
            space
                .insert(
                    ObjectId(0xa1),
                    Rights::READ.union(Rights::CONTROL).union(Rights::DELEGATE),
                )
                .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
        })
        .unwrap_or_else(|_| halt());
    let capability = runtime
        .capabilities_mut(sender)
        .and_then(|space| {
            space
                .insert(ObjectId(0x91), Rights::SIGNAL)
                .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
        })
        .unwrap_or_else(|_| halt());
    let root_capability = runtime
        .capabilities_mut(sender)
        .and_then(|space| {
            space
                .insert(ObjectId(0x92), Rights::CONTROL.union(Rights::DELEGATE))
                .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
        })
        .unwrap_or_else(|_| halt());
    let setting_capability = runtime
        .capabilities_mut(sender)
        .and_then(|space| {
            space
                .insert(
                    ObjectId(0x93),
                    Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE),
                )
                .map_err(|_| mrml_kernel::TaskRuntimeError::IntegrityFailure)
        })
        .unwrap_or_else(|_| halt());
    runtime
        .connect_control_peers(receiver, sender, endpoint, receiver_capability, capability)
        .unwrap_or_else(|_| halt());
    unsafe { service_restart_stage(0x36) };
    let receiver_context = runtime.context_mut(receiver).unwrap_or_else(|_| halt());
    receiver_context.r13 = receiver_capability.token();
    receiver_context.r14 = sender.token();
    receiver_context.r15 = resource_capabilities[0].token();
    receiver_context.rbx = resource_capabilities[1].token();
    let sender_context = runtime.context_mut(sender).unwrap_or_else(|_| halt());
    sender_context.r13 = capability.token();
    sender_context.r14 = receiver.token();
    sender_context.r15 = root_capability.token();
    sender_context.rbx = setting_capability.token();
    sender_context.rbp = supervision_capability.token();
    sender_context.r10 = sender_service.token();
    unsafe { service_restart_stage(0x37) };
    match runtime.start() {
        ScheduleOutcome::Switch { from: None, to } if to == receiver => {}
        ScheduleOutcome::Switch { from: None, to } if to == sender => {
            if !matches!(runtime.yield_current(), Ok(ScheduleOutcome::Switch { to, .. }) if to == receiver)
            {
                halt();
            }
        }
        _ => halt(),
    }
    unsafe {
        let manager_service = (*core::ptr::addr_of!(SERVICE_IDS))
            .map(|ids| ids[2])
            .unwrap_or(receiver_service);
        core::ptr::addr_of_mut!(SERVICE_IDS).write(Some([
            receiver_service,
            sender_service,
            manager_service,
        ]));
        core::ptr::addr_of_mut!(SERVICE_RESTARTED).write(true);
    }
    unsafe { service_restart_stage(0x33) };
    unsafe { enter_service_task(runtime, receiver) }
}

#[cfg(feature = "service-probe")]
unsafe fn service_restart_stage(stage: u32) {
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") SERVICE_PROBE_PORT,
            in("eax") stage,
            options(nomem, nostack)
        )
    }
}

#[cfg(feature = "service-probe")]
unsafe fn verify_restart_budget_exhausted(
    runtime: &mut TaskRuntime<SERVICE_TASK_CAPACITY, SERVICE_CAPABILITY_CAPACITY>,
    supervisor: &mut ServiceSupervisor<SERVICE_TASK_CAPACITY>,
) {
    let management = unsafe {
        (*core::ptr::addr_of!(SERVICE_MANAGEMENT))
            .as_ref()
            .unwrap_or_else(|| halt())
    };
    let controls = unsafe { (*core::ptr::addr_of!(SERVICE_CONTROLS)).unwrap_or_else(|| halt()) };
    let services = unsafe { (*core::ptr::addr_of!(SERVICE_IDS)).unwrap_or_else(|| halt()) };
    let context = UserContext::new(
        PhysAddr::new(SERVICE_ROOT).unwrap_or_else(|_| halt()),
        unsafe { hosted_service_entry() },
        SERVICE_STACK_TOP,
    )
    .unwrap_or_else(|_| halt());
    if supervisor.restart(
        services[0],
        management,
        controls[0],
        runtime,
        Priority::NORMAL,
        context,
    ) != Err(ServiceError::RestartLimit)
    {
        halt();
    }
}

#[cfg(feature = "service-probe")]
unsafe fn hosted_service_entry() -> u64 {
    let entry = unsafe { core::ptr::read_volatile((SERVICE_SHARED_PHYSICAL + 8) as *const u64) };
    let image_base = 0x0000_0001_4000_0000u64;
    let image_end = image_base
        .checked_add(u64::from(mrml_kernel::MAX_SERVICE_IMAGE_BYTES))
        .unwrap_or_else(|| halt());
    if !(image_base..image_end).contains(&entry) || entry.checked_add(0x200).is_none() {
        halt();
    }
    entry
}

#[cfg(feature = "component-service-probe")]
unsafe fn hosted_provider_entry() -> u64 {
    let entry = unsafe { core::ptr::read_volatile((SERVICE_SHARED_PHYSICAL + 16) as *const u64) };
    let image_base = 0x0000_0001_4000_0000u64;
    let image_end = image_base
        .checked_add(u64::from(mrml_kernel::MAX_SERVICE_IMAGE_BYTES))
        .unwrap_or_else(|| halt());
    if !(image_base..image_end).contains(&entry) {
        halt();
    }
    entry
}

#[cfg(feature = "service-preemption-probe")]
unsafe fn enter_service_preemption_context(context: &UserContext) -> ! {
    let transition_stack = unsafe {
        CpuDescriptorState::entry_stack_top_from(core::ptr::addr_of!(CPU0_DESCRIPTORS))
            .unwrap_or_else(|_| halt())
    };
    unsafe { enter_user_context_on_stack(context, transition_stack) }
}

#[cfg(feature = "service-probe")]
unsafe fn service_user_range_is_valid(
    root: PhysAddr,
    address: u64,
    length: usize,
    maximum_length: usize,
    access: UserBufferAccess,
) -> bool {
    let active = unsafe { ActivePageTables::current() }.unwrap_or_else(|_| halt());
    if active.root() != root {
        halt();
    }
    active
        .resolve_user_buffer(root, address, length, maximum_length, access)
        .is_ok()
}

#[cfg(feature = "service-probe")]
unsafe fn try_copy_from_active_user(
    root: PhysAddr,
    task: mrml_kernel::TaskId,
    address: u64,
    output: &mut [u8],
) -> bool {
    let active = unsafe { ActivePageTables::current() }.unwrap_or_else(|_| halt());
    let mut user = ActiveTaskUserCopy::new(&active, root, task, DirectActiveUserMemory);
    match user.validate(
        task,
        address,
        output.len(),
        mrml_kernel::SharedBufferUserAccess::Read,
    ) {
        Ok(()) => {}
        Err(ActiveTaskUserCopyError::Buffer(_)) => return false,
        Err(_) => halt(),
    }
    user.read(task, address, output).unwrap_or_else(|_| halt());
    true
}

#[cfg(feature = "service-probe")]
unsafe fn copy_to_active_user(
    root: PhysAddr,
    task: mrml_kernel::TaskId,
    address: u64,
    input: &[u8],
) {
    if input.is_empty() {
        return;
    }
    let active = unsafe { ActivePageTables::current() }.unwrap_or_else(|_| halt());
    let mut user = ActiveTaskUserCopy::new(&active, root, task, DirectActiveUserMemory);
    user.validate(
        task,
        address,
        input.len(),
        mrml_kernel::SharedBufferUserAccess::Write,
    )
    .unwrap_or_else(|_| halt());
    user.write(task, address, input).unwrap_or_else(|_| halt());
}

#[cfg(feature = "service-probe")]
unsafe fn active_receive_is_valid(root: PhysAddr, pending: PendingBufferReceive) -> bool {
    if root != pending.page_table || pending.payload_capacity == 0 {
        return false;
    }
    if pending
        .wait
        .is_some_and(|wait| wait.task() != pending.task || wait.is_control())
    {
        return false;
    }
    if !unsafe {
        service_user_range_is_valid(
            root,
            pending.payload_address,
            pending.payload_capacity,
            MAX_INLINE_PAYLOAD,
            UserBufferAccess::Write,
        )
    } {
        return false;
    }
    if pending.capability_capacity == 0 {
        return pending.capabilities_address == 0;
    }
    let Some(length) = pending
        .capability_capacity
        .checked_mul(core::mem::size_of::<u64>())
    else {
        return false;
    };
    if !unsafe {
        service_user_range_is_valid(
            root,
            pending.capabilities_address,
            length,
            MAX_CAPABILITIES * core::mem::size_of::<u64>(),
            UserBufferAccess::Write,
        )
    } {
        return false;
    }
    let (Ok(payload_length), Ok(capabilities_length)) = (
        u64::try_from(pending.payload_capacity),
        u64::try_from(length),
    ) else {
        return false;
    };
    let (Some(payload_end), Some(capabilities_end)) = (
        pending.payload_address.checked_add(payload_length),
        pending
            .capabilities_address
            .checked_add(capabilities_length),
    ) else {
        return false;
    };
    if pending.payload_address < capabilities_end && pending.capabilities_address < payload_end {
        return false;
    }
    true
}

#[cfg(feature = "service-probe")]
unsafe fn write_buffer_current(
    root: PhysAddr,
    pending: PendingBufferReceive,
    message: &mrml_kernel::Message,
) -> mrml_kernel::BufferCompletion {
    let completion = mrml_kernel::BufferCompletion::new(
        message.payload().len(),
        message.capability_count(),
        pending.payload_capacity,
        pending.capability_capacity,
    )
    .unwrap_or_else(|_| halt());
    if !unsafe { active_receive_is_valid(root, pending) } {
        halt();
    }
    unsafe {
        copy_to_active_user(
            root,
            pending.task,
            pending.payload_address,
            message.payload(),
        )
    };
    if message.capability_count() != 0 {
        let mut encoded = [0u8; MAX_CAPABILITIES * core::mem::size_of::<u64>()];
        for (index, capability) in message.capabilities().enumerate() {
            let start = index * core::mem::size_of::<u64>();
            encoded[start..start + 8].copy_from_slice(&capability.token().to_le_bytes());
        }
        let encoded_length = message
            .capability_count()
            .checked_mul(core::mem::size_of::<u64>())
            .unwrap_or_else(|| halt());
        unsafe {
            copy_to_active_user(
                root,
                pending.task,
                pending.capabilities_address,
                &encoded[..encoded_length],
            )
        };
    }
    completion
}

#[cfg(feature = "service-probe")]
unsafe fn complete_buffer_current(
    root: PhysAddr,
    pending: PendingBufferReceive,
    message: &mrml_kernel::Message,
    frame: &mut UserCallFrame,
) {
    let completion = unsafe { write_buffer_current(root, pending, message) };
    frame.complete_buffer(completion);
}

#[cfg(feature = "service-probe")]
unsafe fn complete_pending_buffer(
    runtime: &mut TaskRuntime<SERVICE_TASK_CAPACITY, SERVICE_CAPABILITY_CAPACITY>,
    task: mrml_kernel::TaskId,
    dispatch: Option<&mrml_kernel::TaskTerminationDispatch>,
) {
    let Some((pending_slot, pending)) = (unsafe { prepare_pending_buffer(task) }) else {
        return;
    };
    let previous = unsafe { ActivePageTables::current() }.unwrap_or_else(|_| halt());
    let target = runtime
        .context(task)
        .unwrap_or_else(|_| halt())
        .page_table();
    unsafe { asm!("mov cr3, {}", in(reg) target.get(), options(nostack, preserves_flags)) };
    if !unsafe { active_receive_is_valid(target, pending) } {
        unsafe {
            asm!(
                "mov cr3, {}",
                in(reg) previous.root().get(),
                options(nostack, preserves_flags)
            )
        }
        if runtime.current() != Some(task) {
            halt();
        }
        unsafe { commit_pending_buffer_take(pending_slot, pending) };
        unsafe {
            retire_service_protocol_violation(TaskProtocolViolation::BufferedReceiveMappingDrift)
        }
    }
    unsafe { commit_pending_buffer_take(pending_slot, pending) };
    let message = match runtime.receive_ipc_bounded(
        task,
        pending.payload_capacity,
        pending.capability_capacity,
    ) {
        Ok(message) => message,
        Err(mrml_kernel::TaskRuntimeError::ReceiveCapacity) => {
            unsafe {
                asm!(
                    "mov cr3, {}",
                    in(reg) previous.root().get(),
                    options(nostack, preserves_flags)
                )
            }
            match dispatch {
                Some(dispatch) => dispatch.user_context_mut(runtime, task),
                None => runtime
                    .context_mut(task)
                    .map_err(mrml_kernel::TaskTerminationDispatchError::Runtime),
            }
            .unwrap_or_else(|_| halt())
            .complete_error();
            return;
        }
        Err(_) => halt(),
    };
    let completion = unsafe { write_buffer_current(target, pending, &message) };
    unsafe {
        asm!(
            "mov cr3, {}",
            in(reg) previous.root().get(),
            options(nostack, preserves_flags)
        )
    };
    match dispatch {
        Some(dispatch) => dispatch.user_context_mut(runtime, task),
        None => runtime
            .context_mut(task)
            .map_err(mrml_kernel::TaskTerminationDispatchError::Runtime),
    }
    .unwrap_or_else(|_| halt())
    .complete_buffer(completion);
}

#[cfg(feature = "service-probe")]
unsafe fn pending_buffer_slot(task: mrml_kernel::TaskId) -> Option<usize> {
    let buffers = unsafe { &*core::ptr::addr_of!(SERVICE_PENDING_BUFFERS) };
    let mut found = None;
    for (index, pending) in buffers.iter().enumerate() {
        if pending.is_some_and(|pending| pending.task == task) {
            if found.replace(index).is_some() {
                halt();
            }
        }
    }
    found
}

#[cfg(feature = "service-probe")]
unsafe fn has_pending_buffer(task: mrml_kernel::TaskId) -> bool {
    unsafe { pending_buffer_slot(task) }.is_some()
}

#[cfg(feature = "service-probe")]
unsafe fn pending_inline_wait_slot(task: mrml_kernel::TaskId) -> Option<usize> {
    let waits = unsafe { &*core::ptr::addr_of!(SERVICE_PENDING_INLINE_WAITS) };
    let mut found = None;
    for (index, wait) in waits.iter().enumerate() {
        if wait.is_some_and(|wait| wait.task() == task) && found.replace(index).is_some() {
            halt();
        }
    }
    found
}

#[cfg(feature = "deadline-receive-probe")]
unsafe fn deadline_cancellation_escrow() -> &'static mut mrml_kernel::DeadlineReceiveCancellationEscrow<
    SERVICE_TASK_CAPACITY,
> {
    unsafe { &mut *core::ptr::addr_of_mut!(SERVICE_DEADLINE_CANCELLATIONS) }
        .as_mut()
        .unwrap_or_else(|| halt())
}

#[cfg(feature = "deadline-receive-probe")]
unsafe fn deadline_deliver_ipc(
    runtime: &mut TaskRuntime<SERVICE_TASK_CAPACITY, SERVICE_CAPABILITY_CAPACITY>,
    sender: mrml_kernel::TaskId,
    receiver: mrml_kernel::TaskId,
    endpoint: &mut Endpoint,
    endpoint_capability: Capability,
    payload: &[u8],
    requested: &[(Capability, Rights)],
) -> Result<u64, mrml_kernel::DeadlineReceiveSyscallError> {
    let executor = unsafe { &mut *core::ptr::addr_of_mut!(SERVICE_DEADLINE_RECEIVES) }
        .as_mut()
        .unwrap_or_else(|| halt());
    let escrow = unsafe { deadline_cancellation_escrow() };
    executor.validate_escrow(escrow)?;
    let cancellation = if executor.has_pending(receiver)? {
        Some(escrow.get(receiver)?)
    } else {
        None
    };
    let sequence = executor.deliver(
        runtime,
        sender,
        receiver,
        endpoint,
        endpoint_capability,
        payload,
        requested,
    )?;
    if let Some(cancellation) = cancellation {
        escrow.retire(cancellation)?;
    }
    executor.validate_escrow(escrow)?;
    Ok(sequence)
}

#[cfg(all(feature = "service-probe", not(feature = "deadline-receive-probe")))]
unsafe fn insert_pending_inline_wait(wait: mrml_kernel::BlockedReceive) {
    if wait.is_control()
        || unsafe { pending_inline_wait_slot(wait.task()) }.is_some()
        || unsafe { pending_buffer_slot(wait.task()) }.is_some()
    {
        halt();
    }
    let waits = unsafe { &mut *core::ptr::addr_of_mut!(SERVICE_PENDING_INLINE_WAITS) };
    let slot = waits
        .iter()
        .position(Option::is_none)
        .unwrap_or_else(|| halt());
    waits[slot] = Some(wait);
}

#[cfg(all(feature = "service-probe", not(feature = "deadline-receive-probe")))]
unsafe fn commit_pending_inline_wait(task: mrml_kernel::TaskId) {
    let slot = unsafe { pending_inline_wait_slot(task) }.unwrap_or_else(|| halt());
    let waits = unsafe { &mut *core::ptr::addr_of_mut!(SERVICE_PENDING_INLINE_WAITS) };
    let wait = waits[slot].take().unwrap_or_else(|| halt());
    if wait.task() != task || wait.is_control() {
        halt();
    }
}

#[cfg(feature = "service-probe")]
unsafe fn prepare_pending_buffer(
    task: mrml_kernel::TaskId,
) -> Option<(usize, PendingBufferReceive)> {
    let index = unsafe { pending_buffer_slot(task) }?;
    let buffers = unsafe { &*core::ptr::addr_of!(SERVICE_PENDING_BUFFERS) };
    Some((index, buffers[index].unwrap_or_else(|| halt())))
}

#[cfg(feature = "service-probe")]
unsafe fn commit_pending_buffer_take(slot: usize, expected: PendingBufferReceive) {
    let buffers = unsafe { &mut *core::ptr::addr_of_mut!(SERVICE_PENDING_BUFFERS) };
    if buffers.get(slot).copied().flatten() != Some(expected) {
        halt();
    }
    buffers[slot] = None;
}

#[cfg(feature = "service-probe")]
unsafe fn pending_buffer_insert_slot(task: mrml_kernel::TaskId) -> usize {
    if unsafe { pending_buffer_slot(task) }.is_some()
        || unsafe { pending_inline_wait_slot(task) }.is_some()
    {
        halt();
    }
    let buffers = unsafe { &*core::ptr::addr_of!(SERVICE_PENDING_BUFFERS) };
    buffers
        .iter()
        .position(Option::is_none)
        .unwrap_or_else(|| halt())
}

#[cfg(feature = "service-probe")]
unsafe fn insert_pending_buffer(slot: usize, pending: PendingBufferReceive) {
    let buffers = unsafe { &mut *core::ptr::addr_of_mut!(SERVICE_PENDING_BUFFERS) };
    if slot >= buffers.len()
        || buffers[slot].is_some()
        || pending.wait.is_none()
        || buffers
            .iter()
            .flatten()
            .any(|existing| existing.task == pending.task)
    {
        halt();
    }
    buffers[slot] = Some(pending);
}

#[cfg(feature = "buffer-drift-probe")]
unsafe fn arm_buffer_drift_probe() {
    if unsafe { *core::ptr::addr_of!(BUFFER_DRIFT_ARMED) } {
        return;
    }
    let buffers = unsafe { &*core::ptr::addr_of!(SERVICE_PENDING_BUFFERS) };
    let mut pending = buffers.iter().flatten().copied();
    let Some(target) = pending.next() else {
        return;
    };
    if pending.next().is_some() {
        halt();
    }
    let page = target.payload_address & !(mrml_kernel::PAGE_SIZE - 1);
    let mut active = unsafe { ActivePageTables::current() }.unwrap_or_else(|_| halt());
    if active.root() != target.page_table {
        halt();
    }
    let virtual_address = VirtAddr::new(page).unwrap_or_else(|_| halt());
    let leaf = active
        .leaf(virtual_address)
        .ok()
        .flatten()
        .unwrap_or_else(|| halt());
    if !leaf.user() || !leaf.writable() || leaf.executable() || leaf.device_pat_index_three() {
        halt();
    }
    let mapping = Mapping::new(
        virtual_address,
        leaf.physical(),
        1,
        PagePermissions::USER_READ_WRITE,
    )
    .unwrap_or_else(|_| halt());
    unsafe { active.unmap_exact(mapping) }.unwrap_or_else(|_| halt());
    unsafe { core::ptr::addr_of_mut!(BUFFER_DRIFT_ARMED).write(true) };
}

#[cfg(feature = "service-probe")]
unsafe fn enter_service_task(
    runtime: &mut TaskRuntime<SERVICE_TASK_CAPACITY, SERVICE_CAPABILITY_CAPACITY>,
    task: mrml_kernel::TaskId,
) -> ! {
    #[cfg(feature = "buffer-drift-probe")]
    unsafe {
        arm_buffer_drift_probe()
    };
    unsafe { complete_pending_buffer(runtime, task, None) };
    let context = runtime
        .context(task)
        .map(|context| context as *const UserContext)
        .unwrap_or_else(|_| halt());
    unsafe { enter_service_probe_context(&*context) }
}

#[cfg(feature = "service-probe")]
unsafe fn enter_service_dispatch(
    runtime: &mut TaskRuntime<SERVICE_TASK_CAPACITY, SERVICE_CAPABILITY_CAPACITY>,
    task: mrml_kernel::TaskId,
    mut dispatch: mrml_kernel::TaskTerminationDispatch,
) -> ! {
    #[cfg(feature = "buffer-drift-probe")]
    unsafe {
        arm_buffer_drift_probe()
    };
    unsafe { complete_pending_buffer(runtime, task, Some(&dispatch)) };
    dispatch
        .refresh_from_runtime(runtime)
        .unwrap_or_else(|_| halt());
    if dispatch.user().map(|(selected, _)| selected) != Some(task) {
        halt();
    }
    let transition_stack = unsafe {
        CpuDescriptorState::entry_stack_top_from(core::ptr::addr_of!(CPU0_DESCRIPTORS))
            .unwrap_or_else(|_| halt())
    };
    let _ = unsafe { dispatch.enter_user_on_stack(runtime, transition_stack) }
        .unwrap_or_else(|_| halt());
    halt()
}

#[cfg(all(not(feature = "fault-probe"), feature = "gpu-benchmark"))]
fn run_gpu_benchmark(entropy: &[u8; 32]) -> Result<(), ()> {
    let identity = GpuQueueIdentity::from_boot_entropy(entropy).map_err(|_| ())?;
    let mut sender = GpuQueueSender::new(identity.session(), identity.key()).map_err(|_| ())?;
    let mut command = [0u8; GPU_QUEUE_MESSAGE_BYTES];
    sender
        .encode(
            1,
            ResourceCommand::BenchmarkAdd {
                elements: GPU_BENCHMARK_ELEMENTS,
                iterations: GPU_BENCHMARK_ITERATIONS,
            },
            &mut command,
        )
        .map_err(|_| ())?;
    let command_indices = unsafe { &*(GPU_COMMAND_BASE as *const GpuSharedRingIndices) };
    let command_slots = unsafe {
        &mut *((GPU_COMMAND_BASE + core::mem::size_of::<GpuSharedRingIndices>())
            as *mut [[u8; GPU_QUEUE_MESSAGE_BYTES]; 1])
    };
    let mut publisher = GpuGuestCommandPublisher::<1>::new().map_err(|_| ())?;
    publisher
        .publish(command_indices, command_slots, &command)
        .map_err(|_| ())?;
    unsafe {
        asm!("out dx, eax", in("dx") GPU_DOORBELL_PORT, in("eax") 1u32, options(nomem, nostack))
    };

    let published = GPU_COMPLETION_BASE as *const u64;
    while unsafe { published.read_volatile() } != 1 {
        core::hint::spin_loop();
    }
    let slot = (GPU_COMPLETION_BASE + core::mem::size_of::<GpuSharedRingIndices>()) as *const u8;
    let mut completion = [0u8; GPU_QUEUE_MESSAGE_BYTES];
    for (index, byte) in completion.iter_mut().enumerate() {
        *byte = unsafe { slot.add(index).read_volatile() };
    }
    let mut receiver =
        GpuResourceResponseReceiver::new(identity.session(), identity.key()).map_err(|_| ())?;
    match receiver.decode(&completion).map_err(|_| ())? {
        GpuResourceResponse::BenchmarkComplete {
            request_id: 1,
            elapsed_ns,
        } if elapsed_ns != 0 => Ok(()),
        _ => Err(()),
    }
}

#[cfg(all(not(feature = "fault-probe"), feature = "production-policy"))]
fn embedded_minimum_version() -> Option<u64> {
    let bytes = option_env!("MRML_KERNEL_MIN_VERSION")?.as_bytes();
    if bytes.is_empty() || bytes.len() > 20 {
        return None;
    }
    let mut value = 0u64;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((byte - b'0') as u64)?;
    }
    (value != 0).then_some(value)
}

unsafe fn install_descriptor_tables(kernel_stack: u64, double_fault_stack: u64) {
    let state = unsafe {
        core::ptr::addr_of_mut!(CPU0_DESCRIPTORS)
            .as_mut()
            .unwrap_or_else(|| halt())
    };
    unsafe { install_descriptor_state(state, kernel_stack, double_fault_stack) };
}

unsafe fn install_descriptor_state(
    state: &mut CpuDescriptorState,
    kernel_stack: u64,
    double_fault_stack: u64,
) {
    let fallback = mrml_exception_fail_stop as *const () as usize as u64;
    let handlers = unsafe { &mrml_exception_table };
    if unsafe { state.install(kernel_stack, double_fault_stack, handlers, fallback) }.is_err() {
        halt();
    }
    #[cfg(any(
        feature = "application-probe",
        feature = "user-probe",
        feature = "service-probe",
        feature = "smp-service-migration-probe"
    ))]
    if unsafe { state.install_user_call(mrml_user_call as *const () as usize as u64) }.is_err() {
        halt();
    }
    #[cfg(any(
        feature = "timer-probe",
        feature = "deadline-receive-probe",
        feature = "preemption-probe",
        feature = "service-preemption-probe",
        feature = "smp-scheduler-probe",
        feature = "smp-periodic-balance-probe"
    ))]
    if unsafe {
        state.install_external(
            TIMER_VECTOR,
            mrml_timer_interrupt as *const () as usize as u64,
        )
    }
    .is_err()
    {
        halt();
    }
    #[cfg(feature = "smp-ipi-probe")]
    if unsafe {
        state.install_external(
            RESCHEDULE_VECTOR,
            mrml_reschedule_interrupt as *const () as usize as u64,
        )
    }
    .is_err()
    {
        halt();
    }
    #[cfg(any(
        feature = "block-guest-driver-probe",
        feature = "pci-configuration-probe"
    ))]
    if unsafe {
        state.install_external(
            BLOCK_VECTOR,
            mrml_block_interrupt as *const () as usize as u64,
        )
    }
    .is_err()
    {
        halt();
    }
}

fn halt() -> ! {
    loop {
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}
