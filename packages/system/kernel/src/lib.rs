#![no_std]

//! Security primitives shared by the MRML microkernel and its host VMMs.
//! This crate deliberately contains policy data structures, not privileged
//! machine code. Architecture and hypervisor implementations sit behind these
//! narrow types so their unsafe boundaries can be reviewed independently.

pub mod arch;
mod artifact;
mod boot;
mod boot_recovery;
mod boot_recovery_syscall;
mod build_receipt;
mod capability;
mod component_memory;
mod cpu_resource;
mod early;
mod framebuffer;
mod grant;
mod handoff;
mod host_resource;
mod ipc;
mod isolation;
mod memory;
mod memory_resource;
mod pe;
mod platform;
mod policy;
mod protected_channel;
mod protected_execution;
mod protected_monitor;
mod scheduler;
mod service_lifecycle;
mod shared_buffer_syscall;
mod shared_memory;
mod syscall;
mod task_runtime;
mod virtual_block;
mod virtual_gpu;
mod virtual_pci;
mod vm;
mod vm_dispatch;
mod vm_interrupt;

pub use artifact::{
    ArtifactError, ArtifactKind, BOOTSTRAP_STATE_BYTES, BootstrapState, ExecutableArtifactError,
    MAX_CUDA_KERNEL_BUNDLE_BYTES, MAX_KERNEL_IMAGE_BYTES, MAX_LAUNCH_POLICY_BYTES,
    MAX_SERVICE_IMAGE_BYTES, MAX_VM_IMAGE_BYTES, MonotonicStateStore, PendingBootRelease,
    RELEASE_MANIFEST_BYTES, ReleaseManifest, SIGNED_ARTIFACT_HEADER_BYTES,
    SIGNED_ARTIFACT_OVERHEAD_BYTES, SignedArtifact, TrustRoot, VerifiedArtifact,
    VerifiedExecutable, VerifiedRelease, artifact_statement, executable_image_limit,
};
pub use boot::{BootEvidence, BootPolicy, BootValidationError, ValidatedBoot};
pub use boot_recovery::{BootRecoveryDelivery, BootRecoveryDeliveryError};
pub use boot_recovery_syscall::{
    BOOT_RECOVERY_SYSCALL_OPERATION, BootRecoverySyscallError, BootRecoverySyscallExecutor,
    BootRecoverySyscallRequest,
};
pub use build_receipt::{
    BUILD_RECEIPT_MAX_BYTES, BuildInputIdentity, BuildReceipt, BuildReceiptError,
};
pub use capability::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};
pub use component_memory::{
    AccountedComponentImage, ActiveMicrovmGuestRam, ComponentExecutablePages,
    ComponentImageAccountingError, ComponentImagePageClass, ComponentImagePagePlan,
    ComponentImageReleaseSummary, MAX_COMPONENT_IMAGE_REGIONS, MicrovmControlMemory,
    MicrovmGuestRam, MicrovmGuestRamError, MicrovmPageProjection, MicrovmPageProjectionKind,
    PreparedMicrovmGuestRam, account_component_executable, component_image_page_plan,
    prepare_microvm_guest_ram, release_component_image, release_microvm_control_memory,
    release_microvm_guest_ram, reserve_component_executable_mapping, reserve_component_image,
    reserve_microvm_control_memory, reserve_microvm_guest_ram, reserve_microvm_page_projection,
};
pub use cpu_resource::{
    CpuBudgetId, CpuBudgetSpec, CpuBudgetTable, CpuBudgetUsage, CpuResourceError,
    CpuRuntimeReconciliation, CpuRuntimeSlice, VcpuReservationId,
};
pub use early::{EarlyKernelContext, EarlyKernelError};
pub use framebuffer::{Color, FramebufferError, FramebufferInfo, FramebufferSurface, PixelFormat};
pub use grant::{DirectoryGrant, GrantError, GrantMode, MAX_HOST_PATH};
pub use handoff::{
    BootHandoff, HANDOFF_HEADER_BYTES, HANDOFF_RECOVERY_STATE_BYTES, HANDOFF_REGION_BYTES,
    HANDOFF_SERVICE_BYTES, HandoffError, MAX_HANDOFF_BYTES, MAX_HANDOFF_MADT_BYTES,
    MAX_HANDOFF_REGIONS, RecoveryStateMetadata, ServiceLaunch, encode_handoff,
    encode_handoff_with_madt, encode_handoff_with_recovery, encode_handoff_with_smp,
    encode_handoff_with_smp_and_service, encode_handoff_with_smp_service_and_recovery,
};
pub use host_resource::{
    DirectHostResourceError, DirectHostResourceMemory, HostResourceIoError, HostResourceMemory,
    HostResourceRetireError, HostResourceTable, HostResourceTableError,
};
pub use ipc::{
    AuthorizedIpcCapability, AuthorizedSharedIpcBuffer, Endpoint, IpcError, IpcSharedBufferBackend,
    IpcSharedBufferError, IpcSharedBufferIoError, MAX_CAPABILITIES, MAX_INLINE_PAYLOAD,
    MAX_WIRE_MESSAGE, Message, Receiver, WIRE_HEADER_LENGTH,
};
pub use isolation::{
    ComponentServiceArtifactError, ComponentServiceHandoffError, ComponentServiceLaunchError,
    HostSubstrateReason,
    IsolationAdmissionTable, IsolationBackendFailure, IsolationLaunchError,
    IsolationLaunchEvidence, IsolationLaunchRequest, IsolationMode, IsolationPlacement,
    IsolationServiceBackend, IsolationServiceRouteError, IsolationServiceSpec,
    IsolationServiceSpecError, IsolationUnavailableReason, IsolationVcpuReservationError,
    PreparedComponentServiceLaunch, PreparedComponentServiceRouteError, PreparedIsolationLaunch,
    PreparedIsolationServiceRoute, ReservedIsolationVcpus, RoutedIsolationService,
    RunningIsolationDomain, TotalMicrovmClass, TotalMicrovmReport, UnavailableIsolationDomain,
    bind_component_service_handoff, launch_prepared_component_service,
    launch_prepared_isolation_service_route, prepare_component_service_handoff,
    prepare_isolation_service_route, reserve_isolation_vcpus, route_isolation_service,
};
pub use memory::{
    FrameAllocator, MemoryError, MemoryKind, MemoryMap, MemoryRegion, PAGE_SIZE, PhysAddr,
};
pub use memory_resource::{
    MemoryBackingBackendRequest, MemoryBackingKind, MemoryBackingOperationError, MemoryMapping,
    MemoryMappingBackend, MemoryMappingBackendRequest, MemoryMappingId,
    MemoryMappingOperationError, MemoryObjectBackingBackend, MemoryObjectId, MemoryPhysicalBacking,
    MemoryPoolId, MemoryPoolTable, MemoryResourceError, MemoryRevocationSummary, MemoryUsage,
};
pub use pe::{
    MAX_PE_IMAGE_BYTES, MAX_PE_RELOCATIONS, MAX_PE_SECTIONS, PeAllocatedRegion, PeAllocationError,
    PeError, PeImage, PeLoadRegion, PeSection,
};
pub use platform::{Architecture, Hypervisor, IsolationClass, VmRole};
pub use policy::{
    DeviceAddress, DeviceGrant, HostDevice, IommuTopology, MAX_VM_NAME, PolicyError, SystemPolicy,
    VmName, VmPolicy,
};
pub use protected_channel::{
    AUTHORITY_RECEIPT_BYTES, AuthenticatedProtectionAdmission, AuthenticatedProtectionMode,
    AuthorityReceipt, LAUNCH_REQUEST_BYTES, LaunchRequest, ProtectedChannelError,
    UnverifiedVbsAttestationReport, VBS_ATTESTATION_CHALLENGE_BYTES, VBS_ATTESTATION_DATA_BYTES,
    VBS_ATTESTATION_ENVELOPE_BYTES, VBS_ATTESTATION_REPORT_MAX_BYTES, VBS_AUTHORITY_CONTEXT_BYTES,
    VBS_ENCLAVE_IDENTITY_BYTES, VBS_RECEIPT_VERIFICATION_INPUT_BYTES,
    VBS_REPORT_PACKAGE_HEADER_BYTES, VBS_REPORT_SIGNED_STATEMENT_BYTES,
    VBS_SEALED_KEY_BLOB_MAX_BYTES, VBS_SEALED_KEY_CONFIRMATION_BYTES,
    VBS_SEALED_KEY_ENVELOPE_BYTES, VBS_WORKLOAD_CHALLENGE_BYTES, VBS_WORKLOAD_RESULT_BYTES,
    VBS_WORKLOAD_SECRET_REQUEST_BYTES, VbsAttestationData, VbsAttestationEnvelope,
    VbsAttestationExpectation, VbsAuthorityContext, VbsAuthorityOperation, VbsSealedKeyEnvelope,
};
pub use protected_execution::{
    PROTECTION_POLICY_BYTES, PROTECTION_REPORT_BYTES, ProtectionAdmission, ProtectionBackend,
    ProtectionClaims, ProtectionError, ProtectionEvidenceSource, ProtectionPolicy,
    ProtectionReport, ProtectionSession,
};
pub use protected_monitor::{
    DomainId, DomainState, GranuleHardware, GranuleHardwareOutcome, GranuleId, GranuleState,
    GranuleTransition, GranuleTransitionKind, MonitorError, ProtectedMonitor,
};
pub use scheduler::{
    BalanceOutcome, BalancePolicyError, BalanceTarget, DetachedTask, KernelScheduleError,
    KernelScheduler, MigrationMailbox, MigrationMailboxError, OwnershipMailbox,
    OwnershipMailboxError, PeriodicBalancer, Priority, ScheduleOutcome, Scheduler, SchedulerError,
    SchedulerLoad, TaskAttachError, TaskId, TaskMigration, TaskState,
};
pub use service_lifecycle::{
    AccountedServiceSupervisor, AccountedServiceSupervisorError, RestartPolicy,
    ServiceAddressSpaceEraser, ServiceCleanupError, ServiceCleanupTicket, ServiceError,
    ServiceFault, ServiceId, ServiceRecovery, ServiceRecoveryError, ServiceRegistrationPlan,
    ServiceRetirement, ServiceState, ServiceSupervisor,
};
pub use shared_buffer_syscall::{
    SharedBufferSyscallError, SharedBufferSyscallExecutor, SharedBufferUserAccess,
    SharedBufferUserCopy,
};
pub use shared_memory::{
    HostResourceHandle, HostResourceRetirer, ServiceResourceCleanupError, ServiceResourceEraser,
    SharedAccess, SharedBindingError, SharedBindingId, SharedCleanupError, SharedCleanupReport,
    SharedEndpoint, SharedEndpointRequest, SharedMemoryBindings, SharedRevocation,
    revoke_task_shared_bindings_before_resume,
};
pub use syscall::{
    CAPABILITY_TRANSFER_DESCRIPTOR_BYTES, CapabilityTransferDescriptor,
    MAX_SHARED_BUFFER_SYSCALL_BYTES, MAX_SYSCALL_INLINE_PAYLOAD, SyscallError, SyscallRequest,
    UserCallFrame, X86_USER_CALL_VECTOR, decode_capability_transfers,
};
pub use task_runtime::{
    AccountedTaskRuntime, AccountedTaskRuntimeError, ControlEvent, DetachedTaskDomain,
    DomainBalanceError, DomainBalanceOutcome, FaultRetirement, MAX_TASK_DELEGATIONS, PeerDeath,
    PeerDeathReason, PeriodicDomainBalancer, ReceivedMessage, TASK_CONTROL_PEERS,
    TASK_INBOX_MESSAGES, TaskRuntime, TaskRuntimeError, TaskTermination, TimerDomainBalanceOutcome,
};
pub use virtual_block::{
    AdmittedVirtualBlockRequest, CapabilitySelectedVirtualBlockBackend,
    MAX_VIRTUAL_BLOCK_QUEUE_SLOTS, MAX_VIRTUAL_BLOCK_TRANSFER_BYTES,
    VIRTUAL_BLOCK_COMPLETION_ACK_PORT, VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
    VIRTUAL_BLOCK_COMPLETION_BYTES, VIRTUAL_BLOCK_CONFIGURATION_BYTES, VIRTUAL_BLOCK_DOORBELL_PORT,
    VIRTUAL_BLOCK_DOORBELL_VALUE, VIRTUAL_BLOCK_FEATURE_FLUSH,
    VIRTUAL_BLOCK_MMIO_COMPLETION_ACK_OFFSET, VIRTUAL_BLOCK_MMIO_DOORBELL_OFFSET,
    VIRTUAL_BLOCK_REQUEST_BYTES, VIRTUAL_BLOCK_RESUME_STATE_BYTES, VirtualBlockAuthorityError,
    VirtualBlockBackend, VirtualBlockBackendAuthority, VirtualBlockCapabilityError,
    VirtualBlockCompletion, VirtualBlockCompletionAckError, VirtualBlockCompletionAckResult,
    VirtualBlockCompletionAckRunError, VirtualBlockCompletionAckRunResult,
    VirtualBlockCompletionStatus, VirtualBlockConfiguration, VirtualBlockConfigurationPage,
    VirtualBlockDevice, VirtualBlockDeviceState, VirtualBlockDoorbellError,
    VirtualBlockDoorbellResult, VirtualBlockError, VirtualBlockExecutionError,
    VirtualBlockExecutionOutcome, VirtualBlockExecutionResult, VirtualBlockGuestCompletion,
    VirtualBlockGuestCompletionTicket, VirtualBlockGuestDriver, VirtualBlockGuestNotification,
    VirtualBlockGuestQueueTransport, VirtualBlockGuestQueueTransportError,
    VirtualBlockGuestSubmission, VirtualBlockGuestTerminalReason, VirtualBlockLostExecution,
    VirtualBlockMutationError, VirtualBlockOperation, VirtualBlockPciAttachment,
    VirtualBlockPciAttachmentState, VirtualBlockPciCleanupError, VirtualBlockPciCleanupMode,
    VirtualBlockPciCleanupRecord, VirtualBlockPciError, VirtualBlockPciFunctionRevoker,
    VirtualBlockPciGuestMemoryMapper, VirtualBlockPciGuestWindowBackend,
    VirtualBlockPciMemoryMapper, VirtualBlockPciResourceRevoker, VirtualBlockPciWindowBackend,
    VirtualBlockProcessError, VirtualBlockProcessOutcome, VirtualBlockProcessResult,
    VirtualBlockQueueBridge, VirtualBlockQueueError, VirtualBlockQueueLayout, VirtualBlockRequest,
    VirtualBlockRestartImage, VirtualBlockResumePage, VirtualBlockResumeState,
    VirtualBlockRunError, VirtualBlockRunResult, VirtualBlockTicket,
    VirtualBlockTransactionOutcome, VirtualBlockTransactionRunError,
    VirtualBlockTransactionRunResult, VirtualBlockTransport, VirtualBlockVmmMemory,
    execute_virtual_block_request, process_virtual_block_completion_ack,
    process_virtual_block_doorbell, process_virtual_block_mmio_completion_ack,
    process_virtual_block_mmio_doorbell, process_virtual_block_request,
    run_virtual_block_completion_ack_once, run_virtual_block_doorbell_once,
    run_virtual_block_mmio_transaction_once, run_virtual_block_transaction_once,
};
pub use virtual_gpu::{
    BatchedDispatch, BufferAccess, BufferId, BufferMode, ControlBufferId, ControlBufferTable,
    Dispatch, DispatchId, DispatchTable, GPU_DOORBELL_PORT, GPU_QUEUE_MESSAGE_BYTES,
    GpuBatchExecutor, GpuCommandRing, GpuCommandServiceError, GpuCompletion, GpuCompletionReceiver,
    GpuCompletionRing, GpuCompletionSender, GpuCompletionStatus, GpuDataPlaneBinding,
    GpuDispatchBatch, GpuError,
    GpuGuestCommandPublisher, GpuHostBackend, GpuLifecycleError, GpuQueueIdentity,
    GpuQueueReceiver, GpuQueueSender, GpuResourceBackend, GpuResourceOutcome, GpuResourceResponse,
    GpuResourceResponseReceiver, GpuResourceResponseSender, GpuRingConsumer, GpuRingProducer,
    GpuRingTicket, GpuSharedQueueLayout, GpuSharedRingIndices, GpuSubmitError, GpuVmmMemory,
    GpuVmmQueueBridge, GpuVmmQueueError, KernelId, MAX_ACTIVE_EXPERTS, MAX_BATCH_DISPATCHES,
    MAX_DISPATCH_BUFFERS, MAX_DISPATCH_SCALARS, MAX_GPU_BENCHMARK_ELEMENTS,
    MAX_GPU_BENCHMARK_ITERATIONS, MAX_GPU_CONTROL_BYTES, MAX_GPU_QUEUE_SLOTS, MediatedGpuExecutor,
    PreparedGpuBatch, PreparedGpuDispatch, ResourceCommand, ScalarArg, ScalarKind,
    ValidatedExpertSelection, ValidatedGpuBatch, ValidatedKernelLaunch, ValidatedMoeKernelLaunch,
    VerifiedGpuKernelBundle, VirtualGpuSession, process_gpu_resource_command,
    process_gpu_resource_command_with_response, submit_gpu_batch,
    submit_gpu_batch_to_completion_ring, submit_gpu_batch_with_completions,
    submit_gpu_control_batch, verify_gpu_kernel_bundle,
};
pub use virtual_pci::{
    MAX_VIRTUAL_PCI_FUNCTIONS, PCI_COMMAND_INTERRUPT_DISABLE, PCI_COMMAND_MEMORY_SPACE,
    PCI_CONFIGURATION_ADDRESS_PORT, PCI_CONFIGURATION_DATA_PORT, PCI_CONFIGURATION_IO_RULES,
    PCI_TYPE0_CONFIGURATION_BYTES, VirtualPciAttachedFunction, VirtualPciAttachedResources,
    VirtualPciAttachmentId, VirtualPciBackendMemoryMapper, VirtualPciConfigurationMechanismOne,
    VirtualPciConfigurationRouter, VirtualPciError, VirtualPciFunctionRevoker, VirtualPciIdentity,
    VirtualPciIoOutcome, VirtualPciLocation, VirtualPciMemoryBar, VirtualPciMemoryMapper,
    VirtualPciMmioWindow, VirtualPciNativeResourceError, VirtualPciResetError, VirtualPciRunError,
    VirtualPciType0Function, VirtualPciWriteOutcome, run_pci_configuration_once,
    run_pci_configuration_once_with_backend_mapper, run_pci_configuration_once_with_mapper,
};
pub use vm::{
    DeadlineVmBackend, GuestAccess, GuestMappingId, GuestMappingRevoker, GuestMemory, GuestRegion,
    HYPERCALL_BYTES, Hypercall, HypercallOperation, HypercallRouter, IoReadCompleter,
    MAX_GUEST_REGIONS, MappingRevocationError, MmioWriteCompleter, RevocableVmBackend,
    RoutedHypercall, VmBackend, VmDeadlineOutcome, VmError, VmExit, VmId, VmRunError, VmState,
    VmTable, decode_hypercall_exit, revoke_mapping_before_resume,
};
pub use vm_dispatch::{
    ExitDisposition, IoDirection, IoPortPolicy, IoPortRule, MAX_IO_PORT_RULES, dispatch_vm_exit,
    run_vm_once, run_vm_once_for_mmio,
};
pub use vm_interrupt::{
    InterruptPolicy, VirtualBlockInterruptError, inject_virtual_block_interrupt,
    inject_vm_interrupt,
};
