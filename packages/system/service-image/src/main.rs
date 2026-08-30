#![no_std]
#![no_main]
#![cfg_attr(feature = "buffer-drift-probe", allow(dead_code))]
#![cfg_attr(
    any(feature = "block-service-loop", feature = "invalid-return-probe"),
    allow(dead_code)
)]

use core::arch::{asm, global_asm};

#[cfg(not(feature = "preemption-probe"))]
#[allow(unused_imports)]
use mrml_config::{
    CONFIG_RESPONSE_BYTES, CapabilityAuthorizer, ConfigError, ConfigTransaction, ConfigUpdate,
    ConfigValue, ConfigurationResponse, ConfigurationService, MAX_CONFIG_REQUEST_BYTES,
    PERSISTED_RESTART_POLICY_BYTES, PersistedRestartPolicy, ResponseStatus,
    SUPERVISION_REQUEST_BYTES, SUPERVISION_RESPONSE_BYTES, ServicePolicyAuthorizer,
    ServiceRestartAuthorizer, ServiceStateAuthorizer, SettingId, SettingSchema,
    StableConfigurationRecoveryValidator, SupervisionOperation, SupervisionRequest,
    SupervisionResponse, SupervisionState, dispatch_configuration_envelope,
    dispatch_supervision_policy_envelope, dispatch_supervision_query_envelope,
    dispatch_supervision_restart_envelope, encode_commit_message_request,
    encode_schema_message_request, prepare_block_stable_configuration,
    recover_block_stable_total_system_selection,
    recover_selected_runtime_assignment_shared_backend,
};
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
use mrml_crypto::{LAMPORT_PRIVATE_KEY_BYTES, Sha3_256};
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
use mrml_deployment::{
    DEPLOYMENT_CHECKPOINT_BYTES, DEPLOYMENT_RECOVERY_STATE_BYTES, DeploymentRecoveryStateStore,
    DeploymentService, GenerationCandidate, encode_deployment_recovery_state_with_release,
    encode_deployment_release_checkpoint,
};
#[cfg(not(feature = "preemption-probe"))]
use mrml_kernel::{
    Capability, CapabilityError, ObjectId, RestartPolicy, Rights, ServiceId, ServiceState,
};
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
use mrml_kernel::{
    BOOT_RECOVERY_ENVELOPE_BYTES, BootRecoveryEnvelope, CapabilitySpace, RecoveryStateMetadata,
};
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
use mrml_package_format::{
    ComponentInterfaceProvider, ComponentInterfaceRequirement, ComponentProviderForms, RuntimeInventoryRecord,
    RuntimeIsolationClass, RuntimeIsolationPlacement, SystemGenerationDigestRecord,
    encode_interface_catalog, encode_runtime_inventory, encode_system_generation,
    encode_system_release_with_runtime_inventory, parse_system_release,
};
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
use mrml_storage::{
    AUTHORITY_RECOVERY_STATE_BYTES, AllocationImage, AllocationKind, AllocationRecord,
    AuthorityCheckpointProofIssuer, AuthorityRecoveryStateStore, BLOCK_REQUEST_BYTES,
    BLOCK_RESPONSE_BYTES, BlockDeviceDescriptor, BlockDeviceId, BlockRequest, BlockResponse,
    BlockRights, BlockService, BlockServiceBackend, BlockServiceLoop, BlockServiceSyscalls,
    BlockSessionHandle, BlockStatus, BlockVolume, BootRecoveryAdmission, CowMetadataWrite,
    CowPublicationPlan, DirectoryEntry, DirectoryImage, DirectoryMetadata, ExtentImage, ExtentMap,
    ExtentRecord, FileMetadata, FileReadBackend, FileState, MetadataPointer,
    ObjectIdAllocatorImage, OwnerApprovedAuthorityCheckpoint, ReceivedBlockEnvelope,
    SUPERBLOCK_BYTES, StorageAuthorityTable, StorageBlockDevice, StorageName, StorageObjectId,
    StorageObjectKind, StoragePrincipal, StorageRecoveryGrant, StorageRights, StorageTransaction,
    StorageTransactionId, Superblock, VolumeHeader, VolumeId, authority_checkpoint_digest,
    encode_authority_checkpoint, recover_validate_and_commit_stable_authorities,
};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    halt()
}

// This entry is assembly rather than a Rust ABI function because r12-r14 are
// intentional launch registers, not compiler-owned callee-saved temporaries.
#[cfg(not(feature = "preemption-probe"))]
global_asm!(
    r#"
            .section .text$a,"xr"
            .global efi_main
        efi_main:
            and rsp, -16
            sub rsp, 16
            mov [rsp], r11
            mov rdi, r13
            mov rsi, r14
            mov rdx, r12
            mov rcx, r15
            mov r8, rbx
            mov r9, rbp
            call mrml_configuration_receiver
            ud2

            // Fix the secondary entry ABI exactly; assembly fails if the
            // receiver ever grows beyond its reserved 512-byte window.
            .org efi_main + 512, 0xcc
            .global mrml_service_sender
        mrml_service_sender:
            mov rdi, r13
            mov rsi, r14
            mov rdx, r15
            mov rcx, rbx
            mov r8, r12
            mov r9, rbp
            and rsp, -16
            sub rsp, 16
            mov [rsp], r10
            mov [rsp + 8], r11
            call mrml_configuration_sender
            ud2

            .org efi_main + 1024, 0xcc
            .global mrml_service_manager
        mrml_service_manager:
            mov rdi, r13
            mov rsi, r14
            mov rdx, r15
            mov rcx, rbx
            and rsp, -16
            call mrml_restart_manager
            ud2
    "#
);

#[cfg(not(feature = "preemption-probe"))]
const CONFIG_ROOT_OBJECT: ObjectId = ObjectId(0x92);
#[cfg(not(feature = "preemption-probe"))]
const CONFIG_SETTING_OBJECT: ObjectId = ObjectId(0x93);
#[cfg(not(feature = "preemption-probe"))]
static mut CONFIGURATION: Option<ConfigurationService<1, 2>> = None;

#[cfg(not(feature = "preemption-probe"))]
struct KernelAuthorizer;

#[cfg(not(feature = "preemption-probe"))]
impl CapabilityAuthorizer for KernelAuthorizer {
    fn authorize_exact(
        &self,
        capability: Capability,
        rights: Rights,
        expected: ObjectId,
    ) -> Result<(), ConfigError> {
        let mut status = 6u64;
        unsafe {
            asm!(
                "int 0x80",
                inlateout("rax") status,
                in("rdi") capability.token(),
                in("rsi") expected.0,
                inlateout("rdx") u64::from(rights.bits()) => _,
                inlateout("r10") 0u64 => _,
                inlateout("r8") 0u64 => _,
                inlateout("r9") 0u64 => _,
                options(nostack)
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(ConfigError::Unauthorized(CapabilityError::PermissionDenied))
        }
    }
}

#[cfg(not(feature = "preemption-probe"))]
impl ServiceStateAuthorizer for KernelAuthorizer {
    fn query_state(
        &self,
        capability: Capability,
        service: ServiceId,
    ) -> Result<ServiceState, ConfigError> {
        let mut status = 9u64;
        let state: u64;
        unsafe {
            asm!(
                "int 0x80",
                inlateout("rax") status,
                in("rdi") capability.token(),
                in("rsi") service.token(),
                inlateout("rdx") 0u64 => state,
                inlateout("r10") 0u64 => _,
                inlateout("r8") 0u64 => _,
                inlateout("r9") 0u64 => _,
                options(nostack)
            )
        };
        if status != 0 {
            return Err(ConfigError::Unauthorized(CapabilityError::PermissionDenied));
        }
        match state {
            1 => Ok(ServiceState::Running),
            2 => Ok(ServiceState::Exited),
            3 => Ok(ServiceState::Faulted),
            _ => Err(ConfigError::InvalidProtocol),
        }
    }
}

#[cfg(not(feature = "preemption-probe"))]
impl ServiceRestartAuthorizer for KernelAuthorizer {
    fn restart_service(
        &self,
        capability: Capability,
        service: ServiceId,
    ) -> Result<ServiceId, ConfigError> {
        let mut status = 10u64;
        let replacement: u64;
        unsafe {
            asm!(
                "int 0x80",
                inlateout("rax") status,
                in("rdi") capability.token(),
                in("rsi") service.token(),
                inlateout("rdx") 0u64 => replacement,
                inlateout("r10") 0u64 => _,
                inlateout("r8") 0u64 => _,
                inlateout("r9") 0u64 => _,
                options(nostack)
            )
        };
        if status == 0 && replacement != 0 {
            Ok(ServiceId::from_token(replacement))
        } else {
            Err(ConfigError::Unauthorized(CapabilityError::PermissionDenied))
        }
    }
}

#[cfg(not(feature = "preemption-probe"))]
impl ServicePolicyAuthorizer for KernelAuthorizer {
    fn replace_policy(
        &self,
        capability: Capability,
        service: ServiceId,
        policy: RestartPolicy,
    ) -> Result<(), ConfigError> {
        let mut status = 11u64;
        unsafe {
            asm!(
                "int 0x80",
                inlateout("rax") status,
                in("rdi") capability.token(),
                in("rsi") service.token(),
                in("rdx") u64::from(policy.maximum_restarts()),
                in("r10") policy.base_backoff_ticks(),
                in("r8") policy.maximum_backoff_ticks(),
                in("r9") 0u64,
                options(nostack)
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(ConfigError::Unauthorized(CapabilityError::PermissionDenied))
        }
    }
}

#[cfg(all(
    not(feature = "preemption-probe"),
    not(feature = "block-service-loop"),
    not(feature = "invalid-return-probe"),
    not(feature = "buffer-drift-probe")
))]
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_configuration_receiver(
    endpoint: u64,
    sender: u64,
    generation: u64,
    shared_write: u64,
    shared_read: u64,
    restart_manager: u64,
    _recovery_capability: u64,
) -> ! {
    unsafe { verify_shared_buffer_syscalls(shared_write, shared_read, generation) };
    let setting = SettingId::new(1).unwrap_or_else(|_| halt());
    let configuration = core::ptr::addr_of_mut!(CONFIGURATION);
    if unsafe { (*configuration).is_none() } {
        unsafe {
            configuration.write(Some(
                ConfigurationService::empty(CONFIG_ROOT_OBJECT).unwrap_or_else(|_| halt()),
            ))
        };
    }
    let schema_request_id = generation
        .checked_mul(2)
        .and_then(|value| value.checked_sub(1))
        .unwrap_or_else(|| halt());
    unsafe {
        dispatch_next_request(
            configuration,
            endpoint,
            sender,
            schema_request_id,
            0,
            Some(setting),
        )
    };
    let commit_request_id = generation.checked_mul(2).unwrap_or_else(|| halt());
    unsafe { dispatch_next_request(configuration, endpoint, sender, commit_request_id, 1, None) };
    let supervision_request_id = generation
        .checked_mul(3)
        .and_then(|value| value.checked_add(100))
        .unwrap_or_else(|| halt());
    unsafe { dispatch_supervision_query(endpoint, sender, supervision_request_id) };
    let policy_request_id = supervision_request_id
        .checked_add(1)
        .unwrap_or_else(|| halt());
    unsafe {
        dispatch_supervision_policy(
            (*configuration).as_ref().unwrap_or_else(|| halt()),
            endpoint,
            sender,
            policy_request_id,
        )
    };
    unsafe { yield_now() };
    if restart_manager != 0 {
        unsafe { send_buffer(endpoint, restart_manager, b"restart-ready", &[]) };
        unsafe { dispatch_supervision_restart(endpoint, restart_manager, 0x501) };
        unsafe { yield_now() };
        halt();
    }
    unsafe { asm!("int3", options(noreturn, nostack)) }
}

#[cfg(all(not(feature = "preemption-probe"), feature = "buffer-drift-probe"))]
#[repr(C, align(4096))]
struct BufferDriftOutput([u8; 64]);

#[cfg(all(not(feature = "preemption-probe"), feature = "buffer-drift-probe"))]
static mut BUFFER_DRIFT_OUTPUT: BufferDriftOutput = BufferDriftOutput([0; 64]);

#[cfg(all(not(feature = "preemption-probe"), feature = "buffer-drift-probe"))]
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_configuration_receiver(
    _endpoint: u64,
    _sender: u64,
    _generation: u64,
    _shared_write: u64,
    _shared_read: u64,
    _restart_manager: u64,
    _recovery_capability: u64,
) -> ! {
    let output = unsafe { &mut *core::ptr::addr_of_mut!(BUFFER_DRIFT_OUTPUT) };
    let mut no_capabilities = [0u64; 0];
    unsafe { receive_buffer(&mut output.0, &mut no_capabilities) };
    halt()
}

#[cfg(all(
    not(feature = "preemption-probe"),
    not(feature = "block-service-loop"),
    feature = "invalid-return-probe"
))]
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_configuration_receiver(
    _endpoint: u64,
    _sender: u64,
    _generation: u64,
    _shared_write: u64,
    _shared_read: u64,
    _restart_manager: u64,
    _recovery_capability: u64,
) -> ! {
    unsafe { asm!("xor rsp, rsp", "xor eax, eax", "int 0x80", options(noreturn)) }
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
const PROBE_BLOCK_BYTES: usize = mrml_kernel::PAGE_SIZE as usize;
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
const PROBE_BLOCK_COUNT: usize = 64;
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
const PROBE_MAX_BLOCK_REQUESTS: usize = 128;
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
const PROBE_BLOCK_COMPLETION_MAGIC: [u8; 8] = *b"MRMLBC01";
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
const PROBE_RELEASE_CAPACITY: usize = 160 * 1024;
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
struct ProbeBlockBackend {
    bytes: [u8; PROBE_BLOCK_BYTES * PROBE_BLOCK_COUNT],
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
#[repr(C, align(4096))]
struct ProbeBlock([u8; PROBE_BLOCK_BYTES]);

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
static mut PROBE_RECEIVER_SCRATCH: ProbeBlock = ProbeBlock([0; PROBE_BLOCK_BYTES]);
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
static mut PROBE_SENDER_STAGING: ProbeBlock = ProbeBlock([0; PROBE_BLOCK_BYTES]);
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
static mut PROBE_VOLUME_SCRATCH: ProbeBlock = ProbeBlock([0; PROBE_BLOCK_BYTES]);
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
static mut PROBE_FILE_SCRATCH: ProbeBlock = ProbeBlock([0; PROBE_BLOCK_BYTES]);
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
static mut PROBE_PRIMARY_SCRATCH: ProbeBlock = ProbeBlock([0; PROBE_BLOCK_BYTES]);
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
static mut PROBE_SECONDARY_SCRATCH: ProbeBlock = ProbeBlock([0; PROBE_BLOCK_BYTES]);
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
static mut PROBE_METADATA_SCRATCH: ProbeBlock = ProbeBlock([0; PROBE_BLOCK_BYTES]);
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
static mut PROBE_RELEASE_BYTES: [u8; PROBE_RELEASE_CAPACITY] = [0; PROBE_RELEASE_CAPACITY];
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
static mut PROBE_RELEASE_PRIVATE_KEY: [u8; LAMPORT_PRIVATE_KEY_BYTES] =
    [0; LAMPORT_PRIVATE_KEY_BYTES];

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
static mut PROBE_BLOCK_BACKEND: ProbeBlockBackend = ProbeBlockBackend {
    bytes: [0; PROBE_BLOCK_BYTES * PROBE_BLOCK_COUNT],
};

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
unsafe impl BlockServiceBackend for ProbeBlockBackend {
    type Error = ();

    fn read_blocks(
        &mut self,
        device: BlockDeviceId,
        block: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        let range = probe_block_range(device, block, output.len()).ok_or(())?;
        output.copy_from_slice(&self.bytes[range]);
        Ok(())
    }

    fn write_blocks(
        &mut self,
        device: BlockDeviceId,
        block: u64,
        input: &[u8],
    ) -> Result<(), Self::Error> {
        let range = probe_block_range(device, block, input.len()).ok_or(())?;
        self.bytes[range].copy_from_slice(input);
        Ok(())
    }

    fn flush(&mut self, device: BlockDeviceId) -> Result<(), Self::Error> {
        (device == BlockDeviceId::new(1).unwrap())
            .then_some(())
            .ok_or(())
    }

    fn replace_superblock(
        &mut self,
        device: BlockDeviceId,
        block: u64,
        encoded: &[u8; SUPERBLOCK_BYTES],
    ) -> Result<(), Self::Error> {
        let range = probe_block_range(device, block, PROBE_BLOCK_BYTES).ok_or(())?;
        self.bytes[range.clone()].fill(0);
        self.bytes[range.start..range.start + encoded.len()].copy_from_slice(encoded);
        Ok(())
    }
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
fn probe_block_range(
    device: BlockDeviceId,
    block: u64,
    length: usize,
) -> Option<core::ops::Range<usize>> {
    if device != BlockDeviceId::new(1).unwrap()
        || length == 0
        || !length.is_multiple_of(PROBE_BLOCK_BYTES)
    {
        return None;
    }
    let start = usize::try_from(block)
        .ok()?
        .checked_mul(PROBE_BLOCK_BYTES)?;
    let end = start.checked_add(length)?;
    (end <= PROBE_BLOCK_BYTES * PROBE_BLOCK_COUNT).then_some(start..end)
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_configuration_receiver(
    endpoint: u64,
    sender: u64,
    _generation: u64,
    _shared_write: u64,
    _shared_read: u64,
    _restart_manager: u64,
    recovery_capability: u64,
) -> ! {
    if recovery_capability == 0 {
        halt();
    }
    let recovery_envelope = unsafe { verify_recovery_envelope(recovery_capability) };
    let device = BlockDeviceId::new(1).unwrap_or_else(|| halt());
    let principal = StoragePrincipal::new(1).unwrap_or_else(|_| halt());
    let mut service = BlockService::<1, 1>::new();
    service
        .register_device(
            BlockDeviceDescriptor::new(device, PROBE_BLOCK_BYTES as u32, PROBE_BLOCK_COUNT as u64)
                .unwrap_or_else(|| halt()),
        )
        .unwrap_or_else(|_| halt());
    let session = service
        .grant(device, principal, BlockRights::ALL)
        .unwrap_or_else(|_| halt());
    let backend = unsafe { &mut *core::ptr::addr_of_mut!(PROBE_BLOCK_BACKEND) };
    backend.bytes.fill(0);
    let mut loop_state = BlockServiceLoop::<1>::new();
    let mut syscalls = UserspaceBlockSyscalls {
        endpoint,
        reply_task: sender,
    };
    let mut request = [0u8; BLOCK_REQUEST_BYTES];
    let mut capability = [0u64; 1];
    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(PROBE_RECEIVER_SCRATCH) };
    scratch.0.fill(0);
    let mut response = [0u8; BLOCK_RESPONSE_BYTES];
    let mut ready = [0; 8 + BOOT_RECOVERY_ENVELOPE_BYTES];
    ready[..8].copy_from_slice(&session.token().to_le_bytes());
    ready[8..].copy_from_slice(&recovery_envelope.encode());
    unsafe { send_buffer(endpoint, sender, &ready, &[]) };
    ready.fill(0);
    let mut served = 0usize;
    loop {
        request.fill(0);
        capability.fill(0);
        let (payload_length, capability_count) =
            unsafe { receive_buffer(&mut request, &mut capability) };
        if capability_count == 0 {
            if let Some(completed) = decode_probe_block_completion(&request) {
                if payload_length != request.len() || completed != served || served == 0 {
                    halt();
                }
                request.fill(0);
                break;
            }
        }
        if served == PROBE_MAX_BLOCK_REQUESTS {
            halt();
        }
        loop_state
            .serve_received(
                &service,
                backend,
                &mut syscalls,
                principal,
                ReceivedBlockEnvelope {
                    payload_length,
                    capability_count,
                },
                &mut request,
                &mut capability,
                &mut scratch.0,
                &mut response,
            )
            .unwrap_or_else(|_| halt());
        served = served.checked_add(1).unwrap_or_else(|| halt());
    }
    scratch.0.fill(0);
    unsafe { terminate(3) }
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
unsafe fn verify_recovery_envelope(capability: u64) -> BootRecoveryEnvelope {
    let mut encoded = [0xa5; BOOT_RECOVERY_ENVELOPE_BYTES];
    let mut status = 13u64;
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") status,
            in("rdi") capability,
            in("rsi") encoded.as_mut_ptr() as u64,
            inlateout("rdx") 0u64 => _,
            inlateout("r10") 0u64 => _,
            inlateout("r8") 0u64 => _,
            inlateout("r9") 0u64 => _,
            options(nostack)
        )
    };
    let expected = RecoveryStateMetadata::new(8, 2, Some([0x51; 16]), 1).unwrap_or_else(|_| halt());
    let delivered = BootRecoveryEnvelope::decode(&encoded);
    if status != 0 || delivered.map(|value| value.recovery()) != Ok(expected) {
        encoded.fill(0);
        halt();
    }
    let delivered = delivered.unwrap_or_else(|_| halt());
    let mut store = ControlledRecoveryStateStore::new();
    {
        let bound = BootRecoveryAdmission::new(delivered.recovery())
            .unwrap_or_else(|_| halt())
            .bind(&mut store);
        let mut authenticated = [0xa5; AUTHORITY_RECOVERY_STATE_BYTES];
        if bound.load_authenticated(&mut authenticated).is_err() {
            authenticated.fill(0);
            encoded.fill(0);
            halt();
        }
        let mut replay = [0xa5; AUTHORITY_RECOVERY_STATE_BYTES];
        if bound.load_authenticated(&mut replay).is_ok() || replay.iter().any(|byte| *byte != 0) {
            replay.fill(0);
            authenticated.fill(0);
            encoded.fill(0);
            halt();
        }
        replay.fill(0);
        authenticated.fill(0);
    }
    store.encoded.fill(0);
    encoded.fill(0);
    delivered
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
struct ControlledRecoveryStateStore {
    encoded: [u8; AUTHORITY_RECOVERY_STATE_BYTES],
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
impl ControlledRecoveryStateStore {
    fn new() -> Self {
        let mut encoded = [0; AUTHORITY_RECOVERY_STATE_BYTES];
        encoded[..16].copy_from_slice(b"MRML-AUTHSTATE1\0");
        encoded[16..24].copy_from_slice(&8u64.to_le_bytes());
        encoded[24..28].copy_from_slice(&2u32.to_le_bytes());
        encoded[32..48].copy_from_slice(&[0x51; 16]);
        encoded[48..56].copy_from_slice(&1u64.to_le_bytes());
        Self { encoded }
    }

    fn accepted_epoch(&self) -> u64 {
        u64::from_le_bytes(self.encoded[16..24].try_into().unwrap_or_else(|_| halt()))
    }
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
impl AuthorityRecoveryStateStore for ControlledRecoveryStateStore {
    type Error = ();

    fn load_authenticated(
        &self,
        output: &mut [u8; AUTHORITY_RECOVERY_STATE_BYTES],
    ) -> Result<(), Self::Error> {
        *output = self.encoded;
        Ok(())
    }

    fn compare_and_store(
        &mut self,
        expected: &[u8; AUTHORITY_RECOVERY_STATE_BYTES],
        replacement: &[u8; AUTHORITY_RECOVERY_STATE_BYTES],
    ) -> Result<(), Self::Error> {
        let mut required = [0; AUTHORITY_RECOVERY_STATE_BYTES];
        required[..16].copy_from_slice(b"MRML-AUTHSTATE1\0");
        required[16..24].copy_from_slice(&9u64.to_le_bytes());
        required[24..28].copy_from_slice(&3u32.to_le_bytes());
        required[32..48].copy_from_slice(&[0x51; 16]);
        required[48..56].copy_from_slice(&2u64.to_le_bytes());
        if self.encoded != *expected || *replacement != required {
            required.fill(0);
            return Err(());
        }
        self.encoded = required;
        Ok(())
    }
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
struct ControlledAuthorityCheckpoint {
    object: StorageObjectId,
    bytes: [u8; PROBE_BLOCK_BYTES],
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
impl ControlledAuthorityCheckpoint {
    fn new(object: StorageObjectId) -> Self {
        Self {
            object,
            bytes: [0; PROBE_BLOCK_BYTES],
        }
    }

    fn file(&self, length: usize) -> FileState<1> {
        let extent = ExtentRecord::data(self.object, 2, 0, 1, 11, probe_digest(&self.bytes))
            .unwrap_or_else(|_| halt());
        let extents = ExtentMap::build(
            probe_header(),
            self.object,
            2,
            u64::try_from(length).unwrap_or_else(|_| halt()),
            &[extent],
        )
        .unwrap_or_else(|_| halt());
        FileState::new(
            self.object,
            2,
            u64::try_from(length).unwrap_or_else(|_| halt()),
            extents,
        )
        .unwrap_or_else(|_| halt())
    }
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
unsafe impl FileReadBackend for ControlledAuthorityCheckpoint {
    type Error = ();

    fn read_verified_extent(
        &mut self,
        record: ExtentRecord,
        byte_offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        if record.file() != self.object
            || record.metadata_generation() != 2
            || record.content_digest() != probe_digest(&self.bytes)
        {
            return Err(());
        }
        let start = usize::try_from(byte_offset).map_err(|_| ())?;
        let end = start.checked_add(output.len()).ok_or(())?;
        output.copy_from_slice(self.bytes.get(start..end).ok_or(())?);
        Ok(())
    }
}

#[cfg(not(feature = "preemption-probe"))]
unsafe fn verify_shared_buffer_syscalls(write: u64, read: u64, generation: u64) {
    let mut output = [0xa5u8; 8];
    let mut status = 7u64;
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") status,
            in("rdi") read,
            in("rsi") 128u64,
            in("rdx") output.as_mut_ptr() as u64,
            in("r10") output.len() as u64,
            in("r8") 0u64,
            in("r9") 0u64,
            options(nostack)
        )
    };
    if status != 0 || output != [0; 8] {
        halt();
    }
    let input = generation.to_le_bytes();
    status = 8;
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") status,
            in("rdi") write,
            in("rsi") 128u64,
            in("rdx") input.as_ptr() as u64,
            in("r10") input.len() as u64,
            in("r8") 0u64,
            in("r9") 0u64,
            options(nostack)
        )
    };
    if status != 0 {
        halt();
    }
    output.fill(0);
    status = 7;
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") status,
            in("rdi") read,
            in("rsi") 128u64,
            in("rdx") output.as_mut_ptr() as u64,
            in("r10") output.len() as u64,
            in("r8") 0u64,
            in("r9") 0u64,
            options(nostack)
        )
    };
    if status != 0 || output != input {
        halt();
    }
}

#[cfg(not(feature = "preemption-probe"))]
unsafe fn dispatch_supervision_query(endpoint: u64, sender: u64, request_id: u64) {
    let mut request = [0u8; SUPERVISION_REQUEST_BYTES];
    let mut capability_tokens = [0u64; 1];
    let (length, count) = unsafe { receive_buffer(&mut request, &mut capability_tokens) };
    if length != SUPERVISION_REQUEST_BYTES || count != 1 {
        halt();
    }
    let capability = Capability::from_token(capability_tokens[0]);
    let mut response = [0u8; SUPERVISION_RESPONSE_BYTES];
    dispatch_supervision_query_envelope(&KernelAuthorizer, &request, &[capability], &mut response)
        .unwrap_or_else(|_| halt());
    unsafe { release_received_capabilities(&[capability]) };
    let decoded = SupervisionResponse::decode(&response).unwrap_or_else(|_| halt());
    if decoded.request_id != request_id
        || decoded.status != ResponseStatus::Ok
        || decoded.state != SupervisionState::Running
        || decoded.detail != 0
    {
        halt();
    }
    unsafe { send_buffer(endpoint, sender, &response, &[]) };
}

#[cfg(not(feature = "preemption-probe"))]
unsafe fn dispatch_supervision_restart(endpoint: u64, sender: u64, request_id: u64) {
    let mut request = [0u8; SUPERVISION_REQUEST_BYTES];
    let mut capability_tokens = [0u64; 1];
    let (length, count) = unsafe { receive_buffer(&mut request, &mut capability_tokens) };
    if length != SUPERVISION_REQUEST_BYTES || count != 1 {
        halt();
    }
    let decoded_request = SupervisionRequest::decode(&request).unwrap_or_else(|_| halt());
    if decoded_request.request_id != request_id
        || decoded_request.operation != SupervisionOperation::Restart
    {
        halt();
    }
    let capability = Capability::from_token(capability_tokens[0]);
    let mut response = [0u8; SUPERVISION_RESPONSE_BYTES];
    dispatch_supervision_restart_envelope(
        &KernelAuthorizer,
        &request,
        &[capability],
        &mut response,
    )
    .unwrap_or_else(|_| halt());
    unsafe { release_received_capabilities(&[capability]) };
    let decoded = SupervisionResponse::decode(&response).unwrap_or_else(|_| halt());
    if decoded.request_id != request_id
        || decoded.status != ResponseStatus::Ok
        || decoded.service == decoded_request.service
        || decoded.state != SupervisionState::Running
        || decoded.detail != 0
    {
        halt();
    }
    unsafe { send_buffer(endpoint, sender, &response, &[]) };
}

#[cfg(not(feature = "preemption-probe"))]
unsafe fn dispatch_supervision_policy(
    configuration: &ConfigurationService<1, 2>,
    endpoint: u64,
    sender: u64,
    request_id: u64,
) {
    let mut request = [0u8; SUPERVISION_REQUEST_BYTES];
    let mut capability_tokens = [0u64; 2];
    let (length, count) = unsafe { receive_buffer(&mut request, &mut capability_tokens) };
    if length != SUPERVISION_REQUEST_BYTES || count != 2 {
        halt();
    }
    let capabilities = [
        Capability::from_token(capability_tokens[0]),
        Capability::from_token(capability_tokens[1]),
    ];
    let mut response = [0u8; SUPERVISION_RESPONSE_BYTES];
    dispatch_supervision_policy_envelope(
        configuration,
        &KernelAuthorizer,
        &KernelAuthorizer,
        ObjectId(0xa1),
        &request,
        &capabilities,
        &mut response,
    )
    .unwrap_or_else(|_| halt());
    unsafe { release_received_capabilities(&capabilities) };
    let decoded = SupervisionResponse::decode(&response).unwrap_or_else(|_| halt());
    if decoded.request_id != request_id
        || decoded.status != ResponseStatus::Ok
        || decoded.state != SupervisionState::Running
        || decoded.detail != 0
    {
        halt();
    }
    unsafe { send_buffer(endpoint, sender, &response, &[]) };
}

#[cfg(not(feature = "preemption-probe"))]
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_restart_manager(
    endpoint: u64,
    receiver: u64,
    control: u64,
    service: u64,
) -> ! {
    let mut ready = [0u8; 13];
    let mut no_capabilities = [0u64; 0];
    let (length, count) = unsafe { receive_buffer(&mut ready, &mut no_capabilities) };
    if length != ready.len() || count != 0 || &ready != b"restart-ready" {
        halt();
    }
    let retired = ServiceId::from_token(service);
    let mut request = [0u8; SUPERVISION_REQUEST_BYTES];
    SupervisionRequest {
        operation: SupervisionOperation::Restart,
        request_id: 0x501,
        service: retired,
        capability: Capability::from_token(0),
        setting: None,
        setting_capability: Capability::from_token(0),
    }
    .encode(&mut request)
    .unwrap_or_else(|_| halt());
    let descriptor = capability_descriptor(control, Rights::CONTROL);
    unsafe { send_buffer(endpoint, receiver, &request, descriptor.as_slice()) };
    let mut response = [0u8; SUPERVISION_RESPONSE_BYTES];
    let (length, count) = unsafe { receive_buffer(&mut response, &mut no_capabilities) };
    if length != SUPERVISION_RESPONSE_BYTES || count != 0 {
        halt();
    }
    let decoded = SupervisionResponse::decode(&response).unwrap_or_else(|_| halt());
    if decoded.request_id != 0x501
        || decoded.status != ResponseStatus::Ok
        || decoded.service == retired
        || decoded.state != SupervisionState::Running
        || decoded.detail != 0
    {
        halt();
    }
    unsafe { asm!("int3", options(noreturn, nostack)) }
}

#[cfg(not(feature = "preemption-probe"))]
unsafe fn dispatch_next_request(
    configuration: *mut Option<ConfigurationService<1, 2>>,
    endpoint: u64,
    sender: u64,
    request_id: u64,
    expected_revision: u64,
    expected_setting: Option<SettingId>,
) {
    let mut request = [0u8; mrml_config::MAX_CONFIG_REQUEST_BYTES];
    let mut capability_tokens = [0u64; mrml_kernel::MAX_CAPABILITIES];
    let (request_length, capability_count) =
        unsafe { receive_buffer(&mut request, &mut capability_tokens) };
    let mut capabilities = [Capability::from_token(0); mrml_kernel::MAX_CAPABILITIES];
    for (slot, token) in capabilities.iter_mut().zip(capability_tokens) {
        *slot = Capability::from_token(token);
    }
    let mut response = [0u8; CONFIG_RESPONSE_BYTES];
    dispatch_configuration_envelope(
        unsafe { (*configuration).as_mut().unwrap_or_else(|| halt()) },
        &KernelAuthorizer,
        &request[..request_length],
        &capabilities[..capability_count],
        &mut response,
    )
    .unwrap_or_else(|_| halt());
    unsafe { release_received_capabilities(&capabilities[..capability_count]) };
    let decoded = ConfigurationResponse::decode(&response).unwrap_or_else(|_| halt());
    if decoded.request_id != request_id
        || decoded.status != ResponseStatus::Ok
        || decoded.revision != expected_revision
        || decoded.setting != expected_setting
        || decoded.value.is_some()
    {
        halt();
    }
    unsafe { send_buffer(endpoint, sender, &response, &[]) };
}

#[cfg(not(feature = "preemption-probe"))]
unsafe fn verify_response(
    response: &[u8; CONFIG_RESPONSE_BYTES],
    request_id: u64,
    revision: u64,
    setting: Option<SettingId>,
) {
    let decoded = ConfigurationResponse::decode(response).unwrap_or_else(|_| halt());
    if decoded.request_id != request_id
        || decoded.status != ResponseStatus::Ok
        || decoded.revision != revision
        || decoded.setting != setting
        || decoded.value.is_some()
    {
        halt();
    }
}

#[cfg(not(feature = "preemption-probe"))]
unsafe fn yield_now() {
    let mut status = 0u64;
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") status,
            in("rdi") 0u64,
            in("rsi") 0u64,
            in("rdx") 0u64,
            in("r10") 0u64,
            in("r8") 0u64,
            in("r9") 0u64,
            options(nostack)
        )
    };
    if status != 0 {
        halt();
    }
}

#[cfg(all(
    not(feature = "preemption-probe"),
    not(feature = "block-service-loop"),
    not(feature = "invalid-return-probe"),
    not(feature = "buffer-drift-probe")
))]
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_configuration_sender(
    endpoint: u64,
    receiver: u64,
    root_capability: u64,
    setting_capability: u64,
    generation: u64,
    supervision_read: u64,
    supervised_service: u64,
) -> ! {
    let setting = SettingId::new(1).unwrap_or_else(|_| halt());
    let schema = SettingSchema::bytes(
        setting,
        CONFIG_SETTING_OBJECT,
        PERSISTED_RESTART_POLICY_BYTES as u8,
    )
    .unwrap_or_else(|_| halt());
    let mut schema_request = [0u8; MAX_CONFIG_REQUEST_BYTES];
    let schema_request_id = generation
        .checked_mul(2)
        .and_then(|value| value.checked_sub(1))
        .unwrap_or_else(|| halt());
    let schema_length =
        encode_schema_message_request(schema_request_id, schema, &mut schema_request)
            .unwrap_or_else(|_| halt());
    let root_descriptor = capability_descriptor(root_capability, Rights::CONTROL);
    unsafe {
        send_buffer(
            endpoint,
            receiver,
            &schema_request[..schema_length],
            root_descriptor.as_slice(),
        )
    };
    let mut response = [0u8; CONFIG_RESPONSE_BYTES];
    let mut no_capabilities = [0u64; 0];
    let (length, count) = unsafe { receive_buffer(&mut response, &mut no_capabilities) };
    if length != CONFIG_RESPONSE_BYTES || count != 0 {
        halt();
    }
    unsafe { verify_response(&response, schema_request_id, 0, Some(setting)) };

    let policy = PersistedRestartPolicy::new(ObjectId(0xa1), 2, 0, 0).unwrap_or_else(|_| halt());
    let mut encoded_policy = [0; PERSISTED_RESTART_POLICY_BYTES];
    policy.encode(&mut encoded_policy);
    let mut transaction = ConfigTransaction::<1>::new(0);
    transaction
        .push(ConfigUpdate::new(
            setting,
            Capability::from_token(0),
            ConfigValue::bytes(&encoded_policy).unwrap_or_else(|_| halt()),
        ))
        .unwrap_or_else(|_| halt());
    let mut request = [0u8; MAX_CONFIG_REQUEST_BYTES];
    let commit_request_id = generation.checked_mul(2).unwrap_or_else(|| halt());
    let request_length =
        encode_commit_message_request(commit_request_id, &transaction, &mut request)
            .unwrap_or_else(|_| halt());
    let descriptors = capability_descriptors(
        (root_capability, Rights::CONTROL),
        (setting_capability, Rights::READ.union(Rights::WRITE)),
    );
    unsafe {
        send_buffer(
            endpoint,
            receiver,
            &request[..request_length],
            descriptors.as_slice(),
        )
    };
    let (length, count) = unsafe { receive_buffer(&mut response, &mut no_capabilities) };
    if length != CONFIG_RESPONSE_BYTES || count != 0 {
        halt();
    }
    unsafe { verify_response(&response, commit_request_id, 1, None) };
    let supervision_request_id = generation
        .checked_mul(3)
        .and_then(|value| value.checked_add(100))
        .unwrap_or_else(|| halt());
    let mut supervision_request = [0u8; SUPERVISION_REQUEST_BYTES];
    SupervisionRequest {
        operation: SupervisionOperation::Query,
        request_id: supervision_request_id,
        service: ServiceId::from_token(supervised_service),
        capability: Capability::from_token(0),
        setting: None,
        setting_capability: Capability::from_token(0),
    }
    .encode(&mut supervision_request)
    .unwrap_or_else(|_| halt());
    let supervision_descriptor = capability_descriptor(supervision_read, Rights::READ);
    unsafe {
        send_buffer(
            endpoint,
            receiver,
            &supervision_request,
            supervision_descriptor.as_slice(),
        )
    };
    let mut supervision_response = [0u8; SUPERVISION_RESPONSE_BYTES];
    let (length, count) =
        unsafe { receive_buffer(&mut supervision_response, &mut no_capabilities) };
    if length != SUPERVISION_RESPONSE_BYTES || count != 0 {
        halt();
    }
    let decoded = SupervisionResponse::decode(&supervision_response).unwrap_or_else(|_| halt());
    if decoded.request_id != supervision_request_id
        || decoded.status != ResponseStatus::Ok
        || decoded.service != ServiceId::from_token(supervised_service)
        || decoded.state != SupervisionState::Running
        || decoded.detail != 0
    {
        halt();
    }
    let policy_request_id = supervision_request_id
        .checked_add(1)
        .unwrap_or_else(|| halt());
    SupervisionRequest {
        operation: SupervisionOperation::ReplacePolicy,
        request_id: policy_request_id,
        service: ServiceId::from_token(supervised_service),
        capability: Capability::from_token(0),
        setting: Some(setting),
        setting_capability: Capability::from_token(0),
    }
    .encode(&mut supervision_request)
    .unwrap_or_else(|_| halt());
    let descriptors = capability_descriptors(
        (setting_capability, Rights::READ),
        (supervision_read, Rights::CONTROL),
    );
    unsafe {
        send_buffer(
            endpoint,
            receiver,
            &supervision_request,
            descriptors.as_slice(),
        )
    };
    let (length, count) =
        unsafe { receive_buffer(&mut supervision_response, &mut no_capabilities) };
    if length != SUPERVISION_RESPONSE_BYTES || count != 0 {
        halt();
    }
    let decoded = SupervisionResponse::decode(&supervision_response).unwrap_or_else(|_| halt());
    if decoded.request_id != policy_request_id
        || decoded.status != ResponseStatus::Ok
        || decoded.service != ServiceId::from_token(supervised_service)
        || decoded.state != SupervisionState::Running
        || decoded.detail != 0
    {
        halt();
    }
    if generation == 2 {
        unsafe { receive_buffer(&mut response, &mut no_capabilities) };
        halt();
    }
    unsafe { terminate(3) }
}

#[cfg(all(not(feature = "preemption-probe"), feature = "buffer-drift-probe"))]
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_configuration_sender(
    endpoint: u64,
    receiver: u64,
    _root_capability: u64,
    _setting_capability: u64,
    _generation: u64,
    _supervision_read: u64,
    _supervised_service: u64,
) -> ! {
    unsafe { send_buffer(endpoint, receiver, b"mapping-drift", &[]) };
    unsafe { yield_now() };
    unsafe { terminate(3) }
}

#[cfg(all(
    not(feature = "preemption-probe"),
    not(feature = "block-service-loop"),
    feature = "invalid-return-probe"
))]
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_configuration_sender(
    _endpoint: u64,
    _receiver: u64,
    _root_capability: u64,
    _setting_capability: u64,
    _generation: u64,
    _supervision_read: u64,
    _supervised_service: u64,
) -> ! {
    unsafe {
        asm!(
            "int 0x80",
            in("rax") 3u64,
            in("rdi") 0u64,
            in("rsi") 0u64,
            in("rdx") 0u64,
            in("r10") 0u64,
            in("r8") 0u64,
            in("r9") 0u64,
            options(noreturn)
        )
    }
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
struct RemoteBlockDevice {
    endpoint: u64,
    receiver: u64,
    shared_write: u64,
    shared_read: u64,
    shared_transfer: u64,
    session: BlockSessionHandle,
    next_request: u64,
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
enum RemoteBlockBuffer<'a> {
    ServiceReads(&'a [u8]),
    ServiceWrites(&'a mut [u8]),
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
impl RemoteBlockDevice {
    unsafe fn call(
        &mut self,
        request: BlockRequest,
        mut buffer: Option<RemoteBlockBuffer<'_>>,
    ) -> Result<(), u8> {
        if request.request_id() != self.next_request {
            return Err(1);
        }
        let mut wire = [0; BLOCK_REQUEST_BYTES];
        request.encode(&mut wire).map_err(|_| 2)?;
        let descriptor = match &mut buffer {
            Some(RemoteBlockBuffer::ServiceReads(bytes)) => {
                shared_buffer_call(
                    8,
                    Capability::from_token(self.shared_write),
                    0,
                    bytes.as_ptr().cast_mut(),
                    bytes.len(),
                )
                .map_err(|_| 3)?;
                Some(capability_descriptor(
                    self.shared_transfer,
                    Rights::MAP.union(Rights::READ),
                ))
            }
            Some(RemoteBlockBuffer::ServiceWrites(_)) => Some(capability_descriptor(
                self.shared_transfer,
                Rights::MAP.union(Rights::READ).union(Rights::WRITE),
            )),
            None => None,
        };
        unsafe {
            send_buffer(
                self.endpoint,
                self.receiver,
                &wire,
                descriptor.as_ref().map_or(&[], |value| value.as_slice()),
            )
        };
        let mut response = [0; BLOCK_RESPONSE_BYTES];
        let mut no_capabilities = [0u64; 0];
        let (length, count) = unsafe { receive_buffer(&mut response, &mut no_capabilities) };
        if length != response.len() || count != 0 {
            return Err(4);
        }
        let decoded = BlockResponse::decode(&response).map_err(|_| 5)?;
        if decoded.request_id() != self.next_request
            || decoded.status() != BlockStatus::Ok
            || decoded.transferred() != request.byte_length() as u32
        {
            return Err(6);
        }
        if let Some(RemoteBlockBuffer::ServiceWrites(bytes)) = buffer {
            shared_buffer_call(
                7,
                Capability::from_token(self.shared_read),
                0,
                bytes.as_mut_ptr(),
                bytes.len(),
            )
            .map_err(|_| 7)?;
        }
        self.next_request = self.next_request.checked_add(1).ok_or(8)?;
        Ok(())
    }
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
unsafe impl StorageBlockDevice for RemoteBlockDevice {
    type Error = u8;

    fn read_blocks(&mut self, block: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        if output.is_empty() || !output.len().is_multiple_of(PROBE_BLOCK_BYTES) {
            return Err(9);
        }
        for (index, page) in output.chunks_mut(PROBE_BLOCK_BYTES).enumerate() {
            let request = BlockRequest::Read {
                request_id: self.next_request,
                session: self.session,
                block: block.checked_add(index as u64).ok_or(9)?,
                byte_length: PROBE_BLOCK_BYTES as u32,
            };
            unsafe { self.call(request, Some(RemoteBlockBuffer::ServiceWrites(page))) }?;
        }
        Ok(())
    }

    fn write_blocks(&mut self, block: u64, input: &[u8]) -> Result<(), Self::Error> {
        if input.is_empty() || !input.len().is_multiple_of(PROBE_BLOCK_BYTES) {
            return Err(9);
        }
        for (index, page) in input.chunks(PROBE_BLOCK_BYTES).enumerate() {
            let request = BlockRequest::Write {
                request_id: self.next_request,
                session: self.session,
                block: block.checked_add(index as u64).ok_or(9)?,
                byte_length: PROBE_BLOCK_BYTES as u32,
            };
            unsafe { self.call(request, Some(RemoteBlockBuffer::ServiceReads(page))) }?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        let request = BlockRequest::Flush {
            request_id: self.next_request,
            session: self.session,
        };
        unsafe { self.call(request, None) }
    }

    fn replace_superblock(
        &mut self,
        block: u64,
        encoded: &[u8; SUPERBLOCK_BYTES],
    ) -> Result<(), Self::Error> {
        let request = BlockRequest::ReplaceSuperblock {
            request_id: self.next_request,
            session: self.session,
            block,
            encoded: *encoded,
        };
        unsafe { self.call(request, None) }
    }
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
fn probe_digest(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha3_256::new();
    digest.update(bytes);
    digest.finalize()
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
fn probe_volume() -> VolumeId {
    VolumeId::new([0x51; 16]).unwrap_or_else(|_| halt())
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
fn probe_header() -> VolumeHeader {
    VolumeHeader::new(
        probe_volume(),
        PROBE_BLOCK_BYTES as u32,
        PROBE_BLOCK_COUNT as u64,
        1,
        2,
    )
    .unwrap_or_else(|_| halt())
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
fn probe_object(local: u64) -> StorageObjectId {
    StorageObjectId::new(probe_volume(), local).unwrap_or_else(|_| halt())
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
fn write_probe_block(device: &mut RemoteBlockDevice, block: u64, bytes: &mut [u8; PROBE_BLOCK_BYTES]) {
    device.write_blocks(block, bytes).unwrap_or_else(|_| halt());
    bytes.fill(0);
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
struct ProbeDeploymentStateStore {
    bytes: [u8; DEPLOYMENT_RECOVERY_STATE_BYTES],
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
impl DeploymentRecoveryStateStore for ProbeDeploymentStateStore {
    type Error = ();

    fn load_authenticated(
        &self,
        output: &mut [u8; DEPLOYMENT_RECOVERY_STATE_BYTES],
    ) -> Result<(), Self::Error> {
        output.copy_from_slice(&self.bytes);
        Ok(())
    }

    fn compare_and_store(
        &mut self,
        expected: &[u8; DEPLOYMENT_RECOVERY_STATE_BYTES],
        replacement: &[u8; DEPLOYMENT_RECOVERY_STATE_BYTES],
    ) -> Result<(), Self::Error> {
        if self.bytes != *expected {
            return Err(());
        }
        self.bytes.copy_from_slice(replacement);
        Ok(())
    }
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
fn build_probe_deployment_evidence(
    release: &mut [u8],
) -> (
    usize,
    [u8; DEPLOYMENT_CHECKPOINT_BYTES],
    ProbeDeploymentStateStore,
) {
    const RELEASE_GENERATION: u64 = 33;
    let artifact_digest = [0x5a; 64];
    let generation_record = SystemGenerationDigestRecord {
        package_id: "org.mrml.zstd",
        version: 1,
        artifact_digest: &artifact_digest,
    };
    let mut generation = [0u8; 160];
    let generation_length = encode_system_generation(
        RELEASE_GENERATION,
        &[generation_record],
        &mut generation,
    )
    .unwrap_or_else(|_| halt());
    let mut catalog = [0u8; 256];
    let provider = ComponentInterfaceProvider::exact(
        "org.mrml.zstd",
        "org.mrml.interface.compression.zstd",
        3,
        [0x6a; 32],
        ComponentProviderForms::MICROVM,
    )
    .unwrap_or_else(|_| halt());
    let requirement = ComponentInterfaceRequirement::exact(
        "org.mrml.zstd",
        "org.mrml.interface.compression.zstd",
        3,
        [0x6a; 32],
    )
    .unwrap_or_else(|_| halt());
    let catalog_length = encode_interface_catalog(RELEASE_GENERATION, &[requirement], &[provider], &mut catalog)
        .unwrap_or_else(|_| halt());
    let runtime_record = RuntimeInventoryRecord {
        package_id: "org.mrml.zstd",
        version: 1,
        artifact_digest: &artifact_digest,
        class: RuntimeIsolationClass::MicrovmEligible,
        must_run: true,
        preferred: RuntimeIsolationPlacement::NativeService,
        minimum: RuntimeIsolationPlacement::NativeService,
        maximum: RuntimeIsolationPlacement::Microvm,
        supported: RuntimeIsolationPlacement::NativeService.bit()
            | RuntimeIsolationPlacement::Microvm.bit(),
        reason: "",
    };
    let mut runtime = [0u8; 256];
    let runtime_length =
        encode_runtime_inventory(RELEASE_GENERATION, &[runtime_record], &mut runtime)
            .unwrap_or_else(|_| halt());
    let private = unsafe { &mut *core::ptr::addr_of_mut!(PROBE_RELEASE_PRIVATE_KEY) };
    private.fill(0x69);
    let release_length = encode_system_release_with_runtime_inventory(
        &generation[..generation_length],
        &catalog[..catalog_length],
        &runtime[..runtime_length],
        private,
        release,
    )
    .unwrap_or_else(|_| halt());
    private.fill(0);
    let parsed = parse_system_release(&release[..release_length]).unwrap_or_else(|_| halt());
    let deployment_root = ObjectId(0x4445_504c_4f59);
    let mut capabilities = CapabilitySpace::<2>::new();
    let control = capabilities
        .insert(deployment_root, Rights::CONTROL)
        .unwrap_or_else(|_| halt());
    let inspect = capabilities
        .insert(deployment_root, Rights::READ)
        .unwrap_or_else(|_| halt());
    let mut service = DeploymentService::<1>::new(deployment_root).unwrap_or_else(|_| halt());
    let candidate = service
        .stage(
            &capabilities,
            control,
            GenerationCandidate::from_system_release(
                &release[..release_length],
                &parsed.key_id(),
                probe_object(12).local(),
                2,
            )
            .unwrap_or_else(|_| halt()),
        )
        .unwrap_or_else(|_| halt());
    let prepared = service
        .prepare_activation(&capabilities, control, candidate, None)
        .unwrap_or_else(|_| halt());
    let active = service
        .commit_activation(&capabilities, control, prepared)
        .unwrap_or_else(|_| halt());
    let active_release = service
        .active_release(&capabilities, inspect)
        .unwrap_or_else(|_| halt())
        .unwrap_or_else(|| halt());
    let checkpoint = encode_deployment_release_checkpoint(deployment_root, active_release)
        .unwrap_or_else(|_| halt());
    let state = encode_deployment_recovery_state_with_release(
        1,
        deployment_root,
        active,
        Some(active_release),
        probe_object(11),
        2,
    )
    .unwrap_or_else(|_| halt());
    (release_length, checkpoint, ProbeDeploymentStateStore { bytes: state })
}

/// Publishes the controlled probe's four distinct recovery files as one
/// canonical reachable root. The returned root block is identity only; the
/// caller must still recover and validate the graph through its live block
/// session before using any selection.
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
fn publish_probe_total_recovery_graph(
    device: &mut RemoteBlockDevice,
    configuration: &[u8],
    authority_checkpoint: &[u8],
    deployment_checkpoint: &[u8],
    release: &mut [u8],
    release_length: usize,
) -> u64 {
    const GENERATION: u64 = 2;
    const ROOT_GENERATION: u64 = 14;
    let header = probe_header();
    let root = probe_object(1);
    let configuration_object = probe_object(9);
    let authority_object = probe_object(10);
    let deployment_object = probe_object(11);
    let release_object = probe_object(12);
    let root_pointer = MetadataPointer::new(10, 1).unwrap_or_else(|_| halt());
    let entries_pointer = MetadataPointer::new(11, 1).unwrap_or_else(|_| halt());
    let configuration_extents = MetadataPointer::new(13, 1).unwrap_or_else(|_| halt());
    let authority_extents = MetadataPointer::new(15, 1).unwrap_or_else(|_| halt());
    let deployment_extents = MetadataPointer::new(17, 1).unwrap_or_else(|_| halt());
    let release_extents = MetadataPointer::new(19, 1).unwrap_or_else(|_| halt());
    let allocation_pointer = MetadataPointer::new(20, 1).unwrap_or_else(|_| halt());
    let object_ids_pointer = MetadataPointer::new(21, 1).unwrap_or_else(|_| halt());
    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(PROBE_SENDER_STAGING) };
    scratch.0.fill(0);

    DirectoryMetadata::new(header, root, 2, None, 4, entries_pointer)
        .unwrap_or_else(|_| halt())
        .encode(
            (&mut scratch.0[..mrml_storage::DIRECTORY_METADATA_BYTES])
                .try_into()
                .unwrap_or_else(|_| halt()),
        );
    write_probe_block(device, 10, &mut scratch.0);
    let entries = [
        DirectoryEntry::new(
            StorageName::new("configuration").unwrap_or_else(|_| halt()),
            configuration_object,
            StorageObjectKind::File,
            GENERATION,
        )
        .unwrap_or_else(|_| halt()),
        DirectoryEntry::new(
            StorageName::new("authority-checkpoint").unwrap_or_else(|_| halt()),
            authority_object,
            StorageObjectKind::File,
            GENERATION,
        )
        .unwrap_or_else(|_| halt()),
        DirectoryEntry::new(
            StorageName::new("deployment-checkpoint").unwrap_or_else(|_| halt()),
            deployment_object,
            StorageObjectKind::File,
            GENERATION,
        )
        .unwrap_or_else(|_| halt()),
        DirectoryEntry::new(
            StorageName::new("system-release").unwrap_or_else(|_| halt()),
            release_object,
            StorageObjectKind::File,
            GENERATION,
        )
        .unwrap_or_else(|_| halt()),
    ];
    DirectoryImage::<4>::build(header, root, 2, entries_pointer, &entries)
        .unwrap_or_else(|_| halt())
        .encode(&mut scratch.0)
        .unwrap_or_else(|_| halt());
    write_probe_block(device, 11, &mut scratch.0);

    let files = [
        (configuration_object, configuration_extents, 12, 13, 30, configuration),
        (authority_object, authority_extents, 14, 15, 31, authority_checkpoint),
        (deployment_object, deployment_extents, 16, 17, 32, deployment_checkpoint),
    ];
    for (object, extents_pointer, metadata_block, extents_block, data_block, contents) in files {
        scratch.0[..contents.len()].copy_from_slice(contents);
        let padded_digest = probe_digest(&scratch.0);
        write_probe_block(device, data_block, &mut scratch.0);
        FileMetadata::new(
            header,
            object,
            GENERATION,
            u64::try_from(contents.len()).unwrap_or_else(|_| halt()),
            1,
            extents_pointer,
            probe_digest(contents),
        )
        .unwrap_or_else(|_| halt())
        .encode(
            (&mut scratch.0[..mrml_storage::FILE_METADATA_BYTES])
                .try_into()
                .unwrap_or_else(|_| halt()),
        );
        write_probe_block(device, metadata_block, &mut scratch.0);
        let extent = ExtentRecord::data(
            object,
            GENERATION,
            0,
            1,
            data_block,
            padded_digest,
        )
        .unwrap_or_else(|_| halt());
        ExtentImage::<1>::build(
            header,
            object,
            GENERATION,
            u64::try_from(contents.len()).unwrap_or_else(|_| halt()),
            extents_pointer,
            &[extent],
        )
        .unwrap_or_else(|_| halt())
        .encode(&mut scratch.0)
        .unwrap_or_else(|_| halt());
        write_probe_block(device, extents_block, &mut scratch.0);
    }

    let release_blocks = release_length.div_ceil(PROBE_BLOCK_BYTES);
    let release_padded_length = release_blocks * PROBE_BLOCK_BYTES;
    if release_blocks == 0 || release_padded_length > PROBE_RELEASE_CAPACITY {
        halt();
    }
    let release_padded_digest = probe_digest(&release[..release_padded_length]);
    for block in 0..release_blocks {
        let start = block * PROBE_BLOCK_BYTES;
        scratch.0.copy_from_slice(&release[start..start + PROBE_BLOCK_BYTES]);
        write_probe_block(device, 33 + block as u64, &mut scratch.0);
    }
    FileMetadata::new(
        header,
        release_object,
        GENERATION,
        release_length as u64,
        1,
        release_extents,
        probe_digest(&release[..release_length]),
    )
    .unwrap_or_else(|_| halt())
    .encode(
        (&mut scratch.0[..mrml_storage::FILE_METADATA_BYTES])
            .try_into()
            .unwrap_or_else(|_| halt()),
    );
    write_probe_block(device, 18, &mut scratch.0);
    let release_extent = ExtentRecord::data(
        release_object,
        GENERATION,
        0,
        release_blocks as u32,
        33,
        release_padded_digest,
    )
    .unwrap_or_else(|_| halt());
    ExtentImage::<1>::build(
        header,
        release_object,
        GENERATION,
        release_length as u64,
        release_extents,
        &[release_extent],
    )
    .unwrap_or_else(|_| halt())
    .encode(&mut scratch.0)
    .unwrap_or_else(|_| halt());
    write_probe_block(device, 19, &mut scratch.0);

    let records = [
        AllocationRecord::new(root, 2, 10, 1, AllocationKind::ObjectMetadata).unwrap_or_else(|_| halt()),
        AllocationRecord::new(root, 2, 11, 1, AllocationKind::DirectoryEntries).unwrap_or_else(|_| halt()),
        AllocationRecord::new(configuration_object, GENERATION, 12, 1, AllocationKind::ObjectMetadata).unwrap_or_else(|_| halt()),
        AllocationRecord::new(configuration_object, GENERATION, 13, 1, AllocationKind::FileExtents).unwrap_or_else(|_| halt()),
        AllocationRecord::new(authority_object, GENERATION, 14, 1, AllocationKind::ObjectMetadata).unwrap_or_else(|_| halt()),
        AllocationRecord::new(authority_object, GENERATION, 15, 1, AllocationKind::FileExtents).unwrap_or_else(|_| halt()),
        AllocationRecord::new(deployment_object, GENERATION, 16, 1, AllocationKind::ObjectMetadata).unwrap_or_else(|_| halt()),
        AllocationRecord::new(deployment_object, GENERATION, 17, 1, AllocationKind::FileExtents).unwrap_or_else(|_| halt()),
        AllocationRecord::new(release_object, GENERATION, 18, 1, AllocationKind::ObjectMetadata).unwrap_or_else(|_| halt()),
        AllocationRecord::new(release_object, GENERATION, 19, 1, AllocationKind::FileExtents).unwrap_or_else(|_| halt()),
        AllocationRecord::new(root, ROOT_GENERATION, 20, 1, AllocationKind::AllocationMetadata).unwrap_or_else(|_| halt()),
        AllocationRecord::new(root, ROOT_GENERATION, 21, 1, AllocationKind::ObjectIdAllocatorMetadata).unwrap_or_else(|_| halt()),
        AllocationRecord::new(configuration_object, GENERATION, 30, 1, AllocationKind::FileData).unwrap_or_else(|_| halt()),
        AllocationRecord::new(authority_object, GENERATION, 31, 1, AllocationKind::FileData).unwrap_or_else(|_| halt()),
        AllocationRecord::new(deployment_object, GENERATION, 32, 1, AllocationKind::FileData).unwrap_or_else(|_| halt()),
        AllocationRecord::new(release_object, GENERATION, 33, release_blocks as u32, AllocationKind::FileData).unwrap_or_else(|_| halt()),
    ];
    AllocationImage::<16>::build(header, ROOT_GENERATION, allocation_pointer, &records)
        .unwrap_or_else(|_| halt())
        .encode(&mut scratch.0)
        .unwrap_or_else(|_| halt());
    write_probe_block(device, 20, &mut scratch.0);
    ObjectIdAllocatorImage::build(header, ROOT_GENERATION, Some(13), object_ids_pointer)
        .unwrap_or_else(|_| halt())
        .encode(&mut scratch.0)
        .unwrap_or_else(|_| halt());
    write_probe_block(device, 21, &mut scratch.0);

    let candidate = Superblock::new(
        header,
        ROOT_GENERATION,
        ROOT_GENERATION - 1,
        root,
        root_pointer,
        allocation_pointer,
    )
    .unwrap_or_else(|_| halt());
    let mut encoded = [0; SUPERBLOCK_BYTES];
    candidate.encode(&mut encoded);
    device.replace_superblock(1, &encoded).unwrap_or_else(|_| halt());
    device.flush().unwrap_or_else(|_| halt());
    1
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_configuration_sender(
    endpoint: u64,
    receiver: u64,
    shared_resource: u64,
    setting_capability: u64,
    _generation: u64,
    shared_transfer: u64,
    root_capability: u64,
    shared_read: u64,
) -> ! {
    let mut ready = [0u8; 8 + BOOT_RECOVERY_ENVELOPE_BYTES];
    let mut no_capabilities = [0u64; 0];
    let (length, count) = unsafe { receive_buffer(&mut ready, &mut no_capabilities) };
    if length != ready.len() || count != 0 {
        halt();
    }
    let session = BlockSessionHandle::from_token(u64::from_le_bytes(
        ready[..8].try_into().unwrap_or_else(|_| halt()),
    ))
    .unwrap_or_else(|| halt());
    let recovery_envelope = BootRecoveryEnvelope::decode(
        ready[8..].try_into().unwrap_or_else(|_| halt()),
    )
    .unwrap_or_else(|_| halt());
    let recovery = recovery_envelope.recovery();
    ready.fill(0);
    let release = unsafe { &mut *core::ptr::addr_of_mut!(PROBE_RELEASE_BYTES) };
    release.fill(0);
    let (release_length, deployment_checkpoint, mut deployment_state_store) =
        build_probe_deployment_evidence(release);
    let mut device = RemoteBlockDevice {
        endpoint,
        receiver,
        shared_write: shared_resource,
        shared_read,
        shared_transfer,
        session,
        next_request: 1,
    };

    let setting = SettingId::new(1).unwrap_or_else(|_| halt());
    let schema = SettingSchema::bytes(
        setting,
        CONFIG_SETTING_OBJECT,
        PERSISTED_RESTART_POLICY_BYTES as u8,
    )
    .unwrap_or_else(|_| halt());
    let mut configuration =
        ConfigurationService::<1, 2>::new(CONFIG_ROOT_OBJECT, &[schema]).unwrap_or_else(|_| halt());
    let policy = PersistedRestartPolicy::new(ObjectId(0xa1), 3, 5, 20).unwrap_or_else(|_| halt());
    let mut encoded_policy = [0; PERSISTED_RESTART_POLICY_BYTES];
    policy.encode(&mut encoded_policy);
    let mut update = ConfigTransaction::<1>::new(0);
    update
        .push(ConfigUpdate::new(
            setting,
            Capability::from_token(setting_capability),
            ConfigValue::bytes(&encoded_policy).unwrap_or_else(|_| halt()),
        ))
        .unwrap_or_else(|_| halt());
    configuration
        .commit(
            &KernelAuthorizer,
            Capability::from_token(root_capability),
            &update,
        )
        .unwrap_or_else(|_| halt());
    let mut checkpoint = [0; 512];
    let exported = configuration
        .export_checkpoint(
            &KernelAuthorizer,
            Capability::from_token(root_capability),
            &mut checkpoint,
        )
        .unwrap_or_else(|_| halt());

    let header = probe_header();
    let file_object = probe_object(9);
    let current = FileState::new(
        file_object,
        1,
        0,
        ExtentMap::<0>::build(header, file_object, 1, 0, &[]).unwrap_or_else(|_| halt()),
    )
    .unwrap_or_else(|_| halt());
    let staging = unsafe { &mut *core::ptr::addr_of_mut!(PROBE_SENDER_STAGING) };
    staging.0.fill(0);
    staging.0[..exported.length].copy_from_slice(&checkpoint[..exported.length]);
    let extent = ExtentRecord::data(file_object, 2, 0, 1, 3, probe_digest(&staging.0))
        .unwrap_or_else(|_| halt());
    let next = ExtentMap::<1>::build(header, file_object, 2, exported.length as u64, &[extent])
        .unwrap_or_else(|_| halt());
    let metadata = FileMetadata::new(
        header,
        file_object,
        2,
        exported.length as u64,
        1,
        MetadataPointer::new(4, 1).unwrap_or_else(|_| halt()),
        probe_digest(&checkpoint[..exported.length]),
    )
    .unwrap_or_else(|_| halt());
    staging.0.fill(0);
    extent.encode(
        (&mut staging.0[..mrml_storage::EXTENT_RECORD_BYTES])
            .try_into()
            .unwrap_or_else(|_| halt()),
    );
    let extents_digest = probe_digest(&staging.0);
    device
        .write_blocks(4, &staging.0)
        .unwrap_or_else(|_| halt());
    staging.0.fill(0);
    metadata.encode(
        (&mut staging.0[..mrml_storage::FILE_METADATA_BYTES])
            .try_into()
            .unwrap_or_else(|_| halt()),
    );
    let file_metadata_digest = probe_digest(&staging.0);
    device
        .write_blocks(5, &staging.0)
        .unwrap_or_else(|_| halt());
    staging.0.fill(0x61);
    let root_digest = probe_digest(&staging.0);
    device
        .write_blocks(6, &staging.0)
        .unwrap_or_else(|_| halt());
    staging.0.fill(0x71);
    let allocation_digest = probe_digest(&staging.0);
    device
        .write_blocks(7, &staging.0)
        .unwrap_or_else(|_| halt());
    device.flush().unwrap_or_else(|_| halt());
    let active = Superblock::new(
        header,
        1,
        0,
        probe_object(1),
        MetadataPointer::new(8, 1).unwrap_or_else(|_| halt()),
        MetadataPointer::new(9, 1).unwrap_or_else(|_| halt()),
    )
    .unwrap_or_else(|_| halt());
    let plan = CowPublicationPlan::<4>::build(
        header,
        1,
        active,
        probe_object(1),
        MetadataPointer::new(6, 1).unwrap_or_else(|_| halt()),
        MetadataPointer::new(7, 1).unwrap_or_else(|_| halt()),
        &[
            CowMetadataWrite::new(
                MetadataPointer::new(5, 1).unwrap_or_else(|_| halt()),
                2,
                file_metadata_digest,
            )
            .unwrap_or_else(|_| halt()),
            CowMetadataWrite::new(
                MetadataPointer::new(4, 1).unwrap_or_else(|_| halt()),
                2,
                extents_digest,
            )
            .unwrap_or_else(|_| halt()),
            CowMetadataWrite::new(
                MetadataPointer::new(6, 1).unwrap_or_else(|_| halt()),
                2,
                root_digest,
            )
            .unwrap_or_else(|_| halt()),
            CowMetadataWrite::new(
                MetadataPointer::new(7, 1).unwrap_or_else(|_| halt()),
                2,
                allocation_digest,
            )
            .unwrap_or_else(|_| halt()),
        ],
        &[
            MetadataPointer::new(8, 1).unwrap_or_else(|_| halt()),
            MetadataPointer::new(9, 1).unwrap_or_else(|_| halt()),
        ],
    )
    .unwrap_or_else(|_| halt());
    let principal = StoragePrincipal::new(1).unwrap_or_else(|_| halt());
    let mut authority = StorageAuthorityTable::<1>::new();
    let file = authority
        .insert(
            file_object,
            StorageObjectKind::File,
            StorageRights::READ
                .union(StorageRights::WRITE)
                .union(StorageRights::RESIZE),
            principal,
        )
        .unwrap_or_else(|_| halt());
    let volume_scratch = unsafe { &mut *core::ptr::addr_of_mut!(PROBE_VOLUME_SCRATCH) };
    volume_scratch.0.fill(0);
    let mut volume =
        BlockVolume::new(header, 1, device, &mut volume_scratch.0).unwrap_or_else(|_| halt());
    let file_scratch = unsafe { &mut *core::ptr::addr_of_mut!(PROBE_FILE_SCRATCH) };
    file_scratch.0.fill(0);
    let prepared = prepare_block_stable_configuration(
        &configuration,
        &KernelAuthorizer,
        Capability::from_token(root_capability),
        &current,
        &authority,
        file,
        principal,
        next,
        metadata,
        MetadataPointer::new(5, 1).unwrap_or_else(|_| halt()),
        &[],
        &mut checkpoint,
        &mut volume,
        &mut file_scratch.0,
    )
    .unwrap_or_else(|_| halt());
    let mut transaction = StorageTransaction::<1, 2>::new(
        StorageTransactionId::new(72).unwrap_or_else(|_| halt()),
        2,
    )
    .unwrap_or_else(|_| halt());
    prepared.admit(&mut transaction).unwrap_or_else(|_| halt());
    let mut receipt = transaction
        .publish(&plan, &mut volume)
        .unwrap_or_else(|_| halt());
    let stable = match prepared.commit(&KernelAuthorizer, &authority, &mut receipt) {
        Ok(stable) => stable,
        Err(_) => halt(),
    };
    if receipt.remaining() != 0 || stable.file().generation() != 2 {
        halt();
    }
    let grants = [StorageRecoveryGrant::root(
        principal,
        file_object,
        StorageObjectKind::File,
        StorageRights::READ,
    )];
    let mut authority_bytes = [0; 128];
    let authority_length =
        encode_authority_checkpoint(9, probe_volume(), 2, 3, &grants, &mut authority_bytes)
            .unwrap_or_else(|_| halt());
    let authority_digest = authority_checkpoint_digest(&authority_bytes[..authority_length])
        .unwrap_or_else(|_| halt());
    let admission =
        unsafe { OwnerApprovedAuthorityCheckpoint::new(9, probe_volume(), 2, 3, authority_digest) };
    let mut issuer = AuthorityCheckpointProofIssuer::new(admission);
    let authority_object = probe_object(10);
    let mut authority_backend = ControlledAuthorityCheckpoint::new(authority_object);
    authority_backend.bytes[..authority_length]
        .copy_from_slice(&authority_bytes[..authority_length]);
    authority_bytes.fill(0);
    let authority_file = authority_backend.file(authority_length);
    let mut bootstrap = StorageAuthorityTable::<1>::new();
    let bootstrap_file = bootstrap
        .insert(
            authority_object,
            StorageObjectKind::File,
            StorageRights::READ,
            principal,
        )
        .unwrap_or_else(|_| halt());
    let mut state_store = ControlledRecoveryStateStore::new();
    let mut recovered_scratch = [0xa5; 512];
    let validator = StableConfigurationRecoveryValidator::<1, 2, _, _, _>::new(
        stable.file(),
        0,
        principal,
        2,
        &KernelAuthorizer,
        Capability::from_token(root_capability),
        Capability::from_token(setting_capability),
        setting,
        ObjectId(0xa1),
        &mut recovered_scratch,
        &mut volume,
    );
    let mut validator = validator;
    let mut authority_scratch = [0xa5; 128];
    let (authorities, recovered) = {
        let mut boot_store = BootRecoveryAdmission::new(recovery)
            .unwrap_or_else(|_| halt())
            .bind(&mut state_store);
        recover_validate_and_commit_stable_authorities::<1, 1, 1, _, _, _>(
            &authority_file,
            &bootstrap,
            bootstrap_file,
            principal,
            2,
            &mut issuer,
            &mut authority_scratch,
            &mut authority_backend,
            &mut boot_store,
            &mut validator,
        )
        .unwrap_or_else(|_| halt())
    };
    let bound = recovered.policy();
    if bound.service() != policy.service()
        || bound.configuration_revision() != recovered.configuration().revision()
        || bound.setting_revision() != 1
        || authorities.epoch() != 9
        || state_store.accepted_epoch() != 9
        || authority_scratch.iter().any(|byte| *byte != 0)
        || recovered_scratch.iter().any(|byte| *byte != 0)
    {
        halt();
    }
    let mut device = volume.into_device();
    if device.next_request != 19 {
        halt();
    }
    let active_root = publish_probe_total_recovery_graph(
        &mut device,
        &checkpoint[..exported.length],
        &authority_backend.bytes[..authority_length],
        &deployment_checkpoint,
        release,
        release_length,
    );
    let total_volume_scratch = unsafe { &mut *core::ptr::addr_of_mut!(PROBE_VOLUME_SCRATCH) };
    total_volume_scratch.0.fill(0);
    let primary = unsafe { &mut *core::ptr::addr_of_mut!(PROBE_PRIMARY_SCRATCH) };
    let secondary = unsafe { &mut *core::ptr::addr_of_mut!(PROBE_SECONDARY_SCRATCH) };
    let metadata = unsafe { &mut *core::ptr::addr_of_mut!(PROBE_METADATA_SCRATCH) };
    primary.0.fill(0);
    secondary.0.fill(0);
    metadata.0.fill(0);
    let total = recover_block_stable_total_system_selection::<_, 16, 4, 1, 5>(
        probe_header(),
        active_root,
        device,
        &mut total_volume_scratch.0,
        &mut primary.0,
        &mut secondary.0,
        &mut metadata.0,
        probe_object(9),
        probe_object(10),
        probe_object(11),
        probe_object(12),
    )
    .unwrap_or_else(|_| halt());
    let selected = total.selected();
    if selected.volume() != probe_volume()
        || selected.root_generation() != 14
        || selected.configuration().object() != probe_object(9)
        || selected.authority_checkpoint().object() != probe_object(10)
        || selected.deployment_checkpoint().object() != probe_object(11)
        || selected.system_release().object() != probe_object(12)
    {
        halt();
    }
    let (selection, mut total_volume) = total.into_parts();
    let selected = selection.selected();
    let deployment_root = ObjectId(0x4445_504c_4f59);
    let mut deployment_capabilities = CapabilitySpace::<1>::new();
    let inspect = deployment_capabilities
        .insert(deployment_root, Rights::READ)
        .unwrap_or_else(|_| halt());
    let mut deployment_authority = StorageAuthorityTable::<1>::new();
    let deployment_handle = deployment_authority
        .insert(
            probe_object(11),
            StorageObjectKind::File,
            StorageRights::READ,
            principal,
        )
        .unwrap_or_else(|_| halt());
    let mut release_authority = StorageAuthorityTable::<1>::new();
    let release_handle = release_authority
        .insert(
            probe_object(12),
            StorageObjectKind::File,
            StorageRights::READ,
            principal,
        )
        .unwrap_or_else(|_| halt());
    release.fill(0xa5);
    let mut runtime = recover_selected_runtime_assignment_shared_backend::<1, 1, 1, 1, 1, 1, _, _>(
        deployment_root,
        selected,
        &deployment_authority,
        deployment_handle,
        &release_authority,
        release_handle,
        principal,
        &deployment_state_store,
        &mut total_volume,
        &deployment_capabilities,
        inspect,
        release,
        1,
    )
    .unwrap_or_else(|_| halt());
    runtime
        .assignment_mut()
        .assign_from_policy(|record| {
            mrml_kernel::RuntimeDomainAssignment::new(record.package_id, ObjectId(0x434f_4e46_4947))
        })
        .unwrap_or_else(|_| halt());
    let inventory = runtime
        .seal(&deployment_capabilities)
        .unwrap_or_else(|_| halt());
    if inventory.release().release().len() != 1
        || inventory.release().system_generation() != 33
        || inventory.release().policy_generation() != 1
    {
        halt();
    }
    let device = total_volume.into_device();
    primary.0.fill(0);
    secondary.0.fill(0);
    metadata.0.fill(0);
    state_store.encoded.fill(0);
    deployment_state_store.bytes.fill(0);
    release.fill(0);
    authority_backend.bytes.fill(0);
    let completed = device.next_request.checked_sub(1).unwrap_or_else(|| halt());
    if completed == 0 || completed > PROBE_MAX_BLOCK_REQUESTS as u64 {
        halt();
    }
    let mut completion = encode_probe_block_completion(completed);
    unsafe { send_buffer(endpoint, receiver, &completion, &[]) };
    completion.fill(0);
    unsafe { terminate(3) }
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
fn encode_probe_block_completion(completed: u64) -> [u8; BLOCK_REQUEST_BYTES] {
    let mut encoded = [0u8; BLOCK_REQUEST_BYTES];
    encoded[..8].copy_from_slice(&PROBE_BLOCK_COMPLETION_MAGIC);
    encoded[8..16].copy_from_slice(&completed.to_le_bytes());
    encoded
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
fn decode_probe_block_completion(encoded: &[u8; BLOCK_REQUEST_BYTES]) -> Option<usize> {
    if encoded[..8] != PROBE_BLOCK_COMPLETION_MAGIC || encoded[16..].iter().any(|byte| *byte != 0) {
        return None;
    }
    usize::try_from(u64::from_le_bytes(encoded[8..16].try_into().ok()?)).ok()
}

#[cfg(not(feature = "preemption-probe"))]
#[repr(C, align(8))]
struct CapabilityDescriptorBytes<const N: usize>([u8; N]);

#[cfg(not(feature = "preemption-probe"))]
impl<const N: usize> CapabilityDescriptorBytes<N> {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(not(feature = "preemption-probe"))]
fn capability_descriptors(
    first: (u64, Rights),
    second: (u64, Rights),
) -> CapabilityDescriptorBytes<32> {
    let mut descriptors = CapabilityDescriptorBytes([0u8; 32]);
    for (index, (capability, rights)) in [first, second].into_iter().enumerate() {
        let start = index * 16;
        descriptors.0[start..start + 8].copy_from_slice(&capability.to_le_bytes());
        descriptors.0[start + 8..start + 10].copy_from_slice(&rights.bits().to_le_bytes());
    }
    descriptors
}

#[cfg(not(feature = "preemption-probe"))]
fn capability_descriptor(capability: u64, rights: Rights) -> CapabilityDescriptorBytes<16> {
    let mut descriptor = CapabilityDescriptorBytes([0u8; 16]);
    descriptor.0[..8].copy_from_slice(&capability.to_le_bytes());
    descriptor.0[8..10].copy_from_slice(&rights.bits().to_le_bytes());
    descriptor
}

#[cfg(not(feature = "preemption-probe"))]
unsafe fn send_buffer(endpoint: u64, receiver: u64, payload: &[u8], descriptors: &[u8]) {
    if payload.is_empty()
        || payload.len() > mrml_kernel::MAX_INLINE_PAYLOAD
        || !descriptors
            .len()
            .is_multiple_of(mrml_kernel::CAPABILITY_TRANSFER_DESCRIPTOR_BYTES)
        || descriptors.len()
            > mrml_kernel::MAX_CAPABILITIES * mrml_kernel::CAPABILITY_TRANSFER_DESCRIPTOR_BYTES
        || (!descriptors.is_empty()
            && !(descriptors.as_ptr() as usize)
                .is_multiple_of(mrml_kernel::RECEIVED_CAPABILITY_TOKEN_BYTES))
    {
        halt();
    }
    let mut status = 4u64;
    let descriptor_address = if descriptors.is_empty() {
        0
    } else {
        descriptors.as_ptr() as u64
    };
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") status,
            in("rdi") endpoint,
            in("rsi") receiver,
            inlateout("rdx") payload.as_ptr() as u64 => _,
            in("r10") payload.len() as u64,
            in("r8") descriptor_address,
            in("r9") (descriptors.len() / mrml_kernel::CAPABILITY_TRANSFER_DESCRIPTOR_BYTES) as u64,
            options(nostack)
        )
    };
    if status != 0 {
        halt();
    }
}

#[cfg(not(feature = "preemption-probe"))]
unsafe fn receive_buffer(payload: &mut [u8], capabilities: &mut [u64]) -> (usize, usize) {
    let mut status = 5u64;
    let capability_address = if capabilities.is_empty() {
        0
    } else {
        capabilities.as_mut_ptr() as u64
    };
    let payload_length: u64;
    let capability_count: u64;
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") status,
            in("rdi") payload.as_mut_ptr() as u64,
            in("rsi") payload.len() as u64,
            inlateout("rdx") capability_address => payload_length,
            inlateout("r10") capabilities.len() as u64 => capability_count,
            inlateout("r8") 0u64 => _,
            inlateout("r9") 0u64 => _,
            options(nostack)
        )
    };
    if status != 0 {
        halt();
    }
    let payload_length = usize::try_from(payload_length).unwrap_or_else(|_| halt());
    let capability_count = usize::try_from(capability_count).unwrap_or_else(|_| halt());
    if payload_length > payload.len() || capability_count > capabilities.len() {
        halt();
    }
    (payload_length, capability_count)
}

#[cfg(not(feature = "preemption-probe"))]
unsafe fn release_received_capabilities(capabilities: &[Capability]) {
    for capability in capabilities {
        let mut status = 12u64;
        unsafe {
            asm!(
                "int 0x80",
                inlateout("rax") status,
                in("rdi") capability.token(),
                in("rsi") 0u64,
                in("rdx") 0u64,
                in("r10") 0u64,
                in("r8") 0u64,
                in("r9") 0u64,
                options(nostack)
            )
        };
        if status != 0 {
            halt();
        }
    }
}

/// Concrete x86-64 syscall boundary for the block-service loop. The endpoint,
/// reply task are trusted launch state; the loop receives its authenticated
/// principal separately from launch state. Block request bytes can select none
/// of them.
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
#[allow(dead_code)]
struct UserspaceBlockSyscalls {
    endpoint: u64,
    reply_task: u64,
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
unsafe impl BlockServiceSyscalls for UserspaceBlockSyscalls {
    type Error = u64;

    fn receive(
        &mut self,
        payload: &mut [u8; BLOCK_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedBlockEnvelope, Self::Error> {
        let mut status = 5u64;
        let payload_length: u64;
        let capability_count: u64;
        unsafe {
            asm!(
                "int 0x80",
                inlateout("rax") status,
                in("rdi") payload.as_mut_ptr() as u64,
                in("rsi") payload.len() as u64,
                inlateout("rdx") capability_tokens.as_mut_ptr() as u64 => payload_length,
                inlateout("r10") capability_tokens.len() as u64 => capability_count,
                inlateout("r8") 0u64 => _,
                inlateout("r9") 0u64 => _,
                options(nostack)
            )
        };
        if status != 0 {
            return Err(status);
        }
        let payload_length = usize::try_from(payload_length).map_err(|_| u64::MAX)?;
        let capability_count = usize::try_from(capability_count).map_err(|_| u64::MAX)?;
        if payload_length > payload.len() || capability_count > capability_tokens.len() {
            return Err(u64::MAX);
        }
        Ok(ReceivedBlockEnvelope {
            payload_length,
            capability_count,
        })
    }

    fn read_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        shared_buffer_call(7, capability, offset, output.as_mut_ptr(), output.len())
    }

    fn write_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Self::Error> {
        shared_buffer_call(
            8,
            capability,
            offset,
            input.as_ptr().cast_mut(),
            input.len(),
        )
    }

    fn send_response(&mut self, response: &[u8; BLOCK_RESPONSE_BYTES]) -> Result<(), Self::Error> {
        let mut status = 4u64;
        unsafe {
            asm!(
                "int 0x80",
                inlateout("rax") status,
                in("rdi") self.endpoint,
                in("rsi") self.reply_task,
                inlateout("rdx") response.as_ptr() as u64 => _,
                in("r10") response.len() as u64,
                in("r8") 0u64,
                in("r9") 0u64,
                options(nostack)
            )
        };
        if status == 0 { Ok(()) } else { Err(status) }
    }

    fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error> {
        let mut status = 12u64;
        unsafe {
            asm!(
                "int 0x80",
                inlateout("rax") status,
                in("rdi") capability.token(),
                in("rsi") 0u64,
                in("rdx") 0u64,
                in("r10") 0u64,
                in("r8") 0u64,
                in("r9") 0u64,
                options(nostack)
            )
        };
        if status == 0 { Ok(()) } else { Err(status) }
    }
}

#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
#[allow(dead_code)]
fn shared_buffer_call(
    operation: u64,
    capability: Capability,
    offset: u64,
    buffer: *mut u8,
    length: usize,
) -> Result<(), u64> {
    let mut status = operation;
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") status,
            in("rdi") capability.token(),
            in("rsi") offset,
            in("rdx") buffer as u64,
            in("r10") length as u64,
            in("r8") 0u64,
            in("r9") 0u64,
            options(nostack)
        )
    };
    if status == 0 { Ok(()) } else { Err(status) }
}

#[cfg(not(feature = "preemption-probe"))]
unsafe fn terminate(operation: u64) -> ! {
    unsafe {
        asm!(
            "int 0x80",
            in("rax") operation,
            in("rdi") 0u64,
            in("rsi") 0u64,
            in("rdx") 0u64,
            in("r10") 0u64,
            in("r8") 0u64,
            in("r9") 0u64,
            options(noreturn, nostack)
        )
    }
}

#[cfg(feature = "preemption-probe")]
global_asm!(
    r#"
            .section .text
            .global efi_main
        efi_main:
        1:
            pause
            jmp 1b

            .org efi_main + 128, 0xcc
            .global mrml_service_sender
        mrml_service_sender:
            int3
        2:
            pause
            jmp 2b
    "#
);

fn halt() -> ! {
    unsafe {
        asm!(
            "cli",
            "2:",
            "hlt",
            "jmp 2b",
            options(noreturn, nomem, nostack)
        )
    }
}
