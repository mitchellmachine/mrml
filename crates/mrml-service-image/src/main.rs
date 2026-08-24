#![no_std]
#![no_main]

use core::arch::{asm, global_asm};

#[cfg(not(feature = "preemption-probe"))]
use mrml_config::{
    CONFIG_RESPONSE_BYTES, CapabilityAuthorizer, ConfigError, ConfigTransaction, ConfigUpdate,
    ConfigValue, ConfigurationResponse, ConfigurationService, MAX_CONFIG_REQUEST_BYTES,
    ResponseStatus, SUPERVISION_REQUEST_BYTES, SUPERVISION_RESPONSE_BYTES,
    ServiceRestartAuthorizer, ServiceStateAuthorizer, SettingId, SettingSchema,
    SupervisionOperation, SupervisionRequest, SupervisionResponse, SupervisionState,
    dispatch_configuration_envelope, dispatch_supervision_query_envelope,
    dispatch_supervision_restart_envelope, encode_commit_message_request,
    encode_schema_message_request,
};
#[cfg(not(feature = "preemption-probe"))]
use mrml_kernel::{Capability, CapabilityError, ObjectId, Rights, ServiceId, ServiceState};
#[cfg(all(not(feature = "preemption-probe"), feature = "block-service-loop"))]
use mrml_storage::{
    BLOCK_REQUEST_BYTES, BLOCK_RESPONSE_BYTES, BlockServiceSyscalls, ReceivedBlockEnvelope,
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
            sub rsp, 16
            mov [rsp], r10
            call mrml_configuration_sender
            ud2

            .org efi_main + 1024, 0xcc
            .global mrml_service_manager
        mrml_service_manager:
            mov rdi, r13
            mov rsi, r14
            mov rdx, r15
            mov rcx, rbx
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
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_configuration_receiver(
    endpoint: u64,
    sender: u64,
    generation: u64,
    shared_write: u64,
    shared_read: u64,
    restart_manager: u64,
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
    unsafe { yield_now() };
    if restart_manager != 0 {
        unsafe { send_buffer(endpoint, restart_manager, b"restart-ready", &[]) };
        unsafe { dispatch_supervision_restart(endpoint, restart_manager, 0x501) };
        unsafe { yield_now() };
        halt();
    }
    unsafe { asm!("int3", options(noreturn, nostack)) }
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
    }
    .encode(&mut request)
    .unwrap_or_else(|_| halt());
    let descriptor = capability_descriptor(control, Rights::CONTROL);
    unsafe { send_buffer(endpoint, receiver, &request, &descriptor) };
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

#[cfg(not(feature = "preemption-probe"))]
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
    let schema = SettingSchema::boolean(setting, CONFIG_SETTING_OBJECT).unwrap_or_else(|_| halt());
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
            &root_descriptor,
        )
    };
    let mut response = [0u8; CONFIG_RESPONSE_BYTES];
    let mut no_capabilities = [0u64; 0];
    let (length, count) = unsafe { receive_buffer(&mut response, &mut no_capabilities) };
    if length != CONFIG_RESPONSE_BYTES || count != 0 {
        halt();
    }
    unsafe { verify_response(&response, schema_request_id, 0, Some(setting)) };

    let mut transaction = ConfigTransaction::<1>::new(0);
    transaction
        .push(ConfigUpdate::new(
            setting,
            Capability::from_token(0),
            ConfigValue::boolean(generation == 1),
        ))
        .unwrap_or_else(|_| halt());
    let mut request = [0u8; MAX_CONFIG_REQUEST_BYTES];
    let commit_request_id = generation.checked_mul(2).unwrap_or_else(|| halt());
    let request_length =
        encode_commit_message_request(commit_request_id, &transaction, &mut request)
            .unwrap_or_else(|_| halt());
    let descriptors = capability_descriptors(
        (root_capability, Rights::CONTROL),
        (setting_capability, Rights::WRITE),
    );
    unsafe { send_buffer(endpoint, receiver, &request[..request_length], &descriptors) };
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
    }
    .encode(&mut supervision_request)
    .unwrap_or_else(|_| halt());
    let supervision_descriptor = capability_descriptor(supervision_read, Rights::READ);
    unsafe {
        send_buffer(
            endpoint,
            receiver,
            &supervision_request,
            &supervision_descriptor,
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
    if generation == 2 {
        unsafe { receive_buffer(&mut response, &mut no_capabilities) };
        halt();
    }
    unsafe { terminate(3) }
}

#[cfg(not(feature = "preemption-probe"))]
fn capability_descriptors(first: (u64, Rights), second: (u64, Rights)) -> [u8; 32] {
    let mut descriptors = [0u8; 32];
    for (index, (capability, rights)) in [first, second].into_iter().enumerate() {
        let start = index * 16;
        descriptors[start..start + 8].copy_from_slice(&capability.to_le_bytes());
        descriptors[start + 8..start + 10].copy_from_slice(&rights.bits().to_le_bytes());
    }
    descriptors
}

#[cfg(not(feature = "preemption-probe"))]
fn capability_descriptor(capability: u64, rights: Rights) -> [u8; 16] {
    let mut descriptor = [0u8; 16];
    descriptor[..8].copy_from_slice(&capability.to_le_bytes());
    descriptor[8..10].copy_from_slice(&rights.bits().to_le_bytes());
    descriptor
}

#[cfg(not(feature = "preemption-probe"))]
unsafe fn send_buffer(endpoint: u64, receiver: u64, payload: &[u8], descriptors: &[u8]) {
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
            in("r9") (descriptors.len() / 16) as u64,
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
    (payload_length as usize, capability_count as usize)
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
        Ok(ReceivedBlockEnvelope {
            payload_length: usize::try_from(payload_length).map_err(|_| u64::MAX)?,
            capability_count: usize::try_from(capability_count).map_err(|_| u64::MAX)?,
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
