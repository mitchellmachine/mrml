#![no_std]
#![no_main]

use core::arch::{asm, global_asm};

#[cfg(not(feature = "preemption-probe"))]
use mrml_config::{
    CONFIG_RESPONSE_BYTES, CapabilityAuthorizer, ConfigError, ConfigTransaction, ConfigUpdate,
    ConfigValue, ConfigurationResponse, ConfigurationService, MAX_CONFIG_REQUEST_BYTES,
    ResponseStatus, SettingId, SettingSchema, dispatch_configuration_envelope,
    encode_commit_message_request,
};
#[cfg(not(feature = "preemption-probe"))]
use mrml_kernel::{Capability, CapabilityError, ObjectId, Rights};

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
            call mrml_configuration_sender
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
#[unsafe(no_mangle)]
unsafe extern "sysv64" fn mrml_configuration_receiver(
    endpoint: u64,
    sender: u64,
    generation: u64,
) -> ! {
    let setting = SettingId::new(1).unwrap_or_else(|_| halt());
    let configuration = core::ptr::addr_of_mut!(CONFIGURATION);
    if unsafe { (*configuration).is_none() } {
        let schema =
            SettingSchema::boolean(setting, CONFIG_SETTING_OBJECT).unwrap_or_else(|_| halt());
        unsafe {
            configuration.write(Some(
                ConfigurationService::new(CONFIG_ROOT_OBJECT, &[schema]).unwrap_or_else(|_| halt()),
            ))
        };
    }
    let mut request = [0u8; mrml_config::MAX_CONFIG_REQUEST_BYTES];
    let mut capability_tokens = [0u64; mrml_kernel::MAX_CAPABILITIES];
    let (request_length, capability_count) =
        unsafe { receive_buffer(&mut request, &mut capability_tokens) };
    let mut capabilities = [Capability::from_token(0); mrml_kernel::MAX_CAPABILITIES];
    for (slot, token) in capabilities.iter_mut().zip(capability_tokens) {
        *slot = Capability::from_token(token);
    }
    let mut response = [0u8; CONFIG_RESPONSE_BYTES];
    let prior_revision = unsafe {
        (*configuration)
            .as_ref()
            .unwrap_or_else(|| halt())
            .revision()
    };
    dispatch_configuration_envelope(
        unsafe { (*configuration).as_mut().unwrap_or_else(|| halt()) },
        &KernelAuthorizer,
        &request[..request_length],
        &capabilities[..capability_count],
        &mut response,
    )
    .unwrap_or_else(|_| halt());
    let decoded = ConfigurationResponse::decode(&response).unwrap_or_else(|_| halt());
    let expected_revision = prior_revision.checked_add(1).unwrap_or_else(|| halt());
    if decoded.request_id != generation
        || decoded.status != ResponseStatus::Ok
        || decoded.revision != expected_revision
        || decoded.setting.is_some()
        || decoded.value.is_some()
    {
        halt();
    }
    unsafe { send_buffer(endpoint, sender, &response, &[]) };
    unsafe { yield_now() };
    unsafe { asm!("int3", options(noreturn, nostack)) }
}

#[cfg(not(feature = "preemption-probe"))]
unsafe fn verify_response(response: &[u8; CONFIG_RESPONSE_BYTES], generation: u64) {
    let decoded = ConfigurationResponse::decode(response).unwrap_or_else(|_| halt());
    if decoded.request_id != generation
        || decoded.status != ResponseStatus::Ok
        || decoded.revision != 1
        || decoded.setting.is_some()
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
) -> ! {
    let mut transaction = ConfigTransaction::<1>::new(0);
    transaction
        .push(ConfigUpdate::new(
            SettingId::new(1).unwrap_or_else(|_| halt()),
            Capability::from_token(0),
            ConfigValue::boolean(generation == 1),
        ))
        .unwrap_or_else(|_| halt());
    let mut request = [0u8; MAX_CONFIG_REQUEST_BYTES];
    let request_length = encode_commit_message_request(generation, &transaction, &mut request)
        .unwrap_or_else(|_| halt());
    let descriptors = capability_descriptors(
        (root_capability, Rights::CONTROL),
        (setting_capability, Rights::WRITE),
    );
    unsafe { send_buffer(endpoint, receiver, &request[..request_length], &descriptors) };
    let mut response = [0u8; CONFIG_RESPONSE_BYTES];
    let mut no_capabilities = [0u64; 0];
    let (length, count) = unsafe { receive_buffer(&mut response, &mut no_capabilities) };
    if length != CONFIG_RESPONSE_BYTES || count != 0 {
        halt();
    }
    unsafe { verify_response(&response, generation) };
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
