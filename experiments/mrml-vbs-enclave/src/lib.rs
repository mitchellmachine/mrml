#![no_std]

use core::ffi::c_void;
#[cfg(any(target_os = "windows", test))]
use mrml_kernel::{
    AUTHORITY_RECEIPT_BYTES, AuthorityReceipt, LAUNCH_REQUEST_BYTES, LaunchRequest,
    ProtectionBackend, ProtectionClaims, ProtectionPolicy, ProtectionReport,
};
#[cfg(target_os = "windows")]
use mrml_kernel::{VBS_AUTHORITY_CONTEXT_BYTES, VbsAuthorityContext, VbsAuthorityOperation};

#[cfg(any(target_os = "windows", test))]
const AUTHORITY_KEY: [u8; 32] = [0x39; 32];
#[cfg(any(target_os = "windows", test))]
const AUTHORITY_MEASUREMENT: [u8; 64] = [0x51; 64];
#[cfg(any(target_os = "windows", test))]
const AUTHORITY_SECURITY_VERSION: u64 = 1;

#[cfg(any(target_os = "windows", test))]
fn authority_policy() -> ProtectionPolicy {
    ProtectionPolicy::new(
        ProtectionBackend::VbsEnclave,
        ProtectionClaims::VTL0_ISOLATION.union(ProtectionClaims::MEASURED),
        false,
        AUTHORITY_SECURITY_VERSION,
        AUTHORITY_MEASUREMENT,
    )
}

#[cfg(target_os = "windows")]
#[link(name = "vertdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn EnclaveCopyIntoEnclave(
        enclave_address: *mut c_void,
        untrusted_address: *const c_void,
        bytes: usize,
    ) -> i32;
    fn EnclaveCopyOutOfEnclave(
        untrusted_address: *mut c_void,
        enclave_address: *const c_void,
        bytes: usize,
    ) -> i32;
    fn EnclaveUsesAttestedKeys() -> u8;
}

#[cfg(target_os = "windows")]
#[link(name = "vertdll", kind = "raw-dylib")]
#[allow(dead_code)]
unsafe extern "C" {
    #[link_name = "memcpy"]
    fn vertdll_memcpy(destination: *mut c_void, source: *const c_void, bytes: usize)
    -> *mut c_void;
    #[link_name = "memset"]
    fn vertdll_memset(destination: *mut c_void, value: i32, bytes: usize) -> *mut c_void;
    #[link_name = "memcmp"]
    fn vertdll_memcmp(left: *const c_void, right: *const c_void, bytes: usize) -> i32;
}

#[cfg(target_os = "windows")]
core::arch::global_asm!(
    r#"
    .section .rdata$mrmlcfg,"dr"
    .p2align 2
    .globl mrml_guard_function_table
mrml_guard_function_table:
    .rva DllMain
    .rva mrml_authority_probe
    .rva mrml_launch_authority
"#
);

#[cfg(target_os = "windows")]
unsafe extern "C" {
    static mrml_guard_function_table: u32;
}

const ENCLAVE_BYTES: u64 = 2 * 1024 * 1024;
const IMAGE_ENCLAVE_POLICY_STRICT_MEMORY: u32 = 2;
const IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE: u32 = 1;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ImageEnclaveConfig64 {
    size: u32,
    minimum_required_config_size: u32,
    policy_flags: u32,
    number_of_imports: u32,
    import_list: u32,
    import_entry_size: u32,
    family_id: [u8; 16],
    image_id: [u8; 16],
    image_version: u32,
    security_version: u32,
    enclave_size: u64,
    number_of_threads: u32,
    enclave_flags: u32,
}

const _: () = assert!(core::mem::size_of::<ImageEnclaveConfig64>() == 80);

#[unsafe(no_mangle)]
pub static __enclave_config: ImageEnclaveConfig64 = ImageEnclaveConfig64 {
    size: 80,
    minimum_required_config_size: 80,
    policy_flags: IMAGE_ENCLAVE_POLICY_STRICT_MEMORY,
    number_of_imports: 0,
    import_list: 0,
    import_entry_size: 0,
    family_id: *b"MRML-VBS-FAMILY!",
    image_id: *b"MRML-AUTHORITY!!",
    image_version: 1,
    security_version: 1,
    enclave_size: ENCLAVE_BYTES,
    number_of_threads: 1,
    enclave_flags: IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE,
};

#[derive(Clone, Copy)]
#[repr(C)]
struct ImageLoadConfigCodeIntegrity {
    flags: u16,
    catalog: u16,
    catalog_offset: u32,
    reserved: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct ImageLoadConfigDirectory64 {
    size: u32,
    timestamp: u32,
    major_version: u16,
    minor_version: u16,
    global_flags_clear: u32,
    global_flags_set: u32,
    critical_section_timeout: u32,
    decommit_free_block_threshold: u64,
    decommit_total_free_threshold: u64,
    lock_prefix_table: u64,
    maximum_allocation_size: u64,
    virtual_memory_threshold: u64,
    process_affinity_mask: u64,
    process_heap_flags: u32,
    csd_version: u16,
    dependent_load_flags: u16,
    edit_list: u64,
    security_cookie: u64,
    se_handler_table: u64,
    se_handler_count: u64,
    guard_cf_check: u64,
    guard_cf_dispatch: u64,
    guard_cf_function_table: *const u32,
    guard_cf_function_count: u64,
    guard_flags: u32,
    code_integrity: ImageLoadConfigCodeIntegrity,
    guard_address_taken_iat_table: u64,
    guard_address_taken_iat_count: u64,
    guard_long_jump_table: u64,
    guard_long_jump_count: u64,
    dynamic_value_reloc_table: u64,
    chpe_metadata: u64,
    guard_rf_failure_routine: u64,
    guard_rf_failure_routine_pointer: u64,
    dynamic_value_reloc_table_offset: u32,
    dynamic_value_reloc_table_section: u16,
    reserved2: u16,
    guard_rf_verify_stack_pointer: u64,
    hot_patch_table_offset: u32,
    reserved3: u32,
    enclave_configuration_pointer: *const ImageEnclaveConfig64,
}

unsafe impl Sync for ImageLoadConfigDirectory64 {}

const _: () = assert!(core::mem::size_of::<ImageLoadConfigDirectory64>() == 256);
const _: () = assert!(
    core::mem::offset_of!(ImageLoadConfigDirectory64, enclave_configuration_pointer) == 248
);

#[used]
#[unsafe(no_mangle)]
static _load_config_used: ImageLoadConfigDirectory64 = ImageLoadConfigDirectory64 {
    size: 256,
    timestamp: 0,
    major_version: 0,
    minor_version: 0,
    global_flags_clear: 0,
    global_flags_set: 0,
    critical_section_timeout: 0,
    decommit_free_block_threshold: 0,
    decommit_total_free_threshold: 0,
    lock_prefix_table: 0,
    maximum_allocation_size: 0,
    virtual_memory_threshold: 0,
    process_affinity_mask: 0,
    process_heap_flags: 0,
    csd_version: 0,
    dependent_load_flags: 0,
    edit_list: 0,
    security_cookie: 0,
    se_handler_table: 0,
    se_handler_count: 0,
    guard_cf_check: 0,
    guard_cf_dispatch: 0,
    #[cfg(target_os = "windows")]
    guard_cf_function_table: core::ptr::addr_of!(mrml_guard_function_table),
    #[cfg(not(target_os = "windows"))]
    guard_cf_function_table: core::ptr::null(),
    guard_cf_function_count: 3,
    // The image publishes a sorted valid-call-target table and deliberately
    // does not claim compiler CFG instrumentation while the dispatch/check
    // pointers above remain absent.
    guard_flags: 0x0000_0400 | 0x0000_0800,
    code_integrity: ImageLoadConfigCodeIntegrity {
        flags: 0,
        catalog: 0,
        catalog_offset: 0,
        reserved: 0,
    },
    guard_address_taken_iat_table: 0,
    guard_address_taken_iat_count: 0,
    guard_long_jump_table: 0,
    guard_long_jump_count: 0,
    dynamic_value_reloc_table: 0,
    chpe_metadata: 0,
    guard_rf_failure_routine: 0,
    guard_rf_failure_routine_pointer: 0,
    dynamic_value_reloc_table_offset: 0,
    dynamic_value_reloc_table_section: 0,
    reserved2: 0,
    guard_rf_verify_stack_pointer: 0,
    hot_patch_table_offset: 0,
    reserved3: 0,
    enclave_configuration_pointer: core::ptr::from_ref(&__enclave_config),
};

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_: *mut c_void, _: u32, _: *mut c_void) -> i32 {
    1
}

/// Minimal call-boundary proof. It never dereferences host memory; strict-memory
/// authority messages will use explicit enclave copy APIs in the next stage.
#[unsafe(no_mangle)]
pub extern "system" fn mrml_authority_probe(context: *mut c_void) -> *mut c_void {
    ((context as usize) ^ 0x4d52_4d4c) as *mut c_void
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
#[cfg(target_os = "windows")]
enum AuthorityStatus {
    Success = 0,
    ContextCopyFailed = 1,
    InvalidContext = 2,
    RequestCopyFailed = 3,
    RequestRejected = 4,
    ReceiptCopyFailed = 5,
    UnsafeKeyPlatform = 6,
}

#[cfg(any(target_os = "windows", test))]
fn process_authority_request(
    encoded_request: &[u8; LAUNCH_REQUEST_BYTES],
    uses_attested_keys: bool,
) -> Result<[u8; AUTHORITY_RECEIPT_BYTES], ()> {
    if !uses_attested_keys {
        return Err(());
    }
    let request = LaunchRequest::decode(encoded_request).map_err(|_| ())?;
    if request.image_measurement() != AUTHORITY_MEASUREMENT
        || request.policy_measurement() != authority_policy().commitment()
    {
        return Err(());
    }
    let claims = ProtectionClaims::VTL0_ISOLATION.union(ProtectionClaims::MEASURED);
    let report = ProtectionReport::new(
        ProtectionBackend::VbsEnclave,
        claims,
        false,
        AUTHORITY_SECURITY_VERSION,
        request.sequence(),
        request.image_measurement(),
        request.nonce(),
    )
    .map_err(|_| ())?;
    AuthorityReceipt::seal(&AUTHORITY_KEY, request, report).map_err(|_| ())
}

/// Strict-memory VTL1 authority entry. The host context and its buffers are
/// never dereferenced directly; Vertdll performs both boundary copies.
#[cfg(target_os = "windows")]
#[unsafe(no_mangle)]
pub extern "system" fn mrml_launch_authority(context: *mut c_void) -> *mut c_void {
    let mut encoded_context = [0; VBS_AUTHORITY_CONTEXT_BYTES];
    // SAFETY: `encoded_context` is enclave-local writable memory. Vertdll validates and
    // copies from the untrusted pointer without direct enclave dereference.
    if unsafe {
        EnclaveCopyIntoEnclave(
            encoded_context.as_mut_ptr().cast(),
            context.cast_const(),
            encoded_context.len(),
        )
    } != 0
    {
        return AuthorityStatus::ContextCopyFailed as usize as *mut c_void;
    }
    let Ok(call) = VbsAuthorityContext::decode(&encoded_context) else {
        return AuthorityStatus::InvalidContext as usize as *mut c_void;
    };
    if call.operation() != VbsAuthorityOperation::IssueReceipt
        || call.input_bytes() != LAUNCH_REQUEST_BYTES as u64
        || call.output_bytes() != AUTHORITY_RECEIPT_BYTES as u64
    {
        return AuthorityStatus::InvalidContext as usize as *mut c_void;
    }
    let (Ok(request_address), Ok(receipt_address)) = (
        usize::try_from(call.input_address()),
        usize::try_from(call.output_address()),
    ) else {
        return AuthorityStatus::InvalidContext as usize as *mut c_void;
    };
    let mut request = [0; LAUNCH_REQUEST_BYTES];
    // SAFETY: destination is enclave-local and exact-sized; source remains an
    // untrusted address handled exclusively by the Vertdll copy primitive.
    if unsafe {
        EnclaveCopyIntoEnclave(
            request.as_mut_ptr().cast(),
            (request_address as *const u8).cast(),
            request.len(),
        )
    } != 0
    {
        return AuthorityStatus::RequestCopyFailed as usize as *mut c_void;
    }
    // SAFETY: this zero-argument Vertdll query is available only inside a VBS
    // enclave and returns a Windows BOOLEAN. False means receipt issuance must
    // fail closed because debugger or TPM key-provisioning guarantees are absent.
    if unsafe { EnclaveUsesAttestedKeys() } == 0 {
        return AuthorityStatus::UnsafeKeyPlatform as usize as *mut c_void;
    }
    let receipt = match process_authority_request(&request, true) {
        Ok(receipt) => receipt,
        Err(()) => return AuthorityStatus::RequestRejected as usize as *mut c_void,
    };
    // SAFETY: source is enclave-local and exact-sized; destination remains an
    // untrusted address handled exclusively by the Vertdll copy primitive.
    if unsafe {
        EnclaveCopyOutOfEnclave(
            (receipt_address as *mut u8).cast(),
            receipt.as_ptr().cast(),
            receipt.len(),
        )
    } != 0
    {
        return AuthorityStatus::ReceiptCopyFailed as usize as *mut c_void;
    }
    AuthorityStatus::Success as usize as *mut c_void
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_configuration_is_strict_primary_and_non_debug() {
        assert_eq!(core::mem::size_of::<ImageEnclaveConfig64>(), 80);
        assert_eq!(
            __enclave_config.policy_flags,
            IMAGE_ENCLAVE_POLICY_STRICT_MEMORY
        );
        assert_eq!(
            __enclave_config.enclave_flags,
            IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE
        );
        assert_eq!(__enclave_config.enclave_size, ENCLAVE_BYTES);
        assert_eq!(__enclave_config.number_of_threads, 1);
        assert_eq!(core::mem::size_of::<ImageLoadConfigDirectory64>(), 256);
        assert_eq!(
            _load_config_used.enclave_configuration_pointer,
            core::ptr::from_ref(&__enclave_config)
        );
    }

    #[test]
    fn call_probe_never_dereferences_untrusted_context() {
        let context = 0x1234usize as *mut c_void;
        assert_eq!(
            mrml_authority_probe(context) as usize,
            0x1234usize ^ 0x4d52_4d4c
        );
    }

    #[test]
    fn authority_emits_bound_non_debug_vbs_receipt() {
        let request = LaunchRequest::new(
            9,
            [0xa2; 32],
            AUTHORITY_MEASUREMENT,
            authority_policy().commitment(),
        )
        .unwrap();
        let receipt = process_authority_request(&request.encode(), true).unwrap();
        let verified = AuthorityReceipt::verify(&AUTHORITY_KEY, request, &receipt).unwrap();
        assert_eq!(verified.report().backend(), ProtectionBackend::VbsEnclave);
        assert_eq!(
            verified.report().claims(),
            ProtectionClaims::VTL0_ISOLATION.union(ProtectionClaims::MEASURED)
        );
    }

    #[test]
    fn authority_rejects_unapproved_measurement_and_malformed_request() {
        let wrong =
            LaunchRequest::new(9, [0xa2; 32], [0x52; 64], authority_policy().commitment()).unwrap();
        assert_eq!(process_authority_request(&wrong.encode(), true), Err(()));
        let wrong_policy =
            LaunchRequest::new(9, [0xa2; 32], AUTHORITY_MEASUREMENT, [0x73; 64]).unwrap();
        assert_eq!(
            process_authority_request(&wrong_policy.encode(), true),
            Err(())
        );
        let mut malformed = wrong.encode();
        malformed[0] ^= 1;
        assert_eq!(process_authority_request(&malformed, true), Err(()));
    }

    #[test]
    fn authority_refuses_receipts_without_safe_attested_keys() {
        let request = LaunchRequest::new(
            9,
            [0xa2; 32],
            AUTHORITY_MEASUREMENT,
            authority_policy().commitment(),
        )
        .unwrap();
        assert_eq!(process_authority_request(&request.encode(), false), Err(()));
    }
}
