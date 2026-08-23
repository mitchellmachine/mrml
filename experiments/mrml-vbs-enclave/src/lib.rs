#![no_std]

use core::ffi::c_void;

#[cfg(target_os = "windows")]
core::arch::global_asm!(
    r#"
    .section .rdata$mrmlcfg,"dr"
    .p2align 2
    .globl mrml_guard_function_table
mrml_guard_function_table:
    .rva DllMain
    .rva mrml_authority_probe
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
    guard_cf_function_count: 2,
    guard_flags: 0x0000_0100 | 0x0000_0400 | 0x0000_0800,
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

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
}
