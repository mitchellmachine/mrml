#![no_std]

use core::ffi::c_void;

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
