#![no_std]

#[unsafe(no_mangle)]
pub extern "C" fn thin_helper() -> u64 {
    unsafe extern "C" {
        fn thin_leaf() -> u64;
    }
    unsafe { thin_leaf() }
}
