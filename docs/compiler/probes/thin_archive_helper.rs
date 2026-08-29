#![no_std]

#[unsafe(no_mangle)]
pub extern "C" fn thin_helper() -> u64 {
    42
}
