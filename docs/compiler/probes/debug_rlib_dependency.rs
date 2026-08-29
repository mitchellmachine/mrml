#![no_std]

#[unsafe(no_mangle)]
pub extern "C" fn helper() -> u64 {
    42
}
