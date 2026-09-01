#![no_std]

#[unsafe(no_mangle)]
pub extern "C" fn profile_indirect(
    value: u64,
    callback: extern "C" fn(u64) -> u64,
) -> u64 {
    callback(value)
}
