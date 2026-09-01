#![no_std]

#[unsafe(no_mangle)]
pub extern "C" fn profiled_value(value: u64) -> u64 {
    if value == 0 { 1 } else { 2 }
}
