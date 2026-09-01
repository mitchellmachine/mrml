#![no_std]

#[unsafe(no_mangle)]
pub extern "C" fn profiled_condition(first: bool, second: bool, third: bool) -> u64 {
    if first && (second || third) { 1 } else { 2 }
}
