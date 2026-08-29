#![no_std]

#[unsafe(no_mangle)]
pub extern "C" fn thin_leaf() -> u64 {
    42
}
