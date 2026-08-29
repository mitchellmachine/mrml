#![no_std]

unsafe extern "C" {
    fn helper() -> u64;
}

#[unsafe(no_mangle)]
pub extern "C" fn entry() -> u64 {
    unsafe { helper() }
}
