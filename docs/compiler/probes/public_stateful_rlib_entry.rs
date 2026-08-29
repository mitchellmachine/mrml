#![no_std]

unsafe extern "C" {
    fn state_answer() -> i32;
}

#[unsafe(no_mangle)]
pub extern "C" fn start() -> i32 {
    unsafe { state_answer() }
}
