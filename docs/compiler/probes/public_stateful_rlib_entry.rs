#![no_std]

unsafe extern "C" {
    fn state_answer() -> i32;
    static mut EXPORTED_INITIALIZED: i32;
    static mut EXPORTED_ZERO_FILL: i32;
}

#[unsafe(no_mangle)]
pub extern "C" fn start() -> i32 {
    unsafe { state_answer() + EXPORTED_INITIALIZED + EXPORTED_ZERO_FILL - 40 }
}
