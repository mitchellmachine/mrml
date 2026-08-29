#![no_std]

unsafe extern "C" {
    fn rlib_answer() -> i32;
}

#[unsafe(no_mangle)]
pub extern "C" fn start() -> i32 {
    unsafe { rlib_answer() }
}
