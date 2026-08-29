#[unsafe(no_mangle)]
pub extern "C" fn start() -> ! {
    unsafe {
        asm!("int3", options(noreturn, nostack));
    }
}
