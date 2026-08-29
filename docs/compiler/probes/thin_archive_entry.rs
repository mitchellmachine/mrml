#![no_main]
#![no_std]

use core::arch::asm;

unsafe extern "C" {
    fn thin_helper() -> u64;
}

#[unsafe(no_mangle)]
pub extern "C" fn start() -> ! {
    unsafe {
        let status = thin_helper();
        asm!(
            "syscall",
            in("rax") 60_u64,
            in("rdi") status,
            options(noreturn, nostack)
        )
    }
}
