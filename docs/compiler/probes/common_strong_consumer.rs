#![no_main]
#![no_std]

use core::arch::asm;

unsafe extern "C" {
    static shared_common: u64;
}

#[unsafe(no_mangle)]
pub extern "C" fn start() -> ! {
    unsafe {
        let initial: u64;
        asm!(
            "mov {initial}, qword ptr [rip + {symbol}]",
            initial = out(reg) initial,
            symbol = sym shared_common,
            options(nostack, preserves_flags, readonly)
        );
        let status = if initial == 7 { 42_u64 } else { 1_u64 };
        asm!(
            "syscall",
            in("rax") 60_u64,
            in("rdi") status,
            options(noreturn, nostack)
        )
    }
}
