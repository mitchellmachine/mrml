#![no_main]
#![no_std]

use core::arch::asm;

unsafe extern "C" {
    static mut shared_common: u64;
}

#[unsafe(no_mangle)]
pub extern "C" fn start() -> ! {
    unsafe {
        let address: *mut u64;
        asm!(
            "lea {address}, [rip + {symbol}]",
            address = out(reg) address,
            symbol = sym shared_common,
            options(nostack, preserves_flags)
        );
        let initial = address.read_volatile();
        address.write_volatile(42);
        let status = if initial == 0 && address.read_volatile() == 42 {
            42_u64
        } else {
            1_u64
        };
        asm!(
            "syscall",
            in("rax") 60_u64,
            in("rdi") status,
            options(noreturn, nostack)
        )
    }
}
