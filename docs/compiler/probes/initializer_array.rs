#![no_main]
#![no_std]

use core::arch::asm;

#[unsafe(no_mangle)]
pub extern "C" fn retained_initializer() -> u64 {
    7
}

#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".init_array")]
pub static MRML_INITIALIZER: extern "C" fn() -> u64 = retained_initializer;

#[unsafe(no_mangle)]
pub extern "C" fn start() -> ! {
    unsafe {
        asm!(
            "syscall",
            in("rax") 60_u64,
            in("rdi") 42_u64,
            options(noreturn, nostack)
        )
    }
}
