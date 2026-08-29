#![feature(thread_local)]
#![no_main]
#![no_std]

use core::arch::asm;

#[thread_local]
static mut TLS_INITIALIZED: u64 = 7;

#[thread_local]
static mut TLS_ZEROED: u64 = 0;

#[used]
static mut TLS_RUNTIME: [u64; 2] = [7, 0];

#[unsafe(no_mangle)]
pub extern "C" fn start() -> ! {
    unsafe {
        let thread_pointer = core::ptr::addr_of_mut!(TLS_RUNTIME)
            .cast::<u64>()
            .add(2);
        let result: i64;
        asm!(
            "syscall",
            inlateout("rax") 158_u64 => result,
            in("rdi") 0x1002_u64,
            in("rsi") thread_pointer,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
        let initial = TLS_INITIALIZED;
        let zeroed = TLS_ZEROED;
        TLS_INITIALIZED = 20;
        TLS_ZEROED = 22;
        let status = if result == 0
            && initial == 7
            && zeroed == 0
            && TLS_INITIALIZED + TLS_ZEROED == 42
        {
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
