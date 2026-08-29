#![no_main]
#![no_std]

use core::arch::asm;

static mut STATE: u64 = 0;

unsafe extern "C" {
    static __preinit_array_start: extern "C" fn();
    static __preinit_array_end: extern "C" fn();
    static __init_array_start: extern "C" fn();
    static __init_array_end: extern "C" fn();
    static __fini_array_start: extern "C" fn();
    static __fini_array_end: extern "C" fn();
}

#[unsafe(no_mangle)]
pub extern "C" fn preinitialize() {
    unsafe { STATE = 1 }
}

#[unsafe(no_mangle)]
pub extern "C" fn initialize_first() {
    unsafe { STATE = STATE * 10 + 4 }
}

#[unsafe(no_mangle)]
pub extern "C" fn initialize_second() {
    unsafe { STATE = STATE * 10 + 2 }
}

#[unsafe(no_mangle)]
pub extern "C" fn finalize_first() {
    unsafe { STATE = STATE * 10 + 3 }
}

#[unsafe(no_mangle)]
pub extern "C" fn finalize_second() {
    unsafe { STATE = STATE * 10 + 5 }
}

#[used]
#[unsafe(link_section = ".preinit_array")]
static PREINITIALIZER: extern "C" fn() = preinitialize;

#[used]
#[unsafe(link_section = ".init_array.100")]
static INITIALIZER_FIRST: extern "C" fn() = initialize_first;

#[used]
#[unsafe(link_section = ".init_array.200")]
static INITIALIZER_SECOND: extern "C" fn() = initialize_second;

#[used]
#[unsafe(link_section = ".fini_array.100")]
static FINALIZER_FIRST: extern "C" fn() = finalize_first;

#[used]
#[unsafe(link_section = ".fini_array.200")]
static FINALIZER_SECOND: extern "C" fn() = finalize_second;

unsafe fn run_array(start: *const extern "C" fn(), end: *const extern "C" fn()) {
    let mut current = start;
    while current < end {
        unsafe { (*current)() };
        current = unsafe { current.add(1) };
    }
}

unsafe fn run_array_reverse(start: *const extern "C" fn(), end: *const extern "C" fn()) {
    let mut current = end;
    while current > start {
        current = unsafe { current.sub(1) };
        unsafe { (*current)() };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn start() -> ! {
    unsafe {
        let preinit_start: *const extern "C" fn();
        let preinit_end: *const extern "C" fn();
        let init_start: *const extern "C" fn();
        let init_end: *const extern "C" fn();
        let fini_start: *const extern "C" fn();
        let fini_end: *const extern "C" fn();
        asm!(
            "lea {preinit_start}, [rip + {preinit_start_symbol}]",
            "lea {preinit_end}, [rip + {preinit_end_symbol}]",
            "lea {init_start}, [rip + {init_start_symbol}]",
            "lea {init_end}, [rip + {init_end_symbol}]",
            "lea {fini_start}, [rip + {fini_start_symbol}]",
            "lea {fini_end}, [rip + {fini_end_symbol}]",
            preinit_start = out(reg) preinit_start,
            preinit_end = out(reg) preinit_end,
            init_start = out(reg) init_start,
            init_end = out(reg) init_end,
            fini_start = out(reg) fini_start,
            fini_end = out(reg) fini_end,
            preinit_start_symbol = sym __preinit_array_start,
            preinit_end_symbol = sym __preinit_array_end,
            init_start_symbol = sym __init_array_start,
            init_end_symbol = sym __init_array_end,
            fini_start_symbol = sym __fini_array_start,
            fini_end_symbol = sym __fini_array_end,
            options(nostack, preserves_flags)
        );
        run_array(preinit_start, preinit_end);
        run_array(init_start, init_end);
        run_array_reverse(fini_start, fini_end);
        let status = if STATE == 14_253 { 42_u64 } else { 1_u64 };
        asm!(
            "syscall",
            in("rax") 60_u64,
            in("rdi") status,
            options(noreturn, nostack)
        )
    }
}
