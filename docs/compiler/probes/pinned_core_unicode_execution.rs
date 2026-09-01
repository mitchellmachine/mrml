#![no_std]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn entry() -> u32 {
    let value = core::hint::black_box('ß');
    let mut uppercase = value.to_uppercase();
    let first = uppercase.next();
    let second = uppercase.next();
    let end = uppercase.next();
    let classified = core::hint::black_box('λ').is_alphabetic();
    if first == Some('S') && second == Some('S') && end.is_none() && classified {
        42
    } else {
        1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}
