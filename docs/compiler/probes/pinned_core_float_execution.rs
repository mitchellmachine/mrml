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
    let parsed = core::hint::black_box("3.141592653589793")
        .parse::<f64>()
        .unwrap_or(0.0);
    let decoded = char::from_u32(core::hint::black_box(0x1f642)).unwrap_or('\0');
    if parsed.to_bits() == 0x4009_21fb_5444_2d18 && decoded == '🙂' {
        42
    } else {
        1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}
