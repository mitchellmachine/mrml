//! Entry for the opt-in sealed boot diagnostic, not a firmware application.
#![no_std]
#![no_main]

use core::arch::asm;
use mrml_desktop::boot_frame::{BOOT_REPLY_BYTES, BOOT_REQUEST, render_boot_reply};

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(
    request: &[u8; BOOT_REQUEST.len()],
    reply: &mut [u8; BOOT_REPLY_BYTES],
) -> ! {
    if render_boot_reply(request, reply).is_ok() {
        // SAFETY: the diagnostic launcher traps this one-byte completion
        // notification. The guest has no physical device or scanout mapping.
        unsafe { asm!("out 0xe8, al", in("al") 1u8, options(nostack, preserves_flags)) };
    }
    halt()
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    halt()
}

fn halt() -> ! {
    // SAFETY: this terminates the device-free diagnostic on a trapped exit.
    unsafe { asm!("hlt; ud2", options(noreturn, nomem, nostack)) }
}
