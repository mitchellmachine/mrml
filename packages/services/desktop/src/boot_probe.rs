//! Entry for the opt-in sealed boot diagnostic, not a firmware application.
#![no_std]
#![no_main]

use core::arch::asm;
use mrml_desktop::boot_frame::{BOOT_REPLY_BYTES, BOOT_REQUEST, BootDesktop, render_boot_reply};

const REQUEST: usize = BOOT_REQUEST.len();
const BEGIN: [u8; REQUEST] = *b"MRMLDB1\x02";
const ENTER: [u8; REQUEST] = *b"MRMLDB1\x01";
const TEXT_A: [u8; REQUEST] = *b"MRMLDB1\x03";

// The sealed loader requires a real DIR64 relocation when changing the PE base.
static RELOCATION_ANCHOR: fn() -> ! = halt;

#[unsafe(no_mangle)]
extern "efiapi" fn efi_main(request: *const [u8; REQUEST], reply: *mut [u8; BOOT_REPLY_BYTES]) -> ! {
    core::hint::black_box(&RELOCATION_ANCHOR);
    let mut desktop = BootDesktop::new().unwrap_or_else(|_| halt());
    for step in 0..3 {
        // SAFETY: the signed monitor passes distinct aligned, fixed mailbox
        // pages. It touches them only while this vCPU is stopped. No guest
        // reference to either page survives the trapped OUT at the end.
        let completed = unsafe {
            let request = request.read_volatile();
            let reply = &mut *reply;
            match (step, request) {
                (0, BEGIN) => desktop.step(mrml_desktop::boot_frame::BootScene::Begin, reply).map(|()| false),
                (1, ENTER) => desktop.step(mrml_desktop::boot_frame::BootScene::Enter, reply).map(|()| false),
                (2, TEXT_A) => desktop.step(mrml_desktop::boot_frame::BootScene::TextA, reply).map(|()| true),
                (0, _) => render_boot_reply(&request, reply).map(|()| true),
                _ => Err(mrml_desktop::boot_frame::Error::InvalidRequest),
            }
        };
        // SAFETY: both one-byte notifications are trapped, never forwarded.
        // The ordinary memory clobber orders the mailbox before the exit.
        unsafe {
            match completed {
                Ok(false) => asm!("out 0xea, al", in("al") 1u8, options(nostack, preserves_flags)),
                Ok(true) => {
                    asm!("out 0xe8, al", in("al") 1u8, options(nostack, preserves_flags));
                    halt()
                }
                Err(_) => halt(),
            }
        }
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
