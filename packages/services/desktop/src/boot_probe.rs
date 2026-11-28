//! Entry for the opt-in sealed boot diagnostic, not a firmware application.
#![no_std]
#![no_main]

use core::arch::asm;
use mrml_desktop::boot_frame::{
    BOOT_REPLY_BYTES, BOOT_REQUEST, BootPanelDesktop, BootScene, MAX_LIVE_KEYS,
};

const REQUEST: usize = BOOT_REQUEST.len();

// The sealed loader requires a real DIR64 relocation when changing the PE base.
static RELOCATION_ANCHOR: fn() -> ! = halt;

#[unsafe(no_mangle)]
extern "efiapi" fn efi_main(
    request: *const [u8; REQUEST],
    reply: *mut [u8; BOOT_REPLY_BYTES],
) -> ! {
    core::hint::black_box(&RELOCATION_ANCHOR);
    let mut desktop = BootPanelDesktop::new().unwrap_or_else(|_| halt());
    let mut live = false;
    for step in 0..MAX_LIVE_KEYS + 3 {
        // SAFETY: the signed monitor passes distinct aligned, fixed mailbox
        // pages. It touches them only while this vCPU is stopped. No guest
        // reference to either page survives the trapped OUT at the end.
        let completed = unsafe {
            let request = request.read_volatile();
            let reply = &mut *reply;
            match (step, BootScene::parse(&request)) {
                (0, Ok(scene @ (BootScene::Begin | BootScene::LiveBegin))) => {
                    live = scene == BootScene::LiveBegin;
                    desktop.step(scene, reply).map(|()| false)
                }
                (1, Ok(BootScene::Enter)) => desktop.step(BootScene::Enter, reply).map(|()| false),
                (2, Ok(BootScene::TextA)) if !live => {
                    desktop.step(BootScene::TextA, reply).map(|()| true)
                }
                (
                    2..,
                    Ok(
                        scene @ (BootScene::Letter(_)
                        | BootScene::Space
                        | BootScene::Submit
                        | BootScene::Backspace),
                    ),
                ) if live && step < MAX_LIVE_KEYS + 2 => desktop.step(scene, reply).map(|()| false),
                (2.., Ok(BootScene::End)) if live => {
                    desktop.step(BootScene::End, reply).map(|()| true)
                }
                (0, Ok(scene @ (BootScene::Idle | BootScene::Enter))) => {
                    desktop.step(scene, reply).map(|()| true)
                }
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
