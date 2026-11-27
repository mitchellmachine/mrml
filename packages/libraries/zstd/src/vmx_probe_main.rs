//! Signed diagnostic entry for the existing native Zstd ABI-3 provider.
#![no_std]
#![no_main]

use core::arch::asm;
use mrml_interface_zstd_v3::{DECOMPRESS_REQUEST_BYTES, DECOMPRESS_RESPONSE_BYTES, ZstdTransport};
use mrml_zstd::ComponentProvider;

const INPUT: usize = 12;
const MEMORY: usize = 64;

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(
    request: &[u8; DECOMPRESS_REQUEST_BYTES + INPUT],
    reply: &mut [u8; DECOMPRESS_RESPONSE_BYTES + MEMORY],
) -> ! {
    let (wire, source) = request.split_at(DECOMPRESS_REQUEST_BYTES);
    let wire: &[u8; DECOMPRESS_REQUEST_BYTES] = wire.try_into().unwrap();
    let (response, memory) = reply.split_at_mut(DECOMPRESS_RESPONSE_BYTES);
    memory.fill(0);
    memory[..INPUT].copy_from_slice(source);
    if let Ok(result) = ComponentProvider.call(wire, memory) {
        response.copy_from_slice(&result);
        // SAFETY: this entry is only launched by the opt-in MicroVM monitor.
        // The reserved one-byte completion port is trapped, never forwarded.
        unsafe {
            asm!("out 0xe8, al", in("al") 1u8, options(nostack, preserves_flags));
        }
    }
    halt()
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    halt()
}

fn halt() -> ! {
    // SAFETY: this is the isolated guest's fatal/terminal path; HLT is trapped.
    unsafe {
        asm!("hlt; ud2", options(noreturn, nomem, nostack));
    }
}
