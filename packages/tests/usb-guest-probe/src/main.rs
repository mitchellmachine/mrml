#![no_std]
#![no_main]

use core::arch::asm;

// This test fixture is admitted only by the KVM diagnostic. The monitor
// projects this exact writable, non-executable page for the result.
const RESULT: *mut u8 = 0xffff_8001_400f_0000 as *mut u8;

#[unsafe(no_mangle)]
extern "efiapi" fn efi_main() -> ! {
    let result = if mrml_usb_guest_probe::exercise() {
        0x51
    } else {
        0x52
    };
    // SAFETY: the diagnostic launcher maps one result byte at RESULT before entry.
    unsafe { RESULT.write_volatile(result) };
    stop()
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    stop()
}

fn stop() -> ! {
    loop {
        // SAFETY: this diagnostic runs in a privileged guest. The VMM observes HLT.
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
}
