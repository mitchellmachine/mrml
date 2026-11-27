#![no_std]
#![no_main]

use core::arch::asm;
use mrml_usb_guest_probe::BulkTransport;

// This test fixture is admitted only by the KVM diagnostic. The monitor
// projects this exact writable, non-executable page for the result.
const RESULT: *mut u8 = 0xffff_8001_400f_0000 as *mut u8;

#[unsafe(no_mangle)]
extern "efiapi" fn efi_main() -> ! {
    let passed = if read_byte(0) == 0x60 {
        mrml_usb_guest_probe::exercise_transport(Relay)
    } else {
        mrml_usb_guest_probe::exercise()
    };
    let result = if passed { 0x51 } else { 0x52 };
    write_byte(0, result);
    stop()
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    stop()
}

const PAYLOAD: usize = 16;
const MAX_PAYLOAD: usize = 512;

fn read_byte(offset: usize) -> u8 {
    assert!(offset < PAYLOAD + MAX_PAYLOAD);
    // SAFETY: the launcher maps this dedicated page before entering the guest.
    unsafe { RESULT.add(offset).read_volatile() }
}

fn write_byte(offset: usize, byte: u8) {
    assert!(offset < PAYLOAD + MAX_PAYLOAD);
    // SAFETY: this offset stays in the writable, non-executable fixture page.
    unsafe { RESULT.add(offset).write_volatile(byte) }
}

struct Relay;

impl BulkTransport for Relay {
    type Error = ();

    fn bulk_out(&mut self, bytes: &[u8]) -> Result<usize, ()> {
        if !matches!(bytes.len(), 31 | 512) {
            return Err(());
        }
        for (i, &byte) in bytes.iter().enumerate() {
            write_byte(PAYLOAD + i, byte);
        }
        transfer(1, bytes.len())?;
        Ok(bytes.len())
    }

    fn bulk_in(&mut self, bytes: &mut [u8]) -> Result<usize, ()> {
        if !matches!(bytes.len(), 8 | 13 | 18 | 512) {
            return Err(());
        }
        transfer(2, bytes.len())?;
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = read_byte(PAYLOAD + i);
        }
        Ok(bytes.len())
    }
}

fn transfer(operation: u8, length: usize) -> Result<(), ()> {
    let size = (length as u16).to_le_bytes();
    write_byte(1, size[0]);
    write_byte(2, size[1]);
    write_byte(0, operation);
    // SAFETY: the VMM stops the vCPU at HLT and resumes only after publishing
    // the response. The operation has a memory clobber for the mailbox.
    unsafe { asm!("hlt", options(nostack)) };
    (read_byte(0) == 3).then_some(()).ok_or(())
}

fn stop() -> ! {
    loop {
        // SAFETY: this diagnostic runs in a privileged guest. The VMM observes HLT.
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
}
