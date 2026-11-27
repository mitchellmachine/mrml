#![no_std]
#![no_main]

use core::arch::asm;
use mrml_usb_guest_probe::{BulkTransport, Platform, inspect_legacy_ownership};

mod command_probe;

// This test fixture is admitted only by the KVM diagnostic. The monitor
// projects this exact writable, non-executable page for the result.
const RESULT: *mut u8 = 0xffff_8001_400f_0000 as *mut u8;

#[unsafe(no_mangle)]
extern "efiapi" fn efi_main() -> ! {
    let passed = match read_byte(0) {
        0x60 => mrml_usb_guest_probe::exercise_transport(Relay),
        0x61 => preflight(),
        0x62 => command_probe::exercise(0),
        0x63 => command_probe::exercise(1),
        0x64 => command_probe::exercise(2),
        0x65 => command_probe::exercise(3),
        0x66 => command_probe::exercise(4),
        _ => mrml_usb_guest_probe::exercise(),
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
const MAX_PAYLOAD: usize = 33 * 64;

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

// Dedicated scratch bytes at the end of the disposable QEMU fixture aperture.
// No registers, DMA buffer addresses, or PCI authority come from guest input.
const SCRATCH: u64 = 0x10_7fc0;
const MARKER: [u8; 4] = *b"MRML";

struct Preflight;

impl Platform for Preflight {
    type Error = ();

    fn read32(&mut self, offset: u32) -> Result<u32, ()> {
        request_address(u64::from(offset));
        transfer(5, 4)?;
        Ok(u32::from_le_bytes(core::array::from_fn(|i| {
            read_byte(PAYLOAD + i)
        })))
    }

    fn write32(&mut self, _: u32, _: u32) -> Result<(), ()> {
        Err(())
    }

    fn dma_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), ()> {
        if address != SCRATCH || bytes != MARKER {
            return Err(());
        }
        request_address(address);
        for (i, &byte) in bytes.iter().enumerate() {
            write_byte(PAYLOAD + i, byte);
        }
        transfer(6, bytes.len())
    }

    fn dma_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), ()> {
        if address != SCRATCH || bytes.len() != MARKER.len() {
            return Err(());
        }
        request_address(address);
        transfer(7, bytes.len())?;
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = read_byte(PAYLOAD + i);
        }
        Ok(())
    }

    fn publish_dma(&mut self) -> Result<(), ()> {
        Ok(())
    }
    fn acquire_dma(&mut self) -> Result<(), ()> {
        Ok(())
    }
    fn wait_tick(&mut self) -> Result<(), ()> {
        Err(())
    }
}

fn request_address(address: u64) {
    for (i, byte) in address.to_le_bytes().into_iter().enumerate() {
        write_byte(8 + i, byte);
    }
}

fn preflight() -> bool {
    let mut io = Preflight;
    let Ok(cap) = io.read32(0) else { return false };
    if cap & 0xff < 0x20
        || !(0x100..=0x1ff).contains(&(cap >> 16))
        || inspect_legacy_ownership(0x4000, |offset| io.read32(offset)).is_err()
    {
        return false;
    }
    let mut observed = [0; 4];
    io.dma_write(SCRATCH, &MARKER).is_ok()
        && io.dma_read(SCRATCH, &mut observed).is_ok()
        && observed == MARKER
}

fn stop() -> ! {
    loop {
        // SAFETY: this diagnostic runs in a privileged guest. The VMM observes HLT.
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
}
