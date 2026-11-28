#![no_std]
#![no_main]

// Standalone, manually invoked UEFI application. Do not import the normal
// loader or add an ExitBootServices, PCI write, or media I/O path here.
use core::fmt::{self, Write};
#[path = "xhci_inventory_source.rs"]
mod source;
use mrml_kernel::DeviceAddress;
use mrml_kernel::arch::x86_64::PciConfigSpace;
use mrml_storage_usb::xhci::{LegacyOwnership, inspect_legacy_ownership};
#[path = "xhci_inventory_acpi.rs"]
mod acpi;
use mrml_uefi::xhci_inventory::boot_observation::XhciFunction;
use mrml_uefi::xhci_inventory::{DragonairInventory, inspect_dma_geometry};
use mrml_uefi::{
    BootServices, Handle, LOAD_ERROR, LOCATE_BY_PROTOCOL, NOT_FOUND, SUCCESS, Status,
    SystemTable,
};

#[path = "xhci_inventory_pci.rs"]
mod pci;
use pci::{InventoryBar, PCI_IO, PciIo, UINT32, bar0, cfg, locate_function, packed_requester};

const MAX_HANDLES: usize = 256;

#[repr(C)]
struct TextOutput {
    _reset: usize,
    write: unsafe extern "efiapi" fn(*mut Self, *const u16) -> Status,
}
struct Line([u16; 160], usize);
impl Write for Line {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for byte in value.bytes() {
            if self.1 >= self.0.len() - 3 {
                return Err(fmt::Error);
            }
            self.0[self.1] = u16::from(byte);
            self.1 += 1;
        }
        Ok(())
    }
}

fn check(status: Status) -> Result<(), Status> {
    if status == SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

// SAFETY: output is a live firmware-owned Simple Text Output interface.
unsafe fn line(output: *mut TextOutput, args: fmt::Arguments<'_>) -> Result<(), Status> {
    let mut line = Line([0; 160], 0);
    line.write_fmt(args).map_err(|_| LOAD_ERROR)?;
    line.0[line.1..line.1 + 2].copy_from_slice(&[13, 10]);
    // SAFETY: the console is live and this buffer is terminated UTF-16.
    check(unsafe { ((*output).write)(output, line.0.as_ptr()) })
}

struct InventoryConfig<'a>(&'a [Option<(DeviceAddress, *const PciIo)>]);

impl PciConfigSpace for InventoryConfig<'_> {
    fn read_u32(&mut self, requester: DeviceAddress, offset: u16) -> Option<u32> {
        if !matches!(offset, 0 | 8 | 0x0c | 0x18) {
            return None;
        }
        let (_, io) = self
            .0
            .iter()
            .flatten()
            .find(|(address, _)| *address == requester)?;
        // SAFETY: scan records only live PCI I/O interfaces with unique BDFs.
        unsafe { cfg(*io, u32::from(offset)).ok() }
    }
}

struct RecordHex<'a>(&'a [u8]);

impl fmt::Display for RecordHex<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(out, "{byte:02x}")?;
        }
        Ok(())
    }
}

// SAFETY: services and output are the live tables of this UEFI application;
// protocol handles/buffers are firmware-owned until the documented free.
unsafe fn scan(
    image: Handle,
    system: &SystemTable,
    services: &BootServices,
    output: *mut TextOutput,
) -> Result<(), Status> {
    let mut count = 0;
    let mut buffer = core::ptr::null_mut();
    // SAFETY: the live service receives an initialized count and handle buffer out pointer.
    let status = unsafe {
        (services.locate_handle_buffer)(
            LOCATE_BY_PROTOCOL,
            &PCI_IO,
            core::ptr::null_mut(),
            &mut count,
            &mut buffer,
        )
    };
    if status == NOT_FOUND {
        // SAFETY: the console remains live even if no PCI I/O handles were found.
        return unsafe {
            line(
                output,
                format_args!("xhci-inventory: controllers=0 incomplete=0"),
            )
        };
    }
    check(status)?;
    if buffer.is_null() {
        return Err(LOAD_ERROR);
    }
    let mut handles = [core::ptr::null_mut(); MAX_HANDLES];
    let valid_size = (1..=MAX_HANDLES).contains(&count) && buffer.is_aligned();
    if valid_size {
        // SAFETY: the successful firmware handle array is aligned and bounded by valid_size.
        handles[..count].copy_from_slice(unsafe { core::slice::from_raw_parts(buffer, count) });
    }
    // SAFETY: the successful LocateHandleBuffer allocation is still live and not borrowed.
    check(unsafe { (services.free_pool)(buffer.cast()) })?;
    if !valid_size {
        return Err(LOAD_ERROR);
    }

    let mut records = [None::<(DeviceAddress, *const PciIo)>; MAX_HANDLES];
    for (i, handle) in handles[..count].iter().copied().enumerate() {
        if handle.is_null() || handles[..i].contains(&handle) {
            return Err(LOAD_ERROR);
        }
        // SAFETY: non-null handle came from this firmware's LocateHandleBuffer call.
        let (requester, io) = unsafe { locate_function(services, handle) }?;
        if records[..i]
            .iter()
            .flatten()
            .any(|(address, _)| *address == requester)
        {
            return Err(LOAD_ERROR);
        }
        records[i] = Some((requester, io));
    }

    // SAFETY: the firmware mapping and services are still live here; ACPI
    // memory reads use only an exact non-overlapping reported RAM range.
    let tables = unsafe { acpi::read(system, services) };
    // SAFETY: these are the live image, services, and matched firmware handles.
    let origin = unsafe { source::inspect(image, services) }.and_then(|(handle, transport)| {
        let i = handles[..count].iter().position(|&entry| entry == handle)?;
        let (requester, io) = records[i]?;
        // SAFETY: the BDF and live PCI I/O interface were validated above.
        let xhci = unsafe { cfg(io, 8).ok()? } >> 8 == 0x0c0330;
        match (transport, xhci) {
            (source::Transport::Usb, true) => Some(Some(requester)),
            (source::Transport::SataOrNvme, false) => Some(None),
            _ => None,
        }
    });
    let mut config = InventoryConfig(&records[..count]);
    let mut found = 0;
    let mut incomplete = 0;
    let mut dragonair = None;
    for (requester, io) in records[..count].iter().copied().flatten() {
        // SAFETY: class/revision is a standard read-only dword on this live protocol.
        let class = unsafe { cfg(io, 8)? };
        if class >> 8 != 0x0c0330 {
            continue;
        }
        found += 1;
        let (segment, bus, device, function) = (
            requester.segment(),
            requester.bus(),
            requester.device(),
            requester.function(),
        );
        // SAFETY: vendor/device identity is a standard read-only dword on this live protocol.
        let id = unsafe { cfg(io, 0)? };
        if matches!(id as u16, 0 | 0xffff) {
            return Err(LOAD_ERROR);
        }
        // SAFETY: the live protocol returns the command word in the lower half of this dword.
        let command = unsafe { cfg(io, 4)? } as u16;
        // SAFETY: the live protocol returns the header type in this standard config dword.
        let header = (unsafe { cfg(io, 0x0c)? } >> 16) as u8;
        // SAFETY: the console is live; only scalar PCI fields are formatted.
        unsafe {
            line(
                output,
                format_args!(
                    "xhci {segment:04x}:{bus:02x}:{device:02x}.{function} pci={:04x}:{:04x} rev={:02x} cmd={command:04x}",
                    id as u16,
                    id >> 16,
                    class as u8
                ),
            )?
        };
        let relationship = match origin {
            Some(Some(address)) if address == requester => "shared-usb",
            Some(Some(_)) => "separate-usb",
            Some(None) => "non-usb",
            None => "unresolved",
        };
        // SAFETY: the console is live; the relationship is a static label.
        unsafe { line(output, format_args!("xhci boot source: {relationship}"))? };
        // SAFETY: the console and the bounded inventory config remain live.
        let (mcfg_covered, dmar) = unsafe {
            match &tables {
                Ok(tables) => tables.report(output, requester, &mut config)?,
                Err(reason) => {
                    line(output, format_args!("xhci ACPI unavailable: {reason}"))?;
                    (false, None)
                }
            }
        };
        let function = XhciFunction {
            requester: packed_requester(requester),
            vendor_device: id,
            class_revision: class,
        };
        let boot_requester = origin.flatten().map(packed_requester);
        // SAFETY: this PCI interface and its owning services remain live.
        match unsafe { bar0(services, io, command, header, boot_requester, function) } {
            Ok(InventoryBar { base, bytes, boot_evidence }) => {
                let read = |offset| {
                    let mut word = 0u32;
                    // SAFETY: both callers bound aligned BAR0-relative offsets;
                    // the destination is a single aligned u32.
                    check(unsafe {
                        ((*io).mem_read)(
                            io,
                            UINT32,
                            0,
                            u64::from(offset),
                            1,
                            (&mut word as *mut u32).cast(),
                        )
                    })?;
                    Ok::<u32, Status>(word)
                };
                let ownership = inspect_legacy_ownership(bytes, read);
                let geometry = inspect_dma_geometry(bytes, read);
                if function.requester == DragonairInventory::REQUESTER {
                    dragonair = Some(DragonairInventory {
                        boot: boot_evidence,
                        pci_command: command,
                        firmware_owned: matches!(ownership, Ok(LegacyOwnership::Firmware)),
                        geometry,
                        mcfg_covered,
                        dmar,
                    });
                }
                if ownership.is_err() || geometry.is_none() {
                    incomplete += 1;
                }
                // SAFETY: the console remains live and only report text is sent.
                unsafe {
                    line(
                        output,
                        format_args!(
                            "xhci BAR0={base:#018x} size={bytes:#x} ownership={ownership:?}"
                        ),
                    )?;
                    if let Some(evidence) = boot_evidence {
                        let (identity, base, bytes) = evidence.diagnostic_fields();
                        line(output, format_args!(
                            "xhci boot evidence: requester={:08x} pci={:08x} class={:08x} bar0={base:#018x} size={bytes:#x}",
                            identity.requester, identity.vendor_device, identity.class_revision,
                        ))?;
                        let record = evidence.encode();
                        for (index, half) in record.chunks_exact(20).enumerate() {
                            line(output, format_args!("xhci boot wire {index}: {}", RecordHex(half)))?;
                        }
                    }
                    match geometry {
                        Some((count, mask)) => line(
                            output,
                            format_args!("xhci DMA: scratchpads={count} page-mask={mask:#06x}"),
                        )?,
                        None => line(output, format_args!("xhci DMA: unavailable"))?,
                    }
                }
            }
            Err(status) => {
                incomplete += 1;
                // SAFETY: the console remains live; failure does not attempt another device read.
                unsafe {
                    line(
                        output,
                        format_args!("xhci BAR0 unavailable ({status:#018x}); MMIO not read"),
                    )?
                };
            }
        }
    }
    // SAFETY: the console remains live until the application returns.
    unsafe {
        let reference = dragonair.map_or("reference requester unavailable", |sample| {
            sample.compare(found, incomplete)
        });
        line(output, format_args!("xhci Dragonair reference: {reference}"))?;
        line(
            output,
            format_args!("xhci-inventory: controllers={found} incomplete={incomplete}"),
        )
    }
}

#[unsafe(export_name = "efi_main")]
/// # Safety
/// UEFI supplies the live system table and owns every protocol table read here.
pub unsafe extern "efiapi" fn efi_main(image: Handle, system: *mut SystemTable) -> Status {
    if system.is_null() || !system.is_aligned() {
        return LOAD_ERROR;
    }
    // SAFETY: UEFI owns this non-null aligned system table for the duration of the call.
    let system = unsafe { &*system };
    let (services, output) = (system.boot_services, system.con_out.cast::<TextOutput>());
    if services.is_null() || !services.is_aligned() || output.is_null() || !output.is_aligned() {
        return LOAD_ERROR;
    }
    // SAFETY: the checked aligned firmware services and console are live.
    let outcome = unsafe {
        line(output, format_args!("MRML xhci-inventory: read-only"))
            .and_then(|()| scan(image, system, &*services, output))
    };
    if let Err(status) = outcome {
        // SAFETY: the checked console is still live on an error return.
        let _ = unsafe {
            line(
                output,
                format_args!("xhci-inventory: incomplete ({status:#018x})"),
            )
        };
    }
    // SAFETY: the checked console is still live; returning does not exit Boot Services.
    let _ = unsafe {
        line(
            output,
            format_args!("xhci-inventory: returning to firmware; no controller handoff"),
        )
    };
    outcome.err().unwrap_or(SUCCESS)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
