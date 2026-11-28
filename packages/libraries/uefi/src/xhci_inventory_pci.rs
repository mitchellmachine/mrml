//! Read-only firmware PCI I/O for the standalone USB observation and future
//! opt-in diagnostics. Retain no protocol pointers past firmware exit.

use core::ffi::c_void;
use mrml_kernel::DeviceAddress;
use mrml_uefi::xhci_inventory::boot_observation::{RetainedBootXhci, XhciFunction};
use mrml_uefi::xhci_inventory::{BAR_RESOURCE_BYTES, BAR_RESOURCE_HEADER, inspect_bar0};
use mrml_uefi::{BootServices, Guid, Handle, LOAD_ERROR, SUCCESS, Status};

pub(super) const PCI_IO: Guid = Guid {
    data1: 0x4cf5_b200,
    data2: 0x68b8,
    data3: 0x4ca5,
    data4: [0x9e, 0xec, 0xb2, 0x3e, 0x3f, 0x50, 0x02, 0x9a],
};
pub(super) const UINT32: u32 = 2;

// Read-only projection of EFI_PCI_IO_PROTOCOL. Unused entries are slots, not
// callable functions. In particular, there is no typed write or DMA entry.
#[repr(C)]
pub(super) struct PciIo {
    _poll: [usize; 2],
    pub(super) mem_read: unsafe extern "efiapi" fn(*const Self, u32, u8, u64, usize, *mut c_void) -> Status,
    _unused_mem_io: [usize; 3],
    cfg_read: unsafe extern "efiapi" fn(*const Self, u32, u32, usize, *mut c_void) -> Status,
    _unused_cfg_dma: [usize; 7],
    location: unsafe extern "efiapi" fn(
        *const Self,
        *mut usize,
        *mut usize,
        *mut usize,
        *mut usize,
    ) -> Status,
    _attributes: usize,
    bar: unsafe extern "efiapi" fn(*const Self, u8, *mut u64, *mut *mut c_void) -> Status,
}
const _: () = {
    assert!(core::mem::offset_of!(PciIo, mem_read) == 2 * size_of::<usize>());
    assert!(core::mem::offset_of!(PciIo, cfg_read) == 6 * size_of::<usize>());
    assert!(core::mem::offset_of!(PciIo, location) == 14 * size_of::<usize>());
    assert!(core::mem::offset_of!(PciIo, bar) == 16 * size_of::<usize>());
};

fn check(status: Status) -> Result<(), Status> {
    if status == SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

// SAFETY: io is a live EFI PCI I/O protocol with the standard read entry.
pub(super) unsafe fn cfg(io: *const PciIo, offset: u32) -> Result<u32, Status> {
    let mut word = 0u32;
    // SAFETY: the protocol receives one aligned output word and a PCI config offset.
    check(unsafe { ((*io).cfg_read)(io, UINT32, offset, 1, (&mut word as *mut u32).cast()) })?;
    Ok(word)
}

pub(super) struct InventoryBar {
    pub(super) base: u64,
    pub(super) bytes: u32,
    pub(super) boot_evidence: Option<RetainedBootXhci>,
}

// SAFETY: services and io are live firmware interfaces. On a successful
// GetBarAttributes call the firmware provides an ACPI descriptor allocation.
pub(super) unsafe fn bar0(
    services: &BootServices,
    io: *const PciIo,
    command: u16,
    header: u8,
    boot_requester: Option<u32>,
    function: XhciFunction,
) -> Result<InventoryBar, Status> {
    if command & 2 == 0 || header & 0x7f != 0 {
        return Err(LOAD_ERROR);
    }
    // SAFETY: the enumerated type-zero interface permits reads of BAR0 config.
    let lo = unsafe { cfg(io, 0x10)? };
    let hi = if lo & 7 == 4 {
        // SAFETY: BAR0 is 64-bit, so its upper dword is in config offset 0x14.
        unsafe { cfg(io, 0x14)? }
    } else {
        0
    };
    let mut resource: *mut c_void = core::ptr::null_mut();
    // SAFETY: GetBarAttributes receives a null optional mask and a valid output pointer.
    check(unsafe { ((*io).bar)(io, 0, core::ptr::null_mut(), &mut resource) })?;
    if resource.is_null() {
        return Err(LOAD_ERROR);
    }
    let resource = resource.cast::<u8>();
    // SAFETY: the successful call supplies at least a descriptor header.
    let result = if unsafe { core::slice::from_raw_parts(resource, 3) } == BAR_RESOURCE_HEADER {
        // SAFETY: the QWord header declares its complete payload and the firmware supplies the End Tag.
        let descriptor = unsafe { core::slice::from_raw_parts(resource, BAR_RESOURCE_BYTES) };
        inspect_bar0(command, header, lo, hi, descriptor).map(|(base, bytes)| InventoryBar {
            base,
            bytes,
            boot_evidence: RetainedBootXhci::from_firmware(
                boot_requester, function, command, header, lo, hi, descriptor,
            ),
        })
    } else {
        None
    };
    // SAFETY: the resource is the original successful GetBarAttributes allocation.
    check(unsafe { (services.free_pool)(resource.cast()) })?;
    result.ok_or(LOAD_ERROR)
}

pub(super) fn packed_requester(address: DeviceAddress) -> u32 {
    (u32::from(address.segment()) << 16)
        | (u32::from(address.bus()) << 8)
        | (u32::from(address.device()) << 3)
        | u32::from(address.function())
}

// SAFETY: handle must come from the current, live firmware PCI I/O namespace.
pub(super) unsafe fn locate_function(
    services: &BootServices,
    handle: Handle,
) -> Result<(DeviceAddress, *const PciIo), Status> {
    if handle.is_null() {
        return Err(LOAD_ERROR);
    }
    let mut interface = core::ptr::null_mut();
    // SAFETY: the non-null handle was issued by firmware for this protocol.
    check(unsafe { (services.handle_protocol)(handle, &PCI_IO, &mut interface) })?;
    let io = interface.cast::<PciIo>();
    if io.is_null() || !io.is_aligned() {
        return Err(LOAD_ERROR);
    }
    let (mut segment, mut bus, mut device, mut function) = (0, 0, 0, 0);
    // SAFETY: the aligned PCI I/O protocol is live and all four outputs are writable.
    check(unsafe { ((*io).location)(io, &mut segment, &mut bus, &mut device, &mut function) })?;
    let requester = DeviceAddress::new(
        u16::try_from(segment).map_err(|_| LOAD_ERROR)?,
        u8::try_from(bus).map_err(|_| LOAD_ERROR)?,
        u8::try_from(device).map_err(|_| LOAD_ERROR)?,
        u8::try_from(function).map_err(|_| LOAD_ERROR)?,
    )
    .map_err(|_| LOAD_ERROR)?;
    Ok((requester, io))
}
