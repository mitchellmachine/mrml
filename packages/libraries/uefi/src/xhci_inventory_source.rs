use super::PCI_IO;
pub(super) use mrml_uefi::xhci_inventory::SourceTransport as Transport;
use mrml_uefi::{
    BootServices, DEVICE_PATH_PROTOCOL_GUID, Handle, LOADED_IMAGE_GUID, LoadedImageProtocol,
    MAX_UEFI_DEVICE_PATH_BYTES, SUCCESS, copy_single_device_path, xhci_inventory::source_transport,
};

/// # Safety
/// Image and services must designate the currently running EFI application
/// and live boot services. Firmware owns every returned interface.
pub(super) unsafe fn inspect(
    image: Handle,
    services: &BootServices,
) -> Option<(Handle, Transport)> {
    if image.is_null() {
        return None;
    }
    let locate = services.locate_device_path?;
    let mut interface = core::ptr::null_mut();
    // SAFETY: the current image handle is live and the out pointer is writable.
    if unsafe { (services.handle_protocol)(image, &LOADED_IMAGE_GUID, &mut interface) } != SUCCESS {
        return None;
    }
    let loaded = interface.cast::<LoadedImageProtocol>();
    if loaded.is_null() || !loaded.is_aligned() {
        return None;
    }
    // SAFETY: the checked protocol pointer came from the successful query.
    let device = unsafe { (*loaded).device_handle };
    if device.is_null() {
        return None;
    }
    let mut path = core::ptr::null_mut();
    // SAFETY: the loaded-image device handle is live and the out pointer is writable.
    if unsafe { (services.handle_protocol)(device, &DEVICE_PATH_PROTOCOL_GUID, &mut path) }
        != SUCCESS
    {
        return None;
    }
    // SAFETY: the protocol exposes its complete readable path; the copy is bounded.
    let mut buffer = [0; MAX_UEFI_DEVICE_PATH_BYTES];
    // SAFETY: firmware owns this path and does not alias the local scratch.
    let bytes = unsafe { copy_single_device_path(path.cast(), &mut buffer) }.ok()?;
    let mut suffix = buffer.as_mut_ptr();
    let start = suffix.addr();
    let mut handle = core::ptr::null_mut();
    // SAFETY: the copy is a complete single device path; both out slots are live.
    if unsafe { locate(&PCI_IO, &mut suffix, &mut handle) } != SUCCESS || handle.is_null() {
        return None;
    }
    let offset = suffix
        .addr()
        .checked_sub(start)
        .filter(|&offset| offset < bytes)?;
    Some((handle, source_transport(&buffer[..bytes], offset)?))
}
