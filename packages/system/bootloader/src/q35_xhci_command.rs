//! Isolated q35 diagnostic. No physical-device binding or normal boot path.
use mrml_kernel::arch::x86_64::{
    ActivePageTables, Mapping, VerifiedVtdUnit, VtdDmaAperture, VtdRegisterIo, VtdTableMemory,
};
use mrml_storage_usb::xhci::{
    Controller, DmaAssignment, DmaLayout, ManagedVtd, Platform, RevocablePlatform, StartFailure,
    VtdPciPlatform,
};

use mrml_storage_usb::xhci::pci::{PciController, PciLocation, PciSnapshot};

const ECAM: usize = 0xffff_d800_0010_1000;
const BRIDGE: usize = 0xffff_d800_0010_2000;
const BAR: usize = 0xffff_d800_0010_3000;
const PAGE: u64 = 4096;
const TICKS: u32 = 1_000_000;

struct Owner {
    aperture: VtdDmaAperture,
    dma: Mapping,
    bar: Mapping,
    retired: bool,
}

impl Owner {
    fn address(&self, offset: u32, write: bool) -> Result<*mut u32, ()> {
        if self.retired
            || !offset.is_multiple_of(4)
            || !match offset {
                0..=0x3c => !write,
                0x40..=0x4bc | 0x1000..=0x121c | 0x2000..=0x281c => true,
                _ => false,
            }
        {
            return Err(());
        }
        Ok((BAR + offset as usize) as *mut u32)
    }

    fn payload(&self, address: u64, len: usize) -> Result<*mut u8, ()> {
        let offset = address.checked_sub(self.aperture.device_base).ok_or(())?;
        if self.retired || len == 0 || offset.checked_add(len as u64).is_none_or(|end| end > PAGE) {
            return Err(());
        }
        Ok((self.dma.virtual_start().get() + offset) as *mut u8)
    }

    fn pci(&self) -> Result<PciSnapshot, ()> {
        if self.retired {
            return Err(());
        }
        // SAFETY: the sealed QEMU BSP owns only this verified ECAM function,
        // using fixed aligned reads within its aperture.
        let words = unsafe {
            [0, 4, 8, 0xc, 0x10, 0x14].map(|o| ((ECAM + o) as *const u32).read_volatile())
        };
        Ok(PciSnapshot {
            location: PciLocation {
                segment: 0,
                bus: 0x41,
                device: 0,
                function: 0,
            },
            configuration_generation: 1,
            vendor_device: words[0],
            command: words[1] as u16,
            class_revision: words[2],
            header_type: (words[3] >> 16) as u8,
            bar0: words[4],
            bar1: words[5],
            bar0_bytes: 0x4000,
        })
    }
}

impl Platform for Owner {
    type Error = ();
    fn read32(&mut self, offset: u32) -> Result<u32, ()> {
        let ptr = self.address(offset, false)?;
        // SAFETY: address enforces the proved device subregions and width.
        Ok(unsafe { ptr.read_volatile() })
    }
    fn write32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
        let ptr = self.address(offset, true)?;
        // SAFETY: exclusive diagnostic owner, checked active UC mapping.
        unsafe { ptr.write_volatile(value) };
        Ok(())
    }
    fn dma_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), ()> {
        let ptr = self.payload(address, bytes.len())?;
        for (i, byte) in bytes.iter().copied().enumerate() {
            // SAFETY: payload checked this exact pinned range; queue ownership
            // is serialized by the driver ring protocol.
            unsafe { ptr.add(i).write_volatile(byte) };
        }
        Ok(())
    }
    fn dma_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), ()> {
        let ptr = self.payload(address, bytes.len())?;
        for (i, byte) in bytes.iter_mut().enumerate() {
            // SAFETY: exact pinned payload; driver validates publication.
            *byte = unsafe { ptr.add(i).read_volatile() };
        }
        Ok(())
    }
    fn publish_dma(&mut self) -> Result<(), ()> {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    fn acquire_dma(&mut self) -> Result<(), ()> {
        self.publish_dma()
    }
    fn wait_tick(&mut self) -> Result<(), ()> {
        core::hint::spin_loop();
        Ok(())
    }
}

impl VtdPciPlatform for Owner {
    fn validate_aperture(&self, aperture: VtdDmaAperture) -> Result<(), ()> {
        (aperture == self.aperture
            && aperture.pages == 1
            && aperture.physical_base == self.dma.physical_start()
            && self.dma.pages() == 1)
            .then_some(())
            .ok_or(())
    }
    fn live_pci(&mut self, expected: DmaAssignment) -> Result<PciSnapshot, ()> {
        if expected.mapping_generation != 1
            || expected.device_base != self.aperture.device_base
            || expected.bytes != PAGE
        {
            return Err(());
        }
        let pci = self.pci()?;
        (PciController::discover(pci).ok() == Some(expected.controller))
            .then_some(pci)
            .ok_or(())
    }
    fn set_bus_master(
        &mut self,
        expected: DmaAssignment,
        before: u16,
        enabled: bool,
    ) -> Result<(), ()> {
        if self.live_pci(expected)?.command != before || before != if enabled { 3 } else { 7 } {
            return Err(());
        }
        // SAFETY: ManagedVtd independently checked the active aperture before
        // enable, or observed halt before disable. These are the sole scoped
        // endpoint and bridge; command-width writes never touch status.
        unsafe {
            let endpoint = (ECAM + 4) as *mut u16;
            let bridge = (BRIDGE + 4) as *mut u16;
            if endpoint.read_volatile() != before || bridge.read_volatile() != before {
                return Err(());
            }
            if enabled {
                bridge.write_volatile(7);
                if bridge.read_volatile() != 7 {
                    return Err(());
                }
                endpoint.write_volatile(7);
            } else {
                endpoint.write_volatile(3);
                if endpoint.read_volatile() != 3 {
                    return Err(());
                }
                bridge.write_volatile(3);
            }
            if endpoint.read_volatile() != (before ^ 4) || bridge.read_volatile() != (before ^ 4) {
                return Err(());
            }
        }
        Ok(())
    }
    fn release_revoked(&mut self, expected: DmaAssignment) -> Result<(), ()> {
        if self.live_pci(expected)?.command != 3 {
            return Err(());
        }
        // SAFETY: the revocation adapter already halted both BME paths and
        // drained the exact VT-d leaf. This boot allocation remains pinned.
        unsafe {
            if ((BRIDGE + 4) as *const u16).read_volatile() != 3 {
                return Err(());
            }
            let page = self.payload(self.aperture.device_base, PAGE as usize)?;
            for i in 0..PAGE as usize {
                page.add(i).write_volatile(0);
            }
            let mut active = ActivePageTables::current().map_err(|_| ())?;
            active.unmap_exact(self.dma).map_err(|_| ())?;
            active.unmap_exact(self.bar).map_err(|_| ())?;
        }
        self.retired = true;
        Ok(())
    }
}

/// # Safety
/// The exact isolated model, owned BAR, root, ECAM, and exclusive pinned WB
/// backing must all have been independently established by the two releases.
pub(super) unsafe fn run<M: VtdTableMemory, R: VtdRegisterIo>(
    tables: &mut M,
    unit: &mut VerifiedVtdUnit<R>,
    aperture: VtdDmaAperture,
    dma: Mapping,
    bar: Mapping,
) -> bool {
    let attempt = (|| {
        if bar.virtual_start().get() != BAR as u64 || bar.pages() != 3 {
            return None;
        }
        let owner = Owner {
            aperture,
            dma,
            bar,
            retired: false,
        };
        let controller = PciController::discover(owner.pci().ok()?).ok()?;
        if controller.bar0() != (0x8120_0000, 0x4000) {
            return None;
        }
        let base = aperture.device_base;
        let assignment = DmaAssignment {
            controller,
            mapping_generation: 1,
            device_base: base,
            bytes: PAGE,
        };
        let dma = DmaLayout {
            device_contexts: base,
            command_ring: base + 0x100,
            event_segments: base + 0x200,
            event_ring: base + 0x300,
        };
        let platform = ManagedVtd::install(owner, tables, unit, assignment, aperture).ok()?;
        let mut controller = match Controller::start_pci(platform, assignment, dma, TICKS) {
            Ok(controller) => controller,
            Err(StartFailure::Untouched { mut platform, .. }) => {
                let _ = platform.revoke_after_halt();
                return None;
            }
            Err(StartFailure::Programming(failure)) => {
                if let Ok(halted) = failure.retry(TICKS) {
                    let _ = halted.revoke();
                }
                return None;
            }
        };
        let completed = controller.no_op(TICKS).is_ok();
        let mut approved = false;
        if completed {
            super::native_fat32_probe::trace(0xc6);
            for _ in 0..100_000_000 {
                match super::native_fat32_probe::fixture_scratch() {
                    0xb8 => core::hint::spin_loop(),
                    0xba => {
                        approved = true;
                        break;
                    }
                    _ => break,
                }
            }
        }
        controller.stop(TICKS).ok()?.revoke().ok()?;
        if completed && approved {
            super::native_fat32_probe::trace(0xc7);
            Some(())
        } else {
            None
        }
    })();
    attempt.is_some()
}
