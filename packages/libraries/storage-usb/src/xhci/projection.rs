//! Bounds one controller's brokered data plane. This adapter validates
//! accesses; it does not install CPU or IOMMU mappings or authorize PCI.
use super::pci::PciSnapshot;
use super::{DmaAssignment, PciActivation, Platform, RevocablePlatform};

const PAGE: u32 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionError<E> {
    Assignment,
    MmioRange,
    DmaRange,
    Backend(E),
}

/// One fixed assignment and the exact BAR pages approved by the broker.
/// The backend must hold the same resources exclusively until revocation;
/// this allowlist is not a substitute for the broker's hardware protection.
pub struct ScopedXhci<P> {
    backend: P,
    assignment: DmaAssignment,
    pages: [u32; 3],
}

impl<P: Platform> ScopedXhci<P> {
    /// Accepts exactly three distinct BAR-page offsets in ascending order.
    /// The capability page at zero is mandatory. The broker, not the
    /// driver, identifies the other two pages and excludes MSI-X.
    pub fn new(
        backend: P,
        assignment: DmaAssignment,
        pages: [u32; 3],
    ) -> Result<Self, (ProjectionError<P::Error>, P)> {
        let (_, bar_len) = assignment.controller.bar0();
        if !assignment.valid()
            || pages[0] != 0
            || pages[1] <= pages[0]
            || pages[2] <= pages[1]
            || pages.iter().any(|offset| {
                offset % PAGE != 0 || !offset.checked_add(PAGE).is_some_and(|end| end <= bar_len)
            })
        {
            return Err((ProjectionError::Assignment, backend));
        }
        Ok(Self {
            backend,
            assignment,
            pages,
        })
    }

    fn check_mmio(&self, offset: u32) -> Result<(), ProjectionError<P::Error>> {
        let page = offset & !(PAGE - 1);
        if offset % 4 != 0 || !self.pages.contains(&page) {
            return Err(ProjectionError::MmioRange);
        }
        Ok(())
    }

    fn check_dma(&self, address: u64, length: usize) -> Result<(), ProjectionError<P::Error>> {
        let length = u64::try_from(length).map_err(|_| ProjectionError::DmaRange)?;
        if length == 0 || !self.assignment.contains(address, length) {
            return Err(ProjectionError::DmaRange);
        }
        Ok(())
    }
}

impl<P: Platform> Platform for ScopedXhci<P> {
    type Error = ProjectionError<P::Error>;

    fn read32(&mut self, offset: u32) -> Result<u32, Self::Error> {
        self.check_mmio(offset)?;
        self.backend
            .read32(offset)
            .map_err(ProjectionError::Backend)
    }

    fn write32(&mut self, offset: u32, value: u32) -> Result<(), Self::Error> {
        self.check_mmio(offset)?;
        self.backend
            .write32(offset, value)
            .map_err(ProjectionError::Backend)
    }

    fn dma_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        self.check_dma(address, bytes.len())?;
        self.backend
            .dma_write(address, bytes)
            .map_err(ProjectionError::Backend)
    }

    fn dma_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.check_dma(address, bytes.len())?;
        self.backend
            .dma_read(address, bytes)
            .map_err(ProjectionError::Backend)
    }

    fn publish_dma(&mut self) -> Result<(), Self::Error> {
        self.backend.publish_dma().map_err(ProjectionError::Backend)
    }

    fn acquire_dma(&mut self) -> Result<(), Self::Error> {
        self.backend.acquire_dma().map_err(ProjectionError::Backend)
    }

    fn wait_tick(&mut self) -> Result<(), Self::Error> {
        self.backend.wait_tick().map_err(ProjectionError::Backend)
    }
}

impl<P: RevocablePlatform> RevocablePlatform for ScopedXhci<P> {
    fn revoke_after_halt(&mut self) -> Result<(), Self::Error> {
        // The retained backend must still be able to revoke its exact lease
        // even if the current live mapping no longer validates for I/O.
        self.backend
            .revoke_after_halt()
            .map_err(ProjectionError::Backend)
    }
}

impl<P: PciActivation> PciActivation for ScopedXhci<P> {
    fn activation_state(&mut self) -> Result<(PciSnapshot, DmaAssignment), Self::Error> {
        let (snapshot, live) = self
            .backend
            .activation_state()
            .map_err(ProjectionError::Backend)?;
        if live != self.assignment {
            return Err(ProjectionError::Assignment);
        }
        Ok((snapshot, live))
    }

    fn enable_bus_master(
        &mut self,
        expected: DmaAssignment,
        before: u16,
    ) -> Result<(), Self::Error> {
        if expected != self.assignment {
            return Err(ProjectionError::Assignment);
        }
        self.backend
            .enable_bus_master(expected, before)
            .map_err(ProjectionError::Backend)
    }
}
