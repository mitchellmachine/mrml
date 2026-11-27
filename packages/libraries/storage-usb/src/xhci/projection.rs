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

    /// Bind the broker's exact projection to the controller discovered by
    /// the host. Guest-provided geometry must not be used to form this value.
    pub fn for_device_projection(
        backend: P,
        assignment: DmaAssignment,
        projection: mrml_kernel::DeviceDmaProjection,
    ) -> Result<Self, (ProjectionError<P::Error>, P)> {
        let location = assignment.controller.location();
        let address = projection.requester;
        if !projection.valid()
            || (
                location.segment,
                location.bus,
                location.device,
                location.function,
            ) != (
                address.segment(),
                address.bus(),
                address.device(),
                address.function(),
            )
            || assignment.controller.bar0() != (projection.bar_base, projection.bar_bytes)
            || assignment.mapping_generation != projection.dma_generation
            || assignment.device_base != projection.dma_base
            || assignment.bytes != projection.dma_bytes
        {
            return Err((ProjectionError::Assignment, backend));
        }
        Self::new(backend, assignment, projection.bar_pages)
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

impl<L: super::NativePciLease> ScopedXhci<super::NativePciOwner<L>> {
    /// Reconcile the broker choice against the exact retained native binding
    /// before providing any register or DMA operations. On failure the caller
    /// still owns the original lease and must retire or quarantine it.
    pub fn from_native_owner(
        owner: super::NativePciOwner<L>,
        projection: mrml_kernel::DeviceDmaProjection,
    ) -> Result<
        Self,
        (
            ProjectionError<super::NativePciOwnerError<L::Error>>,
            super::NativePciOwner<L>,
        ),
    > {
        if let Err(error) = owner.validate_projection(projection) {
            return Err((ProjectionError::Backend(error), owner));
        }
        let assignment = owner.retained_binding().dma;
        Self::for_device_projection(owner, assignment, projection)
    }
}

impl<P: super::VtdPciPlatform> super::VtdPciPlatform for ScopedXhci<P> {
    fn validate_aperture(
        &self,
        aperture: mrml_kernel::arch::x86_64::VtdDmaAperture,
    ) -> Result<(), Self::Error> {
        self.backend
            .validate_aperture(aperture)
            .map_err(ProjectionError::Backend)
    }

    fn live_pci(&mut self, expected: DmaAssignment) -> Result<PciSnapshot, Self::Error> {
        if expected != self.assignment {
            return Err(ProjectionError::Assignment);
        }
        self.backend
            .live_pci(expected)
            .map_err(ProjectionError::Backend)
    }

    fn set_bus_master(
        &mut self,
        expected: DmaAssignment,
        before: u16,
        enabled: bool,
    ) -> Result<(), Self::Error> {
        if expected != self.assignment {
            return Err(ProjectionError::Assignment);
        }
        self.backend
            .set_bus_master(expected, before, enabled)
            .map_err(ProjectionError::Backend)
    }

    fn release_revoked(&mut self, expected: DmaAssignment) -> Result<(), Self::Error> {
        if expected != self.assignment {
            return Err(ProjectionError::Assignment);
        }
        self.backend
            .release_revoked(expected)
            .map_err(ProjectionError::Backend)
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
