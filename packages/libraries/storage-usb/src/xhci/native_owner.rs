//! Capability-bound owner of one pre-pinned xHCI PCI assignment.
use mrml_kernel::arch::x86_64::{PciConfigSpace, VtdDmaAperture};
use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, DeviceAddress, ObjectId, Rights};

use super::pci::{PciError, PciSnapshot};
use super::{DmaAssignment, Platform, VtdPciPlatform};

/// Canonical binding held by the supervisor's resource allocator. Geometry is
/// evidence; it cannot replace the matching capabilities or exclusive owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativePciBinding {
    pub device: ObjectId,
    pub memory: ObjectId,
    pub bar_generation: u64,
    pub bar_pages: [u32; 3],
    pub allocation_generation: u64,
    pub dma: DmaAssignment,
    pub aperture: VtdDmaAperture,
}

/// Trusted resource lease provided by the kernel's assignment machinery.
/// Methods must remain serialized against reassignment and hot removal.
/// MMIO and CPU access to pinned, zeroed backing must already be confined to
/// this lease. Unreleased or partially released resources must quarantine on
/// drop. A successful release scrubs and withdraws the same exact resources.
pub trait NativePciLease: Platform + PciConfigSpace {
    fn binding(&self) -> NativePciBinding;

    /// Change only Bus Master Enable in the 16-bit PCI Command register.
    /// Recheck the expected value and never write adjacent PCI Status bits.
    fn set_bus_master16(
        &mut self,
        address: DeviceAddress,
        before: u16,
        enabled: bool,
    ) -> Result<(), Self::Error>;

    /// Called only after the exact aperture is withdrawn and drained. Retry
    /// resumes the same release and retains its binding until success.
    fn release_bound_resources(&mut self, binding: NativePciBinding) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativePciOwnerError<E> {
    Capability(CapabilityError),
    Binding,
    ConfigurationUnavailable,
    Pci(PciError),
    Lease(E),
}

pub struct NativePciOwner<L> {
    lease: L,
    binding: NativePciBinding,
    released: bool,
}

impl<L: NativePciLease> NativePciOwner<L> {
    pub fn admit<const N: usize>(
        capabilities: &CapabilitySpace<N>,
        device: Capability,
        memory: Capability,
        expected: NativePciBinding,
        lease: L,
    ) -> Result<Self, NativePciOwnerError<L::Error>> {
        let device = capabilities
            .authorize_exact(device, Rights::CONTROL)
            .map_err(NativePciOwnerError::Capability)?;
        let memory = capabilities
            .authorize_exact(
                memory,
                Rights::MAP
                    .union(Rights::PIN)
                    .union(Rights::READ)
                    .union(Rights::WRITE),
            )
            .map_err(NativePciOwnerError::Capability)?;
        if device != expected.device
            || memory != expected.memory
            || device == memory
            || expected.bar_generation == 0
            || expected.allocation_generation == 0
            || !expected.dma.valid()
            || expected.aperture.device_base != expected.dma.device_base
            || u64::from(expected.aperture.pages) * 4096 != expected.dma.bytes
            || lease.binding() != expected
        {
            return Err(NativePciOwnerError::Binding);
        }
        Ok(Self {
            lease,
            binding: expected,
            released: false,
        })
    }

    /// Reconcile a broker's requested projection with the independently
    /// retained PCI lease. This is a read-only check, not a mapping operation.
    pub fn validate_projection(
        &self,
        projection: mrml_kernel::DeviceDmaProjection,
    ) -> Result<(), NativePciOwnerError<L::Error>> {
        let binding = self.binding;
        self.check(binding.dma)?;
        let dma = binding.dma;
        if !projection.valid()
            || projection.requester != binding.aperture.route.requester()
            || projection.device != binding.device
            || projection.dma_memory != binding.memory
            || projection.bar_generation != binding.bar_generation
            || projection.bar_pages != binding.bar_pages
            || projection.dma_allocation_generation != binding.allocation_generation
            || projection.dma_generation != dma.mapping_generation
            || (projection.bar_base, projection.bar_bytes) != dma.controller.bar0()
            || (projection.dma_base, projection.dma_bytes) != (dma.device_base, dma.bytes)
        {
            return Err(NativePciOwnerError::Binding);
        }
        Ok(())
    }

    fn check(&self, expected: DmaAssignment) -> Result<(), NativePciOwnerError<L::Error>> {
        if self.released || expected != self.binding.dma || self.lease.binding() != self.binding {
            Err(NativePciOwnerError::Binding)
        } else {
            Ok(())
        }
    }

    fn snapshot(
        &mut self,
        expected: DmaAssignment,
    ) -> Result<PciSnapshot, NativePciOwnerError<L::Error>> {
        self.check(expected)?;
        let location = expected.controller.location();
        let address = self.binding.aperture.route.requester();
        if (
            address.segment(),
            address.bus(),
            address.device(),
            address.function(),
        ) != (
            location.segment,
            location.bus,
            location.device,
            location.function,
        ) {
            return Err(NativePciOwnerError::Binding);
        }
        let mut read = |offset| {
            self.lease
                .read_u32(address, offset)
                .ok_or(NativePciOwnerError::ConfigurationUnavailable)
        };
        Ok(PciSnapshot {
            location,
            configuration_generation: expected.controller.configuration_generation(),
            vendor_device: read(0)?,
            class_revision: read(8)?,
            command: read(4)? as u16,
            header_type: (read(12)? >> 16) as u8,
            bar0: read(0x10)?,
            bar1: read(0x14)?,
            bar0_bytes: u64::from(expected.controller.bar0().1),
        })
    }
}

impl<L: NativePciLease> Platform for NativePciOwner<L> {
    type Error = NativePciOwnerError<L::Error>;

    fn read32(&mut self, offset: u32) -> Result<u32, Self::Error> {
        self.check(self.binding.dma)?;
        self.lease
            .read32(offset)
            .map_err(NativePciOwnerError::Lease)
    }
    fn write32(&mut self, offset: u32, value: u32) -> Result<(), Self::Error> {
        self.check(self.binding.dma)?;
        self.lease
            .write32(offset, value)
            .map_err(NativePciOwnerError::Lease)
    }
    fn dma_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        self.check(self.binding.dma)?;
        self.lease
            .dma_write(address, bytes)
            .map_err(NativePciOwnerError::Lease)
    }
    fn dma_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.check(self.binding.dma)?;
        self.lease
            .dma_read(address, bytes)
            .map_err(NativePciOwnerError::Lease)
    }
    fn publish_dma(&mut self) -> Result<(), Self::Error> {
        self.check(self.binding.dma)?;
        self.lease.publish_dma().map_err(NativePciOwnerError::Lease)
    }
    fn acquire_dma(&mut self) -> Result<(), Self::Error> {
        self.check(self.binding.dma)?;
        self.lease.acquire_dma().map_err(NativePciOwnerError::Lease)
    }
    fn wait_tick(&mut self) -> Result<(), Self::Error> {
        self.check(self.binding.dma)?;
        self.lease.wait_tick().map_err(NativePciOwnerError::Lease)
    }
}

impl<L: NativePciLease> VtdPciPlatform for NativePciOwner<L> {
    fn validate_aperture(&self, aperture: VtdDmaAperture) -> Result<(), Self::Error> {
        self.check(self.binding.dma)?;
        if aperture == self.binding.aperture {
            Ok(())
        } else {
            Err(NativePciOwnerError::Binding)
        }
    }

    fn live_pci(&mut self, expected: DmaAssignment) -> Result<PciSnapshot, Self::Error> {
        self.snapshot(expected)
    }

    fn set_bus_master(
        &mut self,
        expected: DmaAssignment,
        before: u16,
        enabled: bool,
    ) -> Result<(), Self::Error> {
        let live = self.snapshot(expected)?;
        expected
            .controller
            .verify_identity(live)
            .map_err(NativePciOwnerError::Pci)?;
        if live.command != before {
            return Err(NativePciOwnerError::Pci(PciError::CommandMismatch));
        }
        self.lease
            .set_bus_master16(self.binding.aperture.route.requester(), before, enabled)
            .map_err(NativePciOwnerError::Lease)
    }

    fn release_revoked(&mut self, expected: DmaAssignment) -> Result<(), Self::Error> {
        self.check(expected)?;
        self.lease
            .release_bound_resources(self.binding)
            .map_err(NativePciOwnerError::Lease)?;
        self.released = true;
        Ok(())
    }
}
