//! Native ECAM PCI lease composition for already pinned xHCI resources.
use mrml_kernel::DeviceAddress;
use mrml_kernel::arch::x86_64::{EcamCommandError, NativeEcamSegment, PciConfigSpace};

use super::{NativePciBinding, NativePciLease, Platform};

/// Trusted owner of the BAR, pinned DMA backing, and exact assignment lock.
/// A failed release keeps the binding live for retry. Dropping an unreleased
/// backing must quarantine it along with its table entries.
pub trait NativePciBacking: Platform {
    fn binding(&self) -> NativePciBinding;
    fn release_after_drain(&mut self, binding: NativePciBinding) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcamLeaseError<E> {
    Binding,
    Command(EcamCommandError),
    Backing(E),
}

/// An ECAM view restricted to the PCI requester in one resource binding.
pub struct EcamPciLease<'a, B> {
    ecam: &'a mut NativeEcamSegment,
    backing: B,
    binding: NativePciBinding,
    released: bool,
}

impl<'a, B: NativePciBacking> EcamPciLease<'a, B> {
    /// # Safety
    ///
    /// The exact requester's ECAM page must be writable device memory and
    /// remain mapped and serialized under the backing's exclusive assignment
    /// lock until release. Only the trusted activation path may call the
    /// bus-master operation, after verifying live identity and active DMA
    /// isolation. No other accessor may mutate this function concurrently.
    pub unsafe fn adopt(
        ecam: &'a mut NativeEcamSegment,
        backing: B,
    ) -> Result<Self, EcamLeaseError<B::Error>> {
        let binding = backing.binding();
        let location = binding.dma.controller.location();
        let request = binding.aperture.route.requester();
        if (
            request.segment(),
            request.bus(),
            request.device(),
            request.function(),
        ) != (
            location.segment,
            location.bus,
            location.device,
            location.function,
        ) {
            return Err(EcamLeaseError::Binding);
        }
        Ok(Self {
            ecam,
            backing,
            binding,
            released: false,
        })
    }

    fn check(&self) -> Result<(), EcamLeaseError<B::Error>> {
        if !self.released && self.backing.binding() == self.binding {
            Ok(())
        } else {
            Err(EcamLeaseError::Binding)
        }
    }

    fn check_target(&self, address: DeviceAddress) -> Result<(), EcamLeaseError<B::Error>> {
        self.check()?;
        if self.binding.aperture.route.requester() == address {
            Ok(())
        } else {
            Err(EcamLeaseError::Binding)
        }
    }
}

impl<B: NativePciBacking> PciConfigSpace for EcamPciLease<'_, B> {
    fn read_u32(&mut self, address: DeviceAddress, offset: u16) -> Option<u32> {
        self.check_target(address).ok()?;
        self.ecam.read_u32(address, offset)
    }
}

impl<B: NativePciBacking> Platform for EcamPciLease<'_, B> {
    type Error = EcamLeaseError<B::Error>;

    fn read32(&mut self, offset: u32) -> Result<u32, Self::Error> {
        self.check()?;
        self.backing.read32(offset).map_err(EcamLeaseError::Backing)
    }

    fn write32(&mut self, offset: u32, value: u32) -> Result<(), Self::Error> {
        self.check()?;
        self.backing
            .write32(offset, value)
            .map_err(EcamLeaseError::Backing)
    }

    fn dma_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.check()?;
        self.backing
            .dma_read(address, bytes)
            .map_err(EcamLeaseError::Backing)
    }

    fn dma_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        self.check()?;
        self.backing
            .dma_write(address, bytes)
            .map_err(EcamLeaseError::Backing)
    }

    fn publish_dma(&mut self) -> Result<(), Self::Error> {
        self.check()?;
        self.backing.publish_dma().map_err(EcamLeaseError::Backing)
    }

    fn acquire_dma(&mut self) -> Result<(), Self::Error> {
        self.check()?;
        self.backing.acquire_dma().map_err(EcamLeaseError::Backing)
    }

    fn wait_tick(&mut self) -> Result<(), Self::Error> {
        self.check()?;
        self.backing.wait_tick().map_err(EcamLeaseError::Backing)
    }
}

impl<B: NativePciBacking> NativePciLease for EcamPciLease<'_, B> {
    fn binding(&self) -> NativePciBinding {
        // Report the current binding so an outer owner can reject stale state.
        self.backing.binding()
    }

    fn set_bus_master16(
        &mut self,
        address: DeviceAddress,
        before: u16,
        enabled: bool,
    ) -> Result<(), Self::Error> {
        self.check_target(address)?;
        // SAFETY: adoption requires the live, writable ECAM page, the exact
        // exclusive lock and the trusted, ordered activation path. The check
        // above rejects substituted or released assignments.
        unsafe { self.ecam.set_bus_master(address, before, enabled) }
            .map_err(EcamLeaseError::Command)
    }

    fn release_bound_resources(&mut self, binding: NativePciBinding) -> Result<(), Self::Error> {
        self.check()?;
        if binding != self.binding {
            return Err(EcamLeaseError::Binding);
        }
        self.backing
            .release_after_drain(binding)
            .map_err(EcamLeaseError::Backing)?;
        self.released = true;
        Ok(())
    }
}
