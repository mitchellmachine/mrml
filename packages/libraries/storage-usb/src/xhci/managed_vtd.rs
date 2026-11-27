//! Supervisor-side xHCI adapter for a preallocated Intel VT-d assignment.
use mrml_kernel::arch::x86_64::{
    VerifiedVtdUnit, VtdApertureInstallError, VtdApertureRevokeError, VtdBindingError,
    VtdDmaAperture, VtdRegisterIo, VtdTableMemory,
};

use super::pci::{PciError, PciSnapshot};
use super::{DmaAssignment, PciActivation, Platform, RevocablePlatform};

const MEMORY: u16 = 1 << 1;
const BUS_MASTER: u16 = 1 << 2;

/// A trusted supervisor owner, not a device-driver capability. It owns the
/// PCI generation, pinned backing, BAR and exclusion of ATS, aliases and
/// reserved ranges. Dropping an unreleased owner must quarantine those
/// resources (including the translation slots); absence of a Rust reference
/// is not evidence that hardware lost access.
pub trait VtdPciPlatform: Platform {
    fn live_pci(&mut self, expected: DmaAssignment) -> Result<PciSnapshot, Self::Error>;

    /// Compare the exact live identity and command under the assignment lock
    /// before a command-width write that changes only Bus Master Enable.
    fn set_bus_master(
        &mut self,
        expected: DmaAssignment,
        before: u16,
        enabled: bool,
    ) -> Result<(), Self::Error>;

    /// After the exact mapping is denied and drained, scrub backing and
    /// withdraw the BAR, CPU mappings and pins. Retry must be idempotent.
    fn release_revoked(&mut self, expected: DmaAssignment) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedVtdError<E> {
    Platform(E),
    Pci(PciError),
    Geometry,
    Install(VtdApertureInstallError),
    Verify(VtdBindingError),
    Revoke(VtdApertureRevokeError),
    Retired,
    NotHalted,
}

/// Owns the supervisor assignment while borrowing its exclusive VT-d views.
/// Normal driver initialization is Controller::start_pci; this adapter
/// independently verifies the mapping on each activation snapshot.
pub struct ManagedVtd<'a, P, M, R> {
    owner: P,
    tables: &'a mut M,
    unit: &'a mut VerifiedVtdUnit<R>,
    assignment: DmaAssignment,
    aperture: VtdDmaAperture,
    cleanup: Cleanup,
    operational: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Cleanup {
    Active,
    Withdrawing,
    Withdrawn,
    Released,
}

impl<'a, P: VtdPciPlatform, M: VtdTableMemory, R: VtdRegisterIo> ManagedVtd<'a, P, M, R> {
    /// Requires an already halted xHCI with PCI memory decoding enabled and
    /// bus mastering off. No failure returns a raw owner that can free pins.
    /// Failed adoption follows the supervisor owner's quarantine policy.
    pub fn install(
        mut owner: P,
        tables: &'a mut M,
        unit: &'a mut VerifiedVtdUnit<R>,
        assignment: DmaAssignment,
        aperture: VtdDmaAperture,
    ) -> Result<Self, ManagedVtdError<P::Error>> {
        let location = assignment.controller.location();
        let requester = aperture.route.requester();
        if !assignment.valid()
            || assignment.device_base != aperture.device_base
            || assignment.bytes != u64::from(aperture.pages) * 4096
            || (
                location.segment,
                location.bus,
                location.device,
                location.function,
            ) != (
                requester.segment(),
                requester.bus(),
                requester.device(),
                requester.function(),
            )
        {
            return Err(ManagedVtdError::Geometry);
        }
        let pci = owner
            .live_pci(assignment)
            .map_err(ManagedVtdError::Platform)?;
        assignment
            .controller
            .verify_unarmed(pci)
            .map_err(ManagedVtdError::Pci)?;
        if pci.command & MEMORY == 0 {
            return Err(ManagedVtdError::Pci(PciError::CommandMismatch));
        }
        // Platform admission proves the BAR and stopped state before this
        // call. Recheck that the controller has not become active.
        let op = owner.read32(0).map_err(ManagedVtdError::Platform)? & 0xff;
        if op < 0x20 || op % 4 != 0 || op + 8 > assignment.controller.bar0().1 {
            return Err(ManagedVtdError::Geometry);
        }
        if owner.read32(op).map_err(ManagedVtdError::Platform)? & 3 != 0
            || owner.read32(op + 4).map_err(ManagedVtdError::Platform)? & (1 | (1 << 11)) != 1
        {
            return Err(ManagedVtdError::Geometry);
        }
        unit.install_routed_dma_aperture(tables, aperture)
            .map_err(ManagedVtdError::Install)?;
        Ok(Self {
            owner,
            tables,
            unit,
            assignment,
            aperture,
            cleanup: Cleanup::Active,
            operational: op,
        })
    }

    fn verify(&mut self) -> Result<(), ManagedVtdError<P::Error>> {
        if self.cleanup != Cleanup::Active {
            return Err(ManagedVtdError::Retired);
        }
        let aperture = self.aperture;
        self.unit
            .verify_routed_dma_aperture(
                self.tables,
                aperture.route,
                aperture.hardware_domain,
                aperture.device_base,
                aperture.physical_base,
                aperture.pages,
            )
            .map_err(ManagedVtdError::Verify)
    }
}

impl<P: VtdPciPlatform, M, R> ManagedVtd<'_, P, M, R> {
    fn check_mmio(&self, offset: u32) -> Result<(), ManagedVtdError<P::Error>> {
        if self.cleanup != Cleanup::Active {
            return Err(ManagedVtdError::Retired);
        }
        if offset % 4 != 0
            || offset
                .checked_add(4)
                .is_none_or(|end| end > self.assignment.controller.bar0().1)
        {
            return Err(ManagedVtdError::Geometry);
        }
        Ok(())
    }

    fn check_dma(&self, address: u64, bytes: usize) -> Result<(), ManagedVtdError<P::Error>> {
        if self.cleanup != Cleanup::Active {
            return Err(ManagedVtdError::Retired);
        }
        if bytes == 0 || !self.assignment.contains(address, bytes as u64) {
            return Err(ManagedVtdError::Geometry);
        }
        Ok(())
    }
}

impl<P: VtdPciPlatform, M, R> Platform for ManagedVtd<'_, P, M, R> {
    type Error = ManagedVtdError<P::Error>;

    fn read32(&mut self, offset: u32) -> Result<u32, Self::Error> {
        self.check_mmio(offset)?;
        self.owner.read32(offset).map_err(ManagedVtdError::Platform)
    }
    fn write32(&mut self, offset: u32, value: u32) -> Result<(), Self::Error> {
        self.check_mmio(offset)?;
        self.owner
            .write32(offset, value)
            .map_err(ManagedVtdError::Platform)
    }
    fn dma_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        self.check_dma(address, bytes.len())?;
        self.owner
            .dma_write(address, bytes)
            .map_err(ManagedVtdError::Platform)
    }
    fn dma_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.check_dma(address, bytes.len())?;
        self.owner
            .dma_read(address, bytes)
            .map_err(ManagedVtdError::Platform)
    }
    fn publish_dma(&mut self) -> Result<(), Self::Error> {
        self.owner.publish_dma().map_err(ManagedVtdError::Platform)
    }
    fn acquire_dma(&mut self) -> Result<(), Self::Error> {
        self.owner.acquire_dma().map_err(ManagedVtdError::Platform)
    }
    fn wait_tick(&mut self) -> Result<(), Self::Error> {
        self.owner.wait_tick().map_err(ManagedVtdError::Platform)
    }
}

impl<P: VtdPciPlatform, M: VtdTableMemory, R: VtdRegisterIo> PciActivation
    for ManagedVtd<'_, P, M, R>
{
    fn activation_state(&mut self) -> Result<(PciSnapshot, DmaAssignment), Self::Error> {
        if self.cleanup != Cleanup::Active {
            return Err(ManagedVtdError::Retired);
        }
        let snapshot = self
            .owner
            .live_pci(self.assignment)
            .map_err(ManagedVtdError::Platform)?;
        self.verify()?;
        Ok((snapshot, self.assignment))
    }

    fn enable_bus_master(
        &mut self,
        expected: DmaAssignment,
        before: u16,
    ) -> Result<(), Self::Error> {
        if before & BUS_MASTER != 0 || expected != self.assignment {
            return Err(ManagedVtdError::Pci(PciError::AssignmentChanged));
        }
        self.verify()?;
        self.owner
            .set_bus_master(expected, before, true)
            .map_err(ManagedVtdError::Platform)
    }
}

impl<P: VtdPciPlatform, M: VtdTableMemory, R: VtdRegisterIo> RevocablePlatform
    for ManagedVtd<'_, P, M, R>
{
    fn revoke_after_halt(&mut self) -> Result<(), Self::Error> {
        if matches!(self.cleanup, Cleanup::Active | Cleanup::Withdrawing) {
            let pci = self
                .owner
                .live_pci(self.assignment)
                .map_err(ManagedVtdError::Platform)?;
            self.assignment
                .controller
                .verify_identity(pci)
                .map_err(ManagedVtdError::Pci)?;
            if pci.command & MEMORY == 0 {
                return Err(ManagedVtdError::Pci(PciError::CommandMismatch));
            }
            let command = self
                .owner
                .read32(self.operational)
                .map_err(ManagedVtdError::Platform)?;
            let status = self
                .owner
                .read32(self.operational + 4)
                .map_err(ManagedVtdError::Platform)?;
            if command & 3 != 0 || status & (1 | (1 << 11)) != 1 {
                return Err(ManagedVtdError::NotHalted);
            }
        }
        finish_cleanup(&mut self.cleanup, &mut self.owner, self.assignment, || {
            self.unit
                .revoke_routed_dma_aperture(self.tables, self.aperture)
                .map_err(ManagedVtdError::Revoke)
        })
    }
}

pub(super) fn finish_cleanup<P: VtdPciPlatform>(
    progress: &mut Cleanup,
    owner: &mut P,
    assignment: DmaAssignment,
    withdraw: impl FnOnce() -> Result<(), ManagedVtdError<P::Error>>,
) -> Result<(), ManagedVtdError<P::Error>> {
    if matches!(*progress, Cleanup::Active | Cleanup::Withdrawing) {
        *progress = Cleanup::Withdrawing;
        let pci = owner
            .live_pci(assignment)
            .map_err(ManagedVtdError::Platform)?;
        assignment
            .controller
            .verify_identity(pci)
            .map_err(ManagedVtdError::Pci)?;
        if pci.command & BUS_MASTER != 0 {
            owner
                .set_bus_master(assignment, pci.command, false)
                .map_err(ManagedVtdError::Platform)?;
        }
        let after = owner
            .live_pci(assignment)
            .map_err(ManagedVtdError::Platform)?;
        assignment
            .controller
            .verify_unarmed(after)
            .map_err(ManagedVtdError::Pci)?;
        if after.command != pci.command & !BUS_MASTER {
            return Err(ManagedVtdError::Pci(PciError::CommandMismatch));
        }
        withdraw()?;
        *progress = Cleanup::Withdrawn;
    }
    if *progress == Cleanup::Withdrawn {
        owner
            .release_revoked(assignment)
            .map_err(ManagedVtdError::Platform)?;
        *progress = Cleanup::Released;
    }
    Ok(())
}
