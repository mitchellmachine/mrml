//! Gate bus-master activation on an exact, already installed DMA assignment.
use mrml_kernel::PhysAddr;
use mrml_kernel::arch::x86_64::{
    VerifiedVtdUnit, VtdRegisterIo, VtdRequesterRoute, VtdTableMemory,
};

use super::pci::{PciController, PciError, PciSnapshot};
use super::{Controller, DmaLayout, Error, RevocablePlatform, ScratchpadPlan, StartFailure};

const MEMORY: u16 = 1 << 1;
const BUS_MASTER: u16 = 1 << 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaAssignment {
    pub controller: PciController,
    pub mapping_generation: u64,
    pub device_base: u64,
    pub bytes: u64,
}

impl DmaAssignment {
    pub(super) fn contains(self, base: u64, bytes: u64) -> bool {
        base >= self.device_base
            && base
                .checked_add(bytes)
                .zip(self.device_base.checked_add(self.bytes))
                .is_some_and(|(end, limit)| end <= limit)
    }

    pub(super) fn valid(self) -> bool {
        self.mapping_generation != 0
            && self.device_base != 0
            && self.device_base % 4096 == 0
            && self.bytes != 0
            && self.bytes % 4096 == 0
            && self.device_base.checked_add(self.bytes).is_some()
    }
}

/// Trusted backend holding the exclusive PCI assignment from discovery through
/// shutdown. A supplied label is not a mapping. Report only the currently
/// installed mapping with synchronized translation caches; the backend
/// must keep both the MMIO and DMA mappings pinned across every operation.
/// Physical backends must enforce this with the kernel and IOMMU.
pub trait PciActivation: RevocablePlatform {
    fn activation_state(&mut self) -> Result<(PciSnapshot, DmaAssignment), Self::Error>;

    /// Compare the exact live assignment and command under the assignment
    /// lock, then set only Bus Master Enable with a command-width write. An
    /// uncertain result must retain the original assignment for shutdown.
    fn enable_bus_master(
        &mut self,
        expected: DmaAssignment,
        before: u16,
    ) -> Result<(), Self::Error>;
}

impl<P: PciActivation> Controller<P> {
    /// Requires a live, isolated, revocable assignment with memory decoding
    /// already on but bus mastering off. Reset and queue-memory publication
    /// precede enabling DMA. Registers are programmed and the controller is
    /// run only after exact PCI readback.
    pub fn start_pci(
        platform: P,
        expected: DmaAssignment,
        dma: DmaLayout,
        ticks: u32,
    ) -> Result<Self, StartFailure<P>> {
        Self::start_checked_pci(platform, expected, dma, ticks, || Ok(()))
    }

    /// Supervisor-only activation with an independent read of the exact
    /// installed VT-d translations. The trusted platform still owns the
    /// assignment lock, pins, cache synchronization and revocation. The
    /// table and register views must refer to those same live resources.
    pub fn start_vtd_pci<M: VtdTableMemory, R: VtdRegisterIo>(
        platform: P,
        expected: DmaAssignment,
        dma: DmaLayout,
        ticks: u32,
        vt_d: VtdActivation<'_, M, R>,
    ) -> Result<Self, StartFailure<P>> {
        let request = vt_d.route.requester();
        let location = expected.controller.location();
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
            return Err(StartFailure::Untouched {
                error: Error::Pci(PciError::AssignmentChanged),
                platform,
            });
        }
        Self::start_checked_pci(platform, expected, dma, ticks, move || {
            let pages = u16::try_from(expected.bytes / 4096).map_err(|_| Error::InvalidDma)?;
            vt_d.unit
                .verify_routed_dma_aperture(
                    vt_d.tables,
                    vt_d.route,
                    vt_d.hardware_domain,
                    expected.device_base,
                    vt_d.physical_base,
                    pages,
                )
                .map_err(Error::Vtd)
        })
    }

    pub(super) fn start_checked_pci(
        platform: P,
        expected: DmaAssignment,
        dma: DmaLayout,
        ticks: u32,
        verify_translation: impl FnMut() -> Result<(), Error<P::Error>>,
    ) -> Result<Self, StartFailure<P>> {
        Self::start_checked_pci_with_scratchpads(
            platform, expected, dma, None, ticks, verify_translation,
        )
    }

    pub(super) fn start_checked_pci_with_scratchpads(
        mut platform: P,
        expected: DmaAssignment,
        dma: DmaLayout,
        scratchpads: Option<ScratchpadPlan>,
        ticks: u32,
        mut verify_translation: impl FnMut() -> Result<(), Error<P::Error>>,
    ) -> Result<Self, StartFailure<P>> {
        if let Err(error) = check(&mut platform, expected, None).and_then(|_| verify_translation())
        {
            return Err(StartFailure::Untouched { error, platform });
        }
        Self::start_inner_with_scratchpads(
            platform,
            expected.controller.bar0().1,
            Some(expected),
            dma,
            scratchpads,
            ticks,
            |platform| {
                let before = check(platform, expected, None)?;
                verify_translation()?;
                platform
                    .enable_bus_master(expected, before)
                    .map_err(Error::Platform)?;
                check(platform, expected, Some(before | BUS_MASTER))?;
                verify_translation()
            },
        )
    }
}

/// Borrowed read access for the startup checks; not a DMA authorization.
pub struct VtdActivation<'a, M, R> {
    pub unit: &'a mut VerifiedVtdUnit<R>,
    pub tables: &'a M,
    pub route: VtdRequesterRoute,
    pub hardware_domain: u16,
    pub physical_base: PhysAddr,
}

fn check<P: PciActivation>(
    platform: &mut P,
    expected: DmaAssignment,
    enabled_command: Option<u16>,
) -> Result<u16, Error<P::Error>> {
    if !expected.valid() {
        return Err(Error::InvalidDma);
    }
    let (live, mapping) = platform.activation_state().map_err(Error::Platform)?;
    if mapping != expected {
        return Err(Error::InvalidDma);
    }
    if let Some(command) = enabled_command {
        expected
            .controller
            .verify_identity(live)
            .map_err(Error::Pci)?;
        if live.command != command {
            return Err(Error::Pci(PciError::CommandMismatch));
        }
    } else {
        expected
            .controller
            .verify_unarmed(live)
            .map_err(Error::Pci)?;
        if live.command & MEMORY == 0 {
            return Err(Error::Pci(PciError::CommandMismatch));
        }
    }
    Ok(live.command)
}
