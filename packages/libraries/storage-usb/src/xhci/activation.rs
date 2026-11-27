//! Gate bus-master activation on an exact, already installed DMA assignment.
use super::pci::{PciController, PciError, PciSnapshot};
use super::{Controller, DmaLayout, Error, RevocablePlatform, StartFailure};

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

    fn valid(self) -> bool {
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
        mut platform: P,
        expected: DmaAssignment,
        dma: DmaLayout,
        ticks: u32,
    ) -> Result<Self, StartFailure<P>> {
        if let Err(error) = check(&mut platform, expected, None) {
            return Err(StartFailure::Untouched { error, platform });
        }
        Self::start_inner(
            platform,
            expected.controller.bar0().1,
            Some(expected),
            dma,
            ticks,
            |platform| {
                let before = check(platform, expected, None)?;
                platform
                    .enable_bus_master(expected, before)
                    .map_err(Error::Platform)?;
                check(platform, expected, Some(before | BUS_MASTER))?;
                Ok(())
            },
        )
    }
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
