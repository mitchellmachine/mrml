//! Fail-closed programming of one quiescent AHCI port's DMA base registers.
//!
//! Engines and interrupts remain disabled. Any uncertainty after the first
//! write quarantines the retained DMA owner instead of making it removable.

use crate::{AhciAbarMapping, AhciPortDmaLayout, AhciRegisterIo, InstalledAhciPortDma};

const PORT_BASE: u32 = 0x100;
const PORT_STRIDE: u32 = 0x80;
const CLB: u32 = 0x00;
const CLBU: u32 = 0x04;
const FB: u32 = 0x08;
const FBU: u32 = 0x0c;
const IE: u32 = 0x14;
const CMD: u32 = 0x18;
const SACT: u32 = 0x34;
const CI: u32 = 0x38;
const ENGINE_MASK: u32 = (1 << 0) | (1 << 4) | (1 << 14) | (1 << 15);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciPortProgramError {
    LayoutMismatch,
    PortBusy,
    RegisterRead,
    RegisterWrite,
    VerificationFailed,
}

#[derive(Debug, Eq, PartialEq)]
pub enum AhciPortProgramFailure {
    Untouched {
        owner: InstalledAhciPortDma,
        error: AhciPortProgramError,
    },
    Quarantined {
        layout: AhciPortDmaLayout,
        error: AhciPortProgramError,
    },
}

impl AhciPortProgramFailure {
    pub const fn error(&self) -> AhciPortProgramError {
        match self {
            Self::Untouched { error, .. } | Self::Quarantined { error, .. } => *error,
        }
    }

    pub fn into_untouched_owner(self) -> Option<InstalledAhciPortDma> {
        match self {
            Self::Untouched { owner, .. } => Some(owner),
            Self::Quarantined { .. } => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ProgrammedAhciPortDma {
    layout: AhciPortDmaLayout,
}

impl ProgrammedAhciPortDma {
    #[cfg(test)]
    pub(crate) const fn from_layout(layout: AhciPortDmaLayout) -> Self {
        Self { layout }
    }

    pub const fn layout(&self) -> AhciPortDmaLayout {
        self.layout
    }

    pub(crate) const fn into_layout(self) -> AhciPortDmaLayout {
        self.layout
    }
}

pub fn program_ahci_port_dma_bases<R: AhciRegisterIo>(
    mapping: AhciAbarMapping,
    owner: InstalledAhciPortDma,
    registers: &mut R,
) -> Result<ProgrammedAhciPortDma, AhciPortProgramFailure> {
    let layout = owner.layout();
    if layout.device_object != mapping.device_object
        || layout.configuration_generation != mapping.configuration_generation
        || layout.mapping_generation != mapping.mapping_generation
        || layout.port >= 32
    {
        return Err(AhciPortProgramFailure::Untouched {
            owner,
            error: AhciPortProgramError::LayoutMismatch,
        });
    }
    let base = PORT_BASE + u32::from(layout.port) * PORT_STRIDE;
    for register in [IE, CMD, SACT, CI] {
        let value = match registers.read_u32(base + register) {
            Ok(value) => value,
            Err(()) => {
                return Err(AhciPortProgramFailure::Untouched {
                    owner,
                    error: AhciPortProgramError::RegisterRead,
                });
            }
        };
        if (register == IE && value != 0)
            || (register == CMD && value & ENGINE_MASK != 0)
            || ((register == SACT || register == CI) && value != 0)
        {
            return Err(AhciPortProgramFailure::Untouched {
                owner,
                error: AhciPortProgramError::PortBusy,
            });
        }
    }

    let values = [
        (CLB, layout.command_list.physical_base as u32),
        (CLBU, (layout.command_list.physical_base >> 32) as u32),
        (FB, layout.received_fis.physical_base as u32),
        (FBU, (layout.received_fis.physical_base >> 32) as u32),
    ];
    for (register, value) in values {
        if registers.write_u32(base + register, value).is_err() {
            return Err(AhciPortProgramFailure::Quarantined {
                layout: owner.into_layout(),
                error: AhciPortProgramError::RegisterWrite,
            });
        }
    }
    for (register, expected) in values {
        match registers.read_u32(base + register) {
            Ok(actual) if actual == expected => {}
            Ok(_) => {
                return Err(AhciPortProgramFailure::Quarantined {
                    layout: owner.into_layout(),
                    error: AhciPortProgramError::VerificationFailed,
                });
            }
            Err(()) => {
                return Err(AhciPortProgramFailure::Quarantined {
                    layout: owner.into_layout(),
                    error: AhciPortProgramError::RegisterRead,
                });
            }
        }
    }
    Ok(ProgrammedAhciPortDma {
        layout: owner.into_layout(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AhciDmaRegion, AhciPortDmaLayout};
    use mrml_kernel::ObjectId;

    #[derive(Default)]
    struct Registers {
        values: [u32; 16],
        writes: usize,
        reject_write: Option<usize>,
        corrupt_readback: bool,
    }

    impl AhciRegisterIo for Registers {
        fn read_u32(&mut self, offset: u32) -> Result<u32, ()> {
            let register = offset.checked_sub(PORT_BASE).ok_or(())?;
            let index = usize::try_from(register / 4).map_err(|_| ())?;
            let mut value = *self.values.get(index).ok_or(())?;
            if self.corrupt_readback && register == CLB && self.writes == 4 {
                value ^= 1;
            }
            Ok(value)
        }

        fn write_u32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
            if self.reject_write == Some(self.writes) {
                return Err(());
            }
            let register = offset.checked_sub(PORT_BASE).ok_or(())?;
            let index = usize::try_from(register / 4).map_err(|_| ())?;
            *self.values.get_mut(index).ok_or(())? = value;
            self.writes += 1;
            Ok(())
        }
    }

    fn mapping() -> AhciAbarMapping {
        AhciAbarMapping {
            device_object: ObjectId(10),
            configuration_generation: 7,
            mapping_generation: 9,
            physical_base: 0xf000_0000,
            virtual_base: 0xffff_9000_0000_0000,
            bytes: 0x2000,
        }
    }

    fn owner() -> InstalledAhciPortDma {
        InstalledAhciPortDma::from_layout(AhciPortDmaLayout {
            device_object: ObjectId(10),
            configuration_generation: 7,
            mapping_generation: 9,
            port: 0,
            command_slot_count: 4,
            command_list: AhciDmaRegion {
                memory_object: ObjectId(20),
                allocation_generation: 1,
                physical_base: 0x1_0000_1000,
                bytes: 1024,
            },
            received_fis: AhciDmaRegion {
                memory_object: ObjectId(21),
                allocation_generation: 2,
                physical_base: 0x2_0000_2000,
                bytes: 256,
            },
            command_tables: AhciDmaRegion {
                memory_object: ObjectId(22),
                allocation_generation: 3,
                physical_base: 0x3000,
                bytes: 1024,
            },
            dma_generation: 11,
        })
    }

    #[test]
    fn programs_and_verifies_both_64_bit_bases_without_starting_engines() {
        let mut registers = Registers::default();
        let programmed = program_ahci_port_dma_bases(mapping(), owner(), &mut registers).unwrap();
        assert_eq!(programmed.layout().dma_generation, 11);
        assert_eq!(&registers.values[..4], &[0x1000, 1, 0x2000, 2]);
        assert_eq!(registers.values[(CMD / 4) as usize], 0);
        assert_eq!(registers.writes, 4);
    }

    #[test]
    fn preflight_failure_returns_the_untouched_owner() {
        let mut registers = Registers::default();
        registers.values[(CMD / 4) as usize] = 1;
        let failure = program_ahci_port_dma_bases(mapping(), owner(), &mut registers).unwrap_err();
        assert_eq!(failure.error(), AhciPortProgramError::PortBusy);
        assert_eq!(
            failure
                .into_untouched_owner()
                .unwrap()
                .layout()
                .dma_generation,
            11
        );
        assert_eq!(registers.writes, 0);
    }

    #[test]
    fn post_write_uncertainty_quarantines_the_layout() {
        for registers in [
            Registers {
                reject_write: Some(2),
                ..Registers::default()
            },
            Registers {
                corrupt_readback: true,
                ..Registers::default()
            },
        ] {
            let mut registers = registers;
            let failure =
                program_ahci_port_dma_bases(mapping(), owner(), &mut registers).unwrap_err();
            assert!(matches!(
                &failure,
                AhciPortProgramFailure::Quarantined { .. }
            ));
            assert!(failure.into_untouched_owner().is_none());
        }
    }
}
