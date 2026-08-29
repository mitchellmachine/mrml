//! Fail-closed activation of an initialized AHCI port command engine.
//!
//! This transition leaves interrupts disabled and issues no command. Once the
//! first engine write occurs, uncertainty quarantines the DMA layout.

use crate::{AhciAbarMapping, AhciPortDmaLayout, AhciRegisterIo, InitializedAhciCommandMemory};

const PORT_BASE: u32 = 0x100;
const PORT_STRIDE: u32 = 0x80;
const IE: u32 = 0x14;
const CMD: u32 = 0x18;
const TFD: u32 = 0x20;
const SACT: u32 = 0x34;
const CI: u32 = 0x38;
const CMD_ST: u32 = 1 << 0;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;
const TFD_BUSY_OR_DRQ: u32 = (1 << 7) | (1 << 3);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciEngineError {
    LayoutMismatch,
    PortBusy,
    RegisterRead,
    RegisterWrite,
    VerificationFailed,
}

#[derive(Debug, Eq, PartialEq)]
pub enum AhciEngineFailure {
    Untouched {
        owner: InitializedAhciCommandMemory,
        error: AhciEngineError,
    },
    Quarantined {
        layout: AhciPortDmaLayout,
        error: AhciEngineError,
    },
}

impl AhciEngineFailure {
    pub const fn error(&self) -> AhciEngineError {
        match self {
            Self::Untouched { error, .. } | Self::Quarantined { error, .. } => *error,
        }
    }

    pub fn into_untouched_owner(self) -> Option<InitializedAhciCommandMemory> {
        match self {
            Self::Untouched { owner, .. } => Some(owner),
            Self::Quarantined { .. } => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ActiveAhciPort {
    layout: AhciPortDmaLayout,
}

impl ActiveAhciPort {
    pub const fn layout(&self) -> AhciPortDmaLayout {
        self.layout
    }
}

pub fn start_ahci_port_engine<R: AhciRegisterIo>(
    mapping: AhciAbarMapping,
    owner: InitializedAhciCommandMemory,
    registers: &mut R,
) -> Result<ActiveAhciPort, AhciEngineFailure> {
    let layout = owner.layout();
    if layout.device_object != mapping.device_object
        || layout.configuration_generation != mapping.configuration_generation
        || layout.mapping_generation != mapping.mapping_generation
        || layout.port >= 32
    {
        return Err(AhciEngineFailure::Untouched {
            owner,
            error: AhciEngineError::LayoutMismatch,
        });
    }
    let base = PORT_BASE + u32::from(layout.port) * PORT_STRIDE;
    let mut values = [0_u32; 5];
    for (index, register) in [CMD, IE, TFD, SACT, CI].into_iter().enumerate() {
        values[index] = match registers.read_u32(base + register) {
            Ok(value) => value,
            Err(()) => {
                return Err(AhciEngineFailure::Untouched {
                    owner,
                    error: AhciEngineError::RegisterRead,
                });
            }
        };
    }
    let [command, interrupt_enable, task_file, active, issued] = values;
    if command & (CMD_ST | CMD_FRE | CMD_FR | CMD_CR) != 0
        || interrupt_enable != 0
        || task_file & TFD_BUSY_OR_DRQ != 0
        || active != 0
        || issued != 0
    {
        return Err(AhciEngineFailure::Untouched {
            owner,
            error: AhciEngineError::PortBusy,
        });
    }

    let fre = command | CMD_FRE;
    write_and_verify(registers, base + CMD, fre, layout)?;
    let started = fre | CMD_ST;
    write_and_verify(registers, base + CMD, started, layout)?;
    Ok(ActiveAhciPort {
        layout: owner.into_layout(),
    })
}

fn write_and_verify<R: AhciRegisterIo>(
    registers: &mut R,
    offset: u32,
    expected: u32,
    layout: AhciPortDmaLayout,
) -> Result<(), AhciEngineFailure> {
    registers
        .write_u32(offset, expected)
        .map_err(|()| AhciEngineFailure::Quarantined {
            layout,
            error: AhciEngineError::RegisterWrite,
        })?;
    match registers.read_u32(offset) {
        Ok(actual) if actual == expected => Ok(()),
        _ => Err(AhciEngineFailure::Quarantined {
            layout,
            error: AhciEngineError::VerificationFailed,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AhciDmaRegion, AhciPortDmaLayout, ProgrammedAhciPortDma, initialize_ahci_command_memory,
    };
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
            let index =
                usize::try_from(offset.checked_sub(PORT_BASE).ok_or(())? / 4).map_err(|_| ())?;
            let mut value = *self.values.get(index).ok_or(())?;
            if self.corrupt_readback && self.writes != 0 && offset == PORT_BASE + CMD {
                value ^= CMD_FRE;
            }
            Ok(value)
        }

        fn write_u32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
            if self.reject_write == Some(self.writes) {
                return Err(());
            }
            let index =
                usize::try_from(offset.checked_sub(PORT_BASE).ok_or(())? / 4).map_err(|_| ())?;
            *self.values.get_mut(index).ok_or(())? = value;
            self.writes += 1;
            Ok(())
        }
    }

    struct Memory {
        words: [u32; 576],
    }

    impl Default for Memory {
        fn default() -> Self {
            Self { words: [0; 576] }
        }
    }

    impl crate::AhciCommandMemoryIo for Memory {
        fn read_u32(&mut self, region: AhciDmaRegion, offset: u64) -> Result<u32, ()> {
            let base = match region.memory_object.0 {
                20 => 0,
                21 => 256,
                22 => 320,
                _ => return Err(()),
            };
            self.words
                .get(base + usize::try_from(offset / 4).map_err(|_| ())?)
                .copied()
                .ok_or(())
        }

        fn write_u32(&mut self, region: AhciDmaRegion, offset: u64, value: u32) -> Result<(), ()> {
            if region.memory_object != ObjectId(20) {
                return Err(());
            }
            *self
                .words
                .get_mut(usize::try_from(offset / 4).map_err(|_| ())?)
                .ok_or(())? = value;
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

    fn owner() -> InitializedAhciCommandMemory {
        let layout = AhciPortDmaLayout {
            device_object: ObjectId(10),
            configuration_generation: 7,
            mapping_generation: 9,
            port: 0,
            command_slot_count: 1,
            command_list: AhciDmaRegion {
                memory_object: ObjectId(20),
                allocation_generation: 1,
                physical_base: 0x1000,
                bytes: 1024,
            },
            received_fis: AhciDmaRegion {
                memory_object: ObjectId(21),
                allocation_generation: 2,
                physical_base: 0x2000,
                bytes: 256,
            },
            command_tables: AhciDmaRegion {
                memory_object: ObjectId(22),
                allocation_generation: 3,
                physical_base: 0x3000,
                bytes: 256,
            },
            dma_generation: 11,
        };
        initialize_ahci_command_memory(
            ProgrammedAhciPortDma::from_layout(layout),
            &mut Memory::default(),
        )
        .unwrap()
    }

    #[test]
    fn starts_fis_receive_before_command_processing_and_keeps_interrupts_disabled() {
        let mut registers = Registers::default();
        let active = start_ahci_port_engine(mapping(), owner(), &mut registers).unwrap();
        assert_eq!(active.layout().dma_generation, 11);
        assert_eq!(registers.values[(CMD / 4) as usize], CMD_FRE | CMD_ST);
        assert_eq!(registers.values[(IE / 4) as usize], 0);
        assert_eq!(registers.writes, 2);
    }

    #[test]
    fn busy_port_returns_the_untouched_owner_without_writes() {
        let mut registers = Registers::default();
        registers.values[(TFD / 4) as usize] = TFD_BUSY_OR_DRQ;
        let failure = start_ahci_port_engine(mapping(), owner(), &mut registers).unwrap_err();
        assert_eq!(failure.error(), AhciEngineError::PortBusy);
        assert!(failure.into_untouched_owner().is_some());
        assert_eq!(registers.writes, 0);
    }

    #[test]
    fn post_write_uncertainty_quarantines_the_layout() {
        for mut registers in [
            Registers {
                reject_write: Some(1),
                ..Registers::default()
            },
            Registers {
                corrupt_readback: true,
                ..Registers::default()
            },
        ] {
            let failure = start_ahci_port_engine(mapping(), owner(), &mut registers).unwrap_err();
            assert!(matches!(failure, AhciEngineFailure::Quarantined { .. }));
        }
    }
}
