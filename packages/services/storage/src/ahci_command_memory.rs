//! Bounded initialization of AHCI command-list and command-table memory.
//!
//! The port engines remain disabled. All retained DMA memory must be observed
//! as zero before each command header receives its exact command-table base.

use crate::{AhciDmaRegion, AhciPortDmaLayout, ProgrammedAhciPortDma};

const COMMAND_HEADER_BYTES: u64 = 32;
const COMMAND_TABLE_BASE_LOW_OFFSET: u64 = 8;
const COMMAND_TABLE_BASE_HIGH_OFFSET: u64 = 12;
const COMMAND_TABLE_BYTES_PER_SLOT: u64 = 256;

pub trait AhciCommandMemoryIo {
    fn read_u32(&mut self, region: AhciDmaRegion, offset: u64) -> Result<u32, ()>;
    fn write_u32(&mut self, region: AhciDmaRegion, offset: u64, value: u32) -> Result<(), ()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciCommandMemoryError {
    InvalidLayout,
    MemoryRead,
    NotZero,
    MemoryWrite,
    VerificationFailed,
}

#[derive(Debug, Eq, PartialEq)]
pub enum AhciCommandMemoryFailure {
    Untouched {
        owner: ProgrammedAhciPortDma,
        error: AhciCommandMemoryError,
    },
    Quarantined {
        layout: AhciPortDmaLayout,
        error: AhciCommandMemoryError,
    },
}

impl AhciCommandMemoryFailure {
    pub const fn error(&self) -> AhciCommandMemoryError {
        match self {
            Self::Untouched { error, .. } | Self::Quarantined { error, .. } => *error,
        }
    }

    pub fn into_untouched_owner(self) -> Option<ProgrammedAhciPortDma> {
        match self {
            Self::Untouched { owner, .. } => Some(owner),
            Self::Quarantined { .. } => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct InitializedAhciCommandMemory {
    layout: AhciPortDmaLayout,
}

impl InitializedAhciCommandMemory {
    pub const fn layout(&self) -> AhciPortDmaLayout {
        self.layout
    }
}

pub fn initialize_ahci_command_memory<M: AhciCommandMemoryIo>(
    owner: ProgrammedAhciPortDma,
    memory: &mut M,
) -> Result<InitializedAhciCommandMemory, AhciCommandMemoryFailure> {
    let layout = owner.layout();
    if layout.command_slot_count == 0
        || layout.command_slot_count > 32
        || layout.command_list.bytes != 1024
        || layout.received_fis.bytes != 256
        || layout.command_tables.bytes
            != u64::from(layout.command_slot_count) * COMMAND_TABLE_BYTES_PER_SLOT
    {
        return Err(AhciCommandMemoryFailure::Untouched {
            owner,
            error: AhciCommandMemoryError::InvalidLayout,
        });
    }
    for region in [
        layout.command_list,
        layout.received_fis,
        layout.command_tables,
    ] {
        let mut offset = 0;
        while offset < region.bytes {
            match memory.read_u32(region, offset) {
                Ok(0) => {}
                Ok(_) => {
                    return Err(AhciCommandMemoryFailure::Untouched {
                        owner,
                        error: AhciCommandMemoryError::NotZero,
                    });
                }
                Err(()) => {
                    return Err(AhciCommandMemoryFailure::Untouched {
                        owner,
                        error: AhciCommandMemoryError::MemoryRead,
                    });
                }
            }
            offset += 4;
        }
    }

    for slot in 0..u64::from(layout.command_slot_count) {
        let table_base = layout.command_tables.physical_base + slot * COMMAND_TABLE_BYTES_PER_SLOT;
        let header = slot * COMMAND_HEADER_BYTES;
        for (offset, value) in [
            (COMMAND_TABLE_BASE_LOW_OFFSET, table_base as u32),
            (COMMAND_TABLE_BASE_HIGH_OFFSET, (table_base >> 32) as u32),
        ] {
            if memory
                .write_u32(layout.command_list, header + offset, value)
                .is_err()
            {
                return Err(AhciCommandMemoryFailure::Quarantined {
                    layout: owner.into_layout(),
                    error: AhciCommandMemoryError::MemoryWrite,
                });
            }
        }
    }
    for slot in 0..u64::from(layout.command_slot_count) {
        let table_base = layout.command_tables.physical_base + slot * COMMAND_TABLE_BYTES_PER_SLOT;
        let header = slot * COMMAND_HEADER_BYTES;
        for (offset, expected) in [
            (COMMAND_TABLE_BASE_LOW_OFFSET, table_base as u32),
            (COMMAND_TABLE_BASE_HIGH_OFFSET, (table_base >> 32) as u32),
        ] {
            match memory.read_u32(layout.command_list, header + offset) {
                Ok(actual) if actual == expected => {}
                _ => {
                    return Err(AhciCommandMemoryFailure::Quarantined {
                        layout: owner.into_layout(),
                        error: AhciCommandMemoryError::VerificationFailed,
                    });
                }
            }
        }
    }
    Ok(InitializedAhciCommandMemory {
        layout: owner.into_layout(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AhciPortDmaLayout, ProgrammedAhciPortDma};
    use mrml_kernel::ObjectId;

    struct Memory {
        command_list: [u32; 256],
        received_fis: [u32; 64],
        command_tables: [u32; 2048],
        writes: usize,
        reject_write: Option<usize>,
        corrupt_readback: bool,
    }

    impl Default for Memory {
        fn default() -> Self {
            Self {
                command_list: [0; 256],
                received_fis: [0; 64],
                command_tables: [0; 2048],
                writes: 0,
                reject_write: None,
                corrupt_readback: false,
            }
        }
    }

    impl AhciCommandMemoryIo for Memory {
        fn read_u32(&mut self, region: AhciDmaRegion, offset: u64) -> Result<u32, ()> {
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            let mut value = match region.memory_object.0 {
                20 => *self.command_list.get(index).ok_or(())?,
                21 => *self.received_fis.get(index).ok_or(())?,
                22 => *self.command_tables.get(index).ok_or(())?,
                _ => return Err(()),
            };
            if self.corrupt_readback
                && self.writes == 8
                && region.memory_object == ObjectId(20)
                && offset == 8
            {
                value ^= 1;
            }
            Ok(value)
        }

        fn write_u32(&mut self, region: AhciDmaRegion, offset: u64, value: u32) -> Result<(), ()> {
            if self.reject_write == Some(self.writes) {
                return Err(());
            }
            if region.memory_object != ObjectId(20) {
                return Err(());
            }
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            *self.command_list.get_mut(index).ok_or(())? = value;
            self.writes += 1;
            Ok(())
        }
    }

    fn owner() -> ProgrammedAhciPortDma {
        ProgrammedAhciPortDma::from_layout(AhciPortDmaLayout {
            device_object: ObjectId(10),
            configuration_generation: 7,
            mapping_generation: 9,
            port: 0,
            command_slot_count: 4,
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
                physical_base: 0x1_0000_3000,
                bytes: 1024,
            },
            dma_generation: 11,
        })
    }

    #[test]
    fn initializes_every_advertised_slot_with_its_exact_table_base() {
        let mut memory = Memory::default();
        let initialized = initialize_ahci_command_memory(owner(), &mut memory).unwrap();
        assert_eq!(initialized.layout().command_slot_count, 4);
        assert_eq!(memory.writes, 8);
        for slot in 0..4_usize {
            assert_eq!(
                memory.command_list[slot * 8 + 2],
                0x3000 + slot as u32 * 256
            );
            assert_eq!(memory.command_list[slot * 8 + 3], 1);
        }
        assert!(memory.received_fis.iter().all(|value| *value == 0));
        assert!(memory.command_tables.iter().all(|value| *value == 0));
    }

    #[test]
    fn dirty_memory_returns_the_untouched_owner_without_writes() {
        let mut memory = Memory::default();
        memory.command_tables[255] = 1;
        let failure = initialize_ahci_command_memory(owner(), &mut memory).unwrap_err();
        assert_eq!(failure.error(), AhciCommandMemoryError::NotZero);
        assert_eq!(
            failure
                .into_untouched_owner()
                .unwrap()
                .layout()
                .dma_generation,
            11
        );
        assert_eq!(memory.writes, 0);
    }

    #[test]
    fn write_or_readback_uncertainty_quarantines_the_layout() {
        for memory in [
            Memory {
                reject_write: Some(3),
                ..Memory::default()
            },
            Memory {
                corrupt_readback: true,
                ..Memory::default()
            },
        ] {
            let mut memory = memory;
            let failure = initialize_ahci_command_memory(owner(), &mut memory).unwrap_err();
            assert!(matches!(
                &failure,
                AhciCommandMemoryFailure::Quarantined { .. }
            ));
            assert!(failure.into_untouched_owner().is_none());
        }
    }
}
