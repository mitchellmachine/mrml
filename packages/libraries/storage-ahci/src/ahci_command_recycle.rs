//! Verified restoration of one completed AHCI command slot.
//!
//! Reuse is permitted only after the command table is zero and the command
//! header again contains only its immutable per-slot table address. Any memory
//! uncertainty quarantines the port layout and data extent.

use crate::{
    ActiveAhciPort, AhciCommandCompletion, AhciCommandMemoryIo, AhciDataDmaRegion,
    AhciPortDmaLayout,
};

const COMMAND_HEADER_BYTES: u64 = 32;
const COMMAND_TABLE_BYTES: u64 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciCommandRecycleError {
    MemoryWrite,
    VerificationFailed,
}

#[derive(Debug, Eq, PartialEq)]
pub struct RecycledAhciCommand {
    owner: ActiveAhciPort,
    data: AhciDataDmaRegion,
}

impl RecycledAhciCommand {
    pub const fn owner(&self) -> &ActiveAhciPort {
        &self.owner
    }
    pub const fn data(&self) -> AhciDataDmaRegion {
        self.data
    }
    pub fn into_parts(self) -> (ActiveAhciPort, AhciDataDmaRegion) {
        (self.owner, self.data)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct AhciCommandRecycleFailure {
    pub layout: AhciPortDmaLayout,
    pub data: AhciDataDmaRegion,
    pub error: AhciCommandRecycleError,
}

pub fn recycle_ahci_command_slot<M: AhciCommandMemoryIo>(
    completion: AhciCommandCompletion,
    memory: &mut M,
) -> Result<RecycledAhciCommand, AhciCommandRecycleFailure> {
    let layout = completion.owner().layout();
    let data = completion.data();
    let slot = u64::from(completion.slot());
    let table_offset = slot * COMMAND_TABLE_BYTES;
    let header_offset = slot * COMMAND_HEADER_BYTES;

    let mut offset = 0;
    while offset < COMMAND_TABLE_BYTES {
        write(
            memory,
            layout,
            data,
            layout.command_tables,
            table_offset + offset,
            0,
        )?;
        offset += 4;
    }
    let table_address = layout.command_tables.physical_base + table_offset;
    for (offset, value) in [
        (0, 0),
        (4, 0),
        (8, table_address as u32),
        (12, (table_address >> 32) as u32),
        (16, 0),
        (20, 0),
        (24, 0),
        (28, 0),
    ] {
        write(
            memory,
            layout,
            data,
            layout.command_list,
            header_offset + offset,
            value,
        )?;
    }

    offset = 0;
    while offset < COMMAND_TABLE_BYTES {
        verify(
            memory,
            layout,
            data,
            layout.command_tables,
            table_offset + offset,
            0,
        )?;
        offset += 4;
    }
    for (offset, expected) in [
        (0, 0),
        (4, 0),
        (8, table_address as u32),
        (12, (table_address >> 32) as u32),
        (16, 0),
        (20, 0),
        (24, 0),
        (28, 0),
    ] {
        verify(
            memory,
            layout,
            data,
            layout.command_list,
            header_offset + offset,
            expected,
        )?;
    }
    Ok(RecycledAhciCommand {
        owner: completion.into_owner(),
        data,
    })
}

fn write<M: AhciCommandMemoryIo>(
    memory: &mut M,
    layout: AhciPortDmaLayout,
    data: AhciDataDmaRegion,
    region: crate::AhciDmaRegion,
    offset: u64,
    value: u32,
) -> Result<(), AhciCommandRecycleFailure> {
    memory
        .write_u32(region, offset, value)
        .map_err(|()| AhciCommandRecycleFailure {
            layout,
            data,
            error: AhciCommandRecycleError::MemoryWrite,
        })
}

fn verify<M: AhciCommandMemoryIo>(
    memory: &mut M,
    layout: AhciPortDmaLayout,
    data: AhciDataDmaRegion,
    region: crate::AhciDmaRegion,
    offset: u64,
    expected: u32,
) -> Result<(), AhciCommandRecycleFailure> {
    match memory.read_u32(region, offset) {
        Ok(actual) if actual == expected => Ok(()),
        _ => Err(AhciCommandRecycleFailure {
            layout,
            data,
            error: AhciCommandRecycleError::VerificationFailed,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AhciAtaCommand, AhciDmaRegion};
    use mrml_kernel::ObjectId;

    struct Memory {
        list: [u32; 256],
        tables: [u32; 128],
        writes: usize,
        fail_write: Option<usize>,
        corrupt_read: bool,
    }

    impl Memory {
        fn dirty() -> Self {
            Self {
                list: [0xa5a5_a5a5; 256],
                tables: [0x5a5a_5a5a; 128],
                writes: 0,
                fail_write: None,
                corrupt_read: false,
            }
        }
    }

    impl AhciCommandMemoryIo for Memory {
        fn read_u32(&mut self, region: AhciDmaRegion, offset: u64) -> Result<u32, ()> {
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            let value = match region.memory_object {
                ObjectId(20) => *self.list.get(index).ok_or(())?,
                ObjectId(22) => *self.tables.get(index).ok_or(())?,
                _ => return Err(()),
            };
            Ok(if self.corrupt_read { value ^ 1 } else { value })
        }

        fn write_u32(&mut self, region: AhciDmaRegion, offset: u64, value: u32) -> Result<(), ()> {
            if self.fail_write == Some(self.writes) {
                return Err(());
            }
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            match region.memory_object {
                ObjectId(20) => *self.list.get_mut(index).ok_or(())? = value,
                ObjectId(22) => *self.tables.get_mut(index).ok_or(())? = value,
                _ => return Err(()),
            }
            self.writes += 1;
            Ok(())
        }
    }

    fn layout() -> AhciPortDmaLayout {
        AhciPortDmaLayout {
            device_object: ObjectId(10),
            configuration_generation: 7,
            mapping_generation: 9,
            port: 0,
            command_slot_count: 2,
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
                bytes: 512,
            },
            dma_generation: 11,
        }
    }

    fn data() -> AhciDataDmaRegion {
        AhciDataDmaRegion {
            memory_object: ObjectId(40),
            allocation_generation: 5,
            physical_base: 0x8000,
            bytes: 512,
        }
    }

    fn completion() -> AhciCommandCompletion {
        AhciCommandCompletion::from_parts(
            ActiveAhciPort::from_layout(layout()),
            1,
            AhciAtaCommand::ReadDmaExt,
            data(),
            4,
            1,
        )
    }

    #[test]
    fn restores_only_completed_slot_to_initialized_state() {
        let mut memory = Memory::dirty();
        let recycled = recycle_ahci_command_slot(completion(), &mut memory).unwrap();
        assert_eq!(recycled.owner().layout(), layout());
        assert_eq!(recycled.data(), data());
        assert!(memory.tables[64..128].iter().all(|word| *word == 0));
        assert!(memory.tables[..64].iter().all(|word| *word == 0x5a5a_5a5a));
        assert_eq!(&memory.list[8..16], &[0, 0, 0x3100, 0, 0, 0, 0, 0]);
        assert!(memory.list[..8].iter().all(|word| *word == 0xa5a5_a5a5));
    }

    #[test]
    fn write_or_readback_uncertainty_quarantines_port_and_data() {
        for mut memory in [
            Memory {
                fail_write: Some(3),
                ..Memory::dirty()
            },
            Memory {
                corrupt_read: true,
                ..Memory::dirty()
            },
        ] {
            let failure = recycle_ahci_command_slot(completion(), &mut memory).unwrap_err();
            assert_eq!((failure.layout, failure.data), (layout(), data()));
        }
    }
}
