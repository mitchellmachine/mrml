//! Capability-bound construction of one non-NCQ ATA DMA command.
//!
//! Construction mutates one idle slot but never sets command issue or enables
//! interrupts. Any uncertainty after mutation quarantines the active layout.

use crate::{
    ActiveAhciPort, AhciCommandMemoryIo, AhciDataCapabilityAuthorizer, AhciDmaRegion,
    AhciPortDmaLayout, AhciRegisterIo,
};
use mrml_kernel::{Capability, CapabilityError, ObjectId, Rights};
#[cfg(test)]
use mrml_kernel::CapabilitySpace;

const PORT_BASE: u32 = 0x100;
const PORT_STRIDE: u32 = 0x80;
const CMD: u32 = 0x18;
const SACT: u32 = 0x34;
const CI: u32 = 0x38;
const CMD_RUNNING: u32 = (1 << 0) | (1 << 4);
const COMMAND_HEADER_BYTES: u64 = 32;
const COMMAND_TABLE_BYTES: u64 = 256;
const PRDT_OFFSET: u64 = 0x80;
const MAX_LBA: u64 = (1_u64 << 48) - 1;
pub const AHCI_MAX_TRANSFER_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciAtaCommand {
    ReadDmaExt,
    WriteDmaExt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciDataDmaRegion {
    pub memory_object: ObjectId,
    pub allocation_generation: u64,
    pub physical_base: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciCommandBuildError {
    DataCapability(CapabilityError),
    WrongMemoryObject,
    InvalidRequest,
    OverlappingDma,
    PortNotRunning,
    SlotBusy,
    RegisterRead,
    MemoryRead,
    MemoryNotClean,
    MemoryWrite,
    VerificationFailed,
}

#[derive(Debug, Eq, PartialEq)]
pub enum AhciCommandBuildFailure {
    Untouched {
        owner: ActiveAhciPort,
        error: AhciCommandBuildError,
    },
    Quarantined {
        layout: AhciPortDmaLayout,
        error: AhciCommandBuildError,
    },
}

impl AhciCommandBuildFailure {
    pub const fn error(&self) -> AhciCommandBuildError {
        match self {
            Self::Untouched { error, .. } | Self::Quarantined { error, .. } => *error,
        }
    }
    pub fn into_untouched_owner(self) -> Option<ActiveAhciPort> {
        match self {
            Self::Untouched { owner, .. } => Some(owner),
            Self::Quarantined { .. } => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PreparedAhciCommand {
    layout: AhciPortDmaLayout,
    slot: u8,
    command: AhciAtaCommand,
    data: AhciDataDmaRegion,
    lba: u64,
    sector_count: u16,
}

impl PreparedAhciCommand {
    #[cfg(test)]
    pub(crate) const fn from_parts(
        layout: AhciPortDmaLayout,
        slot: u8,
        command: AhciAtaCommand,
        data: AhciDataDmaRegion,
        lba: u64,
        sector_count: u16,
    ) -> Self {
        Self {
            layout,
            slot,
            command,
            data,
            lba,
            sector_count,
        }
    }

    pub const fn layout(&self) -> AhciPortDmaLayout {
        self.layout
    }
    pub const fn slot(&self) -> u8 {
        self.slot
    }
    pub const fn command(&self) -> AhciAtaCommand {
        self.command
    }
    pub const fn data(&self) -> AhciDataDmaRegion {
        self.data
    }
    pub const fn lba(&self) -> u64 {
        self.lba
    }
    pub const fn sector_count(&self) -> u16 {
        self.sector_count
    }
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_ahci_dma_command<
    A: AhciDataCapabilityAuthorizer,
    R: AhciRegisterIo,
    M: AhciCommandMemoryIo,
>(
    capabilities: &mut A,
    owner: ActiveAhciPort,
    data_capability: Capability,
    data: AhciDataDmaRegion,
    command: AhciAtaCommand,
    slot: u8,
    lba: u64,
    sector_count: u16,
    registers: &mut R,
    memory: &mut M,
) -> Result<PreparedAhciCommand, AhciCommandBuildFailure> {
    let layout = owner.layout();
    let transfer_bytes = u64::from(sector_count).checked_mul(512);
    if slot >= layout.command_slot_count
        || sector_count == 0
        || transfer_bytes != Some(data.bytes)
        || data.bytes > AHCI_MAX_TRANSFER_BYTES
        || data.allocation_generation == 0
        || data.physical_base == 0
        || data.physical_base.checked_add(data.bytes).is_none()
        || lba > MAX_LBA
        || lba
            .checked_add(u64::from(sector_count) - 1)
            .is_none_or(|last| last > MAX_LBA)
    {
        return untouched(owner, AhciCommandBuildError::InvalidRequest);
    }
    let required = Rights::PIN.union(Rights::MAP).union(match command {
        AhciAtaCommand::ReadDmaExt => Rights::WRITE,
        AhciAtaCommand::WriteDmaExt => Rights::READ,
    });
    let object = match capabilities.authorize_exact(data_capability, required) {
        Ok(object) => object,
        Err(error) => return untouched(owner, AhciCommandBuildError::DataCapability(error)),
    };
    if object != data.memory_object {
        return untouched(owner, AhciCommandBuildError::WrongMemoryObject);
    }
    if overlaps_data(data, layout.command_list)
        || overlaps_data(data, layout.received_fis)
        || overlaps_data(data, layout.command_tables)
    {
        return untouched(owner, AhciCommandBuildError::OverlappingDma);
    }

    let base = PORT_BASE + u32::from(layout.port) * PORT_STRIDE;
    let command_state = match registers.read_u32(base + CMD) {
        Ok(value) => value,
        Err(()) => return untouched(owner, AhciCommandBuildError::RegisterRead),
    };
    let active = match registers.read_u32(base + SACT) {
        Ok(value) => value,
        Err(()) => return untouched(owner, AhciCommandBuildError::RegisterRead),
    };
    let issued = match registers.read_u32(base + CI) {
        Ok(value) => value,
        Err(()) => return untouched(owner, AhciCommandBuildError::RegisterRead),
    };
    if command_state & CMD_RUNNING != CMD_RUNNING {
        return untouched(owner, AhciCommandBuildError::PortNotRunning);
    }
    let slot_mask = 1_u32 << u32::from(slot);
    if active & slot_mask != 0 || issued & slot_mask != 0 {
        return untouched(owner, AhciCommandBuildError::SlotBusy);
    }

    let header = u64::from(slot) * COMMAND_HEADER_BYTES;
    let table = u64::from(slot) * COMMAND_TABLE_BYTES;
    let expected_table = layout.command_tables.physical_base + table;
    for (offset, expected) in [
        (0, 0),
        (4, 0),
        (8, expected_table as u32),
        (12, (expected_table >> 32) as u32),
        (16, 0),
        (20, 0),
        (24, 0),
        (28, 0),
    ] {
        match memory.read_u32(layout.command_list, header + offset) {
            Ok(value) if value == expected => {}
            Ok(_) => return untouched(owner, AhciCommandBuildError::MemoryNotClean),
            Err(()) => return untouched(owner, AhciCommandBuildError::MemoryRead),
        }
    }
    let mut offset = 0;
    while offset < COMMAND_TABLE_BYTES {
        match memory.read_u32(layout.command_tables, table + offset) {
            Ok(0) => {}
            Ok(_) => return untouched(owner, AhciCommandBuildError::MemoryNotClean),
            Err(()) => return untouched(owner, AhciCommandBuildError::MemoryRead),
        }
        offset += 4;
    }

    let opcode = match command {
        AhciAtaCommand::ReadDmaExt => 0x25_u32,
        AhciAtaCommand::WriteDmaExt => 0x35_u32,
    };
    let fis = [
        0x0000_8027 | (opcode << 16),
        (lba as u32 & 0x00ff_ffff) | 0x4000_0000,
        ((lba >> 24) as u32 & 0x00ff_ffff) | (u32::from(sector_count & 0xff) << 24),
        u32::from(sector_count >> 8),
        0,
    ];
    let header_flags =
        5 | (if command == AhciAtaCommand::WriteDmaExt {
            1 << 6
        } else {
            0
        }) | (1 << 16);
    let writes = [
        (layout.command_tables, table, fis[0]),
        (layout.command_tables, table + 4, fis[1]),
        (layout.command_tables, table + 8, fis[2]),
        (layout.command_tables, table + 12, fis[3]),
        (layout.command_tables, table + 16, fis[4]),
        (
            layout.command_tables,
            table + PRDT_OFFSET,
            data.physical_base as u32,
        ),
        (
            layout.command_tables,
            table + PRDT_OFFSET + 4,
            (data.physical_base >> 32) as u32,
        ),
        (layout.command_tables, table + PRDT_OFFSET + 8, 0),
        (
            layout.command_tables,
            table + PRDT_OFFSET + 12,
            data.bytes as u32 - 1,
        ),
        (layout.command_list, header, header_flags),
        (layout.command_list, header + 4, 0),
    ];
    for (region, offset, value) in writes {
        if memory.write_u32(region, offset, value).is_err() {
            return quarantined(owner, AhciCommandBuildError::MemoryWrite);
        }
    }
    for (region, offset, expected) in writes {
        match memory.read_u32(region, offset) {
            Ok(actual) if actual == expected => {}
            _ => return quarantined(owner, AhciCommandBuildError::VerificationFailed),
        }
    }
    Ok(PreparedAhciCommand {
        layout: owner.into_layout(),
        slot,
        command,
        data,
        lba,
        sector_count,
    })
}

fn overlaps_data(data: AhciDataDmaRegion, control: AhciDmaRegion) -> bool {
    data.physical_base < control.physical_base + control.bytes
        && control.physical_base < data.physical_base + data.bytes
}
fn untouched<T>(
    owner: ActiveAhciPort,
    error: AhciCommandBuildError,
) -> Result<T, AhciCommandBuildFailure> {
    Err(AhciCommandBuildFailure::Untouched { owner, error })
}
fn quarantined<T>(
    owner: ActiveAhciPort,
    error: AhciCommandBuildError,
) -> Result<T, AhciCommandBuildFailure> {
    Err(AhciCommandBuildFailure::Quarantined {
        layout: owner.into_layout(),
        error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Registers {
        words: [u32; 16],
    }
    impl Default for Registers {
        fn default() -> Self {
            let mut words = [0; 16];
            words[(CMD / 4) as usize] = CMD_RUNNING;
            Self { words }
        }
    }
    impl AhciRegisterIo for Registers {
        fn read_u32(&mut self, offset: u32) -> Result<u32, ()> {
            let index =
                usize::try_from(offset.checked_sub(PORT_BASE).ok_or(())? / 4).map_err(|_| ())?;
            self.words.get(index).copied().ok_or(())
        }
        fn write_u32(&mut self, _: u32, _: u32) -> Result<(), ()> {
            Err(())
        }
    }

    struct Memory {
        list: [u32; 256],
        tables: [u32; 64],
        writes: usize,
        reject_write: Option<usize>,
    }
    impl Default for Memory {
        fn default() -> Self {
            let mut list = [0; 256];
            list[2] = 0x3000;
            Self {
                list,
                tables: [0; 64],
                writes: 0,
                reject_write: None,
            }
        }
    }
    impl AhciCommandMemoryIo for Memory {
        fn read_u32(&mut self, region: AhciDmaRegion, offset: u64) -> Result<u32, ()> {
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            match region.memory_object.0 {
                20 => self.list.get(index).copied().ok_or(()),
                22 => self.tables.get(index).copied().ok_or(()),
                _ => Err(()),
            }
        }
        fn write_u32(&mut self, region: AhciDmaRegion, offset: u64, value: u32) -> Result<(), ()> {
            if self.reject_write == Some(self.writes) {
                return Err(());
            }
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            match region.memory_object.0 {
                20 => *self.list.get_mut(index).ok_or(())? = value,
                22 => *self.tables.get_mut(index).ok_or(())? = value,
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
    fn capabilities(right: Rights) -> (CapabilitySpace<1>, Capability) {
        let mut capabilities = CapabilitySpace::new();
        let capability = capabilities
            .insert(ObjectId(40), Rights::PIN.union(Rights::MAP).union(right))
            .unwrap();
        (capabilities, capability)
    }

    #[test]
    fn builds_exact_read_fis_header_and_single_prdt_without_issuing() {
        let (mut capabilities, capability) = capabilities(Rights::WRITE);
        let mut registers = Registers::default();
        let mut memory = Memory::default();
        let prepared = prepare_ahci_dma_command(
            &mut capabilities,
            ActiveAhciPort::from_layout(layout()),
            capability,
            data(),
            AhciAtaCommand::ReadDmaExt,
            0,
            0x0102_0304_0506,
            1,
            &mut registers,
            &mut memory,
        )
        .unwrap();
        assert_eq!(
            (prepared.slot(), prepared.lba(), prepared.sector_count()),
            (0, 0x0102_0304_0506, 1)
        );
        assert_eq!(memory.list[0], (1 << 16) | 5);
        assert_eq!(
            &memory.tables[..5],
            &[0x0025_8027, 0x4004_0506, 0x0101_0203, 0, 0]
        );
        assert_eq!(&memory.tables[32..36], &[0x8000, 0, 0, 511]);
        assert_eq!(registers.words[(CI / 4) as usize], 0);
    }

    #[test]
    fn write_uses_host_to_device_header_and_requires_read_authority() {
        let (mut wrong, wrong_capability) = capabilities(Rights::WRITE);
        let mut registers = Registers::default();
        let mut memory = Memory::default();
        assert!(matches!(
            prepare_ahci_dma_command(
                &mut wrong,
                ActiveAhciPort::from_layout(layout()),
                wrong_capability,
                data(),
                AhciAtaCommand::WriteDmaExt,
                0,
                1,
                1,
                &mut registers,
                &mut memory
            ),
            Err(AhciCommandBuildFailure::Untouched {
                error: AhciCommandBuildError::DataCapability(_),
                ..
            })
        ));
        let (mut capabilities, capability) = capabilities(Rights::READ);
        let prepared = prepare_ahci_dma_command(
            &mut capabilities,
            ActiveAhciPort::from_layout(layout()),
            capability,
            data(),
            AhciAtaCommand::WriteDmaExt,
            0,
            1,
            1,
            &mut registers,
            &mut memory,
        )
        .unwrap();
        assert_eq!(prepared.command(), AhciAtaCommand::WriteDmaExt);
        assert_eq!(memory.list[0], (1 << 16) | (1 << 6) | 5);
        assert_eq!(memory.tables[0], 0x0035_8027);
    }

    #[test]
    fn busy_or_dirty_slot_returns_owner_without_memory_writes() {
        let (mut capabilities, capability) = capabilities(Rights::WRITE);
        for (mut registers, mut memory) in [
            (
                {
                    let mut r = Registers::default();
                    r.words[(CI / 4) as usize] = 1;
                    r
                },
                Memory::default(),
            ),
            (Registers::default(), {
                let mut m = Memory::default();
                m.tables[63] = 1;
                m
            }),
        ] {
            let failure = prepare_ahci_dma_command(
                &mut capabilities,
                ActiveAhciPort::from_layout(layout()),
                capability,
                data(),
                AhciAtaCommand::ReadDmaExt,
                0,
                1,
                1,
                &mut registers,
                &mut memory,
            )
            .unwrap_err();
            assert!(failure.into_untouched_owner().is_some());
            assert_eq!(memory.writes, 0);
        }
    }

    #[test]
    fn partial_table_write_quarantines_active_layout() {
        let (mut capabilities, capability) = capabilities(Rights::WRITE);
        let mut registers = Registers::default();
        let mut memory = Memory {
            reject_write: Some(4),
            ..Memory::default()
        };
        let failure = prepare_ahci_dma_command(
            &mut capabilities,
            ActiveAhciPort::from_layout(layout()),
            capability,
            data(),
            AhciAtaCommand::ReadDmaExt,
            0,
            1,
            1,
            &mut registers,
            &mut memory,
        )
        .unwrap_err();
        assert_eq!(failure.error(), AhciCommandBuildError::MemoryWrite);
        assert!(failure.into_untouched_owner().is_none());
    }
}
