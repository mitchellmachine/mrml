//! Bounded ATA FLUSH CACHE EXT execution on one active AHCI port.

use crate::{ActiveAhciPort, AhciCommandMemoryIo, AhciPortDmaLayout, AhciRegisterIo};

const PORT_BASE: u32 = 0x100;
const PORT_STRIDE: u32 = 0x80;
const IS: u32 = 0x10;
const CMD: u32 = 0x18;
const TFD: u32 = 0x20;
const SERR: u32 = 0x30;
const SACT: u32 = 0x34;
const CI: u32 = 0x38;
const CMD_RUNNING: u32 = (1 << 0) | (1 << 4);
const TFD_ERROR_STATE: u32 = (1 << 0) | (1 << 5) | (1 << 7) | (1 << 3);
const IS_TASK_FILE_ERROR: u32 = 1 << 30;
const COMMAND_TABLE_BYTES: u64 = 256;
const FLUSH_CACHE_EXT_FIS: u32 = 0x00ea_8027;
pub const AHCI_FLUSH_COMPLETION_POLL_LIMIT: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciFlushError {
    PortNotReady,
    MemoryNotClean,
    RegisterRead,
    RegisterWrite,
    MemoryRead,
    MemoryWrite,
    VerificationFailed,
    CompletionTimeout,
    DeviceError,
}

#[derive(Debug, Eq, PartialEq)]
pub enum AhciFlushFailure {
    Untouched {
        owner: ActiveAhciPort,
        error: AhciFlushError,
    },
    Quarantined {
        layout: AhciPortDmaLayout,
        error: AhciFlushError,
    },
}

impl AhciFlushFailure {
    pub const fn error(&self) -> AhciFlushError {
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

pub fn flush_ahci_cache<R: AhciRegisterIo, M: AhciCommandMemoryIo>(
    owner: ActiveAhciPort,
    registers: &mut R,
    memory: &mut M,
) -> Result<ActiveAhciPort, AhciFlushFailure> {
    let layout = owner.layout();
    let base = PORT_BASE + u32::from(layout.port) * PORT_STRIDE;
    for (register, required, forbidden) in [
        (CMD, CMD_RUNNING, 0),
        (TFD, 0, TFD_ERROR_STATE),
        (IS, 0, u32::MAX),
        (SERR, 0, u32::MAX),
        (SACT, 0, u32::MAX),
        (CI, 0, u32::MAX),
    ] {
        let value = match registers.read_u32(base + register) {
            Ok(value) => value,
            Err(()) => {
                return Err(AhciFlushFailure::Untouched {
                    owner,
                    error: AhciFlushError::RegisterRead,
                })
            }
        };
        if value & required != required || value & forbidden != 0 {
            return Err(AhciFlushFailure::Untouched {
                owner,
                error: AhciFlushError::PortNotReady,
            });
        }
    }
    let table_address = layout.command_tables.physical_base;
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
        match memory.read_u32(layout.command_list, offset) {
            Ok(actual) if actual == expected => {}
            Ok(_) => {
                return Err(AhciFlushFailure::Untouched {
                    owner,
                    error: AhciFlushError::MemoryNotClean,
                })
            }
            Err(()) => {
                return Err(AhciFlushFailure::Untouched {
                    owner,
                    error: AhciFlushError::MemoryRead,
                })
            }
        }
    }
    let mut offset = 0;
    while offset < COMMAND_TABLE_BYTES {
        match memory.read_u32(layout.command_tables, offset) {
            Ok(0) => {}
            Ok(_) => {
                return Err(AhciFlushFailure::Untouched {
                    owner,
                    error: AhciFlushError::MemoryNotClean,
                })
            }
            Err(()) => {
                return Err(AhciFlushFailure::Untouched {
                    owner,
                    error: AhciFlushError::MemoryRead,
                })
            }
        }
        offset += 4;
    }

    for (region, offset, value) in [
        (layout.command_tables, 0, FLUSH_CACHE_EXT_FIS),
        (layout.command_tables, 4, 0),
        (layout.command_tables, 8, 0),
        (layout.command_tables, 12, 0),
        (layout.command_tables, 16, 0),
        (layout.command_list, 0, 5),
        (layout.command_list, 4, 0),
    ] {
        mutate(
            memory.write_u32(region, offset, value),
            layout,
            AhciFlushError::MemoryWrite,
        )?;
        match memory.read_u32(region, offset) {
            Ok(actual) if actual == value => {}
            _ => return quarantine(layout, AhciFlushError::VerificationFailed),
        }
    }
    mutate(
        registers.write_u32(base + CI, 1),
        layout,
        AhciFlushError::RegisterWrite,
    )?;
    let mut complete = false;
    for _ in 0..AHCI_FLUSH_COMPLETION_POLL_LIMIT {
        let issued = registers
            .read_u32(base + CI)
            .map_err(|()| AhciFlushFailure::Quarantined {
                layout,
                error: AhciFlushError::RegisterRead,
            })?;
        if issued & !1 != 0 {
            return quarantine(layout, AhciFlushError::VerificationFailed);
        }
        if issued & 1 == 0 {
            complete = true;
            break;
        }
    }
    if !complete {
        return quarantine(layout, AhciFlushError::CompletionTimeout);
    }
    let interrupt = post_read(registers, base + IS, layout)?;
    let task_file = post_read(registers, base + TFD, layout)?;
    let sata_error = post_read(registers, base + SERR, layout)?;
    if interrupt & IS_TASK_FILE_ERROR != 0 || task_file & TFD_ERROR_STATE != 0 || sata_error != 0 {
        return quarantine(layout, AhciFlushError::DeviceError);
    }
    match memory.read_u32(layout.command_list, 4) {
        Ok(0) => {}
        _ => return quarantine(layout, AhciFlushError::VerificationFailed),
    }

    offset = 0;
    while offset < COMMAND_TABLE_BYTES {
        mutate(
            memory.write_u32(layout.command_tables, offset, 0),
            layout,
            AhciFlushError::MemoryWrite,
        )?;
        offset += 4;
    }
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
        mutate(
            memory.write_u32(layout.command_list, offset, value),
            layout,
            AhciFlushError::MemoryWrite,
        )?;
    }
    offset = 0;
    while offset < COMMAND_TABLE_BYTES {
        match memory.read_u32(layout.command_tables, offset) {
            Ok(0) => {}
            _ => return quarantine(layout, AhciFlushError::VerificationFailed),
        }
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
        match memory.read_u32(layout.command_list, offset) {
            Ok(actual) if actual == expected => {}
            _ => return quarantine(layout, AhciFlushError::VerificationFailed),
        }
    }
    Ok(ActiveAhciPort::from_layout(layout))
}

fn mutate(
    result: Result<(), ()>,
    layout: AhciPortDmaLayout,
    error: AhciFlushError,
) -> Result<(), AhciFlushFailure> {
    result.map_err(|()| AhciFlushFailure::Quarantined { layout, error })
}
fn post_read<R: AhciRegisterIo>(
    registers: &mut R,
    offset: u32,
    layout: AhciPortDmaLayout,
) -> Result<u32, AhciFlushFailure> {
    registers
        .read_u32(offset)
        .map_err(|()| AhciFlushFailure::Quarantined {
            layout,
            error: AhciFlushError::RegisterRead,
        })
}
fn quarantine<T>(layout: AhciPortDmaLayout, error: AhciFlushError) -> Result<T, AhciFlushFailure> {
    Err(AhciFlushFailure::Quarantined { layout, error })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AhciDmaRegion;
    use mrml_kernel::ObjectId;

    struct Registers {
        words: [u32; 16],
        issue_reads: u32,
        sticky: bool,
    }
    impl Registers {
        fn ready() -> Self {
            let mut words = [0; 16];
            words[(CMD / 4) as usize] = CMD_RUNNING;
            Self {
                words,
                issue_reads: 0,
                sticky: false,
            }
        }
    }
    impl AhciRegisterIo for Registers {
        fn read_u32(&mut self, offset: u32) -> Result<u32, ()> {
            let register = offset.checked_sub(PORT_BASE).ok_or(())?;
            if register == CI && self.words[(CI / 4) as usize] != 0 && !self.sticky {
                self.issue_reads += 1;
                if self.issue_reads == 2 {
                    self.words[(CI / 4) as usize] = 0;
                }
            }
            self.words.get(register as usize / 4).copied().ok_or(())
        }
        fn write_u32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
            let register = offset.checked_sub(PORT_BASE).ok_or(())?;
            *self.words.get_mut(register as usize / 4).ok_or(())? = value;
            Ok(())
        }
    }

    struct Memory {
        list: [u32; 256],
        tables: [u32; 64],
        reject_write: Option<usize>,
        writes: usize,
    }
    impl Memory {
        fn initialized() -> Self {
            let mut list = [0; 256];
            list[2] = 0x3000;
            Self {
                list,
                tables: [0; 64],
                reject_write: None,
                writes: 0,
            }
        }
    }
    impl AhciCommandMemoryIo for Memory {
        fn read_u32(&mut self, region: AhciDmaRegion, offset: u64) -> Result<u32, ()> {
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            match region.memory_object {
                ObjectId(20) => self.list.get(index).copied().ok_or(()),
                ObjectId(22) => self.tables.get(index).copied().ok_or(()),
                _ => Err(()),
            }
        }
        fn write_u32(&mut self, region: AhciDmaRegion, offset: u64, value: u32) -> Result<(), ()> {
            if self.reject_write == Some(self.writes) {
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

    #[test]
    fn issues_flush_cache_ext_without_prdt_and_restores_slot() {
        let mut registers = Registers::ready();
        let mut memory = Memory::initialized();
        let owner = flush_ahci_cache(
            ActiveAhciPort::from_layout(layout()),
            &mut registers,
            &mut memory,
        )
        .unwrap();
        assert_eq!(owner.layout(), layout());
        assert_eq!(registers.issue_reads, 2);
        assert_eq!(&memory.list[..8], &[0, 0, 0x3000, 0, 0, 0, 0, 0]);
        assert!(memory.tables.iter().all(|word| *word == 0));
    }

    #[test]
    fn preflight_preserves_owner_but_post_mutation_uncertainty_quarantines() {
        let mut dirty = Memory::initialized();
        dirty.tables[3] = 1;
        let failure = flush_ahci_cache(
            ActiveAhciPort::from_layout(layout()),
            &mut Registers::ready(),
            &mut dirty,
        )
        .unwrap_err();
        assert_eq!(failure.error(), AhciFlushError::MemoryNotClean);
        assert!(failure.into_untouched_owner().is_some());
        let mut memory = Memory {
            reject_write: Some(2),
            ..Memory::initialized()
        };
        let failure = flush_ahci_cache(
            ActiveAhciPort::from_layout(layout()),
            &mut Registers::ready(),
            &mut memory,
        )
        .unwrap_err();
        assert_eq!(failure.error(), AhciFlushError::MemoryWrite);
        assert!(failure.into_untouched_owner().is_none());
    }
}
