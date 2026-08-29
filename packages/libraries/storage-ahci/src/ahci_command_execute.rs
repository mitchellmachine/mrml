//! Bounded issue and completion of one prepared non-NCQ AHCI command.
//!
//! Interrupts remain disabled. The caller exclusively owns the exact port and
//! polls for completion. Any uncertainty after publishing PxCI quarantines the
//! complete port DMA layout so stale DMA state cannot be reused.

use crate::{
    ActiveAhciPort, AhciAtaCommand, AhciCommandMemoryIo, AhciDataDmaRegion, AhciPortDmaLayout,
    AhciRegisterIo, PreparedAhciCommand,
};

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
const COMMAND_HEADER_BYTES: u32 = 32;

pub const AHCI_COMMAND_COMPLETION_POLL_LIMIT: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciCommandExecuteError {
    PortNotReady,
    RegisterRead,
    RegisterWrite,
    IssueVerificationFailed,
    CompletionTimeout,
    DeviceError,
    MemoryRead,
    TransferLengthMismatch,
}

#[derive(Debug, Eq, PartialEq)]
pub enum AhciCommandExecuteFailure {
    Untouched {
        command: PreparedAhciCommand,
        error: AhciCommandExecuteError,
    },
    Quarantined {
        layout: AhciPortDmaLayout,
        data: AhciDataDmaRegion,
        error: AhciCommandExecuteError,
    },
}

impl AhciCommandExecuteFailure {
    pub const fn error(&self) -> AhciCommandExecuteError {
        match self {
            Self::Untouched { error, .. } | Self::Quarantined { error, .. } => *error,
        }
    }

    pub fn into_untouched_command(self) -> Option<PreparedAhciCommand> {
        match self {
            Self::Untouched { command, .. } => Some(command),
            Self::Quarantined { .. } => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct AhciCommandCompletion {
    owner: ActiveAhciPort,
    slot: u8,
    command: AhciAtaCommand,
    data: AhciDataDmaRegion,
    lba: u64,
    sector_count: u16,
}

impl AhciCommandCompletion {
    #[cfg(test)]
    pub(crate) const fn from_parts(
        owner: ActiveAhciPort,
        slot: u8,
        command: AhciAtaCommand,
        data: AhciDataDmaRegion,
        lba: u64,
        sector_count: u16,
    ) -> Self {
        Self {
            owner,
            slot,
            command,
            data,
            lba,
            sector_count,
        }
    }

    pub const fn owner(&self) -> &ActiveAhciPort {
        &self.owner
    }
    pub const fn command(&self) -> AhciAtaCommand {
        self.command
    }
    pub const fn slot(&self) -> u8 {
        self.slot
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
    pub fn into_owner(self) -> ActiveAhciPort {
        self.owner
    }
}

pub fn execute_ahci_dma_command<R: AhciRegisterIo, M: AhciCommandMemoryIo>(
    command: PreparedAhciCommand,
    registers: &mut R,
    memory: &mut M,
) -> Result<AhciCommandCompletion, AhciCommandExecuteFailure> {
    let layout = command.layout();
    let base = PORT_BASE + u32::from(layout.port) * PORT_STRIDE;
    let slot_mask = 1_u32 << u32::from(command.slot());
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
            Err(()) => return Err(untouched(command, AhciCommandExecuteError::RegisterRead)),
        };
        if value & required != required || value & forbidden != 0 {
            return Err(untouched(command, AhciCommandExecuteError::PortNotReady));
        }
    }

    if registers.write_u32(base + CI, slot_mask).is_err() {
        return Err(quarantined_ref(
            &command,
            AhciCommandExecuteError::RegisterWrite,
        ));
    }
    let first = registers
        .read_u32(base + CI)
        .map_err(|()| quarantined_ref(&command, AhciCommandExecuteError::RegisterRead))?;
    if first & !slot_mask != 0 {
        return Err(quarantined_ref(
            &command,
            AhciCommandExecuteError::IssueVerificationFailed,
        ));
    }
    if first & slot_mask != 0 {
        let mut complete = false;
        for _ in 0..AHCI_COMMAND_COMPLETION_POLL_LIMIT {
            let issued = registers
                .read_u32(base + CI)
                .map_err(|()| quarantined_ref(&command, AhciCommandExecuteError::RegisterRead))?;
            if issued & !slot_mask != 0 {
                return Err(quarantined_ref(
                    &command,
                    AhciCommandExecuteError::IssueVerificationFailed,
                ));
            }
            if issued & slot_mask == 0 {
                complete = true;
                break;
            }
        }
        if !complete {
            return Err(quarantined_ref(
                &command,
                AhciCommandExecuteError::CompletionTimeout,
            ));
        }
    }

    let interrupt = post_issue_read(registers, base + IS, &command)?;
    let task_file = post_issue_read(registers, base + TFD, &command)?;
    let sata_error = post_issue_read(registers, base + SERR, &command)?;
    if interrupt & IS_TASK_FILE_ERROR != 0 || task_file & TFD_ERROR_STATE != 0 || sata_error != 0 {
        return Err(quarantined_ref(
            &command,
            AhciCommandExecuteError::DeviceError,
        ));
    }
    let header_offset = u64::from(COMMAND_HEADER_BYTES * u32::from(command.slot()) + 4);
    let transferred = memory
        .read_u32(layout.command_list, header_offset)
        .map_err(|()| quarantined_ref(&command, AhciCommandExecuteError::MemoryRead))?;
    if u64::from(transferred) != command.data().bytes {
        return Err(quarantined_ref(
            &command,
            AhciCommandExecuteError::TransferLengthMismatch,
        ));
    }

    Ok(AhciCommandCompletion {
        owner: ActiveAhciPort::from_layout(layout),
        slot: command.slot(),
        command: command.command(),
        data: command.data(),
        lba: command.lba(),
        sector_count: command.sector_count(),
    })
}

fn post_issue_read<R: AhciRegisterIo>(
    registers: &mut R,
    offset: u32,
    command: &PreparedAhciCommand,
) -> Result<u32, AhciCommandExecuteFailure> {
    registers
        .read_u32(offset)
        .map_err(|()| quarantined_ref(command, AhciCommandExecuteError::RegisterRead))
}

fn untouched(
    command: PreparedAhciCommand,
    error: AhciCommandExecuteError,
) -> AhciCommandExecuteFailure {
    AhciCommandExecuteFailure::Untouched { command, error }
}

fn quarantined_ref(
    command: &PreparedAhciCommand,
    error: AhciCommandExecuteError,
) -> AhciCommandExecuteFailure {
    AhciCommandExecuteFailure::Quarantined {
        layout: command.layout(),
        data: command.data(),
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AhciCommandMemoryIo, AhciDmaRegion};
    use mrml_kernel::ObjectId;

    struct Registers {
        words: [u32; 16],
        issue_reads: u32,
        complete_after: Option<u32>,
    }

    impl Registers {
        fn ready(complete_after: Option<u32>) -> Self {
            let mut words = [0; 16];
            words[(CMD / 4) as usize] = CMD_RUNNING;
            Self {
                words,
                issue_reads: 0,
                complete_after,
            }
        }
    }

    impl AhciRegisterIo for Registers {
        fn read_u32(&mut self, offset: u32) -> Result<u32, ()> {
            let register = offset.checked_sub(PORT_BASE).ok_or(())?;
            if register == CI && self.words[(CI / 4) as usize] != 0 {
                self.issue_reads += 1;
                if self
                    .complete_after
                    .is_some_and(|limit| self.issue_reads > limit)
                {
                    self.words[(CI / 4) as usize] = 0;
                }
            }
            self.words
                .get(usize::try_from(register / 4).map_err(|_| ())?)
                .copied()
                .ok_or(())
        }

        fn write_u32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
            let register = offset.checked_sub(PORT_BASE).ok_or(())?;
            *self
                .words
                .get_mut(usize::try_from(register / 4).map_err(|_| ())?)
                .ok_or(())? = value;
            Ok(())
        }
    }

    struct Memory(u32);

    impl AhciCommandMemoryIo for Memory {
        fn read_u32(&mut self, region: AhciDmaRegion, offset: u64) -> Result<u32, ()> {
            if region.memory_object == ObjectId(20) && offset == 4 {
                Ok(self.0)
            } else {
                Err(())
            }
        }
        fn write_u32(&mut self, _: AhciDmaRegion, _: u64, _: u32) -> Result<(), ()> {
            Err(())
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

    fn command() -> PreparedAhciCommand {
        PreparedAhciCommand::from_parts(
            layout(),
            0,
            AhciAtaCommand::ReadDmaExt,
            AhciDataDmaRegion {
                memory_object: ObjectId(40),
                allocation_generation: 5,
                physical_base: 0x8000,
                bytes: 512,
            },
            19,
            1,
        )
    }

    #[test]
    fn issues_one_slot_and_returns_owner_only_after_exact_completion() {
        let mut registers = Registers::ready(Some(1));
        let completed =
            execute_ahci_dma_command(command(), &mut registers, &mut Memory(512)).unwrap();
        assert_eq!(completed.owner().layout(), layout());
        assert_eq!((completed.lba(), completed.sector_count()), (19, 1));
        assert_eq!(registers.words[(CI / 4) as usize], 0);
    }

    #[test]
    fn dirty_preissue_state_returns_the_untouched_prepared_command() {
        let mut registers = Registers::ready(Some(1));
        registers.words[(SERR / 4) as usize] = 1;
        let failure =
            execute_ahci_dma_command(command(), &mut registers, &mut Memory(512)).unwrap_err();
        assert_eq!(failure.error(), AhciCommandExecuteError::PortNotReady);
        assert!(failure.into_untouched_command().is_some());
        assert_eq!(registers.words[(CI / 4) as usize], 0);
    }

    #[test]
    fn timeout_and_short_transfer_quarantine_dma_ownership() {
        let mut registers = Registers::ready(None);
        let failure =
            execute_ahci_dma_command(command(), &mut registers, &mut Memory(512)).unwrap_err();
        assert_eq!(failure.error(), AhciCommandExecuteError::CompletionTimeout);
        assert!(failure.into_untouched_command().is_none());

        let mut registers = Registers::ready(Some(0));
        let failure =
            execute_ahci_dma_command(command(), &mut registers, &mut Memory(256)).unwrap_err();
        assert_eq!(
            failure.error(),
            AhciCommandExecuteError::TransferLengthMismatch
        );
        assert!(failure.into_untouched_command().is_none());
    }
}
