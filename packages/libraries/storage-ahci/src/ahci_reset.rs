//! Fail-closed SATA COMRESET and active-port reconstruction.

use crate::{
    stop_ahci_port_engine, ActiveAhciPort, AhciAbarMapping, AhciCommandMemoryIo, AhciDmaRegion,
    AhciPortDmaLayout, AhciRegisterIo, StoppedAhciPort, AHCI_SATA_SIGNATURE,
};

const PORT_BASE: u32 = 0x100;
const PORT_STRIDE: u32 = 0x80;
const IS: u32 = 0x10;
const IE: u32 = 0x14;
const CMD: u32 = 0x18;
const TFD: u32 = 0x20;
const SIG: u32 = 0x24;
const SSTS: u32 = 0x28;
const SCTL: u32 = 0x2c;
const SERR: u32 = 0x30;
const SACT: u32 = 0x34;
const CI: u32 = 0x38;
const CMD_ST: u32 = 1 << 0;
const CMD_FRE: u32 = 1 << 4;
const TFD_UNSAFE: u32 = (1 << 0) | (1 << 3) | (1 << 5) | (1 << 7);
const SCTL_DET_MASK: u32 = 0x0f;
const SCTL_COMRESET: u32 = 1;
const SSTS_DET_MASK: u32 = 0x0f;
const SSTS_SPEED_MASK: u32 = 0x0f << 4;
const SSTS_IPM_MASK: u32 = 0x0f << 8;
const SSTS_ESTABLISHED_ACTIVE: u32 = 3 | (1 << 8);
const COMRESET_HOLD_MICROSECONDS: u32 = 1_000;
pub const AHCI_RESET_LINK_POLL_LIMIT: u32 = 1_000_000;

pub trait AhciResetIo: AhciRegisterIo {
    /// Waits at least `microseconds` using a platform-owned monotonic facility.
    fn delay_microseconds(&mut self, microseconds: u32) -> Result<(), ()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciPortResetError {
    MappingMismatch,
    StopFailed,
    RegisterRead,
    RegisterWrite,
    DelayFailed,
    VerificationFailed,
    LinkTimeout,
    WrongDevice,
    MemoryWrite,
    MemoryVerification,
}

#[derive(Debug, Eq, PartialEq)]
pub struct AhciPortResetFailure {
    pub layout: AhciPortDmaLayout,
    pub error: AhciPortResetError,
}

pub fn reset_ahci_sata_port<R: AhciResetIo, M: AhciCommandMemoryIo>(
    mapping: AhciAbarMapping,
    owner: ActiveAhciPort,
    registers: &mut R,
    memory: &mut M,
) -> Result<ActiveAhciPort, AhciPortResetFailure> {
    let layout = owner.layout();
    if layout.device_object != mapping.device_object
        || layout.configuration_generation != mapping.configuration_generation
        || layout.mapping_generation != mapping.mapping_generation
        || layout.port >= 32
    {
        return fail(layout, AhciPortResetError::MappingMismatch);
    }
    let stopped =
        stop_ahci_port_engine(mapping, owner, registers).map_err(|_| AhciPortResetFailure {
            layout,
            error: AhciPortResetError::StopFailed,
        })?;
    reset_stopped(mapping, stopped, registers, memory)
}

fn reset_stopped<R: AhciResetIo, M: AhciCommandMemoryIo>(
    _: AhciAbarMapping,
    owner: StoppedAhciPort,
    registers: &mut R,
    memory: &mut M,
) -> Result<ActiveAhciPort, AhciPortResetFailure> {
    let layout = owner.layout();
    let base = PORT_BASE + u32::from(layout.port) * PORT_STRIDE;
    let control = read(registers, base + SCTL, layout)?;
    if control & SCTL_DET_MASK != 0 {
        return fail(layout, AhciPortResetError::VerificationFailed);
    }
    write_verify(
        registers,
        base + SCTL,
        (control & !SCTL_DET_MASK) | SCTL_COMRESET,
        layout,
    )?;
    registers
        .delay_microseconds(COMRESET_HOLD_MICROSECONDS)
        .map_err(|()| AhciPortResetFailure {
            layout,
            error: AhciPortResetError::DelayFailed,
        })?;
    write_verify(registers, base + SCTL, control & !SCTL_DET_MASK, layout)?;

    let mut linked = false;
    for _ in 0..AHCI_RESET_LINK_POLL_LIMIT {
        let status = read(registers, base + SSTS, layout)?;
        let speed = status & SSTS_SPEED_MASK;
        if status & (SSTS_DET_MASK | SSTS_IPM_MASK) == SSTS_ESTABLISHED_ACTIVE
            && (speed == 1 << 4 || speed == 2 << 4 || speed == 3 << 4)
        {
            linked = true;
            break;
        }
    }
    if !linked {
        return fail(layout, AhciPortResetError::LinkTimeout);
    }
    if read(registers, base + SIG, layout)? != AHCI_SATA_SIGNATURE {
        return fail(layout, AhciPortResetError::WrongDevice);
    }
    let interrupt = read(registers, base + IS, layout)?;
    if interrupt != 0 {
        write_clear_verify(registers, base + IS, interrupt, layout)?;
    }
    let sata_error = read(registers, base + SERR, layout)?;
    if sata_error != 0 {
        write_clear_verify(registers, base + SERR, sata_error, layout)?;
    }
    if read(registers, base + TFD, layout)? & TFD_UNSAFE != 0
        || read(registers, base + SACT, layout)? != 0
        || read(registers, base + CI, layout)? != 0
        || read(registers, base + IE, layout)? != 0
        || read(registers, base + CMD, layout)? != 0
    {
        return fail(layout, AhciPortResetError::VerificationFailed);
    }

    zero_verify(memory, layout.received_fis, layout)?;
    verify_initialized_command_memory(memory, layout)?;
    write_verify(registers, base + CMD, CMD_FRE, layout)?;
    write_verify(registers, base + CMD, CMD_FRE | CMD_ST, layout)?;
    Ok(ActiveAhciPort::from_layout(layout))
}

fn zero_verify<M: AhciCommandMemoryIo>(
    memory: &mut M,
    region: AhciDmaRegion,
    layout: AhciPortDmaLayout,
) -> Result<(), AhciPortResetFailure> {
    let mut offset = 0;
    while offset < region.bytes {
        memory
            .write_u32(region, offset, 0)
            .map_err(|()| AhciPortResetFailure {
                layout,
                error: AhciPortResetError::MemoryWrite,
            })?;
        offset += 4;
    }
    offset = 0;
    while offset < region.bytes {
        match memory.read_u32(region, offset) {
            Ok(0) => {}
            _ => return fail(layout, AhciPortResetError::MemoryVerification),
        }
        offset += 4;
    }
    Ok(())
}

fn verify_initialized_command_memory<M: AhciCommandMemoryIo>(
    memory: &mut M,
    layout: AhciPortDmaLayout,
) -> Result<(), AhciPortResetFailure> {
    let mut slot = 0_u64;
    while slot < u64::from(layout.command_slot_count) {
        let header = slot * 32;
        let table = slot * 256;
        let address = layout.command_tables.physical_base + table;
        for (offset, expected) in [
            (0, 0),
            (4, 0),
            (8, address as u32),
            (12, (address >> 32) as u32),
            (16, 0),
            (20, 0),
            (24, 0),
            (28, 0),
        ] {
            match memory.read_u32(layout.command_list, header + offset) {
                Ok(actual) if actual == expected => {}
                _ => return fail(layout, AhciPortResetError::MemoryVerification),
            }
        }
        let mut offset = 0;
        while offset < 256 {
            match memory.read_u32(layout.command_tables, table + offset) {
                Ok(0) => {}
                _ => return fail(layout, AhciPortResetError::MemoryVerification),
            }
            offset += 4;
        }
        slot += 1;
    }
    Ok(())
}

fn read<R: AhciRegisterIo>(
    registers: &mut R,
    offset: u32,
    layout: AhciPortDmaLayout,
) -> Result<u32, AhciPortResetFailure> {
    registers
        .read_u32(offset)
        .map_err(|()| AhciPortResetFailure {
            layout,
            error: AhciPortResetError::RegisterRead,
        })
}
fn write_verify<R: AhciRegisterIo>(
    registers: &mut R,
    offset: u32,
    value: u32,
    layout: AhciPortDmaLayout,
) -> Result<(), AhciPortResetFailure> {
    registers
        .write_u32(offset, value)
        .map_err(|()| AhciPortResetFailure {
            layout,
            error: AhciPortResetError::RegisterWrite,
        })?;
    match registers.read_u32(offset) {
        Ok(actual) if actual == value => Ok(()),
        _ => fail(layout, AhciPortResetError::VerificationFailed),
    }
}
fn write_clear_verify<R: AhciRegisterIo>(
    registers: &mut R,
    offset: u32,
    value: u32,
    layout: AhciPortDmaLayout,
) -> Result<(), AhciPortResetFailure> {
    registers
        .write_u32(offset, value)
        .map_err(|()| AhciPortResetFailure {
            layout,
            error: AhciPortResetError::RegisterWrite,
        })?;
    match registers.read_u32(offset) {
        Ok(0) => Ok(()),
        _ => fail(layout, AhciPortResetError::VerificationFailed),
    }
}
fn fail<T>(
    layout: AhciPortDmaLayout,
    error: AhciPortResetError,
) -> Result<T, AhciPortResetFailure> {
    Err(AhciPortResetFailure { layout, error })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_kernel::ObjectId;

    struct Registers {
        words: [u32; 16],
        delays: usize,
        reject_delay: bool,
    }
    impl Registers {
        fn ready() -> Self {
            let mut words = [0; 16];
            words[(CMD / 4) as usize] = CMD_ST | CMD_FRE;
            words[(SIG / 4) as usize] = AHCI_SATA_SIGNATURE;
            words[(SSTS / 4) as usize] = SSTS_ESTABLISHED_ACTIVE | (2 << 4);
            words[(IS / 4) as usize] = 0x10;
            words[(SERR / 4) as usize] = 0x20;
            Self {
                words,
                delays: 0,
                reject_delay: false,
            }
        }
    }
    impl AhciRegisterIo for Registers {
        fn read_u32(&mut self, offset: u32) -> Result<u32, ()> {
            let register = offset.checked_sub(PORT_BASE).ok_or(())?;
            self.words.get(register as usize / 4).copied().ok_or(())
        }
        fn write_u32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
            let register = offset.checked_sub(PORT_BASE).ok_or(())?;
            let word = self.words.get_mut(register as usize / 4).ok_or(())?;
            if register == IS || register == SERR {
                *word &= !value;
            } else {
                *word = value;
            }
            Ok(())
        }
    }
    impl AhciResetIo for Registers {
        fn delay_microseconds(&mut self, microseconds: u32) -> Result<(), ()> {
            self.delays += 1;
            if self.reject_delay || microseconds < COMRESET_HOLD_MICROSECONDS {
                Err(())
            } else {
                Ok(())
            }
        }
    }

    struct Memory {
        list: [u32; 256],
        fis: [u32; 64],
        tables: [u32; 64],
    }
    impl Memory {
        fn initialized() -> Self {
            let mut list = [0; 256];
            list[2] = 0x3000;
            Self {
                list,
                fis: [0xa5a5_a5a5; 64],
                tables: [0; 64],
            }
        }
    }
    impl AhciCommandMemoryIo for Memory {
        fn read_u32(&mut self, region: AhciDmaRegion, offset: u64) -> Result<u32, ()> {
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            match region.memory_object {
                ObjectId(20) => self.list.get(index).copied().ok_or(()),
                ObjectId(21) => self.fis.get(index).copied().ok_or(()),
                ObjectId(22) => self.tables.get(index).copied().ok_or(()),
                _ => Err(()),
            }
        }
        fn write_u32(&mut self, region: AhciDmaRegion, offset: u64, value: u32) -> Result<(), ()> {
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            match region.memory_object {
                ObjectId(20) => *self.list.get_mut(index).ok_or(())? = value,
                ObjectId(21) => *self.fis.get_mut(index).ok_or(())? = value,
                ObjectId(22) => *self.tables.get_mut(index).ok_or(())? = value,
                _ => return Err(()),
            }
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

    #[test]
    fn holds_comreset_clears_errors_and_restarts_clean_port() {
        let mut registers = Registers::ready();
        let mut memory = Memory::initialized();
        let owner = reset_ahci_sata_port(
            mapping(),
            ActiveAhciPort::from_layout(layout()),
            &mut registers,
            &mut memory,
        )
        .unwrap();
        assert_eq!(owner.layout(), layout());
        assert_eq!(registers.delays, 1);
        assert_eq!(registers.words[(CMD / 4) as usize], CMD_ST | CMD_FRE);
        assert_eq!(
            (
                registers.words[(IS / 4) as usize],
                registers.words[(SERR / 4) as usize]
            ),
            (0, 0)
        );
        assert!(memory.fis.iter().all(|word| *word == 0));
    }

    #[test]
    fn mapping_mismatch_and_delay_uncertainty_publish_no_owner() {
        let mut wrong = mapping();
        wrong.mapping_generation += 1;
        let failure = reset_ahci_sata_port(
            wrong,
            ActiveAhciPort::from_layout(layout()),
            &mut Registers::ready(),
            &mut Memory::initialized(),
        )
        .unwrap_err();
        assert_eq!(failure.error, AhciPortResetError::MappingMismatch);
        let mut registers = Registers {
            reject_delay: true,
            ..Registers::ready()
        };
        let failure = reset_ahci_sata_port(
            mapping(),
            ActiveAhciPort::from_layout(layout()),
            &mut registers,
            &mut Memory::initialized(),
        )
        .unwrap_err();
        assert_eq!(failure.error, AhciPortResetError::DelayFailed);
    }
}
