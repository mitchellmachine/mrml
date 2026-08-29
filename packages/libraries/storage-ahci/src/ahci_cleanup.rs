//! Clears stopped-port DMA references and sanitizes memory before reclamation.

use crate::{
    AhciAbarMapping, AhciCommandMemoryIo, AhciPortDmaLayout, AhciRegisterIo, InstalledAhciPortDma,
    StoppedAhciPort,
};

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
pub enum AhciCleanupError {
    LayoutMismatch,
    PortNotQuiescent,
    RegisterRead,
    RegisterWrite,
    MemoryWrite,
    VerificationFailed,
}

#[derive(Debug, Eq, PartialEq)]
pub struct AhciCleanupFailure {
    layout: AhciPortDmaLayout,
    error: AhciCleanupError,
}

impl AhciCleanupFailure {
    pub const fn layout(&self) -> AhciPortDmaLayout {
        self.layout
    }
    pub const fn error(&self) -> AhciCleanupError {
        self.error
    }
}

pub fn reclaim_stopped_ahci_port_dma<R: AhciRegisterIo, M: AhciCommandMemoryIo>(
    mapping: AhciAbarMapping,
    owner: StoppedAhciPort,
    registers: &mut R,
    memory: &mut M,
) -> Result<InstalledAhciPortDma, AhciCleanupFailure> {
    let layout = owner.into_layout();
    if layout.device_object != mapping.device_object
        || layout.configuration_generation != mapping.configuration_generation
        || layout.mapping_generation != mapping.mapping_generation
        || layout.port >= 32
    {
        return failure(layout, AhciCleanupError::LayoutMismatch);
    }
    let base = PORT_BASE + u32::from(layout.port) * PORT_STRIDE;
    for (register, mask) in [
        (IE, u32::MAX),
        (CMD, ENGINE_MASK),
        (SACT, u32::MAX),
        (CI, u32::MAX),
    ] {
        match registers.read_u32(base + register) {
            Ok(value) if value & mask == 0 => {}
            Ok(_) => return failure(layout, AhciCleanupError::PortNotQuiescent),
            Err(()) => return failure(layout, AhciCleanupError::RegisterRead),
        }
    }
    for register in [CLB, CLBU, FB, FBU] {
        if registers.write_u32(base + register, 0).is_err() {
            return failure(layout, AhciCleanupError::RegisterWrite);
        }
    }
    for register in [CLB, CLBU, FB, FBU] {
        match registers.read_u32(base + register) {
            Ok(0) => {}
            _ => return failure(layout, AhciCleanupError::VerificationFailed),
        }
    }
    for region in [
        layout.command_list,
        layout.received_fis,
        layout.command_tables,
    ] {
        let mut offset = 0;
        while offset < region.bytes {
            if memory.write_u32(region, offset, 0).is_err() {
                return failure(layout, AhciCleanupError::MemoryWrite);
            }
            offset += 4;
        }
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
                _ => return failure(layout, AhciCleanupError::VerificationFailed),
            }
            offset += 4;
        }
    }
    Ok(InstalledAhciPortDma::from_reclaimed_layout(layout))
}

fn failure<T>(layout: AhciPortDmaLayout, error: AhciCleanupError) -> Result<T, AhciCleanupFailure> {
    Err(AhciCleanupFailure { layout, error })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AhciDmaRegion;
    use mrml_kernel::ObjectId;

    struct Registers {
        words: [u32; 16],
        writes: usize,
        reject_write: Option<usize>,
    }

    impl Default for Registers {
        fn default() -> Self {
            let mut words = [0; 16];
            words[0] = 0x1000;
            words[2] = 0x2000;
            Self {
                words,
                writes: 0,
                reject_write: None,
            }
        }
    }

    impl AhciRegisterIo for Registers {
        fn read_u32(&mut self, offset: u32) -> Result<u32, ()> {
            let index =
                usize::try_from(offset.checked_sub(PORT_BASE).ok_or(())? / 4).map_err(|_| ())?;
            self.words.get(index).copied().ok_or(())
        }

        fn write_u32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
            if self.reject_write == Some(self.writes) {
                return Err(());
            }
            let index =
                usize::try_from(offset.checked_sub(PORT_BASE).ok_or(())? / 4).map_err(|_| ())?;
            *self.words.get_mut(index).ok_or(())? = value;
            self.writes += 1;
            Ok(())
        }
    }

    struct Memory {
        words: [u32; 384],
        writes: usize,
        reject_write: Option<usize>,
    }

    impl Default for Memory {
        fn default() -> Self {
            Self {
                words: [0x55aa_aa55; 384],
                writes: 0,
                reject_write: None,
            }
        }
    }

    impl AhciCommandMemoryIo for Memory {
        fn read_u32(&mut self, region: AhciDmaRegion, offset: u64) -> Result<u32, ()> {
            let index = memory_index(region, offset)?;
            self.words.get(index).copied().ok_or(())
        }

        fn write_u32(&mut self, region: AhciDmaRegion, offset: u64, value: u32) -> Result<(), ()> {
            if self.reject_write == Some(self.writes) {
                return Err(());
            }
            let index = memory_index(region, offset)?;
            *self.words.get_mut(index).ok_or(())? = value;
            self.writes += 1;
            Ok(())
        }
    }

    fn memory_index(region: AhciDmaRegion, offset: u64) -> Result<usize, ()> {
        let base: usize = match region.memory_object.0 {
            20 => 0,
            21 => 256,
            22 => 320,
            _ => return Err(()),
        };
        base.checked_add(usize::try_from(offset / 4).map_err(|_| ())?)
            .ok_or(())
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
    fn clears_port_bases_and_all_exact_dma_extents_before_restoring_owner() {
        let mut registers = Registers::default();
        let mut memory = Memory::default();
        let owner = reclaim_stopped_ahci_port_dma(
            mapping(),
            StoppedAhciPort::from_layout(layout()),
            &mut registers,
            &mut memory,
        )
        .unwrap();
        assert_eq!(owner.layout(), layout());
        assert_eq!(&registers.words[..4], &[0; 4]);
        assert!(memory.words.iter().all(|word| *word == 0));
        assert_eq!(memory.writes, 384);
    }

    #[test]
    fn nonquiescent_port_is_quarantined_before_mutation() {
        let mut registers = Registers::default();
        registers.words[(CI / 4) as usize] = 1;
        let mut memory = Memory::default();
        let failure = reclaim_stopped_ahci_port_dma(
            mapping(),
            StoppedAhciPort::from_layout(layout()),
            &mut registers,
            &mut memory,
        )
        .unwrap_err();
        assert_eq!(failure.error(), AhciCleanupError::PortNotQuiescent);
        assert_eq!((registers.writes, memory.writes), (0, 0));
    }

    #[test]
    fn register_or_memory_write_uncertainty_never_restores_owner() {
        let mut registers = Registers {
            reject_write: Some(2),
            ..Registers::default()
        };
        let mut memory = Memory::default();
        assert_eq!(
            reclaim_stopped_ahci_port_dma(
                mapping(),
                StoppedAhciPort::from_layout(layout()),
                &mut registers,
                &mut memory
            )
            .unwrap_err()
            .error(),
            AhciCleanupError::RegisterWrite
        );

        let mut registers = Registers::default();
        let mut memory = Memory {
            reject_write: Some(300),
            ..Memory::default()
        };
        assert_eq!(
            reclaim_stopped_ahci_port_dma(
                mapping(),
                StoppedAhciPort::from_layout(layout()),
                &mut registers,
                &mut memory
            )
            .unwrap_err()
            .error(),
            AhciCleanupError::MemoryWrite
        );
    }
}
