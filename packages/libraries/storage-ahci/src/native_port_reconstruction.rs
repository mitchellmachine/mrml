//! Fail-closed reconstruction of the installed native service's active port.

use crate::{ActiveAhciPort, AhciRegisterIo, InstalledAhciServiceLaunch};

const PORT_BASE: u32 = 0x100;
const PORT_STRIDE: u32 = 0x80;
const IE: u32 = 0x14;
const CMD: u32 = 0x18;
const TFD: u32 = 0x20;
const SACT: u32 = 0x34;
const CI: u32 = 0x38;
const CMD_ST: u32 = 1 << 0;
const CMD_FRE: u32 = 1 << 4;
const TFD_BUSY_OR_DRQ: u32 = (1 << 7) | (1 << 3);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciNativePortReconstructionError {
    InvalidInstalledLayout,
    RegisterRead,
    UnstableObservation,
    PortNotIdle,
}

/// Reconstructs the active-port owner from one stable, idle hardware snapshot.
///
/// `registers` must be the launch-bound ABAR view for the installed service.
/// The caller must retain exclusive device control: a concurrent command issuer
/// could invalidate the stable idle observation immediately after this call.
pub fn reconstruct_installed_ahci_port<R: AhciRegisterIo>(
    launch: InstalledAhciServiceLaunch,
    registers: &mut R,
) -> Result<ActiveAhciPort, AhciNativePortReconstructionError> {
    let record = launch.record();
    let mapping = record.mapping();
    let layout = record.layout();
    let base = PORT_BASE
        .checked_add(u32::from(layout.port).checked_mul(PORT_STRIDE).ok_or(
            AhciNativePortReconstructionError::InvalidInstalledLayout,
        )?)
        .ok_or(AhciNativePortReconstructionError::InvalidInstalledLayout)?;
    let required_bytes = u64::from(
        base.checked_add(CI + 4)
            .ok_or(AhciNativePortReconstructionError::InvalidInstalledLayout)?,
    );
    if layout.device_object != mapping.device_object
        || layout.configuration_generation != mapping.configuration_generation
        || layout.mapping_generation != mapping.mapping_generation
        || layout.port >= 32
        || required_bytes > mapping.bytes
    {
        return Err(AhciNativePortReconstructionError::InvalidInstalledLayout);
    }

    let first = read_snapshot(registers, base)?;
    let second = read_snapshot(registers, base)?;
    if first != second {
        return Err(AhciNativePortReconstructionError::UnstableObservation);
    }
    let [interrupt_enable, command, task_file, active, issued] = first;
    if interrupt_enable != 0
        || command & (CMD_ST | CMD_FRE) != CMD_ST | CMD_FRE
        || task_file & TFD_BUSY_OR_DRQ != 0
        || active != 0
        || issued != 0
    {
        return Err(AhciNativePortReconstructionError::PortNotIdle);
    }
    Ok(ActiveAhciPort::from_layout(layout))
}

fn read_snapshot<R: AhciRegisterIo>(
    registers: &mut R,
    base: u32,
) -> Result<[u32; 5], AhciNativePortReconstructionError> {
    let mut values = [0; 5];
    for (index, offset) in [IE, CMD, TFD, SACT, CI].into_iter().enumerate() {
        values[index] = registers
            .read_u32(base + offset)
            .map_err(|()| AhciNativePortReconstructionError::RegisterRead)?;
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AhciAbarMapping, AhciDataDmaRegion, AhciDmaRegion, AhciPortDmaLayout,
        AhciServiceCpuMapping, AhciServiceLaunchRecord,
    };
    use mrml_interface_storage_block_provider_v1::{
        BlockProviderDevice, OpaqueHandle, BLOCK_DEVICE_FLAG_FLUSH, BLOCK_DEVICE_FLAG_RESET,
    };
    use mrml_kernel::{Capability, ObjectId};

    struct Registers {
        values: [u32; 5],
        reads: usize,
        change_on_second_snapshot: bool,
        reject_read: Option<usize>,
    }

    impl AhciRegisterIo for Registers {
        fn read_u32(&mut self, offset: u32) -> Result<u32, ()> {
            let expected = [IE, CMD, TFD, SACT, CI];
            let index = expected
                .iter()
                .position(|candidate| PORT_BASE + *candidate == offset)
                .ok_or(())?;
            if self.reject_read == Some(self.reads) {
                return Err(());
            }
            let mut value = self.values[index];
            if self.change_on_second_snapshot && self.reads == 9 {
                value = 1;
            }
            self.reads += 1;
            Ok(value)
        }

        fn write_u32(&mut self, _: u32, _: u32) -> Result<(), ()> {
            panic!("reconstruction must not write registers")
        }
    }

    fn region(object: u64, physical: u64, bytes: u64) -> AhciDmaRegion {
        AhciDmaRegion {
            memory_object: ObjectId(object),
            allocation_generation: object + 10,
            physical_base: physical,
            bytes,
        }
    }

    fn launch() -> InstalledAhciServiceLaunch {
        let record = AhciServiceLaunchRecord::new(
            4,
            3,
            8,
            BlockProviderDevice {
                session: OpaqueHandle::new(1, 2).unwrap(),
                logical_block_bytes: 512,
                flags: BLOCK_DEVICE_FLAG_FLUSH | BLOCK_DEVICE_FLAG_RESET,
                logical_block_count: 100,
                media_generation: 7,
            },
            AhciAbarMapping {
                device_object: ObjectId(10),
                configuration_generation: 11,
                mapping_generation: 12,
                physical_base: 0x10_0000,
                virtual_base: 0x20_0000,
                bytes: 0x2000,
            },
            AhciPortDmaLayout {
                device_object: ObjectId(10),
                configuration_generation: 11,
                mapping_generation: 12,
                port: 0,
                command_slot_count: 4,
                command_list: region(20, 0x30_0000, 1024),
                received_fis: region(21, 0x31_0000, 256),
                command_tables: region(22, 0x32_0000, 1024),
                dma_generation: 13,
            },
            AhciDataDmaRegion {
                memory_object: ObjectId(23),
                allocation_generation: 33,
                physical_base: 0x40_0000,
                bytes: 4096,
            },
            [
                AhciServiceCpuMapping::new(1, 0x30_0000).unwrap(),
                AhciServiceCpuMapping::new(2, 0x31_0000).unwrap(),
                AhciServiceCpuMapping::new(3, 0x32_0000).unwrap(),
                AhciServiceCpuMapping::new(4, 0x40_0000).unwrap(),
            ],
        )
        .unwrap();
        let authorities = core::array::from_fn(|index| {
            Capability::from_token(((index as u64 + 20) << 32) | 1)
        });
        unsafe {
            InstalledAhciServiceLaunch::from_installed_projection(&record.encode(), 3, authorities)
        }
        .unwrap()
    }

    fn registers() -> Registers {
        Registers {
            values: [0, CMD_ST | CMD_FRE, 0, 0, 0],
            reads: 0,
            change_on_second_snapshot: false,
            reject_read: None,
        }
    }

    #[test]
    fn stable_idle_installed_port_reconstructs_without_register_writes() {
        let installed = launch();
        let mut registers = registers();
        let owner = reconstruct_installed_ahci_port(installed, &mut registers).unwrap();
        assert_eq!(owner.layout(), installed.record().layout());
        assert_eq!(registers.reads, 10);
    }

    #[test]
    fn register_failure_instability_and_nonidle_state_publish_no_owner() {
        let installed = launch();
        let mut failed = registers();
        failed.reject_read = Some(4);
        assert_eq!(
            reconstruct_installed_ahci_port(installed, &mut failed).unwrap_err(),
            AhciNativePortReconstructionError::RegisterRead
        );

        let mut unstable = registers();
        unstable.change_on_second_snapshot = true;
        assert_eq!(
            reconstruct_installed_ahci_port(installed, &mut unstable).unwrap_err(),
            AhciNativePortReconstructionError::UnstableObservation
        );

        for index in 0..5 {
            let mut busy = registers();
            busy.values[index] = match index {
                0 | 3 | 4 => 1,
                2 => TFD_BUSY_OR_DRQ,
                1 => CMD_ST,
                _ => unreachable!(),
            };
            assert_eq!(
                reconstruct_installed_ahci_port(installed, &mut busy).unwrap_err(),
                AhciNativePortReconstructionError::PortNotIdle
            );
        }
    }
}
