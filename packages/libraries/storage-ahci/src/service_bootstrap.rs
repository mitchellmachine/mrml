//! Fail-closed consumption of the kernel-installed AHCI entry projection.

use crate::{
    AhciRawSyscall, AhciServiceLaunchRecordError, AhciUserspaceSyscallError,
    AhciUserspaceSyscalls, InstalledAhciServiceLaunch, AHCI_SERVICE_AUTHORITY_COUNT,
    AHCI_SERVICE_LAUNCH_BYTES,
};
use mrml_kernel::Capability;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciServiceBootstrapError {
    InvalidProjection,
    Syscall(AhciUserspaceSyscallError),
    Launch(AhciServiceLaunchRecordError),
}

/// Copies, validates, binds, and erases the installed AHCI launch record.
///
/// # Safety
///
/// The caller must be the native entry path constructed by the kernel for this
/// exact service domain and must pass its unmodified launch-data capability,
/// provider-generation register, and six fixed-order authority registers.
pub unsafe fn bootstrap_installed_ahci_service<R: AhciRawSyscall>(
    syscalls: &mut AhciUserspaceSyscalls<R>,
    launch_data: Capability,
    provider_generation: u64,
    authorities: [Capability; AHCI_SERVICE_AUTHORITY_COUNT],
    scratch: &mut [u8; AHCI_SERVICE_LAUNCH_BYTES],
) -> Result<InstalledAhciServiceLaunch, AhciServiceBootstrapError> {
    let launch_token = launch_data.token();
    if provider_generation == 0
        || launch_token == 0
        || launch_token >> 32 == 0
        || authorities.contains(&launch_data)
    {
        scratch.fill(0);
        return Err(AhciServiceBootstrapError::InvalidProjection);
    }
    if let Err(error) = syscalls.read_launch_data(launch_data, scratch) {
        scratch.fill(0);
        return Err(AhciServiceBootstrapError::Syscall(error));
    }
    let bound = unsafe {
        InstalledAhciServiceLaunch::from_installed_projection(
            scratch,
            provider_generation,
            authorities,
        )
    };
    scratch.fill(0);
    bound.map_err(AhciServiceBootstrapError::Launch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AhciAbarMapping, AhciDataDmaRegion, AhciDmaRegion, AhciPortDmaLayout,
        AhciServiceCpuMapping, AhciServiceLaunchRecord, AhciSyscallFrame,
    };
    use mrml_interface_storage_block_provider_v1::{
        BlockProviderDevice, OpaqueHandle, BLOCK_DEVICE_FLAG_FLUSH, BLOCK_DEVICE_FLAG_RESET,
    };
    use mrml_kernel::ObjectId;

    const LAUNCH_TOKEN: u64 = (10 << 32) | 1;

    struct Raw {
        bytes: [u8; AHCI_SERVICE_LAUNCH_BYTES],
        status: u64,
        calls: usize,
    }

    unsafe impl AhciRawSyscall for Raw {
        unsafe fn invoke(&mut self, frame: &mut AhciSyscallFrame) {
            self.calls += 1;
            assert_eq!(frame.rax, 7);
            assert_eq!(frame.rdi, LAUNCH_TOKEN);
            assert_eq!(frame.rsi, 0);
            assert_eq!(frame.r10, AHCI_SERVICE_LAUNCH_BYTES as u64);
            if self.status == 0 {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.bytes.as_ptr(),
                        frame.rdx as *mut u8,
                        self.bytes.len(),
                    )
                };
            }
            frame.rax = self.status;
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

    fn record() -> AhciServiceLaunchRecord {
        AhciServiceLaunchRecord::new(
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
                port: 2,
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
        .unwrap()
    }

    fn authorities() -> [Capability; AHCI_SERVICE_AUTHORITY_COUNT] {
        core::array::from_fn(|index| {
            Capability::from_token(((index as u64 + 20) << 32) | (index as u64 + 2))
        })
    }

    #[test]
    fn exact_projection_is_copied_bound_and_erased_once() {
        let raw = Raw {
            bytes: record().encode(),
            status: 0,
            calls: 0,
        };
        let mut syscalls = AhciUserspaceSyscalls::new(raw, 1, 2).unwrap();
        let mut scratch = [0xa5; AHCI_SERVICE_LAUNCH_BYTES];
        let launch = unsafe {
            bootstrap_installed_ahci_service(
                &mut syscalls,
                Capability::from_token(LAUNCH_TOKEN),
                3,
                authorities(),
                &mut scratch,
            )
        }
        .unwrap();
        assert_eq!(launch.record(), record());
        assert_eq!(syscalls.into_raw().calls, 1);
        assert_eq!(scratch, [0; AHCI_SERVICE_LAUNCH_BYTES]);
    }

    #[test]
    fn copy_decode_and_projection_failures_always_erase_scratch() {
        for (status, bytes, provider) in [
            (9, record().encode(), 3),
            (0, [0; AHCI_SERVICE_LAUNCH_BYTES], 3),
            (0, record().encode(), 4),
        ] {
            let raw = Raw {
                bytes,
                status,
                calls: 0,
            };
            let mut syscalls = AhciUserspaceSyscalls::new(raw, 1, 2).unwrap();
            let mut scratch = [0xa5; AHCI_SERVICE_LAUNCH_BYTES];
            assert!(unsafe {
                bootstrap_installed_ahci_service(
                    &mut syscalls,
                    Capability::from_token(LAUNCH_TOKEN),
                    provider,
                    authorities(),
                    &mut scratch,
                )
            }
            .is_err());
            assert_eq!(scratch, [0; AHCI_SERVICE_LAUNCH_BYTES]);
        }

        let mut aliased = authorities();
        aliased[0] = Capability::from_token(LAUNCH_TOKEN);
        let raw = Raw {
            bytes: record().encode(),
            status: 0,
            calls: 0,
        };
        let mut syscalls = AhciUserspaceSyscalls::new(raw, 1, 2).unwrap();
        let mut scratch = [0xa5; AHCI_SERVICE_LAUNCH_BYTES];
        assert_eq!(
            unsafe {
                bootstrap_installed_ahci_service(
                    &mut syscalls,
                    Capability::from_token(LAUNCH_TOKEN),
                    3,
                    aliased,
                    &mut scratch,
                )
            },
            Err(AhciServiceBootstrapError::InvalidProjection)
        );
        assert_eq!(syscalls.into_raw().calls, 0);
        assert_eq!(scratch, [0; AHCI_SERVICE_LAUNCH_BYTES]);
    }
}
