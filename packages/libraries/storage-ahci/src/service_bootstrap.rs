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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciServiceEntryRegisters {
    service_endpoint: u64,
    supervisor_task: u64,
    provider_generation: u64,
    launch_data: Capability,
    service_module_object: u64,
    authorities: [Capability; AHCI_SERVICE_AUTHORITY_COUNT],
}

impl AhciServiceEntryRegisters {
    /// Captures the exact register ABI installed by `NativeDeviceServiceEntry`.
    ///
    /// # Safety
    ///
    /// Every argument must be the unmodified value from its documented native
    /// entry register. Numeric values supplied from any other source have not
    /// been authenticated as capability tokens or launch identity.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn from_installed_registers(
        service_endpoint: u64,
        supervisor_task: u64,
        provider_generation: u64,
        launch_data: u64,
        launch_data_bytes: u64,
        service_module_object: u64,
        device: u64,
        command_list: u64,
        received_fis: u64,
        command_tables: u64,
        device_write_data: u64,
        device_read_data: u64,
    ) -> Result<Self, AhciServiceBootstrapError> {
        let raw_authorities = [
            device,
            command_list,
            received_fis,
            command_tables,
            device_write_data,
            device_read_data,
        ];
        if !valid_token(service_endpoint)
            || !valid_token(supervisor_task)
            || provider_generation == 0
            || service_module_object == 0
            || launch_data_bytes != AHCI_SERVICE_LAUNCH_BYTES as u64
            || !valid_token(launch_data)
            || raw_authorities.iter().any(|token| !valid_token(*token))
            || raw_authorities.contains(&launch_data)
        {
            return Err(AhciServiceBootstrapError::InvalidProjection);
        }
        for (index, token) in raw_authorities.iter().enumerate() {
            if raw_authorities[..index].contains(token) {
                return Err(AhciServiceBootstrapError::InvalidProjection);
            }
        }
        Ok(Self {
            service_endpoint,
            supervisor_task,
            provider_generation,
            launch_data: Capability::from_token(launch_data),
            service_module_object,
            authorities: raw_authorities.map(Capability::from_token),
        })
    }

    pub const fn service_endpoint(self) -> u64 {
        self.service_endpoint
    }

    pub const fn supervisor_task(self) -> u64 {
        self.supervisor_task
    }

    pub const fn provider_generation(self) -> u64 {
        self.provider_generation
    }

    pub const fn service_module_object(self) -> u64 {
        self.service_module_object
    }
}

fn valid_token(token: u64) -> bool {
    token != 0 && token >> 32 != 0
}

/// Bootstraps an AHCI service from one previously validated register capture.
pub fn bootstrap_installed_ahci_entry<R: AhciRawSyscall>(
    syscalls: &mut AhciUserspaceSyscalls<R>,
    entry: AhciServiceEntryRegisters,
    scratch: &mut [u8; AHCI_SERVICE_LAUNCH_BYTES],
) -> Result<InstalledAhciServiceLaunch, AhciServiceBootstrapError> {
    unsafe {
        bootstrap_installed_ahci_service(
            syscalls,
            entry.launch_data,
            entry.provider_generation,
            entry.authorities,
            scratch,
        )
    }
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
    if provider_generation == 0 || !valid_token(launch_token) || authorities.contains(&launch_data)
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
    use mrml_kernel::{ObjectId, Rights};

    const LAUNCH_TOKEN: u64 = (10 << 32) | 1;
    const ENDPOINT_TOKEN: u64 = (11 << 32) | 2;
    const SUPERVISOR_TOKEN: u64 = (12 << 32) | 3;

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

    struct AuthorizeRaw {
        frames: [Option<AhciSyscallFrame>; 2],
        statuses: [u64; 2],
        calls: usize,
    }

    unsafe impl AhciRawSyscall for AuthorizeRaw {
        unsafe fn invoke(&mut self, frame: &mut AhciSyscallFrame) {
            self.frames[self.calls] = Some(*frame);
            let status = self.statuses[self.calls];
            self.calls += 1;
            frame.rax = status;
        }
    }

    #[test]
    fn installed_data_authorizer_binds_exact_roles_object_and_syscall_frame() {
        let authorities = core::array::from_fn(|index| {
            Capability::from_token(((index as u64 + 20) << 32) | 1)
        });
        let installed = unsafe {
            InstalledAhciServiceLaunch::from_installed_projection(
                &record().encode(),
                3,
                authorities,
            )
        }
        .unwrap();
        let mut authorizer = crate::AhciInstalledDataAuthorizer::from_installed_launch(
            AuthorizeRaw {
                frames: [None; 2],
                statuses: [0, 9],
                calls: 0,
            },
            installed,
        );
        let write_rights = Rights::PIN.union(Rights::MAP).union(Rights::WRITE);
        assert_eq!(
            crate::AhciDataCapabilityAuthorizer::authorize_exact(
                &mut authorizer,
                installed.device_write_data(),
                write_rights,
            ),
            Ok(ObjectId(23))
        );
        assert_eq!(
            crate::AhciDataCapabilityAuthorizer::authorize_exact(
                &mut authorizer,
                installed.device_write_data(),
                Rights::PIN.union(Rights::MAP).union(Rights::READ),
            ),
            Err(mrml_kernel::CapabilityError::PermissionDenied)
        );
        assert_eq!(
            crate::AhciDataCapabilityAuthorizer::authorize_exact(
                &mut authorizer,
                installed.device_read_data(),
                Rights::PIN.union(Rights::MAP).union(Rights::READ),
            ),
            Err(mrml_kernel::CapabilityError::PermissionDenied)
        );
        let raw = authorizer.into_raw();
        assert_eq!(raw.calls, 2);
        let frame = raw.frames[0].unwrap();
        assert_eq!(
            (frame.rax, frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9),
            (
                6,
                installed.device_write_data().token(),
                23,
                u64::from(write_rights.bits()),
                0,
                0,
                0,
            )
        );
        let frame = raw.frames[1].unwrap();
        assert_eq!(
            (frame.rax, frame.rdi, frame.rsi, frame.rdx),
            (
                6,
                installed.device_read_data().token(),
                23,
                u64::from(Rights::PIN.union(Rights::MAP).union(Rights::READ).bits()),
            )
        );
    }

    fn authorities() -> [Capability; AHCI_SERVICE_AUTHORITY_COUNT] {
        core::array::from_fn(|index| {
            Capability::from_token(((index as u64 + 20) << 32) | (index as u64 + 2))
        })
    }

    unsafe fn entry_with(
        endpoint: u64,
        launch_bytes: u64,
        command_list: u64,
    ) -> Result<AhciServiceEntryRegisters, AhciServiceBootstrapError> {
        unsafe { entry_with_supervisor(endpoint, SUPERVISOR_TOKEN, launch_bytes, command_list) }
    }

    unsafe fn entry_with_supervisor(
        endpoint: u64,
        supervisor: u64,
        launch_bytes: u64,
        command_list: u64,
    ) -> Result<AhciServiceEntryRegisters, AhciServiceBootstrapError> {
        let authorities = authorities();
        unsafe {
            AhciServiceEntryRegisters::from_installed_registers(
                endpoint,
                supervisor,
                3,
                LAUNCH_TOKEN,
                launch_bytes,
                9,
                authorities[0].token(),
                command_list,
                authorities[2].token(),
                authorities[3].token(),
                authorities[4].token(),
                authorities[5].token(),
            )
        }
    }

    #[test]
    fn exact_entry_registers_bind_once_to_bootstrap() {
        let authorities = authorities();
        let entry = unsafe {
            entry_with(
                ENDPOINT_TOKEN,
                AHCI_SERVICE_LAUNCH_BYTES as u64,
                authorities[1].token(),
            )
        }
        .unwrap();
        assert_eq!(entry.service_endpoint(), ENDPOINT_TOKEN);
        assert_eq!(entry.supervisor_task(), SUPERVISOR_TOKEN);
        assert_eq!(entry.provider_generation(), 3);
        assert_eq!(entry.service_module_object(), 9);
        let equal_bit_pattern = unsafe {
            entry_with(
                SUPERVISOR_TOKEN,
                AHCI_SERVICE_LAUNCH_BYTES as u64,
                authorities[1].token(),
            )
        }
        .unwrap();
        assert_eq!(equal_bit_pattern.service_endpoint(), SUPERVISOR_TOKEN);
        assert_eq!(equal_bit_pattern.supervisor_task(), SUPERVISOR_TOKEN);
        let raw = Raw {
            bytes: record().encode(),
            status: 0,
            calls: 0,
        };
        let mut syscalls =
            AhciUserspaceSyscalls::new(raw, ENDPOINT_TOKEN, SUPERVISOR_TOKEN).unwrap();
        let mut scratch = [0xa5; AHCI_SERVICE_LAUNCH_BYTES];
        assert_eq!(
            bootstrap_installed_ahci_entry(&mut syscalls, entry, &mut scratch)
                .unwrap()
                .record(),
            record()
        );
        assert_eq!(scratch, [0; AHCI_SERVICE_LAUNCH_BYTES]);
    }

    #[test]
    fn entry_register_substitution_and_aliasing_fail_before_copy() {
        let authorities = authorities();
        assert_eq!(
            unsafe {
                entry_with(
                    0,
                    AHCI_SERVICE_LAUNCH_BYTES as u64,
                    authorities[1].token(),
                )
            },
            Err(AhciServiceBootstrapError::InvalidProjection)
        );
        assert_eq!(
            unsafe {
                entry_with(
                    1,
                    AHCI_SERVICE_LAUNCH_BYTES as u64,
                    authorities[1].token(),
                )
            },
            Err(AhciServiceBootstrapError::InvalidProjection)
        );
        assert_eq!(
            unsafe {
                entry_with_supervisor(
                    ENDPOINT_TOKEN,
                    2,
                    AHCI_SERVICE_LAUNCH_BYTES as u64,
                    authorities[1].token(),
                )
            },
            Err(AhciServiceBootstrapError::InvalidProjection)
        );
        assert_eq!(
            unsafe { entry_with(ENDPOINT_TOKEN, 383, authorities[1].token()) },
            Err(AhciServiceBootstrapError::InvalidProjection)
        );
        assert_eq!(
            unsafe {
                entry_with(
                    ENDPOINT_TOKEN,
                    AHCI_SERVICE_LAUNCH_BYTES as u64,
                    LAUNCH_TOKEN,
                )
            },
            Err(AhciServiceBootstrapError::InvalidProjection)
        );
        assert_eq!(
            unsafe {
                entry_with(
                    ENDPOINT_TOKEN,
                    AHCI_SERVICE_LAUNCH_BYTES as u64,
                    authorities[0].token(),
                )
            },
            Err(AhciServiceBootstrapError::InvalidProjection)
        );
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
