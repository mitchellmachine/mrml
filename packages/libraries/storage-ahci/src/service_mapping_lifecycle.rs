//! Combined pre-launch ownership of AHCI MMIO and CPU mappings.

use crate::{
    install_ahci_service_abar, install_ahci_service_cpu_mappings,
    remove_ahci_service_abar, remove_ahci_service_cpu_mappings, AhciAbarDescriptor,
    AhciAbarMappingBackend, AhciAbarMappingError, AhciAbarRemovalBackend, AhciAbarRemovalError,
    AhciInstalledCpuMappings, AhciServiceCpuMappingBackend, AhciServiceCpuMappingError,
    AhciServiceCpuMappingRemovalError, AhciServiceLaunchRecord, InstalledAhciAbarMapping,
};
use mrml_kernel::{Capability, CapabilitySpace};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciServiceMappingTeardown {
    abar: Option<InstalledAhciAbarMapping>,
    cpu: AhciInstalledCpuMappings,
}

impl AhciServiceMappingTeardown {
    pub const fn abar(self) -> Option<InstalledAhciAbarMapping> {
        self.abar
    }
    pub const fn cpu(self) -> AhciInstalledCpuMappings {
        self.cpu
    }
    pub fn complete(&self) -> bool {
        self.abar.is_none() && self.cpu.complete()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AhciServiceMappingInstallError<E> {
    DescriptorMismatch,
    Abar(AhciAbarMappingError),
    Cpu(AhciServiceCpuMappingError<E>),
    CpuRetained {
        error: AhciServiceCpuMappingError<E>,
        retained: AhciServiceMappingTeardown,
    },
    Rollback {
        cpu: AhciServiceCpuMappingError<E>,
        abar: AhciAbarRemovalError,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AhciServiceMappingRemovalError<E> {
    Cpu {
        error: AhciServiceCpuMappingRemovalError<E>,
        retained: AhciServiceMappingTeardown,
    },
    Abar {
        error: AhciAbarRemovalError,
        retained: AhciServiceMappingTeardown,
    },
}

#[allow(clippy::too_many_arguments)]
pub fn install_ahci_service_mappings<
    A: AhciAbarMappingBackend + AhciAbarRemovalBackend,
    D: AhciServiceCpuMappingBackend,
    const C: usize,
>(
    record: AhciServiceLaunchRecord,
    descriptor: AhciAbarDescriptor,
    abar_mapping_capability: Capability,
    abar_control_capability: Capability,
    cpu_mapping_capabilities: [Capability; 4],
    capabilities: &CapabilitySpace<C>,
    abar_backend: &mut A,
    cpu_backend: &mut D,
) -> Result<AhciServiceMappingTeardown, AhciServiceMappingInstallError<D::Error>> {
    let mapping = record.mapping();
    if descriptor.configuration_generation != mapping.configuration_generation
        || descriptor.physical_base != mapping.physical_base
        || descriptor.bytes != mapping.bytes
    {
        return Err(AhciServiceMappingInstallError::DescriptorMismatch);
    }
    let abar = install_ahci_service_abar(
        capabilities,
        abar_mapping_capability,
        mapping.device_object,
        descriptor,
        mapping.virtual_base,
        mapping.mapping_generation,
        abar_backend,
    )
    .map_err(AhciServiceMappingInstallError::Abar)?;
    match install_ahci_service_cpu_mappings(
        record,
        cpu_mapping_capabilities,
        capabilities,
        cpu_backend,
    ) {
        Ok(cpu) => Ok(AhciServiceMappingTeardown {
            abar: Some(abar),
            cpu,
        }),
        Err(cpu) => {
            if let Some(retained_cpu) = cpu.retained() {
                return Err(AhciServiceMappingInstallError::CpuRetained {
                    error: cpu,
                    retained: AhciServiceMappingTeardown {
                        abar: Some(abar),
                        cpu: retained_cpu,
                    },
                });
            }
            match remove_ahci_service_abar(
                abar,
                capabilities,
                abar_control_capability,
                abar_backend,
            ) {
                Ok(_) => Err(AhciServiceMappingInstallError::Cpu(cpu)),
                Err(abar) => Err(AhciServiceMappingInstallError::Rollback { cpu, abar }),
            }
        }
    }
}

pub fn remove_ahci_service_mappings<
    A: AhciAbarRemovalBackend,
    D: AhciServiceCpuMappingBackend,
    const C: usize,
>(
    mut state: AhciServiceMappingTeardown,
    abar_control_capability: Capability,
    capabilities: &CapabilitySpace<C>,
    abar_backend: &mut A,
    cpu_backend: &mut D,
) -> Result<AhciServiceMappingTeardown, AhciServiceMappingRemovalError<D::Error>> {
    if !state.cpu.complete() {
        match remove_ahci_service_cpu_mappings(state.cpu, cpu_backend) {
            Ok(cpu) => state.cpu = cpu,
            Err(error) => {
                let retained_cpu = error.retained;
                state.cpu = retained_cpu;
                return Err(AhciServiceMappingRemovalError::Cpu {
                    error,
                    retained: state,
                });
            }
        }
    }
    if let Some(abar) = state.abar {
        match remove_ahci_service_abar(
            abar,
            capabilities,
            abar_control_capability,
            abar_backend,
        ) {
            Ok(_) => state.abar = None,
            Err(error) => {
                let retained_abar = error.retained();
                state.abar = Some(retained_abar);
                return Err(AhciServiceMappingRemovalError::Abar {
                    error,
                    retained: state,
                });
            }
        }
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AhciAbarMapping, AhciDataDmaRegion, AhciDmaRegion, AhciPciFunctionSnapshot,
        AhciPortDmaBackend, AhciPortDmaLayout, AhciRegisterIo, AhciServiceCpuMapping,
        AhciServiceCpuMappingRequest, ActiveAhciPort, PciFunctionLocation,
        AHCI_SERVICE_CPU_MAPPING_RIGHTS,
    };
    use mrml_interface_storage_block_provider_v1::{
        BlockProviderDevice, OpaqueHandle, BLOCK_DEVICE_FLAG_FLUSH, BLOCK_DEVICE_FLAG_RESET,
    };
    use mrml_kernel::{ObjectId, Rights};

    #[derive(Default)]
    struct AbarBackend {
        mapping: Option<AhciAbarMapping>,
        fail_remove: bool,
    }

    impl AhciAbarMappingBackend for AbarBackend {
        fn map_read_write_nx(&mut self, mapping: AhciAbarMapping) -> Result<(), ()> {
            if self.mapping.replace(mapping).is_some() {
                return Err(());
            }
            Ok(())
        }
    }

    impl AhciAbarRemovalBackend for AbarBackend {
        fn unmap_read_write_nx(&mut self, mapping: AhciAbarMapping) -> Result<(), ()> {
            if self.fail_remove || self.mapping != Some(mapping) {
                return Err(());
            }
            self.mapping = None;
            Ok(())
        }
    }

    #[derive(Default)]
    struct CpuBackend {
        installed: [Option<AhciServiceCpuMappingRequest>; 4],
        install_count: usize,
        fail_install: Option<usize>,
        fail_remove_object: Option<u64>,
    }

    struct Registers([u32; 16]);

    impl Registers {
        fn active() -> Self {
            let mut words = [0; 16];
            words[0] = 0x30_0000;
            words[2] = 0x31_0000;
            words[6] = 0x11;
            Self(words)
        }
    }

    impl AhciRegisterIo for Registers {
        fn read_u32(&mut self, offset: u32) -> Result<u32, ()> {
            let index = usize::try_from(offset.checked_sub(0x200).ok_or(())? / 4).map_err(|_| ())?;
            self.0.get(index).copied().ok_or(())
        }

        fn write_u32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
            let index = usize::try_from(offset.checked_sub(0x200).ok_or(())? / 4).map_err(|_| ())?;
            *self.0.get_mut(index).ok_or(())? = value;
            Ok(())
        }
    }

    struct Data {
        sanitize_failures: usize,
        sanitizations: usize,
    }

    impl crate::AhciDataBufferIo for Data {
        fn prepare_read(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> { Ok(()) }
        fn prepare_write(&mut self, _: AhciDataDmaRegion, _: &[u8]) -> Result<(), ()> { Ok(()) }
        fn complete_read(&mut self, _: AhciDataDmaRegion, _: &mut [u8]) -> Result<(), ()> { Ok(()) }
        fn complete_write(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> { Ok(()) }
        fn sanitize(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> {
            self.sanitizations += 1;
            if self.sanitize_failures == 0 {
                Ok(())
            } else {
                self.sanitize_failures -= 1;
                Err(())
            }
        }
    }

    #[derive(Default)]
    struct DmaBackend {
        removals: usize,
    }

    impl AhciPortDmaBackend for DmaBackend {
        fn install_zeroed_layout(&mut self, _: AhciPortDmaLayout) -> Result<(), ()> { Ok(()) }
        fn remove_layout(&mut self, _: AhciPortDmaLayout) -> Result<(), ()> {
            self.removals += 1;
            Ok(())
        }
    }

    unsafe impl AhciServiceCpuMappingBackend for CpuBackend {
        type Error = u64;

        fn install_rw_nx(
            &mut self,
            request: AhciServiceCpuMappingRequest,
        ) -> Result<(), Self::Error> {
            let index = self.install_count;
            self.install_count += 1;
            if self.fail_install == Some(index) {
                return Err(index as u64);
            }
            self.installed[index] = Some(request);
            Ok(())
        }

        fn remove(
            &mut self,
            request: AhciServiceCpuMappingRequest,
        ) -> Result<(), Self::Error> {
            if self.fail_remove_object == Some(request.memory_object().0) {
                return Err(request.memory_object().0);
            }
            let index = self
                .installed
                .iter()
                .position(|installed| *installed == Some(request))
                .ok_or(u64::MAX)?;
            self.installed[index] = None;
            Ok(())
        }
    }

    fn descriptor() -> AhciAbarDescriptor {
        AhciAbarDescriptor::validate(AhciPciFunctionSnapshot {
            location: PciFunctionLocation::new(0, 0, 31, 2).unwrap(),
            configuration_generation: 11,
            vendor_id: 0x8086,
            device_id: 0x7a62,
            header_type: 0,
            class: 0x01,
            subclass: 0x06,
            programming_interface: 0x01,
            abar: 0x10_0000,
            abar_bytes: 0x2000,
        })
        .unwrap()
    }

    fn record() -> AhciServiceLaunchRecord {
        let region = |object: u64, physical_base: u64, bytes: u64| AhciDmaRegion {
            memory_object: ObjectId(object),
            allocation_generation: object + 10,
            physical_base,
            bytes,
        };
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

    fn authorities() -> (CapabilitySpace<6>, Capability, Capability, [Capability; 4]) {
        let mut capabilities = CapabilitySpace::new();
        let map = capabilities
            .insert(
                ObjectId(10),
                Rights::MAP.union(Rights::READ).union(Rights::WRITE),
            )
            .unwrap();
        let control = capabilities.insert(ObjectId(10), Rights::CONTROL).unwrap();
        let cpu = core::array::from_fn(|index| {
            capabilities
                .insert(
                    ObjectId(index as u64 + 20),
                    AHCI_SERVICE_CPU_MAPPING_RIGHTS,
                )
                .unwrap()
        });
        (capabilities, map, control, cpu)
    }

    #[test]
    fn complete_install_and_teardown_follow_reverse_dependency_order() {
        let (capabilities, map, control, cpu) = authorities();
        let mut abar_backend = AbarBackend::default();
        let mut cpu_backend = CpuBackend::default();
        let state = install_ahci_service_mappings(
            record(),
            descriptor(),
            map,
            control,
            cpu,
            &capabilities,
            &mut abar_backend,
            &mut cpu_backend,
        )
        .unwrap();
        assert!(abar_backend.mapping.is_some());
        let state = remove_ahci_service_mappings(
            state,
            control,
            &capabilities,
            &mut abar_backend,
            &mut cpu_backend,
        )
        .unwrap();
        assert!(state.complete());
        assert!(abar_backend.mapping.is_none());
        assert!(cpu_backend.installed.iter().all(Option::is_none));
    }

    #[test]
    fn clean_cpu_failure_rolls_back_abar_but_uncertain_cpu_retains_both() {
        let (capabilities, map, control, cpu) = authorities();
        let mut abar_backend = AbarBackend::default();
        let mut cpu_backend = CpuBackend {
            fail_install: Some(2),
            ..CpuBackend::default()
        };
        assert!(matches!(
            install_ahci_service_mappings(
                record(), descriptor(), map, control, cpu, &capabilities,
                &mut abar_backend, &mut cpu_backend,
            ),
            Err(AhciServiceMappingInstallError::Cpu(_))
        ));
        assert!(abar_backend.mapping.is_none());

        cpu_backend = CpuBackend {
            fail_install: Some(3),
            fail_remove_object: Some(21),
            ..CpuBackend::default()
        };
        let error = install_ahci_service_mappings(
            record(), descriptor(), map, control, cpu, &capabilities,
            &mut abar_backend, &mut cpu_backend,
        )
        .unwrap_err();
        let AhciServiceMappingInstallError::CpuRetained { retained, .. } = error else {
            panic!("expected combined retained state");
        };
        assert!(retained.abar().is_some());
        cpu_backend.fail_remove_object = None;
        let state = remove_ahci_service_mappings(
            retained, control, &capabilities, &mut abar_backend, &mut cpu_backend,
        )
        .unwrap();
        assert!(state.complete());
    }

    #[test]
    fn abar_withdrawal_uncertainty_is_resumable_after_cpu_cleanup() {
        let (capabilities, map, control, cpu) = authorities();
        let mut abar_backend = AbarBackend::default();
        let mut cpu_backend = CpuBackend::default();
        let state = install_ahci_service_mappings(
            record(), descriptor(), map, control, cpu, &capabilities,
            &mut abar_backend, &mut cpu_backend,
        )
        .unwrap();
        abar_backend.fail_remove = true;
        let error = remove_ahci_service_mappings(
            state, control, &capabilities, &mut abar_backend, &mut cpu_backend,
        )
        .unwrap_err();
        let AhciServiceMappingRemovalError::Abar { retained, .. } = error else {
            panic!("expected retained ABAR cleanup");
        };
        assert!(retained.cpu().complete());
        abar_backend.fail_remove = false;
        assert!(remove_ahci_service_mappings(
            retained, control, &capabilities, &mut abar_backend, &mut cpu_backend,
        )
        .unwrap()
        .complete());
    }

    #[test]
    fn data_and_dma_cleanup_gate_mapping_withdrawal() {
        let (capabilities, map, control, cpu) = authorities();
        let mut abar_backend = AbarBackend::default();
        let mut cpu_backend = CpuBackend::default();
        let state = install_ahci_service_mappings(
            record(), descriptor(), map, control, cpu, &capabilities,
            &mut abar_backend, &mut cpu_backend,
        )
        .unwrap();
        let launch = record();
        let mut command_list = [0xa5; 1024];
        let mut received_fis = [0xa5; 256];
        let mut command_tables = [0xa5; 1024];
        let command_memory = crate::AhciMappedCommandMemory::new(
            launch.layout(),
            &mut command_list,
            &mut received_fis,
            &mut command_tables,
        )
        .unwrap();
        let mut io_capabilities = CapabilitySpace::<2>::new();
        let read_data = io_capabilities
            .insert(
                launch.data().memory_object,
                Rights::PIN.union(Rights::MAP).union(Rights::WRITE),
            )
            .unwrap();
        let write_data = io_capabilities
            .insert(
                launch.data().memory_object,
                Rights::PIN.union(Rights::MAP).union(Rights::READ),
            )
            .unwrap();
        let backend = crate::AhciCommandBlockBackend::new(
            &io_capabilities,
            launch.device().session,
            launch.device().media_generation,
            read_data,
            write_data,
            launch.data(),
            launch.mapping(),
            ActiveAhciPort::from_layout(launch.layout()),
            Registers::active(),
            command_memory,
            Data { sanitize_failures: 1, sanitizations: 0 },
        )
        .unwrap();
        let teardown = match backend.into_teardown() {
            Ok(teardown) => teardown,
            Err(_) => panic!("active backend must yield teardown ownership"),
        };
        let mut dma_backend = DmaBackend::default();
        let error = match crate::quiesce_ahci_command_backend(teardown, state, &mut dma_backend) {
            Ok(_) => panic!("first data sanitization must fail"),
            Err(error) => error,
        };
        let crate::AhciServiceDeviceQuiesceError::Pending(pending) = error.failure() else {
            panic!("expected retryable data cleanup");
        };
        assert!(pending.mappings().abar().is_some());
        assert_eq!(dma_backend.removals, 0);
        let quiesced = crate::resume_ahci_command_backend_teardown(error, &mut dma_backend)
            .unwrap_or_else(|_| panic!("retry must complete"));
        let (quiesced, _, _, data) = quiesced.into_parts();
        assert_eq!(data.sanitizations, 2);
        assert_eq!(dma_backend.removals, 1);
        let state = crate::remove_quiesced_ahci_service_mappings(
            quiesced,
            control,
            &capabilities,
            &mut abar_backend,
            &mut cpu_backend,
        )
        .unwrap();
        assert!(state.complete());
    }
}
