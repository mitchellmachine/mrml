//! Transactional pre-launch CPU mappings for one AHCI service generation.

use crate::AhciServiceLaunchRecord;
use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

const CPU_MAPPING_COUNT: usize = 4;
const PAGE_BYTES: u64 = 4096;
pub const AHCI_SERVICE_CPU_MAPPING_RIGHTS: Rights = Rights::MAP
    .union(Rights::READ)
    .union(Rights::WRITE)
    .union(Rights::INSPECT);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciServiceCpuMappingRequest {
    memory_object: ObjectId,
    allocation_generation: u64,
    mapping_generation: u64,
    physical_base: u64,
    virtual_base: u64,
    exposed_bytes: u64,
    mapped_bytes: u64,
}

impl AhciServiceCpuMappingRequest {
    pub const fn memory_object(self) -> ObjectId {
        self.memory_object
    }
    pub const fn allocation_generation(self) -> u64 {
        self.allocation_generation
    }
    pub const fn mapping_generation(self) -> u64 {
        self.mapping_generation
    }
    pub const fn physical_base(self) -> u64 {
        self.physical_base
    }
    pub const fn virtual_base(self) -> u64 {
        self.virtual_base
    }
    pub const fn exposed_bytes(self) -> u64 {
        self.exposed_bytes
    }
    pub const fn mapped_bytes(self) -> u64 {
        self.mapped_bytes
    }
}

/// Privileged adapter for one exact native RW/NX service mapping.
///
/// # Safety
///
/// Installation must expose only the named memory object and page-rounded
/// range at the requested service virtual address, writable and non-executable.
/// Removal succeeds only after the mapping and required translation-cache state
/// are absent. Failure must leave the request installed or fail-stop the target.
pub unsafe trait AhciServiceCpuMappingBackend {
    type Error;

    fn install_rw_nx(&mut self, request: AhciServiceCpuMappingRequest) -> Result<(), Self::Error>;
    fn remove(&mut self, request: AhciServiceCpuMappingRequest) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciInstalledCpuMappings {
    requests: [AhciServiceCpuMappingRequest; CPU_MAPPING_COUNT],
    installed: [bool; CPU_MAPPING_COUNT],
}

impl AhciInstalledCpuMappings {
    pub const fn requests(self) -> [AhciServiceCpuMappingRequest; CPU_MAPPING_COUNT] {
        self.requests
    }

    pub fn complete(&self) -> bool {
        self.installed.iter().all(|installed| !installed)
    }

    pub fn fully_installed(&self) -> bool {
        self.installed.iter().all(|installed| *installed)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciServiceCpuMappingError<E> {
    Capability {
        index: usize,
        error: CapabilityError,
    },
    WrongMemoryObject(usize),
    Backend {
        index: usize,
        error: E,
    },
    Rollback {
        install_index: usize,
        install: E,
        remove_index: usize,
        remove: E,
        retained: AhciInstalledCpuMappings,
    },
}

impl<E> AhciServiceCpuMappingError<E> {
    pub const fn retained(&self) -> Option<AhciInstalledCpuMappings> {
        match self {
            Self::Rollback { retained, .. } => Some(*retained),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciServiceCpuMappingRemovalError<E> {
    pub index: usize,
    pub error: E,
    pub retained: AhciInstalledCpuMappings,
}

pub fn install_ahci_service_cpu_mappings<B: AhciServiceCpuMappingBackend, const C: usize>(
    record: AhciServiceLaunchRecord,
    mapping_capabilities: [Capability; CPU_MAPPING_COUNT],
    capabilities: &CapabilitySpace<C>,
    backend: &mut B,
) -> Result<AhciInstalledCpuMappings, AhciServiceCpuMappingError<B::Error>> {
    let requests = mapping_requests(record);
    for (index, (request, capability)) in requests.iter().zip(mapping_capabilities).enumerate() {
        let object = capabilities
            .authorize_exact(capability, AHCI_SERVICE_CPU_MAPPING_RIGHTS)
            .map_err(|error| AhciServiceCpuMappingError::Capability { index, error })?;
        if object != request.memory_object {
            return Err(AhciServiceCpuMappingError::WrongMemoryObject(index));
        }
    }

    let mut state = AhciInstalledCpuMappings {
        requests,
        installed: [false; CPU_MAPPING_COUNT],
    };
    for index in 0..CPU_MAPPING_COUNT {
        if let Err(install) = backend.install_rw_nx(state.requests[index]) {
            for remove_index in (0..index).rev() {
                if let Err(remove) = backend.remove(state.requests[remove_index]) {
                    return Err(AhciServiceCpuMappingError::Rollback {
                        install_index: index,
                        install,
                        remove_index,
                        remove,
                        retained: state,
                    });
                }
                state.installed[remove_index] = false;
            }
            return Err(AhciServiceCpuMappingError::Backend {
                index,
                error: install,
            });
        }
        state.installed[index] = true;
    }
    Ok(state)
}

pub fn remove_ahci_service_cpu_mappings<B: AhciServiceCpuMappingBackend>(
    mut state: AhciInstalledCpuMappings,
    backend: &mut B,
) -> Result<AhciInstalledCpuMappings, AhciServiceCpuMappingRemovalError<B::Error>> {
    for index in (0..CPU_MAPPING_COUNT).rev() {
        if !state.installed[index] {
            continue;
        }
        if let Err(error) = backend.remove(state.requests[index]) {
            return Err(AhciServiceCpuMappingRemovalError {
                index,
                error,
                retained: state,
            });
        }
        state.installed[index] = false;
    }
    Ok(state)
}

pub(crate) fn mapping_requests(
    record: AhciServiceLaunchRecord,
) -> [AhciServiceCpuMappingRequest; CPU_MAPPING_COUNT] {
    let layout = record.layout();
    let data = record.data();
    let regions = [
        layout.command_list,
        layout.received_fis,
        layout.command_tables,
        crate::AhciDmaRegion {
            memory_object: data.memory_object,
            allocation_generation: data.allocation_generation,
            physical_base: data.physical_base,
            bytes: data.bytes,
        },
    ];
    let mappings = record.cpu_mappings();
    core::array::from_fn(|index| AhciServiceCpuMappingRequest {
        memory_object: regions[index].memory_object,
        allocation_generation: regions[index].allocation_generation,
        mapping_generation: mappings[index].mapping_generation(),
        physical_base: regions[index].physical_base,
        virtual_base: mappings[index].virtual_base(),
        exposed_bytes: regions[index].bytes,
        mapped_bytes: regions[index].bytes.div_ceil(PAGE_BYTES) * PAGE_BYTES,
    })
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

    #[derive(Default)]
    struct Backend {
        events: [(bool, u64); 8],
        count: usize,
        fail_install: Option<usize>,
        fail_remove: Option<usize>,
    }

    unsafe impl AhciServiceCpuMappingBackend for Backend {
        type Error = usize;

        fn install_rw_nx(
            &mut self,
            request: AhciServiceCpuMappingRequest,
        ) -> Result<(), Self::Error> {
            let index = self.count;
            self.events[self.count] = (true, request.memory_object().0);
            self.count += 1;
            if self.fail_install == Some(index) {
                Err(index)
            } else {
                Ok(())
            }
        }

        fn remove(&mut self, request: AhciServiceCpuMappingRequest) -> Result<(), Self::Error> {
            self.events[self.count] = (false, request.memory_object().0);
            self.count += 1;
            let request_index = request.memory_object().0 as usize - 20;
            if self.fail_remove == Some(request_index) {
                Err(request_index)
            } else {
                Ok(())
            }
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

    fn authorities() -> (CapabilitySpace<4>, [Capability; 4]) {
        let mut space = CapabilitySpace::new();
        let capabilities = core::array::from_fn(|index| {
            space
                .insert(ObjectId(index as u64 + 20), AHCI_SERVICE_CPU_MAPPING_RIGHTS)
                .unwrap()
        });
        (space, capabilities)
    }

    #[test]
    fn exact_launcher_authorities_install_and_remove_four_rw_nx_mappings() {
        let (space, capabilities) = authorities();
        let mut backend = Backend::default();
        let state = install_ahci_service_cpu_mappings(record(), capabilities, &space, &mut backend)
            .unwrap();
        assert_eq!(state.requests()[0].exposed_bytes(), 1024);
        assert_eq!(state.requests()[0].mapped_bytes(), 4096);
        let state = remove_ahci_service_cpu_mappings(state, &mut backend).unwrap();
        assert!(state.complete());
        assert_eq!(
            &backend.events[..backend.count],
            &[
                (true, 20),
                (true, 21),
                (true, 22),
                (true, 23),
                (false, 23),
                (false, 22),
                (false, 21),
                (false, 20),
            ]
        );
    }

    #[test]
    fn capability_failure_reaches_no_backend_and_partial_install_rolls_back() {
        let (mut space, mut capabilities) = authorities();
        space.revoke(capabilities[2]).unwrap();
        let mut backend = Backend::default();
        assert!(matches!(
            install_ahci_service_cpu_mappings(record(), capabilities, &space, &mut backend),
            Err(AhciServiceCpuMappingError::Capability { index: 2, .. })
        ));
        assert_eq!(backend.count, 0);

        let (space, exact) = authorities();
        capabilities = exact;
        backend.fail_install = Some(2);
        assert_eq!(
            install_ahci_service_cpu_mappings(record(), capabilities, &space, &mut backend),
            Err(AhciServiceCpuMappingError::Backend { index: 2, error: 2 })
        );
        assert_eq!(
            &backend.events[..backend.count],
            &[(true, 20), (true, 21), (true, 22), (false, 21), (false, 20)]
        );
    }

    #[test]
    fn uncertain_rollback_retains_exact_retryable_mapping_state() {
        let (space, capabilities) = authorities();
        let mut backend = Backend {
            fail_install: Some(3),
            fail_remove: Some(1),
            ..Backend::default()
        };
        let error = install_ahci_service_cpu_mappings(record(), capabilities, &space, &mut backend)
            .unwrap_err();
        let AhciServiceCpuMappingError::Rollback { retained, .. } = error else {
            panic!("expected retained rollback state");
        };
        backend.fail_remove = None;
        let state = remove_ahci_service_cpu_mappings(retained, &mut backend).unwrap();
        assert!(state.complete());
    }
}
