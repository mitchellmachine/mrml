//! Kernel memory-resource adapter for transactional AHCI service mappings.

use crate::{
    AhciServiceCpuMappingBackend, AhciServiceCpuMappingRequest, AhciServiceLaunchRecord,
    AHCI_SERVICE_CPU_MAPPING_RIGHTS,
};
use mrml_kernel::{
    Capability, CapabilityError, CapabilitySpace, MemoryMappingBackend, MemoryMappingId,
    MemoryMappingOperationError, MemoryObjectId, MemoryPoolTable, MemoryResourceError, ObjectId,
    Rights, PAGE_SIZE,
};

const MAPPING_COUNT: usize = 4;
const TARGET_RIGHTS: Rights = Rights::MAP.union(Rights::CONTROL);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelAhciServiceCpuMappingAdapterError {
    Capability(CapabilityError),
    Resource(MemoryResourceError),
    WrongMemoryObject(usize),
    WrongAllocationGeneration(usize),
    WrongPhysicalBacking(usize),
    WrongServiceTarget,
    InvalidTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelAhciServiceCpuMappingOperationError<E> {
    InvalidRequest,
    DuplicateInstall,
    MissingMapping,
    Mapping(MemoryMappingOperationError<E>),
}

pub struct KernelAhciServiceCpuMappingAdapter<
    'a,
    B,
    const P: usize,
    const O: usize,
    const M: usize,
    const C: usize,
> {
    memory: &'a mut MemoryPoolTable<P, O, M>,
    backend: &'a mut B,
    capabilities: &'a CapabilitySpace<C>,
    memory_objects: [MemoryObjectId; MAPPING_COUNT],
    memory_capabilities: [Capability; MAPPING_COUNT],
    target_capability: Capability,
    target: ObjectId,
    requests: [AhciServiceCpuMappingRequest; MAPPING_COUNT],
    mappings: [Option<MemoryMappingId>; MAPPING_COUNT],
}

impl<'a, B, const P: usize, const O: usize, const M: usize, const C: usize>
    KernelAhciServiceCpuMappingAdapter<'a, B, P, O, M, C>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        record: AhciServiceLaunchRecord,
        expected_target: ObjectId,
        memory: &'a mut MemoryPoolTable<P, O, M>,
        backend: &'a mut B,
        capabilities: &'a CapabilitySpace<C>,
        memory_objects: [MemoryObjectId; MAPPING_COUNT],
        memory_capabilities: [Capability; MAPPING_COUNT],
        target_capability: Capability,
    ) -> Result<Self, KernelAhciServiceCpuMappingAdapterError> {
        let target = capabilities
            .authorize_exact(target_capability, TARGET_RIGHTS)
            .map_err(KernelAhciServiceCpuMappingAdapterError::Capability)?;
        if target != expected_target {
            return Err(KernelAhciServiceCpuMappingAdapterError::WrongServiceTarget);
        }
        let requests = crate::service_cpu_mapping::mapping_requests(record);
        for index in 0..MAPPING_COUNT {
            let object = capabilities
                .authorize_exact(memory_capabilities[index], AHCI_SERVICE_CPU_MAPPING_RIGHTS)
                .map_err(KernelAhciServiceCpuMappingAdapterError::Capability)?;
            if object != requests[index].memory_object() {
                return Err(KernelAhciServiceCpuMappingAdapterError::WrongMemoryObject(
                    index,
                ));
            }
            if object == target {
                return Err(KernelAhciServiceCpuMappingAdapterError::InvalidTarget);
            }
            if u64::from(memory_objects[index].generation())
                != requests[index].allocation_generation()
            {
                return Err(
                    KernelAhciServiceCpuMappingAdapterError::WrongAllocationGeneration(index),
                );
            }
            let physical = memory
                .object_physical_backing(
                    memory_objects[index],
                    memory_capabilities[index],
                    capabilities,
                )
                .map_err(KernelAhciServiceCpuMappingAdapterError::Resource)?
                .ok_or(KernelAhciServiceCpuMappingAdapterError::WrongPhysicalBacking(index))?;
            if physical.start().get() != requests[index].physical_base()
                || physical.pages().checked_mul(PAGE_SIZE) != Some(requests[index].mapped_bytes())
            {
                return Err(KernelAhciServiceCpuMappingAdapterError::WrongPhysicalBacking(index));
            }
        }
        Ok(Self {
            memory,
            backend,
            capabilities,
            memory_objects,
            memory_capabilities,
            target_capability,
            target,
            requests,
            mappings: [None; MAPPING_COUNT],
        })
    }

    pub const fn mappings(&self) -> [Option<MemoryMappingId>; MAPPING_COUNT] {
        self.mappings
    }

    fn request_index(&self, request: AhciServiceCpuMappingRequest) -> Option<usize> {
        self.requests
            .iter()
            .position(|expected| *expected == request)
    }

    pub(crate) fn backend(&self) -> &B {
        self.backend
    }

    pub(crate) fn backend_mut(&mut self) -> &mut B {
        self.backend
    }

    pub(crate) fn target(&self) -> ObjectId {
        self.target
    }

    /// Confirms that one retained mapping ID still describes the exact
    /// launch request before a combined owner treats its page-table leaf as
    /// belonging to this CPU/DMA range.
    pub(crate) fn verify_installed_mapping(
        &self,
        index: usize,
        request: AhciServiceCpuMappingRequest,
    ) -> Result<(), KernelAhciServiceCpuMappingAdapterError> {
        if index >= MAPPING_COUNT || self.requests[index] != request {
            return Err(KernelAhciServiceCpuMappingAdapterError::WrongMemoryObject(
                index,
            ));
        }
        let mapping = self.mappings[index]
            .ok_or(KernelAhciServiceCpuMappingAdapterError::WrongPhysicalBacking(index))?;
        let backend_request = self
            .memory
            .mapping_revocation_request(mapping, self.target_capability, self.capabilities)
            .map_err(KernelAhciServiceCpuMappingAdapterError::Resource)?;
        let described = backend_request.mapping();
        let physical = backend_request
            .physical()
            .ok_or(KernelAhciServiceCpuMappingAdapterError::WrongPhysicalBacking(index))?;
        if backend_request.target() != self.target
            || described.object() != self.memory_objects[index]
            || described.virtual_page() != request.virtual_base() / PAGE_SIZE
            || described.object_page() != 0
            || described.pages() != request.mapped_bytes() / PAGE_SIZE
            || described.access() != Rights::READ.union(Rights::WRITE)
            || physical.start().get() != request.physical_base()
            || physical.pages() != request.mapped_bytes() / PAGE_SIZE
        {
            return Err(KernelAhciServiceCpuMappingAdapterError::WrongPhysicalBacking(index));
        }
        Ok(())
    }
}

// SAFETY: construction exact-matches every public request to one typed,
// physically-backed kernel memory object and one MAP|CONTROL target. Install
// and removal delegate to MemoryPoolTable's transactional backend boundary and
// retain each generational mapping ID until exact removal succeeds.
unsafe impl<B: MemoryMappingBackend, const P: usize, const O: usize, const M: usize, const C: usize>
    AhciServiceCpuMappingBackend for KernelAhciServiceCpuMappingAdapter<'_, B, P, O, M, C>
{
    type Error = KernelAhciServiceCpuMappingOperationError<B::Error>;

    fn install_rw_nx(&mut self, request: AhciServiceCpuMappingRequest) -> Result<(), Self::Error> {
        let index = self
            .request_index(request)
            .ok_or(Self::Error::InvalidRequest)?;
        if self.mappings[index].is_some() {
            return Err(Self::Error::DuplicateInstall);
        }
        let mapping = self
            .memory
            .install_backed_mapping(
                self.memory_objects[index],
                self.memory_capabilities[index],
                self.target_capability,
                request.virtual_base() / PAGE_SIZE,
                0,
                request.mapped_bytes() / PAGE_SIZE,
                Rights::READ.union(Rights::WRITE),
                self.capabilities,
                self.backend,
            )
            .map_err(Self::Error::Mapping)?;
        self.mappings[index] = Some(mapping);
        Ok(())
    }

    fn remove(&mut self, request: AhciServiceCpuMappingRequest) -> Result<(), Self::Error> {
        let index = self
            .request_index(request)
            .ok_or(Self::Error::InvalidRequest)?;
        let mapping = self.mappings[index].ok_or(Self::Error::MissingMapping)?;
        self.memory
            .remove_mapping(
                mapping,
                self.target_capability,
                self.capabilities,
                self.backend,
            )
            .map_err(Self::Error::Mapping)?;
        self.mappings[index] = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        install_ahci_service_cpu_mappings, remove_ahci_service_cpu_mappings, AhciAbarMapping,
        AhciDataDmaRegion, AhciDmaRegion, AhciPortDmaLayout, AhciServiceCpuMapping,
    };
    use mrml_interface_storage_block_provider_v1::{
        BlockProviderDevice, OpaqueHandle, BLOCK_DEVICE_FLAG_FLUSH, BLOCK_DEVICE_FLAG_RESET,
    };
    use mrml_kernel::{
        MemoryBackingBackendRequest, MemoryBackingKind, MemoryMappingBackendRequest,
        MemoryObjectBackingBackend, MemoryPhysicalBacking, ObjectId, PhysAddr,
    };

    struct Backing;

    unsafe impl MemoryObjectBackingBackend for Backing {
        type Error = ();

        fn claim_zeroed(&mut self, _: MemoryBackingBackendRequest) -> Result<(), Self::Error> {
            Ok(())
        }

        fn release_scrubbed(&mut self, _: MemoryBackingBackendRequest) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct NativeMappings {
        installed: [Option<MemoryMappingBackendRequest>; MAPPING_COUNT],
    }

    unsafe impl MemoryMappingBackend for NativeMappings {
        type Error = ();

        fn install(&mut self, request: MemoryMappingBackendRequest) -> Result<(), Self::Error> {
            let slot = self.installed.iter().position(Option::is_none).ok_or(())?;
            self.installed[slot] = Some(request);
            Ok(())
        }

        fn remove(&mut self, request: MemoryMappingBackendRequest) -> Result<(), Self::Error> {
            let slot = self
                .installed
                .iter()
                .position(|installed| *installed == Some(request))
                .ok_or(())?;
            self.installed[slot] = None;
            Ok(())
        }
    }

    fn record(
        objects: [ObjectId; MAPPING_COUNT],
        generations: [u64; MAPPING_COUNT],
    ) -> AhciServiceLaunchRecord {
        let region = |index: usize, physical_base: u64, bytes: u64| AhciDmaRegion {
            memory_object: objects[index],
            allocation_generation: generations[index],
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
            crate::AhciAbarDescriptor {
                location: crate::PciFunctionLocation::new(0, 0, 31, 2).unwrap(),
                configuration_generation: 11,
                vendor_id: 0x8086,
                device_id: 0x7a62,
                physical_base: 0x10_0000,
                bytes: 0x2000,
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
                command_list: region(0, 0x30_0000, 1024),
                received_fis: region(1, 0x31_0000, 256),
                command_tables: region(2, 0x32_0000, 1024),
                dma_generation: 13,
            },
            AhciDataDmaRegion {
                memory_object: objects[3],
                allocation_generation: generations[3],
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

    #[test]
    fn exact_typed_backing_installs_and_retires_four_kernel_mappings() {
        let mut table = MemoryPoolTable::<1, 4, 4>::new(31).unwrap();
        let mut capabilities = CapabilitySpace::<16>::new();
        let root_rights = Rights::ALLOCATE
            .union(Rights::CONTROL)
            .union(Rights::MAP)
            .union(Rights::INSPECT);
        let (pool, pool_capability) = table
            .create_root(4, 4, 0, root_rights, &mut capabilities)
            .unwrap();
        let owner_rights = AHCI_SERVICE_CPU_MAPPING_RIGHTS
            .union(Rights::CONTROL)
            .union(Rights::PIN);
        let mut objects = [None; MAPPING_COUNT];
        let mut mapping_capabilities = [Capability::from_token(0); MAPPING_COUNT];
        let physical = [0x30_0000, 0x31_0000, 0x32_0000, 0x40_0000];
        let mut backing = Backing;
        for index in 0..MAPPING_COUNT {
            let (object, owner) = table
                .allocate_object(
                    pool,
                    pool_capability,
                    1,
                    MemoryBackingKind::Anonymous,
                    owner_rights,
                    &mut capabilities,
                )
                .unwrap();
            table
                .bind_physical_backing(
                    object,
                    owner,
                    MemoryPhysicalBacking::new(PhysAddr::new(physical[index]).unwrap(), 1).unwrap(),
                    &capabilities,
                    &mut backing,
                )
                .unwrap();
            let authority = capabilities.authorize(owner, Rights::READ).unwrap();
            mapping_capabilities[index] = capabilities
                .insert(authority, AHCI_SERVICE_CPU_MAPPING_RIGHTS)
                .unwrap();
            objects[index] = Some(object);
        }
        let objects = objects.map(Option::unwrap);
        let public_objects = core::array::from_fn(|index| {
            capabilities
                .authorize_exact(mapping_capabilities[index], AHCI_SERVICE_CPU_MAPPING_RIGHTS)
                .unwrap()
        });
        let generations = objects.map(|object| u64::from(object.generation()));
        let launch_record = record(public_objects, generations);
        let target = capabilities.insert(ObjectId(0x900), TARGET_RIGHTS).unwrap();
        let mut native = NativeMappings::default();
        let mut adapter = KernelAhciServiceCpuMappingAdapter::new(
            launch_record,
            ObjectId(0x900),
            &mut table,
            &mut native,
            &capabilities,
            objects,
            mapping_capabilities,
            target,
        )
        .unwrap();
        let state = install_ahci_service_cpu_mappings(
            launch_record,
            mapping_capabilities,
            &capabilities,
            &mut adapter,
        )
        .unwrap();
        assert!(adapter.mappings().iter().all(Option::is_some));
        let state = remove_ahci_service_cpu_mappings(state, &mut adapter).unwrap();
        assert!(state.complete());
        assert_eq!(adapter.mappings(), [None; MAPPING_COUNT]);
        drop(adapter);

        let mut substituted_generations = generations;
        substituted_generations[0] += 1;
        assert!(matches!(
            KernelAhciServiceCpuMappingAdapter::new(
                record(public_objects, substituted_generations),
                ObjectId(0x900),
                &mut table,
                &mut native,
                &capabilities,
                objects,
                mapping_capabilities,
                target,
            ),
            Err(KernelAhciServiceCpuMappingAdapterError::WrongAllocationGeneration(0))
        ));
    }
}
