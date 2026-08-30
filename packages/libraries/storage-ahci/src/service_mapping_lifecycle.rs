//! Combined pre-launch ownership of AHCI MMIO and CPU mappings.

use crate::{
    install_ahci_service_abar, install_ahci_service_cpu_mappings, remove_ahci_service_abar,
    remove_ahci_service_cpu_mappings, AhciAbarDescriptor, AhciAbarMappingBackend,
    AhciAbarMappingError, AhciAbarRemovalBackend, AhciAbarRemovalError, AhciInstalledCpuMappings,
    AhciServiceCpuMappingBackend, AhciServiceCpuMappingError, AhciServiceCpuMappingRemovalError,
    AhciServiceLaunchRecord, AhciServiceLaunchRecordError, InstalledAhciAbarMapping,
    PreparedAhciNativeServiceTask,
};
use mrml_kernel::{
    Capability, CapabilitySpace, NativeDeviceServiceActivationError, RestartPolicy, ServiceError,
    ServiceId, ServiceSupervisor, SupervisedServiceTask, TaskRuntime,
};

#[derive(Debug, Eq, PartialEq)]
pub struct AhciServiceMappingTeardown {
    abar: Option<InstalledAhciAbarMapping>,
    cpu: AhciInstalledCpuMappings,
}

impl AhciServiceMappingTeardown {
    pub const fn abar(&self) -> Option<InstalledAhciAbarMapping> {
        self.abar
    }
    pub const fn cpu(&self) -> AhciInstalledCpuMappings {
        self.cpu
    }
    pub fn complete(&self) -> bool {
        self.abar.is_none() && self.cpu.complete()
    }
}

#[derive(Debug, Eq, PartialEq)]
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

#[derive(Debug, Eq, PartialEq)]
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

impl<E> AhciServiceMappingRemovalError<E> {
    pub fn into_retained(self) -> AhciServiceMappingTeardown {
        match self {
            Self::Cpu { retained, .. } | Self::Abar { retained, .. } => retained,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct MappedAhciNativeServiceTask {
    prepared: PreparedAhciNativeServiceTask,
    mappings: AhciServiceMappingTeardown,
}

impl MappedAhciNativeServiceTask {
    pub const fn prepared(&self) -> PreparedAhciNativeServiceTask {
        self.prepared
    }

    pub const fn abar_mapping(&self) -> Option<InstalledAhciAbarMapping> {
        self.mappings.abar()
    }

    pub const fn cpu_mappings(&self) -> AhciInstalledCpuMappings {
        self.mappings.cpu()
    }

    pub const fn into_parts(self) -> (PreparedAhciNativeServiceTask, AhciServiceMappingTeardown) {
        (self.prepared, self.mappings)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ActiveAhciNativeServiceTask {
    mapped: MappedAhciNativeServiceTask,
    binding: SupervisedServiceTask,
}

impl ActiveAhciNativeServiceTask {
    pub const fn mapped(&self) -> &MappedAhciNativeServiceTask {
        &self.mapped
    }

    pub const fn service(&self) -> ServiceId {
        self.binding.service()
    }

    pub(crate) const fn binding(&self) -> SupervisedServiceTask {
        self.binding
    }

    pub(crate) fn into_parts(self) -> (SupervisedServiceTask, MappedAhciNativeServiceTask) {
        (self.binding, self.mapped)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciServiceActivationError {
    Native(NativeDeviceServiceActivationError),
    Service(ServiceError),
}

#[derive(Debug, Eq, PartialEq)]
pub struct AhciServiceActivationFailure {
    error: AhciServiceActivationError,
    mapped: MappedAhciNativeServiceTask,
}

impl AhciServiceActivationFailure {
    pub const fn error(&self) -> AhciServiceActivationError {
        self.error
    }

    pub const fn mapped(&self) -> &MappedAhciNativeServiceTask {
        &self.mapped
    }

    pub fn into_mapped(self) -> MappedAhciNativeServiceTask {
        self.mapped
    }
}

pub fn activate_mapped_ahci_service_task<
    const TASKS: usize,
    const CAPABILITIES: usize,
    const SERVICES: usize,
>(
    mapped: MappedAhciNativeServiceTask,
    restart_policy: RestartPolicy,
    supervisor: &mut ServiceSupervisor<SERVICES>,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
) -> Result<ActiveAhciNativeServiceTask, AhciServiceActivationFailure> {
    let prepared = mapped.prepared();
    let native_task = prepared.task();
    if let Err(error) = native_task.validate_activation_state(runtime) {
        return Err(AhciServiceActivationFailure {
            error: AhciServiceActivationError::Native(error),
            mapped,
        });
    }
    let task = native_task.task();
    let object = prepared.launch().spec().service().domain();
    // The mapped owner proves that native task construction and every
    // launch-bound AHCI mapping completed. Its retained native-task identity is
    // checked against this exact runtime above.
    // SAFETY: the lifecycle object is derived from that same bound launch
    // rather than accepted from a caller.
    match unsafe {
        supervisor.register_and_activate_constructed(object, task, restart_policy, runtime)
    } {
        Ok(binding) => {
            debug_assert_eq!(binding.task(), task);
            Ok(ActiveAhciNativeServiceTask { mapped, binding })
        }
        Err(error) => Err(AhciServiceActivationFailure {
            error: AhciServiceActivationError::Service(error),
            mapped,
        }),
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum PreparedAhciServiceMappingError<E> {
    InvalidBoundLaunch(AhciServiceLaunchRecordError),
    Mapping(AhciServiceMappingInstallError<E>),
}

#[derive(Debug, Eq, PartialEq)]
pub struct PreparedAhciServiceMappingFailure<E> {
    prepared: PreparedAhciNativeServiceTask,
    error: PreparedAhciServiceMappingError<E>,
}

impl<E> PreparedAhciServiceMappingFailure<E> {
    pub const fn prepared(&self) -> PreparedAhciNativeServiceTask {
        self.prepared
    }

    pub const fn error(&self) -> &PreparedAhciServiceMappingError<E> {
        &self.error
    }

    pub fn into_parts(
        self,
    ) -> (
        PreparedAhciNativeServiceTask,
        PreparedAhciServiceMappingError<E>,
    ) {
        (self.prepared, self.error)
    }
}

/// Installs only mappings named by the prepared task's bound launch.
#[allow(clippy::too_many_arguments)]
pub fn install_prepared_ahci_service_mappings<
    A: AhciAbarMappingBackend + AhciAbarRemovalBackend,
    D: AhciServiceCpuMappingBackend,
    const C: usize,
>(
    prepared: PreparedAhciNativeServiceTask,
    descriptor: AhciAbarDescriptor,
    abar_mapping_capability: Capability,
    abar_control_capability: Capability,
    cpu_mapping_capabilities: [Capability; 4],
    capabilities: &CapabilitySpace<C>,
    abar_backend: &mut A,
    cpu_backend: &mut D,
) -> Result<MappedAhciNativeServiceTask, PreparedAhciServiceMappingFailure<D::Error>> {
    let launch = prepared.launch();
    let spec = launch.spec();
    let record = AhciServiceLaunchRecord::new(
        spec.service().system_generation(),
        spec.service().provider_generation(),
        spec.attachment().attachment_generation(),
        spec.device(),
        spec.mapping(),
        spec.layout(),
        spec.data(),
        launch.cpu_mappings(),
    )
    .map_err(|error| PreparedAhciServiceMappingFailure {
        prepared,
        error: PreparedAhciServiceMappingError::InvalidBoundLaunch(error),
    })?;
    install_ahci_service_mappings(
        record,
        descriptor,
        abar_mapping_capability,
        abar_control_capability,
        cpu_mapping_capabilities,
        capabilities,
        abar_backend,
        cpu_backend,
    )
    .map(|mappings| MappedAhciNativeServiceTask { prepared, mappings })
    .map_err(|error| PreparedAhciServiceMappingFailure {
        prepared,
        error: PreparedAhciServiceMappingError::Mapping(error),
    })
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
        match remove_ahci_service_abar(abar, capabilities, abar_control_capability, abar_backend) {
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
        ActiveAhciPort, AhciAbarMapping, AhciDataDmaRegion, AhciDmaRegion, AhciPciFunctionSnapshot,
        AhciPortDmaBackend, AhciPortDmaLayout, AhciRegisterIo, AhciServiceCpuMapping,
        AhciServiceCpuMappingRequest, PciFunctionLocation, AHCI_SERVICE_CPU_MAPPING_RIGHTS,
    };
    use core::cell::Cell;
    use mrml_interface_storage_block_provider_v1::{
        BlockProviderDevice, OpaqueHandle, BLOCK_DEVICE_FLAG_FLUSH, BLOCK_DEVICE_FLAG_RESET,
    };
    use mrml_kernel::arch::x86_64::{
        InactivePageTableMappingBackend, InactivePageTableMappingError, Mapping, PagePermissions,
        PageTableBuildError, PageTableBuilder, PageTableStore, UserContext,
    };
    use mrml_kernel::{
        prepare_native_device_service_task, Capability, DeviceServiceLaunchAttachment,
        IsolationPlacement, IsolationServiceSpec, ObjectId, PhysAddr, Priority, Rights,
        TaskRuntime, TotalMicrovmClass, PAGE_SIZE,
    };

    const TABLE_BASE: u64 = 0x60_0000;

    #[derive(Default)]
    struct WriteFault {
        remaining: Cell<usize>,
    }

    impl WriteFault {
        fn arm(&self, failures: usize) {
            self.remaining.set(failures);
        }
    }

    struct Tables<'a> {
        pages: [[u64; 512]; 8],
        used: usize,
        base: u64,
        fault: &'a WriteFault,
    }

    impl<'a> Tables<'a> {
        fn new(base: u64, fault: &'a WriteFault) -> Self {
            Self {
                pages: [[0; 512]; 8],
                used: 0,
                base,
                fault,
            }
        }

        fn base(&self) -> u64 {
            self.base
        }

        fn slot(&self, frame: PhysAddr) -> Result<usize, PageTableBuildError> {
            let offset = frame
                .get()
                .checked_sub(self.base())
                .ok_or(PageTableBuildError::Storage)?;
            if !offset.is_multiple_of(PAGE_SIZE) {
                return Err(PageTableBuildError::Storage);
            }
            let slot =
                usize::try_from(offset / PAGE_SIZE).map_err(|_| PageTableBuildError::Storage)?;
            if slot >= self.used {
                return Err(PageTableBuildError::Storage);
            }
            Ok(slot)
        }
    }

    impl PageTableStore for Tables<'_> {
        fn allocate_zeroed(&mut self) -> Result<PhysAddr, PageTableBuildError> {
            if self.used == self.pages.len() {
                return Err(PageTableBuildError::Storage);
            }
            let address = self
                .base()
                .checked_add(self.used as u64 * PAGE_SIZE)
                .ok_or(PageTableBuildError::Storage)?;
            self.pages[self.used].fill(0);
            self.used += 1;
            PhysAddr::new(address).map_err(|_| PageTableBuildError::Storage)
        }

        fn read(&self, table: PhysAddr, index: usize) -> Result<u64, PageTableBuildError> {
            self.pages
                .get(self.slot(table)?)
                .and_then(|page| page.get(index))
                .copied()
                .ok_or(PageTableBuildError::Storage)
        }

        fn write(
            &mut self,
            table: PhysAddr,
            index: usize,
            value: u64,
        ) -> Result<(), PageTableBuildError> {
            let slot = self.slot(table)?;
            *self
                .pages
                .get_mut(slot)
                .and_then(|page| page.get_mut(index))
                .ok_or(PageTableBuildError::Storage)? = value;
            let remaining = self.fault.remaining.get();
            if remaining != 0 {
                self.fault.remaining.set(remaining - 1);
                return Err(PageTableBuildError::Storage);
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct AbarBackend {
        mapping: Option<AhciAbarMapping>,
        fail_remove: bool,
    }

    unsafe impl AhciAbarMappingBackend for AbarBackend {
        fn map_read_write_nx(&mut self, mapping: AhciAbarMapping) -> Result<(), ()> {
            if self.mapping.replace(mapping).is_some() {
                return Err(());
            }
            Ok(())
        }
    }

    unsafe impl AhciAbarRemovalBackend for AbarBackend {
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
            let index =
                usize::try_from(offset.checked_sub(0x200).ok_or(())? / 4).map_err(|_| ())?;
            self.0.get(index).copied().ok_or(())
        }

        fn write_u32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
            let index =
                usize::try_from(offset.checked_sub(0x200).ok_or(())? / 4).map_err(|_| ())?;
            *self.0.get_mut(index).ok_or(())? = value;
            Ok(())
        }
    }

    struct Data {
        sanitize_failures: usize,
    }

    impl crate::AhciDataBufferIo for Data {
        fn prepare_read(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> {
            Ok(())
        }
        fn prepare_write(&mut self, _: AhciDataDmaRegion, _: &[u8]) -> Result<(), ()> {
            Ok(())
        }
        fn complete_read(&mut self, _: AhciDataDmaRegion, _: &mut [u8]) -> Result<(), ()> {
            Ok(())
        }
        fn complete_write(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> {
            Ok(())
        }
        fn sanitize(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> {
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
        fn install_zeroed_layout(&mut self, _: AhciPortDmaLayout) -> Result<(), ()> {
            Ok(())
        }
        fn remove_layout(&mut self, _: AhciPortDmaLayout) -> Result<(), ()> {
            self.removals += 1;
            Ok(())
        }
    }

    struct TeardownLease<'a> {
        native: mrml_kernel::NativeDeviceServiceTask<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
        launch: crate::BoundAhciServiceLaunch,
        io_capabilities: CapabilitySpace<2>,
        read_data: Capability,
        write_data: Capability,
        command_list: Option<&'a mut [u8; 1024]>,
        received_fis: Option<&'a mut [u8; 256]>,
        command_tables: Option<&'a mut [u8; 1024]>,
        failures: usize,
        substitute_mapping_generation: Option<u64>,
        sanitize_failures: usize,
        calls: &'a Cell<usize>,
    }

    impl<'a> TeardownLease<'a> {
        fn new(
            native: mrml_kernel::NativeDeviceServiceTask<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
            launch: crate::BoundAhciServiceLaunch,
            command_list: &'a mut [u8; 1024],
            received_fis: &'a mut [u8; 256],
            command_tables: &'a mut [u8; 1024],
            calls: &'a Cell<usize>,
        ) -> Self {
            let mut io_capabilities = CapabilitySpace::<2>::new();
            let data = launch.spec().data();
            let read_data = io_capabilities
                .insert(
                    data.memory_object,
                    Rights::PIN.union(Rights::MAP).union(Rights::WRITE),
                )
                .unwrap();
            let write_data = io_capabilities
                .insert(
                    data.memory_object,
                    Rights::PIN.union(Rights::MAP).union(Rights::READ),
                )
                .unwrap();
            Self {
                native,
                launch,
                io_capabilities,
                read_data,
                write_data,
                command_list: Some(command_list),
                received_fis: Some(received_fis),
                command_tables: Some(command_tables),
                failures: 0,
                substitute_mapping_generation: None,
                sanitize_failures: 0,
                calls,
            }
        }
    }

    unsafe impl<'a> crate::AhciServiceTeardownLease for TeardownLease<'a> {
        type Registers = Registers;
        type CommandMemory = crate::AhciMappedCommandMemory<'a>;
        type DataIo = Data;
        type Error = u8;

        fn native_task(
            &self,
        ) -> mrml_kernel::NativeDeviceServiceTask<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }> {
            self.native
        }

        fn launch(&self) -> crate::BoundAhciServiceLaunch {
            self.launch
        }

        unsafe fn reacquire(
            mut self,
        ) -> Result<
            crate::AhciCommandBackendTeardown<Self::Registers, Self::CommandMemory, Self::DataIo>,
            (Self::Error, Self),
        > {
            self.calls.set(self.calls.get() + 1);
            if self.failures != 0 {
                self.failures -= 1;
                return Err((1, self));
            }

            let spec = self.launch.spec();
            let mut mapping = spec.mapping();
            let mut layout = spec.layout();
            if let Some(generation) = self.substitute_mapping_generation {
                mapping.mapping_generation = generation;
                layout.mapping_generation = generation;
            }
            let command_memory = crate::AhciMappedCommandMemory::new(
                layout,
                self.command_list.take().expect("test lease is one-shot"),
                self.received_fis.take().expect("test lease is one-shot"),
                self.command_tables.take().expect("test lease is one-shot"),
            )
            .expect("test lease has exact command mappings");
            let backend = crate::AhciCommandBlockBackend::new(
                &mut self.io_capabilities,
                spec.device().session,
                spec.device().media_generation,
                self.read_data,
                self.write_data,
                spec.data(),
                mapping,
                ActiveAhciPort::from_layout(layout),
                Registers::active(),
                command_memory,
                Data {
                    sanitize_failures: self.sanitize_failures,
                },
            )
            .expect("test lease has exact retained data authority");
            Ok(backend
                .into_teardown()
                .unwrap_or_else(|_| panic!("test lease must transfer active ownership")))
        }
    }

    #[derive(Default)]
    struct AddressSpaceEraser {
        erased: Option<(mrml_kernel::TaskId, UserContext)>,
    }

    impl mrml_kernel::ServiceAddressSpaceEraser for AddressSpaceEraser {
        type Error = ();

        fn erase(
            &mut self,
            task: mrml_kernel::TaskId,
            context: UserContext,
        ) -> Result<(), Self::Error> {
            if self.erased.replace((task, context)).is_some() {
                return Err(());
            }
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

        fn remove(&mut self, request: AhciServiceCpuMappingRequest) -> Result<(), Self::Error> {
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

    fn expected_abar_page_mapping() -> Mapping {
        let mapping = record().mapping();
        Mapping::new(
            mrml_kernel::arch::x86_64::VirtAddr::new(mapping.virtual_base).unwrap(),
            PhysAddr::new(mapping.physical_base).unwrap(),
            mapping.bytes / PAGE_SIZE,
            PagePermissions::USER_MMIO_READ_WRITE,
        )
        .unwrap()
    }

    fn inactive_abar_tables<'a>(
        base: u64,
        target: ObjectId,
        fault: &'a WriteFault,
    ) -> InactivePageTableMappingBackend<Tables<'a>> {
        let builder = PageTableBuilder::new(Tables::new(base, fault)).unwrap();
        // SAFETY: this modeled hierarchy is exclusively owned, unreachable by
        // every CPU, and `target` is its exact test address-space identity.
        unsafe { InactivePageTableMappingBackend::new(builder, target) }
    }

    #[allow(clippy::too_many_arguments)]
    fn install_inactive_abar<'a, 'fault: 'a>(
        prepared: crate::PreparedAhciNativeServiceTask,
        descriptor: AhciAbarDescriptor,
        mapping: Capability,
        control: Capability,
        authorities: &'a CapabilitySpace<6>,
        runtime: &'a TaskRuntime<3, 8>,
        tables: &'a mut InactivePageTableMappingBackend<Tables<'fault>>,
    ) -> Result<
        crate::KernelAhciAbarPreactivationOwner<'a, Tables<'fault>, 3, 8, 6>,
        crate::KernelAhciAbarPreactivationError,
    > {
        // SAFETY: these tests never activate the modeled root, have no CPU PAT
        // state or physical aliases, and retain the exact prepared-task root and
        // leaves until explicit rollback or poison verification.
        unsafe {
            crate::KernelAhciAbarPreactivationOwner::install(
                prepared,
                descriptor,
                mapping,
                control,
                authorities,
                runtime,
                tables,
            )
        }
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
                .insert(ObjectId(index as u64 + 20), AHCI_SERVICE_CPU_MAPPING_RIGHTS)
                .unwrap()
        });
        (capabilities, map, control, cpu)
    }

    fn service() -> IsolationServiceSpec {
        IsolationServiceSpec::new(
            ObjectId(1),
            ObjectId(2),
            1,
            3,
            4,
            5,
            TotalMicrovmClass::MicrovmEligible,
            IsolationPlacement::NativeService,
        )
        .unwrap()
    }

    fn native_tasks() -> (
        TaskRuntime<3, 8>,
        mrml_kernel::TaskId,
        crate::PreparedAhciNativeServiceTask,
        mrml_kernel::NativeDeviceServiceTask<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
        crate::BoundAhciServiceLaunch,
    ) {
        let mut runtime = TaskRuntime::<3, 8>::new(1_000, 1).unwrap();
        let context =
            |root| UserContext::new(PhysAddr::new(root).unwrap(), 0x40_0000, 0x7000_0000).unwrap();
        let source = runtime
            .create(Priority::NORMAL, context(0x50_0000))
            .unwrap();
        let target = runtime
            .create_for_construction(Priority::NORMAL, context(0x60_0000))
            .unwrap();
        let wrong_target = runtime
            .create_for_construction(Priority::NORMAL, context(0x70_0000))
            .unwrap();
        let endpoint = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(40), Rights::SIGNAL.union(Rights::DELEGATE))
            .unwrap();
        let launch_data = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(30), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let roles = [
            (ObjectId(10), Rights::CONTROL),
            (
                ObjectId(20),
                Rights::MAP.union(Rights::READ).union(Rights::WRITE),
            ),
            (
                ObjectId(21),
                Rights::MAP.union(Rights::READ).union(Rights::WRITE),
            ),
            (
                ObjectId(22),
                Rights::MAP.union(Rights::READ).union(Rights::WRITE),
            ),
            (
                ObjectId(23),
                Rights::PIN.union(Rights::MAP).union(Rights::WRITE),
            ),
            (
                ObjectId(23),
                Rights::PIN.union(Rights::MAP).union(Rights::READ),
            ),
        ];
        let mut handles = [Capability::from_token(0); crate::AHCI_SERVICE_AUTHORITY_COUNT];
        let authority_specs = core::array::from_fn(|index| {
            handles[index] = runtime
                .capabilities_mut(source)
                .unwrap()
                .insert(roles[index].0, roles[index].1.union(Rights::DELEGATE))
                .unwrap();
            (roles[index].0, handles[index], roles[index].1)
        });
        let (correct_attachment, wrong_attachment) = {
            let capabilities = runtime.capabilities(source).unwrap();
            let create = |generation| {
                DeviceServiceLaunchAttachment::new(
                    service(),
                    generation,
                    ObjectId(30),
                    9,
                    crate::AHCI_SERVICE_LAUNCH_BYTES as u32,
                    launch_data,
                    authority_specs,
                    capabilities,
                )
                .unwrap()
            };
            (create(8), create(9))
        };
        let bound = record().bind(service(), correct_attachment).unwrap();
        let correct = crate::prepare_bound_ahci_native_service_task(
            &mut runtime,
            source,
            target,
            bound,
            ObjectId(40),
            endpoint,
            source,
            ObjectId(42),
        )
        .unwrap();
        let wrong = prepare_native_device_service_task(
            &mut runtime,
            source,
            wrong_target,
            service(),
            wrong_attachment,
            ObjectId(40),
            endpoint,
            source,
            ObjectId(42),
        )
        .unwrap();
        (runtime, source, correct, wrong, bound)
    }

    #[test]
    fn prepared_task_installs_only_its_bound_mapping_set() {
        let (_, _, prepared, _, launch) = native_tasks();
        let (capabilities, map, control, cpu) = authorities();
        let mut abar_backend = AbarBackend::default();
        let mut cpu_backend = CpuBackend::default();
        let mapped = crate::install_prepared_ahci_service_mappings(
            prepared,
            descriptor(),
            map,
            control,
            cpu,
            &capabilities,
            &mut abar_backend,
            &mut cpu_backend,
        )
        .unwrap();
        assert_eq!(mapped.prepared(), prepared);
        assert_eq!(mapped.prepared().launch(), launch);
        assert!(mapped.abar_mapping().is_some());
        assert!(mapped.cpu_mappings().fully_installed());
        assert_eq!(abar_backend.mapping, Some(record().mapping()));
        assert!(cpu_backend.installed.iter().all(Option::is_some));
    }

    #[test]
    fn preactivation_owner_installs_verifies_and_rolls_back_exact_device_leaves() {
        let (runtime, _, prepared, _, _) = native_tasks();
        let target = prepared.launch().spec().service().domain();
        let fault = WriteFault::default();
        let mut tables = inactive_abar_tables(TABLE_BASE, target, &fault);
        let (capabilities, map, control, _) = authorities();
        let owner = install_inactive_abar(
            prepared,
            descriptor(),
            map,
            control,
            &capabilities,
            &runtime,
            &mut tables,
        )
        .unwrap();
        assert_eq!(owner.prepared(), prepared);
        assert_eq!(owner.task(), prepared.task().task());
        assert_eq!(owner.root(), prepared.task().page_table_root());
        assert_eq!(owner.mapping(), record().mapping());
        assert_eq!(owner.verify_exact(), Ok(()));
        let returned = match owner.rollback() {
            Ok(returned) => returned,
            Err(_) => panic!("exact inactive rollback must succeed"),
        };
        assert_eq!(returned, prepared);

        let builder = tables.into_builder().unwrap();
        assert_eq!(
            builder.verify_unmapped(expected_abar_page_mapping()),
            Ok(())
        );
    }

    #[test]
    fn preactivation_owner_rejects_descriptor_and_capabilities_before_mapping() {
        let (runtime, _, prepared, _, _) = native_tasks();
        let target = prepared.launch().spec().service().domain();
        let fault = WriteFault::default();
        let mut tables = inactive_abar_tables(TABLE_BASE, target, &fault);
        let (capabilities, map, control, _) = authorities();
        let mut wrong_descriptor = descriptor();
        wrong_descriptor.configuration_generation += 1;
        assert!(matches!(
            install_inactive_abar(
                prepared,
                wrong_descriptor,
                map,
                control,
                &capabilities,
                &runtime,
                &mut tables,
            ),
            Err(crate::KernelAhciAbarPreactivationError::AbarGenerationOrGeometryMismatch)
        ));
        assert!(matches!(
            install_inactive_abar(
                prepared,
                descriptor(),
                Capability::from_token(0),
                control,
                &capabilities,
                &runtime,
                &mut tables,
            ),
            Err(crate::KernelAhciAbarPreactivationError::Mapping(
                AhciAbarMappingError::Capability(_)
            ))
        ));
        assert!(matches!(
            install_inactive_abar(
                prepared,
                descriptor(),
                map,
                map,
                &capabilities,
                &runtime,
                &mut tables,
            ),
            Err(crate::KernelAhciAbarPreactivationError::ControlCapability(
                _
            ))
        ));

        let builder = tables.into_builder().unwrap();
        let pml4_index = ((record().mapping().virtual_base >> 39) & 0x1ff) as usize;
        assert_eq!(builder.store().read(builder.root(), pml4_index), Ok(0));
    }

    #[test]
    fn preactivation_owner_leaves_pci_identity_correlation_to_its_unsafe_caller() {
        let (runtime, _, prepared, _, _) = native_tasks();
        let target = prepared.launch().spec().service().domain();
        let fault = WriteFault::default();
        let mut tables = inactive_abar_tables(TABLE_BASE, target, &fault);
        let (capabilities, map, control, _) = authorities();
        let mut identity_substituted = descriptor();
        identity_substituted.location.bus += 1;
        identity_substituted.vendor_id ^= 0x0101;
        identity_substituted.device_id ^= 0x1010;
        let owner = install_inactive_abar(
            prepared,
            identity_substituted,
            map,
            control,
            &capabilities,
            &runtime,
            &mut tables,
        )
        .unwrap();
        assert_eq!(owner.mapping(), record().mapping());
        assert_eq!(owner.verify_exact(), Ok(()));
        assert!(owner.rollback().is_ok());
    }

    #[test]
    fn preactivation_owner_rejects_runtime_root_and_target_substitution() {
        let (runtime, _, prepared, _, _) = native_tasks();
        let target = prepared.launch().spec().service().domain();
        let (capabilities, map, control, _) = authorities();

        let root_fault = WriteFault::default();
        let mut wrong_root = inactive_abar_tables(0x70_0000, target, &root_fault);
        assert!(matches!(
            install_inactive_abar(
                prepared,
                descriptor(),
                map,
                control,
                &capabilities,
                &runtime,
                &mut wrong_root,
            ),
            Err(crate::KernelAhciAbarPreactivationError::WrongRoot)
        ));

        let target_fault = WriteFault::default();
        let mut wrong_target = inactive_abar_tables(TABLE_BASE, ObjectId(0xdead), &target_fault);
        assert!(matches!(
            install_inactive_abar(
                prepared,
                descriptor(),
                map,
                control,
                &capabilities,
                &runtime,
                &mut wrong_target,
            ),
            Err(crate::KernelAhciAbarPreactivationError::WrongTarget)
        ));

        let other_runtime = TaskRuntime::<3, 8>::new(1_000, 1).unwrap();
        let runtime_fault = WriteFault::default();
        let mut wrong_runtime = inactive_abar_tables(TABLE_BASE, target, &runtime_fault);
        assert!(matches!(
            install_inactive_abar(
                prepared,
                descriptor(),
                map,
                control,
                &capabilities,
                &other_runtime,
                &mut wrong_runtime,
            ),
            Err(crate::KernelAhciAbarPreactivationError::Activation(
                mrml_kernel::NativeDeviceServiceActivationError::WrongRuntime
            ))
        ));
    }

    #[test]
    fn poisoned_inactive_rollback_retains_owner_and_quarantines_hierarchy() {
        let (runtime, _, prepared, _, _) = native_tasks();
        let target = prepared.launch().spec().service().domain();
        let fault = WriteFault::default();
        let mut tables = inactive_abar_tables(TABLE_BASE, target, &fault);
        let (capabilities, map, control, _) = authorities();
        let owner = install_inactive_abar(
            prepared,
            descriptor(),
            map,
            control,
            &capabilities,
            &runtime,
            &mut tables,
        )
        .unwrap();
        fault.arm(2);
        let failure = match owner.rollback() {
            Ok(_) => panic!("injected rollback uncertainty must fail"),
            Err(failure) => failure,
        };
        assert!(matches!(
            failure.error(),
            crate::AhciAbarRemovalError::BackendRejected { .. }
        ));
        assert!(failure.owner().page_tables_poisoned());
        drop(failure.into_owner());
        assert!(matches!(
            tables.into_builder(),
            Err(InactivePageTableMappingError::Poisoned)
        ));
    }

    #[test]
    fn prepared_mapping_failure_returns_task_owner_before_mutation() {
        let (_, _, prepared, _, _) = native_tasks();
        let (capabilities, map, control, cpu) = authorities();
        let mut abar_backend = AbarBackend::default();
        let mut cpu_backend = CpuBackend::default();
        let mut wrong = descriptor();
        wrong.configuration_generation += 1;
        let failure = crate::install_prepared_ahci_service_mappings(
            prepared,
            wrong,
            map,
            control,
            cpu,
            &capabilities,
            &mut abar_backend,
            &mut cpu_backend,
        )
        .unwrap_err();
        assert_eq!(failure.prepared(), prepared);
        assert_eq!(
            failure.error(),
            &crate::PreparedAhciServiceMappingError::Mapping(
                AhciServiceMappingInstallError::DescriptorMismatch
            )
        );
        assert!(abar_backend.mapping.is_none());
        assert!(cpu_backend.installed.iter().all(Option::is_none));
    }

    #[test]
    fn mapped_task_becomes_runnable_only_through_typed_activation() {
        let (mut runtime, source, prepared, _, _) = native_tasks();
        let target = prepared.task().task();
        let (capabilities, map, control, cpu) = authorities();
        let mut abar_backend = AbarBackend::default();
        let mut cpu_backend = CpuBackend::default();
        let mapped = crate::install_prepared_ahci_service_mappings(
            prepared,
            descriptor(),
            map,
            control,
            cpu,
            &capabilities,
            &mut abar_backend,
            &mut cpu_backend,
        )
        .unwrap();
        let expected_prepared = mapped.prepared();
        assert_eq!(runtime.construction_pending(target), Ok(true));
        assert_eq!(runtime.load().runnable(), 1);
        assert!(matches!(
            runtime.start(),
            mrml_kernel::ScheduleOutcome::Switch { to, .. } if to == source
        ));
        assert_eq!(
            runtime.yield_current(),
            Ok(mrml_kernel::ScheduleOutcome::Continue(source))
        );
        let mut supervisor = ServiceSupervisor::<2>::new();
        let installed_context = *runtime.context(target).unwrap();
        runtime.context_mut(target).unwrap().rax = 1;
        let failure = crate::activate_mapped_ahci_service_task(
            mapped,
            RestartPolicy::ONCE_IMMEDIATE,
            &mut supervisor,
            &mut runtime,
        )
        .unwrap_err();
        assert_eq!(
            failure.error(),
            crate::AhciServiceActivationError::Native(
                mrml_kernel::NativeDeviceServiceActivationError::ContextMismatch,
            )
        );
        assert_eq!(runtime.construction_pending(target), Ok(true));
        assert_eq!(runtime.load().runnable(), 1);
        assert!(abar_backend.mapping.is_some());
        assert!(cpu_backend.installed.iter().all(Option::is_some));
        *runtime.context_mut(target).unwrap() = installed_context;
        let active = crate::activate_mapped_ahci_service_task(
            failure.into_mapped(),
            RestartPolicy::ONCE_IMMEDIATE,
            &mut supervisor,
            &mut runtime,
        )
        .unwrap();
        assert_eq!(active.mapped().prepared(), expected_prepared);
        assert!(active.mapped().abar_mapping().is_some());
        assert!(active.mapped().cpu_mappings().fully_installed());
        assert_eq!(supervisor.task(active.service()), Ok(Some(target)));
        assert_eq!(
            supervisor.state(active.service()),
            Ok(mrml_kernel::ServiceState::Running)
        );
        assert_eq!(
            supervisor.register(
                service().domain(),
                mrml_kernel::TaskId::from_token((8u64 << 32) | 7),
            ),
            Err(ServiceError::ObjectAlreadyRegistered)
        );
        assert_eq!(runtime.construction_pending(target), Ok(false));
        assert_eq!(runtime.load().runnable(), 2);
        assert!(matches!(
            runtime.yield_current(),
            Ok(mrml_kernel::ScheduleOutcome::Switch { to, .. }) if to == target
        ));
    }

    #[test]
    fn mapped_activation_rejects_same_task_token_from_another_runtime() {
        let (mut owner_runtime, _, prepared, _, _) = native_tasks();
        let owner_target = prepared.task().task();
        let (mut other_runtime, _, other_prepared, _, _) = native_tasks();
        let other_target = other_prepared.task().task();
        assert_eq!(owner_target, other_target);
        let (capabilities, map, control, cpu) = authorities();
        let mut abar_backend = AbarBackend::default();
        let mut cpu_backend = CpuBackend::default();
        let mapped = crate::install_prepared_ahci_service_mappings(
            prepared,
            descriptor(),
            map,
            control,
            cpu,
            &capabilities,
            &mut abar_backend,
            &mut cpu_backend,
        )
        .unwrap();
        let expected_prepared = mapped.prepared();
        let expected_abar = mapped.abar_mapping();
        let expected_cpu = mapped.cpu_mappings();
        let before = other_runtime.load();
        let mut supervisor = ServiceSupervisor::<1>::new();

        let failure = crate::activate_mapped_ahci_service_task(
            mapped,
            RestartPolicy::ONCE_IMMEDIATE,
            &mut supervisor,
            &mut other_runtime,
        )
        .unwrap_err();
        assert_eq!(
            failure.error(),
            crate::AhciServiceActivationError::Native(
                mrml_kernel::NativeDeviceServiceActivationError::WrongRuntime,
            )
        );
        assert_eq!(failure.mapped().prepared(), expected_prepared);
        assert_eq!(failure.mapped().abar_mapping(), expected_abar);
        assert_eq!(failure.mapped().cpu_mappings(), expected_cpu);
        assert_eq!(other_runtime.load(), before);
        assert_eq!(other_runtime.construction_pending(other_target), Ok(true));
        assert_eq!(owner_runtime.construction_pending(owner_target), Ok(true));
        assert!(abar_backend.mapping.is_some());
        assert!(cpu_backend.installed.iter().all(Option::is_some));
        let mapped = failure.into_mapped();

        let existing = supervisor
            .register(
                ObjectId(0x99),
                mrml_kernel::TaskId::from_token((9u64 << 32) | 7),
            )
            .unwrap();
        let owner_before = owner_runtime.load();
        let failure = crate::activate_mapped_ahci_service_task(
            mapped,
            RestartPolicy::ONCE_IMMEDIATE,
            &mut supervisor,
            &mut owner_runtime,
        )
        .unwrap_err();
        assert_eq!(
            failure.error(),
            crate::AhciServiceActivationError::Service(ServiceError::Full)
        );
        assert_eq!(failure.mapped().prepared(), expected_prepared);
        assert_eq!(failure.mapped().abar_mapping(), expected_abar);
        assert_eq!(failure.mapped().cpu_mappings(), expected_cpu);
        assert_eq!(
            supervisor.state(existing),
            Ok(mrml_kernel::ServiceState::Running)
        );
        assert_eq!(owner_runtime.load(), owner_before);
        assert_eq!(owner_runtime.construction_pending(owner_target), Ok(true));
        let mapped = failure.into_mapped();

        let mut supervisor = ServiceSupervisor::<1>::new();
        let active = crate::activate_mapped_ahci_service_task(
            mapped,
            RestartPolicy::ONCE_IMMEDIATE,
            &mut supervisor,
            &mut owner_runtime,
        )
        .unwrap();
        assert_eq!(supervisor.task(active.service()), Ok(Some(owner_target)));
        assert_eq!(
            supervisor.state(active.service()),
            Ok(mrml_kernel::ServiceState::Running)
        );
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
                record(),
                descriptor(),
                map,
                control,
                cpu,
                &capabilities,
                &mut abar_backend,
                &mut cpu_backend,
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
            record(),
            descriptor(),
            map,
            control,
            cpu,
            &capabilities,
            &mut abar_backend,
            &mut cpu_backend,
        )
        .unwrap_err();
        let AhciServiceMappingInstallError::CpuRetained { retained, .. } = error else {
            panic!("expected combined retained state");
        };
        assert!(retained.abar().is_some());
        cpu_backend.fail_remove_object = None;
        let state = remove_ahci_service_mappings(
            retained,
            control,
            &capabilities,
            &mut abar_backend,
            &mut cpu_backend,
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
        abar_backend.fail_remove = true;
        let error = remove_ahci_service_mappings(
            state,
            control,
            &capabilities,
            &mut abar_backend,
            &mut cpu_backend,
        )
        .unwrap_err();
        let AhciServiceMappingRemovalError::Abar { retained, .. } = error else {
            panic!("expected retained ABAR cleanup");
        };
        assert!(retained.cpu().complete());
        abar_backend.fail_remove = false;
        assert!(remove_ahci_service_mappings(
            retained,
            control,
            &capabilities,
            &mut abar_backend,
            &mut cpu_backend,
        )
        .unwrap()
        .complete());
    }

    #[test]
    fn colliding_runtime_lease_is_rejected_and_substitution_is_quarantined() {
        let (mut runtime, source, prepared, _, _) = native_tasks();
        let native = prepared.task();
        let target = native.task();
        let launch = prepared.launch();
        let (_, _, other_prepared, _, _) = native_tasks();
        let colliding_native = other_prepared.task();
        assert_eq!(colliding_native.task(), native.task());
        assert_ne!(colliding_native, native);
        let (capabilities, map, _control, cpu) = authorities();
        let mut abar_backend = AbarBackend::default();
        let mut cpu_backend = CpuBackend::default();
        let mapped = crate::install_prepared_ahci_service_mappings(
            prepared,
            descriptor(),
            map,
            _control,
            cpu,
            &capabilities,
            &mut abar_backend,
            &mut cpu_backend,
        )
        .unwrap();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let active = crate::activate_mapped_ahci_service_task(
            mapped,
            RestartPolicy::ONCE_IMMEDIATE,
            &mut supervisor,
            &mut runtime,
        )
        .unwrap();
        let service_id = active.service();
        assert!(matches!(
            runtime.start(),
            mrml_kernel::ScheduleOutcome::Switch { to, .. } if to == source
        ));
        assert!(matches!(
            runtime.yield_current().unwrap(),
            mrml_kernel::ScheduleOutcome::Switch { to, .. } if to == target
        ));

        let mut colliding_command_list = [0xa5; 1024];
        let mut colliding_received_fis = [0xa5; 256];
        let mut colliding_command_tables = [0xa5; 1024];
        let colliding_calls = Cell::new(0);
        let colliding_lease = TeardownLease::new(
            colliding_native,
            launch,
            &mut colliding_command_list,
            &mut colliding_received_fis,
            &mut colliding_command_tables,
            &colliding_calls,
        );
        let error = match crate::begin_active_ahci_service_exit(
            active,
            colliding_lease,
            &supervisor,
            &mut runtime,
        ) {
            Ok(_) => panic!("a runtime-collision lease must not freeze the task"),
            Err(error) => error,
        };
        assert_eq!(
            error.binding_error(),
            Some(crate::AhciServiceTeardownLeaseBindingError::NativeTaskMismatch)
        );
        let (active, colliding_lease) = error.into_parts();
        drop(colliding_lease);
        assert_eq!(colliding_calls.get(), 0);
        assert_eq!(runtime.current(), Some(target));

        let mut command_list = [0xa5; 1024];
        let mut received_fis = [0xa5; 256];
        let mut command_tables = [0xa5; 1024];
        let lease_calls = Cell::new(0);
        let mut lease = TeardownLease::new(
            native,
            launch,
            &mut command_list,
            &mut received_fis,
            &mut command_tables,
            &lease_calls,
        );
        lease.substitute_mapping_generation = Some(99);
        let frozen =
            crate::begin_active_ahci_service_exit(active, lease, &supervisor, &mut runtime)
                .unwrap_or_else(|_| panic!("the exact manager lease must freeze"));
        let error = match crate::reacquire_frozen_ahci_service_teardown(frozen) {
            Ok(_) => panic!("substituted teardown state must not become quiescence authority"),
            Err(error) => error,
        };
        assert_eq!(
            error.binding_error(),
            Some(crate::AhciServiceTaskBindingError::MappingMismatch)
        );
        let quarantine = error
            .into_quarantine()
            .unwrap_or_else(|_| panic!("binding failure must retain one quarantine owner"));
        assert_eq!(quarantine.service(), service_id);
        assert_eq!(quarantine.task(), target);
        assert_eq!(quarantine.launch(), launch);
        assert_eq!(quarantine.acquired_mapping().mapping_generation, 99);
        assert!(!quarantine.retained_mappings_complete());
        assert_eq!(lease_calls.get(), 1);
        assert_eq!(runtime.start(), mrml_kernel::ScheduleOutcome::Idle);
        assert!(abar_backend.mapping.is_some());
        assert!(cpu_backend.installed.iter().all(Option::is_some));
        assert_eq!(
            supervisor.state(service_id),
            Ok(mrml_kernel::ServiceState::Running)
        );
    }

    #[test]
    fn data_and_dma_cleanup_gate_mapping_withdrawal() {
        let (mut runtime, source, prepared, mismatched_native, _) = native_tasks();
        let task = prepared.task();
        let target = task.task();
        let launch = prepared.launch();
        let (capabilities, map, control, cpu) = authorities();
        let mut abar_backend = AbarBackend::default();
        let mut cpu_backend = CpuBackend::default();
        let mapped = crate::install_prepared_ahci_service_mappings(
            prepared,
            descriptor(),
            map,
            control,
            cpu,
            &capabilities,
            &mut abar_backend,
            &mut cpu_backend,
        )
        .unwrap();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let active = crate::activate_mapped_ahci_service_task(
            mapped,
            RestartPolicy::ONCE_IMMEDIATE,
            &mut supervisor,
            &mut runtime,
        )
        .unwrap();
        let service_id = active.service();
        let installed_context = *runtime.context(target).unwrap();
        assert_eq!(supervisor.task(service_id), Ok(Some(target)));
        assert!(matches!(
            runtime.start(),
            mrml_kernel::ScheduleOutcome::Switch { to, .. } if to == source
        ));

        let mut command_list = [0xa5; 1024];
        let mut received_fis = [0xa5; 256];
        let mut command_tables = [0xa5; 1024];
        let lease_calls = Cell::new(0);
        let mut lease = TeardownLease::new(
            task,
            launch,
            &mut command_list,
            &mut received_fis,
            &mut command_tables,
            &lease_calls,
        );
        lease.failures = 1;
        lease.sanitize_failures = 1;
        let mut dma_backend = DmaBackend::default();
        let error =
            match crate::begin_active_ahci_service_exit(active, lease, &supervisor, &mut runtime) {
                Ok(_) => panic!("a non-current service task must not freeze"),
                Err(error) => error,
            };
        assert_eq!(
            error.lifecycle_error(),
            Some(
                mrml_kernel::SupervisedNativeDeviceServiceRetirementError::Native(
                    mrml_kernel::NativeDeviceServiceRetirementError::NotCurrent,
                )
            )
        );
        let (active, lease) = error.into_parts();
        assert_eq!(lease_calls.get(), 0);
        assert!(matches!(
            runtime.yield_current().unwrap(),
            mrml_kernel::ScheduleOutcome::Switch { to, .. } if to == target
        ));
        assert!(matches!(
            supervisor.freeze_current_native_device_service(
                active.binding(),
                mismatched_native,
                &mut runtime,
            ),
            Err(
                mrml_kernel::SupervisedNativeDeviceServiceRetirementError::Service(
                    ServiceError::TaskMismatch,
                )
            )
        ));
        assert_eq!(runtime.current(), Some(target));

        let wrong_supervisor = ServiceSupervisor::<1>::new();
        let error = match crate::begin_active_ahci_service_exit(
            active,
            lease,
            &wrong_supervisor,
            &mut runtime,
        ) {
            Ok(_) => panic!("another supervisor must not freeze the service"),
            Err(error) => error,
        };
        assert_eq!(
            error.lifecycle_error(),
            Some(
                mrml_kernel::SupervisedNativeDeviceServiceRetirementError::Service(
                    ServiceError::InvalidService,
                )
            )
        );
        let (active, lease) = error.into_parts();
        assert_eq!(lease_calls.get(), 0);
        assert_eq!(runtime.current(), Some(target));

        let frozen =
            crate::begin_active_ahci_service_exit(active, lease, &supervisor, &mut runtime)
                .unwrap_or_else(|_| panic!("exact current service must freeze"));
        assert_eq!(frozen.service(), service_id);
        assert_eq!(frozen.task(), target);
        assert_eq!(lease_calls.get(), 0);
        assert_eq!(runtime.start(), mrml_kernel::ScheduleOutcome::Idle);
        assert_eq!(
            runtime.create(Priority::NORMAL, installed_context),
            Err(mrml_kernel::TaskRuntimeError::RetirementDispatchPending)
        );
        assert_eq!(
            runtime.capabilities_mut(source).map(|_| ()),
            Err(mrml_kernel::TaskRuntimeError::RetirementDispatchPending)
        );
        assert!(matches!(
            runtime.terminate_current(),
            Err(mrml_kernel::TaskRuntimeError::RetirementDispatchPending)
        ));
        assert_eq!(
            runtime.yield_current(),
            Err(mrml_kernel::TaskRuntimeError::RetirementDispatchPending)
        );
        assert_eq!(
            runtime.revoke_capability(source, Capability::from_token(0)),
            Err(mrml_kernel::TaskRuntimeError::RetirementDispatchPending)
        );
        assert!(matches!(
            runtime.detach_domain(source),
            Err(mrml_kernel::TaskRuntimeError::RetirementDispatchPending)
        ));
        assert_eq!(dma_backend.removals, 0);

        let error = match crate::reacquire_frozen_ahci_service_teardown(frozen) {
            Ok(_) => panic!("injected reacquisition failure must retain the freeze"),
            Err(error) => error,
        };
        assert_eq!(error.lease_error(), Some(&1));
        let (_, frozen) = error
            .into_retry()
            .unwrap_or_else(|_| panic!("lease failure must return the frozen owner"));
        assert_eq!(lease_calls.get(), 1);
        assert_eq!(runtime.start(), mrml_kernel::ScheduleOutcome::Idle);
        assert_eq!(dma_backend.removals, 0);
        assert!(abar_backend.mapping.is_some());
        assert!(cpu_backend.installed.iter().all(Option::is_some));

        let reacquired = crate::reacquire_frozen_ahci_service_teardown(frozen)
            .unwrap_or_else(|_| panic!("exact teardown reacquisition must succeed"));
        assert_eq!(reacquired.service(), service_id);
        assert_eq!(reacquired.task(), target);
        assert_eq!(lease_calls.get(), 2);
        let error = match crate::quiesce_reacquired_ahci_service(reacquired, &mut dma_backend) {
            Ok(_) => panic!("first data sanitization must fail"),
            Err(error) => error,
        };
        let crate::AhciServiceDeviceQuiesceError::Pending(pending) = error.device_error() else {
            panic!("expected retryable data cleanup");
        };
        assert!(!pending.mapping_withdrawal_pending());
        assert_eq!(runtime.start(), mrml_kernel::ScheduleOutcome::Idle);
        assert_eq!(dma_backend.removals, 0);
        let owner = crate::resume_frozen_ahci_service_quiescence(error, &mut dma_backend)
            .unwrap_or_else(|_| panic!("retry must complete"));
        assert_eq!(owner.service(), service_id);

        let mut wrong_supervisor = ServiceSupervisor::<1>::new();
        let wrong_service = wrong_supervisor
            .register_in_runtime(service().domain(), target, &runtime)
            .unwrap();
        // SAFETY: this test backend models truthful stop, sanitization, and DMA
        // withdrawal; the returned owner remains held through typed cleanup.
        let error = match unsafe {
            crate::retire_quiesced_ahci_service_task(owner, &mut wrong_supervisor, &mut runtime)
        } {
            Ok(_) => panic!("another supervisor must not accept the binding"),
            Err(error) => error,
        };
        assert_eq!(
            error.error(),
            mrml_kernel::SupervisedNativeDeviceServiceRetirementError::Service(
                ServiceError::InvalidService,
            )
        );
        assert_eq!(
            wrong_supervisor.state(wrong_service),
            Ok(mrml_kernel::ServiceState::Running)
        );
        assert_eq!(
            supervisor.state(service_id),
            Ok(mrml_kernel::ServiceState::Running)
        );
        assert_eq!(supervisor.pending_cleanup(service_id), Ok(None));
        // SAFETY: the same truthful model proof is retained across the failed
        // supervisor attempt and dispatch remains withheld through cleanup.
        let retired = unsafe {
            crate::retire_quiesced_ahci_service_task(
                error.into_owner(),
                &mut supervisor,
                &mut runtime,
            )
        }
        .unwrap_or_else(|_| panic!("exact frozen task must retire"));
        let cleanup = supervisor
            .pending_cleanup(service_id)
            .unwrap()
            .expect("retirement must retain cleanup");
        assert_eq!(retired.service(), service_id);
        assert_eq!(cleanup.task(), target);
        assert_eq!(supervisor.task(service_id), Ok(None));
        assert_eq!(
            supervisor.state(service_id),
            Ok(mrml_kernel::ServiceState::Exited)
        );
        assert_eq!(supervisor.pending_cleanup(service_id), Ok(Some(cleanup)));
        let mut early_eraser = AddressSpaceEraser::default();
        assert_eq!(
            supervisor.complete_cleanup(cleanup, &mut early_eraser),
            Err(mrml_kernel::ServiceCleanupError::Service(
                ServiceError::ConstructedLifecycleRequired,
            ))
        );
        assert_eq!(early_eraser.erased, None);
        cpu_backend.fail_remove_object = Some(22);
        // SAFETY: these test backends report success only after removing their
        // exact recorded mapping; the retained owner is never dispatched here.
        let error = match unsafe {
            crate::remove_retired_ahci_service_mappings(
                retired,
                control,
                &capabilities,
                &mut abar_backend,
                &mut cpu_backend,
            )
        } {
            Ok(_) => panic!("injected CPU mapping removal must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error.error(),
            AhciServiceMappingRemovalError::Cpu { .. }
        ));
        assert_eq!(
            runtime.yield_current(),
            Err(mrml_kernel::TaskRuntimeError::RetirementDispatchPending)
        );
        cpu_backend.fail_remove_object = None;
        // SAFETY: the same exact model mappings are retained across the failed
        // attempt and both backends truthfully remove them on this retry.
        let removed = unsafe {
            crate::remove_retired_ahci_service_mappings(
                error.into_owner(),
                control,
                &capabilities,
                &mut abar_backend,
                &mut cpu_backend,
            )
        }
        .unwrap_or_else(|_| panic!("mapping-removal retry must complete"));
        assert!(abar_backend.mapping.is_none());
        assert!(cpu_backend.installed.iter().all(Option::is_none));
        let mut eraser = AddressSpaceEraser::default();
        // SAFETY: mapping withdrawal completed above and this model eraser
        // truthfully records exact erasure before returning success.
        let error = match unsafe {
            crate::complete_retired_ahci_service_cleanup(
                removed,
                &mut wrong_supervisor,
                &mut eraser,
            )
        } {
            Ok(_) => panic!("another supervisor must not accept cleanup"),
            Err(error) => error,
        };
        assert!(matches!(
            error.error(),
            mrml_kernel::ServiceCleanupError::Service(ServiceError::InvalidService)
        ));
        assert_eq!(eraser.erased, None);
        // SAFETY: the retained owner still proves mapping withdrawal and the
        // exact model eraser truthfully completes the address-space removal.
        let cleaned = unsafe {
            crate::complete_retired_ahci_service_cleanup(
                error.into_owner(),
                &mut supervisor,
                &mut eraser,
            )
        }
        .unwrap_or_else(|_| panic!("exact address-space cleanup must complete"));
        assert_eq!(eraser.erased, Some((target, installed_context)));
        assert_eq!(supervisor.pending_cleanup(service_id), Ok(None));

        let mut lifecycle_management = CapabilitySpace::<1>::new();
        let lifecycle_control = lifecycle_management
            .insert(service().domain(), Rights::CONTROL)
            .unwrap();
        assert!(matches!(
            supervisor.prepare_restart_at(
                service_id,
                &lifecycle_management,
                lifecycle_control,
                Priority::NORMAL,
                installed_context,
                0,
            ),
            Err(ServiceError::ConstructedLifecycleRequired)
        ));

        let dispatched = crate::dispatch_retired_ahci_service_task(cleaned, &mut runtime)
            .unwrap_or_else(|_| panic!("exact retained termination must dispatch"));
        assert_eq!(dispatched.service(), service_id);
        assert_eq!(
            dispatched.dispatch().user().map(|(task, _)| task),
            Some(source)
        );
        let (retirement, _) = dispatched.into_parts();
        assert_eq!(retirement.native().task(), task);
        assert_eq!(dma_backend.removals, 1);
    }
}
