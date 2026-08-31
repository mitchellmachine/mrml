//! Same-root preactivation ownership of the complete AHCI mapping set.

use crate::kernel_abar_page_table::ExactInactiveAbarBackend;
use crate::service_cpu_mapping::mapping_requests;
use crate::{
    AhciAbarDescriptor, AhciAbarMapping, AhciAbarMappingError, AhciAbarRemovalError,
    AhciInstalledCpuMappings, AhciServiceCpuMappingError, AhciServiceCpuMappingRemovalError,
    AhciServiceLaunchRecord, AhciServiceLaunchRecordError, InstalledAhciAbarMapping,
    KernelAhciServiceCpuMappingAdapter, KernelAhciServiceCpuMappingAdapterError,
    KernelAhciServiceCpuMappingOperationError, PreparedAhciNativeServiceTask,
    install_ahci_service_abar, install_ahci_service_cpu_mappings, remove_ahci_service_abar,
    remove_ahci_service_cpu_mappings,
};
use mrml_kernel::arch::x86_64::{
    InactivePageTableMappingBackend, InactivePageTableMappingError, PageTableStore, VirtAddr,
};
use mrml_kernel::{
    Capability, CapabilityError, CapabilitySpace, MemoryPoolTable,
    NativeDeviceServiceActivationError, ObjectId, PAGE_SIZE, PhysAddr, TaskId, TaskRuntime,
};

type CpuOperationError = KernelAhciServiceCpuMappingOperationError<InactivePageTableMappingError>;
type CpuInstallError = AhciServiceCpuMappingError<CpuOperationError>;
type CpuRemovalError = AhciServiceCpuMappingRemovalError<CpuOperationError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelAhciPreactivationMappingSetError {
    Activation(NativeDeviceServiceActivationError),
    WrongRoot,
    WrongTarget,
    AbarGenerationOrGeometryMismatch,
    InvalidMapping,
    ControlCapability(CapabilityError),
    WrongControlObject,
    LaunchRecord(AhciServiceLaunchRecordError),
    CpuAdapter(KernelAhciServiceCpuMappingAdapterError),
    Abar(AhciAbarMappingError),
    Cpu(CpuInstallError),
    Rollback {
        cpu: CpuInstallError,
        abar: AhciAbarRemovalError,
    },
    CpuRemoval(CpuRemovalError),
    AbarRemoval(AhciAbarRemovalError),
    Incomplete,
    Verification,
    Poisoned,
}

/// The outcome of a failed complete-set installation. A clean failure returns
/// the prepared task for retry. Every retained outcome keeps the sole page
/// table and memory-resource owners so callers cannot activate or discard an
/// uncertain hierarchy.
pub enum KernelAhciPreactivationMappingSetInstallState<
    'runtime,
    'resources,
    S,
    const P: usize,
    const O: usize,
    const M: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> where
    S: PageTableStore,
{
    Clean(PreparedAhciNativeServiceTask),
    Retained(
        KernelAhciPreactivationMappingSetOwner<
            'runtime,
            'resources,
            S,
            P,
            O,
            M,
            TASKS,
            TASK_CAPABILITIES,
            AUTHORITIES,
        >,
    ),
}

pub struct KernelAhciPreactivationMappingSetInstallFailure<
    'runtime,
    'resources,
    S,
    const P: usize,
    const O: usize,
    const M: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> where
    S: PageTableStore,
{
    error: KernelAhciPreactivationMappingSetError,
    state: KernelAhciPreactivationMappingSetInstallState<
        'runtime,
        'resources,
        S,
        P,
        O,
        M,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
}

impl<
    'runtime,
    'resources,
    S: PageTableStore,
    const P: usize,
    const O: usize,
    const M: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>
    KernelAhciPreactivationMappingSetInstallFailure<
        'runtime,
        'resources,
        S,
        P,
        O,
        M,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >
{
    pub const fn error(&self) -> KernelAhciPreactivationMappingSetError {
        self.error
    }

    pub const fn prepared(&self) -> PreparedAhciNativeServiceTask {
        match &self.state {
            KernelAhciPreactivationMappingSetInstallState::Clean(prepared) => *prepared,
            KernelAhciPreactivationMappingSetInstallState::Retained(owner) => owner.prepared,
        }
    }

    pub fn retained(
        &self,
    ) -> Option<
        &KernelAhciPreactivationMappingSetOwner<
            'runtime,
            'resources,
            S,
            P,
            O,
            M,
            TASKS,
            TASK_CAPABILITIES,
            AUTHORITIES,
        >,
    > {
        match &self.state {
            KernelAhciPreactivationMappingSetInstallState::Clean(_) => None,
            KernelAhciPreactivationMappingSetInstallState::Retained(owner) => Some(owner),
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        KernelAhciPreactivationMappingSetError,
        KernelAhciPreactivationMappingSetInstallState<
            'runtime,
            'resources,
            S,
            P,
            O,
            M,
            TASKS,
            TASK_CAPABILITIES,
            AUTHORITIES,
        >,
    ) {
        (self.error, self.state)
    }
}

/// Owns one prepared AHCI task's ABAR and four CPU mappings in one exact,
/// inactive x86 hierarchy. This is deliberately not an activation token and
/// cannot be converted to [`crate::MappedAhciNativeServiceTask`].
pub struct KernelAhciPreactivationMappingSetOwner<
    'runtime,
    'resources,
    S,
    const P: usize,
    const O: usize,
    const M: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> where
    S: PageTableStore,
{
    prepared: PreparedAhciNativeServiceTask,
    runtime: &'runtime TaskRuntime<TASKS, TASK_CAPABILITIES>,
    adapter: KernelAhciServiceCpuMappingAdapter<
        'resources,
        InactivePageTableMappingBackend<S>,
        P,
        O,
        M,
        AUTHORITIES,
    >,
    authorities: &'resources CapabilitySpace<AUTHORITIES>,
    control: Capability,
    abar: Option<InstalledAhciAbarMapping>,
    cpu: AhciInstalledCpuMappings,
    expected: AhciAbarMapping,
    target: ObjectId,
}

pub struct KernelAhciPreactivationMappingSetRollbackFailure<
    'runtime,
    'resources,
    S,
    const P: usize,
    const O: usize,
    const M: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> where
    S: PageTableStore,
{
    error: KernelAhciPreactivationMappingSetError,
    owner: KernelAhciPreactivationMappingSetOwner<
        'runtime,
        'resources,
        S,
        P,
        O,
        M,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
}

impl<
    'runtime,
    'resources,
    S: PageTableStore,
    const P: usize,
    const O: usize,
    const M: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>
    KernelAhciPreactivationMappingSetRollbackFailure<
        'runtime,
        'resources,
        S,
        P,
        O,
        M,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >
{
    pub const fn error(&self) -> KernelAhciPreactivationMappingSetError {
        self.error
    }

    pub fn owner(
        &self,
    ) -> &KernelAhciPreactivationMappingSetOwner<
        'runtime,
        'resources,
        S,
        P,
        O,
        M,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    > {
        &self.owner
    }

    pub fn into_owner(
        self,
    ) -> KernelAhciPreactivationMappingSetOwner<
        'runtime,
        'resources,
        S,
        P,
        O,
        M,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    > {
        self.owner
    }
}

impl<
    'runtime,
    'resources,
    S: PageTableStore,
    const P: usize,
    const O: usize,
    const M: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>
    KernelAhciPreactivationMappingSetOwner<
        'runtime,
        'resources,
        S,
        P,
        O,
        M,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >
{
    /// Installs the launch-bound ABAR and four CPU/DMA mappings in one exact
    /// inactive page-table hierarchy.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own the complete hierarchy and every
    /// physical memory object for this construction-pending task. The root
    /// must remain unreachable from every CPU, VM, and resumable context. PAT
    /// index 3 must be UC on every eligible CPU and cacheable aliases must be
    /// excluded for the complete retained lifetime. The caller must establish
    /// descriptor PCI-identity/device-object correlation and keep all exact
    /// roots, leaves, and memory-resource records unchanged after this owner
    /// is dropped or transferred. This remains preactivation-only.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn install(
        prepared: PreparedAhciNativeServiceTask,
        descriptor: AhciAbarDescriptor,
        abar_mapping_capability: Capability,
        abar_control_capability: Capability,
        cpu_mapping_capabilities: [Capability; 4],
        authorities: &'resources CapabilitySpace<AUTHORITIES>,
        runtime: &'runtime TaskRuntime<TASKS, TASK_CAPABILITIES>,
        tables: &'resources mut InactivePageTableMappingBackend<S>,
        memory: &'resources mut MemoryPoolTable<P, O, M>,
        memory_objects: [mrml_kernel::MemoryObjectId; 4],
        target_capability: Capability,
    ) -> Result<
        Self,
        KernelAhciPreactivationMappingSetInstallFailure<
            'runtime,
            'resources,
            S,
            P,
            O,
            M,
            TASKS,
            TASK_CAPABILITIES,
            AUTHORITIES,
        >,
    > {
        let task = prepared.task();
        let expected = prepared.launch().spec().mapping();
        let target = prepared.launch().spec().service().domain();
        if let Err(error) = task.validate_activation_state(runtime) {
            return Err(clean_install_failure(
                KernelAhciPreactivationMappingSetError::Activation(error),
                prepared,
            ));
        }
        if task.page_table_root() != tables.root() {
            return Err(clean_install_failure(
                KernelAhciPreactivationMappingSetError::WrongRoot,
                prepared,
            ));
        }
        if tables.target() != target {
            return Err(clean_install_failure(
                KernelAhciPreactivationMappingSetError::WrongTarget,
                prepared,
            ));
        }
        if descriptor.configuration_generation != expected.configuration_generation
            || descriptor.physical_base != expected.physical_base
            || descriptor.bytes != expected.bytes
        {
            return Err(clean_install_failure(
                KernelAhciPreactivationMappingSetError::AbarGenerationOrGeometryMismatch,
                prepared,
            ));
        }
        if mapping_range(expected).is_none() {
            return Err(clean_install_failure(
                KernelAhciPreactivationMappingSetError::InvalidMapping,
                prepared,
            ));
        }
        let control_object = match authorities
            .authorize_exact(abar_control_capability, mrml_kernel::Rights::CONTROL)
        {
            Ok(object) => object,
            Err(error) => {
                return Err(clean_install_failure(
                    KernelAhciPreactivationMappingSetError::ControlCapability(error),
                    prepared,
                ));
            }
        };
        if control_object != expected.device_object {
            return Err(clean_install_failure(
                KernelAhciPreactivationMappingSetError::WrongControlObject,
                prepared,
            ));
        }
        let record = launch_record(prepared).map_err(|error| {
            clean_install_failure(
                KernelAhciPreactivationMappingSetError::LaunchRecord(error),
                prepared,
            )
        })?;
        let mut adapter = match KernelAhciServiceCpuMappingAdapter::new(
            record,
            target,
            memory,
            tables,
            authorities,
            memory_objects,
            cpu_mapping_capabilities,
            target_capability,
        ) {
            Ok(adapter) => adapter,
            Err(error) => {
                return Err(clean_install_failure(
                    KernelAhciPreactivationMappingSetError::CpuAdapter(error),
                    prepared,
                ));
            }
        };
        let cpu_progress =
            AhciInstalledCpuMappings::from_progress(mapping_requests(record), [false; 4]);
        let installed_abar = {
            let mut backend =
                ExactInactiveAbarBackend::new(adapter.backend_mut(), expected, target);
            match install_ahci_service_abar(
                authorities,
                abar_mapping_capability,
                expected.device_object,
                descriptor,
                expected.virtual_base,
                expected.mapping_generation,
                &mut backend,
            ) {
                Ok(installed) => installed,
                Err(error) => {
                    let owner = Self {
                        prepared,
                        runtime,
                        adapter,
                        authorities,
                        control: abar_control_capability,
                        abar: None,
                        cpu: cpu_progress,
                        expected,
                        target,
                    };
                    if owner.adapter.backend().is_poisoned() {
                        return Err(retained_install_failure(
                            KernelAhciPreactivationMappingSetError::Abar(error),
                            owner,
                        ));
                    }
                    return Err(clean_install_failure(
                        KernelAhciPreactivationMappingSetError::Abar(error),
                        prepared,
                    ));
                }
            }
        };
        match install_ahci_service_cpu_mappings(
            record,
            cpu_mapping_capabilities,
            authorities,
            &mut adapter,
        ) {
            Ok(cpu) => Ok(Self {
                prepared,
                runtime,
                adapter,
                authorities,
                control: abar_control_capability,
                abar: Some(installed_abar),
                cpu,
                expected,
                target,
            }),
            Err(error) => {
                let retained_cpu = error.retained().unwrap_or(cpu_progress);
                let owner = Self {
                    prepared,
                    runtime,
                    adapter,
                    authorities,
                    control: abar_control_capability,
                    abar: Some(installed_abar),
                    cpu: retained_cpu,
                    expected,
                    target,
                };
                if error.retained().is_some() || owner.adapter.backend().is_poisoned() {
                    return Err(retained_install_failure(
                        KernelAhciPreactivationMappingSetError::Cpu(error),
                        owner,
                    ));
                }
                let mut owner = owner;
                let abar_result = {
                    let mut backend = ExactInactiveAbarBackend::new(
                        owner.adapter.backend_mut(),
                        owner.expected,
                        owner.target,
                    );
                    remove_ahci_service_abar(
                        installed_abar,
                        owner.authorities,
                        owner.control,
                        &mut backend,
                    )
                };
                match abar_result {
                    Ok(_) => Err(clean_install_failure(
                        KernelAhciPreactivationMappingSetError::Cpu(error),
                        prepared,
                    )),
                    Err(abar) => Err(retained_install_failure(
                        KernelAhciPreactivationMappingSetError::Rollback { cpu: error, abar },
                        owner,
                    )),
                }
            }
        }
    }

    pub const fn prepared(&self) -> PreparedAhciNativeServiceTask {
        self.prepared
    }

    pub const fn task(&self) -> TaskId {
        self.prepared.task().task()
    }

    pub const fn root(&self) -> PhysAddr {
        self.prepared.task().page_table_root()
    }

    pub const fn target(&self) -> ObjectId {
        self.target
    }

    pub const fn abar_mapping(&self) -> Option<AhciAbarMapping> {
        match self.abar {
            Some(installed) => Some(installed.mapping()),
            None => None,
        }
    }

    pub const fn cpu_mappings(&self) -> AhciInstalledCpuMappings {
        self.cpu
    }

    pub fn page_tables_poisoned(&self) -> bool {
        self.adapter.backend().is_poisoned()
    }

    /// Verifies all five launch ranges and the four retained memory-resource
    /// records in the same inactive hierarchy without creating an activation
    /// proof.
    pub fn verify_exact(&self) -> Result<(), KernelAhciPreactivationMappingSetError> {
        self.validate_bound_state()?;
        if self.adapter.backend().is_poisoned() {
            return Err(KernelAhciPreactivationMappingSetError::Poisoned);
        }
        let abar = self
            .abar
            .ok_or(KernelAhciPreactivationMappingSetError::Incomplete)?;
        if !self.cpu.fully_installed() {
            return Err(KernelAhciPreactivationMappingSetError::Incomplete);
        }
        if abar.mapping() != self.expected {
            return Err(KernelAhciPreactivationMappingSetError::Verification);
        }
        let (abar_virtual, abar_physical, abar_pages) = mapping_range(self.expected)
            .ok_or(KernelAhciPreactivationMappingSetError::InvalidMapping)?;
        self.adapter
            .backend()
            .verify_user_device_rw_nx(self.target, abar_virtual, abar_physical, abar_pages)
            .map_err(|_| KernelAhciPreactivationMappingSetError::Verification)?;
        let record = launch_record(self.prepared)
            .map_err(KernelAhciPreactivationMappingSetError::LaunchRecord)?;
        let requests = mapping_requests(record);
        if self.cpu.requests() != requests {
            return Err(KernelAhciPreactivationMappingSetError::Verification);
        }
        for (index, request) in requests.into_iter().enumerate() {
            if !self.cpu.installed(index) {
                return Err(KernelAhciPreactivationMappingSetError::Incomplete);
            }
            self.adapter
                .verify_installed_mapping(index, request)
                .map_err(KernelAhciPreactivationMappingSetError::CpuAdapter)?;
            let virtual_start = VirtAddr::new(request.virtual_base())
                .map_err(|_| KernelAhciPreactivationMappingSetError::Verification)?;
            let physical_start = PhysAddr::new(request.physical_base())
                .map_err(|_| KernelAhciPreactivationMappingSetError::Verification)?;
            self.adapter
                .backend()
                .verify_user_rw_nx(
                    self.target,
                    virtual_start,
                    physical_start,
                    request.mapped_bytes() / PAGE_SIZE,
                )
                .map_err(|_| KernelAhciPreactivationMappingSetError::Verification)?;
        }
        Ok(())
    }

    /// Withdraws CPU mappings in reverse order, then the ABAR, returning the
    /// prepared task only after all five mappings and ledger records are gone.
    pub fn rollback(
        self,
    ) -> Result<
        PreparedAhciNativeServiceTask,
        KernelAhciPreactivationMappingSetRollbackFailure<
            'runtime,
            'resources,
            S,
            P,
            O,
            M,
            TASKS,
            TASK_CAPABILITIES,
            AUTHORITIES,
        >,
    > {
        let mut owner = self;
        if let Err(error) = owner.validate_bound_state() {
            return Err(KernelAhciPreactivationMappingSetRollbackFailure { error, owner });
        }
        if owner.adapter.backend().is_poisoned() {
            return Err(KernelAhciPreactivationMappingSetRollbackFailure {
                error: KernelAhciPreactivationMappingSetError::Poisoned,
                owner,
            });
        }
        if !owner.cpu.complete() {
            match remove_ahci_service_cpu_mappings(owner.cpu, &mut owner.adapter) {
                Ok(cpu) => owner.cpu = cpu,
                Err(error) => {
                    owner.cpu = error.retained;
                    return Err(KernelAhciPreactivationMappingSetRollbackFailure {
                        error: KernelAhciPreactivationMappingSetError::CpuRemoval(error),
                        owner,
                    });
                }
            }
        }
        if let Some(abar) = owner.abar {
            let result = {
                let mut backend = ExactInactiveAbarBackend::new(
                    owner.adapter.backend_mut(),
                    owner.expected,
                    owner.target,
                );
                remove_ahci_service_abar(abar, owner.authorities, owner.control, &mut backend)
            };
            match result {
                Ok(_) => owner.abar = None,
                Err(error) => {
                    owner.abar = Some(error.retained());
                    return Err(KernelAhciPreactivationMappingSetRollbackFailure {
                        error: KernelAhciPreactivationMappingSetError::AbarRemoval(error),
                        owner,
                    });
                }
            }
        }
        Ok(owner.prepared)
    }

    fn validate_bound_state(&self) -> Result<(), KernelAhciPreactivationMappingSetError> {
        self.prepared
            .task()
            .validate_activation_state(self.runtime)
            .map_err(KernelAhciPreactivationMappingSetError::Activation)?;
        if self.prepared.task().page_table_root() != self.adapter.backend().root() {
            return Err(KernelAhciPreactivationMappingSetError::WrongRoot);
        }
        if self.adapter.backend().target() != self.target || self.adapter.target() != self.target {
            return Err(KernelAhciPreactivationMappingSetError::WrongTarget);
        }
        Ok(())
    }
}

fn clean_install_failure<
    'runtime,
    'resources,
    S: PageTableStore,
    const P: usize,
    const O: usize,
    const M: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>(
    error: KernelAhciPreactivationMappingSetError,
    prepared: PreparedAhciNativeServiceTask,
) -> KernelAhciPreactivationMappingSetInstallFailure<
    'runtime,
    'resources,
    S,
    P,
    O,
    M,
    TASKS,
    TASK_CAPABILITIES,
    AUTHORITIES,
> {
    KernelAhciPreactivationMappingSetInstallFailure {
        error,
        state: KernelAhciPreactivationMappingSetInstallState::Clean(prepared),
    }
}

fn retained_install_failure<
    'runtime,
    'resources,
    S: PageTableStore,
    const P: usize,
    const O: usize,
    const M: usize,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
>(
    error: KernelAhciPreactivationMappingSetError,
    owner: KernelAhciPreactivationMappingSetOwner<
        'runtime,
        'resources,
        S,
        P,
        O,
        M,
        TASKS,
        TASK_CAPABILITIES,
        AUTHORITIES,
    >,
) -> KernelAhciPreactivationMappingSetInstallFailure<
    'runtime,
    'resources,
    S,
    P,
    O,
    M,
    TASKS,
    TASK_CAPABILITIES,
    AUTHORITIES,
> {
    KernelAhciPreactivationMappingSetInstallFailure {
        error,
        state: KernelAhciPreactivationMappingSetInstallState::Retained(owner),
    }
}

fn launch_record(
    prepared: PreparedAhciNativeServiceTask,
) -> Result<AhciServiceLaunchRecord, AhciServiceLaunchRecordError> {
    let spec = prepared.launch().spec();
    AhciServiceLaunchRecord::new(
        spec.service().system_generation(),
        spec.service().provider_generation(),
        spec.attachment().attachment_generation(),
        spec.device(),
        spec.mapping(),
        spec.layout(),
        spec.data(),
        prepared.launch().cpu_mappings(),
    )
}

fn mapping_range(mapping: AhciAbarMapping) -> Option<(VirtAddr, PhysAddr, u64)> {
    if mapping.bytes == 0 || !mapping.bytes.is_multiple_of(PAGE_SIZE) {
        return None;
    }
    let virtual_start = VirtAddr::new(mapping.virtual_base).ok()?;
    let physical_start = PhysAddr::new(mapping.physical_base).ok()?;
    Some((virtual_start, physical_start, mapping.bytes / PAGE_SIZE))
}
