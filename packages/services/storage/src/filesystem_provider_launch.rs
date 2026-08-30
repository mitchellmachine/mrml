use crate::{
    FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES, FilesystemBlockAssociation,
    FilesystemBlockAssociationHandoff,
};
use mrml_kernel::{
    Capability, CapabilityError, CapabilitySpace, ComponentServiceLaunchAttachment,
    ComponentServiceReadTransferAttachment, ComponentServiceReadTransferCopyTaskBinding,
    ComponentServiceReadTransferMemoryRoot, IsolationPlacement, IsolationServiceSpec,
    MemoryMappingRevocationBackend, MemoryObjectBackingBackend, MemoryPoolTable,
    NativeComponentServiceCopyReadTransferActiveRetirementError,
    NativeComponentServiceCopyReadTransferError,
    NativeComponentServiceCopyReadTransferRetirementMappingError,
    NativeComponentServiceCopyReadTransferTask, NativeComponentServiceCopyReadTransferTeardown,
    NativeComponentServiceCopyReadTransferTeardownError, ObjectId, Rights, TaskId, TaskRuntime,
    TaskRuntimeError, TaskTermination, TaskTerminationDispatch, TaskTerminationDispatchError,
    prepare_native_component_service_task_from_copy_read_transfer_attachment,
    retire_current_native_component_service_copy_read_transfer_on_active_x86_64,
    retire_current_native_component_service_copy_read_transfer_with_mapping_revocation,
    teardown_native_component_service_copy_read_transfer,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemProviderLaunchReceipt<I> {
    association_generation: u64,
    filesystem_provider_generation: u64,
    block_provider_generation: u64,
    system_generation: u64,
    instance: I,
}

impl<I> FilesystemProviderLaunchReceipt<I> {
    pub const fn association_generation(&self) -> u64 {
        self.association_generation
    }

    pub const fn filesystem_provider_generation(&self) -> u64 {
        self.filesystem_provider_generation
    }

    pub const fn block_provider_generation(&self) -> u64 {
        self.block_provider_generation
    }

    pub const fn system_generation(&self) -> u64 {
        self.system_generation
    }

    pub const fn instance(&self) -> &I {
        &self.instance
    }

    pub fn into_instance(self) -> I {
        self.instance
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemProviderLaunchError<E> {
    Capability(CapabilityError),
    WrongEndpointAuthority,
    WrongTransferAuthority,
    TransferTooSmall,
    Backend(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilesystemProviderLaunchSpecError {
    WrongPlacement,
    WrongInterface,
    WrongInterfaceGeneration,
    WrongProviderGeneration,
    WrongSystemGeneration,
    WrongLaunchPolicy,
    WrongAssociationGeneration,
    WrongLaunchDataLength,
    WrongDependencyEndpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeFilesystemProviderLaunchSpec {
    service: IsolationServiceSpec,
    attachment: ComponentServiceLaunchAttachment,
}

impl NativeFilesystemProviderLaunchSpec {
    pub fn new(
        association: FilesystemBlockAssociation,
        service: IsolationServiceSpec,
        attachment: ComponentServiceLaunchAttachment,
        block_endpoint: Capability,
    ) -> Result<Self, NativeFilesystemProviderLaunchSpecError> {
        if service.placement() != IsolationPlacement::NativeService {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongPlacement);
        }
        if service.interface() != association.filesystem_binding.interface_object {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongInterface);
        }
        if service.interface_generation() != association.filesystem_binding.interface_generation {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongInterfaceGeneration);
        }
        if service.provider_generation() != association.filesystem_binding.provider_generation {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongProviderGeneration);
        }
        if service.system_generation() != association.filesystem_binding.system_generation {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongSystemGeneration);
        }
        if attachment.domain() != service.domain()
            || attachment.system_generation() != service.system_generation()
            || attachment.policy_generation() != service.policy_generation()
        {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongLaunchPolicy);
        }
        if attachment.association_generation() != association.association_generation {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongAssociationGeneration);
        }
        if attachment.launch_data_bytes() as usize != FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongLaunchDataLength);
        }
        if attachment.dependency_endpoint_object() != association.block_binding.endpoint_object
            || attachment.dependency_endpoint() != block_endpoint
        {
            return Err(NativeFilesystemProviderLaunchSpecError::WrongDependencyEndpoint);
        }
        Ok(Self {
            service,
            attachment,
        })
    }

    pub const fn service(self) -> IsolationServiceSpec {
        self.service
    }

    pub const fn attachment(self) -> ComponentServiceLaunchAttachment {
        self.attachment
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilesystemProviderLaunchPreflightError {
    Source(TaskRuntimeError),
    Target(TaskRuntimeError),
    Capability(CapabilityError),
    WrongEndpointAuthority,
    WrongTransferAuthority,
    TransferTooSmall,
    WrongPageTableRoot,
    Spec(NativeFilesystemProviderLaunchSpecError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilesystemProviderLaunchError {
    Preflight(NativeFilesystemProviderLaunchPreflightError),
    Rollback {
        preflight: NativeFilesystemProviderLaunchPreflightError,
        cleanup: TaskRuntimeError,
    },
    Construction(NativeComponentServiceCopyReadTransferError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilesystemProviderInstance {
    Active(NativeComponentServiceCopyReadTransferTask),
    Teardown(NativeComponentServiceCopyReadTransferTeardown),
}

impl NativeFilesystemProviderInstance {
    pub const fn active(self) -> Option<NativeComponentServiceCopyReadTransferTask> {
        match self {
            Self::Active(active) => Some(active),
            Self::Teardown(_) => None,
        }
    }

    pub const fn teardown(self) -> Option<NativeComponentServiceCopyReadTransferTeardown> {
        match self {
            Self::Active(_) => None,
            Self::Teardown(state) => Some(state),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilesystemProviderRetirementError<M> {
    TeardownProgressed,
    RetirementMapping(NativeComponentServiceCopyReadTransferRetirementMappingError<M>),
    Dispatch {
        termination: TaskTermination,
        error: TaskTerminationDispatchError,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub struct NativeFilesystemProviderRetirement {
    termination: TaskTermination,
    dispatch: TaskTerminationDispatch,
}

impl NativeFilesystemProviderRetirement {
    pub const fn termination(&self) -> TaskTermination {
        self.termination
    }

    pub const fn dispatch(&self) -> &TaskTerminationDispatch {
        &self.dispatch
    }

    pub fn into_parts(self) -> (TaskTermination, TaskTerminationDispatch) {
        (self.termination, self.dispatch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilesystemProviderActiveRetirementError {
    TeardownProgressed,
    Retirement(NativeComponentServiceCopyReadTransferActiveRetirementError),
    Dispatch {
        termination: TaskTermination,
        error: TaskTerminationDispatchError,
    },
}

pub fn retire_current_native_filesystem_provider<
    M: MemoryMappingRevocationBackend,
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    receipt: &mut FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    memory: &mut MemoryPoolTable<POOLS, OBJECTS, MAPPINGS>,
    mapping_backend: &mut M,
) -> Result<NativeFilesystemProviderRetirement, NativeFilesystemProviderRetirementError<M::Error>> {
    let active = match receipt.instance {
        NativeFilesystemProviderInstance::Active(active) => active,
        NativeFilesystemProviderInstance::Teardown(state)
            if state.is_pristine() && state.retired_context().is_none() =>
        {
            state.active()
        }
        NativeFilesystemProviderInstance::Teardown(_) => {
            return Err(NativeFilesystemProviderRetirementError::TeardownProgressed);
        }
    };
    match retire_current_native_component_service_copy_read_transfer_with_mapping_revocation(
        active,
        runtime,
        memory,
        mapping_backend,
    ) {
        Ok((termination, state)) => {
            receipt.instance = NativeFilesystemProviderInstance::Teardown(state);
            let dispatch = runtime
                .dispatch_after_termination(termination)
                .map_err(|error| NativeFilesystemProviderRetirementError::Dispatch {
                    termination,
                    error,
                })?;
            Ok(NativeFilesystemProviderRetirement {
                termination,
                dispatch,
            })
        }
        Err(error) => {
            if let Some(state) = error.state() {
                receipt.instance = NativeFilesystemProviderInstance::Teardown(state);
            }
            Err(NativeFilesystemProviderRetirementError::RetirementMapping(
                error,
            ))
        }
    }
}

/// Retires the current filesystem provider through its physically active x86-64
/// page-table root and retains exact teardown state in `receipt`.
///
/// # Safety
///
/// The safety contract of
/// [`retire_current_native_component_service_copy_read_transfer_on_active_x86_64`]
/// applies to the provider task and its local mapping.
pub unsafe fn retire_current_native_filesystem_provider_on_active_x86_64<
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    receipt: &mut FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    memory: &mut MemoryPoolTable<POOLS, OBJECTS, MAPPINGS>,
) -> Result<NativeFilesystemProviderRetirement, NativeFilesystemProviderActiveRetirementError> {
    let active = match receipt.instance {
        NativeFilesystemProviderInstance::Active(active) => active,
        NativeFilesystemProviderInstance::Teardown(state)
            if state.is_pristine() && state.retired_context().is_none() =>
        {
            state.active()
        }
        NativeFilesystemProviderInstance::Teardown(_) => {
            return Err(NativeFilesystemProviderActiveRetirementError::TeardownProgressed);
        }
    };
    match unsafe {
        retire_current_native_component_service_copy_read_transfer_on_active_x86_64(
            active, runtime, memory,
        )
    } {
        Ok((termination, state)) => {
            receipt.instance = NativeFilesystemProviderInstance::Teardown(state);
            let dispatch = runtime
                .dispatch_after_termination(termination)
                .map_err(
                    |error| NativeFilesystemProviderActiveRetirementError::Dispatch {
                        termination,
                        error,
                    },
                )?;
            Ok(NativeFilesystemProviderRetirement {
                termination,
                dispatch,
            })
        }
        Err(error) => {
            if let Some(state) = error.state() {
                receipt.instance = NativeFilesystemProviderInstance::Teardown(state);
            }
            Err(NativeFilesystemProviderActiveRetirementError::Retirement(
                error,
            ))
        }
    }
}

fn reject_native_filesystem_provider_preflight<const TASKS: usize, const CAPABILITIES: usize>(
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    source_task: TaskId,
    transfer: ComponentServiceReadTransferAttachment,
    preflight: NativeFilesystemProviderLaunchPreflightError,
) -> NativeFilesystemProviderLaunchError {
    match runtime.revoke_capability_pair(
        source_task,
        transfer.local_read(),
        transfer.provider_write(),
    ) {
        Ok(()) => NativeFilesystemProviderLaunchError::Preflight(preflight),
        Err(cleanup) => NativeFilesystemProviderLaunchError::Rollback { preflight, cleanup },
    }
}

#[allow(clippy::too_many_arguments)]
pub fn launch_native_filesystem_provider<const TASKS: usize, const CAPABILITIES: usize>(
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    source_task: TaskId,
    target_task: TaskId,
    block_endpoint: Capability,
    transfer: ComponentServiceReadTransferAttachment,
    association: FilesystemBlockAssociation,
    service: IsolationServiceSpec,
    launch_attachment: ComponentServiceLaunchAttachment,
    memory: ComponentServiceReadTransferMemoryRoot,
    binding: ComponentServiceReadTransferCopyTaskBinding,
    local_page_table_root: mrml_kernel::PhysAddr,
    supervisor_task_object: ObjectId,
) -> Result<
    FilesystemProviderLaunchReceipt<NativeFilesystemProviderInstance>,
    NativeFilesystemProviderLaunchError,
> {
    let target_context = match runtime.context(target_task) {
        Ok(context) => context,
        Err(error) => {
            return Err(reject_native_filesystem_provider_preflight(
                runtime,
                source_task,
                transfer,
                NativeFilesystemProviderLaunchPreflightError::Target(error),
            ));
        }
    };
    if target_context.page_table() != local_page_table_root {
        return Err(reject_native_filesystem_provider_preflight(
            runtime,
            source_task,
            transfer,
            NativeFilesystemProviderLaunchPreflightError::WrongPageTableRoot,
        ));
    }
    let preflight = runtime
        .capabilities(source_task)
        .map_err(NativeFilesystemProviderLaunchPreflightError::Source)
        .and_then(|capabilities| {
            let endpoint_object = capabilities
                .authorize_exact(block_endpoint, Rights::SIGNAL.union(Rights::DELEGATE))
                .map_err(NativeFilesystemProviderLaunchPreflightError::Capability)?;
            if endpoint_object != association.block_binding.endpoint_object {
                return Err(NativeFilesystemProviderLaunchPreflightError::WrongEndpointAuthority);
            }
            let local_object = capabilities
                .authorize_exact(
                    transfer.local_read(),
                    Rights::MAP.union(Rights::READ).union(Rights::DELEGATE),
                )
                .map_err(NativeFilesystemProviderLaunchPreflightError::Capability)?;
            let write_object = capabilities
                .authorize_exact(
                    transfer.provider_write(),
                    Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE),
                )
                .map_err(NativeFilesystemProviderLaunchPreflightError::Capability)?;
            if local_object != transfer.shared_object() || write_object != transfer.shared_object()
            {
                return Err(NativeFilesystemProviderLaunchPreflightError::WrongTransferAuthority);
            }
            if transfer.shared_bytes() < association.logical_block_bytes {
                return Err(NativeFilesystemProviderLaunchPreflightError::TransferTooSmall);
            }
            NativeFilesystemProviderLaunchSpec::new(
                association,
                service,
                launch_attachment,
                block_endpoint,
            )
            .map_err(NativeFilesystemProviderLaunchPreflightError::Spec)
        });
    if let Err(preflight) = preflight {
        return Err(reject_native_filesystem_provider_preflight(
            runtime,
            source_task,
            transfer,
            preflight,
        ));
    }
    let active = prepare_native_component_service_task_from_copy_read_transfer_attachment(
        runtime,
        source_task,
        target_task,
        service,
        launch_attachment,
        transfer,
        memory,
        binding,
        local_page_table_root,
        association.filesystem_binding.endpoint_object,
        supervisor_task_object,
        association.filesystem_binding.module_object,
    )
    .map_err(NativeFilesystemProviderLaunchError::Construction)?;
    Ok(receipt(
        association.handoff(),
        NativeFilesystemProviderInstance::Active(active),
    ))
}

pub struct NativeFilesystemProviderTeardownBackend<
    'a,
    F,
    B,
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
> {
    runtime: &'a mut TaskRuntime<TASKS, CAPABILITIES>,
    memory: &'a mut MemoryPoolTable<POOLS, OBJECTS, MAPPINGS>,
    local_backend: &'a mut F,
    backing_backend: &'a mut B,
}

impl<
    'a,
    F,
    B,
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
> NativeFilesystemProviderTeardownBackend<'a, F, B, POOLS, OBJECTS, MAPPINGS, TASKS, CAPABILITIES>
{
    pub const fn new(
        runtime: &'a mut TaskRuntime<TASKS, CAPABILITIES>,
        memory: &'a mut MemoryPoolTable<POOLS, OBJECTS, MAPPINGS>,
        local_backend: &'a mut F,
        backing_backend: &'a mut B,
    ) -> Self {
        Self {
            runtime,
            memory,
            local_backend,
            backing_backend,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemProviderTeardownError<I, E> {
    receipt: FilesystemProviderLaunchReceipt<I>,
    error: E,
}

impl<I, E> FilesystemProviderTeardownError<I, E> {
    pub const fn receipt(&self) -> &FilesystemProviderLaunchReceipt<I> {
        &self.receipt
    }

    pub const fn error(&self) -> &E {
        &self.error
    }

    pub fn into_parts(self) -> (FilesystemProviderLaunchReceipt<I>, E) {
        (self.receipt, self.error)
    }
}

/// Placement-specific construction boundary for an isolated filesystem
/// provider with one exact block dependency.
///
/// # Safety
///
/// Implementations must create a fresh provider domain, project `handoff` as
/// read-only launch data, attenuate `block_endpoint` to exact SIGNAL, project
/// the attachment's local read and delegable provider-write handles, bind all
/// projections to that same domain generation, and publish no endpoint or ready
/// signal unless every projection and provider construction succeeds. Failure
/// must revoke and erase every partial projection and domain. A successful
/// return must be the exact live instance or cleanup owner for those resources;
/// the caller retains it in the launch receipt until supervised teardown.
pub unsafe trait FilesystemProviderLaunchBackend {
    type Error;
    type Instance;

    fn launch(
        &mut self,
        association: FilesystemBlockAssociation,
        handoff: &[u8; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
        block_endpoint: Capability,
        transfer: ComponentServiceReadTransferAttachment,
    ) -> Result<Self::Instance, Self::Error>;
}

/// Placement-specific teardown boundary for a successfully launched provider.
///
/// # Safety
///
/// Implementations must advance `instance` only after each cleanup stage is
/// confirmed. On failure it must retain the exact live resources and progress
/// needed for a safe retry. Success means the complete provider domain and all
/// projections owned by the instance are retired.
pub unsafe trait FilesystemProviderTeardownBackend {
    type Instance;
    type TeardownError;

    fn teardown(&mut self, instance: &mut Self::Instance) -> Result<(), Self::TeardownError>;
}

pub fn launch_filesystem_provider<B: FilesystemProviderLaunchBackend, const CAPABILITIES: usize>(
    capabilities: &CapabilitySpace<CAPABILITIES>,
    block_endpoint_capability: Capability,
    transfer: ComponentServiceReadTransferAttachment,
    association: FilesystemBlockAssociation,
    backend: &mut B,
) -> Result<FilesystemProviderLaunchReceipt<B::Instance>, FilesystemProviderLaunchError<B::Error>> {
    let endpoint_object = capabilities
        .authorize_exact(
            block_endpoint_capability,
            Rights::SIGNAL.union(Rights::DELEGATE),
        )
        .map_err(FilesystemProviderLaunchError::Capability)?;
    if endpoint_object != association.block_binding.endpoint_object {
        return Err(FilesystemProviderLaunchError::WrongEndpointAuthority);
    }
    let local_object = capabilities
        .authorize_exact(
            transfer.local_read(),
            Rights::MAP.union(Rights::READ).union(Rights::DELEGATE),
        )
        .map_err(FilesystemProviderLaunchError::Capability)?;
    let write_object = capabilities
        .authorize_exact(
            transfer.provider_write(),
            Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE),
        )
        .map_err(FilesystemProviderLaunchError::Capability)?;
    if local_object != transfer.shared_object() || write_object != transfer.shared_object() {
        return Err(FilesystemProviderLaunchError::WrongTransferAuthority);
    }
    if transfer.shared_bytes() < association.logical_block_bytes {
        return Err(FilesystemProviderLaunchError::TransferTooSmall);
    }
    let handoff = association.handoff();
    let mut encoded = handoff.encode();
    let launched = backend
        .launch(association, &encoded, block_endpoint_capability, transfer)
        .map_err(FilesystemProviderLaunchError::Backend);
    encoded.fill(0);
    Ok(receipt(handoff, launched?))
}

fn receipt<I>(
    handoff: FilesystemBlockAssociationHandoff,
    instance: I,
) -> FilesystemProviderLaunchReceipt<I> {
    FilesystemProviderLaunchReceipt {
        association_generation: handoff.association_generation(),
        filesystem_provider_generation: handoff.filesystem_provider_generation(),
        block_provider_generation: handoff.block_provider_generation(),
        system_generation: handoff.system_generation(),
        instance,
    }
}

pub fn teardown_filesystem_provider<B: FilesystemProviderTeardownBackend>(
    mut receipt: FilesystemProviderLaunchReceipt<B::Instance>,
    backend: &mut B,
) -> Result<(), FilesystemProviderTeardownError<B::Instance, B::TeardownError>> {
    match backend.teardown(&mut receipt.instance) {
        Ok(()) => Ok(()),
        Err(error) => Err(FilesystemProviderTeardownError { receipt, error }),
    }
}

// SAFETY: the exact kernel retry state replaces the active instance before any
// backend error is returned. A caller therefore retries from confirmed progress
// and cannot repeat a completed unmap, scrub, or object release.
unsafe impl<
    'a,
    F: MemoryMappingRevocationBackend,
    B: MemoryObjectBackingBackend,
    const POOLS: usize,
    const OBJECTS: usize,
    const MAPPINGS: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
> FilesystemProviderTeardownBackend
    for NativeFilesystemProviderTeardownBackend<
        'a,
        F,
        B,
        POOLS,
        OBJECTS,
        MAPPINGS,
        TASKS,
        CAPABILITIES,
    >
{
    type Instance = NativeFilesystemProviderInstance;
    type TeardownError = NativeComponentServiceCopyReadTransferTeardownError<F::Error, B::Error>;

    fn teardown(&mut self, instance: &mut Self::Instance) -> Result<(), Self::TeardownError> {
        let state = match *instance {
            NativeFilesystemProviderInstance::Active(active) => {
                NativeComponentServiceCopyReadTransferTeardown::new(active)
            }
            NativeFilesystemProviderInstance::Teardown(state) => state,
        };
        match teardown_native_component_service_copy_read_transfer(
            state,
            self.runtime,
            self.memory,
            self.local_backend,
            self.backing_backend,
        ) {
            Ok(released_pages) => {
                debug_assert_eq!(released_pages, 1);
                Ok(())
            }
            Err(error) => {
                *instance = NativeFilesystemProviderInstance::Teardown(error.state());
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StorageModuleBinding, StorageModuleClass};
    use mrml_interface_storage_block_provider_v1::OpaqueHandle as BlockOpaqueHandle;
    use mrml_interface_storage_filesystem_v3::OpaqueHandle as FilesystemOpaqueHandle;
    use mrml_kernel::ObjectId;
    use mrml_kernel::arch::x86_64::{
        InactivePageTableMappingBackend, Mapping, PagePermissions, PageTableBuilder,
        PreallocatedPageTableStore, UserContext, VirtAddr,
    };
    use mrml_kernel::{
        IsolationServiceSpec, MemoryBackingBackendRequest, MemoryPhysicalBacking, MemoryPoolTable,
        Priority, ScheduleOutcome, TotalMicrovmClass,
    };

    #[test]
    fn retirement_transfers_exact_termination_with_opaque_dispatch() {
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let exiting = runtime
            .create(
                Priority::NORMAL,
                UserContext::new(
                    mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
                    0x40_0000,
                    0x7000_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let successor_context = UserContext::new(
            mrml_kernel::PhysAddr::new(0x30_0000).unwrap(),
            0x50_0000,
            0x7100_0000,
        )
        .unwrap();
        let successor = runtime.create(Priority::NORMAL, successor_context).unwrap();
        assert!(matches!(
            runtime.start(),
            ScheduleOutcome::Switch { to, .. } if to == exiting
        ));
        let termination = runtime.terminate_current().unwrap();
        let dispatch = runtime.dispatch_after_termination(termination).unwrap();
        let retirement = NativeFilesystemProviderRetirement {
            termination,
            dispatch,
        };

        let (retained_termination, retained_dispatch) = retirement.into_parts();
        assert_eq!(retained_termination.task, exiting);
        assert_eq!(
            retained_termination.next,
            ScheduleOutcome::Switch {
                from: Some(exiting),
                to: successor,
            }
        );
        assert_eq!(
            retained_dispatch.user(),
            Some((successor, successor_context))
        );
    }

    #[derive(Default)]
    struct NativeBackingBackend {
        claimed: Option<MemoryBackingBackendRequest>,
    }

    unsafe impl MemoryObjectBackingBackend for NativeBackingBackend {
        type Error = &'static str;

        fn claim_zeroed(
            &mut self,
            request: MemoryBackingBackendRequest,
        ) -> Result<(), Self::Error> {
            if self.claimed.replace(request).is_some() {
                return Err("occupied");
            }
            Ok(())
        }

        fn release_scrubbed(
            &mut self,
            request: MemoryBackingBackendRequest,
        ) -> Result<(), Self::Error> {
            if self.claimed != Some(request) {
                return Err("substitution");
            }
            self.claimed = None;
            Ok(())
        }
    }

    #[repr(C, align(4096))]
    struct PageTableArena([u64; 512 * 5]);

    struct RejectingRevoker;

    // SAFETY: this backend never mutates native mapping state and never reports
    // successful withdrawal.
    unsafe impl MemoryMappingRevocationBackend for RejectingRevoker {
        type Error = &'static str;

        fn revoke(
            &mut self,
            _request: mrml_kernel::MemoryMappingBackendRequest,
        ) -> Result<(), Self::Error> {
            Err("revoke")
        }
    }

    struct Backend {
        fail: bool,
        fail_teardown: bool,
        calls: usize,
        teardown_calls: usize,
        observed: [u8; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
    }

    unsafe impl FilesystemProviderTeardownBackend for Backend {
        type Instance = u64;
        type TeardownError = ();

        fn teardown(&mut self, instance: &mut Self::Instance) -> Result<(), Self::TeardownError> {
            self.teardown_calls += 1;
            *instance += 1;
            if self.fail_teardown { Err(()) } else { Ok(()) }
        }
    }

    unsafe impl FilesystemProviderLaunchBackend for Backend {
        type Error = ();
        type Instance = u64;

        fn launch(
            &mut self,
            association: FilesystemBlockAssociation,
            handoff: &[u8; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
            block_endpoint: Capability,
            transfer: ComponentServiceReadTransferAttachment,
        ) -> Result<Self::Instance, Self::Error> {
            assert_eq!(association.association_generation, 12);
            assert_ne!(block_endpoint.token(), 0);
            assert_eq!(transfer.shared_bytes(), 4096);
            self.calls += 1;
            self.observed = *handoff;
            if self.fail { Err(()) } else { Ok(0xfeed) }
        }
    }

    fn association() -> FilesystemBlockAssociation {
        FilesystemBlockAssociation {
            filesystem_binding: StorageModuleBinding {
                class: StorageModuleClass::Filesystem,
                module_object: ObjectId(41),
                interface_object: ObjectId(42),
                provider_object: ObjectId(43),
                endpoint_object: ObjectId(44),
                interface_generation: 3,
                provider_generation: 5,
                system_generation: 9,
                binding_generation: 3,
            },
            block_binding: StorageModuleBinding {
                class: StorageModuleClass::BlockProvider,
                module_object: ObjectId(11),
                interface_object: ObjectId(10),
                provider_object: ObjectId(20),
                endpoint_object: ObjectId(21),
                interface_generation: 1,
                provider_generation: 7,
                system_generation: 9,
                binding_generation: 4,
            },
            volume: FilesystemOpaqueHandle::new(2, 6).unwrap(),
            block_session: BlockOpaqueHandle::new(8, 10).unwrap(),
            logical_block_bytes: 4096,
            association_generation: 12,
        }
    }

    fn provider_task() -> mrml_kernel::TaskId {
        let mut runtime = mrml_kernel::TaskRuntime::<1, 1>::new(100, 1).unwrap();
        runtime
            .create(
                mrml_kernel::Priority::NORMAL,
                UserContext::new(
                    mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
                    0x40_0000,
                    0x7000_0000,
                )
                .unwrap(),
            )
            .unwrap()
    }

    fn transfer_attachment<const C: usize>(
        capabilities: &mut CapabilitySpace<C>,
    ) -> ComponentServiceReadTransferAttachment {
        let local_read = capabilities
            .insert(
                ObjectId(0x80),
                Rights::MAP.union(Rights::READ).union(Rights::DELEGATE),
            )
            .unwrap();
        let provider_write = capabilities
            .insert(
                ObjectId(0x80),
                Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE),
            )
            .unwrap();
        ComponentServiceReadTransferAttachment::new(
            provider_task(),
            ObjectId(0x80),
            6,
            4096,
            local_read,
            provider_write,
            capabilities,
        )
        .unwrap()
    }

    fn native_launch_spec(
        association_generation: u64,
        launch_data_bytes: u32,
    ) -> (
        CapabilitySpace<2>,
        Capability,
        IsolationServiceSpec,
        ComponentServiceLaunchAttachment,
    ) {
        let association = association();
        let service = IsolationServiceSpec::new(
            association.filesystem_binding.provider_object,
            association.filesystem_binding.interface_object,
            association.filesystem_binding.interface_generation,
            association.filesystem_binding.provider_generation,
            association.filesystem_binding.system_generation,
            2,
            TotalMicrovmClass::MicrovmEligible,
            IsolationPlacement::NativeService,
        )
        .unwrap();
        let mut capabilities = CapabilitySpace::<2>::new();
        let data = capabilities
            .insert(ObjectId(0x90), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let endpoint = capabilities
            .insert(
                association.block_binding.endpoint_object,
                Rights::SIGNAL.union(Rights::DELEGATE),
            )
            .unwrap();
        let attachment = ComponentServiceLaunchAttachment::new(
            service,
            association_generation,
            ObjectId(0x90),
            3,
            launch_data_bytes,
            data,
            association.block_binding.endpoint_object,
            association.block_binding.binding_generation,
            endpoint,
            &capabilities,
        )
        .unwrap();
        (capabilities, endpoint, service, attachment)
    }

    #[test]
    fn exact_endpoint_launches_with_canonical_handoff_and_returns_bound_receipt() {
        let association = association();
        let mut capabilities = CapabilitySpace::<3>::new();
        let endpoint = capabilities
            .insert(
                association.block_binding.endpoint_object,
                Rights::SIGNAL.union(Rights::DELEGATE),
            )
            .unwrap();
        let transfer = transfer_attachment(&mut capabilities);
        let mut backend = Backend {
            fail: false,
            fail_teardown: false,
            calls: 0,
            teardown_calls: 0,
            observed: [0; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
        };
        let receipt = launch_filesystem_provider(
            &capabilities,
            endpoint,
            transfer,
            association,
            &mut backend,
        )
        .unwrap();
        assert_eq!(backend.calls, 1);
        assert_eq!(
            FilesystemBlockAssociationHandoff::decode(&backend.observed),
            Ok(association.handoff())
        );
        assert_eq!(receipt.association_generation(), 12);
        assert_eq!(receipt.filesystem_provider_generation(), 5);
        assert_eq!(receipt.block_provider_generation(), 7);
        assert_eq!(receipt.system_generation(), 9);
        assert_eq!(*receipt.instance(), 0xfeed);
        assert_eq!(receipt.into_instance(), 0xfeed);
    }

    #[test]
    fn native_launch_spec_exact_matches_service_handoff_and_endpoint() {
        let association = association();
        let (_capabilities, endpoint, service, attachment) =
            native_launch_spec(association.association_generation, 144);
        let plan =
            NativeFilesystemProviderLaunchSpec::new(association, service, attachment, endpoint)
                .unwrap();
        assert_eq!(plan.service(), service);
        assert_eq!(plan.attachment(), attachment);

        let mut wrong_provider = association;
        wrong_provider.filesystem_binding.provider_generation += 1;
        assert_eq!(
            NativeFilesystemProviderLaunchSpec::new(wrong_provider, service, attachment, endpoint,),
            Err(NativeFilesystemProviderLaunchSpecError::WrongProviderGeneration)
        );
        let (_capabilities, endpoint, service, wrong_association) =
            native_launch_spec(association.association_generation + 1, 144);
        assert_eq!(
            NativeFilesystemProviderLaunchSpec::new(
                association,
                service,
                wrong_association,
                endpoint,
            ),
            Err(NativeFilesystemProviderLaunchSpecError::WrongAssociationGeneration)
        );
        let (_capabilities, endpoint, service, wrong_length) =
            native_launch_spec(association.association_generation, 143);
        assert_eq!(
            NativeFilesystemProviderLaunchSpec::new(association, service, wrong_length, endpoint,),
            Err(NativeFilesystemProviderLaunchSpecError::WrongLaunchDataLength)
        );
    }

    #[test]
    fn native_preflight_rejection_revokes_both_consumed_transfer_roots() {
        let mut runtime = TaskRuntime::<1, 2>::new(100, 1).unwrap();
        let source = runtime
            .create(
                mrml_kernel::Priority::NORMAL,
                UserContext::new(
                    mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
                    0x40_0000,
                    0x7000_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let local_read = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(
                ObjectId(0xa0),
                Rights::MAP.union(Rights::READ).union(Rights::DELEGATE),
            )
            .unwrap();
        let provider_write = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(
                ObjectId(0xa0),
                Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE),
            )
            .unwrap();
        let transfer = ComponentServiceReadTransferAttachment::new(
            provider_task(),
            ObjectId(0xa0),
            1,
            4096,
            local_read,
            provider_write,
            runtime.capabilities(source).unwrap(),
        )
        .unwrap();
        assert_eq!(
            reject_native_filesystem_provider_preflight(
                &mut runtime,
                source,
                transfer,
                NativeFilesystemProviderLaunchPreflightError::WrongTransferAuthority,
            ),
            NativeFilesystemProviderLaunchError::Preflight(
                NativeFilesystemProviderLaunchPreflightError::WrongTransferAuthority
            )
        );
        assert_eq!(
            runtime
                .capabilities(source)
                .unwrap()
                .authorize(local_read, Rights::READ),
            Err(CapabilityError::Invalid)
        );
        assert_eq!(
            runtime
                .capabilities(source)
                .unwrap()
                .authorize(provider_write, Rights::WRITE),
            Err(CapabilityError::Invalid)
        );
    }

    #[test]
    fn native_launch_and_teardown_retain_one_exact_copy_task_lifecycle() {
        let association = association();
        let mut page_tables = PageTableArena([0; 512 * 5]);
        let page_table_base =
            mrml_kernel::PhysAddr::new(page_tables.0.as_mut_ptr() as u64).unwrap();
        let mut runtime = TaskRuntime::<3, 8>::new(1_000, 1).unwrap();
        let context = |physical, page_table, stack| {
            UserContext::new(
                mrml_kernel::PhysAddr::new(physical).unwrap(),
                page_table,
                stack,
            )
            .unwrap()
        };
        let source = runtime
            .create(
                mrml_kernel::Priority::NORMAL,
                context(0x20_0000, 0x40_0000, 0x7000_0000),
            )
            .unwrap();
        let target = runtime
            .create(
                mrml_kernel::Priority::NORMAL,
                context(page_table_base.get(), 0x50_0000, 0x7100_0000),
            )
            .unwrap();
        let provider = runtime
            .create(
                mrml_kernel::Priority::NORMAL,
                context(0x40_0000, 0x60_0000, 0x7200_0000),
            )
            .unwrap();
        let mut memory = MemoryPoolTable::<1, 1, 1>::new(0x2a).unwrap();
        let pool_rights = Rights::ALLOCATE
            .union(Rights::CONTROL)
            .union(Rights::INSPECT);
        let (pool, pool_capability) = memory
            .create_root(
                1,
                1,
                0,
                pool_rights,
                runtime.capabilities_mut(source).unwrap(),
            )
            .unwrap();
        let root = mrml_kernel::reserve_component_service_read_transfer_memory(
            &mut memory,
            pool,
            pool_capability,
            &mut runtime,
            source,
        )
        .unwrap();
        let mut backing = NativeBackingBackend::default();
        mrml_kernel::bind_component_service_read_transfer_backing(
            &mut memory,
            root,
            MemoryPhysicalBacking::new(mrml_kernel::PhysAddr::new(0x80_0000).unwrap(), 1).unwrap(),
            &runtime,
            source,
            &mut backing,
        )
        .unwrap();
        let local_target = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0x7100), Rights::MAP.union(Rights::CONTROL))
            .unwrap();
        // SAFETY: the aligned test arena remains exclusively owned and
        // unreachable by every CPU for the complete adapter lifetime.
        let store = unsafe { PreallocatedPageTableStore::new(page_table_base, 5) }.unwrap();
        let builder = PageTableBuilder::new(store).unwrap();
        // SAFETY: the builder is exclusively owned and never activated.
        let mut local_mapping =
            unsafe { InactivePageTableMappingBackend::new(builder, ObjectId(0x7100)) };
        let mapping = mrml_kernel::install_component_service_read_transfer_local_mapping(
            &mut memory,
            root,
            local_target,
            0x300,
            &mut local_mapping,
            &runtime,
            source,
        )
        .unwrap();
        let binding = mrml_kernel::bind_component_service_read_transfer_copy_tasks(
            mapping, target, provider, &runtime,
        )
        .unwrap();
        let service = IsolationServiceSpec::new(
            association.filesystem_binding.provider_object,
            association.filesystem_binding.interface_object,
            association.filesystem_binding.interface_generation,
            association.filesystem_binding.provider_generation,
            association.filesystem_binding.system_generation,
            2,
            TotalMicrovmClass::MicrovmEligible,
            IsolationPlacement::NativeService,
        )
        .unwrap();
        let launch_data = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0x90), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let endpoint = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(
                association.block_binding.endpoint_object,
                Rights::SIGNAL.union(Rights::DELEGATE),
            )
            .unwrap();
        let launch_attachment = ComponentServiceLaunchAttachment::new(
            service,
            association.association_generation,
            ObjectId(0x90),
            3,
            FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES as u32,
            launch_data,
            association.block_binding.endpoint_object,
            association.block_binding.binding_generation,
            endpoint,
            runtime.capabilities(source).unwrap(),
        )
        .unwrap();
        let transfer = mrml_kernel::prepare_component_service_read_transfer_attachment(
            &mut runtime,
            source,
            provider,
            root.shared_object(),
            root.generation(),
            root.bytes(),
            root.root(),
        )
        .unwrap();
        let wrong_root =
            mrml_kernel::PhysAddr::new(page_table_base.get() + mrml_kernel::PAGE_SIZE).unwrap();
        assert_eq!(
            launch_native_filesystem_provider(
                &mut runtime,
                source,
                target,
                endpoint,
                transfer,
                association,
                service,
                launch_attachment,
                root,
                binding,
                wrong_root,
                ObjectId(0x91),
            ),
            Err(NativeFilesystemProviderLaunchError::Preflight(
                NativeFilesystemProviderLaunchPreflightError::WrongPageTableRoot
            ))
        );
        let transfer = mrml_kernel::prepare_component_service_read_transfer_attachment(
            &mut runtime,
            source,
            provider,
            root.shared_object(),
            root.generation(),
            root.bytes(),
            root.root(),
        )
        .unwrap();
        let mut receipt = launch_native_filesystem_provider(
            &mut runtime,
            source,
            target,
            endpoint,
            transfer,
            association,
            service,
            launch_attachment,
            root,
            binding,
            local_mapping.root(),
            ObjectId(0x91),
        )
        .unwrap();
        assert_eq!(
            receipt.association_generation(),
            association.association_generation
        );
        assert_eq!(
            receipt.instance().active().unwrap().construction().task(),
            target
        );
        assert!(matches!(
            unsafe {
                retire_current_native_filesystem_provider_on_active_x86_64(
                    &mut receipt,
                    &mut runtime,
                    &mut memory,
                )
            },
            Err(NativeFilesystemProviderActiveRetirementError::Retirement(
                NativeComponentServiceCopyReadTransferActiveRetirementError::Retirement(
                    mrml_kernel::NativeComponentServiceCopyReadTransferRetirementError::NotCurrent
                )
            ))
        ));
        assert!(receipt.instance().active().is_some());
        let failure = {
            let mut teardown = NativeFilesystemProviderTeardownBackend::new(
                &mut runtime,
                &mut memory,
                &mut local_mapping,
                &mut backing,
            );
            teardown_filesystem_provider(receipt, &mut teardown).unwrap_err()
        };
        assert!(matches!(
            failure.error(),
            NativeComponentServiceCopyReadTransferTeardownError::TaskStillLive {
                task,
                ..
            } if *task == target
        ));
        assert!(failure.receipt().instance().teardown().is_some());
        let (mut receipt, _) = failure.into_parts();
        runtime.start();
        runtime.yield_current().unwrap();
        assert_eq!(runtime.current(), Some(target));
        let mut rejecting = RejectingRevoker;
        assert!(matches!(
            retire_current_native_filesystem_provider(
                &mut receipt,
                &mut runtime,
                &mut memory,
                &mut rejecting,
            ),
            Err(NativeFilesystemProviderRetirementError::RetirementMapping(
                NativeComponentServiceCopyReadTransferRetirementMappingError::LocalMapping {
                    termination,
                    error: mrml_kernel::MemoryMappingOperationError::Backend("revoke"),
                    ..
                }
            )) if termination.task == target
        ));
        let retained = receipt.instance().teardown().unwrap();
        assert_eq!(
            retained.retired_context().unwrap().page_table(),
            local_mapping.root()
        );
        assert!(!retained.mapping_removed());
        let mut teardown = NativeFilesystemProviderTeardownBackend::new(
            &mut runtime,
            &mut memory,
            &mut local_mapping,
            &mut backing,
        );
        teardown_filesystem_provider(receipt, &mut teardown).unwrap();
        let expected = Mapping::new(
            VirtAddr::new(0x300 * mrml_kernel::PAGE_SIZE).unwrap(),
            mrml_kernel::PhysAddr::new(0x80_0000).unwrap(),
            1,
            PagePermissions::USER_READ,
        )
        .unwrap();
        assert_eq!(
            local_mapping
                .into_builder()
                .unwrap()
                .verify_unmapped(expected),
            Ok(())
        );
        assert!(backing.claimed.is_none());
        assert_eq!(
            memory
                .usage(pool, pool_capability, runtime.capabilities(source).unwrap())
                .unwrap()
                .object_pages(),
            0
        );
    }

    #[test]
    fn substituted_endpoint_and_backend_failure_never_become_success_receipts() {
        let association = association();
        let mut capabilities = CapabilitySpace::<3>::new();
        let substituted = capabilities
            .insert(ObjectId(22), Rights::SIGNAL.union(Rights::DELEGATE))
            .unwrap();
        let transfer = transfer_attachment(&mut capabilities);
        let mut backend = Backend {
            fail: false,
            fail_teardown: false,
            calls: 0,
            teardown_calls: 0,
            observed: [0; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
        };
        assert_eq!(
            launch_filesystem_provider(
                &capabilities,
                substituted,
                transfer,
                association,
                &mut backend,
            ),
            Err(FilesystemProviderLaunchError::WrongEndpointAuthority)
        );
        assert_eq!(backend.calls, 0);

        let mut oversized = association;
        oversized.logical_block_bytes = 8192;
        let mut capabilities = CapabilitySpace::<3>::new();
        let endpoint = capabilities
            .insert(
                oversized.block_binding.endpoint_object,
                Rights::SIGNAL.union(Rights::DELEGATE),
            )
            .unwrap();
        let transfer = transfer_attachment(&mut capabilities);
        assert_eq!(
            launch_filesystem_provider(&capabilities, endpoint, transfer, oversized, &mut backend,),
            Err(FilesystemProviderLaunchError::TransferTooSmall)
        );
        assert_eq!(backend.calls, 0);

        let mut capabilities = CapabilitySpace::<3>::new();
        let endpoint = capabilities
            .insert(
                association.block_binding.endpoint_object,
                Rights::SIGNAL.union(Rights::DELEGATE),
            )
            .unwrap();
        let transfer = transfer_attachment(&mut capabilities);
        backend.fail = true;
        assert_eq!(
            launch_filesystem_provider(
                &capabilities,
                endpoint,
                transfer,
                association,
                &mut backend,
            ),
            Err(FilesystemProviderLaunchError::Backend(()))
        );
        assert_eq!(backend.calls, 1);
    }

    #[test]
    fn teardown_failure_returns_exact_progressed_receipt_for_retry() {
        let mut backend = Backend {
            fail: false,
            fail_teardown: true,
            calls: 0,
            teardown_calls: 0,
            observed: [0; FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES],
        };
        let receipt = receipt(association().handoff(), 40);
        let failure = teardown_filesystem_provider(receipt, &mut backend).unwrap_err();
        assert_eq!(backend.teardown_calls, 1);
        assert_eq!(*failure.receipt().instance(), 41);
        assert_eq!(failure.receipt().association_generation(), 12);
        assert_eq!(failure.error(), &());
        let (receipt, ()) = failure.into_parts();
        backend.fail_teardown = false;
        assert_eq!(teardown_filesystem_provider(receipt, &mut backend), Ok(()));
        assert_eq!(backend.teardown_calls, 2);
    }
}
