//! Capability-checked preactivation ownership of one AHCI ABAR page-table map.

use crate::{
    AhciAbarDescriptor, AhciAbarMapping, AhciAbarMappingBackend, AhciAbarMappingError,
    AhciAbarRemovalBackend, AhciAbarRemovalError, InstalledAhciAbarMapping,
    PreparedAhciNativeServiceTask, install_ahci_service_abar, remove_ahci_service_abar,
};
use mrml_kernel::arch::x86_64::{
    InactivePageTableMappingBackend, Mapping, PagePermissions, PageTableStore, VirtAddr,
};
use mrml_kernel::{
    Capability, CapabilityError, CapabilitySpace, NativeDeviceServiceActivationError, ObjectId,
    PAGE_SIZE, PhysAddr, Rights, TaskId, TaskRuntime,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelAhciAbarPreactivationError {
    Activation(NativeDeviceServiceActivationError),
    WrongRoot,
    WrongTarget,
    AbarGenerationOrGeometryMismatch,
    DescriptorIdentityMismatch,
    InvalidMapping,
    ControlCapability(CapabilityError),
    WrongControlObject,
    Mapping(AhciAbarMappingError),
}

/// Retains an installed ABAR, its capabilities, and the inactive hierarchy
/// until exact rollback succeeds.
///
/// This owner is deliberately not a mapped-task or activation proof. It cannot
/// create [`crate::MappedAhciNativeServiceTask`] and does not implement the
/// generic mapping backend traits. A later transition must bind the CPU
/// mappings, consume or revalidate the exact hierarchy, and create the active
/// lifetime owner.
pub struct KernelAhciAbarPreactivationOwner<
    'a,
    S,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> {
    prepared: PreparedAhciNativeServiceTask,
    runtime: &'a TaskRuntime<TASKS, TASK_CAPABILITIES>,
    tables: &'a mut InactivePageTableMappingBackend<S>,
    authorities: &'a CapabilitySpace<AUTHORITIES>,
    control: Capability,
    installed: InstalledAhciAbarMapping,
    expected: AhciAbarMapping,
    target: ObjectId,
}

pub struct KernelAhciAbarRollbackFailure<
    'a,
    S,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> {
    error: AhciAbarRemovalError,
    owner: KernelAhciAbarPreactivationOwner<'a, S, TASKS, TASK_CAPABILITIES, AUTHORITIES>,
}

impl<'a, S, const TASKS: usize, const TASK_CAPABILITIES: usize, const AUTHORITIES: usize>
    KernelAhciAbarRollbackFailure<'a, S, TASKS, TASK_CAPABILITIES, AUTHORITIES>
{
    pub const fn error(&self) -> AhciAbarRemovalError {
        self.error
    }

    pub const fn owner(
        &self,
    ) -> &KernelAhciAbarPreactivationOwner<'a, S, TASKS, TASK_CAPABILITIES, AUTHORITIES> {
        &self.owner
    }

    pub fn into_owner(
        self,
    ) -> KernelAhciAbarPreactivationOwner<'a, S, TASKS, TASK_CAPABILITIES, AUTHORITIES> {
        self.owner
    }
}

impl<
    'a,
    S: PageTableStore,
    const TASKS: usize,
    const TASK_CAPABILITIES: usize,
    const AUTHORITIES: usize,
> KernelAhciAbarPreactivationOwner<'a, S, TASKS, TASK_CAPABILITIES, AUTHORITIES>
{
    /// Authorizes and installs the launch-bound ABAR before task activation.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own the complete hierarchy for this exact
    /// construction-pending native task. No other task, VM, CPU, or resumable
    /// context may reference the root. IA32_PAT index 3 must be UC on every CPU
    /// that could later execute the task, and every cacheable physical alias
    /// must remain excluded for the complete installed lifetime. The caller
    /// must also establish that the descriptor identity bound into the launch
    /// came from the trusted PCI/device-object correlation path. This owner
    /// exact-matches that retained identity plus generation and geometry. After this
    /// borrowed owner is dropped or transferred, the exact root and leaves must
    /// remain inactive and unchanged until a later owner consumes and
    /// revalidates them. This operation is not an activation seal.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn install(
        prepared: PreparedAhciNativeServiceTask,
        descriptor: AhciAbarDescriptor,
        mapping_capability: Capability,
        control: Capability,
        authorities: &'a CapabilitySpace<AUTHORITIES>,
        runtime: &'a TaskRuntime<TASKS, TASK_CAPABILITIES>,
        tables: &'a mut InactivePageTableMappingBackend<S>,
    ) -> Result<Self, KernelAhciAbarPreactivationError> {
        let task = prepared.task();
        task.validate_activation_state(runtime)
            .map_err(KernelAhciAbarPreactivationError::Activation)?;
        if task.page_table_root() != tables.root() {
            return Err(KernelAhciAbarPreactivationError::WrongRoot);
        }
        let spec = prepared.launch().spec();
        let target = spec.service().domain();
        if tables.target() != target {
            return Err(KernelAhciAbarPreactivationError::WrongTarget);
        }
        let expected = spec.mapping();
        if descriptor.configuration_generation != expected.configuration_generation
            || descriptor.physical_base != expected.physical_base
            || descriptor.bytes != expected.bytes
        {
            return Err(KernelAhciAbarPreactivationError::AbarGenerationOrGeometryMismatch);
        }
        if !descriptor.identity_matches(spec.descriptor()) {
            return Err(KernelAhciAbarPreactivationError::DescriptorIdentityMismatch);
        }
        mapping_range(expected).ok_or(KernelAhciAbarPreactivationError::InvalidMapping)?;
        let control_object = authorities
            .authorize_exact(control, Rights::CONTROL)
            .map_err(KernelAhciAbarPreactivationError::ControlCapability)?;
        if control_object != expected.device_object {
            return Err(KernelAhciAbarPreactivationError::WrongControlObject);
        }

        let installed = {
            let mut backend = ExactInactiveAbarBackend {
                tables: &mut *tables,
                expected,
                target,
            };
            install_ahci_service_abar(
                authorities,
                mapping_capability,
                expected.device_object,
                descriptor,
                expected.virtual_base,
                expected.mapping_generation,
                &mut backend,
            )
            .map_err(KernelAhciAbarPreactivationError::Mapping)?
        };
        debug_assert_eq!(installed.mapping(), expected);
        Ok(Self {
            prepared,
            runtime,
            tables,
            authorities,
            control,
            installed,
            expected,
            target,
        })
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

    pub const fn mapping(&self) -> AhciAbarMapping {
        self.expected
    }

    pub const fn page_tables_poisoned(&self) -> bool {
        self.tables.is_poisoned()
    }

    /// Rechecks the bound runtime/root/target and exact device leaves without
    /// turning this preactivation owner into an activation proof.
    pub fn verify_exact(&self) -> Result<(), KernelAhciAbarPreactivationError> {
        self.validate_bound_state()?;
        let (virtual_start, physical_start, pages) =
            mapping_range(self.expected).ok_or(KernelAhciAbarPreactivationError::InvalidMapping)?;
        self.tables
            .verify_user_device_rw_nx(self.target, virtual_start, physical_start, pages)
            .map_err(|_| {
                KernelAhciAbarPreactivationError::Mapping(AhciAbarMappingError::BackendRejected)
            })
    }

    /// Removes the exact inactive leaves and returns the prepared task only
    /// after capability revalidation and confirmed withdrawal.
    #[allow(clippy::result_large_err)]
    pub fn rollback(
        self,
    ) -> Result<
        PreparedAhciNativeServiceTask,
        KernelAhciAbarRollbackFailure<'a, S, TASKS, TASK_CAPABILITIES, AUTHORITIES>,
    > {
        if self.validate_bound_state().is_err() {
            return Err(KernelAhciAbarRollbackFailure {
                error: AhciAbarRemovalError::BackendRejected {
                    retained: self.installed,
                },
                owner: self,
            });
        }
        let result = {
            let mut backend = ExactInactiveAbarBackend {
                tables: &mut *self.tables,
                expected: self.expected,
                target: self.target,
            };
            remove_ahci_service_abar(self.installed, self.authorities, self.control, &mut backend)
        };
        match result {
            Ok(mapping) => {
                debug_assert_eq!(mapping, self.expected);
                Ok(self.prepared)
            }
            Err(error) => Err(KernelAhciAbarRollbackFailure { error, owner: self }),
        }
    }

    fn validate_bound_state(&self) -> Result<(), KernelAhciAbarPreactivationError> {
        self.prepared
            .task()
            .validate_activation_state(self.runtime)
            .map_err(KernelAhciAbarPreactivationError::Activation)?;
        if self.prepared.task().page_table_root() != self.tables.root() {
            return Err(KernelAhciAbarPreactivationError::WrongRoot);
        }
        if self.tables.target() != self.target {
            return Err(KernelAhciAbarPreactivationError::WrongTarget);
        }
        Ok(())
    }
}

pub(crate) struct ExactInactiveAbarBackend<'a, S> {
    tables: &'a mut InactivePageTableMappingBackend<S>,
    expected: AhciAbarMapping,
    target: ObjectId,
}

impl<'a, S> ExactInactiveAbarBackend<'a, S> {
    pub(crate) fn new(
        tables: &'a mut InactivePageTableMappingBackend<S>,
        expected: AhciAbarMapping,
        target: ObjectId,
    ) -> ExactInactiveAbarBackend<'a, S> {
        Self {
            tables,
            expected,
            target,
        }
    }
}

// SAFETY: this private backend is constructed only inside the capability- and
// ABAR-generation/geometry-checking preactivation owner. It exact-matches the
// launch range and delegates to the unsafe inactive-page-table operation under
// the owner's retained root-exclusivity, PAT, and alias-lifetime obligations.
unsafe impl<S: PageTableStore> AhciAbarMappingBackend for ExactInactiveAbarBackend<'_, S> {
    fn map_read_write_nx(&mut self, mapping: AhciAbarMapping) -> Result<(), ()> {
        if mapping != self.expected {
            return Err(());
        }
        let (virtual_start, physical_start, pages) = mapping_range(mapping).ok_or(())?;
        // SAFETY: the enclosing unsafe owner construction retains the exact
        // task/root, PAT-index-3 UC, and alias-exclusion obligations.
        unsafe {
            self.tables
                .install_user_device_rw_nx(self.target, virtual_start, physical_start, pages)
        }
        .map_err(|_| ())
    }
}

// SAFETY: this private backend is available only to the retained preactivation
// owner. The task/root remains inactive, and success exact-matches and removes
// every device leaf; uncertainty poisons the underlying hierarchy.
unsafe impl<S: PageTableStore> AhciAbarRemovalBackend for ExactInactiveAbarBackend<'_, S> {
    fn unmap_read_write_nx(&mut self, mapping: AhciAbarMapping) -> Result<(), ()> {
        if mapping != self.expected {
            return Err(());
        }
        let (virtual_start, physical_start, pages) = mapping_range(mapping).ok_or(())?;
        self.tables
            .remove_user_device_rw_nx(self.target, virtual_start, physical_start, pages)
            .map_err(|_| ())
    }
}

fn mapping_range(mapping: AhciAbarMapping) -> Option<(VirtAddr, PhysAddr, u64)> {
    if mapping.bytes == 0 || !mapping.bytes.is_multiple_of(PAGE_SIZE) {
        return None;
    }
    let exact = Mapping::new(
        VirtAddr::new(mapping.virtual_base).ok()?,
        PhysAddr::new(mapping.physical_base).ok()?,
        mapping.bytes / PAGE_SIZE,
        PagePermissions::USER_MMIO_READ_WRITE,
    )
    .ok()?;
    Some((exact.virtual_start(), exact.physical_start(), exact.pages()))
}
