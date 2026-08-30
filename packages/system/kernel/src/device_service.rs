//! Fixed-capacity native device-service construction.
//!
//! Device services need several independently attenuated authorities, unlike a
//! component with one dependency endpoint. This module reuses the task runtime's
//! atomic construction projection and the existing native service identity ABI;
//! it does not create a second capability model or accept authority from launch
//! record bytes.

use crate::{
    Capability, CapabilityError, CapabilitySpace, IsolationPlacement, IsolationServiceSpec,
    ObjectId, PhysAddr, Rights, TaskId, TaskRuntime, TaskRuntimeError,
};
use crate::arch::x86_64::UserContext;

pub const MAX_NATIVE_DEVICE_SERVICE_AUTHORITIES: usize = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceServiceAuthority {
    object: ObjectId,
    source: Capability,
    target_rights: Rights,
}

impl DeviceServiceAuthority {
    pub const fn object(self) -> ObjectId {
        self.object
    }

    pub const fn source(self) -> Capability {
        self.source
    }

    pub const fn target_rights(self) -> Rights {
        self.target_rights
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceServiceLaunchAttachmentError {
    InvalidCount,
    InvalidIdentity,
    InvalidGeneration,
    InvalidLength,
    InvalidRights,
    DuplicateCapability,
    LaunchDataCapability(CapabilityError),
    WrongLaunchDataObject,
    AuthorityCapability(CapabilityError),
    WrongAuthorityObject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceServiceLaunchAttachment<const N: usize> {
    domain: ObjectId,
    system_generation: u64,
    policy_generation: u64,
    attachment_generation: u64,
    launch_data_object: ObjectId,
    launch_data_generation: u64,
    launch_data_bytes: u32,
    launch_data: Capability,
    authorities: [DeviceServiceAuthority; N],
}

impl<const N: usize> DeviceServiceLaunchAttachment<N> {
    #[allow(clippy::too_many_arguments)]
    pub fn new<const C: usize>(
        spec: IsolationServiceSpec,
        attachment_generation: u64,
        launch_data_object: ObjectId,
        launch_data_generation: u64,
        launch_data_bytes: u32,
        launch_data: Capability,
        authorities: [(ObjectId, Capability, Rights); N],
        capabilities: &CapabilitySpace<C>,
    ) -> Result<Self, DeviceServiceLaunchAttachmentError> {
        if N == 0 || N > MAX_NATIVE_DEVICE_SERVICE_AUTHORITIES {
            return Err(DeviceServiceLaunchAttachmentError::InvalidCount);
        }
        if launch_data_object.0 == 0 {
            return Err(DeviceServiceLaunchAttachmentError::InvalidIdentity);
        }
        if attachment_generation == 0 || launch_data_generation == 0 {
            return Err(DeviceServiceLaunchAttachmentError::InvalidGeneration);
        }
        if launch_data_bytes == 0 || launch_data_bytes > 4096 {
            return Err(DeviceServiceLaunchAttachmentError::InvalidLength);
        }
        let actual_data = capabilities
            .authorize_exact(launch_data, Rights::READ.union(Rights::DELEGATE))
            .map_err(DeviceServiceLaunchAttachmentError::LaunchDataCapability)?;
        if actual_data != launch_data_object {
            return Err(DeviceServiceLaunchAttachmentError::WrongLaunchDataObject);
        }
        let mut admitted = [DeviceServiceAuthority {
            object: ObjectId(0),
            source: Capability::from_token(0),
            target_rights: Rights::NONE,
        }; N];
        for (index, (object, source, target_rights)) in authorities.into_iter().enumerate() {
            if object.0 == 0 || object == launch_data_object {
                return Err(DeviceServiceLaunchAttachmentError::InvalidIdentity);
            }
            if target_rights.bits() == 0 || target_rights.contains(Rights::DELEGATE) {
                return Err(DeviceServiceLaunchAttachmentError::InvalidRights);
            }
            if source == launch_data
                || admitted[..index]
                    .iter()
                    .any(|authority| authority.source == source)
            {
                return Err(DeviceServiceLaunchAttachmentError::DuplicateCapability);
            }
            let actual = capabilities
                .authorize_exact(source, target_rights.union(Rights::DELEGATE))
                .map_err(DeviceServiceLaunchAttachmentError::AuthorityCapability)?;
            if actual != object {
                return Err(DeviceServiceLaunchAttachmentError::WrongAuthorityObject);
            }
            admitted[index] = DeviceServiceAuthority {
                object,
                source,
                target_rights,
            };
        }
        Ok(Self {
            domain: spec.domain(),
            system_generation: spec.system_generation(),
            policy_generation: spec.policy_generation(),
            attachment_generation,
            launch_data_object,
            launch_data_generation,
            launch_data_bytes,
            launch_data,
            authorities: admitted,
        })
    }

    pub const fn attachment_generation(self) -> u64 {
        self.attachment_generation
    }

    pub const fn launch_data_object(self) -> ObjectId {
        self.launch_data_object
    }

    pub const fn launch_data_generation(self) -> u64 {
        self.launch_data_generation
    }

    pub const fn launch_data_bytes(self) -> u32 {
        self.launch_data_bytes
    }

    pub const fn launch_data(self) -> Capability {
        self.launch_data
    }

    pub const fn authorities(self) -> [DeviceServiceAuthority; N] {
        self.authorities
    }

    pub fn matches_spec(self, spec: IsolationServiceSpec) -> bool {
        self.domain == spec.domain()
            && self.system_generation == spec.system_generation()
            && self.policy_generation == spec.policy_generation()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDeviceServiceEntryError {
    InvalidIdentity,
    AttachmentMismatch,
    LaunchDataCapability(CapabilityError),
    WrongLaunchDataObject,
    AuthorityCapability(CapabilityError),
    WrongAuthorityObject,
    LaunchRegistersOccupied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeDeviceServiceEntry<const N: usize> {
    service_endpoint_object: ObjectId,
    supervisor_task_object: ObjectId,
    provider_generation: u64,
    service_module_object: ObjectId,
    attachment: DeviceServiceLaunchAttachment<N>,
    launch_data: Capability,
    authorities: [Capability; N],
}

impl<const N: usize> NativeDeviceServiceEntry<N> {
    #[allow(clippy::too_many_arguments)]
    pub fn new<const C: usize>(
        spec: IsolationServiceSpec,
        attachment: DeviceServiceLaunchAttachment<N>,
        service_endpoint_object: ObjectId,
        supervisor_task_object: ObjectId,
        service_module_object: ObjectId,
        launch_data: Capability,
        authorities: [Capability; N],
        target_capabilities: &CapabilitySpace<C>,
    ) -> Result<Self, NativeDeviceServiceEntryError> {
        if N == 0
            || N > MAX_NATIVE_DEVICE_SERVICE_AUTHORITIES
            || service_endpoint_object.0 == 0
            || supervisor_task_object.0 == 0
            || service_module_object.0 == 0
            || service_endpoint_object == supervisor_task_object
        {
            return Err(NativeDeviceServiceEntryError::InvalidIdentity);
        }
        if !attachment.matches_spec(spec) {
            return Err(NativeDeviceServiceEntryError::AttachmentMismatch);
        }
        let actual_data = target_capabilities
            .authorize_exact(launch_data, Rights::READ)
            .map_err(NativeDeviceServiceEntryError::LaunchDataCapability)?;
        if actual_data != attachment.launch_data_object() {
            return Err(NativeDeviceServiceEntryError::WrongLaunchDataObject);
        }
        for (projected, expected) in authorities.into_iter().zip(attachment.authorities()) {
            let actual = target_capabilities
                .authorize_exact(projected, expected.target_rights())
                .map_err(NativeDeviceServiceEntryError::AuthorityCapability)?;
            if actual != expected.object() {
                return Err(NativeDeviceServiceEntryError::WrongAuthorityObject);
            }
        }
        Ok(Self {
            service_endpoint_object,
            supervisor_task_object,
            provider_generation: spec.provider_generation(),
            service_module_object,
            attachment,
            launch_data,
            authorities,
        })
    }

    pub const fn launch_data(self) -> Capability {
        self.launch_data
    }

    pub const fn authorities(self) -> [Capability; N] {
        self.authorities
    }

    pub const fn attachment(self) -> DeviceServiceLaunchAttachment<N> {
        self.attachment
    }

    pub fn install(
        self,
        mut context: UserContext,
    ) -> Result<UserContext, (Self, NativeDeviceServiceEntryError, UserContext)> {
        if context.r13 != 0
            || context.r14 != 0
            || context.r12 != 0
            || context.r15 != 0
            || context.r11 != 0
            || context.r10 != 0
            || context.rbx != 0
            || context.rdx != 0
            || context.rbp != 0
            || context.rsi != 0
            || context.r9 != 0
            || context.r8 != 0
        {
            return Err((
                self,
                NativeDeviceServiceEntryError::LaunchRegistersOccupied,
                context,
            ));
        }
        context.r13 = self.service_endpoint_object.0;
        context.r14 = self.supervisor_task_object.0;
        context.r12 = self.provider_generation;
        context.r15 = self.launch_data.token();
        context.r11 = u64::from(self.attachment.launch_data_bytes());
        context.r10 = self.service_module_object.0;
        for (index, capability) in self.authorities.into_iter().enumerate() {
            match index {
                0 => context.rbx = capability.token(),
                1 => context.rdx = capability.token(),
                2 => context.rbp = capability.token(),
                3 => context.rsi = capability.token(),
                4 => context.r9 = capability.token(),
                5 => context.r8 = capability.token(),
                _ => unreachable!("attachment construction bounds authority count"),
            }
        }
        Ok(context)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDeviceServiceTaskError {
    WrongPlacement,
    Runtime(TaskRuntimeError),
    Entry(NativeDeviceServiceEntryError),
    Rollback {
        entry: NativeDeviceServiceEntryError,
        cleanup: TaskRuntimeError,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeDeviceServiceTask<const N: usize> {
    source_task: TaskId,
    task: TaskId,
    page_table_root: PhysAddr,
    entry: NativeDeviceServiceEntry<N>,
}

impl<const N: usize> NativeDeviceServiceTask<N> {
    pub const fn source_task(self) -> TaskId {
        self.source_task
    }

    pub const fn task(self) -> TaskId {
        self.task
    }

    pub const fn page_table_root(self) -> PhysAddr {
        self.page_table_root
    }

    pub const fn entry(self) -> NativeDeviceServiceEntry<N> {
        self.entry
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeDeviceServiceRetirement<const N: usize> {
    task: NativeDeviceServiceTask<N>,
    context: UserContext,
}

impl<const N: usize> NativeDeviceServiceRetirement<N> {
    pub const fn task(self) -> NativeDeviceServiceTask<N> {
        self.task
    }

    pub const fn context(self) -> UserContext {
        self.context
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDeviceServiceRetirementError {
    NotCurrent,
    RootMismatch,
    Runtime(TaskRuntimeError),
}

/// Retires the exact current native device-service task after device-specific
/// quiescence has completed outside the kernel.
pub fn retire_current_native_device_service_task<
    const N: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    task: NativeDeviceServiceTask<N>,
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
) -> Result<(crate::TaskTermination, NativeDeviceServiceRetirement<N>), NativeDeviceServiceRetirementError>
{
    if runtime.current() != Some(task.task) {
        return Err(NativeDeviceServiceRetirementError::NotCurrent);
    }
    let context = *runtime
        .context(task.task)
        .map_err(NativeDeviceServiceRetirementError::Runtime)?;
    if context.page_table() != task.page_table_root {
        return Err(NativeDeviceServiceRetirementError::RootMismatch);
    }
    let (termination, retired_context) = runtime
        .terminate_current_with_context()
        .map_err(NativeDeviceServiceRetirementError::Runtime)?;
    debug_assert_eq!(termination.task(), task.task);
    debug_assert_eq!(retired_context, context);
    Ok((
        termination,
        NativeDeviceServiceRetirement {
            task,
            context: retired_context,
        },
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_native_device_service_task<
    const N: usize,
    const TASKS: usize,
    const CAPABILITIES: usize,
>(
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    source_task: TaskId,
    target_task: TaskId,
    spec: IsolationServiceSpec,
    attachment: DeviceServiceLaunchAttachment<N>,
    service_endpoint_object: ObjectId,
    supervisor_task_object: ObjectId,
    service_module_object: ObjectId,
) -> Result<NativeDeviceServiceTask<N>, NativeDeviceServiceTaskError> {
    if spec.placement() != IsolationPlacement::NativeService {
        return Err(NativeDeviceServiceTaskError::WrongPlacement);
    }
    let context = *runtime
        .context(target_task)
        .map_err(NativeDeviceServiceTaskError::Runtime)?;
    let mut requested = [(attachment.launch_data(), Rights::READ);
        MAX_NATIVE_DEVICE_SERVICE_AUTHORITIES + 1];
    for (slot, authority) in requested[1..=N]
        .iter_mut()
        .zip(attachment.authorities())
    {
        *slot = (authority.source(), authority.target_rights());
    }
    let projection = runtime
        .project_capabilities_for_construction(
            source_task,
            target_task,
            &requested[..=N],
        )
        .map_err(NativeDeviceServiceTaskError::Runtime)?;
    let mut projected = projection.capabilities();
    let launch_data = projected
        .next()
        .expect("device construction always projects launch data");
    let mut authorities = [Capability::from_token(0); N];
    for authority in &mut authorities {
        *authority = projected
            .next()
            .expect("attachment count fixes projected authority count");
    }
    debug_assert!(projected.next().is_none());
    let entry = match NativeDeviceServiceEntry::new(
        spec,
        attachment,
        service_endpoint_object,
        supervisor_task_object,
        service_module_object,
        launch_data,
        authorities,
        runtime
            .capabilities(target_task)
            .expect("successful projection preserves target task"),
    ) {
        Ok(entry) => entry,
        Err(error) => {
            return rollback_projection(runtime, target_task, launch_data, authorities, error);
        }
    };
    let installed = match entry.install(context) {
        Ok(installed) => installed,
        Err((_, error, _)) => {
            return rollback_projection(runtime, target_task, launch_data, authorities, error);
        }
    };
    *runtime
        .context_mut(target_task)
        .expect("successful projection preserves target task") = installed;
    Ok(NativeDeviceServiceTask {
        source_task,
        task: target_task,
        page_table_root: context.page_table(),
        entry,
    })
}

fn rollback_projection<const N: usize, const TASKS: usize, const CAPABILITIES: usize>(
    runtime: &mut TaskRuntime<TASKS, CAPABILITIES>,
    target_task: TaskId,
    launch_data: Capability,
    authorities: [Capability; N],
    entry: NativeDeviceServiceEntryError,
) -> Result<NativeDeviceServiceTask<N>, NativeDeviceServiceTaskError> {
    let mut cleanup = runtime.revoke_capability(target_task, launch_data).err();
    for authority in authorities {
        if let Err(error) = runtime.revoke_capability(target_task, authority) {
            cleanup = cleanup.or(Some(error));
        }
    }
    match cleanup {
        Some(cleanup) => Err(NativeDeviceServiceTaskError::Rollback { entry, cleanup }),
        None => Err(NativeDeviceServiceTaskError::Entry(entry)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PhysAddr, Priority, TotalMicrovmClass};

    fn spec(placement: IsolationPlacement) -> IsolationServiceSpec {
        IsolationServiceSpec::new(
            ObjectId(0x40),
            ObjectId(0x41),
            1,
            9,
            11,
            7,
            TotalMicrovmClass::MicrovmEligible,
            placement,
        )
        .unwrap()
    }

    fn context(root: u64) -> UserContext {
        UserContext::new(PhysAddr::new(root).unwrap(), 0x40_0000, 0x7000_0000).unwrap()
    }

    fn runtime() -> (TaskRuntime<2, 8>, TaskId, TaskId) {
        let mut runtime = TaskRuntime::<2, 8>::new(1_000, 1).unwrap();
        let source = runtime.create(Priority::NORMAL, context(0x20_0000)).unwrap();
        let target = runtime.create(Priority::NORMAL, context(0x30_0000)).unwrap();
        (runtime, source, target)
    }

    fn attachment<const N: usize>(
        runtime: &mut TaskRuntime<2, 8>,
        source: TaskId,
        rights: [Rights; N],
    ) -> (DeviceServiceLaunchAttachment<N>, Capability, [Capability; N]) {
        let launch_data = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0x80), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let mut handles = [Capability::from_token(0); N];
        let authorities = core::array::from_fn(|index| {
            let object = ObjectId(0x90 + index as u64);
            let handle = runtime
                .capabilities_mut(source)
                .unwrap()
                .insert(object, rights[index].union(Rights::DELEGATE))
                .unwrap();
            handles[index] = handle;
            (object, handle, rights[index])
        });
        let attachment = DeviceServiceLaunchAttachment::new(
            spec(IsolationPlacement::NativeService),
            13,
            ObjectId(0x80),
            3,
            256,
            launch_data,
            authorities,
            runtime.capabilities(source).unwrap(),
        )
        .unwrap();
        (attachment, launch_data, handles)
    }

    #[test]
    fn six_exact_authorities_project_atomically_into_the_fixed_entry_abi() {
        let (mut runtime, source, target) = runtime();
        let rights = [
            Rights::CONTROL,
            Rights::MAP.union(Rights::READ),
            Rights::MAP.union(Rights::WRITE),
            Rights::PIN.union(Rights::READ),
            Rights::PIN.union(Rights::WRITE),
            Rights::SIGNAL,
        ];
        let (attachment, _, _) = attachment(&mut runtime, source, rights);
        let task = prepare_native_device_service_task(
            &mut runtime,
            source,
            target,
            spec(IsolationPlacement::NativeService),
            attachment,
            ObjectId(0xa0),
            ObjectId(0xa1),
            ObjectId(0xa2),
        )
        .unwrap();
        let entry = task.entry();
        let projected = entry.authorities();
        let installed = runtime.context(target).unwrap();
        assert_eq!(installed.r13, 0xa0);
        assert_eq!(installed.r14, 0xa1);
        assert_eq!(installed.r12, 9);
        assert_eq!(installed.r15, entry.launch_data().token());
        assert_eq!(installed.r11, 256);
        assert_eq!(installed.r10, 0xa2);
        assert_eq!(
            [
                installed.rbx,
                installed.rdx,
                installed.rbp,
                installed.rsi,
                installed.r9,
                installed.r8,
            ],
            projected.map(Capability::token)
        );
        for ((capability, expected), index) in projected.into_iter().zip(rights).zip(0_u64..) {
            assert_eq!(
                runtime
                    .capabilities(target)
                    .unwrap()
                    .authorize_exact(capability, expected),
                Ok(ObjectId(0x90 + index))
            );
            assert_eq!(
                runtime
                    .capabilities(target)
                    .unwrap()
                    .authorize(capability, expected.union(Rights::DELEGATE)),
                Err(CapabilityError::PermissionDenied)
            );
        }
    }

    #[test]
    fn attachment_rejects_overbroad_sources_duplicate_handles_and_delegable_targets() {
        let (mut runtime, source, _) = runtime();
        let launch_data = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(ObjectId(0x80), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let broad = runtime
            .capabilities_mut(source)
            .unwrap()
            .insert(
                ObjectId(0x90),
                Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE),
            )
            .unwrap();
        let create = |authorities| {
            DeviceServiceLaunchAttachment::new(
                spec(IsolationPlacement::NativeService),
                13,
                ObjectId(0x80),
                3,
                256,
                launch_data,
                authorities,
                runtime.capabilities(source).unwrap(),
            )
        };
        assert_eq!(
            create([(ObjectId(0x90), broad, Rights::READ)]),
            Err(DeviceServiceLaunchAttachmentError::AuthorityCapability(
                CapabilityError::PermissionDenied
            ))
        );
        assert_eq!(
            create([(ObjectId(0x90), broad, Rights::DELEGATE)]),
            Err(DeviceServiceLaunchAttachmentError::InvalidRights)
        );
        assert_eq!(
            DeviceServiceLaunchAttachment::new(
                spec(IsolationPlacement::NativeService),
                13,
                ObjectId(0x80),
                3,
                256,
                launch_data,
                [
                    (ObjectId(0x90), broad, Rights::READ.union(Rights::WRITE)),
                    (ObjectId(0x90), broad, Rights::READ.union(Rights::WRITE)),
                ],
                runtime.capabilities(source).unwrap(),
            ),
            Err(DeviceServiceLaunchAttachmentError::DuplicateCapability)
        );
    }

    #[test]
    fn authority_count_is_fixed_to_the_native_entry_register_budget() {
        let capabilities = CapabilitySpace::<1>::new();
        assert_eq!(
            DeviceServiceLaunchAttachment::new(
                spec(IsolationPlacement::NativeService),
                13,
                ObjectId(0x80),
                3,
                256,
                Capability::from_token(1),
                [],
                &capabilities,
            ),
            Err(DeviceServiceLaunchAttachmentError::InvalidCount)
        );
        assert_eq!(
            DeviceServiceLaunchAttachment::new(
                spec(IsolationPlacement::NativeService),
                13,
                ObjectId(0x80),
                3,
                256,
                Capability::from_token(1),
                [(ObjectId(1), Capability::from_token(2), Rights::READ); 7],
                &capabilities,
            ),
            Err(DeviceServiceLaunchAttachmentError::InvalidCount)
        );
    }

    #[test]
    fn occupied_entry_register_rolls_back_every_projected_leaf() {
        let (mut runtime, source, target) = runtime();
        runtime.context_mut(target).unwrap().r9 = 1;
        let original = *runtime.context(target).unwrap();
        let (attachment, _, _) = attachment(&mut runtime, source, [Rights::CONTROL]);
        assert_eq!(
            prepare_native_device_service_task(
                &mut runtime,
                source,
                target,
                spec(IsolationPlacement::NativeService),
                attachment,
                ObjectId(0xa0),
                ObjectId(0xa1),
                ObjectId(0xa2),
            ),
            Err(NativeDeviceServiceTaskError::Entry(
                NativeDeviceServiceEntryError::LaunchRegistersOccupied
            ))
        );
        assert_eq!(*runtime.context(target).unwrap(), original);
        assert!(runtime.capabilities(target).unwrap().is_empty());
    }

    #[test]
    fn source_revocation_reaches_each_derived_target_authority() {
        let (mut runtime, source, target) = runtime();
        let (attachment, launch_data, source_authorities) = attachment(
            &mut runtime,
            source,
            [Rights::CONTROL, Rights::MAP.union(Rights::READ)],
        );
        let task = prepare_native_device_service_task(
            &mut runtime,
            source,
            target,
            spec(IsolationPlacement::NativeService),
            attachment,
            ObjectId(0xa0),
            ObjectId(0xa1),
            ObjectId(0xa2),
        )
        .unwrap();
        runtime.revoke_capability(source, launch_data).unwrap();
        runtime
            .revoke_capability(source, source_authorities[0])
            .unwrap();
        assert_eq!(
            runtime
                .capabilities(target)
                .unwrap()
                .authorize(task.entry().launch_data(), Rights::READ),
            Err(CapabilityError::Invalid)
        );
        assert_eq!(
            runtime
                .capabilities(target)
                .unwrap()
                .authorize(task.entry().authorities()[0], Rights::CONTROL),
            Err(CapabilityError::Invalid)
        );
        assert_eq!(
            runtime
                .capabilities(target)
                .unwrap()
                .authorize_exact(
                    task.entry().authorities()[1],
                    Rights::MAP.union(Rights::READ),
                ),
            Ok(ObjectId(0x91))
        );
    }

    #[test]
    fn native_device_retirement_exact_matches_current_task_and_root() {
        let (mut runtime, source, target) = runtime();
        let (attachment, _, _) = attachment(&mut runtime, source, [Rights::CONTROL]);
        let task = prepare_native_device_service_task(
            &mut runtime,
            source,
            target,
            spec(IsolationPlacement::NativeService),
            attachment,
            ObjectId(0xa0),
            ObjectId(0xa1),
            ObjectId(0xa2),
        )
        .unwrap();
        assert_eq!(task.page_table_root(), PhysAddr::new(0x30_0000).unwrap());
        assert!(matches!(
            runtime.start(),
            crate::ScheduleOutcome::Switch { to, .. } if to == source
        ));
        assert_eq!(
            retire_current_native_device_service_task(task, &mut runtime),
            Err(NativeDeviceServiceRetirementError::NotCurrent)
        );
        runtime.yield_current().unwrap();
        assert_eq!(runtime.current(), Some(target));

        let installed = *runtime.context(target).unwrap();
        *runtime.context_mut(target).unwrap() = context(0x40_0000);
        assert_eq!(
            retire_current_native_device_service_task(task, &mut runtime),
            Err(NativeDeviceServiceRetirementError::RootMismatch)
        );
        assert_eq!(runtime.current(), Some(target));

        *runtime.context_mut(target).unwrap() = installed;
        let (termination, retired) =
            retire_current_native_device_service_task(task, &mut runtime).unwrap();
        assert_eq!(termination.task(), target);
        assert_eq!(retired.task(), task);
        assert_eq!(retired.context(), installed);
        assert!(matches!(
            runtime.context(target),
            Err(TaskRuntimeError::MissingTask)
        ));
    }
}
