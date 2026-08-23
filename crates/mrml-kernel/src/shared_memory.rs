use crate::{
    Capability, CapabilityError, CapabilitySpace, GuestMappingId, GuestMemory,
    MappingRevocationError, ObjectId, RevocableVmBackend, Rights, ServiceAddressSpaceEraser,
    TaskId, VmId, revoke_mapping_before_resume,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostResourceHandle(u64);

impl HostResourceHandle {
    pub const fn new(token: u64) -> Result<Self, SharedBindingError> {
        if token == 0 {
            return Err(SharedBindingError::InvalidHostHandle);
        }
        Ok(Self(token))
    }

    pub const fn token(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedAccess {
    ReadOnly,
    ReadWrite,
}

impl SharedAccess {
    const fn rights(self) -> Rights {
        match self {
            Self::ReadOnly => Rights::MAP.union(Rights::READ),
            Self::ReadWrite => Rights::MAP.union(Rights::READ).union(Rights::WRITE),
        }
    }

    const fn permits(self, requested: Self) -> bool {
        matches!(self, Self::ReadWrite) || matches!(requested, Self::ReadOnly)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedEndpoint {
    vm: VmId,
    task: Option<TaskId>,
    mapping: GuestMappingId,
    access: SharedAccess,
}

impl SharedEndpoint {
    pub const fn new(vm: VmId, mapping: GuestMappingId, access: SharedAccess) -> Self {
        Self {
            vm,
            task: None,
            mapping,
            access,
        }
    }

    pub const fn for_task(
        vm: VmId,
        task: TaskId,
        mapping: GuestMappingId,
        access: SharedAccess,
    ) -> Self {
        Self {
            vm,
            task: Some(task),
            mapping,
            access,
        }
    }
}

pub struct SharedEndpointRequest<'a, const CAPS: usize, const MAPPINGS: usize> {
    capabilities: &'a CapabilitySpace<CAPS>,
    authority: Capability,
    memory: &'a GuestMemory<MAPPINGS>,
    endpoint: SharedEndpoint,
}

impl<'a, const CAPS: usize, const MAPPINGS: usize> SharedEndpointRequest<'a, CAPS, MAPPINGS> {
    pub const fn new(
        capabilities: &'a CapabilitySpace<CAPS>,
        authority: Capability,
        memory: &'a GuestMemory<MAPPINGS>,
        endpoint: SharedEndpoint,
    ) -> Self {
        Self {
            capabilities,
            authority,
            memory,
            endpoint,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedBindingId(u64);

impl SharedBindingId {
    const fn new(index: usize, generation: u32) -> Self {
        Self(((generation as u64) << 32) | index as u64)
    }

    const fn index(self) -> usize {
        self.0 as u32 as usize
    }

    const fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }

    pub const fn token(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedBindingError {
    InvalidHostHandle,
    TableFull,
    DuplicateHostHandle,
    DuplicateMapping,
    StaleBinding,
    StaleMapping,
    WrongVm,
    WrongTask,
    WrongMapping,
    WrongObject,
    AccessDenied,
    ExecutableMapping,
    ResourceMismatch,
    SequenceExhausted,
    Capability(CapabilityError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedRevocation {
    handle: HostResourceHandle,
    last_endpoint: bool,
}

impl SharedRevocation {
    pub const fn handle(self) -> HostResourceHandle {
        self.handle
    }

    /// The opaque host resource may be destroyed only after this is true and
    /// the native mapping represented by the revoked endpoint is invalidated.
    pub const fn is_last_endpoint(self) -> bool {
        self.last_endpoint
    }
}

impl From<CapabilityError> for SharedBindingError {
    fn from(value: CapabilityError) -> Self {
        Self::Capability(value)
    }
}

#[derive(Clone, Copy)]
struct Binding {
    generation: u32,
    resource: u64,
    vm: VmId,
    task: Option<TaskId>,
    mapping: GuestMappingId,
    object: ObjectId,
    handle: HostResourceHandle,
    access: SharedAccess,
    host_start: crate::PhysAddr,
    pages: u64,
}

/// Fixed-capacity binding between one live guest mapping and one opaque host
/// resource. The token is never placed in guest memory. Every resolution
/// repeats capability, VM, mapping-identity, and liveness checks.
pub struct SharedMemoryBindings<const N: usize> {
    entries: [Option<Binding>; N],
    generations: [u32; N],
    next_resource: u64,
}

impl<const N: usize> SharedMemoryBindings<N> {
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            generations: [0; N],
            next_resource: 1,
        }
    }

    pub fn bind<const CAPS: usize, const MAPPINGS: usize>(
        &mut self,
        capabilities: &CapabilitySpace<CAPS>,
        authority: Capability,
        memory: &GuestMemory<MAPPINGS>,
        endpoint: SharedEndpoint,
        handle: HostResourceHandle,
    ) -> Result<SharedBindingId, SharedBindingError> {
        let object = capabilities.authorize(authority, endpoint.access.rights())?;
        let region = memory
            .region(endpoint.mapping)
            .map_err(|_| SharedBindingError::StaleMapping)?;
        validate_region(region, endpoint.access)?;
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.handle == handle)
        {
            return Err(SharedBindingError::DuplicateHostHandle);
        }
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.vm == endpoint.vm && entry.mapping == endpoint.mapping)
        {
            return Err(SharedBindingError::DuplicateMapping);
        }
        let index = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or(SharedBindingError::TableFull)?;
        let resource = self.next_resource;
        let next_resource = self
            .next_resource
            .checked_add(1)
            .ok_or(SharedBindingError::SequenceExhausted)?;
        let generation = self.generations[index]
            .checked_add(1)
            .ok_or(SharedBindingError::SequenceExhausted)?;
        self.next_resource = next_resource;
        self.generations[index] = generation;
        self.entries[index] = Some(Binding {
            generation,
            resource,
            vm: endpoint.vm,
            task: endpoint.task,
            mapping: endpoint.mapping,
            object,
            handle,
            access: endpoint.access,
            host_start: region.host_start(),
            pages: region.pages(),
        });
        Ok(SharedBindingId::new(index, generation))
    }

    /// Adds a second VM mapping to an existing shared resource. The controller
    /// must hold exact `CONTROL` authority for the source object, while the new
    /// endpoint independently proves its requested mapping rights and liveness.
    /// Access can only preserve or reduce the source endpoint's access.
    pub fn share<
        const CONTROL_CAPS: usize,
        const DESTINATION_CAPS: usize,
        const MAPPINGS: usize,
    >(
        &mut self,
        source: SharedBindingId,
        controller: &CapabilitySpace<CONTROL_CAPS>,
        control: Capability,
        request: SharedEndpointRequest<'_, DESTINATION_CAPS, MAPPINGS>,
    ) -> Result<SharedBindingId, SharedBindingError> {
        let source_entry = *self.entry(source)?;
        if controller.authorize(control, Rights::CONTROL)? != source_entry.object {
            return Err(SharedBindingError::WrongObject);
        }
        let destination = request.endpoint;
        let destination_object = request
            .capabilities
            .authorize(request.authority, destination.access.rights())?;
        if destination_object != source_entry.object {
            return Err(SharedBindingError::WrongObject);
        }
        if !source_entry.access.permits(destination.access) {
            return Err(SharedBindingError::AccessDenied);
        }
        let destination_region = request
            .memory
            .region(destination.mapping)
            .map_err(|_| SharedBindingError::StaleMapping)?;
        validate_region(destination_region, destination.access)?;
        if destination_region.host_start() != source_entry.host_start
            || destination_region.pages() != source_entry.pages
        {
            return Err(SharedBindingError::ResourceMismatch);
        }
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.vm == destination.vm && entry.mapping == destination.mapping)
        {
            return Err(SharedBindingError::DuplicateMapping);
        }
        let index = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or(SharedBindingError::TableFull)?;
        let generation = self.generations[index]
            .checked_add(1)
            .ok_or(SharedBindingError::SequenceExhausted)?;
        self.generations[index] = generation;
        self.entries[index] = Some(Binding {
            generation,
            resource: source_entry.resource,
            vm: destination.vm,
            task: destination.task,
            mapping: destination.mapping,
            object: source_entry.object,
            handle: source_entry.handle,
            access: destination.access,
            host_start: source_entry.host_start,
            pages: source_entry.pages,
        });
        Ok(SharedBindingId::new(index, generation))
    }

    pub fn resolve<const CAPS: usize, const MAPPINGS: usize>(
        &self,
        id: SharedBindingId,
        capabilities: &CapabilitySpace<CAPS>,
        authority: Capability,
        memory: &GuestMemory<MAPPINGS>,
        endpoint: SharedEndpoint,
    ) -> Result<HostResourceHandle, SharedBindingError> {
        let object = capabilities.authorize(authority, endpoint.access.rights())?;
        let entry = self.entry(id)?;
        if object != entry.object {
            return Err(SharedBindingError::WrongObject);
        }
        if entry.vm != endpoint.vm {
            return Err(SharedBindingError::WrongVm);
        }
        if entry.task != endpoint.task {
            return Err(SharedBindingError::WrongTask);
        }
        if entry.mapping != endpoint.mapping {
            return Err(SharedBindingError::WrongMapping);
        }
        let region = memory
            .region(endpoint.mapping)
            .map_err(|_| SharedBindingError::StaleMapping)?;
        validate_region(region, endpoint.access)?;
        if region.host_start() != entry.host_start || region.pages() != entry.pages {
            return Err(SharedBindingError::ResourceMismatch);
        }
        if !entry.access.permits(endpoint.access) {
            return Err(SharedBindingError::AccessDenied);
        }
        Ok(entry.handle)
    }

    pub fn revoke<const CAPS: usize>(
        &mut self,
        id: SharedBindingId,
        capabilities: &CapabilitySpace<CAPS>,
        authority: Capability,
    ) -> Result<SharedRevocation, SharedBindingError> {
        let object = capabilities.authorize(authority, Rights::CONTROL)?;
        let entry = *self.entry(id)?;
        if object != entry.object {
            return Err(SharedBindingError::WrongObject);
        }
        self.entries[id.index()] = None;
        let last_endpoint = !self
            .entries
            .iter()
            .flatten()
            .any(|candidate| candidate.resource == entry.resource);
        Ok(SharedRevocation {
            handle: entry.handle,
            last_endpoint,
        })
    }

    fn next_for_task(&self, task: TaskId) -> Option<(SharedBindingId, GuestMappingId)> {
        self.entries.iter().enumerate().find_map(|(index, entry)| {
            let entry = entry.as_ref().filter(|entry| entry.task == Some(task))?;
            Some((SharedBindingId::new(index, entry.generation), entry.mapping))
        })
    }

    fn revoke_retired_task(
        &mut self,
        id: SharedBindingId,
        task: TaskId,
        mapping: GuestMappingId,
    ) -> Result<SharedRevocation, SharedBindingError> {
        let entry = *self.entry(id)?;
        if entry.task != Some(task) {
            return Err(SharedBindingError::WrongTask);
        }
        if entry.mapping != mapping {
            return Err(SharedBindingError::WrongMapping);
        }
        self.entries[id.index()] = None;
        Ok(SharedRevocation {
            handle: entry.handle,
            last_endpoint: !self
                .entries
                .iter()
                .flatten()
                .any(|candidate| candidate.resource == entry.resource),
        })
    }

    fn entry(&self, id: SharedBindingId) -> Result<&Binding, SharedBindingError> {
        self.entries
            .get(id.index())
            .and_then(Option::as_ref)
            .filter(|entry| entry.generation == id.generation())
            .ok_or(SharedBindingError::StaleBinding)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedCleanupError<E> {
    Mapping(MappingRevocationError<E>),
    Binding(SharedBindingError),
    ReportFull,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedCleanupReport<const N: usize> {
    entries: [Option<SharedRevocation>; N],
    count: usize,
}

impl<const N: usize> SharedCleanupReport<N> {
    pub const fn len(&self) -> usize {
        self.count
    }
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn get(&self, index: usize) -> Option<SharedRevocation> {
        self.entries.get(index).copied().flatten()
    }

    fn push(&mut self, revocation: SharedRevocation) -> Result<(), SharedBindingError> {
        let slot = self
            .entries
            .get_mut(self.count)
            .ok_or(SharedBindingError::TableFull)?;
        *slot = Some(revocation);
        self.count += 1;
        Ok(())
    }
}

/// Removes every task-owned native mapping before retiring its common mapping
/// identity and shared-resource binding. VM-owned and other task-owned
/// endpoints remain live. A native failure leaves the current binding intact;
/// the backend's revocation contract prevents subsequent vCPU execution when
/// hardware state is uncertain.
pub fn revoke_task_shared_bindings_before_resume<
    B: RevocableVmBackend,
    const BINDINGS: usize,
    const MAPPINGS: usize,
>(
    backend: &mut B,
    memory: &mut GuestMemory<MAPPINGS>,
    bindings: &mut SharedMemoryBindings<BINDINGS>,
    task: TaskId,
) -> Result<SharedCleanupReport<BINDINGS>, SharedCleanupError<B::Error>> {
    let mut report = SharedCleanupReport {
        entries: [None; BINDINGS],
        count: 0,
    };
    while let Some((binding, mapping)) = bindings.next_for_task(task) {
        revoke_mapping_before_resume(backend, memory, mapping)
            .map_err(SharedCleanupError::Mapping)?;
        let revocation = bindings
            .revoke_retired_task(binding, task, mapping)
            .map_err(SharedCleanupError::Binding)?;
        report
            .push(revocation)
            .map_err(|_| SharedCleanupError::ReportFull)?;
    }
    Ok(report)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceResourceCleanupError<BackendError, EraserError, ResourceError> {
    Shared(SharedCleanupError<BackendError>),
    AddressSpace(EraserError),
    HostResource(ResourceError),
    ReportFull,
}

pub trait HostResourceRetirer {
    type Error;
    fn retire(&mut self, handle: HostResourceHandle) -> Result<(), Self::Error>;
}

/// Couples task-owned shared-binding retirement to address-space erasure. The
/// object retains completed handle revocations across an eraser failure so a
/// retry cannot lose final-reference cleanup obligations.
pub struct ServiceResourceEraser<'a, E, R, B, const BINDINGS: usize, const MAPPINGS: usize> {
    address_space: &'a mut E,
    resources: &'a mut R,
    backend: &'a mut B,
    memory: &'a mut GuestMemory<MAPPINGS>,
    bindings: &'a mut SharedMemoryBindings<BINDINGS>,
    report: SharedCleanupReport<BINDINGS>,
    processed: usize,
}

impl<'a, E, R, B, const BINDINGS: usize, const MAPPINGS: usize>
    ServiceResourceEraser<'a, E, R, B, BINDINGS, MAPPINGS>
{
    pub const fn new(
        address_space: &'a mut E,
        resources: &'a mut R,
        backend: &'a mut B,
        memory: &'a mut GuestMemory<MAPPINGS>,
        bindings: &'a mut SharedMemoryBindings<BINDINGS>,
    ) -> Self {
        Self {
            address_space,
            resources,
            backend,
            memory,
            bindings,
            report: SharedCleanupReport {
                entries: [None; BINDINGS],
                count: 0,
            },
            processed: 0,
        }
    }

    pub const fn report(&self) -> &SharedCleanupReport<BINDINGS> {
        &self.report
    }
}

impl<E, R, B, const BINDINGS: usize, const MAPPINGS: usize> ServiceAddressSpaceEraser
    for ServiceResourceEraser<'_, E, R, B, BINDINGS, MAPPINGS>
where
    E: ServiceAddressSpaceEraser,
    R: HostResourceRetirer,
    B: RevocableVmBackend,
{
    type Error = ServiceResourceCleanupError<B::Error, E::Error, R::Error>;

    fn erase(
        &mut self,
        task: TaskId,
        context: crate::arch::x86_64::UserContext,
    ) -> Result<(), Self::Error> {
        let completed = revoke_task_shared_bindings_before_resume(
            self.backend,
            self.memory,
            self.bindings,
            task,
        )
        .map_err(ServiceResourceCleanupError::Shared)?;
        for index in 0..completed.len() {
            self.report
                .push(
                    completed
                        .get(index)
                        .ok_or(ServiceResourceCleanupError::ReportFull)?,
                )
                .map_err(|_| ServiceResourceCleanupError::ReportFull)?;
        }
        while self.processed < self.report.len() {
            let revocation = self
                .report
                .get(self.processed)
                .ok_or(ServiceResourceCleanupError::ReportFull)?;
            if revocation.is_last_endpoint() {
                self.resources
                    .retire(revocation.handle())
                    .map_err(ServiceResourceCleanupError::HostResource)?;
            }
            self.processed += 1;
        }
        self.address_space
            .erase(task, context)
            .map_err(ServiceResourceCleanupError::AddressSpace)
    }
}

fn validate_region(
    region: crate::GuestRegion,
    access: SharedAccess,
) -> Result<(), SharedBindingError> {
    if region.is_executable() {
        return Err(SharedBindingError::ExecutableMapping);
    }
    if matches!(access, SharedAccess::ReadWrite) && !region.is_writable() {
        return Err(SharedBindingError::AccessDenied);
    }
    Ok(())
}

impl<const N: usize> Default for SharedMemoryBindings<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::{TrapDisposition, UserContext};
    use crate::{
        GuestRegion, KernelScheduler, PhysAddr, Priority, ScheduleOutcome, ServiceSupervisor,
        TaskRuntime, VmBackend, VmExit, VmTable,
    };

    struct CleanupBackend {
        fail: bool,
        calls: [(u64, u64); 2],
        count: usize,
    }

    struct RetryEraser {
        calls: usize,
    }

    struct RetryRetirer {
        calls: usize,
    }

    impl HostResourceRetirer for RetryRetirer {
        type Error = ();
        fn retire(&mut self, _handle: HostResourceHandle) -> Result<(), Self::Error> {
            self.calls += 1;
            if self.calls == 1 { Err(()) } else { Ok(()) }
        }
    }

    impl ServiceAddressSpaceEraser for RetryEraser {
        type Error = ();
        fn erase(
            &mut self,
            _task: TaskId,
            _context: crate::arch::x86_64::UserContext,
        ) -> Result<(), Self::Error> {
            self.calls += 1;
            if self.calls == 1 { Err(()) } else { Ok(()) }
        }
    }

    impl VmBackend for CleanupBackend {
        type Error = ();
        fn run(&mut self, _vcpu: u32) -> Result<VmExit, Self::Error> {
            Err(())
        }
        fn read_guest(&self, _address: u64, _output: &mut [u8]) -> Result<(), Self::Error> {
            Err(())
        }
        fn write_guest(&mut self, _address: u64, _input: &[u8]) -> Result<(), Self::Error> {
            Err(())
        }
        fn inject_interrupt(&mut self, _vcpu: u32, _vector: u8) -> Result<(), Self::Error> {
            Err(())
        }
    }

    impl RevocableVmBackend for CleanupBackend {
        fn revoke_guest_mapping(&mut self, address: u64, bytes: u64) -> Result<(), Self::Error> {
            self.calls[self.count] = (address, bytes);
            self.count += 1;
            if self.fail { Err(()) } else { Ok(()) }
        }
    }

    fn tasks() -> (TaskId, TaskId) {
        let mut scheduler = KernelScheduler::<2>::new(1_000, 1).unwrap();
        (
            scheduler.create(Priority::NORMAL).unwrap(),
            scheduler.create(Priority::NORMAL).unwrap(),
        )
    }

    const OBJECT: ObjectId = ObjectId(17);

    fn vm() -> VmId {
        VmTable::<1>::new().create(4).unwrap()
    }

    fn mapped() -> (GuestMemory<2>, GuestMappingId) {
        let mut memory = GuestMemory::new();
        let mapping = memory
            .map(GuestRegion::new(0x4000, PhysAddr::new(0x8000).unwrap(), 1, true, false).unwrap())
            .unwrap();
        (memory, mapping)
    }

    #[test]
    fn binding_requires_exact_authority_and_live_mapping() {
        let vm = vm();
        let (mut memory, mapping) = mapped();
        let rights = Rights::MAP
            .union(Rights::READ)
            .union(Rights::WRITE)
            .union(Rights::CONTROL);
        let mut capabilities = CapabilitySpace::<2>::new();
        let authority = capabilities.insert(OBJECT, rights).unwrap();
        let mut bindings = SharedMemoryBindings::<2>::new();
        let handle = HostResourceHandle::new(91).unwrap();
        let id = bindings
            .bind(
                &capabilities,
                authority,
                &memory,
                SharedEndpoint::new(vm, mapping, SharedAccess::ReadWrite),
                handle,
            )
            .unwrap();
        assert_eq!(
            bindings.resolve(
                id,
                &capabilities,
                authority,
                &memory,
                SharedEndpoint::new(vm, mapping, SharedAccess::ReadWrite),
            ),
            Ok(handle)
        );
        memory.unmap(mapping).unwrap();
        assert_eq!(
            bindings.resolve(
                id,
                &capabilities,
                authority,
                &memory,
                SharedEndpoint::new(vm, mapping, SharedAccess::ReadOnly),
            ),
            Err(SharedBindingError::StaleMapping)
        );
    }

    #[test]
    fn rejects_aliases_attenuation_and_stale_binding_reuse() {
        let mut vms = VmTable::<2>::new();
        let first_vm = vms.create(4).unwrap();
        let second_vm = vms.create(4).unwrap();
        let (memory, mapping) = mapped();
        let mut capabilities = CapabilitySpace::<3>::new();
        let root = capabilities
            .insert(
                OBJECT,
                Rights::MAP
                    .union(Rights::READ)
                    .union(Rights::WRITE)
                    .union(Rights::CONTROL),
            )
            .unwrap();
        let read = capabilities
            .insert(ObjectId(17), Rights::MAP.union(Rights::READ))
            .unwrap();
        let wrong = capabilities
            .insert(ObjectId(18), Rights::MAP.union(Rights::READ))
            .unwrap();
        let mut bindings = SharedMemoryBindings::<1>::new();
        let handle = HostResourceHandle::new(7).unwrap();
        let id = bindings
            .bind(
                &capabilities,
                root,
                &memory,
                SharedEndpoint::new(first_vm, mapping, SharedAccess::ReadWrite),
                handle,
            )
            .unwrap();
        assert_eq!(
            bindings.resolve(
                id,
                &capabilities,
                read,
                &memory,
                SharedEndpoint::new(first_vm, mapping, SharedAccess::ReadWrite),
            ),
            Err(SharedBindingError::Capability(
                CapabilityError::PermissionDenied
            ))
        );
        assert_eq!(
            bindings.resolve(
                id,
                &capabilities,
                wrong,
                &memory,
                SharedEndpoint::new(first_vm, mapping, SharedAccess::ReadOnly),
            ),
            Err(SharedBindingError::WrongObject)
        );
        assert_eq!(
            bindings.resolve(
                id,
                &capabilities,
                read,
                &memory,
                SharedEndpoint::new(second_vm, mapping, SharedAccess::ReadOnly),
            ),
            Err(SharedBindingError::WrongVm)
        );
        assert_eq!(
            bindings.revoke(id, &capabilities, root),
            Ok(SharedRevocation {
                handle,
                last_endpoint: true,
            })
        );
        let replacement = bindings
            .bind(
                &capabilities,
                root,
                &memory,
                SharedEndpoint::new(first_vm, mapping, SharedAccess::ReadOnly),
                HostResourceHandle::new(8).unwrap(),
            )
            .unwrap();
        assert_ne!(id, replacement);
        assert_eq!(
            bindings.resolve(
                replacement,
                &capabilities,
                root,
                &memory,
                SharedEndpoint::new(first_vm, mapping, SharedAccess::ReadWrite),
            ),
            Err(SharedBindingError::AccessDenied)
        );
        assert_eq!(
            bindings.resolve(
                id,
                &capabilities,
                read,
                &memory,
                SharedEndpoint::new(first_vm, mapping, SharedAccess::ReadOnly),
            ),
            Err(SharedBindingError::StaleBinding)
        );
    }

    #[test]
    fn rejects_zero_and_duplicate_host_resources() {
        assert_eq!(
            HostResourceHandle::new(0),
            Err(SharedBindingError::InvalidHostHandle)
        );
        let vm = vm();
        let (memory, mapping) = mapped();
        let mut capabilities = CapabilitySpace::<1>::new();
        let authority = capabilities
            .insert(OBJECT, Rights::MAP.union(Rights::READ))
            .unwrap();
        let mut bindings = SharedMemoryBindings::<2>::new();
        let handle = HostResourceHandle::new(4).unwrap();
        bindings
            .bind(
                &capabilities,
                authority,
                &memory,
                SharedEndpoint::new(vm, mapping, SharedAccess::ReadOnly),
                handle,
            )
            .unwrap();
        assert_eq!(
            bindings.bind(
                &capabilities,
                authority,
                &memory,
                SharedEndpoint::new(vm, mapping, SharedAccess::ReadOnly),
                handle,
            ),
            Err(SharedBindingError::DuplicateHostHandle)
        );
        assert_eq!(
            bindings.bind(
                &capabilities,
                authority,
                &memory,
                SharedEndpoint::new(vm, mapping, SharedAccess::ReadOnly),
                HostResourceHandle::new(5).unwrap(),
            ),
            Err(SharedBindingError::DuplicateMapping)
        );
    }

    #[test]
    fn multi_party_share_attenuates_access_and_releases_handle_only_at_last_endpoint() {
        let mut vms = VmTable::<2>::new();
        let owner_vm = vms.create(4).unwrap();
        let peer_vm = vms.create(4).unwrap();
        let (owner_memory, owner_mapping) = mapped();
        let (peer_memory, peer_mapping) = mapped();
        let mut mismatched_memory = GuestMemory::<1>::new();
        let mismatched_mapping = mismatched_memory
            .map(GuestRegion::new(0x5000, PhysAddr::new(0x9000).unwrap(), 1, false, false).unwrap())
            .unwrap();
        let mut owner_capabilities = CapabilitySpace::<1>::new();
        let owner = owner_capabilities
            .insert(
                OBJECT,
                Rights::MAP
                    .union(Rights::READ)
                    .union(Rights::WRITE)
                    .union(Rights::CONTROL),
            )
            .unwrap();
        let mut peer_capabilities = CapabilitySpace::<2>::new();
        let peer_read = peer_capabilities
            .insert(OBJECT, Rights::MAP.union(Rights::READ))
            .unwrap();
        let peer_write = peer_capabilities
            .insert(OBJECT, Rights::MAP.union(Rights::READ).union(Rights::WRITE))
            .unwrap();
        let handle = HostResourceHandle::new(0x55).unwrap();
        let mut bindings = SharedMemoryBindings::<3>::new();
        let owner_binding = bindings
            .bind(
                &owner_capabilities,
                owner,
                &owner_memory,
                SharedEndpoint::new(owner_vm, owner_mapping, SharedAccess::ReadWrite),
                handle,
            )
            .unwrap();
        let peer_binding = bindings
            .share(
                owner_binding,
                &owner_capabilities,
                owner,
                SharedEndpointRequest::new(
                    &peer_capabilities,
                    peer_read,
                    &peer_memory,
                    SharedEndpoint::new(peer_vm, peer_mapping, SharedAccess::ReadOnly),
                ),
            )
            .unwrap();
        assert_eq!(
            bindings.share(
                owner_binding,
                &owner_capabilities,
                owner,
                SharedEndpointRequest::new(
                    &peer_capabilities,
                    peer_read,
                    &mismatched_memory,
                    SharedEndpoint::new(peer_vm, mismatched_mapping, SharedAccess::ReadOnly),
                ),
            ),
            Err(SharedBindingError::ResourceMismatch)
        );
        assert_eq!(
            bindings.resolve(
                peer_binding,
                &peer_capabilities,
                peer_read,
                &peer_memory,
                SharedEndpoint::new(peer_vm, peer_mapping, SharedAccess::ReadOnly),
            ),
            Ok(handle)
        );
        assert_eq!(
            bindings.share(
                peer_binding,
                &owner_capabilities,
                owner,
                SharedEndpointRequest::new(
                    &peer_capabilities,
                    peer_write,
                    &peer_memory,
                    SharedEndpoint::new(peer_vm, owner_mapping, SharedAccess::ReadWrite),
                ),
            ),
            Err(SharedBindingError::AccessDenied)
        );

        assert_eq!(
            bindings.revoke(owner_binding, &owner_capabilities, owner),
            Ok(SharedRevocation {
                handle,
                last_endpoint: false,
            })
        );
        assert_eq!(
            bindings.resolve(
                owner_binding,
                &owner_capabilities,
                owner,
                &owner_memory,
                SharedEndpoint::new(owner_vm, owner_mapping, SharedAccess::ReadOnly),
            ),
            Err(SharedBindingError::StaleBinding)
        );
        assert_eq!(
            bindings.resolve(
                peer_binding,
                &peer_capabilities,
                peer_read,
                &peer_memory,
                SharedEndpoint::new(peer_vm, peer_mapping, SharedAccess::ReadOnly),
            ),
            Ok(handle)
        );
        assert_eq!(
            bindings.revoke(peer_binding, &owner_capabilities, owner),
            Ok(SharedRevocation {
                handle,
                last_endpoint: true,
            })
        );
    }

    #[test]
    fn task_cleanup_revokes_native_mapping_and_preserves_peer_endpoint() {
        let (owner_task, peer_task) = tasks();
        let mut vms = VmTable::<2>::new();
        let owner_vm = vms.create(4).unwrap();
        let peer_vm = vms.create(4).unwrap();
        let (mut owner_memory, owner_mapping) = mapped();
        let (mut peer_memory, peer_mapping) = mapped();
        let mut owner_capabilities = CapabilitySpace::<1>::new();
        let owner = owner_capabilities
            .insert(
                OBJECT,
                Rights::MAP
                    .union(Rights::READ)
                    .union(Rights::WRITE)
                    .union(Rights::CONTROL),
            )
            .unwrap();
        let mut peer_capabilities = CapabilitySpace::<1>::new();
        let peer = peer_capabilities
            .insert(OBJECT, Rights::MAP.union(Rights::READ))
            .unwrap();
        let handle = HostResourceHandle::new(0x91).unwrap();
        let mut bindings = SharedMemoryBindings::<2>::new();
        let owner_binding = bindings
            .bind(
                &owner_capabilities,
                owner,
                &owner_memory,
                SharedEndpoint::for_task(
                    owner_vm,
                    owner_task,
                    owner_mapping,
                    SharedAccess::ReadWrite,
                ),
                handle,
            )
            .unwrap();
        let peer_binding = bindings
            .share(
                owner_binding,
                &owner_capabilities,
                owner,
                SharedEndpointRequest::new(
                    &peer_capabilities,
                    peer,
                    &peer_memory,
                    SharedEndpoint::for_task(
                        peer_vm,
                        peer_task,
                        peer_mapping,
                        SharedAccess::ReadOnly,
                    ),
                ),
            )
            .unwrap();

        let mut backend = CleanupBackend {
            fail: false,
            calls: [(0, 0); 2],
            count: 0,
        };
        let report = revoke_task_shared_bindings_before_resume(
            &mut backend,
            &mut owner_memory,
            &mut bindings,
            owner_task,
        )
        .unwrap();
        assert_eq!(backend.calls[0], (0x4000, crate::PAGE_SIZE));
        assert_eq!(report.len(), 1);
        assert!(!report.get(0).unwrap().is_last_endpoint());
        assert_eq!(
            owner_memory.region(owner_mapping),
            Err(crate::VmError::StaleMapping)
        );
        assert_eq!(
            bindings.resolve(
                peer_binding,
                &peer_capabilities,
                peer,
                &peer_memory,
                SharedEndpoint::for_task(peer_vm, peer_task, peer_mapping, SharedAccess::ReadOnly),
            ),
            Ok(handle)
        );
        assert_eq!(
            bindings.resolve(
                peer_binding,
                &peer_capabilities,
                peer,
                &peer_memory,
                SharedEndpoint::for_task(
                    peer_vm,
                    owner_task,
                    peer_mapping,
                    SharedAccess::ReadOnly,
                ),
            ),
            Err(SharedBindingError::WrongTask)
        );

        let final_report = revoke_task_shared_bindings_before_resume(
            &mut backend,
            &mut peer_memory,
            &mut bindings,
            peer_task,
        )
        .unwrap();
        assert!(final_report.get(0).unwrap().is_last_endpoint());
    }

    #[test]
    fn failed_native_task_cleanup_keeps_mapping_and_binding_live() {
        let (task, _) = tasks();
        let vm = vm();
        let (mut memory, mapping) = mapped();
        let mut capabilities = CapabilitySpace::<1>::new();
        let authority = capabilities
            .insert(
                OBJECT,
                Rights::MAP.union(Rights::READ).union(Rights::CONTROL),
            )
            .unwrap();
        let endpoint = SharedEndpoint::for_task(vm, task, mapping, SharedAccess::ReadOnly);
        let handle = HostResourceHandle::new(0x92).unwrap();
        let mut bindings = SharedMemoryBindings::<1>::new();
        let binding = bindings
            .bind(&capabilities, authority, &memory, endpoint, handle)
            .unwrap();
        let mut backend = CleanupBackend {
            fail: true,
            calls: [(0, 0); 2],
            count: 0,
        };
        assert_eq!(
            revoke_task_shared_bindings_before_resume(
                &mut backend,
                &mut memory,
                &mut bindings,
                task,
            ),
            Err(SharedCleanupError::Mapping(
                MappingRevocationError::Backend(())
            ))
        );
        assert!(memory.region(mapping).is_ok());
        assert_eq!(
            bindings.resolve(binding, &capabilities, authority, &memory, endpoint),
            Ok(handle)
        );
    }

    #[test]
    fn composite_cleanup_retains_handle_report_across_erasure_retry() {
        let (task, _) = tasks();
        let vm = vm();
        let (mut memory, mapping) = mapped();
        let mut capabilities = CapabilitySpace::<1>::new();
        let authority = capabilities
            .insert(
                OBJECT,
                Rights::MAP.union(Rights::READ).union(Rights::CONTROL),
            )
            .unwrap();
        let endpoint = SharedEndpoint::for_task(vm, task, mapping, SharedAccess::ReadOnly);
        let mut bindings = SharedMemoryBindings::<1>::new();
        bindings
            .bind(
                &capabilities,
                authority,
                &memory,
                endpoint,
                HostResourceHandle::new(0xa1).unwrap(),
            )
            .unwrap();
        let mut backend = CleanupBackend {
            fail: false,
            calls: [(0, 0); 2],
            count: 0,
        };
        let mut address_space = RetryEraser { calls: 0 };
        let mut resources = RetryRetirer { calls: 0 };
        let context = crate::arch::x86_64::UserContext::new(
            PhysAddr::new(0x20_0000).unwrap(),
            0x40_0000,
            0x7000_0000,
        )
        .unwrap();
        let mut eraser = ServiceResourceEraser::new(
            &mut address_space,
            &mut resources,
            &mut backend,
            &mut memory,
            &mut bindings,
        );
        assert_eq!(
            eraser.erase(task, context),
            Err(ServiceResourceCleanupError::HostResource(()))
        );
        assert_eq!(eraser.report().len(), 1);
        assert!(eraser.report().get(0).unwrap().is_last_endpoint());
        assert_eq!(
            eraser.erase(task, context),
            Err(ServiceResourceCleanupError::AddressSpace(()))
        );
        assert_eq!(eraser.erase(task, context), Ok(()));
        assert_eq!(eraser.report().len(), 1);
    }

    #[test]
    fn supervised_recovery_completes_native_shared_cleanup_before_returning_peer() {
        let context =
            UserContext::new(PhysAddr::new(0x20_0000).unwrap(), 0x40_0000, 0x7000_0000).unwrap();
        let mut runtime = TaskRuntime::<3, 0>::new(1_000, 1).unwrap();
        let faulted = runtime.create(Priority::NORMAL, context).unwrap();
        let observer = runtime
            .create(
                Priority::NORMAL,
                UserContext::new(PhysAddr::new(0x30_0000).unwrap(), 0x50_0000, 0x7100_0000)
                    .unwrap(),
            )
            .unwrap();
        assert!(matches!(runtime.start(), ScheduleOutcome::Switch { to, .. } if to == faulted));
        let mut supervisor = ServiceSupervisor::<1>::new();
        let object = ObjectId(0xa5);
        let service = supervisor.register(object, faulted).unwrap();
        let mut management = CapabilitySpace::<1>::new();
        let control = management.insert(object, Rights::CONTROL).unwrap();

        let vm = vm();
        let (mut memory, mapping) = mapped();
        let mut binding_authority = CapabilitySpace::<1>::new();
        let authority = binding_authority
            .insert(object, Rights::MAP.union(Rights::READ))
            .unwrap();
        let endpoint = SharedEndpoint::for_task(vm, faulted, mapping, SharedAccess::ReadOnly);
        let handle = HostResourceHandle::new(0xa6).unwrap();
        let mut bindings = SharedMemoryBindings::<1>::new();
        let binding = bindings
            .bind(&binding_authority, authority, &memory, endpoint, handle)
            .unwrap();
        let mut backend = CleanupBackend {
            fail: false,
            calls: [(0, 0); 2],
            count: 0,
        };
        // These retry fakes succeed on their second call. Starting at one
        // makes this test exercise the successful composite path.
        let mut address_space = RetryEraser { calls: 1 };
        let mut resources = RetryRetirer { calls: 1 };
        let recovery = {
            let mut eraser = ServiceResourceEraser::new(
                &mut address_space,
                &mut resources,
                &mut backend,
                &mut memory,
                &mut bindings,
            );
            supervisor
                .recover_current_fault(
                    &mut runtime,
                    TrapDisposition::TerminateUser {
                        vector: 14,
                        address: Some(0xbeef),
                    },
                    0,
                    &mut eraser,
                    &management,
                    control,
                    Priority::NORMAL,
                )
                .unwrap()
        };

        assert_eq!(recovery.retired, service);
        assert!(matches!(recovery.next, ScheduleOutcome::Switch { to, .. } if to == observer));
        assert_eq!(runtime.current(), Some(observer));
        assert_eq!(backend.calls[0], (0x4000, crate::PAGE_SIZE));
        assert_eq!(memory.region(mapping), Err(crate::VmError::StaleMapping));
        assert_eq!(
            bindings.resolve(binding, &binding_authority, authority, &memory, endpoint),
            Err(SharedBindingError::StaleBinding)
        );
        assert_eq!(resources.calls, 2);
        assert_eq!(address_space.calls, 2);
        assert_eq!(
            supervisor.state(recovery.replacement),
            Ok(crate::ServiceState::Running)
        );
    }

    #[test]
    fn shared_data_rejects_executable_or_insufficient_native_mapping_permissions() {
        let vm = vm();
        let mut memory = GuestMemory::<2>::new();
        let read_only = memory
            .map(GuestRegion::new(0x4000, PhysAddr::new(0x8000).unwrap(), 1, false, false).unwrap())
            .unwrap();
        let executable = memory
            .map(GuestRegion::new(0x5000, PhysAddr::new(0x9000).unwrap(), 1, false, true).unwrap())
            .unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let authority = capabilities
            .insert(OBJECT, Rights::MAP.union(Rights::READ).union(Rights::WRITE))
            .unwrap();
        let mut bindings = SharedMemoryBindings::<1>::new();
        assert_eq!(
            bindings.bind(
                &capabilities,
                authority,
                &memory,
                SharedEndpoint::new(vm, read_only, SharedAccess::ReadWrite),
                HostResourceHandle::new(1).unwrap(),
            ),
            Err(SharedBindingError::AccessDenied)
        );
        assert_eq!(
            bindings.bind(
                &capabilities,
                authority,
                &memory,
                SharedEndpoint::new(vm, executable, SharedAccess::ReadOnly),
                HostResourceHandle::new(2).unwrap(),
            ),
            Err(SharedBindingError::ExecutableMapping)
        );
    }
}
