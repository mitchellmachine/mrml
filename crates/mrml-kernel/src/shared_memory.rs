use crate::{
    Capability, CapabilityError, CapabilitySpace, GuestMappingId, GuestMemory, ObjectId, Rights,
    VmId,
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
    mapping: GuestMappingId,
    access: SharedAccess,
}

impl SharedEndpoint {
    pub const fn new(vm: VmId, mapping: GuestMappingId, access: SharedAccess) -> Self {
        Self {
            vm,
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

    fn entry(&self, id: SharedBindingId) -> Result<&Binding, SharedBindingError> {
        self.entries
            .get(id.index())
            .and_then(Option::as_ref)
            .filter(|entry| entry.generation == id.generation())
            .ok_or(SharedBindingError::StaleBinding)
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
    use crate::{GuestRegion, PhysAddr, VmTable};

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
