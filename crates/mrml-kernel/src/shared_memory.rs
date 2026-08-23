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
    SequenceExhausted,
    Capability(CapabilityError),
}

impl From<CapabilityError> for SharedBindingError {
    fn from(value: CapabilityError) -> Self {
        Self::Capability(value)
    }
}

#[derive(Clone, Copy)]
struct Binding {
    generation: u32,
    vm: VmId,
    mapping: GuestMappingId,
    object: ObjectId,
    handle: HostResourceHandle,
    access: SharedAccess,
}

/// Fixed-capacity binding between one live guest mapping and one opaque host
/// resource. The token is never placed in guest memory. Every resolution
/// repeats capability, VM, mapping-identity, and liveness checks.
pub struct SharedMemoryBindings<const N: usize> {
    entries: [Option<Binding>; N],
    generations: [u32; N],
}

impl<const N: usize> SharedMemoryBindings<N> {
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            generations: [0; N],
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
        memory
            .region(endpoint.mapping)
            .map_err(|_| SharedBindingError::StaleMapping)?;
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
        let generation = self.generations[index]
            .checked_add(1)
            .ok_or(SharedBindingError::SequenceExhausted)?;
        self.generations[index] = generation;
        self.entries[index] = Some(Binding {
            generation,
            vm: endpoint.vm,
            mapping: endpoint.mapping,
            object,
            handle,
            access: endpoint.access,
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
        memory
            .region(endpoint.mapping)
            .map_err(|_| SharedBindingError::StaleMapping)?;
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
    ) -> Result<HostResourceHandle, SharedBindingError> {
        let object = capabilities.authorize(authority, Rights::CONTROL)?;
        let entry = *self.entry(id)?;
        if object != entry.object {
            return Err(SharedBindingError::WrongObject);
        }
        self.entries[id.index()] = None;
        Ok(entry.handle)
    }

    fn entry(&self, id: SharedBindingId) -> Result<&Binding, SharedBindingError> {
        self.entries
            .get(id.index())
            .and_then(Option::as_ref)
            .filter(|entry| entry.generation == id.generation())
            .ok_or(SharedBindingError::StaleBinding)
    }
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
        assert_eq!(bindings.revoke(id, &capabilities, root), Ok(handle));
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
}
