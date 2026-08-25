use core::array;

use crate::{Capability, CapabilityError, CapabilitySpace, ObjectId, PAGE_SIZE, PhysAddr, Rights};

const POOL_RIGHTS: Rights = Rights::ALLOCATE
    .union(Rights::DELEGATE)
    .union(Rights::CONTROL)
    .union(Rights::MAP)
    .union(Rights::SHARE)
    .union(Rights::PIN)
    .union(Rights::INSPECT);
const OBJECT_RIGHTS: Rights = Rights::READ
    .union(Rights::WRITE)
    .union(Rights::EXECUTE)
    .union(Rights::MAP)
    .union(Rights::SHARE)
    .union(Rights::PIN)
    .union(Rights::INSPECT)
    .union(Rights::DELEGATE)
    .union(Rights::CONTROL);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryPoolId {
    slot: u16,
    generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryObjectId {
    slot: u16,
    generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryMappingId {
    slot: u16,
    generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryMapping {
    object: MemoryObjectId,
    virtual_page: u64,
    object_page: u64,
    pages: u64,
    access: Rights,
}

impl MemoryMapping {
    pub const fn object(self) -> MemoryObjectId {
        self.object
    }
    pub const fn virtual_page(self) -> u64 {
        self.virtual_page
    }
    pub const fn object_page(self) -> u64 {
        self.object_page
    }
    pub const fn pages(self) -> u64 {
        self.pages
    }
    pub const fn access(self) -> Rights {
        self.access
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryMappingBackendRequest {
    mapping: MemoryMapping,
    target: ObjectId,
    physical: Option<MemoryPhysicalBacking>,
}

impl MemoryMappingBackendRequest {
    pub const fn mapping(self) -> MemoryMapping {
        self.mapping
    }
    pub const fn target(self) -> ObjectId {
        self.target
    }
    pub const fn physical(self) -> Option<MemoryPhysicalBacking> {
        self.physical
    }
}

/// Privileged adapter for one exact native mapping implementation.
///
/// # Safety
///
/// `install` may return success only after the exact request is usable with no
/// broader access; failure must leave no usable part of the requested mapping.
/// `remove` may return success only after the exact mapping is absent and all
/// required CPU, device, VMM, and translation-cache invalidation is complete.
/// Failure must retain the mapping or fail-stop every consumer. The request is
/// validated data and never substitutes for the capabilities checked by the
/// policy table before either call.
pub unsafe trait MemoryMappingBackend {
    type Error;

    fn install(&mut self, request: MemoryMappingBackendRequest) -> Result<(), Self::Error>;
    fn remove(&mut self, request: MemoryMappingBackendRequest) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryMappingOperationError<E> {
    Policy(MemoryResourceError),
    Backend(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryBackingKind {
    Anonymous,
    Shared,
    Guest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryPhysicalBacking {
    start: PhysAddr,
    pages: u64,
}

impl MemoryPhysicalBacking {
    pub const fn new(start: PhysAddr, pages: u64) -> Result<Self, MemoryResourceError> {
        if pages == 0 {
            return Err(MemoryResourceError::InvalidPhysicalBacking);
        }
        let bytes = match pages.checked_mul(PAGE_SIZE) {
            Some(bytes) => bytes,
            None => return Err(MemoryResourceError::Arithmetic),
        };
        if start.get().checked_add(bytes).is_none() {
            return Err(MemoryResourceError::Arithmetic);
        }
        Ok(Self { start, pages })
    }
    pub const fn start(self) -> PhysAddr {
        self.start
    }
    pub const fn pages(self) -> u64 {
        self.pages
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryBackingBackendRequest {
    object: MemoryObjectId,
    physical: MemoryPhysicalBacking,
    kind: MemoryBackingKind,
}

impl MemoryBackingBackendRequest {
    pub const fn object(self) -> MemoryObjectId {
        self.object
    }
    pub const fn physical(self) -> MemoryPhysicalBacking {
        self.physical
    }
    pub const fn kind(self) -> MemoryBackingKind {
        self.kind
    }
}

/// Privileged adapter that owns allocation, zeroing, scrubbing, and release of
/// exact physical backing.
///
/// # Safety
///
/// `claim_zeroed` may succeed only when the exact physical run is exclusively
/// reserved for the object, contains no prior data, and has no CPU/device/VMM
/// alias. Failure must leave it unclaimed. `release_scrubbed` may succeed only
/// after every external mapping and DMA path is revoked, all invalidations are
/// complete, the entire run is scrubbed, and the run is safe for reuse. Failure
/// must retain exclusive ownership or fail-stop all consumers. The request is
/// validated data, not authority.
pub unsafe trait MemoryObjectBackingBackend {
    type Error;

    fn claim_zeroed(&mut self, request: MemoryBackingBackendRequest) -> Result<(), Self::Error>;
    fn release_scrubbed(&mut self, request: MemoryBackingBackendRequest)
    -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryBackingOperationError<E> {
    Policy(MemoryResourceError),
    Backend(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryUsage {
    limit_pages: u64,
    object_pages: u64,
    child_reserved_pages: u64,
    mapping_limit: u32,
    child_mapping_reservations: u32,
    active_mappings: u32,
    active_children: u16,
    child_limit: u16,
    live_objects: u32,
}

impl MemoryUsage {
    pub const fn limit_pages(self) -> u64 {
        self.limit_pages
    }
    pub const fn committed_pages(self) -> u64 {
        self.object_pages + self.child_reserved_pages
    }
    pub const fn object_pages(self) -> u64 {
        self.object_pages
    }
    pub const fn child_reserved_pages(self) -> u64 {
        self.child_reserved_pages
    }
    pub const fn available_pages(self) -> u64 {
        self.limit_pages - self.committed_pages()
    }
    pub const fn mapping_limit(self) -> u32 {
        self.mapping_limit
    }
    pub const fn child_mapping_reservations(self) -> u32 {
        self.child_mapping_reservations
    }
    pub const fn active_mappings(self) -> u32 {
        self.active_mappings
    }
    pub const fn active_children(self) -> u16 {
        self.active_children
    }
    pub const fn child_limit(self) -> u16 {
        self.child_limit
    }
    pub const fn live_objects(self) -> u32 {
        self.live_objects
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryRevocationSummary {
    pools: u32,
    objects: u32,
    pages: u64,
}

impl MemoryRevocationSummary {
    pub const fn pools(self) -> u32 {
        self.pools
    }
    pub const fn objects(self) -> u32 {
        self.objects
    }
    pub const fn pages(self) -> u64 {
        self.pages
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryResourceError {
    InvalidNamespace,
    InvalidLimit,
    InvalidRights,
    CapacityExhausted,
    PoolExhausted,
    MappingLimitExceeded,
    ChildLimitExceeded,
    InvalidPool,
    InvalidObject,
    WrongPool,
    InvalidMapping,
    MappingOverlap,
    MappingsActive,
    ObjectRange,
    InvalidPhysicalBacking,
    PhysicalBackingActive,
    PhysicalBackingAbsent,
    PhysicalOverlap,
    GenerationExhausted,
    Arithmetic,
    Capability(CapabilityError),
}

impl From<CapabilityError> for MemoryResourceError {
    fn from(value: CapabilityError) -> Self {
        Self::Capability(value)
    }
}

#[derive(Clone, Copy)]
struct PoolEntry {
    generation: u32,
    authority: ObjectId,
    parent: Option<MemoryPoolId>,
    limit_pages: u64,
    object_pages: u64,
    child_reserved_pages: u64,
    mapping_limit: u32,
    child_mapping_reservations: u32,
    active_mappings: u32,
    child_limit: u16,
    active_children: u16,
    live_objects: u32,
    occupied: bool,
}

impl PoolEntry {
    const EMPTY: Self = Self {
        generation: 1,
        authority: ObjectId(0),
        parent: None,
        limit_pages: 0,
        object_pages: 0,
        child_reserved_pages: 0,
        mapping_limit: 0,
        child_mapping_reservations: 0,
        active_mappings: 0,
        child_limit: 0,
        active_children: 0,
        live_objects: 0,
        occupied: false,
    };

    const fn committed_pages(self) -> Option<u64> {
        self.object_pages.checked_add(self.child_reserved_pages)
    }
}

#[derive(Clone, Copy)]
struct ObjectEntry {
    generation: u32,
    authority: ObjectId,
    pool: MemoryPoolId,
    pages: u64,
    backing: MemoryBackingKind,
    physical: Option<MemoryPhysicalBacking>,
    occupied: bool,
}

#[derive(Clone, Copy)]
struct MappingEntry {
    generation: u32,
    object: MemoryObjectId,
    target: ObjectId,
    virtual_page: u64,
    object_page: u64,
    pages: u64,
    access: Rights,
    physical: Option<MemoryPhysicalBacking>,
    occupied: bool,
}

#[derive(Clone, Copy)]
struct PreparedMapping {
    slot: usize,
    entry: MappingEntry,
    pool: MemoryPoolId,
    next_active_mappings: u32,
}

impl MappingEntry {
    const EMPTY: Self = Self {
        generation: 1,
        object: MemoryObjectId {
            slot: 0,
            generation: 0,
        },
        target: ObjectId(0),
        virtual_page: 0,
        object_page: 0,
        pages: 0,
        access: Rights::NONE,
        physical: None,
        occupied: false,
    };
}

impl ObjectEntry {
    const EMPTY: Self = Self {
        generation: 1,
        authority: ObjectId(0),
        pool: MemoryPoolId {
            slot: 0,
            generation: 0,
        },
        pages: 0,
        backing: MemoryBackingKind::Anonymous,
        physical: None,
        occupied: false,
    };
}

/// Fixed-capacity quantitative memory authority and commitment accounting.
///
/// This policy core records commitments and mapping reservations; it does not
/// allocate frames, edit page tables, or grant hardware mappings. Those later
/// operations must consume the exact object plus separate target authority and
/// retain the reservation until teardown and invalidation complete.
pub struct MemoryPoolTable<const P: usize, const O: usize, const M: usize = O> {
    namespace: u16,
    pools: [PoolEntry; P],
    objects: [ObjectEntry; O],
    mappings: [MappingEntry; M],
}

impl<const P: usize, const O: usize, const M: usize> MemoryPoolTable<P, O, M> {
    pub fn new(namespace: u16) -> Result<Self, MemoryResourceError> {
        if namespace == 0
            || namespace > 0x7fff
            || P == 0
            || O == 0
            || M == 0
            || P > u16::MAX as usize
            || O > u16::MAX as usize
            || M > u16::MAX as usize
        {
            return Err(MemoryResourceError::InvalidNamespace);
        }
        Ok(Self {
            namespace,
            pools: array::from_fn(|_| PoolEntry::EMPTY),
            objects: array::from_fn(|_| ObjectEntry::EMPTY),
            mappings: array::from_fn(|_| MappingEntry::EMPTY),
        })
    }

    pub fn create_root<const C: usize>(
        &mut self,
        limit_pages: u64,
        mapping_limit: u32,
        child_limit: u16,
        rights: Rights,
        capabilities: &mut CapabilitySpace<C>,
    ) -> Result<(MemoryPoolId, Capability), MemoryResourceError> {
        validate_pool_shape(limit_pages, mapping_limit, rights)?;
        let slot = self.free_pool_slot()?;
        let generation = self.pools[slot].generation;
        let id = MemoryPoolId {
            slot: slot as u16,
            generation,
        };
        let authority = self.pool_authority(id)?;
        let capability = capabilities.insert(authority, rights)?;
        self.pools[slot] = PoolEntry {
            generation,
            authority,
            parent: None,
            limit_pages,
            object_pages: 0,
            child_reserved_pages: 0,
            mapping_limit,
            child_mapping_reservations: 0,
            active_mappings: 0,
            child_limit,
            active_children: 0,
            live_objects: 0,
            occupied: true,
        };
        Ok((id, capability))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn derive_pool<const S: usize, const D: usize>(
        &mut self,
        parent: MemoryPoolId,
        parent_capability: Capability,
        source: &CapabilitySpace<S>,
        limit_pages: u64,
        mapping_limit: u32,
        child_limit: u16,
        rights: Rights,
        destination: &mut CapabilitySpace<D>,
    ) -> Result<(MemoryPoolId, Capability), MemoryResourceError> {
        validate_pool_shape(limit_pages, mapping_limit, rights)?;
        let parent_entry = *self.pool(parent)?;
        source.authorize(parent_capability, rights.union(Rights::DELEGATE))?;
        if source.authorize(parent_capability, Rights::ALLOCATE)? != parent_entry.authority {
            return Err(MemoryResourceError::Capability(
                CapabilityError::PermissionDenied,
            ));
        }
        let committed = parent_entry
            .committed_pages()
            .ok_or(MemoryResourceError::Arithmetic)?;
        let available = parent_entry
            .limit_pages
            .checked_sub(committed)
            .ok_or(MemoryResourceError::Arithmetic)?;
        if limit_pages > available {
            return Err(MemoryResourceError::PoolExhausted);
        }
        if parent_entry.active_children >= parent_entry.child_limit {
            return Err(MemoryResourceError::ChildLimitExceeded);
        }
        let mapping_reservations = parent_entry
            .child_mapping_reservations
            .checked_add(mapping_limit)
            .ok_or(MemoryResourceError::Arithmetic)?;
        let mapping_total = mapping_reservations
            .checked_add(parent_entry.active_mappings)
            .ok_or(MemoryResourceError::Arithmetic)?;
        if mapping_total > parent_entry.mapping_limit {
            return Err(MemoryResourceError::MappingLimitExceeded);
        }
        let slot = self.free_pool_slot()?;
        let generation = self.pools[slot].generation;
        let id = MemoryPoolId {
            slot: slot as u16,
            generation,
        };
        let authority = self.pool_authority(id)?;
        let capability = destination.insert(authority, rights)?;
        let parent_mut = self.pool_mut(parent)?;
        parent_mut.child_reserved_pages = parent_mut
            .child_reserved_pages
            .checked_add(limit_pages)
            .ok_or(MemoryResourceError::Arithmetic)?;
        parent_mut.child_mapping_reservations = mapping_reservations;
        parent_mut.active_children = parent_mut
            .active_children
            .checked_add(1)
            .ok_or(MemoryResourceError::Arithmetic)?;
        self.pools[slot] = PoolEntry {
            generation,
            authority,
            parent: Some(parent),
            limit_pages,
            object_pages: 0,
            child_reserved_pages: 0,
            mapping_limit,
            child_mapping_reservations: 0,
            active_mappings: 0,
            child_limit,
            active_children: 0,
            live_objects: 0,
            occupied: true,
        };
        Ok((id, capability))
    }

    pub fn allocate_object<const C: usize>(
        &mut self,
        pool: MemoryPoolId,
        pool_capability: Capability,
        pages: u64,
        backing: MemoryBackingKind,
        rights: Rights,
        capabilities: &mut CapabilitySpace<C>,
    ) -> Result<(MemoryObjectId, Capability), MemoryResourceError> {
        if pages == 0 {
            return Err(MemoryResourceError::InvalidLimit);
        }
        if rights.bits() == 0 || !OBJECT_RIGHTS.contains(rights) {
            return Err(MemoryResourceError::InvalidRights);
        }
        let pool_entry = *self.pool(pool)?;
        if capabilities.authorize(pool_capability, Rights::ALLOCATE)? != pool_entry.authority {
            return Err(MemoryResourceError::Capability(
                CapabilityError::PermissionDenied,
            ));
        }
        let committed = pool_entry
            .committed_pages()
            .ok_or(MemoryResourceError::Arithmetic)?;
        let available = pool_entry
            .limit_pages
            .checked_sub(committed)
            .ok_or(MemoryResourceError::Arithmetic)?;
        if pages > available {
            return Err(MemoryResourceError::PoolExhausted);
        }
        let next_object_pages = pool_entry
            .object_pages
            .checked_add(pages)
            .ok_or(MemoryResourceError::Arithmetic)?;
        let next_live_objects = pool_entry
            .live_objects
            .checked_add(1)
            .ok_or(MemoryResourceError::Arithmetic)?;
        let slot = self.free_object_slot()?;
        let generation = self.objects[slot].generation;
        let id = MemoryObjectId {
            slot: slot as u16,
            generation,
        };
        let authority = self.object_authority(id)?;
        let capability = capabilities.insert(authority, rights)?;
        let pool_mut = self.pool_mut(pool)?;
        pool_mut.object_pages = next_object_pages;
        pool_mut.live_objects = next_live_objects;
        self.objects[slot] = ObjectEntry {
            generation,
            authority,
            pool,
            pages,
            backing,
            physical: None,
            occupied: true,
        };
        Ok((id, capability))
    }

    pub fn release_object<const C: usize>(
        &mut self,
        object: MemoryObjectId,
        capability: Capability,
        capabilities: &mut CapabilitySpace<C>,
    ) -> Result<u64, MemoryResourceError> {
        let entry = *self.object(object)?;
        if capabilities.authorize(capability, Rights::CONTROL)? != entry.authority {
            return Err(MemoryResourceError::Capability(
                CapabilityError::PermissionDenied,
            ));
        }
        let next_generation = entry
            .generation
            .checked_add(1)
            .ok_or(MemoryResourceError::GenerationExhausted)?;
        let pool = *self.pool(entry.pool)?;
        let next_pages = pool
            .object_pages
            .checked_sub(entry.pages)
            .ok_or(MemoryResourceError::Arithmetic)?;
        let next_objects = pool
            .live_objects
            .checked_sub(1)
            .ok_or(MemoryResourceError::Arithmetic)?;
        if self
            .mappings
            .iter()
            .any(|mapping| mapping.occupied && mapping.object == object)
        {
            return Err(MemoryResourceError::MappingsActive);
        }
        if entry.physical.is_some() {
            return Err(MemoryResourceError::PhysicalBackingActive);
        }
        capabilities.revoke(capability)?;
        let pool_mut = self.pool_mut(entry.pool)?;
        pool_mut.object_pages = next_pages;
        pool_mut.live_objects = next_objects;
        self.objects[object.slot as usize] = ObjectEntry {
            generation: next_generation,
            ..ObjectEntry::EMPTY
        };
        Ok(entry.pages)
    }

    pub fn bind_physical_backing<B: MemoryObjectBackingBackend, const C: usize>(
        &mut self,
        object: MemoryObjectId,
        capability: Capability,
        physical: MemoryPhysicalBacking,
        capabilities: &CapabilitySpace<C>,
        backend: &mut B,
    ) -> Result<(), MemoryBackingOperationError<B::Error>> {
        let entry = *self
            .object(object)
            .map_err(MemoryBackingOperationError::Policy)?;
        if capabilities
            .authorize(capability, Rights::CONTROL.union(Rights::PIN))
            .map_err(MemoryResourceError::from)
            .map_err(MemoryBackingOperationError::Policy)?
            != entry.authority
        {
            return Err(MemoryBackingOperationError::Policy(
                MemoryResourceError::Capability(CapabilityError::PermissionDenied),
            ));
        }
        if entry.physical.is_some() {
            return Err(MemoryBackingOperationError::Policy(
                MemoryResourceError::PhysicalBackingActive,
            ));
        }
        if physical.pages != entry.pages {
            return Err(MemoryBackingOperationError::Policy(
                MemoryResourceError::InvalidPhysicalBacking,
            ));
        }
        let physical_limit = physical_end(physical).map_err(MemoryBackingOperationError::Policy)?;
        if self.objects.iter().any(|other| {
            other.occupied
                && other.physical.is_some_and(|existing| {
                    physical_end(existing).map_or(true, |existing_end| {
                        ranges_overlap(
                            physical.start.get(),
                            physical_limit,
                            existing.start.get(),
                            existing_end,
                        )
                    })
                })
        }) {
            return Err(MemoryBackingOperationError::Policy(
                MemoryResourceError::PhysicalOverlap,
            ));
        }
        let request = MemoryBackingBackendRequest {
            object,
            physical,
            kind: entry.backing,
        };
        backend
            .claim_zeroed(request)
            .map_err(MemoryBackingOperationError::Backend)?;
        self.objects[object.slot as usize].physical = Some(physical);
        Ok(())
    }

    pub fn release_physical_backing<B: MemoryObjectBackingBackend, const C: usize>(
        &mut self,
        object: MemoryObjectId,
        capability: Capability,
        capabilities: &CapabilitySpace<C>,
        backend: &mut B,
    ) -> Result<MemoryPhysicalBacking, MemoryBackingOperationError<B::Error>> {
        let entry = *self
            .object(object)
            .map_err(MemoryBackingOperationError::Policy)?;
        if capabilities
            .authorize(capability, Rights::CONTROL)
            .map_err(MemoryResourceError::from)
            .map_err(MemoryBackingOperationError::Policy)?
            != entry.authority
        {
            return Err(MemoryBackingOperationError::Policy(
                MemoryResourceError::Capability(CapabilityError::PermissionDenied),
            ));
        }
        if self
            .mappings
            .iter()
            .any(|mapping| mapping.occupied && mapping.object == object)
        {
            return Err(MemoryBackingOperationError::Policy(
                MemoryResourceError::MappingsActive,
            ));
        }
        let physical = entry.physical.ok_or(MemoryBackingOperationError::Policy(
            MemoryResourceError::PhysicalBackingAbsent,
        ))?;
        let request = MemoryBackingBackendRequest {
            object,
            physical,
            kind: entry.backing,
        };
        backend
            .release_scrubbed(request)
            .map_err(MemoryBackingOperationError::Backend)?;
        self.objects[object.slot as usize].physical = None;
        Ok(physical)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reserve_mapping<const C: usize>(
        &mut self,
        object: MemoryObjectId,
        object_capability: Capability,
        target_capability: Capability,
        virtual_page: u64,
        object_page: u64,
        pages: u64,
        access: Rights,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<MemoryMappingId, MemoryResourceError> {
        let prepared = self.prepare_mapping(
            object,
            object_capability,
            target_capability,
            virtual_page,
            object_page,
            pages,
            access,
            capabilities,
        )?;
        Ok(self.commit_mapping(prepared))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn install_mapping<B: MemoryMappingBackend, const C: usize>(
        &mut self,
        object: MemoryObjectId,
        object_capability: Capability,
        target_capability: Capability,
        virtual_page: u64,
        object_page: u64,
        pages: u64,
        access: Rights,
        capabilities: &CapabilitySpace<C>,
        backend: &mut B,
    ) -> Result<MemoryMappingId, MemoryMappingOperationError<B::Error>> {
        let prepared = self
            .prepare_mapping(
                object,
                object_capability,
                target_capability,
                virtual_page,
                object_page,
                pages,
                access,
                capabilities,
            )
            .map_err(MemoryMappingOperationError::Policy)?;
        backend
            .install(mapping_backend_request(prepared.entry))
            .map_err(MemoryMappingOperationError::Backend)?;
        Ok(self.commit_mapping(prepared))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn install_backed_mapping<B: MemoryMappingBackend, const C: usize>(
        &mut self,
        object: MemoryObjectId,
        object_capability: Capability,
        target_capability: Capability,
        virtual_page: u64,
        object_page: u64,
        pages: u64,
        access: Rights,
        capabilities: &CapabilitySpace<C>,
        backend: &mut B,
    ) -> Result<MemoryMappingId, MemoryMappingOperationError<B::Error>> {
        let mut prepared = self
            .prepare_mapping(
                object,
                object_capability,
                target_capability,
                virtual_page,
                object_page,
                pages,
                access,
                capabilities,
            )
            .map_err(MemoryMappingOperationError::Policy)?;
        let backing = self
            .object(object)
            .map_err(MemoryMappingOperationError::Policy)?
            .physical
            .ok_or(MemoryMappingOperationError::Policy(
                MemoryResourceError::PhysicalBackingAbsent,
            ))?;
        let offset =
            object_page
                .checked_mul(PAGE_SIZE)
                .ok_or(MemoryMappingOperationError::Policy(
                    MemoryResourceError::Arithmetic,
                ))?;
        let start =
            backing
                .start
                .get()
                .checked_add(offset)
                .ok_or(MemoryMappingOperationError::Policy(
                    MemoryResourceError::Arithmetic,
                ))?;
        let physical = MemoryPhysicalBacking::new(
            PhysAddr::new(start).map_err(|_| {
                MemoryMappingOperationError::Policy(MemoryResourceError::InvalidPhysicalBacking)
            })?,
            pages,
        )
        .map_err(MemoryMappingOperationError::Policy)?;
        prepared.entry.physical = Some(physical);
        backend
            .install(mapping_backend_request(prepared.entry))
            .map_err(MemoryMappingOperationError::Backend)?;
        Ok(self.commit_mapping(prepared))
    }

    /// Retires one reservation only after its actual page-table/backend mapping
    /// has been removed and every required invalidation has completed.
    ///
    /// # Safety
    ///
    /// The caller must prove that no CPU, device, VMM backend, cached
    /// translation, or peer can still use the represented mapping.
    pub unsafe fn release_mapping<const C: usize>(
        &mut self,
        mapping: MemoryMappingId,
        target_capability: Capability,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<(), MemoryResourceError> {
        let (entry, pool, next_generation, next_mappings) =
            self.prepare_mapping_release(mapping, target_capability, capabilities)?;
        self.commit_mapping_release(mapping, entry, pool, next_generation, next_mappings);
        Ok(())
    }

    pub fn remove_mapping<B: MemoryMappingBackend, const C: usize>(
        &mut self,
        mapping: MemoryMappingId,
        target_capability: Capability,
        capabilities: &CapabilitySpace<C>,
        backend: &mut B,
    ) -> Result<(), MemoryMappingOperationError<B::Error>> {
        let (entry, pool, next_generation, next_mappings) = self
            .prepare_mapping_release(mapping, target_capability, capabilities)
            .map_err(MemoryMappingOperationError::Policy)?;
        backend
            .remove(mapping_backend_request(entry))
            .map_err(MemoryMappingOperationError::Backend)?;
        self.commit_mapping_release(mapping, entry, pool, next_generation, next_mappings);
        Ok(())
    }

    pub fn mapping_info<const C: usize>(
        &self,
        mapping: MemoryMappingId,
        target_capability: Capability,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<MemoryMapping, MemoryResourceError> {
        let entry = *self.mapping(mapping)?;
        if capabilities.authorize(target_capability, Rights::INSPECT)? != entry.target {
            return Err(MemoryResourceError::Capability(
                CapabilityError::PermissionDenied,
            ));
        }
        Ok(MemoryMapping {
            object: entry.object,
            virtual_page: entry.virtual_page,
            object_page: entry.object_page,
            pages: entry.pages,
            access: entry.access,
        })
    }

    pub fn usage<const C: usize>(
        &self,
        pool: MemoryPoolId,
        capability: Capability,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<MemoryUsage, MemoryResourceError> {
        let entry = *self.pool(pool)?;
        if capabilities.authorize(capability, Rights::INSPECT)? != entry.authority {
            return Err(MemoryResourceError::Capability(
                CapabilityError::PermissionDenied,
            ));
        }
        Ok(MemoryUsage {
            limit_pages: entry.limit_pages,
            object_pages: entry.object_pages,
            child_reserved_pages: entry.child_reserved_pages,
            mapping_limit: entry.mapping_limit,
            child_mapping_reservations: entry.child_mapping_reservations,
            active_mappings: entry.active_mappings,
            active_children: entry.active_children,
            child_limit: entry.child_limit,
            live_objects: entry.live_objects,
        })
    }

    pub fn revoke_pool<const C: usize>(
        &mut self,
        pool: MemoryPoolId,
        capability: Capability,
        capabilities: &mut CapabilitySpace<C>,
    ) -> Result<MemoryRevocationSummary, MemoryResourceError> {
        let root = *self.pool(pool)?;
        if capabilities.authorize(capability, Rights::CONTROL)? != root.authority {
            return Err(MemoryResourceError::Capability(
                CapabilityError::PermissionDenied,
            ));
        }
        let mut affected_pools = [false; P];
        for (slot, affected) in affected_pools.iter_mut().enumerate() {
            if self.pools[slot].occupied && self.is_descendant_or_self(slot, pool)? {
                self.pools[slot]
                    .generation
                    .checked_add(1)
                    .ok_or(MemoryResourceError::GenerationExhausted)?;
                *affected = true;
            }
        }
        let mut summary = MemoryRevocationSummary::default();
        let mut affected_objects = [false; O];
        for (slot, affected) in affected_objects.iter_mut().enumerate() {
            let object = self.objects[slot];
            if object.occupied && affected_pools[object.pool.slot as usize] {
                object
                    .generation
                    .checked_add(1)
                    .ok_or(MemoryResourceError::GenerationExhausted)?;
                summary.objects = summary
                    .objects
                    .checked_add(1)
                    .ok_or(MemoryResourceError::Arithmetic)?;
                summary.pages = summary
                    .pages
                    .checked_add(object.pages)
                    .ok_or(MemoryResourceError::Arithmetic)?;
                *affected = true;
            }
        }
        if self
            .objects
            .iter()
            .enumerate()
            .any(|(slot, object)| affected_objects[slot] && object.physical.is_some())
        {
            return Err(MemoryResourceError::PhysicalBackingActive);
        }
        if self
            .mappings
            .iter()
            .any(|mapping| mapping.occupied && affected_objects[mapping.object.slot as usize])
        {
            return Err(MemoryResourceError::MappingsActive);
        }
        summary.pools = u32::try_from(affected_pools.iter().filter(|value| **value).count())
            .map_err(|_| MemoryResourceError::Arithmetic)?;
        let parent_update = if let Some(parent) = root.parent {
            let entry = *self.pool(parent)?;
            Some((
                parent,
                entry
                    .child_reserved_pages
                    .checked_sub(root.limit_pages)
                    .ok_or(MemoryResourceError::Arithmetic)?,
                entry
                    .child_mapping_reservations
                    .checked_sub(root.mapping_limit)
                    .ok_or(MemoryResourceError::Arithmetic)?,
                entry
                    .active_children
                    .checked_sub(1)
                    .ok_or(MemoryResourceError::Arithmetic)?,
            ))
        } else {
            None
        };
        capabilities.revoke(capability)?;
        for (slot, affected) in affected_objects.into_iter().enumerate() {
            if affected {
                let generation = self.objects[slot].generation + 1;
                self.objects[slot] = ObjectEntry {
                    generation,
                    ..ObjectEntry::EMPTY
                };
            }
        }
        for (slot, affected) in affected_pools.into_iter().enumerate() {
            if affected {
                let generation = self.pools[slot].generation + 1;
                self.pools[slot] = PoolEntry {
                    generation,
                    ..PoolEntry::EMPTY
                };
            }
        }
        if let Some((parent, pages, mappings, children)) = parent_update {
            let entry = self.pool_mut(parent)?;
            entry.child_reserved_pages = pages;
            entry.child_mapping_reservations = mappings;
            entry.active_children = children;
        }
        Ok(summary)
    }

    pub fn object_backing(
        &self,
        object: MemoryObjectId,
    ) -> Result<MemoryBackingKind, MemoryResourceError> {
        Ok(self.object(object)?.backing)
    }

    pub fn object_pool(&self, object: MemoryObjectId) -> Result<MemoryPoolId, MemoryResourceError> {
        Ok(self.object(object)?.pool)
    }

    pub fn object_physical_backing<const C: usize>(
        &self,
        object: MemoryObjectId,
        capability: Capability,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<Option<MemoryPhysicalBacking>, MemoryResourceError> {
        let entry = *self.object(object)?;
        if capabilities.authorize(capability, Rights::INSPECT)? != entry.authority {
            return Err(MemoryResourceError::Capability(
                CapabilityError::PermissionDenied,
            ));
        }
        Ok(entry.physical)
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_mapping<const C: usize>(
        &self,
        object: MemoryObjectId,
        object_capability: Capability,
        target_capability: Capability,
        virtual_page: u64,
        object_page: u64,
        pages: u64,
        access: Rights,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<PreparedMapping, MemoryResourceError> {
        let allowed_access = Rights::READ.union(Rights::WRITE).union(Rights::EXECUTE);
        if pages == 0
            || access.bits() == 0
            || !allowed_access.contains(access)
            || (access.contains(Rights::WRITE) && access.contains(Rights::EXECUTE))
        {
            return Err(MemoryResourceError::InvalidRights);
        }
        let object_entry = *self.object(object)?;
        if capabilities.authorize(object_capability, Rights::MAP.union(access))?
            != object_entry.authority
        {
            return Err(MemoryResourceError::Capability(
                CapabilityError::PermissionDenied,
            ));
        }
        let target = capabilities.authorize(target_capability, Rights::MAP)?;
        let object_end = object_page
            .checked_add(pages)
            .ok_or(MemoryResourceError::Arithmetic)?;
        if object_end > object_entry.pages {
            return Err(MemoryResourceError::ObjectRange);
        }
        let virtual_end = virtual_page
            .checked_add(pages)
            .ok_or(MemoryResourceError::Arithmetic)?;
        if self.mappings.iter().any(|mapping| {
            mapping.occupied
                && mapping.target == target
                && ranges_overlap(
                    virtual_page,
                    virtual_end,
                    mapping.virtual_page,
                    mapping.virtual_page + mapping.pages,
                )
        }) {
            return Err(MemoryResourceError::MappingOverlap);
        }
        let pool = *self.pool(object_entry.pool)?;
        let next_active_mappings = pool
            .active_mappings
            .checked_add(1)
            .ok_or(MemoryResourceError::Arithmetic)?;
        let used = pool
            .child_mapping_reservations
            .checked_add(next_active_mappings)
            .ok_or(MemoryResourceError::Arithmetic)?;
        if used > pool.mapping_limit {
            return Err(MemoryResourceError::MappingLimitExceeded);
        }
        let slot = self.free_mapping_slot()?;
        Ok(PreparedMapping {
            slot,
            entry: MappingEntry {
                generation: self.mappings[slot].generation,
                object,
                target,
                virtual_page,
                object_page,
                pages,
                access,
                physical: None,
                occupied: true,
            },
            pool: object_entry.pool,
            next_active_mappings,
        })
    }

    fn commit_mapping(&mut self, prepared: PreparedMapping) -> MemoryMappingId {
        self.pools[prepared.pool.slot as usize].active_mappings = prepared.next_active_mappings;
        self.mappings[prepared.slot] = prepared.entry;
        MemoryMappingId {
            slot: prepared.slot as u16,
            generation: prepared.entry.generation,
        }
    }

    fn prepare_mapping_release<const C: usize>(
        &self,
        mapping: MemoryMappingId,
        target_capability: Capability,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<(MappingEntry, MemoryPoolId, u32, u32), MemoryResourceError> {
        let entry = *self.mapping(mapping)?;
        if capabilities.authorize(target_capability, Rights::CONTROL)? != entry.target {
            return Err(MemoryResourceError::Capability(
                CapabilityError::PermissionDenied,
            ));
        }
        let next_generation = entry
            .generation
            .checked_add(1)
            .ok_or(MemoryResourceError::GenerationExhausted)?;
        let object = *self.object(entry.object)?;
        let pool = *self.pool(object.pool)?;
        let next_mappings = pool
            .active_mappings
            .checked_sub(1)
            .ok_or(MemoryResourceError::Arithmetic)?;
        Ok((entry, object.pool, next_generation, next_mappings))
    }

    fn commit_mapping_release(
        &mut self,
        mapping: MemoryMappingId,
        _entry: MappingEntry,
        pool: MemoryPoolId,
        next_generation: u32,
        next_mappings: u32,
    ) {
        self.pools[pool.slot as usize].active_mappings = next_mappings;
        self.mappings[mapping.slot as usize] = MappingEntry {
            generation: next_generation,
            ..MappingEntry::EMPTY
        };
    }

    fn pool(&self, id: MemoryPoolId) -> Result<&PoolEntry, MemoryResourceError> {
        self.pools
            .get(id.slot as usize)
            .filter(|entry| entry.occupied && entry.generation == id.generation)
            .ok_or(MemoryResourceError::InvalidPool)
    }

    fn pool_mut(&mut self, id: MemoryPoolId) -> Result<&mut PoolEntry, MemoryResourceError> {
        self.pools
            .get_mut(id.slot as usize)
            .filter(|entry| entry.occupied && entry.generation == id.generation)
            .ok_or(MemoryResourceError::InvalidPool)
    }

    fn object(&self, id: MemoryObjectId) -> Result<&ObjectEntry, MemoryResourceError> {
        self.objects
            .get(id.slot as usize)
            .filter(|entry| entry.occupied && entry.generation == id.generation)
            .ok_or(MemoryResourceError::InvalidObject)
    }

    fn mapping(&self, id: MemoryMappingId) -> Result<&MappingEntry, MemoryResourceError> {
        self.mappings
            .get(id.slot as usize)
            .filter(|entry| entry.occupied && entry.generation == id.generation)
            .ok_or(MemoryResourceError::InvalidMapping)
    }

    fn free_pool_slot(&self) -> Result<usize, MemoryResourceError> {
        self.pools
            .iter()
            .position(|entry| !entry.occupied && entry.generation != u32::MAX)
            .ok_or(MemoryResourceError::CapacityExhausted)
    }

    fn free_object_slot(&self) -> Result<usize, MemoryResourceError> {
        self.objects
            .iter()
            .position(|entry| !entry.occupied && entry.generation != u32::MAX)
            .ok_or(MemoryResourceError::CapacityExhausted)
    }

    fn free_mapping_slot(&self) -> Result<usize, MemoryResourceError> {
        self.mappings
            .iter()
            .position(|entry| !entry.occupied && entry.generation != u32::MAX)
            .ok_or(MemoryResourceError::CapacityExhausted)
    }

    fn pool_authority(&self, id: MemoryPoolId) -> Result<ObjectId, MemoryResourceError> {
        authority(self.namespace, false, id.slot, id.generation)
    }

    fn object_authority(&self, id: MemoryObjectId) -> Result<ObjectId, MemoryResourceError> {
        authority(self.namespace, true, id.slot, id.generation)
    }

    fn is_descendant_or_self(
        &self,
        slot: usize,
        root: MemoryPoolId,
    ) -> Result<bool, MemoryResourceError> {
        let mut current = MemoryPoolId {
            slot: slot as u16,
            generation: self.pools[slot].generation,
        };
        for _ in 0..P {
            if current == root {
                return Ok(true);
            }
            let entry = self.pool(current)?;
            let Some(parent) = entry.parent else {
                return Ok(false);
            };
            current = parent;
        }
        Err(MemoryResourceError::Arithmetic)
    }
}

const fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

const fn physical_end(backing: MemoryPhysicalBacking) -> Result<u64, MemoryResourceError> {
    let bytes = match backing.pages.checked_mul(PAGE_SIZE) {
        Some(bytes) => bytes,
        None => return Err(MemoryResourceError::Arithmetic),
    };
    match backing.start.get().checked_add(bytes) {
        Some(end) => Ok(end),
        None => Err(MemoryResourceError::Arithmetic),
    }
}

const fn mapping_backend_request(entry: MappingEntry) -> MemoryMappingBackendRequest {
    MemoryMappingBackendRequest {
        mapping: MemoryMapping {
            object: entry.object,
            virtual_page: entry.virtual_page,
            object_page: entry.object_page,
            pages: entry.pages,
            access: entry.access,
        },
        target: entry.target,
        physical: entry.physical,
    }
}

fn validate_pool_shape(
    limit_pages: u64,
    mapping_limit: u32,
    rights: Rights,
) -> Result<(), MemoryResourceError> {
    if limit_pages == 0 || mapping_limit == 0 {
        return Err(MemoryResourceError::InvalidLimit);
    }
    if rights.bits() == 0 || !POOL_RIGHTS.contains(rights) {
        return Err(MemoryResourceError::InvalidRights);
    }
    Ok(())
}

fn authority(
    namespace: u16,
    object: bool,
    slot: u16,
    generation: u32,
) -> Result<ObjectId, MemoryResourceError> {
    if generation == 0 || generation == u32::MAX {
        return Err(MemoryResourceError::GenerationExhausted);
    }
    let value = ((object as u64) << 63)
        | (u64::from(namespace) << 48)
        | (u64::from(generation) << 16)
        | u64::from(slot)
            .checked_add(1)
            .ok_or(MemoryResourceError::Arithmetic)?;
    Ok(ObjectId(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingMappingBackend {
        installed: Option<MemoryMappingBackendRequest>,
        install_calls: u32,
        remove_calls: u32,
        fail_install: bool,
        fail_remove: bool,
    }

    // SAFETY: the test backend publishes only the exact copied request on
    // success, leaves no request on install failure, and retains the exact
    // request on remove failure.
    unsafe impl MemoryMappingBackend for RecordingMappingBackend {
        type Error = &'static str;

        fn install(&mut self, request: MemoryMappingBackendRequest) -> Result<(), Self::Error> {
            self.install_calls += 1;
            if self.fail_install {
                return Err("install");
            }
            if self.installed.replace(request).is_some() {
                return Err("occupied");
            }
            Ok(())
        }

        fn remove(&mut self, request: MemoryMappingBackendRequest) -> Result<(), Self::Error> {
            self.remove_calls += 1;
            if self.fail_remove {
                return Err("remove");
            }
            if self.installed != Some(request) {
                return Err("substitution");
            }
            self.installed = None;
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingBackingBackend {
        claimed: Option<MemoryBackingBackendRequest>,
        claim_calls: u32,
        release_calls: u32,
        fail_claim: bool,
        fail_release: bool,
    }

    // SAFETY: the test backend records only the exact request on successful
    // claim, leaves no claim on failure, and retains it on release failure.
    unsafe impl MemoryObjectBackingBackend for RecordingBackingBackend {
        type Error = &'static str;

        fn claim_zeroed(
            &mut self,
            request: MemoryBackingBackendRequest,
        ) -> Result<(), Self::Error> {
            self.claim_calls += 1;
            if self.fail_claim {
                return Err("claim");
            }
            if self.claimed.replace(request).is_some() {
                return Err("occupied");
            }
            Ok(())
        }

        fn release_scrubbed(
            &mut self,
            request: MemoryBackingBackendRequest,
        ) -> Result<(), Self::Error> {
            self.release_calls += 1;
            if self.fail_release {
                return Err("release");
            }
            if self.claimed != Some(request) {
                return Err("substitution");
            }
            self.claimed = None;
            Ok(())
        }
    }

    const ROOT_RIGHTS: Rights = Rights::ALLOCATE
        .union(Rights::DELEGATE)
        .union(Rights::CONTROL)
        .union(Rights::INSPECT);
    const CHILD_RIGHTS: Rights = Rights::ALLOCATE
        .union(Rights::CONTROL)
        .union(Rights::INSPECT);
    const OBJECT_OWNER: Rights = Rights::READ
        .union(Rights::WRITE)
        .union(Rights::MAP)
        .union(Rights::PIN)
        .union(Rights::INSPECT)
        .union(Rights::CONTROL);

    #[test]
    fn exact_limit_and_one_page_over_are_local_and_content_free() {
        let mut table = MemoryPoolTable::<2, 3>::new(7).unwrap();
        let mut capabilities = CapabilitySpace::<8>::new();
        let (root, root_cap) = table
            .create_root(8, 4, 1, ROOT_RIGHTS, &mut capabilities)
            .unwrap();
        let (object, _) = table
            .allocate_object(
                root,
                root_cap,
                8,
                MemoryBackingKind::Anonymous,
                OBJECT_OWNER,
                &mut capabilities,
            )
            .unwrap();
        assert_eq!(table.object_pool(object), Ok(root));
        assert_eq!(
            table.allocate_object(
                root,
                root_cap,
                1,
                MemoryBackingKind::Anonymous,
                OBJECT_OWNER,
                &mut capabilities,
            ),
            Err(MemoryResourceError::PoolExhausted)
        );
        let usage = table.usage(root, root_cap, &capabilities).unwrap();
        assert_eq!((usage.limit_pages(), usage.committed_pages()), (8, 8));
        assert_eq!((usage.available_pages(), usage.live_objects()), (0, 1));
    }

    #[test]
    fn child_commitment_attenuates_quantity_mapping_and_rights() {
        let mut table = MemoryPoolTable::<3, 4>::new(8).unwrap();
        let mut root_space = CapabilitySpace::<4>::new();
        let (root, root_cap) = table
            .create_root(16, 8, 2, ROOT_RIGHTS, &mut root_space)
            .unwrap();
        let mut child_space = CapabilitySpace::<4>::new();
        let (child, child_cap) = table
            .derive_pool(
                root,
                root_cap,
                &root_space,
                6,
                3,
                0,
                CHILD_RIGHTS,
                &mut child_space,
            )
            .unwrap();
        assert_eq!(
            table.derive_pool(
                root,
                root_cap,
                &root_space,
                1,
                6,
                0,
                CHILD_RIGHTS,
                &mut child_space,
            ),
            Err(MemoryResourceError::MappingLimitExceeded)
        );
        table
            .derive_pool(
                root,
                root_cap,
                &root_space,
                1,
                1,
                0,
                CHILD_RIGHTS,
                &mut child_space,
            )
            .unwrap();
        assert_eq!(
            table.derive_pool(
                root,
                root_cap,
                &root_space,
                1,
                1,
                0,
                CHILD_RIGHTS,
                &mut child_space,
            ),
            Err(MemoryResourceError::ChildLimitExceeded)
        );
        table
            .allocate_object(
                child,
                child_cap,
                6,
                MemoryBackingKind::Shared,
                OBJECT_OWNER,
                &mut child_space,
            )
            .unwrap();
        assert_eq!(
            table.allocate_object(
                child,
                child_cap,
                1,
                MemoryBackingKind::Anonymous,
                OBJECT_OWNER,
                &mut child_space,
            ),
            Err(MemoryResourceError::PoolExhausted)
        );
        let root_usage = table.usage(root, root_cap, &root_space).unwrap();
        assert_eq!(root_usage.child_reserved_pages(), 7);
        assert_eq!(root_usage.child_mapping_reservations(), 4);
        assert_eq!(root_usage.committed_pages(), 7);
    }

    #[test]
    fn release_and_parent_revocation_stale_every_descendant_handle() {
        let mut table = MemoryPoolTable::<3, 4>::new(9).unwrap();
        let mut root_space = CapabilitySpace::<6>::new();
        let (root, root_cap) = table
            .create_root(16, 8, 2, ROOT_RIGHTS, &mut root_space)
            .unwrap();
        let mut child_space = CapabilitySpace::<8>::new();
        let (child, child_cap) = table
            .derive_pool(
                root,
                root_cap,
                &root_space,
                8,
                4,
                1,
                CHILD_RIGHTS.union(Rights::DELEGATE),
                &mut child_space,
            )
            .unwrap();
        let (first, first_cap) = table
            .allocate_object(
                child,
                child_cap,
                2,
                MemoryBackingKind::Anonymous,
                OBJECT_OWNER,
                &mut child_space,
            )
            .unwrap();
        assert_eq!(
            table.release_object(first, first_cap, &mut child_space),
            Ok(2)
        );
        assert_eq!(
            table.object_backing(first),
            Err(MemoryResourceError::InvalidObject)
        );
        let (second, _) = table
            .allocate_object(
                child,
                child_cap,
                3,
                MemoryBackingKind::Guest,
                OBJECT_OWNER,
                &mut child_space,
            )
            .unwrap();
        assert_ne!(first, second);
        let summary = table.revoke_pool(root, root_cap, &mut root_space).unwrap();
        assert_eq!(
            (summary.pools(), summary.objects(), summary.pages()),
            (2, 1, 3)
        );
        assert_eq!(
            table.usage(child, child_cap, &child_space),
            Err(MemoryResourceError::InvalidPool)
        );
        assert_eq!(
            table.object_pool(second),
            Err(MemoryResourceError::InvalidObject)
        );
    }

    #[test]
    fn inspection_and_control_are_independent_authorities() {
        let mut table = MemoryPoolTable::<1, 1>::new(10).unwrap();
        let mut owner = CapabilitySpace::<3>::new();
        let (root, root_cap) = table.create_root(4, 2, 0, ROOT_RIGHTS, &mut owner).unwrap();
        let mut monitor = CapabilitySpace::<1>::new();
        let inspect = owner
            .derive(root_cap, Rights::INSPECT, &mut monitor)
            .unwrap();
        assert_eq!(
            table.usage(root, inspect, &monitor).unwrap().limit_pages(),
            4
        );
        assert_eq!(
            table.revoke_pool(root, inspect, &mut monitor),
            Err(MemoryResourceError::Capability(
                CapabilityError::PermissionDenied
            ))
        );
    }

    #[test]
    fn mappings_enforce_dual_authority_ranges_wx_overlap_and_budget() {
        let mut table = MemoryPoolTable::<2, 1, 3>::new(11).unwrap();
        let mut caps = CapabilitySpace::<6>::new();
        let (root, root_cap) = table.create_root(5, 2, 1, ROOT_RIGHTS, &mut caps).unwrap();
        let (object, object_cap) = table
            .allocate_object(
                root,
                root_cap,
                4,
                MemoryBackingKind::Anonymous,
                OBJECT_OWNER,
                &mut caps,
            )
            .unwrap();
        let target = caps
            .insert(
                ObjectId(77),
                Rights::MAP.union(Rights::CONTROL).union(Rights::INSPECT),
            )
            .unwrap();
        let non_target = caps.insert(ObjectId(78), Rights::CONTROL).unwrap();
        assert!(matches!(
            table.reserve_mapping(
                object,
                object_cap,
                non_target,
                10,
                0,
                1,
                Rights::READ,
                &caps,
            ),
            Err(MemoryResourceError::Capability(_))
        ));
        assert!(matches!(
            table.reserve_mapping(object, target, target, 10, 0, 1, Rights::READ, &caps,),
            Err(MemoryResourceError::Capability(_))
        ));
        assert_eq!(
            table.reserve_mapping(
                object,
                object_cap,
                target,
                u64::MAX,
                0,
                1,
                Rights::READ,
                &caps,
            ),
            Err(MemoryResourceError::Arithmetic)
        );
        let mapping = table
            .reserve_mapping(
                object,
                object_cap,
                target,
                10,
                1,
                2,
                Rights::READ.union(Rights::WRITE),
                &caps,
            )
            .unwrap();
        let info = table.mapping_info(mapping, target, &caps).unwrap();
        assert_eq!(
            (
                info.object(),
                info.virtual_page(),
                info.object_page(),
                info.pages(),
                info.access()
            ),
            (object, 10, 1, 2, Rights::READ.union(Rights::WRITE))
        );
        assert_eq!(
            table.reserve_mapping(object, object_cap, target, 11, 0, 1, Rights::READ, &caps),
            Err(MemoryResourceError::MappingOverlap)
        );
        assert_eq!(
            table.reserve_mapping(
                object,
                object_cap,
                target,
                20,
                0,
                1,
                Rights::WRITE.union(Rights::EXECUTE),
                &caps,
            ),
            Err(MemoryResourceError::InvalidRights)
        );
        assert_eq!(
            table.reserve_mapping(object, object_cap, target, 20, 4, 1, Rights::READ, &caps),
            Err(MemoryResourceError::ObjectRange)
        );
        let second = table
            .reserve_mapping(object, object_cap, target, 20, 0, 1, Rights::READ, &caps)
            .unwrap();
        assert_eq!(
            table.reserve_mapping(object, object_cap, target, 30, 0, 1, Rights::READ, &caps),
            Err(MemoryResourceError::MappingLimitExceeded)
        );
        assert_eq!(
            table
                .usage(root, root_cap, &caps)
                .unwrap()
                .active_mappings(),
            2
        );
        let mut child_space = CapabilitySpace::<1>::new();
        assert_eq!(
            table.derive_pool(
                root,
                root_cap,
                &caps,
                1,
                1,
                0,
                CHILD_RIGHTS,
                &mut child_space,
            ),
            Err(MemoryResourceError::MappingLimitExceeded)
        );
        unsafe { table.release_mapping(mapping, target, &caps) }.unwrap();
        table
            .derive_pool(
                root,
                root_cap,
                &caps,
                1,
                1,
                0,
                CHILD_RIGHTS,
                &mut child_space,
            )
            .unwrap();
        assert_eq!(
            table.mapping_info(mapping, target, &caps),
            Err(MemoryResourceError::InvalidMapping)
        );
        assert_eq!(
            table.release_object(object, object_cap, &mut caps),
            Err(MemoryResourceError::MappingsActive)
        );
        assert_eq!(
            table.mapping_info(second, target, &caps).unwrap().object(),
            object
        );
        unsafe { table.release_mapping(second, target, &caps) }.unwrap();
        table.release_object(object, object_cap, &mut caps).unwrap();
        assert_eq!(
            table
                .usage(root, root_cap, &caps)
                .unwrap()
                .active_mappings(),
            0
        );
    }

    #[test]
    fn pool_revocation_requires_prior_mapping_teardown_without_partial_mutation() {
        let mut table = MemoryPoolTable::<2, 1, 1>::new(12).unwrap();
        let mut root_space = CapabilitySpace::<3>::new();
        let (root, root_cap) = table
            .create_root(8, 2, 1, ROOT_RIGHTS, &mut root_space)
            .unwrap();
        let mut child_space = CapabilitySpace::<5>::new();
        let (child, child_cap) = table
            .derive_pool(
                root,
                root_cap,
                &root_space,
                4,
                1,
                0,
                CHILD_RIGHTS,
                &mut child_space,
            )
            .unwrap();
        let (object, object_cap) = table
            .allocate_object(
                child,
                child_cap,
                1,
                MemoryBackingKind::Shared,
                OBJECT_OWNER,
                &mut child_space,
            )
            .unwrap();
        let target = child_space
            .insert(
                ObjectId(88),
                Rights::MAP.union(Rights::CONTROL).union(Rights::INSPECT),
            )
            .unwrap();
        let mapping = table
            .reserve_mapping(
                object,
                object_cap,
                target,
                40,
                0,
                1,
                Rights::READ,
                &child_space,
            )
            .unwrap();
        assert_eq!(
            table.revoke_pool(root, root_cap, &mut root_space),
            Err(MemoryResourceError::MappingsActive)
        );
        assert_eq!(
            table
                .mapping_info(mapping, target, &child_space)
                .unwrap()
                .object(),
            object
        );
        unsafe { table.release_mapping(mapping, target, &child_space) }.unwrap();
        let summary = table.revoke_pool(root, root_cap, &mut root_space).unwrap();
        assert_eq!(
            (summary.pools(), summary.objects(), summary.pages()),
            (2, 1, 1)
        );
    }

    #[test]
    fn backend_mapping_publication_and_retirement_are_transactional() {
        let mut table = MemoryPoolTable::<1, 1, 1>::new(13).unwrap();
        let mut caps = CapabilitySpace::<5>::new();
        let (root, root_cap) = table.create_root(2, 1, 0, ROOT_RIGHTS, &mut caps).unwrap();
        let (object, object_cap) = table
            .allocate_object(
                root,
                root_cap,
                2,
                MemoryBackingKind::Anonymous,
                OBJECT_OWNER,
                &mut caps,
            )
            .unwrap();
        let target = caps
            .insert(
                ObjectId(99),
                Rights::MAP.union(Rights::CONTROL).union(Rights::INSPECT),
            )
            .unwrap();
        let mut backend = RecordingMappingBackend {
            fail_install: true,
            ..RecordingMappingBackend::default()
        };
        assert_eq!(
            table.install_mapping(
                object,
                object_cap,
                target,
                0x200,
                0,
                2,
                Rights::WRITE.union(Rights::EXECUTE),
                &caps,
                &mut backend,
            ),
            Err(MemoryMappingOperationError::Policy(
                MemoryResourceError::InvalidRights
            ))
        );
        assert_eq!(backend.install_calls, 0);
        assert_eq!(
            table.install_mapping(
                object,
                object_cap,
                target,
                0x200,
                0,
                2,
                Rights::READ,
                &caps,
                &mut backend,
            ),
            Err(MemoryMappingOperationError::Backend("install"))
        );
        assert_eq!(backend.install_calls, 1);
        assert_eq!(backend.installed, None);
        assert_eq!(
            table
                .usage(root, root_cap, &caps)
                .unwrap()
                .active_mappings(),
            0
        );

        backend.fail_install = false;
        let mapping = table
            .install_mapping(
                object,
                object_cap,
                target,
                0x200,
                0,
                2,
                Rights::READ,
                &caps,
                &mut backend,
            )
            .unwrap();
        let request = backend.installed.unwrap();
        assert_eq!(request.target(), ObjectId(99));
        assert_eq!(request.mapping().object(), object);
        assert_eq!(request.mapping().virtual_page(), 0x200);
        assert_eq!(request.mapping().pages(), 2);
        assert_eq!(
            table
                .usage(root, root_cap, &caps)
                .unwrap()
                .active_mappings(),
            1
        );

        backend.fail_remove = true;
        assert_eq!(
            table.remove_mapping(mapping, target, &caps, &mut backend),
            Err(MemoryMappingOperationError::Backend("remove"))
        );
        assert_eq!(backend.installed, Some(request));
        assert_eq!(
            table.mapping_info(mapping, target, &caps).unwrap(),
            request.mapping()
        );
        assert_eq!(
            table
                .usage(root, root_cap, &caps)
                .unwrap()
                .active_mappings(),
            1
        );

        backend.fail_remove = false;
        table
            .remove_mapping(mapping, target, &caps, &mut backend)
            .unwrap();
        assert_eq!(backend.installed, None);
        assert_eq!(backend.remove_calls, 2);
        assert_eq!(
            table.mapping_info(mapping, target, &caps),
            Err(MemoryResourceError::InvalidMapping)
        );
        assert_eq!(
            table
                .usage(root, root_cap, &caps)
                .unwrap()
                .active_mappings(),
            0
        );
    }

    #[test]
    fn physical_backing_claim_scrub_and_release_are_exact_and_fail_closed() {
        assert_eq!(
            MemoryPhysicalBacking::new(PhysAddr::new(0x1000).unwrap(), 0),
            Err(MemoryResourceError::InvalidPhysicalBacking)
        );
        let mut table = MemoryPoolTable::<1, 2, 1>::new(14).unwrap();
        let mut caps = CapabilitySpace::<8>::new();
        let (root, root_cap) = table.create_root(4, 1, 0, ROOT_RIGHTS, &mut caps).unwrap();
        let (first, first_cap) = table
            .allocate_object(
                root,
                root_cap,
                2,
                MemoryBackingKind::Anonymous,
                OBJECT_OWNER,
                &mut caps,
            )
            .unwrap();
        let (second, second_cap) = table
            .allocate_object(
                root,
                root_cap,
                2,
                MemoryBackingKind::Shared,
                OBJECT_OWNER,
                &mut caps,
            )
            .unwrap();
        let wrong = caps
            .insert(ObjectId(100), Rights::CONTROL.union(Rights::PIN))
            .unwrap();
        let target = caps
            .insert(
                ObjectId(101),
                Rights::MAP.union(Rights::CONTROL).union(Rights::INSPECT),
            )
            .unwrap();
        let physical = MemoryPhysicalBacking::new(PhysAddr::new(0x20_0000).unwrap(), 2).unwrap();
        let mut mapping_backend = RecordingMappingBackend::default();
        assert_eq!(
            table.install_backed_mapping(
                first,
                first_cap,
                target,
                0x300,
                1,
                1,
                Rights::READ,
                &caps,
                &mut mapping_backend,
            ),
            Err(MemoryMappingOperationError::Policy(
                MemoryResourceError::PhysicalBackingAbsent
            ))
        );
        assert_eq!(mapping_backend.install_calls, 0);
        let mut backend = RecordingBackingBackend {
            fail_claim: true,
            ..RecordingBackingBackend::default()
        };
        assert!(matches!(
            table.bind_physical_backing(first, wrong, physical, &caps, &mut backend),
            Err(MemoryBackingOperationError::Policy(
                MemoryResourceError::Capability(_)
            ))
        ));
        assert_eq!(backend.claim_calls, 0);
        assert_eq!(
            table.bind_physical_backing(first, first_cap, physical, &caps, &mut backend),
            Err(MemoryBackingOperationError::Backend("claim"))
        );
        assert_eq!(
            table.object_physical_backing(first, first_cap, &caps),
            Ok(None)
        );

        backend.fail_claim = false;
        table
            .bind_physical_backing(first, first_cap, physical, &caps, &mut backend)
            .unwrap();
        let request = backend.claimed.unwrap();
        assert_eq!(request.object(), first);
        assert_eq!(request.physical(), physical);
        assert_eq!(request.kind(), MemoryBackingKind::Anonymous);
        assert_eq!(
            table.object_physical_backing(first, first_cap, &caps),
            Ok(Some(physical))
        );
        assert_eq!(
            table.release_object(first, first_cap, &mut caps),
            Err(MemoryResourceError::PhysicalBackingActive)
        );
        assert_eq!(
            table.bind_physical_backing(second, second_cap, physical, &caps, &mut backend),
            Err(MemoryBackingOperationError::Policy(
                MemoryResourceError::PhysicalOverlap
            ))
        );
        assert_eq!(backend.claim_calls, 2);
        assert_eq!(
            table.revoke_pool(root, root_cap, &mut caps),
            Err(MemoryResourceError::PhysicalBackingActive)
        );

        let mapping = table
            .install_backed_mapping(
                first,
                first_cap,
                target,
                0x300,
                1,
                1,
                Rights::READ,
                &caps,
                &mut mapping_backend,
            )
            .unwrap();
        let mapping_request = mapping_backend.installed.unwrap();
        assert_eq!(
            mapping_request.physical(),
            Some(MemoryPhysicalBacking::new(PhysAddr::new(0x20_1000).unwrap(), 1).unwrap())
        );
        assert_eq!(mapping_request.mapping().object_page(), 1);
        assert_eq!(
            table.release_physical_backing(first, first_cap, &caps, &mut backend),
            Err(MemoryBackingOperationError::Policy(
                MemoryResourceError::MappingsActive
            ))
        );
        assert_eq!(backend.release_calls, 0);
        mapping_backend.fail_remove = true;
        assert_eq!(
            table.remove_mapping(mapping, target, &caps, &mut mapping_backend),
            Err(MemoryMappingOperationError::Backend("remove"))
        );
        assert_eq!(mapping_backend.installed, Some(mapping_request));
        mapping_backend.fail_remove = false;
        table
            .remove_mapping(mapping, target, &caps, &mut mapping_backend)
            .unwrap();
        assert_eq!(mapping_backend.installed, None);

        backend.fail_release = true;
        assert_eq!(
            table.release_physical_backing(first, first_cap, &caps, &mut backend),
            Err(MemoryBackingOperationError::Backend("release"))
        );
        assert_eq!(backend.claimed, Some(request));
        assert_eq!(
            table.object_physical_backing(first, first_cap, &caps),
            Ok(Some(physical))
        );
        backend.fail_release = false;
        assert_eq!(
            table.release_physical_backing(first, first_cap, &caps, &mut backend),
            Ok(physical)
        );
        assert_eq!(backend.claimed, None);
        assert_eq!(backend.release_calls, 2);
        assert_eq!(
            table.object_physical_backing(first, first_cap, &caps),
            Ok(None)
        );
        assert_eq!(table.release_object(first, first_cap, &mut caps), Ok(2));
    }
}
