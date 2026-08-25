use core::array;

use crate::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

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
pub enum MemoryBackingKind {
    Anonymous,
    Shared,
    Guest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryUsage {
    limit_pages: u64,
    object_pages: u64,
    child_reserved_pages: u64,
    mapping_limit: u32,
    child_mapping_reservations: u32,
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
    occupied: bool,
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
        occupied: false,
    };
}

/// Fixed-capacity quantitative memory authority and commitment accounting.
///
/// This policy core records commitments; it does not allocate frames or grant
/// mappings. Those later operations must consume the resulting exact object and
/// separate mapping/content authority.
pub struct MemoryPoolTable<const P: usize, const O: usize> {
    namespace: u16,
    pools: [PoolEntry; P],
    objects: [ObjectEntry; O],
}

impl<const P: usize, const O: usize> MemoryPoolTable<P, O> {
    pub fn new(namespace: u16) -> Result<Self, MemoryResourceError> {
        if namespace == 0
            || namespace > 0x7fff
            || P == 0
            || O == 0
            || P > u16::MAX as usize
            || O > u16::MAX as usize
        {
            return Err(MemoryResourceError::InvalidNamespace);
        }
        Ok(Self {
            namespace,
            pools: array::from_fn(|_| PoolEntry::EMPTY),
            objects: array::from_fn(|_| ObjectEntry::EMPTY),
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
        let mapping_total = parent_entry
            .child_mapping_reservations
            .checked_add(mapping_limit)
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
        parent_mut.child_mapping_reservations = mapping_total;
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
}
