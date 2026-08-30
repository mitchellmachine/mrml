use crate::{
    StorageAuthorityError, StorageAuthorityTable, StorageHandle, StorageObjectId,
    StorageObjectKind, StoragePrincipal, StorageRights, VolumeId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemOpenKind {
    Directory,
    File,
}

impl FilesystemOpenKind {
    const fn storage_kind(self) -> StorageObjectKind {
        match self {
            Self::Directory => StorageObjectKind::Directory,
            Self::File => StorageObjectKind::File,
        }
    }
}

/// Runtime-authenticated association between one provider lookup result and one
/// stable storage object. This is evidence for identity mapping, not authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedFilesystemLookup {
    volume: VolumeId,
    mount_generation: u64,
    parent: StorageObjectId,
    provider_object: u64,
    child: StorageObjectId,
    kind: FilesystemOpenKind,
}

impl AuthenticatedFilesystemLookup {
    /// Creates a lookup association after the runtime has authenticated the
    /// exact provider endpoint, mount generation, parent, and returned object.
    ///
    /// # Safety
    ///
    /// The caller must prove that `provider_object` was returned by the exact
    /// live provider/mount for `parent`, and that `child` is the stable object
    /// assigned to that provider identity. Numeric equality, a name, or media
    /// metadata alone is insufficient.
    pub unsafe fn new(
        volume: VolumeId,
        mount_generation: u64,
        parent: StorageObjectId,
        provider_object: u64,
        child: StorageObjectId,
        kind: FilesystemOpenKind,
    ) -> Option<Self> {
        if mount_generation == 0
            || provider_object == 0
            || parent.volume() != volume
            || child.volume() != volume
            || parent == child
        {
            return None;
        }
        Some(Self {
            volume,
            mount_generation,
            parent,
            provider_object,
            child,
            kind,
        })
    }

    pub const fn provider_object(self) -> u64 {
        self.provider_object
    }

    pub const fn child(self) -> StorageObjectId {
        self.child
    }
}

#[derive(Clone, Copy)]
struct OpenedFilesystemHandle {
    volume: VolumeId,
    mount_generation: u64,
    handle: StorageHandle,
    owner: StoragePrincipal,
}

impl OpenedFilesystemHandle {
    const EMPTY: Option<Self> = None;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemOpenError {
    Capacity,
    WrongParent,
    Authority(StorageAuthorityError),
}

pub struct FilesystemOpenBroker<const N: usize> {
    opened: [Option<OpenedFilesystemHandle>; N],
}

impl<const N: usize> FilesystemOpenBroker<N> {
    pub const fn new() -> Self {
        Self {
            opened: [OpenedFilesystemHandle::EMPTY; N],
        }
    }

    pub fn open_child<const A: usize>(
        &mut self,
        authorities: &mut StorageAuthorityTable<A>,
        parent: StorageHandle,
        owner: StoragePrincipal,
        lookup: AuthenticatedFilesystemLookup,
        requested: StorageRights,
    ) -> Result<StorageHandle, FilesystemOpenError> {
        let parent_object = authorities
            .authorize(
                parent,
                owner,
                StorageObjectKind::Directory,
                StorageRights::OPEN_CHILD,
            )
            .map_err(FilesystemOpenError::Authority)?;
        if parent_object != lookup.parent || parent_object.volume() != lookup.volume {
            return Err(FilesystemOpenError::WrongParent);
        }
        let slot = self
            .opened
            .iter()
            .position(Option::is_none)
            .ok_or(FilesystemOpenError::Capacity)?;
        let handle = authorities
            .insert_child_derived(
                parent,
                owner,
                StorageRights::OPEN_CHILD,
                lookup.child,
                lookup.kind.storage_kind(),
                requested,
            )
            .map_err(FilesystemOpenError::Authority)?;
        self.opened[slot] = Some(OpenedFilesystemHandle {
            volume: lookup.volume,
            mount_generation: lookup.mount_generation,
            handle,
            owner,
        });
        Ok(handle)
    }

    pub fn revoke_mount<const A: usize>(
        &mut self,
        authorities: &mut StorageAuthorityTable<A>,
        volume: VolumeId,
        mount_generation: u64,
    ) -> Result<usize, FilesystemOpenError> {
        if mount_generation == 0 {
            return Err(FilesystemOpenError::WrongParent);
        }
        let mut revoked = 0;
        for record in &mut self.opened {
            let Some(opened) = *record else {
                continue;
            };
            if opened.volume != volume || opened.mount_generation != mount_generation {
                continue;
            }
            match authorities.revoke(opened.handle, opened.owner) {
                Ok(count) => revoked += count,
                Err(StorageAuthorityError::InvalidHandle) => {}
                Err(error) => return Err(FilesystemOpenError::Authority(error)),
            }
            *record = None;
        }
        Ok(revoked)
    }
}

impl<const N: usize> Default for FilesystemOpenBroker<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(byte: u8) -> VolumeId {
        VolumeId::new([byte; 16]).unwrap()
    }

    fn object(volume: VolumeId, local: u64) -> StorageObjectId {
        StorageObjectId::new(volume, local).unwrap()
    }

    fn principal(value: u64) -> StoragePrincipal {
        StoragePrincipal::new(value).unwrap()
    }

    fn lookup(
        volume: VolumeId,
        parent: StorageObjectId,
        child: StorageObjectId,
    ) -> AuthenticatedFilesystemLookup {
        // SAFETY: The test fixture defines this exact provider result mapping.
        unsafe {
            AuthenticatedFilesystemLookup::new(
                volume,
                7,
                parent,
                55,
                child,
                FilesystemOpenKind::File,
            )
            .unwrap()
        }
    }

    #[test]
    fn lookup_only_parent_cannot_open_child() {
        let volume = volume(1);
        let parent_object = object(volume, 1);
        let child = object(volume, 2);
        let owner = principal(9);
        let mut authorities = StorageAuthorityTable::<4>::new();
        let parent = authorities
            .insert(
                parent_object,
                StorageObjectKind::Directory,
                StorageRights::LOOKUP,
                owner,
            )
            .unwrap();
        let mut broker = FilesystemOpenBroker::<2>::new();
        assert_eq!(
            broker.open_child(
                &mut authorities,
                parent,
                owner,
                lookup(volume, parent_object, child),
                StorageRights::READ,
            ),
            Err(FilesystemOpenError::Authority(StorageAuthorityError::Denied))
        );
        assert!(authorities.has_capacity());
    }

    #[test]
    fn open_child_derives_only_requested_kind_valid_rights() {
        let volume = volume(1);
        let parent_object = object(volume, 1);
        let child = object(volume, 2);
        let owner = principal(9);
        let mut authorities = StorageAuthorityTable::<4>::new();
        let parent = authorities
            .insert(
                parent_object,
                StorageObjectKind::Directory,
                StorageRights::LOOKUP.union(StorageRights::OPEN_CHILD),
                owner,
            )
            .unwrap();
        let mut broker = FilesystemOpenBroker::<2>::new();
        let file = broker
            .open_child(
                &mut authorities,
                parent,
                owner,
                lookup(volume, parent_object, child),
                StorageRights::READ,
            )
            .unwrap();
        assert_eq!(
            authorities.authorize(file, owner, StorageObjectKind::File, StorageRights::READ),
            Ok(child)
        );
        assert_eq!(
            authorities.authorize(file, owner, StorageObjectKind::File, StorageRights::WRITE),
            Err(StorageAuthorityError::Denied)
        );
    }

    #[test]
    fn substituted_parent_fails_before_child_handle_creation() {
        let volume = volume(1);
        let parent_object = object(volume, 1);
        let other_parent = object(volume, 3);
        let child = object(volume, 2);
        let owner = principal(9);
        let mut authorities = StorageAuthorityTable::<2>::new();
        let parent = authorities
            .insert(
                parent_object,
                StorageObjectKind::Directory,
                StorageRights::OPEN_CHILD,
                owner,
            )
            .unwrap();
        let mut broker = FilesystemOpenBroker::<1>::new();
        assert_eq!(
            broker.open_child(
                &mut authorities,
                parent,
                owner,
                lookup(volume, other_parent, child),
                StorageRights::READ,
            ),
            Err(FilesystemOpenError::WrongParent)
        );
        assert!(authorities.has_capacity());
    }

    #[test]
    fn mount_revocation_removes_exact_open_handles_and_descendants() {
        let volume = volume(1);
        let parent_object = object(volume, 1);
        let child = object(volume, 2);
        let owner = principal(9);
        let delegate = principal(10);
        let mut authorities = StorageAuthorityTable::<5>::new();
        let parent = authorities
            .insert(
                parent_object,
                StorageObjectKind::Directory,
                StorageRights::OPEN_CHILD,
                owner,
            )
            .unwrap();
        let mut broker = FilesystemOpenBroker::<2>::new();
        let file = broker
            .open_child(
                &mut authorities,
                parent,
                owner,
                lookup(volume, parent_object, child),
                StorageRights::READ.union(StorageRights::DELEGATE),
            )
            .unwrap();
        let derived = authorities
            .derive(file, owner, delegate, StorageRights::READ)
            .unwrap();
        assert_eq!(broker.revoke_mount(&mut authorities, volume, 7), Ok(2));
        for (handle, principal) in [(file, owner), (derived, delegate)] {
            assert_eq!(
                authorities.authorize(
                    handle,
                    principal,
                    StorageObjectKind::File,
                    StorageRights::READ,
                ),
                Err(StorageAuthorityError::InvalidHandle)
            );
        }
        assert_eq!(
            authorities.authorize(
                parent,
                owner,
                StorageObjectKind::Directory,
                StorageRights::OPEN_CHILD,
            ),
            Ok(parent_object)
        );
    }

    #[test]
    fn authenticated_lookup_rejects_zero_cross_volume_and_self_mapping() {
        let first = volume(1);
        let second = volume(2);
        let parent = object(first, 1);
        let child = object(first, 2);
        for candidate in [
            unsafe {
                AuthenticatedFilesystemLookup::new(
                    first,
                    0,
                    parent,
                    1,
                    child,
                    FilesystemOpenKind::File,
                )
            },
            unsafe {
                AuthenticatedFilesystemLookup::new(
                    first,
                    1,
                    parent,
                    0,
                    child,
                    FilesystemOpenKind::File,
                )
            },
            unsafe {
                AuthenticatedFilesystemLookup::new(
                    first,
                    1,
                    parent,
                    1,
                    object(second, 2),
                    FilesystemOpenKind::File,
                )
            },
            unsafe {
                AuthenticatedFilesystemLookup::new(
                    first,
                    1,
                    parent,
                    1,
                    parent,
                    FilesystemOpenKind::Directory,
                )
            },
        ] {
            assert_eq!(candidate, None);
        }
    }
}
