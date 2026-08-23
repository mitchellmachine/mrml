use crate::StorageObjectId;
use core::array;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StorageObjectKind {
    Volume = 1,
    Directory = 2,
    File = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageRights(u32);

impl StorageRights {
    pub const NONE: Self = Self(0);
    pub const LOOKUP: Self = Self(1 << 0);
    pub const ENUMERATE: Self = Self(1 << 1);
    pub const CREATE_FILE: Self = Self(1 << 2);
    pub const CREATE_DIRECTORY: Self = Self(1 << 3);
    pub const RENAME_CHILD: Self = Self(1 << 4);
    pub const REMOVE_CHILD: Self = Self(1 << 5);
    pub const READ: Self = Self(1 << 8);
    pub const WRITE: Self = Self(1 << 9);
    pub const RESIZE: Self = Self(1 << 10);
    pub const MAP: Self = Self(1 << 11);
    pub const READ_METADATA: Self = Self(1 << 12);
    pub const WRITE_METADATA: Self = Self(1 << 13);
    pub const CONTROL: Self = Self(1 << 16);
    pub const DELEGATE: Self = Self(1 << 31);
    const DIRECTORY_MASK: u32 = Self::LOOKUP.0
        | Self::ENUMERATE.0
        | Self::CREATE_FILE.0
        | Self::CREATE_DIRECTORY.0
        | Self::RENAME_CHILD.0
        | Self::REMOVE_CHILD.0
        | Self::READ_METADATA.0
        | Self::WRITE_METADATA.0
        | Self::DELEGATE.0;
    const FILE_MASK: u32 = Self::READ.0
        | Self::WRITE.0
        | Self::RESIZE.0
        | Self::MAP.0
        | Self::READ_METADATA.0
        | Self::WRITE_METADATA.0
        | Self::DELEGATE.0;
    const VOLUME_MASK: u32 =
        Self::READ_METADATA.0 | Self::WRITE_METADATA.0 | Self::CONTROL.0 | Self::DELEGATE.0;
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    pub const fn contains(self, requested: Self) -> bool {
        self.0 & requested.0 == requested.0
    }
    pub const fn bits(self) -> u32 {
        self.0
    }
    pub const fn from_bits(
        kind: StorageObjectKind,
        bits: u32,
    ) -> Result<Self, StorageAuthorityError> {
        let rights = Self(bits);
        if !rights.valid_for(kind) {
            Err(StorageAuthorityError::InvalidRights)
        } else {
            Ok(rights)
        }
    }
    const fn mask(kind: StorageObjectKind) -> u32 {
        match kind {
            StorageObjectKind::Volume => Self::VOLUME_MASK,
            StorageObjectKind::Directory => Self::DIRECTORY_MASK,
            StorageObjectKind::File => Self::FILE_MASK,
        }
    }
    const fn valid_for(self, kind: StorageObjectKind) -> bool {
        self.0 != 0 && self.0 & !Self::mask(kind) == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageHandle {
    slot: u32,
    generation: u32,
}
impl StorageHandle {
    pub const fn token(self) -> u64 {
        ((self.generation as u64) << 32) | self.slot as u64
    }
    pub const fn from_token(token: u64) -> Self {
        Self {
            slot: token as u32,
            generation: (token >> 32) as u32,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoragePrincipal(u64);
impl StoragePrincipal {
    pub const fn new(value: u64) -> Result<Self, StorageAuthorityError> {
        if value == 0 {
            Err(StorageAuthorityError::InvalidPrincipal)
        } else {
            Ok(Self(value))
        }
    }
}

#[derive(Clone, Copy)]
struct Entry {
    generation: u32,
    object: Option<StorageObjectId>,
    kind: StorageObjectKind,
    rights: StorageRights,
    owner: Option<StoragePrincipal>,
    parent: Option<StorageHandle>,
    retired: bool,
}
impl Entry {
    const EMPTY: Self = Self {
        generation: 1,
        object: None,
        kind: StorageObjectKind::File,
        rights: StorageRights::NONE,
        owner: None,
        parent: None,
        retired: false,
    };
}

pub struct StorageAuthorityTable<const N: usize> {
    entries: [Entry; N],
}

impl<const N: usize> StorageAuthorityTable<N> {
    pub fn new() -> Self {
        Self {
            entries: array::from_fn(|_| Entry::EMPTY),
        }
    }
    pub fn insert(
        &mut self,
        object: StorageObjectId,
        kind: StorageObjectKind,
        rights: StorageRights,
        owner: StoragePrincipal,
    ) -> Result<StorageHandle, StorageAuthorityError> {
        self.insert_derived(object, kind, rights, owner, None)
    }
    pub fn authorize(
        &self,
        handle: StorageHandle,
        owner: StoragePrincipal,
        kind: StorageObjectKind,
        requested: StorageRights,
    ) -> Result<StorageObjectId, StorageAuthorityError> {
        if !requested.valid_for(kind) {
            return Err(StorageAuthorityError::InvalidRights);
        }
        let entry = self.entry(handle)?;
        if entry.owner != Some(owner) || entry.kind != kind || !entry.rights.contains(requested) {
            return Err(StorageAuthorityError::Denied);
        }
        entry.object.ok_or(StorageAuthorityError::InvalidHandle)
    }
    pub fn derive(
        &mut self,
        handle: StorageHandle,
        source_owner: StoragePrincipal,
        destination_owner: StoragePrincipal,
        requested: StorageRights,
    ) -> Result<StorageHandle, StorageAuthorityError> {
        let entry = *self.entry(handle)?;
        if entry.owner != Some(source_owner) {
            return Err(StorageAuthorityError::Denied);
        }
        if !entry.rights.contains(StorageRights::DELEGATE) {
            return Err(StorageAuthorityError::DelegationDenied);
        }
        if !requested.valid_for(entry.kind) || !entry.rights.contains(requested) {
            return Err(StorageAuthorityError::Denied);
        }
        self.insert_derived(
            entry.object.ok_or(StorageAuthorityError::InvalidHandle)?,
            entry.kind,
            requested,
            destination_owner,
            Some(handle),
        )
    }
    pub fn revoke(
        &mut self,
        handle: StorageHandle,
        owner: StoragePrincipal,
    ) -> Result<usize, StorageAuthorityError> {
        let slot =
            usize::try_from(handle.slot).map_err(|_| StorageAuthorityError::InvalidHandle)?;
        let entry = self
            .entries
            .get(slot)
            .ok_or(StorageAuthorityError::InvalidHandle)?;
        if entry.object.is_none()
            || entry.generation != handle.generation
            || entry.owner != Some(owner)
        {
            return Err(StorageAuthorityError::InvalidHandle);
        }
        let mut revoke = [false; N];
        revoke[slot] = true;
        for (index, entry) in self.entries.iter().enumerate() {
            let mut parent = entry.parent;
            let mut depth = 0;
            while let Some(candidate) = parent {
                if candidate == handle {
                    revoke[index] = true;
                    break;
                }
                if depth == N {
                    return Err(StorageAuthorityError::InvalidLineage);
                }
                parent = self.entry(candidate)?.parent;
                depth += 1;
            }
        }
        let mut count = 0;
        for (entry, selected) in self.entries.iter_mut().zip(revoke) {
            if selected {
                Self::retire(entry);
                count += 1;
            }
        }
        Ok(count)
    }
    fn insert_derived(
        &mut self,
        object: StorageObjectId,
        kind: StorageObjectKind,
        rights: StorageRights,
        owner: StoragePrincipal,
        parent: Option<StorageHandle>,
    ) -> Result<StorageHandle, StorageAuthorityError> {
        if !rights.valid_for(kind) {
            return Err(StorageAuthorityError::InvalidRights);
        }
        let (slot, entry) = self
            .entries
            .iter_mut()
            .enumerate()
            .find(|(_, entry)| entry.object.is_none() && !entry.retired)
            .ok_or(StorageAuthorityError::Full)?;
        entry.object = Some(object);
        entry.kind = kind;
        entry.rights = rights;
        entry.owner = Some(owner);
        entry.parent = parent;
        Ok(StorageHandle {
            slot: slot as u32,
            generation: entry.generation,
        })
    }
    fn retire(entry: &mut Entry) {
        entry.object = None;
        entry.rights = StorageRights::NONE;
        entry.owner = None;
        entry.parent = None;
        if let Some(next) = entry.generation.checked_add(1) {
            entry.generation = next;
        } else {
            entry.retired = true;
        }
    }
    fn entry(&self, handle: StorageHandle) -> Result<&Entry, StorageAuthorityError> {
        let slot =
            usize::try_from(handle.slot).map_err(|_| StorageAuthorityError::InvalidHandle)?;
        self.entries
            .get(slot)
            .filter(|entry| entry.object.is_some() && entry.generation == handle.generation)
            .ok_or(StorageAuthorityError::InvalidHandle)
    }
}
impl<const N: usize> Default for StorageAuthorityTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageAuthorityError {
    Full,
    InvalidHandle,
    InvalidRights,
    InvalidPrincipal,
    InvalidLineage,
    Denied,
    DelegationDenied,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VolumeId;
    fn object(local: u64) -> StorageObjectId {
        StorageObjectId::new(VolumeId::new([1; 16]).unwrap(), local).unwrap()
    }
    fn principal(value: u64) -> StoragePrincipal {
        StoragePrincipal::new(value).unwrap()
    }
    #[test]
    fn kind_and_principal_checks_reject_cross_object_authority() {
        let mut table = StorageAuthorityTable::<2>::new();
        assert_eq!(
            table.insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::READ,
                principal(1)
            ),
            Err(StorageAuthorityError::InvalidRights)
        );
        let directory = table
            .insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::LOOKUP.union(StorageRights::DELEGATE),
                principal(1),
            )
            .unwrap();
        assert_eq!(
            table.authorize(
                directory,
                principal(1),
                StorageObjectKind::File,
                StorageRights::READ
            ),
            Err(StorageAuthorityError::Denied)
        );
        assert_eq!(
            table.authorize(
                directory,
                principal(2),
                StorageObjectKind::Directory,
                StorageRights::LOOKUP
            ),
            Err(StorageAuthorityError::Denied)
        );
    }
    #[test]
    fn parent_revocation_removes_all_cross_principal_descendants() {
        let mut table = StorageAuthorityTable::<4>::new();
        let root = table
            .insert(
                object(2),
                StorageObjectKind::File,
                StorageRights::READ
                    .union(StorageRights::WRITE)
                    .union(StorageRights::DELEGATE),
                principal(1),
            )
            .unwrap();
        let child = table
            .derive(
                root,
                principal(1),
                principal(2),
                StorageRights::READ.union(StorageRights::DELEGATE),
            )
            .unwrap();
        let grandchild = table
            .derive(child, principal(2), principal(3), StorageRights::READ)
            .unwrap();
        assert_eq!(table.revoke(root, principal(1)), Ok(3));
        for (handle, owner) in [(child, principal(2)), (grandchild, principal(3))] {
            assert_eq!(
                table.authorize(handle, owner, StorageObjectKind::File, StorageRights::READ),
                Err(StorageAuthorityError::InvalidHandle)
            );
        }
        let replacement = table
            .insert(
                object(3),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(2),
            )
            .unwrap();
        assert_ne!(replacement, child);
    }
    #[test]
    fn attenuation_and_full_table_fail_without_changing_source() {
        let mut table = StorageAuthorityTable::<1>::new();
        let root = table
            .insert(
                object(4),
                StorageObjectKind::Directory,
                StorageRights::LOOKUP.union(StorageRights::DELEGATE),
                principal(1),
            )
            .unwrap();
        assert_eq!(
            table.derive(root, principal(1), principal(2), StorageRights::LOOKUP),
            Err(StorageAuthorityError::Full)
        );
        assert_eq!(
            table.authorize(
                root,
                principal(1),
                StorageObjectKind::Directory,
                StorageRights::LOOKUP
            ),
            Ok(object(4))
        );
        assert_eq!(
            table.derive(
                root,
                principal(1),
                principal(2),
                StorageRights::LOOKUP.union(StorageRights::REMOVE_CHILD)
            ),
            Err(StorageAuthorityError::Denied)
        );
    }
}
