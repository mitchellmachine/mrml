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
    pub const OPEN_CHILD: Self = Self(1 << 6);
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
        | Self::OPEN_CHILD.0
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
    reserved: bool,
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
        reserved: false,
        retired: false,
    };
}

pub struct StorageAuthorityTable<const N: usize> {
    entries: [Entry; N],
}

#[derive(Debug, Eq, PartialEq)]
pub struct StorageAuthorityReservation {
    slot: u32,
    generation: u32,
    object: StorageObjectId,
    kind: StorageObjectKind,
    rights: StorageRights,
    owner: StoragePrincipal,
    parent: Option<StorageHandle>,
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
    pub fn has_capacity(&self) -> bool {
        self.entries.iter().enumerate().any(|(slot, entry)| {
            entry.object.is_none() && !entry.retired && u32::try_from(slot).is_ok()
        })
    }

    pub fn reserve_insert(
        &mut self,
        object: StorageObjectId,
        kind: StorageObjectKind,
        rights: StorageRights,
        owner: StoragePrincipal,
    ) -> Result<StorageAuthorityReservation, StorageAuthorityError> {
        self.reserve_insert_derived(object, kind, rights, owner, None)
    }

    pub fn reserve_child_insert(
        &mut self,
        parent: StorageHandle,
        owner: StoragePrincipal,
        required_parent_right: StorageRights,
        object: StorageObjectId,
        kind: StorageObjectKind,
        rights: StorageRights,
    ) -> Result<StorageAuthorityReservation, StorageAuthorityError> {
        let parent_entry = *self.entry(parent)?;
        if parent_entry.owner != Some(owner)
            || parent_entry.kind != StorageObjectKind::Directory
            || !parent_entry.rights.contains(required_parent_right)
        {
            return Err(StorageAuthorityError::Denied);
        }
        self.reserve_insert_derived(object, kind, rights, owner, Some(parent))
    }

    fn reserve_insert_derived(
        &mut self,
        object: StorageObjectId,
        kind: StorageObjectKind,
        rights: StorageRights,
        owner: StoragePrincipal,
        parent: Option<StorageHandle>,
    ) -> Result<StorageAuthorityReservation, StorageAuthorityError> {
        if !rights.valid_for(kind) {
            return Err(StorageAuthorityError::InvalidRights);
        }
        let (slot, entry) = self
            .entries
            .iter_mut()
            .enumerate()
            .find(|(_, entry)| entry.object.is_none() && !entry.retired)
            .ok_or(StorageAuthorityError::Full)?;
        let slot = u32::try_from(slot).map_err(|_| StorageAuthorityError::Full)?;
        entry.object = Some(object);
        entry.kind = kind;
        entry.rights = rights;
        entry.owner = Some(owner);
        entry.parent = parent;
        entry.reserved = true;
        Ok(StorageAuthorityReservation {
            slot,
            generation: entry.generation,
            object,
            kind,
            rights,
            owner,
            parent,
        })
    }

    pub fn activate_reservation(
        &mut self,
        reservation: StorageAuthorityReservation,
    ) -> Result<StorageHandle, StorageAuthorityError> {
        let entry = self.reserved_entry_mut(&reservation)?;
        entry.reserved = false;
        Ok(StorageHandle {
            slot: reservation.slot,
            generation: reservation.generation,
        })
    }

    pub(crate) fn reservation_is_valid(&self, reservation: &StorageAuthorityReservation) -> bool {
        usize::try_from(reservation.slot)
            .ok()
            .and_then(|slot| self.entries.get(slot))
            .is_some_and(|entry| reservation.matches(*entry))
    }

    pub(crate) fn reservation_parent_matches(
        &self,
        reservation: &StorageAuthorityReservation,
        parent_object: StorageObjectId,
        required_right: StorageRights,
    ) -> bool {
        reservation.parent.is_some_and(|parent| {
            self.entry(parent).is_ok_and(|entry| {
                entry.object == Some(parent_object)
                    && entry.kind == StorageObjectKind::Directory
                    && entry.owner == Some(reservation.owner)
                    && entry.rights.contains(required_right)
            })
        })
    }

    pub(crate) fn activate_validated(
        &mut self,
        reservation: StorageAuthorityReservation,
    ) -> StorageHandle {
        let slot = reservation.slot as usize;
        debug_assert!(self.reservation_is_valid(&reservation));
        self.entries[slot].reserved = false;
        StorageHandle {
            slot: reservation.slot,
            generation: reservation.generation,
        }
    }

    pub fn cancel_reservation(
        &mut self,
        reservation: StorageAuthorityReservation,
    ) -> Result<(), StorageAuthorityError> {
        let entry = self.reserved_entry_mut(&reservation)?;
        Self::retire(entry);
        Ok(())
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

    pub(crate) fn insert_child_derived(
        &mut self,
        parent: StorageHandle,
        owner: StoragePrincipal,
        required_parent_right: StorageRights,
        object: StorageObjectId,
        kind: StorageObjectKind,
        requested: StorageRights,
    ) -> Result<StorageHandle, StorageAuthorityError> {
        let parent_entry = *self.entry(parent)?;
        if parent_entry.owner != Some(owner)
            || parent_entry.kind != StorageObjectKind::Directory
            || !parent_entry.rights.contains(required_parent_right)
            || !requested.valid_for(kind)
        {
            return Err(StorageAuthorityError::Denied);
        }
        self.insert_derived(object, kind, requested, owner, Some(parent))
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
            || entry.reserved
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
        let slot = u32::try_from(slot).map_err(|_| StorageAuthorityError::Full)?;
        entry.object = Some(object);
        entry.kind = kind;
        entry.rights = rights;
        entry.owner = Some(owner);
        entry.parent = parent;
        entry.reserved = false;
        Ok(StorageHandle {
            slot,
            generation: entry.generation,
        })
    }
    fn retire(entry: &mut Entry) {
        entry.object = None;
        entry.rights = StorageRights::NONE;
        entry.owner = None;
        entry.parent = None;
        entry.reserved = false;
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
            .filter(|entry| {
                entry.object.is_some() && !entry.reserved && entry.generation == handle.generation
            })
            .ok_or(StorageAuthorityError::InvalidHandle)
    }

    fn reserved_entry_mut(
        &mut self,
        reservation: &StorageAuthorityReservation,
    ) -> Result<&mut Entry, StorageAuthorityError> {
        let slot = usize::try_from(reservation.slot)
            .map_err(|_| StorageAuthorityError::InvalidReservation)?;
        self.entries
            .get_mut(slot)
            .filter(|entry| reservation.matches(**entry))
            .ok_or(StorageAuthorityError::InvalidReservation)
    }
}

impl StorageAuthorityReservation {
    pub(crate) const fn object(&self) -> StorageObjectId {
        self.object
    }

    pub(crate) const fn kind(&self) -> StorageObjectKind {
        self.kind
    }

    pub(crate) const fn has_parent(&self) -> bool {
        self.parent.is_some()
    }

    fn matches(&self, entry: Entry) -> bool {
        entry.reserved
            && entry.generation == self.generation
            && entry.object == Some(self.object)
            && entry.kind == self.kind
            && entry.rights == self.rights
            && entry.owner == Some(self.owner)
            && entry.parent == self.parent
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
    InvalidReservation,
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
    fn inactive_authority_reservations_cancel_or_activate_exactly_once() {
        let mut table = StorageAuthorityTable::<1>::new();
        let reservation = table
            .reserve_insert(
                object(9),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(1),
            )
            .unwrap();
        let guessed = StorageHandle {
            slot: reservation.slot,
            generation: reservation.generation,
        };
        assert_eq!(
            table.authorize(
                guessed,
                principal(1),
                StorageObjectKind::File,
                StorageRights::READ
            ),
            Err(StorageAuthorityError::InvalidHandle)
        );
        assert!(!table.has_capacity());
        let stale = StorageAuthorityReservation {
            slot: reservation.slot,
            generation: reservation.generation,
            object: reservation.object,
            kind: reservation.kind,
            rights: reservation.rights,
            owner: reservation.owner,
            parent: reservation.parent,
        };
        table.cancel_reservation(reservation).unwrap();
        assert_eq!(
            table.activate_reservation(stale),
            Err(StorageAuthorityError::InvalidReservation)
        );

        let reservation = table
            .reserve_insert(
                object(10),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(1),
            )
            .unwrap();
        let replay = StorageAuthorityReservation {
            slot: reservation.slot,
            generation: reservation.generation,
            object: reservation.object,
            kind: reservation.kind,
            rights: reservation.rights,
            owner: reservation.owner,
            parent: reservation.parent,
        };
        let handle = table.activate_reservation(reservation).unwrap();
        assert_eq!(handle.generation, 2);
        assert_eq!(
            table.authorize(
                handle,
                principal(1),
                StorageObjectKind::File,
                StorageRights::READ
            ),
            Ok(object(10))
        );
        assert_eq!(
            table.activate_reservation(replay),
            Err(StorageAuthorityError::InvalidReservation)
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
