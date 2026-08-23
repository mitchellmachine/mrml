use crate::{
    DirectoryEntry, DirectoryMetadata, MetadataPointer, StorageAuthorityError,
    StorageAuthorityTable, StorageHandle, StorageName, StorageObjectId, StorageObjectKind,
    StoragePrincipal, StorageRights, VolumeHeader, VolumeId,
};

pub struct StorageObjectAllocator {
    volume: VolumeId,
    next_local: Option<u64>,
}

impl StorageObjectAllocator {
    pub const fn new(volume: VolumeId, next_local: u64) -> Result<Self, DirectoryError> {
        if next_local == 0 {
            return Err(DirectoryError::IdentityExhausted);
        }
        Ok(Self {
            volume,
            next_local: Some(next_local),
        })
    }

    pub fn peek(&self) -> Result<StorageObjectId, DirectoryError> {
        StorageObjectId::new(
            self.volume,
            self.next_local.ok_or(DirectoryError::IdentityExhausted)?,
        )
        .map_err(|_| DirectoryError::IdentityExhausted)
    }

    fn consume(&mut self) -> Result<StorageObjectId, DirectoryError> {
        let object = self.peek()?;
        self.next_local = object.local().checked_add(1);
        Ok(object)
    }
}

pub struct DirectoryState<const N: usize> {
    object: StorageObjectId,
    generation: u64,
    entries: [Option<DirectoryEntry>; N],
    count: usize,
}

impl<const N: usize> DirectoryState<N> {
    pub fn new(
        object: StorageObjectId,
        generation: u64,
        entries: &[DirectoryEntry],
    ) -> Result<Self, DirectoryError> {
        if generation == 0 || entries.len() > N {
            return Err(DirectoryError::InvalidState);
        }
        let mut stored = [None; N];
        for (index, entry) in entries.iter().copied().enumerate() {
            if entry.object().volume() != object.volume()
                || entry.object() == object
                || entries[..index]
                    .iter()
                    .any(|prior| prior.name() == entry.name() || prior.object() == entry.object())
            {
                return Err(DirectoryError::InvalidState);
            }
            stored[index] = Some(entry);
        }
        Ok(Self {
            object,
            generation,
            entries: stored,
            count: entries.len(),
        })
    }

    pub const fn object(&self) -> StorageObjectId {
        self.object
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn metadata(
        &self,
        header: VolumeHeader,
        parent: Option<StorageObjectId>,
        entries: MetadataPointer,
    ) -> Result<DirectoryMetadata, DirectoryError> {
        DirectoryMetadata::new(
            header,
            self.object,
            self.generation,
            parent,
            u32::try_from(self.count).map_err(|_| DirectoryError::Capacity)?,
            entries,
        )
        .map_err(|_| DirectoryError::InvalidState)
    }

    pub fn lookup<const A: usize>(
        &self,
        authority: &StorageAuthorityTable<A>,
        directory: StorageHandle,
        principal: StoragePrincipal,
        name: StorageName,
    ) -> Result<DirectoryEntry, DirectoryError> {
        self.authorize(authority, directory, principal, StorageRights::LOOKUP)?;
        let index = self.find_name(name).ok_or(DirectoryError::NotFound)?;
        self.entries[index].ok_or(DirectoryError::InvalidState)
    }

    pub fn enumerate<const A: usize>(
        &self,
        authority: &StorageAuthorityTable<A>,
        directory: StorageHandle,
        principal: StoragePrincipal,
        index: usize,
    ) -> Result<DirectoryEntry, DirectoryError> {
        self.authorize(authority, directory, principal, StorageRights::ENUMERATE)?;
        self.entries
            .iter()
            .flatten()
            .nth(index)
            .copied()
            .ok_or(DirectoryError::NotFound)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create<const A: usize>(
        &mut self,
        authority: &mut StorageAuthorityTable<A>,
        directory: StorageHandle,
        principal: StoragePrincipal,
        allocator: &mut StorageObjectAllocator,
        name: StorageName,
        kind: StorageObjectKind,
        initial_rights: StorageRights,
    ) -> Result<(DirectoryEntry, StorageHandle), DirectoryError> {
        let create_right = match kind {
            StorageObjectKind::File => StorageRights::CREATE_FILE,
            StorageObjectKind::Directory => StorageRights::CREATE_DIRECTORY,
            StorageObjectKind::Volume => return Err(DirectoryError::InvalidKind),
        };
        self.authorize(authority, directory, principal, create_right)?;
        let slot = self.preflight_insert(name, allocator.peek()?)?;
        self.next_generation()?;
        StorageRights::from_bits(kind, initial_rights.bits()).map_err(DirectoryError::Authority)?;
        if !authority.has_capacity() {
            return Err(DirectoryError::Authority(StorageAuthorityError::Full));
        }

        let object = allocator.peek()?;
        let entry =
            DirectoryEntry::new(name, object, kind, 1).map_err(|_| DirectoryError::InvalidState)?;
        let child = authority
            .insert(object, kind, initial_rights, principal)
            .map_err(DirectoryError::Authority)?;
        let consumed = allocator.consume()?;
        debug_assert_eq!(consumed, object);
        self.entries[slot] = Some(entry);
        self.count += 1;
        self.generation += 1;
        Ok((entry, child))
    }

    pub fn remove<const A: usize>(
        &mut self,
        authority: &StorageAuthorityTable<A>,
        directory: StorageHandle,
        principal: StoragePrincipal,
        name: StorageName,
    ) -> Result<DirectoryEntry, DirectoryError> {
        self.authorize(authority, directory, principal, StorageRights::REMOVE_CHILD)?;
        let index = self.find_name(name).ok_or(DirectoryError::NotFound)?;
        self.next_generation()?;
        let removed = self.entries[index]
            .take()
            .ok_or(DirectoryError::InvalidState)?;
        self.count -= 1;
        self.generation += 1;
        Ok(removed)
    }

    pub fn rename<const A: usize>(
        &mut self,
        authority: &StorageAuthorityTable<A>,
        directory: StorageHandle,
        principal: StoragePrincipal,
        old_name: StorageName,
        new_name: StorageName,
    ) -> Result<DirectoryEntry, DirectoryError> {
        self.authorize(authority, directory, principal, StorageRights::RENAME_CHILD)?;
        let index = self.find_name(old_name).ok_or(DirectoryError::NotFound)?;
        if self.find_name(new_name).is_some() {
            return Err(DirectoryError::AlreadyExists);
        }
        self.next_generation()?;
        let old = self.entries[index].ok_or(DirectoryError::InvalidState)?;
        let renamed = DirectoryEntry::new(
            new_name,
            old.object(),
            old.kind(),
            old.metadata_generation(),
        )
        .map_err(|_| DirectoryError::InvalidState)?;
        self.entries[index] = Some(renamed);
        self.generation += 1;
        Ok(renamed)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn move_to<const M: usize, const A: usize>(
        &mut self,
        source_authority: StorageHandle,
        destination: &mut DirectoryState<M>,
        destination_authority: StorageHandle,
        authority: &StorageAuthorityTable<A>,
        principal: StoragePrincipal,
        old_name: StorageName,
        new_name: StorageName,
    ) -> Result<DirectoryEntry, DirectoryError> {
        if self.object == destination.object {
            return Err(DirectoryError::SameDirectory);
        }
        self.authorize(
            authority,
            source_authority,
            principal,
            StorageRights::RENAME_CHILD,
        )?;
        destination.authorize(
            authority,
            destination_authority,
            principal,
            StorageRights::RENAME_CHILD,
        )?;
        let source_index = self.find_name(old_name).ok_or(DirectoryError::NotFound)?;
        let old = self.entries[source_index].ok_or(DirectoryError::InvalidState)?;
        if old.kind() == StorageObjectKind::Directory {
            return Err(DirectoryError::AncestryRequired);
        }
        let destination_slot = destination.preflight_insert(new_name, old.object())?;
        self.next_generation()?;
        destination.next_generation()?;
        let moved = DirectoryEntry::new(
            new_name,
            old.object(),
            old.kind(),
            old.metadata_generation(),
        )
        .map_err(|_| DirectoryError::InvalidState)?;

        self.entries[source_index] = None;
        self.count -= 1;
        self.generation += 1;
        destination.entries[destination_slot] = Some(moved);
        destination.count += 1;
        destination.generation += 1;
        Ok(moved)
    }

    fn authorize<const A: usize>(
        &self,
        authority: &StorageAuthorityTable<A>,
        handle: StorageHandle,
        principal: StoragePrincipal,
        rights: StorageRights,
    ) -> Result<(), DirectoryError> {
        let object = authority
            .authorize(handle, principal, StorageObjectKind::Directory, rights)
            .map_err(DirectoryError::Authority)?;
        if object != self.object {
            return Err(DirectoryError::WrongDirectory);
        }
        Ok(())
    }

    fn find_name(&self, name: StorageName) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.name() == name))
    }

    fn preflight_insert(
        &self,
        name: StorageName,
        object: StorageObjectId,
    ) -> Result<usize, DirectoryError> {
        if object.volume() != self.object.volume() {
            return Err(DirectoryError::WrongVolume);
        }
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.name() == name || entry.object() == object)
        {
            return Err(DirectoryError::AlreadyExists);
        }
        self.entries
            .iter()
            .position(Option::is_none)
            .ok_or(DirectoryError::Capacity)
    }

    fn next_generation(&self) -> Result<u64, DirectoryError> {
        self.generation
            .checked_add(1)
            .ok_or(DirectoryError::GenerationExhausted)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryError {
    Authority(StorageAuthorityError),
    InvalidState,
    InvalidKind,
    WrongDirectory,
    WrongVolume,
    NotFound,
    AlreadyExists,
    Capacity,
    GenerationExhausted,
    IdentityExhausted,
    SameDirectory,
    AncestryRequired,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume() -> VolumeId {
        VolumeId::new([4; 16]).unwrap()
    }

    fn object(local: u64) -> StorageObjectId {
        StorageObjectId::new(volume(), local).unwrap()
    }

    fn name(value: &str) -> StorageName {
        StorageName::new(value).unwrap()
    }

    fn principal() -> StoragePrincipal {
        StoragePrincipal::new(1).unwrap()
    }

    fn directory_rights() -> StorageRights {
        StorageRights::LOOKUP
            .union(StorageRights::ENUMERATE)
            .union(StorageRights::CREATE_FILE)
            .union(StorageRights::CREATE_DIRECTORY)
            .union(StorageRights::RENAME_CHILD)
            .union(StorageRights::REMOVE_CHILD)
    }

    #[test]
    fn create_returns_object_bound_authority_and_supports_lookup() {
        let mut authority = StorageAuthorityTable::<4>::new();
        let root = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                directory_rights(),
                principal(),
            )
            .unwrap();
        let mut allocator = StorageObjectAllocator::new(volume(), 10).unwrap();
        let mut directory = DirectoryState::<2>::new(object(1), 1, &[]).unwrap();
        let (entry, child) = directory
            .create(
                &mut authority,
                root,
                principal(),
                &mut allocator,
                name("file"),
                StorageObjectKind::File,
                StorageRights::READ.union(StorageRights::WRITE),
            )
            .unwrap();
        assert_eq!(entry.object(), object(10));
        assert_eq!(directory.generation(), 2);
        assert_eq!(
            directory.lookup(&authority, root, principal(), name("file")),
            Ok(entry)
        );
        assert_eq!(
            directory.enumerate(&authority, root, principal(), 0),
            Ok(entry)
        );
        assert_eq!(
            authority.authorize(
                child,
                principal(),
                StorageObjectKind::File,
                StorageRights::WRITE
            ),
            Ok(object(10))
        );
    }

    #[test]
    fn denied_or_full_create_changes_neither_directory_nor_allocator() {
        let mut authority = StorageAuthorityTable::<2>::new();
        let lookup_only = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::LOOKUP,
                principal(),
            )
            .unwrap();
        let mut allocator = StorageObjectAllocator::new(volume(), 10).unwrap();
        let mut directory = DirectoryState::<1>::new(object(1), 1, &[]).unwrap();
        assert!(matches!(
            directory.create(
                &mut authority,
                lookup_only,
                principal(),
                &mut allocator,
                name("denied"),
                StorageObjectKind::File,
                StorageRights::READ
            ),
            Err(DirectoryError::Authority(_))
        ));
        assert_eq!(directory.generation(), 1);
        assert_eq!(allocator.peek(), Ok(object(10)));
        let root = authority
            .insert(
                object(2),
                StorageObjectKind::Directory,
                StorageRights::CREATE_FILE,
                principal(),
            )
            .unwrap();
        let mut other = DirectoryState::<1>::new(object(2), 1, &[]).unwrap();
        assert!(matches!(
            other.create(
                &mut authority,
                root,
                principal(),
                &mut allocator,
                name("full"),
                StorageObjectKind::File,
                StorageRights::READ
            ),
            Err(DirectoryError::Authority(StorageAuthorityError::Full))
        ));
        assert_eq!(allocator.peek(), Ok(object(10)));
    }

    #[test]
    fn duplicate_state_and_generation_exhaustion_fail_without_mutation() {
        let first =
            DirectoryEntry::new(name("same"), object(8), StorageObjectKind::File, 1).unwrap();
        let duplicate_name =
            DirectoryEntry::new(name("same"), object(9), StorageObjectKind::File, 1).unwrap();
        assert!(matches!(
            DirectoryState::<2>::new(object(1), 1, &[first, duplicate_name]),
            Err(DirectoryError::InvalidState)
        ));
        let self_entry =
            DirectoryEntry::new(name("self"), object(1), StorageObjectKind::Directory, 1).unwrap();
        assert!(matches!(
            DirectoryState::<1>::new(object(1), 1, &[self_entry]),
            Err(DirectoryError::InvalidState)
        ));
        let mut directory = DirectoryState::<2>::new(object(1), u64::MAX, &[first]).unwrap();
        let mut authority = StorageAuthorityTable::<1>::new();
        let rename = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::RENAME_CHILD,
                principal(),
            )
            .unwrap();
        assert_eq!(
            directory.rename(&authority, rename, principal(), name("same"), name("new")),
            Err(DirectoryError::GenerationExhausted)
        );
        assert_eq!((directory.len(), directory.generation()), (1, u64::MAX));
    }

    #[test]
    fn identity_allocator_issues_maximum_identity_once_then_exhausts() {
        let mut allocator = StorageObjectAllocator::new(volume(), u64::MAX).unwrap();
        assert_eq!(allocator.peek(), Ok(object(u64::MAX)));
        assert_eq!(allocator.consume(), Ok(object(u64::MAX)));
        assert_eq!(allocator.peek(), Err(DirectoryError::IdentityExhausted));
        assert_eq!(allocator.consume(), Err(DirectoryError::IdentityExhausted));
    }

    #[test]
    fn rename_preserves_identity_and_existing_object_capability() {
        let entry =
            DirectoryEntry::new(name("old"), object(9), StorageObjectKind::File, 3).unwrap();
        let mut directory = DirectoryState::<2>::new(object(1), 4, &[entry]).unwrap();
        let mut authority = StorageAuthorityTable::<2>::new();
        let root = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::RENAME_CHILD,
                principal(),
            )
            .unwrap();
        let open = authority
            .insert(
                object(9),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(),
            )
            .unwrap();
        let renamed = directory
            .rename(&authority, root, principal(), name("old"), name("new"))
            .unwrap();
        assert_eq!(renamed.object(), entry.object());
        assert_eq!(renamed.metadata_generation(), 3);
        assert_eq!(
            authority.authorize(
                open,
                principal(),
                StorageObjectKind::File,
                StorageRights::READ
            ),
            Ok(object(9))
        );
    }

    #[test]
    fn cross_directory_move_preflights_destination_before_mutation() {
        let entry =
            DirectoryEntry::new(name("old"), object(9), StorageObjectKind::File, 3).unwrap();
        let occupied =
            DirectoryEntry::new(name("occupied"), object(8), StorageObjectKind::File, 1).unwrap();
        let mut source = DirectoryState::<1>::new(object(1), 4, &[entry]).unwrap();
        let mut destination = DirectoryState::<1>::new(object(2), 7, &[occupied]).unwrap();
        let mut authority = StorageAuthorityTable::<2>::new();
        let source_handle = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::RENAME_CHILD,
                principal(),
            )
            .unwrap();
        let destination_handle = authority
            .insert(
                object(2),
                StorageObjectKind::Directory,
                StorageRights::RENAME_CHILD,
                principal(),
            )
            .unwrap();
        assert_eq!(
            source.move_to(
                source_handle,
                &mut destination,
                destination_handle,
                &authority,
                principal(),
                name("old"),
                name("new")
            ),
            Err(DirectoryError::Capacity)
        );
        assert_eq!((source.len(), source.generation()), (1, 4));
        assert_eq!((destination.len(), destination.generation()), (1, 7));
        let mut empty = DirectoryState::<1>::new(object(3), 1, &[]).unwrap();
        // A distinct destination requires its own exact authority.
        let mut authority = StorageAuthorityTable::<3>::new();
        let source_handle = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::RENAME_CHILD,
                principal(),
            )
            .unwrap();
        let empty_authority = authority
            .insert(
                object(3),
                StorageObjectKind::Directory,
                StorageRights::RENAME_CHILD,
                principal(),
            )
            .unwrap();
        let moved = source
            .move_to(
                source_handle,
                &mut empty,
                empty_authority,
                &authority,
                principal(),
                name("old"),
                name("new"),
            )
            .unwrap();
        assert_eq!(moved.object(), object(9));
        assert_eq!((source.len(), source.generation()), (0, 5));
        assert_eq!((empty.len(), empty.generation()), (1, 2));
    }

    #[test]
    fn remove_requires_right_and_does_not_revoke_open_object_authority() {
        let entry =
            DirectoryEntry::new(name("file"), object(9), StorageObjectKind::File, 1).unwrap();
        let mut directory = DirectoryState::<1>::new(object(1), 1, &[entry]).unwrap();
        let mut authority = StorageAuthorityTable::<3>::new();
        let denied = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::LOOKUP,
                principal(),
            )
            .unwrap();
        let remove = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::REMOVE_CHILD,
                principal(),
            )
            .unwrap();
        let open = authority
            .insert(
                object(9),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(),
            )
            .unwrap();
        assert!(
            directory
                .remove(&authority, denied, principal(), name("file"))
                .is_err()
        );
        assert_eq!(
            directory.remove(&authority, remove, principal(), name("file")),
            Ok(entry)
        );
        assert_eq!(
            authority.authorize(
                open,
                principal(),
                StorageObjectKind::File,
                StorageRights::READ
            ),
            Ok(object(9))
        );
    }

    #[test]
    fn cross_directory_directory_move_requires_future_ancestry_proof() {
        let child =
            DirectoryEntry::new(name("child"), object(9), StorageObjectKind::Directory, 1).unwrap();
        let mut source = DirectoryState::<1>::new(object(1), 1, &[child]).unwrap();
        let mut destination = DirectoryState::<1>::new(object(2), 1, &[]).unwrap();
        let mut authority = StorageAuthorityTable::<2>::new();
        let source_handle = authority
            .insert(
                object(1),
                StorageObjectKind::Directory,
                StorageRights::RENAME_CHILD,
                principal(),
            )
            .unwrap();
        let destination_handle = authority
            .insert(
                object(2),
                StorageObjectKind::Directory,
                StorageRights::RENAME_CHILD,
                principal(),
            )
            .unwrap();
        assert_eq!(
            source.move_to(
                source_handle,
                &mut destination,
                destination_handle,
                &authority,
                principal(),
                name("child"),
                name("moved"),
            ),
            Err(DirectoryError::AncestryRequired)
        );
        assert_eq!((source.len(), source.generation()), (1, 1));
        assert_eq!((destination.len(), destination.generation()), (0, 1));
    }
}
