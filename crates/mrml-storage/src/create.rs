use crate::{
    AllocationImage, AllocationKind, CommittedDirectoryMovePlan, CowMetadataImage, CowPlanError,
    CowPublicationPlan, DirectoryState, FileState, MetadataPointer, ObjectIdAllocatorImage,
    PreparedAllocationUpdate, PreparedDirectoryMovePlan, PreparedInitialDirectory,
    PreparedInitialFile, PreparedObjectIdReservation, StorageAuthorityError,
    StorageAuthorityReservation, StorageAuthorityTable, StorageHandle, StorageObjectId,
    StorageObjectKind, StorageTransaction, StorageTransactionId, Superblock, TransactionError,
    TransactionParticipant, TransactionReceipt, VolumeHeader,
};

pub enum PreparedInitialObject {
    File(PreparedInitialFile),
    Directory(PreparedInitialDirectory),
}

impl PreparedInitialObject {
    pub const fn object(&self) -> StorageObjectId {
        match self {
            Self::File(file) => file.object(),
            Self::Directory(directory) => directory.object(),
        }
    }

    pub const fn kind(&self) -> StorageObjectKind {
        match self {
            Self::File(_) => StorageObjectKind::File,
            Self::Directory(_) => StorageObjectKind::Directory,
        }
    }

    fn participant(&self) -> Result<TransactionParticipant, TransactionError> {
        match self {
            Self::File(file) => file.transaction_participant(),
            Self::Directory(directory) => directory.transaction_participant(),
        }
    }

    fn images(&self) -> [CowMetadataImage; 2] {
        match self {
            Self::File(file) => file.metadata_images(),
            Self::Directory(directory) => directory.metadata_images(),
        }
    }

    fn allocation_owned_by<const A: usize>(
        &self,
        allocation: &PreparedAllocationUpdate<A>,
    ) -> bool {
        let images = self.images();
        let subordinate_kind = match self {
            Self::File(_) => AllocationKind::FileExtents,
            Self::Directory(_) => AllocationKind::DirectoryEntries,
        };
        allocation.owns_image(
            self.object(),
            1,
            images[0].pointer(),
            AllocationKind::ObjectMetadata,
        ) && allocation.owns_image(self.object(), 1, images[1].pointer(), subordinate_kind)
    }

    fn admit<const P: usize, const W: usize>(
        &self,
        transaction: &mut StorageTransaction<P, W>,
    ) -> Result<(), TransactionError> {
        match self {
            Self::File(file) => transaction.admit_initial_file(file),
            Self::Directory(directory) => transaction.admit_initial_directory(directory),
        }
    }

    fn into_state(self) -> InitialObjectState {
        match self {
            Self::File(file) => InitialObjectState::File(file.into_state()),
            Self::Directory(directory) => InitialObjectState::Directory(directory.into_state()),
        }
    }
}

pub enum InitialObjectState {
    File(FileState<0>),
    Directory(DirectoryState<0>),
}

pub struct PreparedCreate<const C: usize, const E: usize, const A: usize> {
    directories: PreparedDirectoryMovePlan<C, E>,
    child: PreparedInitialObject,
    object_id: PreparedObjectIdReservation,
    allocation: PreparedAllocationUpdate<A>,
    authority: StorageAuthorityReservation,
}

impl<const C: usize, const E: usize, const A: usize> PreparedCreate<C, E, A> {
    pub fn new(
        directories: PreparedDirectoryMovePlan<C, E>,
        child: PreparedInitialObject,
        object_id: PreparedObjectIdReservation,
        allocation: PreparedAllocationUpdate<A>,
        authority: StorageAuthorityReservation,
    ) -> Result<Self, PreparedCreateError> {
        if directories.is_empty()
            || child.object() != object_id.allocated()
            || authority.object() != child.object()
            || authority.kind() != child.kind()
        {
            return Err(PreparedCreateError::InvalidBinding);
        }
        Ok(Self {
            directories,
            child,
            object_id,
            allocation,
            authority,
        })
    }

    pub const fn object(&self) -> StorageObjectId {
        self.child.object()
    }

    pub fn transaction<const P: usize, const W: usize>(
        &self,
        identity: StorageTransactionId,
        publication_generation: u64,
    ) -> Result<StorageTransaction<P, W>, TransactionError> {
        let mut transaction = StorageTransaction::new(identity, publication_generation)?;
        for index in 0..self.directories.len() {
            transaction.admit_directory(
                self.directories
                    .update(index)
                    .ok_or(TransactionError::ParticipantMismatch)?,
            )?;
        }
        self.child.admit(&mut transaction)?;
        transaction.admit_object_id_allocator(&self.object_id)?;
        transaction.admit_allocation(&self.allocation)?;
        Ok(transaction)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn publication_plan<const W: usize>(
        &self,
        header: VolumeHeader,
        active_superblock_block: u64,
        active: Superblock,
        root: StorageObjectId,
        protected_active: &[MetadataPointer],
    ) -> Result<CowPublicationPlan<W>, CowPlanError> {
        let publication_generation = active
            .generation()
            .checked_add(1)
            .ok_or(CowPlanError::GenerationExhausted)?;
        let required = self
            .directories
            .len()
            .checked_mul(2)
            .and_then(|count| count.checked_add(4))
            .ok_or(CowPlanError::Capacity)?;
        if required > W {
            return Err(CowPlanError::Capacity);
        }
        if self.allocation.generation() != publication_generation
            || self.object_id.generation() != publication_generation
            || !self.object_id.allocation_owned_by(&self.allocation, root)
            || !self.child.allocation_owned_by(&self.allocation)
        {
            return Err(CowPlanError::InvalidWrite);
        }
        let root_metadata = self
            .directories
            .update(0)
            .and_then(|_| {
                (0..self.directories.len())
                    .filter_map(|index| self.directories.update(index))
                    .find(|update| update.object() == root)
            })
            .ok_or(CowPlanError::MissingPublicationRoot)?
            .metadata_image()
            .pointer();
        for index in 0..self.directories.len() {
            let update = self
                .directories
                .update(index)
                .ok_or(CowPlanError::InvalidWrite)?;
            if !self.allocation.owns_image(
                update.object(),
                update.generation(),
                update.metadata_image().pointer(),
                AllocationKind::ObjectMetadata,
            ) || !self.allocation.owns_image(
                update.object(),
                update.generation(),
                update.entries_image().pointer(),
                AllocationKind::DirectoryEntries,
            ) {
                return Err(CowPlanError::InvalidWrite);
            }
        }
        let allocation_write = self
            .allocation
            .metadata_image()
            .bind(publication_generation)?;
        let mut writes = [allocation_write; W];
        let mut count = 0;
        for index in 0..self.directories.len() {
            for image in self
                .directories
                .update(index)
                .ok_or(CowPlanError::InvalidWrite)?
                .metadata_images()
            {
                writes[count] = image.bind(publication_generation)?;
                count += 1;
            }
        }
        for image in self.child.images() {
            writes[count] = image.bind(publication_generation)?;
            count += 1;
        }
        writes[count] = self
            .object_id
            .metadata_image()
            .bind(publication_generation)?;
        count += 1;
        writes[count] = allocation_write;
        count += 1;
        CowPublicationPlan::build(
            header,
            active_superblock_block,
            active,
            root,
            root_metadata,
            self.allocation.pointer(),
            &writes[..count],
            protected_active,
        )
    }

    // Returning the bounded prepared value preserves the caller's ability to
    // retry or cancel after a hostile receipt/authority mismatch in `no_std`.
    #[allow(clippy::result_large_err)]
    pub fn commit<const P: usize, const N: usize>(
        self,
        receipt: &mut TransactionReceipt<P>,
        authorities: &mut StorageAuthorityTable<N>,
    ) -> Result<CommittedCreate<C, E, A>, (Self, CreateCommitError)> {
        if !authorities.reservation_is_valid(&self.authority) {
            return Err((self, CreateCommitError::Authority));
        }
        let (directory_participants, directory_count) = match self.directories.participants() {
            Ok(participants) => participants,
            Err(error) => return Err((self, CreateCommitError::Transaction(error))),
        };
        let additional = [
            self.child.participant().ok(),
            self.object_id.transaction_participant().ok(),
            self.allocation.transaction_participant().ok(),
        ];
        if additional.iter().any(Option::is_none) {
            return Err((
                self,
                CreateCommitError::Transaction(TransactionError::ParticipantMismatch),
            ));
        }
        if let Err(error) = receipt.consume_batch_with(
            &directory_participants,
            directory_count,
            &additional,
            additional.len(),
        ) {
            return Err((self, CreateCommitError::Transaction(error)));
        }
        let Self {
            directories,
            child,
            object_id,
            allocation,
            authority,
        } = self;
        let handle = authorities.activate_validated(authority);
        let (object_id_allocator, allocated) = object_id.into_successor();
        debug_assert_eq!(allocated, child.object());
        Ok(CommittedCreate {
            directories: directories.into_committed(),
            child: child.into_state(),
            object_id_allocator,
            allocation: allocation.into_successor(),
            handle,
        })
    }

    pub fn cancel<const N: usize>(
        self,
        authorities: &mut StorageAuthorityTable<N>,
    ) -> Result<(), StorageAuthorityError> {
        authorities.cancel_reservation(self.authority)
    }
}

pub struct CommittedCreate<const C: usize, const E: usize, const A: usize> {
    pub directories: CommittedDirectoryMovePlan<C, E>,
    pub child: InitialObjectState,
    pub object_id_allocator: ObjectIdAllocatorImage,
    pub allocation: AllocationImage<A>,
    pub handle: StorageHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedCreateError {
    InvalidBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateCommitError {
    Transaction(TransactionError),
    Authority,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AllocationChange, AllocationRecord, AllocationWriteBackend, CowMetadataWrite,
        CowPublicationBackend, DirectoryAncestryBackend, DirectoryEntry, DirectoryMetadata,
        DirectorySuccessorBackend, DirectorySuccessorLayout, DirectoryWriteBackend,
        InitialFileWriteBackend, ObjectIdAllocatorWriteBackend, StorageName, StoragePrincipal,
        StorageRights, VolumeId, prepare_initial_file, prove_directory_mutation_ancestry,
    };

    fn volume() -> VolumeId {
        VolumeId::new([12; 16]).unwrap()
    }

    fn object(local: u64) -> StorageObjectId {
        StorageObjectId::new(volume(), local).unwrap()
    }

    fn pointer(block: u64) -> MetadataPointer {
        MetadataPointer::new(block, 1).unwrap()
    }

    fn header() -> VolumeHeader {
        VolumeHeader::new(volume(), 4096, 200, 1, 2).unwrap()
    }

    struct Backend {
        root: DirectoryState<2>,
        staged: usize,
        verified: usize,
        replaced: usize,
    }

    unsafe impl DirectoryAncestryBackend for Backend {
        type Error = ();

        fn load_directory_metadata(
            &mut self,
            requested: StorageObjectId,
        ) -> Result<DirectoryMetadata, Self::Error> {
            assert_eq!(requested, object(1));
            Ok(DirectoryMetadata::new(header(), object(1), 5, None, 0, pointer(11)).unwrap())
        }
    }

    unsafe impl DirectorySuccessorBackend<2> for Backend {
        type Error = ();

        fn load_directory_state(
            &mut self,
            requested: StorageObjectId,
            generation: u64,
        ) -> Result<DirectoryState<2>, Self::Error> {
            assert_eq!((requested, generation), (object(1), 5));
            Ok(self.root.clone())
        }
    }

    unsafe impl DirectoryWriteBackend for Backend {
        type Error = ();

        fn stage_directory_metadata(
            &mut self,
            _image: CowMetadataImage,
            _encoded: &[u8; crate::DIRECTORY_METADATA_BYTES],
        ) -> Result<(), Self::Error> {
            self.staged += 1;
            Ok(())
        }

        fn stage_directory_entries(
            &mut self,
            _image: CowMetadataImage,
            _encoded: &[u8],
        ) -> Result<(), Self::Error> {
            self.staged += 1;
            Ok(())
        }

        fn flush_directory_update(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    unsafe impl InitialFileWriteBackend for Backend {
        type Error = ();

        fn stage_initial_file_metadata(
            &mut self,
            _image: CowMetadataImage,
            _encoded: &[u8; crate::FILE_METADATA_BYTES],
        ) -> Result<(), Self::Error> {
            self.staged += 1;
            Ok(())
        }

        fn stage_initial_file_extents(
            &mut self,
            _image: CowMetadataImage,
            _encoded: &[u8],
        ) -> Result<(), Self::Error> {
            self.staged += 1;
            Ok(())
        }

        fn flush_initial_file(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    unsafe impl ObjectIdAllocatorWriteBackend for Backend {
        type Error = ();

        fn stage_object_id_allocator(
            &mut self,
            _image: CowMetadataImage,
            _encoded: &[u8],
        ) -> Result<(), Self::Error> {
            self.staged += 1;
            Ok(())
        }

        fn flush_object_id_allocator(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    unsafe impl AllocationWriteBackend for Backend {
        type Error = ();

        fn stage_allocation_image(
            &mut self,
            _image: CowMetadataImage,
            _encoded: &[u8],
        ) -> Result<(), Self::Error> {
            self.staged += 1;
            Ok(())
        }

        fn flush_allocation_image(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    unsafe impl CowPublicationBackend for Backend {
        type Error = ();

        fn verify_new_metadata(&mut self, _write: CowMetadataWrite) -> Result<(), Self::Error> {
            self.verified += 1;
            Ok(())
        }

        fn flush_new_metadata(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn replace_superblock(
            &mut self,
            block: u64,
            _encoded: &[u8; crate::SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            assert_eq!(block, 2);
            self.replaced += 1;
            Ok(())
        }

        fn flush_superblock(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn complete_file_create_publishes_and_activates_as_one_receipt_set() {
        let root = object(1);
        let child = object(10);
        let mut backend = Backend {
            root: DirectoryState::new(root, 5, &[]).unwrap(),
            staged: 0,
            verified: 0,
            replaced: 0,
        };
        let proof = prove_directory_mutation_ancestry::<1, _>(root, root, 5, &mut backend).unwrap();
        let entry = DirectoryEntry::new(
            StorageName::new("created").unwrap(),
            child,
            StorageObjectKind::File,
            1,
        )
        .unwrap();
        let successor = proof
            .construct_create_successors::<1, 2, _>(entry, &mut backend)
            .unwrap();
        let mut directory_metadata = [[0; crate::DIRECTORY_METADATA_BYTES]; 1];
        let mut directory_entries = [[0; 4096]; 1];
        let directories = successor
            .stage(
                header(),
                &[DirectorySuccessorLayout::new(pointer(60), pointer(61))],
                &mut directory_metadata,
                &mut directory_entries,
                &mut backend,
            )
            .unwrap();
        let mut file_metadata = [0; crate::FILE_METADATA_BYTES];
        let mut file_extents = [0; 4096];
        let initial_file = prepare_initial_file(
            header(),
            child,
            pointer(62),
            pointer(63),
            &mut file_metadata,
            &mut file_extents,
            &mut backend,
        )
        .unwrap();
        let active_object_ids =
            ObjectIdAllocatorImage::build(header(), 5, Some(10), pointer(30)).unwrap();
        let mut object_id_output = [0; 4096];
        let object_id = active_object_ids
            .prepare_reservation(header(), pointer(64), &mut object_id_output, &mut backend)
            .unwrap();
        let active_allocation = AllocationImage::<8>::build(
            header(),
            5,
            pointer(20),
            &[
                AllocationRecord::new(root, 5, 10, 1, AllocationKind::ObjectMetadata).unwrap(),
                AllocationRecord::new(root, 5, 20, 1, AllocationKind::AllocationMetadata).unwrap(),
            ],
        )
        .unwrap();
        let changes = [
            AllocationChange::Allocate(
                AllocationRecord::new(root, 6, 60, 1, AllocationKind::ObjectMetadata).unwrap(),
            ),
            AllocationChange::Allocate(
                AllocationRecord::new(root, 6, 61, 1, AllocationKind::DirectoryEntries).unwrap(),
            ),
            AllocationChange::Allocate(
                AllocationRecord::new(child, 1, 62, 1, AllocationKind::ObjectMetadata).unwrap(),
            ),
            AllocationChange::Allocate(
                AllocationRecord::new(child, 1, 63, 1, AllocationKind::FileExtents).unwrap(),
            ),
            AllocationChange::Allocate(
                AllocationRecord::new(root, 6, 64, 1, AllocationKind::ObjectIdAllocatorMetadata)
                    .unwrap(),
            ),
        ];
        let mut allocation_output = [0; 4096];
        let allocation = active_allocation
            .prepare_successor(
                header(),
                root,
                pointer(65),
                &changes,
                &mut allocation_output,
                &mut backend,
            )
            .unwrap();
        let principal = StoragePrincipal::new(7).unwrap();
        let rights = StorageRights::READ.union(StorageRights::WRITE);
        let mut authorities = StorageAuthorityTable::<2>::new();
        let authority = authorities
            .reserve_insert(child, StorageObjectKind::File, rights, principal)
            .unwrap();
        let prepared = PreparedCreate::new(
            directories,
            PreparedInitialObject::File(initial_file),
            object_id,
            allocation,
            authority,
        )
        .unwrap();
        assert_eq!(
            authorities.authorize(
                StorageHandle::from_token(1_u64 << 32),
                principal,
                StorageObjectKind::File,
                StorageRights::READ,
            ),
            Err(StorageAuthorityError::InvalidHandle)
        );
        assert!(matches!(
            prepared.transaction::<3, 6>(StorageTransactionId::new(50).unwrap(), 6),
            Err(TransactionError::Capacity)
        ));
        let transaction = prepared
            .transaction::<4, 6>(StorageTransactionId::new(51).unwrap(), 6)
            .unwrap();
        assert_eq!(transaction.participant_count(), 4);
        let active_superblock =
            Superblock::new(header(), 5, 4, root, pointer(10), pointer(20)).unwrap();
        assert!(matches!(
            prepared.publication_plan::<5>(
                header(),
                1,
                active_superblock,
                root,
                &[pointer(10), pointer(20), pointer(30)],
            ),
            Err(CowPlanError::Capacity)
        ));
        let publication = prepared
            .publication_plan::<6>(
                header(),
                1,
                active_superblock,
                root,
                &[pointer(10), pointer(20), pointer(30)],
            )
            .unwrap();
        let mut receipt = transaction.publish(&publication, &mut backend).unwrap();
        assert_eq!(receipt.remaining(), 4);
        let mut unrelated_authorities = StorageAuthorityTable::<2>::new();
        let prepared = match prepared.commit(&mut receipt, &mut unrelated_authorities) {
            Err((prepared, CreateCommitError::Authority)) => prepared,
            _ => panic!("unrelated authority table accepted create"),
        };
        assert_eq!(receipt.remaining(), 4);
        let committed = match prepared.commit(&mut receipt, &mut authorities) {
            Ok(committed) => committed,
            Err((_, error)) => panic!("create commit failed: {error:?}"),
        };
        assert_eq!(receipt.remaining(), 0);
        assert_eq!(backend.verified, 6);
        assert_eq!(backend.replaced, 1);
        assert_eq!(committed.directories.state(0).unwrap().generation(), 6);
        assert_eq!(committed.object_id_allocator.next_local(), Some(11));
        assert_eq!(committed.allocation.generation(), 6);
        assert_eq!(
            authorities.authorize(
                committed.handle,
                principal,
                StorageObjectKind::File,
                StorageRights::READ,
            ),
            Ok(child)
        );
        assert!(matches!(committed.child, InitialObjectState::File(_)));
    }
}
