use crate::{
    AllocationImage, AllocationKind, CommittedDirectoryMovePlan, CowMetadataImage, CowPlanError,
    CowPublicationPlan, DirectoryState, FileState, MetadataPointer, ObjectIdAllocatorImage,
    PreparedAllocationUpdate, PreparedDirectoryMovePlan, PreparedInitialDirectory,
    PreparedInitialFile, PreparedObjectIdReservation, StorageAuthorityError,
    StorageAuthorityReservation, StorageAuthorityTable, StorageHandle, StorageObjectId,
    StorageObjectKind, StorageRights, StorageTransaction, StorageTransactionId, Superblock,
    TransactionError, TransactionParticipant, TransactionReceipt, VolumeHeader,
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
            Self::Directory(directory) => {
                let (state, parent) = directory.into_state();
                InitialObjectState::Directory(InitialDirectoryState { state, parent })
            }
        }
    }
}

pub enum InitialObjectState {
    File(FileState<0>),
    Directory(InitialDirectoryState),
}

pub struct InitialDirectoryState {
    state: DirectoryState<0>,
    parent: StorageObjectId,
}

impl InitialDirectoryState {
    pub const fn state(&self) -> &DirectoryState<0> {
        &self.state
    }

    pub const fn parent(&self) -> StorageObjectId {
        self.parent
    }
}

pub struct PreparedCreate<const C: usize, const E: usize, const A: usize> {
    directories: PreparedDirectoryMovePlan<C, E>,
    child: PreparedInitialObject,
    object_id: PreparedObjectIdReservation,
    allocation: PreparedAllocationUpdate<A>,
    authority: StorageAuthorityReservation,
    creation_parent: StorageObjectId,
}

impl<const C: usize, const E: usize, const A: usize> PreparedCreate<C, E, A> {
    pub fn new(
        directories: PreparedDirectoryMovePlan<C, E>,
        child: PreparedInitialObject,
        object_id: PreparedObjectIdReservation,
        allocation: PreparedAllocationUpdate<A>,
        authority: StorageAuthorityReservation,
    ) -> Result<Self, PreparedCreateError> {
        let creation_parent = directories.creation_parent(child.object(), child.kind());
        let parent_matches = match &child {
            PreparedInitialObject::File(_) => creation_parent.is_some(),
            PreparedInitialObject::Directory(directory) => {
                creation_parent == Some(directory.parent())
            }
        };
        if directories.is_empty()
            || child.object() != object_id.allocated()
            || authority.object() != child.object()
            || authority.kind() != child.kind()
            || !authority.has_parent()
            || !parent_matches
        {
            return Err(PreparedCreateError::InvalidBinding);
        }
        Ok(Self {
            directories,
            child,
            object_id,
            allocation,
            authority,
            creation_parent: creation_parent.ok_or(PreparedCreateError::InvalidBinding)?,
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
        let create_right = match self.child.kind() {
            StorageObjectKind::File => StorageRights::CREATE_FILE,
            StorageObjectKind::Directory => StorageRights::CREATE_DIRECTORY,
            StorageObjectKind::Volume => {
                return Err((self, CreateCommitError::Authority));
            }
        };
        if !authorities.reservation_is_valid(&self.authority)
            || !authorities.reservation_parent_matches(
                &self.authority,
                self.creation_parent,
                create_right,
            )
        {
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
            creation_parent: _,
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
        CowPublicationBackend, CowPublishError, DirectoryAncestryBackend, DirectoryEntry,
        DirectoryImage, DirectoryMetadata, DirectorySuccessorBackend, DirectorySuccessorLayout,
        DirectoryWriteBackend, InitialFileWriteBackend, ObjectIdAllocatorWriteBackend,
        RecoveryMetadataBackend, StorageName, StoragePrincipal, TransactionPublishError, VolumeId,
        prepare_initial_directory, prepare_initial_file, prove_directory_mutation_ancestry,
        recover_reachable_superblock,
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
        images: [[u8; 4096]; 6],
        present: [bool; 6],
    }

    impl Backend {
        fn new(root: DirectoryState<2>) -> Self {
            Self {
                root,
                staged: 0,
                verified: 0,
                replaced: 0,
                images: [[0; 4096]; 6],
                present: [false; 6],
            }
        }

        fn stage(&mut self, image: CowMetadataImage, encoded: &[u8]) -> Result<(), ()> {
            let index = usize::try_from(image.pointer().block().checked_sub(60).ok_or(())?)
                .map_err(|_| ())?;
            let output = self.images.get_mut(index).ok_or(())?;
            if encoded.len() > output.len() || image.pointer().blocks() != 1 {
                return Err(());
            }
            output.fill(0);
            output[..encoded.len()].copy_from_slice(encoded);
            let mut digest = mrml_crypto::Sha3_256::new();
            digest.update(output);
            if digest.finalize() != image.digest() {
                return Err(());
            }
            self.present[index] = true;
            self.staged += 1;
            Ok(())
        }
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
            image: CowMetadataImage,
            encoded: &[u8; crate::DIRECTORY_METADATA_BYTES],
        ) -> Result<(), Self::Error> {
            self.stage(image, encoded)
        }

        fn stage_directory_entries(
            &mut self,
            image: CowMetadataImage,
            encoded: &[u8],
        ) -> Result<(), Self::Error> {
            self.stage(image, encoded)
        }

        fn flush_directory_update(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    unsafe impl InitialFileWriteBackend for Backend {
        type Error = ();

        fn stage_initial_file_metadata(
            &mut self,
            image: CowMetadataImage,
            encoded: &[u8; crate::FILE_METADATA_BYTES],
        ) -> Result<(), Self::Error> {
            self.stage(image, encoded)
        }

        fn stage_initial_file_extents(
            &mut self,
            image: CowMetadataImage,
            encoded: &[u8],
        ) -> Result<(), Self::Error> {
            self.stage(image, encoded)
        }

        fn flush_initial_file(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    unsafe impl ObjectIdAllocatorWriteBackend for Backend {
        type Error = ();

        fn stage_object_id_allocator(
            &mut self,
            image: CowMetadataImage,
            encoded: &[u8],
        ) -> Result<(), Self::Error> {
            self.stage(image, encoded)
        }

        fn flush_object_id_allocator(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    unsafe impl AllocationWriteBackend for Backend {
        type Error = ();

        fn stage_allocation_image(
            &mut self,
            image: CowMetadataImage,
            encoded: &[u8],
        ) -> Result<(), Self::Error> {
            self.stage(image, encoded)
        }

        fn flush_allocation_image(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    unsafe impl CowPublicationBackend for Backend {
        type Error = ();

        fn verify_new_metadata(&mut self, write: CowMetadataWrite) -> Result<(), Self::Error> {
            let index = usize::try_from(write.pointer().block().checked_sub(60).ok_or(())?)
                .map_err(|_| ())?;
            let image = self.images.get(index).ok_or(())?;
            if !self.present.get(index).copied().unwrap_or(false) {
                return Err(());
            }
            let mut digest = mrml_crypto::Sha3_256::new();
            digest.update(image);
            if digest.finalize() != write.digest() {
                return Err(());
            }
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

    struct CrashBackend {
        images: [[u8; 4096]; 6],
        primary: [u8; crate::SUPERBLOCK_BYTES],
        secondary: [u8; crate::SUPERBLOCK_BYTES],
        volatile_secondary: Option<[u8; crate::SUPERBLOCK_BYTES]>,
        event: usize,
        fail_at: Option<usize>,
        persist_on_replace: bool,
        persist_on_failed_flush: bool,
    }

    impl CrashBackend {
        fn new(
            images: [[u8; 4096]; 6],
            fail_at: Option<usize>,
            persist_on_replace: bool,
            persist_on_failed_flush: bool,
        ) -> Self {
            let mut primary = [0; crate::SUPERBLOCK_BYTES];
            Superblock::new(header(), 5, 4, object(1), pointer(10), pointer(20))
                .unwrap()
                .encode(&mut primary);
            Self {
                images,
                primary,
                secondary: [0; crate::SUPERBLOCK_BYTES],
                volatile_secondary: None,
                event: 0,
                fail_at,
                persist_on_replace,
                persist_on_failed_flush,
            }
        }

        fn fails_now(&mut self) -> bool {
            let fails = self.fail_at == Some(self.event);
            self.event += 1;
            fails
        }

        fn recovered_generation(&self) -> u64 {
            let mut scratch = [0; 4096];
            recover_reachable_superblock::<_, 8, 2, 0, 2>(
                header(),
                &self.primary,
                &self.secondary,
                RecoveryImages::new(self.images),
                &mut scratch,
            )
            .unwrap()
            .superblock()
            .generation()
        }
    }

    unsafe impl CowPublicationBackend for CrashBackend {
        type Error = usize;

        fn verify_new_metadata(&mut self, write: CowMetadataWrite) -> Result<(), Self::Error> {
            let index = usize::try_from(write.pointer().block() - 60).unwrap();
            let mut digest = mrml_crypto::Sha3_256::new();
            digest.update(&self.images[index]);
            assert_eq!(digest.finalize(), write.digest());
            if self.fails_now() {
                Err(self.event - 1)
            } else {
                Ok(())
            }
        }

        fn flush_new_metadata(&mut self) -> Result<(), Self::Error> {
            if self.fails_now() {
                Err(self.event - 1)
            } else {
                Ok(())
            }
        }

        fn replace_superblock(
            &mut self,
            block: u64,
            encoded: &[u8; crate::SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            assert_eq!(block, 2);
            self.volatile_secondary = Some(*encoded);
            if self.persist_on_replace {
                self.secondary = *encoded;
            }
            if self.fails_now() {
                Err(self.event - 1)
            } else {
                Ok(())
            }
        }

        fn flush_superblock(&mut self) -> Result<(), Self::Error> {
            let fails = self.fails_now();
            if !fails || self.persist_on_failed_flush {
                self.secondary = self.volatile_secondary.unwrap();
            }
            if fails { Err(self.event - 1) } else { Ok(()) }
        }
    }

    struct RecoveryImages {
        old_root: [u8; 4096],
        old_entries: [u8; 4096],
        old_allocation: [u8; 4096],
        old_allocator: [u8; 4096],
        new: [[u8; 4096]; 6],
    }

    impl RecoveryImages {
        fn new(new: [[u8; 4096]; 6]) -> Self {
            let root = object(1);
            let mut old_root = [0; 4096];
            DirectoryMetadata::new(header(), root, 5, None, 0, pointer(11))
                .unwrap()
                .encode(
                    (&mut old_root[..crate::DIRECTORY_METADATA_BYTES])
                        .try_into()
                        .unwrap(),
                );
            let mut old_entries = [0; 4096];
            DirectoryImage::<2>::build(header(), root, 5, pointer(11), &[])
                .unwrap()
                .encode(&mut old_entries)
                .unwrap();
            let mut old_allocation = [0; 4096];
            AllocationImage::<8>::build(
                header(),
                5,
                pointer(20),
                &[
                    AllocationRecord::new(root, 5, 10, 1, AllocationKind::ObjectMetadata).unwrap(),
                    AllocationRecord::new(root, 5, 11, 1, AllocationKind::DirectoryEntries)
                        .unwrap(),
                    AllocationRecord::new(root, 5, 20, 1, AllocationKind::AllocationMetadata)
                        .unwrap(),
                    AllocationRecord::new(
                        root,
                        5,
                        30,
                        1,
                        AllocationKind::ObjectIdAllocatorMetadata,
                    )
                    .unwrap(),
                ],
            )
            .unwrap()
            .encode(&mut old_allocation)
            .unwrap();
            let mut old_allocator = [0; 4096];
            ObjectIdAllocatorImage::build(header(), 5, Some(10), pointer(30))
                .unwrap()
                .encode(&mut old_allocator)
                .unwrap();
            Self {
                old_root,
                old_entries,
                old_allocation,
                old_allocator,
                new,
            }
        }
    }

    unsafe impl RecoveryMetadataBackend for RecoveryImages {
        type Error = ();

        fn read_metadata(
            &mut self,
            requested: MetadataPointer,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            let source = match requested.block() {
                10 => &self.old_root,
                11 => &self.old_entries,
                20 => &self.old_allocation,
                30 => &self.old_allocator,
                60..=65 => &self.new[usize::try_from(requested.block() - 60).unwrap()],
                _ => return Err(()),
            };
            if requested.blocks() != 1 || output.len() != source.len() {
                return Err(());
            }
            output.copy_from_slice(source);
            Ok(())
        }
    }

    fn prepared_directory_create(
        metadata_parent: StorageObjectId,
    ) -> Result<
        (
            PreparedCreate<1, 2, 8>,
            StorageAuthorityTable<2>,
            Backend,
            StoragePrincipal,
            StorageHandle,
        ),
        PreparedCreateError,
    > {
        let root = object(1);
        let child = object(10);
        let mut backend = Backend::new(DirectoryState::new(root, 5, &[]).unwrap());
        let proof = prove_directory_mutation_ancestry::<1, _>(root, root, 5, &mut backend).unwrap();
        let entry = DirectoryEntry::new(
            StorageName::new("created-directory").unwrap(),
            child,
            StorageObjectKind::Directory,
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
        let mut child_metadata = [0; crate::DIRECTORY_METADATA_BYTES];
        let mut child_entries = [0; 4096];
        let initial_directory = prepare_initial_directory(
            header(),
            child,
            metadata_parent,
            pointer(62),
            pointer(63),
            &mut child_metadata,
            &mut child_entries,
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
                AllocationRecord::new(root, 5, 11, 1, AllocationKind::DirectoryEntries).unwrap(),
                AllocationRecord::new(root, 5, 20, 1, AllocationKind::AllocationMetadata).unwrap(),
                AllocationRecord::new(root, 5, 30, 1, AllocationKind::ObjectIdAllocatorMetadata)
                    .unwrap(),
            ],
        )
        .unwrap();
        let changes = [
            AllocationChange::Free(
                AllocationRecord::new(root, 5, 10, 1, AllocationKind::ObjectMetadata).unwrap(),
            ),
            AllocationChange::Free(
                AllocationRecord::new(root, 5, 11, 1, AllocationKind::DirectoryEntries).unwrap(),
            ),
            AllocationChange::Free(
                AllocationRecord::new(root, 5, 30, 1, AllocationKind::ObjectIdAllocatorMetadata)
                    .unwrap(),
            ),
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
                AllocationRecord::new(child, 1, 63, 1, AllocationKind::DirectoryEntries).unwrap(),
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
        let principal = StoragePrincipal::new(9).unwrap();
        let rights = StorageRights::LOOKUP.union(StorageRights::ENUMERATE);
        let mut authorities = StorageAuthorityTable::<2>::new();
        let root_handle = authorities
            .insert(
                root,
                StorageObjectKind::Directory,
                StorageRights::LOOKUP
                    .union(StorageRights::OPEN_CHILD)
                    .union(StorageRights::CREATE_DIRECTORY),
                principal,
            )
            .unwrap();
        let authority = authorities
            .reserve_child_insert(
                root_handle,
                principal,
                StorageRights::CREATE_DIRECTORY,
                child,
                StorageObjectKind::Directory,
                rights,
            )
            .unwrap();
        PreparedCreate::new(
            directories,
            PreparedInitialObject::Directory(initial_directory),
            object_id,
            allocation,
            authority,
        )
        .map(|prepared| (prepared, authorities, backend, principal, root_handle))
    }

    #[test]
    fn complete_file_create_publishes_and_activates_as_one_receipt_set() {
        let root = object(1);
        let child = object(10);
        let mut backend = Backend::new(DirectoryState::new(root, 5, &[]).unwrap());
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
                AllocationRecord::new(root, 5, 11, 1, AllocationKind::DirectoryEntries).unwrap(),
                AllocationRecord::new(root, 5, 20, 1, AllocationKind::AllocationMetadata).unwrap(),
                AllocationRecord::new(root, 5, 30, 1, AllocationKind::ObjectIdAllocatorMetadata)
                    .unwrap(),
            ],
        )
        .unwrap();
        let changes = [
            AllocationChange::Free(
                AllocationRecord::new(root, 5, 10, 1, AllocationKind::ObjectMetadata).unwrap(),
            ),
            AllocationChange::Free(
                AllocationRecord::new(root, 5, 11, 1, AllocationKind::DirectoryEntries).unwrap(),
            ),
            AllocationChange::Free(
                AllocationRecord::new(root, 5, 30, 1, AllocationKind::ObjectIdAllocatorMetadata)
                    .unwrap(),
            ),
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
        let root_handle = authorities
            .insert(
                root,
                StorageObjectKind::Directory,
                StorageRights::CREATE_FILE,
                principal,
            )
            .unwrap();
        let authority = authorities
            .reserve_child_insert(
                root_handle,
                principal,
                StorageRights::CREATE_FILE,
                child,
                StorageObjectKind::File,
                rights,
            )
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
                StorageHandle::from_token((1_u64 << 32) | 1),
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
        assert_eq!(authorities.revoke(root_handle, principal), Ok(2));
        assert_eq!(
            authorities.authorize(
                committed.handle,
                principal,
                StorageObjectKind::File,
                StorageRights::READ,
            ),
            Err(StorageAuthorityError::InvalidHandle)
        );
    }

    #[test]
    fn complete_directory_create_binds_parent_and_activates_directory_rights() {
        assert!(matches!(
            prepared_directory_create(object(2)),
            Err(PreparedCreateError::InvalidBinding)
        ));

        let (prepared, mut authorities, mut backend, principal, root_handle) =
            prepared_directory_create(object(1)).unwrap();
        let transaction = prepared
            .transaction::<4, 6>(StorageTransactionId::new(52).unwrap(), 6)
            .unwrap();
        let active = Superblock::new(header(), 5, 4, object(1), pointer(10), pointer(20)).unwrap();
        let publication = prepared
            .publication_plan::<6>(
                header(),
                1,
                active,
                object(1),
                &[pointer(10), pointer(20), pointer(30)],
            )
            .unwrap();
        let mut receipt = transaction.publish(&publication, &mut backend).unwrap();
        let committed = match prepared.commit(&mut receipt, &mut authorities) {
            Ok(committed) => committed,
            Err((_, error)) => panic!("directory create commit failed: {error:?}"),
        };
        assert_eq!(receipt.remaining(), 0);
        assert_eq!((backend.verified, backend.replaced), (6, 1));
        assert_eq!(
            authorities.authorize(
                committed.handle,
                principal,
                StorageObjectKind::Directory,
                StorageRights::LOOKUP,
            ),
            Ok(object(10))
        );
        let InitialObjectState::Directory(directory) = committed.child else {
            panic!("directory create returned the wrong child type");
        };
        assert_eq!(directory.parent(), object(1));
        assert_eq!(directory.state().object(), object(10));
        assert_eq!(directory.state().generation(), 1);
        assert!(directory.state().is_empty());
        assert_eq!(authorities.revoke(root_handle, principal), Ok(2));
        assert_eq!(
            authorities.authorize(
                committed.handle,
                principal,
                StorageObjectKind::Directory,
                StorageRights::LOOKUP,
            ),
            Err(StorageAuthorityError::InvalidHandle)
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum CrashOutcome {
        Rejected,
        FailStop,
        Committed,
    }

    fn run_directory_create_crash(
        fail_at: Option<usize>,
        persist_on_replace: bool,
        persist_on_failed_flush: bool,
    ) -> (CrashOutcome, u64) {
        let (prepared, mut authorities, staged, principal, root_handle) =
            prepared_directory_create(object(1)).unwrap();
        let transaction = prepared
            .transaction::<4, 6>(StorageTransactionId::new(60).unwrap(), 6)
            .unwrap();
        let active = Superblock::new(header(), 5, 4, object(1), pointer(10), pointer(20)).unwrap();
        let publication = prepared
            .publication_plan::<6>(
                header(),
                1,
                active,
                object(1),
                &[pointer(10), pointer(11), pointer(20), pointer(30)],
            )
            .unwrap();
        let mut crash = CrashBackend::new(
            staged.images,
            fail_at,
            persist_on_replace,
            persist_on_failed_flush,
        );
        let outcome = match transaction.publish(&publication, &mut crash) {
            Ok(mut receipt) => {
                let committed = match prepared.commit(&mut receipt, &mut authorities) {
                    Ok(committed) => committed,
                    Err((_, error)) => panic!("successful publication did not commit: {error:?}"),
                };
                assert_eq!(receipt.remaining(), 0);
                assert_eq!(
                    authorities.authorize(
                        committed.handle,
                        principal,
                        StorageObjectKind::Directory,
                        StorageRights::LOOKUP,
                    ),
                    Ok(object(10))
                );
                CrashOutcome::Committed
            }
            Err(TransactionPublishError::Publication(CowPublishError::Rejected(_))) => {
                assert_eq!(
                    authorities.authorize(
                        StorageHandle::from_token((1_u64 << 32) | 1),
                        principal,
                        StorageObjectKind::Directory,
                        StorageRights::LOOKUP,
                    ),
                    Err(StorageAuthorityError::InvalidHandle)
                );
                prepared.cancel(&mut authorities).unwrap();
                CrashOutcome::Rejected
            }
            Err(TransactionPublishError::Publication(CowPublishError::FailStop(_))) => {
                assert_eq!(
                    authorities.authorize(
                        StorageHandle::from_token((1_u64 << 32) | 1),
                        principal,
                        StorageObjectKind::Directory,
                        StorageRights::LOOKUP,
                    ),
                    Err(StorageAuthorityError::InvalidHandle)
                );
                prepared.cancel(&mut authorities).unwrap();
                CrashOutcome::FailStop
            }
            Err(TransactionPublishError::WrongPlan) => panic!("complete create plan rejected"),
        };
        let recovered_generation = crash.recovered_generation();
        if outcome == CrashOutcome::FailStop && recovered_generation == 6 {
            let recovered_root =
                DirectoryImage::<2>::decode(header(), object(1), 6, pointer(61), &crash.images[1])
                    .unwrap();
            let (entry, reconciled) = recovered_root
                .state()
                .open_child(
                    &mut authorities,
                    root_handle,
                    principal,
                    StorageName::new("created-directory").unwrap(),
                    StorageRights::LOOKUP,
                )
                .unwrap();
            assert_eq!(entry.object(), object(10));
            assert_eq!(
                authorities.authorize(
                    reconciled,
                    principal,
                    StorageObjectKind::Directory,
                    StorageRights::LOOKUP,
                ),
                Ok(object(10))
            );
        }
        (outcome, recovered_generation)
    }

    #[test]
    fn interrupted_directory_create_recovers_only_complete_old_or_new_graph() {
        for failure in 0..7 {
            assert_eq!(
                run_directory_create_crash(Some(failure), false, false),
                (CrashOutcome::Rejected, 5)
            );
        }
        for persists in [false, true] {
            assert_eq!(
                run_directory_create_crash(Some(7), persists, false),
                (CrashOutcome::FailStop, if persists { 6 } else { 5 },)
            );
        }
        for persists in [false, true] {
            assert_eq!(
                run_directory_create_crash(Some(8), false, persists),
                (CrashOutcome::FailStop, if persists { 6 } else { 5 },)
            );
        }
        assert_eq!(
            run_directory_create_crash(None, false, false),
            (CrashOutcome::Committed, 6)
        );
    }
}
