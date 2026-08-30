use crate::{
    CowMetadataImage, CowPublicationBackend, CowPublicationPlan, CowPublishError, ExtentError,
    ExtentImage, ExtentKind, ExtentMap, ExtentRecord, FileMetadata, MetadataPointer,
    StorageAuthorityError, StorageAuthorityTable, StorageHandle, StorageObjectId,
    StorageObjectKind, StoragePrincipal, StorageRights, TransactionError, TransactionParticipant,
    TransactionReceipt, VolumeHeader,
};

pub const MAX_FILE_READ_BYTES: usize = 1 << 20;
pub const MAX_FILE_WRITE_BYTES: usize = 1 << 20;
pub const MAX_PROTECTED_METADATA_RANGES: usize = 1024;

pub struct FileState<const N: usize> {
    object: StorageObjectId,
    generation: u64,
    length: u64,
    extents: ExtentMap<N>,
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_initial_file<B: InitialFileWriteBackend>(
    header: VolumeHeader,
    object: StorageObjectId,
    metadata_pointer: MetadataPointer,
    extents_pointer: MetadataPointer,
    metadata_output: &mut [u8; crate::FILE_METADATA_BYTES],
    extents_output: &mut [u8],
    backend: &mut B,
) -> Result<PreparedInitialFile, InitialFileError<B::Error>> {
    if object.volume() != header.volume()
        || !metadata_pointer_valid(header, metadata_pointer)
        || !metadata_pointer_valid(header, extents_pointer)
        || metadata_pointers_overlap(metadata_pointer, extents_pointer)
    {
        return Err(InitialFileError::InvalidLayout);
    }
    let content = mrml_crypto::Sha3_256::new();
    let content_digest = content.finalize();
    let metadata = FileMetadata::new(header, object, 1, 0, 0, extents_pointer, content_digest)
        .map_err(|_| InitialFileError::InvalidLayout)?;
    metadata.encode(metadata_output);
    let extent_image = ExtentImage::<0>::build(header, object, 1, 0, extents_pointer, &[])
        .map_err(InitialFileError::Extent)?;
    extent_image
        .encode(extents_output)
        .map_err(InitialFileError::Extent)?;
    let file_metadata = CowMetadataImage::new(
        metadata_pointer,
        crate::cow::zero_padded_image_digest(
            header.block_size(),
            metadata_pointer,
            metadata_output,
        )
        .ok_or(InitialFileError::InvalidLayout)?,
    );
    let extent_metadata = CowMetadataImage::new(extents_pointer, complete_digest(extents_output));
    backend
        .stage_initial_file_metadata(file_metadata, metadata_output)
        .map_err(InitialFileError::Backend)?;
    backend
        .stage_initial_file_extents(extent_metadata, extents_output)
        .map_err(InitialFileError::Backend)?;
    backend
        .flush_initial_file()
        .map_err(InitialFileError::Backend)?;
    let extents =
        ExtentMap::<0>::build(header, object, 1, 0, &[]).map_err(InitialFileError::Extent)?;
    Ok(PreparedInitialFile {
        state: FileState::new(object, 1, 0, extents)
            .map_err(|_| InitialFileError::InvalidLayout)?,
        file_metadata,
        extent_metadata,
    })
}

pub struct PreparedInitialFile {
    state: FileState<0>,
    file_metadata: CowMetadataImage,
    extent_metadata: CowMetadataImage,
}

impl PreparedInitialFile {
    pub const fn object(&self) -> StorageObjectId {
        self.state.object
    }

    pub const fn state(&self) -> &FileState<0> {
        &self.state
    }

    pub const fn metadata_image(&self) -> CowMetadataImage {
        self.file_metadata
    }

    pub const fn extent_metadata_image(&self) -> CowMetadataImage {
        self.extent_metadata
    }

    pub(crate) fn transaction_participant(
        &self,
    ) -> Result<TransactionParticipant, TransactionError> {
        TransactionParticipant::creation(self.state.object, StorageObjectKind::File)
    }

    pub(crate) const fn metadata_images(&self) -> [CowMetadataImage; 2] {
        [self.file_metadata, self.extent_metadata]
    }

    pub fn commit_transaction<const P: usize>(
        self,
        receipt: &mut TransactionReceipt<P>,
    ) -> Result<FileState<0>, TransactionError> {
        receipt.consume(self.transaction_participant()?)?;
        Ok(self.state)
    }

    pub(crate) fn into_state(self) -> FileState<0> {
        self.state
    }
}

/// Persistence boundary for a new unreachable empty file.
///
/// # Safety
///
/// Implementations must write the fixed file-metadata record as the exact
/// prefix of its named range, zero every remaining byte in that range, and
/// verify the complete padded range against the supplied digest. They must also
/// write and verify the complete subordinate image at its exact range, keep
/// both unreachable, and make both durable before `flush_initial_file`
/// succeeds. They must not redirect, shorten, merge, or acknowledge stale or
/// partially written images.
pub unsafe trait InitialFileWriteBackend {
    type Error;

    fn stage_initial_file_metadata(
        &mut self,
        image: CowMetadataImage,
        encoded: &[u8; crate::FILE_METADATA_BYTES],
    ) -> Result<(), Self::Error>;

    fn stage_initial_file_extents(
        &mut self,
        image: CowMetadataImage,
        encoded: &[u8],
    ) -> Result<(), Self::Error>;

    fn flush_initial_file(&mut self) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialFileError<E> {
    InvalidLayout,
    Extent(ExtentError),
    Backend(E),
}

impl<const N: usize> FileState<N> {
    pub fn new(
        object: StorageObjectId,
        generation: u64,
        length: u64,
        extents: ExtentMap<N>,
    ) -> Result<Self, FileStateError> {
        if generation == 0
            || extents.file() != object
            || extents.metadata_generation() != generation
            || extents.file_length() != length
        {
            return Err(FileStateError::InvalidState);
        }
        Ok(Self {
            object,
            generation,
            length,
            extents,
        })
    }

    pub const fn object(&self) -> StorageObjectId {
        self.object
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn length(&self) -> u64 {
        self.length
    }

    pub(crate) const fn extents(&self) -> &ExtentMap<N> {
        &self.extents
    }

    pub fn read<const A: usize, B: FileReadBackend>(
        &self,
        authority: &StorageAuthorityTable<A>,
        file: StorageHandle,
        principal: StoragePrincipal,
        offset: u64,
        output: &mut [u8],
        backend: &mut B,
    ) -> Result<usize, FileReadError<B::Error>> {
        let authorized = authority
            .authorize(
                file,
                principal,
                StorageObjectKind::File,
                StorageRights::READ,
            )
            .map_err(FileReadError::Authority)?;
        if authorized != self.object {
            return Err(FileReadError::WrongFile);
        }
        if output.len() > MAX_FILE_READ_BYTES {
            return Err(FileReadError::TooLarge);
        }
        let length = u64::try_from(output.len()).map_err(|_| FileReadError::Arithmetic)?;
        let end = offset
            .checked_add(length)
            .ok_or(FileReadError::Arithmetic)?;
        if end > self.length {
            return Err(FileReadError::OutOfRange);
        }
        output.fill(0);
        if output.is_empty() {
            return Ok(0);
        }

        let block_size = u64::from(self.extents.block_size());
        let mut position = offset;
        let mut written = 0_usize;
        while written < output.len() {
            let logical_block = position / block_size;
            let record = self
                .extents
                .record_for(logical_block)
                .map_err(FileReadError::Extent)?;
            let extent_start = record
                .logical_block()
                .checked_mul(block_size)
                .ok_or(FileReadError::Arithmetic)?;
            let extent_end = record
                .logical_block()
                .checked_add(u64::from(record.block_count()))
                .and_then(|blocks| blocks.checked_mul(block_size))
                .ok_or(FileReadError::Arithmetic)?
                .min(self.length);
            let available =
                usize::try_from(extent_end - position).map_err(|_| FileReadError::Arithmetic)?;
            let count = available.min(output.len() - written);
            let destination = &mut output[written..written + count];
            if record.kind() == ExtentKind::Data
                && let Err(error) =
                    backend.read_verified_extent(record, position - extent_start, destination)
            {
                output.fill(0);
                return Err(FileReadError::Backend(error));
            }
            position = position
                .checked_add(u64::try_from(count).map_err(|_| FileReadError::Arithmetic)?)
                .ok_or(FileReadError::Arithmetic)?;
            written += count;
        }
        Ok(written)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_write<const M: usize, const A: usize, B: FileWriteBackend>(
        &self,
        authority: &StorageAuthorityTable<A>,
        file: StorageHandle,
        principal: StoragePrincipal,
        offset: u64,
        data: &[u8],
        new_length: u64,
        next_extents: ExtentMap<M>,
        next_metadata: FileMetadata,
        file_metadata_pointer: MetadataPointer,
        protected_metadata: &[MetadataPointer],
        backend: &mut B,
    ) -> Result<PreparedFileWrite<M>, FileWriteError<B::Error>> {
        let requested = if new_length == self.length {
            StorageRights::WRITE
        } else {
            StorageRights::WRITE.union(StorageRights::RESIZE)
        };
        let authorized = authority
            .authorize(file, principal, StorageObjectKind::File, requested)
            .map_err(FileWriteError::Authority)?;
        if authorized != self.object {
            return Err(FileWriteError::WrongFile);
        }
        if data.is_empty() || data.len() > MAX_FILE_WRITE_BYTES {
            return Err(FileWriteError::InvalidLength);
        }
        let data_length = u64::try_from(data.len()).map_err(|_| FileWriteError::Arithmetic)?;
        let end = offset
            .checked_add(data_length)
            .ok_or(FileWriteError::Arithmetic)?;
        if end > new_length {
            return Err(FileWriteError::OutOfRange);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(FileWriteError::GenerationExhausted)?;
        if next_extents.file() != self.object
            || next_extents.metadata_generation() != generation
            || next_extents.file_length() != new_length
            || next_extents.block_size() != self.extents.block_size()
            || next_metadata.object() != self.object
            || next_metadata.generation() != generation
            || next_metadata.length() != new_length
            || usize::try_from(next_metadata.extent_count()).ok() != Some(next_extents.len())
        {
            return Err(FileWriteError::InvalidSuccessor);
        }
        if protected_metadata.len() > MAX_PROTECTED_METADATA_RANGES {
            return Err(FileWriteError::Capacity);
        }
        let mut encoded_metadata = [0; crate::FILE_METADATA_BYTES];
        next_metadata.encode(&mut encoded_metadata);
        let file_metadata = CowMetadataImage::new(
            file_metadata_pointer,
            crate::cow::zero_padded_image_digest(
                next_extents.block_size(),
                file_metadata_pointer,
                &encoded_metadata,
            )
            .ok_or(FileWriteError::Arithmetic)?,
        );
        let extent_capacity = u64::from(next_metadata.extents().blocks())
            .checked_mul(u64::from(next_extents.block_size()))
            .ok_or(FileWriteError::Arithmetic)?;
        let encoded_extent_bytes = u64::try_from(next_extents.len())
            .map_err(|_| FileWriteError::Arithmetic)?
            .checked_mul(crate::EXTENT_RECORD_BYTES as u64)
            .ok_or(FileWriteError::Arithmetic)?;
        if encoded_extent_bytes > extent_capacity {
            return Err(FileWriteError::InvalidSuccessor);
        }
        let mut extent_digest = mrml_crypto::Sha3_256::new();
        for index in 0..next_extents.len() {
            let record = next_extents
                .record(index)
                .ok_or(FileWriteError::InvalidSuccessor)?;
            let mut encoded = [0; crate::EXTENT_RECORD_BYTES];
            record.encode(&mut encoded);
            extent_digest.update(&encoded);
        }
        let mut padding = extent_capacity - encoded_extent_bytes;
        const ZEROES: [u8; 256] = [0; 256];
        while padding != 0 {
            let count = usize::try_from(padding.min(ZEROES.len() as u64))
                .map_err(|_| FileWriteError::Arithmetic)?;
            extent_digest.update(&ZEROES[..count]);
            padding -= count as u64;
        }
        let extent_metadata =
            CowMetadataImage::new(next_metadata.extents(), extent_digest.finalize());
        for next_index in 0..next_extents.len() {
            let next = next_extents
                .record(next_index)
                .ok_or(FileWriteError::InvalidSuccessor)?;
            if next.kind() != ExtentKind::Data {
                continue;
            }
            for old_index in 0..self.extents.len() {
                let old = self
                    .extents
                    .record(old_index)
                    .ok_or(FileWriteError::InvalidSuccessor)?;
                if old.kind() == ExtentKind::Data && data_extents_overlap(old, next) {
                    return Err(FileWriteError::OverwritesActiveData);
                }
            }
            if protected_metadata
                .iter()
                .copied()
                .any(|pointer| data_overlaps_metadata(next, pointer))
            {
                return Err(FileWriteError::OverwritesMetadata);
            }
        }

        for index in 0..next_extents.len() {
            let record = next_extents
                .record(index)
                .ok_or(FileWriteError::InvalidSuccessor)?;
            if record.kind() == ExtentKind::Data {
                backend
                    .stage_new_extent(
                        self.object,
                        self.generation,
                        self.length,
                        record,
                        new_length,
                        offset,
                        data,
                    )
                    .map_err(FileWriteError::Backend)?;
            }
        }
        backend
            .flush_new_file_data(
                self.object,
                generation,
                new_length,
                next_metadata.content_digest(),
            )
            .map_err(FileWriteError::Backend)?;
        Ok(PreparedFileWrite {
            state: FileState {
                object: self.object,
                generation,
                length: new_length,
                extents: next_extents,
            },
            file_metadata,
            extent_metadata,
            file,
            principal,
            requested,
        })
    }
}

pub struct PreparedFileWrite<const N: usize> {
    state: FileState<N>,
    file_metadata: CowMetadataImage,
    extent_metadata: CowMetadataImage,
    file: StorageHandle,
    principal: StoragePrincipal,
    requested: StorageRights,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileWriteCommitError {
    Authority(StorageAuthorityError),
    WrongFile,
    Transaction(TransactionError),
}

impl<const N: usize> PreparedFileWrite<N> {
    pub const fn generation(&self) -> u64 {
        self.state.generation
    }

    pub const fn metadata_image(&self) -> CowMetadataImage {
        self.file_metadata
    }

    pub const fn extent_metadata_image(&self) -> CowMetadataImage {
        self.extent_metadata
    }

    pub(crate) fn transaction_participant(
        &self,
    ) -> Result<TransactionParticipant, TransactionError> {
        TransactionParticipant::new(
            self.state.object,
            StorageObjectKind::File,
            self.state.generation - 1,
            self.state.generation,
        )
    }

    pub(crate) const fn metadata_images(&self) -> [CowMetadataImage; 2] {
        [self.file_metadata, self.extent_metadata]
    }

    /// Revalidates the exact retained file authority immediately before the
    /// one-use transaction receipt is consumed. Revocation or rebinding leaves
    /// both the receipt and prepared successor untouched for explicit policy.
    pub fn commit_transaction_authorized<const P: usize, const A: usize>(
        self,
        authority: &StorageAuthorityTable<A>,
        receipt: &mut TransactionReceipt<P>,
    ) -> Result<FileState<N>, (Self, FileWriteCommitError)> {
        let object = match authority.authorize(
            self.file,
            self.principal,
            StorageObjectKind::File,
            self.requested,
        ) {
            Ok(object) => object,
            Err(error) => return Err((self, FileWriteCommitError::Authority(error))),
        };
        if object != self.state.object {
            return Err((self, FileWriteCommitError::WrongFile));
        }
        let participant = match self.transaction_participant() {
            Ok(participant) => participant,
            Err(error) => return Err((self, FileWriteCommitError::Transaction(error))),
        };
        if let Err(error) = receipt.consume(participant) {
            return Err((self, FileWriteCommitError::Transaction(error)));
        }
        Ok(self.state)
    }

    pub fn publish<const M: usize, B: CowPublicationBackend>(
        self,
        plan: &CowPublicationPlan<M>,
        backend: &mut B,
    ) -> Result<FileState<N>, FileWritePublishError<B::Error>> {
        let file_metadata = self
            .file_metadata
            .bind(plan.generation())
            .map_err(|_| FileWritePublishError::WrongMetadataPlan)?;
        let extent_metadata = self
            .extent_metadata
            .bind(plan.generation())
            .map_err(|_| FileWritePublishError::WrongMetadataPlan)?;
        if !plan.contains_write(file_metadata) || !plan.contains_write(extent_metadata) {
            return Err(FileWritePublishError::WrongMetadataPlan);
        }
        plan.publish(backend)
            .map_err(FileWritePublishError::Publication)?;
        Ok(self.state)
    }
}

/// Verified data boundary used by the storage service read path.
///
/// # Safety
///
/// Before copying any requested subrange, an implementation must read the exact
/// complete physical extent named by `record`, verify SHA3-256 over those bytes
/// against `record.content_digest()`, and bind the read to the same immutable
/// device generation. It must reject short, redirected, stale, or mismatched
/// data and may not copy bytes outside the requested subrange into `output`.
pub unsafe trait FileReadBackend {
    type Error;

    fn read_verified_extent(
        &mut self,
        record: ExtentRecord,
        byte_offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error>;
}

/// COW data-staging boundary used before metadata publication.
///
/// # Safety
///
/// For every supplied next-generation data extent, an implementation must
/// construct the complete logical extent from verified old-generation content,
/// zero-filled holes, and exactly the caller patch; write it only to the exact
/// new physical range; and verify its SHA3-256 digest against the record. It
/// must bind all old reads to the named object/generation/length and reject
/// stale, short, aliased, redirected, or mismatched data. Before a successful
/// flush it must also verify SHA3-256 over the exact logical file length against
/// the supplied canonical `FileMetadata` content digest. A successful flush
/// makes every staged extent durable before metadata publication begins.
pub unsafe trait FileWriteBackend {
    type Error;

    #[allow(clippy::too_many_arguments)]
    fn stage_new_extent(
        &mut self,
        file: StorageObjectId,
        old_generation: u64,
        old_length: u64,
        next: ExtentRecord,
        new_length: u64,
        patch_offset: u64,
        patch: &[u8],
    ) -> Result<(), Self::Error>;

    fn flush_new_file_data(
        &mut self,
        file: StorageObjectId,
        generation: u64,
        length: u64,
        content_digest: [u8; 32],
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileReadError<E> {
    Authority(StorageAuthorityError),
    WrongFile,
    TooLarge,
    OutOfRange,
    Arithmetic,
    Extent(ExtentError),
    Backend(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileStateError {
    InvalidState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileWriteError<E> {
    Authority(StorageAuthorityError),
    WrongFile,
    InvalidLength,
    OutOfRange,
    Arithmetic,
    GenerationExhausted,
    InvalidSuccessor,
    Capacity,
    OverwritesActiveData,
    OverwritesMetadata,
    Backend(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileWritePublishError<E> {
    WrongMetadataPlan,
    Publication(CowPublishError<E>),
}

fn data_extents_overlap(left: ExtentRecord, right: ExtentRecord) -> bool {
    let left_start = left.physical_block().unwrap_or(0);
    let right_start = right.physical_block().unwrap_or(0);
    left_start < right_start + u64::from(right.block_count())
        && right_start < left_start + u64::from(left.block_count())
}

fn data_overlaps_metadata(data: ExtentRecord, metadata: MetadataPointer) -> bool {
    let data_start = data.physical_block().unwrap_or(0);
    data_start < metadata.block() + u64::from(metadata.blocks())
        && metadata.block() < data_start + u64::from(data.block_count())
}

fn metadata_pointer_valid(header: VolumeHeader, pointer: MetadataPointer) -> bool {
    pointer
        .block()
        .checked_add(u64::from(pointer.blocks()))
        .is_some_and(|end| end <= header.block_count())
        && !metadata_pointer_contains(pointer, 0)
        && !metadata_pointer_contains(pointer, header.primary_superblock())
        && !metadata_pointer_contains(pointer, header.secondary_superblock())
}

fn metadata_pointers_overlap(left: MetadataPointer, right: MetadataPointer) -> bool {
    left.block() < right.block() + u64::from(right.blocks())
        && right.block() < left.block() + u64::from(left.blocks())
}

fn metadata_pointer_contains(pointer: MetadataPointer, block: u64) -> bool {
    block >= pointer.block() && block < pointer.block() + u64::from(pointer.blocks())
}

fn complete_digest(input: &[u8]) -> [u8; 32] {
    let mut digest = mrml_crypto::Sha3_256::new();
    digest.update(input);
    digest.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CowMetadataWrite, StorageTransaction, StorageTransactionId, Superblock, VolumeHeader,
        VolumeId,
    };
    use mrml_crypto::Sha3_256;

    const BLOCK_SIZE: usize = 4096;

    fn volume() -> VolumeId {
        VolumeId::new([5; 16]).unwrap()
    }

    fn object(local: u64) -> StorageObjectId {
        StorageObjectId::new(volume(), local).unwrap()
    }

    fn principal() -> StoragePrincipal {
        StoragePrincipal::new(1).unwrap()
    }

    fn digest(bytes: &[u8]) -> [u8; 32] {
        let mut digest = Sha3_256::new();
        digest.update(bytes);
        digest.finalize()
    }

    struct Backend {
        bytes: [u8; 40 * BLOCK_SIZE],
        calls: usize,
        staged: usize,
        flushed: bool,
        fail_stage: bool,
    }

    unsafe impl FileReadBackend for Backend {
        type Error = ();

        fn read_verified_extent(
            &mut self,
            record: ExtentRecord,
            byte_offset: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            self.calls += 1;
            let physical = usize::try_from(record.physical_block().ok_or(())?).map_err(|_| ())?;
            let start = physical.checked_mul(BLOCK_SIZE).ok_or(())?;
            let length = usize::try_from(record.block_count())
                .map_err(|_| ())?
                .checked_mul(BLOCK_SIZE)
                .ok_or(())?;
            let extent = self.bytes.get(start..start + length).ok_or(())?;
            if digest(extent) != record.content_digest() {
                return Err(());
            }
            let offset = usize::try_from(byte_offset).map_err(|_| ())?;
            let source = extent.get(offset..offset + output.len()).ok_or(())?;
            output.copy_from_slice(source);
            Ok(())
        }
    }

    unsafe impl FileWriteBackend for Backend {
        type Error = ();

        fn stage_new_extent(
            &mut self,
            file: StorageObjectId,
            old_generation: u64,
            old_length: u64,
            next: ExtentRecord,
            new_length: u64,
            patch_offset: u64,
            patch: &[u8],
        ) -> Result<(), Self::Error> {
            self.staged += 1;
            if self.fail_stage
                || file != object(7)
                || old_generation != 3
                || old_length != 2 * BLOCK_SIZE as u64 + 100
                || new_length != old_length
            {
                return Err(());
            }
            let mut image = [0; 3 * BLOCK_SIZE];
            image[..BLOCK_SIZE].copy_from_slice(&self.bytes[10 * BLOCK_SIZE..11 * BLOCK_SIZE]);
            image[2 * BLOCK_SIZE..2 * BLOCK_SIZE + 100]
                .copy_from_slice(&self.bytes[20 * BLOCK_SIZE..20 * BLOCK_SIZE + 100]);
            let patch_start = usize::try_from(patch_offset).map_err(|_| ())?;
            image
                .get_mut(patch_start..patch_start + patch.len())
                .ok_or(())?
                .copy_from_slice(patch);
            let logical_start = usize::try_from(next.logical_block()).map_err(|_| ())? * BLOCK_SIZE;
            let extent_length = usize::try_from(next.block_count()).map_err(|_| ())? * BLOCK_SIZE;
            let source = image
                .get(logical_start..logical_start + extent_length)
                .ok_or(())?;
            if digest(source) != next.content_digest() {
                return Err(());
            }
            let physical = usize::try_from(next.physical_block().ok_or(())?).map_err(|_| ())?;
            self.bytes[physical * BLOCK_SIZE..physical * BLOCK_SIZE + extent_length]
                .copy_from_slice(source);
            Ok(())
        }

        fn flush_new_file_data(
            &mut self,
            file: StorageObjectId,
            generation: u64,
            length: u64,
            content_digest: [u8; 32],
        ) -> Result<(), Self::Error> {
            if file != object(7) || generation != 4 {
                return Err(());
            }
            let length = usize::try_from(length).map_err(|_| ())?;
            if digest(&self.bytes[30 * BLOCK_SIZE..30 * BLOCK_SIZE + length]) != content_digest {
                return Err(());
            }
            self.flushed = true;
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
            self.flushed = true;
            Ok(())
        }
    }

    struct PublishBackend {
        verified: usize,
        replaced: usize,
    }

    struct WriteRecorder {
        stages: usize,
        flushed: bool,
    }

    unsafe impl FileWriteBackend for WriteRecorder {
        type Error = ();

        fn stage_new_extent(
            &mut self,
            _file: StorageObjectId,
            _old_generation: u64,
            _old_length: u64,
            _next: ExtentRecord,
            _new_length: u64,
            _patch_offset: u64,
            _patch: &[u8],
        ) -> Result<(), Self::Error> {
            self.stages += 1;
            Ok(())
        }

        fn flush_new_file_data(
            &mut self,
            _file: StorageObjectId,
            _generation: u64,
            _length: u64,
            _content_digest: [u8; 32],
        ) -> Result<(), Self::Error> {
            self.flushed = true;
            Ok(())
        }
    }

    unsafe impl CowPublicationBackend for PublishBackend {
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

    fn state() -> (FileState<3>, Backend) {
        let mut backend = Backend {
            bytes: [0; 40 * BLOCK_SIZE],
            calls: 0,
            staged: 0,
            flushed: false,
            fail_stage: false,
        };
        backend.bytes[10 * BLOCK_SIZE..11 * BLOCK_SIZE].fill(b'A');
        backend.bytes[20 * BLOCK_SIZE..21 * BLOCK_SIZE].fill(b'B');
        let records = [
            ExtentRecord::data(
                object(7),
                3,
                0,
                1,
                10,
                digest(&backend.bytes[10 * BLOCK_SIZE..11 * BLOCK_SIZE]),
            )
            .unwrap(),
            ExtentRecord::hole(object(7), 3, 1, 1).unwrap(),
            ExtentRecord::data(
                object(7),
                3,
                2,
                1,
                20,
                digest(&backend.bytes[20 * BLOCK_SIZE..21 * BLOCK_SIZE]),
            )
            .unwrap(),
        ];
        let header = VolumeHeader::new(volume(), BLOCK_SIZE as u32, 100, 1, 2).unwrap();
        let length = 2 * BLOCK_SIZE as u64 + 100;
        let map = ExtentMap::build(header, object(7), 3, length, &records).unwrap();
        (FileState::new(object(7), 3, length, map).unwrap(), backend)
    }

    #[test]
    fn initial_empty_file_stages_canonical_creation_images() {
        let header = VolumeHeader::new(volume(), BLOCK_SIZE as u32, 100, 1, 2).unwrap();
        let mut metadata = [0; crate::FILE_METADATA_BYTES];
        let mut extents = [0; BLOCK_SIZE];
        let mut backend = Backend {
            bytes: [0; 40 * BLOCK_SIZE],
            calls: 0,
            staged: 0,
            flushed: false,
            fail_stage: false,
        };
        let prepared = prepare_initial_file(
            header,
            object(8),
            MetadataPointer::new(30, 1).unwrap(),
            MetadataPointer::new(31, 1).unwrap(),
            &mut metadata,
            &mut extents,
            &mut backend,
        )
        .unwrap();
        assert_eq!(
            (prepared.object(), prepared.state().generation()),
            (object(8), 1)
        );
        assert_eq!(prepared.state().length(), 0);
        assert_eq!((backend.staged, backend.flushed), (2, true));
        let mut complete_metadata = [0; BLOCK_SIZE];
        complete_metadata[..crate::FILE_METADATA_BYTES].copy_from_slice(&metadata);
        assert_eq!(
            prepared.metadata_image().digest(),
            digest(&complete_metadata)
        );
        assert_ne!(prepared.metadata_image().digest(), digest(&metadata));
        assert_eq!(
            FileMetadata::decode(&metadata, header)
                .unwrap()
                .content_digest(),
            digest(&[])
        );
        assert!(
            ExtentImage::<0>::decode(
                header,
                object(8),
                1,
                0,
                MetadataPointer::new(31, 1).unwrap(),
                &extents,
            )
            .is_ok()
        );
        let mut transaction =
            StorageTransaction::<1, 2>::new(StorageTransactionId::new(40).unwrap(), 2).unwrap();
        transaction.admit_initial_file(&prepared).unwrap();
        assert_eq!(transaction.participant_count(), 1);

        let mut rejected = Backend {
            bytes: [0; 40 * BLOCK_SIZE],
            calls: 0,
            staged: 0,
            flushed: false,
            fail_stage: false,
        };
        assert!(matches!(
            prepare_initial_file(
                header,
                object(8),
                MetadataPointer::new(30, 1).unwrap(),
                MetadataPointer::new(30, 1).unwrap(),
                &mut metadata,
                &mut extents,
                &mut rejected,
            ),
            Err(InitialFileError::InvalidLayout)
        ));
        assert_eq!(rejected.staged, 0);
    }

    #[test]
    fn read_crosses_verified_data_hole_and_partial_tail() {
        let (state, mut backend) = state();
        let mut authority = StorageAuthorityTable::<1>::new();
        let handle = authority
            .insert(
                object(7),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(),
            )
            .unwrap();
        let mut output = [0xff; 4200];
        assert_eq!(
            state.read(
                &authority,
                handle,
                principal(),
                4090,
                &mut output,
                &mut backend
            ),
            Ok(output.len())
        );
        assert_eq!(&output[..6], &[b'A'; 6]);
        assert!(output[6..4102].iter().all(|byte| *byte == 0));
        assert_eq!(&output[4102..], &[b'B'; 98]);
        assert_eq!(backend.calls, 2);
    }

    #[test]
    fn authority_and_range_failures_never_reach_backend() {
        let (state, mut backend) = state();
        let mut authority = StorageAuthorityTable::<2>::new();
        let wrong = authority
            .insert(
                object(8),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(),
            )
            .unwrap();
        let write_only = authority
            .insert(
                object(7),
                StorageObjectKind::File,
                StorageRights::WRITE,
                principal(),
            )
            .unwrap();
        let mut output = [7; 8];
        assert_eq!(
            state.read(&authority, wrong, principal(), 0, &mut output, &mut backend),
            Err(FileReadError::WrongFile)
        );
        assert!(matches!(
            state.read(
                &authority,
                write_only,
                principal(),
                0,
                &mut output,
                &mut backend
            ),
            Err(FileReadError::Authority(_))
        ));
        assert_eq!(backend.calls, 0);
        let mut authority = StorageAuthorityTable::<1>::new();
        let read = authority
            .insert(
                object(7),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(),
            )
            .unwrap();
        assert_eq!(
            state.read(
                &authority,
                read,
                principal(),
                state.length(),
                &mut output,
                &mut backend
            ),
            Err(FileReadError::OutOfRange)
        );
        assert_eq!(backend.calls, 0);
    }

    #[test]
    fn digest_failure_erases_partial_output() {
        let (state, mut backend) = state();
        backend.bytes[20 * BLOCK_SIZE] ^= 1;
        let mut authority = StorageAuthorityTable::<1>::new();
        let read = authority
            .insert(
                object(7),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(),
            )
            .unwrap();
        let mut output = [9; 4200];
        assert_eq!(
            state.read(
                &authority,
                read,
                principal(),
                4090,
                &mut output,
                &mut backend
            ),
            Err(FileReadError::Backend(()))
        );
        assert!(output.iter().all(|byte| *byte == 0));
        assert_eq!(backend.calls, 2);
    }

    #[test]
    fn empty_read_at_end_succeeds_but_oversized_read_is_rejected() {
        let (state, mut backend) = state();
        let mut authority = StorageAuthorityTable::<1>::new();
        let read = authority
            .insert(
                object(7),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(),
            )
            .unwrap();
        assert_eq!(
            state.read(
                &authority,
                read,
                principal(),
                state.length(),
                &mut [],
                &mut backend
            ),
            Ok(0)
        );
        let mut oversized = [0; MAX_FILE_READ_BYTES + 1];
        assert_eq!(
            state.read(
                &authority,
                read,
                principal(),
                0,
                &mut oversized,
                &mut backend
            ),
            Err(FileReadError::TooLarge)
        );
        assert_eq!(backend.calls, 0);
    }

    fn successor_map(patch: &[u8]) -> (ExtentMap<1>, FileMetadata, MetadataPointer) {
        let mut image = [0; 3 * BLOCK_SIZE];
        image[..BLOCK_SIZE].fill(b'A');
        image[2 * BLOCK_SIZE..2 * BLOCK_SIZE + 100].fill(b'B');
        image[4090..4090 + patch.len()].copy_from_slice(patch);
        let record = ExtentRecord::data(object(7), 4, 0, 3, 30, digest(&image)).unwrap();
        let header = VolumeHeader::new(volume(), BLOCK_SIZE as u32, 100, 1, 2).unwrap();
        let length = 2 * BLOCK_SIZE as u64 + 100;
        let metadata = FileMetadata::new(
            header,
            object(7),
            4,
            length,
            1,
            MetadataPointer::new(90, 1).unwrap(),
            digest(&image[..usize::try_from(length).unwrap()]),
        )
        .unwrap();
        (
            ExtentMap::build(header, object(7), 4, length, &[record]).unwrap(),
            metadata,
            MetadataPointer::new(70, 1).unwrap(),
        )
    }

    #[test]
    fn write_stages_complete_disjoint_successor_before_returning_prepared_state() {
        let (state, mut backend) = state();
        let mut authority = StorageAuthorityTable::<1>::new();
        let write = authority
            .insert(
                object(7),
                StorageObjectKind::File,
                StorageRights::WRITE,
                principal(),
            )
            .unwrap();
        let patch = [b'C'; 4200];
        let (next, metadata, metadata_pointer) = successor_map(&patch);
        let prepared = state
            .prepare_write(
                &authority,
                write,
                principal(),
                4090,
                &patch,
                state.length(),
                next,
                metadata,
                metadata_pointer,
                &[MetadataPointer::new(50, 1).unwrap()],
                &mut backend,
            )
            .unwrap();
        assert_eq!(prepared.generation(), 4);
        assert_eq!(backend.staged, 1);
        assert!(backend.flushed);
        assert_eq!(
            &backend.bytes[30 * BLOCK_SIZE + 4090..30 * BLOCK_SIZE + 8290],
            &patch
        );
    }

    #[test]
    fn write_requires_resize_and_rejects_active_or_metadata_overlap_before_backend() {
        let (state, mut backend) = state();
        let mut authority = StorageAuthorityTable::<1>::new();
        let write = authority
            .insert(
                object(7),
                StorageObjectKind::File,
                StorageRights::WRITE,
                principal(),
            )
            .unwrap();
        let patch = [1; 1];
        let (next, metadata, metadata_pointer) = successor_map(&patch);
        assert!(matches!(
            state.prepare_write(
                &authority,
                write,
                principal(),
                0,
                &patch,
                state.length() + 1,
                next,
                metadata,
                metadata_pointer,
                &[],
                &mut backend
            ),
            Err(FileWriteError::Authority(_))
        ));
        let old_overlap = ExtentRecord::data(object(7), 4, 0, 3, 10, [1; 32]).unwrap();
        let header = VolumeHeader::new(volume(), BLOCK_SIZE as u32, 100, 1, 2).unwrap();
        let map =
            ExtentMap::<1>::build(header, object(7), 4, state.length(), &[old_overlap]).unwrap();
        assert_eq!(
            state
                .prepare_write(
                    &authority,
                    write,
                    principal(),
                    0,
                    &patch,
                    state.length(),
                    map,
                    metadata,
                    metadata_pointer,
                    &[],
                    &mut backend
                )
                .map(|_| ()),
            Err(FileWriteError::OverwritesActiveData)
        );
        let (next, metadata, metadata_pointer) = successor_map(&patch);
        assert_eq!(
            state
                .prepare_write(
                    &authority,
                    write,
                    principal(),
                    0,
                    &patch,
                    state.length(),
                    next,
                    metadata,
                    metadata_pointer,
                    &[MetadataPointer::new(30, 1).unwrap()],
                    &mut backend
                )
                .map(|_| ()),
            Err(FileWriteError::OverwritesMetadata)
        );
        assert_eq!(backend.staged, 0);
    }

    #[test]
    fn prepared_write_publishes_only_through_matching_metadata_plan() {
        let (state, mut data_backend) = state();
        let mut authority = StorageAuthorityTable::<1>::new();
        let write = authority
            .insert(
                object(7),
                StorageObjectKind::File,
                StorageRights::WRITE,
                principal(),
            )
            .unwrap();
        let patch = [b'D'; 16];
        let (next, next_metadata, metadata_pointer) = successor_map(&patch);
        let prepared = state
            .prepare_write(
                &authority,
                write,
                principal(),
                4090,
                &patch,
                state.length(),
                next,
                next_metadata,
                metadata_pointer,
                &[MetadataPointer::new(50, 1).unwrap()],
                &mut data_backend,
            )
            .unwrap();
        let file_metadata = prepared.metadata_image().bind(4).unwrap();
        let extent_metadata = prepared.extent_metadata_image().bind(4).unwrap();
        let header = VolumeHeader::new(volume(), BLOCK_SIZE as u32, 100, 1, 2).unwrap();
        let active = Superblock::new(
            header,
            3,
            2,
            object(1),
            MetadataPointer::new(50, 1).unwrap(),
            MetadataPointer::new(60, 1).unwrap(),
        )
        .unwrap();
        let root = CowMetadataWrite::new(MetadataPointer::new(71, 1).unwrap(), 4, [8; 32]).unwrap();
        let allocation =
            CowMetadataWrite::new(MetadataPointer::new(80, 1).unwrap(), 4, [9; 32]).unwrap();
        let plan = CowPublicationPlan::<4>::build(
            header,
            1,
            active,
            object(1),
            root.pointer(),
            allocation.pointer(),
            &[file_metadata, extent_metadata, root, allocation],
            &[
                MetadataPointer::new(50, 1).unwrap(),
                MetadataPointer::new(60, 1).unwrap(),
            ],
        )
        .unwrap();
        let mut publication = PublishBackend {
            verified: 0,
            replaced: 0,
        };
        let committed = prepared.publish(&plan, &mut publication).unwrap();
        assert_eq!(
            (committed.generation(), committed.length()),
            (4, state.length())
        );
        assert_eq!((publication.verified, publication.replaced), (4, 1));

        let (next, next_metadata, metadata_pointer) = successor_map(&patch);
        let prepared = state
            .prepare_write(
                &authority,
                write,
                principal(),
                4090,
                &patch,
                state.length(),
                next,
                next_metadata,
                metadata_pointer,
                &[MetadataPointer::new(50, 1).unwrap()],
                &mut data_backend,
            )
            .unwrap();
        let second_file_metadata = prepared.metadata_image().bind(4).unwrap();
        let incomplete = CowPublicationPlan::<3>::build(
            header,
            1,
            active,
            object(1),
            root.pointer(),
            allocation.pointer(),
            &[second_file_metadata, root, allocation],
            &[
                MetadataPointer::new(50, 1).unwrap(),
                MetadataPointer::new(60, 1).unwrap(),
            ],
        )
        .unwrap();
        let mut rejected = PublishBackend {
            verified: 0,
            replaced: 0,
        };
        assert!(matches!(
            prepared.publish(&incomplete, &mut rejected),
            Err(FileWritePublishError::WrongMetadataPlan)
        ));
        assert_eq!((rejected.verified, rejected.replaced), (0, 0));
    }

    #[test]
    fn prepared_write_commits_from_one_use_transaction_receipt() {
        let (state, mut data_backend) = state();
        let mut authority = StorageAuthorityTable::<1>::new();
        let write = authority
            .insert(
                object(7),
                StorageObjectKind::File,
                StorageRights::WRITE,
                principal(),
            )
            .unwrap();
        let patch = [b'E'; 16];
        let (next, next_metadata, metadata_pointer) = successor_map(&patch);
        let prepared = state
            .prepare_write(
                &authority,
                write,
                principal(),
                4090,
                &patch,
                state.length(),
                next,
                next_metadata,
                metadata_pointer,
                &[MetadataPointer::new(50, 1).unwrap()],
                &mut data_backend,
            )
            .unwrap();

        let publication_generation = 10;
        let mut transaction = StorageTransaction::<1, 2>::new(
            StorageTransactionId::new(11).unwrap(),
            publication_generation,
        )
        .unwrap();
        transaction.admit_file(&prepared).unwrap();
        let header = VolumeHeader::new(volume(), BLOCK_SIZE as u32, 100, 1, 2).unwrap();
        let active = Superblock::new(
            header,
            publication_generation - 1,
            8,
            object(1),
            MetadataPointer::new(50, 1).unwrap(),
            MetadataPointer::new(60, 1).unwrap(),
        )
        .unwrap();
        let root = CowMetadataWrite::new(
            MetadataPointer::new(71, 1).unwrap(),
            publication_generation,
            [8; 32],
        )
        .unwrap();
        let allocation = CowMetadataWrite::new(
            MetadataPointer::new(80, 1).unwrap(),
            publication_generation,
            [9; 32],
        )
        .unwrap();
        let plan = CowPublicationPlan::<4>::build(
            header,
            1,
            active,
            object(1),
            root.pointer(),
            allocation.pointer(),
            &[
                prepared
                    .metadata_image()
                    .bind(publication_generation)
                    .unwrap(),
                prepared
                    .extent_metadata_image()
                    .bind(publication_generation)
                    .unwrap(),
                root,
                allocation,
            ],
            &[
                MetadataPointer::new(50, 1).unwrap(),
                MetadataPointer::new(60, 1).unwrap(),
            ],
        )
        .unwrap();
        let mut publication = PublishBackend {
            verified: 0,
            replaced: 0,
        };
        let mut receipt = transaction.publish(&plan, &mut publication).unwrap();
        let participant = prepared.transaction_participant().unwrap();
        assert_eq!(authority.revoke(write, principal()), Ok(1));
        let (_, error) = match prepared.commit_transaction_authorized(&authority, &mut receipt) {
            Err(failure) => failure,
            Ok(_) => panic!("revoked file write authority committed"),
        };
        assert_eq!(
            error,
            FileWriteCommitError::Authority(StorageAuthorityError::InvalidHandle)
        );
        assert_eq!(receipt.remaining(), 1);
        assert_eq!(receipt.consume(participant), Ok(()));
        assert_eq!(
            receipt.consume(participant),
            Err(TransactionError::ParticipantMismatch)
        );
        assert_eq!((publication.verified, publication.replaced), (4, 1));
    }

    #[test]
    fn resize_succeeds_with_both_rights_and_metadata_mismatch_prevents_staging() {
        let (state, _) = state();
        let mut authority = StorageAuthorityTable::<1>::new();
        let write = authority
            .insert(
                object(7),
                StorageObjectKind::File,
                StorageRights::WRITE.union(StorageRights::RESIZE),
                principal(),
            )
            .unwrap();
        let new_length = state.length() + 1;
        let header = VolumeHeader::new(volume(), BLOCK_SIZE as u32, 100, 1, 2).unwrap();
        let record = ExtentRecord::data(object(7), 4, 0, 3, 30, [3; 32]).unwrap();
        let next = ExtentMap::<1>::build(header, object(7), 4, new_length, &[record]).unwrap();
        let metadata = FileMetadata::new(
            header,
            object(7),
            4,
            new_length,
            1,
            MetadataPointer::new(90, 1).unwrap(),
            [4; 32],
        )
        .unwrap();
        let mut recorder = WriteRecorder {
            stages: 0,
            flushed: false,
        };
        let prepared = state
            .prepare_write(
                &authority,
                write,
                principal(),
                state.length(),
                &[5],
                new_length,
                next,
                metadata,
                MetadataPointer::new(70, 1).unwrap(),
                &[],
                &mut recorder,
            )
            .unwrap();
        assert_eq!(prepared.generation(), 4);
        assert_eq!((recorder.stages, recorder.flushed), (1, true));

        let next = ExtentMap::<1>::build(header, object(7), 4, new_length, &[record]).unwrap();
        let mismatched = FileMetadata::new(
            header,
            object(7),
            4,
            new_length,
            2,
            MetadataPointer::new(90, 1).unwrap(),
            [4; 32],
        )
        .unwrap();
        let mut untouched = WriteRecorder {
            stages: 0,
            flushed: false,
        };
        assert!(matches!(
            state.prepare_write(
                &authority,
                write,
                principal(),
                state.length(),
                &[5],
                new_length,
                next,
                mismatched,
                MetadataPointer::new(70, 1).unwrap(),
                &[],
                &mut untouched,
            ),
            Err(FileWriteError::InvalidSuccessor)
        ));
        assert_eq!((untouched.stages, untouched.flushed), (0, false));
    }

    #[test]
    fn staging_failure_never_produces_a_prepared_write() {
        let (state, mut backend) = state();
        backend.fail_stage = true;
        let mut authority = StorageAuthorityTable::<1>::new();
        let write = authority
            .insert(
                object(7),
                StorageObjectKind::File,
                StorageRights::WRITE,
                principal(),
            )
            .unwrap();
        let patch = [1; 1];
        let (next, metadata, metadata_pointer) = successor_map(&patch);
        assert!(matches!(
            state.prepare_write(
                &authority,
                write,
                principal(),
                0,
                &patch,
                state.length(),
                next,
                metadata,
                metadata_pointer,
                &[],
                &mut backend,
            ),
            Err(FileWriteError::Backend(()))
        ));
        assert_eq!(backend.staged, 1);
        assert!(!backend.flushed);
        assert_eq!(state.generation(), 3);
    }

    #[test]
    fn whole_file_digest_failure_rejects_after_staging_but_before_publication() {
        let (state, mut backend) = state();
        let mut authority = StorageAuthorityTable::<1>::new();
        let write = authority
            .insert(
                object(7),
                StorageObjectKind::File,
                StorageRights::WRITE,
                principal(),
            )
            .unwrap();
        let patch = [1; 1];
        let (next, metadata, metadata_pointer) = successor_map(&patch);
        let header = VolumeHeader::new(volume(), BLOCK_SIZE as u32, 100, 1, 2).unwrap();
        let wrong_digest = FileMetadata::new(
            header,
            metadata.object(),
            metadata.generation(),
            metadata.length(),
            metadata.extent_count(),
            metadata.extents(),
            [0; 32],
        )
        .unwrap();
        assert!(matches!(
            state.prepare_write(
                &authority,
                write,
                principal(),
                0,
                &patch,
                state.length(),
                next,
                wrong_digest,
                metadata_pointer,
                &[],
                &mut backend,
            ),
            Err(FileWriteError::Backend(()))
        ));
        assert_eq!(backend.staged, 1);
        assert!(!backend.flushed);
        assert_eq!(state.generation(), 3);
    }
}
