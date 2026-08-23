use mrml_crypto::Sha3_256;

use crate::{
    CowMetadataImage, DirectoryEntry, DirectoryMetadata, MetadataPointer, StorageAuthorityError,
    StorageAuthorityTable, StorageHandle, StorageName, StorageObjectId, StorageObjectKind,
    StoragePrincipal, StorageRights, TransactionError, TransactionParticipant, TransactionReceipt,
    VolumeHeader, VolumeId,
};

pub const DIRECTORY_IMAGE_HEADER_BYTES: usize = 96;

const DIRECTORY_IMAGE_MAGIC: [u8; 8] = *b"MRDEI001";
const DIRECTORY_IMAGE_VERSION: u16 = 1;
const DIRECTORY_IMAGE_DIGEST_OFFSET: usize = 64;

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

#[derive(Clone)]
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
        if entries.len() > N {
            return Err(DirectoryError::InvalidState);
        }
        let mut stored = [None; N];
        for (slot, entry) in stored.iter_mut().zip(entries.iter().copied()) {
            *slot = Some(entry);
        }
        Self::from_stored(object, generation, stored, entries.len())
    }

    fn from_stored(
        object: StorageObjectId,
        generation: u64,
        stored: [Option<DirectoryEntry>; N],
        count: usize,
    ) -> Result<Self, DirectoryError> {
        if generation == 0 || count > N || stored[..count].iter().any(Option::is_none) {
            return Err(DirectoryError::InvalidState);
        }
        for index in 0..count {
            let entry = stored[index].ok_or(DirectoryError::InvalidState)?;
            if entry.object().volume() != object.volume()
                || entry.object() == object
                || stored[..index]
                    .iter()
                    .flatten()
                    .any(|prior| prior.name() == entry.name() || prior.object() == entry.object())
            {
                return Err(DirectoryError::InvalidState);
            }
        }
        Ok(Self {
            object,
            generation,
            entries: stored,
            count,
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

    pub const fn entry(&self, index: usize) -> Option<DirectoryEntry> {
        if index < self.count {
            self.entries[index]
        } else {
            None
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_successor<B: DirectoryWriteBackend>(
        &self,
        header: VolumeHeader,
        parent: Option<StorageObjectId>,
        successor: DirectoryState<N>,
        metadata_pointer: MetadataPointer,
        entries_pointer: MetadataPointer,
        metadata_output: &mut [u8; crate::DIRECTORY_METADATA_BYTES],
        entries_output: &mut [u8],
        backend: &mut B,
    ) -> Result<PreparedDirectoryUpdate<N>, DirectoryUpdateError<B::Error>> {
        if successor.object != self.object
            || self.generation.checked_add(1) != Some(successor.generation)
            || !metadata_pointer_valid(header, metadata_pointer)
            || !metadata_pointer_valid(header, entries_pointer)
            || pointers_overlap(metadata_pointer, entries_pointer)
        {
            return Err(DirectoryUpdateError::InvalidSuccessor);
        }
        let metadata = successor
            .metadata(header, parent, entries_pointer)
            .map_err(|_| DirectoryUpdateError::InvalidSuccessor)?;
        metadata.encode(metadata_output);
        let entries = DirectoryImage::from_state(header, entries_pointer, successor.clone())
            .map_err(|_| DirectoryUpdateError::InvalidSuccessor)?;
        entries
            .encode(entries_output)
            .map_err(|_| DirectoryUpdateError::InvalidSuccessor)?;
        let metadata_image = CowMetadataImage::new(metadata_pointer, digest(metadata_output));
        let entries_image = CowMetadataImage::new(entries_pointer, digest(entries_output));
        backend
            .stage_directory_metadata(metadata_image, metadata_output)
            .map_err(DirectoryUpdateError::Backend)?;
        backend
            .stage_directory_entries(entries_image, entries_output)
            .map_err(DirectoryUpdateError::Backend)?;
        backend
            .flush_directory_update()
            .map_err(DirectoryUpdateError::Backend)?;
        Ok(PreparedDirectoryUpdate {
            old_generation: self.generation,
            successor,
            metadata: metadata_image,
            entries: entries_image,
        })
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

pub struct DirectoryImage<const N: usize> {
    volume: VolumeId,
    pointer: MetadataPointer,
    encoded_len: usize,
    state: DirectoryState<N>,
}

pub struct PreparedDirectoryUpdate<const N: usize> {
    old_generation: u64,
    successor: DirectoryState<N>,
    metadata: CowMetadataImage,
    entries: CowMetadataImage,
}

impl<const N: usize> PreparedDirectoryUpdate<N> {
    pub const fn generation(&self) -> u64 {
        self.successor.generation
    }

    pub const fn object(&self) -> StorageObjectId {
        self.successor.object
    }

    pub const fn metadata_image(&self) -> CowMetadataImage {
        self.metadata
    }

    pub const fn entries_image(&self) -> CowMetadataImage {
        self.entries
    }

    pub(crate) fn transaction_participant(
        &self,
    ) -> Result<TransactionParticipant, TransactionError> {
        TransactionParticipant::new(
            self.successor.object,
            StorageObjectKind::Directory,
            self.old_generation,
            self.successor.generation,
        )
    }

    pub(crate) const fn metadata_images(&self) -> [CowMetadataImage; 2] {
        [self.metadata, self.entries]
    }

    pub fn commit_transaction<const P: usize>(
        self,
        receipt: &mut TransactionReceipt<P>,
    ) -> Result<DirectoryState<N>, TransactionError> {
        receipt.consume(self.transaction_participant()?)?;
        Ok(self.successor)
    }
}

impl<const N: usize> DirectoryImage<N> {
    fn from_state(
        header: VolumeHeader,
        pointer: MetadataPointer,
        state: DirectoryState<N>,
    ) -> Result<Self, DirectoryImageError> {
        if !pointer_fits(header, pointer) || state.object.volume() != header.volume() {
            return Err(DirectoryImageError::InvalidImage);
        }
        let encoded_len = image_bytes(header, pointer)?;
        let used = state
            .len()
            .checked_mul(crate::DIRECTORY_ENTRY_BYTES)
            .and_then(|bytes| bytes.checked_add(DIRECTORY_IMAGE_HEADER_BYTES))
            .ok_or(DirectoryImageError::Arithmetic)?;
        if used > encoded_len {
            return Err(DirectoryImageError::Capacity);
        }
        Ok(Self {
            volume: header.volume(),
            pointer,
            encoded_len,
            state,
        })
    }

    pub fn build(
        header: VolumeHeader,
        object: StorageObjectId,
        generation: u64,
        pointer: MetadataPointer,
        entries: &[DirectoryEntry],
    ) -> Result<Self, DirectoryImageError> {
        if !pointer_fits(header, pointer) {
            return Err(DirectoryImageError::InvalidImage);
        }
        let encoded_len = image_bytes(header, pointer)?;
        let used = entries
            .len()
            .checked_mul(crate::DIRECTORY_ENTRY_BYTES)
            .and_then(|bytes| bytes.checked_add(DIRECTORY_IMAGE_HEADER_BYTES))
            .ok_or(DirectoryImageError::Arithmetic)?;
        if used > encoded_len {
            return Err(DirectoryImageError::Capacity);
        }
        Ok(Self {
            volume: header.volume(),
            pointer,
            encoded_len,
            state: DirectoryState::new(object, generation, entries)
                .map_err(|_| DirectoryImageError::InvalidImage)?,
        })
    }

    pub fn decode(
        header: VolumeHeader,
        object: StorageObjectId,
        generation: u64,
        pointer: MetadataPointer,
        input: &[u8],
    ) -> Result<Self, DirectoryImageError> {
        if !pointer_fits(header, pointer) || input.len() != image_bytes(header, pointer)? {
            return Err(DirectoryImageError::InvalidImage);
        }
        if input[..8] != DIRECTORY_IMAGE_MAGIC
            || get_u16(input, 10)? != DIRECTORY_IMAGE_HEADER_BYTES as u16
            || get_u16(input, 12)? != crate::DIRECTORY_ENTRY_BYTES as u16
            || input[14..16].iter().any(|byte| *byte != 0)
            || input[52..DIRECTORY_IMAGE_DIGEST_OFFSET]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(DirectoryImageError::NonCanonical);
        }
        if get_u16(input, 8)? != DIRECTORY_IMAGE_VERSION {
            return Err(DirectoryImageError::UnsupportedVersion);
        }
        if read_volume(input, 16)? != header.volume() {
            return Err(DirectoryImageError::WrongVolume);
        }
        if get_u64(input, 32)? != object.local() || get_u64(input, 40)? != generation {
            return Err(DirectoryImageError::InvalidImage);
        }
        if input[DIRECTORY_IMAGE_DIGEST_OFFSET..DIRECTORY_IMAGE_HEADER_BYTES] != image_digest(input)
        {
            return Err(DirectoryImageError::Corrupt);
        }
        let count =
            usize::try_from(get_u32(input, 48)?).map_err(|_| DirectoryImageError::Capacity)?;
        if count > N {
            return Err(DirectoryImageError::Capacity);
        }
        let used = count
            .checked_mul(crate::DIRECTORY_ENTRY_BYTES)
            .and_then(|bytes| bytes.checked_add(DIRECTORY_IMAGE_HEADER_BYTES))
            .ok_or(DirectoryImageError::Arithmetic)?;
        if used > input.len() || input[used..].iter().any(|byte| *byte != 0) {
            return Err(DirectoryImageError::NonCanonical);
        }
        let mut entries = [None; N];
        for (index, slot) in entries[..count].iter_mut().enumerate() {
            let start = DIRECTORY_IMAGE_HEADER_BYTES + index * crate::DIRECTORY_ENTRY_BYTES;
            *slot = Some(
                DirectoryEntry::decode(
                    &input[start..start + crate::DIRECTORY_ENTRY_BYTES],
                    header.volume(),
                )
                .map_err(|_| DirectoryImageError::InvalidEntry)?,
            );
        }
        Ok(Self {
            volume: header.volume(),
            pointer,
            encoded_len: input.len(),
            state: DirectoryState::from_stored(object, generation, entries, count)
                .map_err(|_| DirectoryImageError::InvalidEntry)?,
        })
    }

    pub const fn pointer(&self) -> MetadataPointer {
        self.pointer
    }

    pub const fn state(&self) -> &DirectoryState<N> {
        &self.state
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<(), DirectoryImageError> {
        if output.len() != self.encoded_len {
            return Err(DirectoryImageError::Truncated);
        }
        output.fill(0);
        output[..8].copy_from_slice(&DIRECTORY_IMAGE_MAGIC);
        put_u16(output, 8, DIRECTORY_IMAGE_VERSION);
        put_u16(output, 10, DIRECTORY_IMAGE_HEADER_BYTES as u16);
        put_u16(output, 12, crate::DIRECTORY_ENTRY_BYTES as u16);
        output[16..32].copy_from_slice(&self.volume.bytes());
        put_u64(output, 32, self.state.object().local());
        put_u64(output, 40, self.state.generation());
        put_u32(output, 48, self.state.len() as u32);
        for index in 0..self.state.len() {
            let start = DIRECTORY_IMAGE_HEADER_BYTES + index * crate::DIRECTORY_ENTRY_BYTES;
            let end = start + crate::DIRECTORY_ENTRY_BYTES;
            let encoded: &mut [u8; crate::DIRECTORY_ENTRY_BYTES] = (&mut output[start..end])
                .try_into()
                .map_err(|_| DirectoryImageError::Truncated)?;
            self.state
                .entry(index)
                .ok_or(DirectoryImageError::InvalidEntry)?
                .encode(encoded);
        }
        let digest = image_digest(output);
        output[DIRECTORY_IMAGE_DIGEST_OFFSET..DIRECTORY_IMAGE_HEADER_BYTES]
            .copy_from_slice(&digest);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryImageError {
    Truncated,
    UnsupportedVersion,
    NonCanonical,
    Corrupt,
    WrongVolume,
    InvalidImage,
    InvalidEntry,
    Capacity,
    Arithmetic,
}

/// Persistence boundary for an unreachable directory metadata successor.
///
/// # Safety
///
/// Implementations must write each complete supplied image to its exact range,
/// verify the complete bytes against the supplied digest, keep both ranges
/// unreachable from the active root, and make both images durable before
/// `flush_directory_update` succeeds. They must not redirect, shorten, merge,
/// reorder, or acknowledge stale or partially written images.
pub unsafe trait DirectoryWriteBackend {
    type Error;

    fn stage_directory_metadata(
        &mut self,
        image: CowMetadataImage,
        encoded: &[u8; crate::DIRECTORY_METADATA_BYTES],
    ) -> Result<(), Self::Error>;

    fn stage_directory_entries(
        &mut self,
        image: CowMetadataImage,
        encoded: &[u8],
    ) -> Result<(), Self::Error>;

    fn flush_directory_update(&mut self) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryUpdateError<E> {
    InvalidSuccessor,
    Backend(E),
}

fn digest(input: &[u8]) -> [u8; 32] {
    let mut digest = Sha3_256::new();
    digest.update(input);
    digest.finalize()
}

fn image_digest(input: &[u8]) -> [u8; 32] {
    let mut digest = Sha3_256::new();
    digest.update(&input[..DIRECTORY_IMAGE_DIGEST_OFFSET]);
    digest.update(&[0; 32]);
    digest.update(&input[DIRECTORY_IMAGE_HEADER_BYTES..]);
    digest.finalize()
}

fn image_bytes(
    header: VolumeHeader,
    pointer: MetadataPointer,
) -> Result<usize, DirectoryImageError> {
    usize::try_from(
        u64::from(header.block_size())
            .checked_mul(u64::from(pointer.blocks()))
            .ok_or(DirectoryImageError::Arithmetic)?,
    )
    .map_err(|_| DirectoryImageError::Arithmetic)
}

fn pointer_fits(header: VolumeHeader, pointer: MetadataPointer) -> bool {
    pointer
        .block()
        .checked_add(u64::from(pointer.blocks()))
        .is_some_and(|end| end <= header.block_count())
        && !pointer_contains(pointer, 0)
        && !pointer_contains(pointer, header.primary_superblock())
        && !pointer_contains(pointer, header.secondary_superblock())
}

fn metadata_pointer_valid(header: VolumeHeader, pointer: MetadataPointer) -> bool {
    pointer_fits(header, pointer)
}

fn pointers_overlap(left: MetadataPointer, right: MetadataPointer) -> bool {
    left.block() < right.block() + u64::from(right.blocks())
        && right.block() < left.block() + u64::from(left.blocks())
}

fn pointer_contains(pointer: MetadataPointer, block: u64) -> bool {
    block >= pointer.block() && block < pointer.block() + u64::from(pointer.blocks())
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(input: &[u8], offset: usize) -> Result<u16, DirectoryImageError> {
    input
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(DirectoryImageError::Truncated)
}

fn get_u32(input: &[u8], offset: usize) -> Result<u32, DirectoryImageError> {
    input
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(DirectoryImageError::Truncated)
}

fn get_u64(input: &[u8], offset: usize) -> Result<u64, DirectoryImageError> {
    input
        .get(offset..offset + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(DirectoryImageError::Truncated)
}

fn read_volume(input: &[u8], offset: usize) -> Result<VolumeId, DirectoryImageError> {
    let bytes: [u8; 16] = input
        .get(offset..offset + 16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(DirectoryImageError::Truncated)?;
    VolumeId::new(bytes).map_err(|_| DirectoryImageError::WrongVolume)
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
    use crate::{
        CowMetadataWrite, CowPublicationBackend, CowPublicationPlan, StorageTransaction,
        StorageTransactionId, Superblock,
    };

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

    struct UpdateBackend {
        staged: usize,
        flushed: bool,
        verified: usize,
    }

    unsafe impl DirectoryWriteBackend for UpdateBackend {
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
            self.flushed = true;
            Ok(())
        }
    }

    unsafe impl CowPublicationBackend for UpdateBackend {
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
            Ok(())
        }

        fn flush_superblock(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn directory_successor_is_staged_and_activated_by_one_use_receipt() {
        let header = VolumeHeader::new(volume(), 4096, 100, 1, 2).unwrap();
        let active = DirectoryState::<2>::new(object(1), 1, &[]).unwrap();
        let entry =
            DirectoryEntry::new(name("file"), object(2), StorageObjectKind::File, 1).unwrap();
        let successor = DirectoryState::<2>::new(object(1), 2, &[entry]).unwrap();
        let metadata_pointer = MetadataPointer::new(60, 1).unwrap();
        let entries_pointer = MetadataPointer::new(61, 1).unwrap();
        let mut metadata = [0; crate::DIRECTORY_METADATA_BYTES];
        let mut entries = [0; 4096];
        let mut backend = UpdateBackend {
            staged: 0,
            flushed: false,
            verified: 0,
        };
        let prepared = active
            .prepare_successor(
                header,
                None,
                successor,
                metadata_pointer,
                entries_pointer,
                &mut metadata,
                &mut entries,
                &mut backend,
            )
            .unwrap();
        assert_eq!((backend.staged, backend.flushed), (2, true));

        let mut transaction =
            StorageTransaction::<1, 2>::new(StorageTransactionId::new(30).unwrap(), 6).unwrap();
        transaction.admit_directory(&prepared).unwrap();
        let active_root = Superblock::new(
            header,
            5,
            4,
            object(1),
            MetadataPointer::new(10, 1).unwrap(),
            MetadataPointer::new(20, 1).unwrap(),
        )
        .unwrap();
        let allocation =
            CowMetadataWrite::new(MetadataPointer::new(50, 1).unwrap(), 6, [9; 32]).unwrap();
        let plan = CowPublicationPlan::<3>::build(
            header,
            1,
            active_root,
            object(1),
            metadata_pointer,
            allocation.pointer(),
            &[
                prepared.metadata_image().bind(6).unwrap(),
                prepared.entries_image().bind(6).unwrap(),
                allocation,
            ],
            &[
                MetadataPointer::new(10, 1).unwrap(),
                MetadataPointer::new(11, 1).unwrap(),
                MetadataPointer::new(20, 1).unwrap(),
            ],
        )
        .unwrap();
        let mut receipt = transaction.publish(&plan, &mut backend).unwrap();
        let committed = prepared.commit_transaction(&mut receipt).unwrap();
        assert_eq!(committed.generation(), 2);
        assert_eq!(committed.entry(0), Some(entry));
        assert_eq!(receipt.remaining(), 0);
        assert_eq!(backend.verified, 3);
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

    #[test]
    fn directory_image_round_trip_binds_owner_generation_and_zero_padding() {
        let pointer = MetadataPointer::new(30, 1).unwrap();
        let entries = [
            DirectoryEntry::new(name("child"), object(8), StorageObjectKind::Directory, 2).unwrap(),
            DirectoryEntry::new(name("file"), object(9), StorageObjectKind::File, 3).unwrap(),
        ];
        let header = VolumeHeader::new(volume(), 4096, 100, 1, 2).unwrap();
        let image = DirectoryImage::<2>::build(header, object(1), 4, pointer, &entries).unwrap();
        let mut encoded = [0; 4096];
        image.encode(&mut encoded).unwrap();
        let decoded = DirectoryImage::<2>::decode(header, object(1), 4, pointer, &encoded).unwrap();
        assert_eq!(decoded.pointer(), pointer);
        assert_eq!(decoded.state().len(), 2);
        assert_eq!(decoded.state().entry(1), Some(entries[1]));
        assert!(matches!(
            DirectoryImage::<2>::decode(header, object(1), 5, pointer, &encoded),
            Err(DirectoryImageError::InvalidImage)
        ));

        encoded[4095] = 1;
        let digest = image_digest(&encoded);
        encoded[DIRECTORY_IMAGE_DIGEST_OFFSET..DIRECTORY_IMAGE_HEADER_BYTES]
            .copy_from_slice(&digest);
        assert!(matches!(
            DirectoryImage::<2>::decode(header, object(1), 4, pointer, &encoded),
            Err(DirectoryImageError::NonCanonical)
        ));
    }
}
