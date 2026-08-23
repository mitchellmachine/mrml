use crate::{
    ExtentError, ExtentKind, ExtentMap, ExtentRecord, StorageAuthorityError, StorageAuthorityTable,
    StorageHandle, StorageObjectId, StorageObjectKind, StoragePrincipal, StorageRights,
};

pub const MAX_FILE_READ_BYTES: usize = 1 << 20;

pub struct FileState<const N: usize> {
    object: StorageObjectId,
    generation: u64,
    length: u64,
    extents: ExtentMap<N>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VolumeHeader, VolumeId};
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
        bytes: [u8; 24 * BLOCK_SIZE],
        calls: usize,
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

    fn state() -> (FileState<3>, Backend) {
        let mut backend = Backend {
            bytes: [0; 24 * BLOCK_SIZE],
            calls: 0,
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
}
