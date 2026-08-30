use crate::{
    BlockService, BlockServiceBackend, BlockServiceError, BlockSessionHandle, StoragePrincipal,
};
use mrml_interface_storage_filesystem_v3::OpaqueHandle;

pub const FILESYSTEM_BOOT_SECTOR_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemBootSectorError<E> {
    VolumeMismatch,
    InvalidBlockGeometry,
    Block(BlockServiceError<E>),
}

/// Exact authorized bridge from a filesystem volume identity to block zero.
///
/// The opaque volume remains non-authorizing. Construction authenticates the
/// block session owner and exact geometry; each read rechecks ordinary block
/// `READ` authority through `BlockService`.
pub struct FilesystemBootSectorReader<
    'a,
    B: BlockServiceBackend,
    const DEVICES: usize,
    const SESSIONS: usize,
> {
    service: &'a BlockService<DEVICES, SESSIONS>,
    backend: &'a mut B,
    session: BlockSessionHandle,
    owner: StoragePrincipal,
    volume: OpaqueHandle,
    scratch: &'a mut [u8],
}

impl<'a, B: BlockServiceBackend, const DEVICES: usize, const SESSIONS: usize>
    FilesystemBootSectorReader<'a, B, DEVICES, SESSIONS>
{
    pub fn new(
        service: &'a BlockService<DEVICES, SESSIONS>,
        backend: &'a mut B,
        session: BlockSessionHandle,
        owner: StoragePrincipal,
        volume: OpaqueHandle,
        scratch: &'a mut [u8],
    ) -> Result<Self, FilesystemBootSectorError<core::convert::Infallible>> {
        let descriptor = service
            .session_descriptor(session, owner)
            .map_err(FilesystemBootSectorError::Block)?;
        if descriptor.block_count() == 0
            || descriptor.block_size() < FILESYSTEM_BOOT_SECTOR_BYTES as u32
            || scratch.len() != descriptor.block_size() as usize
        {
            scratch.fill(0);
            return Err(FilesystemBootSectorError::InvalidBlockGeometry);
        }
        scratch.fill(0);
        Ok(Self {
            service,
            backend,
            session,
            owner,
            volume,
            scratch,
        })
    }

    pub const fn volume(&self) -> OpaqueHandle {
        self.volume
    }

    pub fn read(
        &mut self,
        volume: OpaqueHandle,
        output: &mut [u8; FILESYSTEM_BOOT_SECTOR_BYTES],
    ) -> Result<(), FilesystemBootSectorError<B::Error>> {
        output.fill(0);
        if volume != self.volume {
            return Err(FilesystemBootSectorError::VolumeMismatch);
        }
        self.scratch.fill(0);
        let result = self
            .service
            .read_blocks(self.backend, self.session, self.owner, 0, self.scratch)
            .map_err(FilesystemBootSectorError::Block);
        if result.is_ok() {
            output.copy_from_slice(&self.scratch[..FILESYSTEM_BOOT_SECTOR_BYTES]);
        }
        self.scratch.fill(0);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockDeviceDescriptor, BlockDeviceId, BlockRights};

    const BLOCK_SIZE: usize = 4096;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum BackendError {
        Failed,
        WrongDevice,
    }

    struct Backend {
        device: BlockDeviceId,
        block: [u8; BLOCK_SIZE],
        calls: usize,
        fail: bool,
    }

    unsafe impl BlockServiceBackend for Backend {
        type Error = BackendError;

        fn read_blocks(
            &mut self,
            device: BlockDeviceId,
            block: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            if self.fail {
                return Err(BackendError::Failed);
            }
            if device != self.device || block != 0 || output.len() != BLOCK_SIZE {
                return Err(BackendError::WrongDevice);
            }
            output.copy_from_slice(&self.block);
            self.calls += 1;
            Ok(())
        }

        fn write_blocks(
            &mut self,
            _device: BlockDeviceId,
            _block: u64,
            _input: &[u8],
        ) -> Result<(), Self::Error> {
            unreachable!()
        }

        fn flush(&mut self, _device: BlockDeviceId) -> Result<(), Self::Error> {
            unreachable!()
        }

        fn replace_superblock(
            &mut self,
            _device: BlockDeviceId,
            _block: u64,
            _encoded: &[u8; crate::SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            unreachable!()
        }
    }

    fn owner(value: u64) -> StoragePrincipal {
        StoragePrincipal::new(value).unwrap()
    }

    fn fixture(
        rights: BlockRights,
    ) -> (
        BlockService<1, 1>,
        BlockSessionHandle,
        Backend,
        OpaqueHandle,
    ) {
        let device = BlockDeviceId::new(3).unwrap();
        let mut service = BlockService::new();
        service
            .register_device(
                BlockDeviceDescriptor::new(device, BLOCK_SIZE as u32, 8).unwrap(),
            )
            .unwrap();
        let session = service.grant(device, owner(7), rights).unwrap();
        let mut block = [0; BLOCK_SIZE];
        for (index, byte) in block[..FILESYSTEM_BOOT_SECTOR_BYTES]
            .iter_mut()
            .enumerate()
        {
            *byte = index as u8;
        }
        (
            service,
            session,
            Backend {
                device,
                block,
                calls: 0,
                fail: false,
            },
            OpaqueHandle::new(5, 9).unwrap(),
        )
    }

    #[test]
    fn exact_volume_reads_authorized_block_zero_and_erases_full_scratch() {
        let (service, session, mut backend, volume) = fixture(BlockRights::READ);
        let mut scratch = [0xaa; BLOCK_SIZE];
        let mut output = [0xbb; FILESYSTEM_BOOT_SECTOR_BYTES];
        {
            let mut reader = FilesystemBootSectorReader::new(
                &service,
                &mut backend,
                session,
                owner(7),
                volume,
                &mut scratch,
            )
            .unwrap();
            reader.read(volume, &mut output).unwrap();
        }
        assert_eq!(output[0], 0);
        assert_eq!(output[511], 255);
        assert_eq!(scratch, [0; BLOCK_SIZE]);
        assert_eq!(backend.calls, 1);
    }

    #[test]
    fn mismatch_denial_and_backend_failure_publish_no_sector_bytes() {
        let (service, session, mut backend, volume) = fixture(BlockRights::READ);
        let mut scratch = [0xaa; BLOCK_SIZE];
        let mut output = [0xbb; FILESYSTEM_BOOT_SECTOR_BYTES];
        {
            let mut reader = FilesystemBootSectorReader::new(
                &service,
                &mut backend,
                session,
                owner(7),
                volume,
                &mut scratch,
            )
            .unwrap();
            assert_eq!(
                reader.read(OpaqueHandle::new(6, 9).unwrap(), &mut output),
                Err(FilesystemBootSectorError::VolumeMismatch)
            );
            assert_eq!(output, [0; FILESYSTEM_BOOT_SECTOR_BYTES]);
        }
        assert_eq!(backend.calls, 0);

        let (service, session, mut backend, volume) = fixture(BlockRights::WRITE);
        let mut scratch = [0xaa; BLOCK_SIZE];
        {
            let mut reader = FilesystemBootSectorReader::new(
                &service,
                &mut backend,
                session,
                owner(7),
                volume,
                &mut scratch,
            )
            .unwrap();
            assert_eq!(
                reader.read(volume, &mut output),
                Err(FilesystemBootSectorError::Block(BlockServiceError::Denied))
            );
        }
        assert_eq!(output, [0; FILESYSTEM_BOOT_SECTOR_BYTES]);
        assert_eq!(scratch, [0; BLOCK_SIZE]);
        assert_eq!(backend.calls, 0);

        let (service, session, mut backend, volume) = fixture(BlockRights::READ);
        backend.fail = true;
        let mut scratch = [0xaa; BLOCK_SIZE];
        let mut reader = FilesystemBootSectorReader::new(
            &service,
            &mut backend,
            session,
            owner(7),
            volume,
            &mut scratch,
        )
        .unwrap();
        assert_eq!(
            reader.read(volume, &mut output),
            Err(FilesystemBootSectorError::Block(
                BlockServiceError::Backend(BackendError::Failed)
            ))
        );
        drop(reader);
        assert_eq!(output, [0; FILESYSTEM_BOOT_SECTOR_BYTES]);
        assert_eq!(scratch, [0; BLOCK_SIZE]);
        assert_eq!(backend.calls, 0);
    }
}
