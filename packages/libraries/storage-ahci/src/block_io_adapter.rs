//! Canonical block-provider read/write adaptation for one AHCI provider.
//!
//! This boundary validates the stable interface request and exact device
//! generation before invoking device mechanism. The backend receives only the
//! selected catalog record and the exact borrowed memory extent.

use mrml_interface_storage_block_provider_v1::{
    decode_read_request, decode_write_request, encode_read_response, encode_write_response,
    BlockProviderDevice, BlockProviderReadTransport, BlockProviderWriteTransport, ProtocolError,
    ReadError, WriteError, BLOCK_DEVICE_FLAG_READ_ONLY, READ_REQUEST_BYTES, READ_RESPONSE_BYTES,
    WRITE_REQUEST_BYTES, WRITE_RESPONSE_BYTES,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciBlockIoError {
    PermissionDenied,
    MediaChanged,
    IoFailure,
}

/// Device-mechanism boundary behind the stable block-provider interface.
///
/// Implementations must bind I/O to `device.session` and
/// `device.media_generation`, complete or quarantine all DMA ownership before
/// returning, and never retain the borrowed slice.
pub trait AhciBlockIoBackend {
    fn read(
        &mut self,
        device: BlockProviderDevice,
        lba: u64,
        sector_count: u32,
        output: &mut [u8],
    ) -> Result<(), AhciBlockIoError>;

    fn write(
        &mut self,
        device: BlockProviderDevice,
        lba: u64,
        sector_count: u32,
        input: &[u8],
    ) -> Result<(), AhciBlockIoError>;
}

pub struct AhciBlockIoAdapter<'a, B> {
    devices: &'a [BlockProviderDevice],
    backend: B,
}

impl<'a, B> AhciBlockIoAdapter<'a, B> {
    pub const fn new(devices: &'a [BlockProviderDevice], backend: B) -> Self {
        Self { devices, backend }
    }

    pub fn into_backend(self) -> B {
        self.backend
    }

    fn device(
        &self,
        session: mrml_interface_storage_block_provider_v1::OpaqueHandle,
    ) -> Option<BlockProviderDevice> {
        self.devices
            .iter()
            .copied()
            .find(|device| device.session == session)
    }
}

impl<B: AhciBlockIoBackend> BlockProviderReadTransport for AhciBlockIoAdapter<'_, B> {
    fn read(
        &mut self,
        request: &[u8; READ_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; READ_RESPONSE_BYTES], ProtocolError> {
        let request = decode_read_request(request, memory.len() as u64)?;
        let Some(device) = self.device(request.session) else {
            return Ok(encode_read_response(Err(ReadError::StaleObject)));
        };
        let Some(bytes) = validate_range(device, request.lba, request.sector_count) else {
            return Ok(encode_read_response(Err(ReadError::InvalidRequest)));
        };
        if request.output.length() != bytes {
            return Ok(encode_read_response(Err(ReadError::InvalidRequest)));
        }
        let start =
            usize::try_from(request.output.offset()).map_err(|_| ProtocolError::InvalidRequest)?;
        let length = usize::try_from(bytes).map_err(|_| ProtocolError::InvalidRequest)?;
        let output = memory
            .get_mut(
                start
                    ..start
                        .checked_add(length)
                        .ok_or(ProtocolError::InvalidRequest)?,
            )
            .ok_or(ProtocolError::InvalidRequest)?;
        let result = self
            .backend
            .read(device, request.lba, request.sector_count, output)
            .map(|()| bytes)
            .map_err(map_read_error);
        Ok(encode_read_response(result))
    }
}

impl<B: AhciBlockIoBackend> BlockProviderWriteTransport for AhciBlockIoAdapter<'_, B> {
    fn write(
        &mut self,
        request: &[u8; WRITE_REQUEST_BYTES],
        memory: &[u8],
    ) -> Result<[u8; WRITE_RESPONSE_BYTES], ProtocolError> {
        let request = decode_write_request(request, memory.len() as u64)?;
        let Some(device) = self.device(request.session) else {
            return Ok(encode_write_response(Err(WriteError::StaleObject)));
        };
        if device.flags & BLOCK_DEVICE_FLAG_READ_ONLY != 0 {
            return Ok(encode_write_response(Err(WriteError::ReadOnly)));
        }
        let Some(bytes) = validate_range(device, request.lba, request.sector_count) else {
            return Ok(encode_write_response(Err(WriteError::InvalidRequest)));
        };
        if request.input.length() != bytes {
            return Ok(encode_write_response(Err(WriteError::InvalidRequest)));
        }
        let start =
            usize::try_from(request.input.offset()).map_err(|_| ProtocolError::InvalidRequest)?;
        let length = usize::try_from(bytes).map_err(|_| ProtocolError::InvalidRequest)?;
        let input = memory
            .get(
                start
                    ..start
                        .checked_add(length)
                        .ok_or(ProtocolError::InvalidRequest)?,
            )
            .ok_or(ProtocolError::InvalidRequest)?;
        let result = self
            .backend
            .write(device, request.lba, request.sector_count, input)
            .map(|()| bytes)
            .map_err(map_write_error);
        Ok(encode_write_response(result))
    }
}

fn validate_range(device: BlockProviderDevice, lba: u64, sector_count: u32) -> Option<u64> {
    let count = u64::from(sector_count);
    let end = lba.checked_add(count)?;
    let bytes = count.checked_mul(u64::from(device.logical_block_bytes))?;
    (sector_count != 0 && end <= device.logical_block_count).then_some(bytes)
}

const fn map_read_error(error: AhciBlockIoError) -> ReadError {
    match error {
        AhciBlockIoError::PermissionDenied => ReadError::PermissionDenied,
        AhciBlockIoError::MediaChanged => ReadError::MediaChanged,
        AhciBlockIoError::IoFailure => ReadError::IoFailure,
    }
}

const fn map_write_error(error: AhciBlockIoError) -> WriteError {
    match error {
        AhciBlockIoError::PermissionDenied => WriteError::PermissionDenied,
        AhciBlockIoError::MediaChanged => WriteError::MediaChanged,
        AhciBlockIoError::IoFailure => WriteError::IoFailure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_interface_storage_block_provider_v1::{
        decode_read_response, decode_write_response, encode_read_request, encode_write_request,
        BorrowedReadView, BorrowedWriteView, OpaqueHandle,
    };

    #[derive(Default)]
    struct Backend {
        reads: usize,
        writes: usize,
        seen_generation: u64,
    }

    impl AhciBlockIoBackend for Backend {
        fn read(
            &mut self,
            device: BlockProviderDevice,
            lba: u64,
            count: u32,
            output: &mut [u8],
        ) -> Result<(), AhciBlockIoError> {
            assert_eq!((lba, count, output.len()), (4, 2, 1024));
            self.reads += 1;
            self.seen_generation = device.media_generation;
            output.fill(0x5a);
            Ok(())
        }
        fn write(
            &mut self,
            device: BlockProviderDevice,
            lba: u64,
            count: u32,
            input: &[u8],
        ) -> Result<(), AhciBlockIoError> {
            assert_eq!((lba, count, input.len(), input[0]), (4, 2, 1024, 0xa5));
            self.writes += 1;
            self.seen_generation = device.media_generation;
            Ok(())
        }
    }

    fn device(flags: u32) -> BlockProviderDevice {
        BlockProviderDevice {
            session: OpaqueHandle::new(3, 7).unwrap(),
            logical_block_bytes: 512,
            flags,
            logical_block_count: 100,
            media_generation: 11,
        }
    }

    #[test]
    fn exact_read_and_write_reach_backend_with_media_generation() {
        let devices = [device(0)];
        let mut adapter = AhciBlockIoAdapter::new(&devices, Backend::default());
        let mut memory = [0u8; 1040];
        let read = encode_read_request(
            devices[0].session,
            4,
            2,
            BorrowedWriteView::within(16, 1024, 1040).unwrap(),
        )
        .unwrap();
        let response = adapter.read(&read, &mut memory).unwrap();
        assert_eq!(decode_read_response(&response, 1024), Ok(Ok(1024)));
        assert!(memory[16..].iter().all(|byte| *byte == 0x5a));
        memory[16..].fill(0xa5);
        let write = encode_write_request(
            devices[0].session,
            4,
            2,
            BorrowedReadView::within(16, 1024, 1040).unwrap(),
        )
        .unwrap();
        let response = adapter.write(&write, &memory).unwrap();
        assert_eq!(decode_write_response(&response, 1024), Ok(Ok(1024)));
        let backend = adapter.into_backend();
        assert_eq!(
            (backend.reads, backend.writes, backend.seen_generation),
            (1, 1, 11)
        );
    }

    #[test]
    fn stale_geometry_and_read_only_requests_never_reach_backend() {
        let devices = [device(BLOCK_DEVICE_FLAG_READ_ONLY)];
        let mut adapter = AhciBlockIoAdapter::new(&devices, Backend::default());
        let mut memory = [0u8; 1024];
        let stale = OpaqueHandle::new(3, 8).unwrap();
        let read = encode_read_request(
            stale,
            0,
            2,
            BorrowedWriteView::within(0, 1024, 1024).unwrap(),
        )
        .unwrap();
        assert_eq!(
            decode_read_response(&adapter.read(&read, &mut memory).unwrap(), 1024),
            Ok(Err(ReadError::StaleObject))
        );
        let overrun = encode_read_request(
            devices[0].session,
            99,
            2,
            BorrowedWriteView::within(0, 1024, 1024).unwrap(),
        )
        .unwrap();
        assert_eq!(
            decode_read_response(&adapter.read(&overrun, &mut memory).unwrap(), 1024),
            Ok(Err(ReadError::InvalidRequest))
        );
        let write = encode_write_request(
            devices[0].session,
            4,
            2,
            BorrowedReadView::within(0, 1024, 1024).unwrap(),
        )
        .unwrap();
        assert_eq!(
            decode_write_response(&adapter.write(&write, &memory).unwrap(), 1024),
            Ok(Err(WriteError::ReadOnly))
        );
        let backend = adapter.into_backend();
        assert_eq!((backend.reads, backend.writes), (0, 0));
    }
}
