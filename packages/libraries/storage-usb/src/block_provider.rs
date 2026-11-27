//! Read-only USB data plane for the canonical block provider protocol.
//! The service runtime must authenticate the sender and bound the writable
//! view before calling this adapter. It does not grant or revoke DMA rights.

use mrml_interface_storage_block_provider_v1::{
    BLOCK_DEVICE_FLAG_READ_ONLY, BlockProviderDevice, BlockProviderReadTransport,
    BlockProviderTransport, ENUMERATE_REQUEST_BYTES, ENUMERATE_RESPONSE_BYTES, EnumerateError,
    OpaqueHandle, ProtocolError, READ_REQUEST_BYTES, READ_RESPONSE_BYTES, ReadError,
    decode_enumerate_request, decode_read_request, encode_block_device_catalog,
    encode_enumerate_response, encode_read_response,
};

use crate::{BulkTransport, SECTOR_BYTES, UsbDisk};

/// One USB disk bound to one non-reusable block session. The caller selects the
/// handle from the service's generational session allocator, not from a request.
pub struct UsbReadProvider<T: BulkTransport> {
    disk: UsbDisk<T>,
    device: BlockProviderDevice,
    available: bool,
}

impl<T: BulkTransport> UsbReadProvider<T> {
    pub fn new(disk: UsbDisk<T>, session: OpaqueHandle, media_generation: u64) -> Option<Self> {
        if media_generation == 0 {
            return None;
        }
        let device = BlockProviderDevice {
            session,
            flags: BLOCK_DEVICE_FLAG_READ_ONLY,
            logical_block_bytes: SECTOR_BYTES as u32,
            logical_block_count: disk.sectors(),
            media_generation,
        };
        Some(Self {
            disk,
            device,
            available: true,
        })
    }

    /// Stop serving this session permanently. Hardware teardown is still
    /// mandatory and is owned by the device lease, not by this adapter.
    pub fn invalidate_session(&mut self) {
        self.available = false;
    }

    /// Recover the transport session for device-lease teardown.
    pub fn into_disk(self) -> UsbDisk<T> {
        self.disk
    }
}

impl<T: BulkTransport> BlockProviderTransport for UsbReadProvider<T> {
    fn enumerate(
        &mut self,
        request: &[u8; ENUMERATE_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; ENUMERATE_RESPONSE_BYTES], ProtocolError> {
        let request = decode_enumerate_request(request, memory.len() as u64)?;
        let devices = if self.available {
            core::slice::from_ref(&self.device)
        } else {
            &[]
        };
        let result = encode_block_device_catalog(devices, request.output, memory)
            .map_err(|_| EnumerateError::InvalidRequest);
        Ok(encode_enumerate_response(result))
    }
}

impl<T: BulkTransport> BlockProviderReadTransport for UsbReadProvider<T> {
    fn read(
        &mut self,
        request: &[u8; READ_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; READ_RESPONSE_BYTES], ProtocolError> {
        let request = decode_read_request(request, memory.len() as u64)?;
        if !self.available || request.session != self.device.session {
            return Ok(encode_read_response(Err(ReadError::StaleObject)));
        }
        // Require the exact sector-sized borrowed view and validate the LBA
        // before any device I/O. Do not implement writes, flushes, or reset.
        if request.sector_count != 1
            || request.output.length() != SECTOR_BYTES as u64
            || request.lba >= self.device.logical_block_count
        {
            return Ok(encode_read_response(Err(ReadError::InvalidRequest)));
        }
        let start =
            usize::try_from(request.output.offset()).map_err(|_| ProtocolError::InvalidRequest)?;
        let end = start
            .checked_add(SECTOR_BYTES)
            .ok_or(ProtocolError::InvalidRequest)?;
        let output = memory
            .get_mut(start..end)
            .ok_or(ProtocolError::InvalidRequest)?;
        let mut sector = [0; SECTOR_BYTES];
        if self.disk.read_sector(request.lba, &mut sector).is_err() {
            // Retire the session on transport failure; the only recovery is
            // a fresh lease and a fresh handle, never a read through stale state.
            self.invalidate_session();
            return Ok(encode_read_response(Err(ReadError::IoFailure)));
        }
        output.copy_from_slice(&sector);
        Ok(encode_read_response(Ok(SECTOR_BYTES as u64)))
    }
}
