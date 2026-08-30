#![no_std]

mod dependency_handoff;

#[path = "../1.rs"]
mod generated;

pub use generated::*;
pub use dependency_handoff::{
    BLOCK_PROVIDER_DEPENDENCY_HANDOFF_BYTES, BlockProviderDependencyHandoff,
    BlockProviderDependencyHandoffError,
};

pub const MAX_BLOCK_TRANSFER_BYTES: u64 = 1024 * 1024;
pub const MAX_DEVICE_CATALOG_BYTES: u64 = 64 * 1024;
pub const ABI_CALL_HEADER_BYTES: usize = 72;
pub const ENUMERATE_REQUEST_BYTES: usize = ABI_CALL_HEADER_BYTES + 16;
pub const ENUMERATE_RESPONSE_BYTES: usize = 16;
pub const READ_REQUEST_BYTES: usize = ABI_CALL_HEADER_BYTES + 40;
pub const READ_RESPONSE_BYTES: usize = 16;
pub const WRITE_REQUEST_BYTES: usize = ABI_CALL_HEADER_BYTES + 40;
pub const WRITE_RESPONSE_BYTES: usize = 16;
pub const FLUSH_REQUEST_BYTES: usize = ABI_CALL_HEADER_BYTES + 8;
pub const FLUSH_RESPONSE_BYTES: usize = 16;
pub const RESET_REQUEST_BYTES: usize = ABI_CALL_HEADER_BYTES + 8;
pub const RESET_RESPONSE_BYTES: usize = 16;
const ABI_MAGIC: [u8; 8] = *b"MRMLABI\0";
const ABI_SCHEMA_VERSION: u16 = 1;
pub const BLOCK_DEVICE_CATALOG_HEADER_BYTES: usize = 16;
pub const BLOCK_DEVICE_CATALOG_RECORD_BYTES: usize = 32;
const BLOCK_DEVICE_CATALOG_MAGIC: [u8; 8] = *b"MRMLBLK\0";
const BLOCK_DEVICE_CATALOG_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockProviderDevice {
    pub session: OpaqueHandle,
    pub logical_block_bytes: u32,
    pub flags: u32,
    pub logical_block_count: u64,
    pub media_generation: u64,
}

pub const BLOCK_DEVICE_FLAG_READ_ONLY: u32 = 1 << 0;
pub const BLOCK_DEVICE_FLAG_FLUSH: u32 = 1 << 1;
pub const BLOCK_DEVICE_FLAG_RESET: u32 = 1 << 2;
const BLOCK_DEVICE_KNOWN_FLAGS: u32 =
    BLOCK_DEVICE_FLAG_READ_ONLY | BLOCK_DEVICE_FLAG_FLUSH | BLOCK_DEVICE_FLAG_RESET;

pub fn encode_block_device_catalog(
    devices: &[BlockProviderDevice],
    output: BorrowedWriteView,
    memory: &mut [u8],
) -> Result<u64, ProtocolError> {
    let count = u32::try_from(devices.len()).map_err(|_| ProtocolError::InvalidRequest)?;
    let records = devices
        .len()
        .checked_mul(BLOCK_DEVICE_CATALOG_RECORD_BYTES)
        .ok_or(ProtocolError::InvalidRequest)?;
    let written = BLOCK_DEVICE_CATALOG_HEADER_BYTES
        .checked_add(records)
        .ok_or(ProtocolError::InvalidRequest)?;
    if written as u64 > output.length() || written as u64 > MAX_DEVICE_CATALOG_BYTES {
        return Err(ProtocolError::InvalidRequest);
    }
    for device in devices {
        if device.logical_block_bytes < 512
            || device.logical_block_bytes > 65_536
            || !device.logical_block_bytes.is_power_of_two()
            || device.flags & !BLOCK_DEVICE_KNOWN_FLAGS != 0
            || device.logical_block_count == 0
            || device.media_generation == 0
        {
            return Err(ProtocolError::InvalidRequest);
        }
    }
    let start = usize::try_from(output.offset()).map_err(|_| ProtocolError::InvalidRequest)?;
    let end = start
        .checked_add(written)
        .ok_or(ProtocolError::InvalidRequest)?;
    let destination = memory
        .get_mut(start..end)
        .ok_or(ProtocolError::InvalidRequest)?;
    destination.fill(0);
    destination[0..8].copy_from_slice(&BLOCK_DEVICE_CATALOG_MAGIC);
    destination[8..10].copy_from_slice(&BLOCK_DEVICE_CATALOG_VERSION.to_le_bytes());
    destination[10..12].copy_from_slice(&(BLOCK_DEVICE_CATALOG_RECORD_BYTES as u16).to_le_bytes());
    destination[12..16].copy_from_slice(&count.to_le_bytes());
    for (index, device) in devices.iter().enumerate() {
        let offset = BLOCK_DEVICE_CATALOG_HEADER_BYTES + index * BLOCK_DEVICE_CATALOG_RECORD_BYTES;
        destination[offset..offset + 4].copy_from_slice(&device.session.index().to_le_bytes());
        destination[offset + 4..offset + 8]
            .copy_from_slice(&device.session.generation().to_le_bytes());
        destination[offset + 8..offset + 12]
            .copy_from_slice(&device.logical_block_bytes.to_le_bytes());
        destination[offset + 12..offset + 16].copy_from_slice(&device.flags.to_le_bytes());
        destination[offset + 16..offset + 24]
            .copy_from_slice(&device.logical_block_count.to_le_bytes());
        destination[offset + 24..offset + 32]
            .copy_from_slice(&device.media_generation.to_le_bytes());
    }
    Ok(written as u64)
}

pub fn validate_block_device_catalog(bytes: &[u8]) -> Result<u32, ProtocolError> {
    if bytes.len() < BLOCK_DEVICE_CATALOG_HEADER_BYTES
        || bytes.len() > MAX_DEVICE_CATALOG_BYTES as usize
        || bytes[0..8] != BLOCK_DEVICE_CATALOG_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != BLOCK_DEVICE_CATALOG_VERSION
        || u16::from_le_bytes(bytes[10..12].try_into().unwrap())
            != BLOCK_DEVICE_CATALOG_RECORD_BYTES as u16
    {
        return Err(ProtocolError::InvalidResponse);
    }
    let count = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let records = usize::try_from(count)
        .map_err(|_| ProtocolError::InvalidResponse)?
        .checked_mul(BLOCK_DEVICE_CATALOG_RECORD_BYTES)
        .ok_or(ProtocolError::InvalidResponse)?;
    let expected = BLOCK_DEVICE_CATALOG_HEADER_BYTES
        .checked_add(records)
        .ok_or(ProtocolError::InvalidResponse)?;
    if bytes.len() != expected {
        return Err(ProtocolError::InvalidResponse);
    }
    for index in 0..count {
        decode_catalog_record_after_header(bytes, index)?;
    }
    Ok(count)
}

pub fn decode_block_device_catalog_record(
    bytes: &[u8],
    index: u32,
) -> Result<BlockProviderDevice, ProtocolError> {
    let count = validate_catalog_header_and_length(bytes)?;
    if index >= count {
        return Err(ProtocolError::InvalidRequest);
    }
    decode_catalog_record_after_header(bytes, index)
}

fn decode_catalog_record_after_header(
    bytes: &[u8],
    index: u32,
) -> Result<BlockProviderDevice, ProtocolError> {
    let offset = BLOCK_DEVICE_CATALOG_HEADER_BYTES
        + usize::try_from(index).map_err(|_| ProtocolError::InvalidRequest)?
            * BLOCK_DEVICE_CATALOG_RECORD_BYTES;
    let session = OpaqueHandle::new(
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
        u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()),
    )
    .ok_or(ProtocolError::InvalidResponse)?;
    let device = BlockProviderDevice {
        session,
        logical_block_bytes: u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()),
        flags: u32::from_le_bytes(bytes[offset + 12..offset + 16].try_into().unwrap()),
        logical_block_count: u64::from_le_bytes(
            bytes[offset + 16..offset + 24].try_into().unwrap(),
        ),
        media_generation: u64::from_le_bytes(bytes[offset + 24..offset + 32].try_into().unwrap()),
    };
    if device.logical_block_bytes < 512
        || device.logical_block_bytes > 65_536
        || !device.logical_block_bytes.is_power_of_two()
        || device.flags & !BLOCK_DEVICE_KNOWN_FLAGS != 0
        || device.logical_block_count == 0
        || device.media_generation == 0
    {
        return Err(ProtocolError::InvalidResponse);
    }
    Ok(device)
}

fn validate_catalog_header_and_length(bytes: &[u8]) -> Result<u32, ProtocolError> {
    if bytes.len() < BLOCK_DEVICE_CATALOG_HEADER_BYTES
        || bytes.len() > MAX_DEVICE_CATALOG_BYTES as usize
        || bytes[0..8] != BLOCK_DEVICE_CATALOG_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != BLOCK_DEVICE_CATALOG_VERSION
        || u16::from_le_bytes(bytes[10..12].try_into().unwrap())
            != BLOCK_DEVICE_CATALOG_RECORD_BYTES as u16
    {
        return Err(ProtocolError::InvalidResponse);
    }
    let count = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let expected = BLOCK_DEVICE_CATALOG_HEADER_BYTES
        .checked_add(
            usize::try_from(count)
                .map_err(|_| ProtocolError::InvalidResponse)?
                .checked_mul(BLOCK_DEVICE_CATALOG_RECORD_BYTES)
                .ok_or(ProtocolError::InvalidResponse)?,
        )
        .ok_or(ProtocolError::InvalidResponse)?;
    (bytes.len() == expected)
        .then_some(count)
        .ok_or(ProtocolError::InvalidResponse)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidHeader,
    InvalidRequest,
    InvalidResponse,
    Transport,
}

pub trait BlockProviderTransport {
    fn enumerate(
        &mut self,
        request: &[u8; ENUMERATE_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; ENUMERATE_RESPONSE_BYTES], ProtocolError>;
}

pub trait BlockProviderReadTransport {
    fn read(
        &mut self,
        request: &[u8; READ_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; READ_RESPONSE_BYTES], ProtocolError>;
}

pub trait BlockProviderWriteTransport {
    fn write(
        &mut self,
        request: &[u8; WRITE_REQUEST_BYTES],
        memory: &[u8],
    ) -> Result<[u8; WRITE_RESPONSE_BYTES], ProtocolError>;
}

pub trait BlockProviderControlTransport {
    fn flush(
        &mut self,
        request: &[u8; FLUSH_REQUEST_BYTES],
    ) -> Result<[u8; FLUSH_RESPONSE_BYTES], ProtocolError>;
    fn reset(
        &mut self,
        request: &[u8; RESET_REQUEST_BYTES],
    ) -> Result<[u8; RESET_RESPONSE_BYTES], ProtocolError>;
}

pub trait BlockProviderServiceEndpoint {
    fn invoke_enumerate(
        &mut self,
        endpoint: OpaqueHandle,
        request: &[u8; ENUMERATE_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; ENUMERATE_RESPONSE_BYTES], ProtocolError>;
}

pub trait BlockProviderReadServiceEndpoint {
    fn invoke_read(
        &mut self,
        endpoint: OpaqueHandle,
        request: &[u8; READ_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; READ_RESPONSE_BYTES], ProtocolError>;
}

pub trait BlockProviderWriteServiceEndpoint {
    fn invoke_write(
        &mut self,
        endpoint: OpaqueHandle,
        request: &[u8; WRITE_REQUEST_BYTES],
        memory: &[u8],
    ) -> Result<[u8; WRITE_RESPONSE_BYTES], ProtocolError>;
}

pub trait BlockProviderControlServiceEndpoint {
    fn invoke_flush(
        &mut self,
        endpoint: OpaqueHandle,
        request: &[u8; FLUSH_REQUEST_BYTES],
    ) -> Result<[u8; FLUSH_RESPONSE_BYTES], ProtocolError>;
    fn invoke_reset(
        &mut self,
        endpoint: OpaqueHandle,
        request: &[u8; RESET_REQUEST_BYTES],
    ) -> Result<[u8; RESET_RESPONSE_BYTES], ProtocolError>;
}

pub struct IsolatedBlockProviderTransport<E> {
    endpoint: OpaqueHandle,
    maximum_memory_bytes: usize,
    service: E,
}

impl<E> IsolatedBlockProviderTransport<E> {
    pub fn new(
        endpoint: OpaqueHandle,
        maximum_memory_bytes: usize,
        service: E,
    ) -> Result<Self, ProtocolError> {
        let maximum =
            u64::try_from(maximum_memory_bytes).map_err(|_| ProtocolError::InvalidRequest)?;
        if maximum == 0 || maximum > MAX_BLOCK_TRANSFER_BYTES {
            return Err(ProtocolError::InvalidRequest);
        }
        Ok(Self {
            endpoint,
            maximum_memory_bytes,
            service,
        })
    }

    pub const fn endpoint(&self) -> OpaqueHandle {
        self.endpoint
    }

    pub fn into_service(self) -> E {
        self.service
    }
}

impl<E: BlockProviderServiceEndpoint> BlockProviderTransport for IsolatedBlockProviderTransport<E> {
    fn enumerate(
        &mut self,
        request: &[u8; ENUMERATE_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; ENUMERATE_RESPONSE_BYTES], ProtocolError> {
        if memory.len() > self.maximum_memory_bytes {
            return Err(ProtocolError::InvalidRequest);
        }
        decode_enumerate_request(request, memory.len() as u64)?;
        self.service
            .invoke_enumerate(self.endpoint, request, memory)
    }
}

impl<E: BlockProviderReadServiceEndpoint> BlockProviderReadTransport
    for IsolatedBlockProviderTransport<E>
{
    fn read(
        &mut self,
        request: &[u8; READ_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; READ_RESPONSE_BYTES], ProtocolError> {
        if memory.len() > self.maximum_memory_bytes {
            return Err(ProtocolError::InvalidRequest);
        }
        decode_read_request(request, memory.len() as u64)?;
        self.service.invoke_read(self.endpoint, request, memory)
    }
}

impl<E: BlockProviderWriteServiceEndpoint> BlockProviderWriteTransport
    for IsolatedBlockProviderTransport<E>
{
    fn write(
        &mut self,
        request: &[u8; WRITE_REQUEST_BYTES],
        memory: &[u8],
    ) -> Result<[u8; WRITE_RESPONSE_BYTES], ProtocolError> {
        if memory.len() > self.maximum_memory_bytes {
            return Err(ProtocolError::InvalidRequest);
        }
        decode_write_request(request, memory.len() as u64)?;
        self.service.invoke_write(self.endpoint, request, memory)
    }
}

impl<E: BlockProviderControlServiceEndpoint> BlockProviderControlTransport
    for IsolatedBlockProviderTransport<E>
{
    fn flush(
        &mut self,
        request: &[u8; FLUSH_REQUEST_BYTES],
    ) -> Result<[u8; FLUSH_RESPONSE_BYTES], ProtocolError> {
        decode_flush_request(request)?;
        self.service.invoke_flush(self.endpoint, request)
    }

    fn reset(
        &mut self,
        request: &[u8; RESET_REQUEST_BYTES],
    ) -> Result<[u8; RESET_RESPONSE_BYTES], ProtocolError> {
        decode_reset_request(request)?;
        self.service.invoke_reset(self.endpoint, request)
    }
}

pub fn encode_enumerate_request(
    output: BorrowedWriteView,
) -> Result<[u8; ENUMERATE_REQUEST_BYTES], ProtocolError> {
    let request = EnumerateRequest { output };
    if !request.validate() {
        return Err(ProtocolError::InvalidRequest);
    }
    let mut bytes = [0; ENUMERATE_REQUEST_BYTES];
    bytes[0..8].copy_from_slice(&ABI_MAGIC);
    bytes[8..10].copy_from_slice(&ABI_SCHEMA_VERSION.to_le_bytes());
    bytes[16..48].copy_from_slice(&INTERFACE_FINGERPRINT);
    bytes[48..52].copy_from_slice(&INTERFACE_GENERATION.to_le_bytes());
    bytes[52..56].copy_from_slice(&OP_ENUMERATE.to_le_bytes());
    bytes[56..64].copy_from_slice(&16_u64.to_le_bytes());
    bytes[64..72].copy_from_slice(&(ENUMERATE_RESPONSE_BYTES as u64).to_le_bytes());
    bytes[72..80].copy_from_slice(&output.offset().to_le_bytes());
    bytes[80..88].copy_from_slice(&output.length().to_le_bytes());
    Ok(bytes)
}

pub fn decode_enumerate_request(
    bytes: &[u8; ENUMERATE_REQUEST_BYTES],
    memory_length: u64,
) -> Result<EnumerateRequest, ProtocolError> {
    if bytes[0..8] != ABI_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != ABI_SCHEMA_VERSION
        || bytes[10..16] != [0; 6]
        || bytes[16..48] != INTERFACE_FINGERPRINT
        || u32::from_le_bytes(bytes[48..52].try_into().unwrap()) != INTERFACE_GENERATION
        || u32::from_le_bytes(bytes[52..56].try_into().unwrap()) != OP_ENUMERATE
        || u64::from_le_bytes(bytes[56..64].try_into().unwrap()) != 16
        || u64::from_le_bytes(bytes[64..72].try_into().unwrap()) != ENUMERATE_RESPONSE_BYTES as u64
    {
        return Err(ProtocolError::InvalidHeader);
    }
    let output = BorrowedWriteView::within(
        u64::from_le_bytes(bytes[72..80].try_into().unwrap()),
        u64::from_le_bytes(bytes[80..88].try_into().unwrap()),
        memory_length,
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let request = EnumerateRequest { output };
    request
        .validate()
        .then_some(request)
        .ok_or(ProtocolError::InvalidRequest)
}

pub fn encode_enumerate_response(
    result: Result<EnumerateResponse, EnumerateError>,
) -> [u8; ENUMERATE_RESPONSE_BYTES] {
    let mut bytes = [0; ENUMERATE_RESPONSE_BYTES];
    let (status, written) = match result {
        Ok(written) => (0, written),
        Err(error) => (error as u32, 0),
    };
    bytes[0..4].copy_from_slice(&status.to_le_bytes());
    bytes[8..16].copy_from_slice(&written.to_le_bytes());
    bytes
}

pub fn decode_enumerate_response(
    bytes: &[u8; ENUMERATE_RESPONSE_BYTES],
    output_length: u64,
) -> Result<Result<EnumerateResponse, EnumerateError>, ProtocolError> {
    if bytes[4..8] != [0; 4] {
        return Err(ProtocolError::InvalidResponse);
    }
    let status = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let written = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    match status {
        0 if written <= output_length && written <= MAX_DEVICE_CATALOG_BYTES => Ok(Ok(written)),
        1 if written == 0 => Ok(Err(EnumerateError::InvalidRequest)),
        2 if written == 0 => Ok(Err(EnumerateError::ResourceUnavailable)),
        _ => Err(ProtocolError::InvalidResponse),
    }
}

pub fn encode_read_request(
    session: OpaqueHandle,
    lba: u64,
    sector_count: u32,
    output: BorrowedWriteView,
) -> Result<[u8; READ_REQUEST_BYTES], ProtocolError> {
    let request = ReadRequest {
        session,
        lba,
        sector_count,
        output,
    };
    if !request.validate() || sector_count == 0 || output.length() == 0 {
        return Err(ProtocolError::InvalidRequest);
    }
    let mut bytes = [0; READ_REQUEST_BYTES];
    bytes[0..8].copy_from_slice(&ABI_MAGIC);
    bytes[8..10].copy_from_slice(&ABI_SCHEMA_VERSION.to_le_bytes());
    bytes[16..48].copy_from_slice(&INTERFACE_FINGERPRINT);
    bytes[48..52].copy_from_slice(&INTERFACE_GENERATION.to_le_bytes());
    bytes[52..56].copy_from_slice(&OP_READ.to_le_bytes());
    bytes[56..64].copy_from_slice(&40_u64.to_le_bytes());
    bytes[64..72].copy_from_slice(&(READ_RESPONSE_BYTES as u64).to_le_bytes());
    bytes[72..76].copy_from_slice(&session.index().to_le_bytes());
    bytes[76..80].copy_from_slice(&session.generation().to_le_bytes());
    bytes[80..88].copy_from_slice(&lba.to_le_bytes());
    bytes[88..92].copy_from_slice(&sector_count.to_le_bytes());
    bytes[96..104].copy_from_slice(&output.offset().to_le_bytes());
    bytes[104..112].copy_from_slice(&output.length().to_le_bytes());
    Ok(bytes)
}

pub fn decode_read_request(
    bytes: &[u8; READ_REQUEST_BYTES],
    memory_length: u64,
) -> Result<ReadRequest, ProtocolError> {
    if bytes[0..8] != ABI_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != ABI_SCHEMA_VERSION
        || bytes[10..16] != [0; 6]
        || bytes[16..48] != INTERFACE_FINGERPRINT
        || u32::from_le_bytes(bytes[48..52].try_into().unwrap()) != INTERFACE_GENERATION
        || u32::from_le_bytes(bytes[52..56].try_into().unwrap()) != OP_READ
        || u64::from_le_bytes(bytes[56..64].try_into().unwrap()) != 40
        || u64::from_le_bytes(bytes[64..72].try_into().unwrap()) != READ_RESPONSE_BYTES as u64
        || bytes[92..96] != [0; 4]
    {
        return Err(ProtocolError::InvalidHeader);
    }
    let session = OpaqueHandle::new(
        u32::from_le_bytes(bytes[72..76].try_into().unwrap()),
        u32::from_le_bytes(bytes[76..80].try_into().unwrap()),
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let output = BorrowedWriteView::within(
        u64::from_le_bytes(bytes[96..104].try_into().unwrap()),
        u64::from_le_bytes(bytes[104..112].try_into().unwrap()),
        memory_length,
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let request = ReadRequest {
        session,
        lba: u64::from_le_bytes(bytes[80..88].try_into().unwrap()),
        sector_count: u32::from_le_bytes(bytes[88..92].try_into().unwrap()),
        output,
    };
    (request.validate() && request.sector_count != 0 && request.output.length() != 0)
        .then_some(request)
        .ok_or(ProtocolError::InvalidRequest)
}

pub fn encode_read_response(result: Result<ReadResponse, ReadError>) -> [u8; READ_RESPONSE_BYTES] {
    let mut bytes = [0; READ_RESPONSE_BYTES];
    let (status, transferred) = match result {
        Ok(transferred) => (0, transferred),
        Err(error) => (error as u32, 0),
    };
    bytes[0..4].copy_from_slice(&status.to_le_bytes());
    bytes[8..16].copy_from_slice(&transferred.to_le_bytes());
    bytes
}

pub fn decode_read_response(
    bytes: &[u8; READ_RESPONSE_BYTES],
    output_length: u64,
) -> Result<Result<ReadResponse, ReadError>, ProtocolError> {
    if bytes[4..8] != [0; 4] {
        return Err(ProtocolError::InvalidResponse);
    }
    let status = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let transferred = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    match status {
        0 if transferred != 0
            && transferred <= output_length
            && transferred <= MAX_BLOCK_TRANSFER_BYTES =>
        {
            Ok(Ok(transferred))
        }
        1 if transferred == 0 => Ok(Err(ReadError::InvalidRequest)),
        2 if transferred == 0 => Ok(Err(ReadError::StaleObject)),
        3 if transferred == 0 => Ok(Err(ReadError::PermissionDenied)),
        4 if transferred == 0 => Ok(Err(ReadError::MediaChanged)),
        5 if transferred == 0 => Ok(Err(ReadError::IoFailure)),
        _ => Err(ProtocolError::InvalidResponse),
    }
}

pub fn encode_write_request(
    session: OpaqueHandle,
    lba: u64,
    sector_count: u32,
    input: BorrowedReadView,
) -> Result<[u8; WRITE_REQUEST_BYTES], ProtocolError> {
    let request = WriteRequest {
        session,
        lba,
        sector_count,
        input,
    };
    if !request.validate() || sector_count == 0 || input.length() == 0 {
        return Err(ProtocolError::InvalidRequest);
    }
    let mut bytes = [0; WRITE_REQUEST_BYTES];
    bytes[0..8].copy_from_slice(&ABI_MAGIC);
    bytes[8..10].copy_from_slice(&ABI_SCHEMA_VERSION.to_le_bytes());
    bytes[16..48].copy_from_slice(&INTERFACE_FINGERPRINT);
    bytes[48..52].copy_from_slice(&INTERFACE_GENERATION.to_le_bytes());
    bytes[52..56].copy_from_slice(&OP_WRITE.to_le_bytes());
    bytes[56..64].copy_from_slice(&40_u64.to_le_bytes());
    bytes[64..72].copy_from_slice(&(WRITE_RESPONSE_BYTES as u64).to_le_bytes());
    bytes[72..76].copy_from_slice(&session.index().to_le_bytes());
    bytes[76..80].copy_from_slice(&session.generation().to_le_bytes());
    bytes[80..88].copy_from_slice(&lba.to_le_bytes());
    bytes[88..92].copy_from_slice(&sector_count.to_le_bytes());
    bytes[96..104].copy_from_slice(&input.offset().to_le_bytes());
    bytes[104..112].copy_from_slice(&input.length().to_le_bytes());
    Ok(bytes)
}

pub fn decode_write_request(
    bytes: &[u8; WRITE_REQUEST_BYTES],
    memory_length: u64,
) -> Result<WriteRequest, ProtocolError> {
    if bytes[0..8] != ABI_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != ABI_SCHEMA_VERSION
        || bytes[10..16] != [0; 6]
        || bytes[16..48] != INTERFACE_FINGERPRINT
        || u32::from_le_bytes(bytes[48..52].try_into().unwrap()) != INTERFACE_GENERATION
        || u32::from_le_bytes(bytes[52..56].try_into().unwrap()) != OP_WRITE
        || u64::from_le_bytes(bytes[56..64].try_into().unwrap()) != 40
        || u64::from_le_bytes(bytes[64..72].try_into().unwrap()) != WRITE_RESPONSE_BYTES as u64
        || bytes[92..96] != [0; 4]
    {
        return Err(ProtocolError::InvalidHeader);
    }
    let session = OpaqueHandle::new(
        u32::from_le_bytes(bytes[72..76].try_into().unwrap()),
        u32::from_le_bytes(bytes[76..80].try_into().unwrap()),
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let input = BorrowedReadView::within(
        u64::from_le_bytes(bytes[96..104].try_into().unwrap()),
        u64::from_le_bytes(bytes[104..112].try_into().unwrap()),
        memory_length,
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let request = WriteRequest {
        session,
        lba: u64::from_le_bytes(bytes[80..88].try_into().unwrap()),
        sector_count: u32::from_le_bytes(bytes[88..92].try_into().unwrap()),
        input,
    };
    (request.validate() && request.sector_count != 0 && request.input.length() != 0)
        .then_some(request)
        .ok_or(ProtocolError::InvalidRequest)
}

pub fn encode_write_response(
    result: Result<WriteResponse, WriteError>,
) -> [u8; WRITE_RESPONSE_BYTES] {
    let mut bytes = [0; WRITE_RESPONSE_BYTES];
    let (status, transferred) = match result {
        Ok(transferred) => (0, transferred),
        Err(error) => (error as u32, 0),
    };
    bytes[0..4].copy_from_slice(&status.to_le_bytes());
    bytes[8..16].copy_from_slice(&transferred.to_le_bytes());
    bytes
}

pub fn decode_write_response(
    bytes: &[u8; WRITE_RESPONSE_BYTES],
    input_length: u64,
) -> Result<Result<WriteResponse, WriteError>, ProtocolError> {
    if bytes[4..8] != [0; 4] {
        return Err(ProtocolError::InvalidResponse);
    }
    let status = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let transferred = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    match status {
        0 if transferred != 0
            && transferred <= input_length
            && transferred <= MAX_BLOCK_TRANSFER_BYTES =>
        {
            Ok(Ok(transferred))
        }
        1 if transferred == 0 => Ok(Err(WriteError::InvalidRequest)),
        2 if transferred == 0 => Ok(Err(WriteError::StaleObject)),
        3 if transferred == 0 => Ok(Err(WriteError::PermissionDenied)),
        4 if transferred == 0 => Ok(Err(WriteError::MediaChanged)),
        5 if transferred == 0 => Ok(Err(WriteError::ReadOnly)),
        6 if transferred == 0 => Ok(Err(WriteError::IoFailure)),
        _ => Err(ProtocolError::InvalidResponse),
    }
}

fn encode_control_request(session: OpaqueHandle, operation: u32) -> [u8; FLUSH_REQUEST_BYTES] {
    let mut bytes = [0; FLUSH_REQUEST_BYTES];
    bytes[0..8].copy_from_slice(&ABI_MAGIC);
    bytes[8..10].copy_from_slice(&ABI_SCHEMA_VERSION.to_le_bytes());
    bytes[16..48].copy_from_slice(&INTERFACE_FINGERPRINT);
    bytes[48..52].copy_from_slice(&INTERFACE_GENERATION.to_le_bytes());
    bytes[52..56].copy_from_slice(&operation.to_le_bytes());
    bytes[56..64].copy_from_slice(&8_u64.to_le_bytes());
    bytes[64..72].copy_from_slice(&16_u64.to_le_bytes());
    bytes[72..76].copy_from_slice(&session.index().to_le_bytes());
    bytes[76..80].copy_from_slice(&session.generation().to_le_bytes());
    bytes
}

fn decode_control_request(
    bytes: &[u8; FLUSH_REQUEST_BYTES],
    operation: u32,
) -> Result<OpaqueHandle, ProtocolError> {
    if bytes[0..8] != ABI_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != ABI_SCHEMA_VERSION
        || bytes[10..16] != [0; 6]
        || bytes[16..48] != INTERFACE_FINGERPRINT
        || u32::from_le_bytes(bytes[48..52].try_into().unwrap()) != INTERFACE_GENERATION
        || u32::from_le_bytes(bytes[52..56].try_into().unwrap()) != operation
        || u64::from_le_bytes(bytes[56..64].try_into().unwrap()) != 8
        || u64::from_le_bytes(bytes[64..72].try_into().unwrap()) != 16
    {
        return Err(ProtocolError::InvalidHeader);
    }
    OpaqueHandle::new(
        u32::from_le_bytes(bytes[72..76].try_into().unwrap()),
        u32::from_le_bytes(bytes[76..80].try_into().unwrap()),
    )
    .ok_or(ProtocolError::InvalidRequest)
}

pub fn encode_flush_request(session: OpaqueHandle) -> [u8; FLUSH_REQUEST_BYTES] {
    encode_control_request(session, OP_FLUSH)
}

pub fn decode_flush_request(
    bytes: &[u8; FLUSH_REQUEST_BYTES],
) -> Result<FlushRequest, ProtocolError> {
    Ok(FlushRequest {
        session: decode_control_request(bytes, OP_FLUSH)?,
    })
}

pub fn encode_flush_response(
    result: Result<FlushResponse, FlushError>,
) -> [u8; FLUSH_RESPONSE_BYTES] {
    let mut bytes = [0; FLUSH_RESPONSE_BYTES];
    let (status, serial) = match result {
        Ok(serial) => (0, serial),
        Err(error) => (error as u32, 0),
    };
    bytes[0..4].copy_from_slice(&status.to_le_bytes());
    bytes[8..16].copy_from_slice(&serial.to_le_bytes());
    bytes
}

pub fn decode_flush_response(
    bytes: &[u8; FLUSH_RESPONSE_BYTES],
) -> Result<Result<FlushResponse, FlushError>, ProtocolError> {
    if bytes[4..8] != [0; 4] {
        return Err(ProtocolError::InvalidResponse);
    }
    let status = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let serial = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    match status {
        0 if serial != 0 => Ok(Ok(serial)),
        1 if serial == 0 => Ok(Err(FlushError::StaleObject)),
        2 if serial == 0 => Ok(Err(FlushError::PermissionDenied)),
        3 if serial == 0 => Ok(Err(FlushError::IoFailure)),
        _ => Err(ProtocolError::InvalidResponse),
    }
}

pub fn encode_reset_request(session: OpaqueHandle) -> [u8; RESET_REQUEST_BYTES] {
    encode_control_request(session, OP_RESET)
}

pub fn decode_reset_request(
    bytes: &[u8; RESET_REQUEST_BYTES],
) -> Result<ResetRequest, ProtocolError> {
    Ok(ResetRequest {
        session: decode_control_request(bytes, OP_RESET)?,
    })
}

pub fn encode_reset_response(
    result: Result<ResetResponse, ResetError>,
) -> [u8; RESET_RESPONSE_BYTES] {
    let mut bytes = [0; RESET_RESPONSE_BYTES];
    let (status, generation) = match result {
        Ok(generation) => (0, generation),
        Err(error) => (error as u32, 0),
    };
    bytes[0..4].copy_from_slice(&status.to_le_bytes());
    bytes[8..16].copy_from_slice(&generation.to_le_bytes());
    bytes
}

pub fn decode_reset_response(
    bytes: &[u8; RESET_RESPONSE_BYTES],
) -> Result<Result<ResetResponse, ResetError>, ProtocolError> {
    if bytes[4..8] != [0; 4] {
        return Err(ProtocolError::InvalidResponse);
    }
    let status = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let generation = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    match status {
        0 if generation != 0 => Ok(Ok(generation)),
        1 if generation == 0 => Ok(Err(ResetError::StaleObject)),
        2 if generation == 0 => Ok(Err(ResetError::PermissionDenied)),
        3 if generation == 0 => Ok(Err(ResetError::CleanupIncomplete)),
        _ => Err(ProtocolError::InvalidResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_and_handles_are_bounded_and_generational() {
        assert!(OpaqueHandle::new(4, 0).is_none());
        let session = OpaqueHandle::new(4, 7).unwrap();
        let output =
            BorrowedWriteView::within(0, MAX_BLOCK_TRANSFER_BYTES, MAX_BLOCK_TRANSFER_BYTES)
                .unwrap();
        assert!(ReadRequest {
            session,
            lba: 9,
            sector_count: 2048,
            output
        }
        .validate());
        assert!(BorrowedWriteView::within(
            0,
            MAX_BLOCK_TRANSFER_BYTES + 1,
            MAX_BLOCK_TRANSFER_BYTES + 1
        )
        .is_some_and(|output| !ReadRequest {
            session,
            lba: 9,
            sector_count: 2048,
            output
        }
        .validate()));
    }

    struct Endpoint {
        seen: Option<OpaqueHandle>,
    }

    impl BlockProviderServiceEndpoint for Endpoint {
        fn invoke_enumerate(
            &mut self,
            endpoint: OpaqueHandle,
            request: &[u8; ENUMERATE_REQUEST_BYTES],
            memory: &mut [u8],
        ) -> Result<[u8; ENUMERATE_RESPONSE_BYTES], ProtocolError> {
            self.seen = Some(endpoint);
            let request = decode_enumerate_request(request, memory.len() as u64)?;
            Ok(encode_enumerate_response(Ok(request.output.length())))
        }
    }

    impl BlockProviderReadServiceEndpoint for Endpoint {
        fn invoke_read(
            &mut self,
            endpoint: OpaqueHandle,
            request: &[u8; READ_REQUEST_BYTES],
            memory: &mut [u8],
        ) -> Result<[u8; READ_RESPONSE_BYTES], ProtocolError> {
            self.seen = Some(endpoint);
            let request = decode_read_request(request, memory.len() as u64)?;
            let start = usize::try_from(request.output.offset())
                .map_err(|_| ProtocolError::InvalidRequest)?;
            let end = start
                .checked_add(
                    usize::try_from(request.output.length())
                        .map_err(|_| ProtocolError::InvalidRequest)?,
                )
                .ok_or(ProtocolError::InvalidRequest)?;
            memory
                .get_mut(start..end)
                .ok_or(ProtocolError::InvalidRequest)?
                .fill(0x5a);
            Ok(encode_read_response(Ok(request.output.length())))
        }
    }

    impl BlockProviderWriteServiceEndpoint for Endpoint {
        fn invoke_write(
            &mut self,
            endpoint: OpaqueHandle,
            request: &[u8; WRITE_REQUEST_BYTES],
            memory: &[u8],
        ) -> Result<[u8; WRITE_RESPONSE_BYTES], ProtocolError> {
            self.seen = Some(endpoint);
            let request = decode_write_request(request, memory.len() as u64)?;
            let start = usize::try_from(request.input.offset())
                .map_err(|_| ProtocolError::InvalidRequest)?;
            let end = start
                .checked_add(
                    usize::try_from(request.input.length())
                        .map_err(|_| ProtocolError::InvalidRequest)?,
                )
                .ok_or(ProtocolError::InvalidRequest)?;
            if !memory
                .get(start..end)
                .ok_or(ProtocolError::InvalidRequest)?
                .iter()
                .all(|byte| *byte == 0x3c)
            {
                return Err(ProtocolError::Transport);
            }
            Ok(encode_write_response(Ok(request.input.length())))
        }
    }

    impl BlockProviderControlServiceEndpoint for Endpoint {
        fn invoke_flush(
            &mut self,
            endpoint: OpaqueHandle,
            request: &[u8; FLUSH_REQUEST_BYTES],
        ) -> Result<[u8; FLUSH_RESPONSE_BYTES], ProtocolError> {
            self.seen = Some(endpoint);
            let request = decode_flush_request(request)?;
            Ok(encode_flush_response(Ok(u64::from(
                request.session.generation(),
            ))))
        }

        fn invoke_reset(
            &mut self,
            endpoint: OpaqueHandle,
            request: &[u8; RESET_REQUEST_BYTES],
        ) -> Result<[u8; RESET_RESPONSE_BYTES], ProtocolError> {
            self.seen = Some(endpoint);
            let request = decode_reset_request(request)?;
            Ok(encode_reset_response(Ok(u64::from(
                request.session.generation(),
            ) + 1)))
        }
    }

    #[test]
    fn enumerate_round_trips_through_exact_endpoint_generation() {
        let endpoint = OpaqueHandle::new(7, 11).unwrap();
        let output = BorrowedWriteView::within(8, 512, 520).unwrap();
        let request = encode_enumerate_request(output).unwrap();
        assert_eq!(
            decode_enumerate_request(&request, 520).unwrap().output,
            output
        );
        let service = Endpoint { seen: None };
        let mut transport = IsolatedBlockProviderTransport::new(endpoint, 520, service).unwrap();
        assert_eq!(
            decode_enumerate_response(
                &transport.enumerate(&request, &mut [0; 520]).unwrap(),
                output.length(),
            ),
            Ok(Ok(512))
        );
        assert_eq!(transport.into_service().seen, Some(endpoint));
    }

    #[test]
    fn enumerate_codec_rejects_stale_headers_ranges_and_responses() {
        let output = BorrowedWriteView::within(0, 512, 512).unwrap();
        let mut request = encode_enumerate_request(output).unwrap();
        request[16] ^= 1;
        assert_eq!(
            decode_enumerate_request(&request, 512),
            Err(ProtocolError::InvalidHeader)
        );
        request = encode_enumerate_request(output).unwrap();
        assert_eq!(
            decode_enumerate_request(&request, 511),
            Err(ProtocolError::InvalidRequest)
        );
        let response = encode_enumerate_response(Ok(513));
        assert_eq!(
            decode_enumerate_response(&response, 512),
            Err(ProtocolError::InvalidResponse)
        );
    }

    #[test]
    fn canonical_catalog_is_bounded_zeroed_and_generational() {
        let devices = [BlockProviderDevice {
            session: OpaqueHandle::new(3, 7).unwrap(),
            logical_block_bytes: 4096,
            flags: BLOCK_DEVICE_FLAG_FLUSH | BLOCK_DEVICE_FLAG_RESET,
            logical_block_count: 128,
            media_generation: 9,
        }];
        let output = BorrowedWriteView::within(8, 48, 56).unwrap();
        let mut memory = [0xa5; 56];
        assert_eq!(
            encode_block_device_catalog(&devices, output, &mut memory),
            Ok(48)
        );
        assert_eq!(&memory[8..16], b"MRMLBLK\0");
        assert_eq!(u32::from_le_bytes(memory[20..24].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(memory[24..28].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(memory[28..32].try_into().unwrap()), 7);
        assert_eq!(u64::from_le_bytes(memory[48..56].try_into().unwrap()), 9);
        let catalog = &memory[8..56];
        assert_eq!(validate_block_device_catalog(catalog), Ok(1));
        assert_eq!(
            decode_block_device_catalog_record(catalog, 0),
            Ok(devices[0])
        );
        assert_eq!(
            decode_block_device_catalog_record(catalog, 1),
            Err(ProtocolError::InvalidRequest)
        );
    }

    #[test]
    fn catalog_decoder_rejects_truncation_counts_flags_and_stale_handles() {
        let devices = [BlockProviderDevice {
            session: OpaqueHandle::new(3, 7).unwrap(),
            logical_block_bytes: 4096,
            flags: BLOCK_DEVICE_FLAG_FLUSH,
            logical_block_count: 128,
            media_generation: 9,
        }];
        let output = BorrowedWriteView::within(0, 48, 48).unwrap();
        let mut catalog = [0; 48];
        encode_block_device_catalog(&devices, output, &mut catalog).unwrap();
        assert_eq!(
            validate_block_device_catalog(&catalog[..47]),
            Err(ProtocolError::InvalidResponse)
        );
        let mut hostile = catalog;
        hostile[12..16].copy_from_slice(&2_u32.to_le_bytes());
        assert_eq!(
            validate_block_device_catalog(&hostile),
            Err(ProtocolError::InvalidResponse)
        );
        hostile = catalog;
        hostile[20..24].fill(0);
        assert_eq!(
            validate_block_device_catalog(&hostile),
            Err(ProtocolError::InvalidResponse)
        );
        hostile = catalog;
        hostile[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            validate_block_device_catalog(&hostile),
            Err(ProtocolError::InvalidResponse)
        );
    }

    #[test]
    fn read_round_trips_through_exact_endpoint_and_borrowed_output() {
        let endpoint = OpaqueHandle::new(9, 13).unwrap();
        let session = OpaqueHandle::new(4, 7).unwrap();
        let output = BorrowedWriteView::within(16, 1024, 1040).unwrap();
        let request = encode_read_request(session, 33, 2, output).unwrap();
        assert_eq!(
            decode_read_request(&request, 1040).unwrap().session,
            session
        );
        let service = Endpoint { seen: None };
        let mut transport = IsolatedBlockProviderTransport::new(endpoint, 1040, service).unwrap();
        let mut memory = [0; 1040];
        let response = transport.read(&request, &mut memory).unwrap();
        assert_eq!(decode_read_response(&response, 1024), Ok(Ok(1024)));
        assert!(memory[16..1040].iter().all(|byte| *byte == 0x5a));
        assert_eq!(transport.into_service().seen, Some(endpoint));
    }

    #[test]
    fn read_codec_rejects_zero_reserved_stale_and_excess_results() {
        let session = OpaqueHandle::new(4, 7).unwrap();
        let output = BorrowedWriteView::within(0, 512, 512).unwrap();
        assert_eq!(
            encode_read_request(session, 0, 0, output),
            Err(ProtocolError::InvalidRequest)
        );
        let mut request = encode_read_request(session, 0, 1, output).unwrap();
        request[92] = 1;
        assert_eq!(
            decode_read_request(&request, 512),
            Err(ProtocolError::InvalidHeader)
        );
        request = encode_read_request(session, 0, 1, output).unwrap();
        assert_eq!(
            decode_read_request(&request, 511),
            Err(ProtocolError::InvalidRequest)
        );
        assert_eq!(
            decode_read_response(&encode_read_response(Ok(513)), 512),
            Err(ProtocolError::InvalidResponse)
        );
        assert_eq!(
            decode_read_response(&encode_read_response(Err(ReadError::StaleObject)), 512),
            Ok(Err(ReadError::StaleObject))
        );
    }

    #[test]
    fn write_round_trips_without_granting_provider_memory_mutation() {
        let endpoint = OpaqueHandle::new(9, 14).unwrap();
        let session = OpaqueHandle::new(5, 8).unwrap();
        let input = BorrowedReadView::within(16, 1024, 1040).unwrap();
        let request = encode_write_request(session, 44, 2, input).unwrap();
        assert_eq!(
            decode_write_request(&request, 1040).unwrap().session,
            session
        );
        let service = Endpoint { seen: None };
        let mut transport = IsolatedBlockProviderTransport::new(endpoint, 1040, service).unwrap();
        let mut memory = [0; 1040];
        memory[16..].fill(0x3c);
        let response = transport.write(&request, &memory).unwrap();
        assert_eq!(decode_write_response(&response, 1024), Ok(Ok(1024)));
        assert_eq!(transport.into_service().seen, Some(endpoint));
    }

    #[test]
    fn write_codec_rejects_zero_reserved_stale_and_excess_results() {
        let session = OpaqueHandle::new(5, 8).unwrap();
        let input = BorrowedReadView::within(0, 512, 512).unwrap();
        assert_eq!(
            encode_write_request(session, 0, 0, input),
            Err(ProtocolError::InvalidRequest)
        );
        let mut request = encode_write_request(session, 0, 1, input).unwrap();
        request[92] = 1;
        assert_eq!(
            decode_write_request(&request, 512),
            Err(ProtocolError::InvalidHeader)
        );
        request = encode_write_request(session, 0, 1, input).unwrap();
        assert_eq!(
            decode_write_request(&request, 511),
            Err(ProtocolError::InvalidRequest)
        );
        assert_eq!(
            decode_write_response(&encode_write_response(Ok(513)), 512),
            Err(ProtocolError::InvalidResponse)
        );
        assert_eq!(
            decode_write_response(&encode_write_response(Err(WriteError::ReadOnly)), 512),
            Ok(Err(WriteError::ReadOnly))
        );
    }

    #[test]
    fn flush_and_reset_route_separately_through_exact_endpoint() {
        let endpoint = OpaqueHandle::new(9, 15).unwrap();
        let session = OpaqueHandle::new(6, 10).unwrap();
        let service = Endpoint { seen: None };
        let mut transport = IsolatedBlockProviderTransport::new(endpoint, 4096, service).unwrap();
        let flush = transport.flush(&encode_flush_request(session)).unwrap();
        assert_eq!(decode_flush_response(&flush), Ok(Ok(10)));
        let reset = transport.reset(&encode_reset_request(session)).unwrap();
        assert_eq!(decode_reset_response(&reset), Ok(Ok(11)));
        assert_eq!(transport.into_service().seen, Some(endpoint));
    }

    #[test]
    fn control_codecs_reject_cross_operation_stale_and_zero_success() {
        let session = OpaqueHandle::new(6, 10).unwrap();
        let flush = encode_flush_request(session);
        assert_eq!(
            decode_reset_request(&flush),
            Err(ProtocolError::InvalidHeader)
        );
        let mut reset = encode_reset_request(session);
        reset[16] ^= 1;
        assert_eq!(
            decode_reset_request(&reset),
            Err(ProtocolError::InvalidHeader)
        );
        assert_eq!(
            decode_flush_response(&encode_flush_response(Ok(0))),
            Err(ProtocolError::InvalidResponse)
        );
        assert_eq!(
            decode_reset_response(&encode_reset_response(Err(ResetError::CleanupIncomplete))),
            Ok(Err(ResetError::CleanupIncomplete))
        );
    }
}
