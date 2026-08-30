#![no_std]

#[path = "../1.rs"]
mod generated;

pub use generated::*;

pub const MAX_FILESYSTEM_TRANSFER_BYTES: u64 = 1024 * 1024;
pub const MAX_FILESYSTEM_REPORT_BYTES: u64 = 64 * 1024;
pub const ABI_CALL_HEADER_BYTES: usize = 72;
pub const PROBE_REQUEST_BYTES: usize = ABI_CALL_HEADER_BYTES + 24;
pub const PROBE_RESPONSE_BYTES: usize = 16;
pub const MOUNT_REQUEST_BYTES: usize = ABI_CALL_HEADER_BYTES + 24;
pub const MOUNT_RESPONSE_BYTES: usize = 16;
pub const UNMOUNT_REQUEST_BYTES: usize = ABI_CALL_HEADER_BYTES + 16;
pub const UNMOUNT_RESPONSE_BYTES: usize = 16;
pub const READ_REQUEST_BYTES: usize = ABI_CALL_HEADER_BYTES + 48;
pub const READ_RESPONSE_BYTES: usize = 16;
pub const WRITE_REQUEST_BYTES: usize = ABI_CALL_HEADER_BYTES + 48;
pub const WRITE_RESPONSE_BYTES: usize = 16;
pub const LOOKUP_REQUEST_BYTES: usize = ABI_CALL_HEADER_BYTES + 40;
pub const LOOKUP_RESPONSE_BYTES: usize = 16;
const ABI_MAGIC: [u8; 8] = *b"MRMLABI\0";
const ABI_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidHeader,
    InvalidRequest,
    InvalidResponse,
    Transport,
}

pub trait FilesystemTransport {
    fn probe(
        &mut self,
        request: &[u8; PROBE_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; PROBE_RESPONSE_BYTES], ProtocolError>;
}

pub trait FilesystemServiceEndpoint {
    fn invoke_probe(
        &mut self,
        endpoint: OpaqueHandle,
        request: &[u8; PROBE_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; PROBE_RESPONSE_BYTES], ProtocolError>;
}

pub trait FilesystemLookupTransport {
    fn lookup(
        &mut self,
        request: &[u8; LOOKUP_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; LOOKUP_RESPONSE_BYTES], ProtocolError>;
}

pub trait FilesystemLookupEndpoint {
    fn invoke_lookup(
        &mut self,
        endpoint: OpaqueHandle,
        request: &[u8; LOOKUP_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; LOOKUP_RESPONSE_BYTES], ProtocolError>;
}

pub trait FilesystemMountTransport {
    fn mount(
        &mut self,
        request: &[u8; MOUNT_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; MOUNT_RESPONSE_BYTES], ProtocolError>;
}

pub trait FilesystemMountEndpoint {
    fn invoke_mount(
        &mut self,
        endpoint: OpaqueHandle,
        request: &[u8; MOUNT_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; MOUNT_RESPONSE_BYTES], ProtocolError>;
}

pub trait FilesystemUnmountTransport {
    fn unmount(
        &mut self,
        request: &[u8; UNMOUNT_REQUEST_BYTES],
    ) -> Result<[u8; UNMOUNT_RESPONSE_BYTES], ProtocolError>;
}

pub trait FilesystemUnmountEndpoint {
    fn invoke_unmount(
        &mut self,
        endpoint: OpaqueHandle,
        request: &[u8; UNMOUNT_REQUEST_BYTES],
    ) -> Result<[u8; UNMOUNT_RESPONSE_BYTES], ProtocolError>;
}

pub trait FilesystemReadTransport {
    fn read(
        &mut self,
        request: &[u8; READ_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; READ_RESPONSE_BYTES], ProtocolError>;
}

pub trait FilesystemReadEndpoint {
    fn invoke_read(
        &mut self,
        endpoint: OpaqueHandle,
        request: &[u8; READ_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; READ_RESPONSE_BYTES], ProtocolError>;
}

pub trait FilesystemWriteTransport {
    fn write(
        &mut self,
        request: &[u8; WRITE_REQUEST_BYTES],
        memory: &[u8],
    ) -> Result<[u8; WRITE_RESPONSE_BYTES], ProtocolError>;
}

pub trait FilesystemWriteEndpoint {
    fn invoke_write(
        &mut self,
        endpoint: OpaqueHandle,
        request: &[u8; WRITE_REQUEST_BYTES],
        memory: &[u8],
    ) -> Result<[u8; WRITE_RESPONSE_BYTES], ProtocolError>;
}

pub struct IsolatedFilesystemTransport<E> {
    endpoint: OpaqueHandle,
    maximum_memory_bytes: usize,
    service: E,
}

impl<E> IsolatedFilesystemTransport<E> {
    pub fn new(
        endpoint: OpaqueHandle,
        maximum_memory_bytes: usize,
        service: E,
    ) -> Result<Self, ProtocolError> {
        let maximum = u64::try_from(maximum_memory_bytes)
            .map_err(|_| ProtocolError::InvalidRequest)?;
        if maximum == 0 || maximum > MAX_FILESYSTEM_TRANSFER_BYTES {
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

impl<E: FilesystemServiceEndpoint> FilesystemTransport for IsolatedFilesystemTransport<E> {
    fn probe(
        &mut self,
        request: &[u8; PROBE_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; PROBE_RESPONSE_BYTES], ProtocolError> {
        if memory.len() > self.maximum_memory_bytes {
            return Err(ProtocolError::InvalidRequest);
        }
        decode_probe_request(request, memory.len() as u64)?;
        self.service.invoke_probe(self.endpoint, request, memory)
    }
}

impl<E: FilesystemLookupEndpoint> FilesystemLookupTransport for IsolatedFilesystemTransport<E> {
    fn lookup(
        &mut self,
        request: &[u8; LOOKUP_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; LOOKUP_RESPONSE_BYTES], ProtocolError> {
        if memory.len() > self.maximum_memory_bytes {
            return Err(ProtocolError::InvalidRequest);
        }
        decode_lookup_request(request, memory.len() as u64)?;
        self.service.invoke_lookup(self.endpoint, request, memory)
    }
}

impl<E: FilesystemMountEndpoint> FilesystemMountTransport for IsolatedFilesystemTransport<E> {
    fn mount(
        &mut self,
        request: &[u8; MOUNT_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; MOUNT_RESPONSE_BYTES], ProtocolError> {
        if memory.len() > self.maximum_memory_bytes {
            return Err(ProtocolError::InvalidRequest);
        }
        decode_mount_request(request, memory.len() as u64)?;
        self.service.invoke_mount(self.endpoint, request, memory)
    }
}

impl<E: FilesystemUnmountEndpoint> FilesystemUnmountTransport for IsolatedFilesystemTransport<E> {
    fn unmount(
        &mut self,
        request: &[u8; UNMOUNT_REQUEST_BYTES],
    ) -> Result<[u8; UNMOUNT_RESPONSE_BYTES], ProtocolError> {
        decode_unmount_request(request)?;
        self.service.invoke_unmount(self.endpoint, request)
    }
}

impl<E: FilesystemReadEndpoint> FilesystemReadTransport for IsolatedFilesystemTransport<E> {
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

impl<E: FilesystemWriteEndpoint> FilesystemWriteTransport for IsolatedFilesystemTransport<E> {
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

pub fn encode_probe_request(
    volume: OpaqueHandle,
    header: BorrowedReadView,
) -> Result<[u8; PROBE_REQUEST_BYTES], ProtocolError> {
    let request = ProbeRequest { volume, header };
    if !request.validate() {
        return Err(ProtocolError::InvalidRequest);
    }
    let mut bytes = [0; PROBE_REQUEST_BYTES];
    bytes[0..8].copy_from_slice(&ABI_MAGIC);
    bytes[8..10].copy_from_slice(&ABI_SCHEMA_VERSION.to_le_bytes());
    bytes[16..48].copy_from_slice(&INTERFACE_FINGERPRINT);
    bytes[48..52].copy_from_slice(&INTERFACE_GENERATION.to_le_bytes());
    bytes[52..56].copy_from_slice(&OP_PROBE.to_le_bytes());
    bytes[56..64].copy_from_slice(&24_u64.to_le_bytes());
    bytes[64..72].copy_from_slice(&(PROBE_RESPONSE_BYTES as u64).to_le_bytes());
    bytes[72..76].copy_from_slice(&volume.index().to_le_bytes());
    bytes[76..80].copy_from_slice(&volume.generation().to_le_bytes());
    bytes[80..88].copy_from_slice(&header.offset().to_le_bytes());
    bytes[88..96].copy_from_slice(&header.length().to_le_bytes());
    Ok(bytes)
}

pub fn decode_probe_request(
    bytes: &[u8; PROBE_REQUEST_BYTES],
    memory_length: u64,
) -> Result<ProbeRequest, ProtocolError> {
    if bytes[0..8] != ABI_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != ABI_SCHEMA_VERSION
        || bytes[10..16] != [0; 6]
        || bytes[16..48] != INTERFACE_FINGERPRINT
        || u32::from_le_bytes(bytes[48..52].try_into().unwrap()) != INTERFACE_GENERATION
        || u32::from_le_bytes(bytes[52..56].try_into().unwrap()) != OP_PROBE
        || u64::from_le_bytes(bytes[56..64].try_into().unwrap()) != 24
        || u64::from_le_bytes(bytes[64..72].try_into().unwrap()) != PROBE_RESPONSE_BYTES as u64
    {
        return Err(ProtocolError::InvalidHeader);
    }
    let volume = OpaqueHandle::new(
        u32::from_le_bytes(bytes[72..76].try_into().unwrap()),
        u32::from_le_bytes(bytes[76..80].try_into().unwrap()),
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let header = BorrowedReadView::within(
        u64::from_le_bytes(bytes[80..88].try_into().unwrap()),
        u64::from_le_bytes(bytes[88..96].try_into().unwrap()),
        memory_length,
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let request = ProbeRequest { volume, header };
    if !request.validate() {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(request)
}

pub fn encode_probe_response(
    result: Result<ProbeResponse, ProbeError>,
) -> [u8; PROBE_RESPONSE_BYTES] {
    let mut bytes = [0; PROBE_RESPONSE_BYTES];
    let (status, confidence) = match result {
        Ok(confidence) => (0, confidence),
        Err(error) => (error as u32, 0),
    };
    bytes[0..4].copy_from_slice(&status.to_le_bytes());
    bytes[8..12].copy_from_slice(&confidence.to_le_bytes());
    bytes
}

pub fn decode_probe_response(
    bytes: &[u8; PROBE_RESPONSE_BYTES],
) -> Result<Result<ProbeResponse, ProbeError>, ProtocolError> {
    if bytes[4..8] != [0; 4] || bytes[12..16] != [0; 4] {
        return Err(ProtocolError::InvalidResponse);
    }
    let status = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let confidence = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    match status {
        0 if confidence <= 100 => Ok(Ok(confidence)),
        1 if confidence == 0 => Ok(Err(ProbeError::InvalidRequest)),
        2 if confidence == 0 => Ok(Err(ProbeError::UnsupportedFilesystem)),
        _ => Err(ProtocolError::InvalidResponse),
    }
}

pub fn encode_mount_request(
    volume: OpaqueHandle,
    options: BorrowedReadView,
) -> Result<[u8; MOUNT_REQUEST_BYTES], ProtocolError> {
    let request = MountRequest { volume, options };
    if !request.validate() {
        return Err(ProtocolError::InvalidRequest);
    }
    let mut bytes = [0; MOUNT_REQUEST_BYTES];
    bytes[0..8].copy_from_slice(&ABI_MAGIC);
    bytes[8..10].copy_from_slice(&ABI_SCHEMA_VERSION.to_le_bytes());
    bytes[16..48].copy_from_slice(&INTERFACE_FINGERPRINT);
    bytes[48..52].copy_from_slice(&INTERFACE_GENERATION.to_le_bytes());
    bytes[52..56].copy_from_slice(&OP_MOUNT.to_le_bytes());
    bytes[56..64].copy_from_slice(&24_u64.to_le_bytes());
    bytes[64..72].copy_from_slice(&(MOUNT_RESPONSE_BYTES as u64).to_le_bytes());
    bytes[72..76].copy_from_slice(&volume.index().to_le_bytes());
    bytes[76..80].copy_from_slice(&volume.generation().to_le_bytes());
    bytes[80..88].copy_from_slice(&options.offset().to_le_bytes());
    bytes[88..96].copy_from_slice(&options.length().to_le_bytes());
    Ok(bytes)
}

pub fn decode_mount_request(
    bytes: &[u8; MOUNT_REQUEST_BYTES],
    memory_length: u64,
) -> Result<MountRequest, ProtocolError> {
    if bytes[0..8] != ABI_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != ABI_SCHEMA_VERSION
        || bytes[10..16] != [0; 6]
        || bytes[16..48] != INTERFACE_FINGERPRINT
        || u32::from_le_bytes(bytes[48..52].try_into().unwrap()) != INTERFACE_GENERATION
        || u32::from_le_bytes(bytes[52..56].try_into().unwrap()) != OP_MOUNT
        || u64::from_le_bytes(bytes[56..64].try_into().unwrap()) != 24
        || u64::from_le_bytes(bytes[64..72].try_into().unwrap()) != MOUNT_RESPONSE_BYTES as u64
    {
        return Err(ProtocolError::InvalidHeader);
    }
    let volume = OpaqueHandle::new(
        u32::from_le_bytes(bytes[72..76].try_into().unwrap()),
        u32::from_le_bytes(bytes[76..80].try_into().unwrap()),
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let options = BorrowedReadView::within(
        u64::from_le_bytes(bytes[80..88].try_into().unwrap()),
        u64::from_le_bytes(bytes[88..96].try_into().unwrap()),
        memory_length,
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let request = MountRequest { volume, options };
    request
        .validate()
        .then_some(request)
        .ok_or(ProtocolError::InvalidRequest)
}

pub fn encode_mount_response(result: Result<MountResponse, MountError>) -> [u8; 16] {
    let mut bytes = [0; MOUNT_RESPONSE_BYTES];
    let (status, generation) = match result {
        Ok(generation) => (0, generation),
        Err(error) => (error as u32, 0),
    };
    bytes[0..4].copy_from_slice(&status.to_le_bytes());
    bytes[8..16].copy_from_slice(&generation.to_le_bytes());
    bytes
}

pub fn decode_mount_response(
    bytes: &[u8; MOUNT_RESPONSE_BYTES],
) -> Result<Result<MountResponse, MountError>, ProtocolError> {
    if bytes[4..8] != [0; 4] {
        return Err(ProtocolError::InvalidResponse);
    }
    let status = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let generation = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    match status {
        0 if generation != 0 => Ok(Ok(generation)),
        1 if generation == 0 => Ok(Err(MountError::InvalidRequest)),
        2 if generation == 0 => Ok(Err(MountError::StaleObject)),
        3 if generation == 0 => Ok(Err(MountError::PermissionDenied)),
        4 if generation == 0 => Ok(Err(MountError::InconsistentFilesystem)),
        _ => Err(ProtocolError::InvalidResponse),
    }
}

pub fn encode_unmount_request(
    volume: OpaqueHandle,
    generation: u64,
) -> Result<[u8; UNMOUNT_REQUEST_BYTES], ProtocolError> {
    let request = UnmountRequest { volume, generation };
    if !request.validate() || generation == 0 {
        return Err(ProtocolError::InvalidRequest);
    }
    let mut bytes = [0; UNMOUNT_REQUEST_BYTES];
    bytes[0..8].copy_from_slice(&ABI_MAGIC);
    bytes[8..10].copy_from_slice(&ABI_SCHEMA_VERSION.to_le_bytes());
    bytes[16..48].copy_from_slice(&INTERFACE_FINGERPRINT);
    bytes[48..52].copy_from_slice(&INTERFACE_GENERATION.to_le_bytes());
    bytes[52..56].copy_from_slice(&OP_UNMOUNT.to_le_bytes());
    bytes[56..64].copy_from_slice(&16_u64.to_le_bytes());
    bytes[64..72].copy_from_slice(&(UNMOUNT_RESPONSE_BYTES as u64).to_le_bytes());
    bytes[72..76].copy_from_slice(&volume.index().to_le_bytes());
    bytes[76..80].copy_from_slice(&volume.generation().to_le_bytes());
    bytes[80..88].copy_from_slice(&generation.to_le_bytes());
    Ok(bytes)
}

pub fn decode_unmount_request(
    bytes: &[u8; UNMOUNT_REQUEST_BYTES],
) -> Result<UnmountRequest, ProtocolError> {
    if bytes[0..8] != ABI_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != ABI_SCHEMA_VERSION
        || bytes[10..16] != [0; 6]
        || bytes[16..48] != INTERFACE_FINGERPRINT
        || u32::from_le_bytes(bytes[48..52].try_into().unwrap()) != INTERFACE_GENERATION
        || u32::from_le_bytes(bytes[52..56].try_into().unwrap()) != OP_UNMOUNT
        || u64::from_le_bytes(bytes[56..64].try_into().unwrap()) != 16
        || u64::from_le_bytes(bytes[64..72].try_into().unwrap()) != UNMOUNT_RESPONSE_BYTES as u64
    {
        return Err(ProtocolError::InvalidHeader);
    }
    let volume = OpaqueHandle::new(
        u32::from_le_bytes(bytes[72..76].try_into().unwrap()),
        u32::from_le_bytes(bytes[76..80].try_into().unwrap()),
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let generation = u64::from_le_bytes(bytes[80..88].try_into().unwrap());
    if generation == 0 {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(UnmountRequest { volume, generation })
}

pub fn encode_unmount_response(result: Result<UnmountResponse, UnmountError>) -> [u8; 16] {
    let mut bytes = [0; UNMOUNT_RESPONSE_BYTES];
    let (status, serial) = match result {
        Ok(serial) => (0, serial),
        Err(error) => (error as u32, 0),
    };
    bytes[0..4].copy_from_slice(&status.to_le_bytes());
    bytes[8..16].copy_from_slice(&serial.to_le_bytes());
    bytes
}

pub fn decode_unmount_response(
    bytes: &[u8; UNMOUNT_RESPONSE_BYTES],
) -> Result<Result<UnmountResponse, UnmountError>, ProtocolError> {
    if bytes[4..8] != [0; 4] {
        return Err(ProtocolError::InvalidResponse);
    }
    let status = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let serial = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    match status {
        0 if serial != 0 => Ok(Ok(serial)),
        1 if serial == 0 => Ok(Err(UnmountError::StaleObject)),
        2 if serial == 0 => Ok(Err(UnmountError::Busy)),
        3 if serial == 0 => Ok(Err(UnmountError::IoFailure)),
        _ => Err(ProtocolError::InvalidResponse),
    }
}

pub fn encode_lookup_request(
    volume: OpaqueHandle,
    generation: u64,
    directory: OpaqueHandle,
    name: BorrowedReadView,
) -> Result<[u8; LOOKUP_REQUEST_BYTES], ProtocolError> {
    let request = LookupRequest {
        volume,
        generation,
        directory,
        name,
    };
    if !request.validate() {
        return Err(ProtocolError::InvalidRequest);
    }
    let mut bytes = [0; LOOKUP_REQUEST_BYTES];
    bytes[0..8].copy_from_slice(&ABI_MAGIC);
    bytes[8..10].copy_from_slice(&ABI_SCHEMA_VERSION.to_le_bytes());
    bytes[16..48].copy_from_slice(&INTERFACE_FINGERPRINT);
    bytes[48..52].copy_from_slice(&INTERFACE_GENERATION.to_le_bytes());
    bytes[52..56].copy_from_slice(&OP_LOOKUP.to_le_bytes());
    bytes[56..64].copy_from_slice(&40_u64.to_le_bytes());
    bytes[64..72].copy_from_slice(&(LOOKUP_RESPONSE_BYTES as u64).to_le_bytes());
    bytes[72..76].copy_from_slice(&volume.index().to_le_bytes());
    bytes[76..80].copy_from_slice(&volume.generation().to_le_bytes());
    bytes[80..88].copy_from_slice(&generation.to_le_bytes());
    bytes[88..92].copy_from_slice(&directory.index().to_le_bytes());
    bytes[92..96].copy_from_slice(&directory.generation().to_le_bytes());
    bytes[96..104].copy_from_slice(&name.offset().to_le_bytes());
    bytes[104..112].copy_from_slice(&name.length().to_le_bytes());
    Ok(bytes)
}

pub fn decode_lookup_request(
    bytes: &[u8; LOOKUP_REQUEST_BYTES],
    memory_length: u64,
) -> Result<LookupRequest, ProtocolError> {
    if bytes[0..8] != ABI_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != ABI_SCHEMA_VERSION
        || bytes[10..16] != [0; 6]
        || bytes[16..48] != INTERFACE_FINGERPRINT
        || u32::from_le_bytes(bytes[48..52].try_into().unwrap()) != INTERFACE_GENERATION
        || u32::from_le_bytes(bytes[52..56].try_into().unwrap()) != OP_LOOKUP
        || u64::from_le_bytes(bytes[56..64].try_into().unwrap()) != 40
        || u64::from_le_bytes(bytes[64..72].try_into().unwrap()) != LOOKUP_RESPONSE_BYTES as u64
    {
        return Err(ProtocolError::InvalidHeader);
    }
    let volume = OpaqueHandle::new(
        u32::from_le_bytes(bytes[72..76].try_into().unwrap()),
        u32::from_le_bytes(bytes[76..80].try_into().unwrap()),
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let generation = u64::from_le_bytes(bytes[80..88].try_into().unwrap());
    let directory = OpaqueHandle::new(
        u32::from_le_bytes(bytes[88..92].try_into().unwrap()),
        u32::from_le_bytes(bytes[92..96].try_into().unwrap()),
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let name = BorrowedReadView::within(
        u64::from_le_bytes(bytes[96..104].try_into().unwrap()),
        u64::from_le_bytes(bytes[104..112].try_into().unwrap()),
        memory_length,
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let request = LookupRequest {
        volume,
        generation,
        directory,
        name,
    };
    request
        .validate()
        .then_some(request)
        .ok_or(ProtocolError::InvalidRequest)
}

pub fn encode_lookup_response(result: Result<LookupResponse, LookupError>) -> [u8; 16] {
    let mut bytes = [0; LOOKUP_RESPONSE_BYTES];
    let (status, object) = match result {
        Ok(object) => (0, object),
        Err(error) => (error as u32, 0),
    };
    bytes[0..4].copy_from_slice(&status.to_le_bytes());
    bytes[8..16].copy_from_slice(&object.to_le_bytes());
    bytes
}

pub fn decode_lookup_response(
    bytes: &[u8; LOOKUP_RESPONSE_BYTES],
) -> Result<Result<LookupResponse, LookupError>, ProtocolError> {
    if bytes[4..8] != [0; 4] {
        return Err(ProtocolError::InvalidResponse);
    }
    let status = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let object = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    match status {
        0 if object != 0 => Ok(Ok(object)),
        1 if object == 0 => Ok(Err(LookupError::InvalidRequest)),
        2 if object == 0 => Ok(Err(LookupError::StaleObject)),
        3 if object == 0 => Ok(Err(LookupError::NotFound)),
        4 if object == 0 => Ok(Err(LookupError::PermissionDenied)),
        _ => Err(ProtocolError::InvalidResponse),
    }
}

pub fn encode_read_request(
    volume: OpaqueHandle,
    generation: u64,
    file: OpaqueHandle,
    offset: u64,
    output: BorrowedWriteView,
) -> Result<[u8; READ_REQUEST_BYTES], ProtocolError> {
    let request = ReadRequest {
        volume,
        generation,
        file,
        offset,
        output,
    };
    if !request.validate()
        || generation == 0
        || output.length() == 0
        || offset.checked_add(output.length()).is_none()
    {
        return Err(ProtocolError::InvalidRequest);
    }
    let mut bytes = [0; READ_REQUEST_BYTES];
    bytes[0..8].copy_from_slice(&ABI_MAGIC);
    bytes[8..10].copy_from_slice(&ABI_SCHEMA_VERSION.to_le_bytes());
    bytes[16..48].copy_from_slice(&INTERFACE_FINGERPRINT);
    bytes[48..52].copy_from_slice(&INTERFACE_GENERATION.to_le_bytes());
    bytes[52..56].copy_from_slice(&OP_READ.to_le_bytes());
    bytes[56..64].copy_from_slice(&48_u64.to_le_bytes());
    bytes[64..72].copy_from_slice(&(READ_RESPONSE_BYTES as u64).to_le_bytes());
    bytes[72..76].copy_from_slice(&volume.index().to_le_bytes());
    bytes[76..80].copy_from_slice(&volume.generation().to_le_bytes());
    bytes[80..88].copy_from_slice(&generation.to_le_bytes());
    bytes[88..92].copy_from_slice(&file.index().to_le_bytes());
    bytes[92..96].copy_from_slice(&file.generation().to_le_bytes());
    bytes[96..104].copy_from_slice(&offset.to_le_bytes());
    bytes[104..112].copy_from_slice(&output.offset().to_le_bytes());
    bytes[112..120].copy_from_slice(&output.length().to_le_bytes());
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
        || u64::from_le_bytes(bytes[56..64].try_into().unwrap()) != 48
        || u64::from_le_bytes(bytes[64..72].try_into().unwrap()) != READ_RESPONSE_BYTES as u64
    {
        return Err(ProtocolError::InvalidHeader);
    }
    let volume = OpaqueHandle::new(
        u32::from_le_bytes(bytes[72..76].try_into().unwrap()),
        u32::from_le_bytes(bytes[76..80].try_into().unwrap()),
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let generation = u64::from_le_bytes(bytes[80..88].try_into().unwrap());
    let file = OpaqueHandle::new(
        u32::from_le_bytes(bytes[88..92].try_into().unwrap()),
        u32::from_le_bytes(bytes[92..96].try_into().unwrap()),
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let offset = u64::from_le_bytes(bytes[96..104].try_into().unwrap());
    let output = BorrowedWriteView::within(
        u64::from_le_bytes(bytes[104..112].try_into().unwrap()),
        u64::from_le_bytes(bytes[112..120].try_into().unwrap()),
        memory_length,
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let request = ReadRequest {
        volume,
        generation,
        file,
        offset,
        output,
    };
    (request.validate()
        && generation != 0
        && output.length() != 0
        && offset.checked_add(output.length()).is_some())
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
        0 if transferred <= output_length && transferred <= MAX_FILESYSTEM_TRANSFER_BYTES => {
            Ok(Ok(transferred))
        }
        1 if transferred == 0 => Ok(Err(ReadError::InvalidRequest)),
        2 if transferred == 0 => Ok(Err(ReadError::StaleObject)),
        3 if transferred == 0 => Ok(Err(ReadError::PermissionDenied)),
        4 if transferred == 0 => Ok(Err(ReadError::IoFailure)),
        _ => Err(ProtocolError::InvalidResponse),
    }
}

pub fn encode_write_request(
    volume: OpaqueHandle,
    generation: u64,
    file: OpaqueHandle,
    offset: u64,
    input: BorrowedReadView,
) -> Result<[u8; WRITE_REQUEST_BYTES], ProtocolError> {
    let request = WriteRequest {
        volume,
        generation,
        file,
        offset,
        input,
    };
    if !request.validate()
        || generation == 0
        || input.length() == 0
        || offset.checked_add(input.length()).is_none()
    {
        return Err(ProtocolError::InvalidRequest);
    }
    let mut bytes = [0; WRITE_REQUEST_BYTES];
    bytes[0..8].copy_from_slice(&ABI_MAGIC);
    bytes[8..10].copy_from_slice(&ABI_SCHEMA_VERSION.to_le_bytes());
    bytes[16..48].copy_from_slice(&INTERFACE_FINGERPRINT);
    bytes[48..52].copy_from_slice(&INTERFACE_GENERATION.to_le_bytes());
    bytes[52..56].copy_from_slice(&OP_WRITE.to_le_bytes());
    bytes[56..64].copy_from_slice(&48_u64.to_le_bytes());
    bytes[64..72].copy_from_slice(&(WRITE_RESPONSE_BYTES as u64).to_le_bytes());
    bytes[72..76].copy_from_slice(&volume.index().to_le_bytes());
    bytes[76..80].copy_from_slice(&volume.generation().to_le_bytes());
    bytes[80..88].copy_from_slice(&generation.to_le_bytes());
    bytes[88..92].copy_from_slice(&file.index().to_le_bytes());
    bytes[92..96].copy_from_slice(&file.generation().to_le_bytes());
    bytes[96..104].copy_from_slice(&offset.to_le_bytes());
    bytes[104..112].copy_from_slice(&input.offset().to_le_bytes());
    bytes[112..120].copy_from_slice(&input.length().to_le_bytes());
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
        || u64::from_le_bytes(bytes[56..64].try_into().unwrap()) != 48
        || u64::from_le_bytes(bytes[64..72].try_into().unwrap()) != WRITE_RESPONSE_BYTES as u64
    {
        return Err(ProtocolError::InvalidHeader);
    }
    let volume = OpaqueHandle::new(
        u32::from_le_bytes(bytes[72..76].try_into().unwrap()),
        u32::from_le_bytes(bytes[76..80].try_into().unwrap()),
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let generation = u64::from_le_bytes(bytes[80..88].try_into().unwrap());
    let file = OpaqueHandle::new(
        u32::from_le_bytes(bytes[88..92].try_into().unwrap()),
        u32::from_le_bytes(bytes[92..96].try_into().unwrap()),
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let offset = u64::from_le_bytes(bytes[96..104].try_into().unwrap());
    let input = BorrowedReadView::within(
        u64::from_le_bytes(bytes[104..112].try_into().unwrap()),
        u64::from_le_bytes(bytes[112..120].try_into().unwrap()),
        memory_length,
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let request = WriteRequest {
        volume,
        generation,
        file,
        offset,
        input,
    };
    (request.validate()
        && generation != 0
        && input.length() != 0
        && offset.checked_add(input.length()).is_some())
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
            && transferred <= MAX_FILESYSTEM_TRANSFER_BYTES =>
        {
            Ok(Ok(transferred))
        }
        1 if transferred == 0 => Ok(Err(WriteError::InvalidRequest)),
        2 if transferred == 0 => Ok(Err(WriteError::StaleObject)),
        3 if transferred == 0 => Ok(Err(WriteError::PermissionDenied)),
        4 if transferred == 0 => Ok(Err(WriteError::ReadOnly)),
        5 if transferred == 0 => Ok(Err(WriteError::NoSpace)),
        6 if transferred == 0 => Ok(Err(WriteError::IoFailure)),
        _ => Err(ProtocolError::InvalidResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_views_and_mount_generations_are_explicit() {
        let volume = OpaqueHandle::new(2, 5).unwrap();
        let file = OpaqueHandle::new(9, 3).unwrap();
        let output = BorrowedWriteView::within(0, MAX_FILESYSTEM_TRANSFER_BYTES, MAX_FILESYSTEM_TRANSFER_BYTES).unwrap();
        assert!(ReadRequest { volume, generation: 11, file, offset: 0, output }.validate());
        let oversized = BorrowedWriteView::within(0, MAX_FILESYSTEM_TRANSFER_BYTES + 1, MAX_FILESYSTEM_TRANSFER_BYTES + 1).unwrap();
        assert!(!ReadRequest { volume, generation: 11, file, offset: 0, output: oversized }.validate());
    }

    struct Endpoint {
        seen: Option<OpaqueHandle>,
    }

    impl FilesystemServiceEndpoint for Endpoint {
        fn invoke_probe(
            &mut self,
            endpoint: OpaqueHandle,
            _request: &[u8; PROBE_REQUEST_BYTES],
            _memory: &mut [u8],
        ) -> Result<[u8; PROBE_RESPONSE_BYTES], ProtocolError> {
            self.seen = Some(endpoint);
            Ok(encode_probe_response(Ok(100)))
        }
    }

    #[test]
    fn canonical_probe_round_trips_through_exact_endpoint_generation() {
        let volume = OpaqueHandle::new(2, 5).unwrap();
        let endpoint = OpaqueHandle::new(7, 11).unwrap();
        let header = BorrowedReadView::within(8, 512, 520).unwrap();
        let request = encode_probe_request(volume, header).unwrap();
        assert_eq!(decode_probe_request(&request, 520).unwrap().volume, volume);
        let service = Endpoint { seen: None };
        let mut transport = IsolatedFilesystemTransport::new(endpoint, 520, service).unwrap();
        assert_eq!(
            decode_probe_response(&transport.probe(&request, &mut [0; 520]).unwrap()),
            Ok(Ok(100))
        );
        assert_eq!(transport.into_service().seen, Some(endpoint));
    }

    #[test]
    fn probe_codec_rejects_stale_headers_ranges_and_responses() {
        let volume = OpaqueHandle::new(2, 5).unwrap();
        let header = BorrowedReadView::within(0, 512, 512).unwrap();
        let mut request = encode_probe_request(volume, header).unwrap();
        request[16] ^= 1;
        assert_eq!(
            decode_probe_request(&request, 512),
            Err(ProtocolError::InvalidHeader)
        );
        request = encode_probe_request(volume, header).unwrap();
        assert_eq!(
            decode_probe_request(&request, 511),
            Err(ProtocolError::InvalidRequest)
        );
        let mut response = encode_probe_response(Ok(100));
        response[8..12].copy_from_slice(&101_u32.to_le_bytes());
        assert_eq!(
            decode_probe_response(&response),
            Err(ProtocolError::InvalidResponse)
        );
    }

    #[test]
    fn lookup_codec_binds_generations_range_and_non_authorizing_identity() {
        let volume = OpaqueHandle::new(2, 5).unwrap();
        let directory = OpaqueHandle::new(9, 3).unwrap();
        let name = BorrowedReadView::within(16, 24, 64).unwrap();
        let request = encode_lookup_request(volume, 11, directory, name).unwrap();
        assert_eq!(
            decode_lookup_request(&request, 64),
            Ok(LookupRequest {
                volume,
                generation: 11,
                directory,
                name,
            })
        );
        assert_eq!(
            decode_lookup_response(&encode_lookup_response(Ok(41))),
            Ok(Ok(41))
        );
        assert_eq!(
            decode_lookup_response(&encode_lookup_response(Err(LookupError::PermissionDenied))),
            Ok(Err(LookupError::PermissionDenied))
        );

        let mut stale = request;
        stale[52..56].copy_from_slice(&OP_READ.to_le_bytes());
        assert_eq!(
            decode_lookup_request(&stale, 64),
            Err(ProtocolError::InvalidHeader)
        );
        assert_eq!(
            decode_lookup_request(&request, 39),
            Err(ProtocolError::InvalidRequest)
        );
        let mut invalid = encode_lookup_response(Ok(41));
        invalid[4] = 1;
        assert_eq!(
            decode_lookup_response(&invalid),
            Err(ProtocolError::InvalidResponse)
        );
        assert_eq!(
            decode_lookup_response(&encode_lookup_response(Ok(0))),
            Err(ProtocolError::InvalidResponse)
        );
    }

    struct LookupEndpoint {
        seen: Option<OpaqueHandle>,
    }

    impl FilesystemLookupEndpoint for LookupEndpoint {
        fn invoke_lookup(
            &mut self,
            endpoint: OpaqueHandle,
            _request: &[u8; LOOKUP_REQUEST_BYTES],
            _memory: &mut [u8],
        ) -> Result<[u8; LOOKUP_RESPONSE_BYTES], ProtocolError> {
            self.seen = Some(endpoint);
            Ok(encode_lookup_response(Ok(41)))
        }
    }

    #[test]
    fn lookup_transport_preserves_endpoint_generation_and_memory_bound() {
        let endpoint = OpaqueHandle::new(7, 11).unwrap();
        let volume = OpaqueHandle::new(2, 5).unwrap();
        let directory = OpaqueHandle::new(9, 3).unwrap();
        let name = BorrowedReadView::within(8, 8, 32).unwrap();
        let request = encode_lookup_request(volume, 12, directory, name).unwrap();
        let service = LookupEndpoint { seen: None };
        let mut transport = IsolatedFilesystemTransport::new(endpoint, 32, service).unwrap();
        assert_eq!(
            decode_lookup_response(&transport.lookup(&request, &mut [0; 32]).unwrap()),
            Ok(Ok(41))
        );
        assert_eq!(transport.service.seen, Some(endpoint));
        assert_eq!(
            transport.lookup(&request, &mut [0; 33]),
            Err(ProtocolError::InvalidRequest)
        );
    }

    struct MountEndpoint {
        seen: Option<OpaqueHandle>,
    }

    impl FilesystemMountEndpoint for MountEndpoint {
        fn invoke_mount(
            &mut self,
            endpoint: OpaqueHandle,
            _request: &[u8; MOUNT_REQUEST_BYTES],
            _memory: &mut [u8],
        ) -> Result<[u8; MOUNT_RESPONSE_BYTES], ProtocolError> {
            self.seen = Some(endpoint);
            Ok(encode_mount_response(Ok(12)))
        }
    }

    #[test]
    fn mount_codec_and_transport_bind_volume_options_and_endpoint_generations() {
        let endpoint = OpaqueHandle::new(7, 11).unwrap();
        let volume = OpaqueHandle::new(2, 5).unwrap();
        let options = BorrowedReadView::within(8, 8, 32).unwrap();
        let request = encode_mount_request(volume, options).unwrap();
        assert_eq!(
            decode_mount_request(&request, 32),
            Ok(MountRequest { volume, options })
        );
        let service = MountEndpoint { seen: None };
        let mut transport = IsolatedFilesystemTransport::new(endpoint, 32, service).unwrap();
        assert_eq!(
            decode_mount_response(&transport.mount(&request, &mut [0; 32]).unwrap()),
            Ok(Ok(12))
        );
        assert_eq!(transport.service.seen, Some(endpoint));
        assert_eq!(
            transport.mount(&request, &mut [0; 33]),
            Err(ProtocolError::InvalidRequest)
        );
        assert_eq!(
            decode_mount_request(&request, 15),
            Err(ProtocolError::InvalidRequest)
        );
        assert_eq!(
            decode_mount_response(&encode_mount_response(Ok(0))),
            Err(ProtocolError::InvalidResponse)
        );
        let mut invalid = encode_mount_response(Err(MountError::PermissionDenied));
        invalid[8] = 1;
        assert_eq!(
            decode_mount_response(&invalid),
            Err(ProtocolError::InvalidResponse)
        );
    }

    struct UnmountEndpoint {
        seen: Option<OpaqueHandle>,
    }

    impl FilesystemUnmountEndpoint for UnmountEndpoint {
        fn invoke_unmount(
            &mut self,
            endpoint: OpaqueHandle,
            _request: &[u8; UNMOUNT_REQUEST_BYTES],
        ) -> Result<[u8; UNMOUNT_RESPONSE_BYTES], ProtocolError> {
            self.seen = Some(endpoint);
            Ok(encode_unmount_response(Ok(13)))
        }
    }

    #[test]
    fn unmount_codec_and_transport_bind_exact_lifecycle_generation() {
        let endpoint = OpaqueHandle::new(7, 11).unwrap();
        let volume = OpaqueHandle::new(2, 5).unwrap();
        let request = encode_unmount_request(volume, 12).unwrap();
        assert_eq!(
            decode_unmount_request(&request),
            Ok(UnmountRequest {
                volume,
                generation: 12,
            })
        );
        let service = UnmountEndpoint { seen: None };
        let mut transport = IsolatedFilesystemTransport::new(endpoint, 32, service).unwrap();
        assert_eq!(
            decode_unmount_response(&transport.unmount(&request).unwrap()),
            Ok(Ok(13))
        );
        assert_eq!(transport.service.seen, Some(endpoint));
        assert_eq!(
            encode_unmount_request(volume, 0),
            Err(ProtocolError::InvalidRequest)
        );
        let mut stale = request;
        stale[52..56].copy_from_slice(&OP_MOUNT.to_le_bytes());
        assert_eq!(
            decode_unmount_request(&stale),
            Err(ProtocolError::InvalidHeader)
        );
        assert_eq!(
            decode_unmount_response(&encode_unmount_response(Ok(0))),
            Err(ProtocolError::InvalidResponse)
        );
        let mut invalid = encode_unmount_response(Err(UnmountError::Busy));
        invalid[8] = 1;
        assert_eq!(
            decode_unmount_response(&invalid),
            Err(ProtocolError::InvalidResponse)
        );
    }

    struct ReadEndpoint {
        seen: Option<OpaqueHandle>,
    }

    impl FilesystemReadEndpoint for ReadEndpoint {
        fn invoke_read(
            &mut self,
            endpoint: OpaqueHandle,
            request: &[u8; READ_REQUEST_BYTES],
            memory: &mut [u8],
        ) -> Result<[u8; READ_RESPONSE_BYTES], ProtocolError> {
            self.seen = Some(endpoint);
            let request = decode_read_request(request, memory.len() as u64)?;
            Ok(encode_read_response(Ok(request.output.length())))
        }
    }

    #[test]
    fn read_codec_and_transport_bind_objects_range_and_bounded_completion() {
        let endpoint = OpaqueHandle::new(7, 11).unwrap();
        let volume = OpaqueHandle::new(2, 5).unwrap();
        let file = OpaqueHandle::new(9, 3).unwrap();
        let output = BorrowedWriteView::within(8, 16, 32).unwrap();
        let request = encode_read_request(volume, 12, file, 40, output).unwrap();
        assert_eq!(
            decode_read_request(&request, 32),
            Ok(ReadRequest {
                volume,
                generation: 12,
                file,
                offset: 40,
                output,
            })
        );
        let service = ReadEndpoint { seen: None };
        let mut transport = IsolatedFilesystemTransport::new(endpoint, 32, service).unwrap();
        assert_eq!(
            decode_read_response(&transport.read(&request, &mut [0; 32]).unwrap(), 16),
            Ok(Ok(16))
        );
        assert_eq!(transport.service.seen, Some(endpoint));
        assert_eq!(
            decode_read_response(&encode_read_response(Ok(0)), 16),
            Ok(Ok(0))
        );
        assert_eq!(
            decode_read_response(&encode_read_response(Ok(17)), 16),
            Err(ProtocolError::InvalidResponse)
        );
        assert_eq!(
            encode_read_request(volume, 12, file, u64::MAX, output),
            Err(ProtocolError::InvalidRequest)
        );
        assert_eq!(
            transport.read(&request, &mut [0; 33]),
            Err(ProtocolError::InvalidRequest)
        );
        let mut invalid = encode_read_response(Err(ReadError::IoFailure));
        invalid[8] = 1;
        assert_eq!(
            decode_read_response(&invalid, 16),
            Err(ProtocolError::InvalidResponse)
        );
    }

    struct WriteEndpoint {
        seen: Option<OpaqueHandle>,
    }

    impl FilesystemWriteEndpoint for WriteEndpoint {
        fn invoke_write(
            &mut self,
            endpoint: OpaqueHandle,
            request: &[u8; WRITE_REQUEST_BYTES],
            memory: &[u8],
        ) -> Result<[u8; WRITE_RESPONSE_BYTES], ProtocolError> {
            self.seen = Some(endpoint);
            let request = decode_write_request(request, memory.len() as u64)?;
            Ok(encode_write_response(Ok(request.input.length())))
        }
    }

    #[test]
    fn write_codec_preserves_read_only_and_bounds_exact_input() {
        let endpoint = OpaqueHandle::new(7, 11).unwrap();
        let volume = OpaqueHandle::new(2, 5).unwrap();
        let file = OpaqueHandle::new(9, 3).unwrap();
        let input = BorrowedReadView::within(8, 16, 32).unwrap();
        let request = encode_write_request(volume, 12, file, 40, input).unwrap();
        assert_eq!(
            decode_write_request(&request, 32),
            Ok(WriteRequest {
                volume,
                generation: 12,
                file,
                offset: 40,
                input,
            })
        );
        let service = WriteEndpoint { seen: None };
        let mut transport = IsolatedFilesystemTransport::new(endpoint, 32, service).unwrap();
        assert_eq!(
            decode_write_response(&transport.write(&request, &[0; 32]).unwrap(), 16),
            Ok(Ok(16))
        );
        assert_eq!(transport.service.seen, Some(endpoint));
        assert_eq!(
            decode_write_response(&encode_write_response(Err(WriteError::ReadOnly)), 16),
            Ok(Err(WriteError::ReadOnly))
        );
        assert_eq!(
            decode_write_response(&encode_write_response(Ok(0)), 16),
            Err(ProtocolError::InvalidResponse)
        );
        assert_eq!(
            decode_write_response(&encode_write_response(Ok(17)), 16),
            Err(ProtocolError::InvalidResponse)
        );
        assert_eq!(
            encode_write_request(volume, 12, file, u64::MAX, input),
            Err(ProtocolError::InvalidRequest)
        );
        assert_eq!(
            transport.write(&request, &[0; 33]),
            Err(ProtocolError::InvalidRequest)
        );
        let mut invalid = encode_write_response(Err(WriteError::NoSpace));
        invalid[8] = 1;
        assert_eq!(
            decode_write_response(&invalid, 16),
            Err(ProtocolError::InvalidResponse)
        );
    }
}
