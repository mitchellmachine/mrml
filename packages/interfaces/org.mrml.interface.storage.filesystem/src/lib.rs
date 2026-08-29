#![no_std]

#[path = "../1.rs"]
mod generated;

pub use generated::*;

pub const MAX_FILESYSTEM_TRANSFER_BYTES: u64 = 1024 * 1024;
pub const MAX_FILESYSTEM_REPORT_BYTES: u64 = 64 * 1024;
pub const ABI_CALL_HEADER_BYTES: usize = 72;
pub const PROBE_REQUEST_BYTES: usize = ABI_CALL_HEADER_BYTES + 24;
pub const PROBE_RESPONSE_BYTES: usize = 16;
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
}
