#![no_std]

#[path = "../1.rs"]
mod generated;

pub use generated::*;

pub const MAX_BLOCK_TRANSFER_BYTES: u64 = 1024 * 1024;
pub const MAX_DEVICE_CATALOG_BYTES: u64 = 64 * 1024;
pub const ABI_CALL_HEADER_BYTES: usize = 72;
pub const ENUMERATE_REQUEST_BYTES: usize = ABI_CALL_HEADER_BYTES + 16;
pub const ENUMERATE_RESPONSE_BYTES: usize = 16;
const ABI_MAGIC: [u8; 8] = *b"MRMLABI\0";
const ABI_SCHEMA_VERSION: u16 = 1;

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

pub trait BlockProviderServiceEndpoint {
    fn invoke_enumerate(
        &mut self,
        endpoint: OpaqueHandle,
        request: &[u8; ENUMERATE_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; ENUMERATE_RESPONSE_BYTES], ProtocolError>;
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
        if maximum == 0 || maximum > MAX_DEVICE_CATALOG_BYTES {
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
        || u64::from_le_bytes(bytes[64..72].try_into().unwrap())
            != ENUMERATE_RESPONSE_BYTES as u64
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_and_handles_are_bounded_and_generational() {
        assert!(OpaqueHandle::new(4, 0).is_none());
        let session = OpaqueHandle::new(4, 7).unwrap();
        let output = BorrowedWriteView::within(0, MAX_BLOCK_TRANSFER_BYTES, MAX_BLOCK_TRANSFER_BYTES).unwrap();
        assert!(ReadRequest { session, lba: 9, sector_count: 2048, output }.validate());
        assert!(BorrowedWriteView::within(0, MAX_BLOCK_TRANSFER_BYTES + 1, MAX_BLOCK_TRANSFER_BYTES + 1)
            .is_some_and(|output| !ReadRequest { session, lba: 9, sector_count: 2048, output }.validate()));
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

    #[test]
    fn enumerate_round_trips_through_exact_endpoint_generation() {
        let endpoint = OpaqueHandle::new(7, 11).unwrap();
        let output = BorrowedWriteView::within(8, 512, 520).unwrap();
        let request = encode_enumerate_request(output).unwrap();
        assert_eq!(decode_enumerate_request(&request, 520).unwrap().output, output);
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
}
