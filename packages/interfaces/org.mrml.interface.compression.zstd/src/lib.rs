#![no_std]

#[path = "../3.rs"]
mod generated;

pub use generated::*;

pub const ABI_CALL_HEADER_BYTES: usize = 72;
pub const DECOMPRESS_REQUEST_BYTES: usize = ABI_CALL_HEADER_BYTES + 32;
pub const DECOMPRESS_RESPONSE_BYTES: usize = 16;
const ABI_MAGIC: [u8; 8] = *b"MRMLABI\0";
const ABI_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidHeader,
    InvalidRequest,
    InvalidResponse,
    Transport,
}

/// Safe, source-level adapter for exercising the stable byte interface.
///
/// This Rust trait is not an MRML ABI. Implementations receive the canonical
/// generation-3 descriptors below, which are the cross-component contract.
pub trait ZstdTransport {
    fn call(
        &mut self,
        request: &[u8; DECOMPRESS_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; DECOMPRESS_RESPONSE_BYTES], ProtocolError>;
}

pub fn encode_decompress_request(
    input: BorrowedReadView,
    output: BorrowedWriteView,
) -> Result<[u8; DECOMPRESS_REQUEST_BYTES], ProtocolError> {
    let request = DecompressRequest { input, output };
    if !request.validate() {
        return Err(ProtocolError::InvalidRequest);
    }
    let mut bytes = [0_u8; DECOMPRESS_REQUEST_BYTES];
    bytes[0..8].copy_from_slice(&ABI_MAGIC);
    bytes[8..10].copy_from_slice(&ABI_SCHEMA_VERSION.to_le_bytes());
    bytes[16..48].copy_from_slice(&INTERFACE_FINGERPRINT);
    bytes[48..52].copy_from_slice(&INTERFACE_GENERATION.to_le_bytes());
    bytes[52..56].copy_from_slice(&OP_DECOMPRESS.to_le_bytes());
    bytes[56..64].copy_from_slice(&32_u64.to_le_bytes());
    bytes[64..72].copy_from_slice(&(DECOMPRESS_RESPONSE_BYTES as u64).to_le_bytes());
    bytes[72..80].copy_from_slice(&input.offset().to_le_bytes());
    bytes[80..88].copy_from_slice(&input.length().to_le_bytes());
    bytes[88..96].copy_from_slice(&output.offset().to_le_bytes());
    bytes[96..104].copy_from_slice(&output.length().to_le_bytes());
    Ok(bytes)
}

pub fn decode_decompress_request(
    bytes: &[u8; DECOMPRESS_REQUEST_BYTES],
    memory_length: u64,
) -> Result<DecompressRequest, ProtocolError> {
    if bytes[0..8] != ABI_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != ABI_SCHEMA_VERSION
        || bytes[10..16] != [0; 6]
        || bytes[16..48] != INTERFACE_FINGERPRINT
        || u32::from_le_bytes(bytes[48..52].try_into().unwrap()) != INTERFACE_GENERATION
        || u32::from_le_bytes(bytes[52..56].try_into().unwrap()) != OP_DECOMPRESS
        || u64::from_le_bytes(bytes[56..64].try_into().unwrap()) != 32
        || u64::from_le_bytes(bytes[64..72].try_into().unwrap()) != DECOMPRESS_RESPONSE_BYTES as u64
    {
        return Err(ProtocolError::InvalidHeader);
    }
    let input = BorrowedReadView::within(
        u64::from_le_bytes(bytes[72..80].try_into().unwrap()),
        u64::from_le_bytes(bytes[80..88].try_into().unwrap()),
        memory_length,
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let output = BorrowedWriteView::within(
        u64::from_le_bytes(bytes[88..96].try_into().unwrap()),
        u64::from_le_bytes(bytes[96..104].try_into().unwrap()),
        memory_length,
    )
    .ok_or(ProtocolError::InvalidRequest)?;
    let request = DecompressRequest { input, output };
    let input_end = input
        .offset()
        .checked_add(input.length())
        .ok_or(ProtocolError::InvalidRequest)?;
    let output_end = output
        .offset()
        .checked_add(output.length())
        .ok_or(ProtocolError::InvalidRequest)?;
    if !request.validate() || (input.offset() < output_end && output.offset() < input_end) {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(request)
}

pub fn encode_decompress_response(
    result: Result<u64, DecompressError>,
) -> [u8; DECOMPRESS_RESPONSE_BYTES] {
    let mut bytes = [0_u8; DECOMPRESS_RESPONSE_BYTES];
    let (status, written) = match result {
        Ok(written) => (0, written),
        Err(error) => (error as u32, 0),
    };
    bytes[0..4].copy_from_slice(&status.to_le_bytes());
    bytes[8..16].copy_from_slice(&written.to_le_bytes());
    bytes
}

pub fn encode_output_too_small(required: u64) -> [u8; DECOMPRESS_RESPONSE_BYTES] {
    let mut bytes = encode_decompress_response(Err(DecompressError::OutputTooSmall));
    bytes[8..16].copy_from_slice(&required.to_le_bytes());
    bytes
}

pub fn decode_decompress_response(
    bytes: &[u8; DECOMPRESS_RESPONSE_BYTES],
) -> Result<Result<u64, (DecompressError, u64)>, ProtocolError> {
    if bytes[4..8] != [0; 4] {
        return Err(ProtocolError::InvalidResponse);
    }
    let status = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let written = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    match status {
        0 => Ok(Ok(written)),
        1 => Ok(Err((DecompressError::InvalidFrame, written))),
        2 => Ok(Err((DecompressError::OutputTooSmall, written))),
        _ => Err(ProtocolError::InvalidResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_request_round_trips_and_rejects_overlap() {
        let input = BorrowedReadView::within(0, 8, 32).unwrap();
        let output = BorrowedWriteView::within(8, 24, 32).unwrap();
        let request = encode_decompress_request(input, output).unwrap();
        assert_eq!(
            decode_decompress_request(&request, 32)
                .unwrap()
                .output
                .length(),
            24
        );
        let overlap =
            encode_decompress_request(input, BorrowedWriteView::within(4, 8, 32).unwrap()).unwrap();
        assert_eq!(
            decode_decompress_request(&overlap, 32),
            Err(ProtocolError::InvalidRequest)
        );
    }

    #[test]
    fn responses_are_bounded_and_typed() {
        assert_eq!(
            decode_decompress_response(&encode_decompress_response(Ok(17))),
            Ok(Ok(17))
        );
        assert_eq!(
            decode_decompress_response(&encode_output_too_small(4096)),
            Ok(Err((DecompressError::OutputTooSmall, 4096)))
        );
    }
}
