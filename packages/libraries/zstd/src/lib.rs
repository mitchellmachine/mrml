#![no_std]

#[cfg(any(windows, unix))]
mod bits;
#[cfg(any(windows, unix))]
mod fse;
#[cfg(any(windows, unix))]
mod huffman;
mod kernel_transport;
#[cfg(any(windows, unix))]
mod sequences;
mod service_loop;
mod task_runtime_adapter;
mod userspace_syscall_adapter;

use core::fmt;
use mrml_interface_zstd_v3::{
    decode_decompress_request, encode_decompress_response, encode_output_too_small,
    DecompressError, ProtocolError, ZstdTransport, DECOMPRESS_REQUEST_BYTES,
    DECOMPRESS_RESPONSE_BYTES,
};
#[cfg(any(windows, unix))]
use mrml_runtime::Vector;

pub use kernel_transport::{ZstdKernelTransport, ZstdKernelTransportError};
pub use service_loop::{
    ReceivedZstdEnvelope, ZstdServiceLoop, ZstdServiceLoopError, ZstdServiceSyscalls,
};
pub use task_runtime_adapter::{
    ZstdAdmittedTaskRuntimeEndpoint, ZstdNativeServiceBackend, ZstdNativeServiceEndpoint,
    ZstdNativeServiceError, ZstdResolvedServiceBinding, ZstdServiceBindingError,
    ZstdTaskRuntimeAdapter, ZstdTaskRuntimeAdapterError, ZstdTaskRuntimeEndpoint,
};
pub use userspace_syscall_adapter::{
    ZstdRawSyscall, ZstdSyscallFrame, ZstdUserspaceSyscallError, ZstdUserspaceSyscalls,
};

pub const FRAME_MAGIC: u32 = 0xfd2f_b528;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    Truncated,
    InvalidMagic(u32),
    ReservedHeaderBit,
    DictionaryRequired(u32),
    ReservedBlock,
    UnsupportedCompressedBlock,
    InvalidLiteralsSection,
    InvalidSequencesSection,
    ContentSizeMismatch,
    TrailingData,
    Allocation,
    InvalidBitstream,
    InvalidFseTable,
    InvalidFseState,
    InvalidHuffmanTree,
    InvalidHuffmanStream,
    HuffmanSymbolTruncated(u8, usize),
    InvalidOffset,
    BlockTooLarge,
    InputTooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => output.write_str("truncated Zstandard frame"),
            Self::InvalidMagic(magic) => write!(output, "invalid Zstandard magic 0x{magic:08x}"),
            Self::ReservedHeaderBit => output.write_str("reserved Zstandard frame bit is set"),
            Self::DictionaryRequired(id) => write!(output, "Zstandard dictionary {id} is required"),
            Self::ReservedBlock => output.write_str("reserved Zstandard block type"),
            Self::UnsupportedCompressedBlock => {
                output.write_str("compressed Zstandard blocks are not implemented yet")
            }
            Self::InvalidLiteralsSection => output.write_str("invalid Zstandard literals section"),
            Self::InvalidSequencesSection => {
                output.write_str("invalid Zstandard sequences section")
            }
            Self::ContentSizeMismatch => {
                output.write_str("Zstandard content size does not match decoded data")
            }
            Self::TrailingData => output.write_str("trailing data after Zstandard frame"),
            Self::Allocation => output.write_str("not enough memory for Zstandard output"),
            Self::InvalidBitstream => output.write_str("invalid Zstandard reverse bitstream"),
            Self::InvalidFseTable => output.write_str("invalid Zstandard FSE table"),
            Self::InvalidFseState => output.write_str("invalid Zstandard FSE state"),
            Self::InvalidHuffmanTree => output.write_str("invalid Zstandard Huffman tree"),
            Self::InvalidHuffmanStream => output.write_str("invalid Zstandard Huffman stream"),
            Self::HuffmanSymbolTruncated(bits, remaining) => write!(
                output,
                "Zstandard Huffman symbol needs {bits} bits with {remaining} remaining"
            ),
            Self::InvalidOffset => output.write_str("invalid Zstandard match offset"),
            Self::BlockTooLarge => output.write_str("Zstandard block exceeds 128 KiB"),
            Self::InputTooLarge => output.write_str("Zstandard HTTP input exceeds 8 MiB"),
        }
    }
}

impl core::error::Error for Error {}
pub type Result<T> = core::result::Result<T, Error>;

/// Canonical in-process provider for
/// `org.mrml.interface.compression.zstd@3`.
///
/// The resolver supplies the immutable provider generation. This value carries
/// no authority and does not perform path or filename lookup.
#[derive(Default)]
pub struct ComponentProvider;

impl ZstdTransport for ComponentProvider {
    fn call(
        &mut self,
        request_bytes: &[u8; DECOMPRESS_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> core::result::Result<[u8; DECOMPRESS_RESPONSE_BYTES], ProtocolError> {
        let request = decode_decompress_request(request_bytes, memory.len() as u64)?;
        let input_start =
            usize::try_from(request.input.offset()).map_err(|_| ProtocolError::InvalidRequest)?;
        let input_end = usize::try_from(
            request
                .input
                .offset()
                .checked_add(request.input.length())
                .ok_or(ProtocolError::InvalidRequest)?,
        )
        .map_err(|_| ProtocolError::InvalidRequest)?;
        let output_start =
            usize::try_from(request.output.offset()).map_err(|_| ProtocolError::InvalidRequest)?;
        let output_capacity =
            usize::try_from(request.output.length()).map_err(|_| ProtocolError::InvalidRequest)?;
        #[cfg(any(windows, unix))]
        {
            let decoded = match decode(&memory[input_start..input_end]) {
                Ok(decoded) => decoded,
                Err(_) => {
                    return Ok(encode_decompress_response(Err(
                        DecompressError::InvalidFrame,
                    )));
                }
            };
            if decoded.len() > output_capacity {
                return Ok(encode_output_too_small(decoded.len() as u64));
            }
            let output_end = output_start
                .checked_add(decoded.len())
                .ok_or(ProtocolError::InvalidRequest)?;
            memory[output_start..output_end].copy_from_slice(&decoded);
            Ok(encode_decompress_response(Ok(decoded.len() as u64)))
        }
        #[cfg(not(any(windows, unix)))]
        {
            let output_limit = output_start
                .checked_add(output_capacity)
                .ok_or(ProtocolError::InvalidRequest)?;
            if output_limit > memory.len() {
                return Err(ProtocolError::InvalidRequest);
            }
            let decoded = if input_end <= output_start {
                let (input_memory, output_memory) = memory.split_at_mut(output_start);
                decode_into(
                    &input_memory[input_start..input_end],
                    &mut output_memory[..output_capacity],
                )
            } else if output_limit <= input_start {
                let (output_memory, input_memory) = memory.split_at_mut(input_start);
                decode_into(
                    &input_memory[..input_end - input_start],
                    &mut output_memory[output_start..output_limit],
                )
            } else {
                return Err(ProtocolError::InvalidRequest);
            };
            match decoded {
                Ok(written) => Ok(encode_decompress_response(Ok(written as u64))),
                Err(DecodeIntoError::OutputTooSmall(required)) => {
                    Ok(encode_output_too_small(required))
                }
                Err(DecodeIntoError::Frame(_)) => Ok(encode_decompress_response(Err(
                    DecompressError::InvalidFrame,
                ))),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FrameInfo {
    pub header_bytes: usize,
    pub window_size: u64,
    pub content_size: Option<u64>,
    pub checksum: bool,
}

pub const HTTP_MAX_WINDOW: usize = 8 * 1024 * 1024;
const MAX_BLOCK: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpEncodingProfile {
    /// Deterministic standards-conformant raw/RLE blocks. This profile is a
    /// bounded cache representation floor, not a level-22 equivalence claim.
    BoundedRawRleV1,
    /// Deterministic bounded RFC 8878 software encoding with raw, RLE, and
    /// predefined-FSE compressed block candidates selected by exact size.
    BoundedRfc8878V2,
}

/// Encode one deterministic Zstandard frame suitable for precomputed HTTP
/// content coding. The frame carries an exact content size, no dictionary, no
/// checksum, and never advertises a window above 8 MiB.
#[cfg(any(windows, unix))]
pub fn encode_http(input: &[u8], profile: HttpEncodingProfile) -> Result<Vector<u8>> {
    if input.len() > HTTP_MAX_WINDOW {
        return Err(Error::InputTooLarge);
    }
    let mut output = Vector::new();
    output
        .try_extend_from_slice(&FRAME_MAGIC.to_le_bytes())
        .map_err(|_| Error::Allocation)?;
    let size = input.len() as u64;
    if size < 256 {
        output.try_push(0x20).map_err(|_| Error::Allocation)?;
        output.try_push(size as u8).map_err(|_| Error::Allocation)?;
    } else if size < 65_792 {
        output.try_push(0x60).map_err(|_| Error::Allocation)?;
        output
            .try_extend_from_slice(&((size - 256) as u16).to_le_bytes())
            .map_err(|_| Error::Allocation)?;
    } else if size <= u32::MAX as u64 {
        output.try_push(0xa0).map_err(|_| Error::Allocation)?;
        output
            .try_extend_from_slice(&(size as u32).to_le_bytes())
            .map_err(|_| Error::Allocation)?;
    } else {
        output.try_push(0xe0).map_err(|_| Error::Allocation)?;
        output
            .try_extend_from_slice(&size.to_le_bytes())
            .map_err(|_| Error::Allocation)?;
    }

    if input.is_empty() {
        output
            .try_extend_from_slice(&[1, 0, 0])
            .map_err(|_| Error::Allocation)?;
        return Ok(output);
    }
    let mut sequence_state = sequences::EncoderState::new();
    for (index, block) in input.chunks(MAX_BLOCK).enumerate() {
        let last = (index + 1) * MAX_BLOCK >= input.len();
        let rle = block.iter().all(|byte| *byte == block[0]);
        let compressed = if profile == HttpEncodingProfile::BoundedRfc8878V2 && !rle {
            encode_compressed_candidate(block, &mut sequence_state)?
        } else {
            None
        };
        let block_type = if rle {
            1
        } else if compressed.is_some() {
            2
        } else {
            0
        };
        let payload_size = compressed.as_ref().map_or(block.len(), Vector::len);
        let header = ((payload_size as u32) << 3) | (block_type << 1) | last as u32;
        output
            .try_extend_from_slice(&[header as u8, (header >> 8) as u8, (header >> 16) as u8])
            .map_err(|_| Error::Allocation)?;
        if let Some(compressed) = compressed {
            output
                .try_extend_from_slice(&compressed)
                .map_err(|_| Error::Allocation)?;
        } else if rle {
            output.try_push(block[0]).map_err(|_| Error::Allocation)?;
        } else {
            output
                .try_extend_from_slice(block)
                .map_err(|_| Error::Allocation)?;
        }
    }
    Ok(output)
}

#[cfg(any(windows, unix))]
fn encode_compressed_candidate(
    block: &[u8],
    sequence_state: &mut sequences::EncoderState,
) -> Result<Option<Vector<u8>>> {
    const HASH_BITS: usize = 16;
    const HASH_SIZE: usize = 1 << HASH_BITS;
    const EMPTY: u32 = u32::MAX;
    let mut positions = Vector::with_capacity(HASH_SIZE).map_err(|_| Error::Allocation)?;
    positions.resize(HASH_SIZE, EMPTY);
    let mut literals = Vector::new();
    let mut commands = Vector::new();
    let mut anchor = 0usize;
    let mut cursor = 0usize;
    while cursor + 4 <= block.len() {
        let value = u32::from_le_bytes(block[cursor..cursor + 4].try_into().unwrap());
        let hash = ((value.wrapping_mul(0x9e37_79b1)) >> (32 - HASH_BITS)) as usize;
        let previous = positions[hash];
        positions[hash] = cursor as u32;
        if previous == EMPTY {
            cursor += 1;
            continue;
        }
        let previous = previous as usize;
        if previous >= cursor || block[previous..previous + 4] != block[cursor..cursor + 4] {
            cursor += 1;
            continue;
        }
        let mut length = 4usize;
        while cursor + length < block.len() && block[previous + length] == block[cursor + length] {
            length += 1;
        }
        literals
            .try_extend_from_slice(&block[anchor..cursor])
            .map_err(|_| Error::Allocation)?;
        commands.push(sequences::Sequence::new(
            (cursor - anchor) as u32,
            length as u32,
            (cursor - previous) as u32,
        ));
        let end = cursor + length;
        cursor += 1;
        while cursor + 4 <= end {
            let value = u32::from_le_bytes(block[cursor..cursor + 4].try_into().unwrap());
            let hash = ((value.wrapping_mul(0x9e37_79b1)) >> (32 - HASH_BITS)) as usize;
            positions[hash] = cursor as u32;
            cursor += 1;
        }
        cursor = end;
        anchor = end;
    }
    if commands.is_empty() {
        return Ok(None);
    }
    literals
        .try_extend_from_slice(&block[anchor..])
        .map_err(|_| Error::Allocation)?;
    let raw_literals = encode_raw_literals(&literals)?;
    let encoded_literals = encode_huffman_literals(&literals)?;
    let mut candidate = match encoded_literals {
        Some(encoded) if encoded.len() < raw_literals.len() => encoded,
        _ => raw_literals,
    };
    let mut candidate_state = sequence_state.clone();
    candidate
        .try_extend_from_slice(&sequences::encode(&commands, &mut candidate_state)?)
        .map_err(|_| Error::Allocation)?;
    if candidate.len() < block.len() {
        // Selection is fail closed: a candidate must pass the independent
        // decoder path before it can become a cached HTTP representation.
        let mut verified = Vector::with_capacity(block.len()).map_err(|_| Error::Allocation)?;
        let mut huffman_table = None;
        let mut decoder_state = sequences::State::new();
        if decode_compressed_block(
            &candidate,
            &mut verified,
            &mut huffman_table,
            &mut decoder_state,
        )
        .is_err()
            || &verified[..] != block
        {
            return Ok(None);
        }
        *sequence_state = candidate_state;
        Ok(Some(candidate))
    } else {
        Ok(None)
    }
}

#[cfg(any(windows, unix))]
fn encode_huffman_literals(literals: &[u8]) -> Result<Option<Vector<u8>>> {
    if literals.len() < 2 || literals.len() > MAX_BLOCK {
        return Ok(None);
    }
    let mut frequencies = [0u32; 256];
    for symbol in literals {
        frequencies[*symbol as usize] = frequencies[*symbol as usize]
            .checked_add(1)
            .ok_or(Error::BlockTooLarge)?;
    }
    let table = match huffman::EncoderTable::from_frequencies(&frequencies) {
        Ok(table) => table,
        Err(Error::InvalidHuffmanTree) => return Ok(None),
        Err(error) => return Err(error),
    };
    let tree = table.serialize_tree()?;
    let regenerated = literals.len();
    let one_stream = table.encode_stream(literals)?;
    let one_size = tree
        .len()
        .checked_add(one_stream.len())
        .ok_or(Error::BlockTooLarge)?;
    if regenerated <= 1023 && one_size <= 1023 {
        let packed = 2u32 | (regenerated as u32) << 4 | (one_size as u32) << 14;
        let mut output = Vector::new();
        output
            .try_extend_from_slice(&[packed as u8, (packed >> 8) as u8, (packed >> 16) as u8])
            .map_err(|_| Error::Allocation)?;
        output
            .try_extend_from_slice(&tree)
            .map_err(|_| Error::Allocation)?;
        output
            .try_extend_from_slice(&one_stream)
            .map_err(|_| Error::Allocation)?;
        return Ok(Some(output));
    }
    if regenerated < 4 {
        return Ok(None);
    }

    let per = regenerated.div_ceil(4);
    let boundaries = [0, per, per * 2, per * 3, regenerated];
    let mut streams: [Vector<u8>; 4] = core::array::from_fn(|_| Vector::new());
    for index in 0..4 {
        streams[index] =
            table.encode_stream(&literals[boundaries[index]..boundaries[index + 1]])?;
    }
    if streams[..3]
        .iter()
        .any(|stream| stream.len() > u16::MAX as usize)
    {
        return Ok(None);
    }
    let compressed_size = tree
        .len()
        .checked_add(6)
        .and_then(|size| {
            streams
                .iter()
                .try_fold(size, |total, stream| total.checked_add(stream.len()))
        })
        .ok_or(Error::BlockTooLarge)?;
    let (packed, header_bytes) = if regenerated <= 1023 && compressed_size <= 1023 {
        (
            6u64 | (regenerated as u64) << 4 | (compressed_size as u64) << 14,
            3,
        )
    } else if regenerated <= 16_383 && compressed_size <= 16_383 {
        (
            10u64 | (regenerated as u64) << 4 | (compressed_size as u64) << 18,
            4,
        )
    } else if regenerated <= 0x3ffff && compressed_size <= 0x3ffff {
        (
            14u64 | (regenerated as u64) << 4 | (compressed_size as u64) << 22,
            5,
        )
    } else {
        return Ok(None);
    };
    let mut output = Vector::new();
    for shift in 0..header_bytes {
        output
            .try_push((packed >> (shift * 8)) as u8)
            .map_err(|_| Error::Allocation)?;
    }
    output
        .try_extend_from_slice(&tree)
        .map_err(|_| Error::Allocation)?;
    for stream in &streams[..3] {
        output
            .try_extend_from_slice(&(stream.len() as u16).to_le_bytes())
            .map_err(|_| Error::Allocation)?;
    }
    for stream in streams {
        output
            .try_extend_from_slice(&stream)
            .map_err(|_| Error::Allocation)?;
    }
    Ok(Some(output))
}

#[cfg(any(windows, unix))]
fn encode_raw_literals(literals: &[u8]) -> Result<Vector<u8>> {
    if literals.len() > MAX_BLOCK {
        return Err(Error::BlockTooLarge);
    }
    let size = literals.len();
    let mut output = Vector::new();
    if size <= 31 {
        output
            .try_push((size as u8) << 3)
            .map_err(|_| Error::Allocation)?;
    } else if size <= 4095 {
        output
            .try_extend_from_slice(&[4 | ((size as u8 & 15) << 4), (size >> 4) as u8])
            .map_err(|_| Error::Allocation)?;
    } else {
        output
            .try_extend_from_slice(&[
                12 | ((size as u8 & 15) << 4),
                (size >> 4) as u8,
                (size >> 12) as u8,
            ])
            .map_err(|_| Error::Allocation)?;
    }
    output
        .try_extend_from_slice(literals)
        .map_err(|_| Error::Allocation)?;
    Ok(output)
}

pub fn inspect_frame(input: &[u8]) -> Result<FrameInfo> {
    let magic = read_u32(input, 0)?;
    if magic != FRAME_MAGIC {
        return Err(Error::InvalidMagic(magic));
    }
    let descriptor = *input.get(4).ok_or(Error::Truncated)?;
    if descriptor & 0x08 != 0 {
        return Err(Error::ReservedHeaderBit);
    }
    let single_segment = descriptor & 0x20 != 0;
    let checksum = descriptor & 0x04 != 0;
    let dictionary_size = [0usize, 1, 2, 4][(descriptor & 3) as usize];
    let content_flag = descriptor >> 6;
    let content_size_bytes = match content_flag {
        0 if single_segment => 1,
        0 => 0,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let mut cursor = 5;
    let window_size = if single_segment {
        0
    } else {
        let value = *input.get(cursor).ok_or(Error::Truncated)?;
        cursor += 1;
        let exponent = (value >> 3) as u32 + 10;
        let base = 1u64.checked_shl(exponent).ok_or(Error::Truncated)?;
        base + (base >> 3) * (value & 7) as u64
    };
    let dictionary_id = read_variable(input, cursor, dictionary_size)? as u32;
    cursor += dictionary_size;
    if dictionary_id != 0 {
        return Err(Error::DictionaryRequired(dictionary_id));
    }
    let mut content_size = if content_size_bytes == 0 {
        None
    } else {
        Some(read_variable(input, cursor, content_size_bytes)?)
    };
    if content_size_bytes == 2 {
        content_size = content_size.map(|size| size + 256);
    }
    cursor += content_size_bytes;
    Ok(FrameInfo {
        header_bytes: cursor,
        window_size: if single_segment {
            content_size.unwrap_or(0)
        } else {
            window_size
        },
        content_size,
        checksum,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeIntoError {
    Frame(Error),
    OutputTooSmall(u64),
}

impl From<Error> for DecodeIntoError {
    fn from(error: Error) -> Self {
        Self::Frame(error)
    }
}

/// Allocation-free target floor for complete raw/RLE frames. Entropy-coded
/// blocks fail closed until their bounded table workspace is migrated.
pub fn decode_into(
    input: &[u8],
    output: &mut [u8],
) -> core::result::Result<usize, DecodeIntoError> {
    let info = inspect_frame(input)?;
    let mut cursor = info.header_bytes;
    let mut written = 0usize;
    loop {
        let header = read_u24(input, cursor)?;
        cursor += 3;
        let last = header & 1 != 0;
        let block_type = (header >> 1) & 3;
        let block_size = (header >> 3) as usize;
        let next = written
            .checked_add(block_size)
            .ok_or(Error::BlockTooLarge)?;
        match block_type {
            0 => {
                let end = cursor.checked_add(block_size).ok_or(Error::Truncated)?;
                let bytes = input.get(cursor..end).ok_or(Error::Truncated)?;
                if let Some(destination) = output.get_mut(written..next) {
                    destination.copy_from_slice(bytes);
                }
                cursor = end;
            }
            1 => {
                let byte = *input.get(cursor).ok_or(Error::Truncated)?;
                cursor += 1;
                if let Some(destination) = output.get_mut(written..next) {
                    destination.fill(byte);
                }
            }
            2 => return Err(Error::UnsupportedCompressedBlock.into()),
            _ => return Err(Error::ReservedBlock.into()),
        }
        written = next;
        if last {
            break;
        }
    }
    if info.checksum {
        cursor = cursor.checked_add(4).ok_or(Error::Truncated)?;
    }
    if cursor > input.len() {
        return Err(Error::Truncated.into());
    }
    if cursor != input.len() {
        return Err(Error::TrailingData.into());
    }
    if info.content_size.is_some_and(|size| size != written as u64) {
        return Err(Error::ContentSizeMismatch.into());
    }
    if written > output.len() {
        return Err(DecodeIntoError::OutputTooSmall(written as u64));
    }
    Ok(written)
}

/// Host decoder with entropy-coded Huffman/FSE support.
#[cfg(any(windows, unix))]
pub fn decode(input: &[u8]) -> Result<Vector<u8>> {
    let info = inspect_frame(input)?;
    let capacity = info
        .content_size
        .and_then(|size| usize::try_from(size).ok())
        .unwrap_or(0);
    let mut output = Vector::with_capacity(capacity).map_err(|_| Error::Allocation)?;
    let mut huffman_table = None;
    let mut sequence_state = sequences::State::new();
    let mut cursor = info.header_bytes;
    loop {
        let header = read_u24(input, cursor)?;
        cursor += 3;
        let last = header & 1 != 0;
        let block_type = (header >> 1) & 3;
        let block_size = (header >> 3) as usize;
        match block_type {
            0 => {
                let bytes = input
                    .get(cursor..cursor.checked_add(block_size).ok_or(Error::Truncated)?)
                    .ok_or(Error::Truncated)?;
                output
                    .try_extend_from_slice(bytes)
                    .map_err(|_| Error::Allocation)?;
                cursor += block_size;
            }
            1 => {
                let byte = *input.get(cursor).ok_or(Error::Truncated)?;
                cursor += 1;
                for _ in 0..block_size {
                    output.push(byte);
                }
            }
            2 => {
                let block = input
                    .get(cursor..cursor.checked_add(block_size).ok_or(Error::Truncated)?)
                    .ok_or(Error::Truncated)?;
                decode_compressed_block(
                    block,
                    &mut output,
                    &mut huffman_table,
                    &mut sequence_state,
                )?;
                cursor += block_size;
            }
            _ => return Err(Error::ReservedBlock),
        }
        if last {
            break;
        }
    }
    if info.checksum {
        cursor = cursor.checked_add(4).ok_or(Error::Truncated)?;
    }
    if cursor > input.len() {
        return Err(Error::Truncated);
    }
    if cursor != input.len() {
        return Err(Error::TrailingData);
    }
    if info
        .content_size
        .is_some_and(|size| size != output.len() as u64)
    {
        return Err(Error::ContentSizeMismatch);
    }
    Ok(output)
}

#[cfg(any(windows, unix))]
enum Literals<'a> {
    Raw(&'a [u8]),
    Rle { byte: u8, count: usize },
    Decoded(Vector<u8>),
}

#[cfg(any(windows, unix))]
fn decode_compressed_block(
    block: &[u8],
    output: &mut Vector<u8>,
    huffman_table: &mut Option<huffman::Table>,
    sequence_state: &mut sequences::State,
) -> Result<()> {
    let (literals, consumed) = parse_literals(block, huffman_table)?;
    let commands = sequences::decode(
        block
            .get(consumed..)
            .ok_or(Error::InvalidSequencesSection)?,
        sequence_state,
    )?;
    match literals {
        Literals::Raw(bytes) => sequences::execute(&commands, bytes, output)?,
        Literals::Rle { byte, count } => {
            let mut bytes = Vector::with_capacity(count).map_err(|_| Error::Allocation)?;
            bytes.resize(count, byte);
            sequences::execute(&commands, &bytes, output)?;
        }
        Literals::Decoded(bytes) => sequences::execute(&commands, &bytes, output)?,
    }
    Ok(())
}

#[cfg(any(windows, unix))]
fn parse_literals<'a>(
    block: &'a [u8],
    previous_table: &mut Option<huffman::Table>,
) -> Result<(Literals<'a>, usize)> {
    let first = *block.first().ok_or(Error::InvalidLiteralsSection)?;
    let kind = first & 3;
    let size_format = (first >> 2) & 3;
    if kind >= 2 {
        return parse_huffman_literals(block, kind == 3, size_format, previous_table);
    }
    let (header_bytes, regenerated_size): (usize, usize) = match size_format {
        0 | 2 => (1, (first >> 3) as usize),
        1 => {
            let second = *block.get(1).ok_or(Error::InvalidLiteralsSection)?;
            (2, (first as usize >> 4) | (second as usize) << 4)
        }
        _ => {
            let second = *block.get(1).ok_or(Error::InvalidLiteralsSection)?;
            let third = *block.get(2).ok_or(Error::InvalidLiteralsSection)?;
            (
                3,
                (first as usize >> 4) | (second as usize) << 4 | (third as usize) << 12,
            )
        }
    };
    if kind == 0 {
        let end = header_bytes
            .checked_add(regenerated_size)
            .ok_or(Error::InvalidLiteralsSection)?;
        let bytes = block
            .get(header_bytes..end)
            .ok_or(Error::InvalidLiteralsSection)?;
        Ok((Literals::Raw(bytes), end))
    } else {
        let byte = *block
            .get(header_bytes)
            .ok_or(Error::InvalidLiteralsSection)?;
        Ok((
            Literals::Rle {
                byte,
                count: regenerated_size,
            },
            header_bytes + 1,
        ))
    }
}

#[cfg(any(windows, unix))]
fn parse_huffman_literals<'a>(
    block: &'a [u8],
    reuse: bool,
    size_format: u8,
    previous_table: &mut Option<huffman::Table>,
) -> Result<(Literals<'a>, usize)> {
    let (regenerated, compressed, header_bytes, four_streams) = match size_format {
        0 | 1 => {
            let bytes = block.get(..3).ok_or(Error::InvalidLiteralsSection)?;
            let regenerated = (bytes[0] as usize >> 4) | ((bytes[1] as usize & 0x3f) << 4);
            let compressed = (bytes[1] as usize >> 6) | (bytes[2] as usize) << 2;
            (regenerated, compressed, 3, size_format == 1)
        }
        2 => {
            let bytes = block.get(..4).ok_or(Error::InvalidLiteralsSection)?;
            let regenerated =
                (bytes[0] as usize >> 4) | (bytes[1] as usize) << 4 | (bytes[2] as usize & 3) << 12;
            let compressed = (bytes[2] as usize >> 2) | (bytes[3] as usize) << 6;
            (regenerated, compressed, 4, true)
        }
        _ => {
            let bytes = block.get(..5).ok_or(Error::InvalidLiteralsSection)?;
            let packed = read_variable(bytes, 0, 5)?;
            (
                ((packed >> 4) & 0x3ffff) as usize,
                ((packed >> 22) & 0x3ffff) as usize,
                5,
                true,
            )
        }
    };
    if regenerated > 128 * 1024 || compressed == 0 {
        return Err(Error::InvalidLiteralsSection);
    }
    let payload = block
        .get(header_bytes..header_bytes + compressed)
        .ok_or(Error::InvalidLiteralsSection)?;
    let (table, tree_bytes) = if reuse {
        (previous_table.clone().ok_or(Error::InvalidHuffmanTree)?, 0)
    } else {
        huffman::parse_tree(payload)?
    };
    let streams = payload
        .get(tree_bytes..)
        .ok_or(Error::InvalidLiteralsSection)?;
    let mut decoded = Vector::with_capacity(regenerated).map_err(|_| Error::Allocation)?;
    if four_streams {
        let jump = streams.get(..6).ok_or(Error::InvalidHuffmanStream)?;
        let first = u16::from_le_bytes(jump[0..2].try_into().unwrap()) as usize;
        let second = u16::from_le_bytes(jump[2..4].try_into().unwrap()) as usize;
        let third = u16::from_le_bytes(jump[4..6].try_into().unwrap()) as usize;
        let total = 6usize
            .checked_add(first)
            .and_then(|value| value.checked_add(second))
            .and_then(|value| value.checked_add(third))
            .ok_or(Error::InvalidHuffmanStream)?;
        if total >= streams.len() || regenerated < 4 {
            return Err(Error::InvalidHuffmanStream);
        }
        let per = regenerated.div_ceil(4);
        let last = regenerated
            .checked_sub(per * 3)
            .ok_or(Error::InvalidHuffmanStream)?;
        let starts = [6, 6 + first, 6 + first + second, total];
        let ends = [6 + first, 6 + first + second, total, streams.len()];
        let counts = [per, per, per, last];
        for index in 0..4 {
            huffman::decode_stream(
                &streams[starts[index]..ends[index]],
                &table,
                counts[index],
                &mut decoded,
            )?;
        }
    } else {
        huffman::decode_stream(streams, &table, regenerated, &mut decoded)?;
    }
    *previous_table = Some(table);
    Ok((Literals::Decoded(decoded), header_bytes + compressed))
}

fn read_variable(input: &[u8], offset: usize, width: usize) -> Result<u64> {
    let bytes = input
        .get(offset..offset.checked_add(width).ok_or(Error::Truncated)?)
        .ok_or(Error::Truncated)?;
    let mut value = 0u64;
    for (shift, byte) in bytes.iter().enumerate() {
        value |= (*byte as u64) << (shift * 8);
    }
    Ok(value)
}

fn read_u24(input: &[u8], offset: usize) -> Result<u32> {
    let bytes = input.get(offset..offset + 3).ok_or(Error::Truncated)?;
    Ok(bytes[0] as u32 | (bytes[1] as u32) << 8 | (bytes[2] as u32) << 16)
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32> {
    input
        .get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .ok_or(Error::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_single_segment_raw_block() {
        let frame = [
            0x28, 0xb5, 0x2f, 0xfd, 0x20, 3, 0x19, 0, 0, b'a', b'b', b'c',
        ];
        assert_eq!(&*decode(&frame).unwrap(), b"abc");
    }

    #[test]
    fn http_encoder_is_deterministic_bounded_and_round_trips() {
        for input in [
            &b""[..],
            &b"mrml"[..],
            &[7; 4096][..],
            &[0x5a; 256 * 1024][..],
        ] {
            let first = encode_http(input, HttpEncodingProfile::BoundedRawRleV1).unwrap();
            let second = encode_http(input, HttpEncodingProfile::BoundedRawRleV1).unwrap();
            assert_eq!(first, second);
            let info = inspect_frame(&first).unwrap();
            assert_eq!(info.content_size, Some(input.len() as u64));
            assert!(info.window_size <= HTTP_MAX_WINDOW as u64);
            assert_eq!(&decode(&first).unwrap()[..], input);
        }
        let mut oversized = Vector::new();
        oversized.try_resize(HTTP_MAX_WINDOW + 1, 0).unwrap();
        assert_eq!(
            encode_http(&oversized, HttpEncodingProfile::BoundedRawRleV1),
            Err(Error::InputTooLarge)
        );
    }

    #[test]
    fn http_encoder_uses_rle_without_overstating_compression_profile() {
        let input = [b'x'; 64 * 1024];
        let encoded = encode_http(&input, HttpEncodingProfile::BoundedRawRleV1).unwrap();
        assert!(encoded.len() < 32);
        assert_eq!(&decode(&encoded).unwrap()[..], &input);
    }

    #[test]
    fn rfc_profile_selects_smaller_predefined_fse_block_deterministically() {
        let mut input = Vector::new();
        for _ in 0..4096 {
            input.try_extend_from_slice(b"mrml-zstd-").unwrap();
        }
        let first = encode_http(&input, HttpEncodingProfile::BoundedRfc8878V2).unwrap();
        let second = encode_http(&input, HttpEncodingProfile::BoundedRfc8878V2).unwrap();
        assert_eq!(first, second);
        let info = inspect_frame(&first).unwrap();
        assert_eq!((read_u24(&first, info.header_bytes).unwrap() >> 1) & 3, 2);
        assert!(first.len() < input.len() / 8);
        assert_eq!(&decode(&first).unwrap()[..], &input[..]);
    }

    #[test]
    fn direct_weight_huffman_literal_section_round_trips() {
        let mut literals = Vector::new();
        for index in 0..1000 {
            literals.push(if index % 13 == 0 { b'b' } else { b'a' });
        }
        let encoded = encode_huffman_literals(&literals).unwrap().unwrap();
        assert!(encoded.len() < encode_raw_literals(&literals).unwrap().len());
        let (decoded, consumed) = parse_literals(&encoded, &mut None).unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            Literals::Decoded(bytes) => assert_eq!(&bytes[..], &literals[..]),
            _ => panic!("expected Huffman literal section"),
        }
    }

    #[test]
    fn four_stream_huffman_literals_cover_large_header_formats() {
        for (length, expected_format) in [(5_000usize, 2u8), (20_000, 3)] {
            let mut literals = Vector::new();
            for index in 0..length {
                literals.push(if index % 11 == 0 { b'b' } else { b'a' });
            }
            let encoded = encode_huffman_literals(&literals).unwrap().unwrap();
            assert_eq!((encoded[0] >> 2) & 3, expected_format);
            let (decoded, consumed) = parse_literals(&encoded, &mut None).unwrap();
            assert_eq!(consumed, encoded.len());
            match decoded {
                Literals::Decoded(bytes) => assert_eq!(bytes, literals),
                _ => panic!("expected four-stream Huffman literals"),
            }
        }
    }

    #[test]
    fn malformed_four_stream_jumps_and_literal_resource_bounds_fail_closed() {
        let mut literals = Vector::new();
        literals.try_resize(5_000, b'a').unwrap();
        for index in (0..literals.len()).step_by(11) {
            literals[index] = b'b';
        }
        let encoded = encode_huffman_literals(&literals).unwrap().unwrap();
        assert_eq!((encoded[0] >> 2) & 3, 2);
        let (_, tree_bytes) = huffman::parse_tree(&encoded[4..]).unwrap();
        let jump = 4 + tree_bytes;
        let mut malformed = encoded.clone();
        malformed[jump..jump + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(matches!(
            parse_literals(&malformed, &mut None),
            Err(Error::InvalidHuffmanStream)
        ));
        assert!(matches!(
            parse_literals(&encoded[..3], &mut None),
            Err(Error::InvalidLiteralsSection)
        ));

        let mut oversized = Vector::new();
        oversized.try_resize(MAX_BLOCK + 1, b'a').unwrap();
        assert_eq!(encode_huffman_literals(&oversized), Ok(None));
    }

    #[test]
    fn deterministic_profile_corpus_records_bounded_ratios() {
        let mut html = Vector::new();
        for _ in 0..1_000 {
            html.try_extend_from_slice(
                b"<article><h2>MRML</h2><p>bounded semantic page</p></article>",
            )
            .unwrap();
        }
        let first = encode_http(&html, HttpEncodingProfile::BoundedRfc8878V2).unwrap();
        let second = encode_http(&html, HttpEncodingProfile::BoundedRfc8878V2).unwrap();
        assert_eq!(first, second);
        assert!(first.len() * 100 < html.len() * 20);
        assert_eq!(decode(&first).unwrap(), html);

        let mut incompressible = Vector::new();
        let mut state = 0x6d72_6d6cu32;
        for _ in 0..64 * 1024 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            incompressible.push((state >> 24) as u8);
        }
        let encoded = encode_http(&incompressible, HttpEncodingProfile::BoundedRfc8878V2).unwrap();
        // Four-byte magic, five-byte single-segment header at this size, and
        // one three-byte raw block header are the bounded expansion ceiling.
        assert!(encoded.len() <= incompressible.len() + 12);
        assert_eq!(decode(&encoded).unwrap(), incompressible);
    }

    #[cfg(unix)]
    #[test]
    fn external_zstd_1_5_7_decodes_rfc_profile_when_configured() {
        let Some(oracle) = mrml_runtime::environment_variable("MRML_ZSTD_ORACLE_1_5_7") else {
            return;
        };
        let input = b"MRML RFC 8878 interoperability probe: abcabcabcabcabcabcabcabc";
        let encoded = encode_http(input, HttpEncodingProfile::BoundedRfc8878V2).unwrap();
        let stem =
            mrml_runtime::mrml_format!("/tmp/mrml-zstd-oracle-{}", mrml_runtime::process_id());
        let frame_path = mrml_runtime::mrml_format!("{stem}.zst");
        mrml_runtime::write_file(&frame_path, &encoded).unwrap();
        let output = mrml_runtime::Command::new(&oracle)
            .args(["--decompress", "--stdout", "--quiet"])
            .arg(&frame_path)
            .output()
            .unwrap();
        mrml_runtime::remove_file(&frame_path).unwrap();
        assert!(
            output.status.success(),
            "pinned zstd rejected MRML frame: {}",
            core::str::from_utf8(&output.stderr).unwrap_or("non-UTF-8 error")
        );
        assert_eq!(&output.stdout[..], input);

        // Exercise the four-stream Huffman literal layout independently of the
        // match finder by placing one literal section and zero sequences in a
        // complete compressed block.
        let mut large = Vector::new();
        for index in 0..5_000 {
            large.push(if index % 11 == 0 { b'b' } else { b'a' });
        }
        let mut block = encode_huffman_literals(&large).unwrap().unwrap();
        block.push(0); // zero sequences
        let mut frame = Vector::new();
        frame
            .try_extend_from_slice(&FRAME_MAGIC.to_le_bytes())
            .unwrap();
        frame.push(0x60); // single segment with a two-byte content size
        frame
            .try_extend_from_slice(&((large.len() - 256) as u16).to_le_bytes())
            .unwrap();
        let header = ((block.len() as u32) << 3) | (2 << 1) | 1;
        frame
            .try_extend_from_slice(&[header as u8, (header >> 8) as u8, (header >> 16) as u8])
            .unwrap();
        frame.try_extend_from_slice(&block).unwrap();
        mrml_runtime::write_file(&frame_path, &frame).unwrap();
        let output = mrml_runtime::Command::new(&oracle)
            .args(["--decompress", "--stdout", "--quiet"])
            .arg(&frame_path)
            .output()
            .unwrap();
        mrml_runtime::remove_file(&frame_path).unwrap();
        assert!(
            output.status.success(),
            "pinned zstd rejected four-stream MRML frame: {}",
            core::str::from_utf8(&output.stderr).unwrap_or("non-UTF-8 error")
        );
        assert_eq!(output.stdout, large);
    }

    #[test]
    fn allocation_free_target_floor_is_bounded_and_fail_closed() {
        let raw = [
            0x28, 0xb5, 0x2f, 0xfd, 0x20, 3, 0x19, 0, 0, b'a', b'b', b'c',
        ];
        let rle = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 5, 0x2b, 0, 0, b'x'];
        let compressed = [
            0x28, 0xb5, 0x2f, 0xfd, 0x20, 3, 0x2d, 0, 0, 0x18, b'a', b'b', b'c', 0,
        ];
        let mut output = [0xcc; 5];
        assert_eq!(decode_into(&raw, &mut output), Ok(3));
        assert_eq!(&output[..3], b"abc");
        assert_eq!(decode_into(&rle, &mut output), Ok(5));
        assert_eq!(&output, b"xxxxx");
        assert_eq!(
            decode_into(&raw, &mut output[..2]),
            Err(DecodeIntoError::OutputTooSmall(3))
        );
        assert_eq!(
            decode_into(&compressed, &mut output),
            Err(DecodeIntoError::Frame(Error::UnsupportedCompressedBlock))
        );
    }

    #[test]
    fn abi_three_provider_uses_bounded_views_and_reports_required_output() {
        use mrml_interface_zstd_v3::{
            decode_decompress_response, encode_decompress_request, BorrowedReadView,
            BorrowedWriteView,
        };

        let frame = [
            0x28, 0xb5, 0x2f, 0xfd, 0x20, 3, 0x19, 0, 0, b'a', b'b', b'c',
        ];
        let mut memory = [0_u8; 32];
        memory[..frame.len()].copy_from_slice(&frame);
        let input = BorrowedReadView::within(0, frame.len() as u64, 32).unwrap();
        let small = BorrowedWriteView::within(frame.len() as u64, 2, 32).unwrap();
        let request = encode_decompress_request(input, small).unwrap();
        let response = ComponentProvider.call(&request, &mut memory).unwrap();
        assert_eq!(
            decode_decompress_response(&response),
            Ok(Err((DecompressError::OutputTooSmall, 3)))
        );

        let output = BorrowedWriteView::within(frame.len() as u64, 3, 32).unwrap();
        let request = encode_decompress_request(input, output).unwrap();
        let response = ComponentProvider.call(&request, &mut memory).unwrap();
        assert_eq!(decode_decompress_response(&response), Ok(Ok(3)));
        assert_eq!(&memory[frame.len()..frame.len() + 3], b"abc");
    }

    #[test]
    fn decodes_single_segment_rle_block() {
        let frame = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 5, 0x2b, 0, 0, b'x'];
        assert_eq!(&*decode(&frame).unwrap(), b"xxxxx");
    }

    #[test]
    fn parses_kiwix_style_streaming_header() {
        let prefix = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x68, 0x4c, 0xb0, 0x00];
        let info = inspect_frame(&prefix).unwrap();
        assert_eq!(info.header_bytes, 6);
        assert_eq!(info.window_size, 1 << 23);
        assert_eq!(info.content_size, None);
        assert_eq!(read_u24(&prefix, info.header_bytes).unwrap() >> 3, 5641);
    }

    #[test]
    fn decodes_compressed_block_with_raw_literals_and_no_sequences() {
        let frame = [
            0x28, 0xb5, 0x2f, 0xfd, 0x20, 3, 0x2d, 0, 0, 0x18, b'a', b'b', b'c', 0,
        ];
        assert_eq!(&*decode(&frame).unwrap(), b"abc");
    }

    #[test]
    fn decodes_compressed_block_with_rle_literals_and_no_sequences() {
        let frame = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 5, 0x1d, 0, 0, 0x29, b'x', 0];
        assert_eq!(&*decode(&frame).unwrap(), b"xxxxx");
    }
}
