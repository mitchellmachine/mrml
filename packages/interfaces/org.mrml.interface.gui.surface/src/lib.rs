#![no_std]

#[path = "../1.rs"]
mod generated;

pub use generated::*;

pub const ABI_CALL_HEADER_BYTES: usize = 72;
pub const COMMIT_REQUEST_BYTES: usize = ABI_CALL_HEADER_BYTES + 40;
pub const COMMIT_RESPONSE_BYTES: usize = 16;
pub const SURFACE_STATE_BYTES: usize = 200;
pub const MAX_DAMAGE_RECTS: usize = 8;
pub const MAX_GRAPHICS_DIMENSION: u32 = 16_384;
pub const MAX_GRAPHICS_BUFFER_BYTES: u64 = 1 << 30;
pub const MAX_LOGICAL_COORDINATE: i32 = 1 << 20;

const ABI_MAGIC: [u8; 8] = *b"MRMLABI\0";
const ABI_SCHEMA_VERSION: u16 = 1;
const STATE_MAGIC: [u8; 8] = *b"MRMLSF1\0";
const STATE_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurfaceProtocolError {
    InvalidHeader,
    InvalidHandle,
    InvalidView,
    InvalidState,
    InvalidResponse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurfaceFormat {
    Bgra8Srgb = 1,
    Rgba8Srgb = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogicalRect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceState {
    pub logical_bounds: LogicalRect,
    pub scale_numerator: u16,
    pub scale_denominator: u16,
    pub buffer_width: u32,
    pub buffer_height: u32,
    pub buffer_stride: u32,
    pub buffer_byte_length: u64,
    pub format: SurfaceFormat,
    pub serial: u64,
    pub damage_count: u32,
    pub damage: [LogicalRect; MAX_DAMAGE_RECTS],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitEnvelope {
    pub surface: OpaqueHandle,
    pub output: OpaqueHandle,
    pub buffer: OpaqueHandle,
    pub state: BorrowedReadView,
}

pub fn encode_commit_request(
    surface: OpaqueHandle,
    output: OpaqueHandle,
    buffer: OpaqueHandle,
    state: BorrowedReadView,
) -> Result<[u8; COMMIT_REQUEST_BYTES], SurfaceProtocolError> {
    if state.length() != SURFACE_STATE_BYTES as u64 {
        return Err(SurfaceProtocolError::InvalidView);
    }
    let mut bytes = [0_u8; COMMIT_REQUEST_BYTES];
    bytes[0..8].copy_from_slice(&ABI_MAGIC);
    bytes[8..10].copy_from_slice(&ABI_SCHEMA_VERSION.to_le_bytes());
    bytes[16..48].copy_from_slice(&INTERFACE_FINGERPRINT);
    bytes[48..52].copy_from_slice(&INTERFACE_GENERATION.to_le_bytes());
    bytes[52..56].copy_from_slice(&OP_COMMIT.to_le_bytes());
    bytes[56..64].copy_from_slice(&40_u64.to_le_bytes());
    bytes[64..72].copy_from_slice(&(COMMIT_RESPONSE_BYTES as u64).to_le_bytes());
    encode_handle(surface, &mut bytes[72..80]);
    encode_handle(output, &mut bytes[80..88]);
    encode_handle(buffer, &mut bytes[88..96]);
    bytes[96..104].copy_from_slice(&state.offset().to_le_bytes());
    bytes[104..112].copy_from_slice(&state.length().to_le_bytes());
    Ok(bytes)
}

pub fn decode_commit_request(
    bytes: &[u8; COMMIT_REQUEST_BYTES],
    memory_length: u64,
) -> Result<CommitEnvelope, SurfaceProtocolError> {
    if bytes[0..8] != ABI_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != ABI_SCHEMA_VERSION
        || bytes[10..16] != [0; 6]
        || bytes[16..48] != INTERFACE_FINGERPRINT
        || u32::from_le_bytes(bytes[48..52].try_into().unwrap()) != INTERFACE_GENERATION
        || u32::from_le_bytes(bytes[52..56].try_into().unwrap()) != OP_COMMIT
        || u64::from_le_bytes(bytes[56..64].try_into().unwrap()) != 40
        || u64::from_le_bytes(bytes[64..72].try_into().unwrap()) != COMMIT_RESPONSE_BYTES as u64
    {
        return Err(SurfaceProtocolError::InvalidHeader);
    }
    let surface = decode_handle(&bytes[72..80])?;
    let output = decode_handle(&bytes[80..88])?;
    let buffer = decode_handle(&bytes[88..96])?;
    let state = BorrowedReadView::within(
        u64::from_le_bytes(bytes[96..104].try_into().unwrap()),
        u64::from_le_bytes(bytes[104..112].try_into().unwrap()),
        memory_length,
    )
    .ok_or(SurfaceProtocolError::InvalidView)?;
    if state.length() != SURFACE_STATE_BYTES as u64 {
        return Err(SurfaceProtocolError::InvalidView);
    }
    Ok(CommitEnvelope {
        surface,
        output,
        buffer,
        state,
    })
}

pub fn encode_surface_state(
    state: SurfaceState,
) -> Result<[u8; SURFACE_STATE_BYTES], SurfaceProtocolError> {
    validate_state(&state)?;
    let mut bytes = [0_u8; SURFACE_STATE_BYTES];
    bytes[0..8].copy_from_slice(&STATE_MAGIC);
    bytes[8..10].copy_from_slice(&STATE_VERSION.to_le_bytes());
    encode_rect(state.logical_bounds, &mut bytes[12..28]);
    bytes[28..30].copy_from_slice(&state.scale_numerator.to_le_bytes());
    bytes[30..32].copy_from_slice(&state.scale_denominator.to_le_bytes());
    bytes[32..36].copy_from_slice(&state.buffer_width.to_le_bytes());
    bytes[36..40].copy_from_slice(&state.buffer_height.to_le_bytes());
    bytes[40..44].copy_from_slice(&state.buffer_stride.to_le_bytes());
    bytes[44..48].copy_from_slice(&(state.format as u32).to_le_bytes());
    bytes[48..56].copy_from_slice(&state.buffer_byte_length.to_le_bytes());
    bytes[56..64].copy_from_slice(&state.serial.to_le_bytes());
    bytes[64..68].copy_from_slice(&state.damage_count.to_le_bytes());
    for (index, rect) in state.damage.iter().enumerate() {
        let start = 72 + index * 16;
        encode_rect(*rect, &mut bytes[start..start + 16]);
    }
    Ok(bytes)
}

pub fn decode_surface_state(
    bytes: &[u8; SURFACE_STATE_BYTES],
) -> Result<SurfaceState, SurfaceProtocolError> {
    if bytes[0..8] != STATE_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != STATE_VERSION
        || bytes[10..12] != [0; 2]
        || bytes[68..72] != [0; 4]
    {
        return Err(SurfaceProtocolError::InvalidState);
    }
    let format = match u32::from_le_bytes(bytes[44..48].try_into().unwrap()) {
        1 => SurfaceFormat::Bgra8Srgb,
        2 => SurfaceFormat::Rgba8Srgb,
        _ => return Err(SurfaceProtocolError::InvalidState),
    };
    let mut damage = [LogicalRect {
        x: 0,
        y: 0,
        width: 0,
        height: 0,
    }; MAX_DAMAGE_RECTS];
    for (index, rect) in damage.iter_mut().enumerate() {
        let start = 72 + index * 16;
        *rect = decode_rect(&bytes[start..start + 16]);
    }
    let state = SurfaceState {
        logical_bounds: decode_rect(&bytes[12..28]),
        scale_numerator: u16::from_le_bytes(bytes[28..30].try_into().unwrap()),
        scale_denominator: u16::from_le_bytes(bytes[30..32].try_into().unwrap()),
        buffer_width: u32::from_le_bytes(bytes[32..36].try_into().unwrap()),
        buffer_height: u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
        buffer_stride: u32::from_le_bytes(bytes[40..44].try_into().unwrap()),
        buffer_byte_length: u64::from_le_bytes(bytes[48..56].try_into().unwrap()),
        format,
        serial: u64::from_le_bytes(bytes[56..64].try_into().unwrap()),
        damage_count: u32::from_le_bytes(bytes[64..68].try_into().unwrap()),
        damage,
    };
    validate_state(&state)?;
    Ok(state)
}

pub fn encode_commit_response(result: Result<u64, CommitError>) -> [u8; COMMIT_RESPONSE_BYTES] {
    let mut bytes = [0_u8; COMMIT_RESPONSE_BYTES];
    let (status, serial) = match result {
        Ok(serial) => (0, serial),
        Err(error) => (error as u32, 0),
    };
    bytes[0..4].copy_from_slice(&status.to_le_bytes());
    bytes[8..16].copy_from_slice(&serial.to_le_bytes());
    bytes
}

pub fn decode_commit_response(
    bytes: &[u8; COMMIT_RESPONSE_BYTES],
) -> Result<Result<u64, CommitError>, SurfaceProtocolError> {
    if bytes[4..8] != [0; 4] {
        return Err(SurfaceProtocolError::InvalidResponse);
    }
    let status = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let serial = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    match status {
        0 if serial != 0 => Ok(Ok(serial)),
        1 if serial == 0 => Ok(Err(CommitError::InvalidRequest)),
        2 if serial == 0 => Ok(Err(CommitError::StaleObject)),
        3 if serial == 0 => Ok(Err(CommitError::PermissionDenied)),
        4 if serial == 0 => Ok(Err(CommitError::ResourceUnavailable)),
        _ => Err(SurfaceProtocolError::InvalidResponse),
    }
}

fn validate_state(state: &SurfaceState) -> Result<(), SurfaceProtocolError> {
    let bounds = state.logical_bounds;
    let Some(bounds_right) = bounds.x.checked_add_unsigned(bounds.width) else {
        return Err(SurfaceProtocolError::InvalidState);
    };
    let Some(bounds_bottom) = bounds.y.checked_add_unsigned(bounds.height) else {
        return Err(SurfaceProtocolError::InvalidState);
    };
    let Some(minimum_stride) = state.buffer_width.checked_mul(4) else {
        return Err(SurfaceProtocolError::InvalidState);
    };
    let Some(required_bytes) = (state.buffer_stride as u64).checked_mul(state.buffer_height as u64)
    else {
        return Err(SurfaceProtocolError::InvalidState);
    };
    let Some(expected_width) =
        scaled_extent(bounds.width, state.scale_numerator, state.scale_denominator)
    else {
        return Err(SurfaceProtocolError::InvalidState);
    };
    let Some(expected_height) = scaled_extent(
        bounds.height,
        state.scale_numerator,
        state.scale_denominator,
    ) else {
        return Err(SurfaceProtocolError::InvalidState);
    };
    if bounds.width == 0
        || bounds.height == 0
        || bounds.width > MAX_LOGICAL_COORDINATE as u32
        || bounds.height > MAX_LOGICAL_COORDINATE as u32
        || bounds.x < -MAX_LOGICAL_COORDINATE
        || bounds.y < -MAX_LOGICAL_COORDINATE
        || bounds_right > MAX_LOGICAL_COORDINATE
        || bounds_bottom > MAX_LOGICAL_COORDINATE
        || state.scale_numerator == 0
        || state.scale_denominator == 0
        || state.scale_numerator > 4096
        || state.scale_denominator > 4096
        || state.buffer_width == 0
        || state.buffer_height == 0
        || state.buffer_width > MAX_GRAPHICS_DIMENSION
        || state.buffer_height > MAX_GRAPHICS_DIMENSION
        || state.buffer_width != expected_width
        || state.buffer_height != expected_height
        || state.buffer_stride < minimum_stride
        || state.buffer_byte_length == 0
        || state.buffer_byte_length > MAX_GRAPHICS_BUFFER_BYTES
        || required_bytes > state.buffer_byte_length
        || (state.damage_count as usize) > MAX_DAMAGE_RECTS
        || state.serial == 0
    {
        return Err(SurfaceProtocolError::InvalidState);
    }
    for (index, rect) in state.damage.iter().enumerate() {
        if index < state.damage_count as usize {
            if rect.width == 0 || rect.height == 0 || !contains(bounds, *rect) {
                return Err(SurfaceProtocolError::InvalidState);
            }
        } else if *rect
            != (LogicalRect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            })
        {
            return Err(SurfaceProtocolError::InvalidState);
        }
    }
    Ok(())
}

fn scaled_extent(logical: u32, numerator: u16, denominator: u16) -> Option<u32> {
    if numerator == 0 || denominator == 0 {
        return None;
    }
    let scaled = (logical as u64).checked_mul(numerator as u64)?;
    let rounded = scaled.checked_add(denominator as u64 - 1)? / denominator as u64;
    u32::try_from(rounded).ok()
}

fn contains(bounds: LogicalRect, rect: LogicalRect) -> bool {
    let Some(bounds_right) = bounds.x.checked_add_unsigned(bounds.width) else {
        return false;
    };
    let Some(bounds_bottom) = bounds.y.checked_add_unsigned(bounds.height) else {
        return false;
    };
    let Some(right) = rect.x.checked_add_unsigned(rect.width) else {
        return false;
    };
    let Some(bottom) = rect.y.checked_add_unsigned(rect.height) else {
        return false;
    };
    rect.x >= bounds.x && rect.y >= bounds.y && right <= bounds_right && bottom <= bounds_bottom
}

fn encode_handle(handle: OpaqueHandle, bytes: &mut [u8]) {
    bytes[0..4].copy_from_slice(&handle.index().to_le_bytes());
    bytes[4..8].copy_from_slice(&handle.generation().to_le_bytes());
}

fn decode_handle(bytes: &[u8]) -> Result<OpaqueHandle, SurfaceProtocolError> {
    OpaqueHandle::new(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
    )
    .ok_or(SurfaceProtocolError::InvalidHandle)
}

fn encode_rect(rect: LogicalRect, bytes: &mut [u8]) {
    bytes[0..4].copy_from_slice(&rect.x.to_le_bytes());
    bytes[4..8].copy_from_slice(&rect.y.to_le_bytes());
    bytes[8..12].copy_from_slice(&rect.width.to_le_bytes());
    bytes[12..16].copy_from_slice(&rect.height.to_le_bytes());
}

fn decode_rect(bytes: &[u8]) -> LogicalRect {
    LogicalRect {
        x: i32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        y: i32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        width: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        height: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> SurfaceState {
        let mut damage = [LogicalRect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        }; MAX_DAMAGE_RECTS];
        damage[0] = LogicalRect {
            x: 10,
            y: 20,
            width: 100,
            height: 50,
        };
        SurfaceState {
            logical_bounds: LogicalRect {
                x: 10,
                y: 20,
                width: 800,
                height: 600,
            },
            scale_numerator: 3,
            scale_denominator: 2,
            buffer_width: 1200,
            buffer_height: 900,
            buffer_stride: 4800,
            buffer_byte_length: 4_320_000,
            format: SurfaceFormat::Bgra8Srgb,
            serial: 17,
            damage_count: 1,
            damage,
        }
    }

    #[test]
    fn canonical_commit_and_state_round_trip() {
        let memory_length = 256;
        let view = BorrowedReadView::within(24, SURFACE_STATE_BYTES as u64, memory_length).unwrap();
        let surface = OpaqueHandle::new(1, 2).unwrap();
        let output = OpaqueHandle::new(3, 4).unwrap();
        let buffer = OpaqueHandle::new(5, 6).unwrap();
        let request = encode_commit_request(surface, output, buffer, view).unwrap();
        assert_eq!(
            decode_commit_request(&request, memory_length).unwrap(),
            CommitEnvelope {
                surface,
                output,
                buffer,
                state: view
            }
        );
        let encoded = encode_surface_state(state()).unwrap();
        assert_eq!(decode_surface_state(&encoded), Ok(state()));
    }

    #[test]
    fn noncanonical_state_and_response_fail_closed() {
        let mut invalid = state();
        invalid.damage[1] = invalid.damage[0];
        assert_eq!(
            encode_surface_state(invalid),
            Err(SurfaceProtocolError::InvalidState)
        );
        let mut bytes = encode_surface_state(state()).unwrap();
        bytes[44..48].copy_from_slice(&99_u32.to_le_bytes());
        assert_eq!(
            decode_surface_state(&bytes),
            Err(SurfaceProtocolError::InvalidState)
        );
        assert_eq!(
            decode_commit_response(&encode_commit_response(Ok(17))),
            Ok(Ok(17))
        );
        assert_eq!(
            decode_commit_response(&encode_commit_response(Err(CommitError::StaleObject))),
            Ok(Err(CommitError::StaleObject))
        );
    }

    #[test]
    fn hostile_lengths_geometry_and_headers_fail_before_dispatch() {
        let view = BorrowedReadView::within(0, SURFACE_STATE_BYTES as u64, 256).unwrap();
        let mut request = encode_commit_request(
            OpaqueHandle::new(1, 1).unwrap(),
            OpaqueHandle::new(2, 1).unwrap(),
            OpaqueHandle::new(3, 1).unwrap(),
            view,
        )
        .unwrap();
        request[52..56].copy_from_slice(&2_u32.to_le_bytes());
        assert_eq!(
            decode_commit_request(&request, 256),
            Err(SurfaceProtocolError::InvalidHeader)
        );

        let mut invalid = state();
        invalid.buffer_stride -= 1;
        assert_eq!(
            encode_surface_state(invalid),
            Err(SurfaceProtocolError::InvalidState)
        );
        invalid = state();
        invalid.logical_bounds.x = MAX_LOGICAL_COORDINATE;
        assert_eq!(
            encode_surface_state(invalid),
            Err(SurfaceProtocolError::InvalidState)
        );
        invalid = state();
        invalid.buffer_byte_length = MAX_GRAPHICS_BUFFER_BYTES + 1;
        assert_eq!(
            encode_surface_state(invalid),
            Err(SurfaceProtocolError::InvalidState)
        );
    }
}
