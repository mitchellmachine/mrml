pub const ABI_CALL_HEADER_BYTES: usize = 72;
const ABI_MAGIC: [u8; 8] = *b"MRMLABI\0";
const ABI_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceIdentity {
    name: String,
    generation: u32,
}

impl InterfaceIdentity {
    pub fn new(name: String, generation: u32) -> Result<Self, AbiError> {
        if !interface_name(&name) {
            return Err(AbiError::InvalidInterfaceName);
        }
        if generation == 0 {
            return Err(AbiError::InvalidInterfaceGeneration);
        }
        Ok(Self { name, generation })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiBorrowedView {
    offset: u64,
    length: u64,
}

impl AbiBorrowedView {
    pub fn within(offset: u64, length: u64, object_length: u64) -> Result<Self, AbiError> {
        let end = offset.checked_add(length).ok_or(AbiError::ViewOverflow)?;
        if end > object_length {
            return Err(AbiError::ViewOutOfBounds);
        }
        Ok(Self { offset, length })
    }

    pub const fn offset(self) -> u64 {
        self.offset
    }

    pub const fn length(self) -> u64 {
        self.length
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiOpaqueHandle {
    index: u32,
    generation: u32,
}

impl AbiOpaqueHandle {
    pub const fn new(index: u32, generation: u32) -> Result<Self, AbiError> {
        if generation == 0 {
            return Err(AbiError::InvalidHandleGeneration);
        }
        Ok(Self { index, generation })
    }

    pub const fn index(self) -> u32 {
        self.index
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiCallHeader {
    interface_fingerprint: [u8; 32],
    interface_generation: u32,
    operation: u32,
    request_bytes: u64,
    response_bytes: u64,
}

impl AbiCallHeader {
    pub fn new(
        interface_fingerprint: [u8; 32],
        interface_generation: u32,
        operation: u32,
        request_bytes: u64,
        response_bytes: u64,
    ) -> Result<Self, AbiError> {
        if interface_fingerprint.iter().all(|byte| *byte == 0) {
            return Err(AbiError::InvalidFingerprint);
        }
        if interface_generation == 0 || operation == 0 {
            return Err(AbiError::InvalidCallIdentity);
        }
        Ok(Self {
            interface_fingerprint,
            interface_generation,
            operation,
            request_bytes,
            response_bytes,
        })
    }

    pub fn encode(self) -> [u8; ABI_CALL_HEADER_BYTES] {
        let mut output = [0_u8; ABI_CALL_HEADER_BYTES];
        output[0..8].copy_from_slice(&ABI_MAGIC);
        output[8..10].copy_from_slice(&ABI_SCHEMA_VERSION.to_le_bytes());
        output[16..48].copy_from_slice(&self.interface_fingerprint);
        output[48..52].copy_from_slice(&self.interface_generation.to_le_bytes());
        output[52..56].copy_from_slice(&self.operation.to_le_bytes());
        output[56..64].copy_from_slice(&self.request_bytes.to_le_bytes());
        output[64..72].copy_from_slice(&self.response_bytes.to_le_bytes());
        output
    }

    pub fn decode(input: &[u8]) -> Result<Self, AbiError> {
        if input.len() != ABI_CALL_HEADER_BYTES || input[0..8] != ABI_MAGIC {
            return Err(AbiError::InvalidHeader);
        }
        if u16::from_le_bytes(input[8..10].try_into().unwrap()) != ABI_SCHEMA_VERSION
            || input[10..16] != [0; 6]
        {
            return Err(AbiError::InvalidHeader);
        }
        Self::new(
            input[16..48].try_into().unwrap(),
            u32::from_le_bytes(input[48..52].try_into().unwrap()),
            u32::from_le_bytes(input[52..56].try_into().unwrap()),
            u64::from_le_bytes(input[56..64].try_into().unwrap()),
            u64::from_le_bytes(input[64..72].try_into().unwrap()),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbiError {
    InvalidInterfaceName,
    InvalidInterfaceGeneration,
    ViewOverflow,
    ViewOutOfBounds,
    InvalidHandleGeneration,
    InvalidFingerprint,
    InvalidCallIdentity,
    InvalidHeader,
}

fn interface_name(value: &str) -> bool {
    value.starts_with("org.mrml.interface.")
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && segment
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_lowercase)
                && segment
                    .as_bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_generation_is_separate_and_exact() {
        let identity =
            InterfaceIdentity::new("org.mrml.interface.compression.zstd".into(), 3).unwrap();
        assert_eq!(identity.name(), "org.mrml.interface.compression.zstd");
        assert_eq!(identity.generation(), 3);
        assert!(InterfaceIdentity::new("org.mrml.zstd".into(), 3).is_err());
        assert!(InterfaceIdentity::new("org.mrml.interface.compression.zstd".into(), 0).is_err());
    }

    #[test]
    fn borrowed_views_and_handles_fail_closed() {
        assert_eq!(AbiBorrowedView::within(8, 4, 12).unwrap().offset(), 8);
        assert_eq!(AbiBorrowedView::within(8, 4, 12).unwrap().length(), 4);
        assert_eq!(
            AbiBorrowedView::within(u64::MAX, 1, u64::MAX),
            Err(AbiError::ViewOverflow)
        );
        assert_eq!(
            AbiBorrowedView::within(8, 5, 12),
            Err(AbiError::ViewOutOfBounds)
        );
        let handle = AbiOpaqueHandle::new(7, 9).unwrap();
        assert_eq!((handle.index(), handle.generation()), (7, 9));
        assert_eq!(
            AbiOpaqueHandle::new(7, 0),
            Err(AbiError::InvalidHandleGeneration)
        );
    }

    #[test]
    fn call_header_round_trips_canonical_little_endian_bytes() {
        let header = AbiCallHeader::new([0x5a; 32], 3, 7, 4096, 2048).unwrap();
        let encoded = header.encode();
        assert_eq!(&encoded[0..8], b"MRMLABI\0");
        assert_eq!(AbiCallHeader::decode(&encoded), Ok(header));
        let mut malformed = encoded;
        malformed[14] = 1;
        assert_eq!(
            AbiCallHeader::decode(&malformed),
            Err(AbiError::InvalidHeader)
        );
    }
}
