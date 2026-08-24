use crate::{
    BlockService, BlockServiceBackend, BlockServiceError, BlockSessionHandle, SUPERBLOCK_BYTES,
    StoragePrincipal,
};

pub const BLOCK_PROTOCOL_VERSION: u16 = 1;
pub const BLOCK_REQUEST_BYTES: usize = 320;
pub const BLOCK_RESPONSE_BYTES: usize = 32;
pub const MAX_BLOCK_TRANSFER_BYTES: usize = 1024 * 1024;

const REQUEST_MAGIC: [u8; 8] = *b"MRMLBLK1";
const RESPONSE_MAGIC: [u8; 8] = *b"MRMLBRS1";
const REQUEST_HEADER_BYTES: usize = 64;
const REPLACE_PAYLOAD_OFFSET: usize = REQUEST_HEADER_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BlockOpcode {
    Read = 1,
    Write = 2,
    Flush = 3,
    ReplaceSuperblock = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockBufferAccess {
    None,
    ServiceReads,
    ServiceWrites,
}

impl BlockBufferAccess {
    pub const fn capability_count(self) -> usize {
        match self {
            Self::None => 0,
            Self::ServiceReads | Self::ServiceWrites => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockRequest {
    Read {
        request_id: u64,
        session: BlockSessionHandle,
        block: u64,
        byte_length: u32,
    },
    Write {
        request_id: u64,
        session: BlockSessionHandle,
        block: u64,
        byte_length: u32,
    },
    Flush {
        request_id: u64,
        session: BlockSessionHandle,
    },
    ReplaceSuperblock {
        request_id: u64,
        session: BlockSessionHandle,
        block: u64,
        encoded: [u8; SUPERBLOCK_BYTES],
    },
}

impl BlockRequest {
    pub const fn request_id(self) -> u64 {
        match self {
            Self::Read { request_id, .. }
            | Self::Write { request_id, .. }
            | Self::Flush { request_id, .. }
            | Self::ReplaceSuperblock { request_id, .. } => request_id,
        }
    }

    pub const fn session(self) -> BlockSessionHandle {
        match self {
            Self::Read { session, .. }
            | Self::Write { session, .. }
            | Self::Flush { session, .. }
            | Self::ReplaceSuperblock { session, .. } => session,
        }
    }

    pub const fn buffer_access(self) -> BlockBufferAccess {
        match self {
            Self::Read { .. } => BlockBufferAccess::ServiceWrites,
            Self::Write { .. } => BlockBufferAccess::ServiceReads,
            Self::Flush { .. } | Self::ReplaceSuperblock { .. } => BlockBufferAccess::None,
        }
    }

    pub const fn byte_length(self) -> usize {
        match self {
            Self::Read { byte_length, .. } | Self::Write { byte_length, .. } => {
                byte_length as usize
            }
            Self::Flush { .. } | Self::ReplaceSuperblock { .. } => 0,
        }
    }

    pub fn encode(self, output: &mut [u8; BLOCK_REQUEST_BYTES]) -> Result<(), BlockProtocolError> {
        *output = [0; BLOCK_REQUEST_BYTES];
        output[..8].copy_from_slice(&REQUEST_MAGIC);
        put_u16(output, 8, BLOCK_PROTOCOL_VERSION);
        put_u16(output, 10, REQUEST_HEADER_BYTES as u16);
        let (opcode, capabilities, request_id, session, block, byte_length, payload_length) =
            match self {
                Self::Read {
                    request_id,
                    session,
                    block,
                    byte_length,
                } => (
                    BlockOpcode::Read,
                    1,
                    request_id,
                    session,
                    block,
                    byte_length,
                    0,
                ),
                Self::Write {
                    request_id,
                    session,
                    block,
                    byte_length,
                } => (
                    BlockOpcode::Write,
                    1,
                    request_id,
                    session,
                    block,
                    byte_length,
                    0,
                ),
                Self::Flush {
                    request_id,
                    session,
                } => (BlockOpcode::Flush, 0, request_id, session, 0, 0, 0),
                Self::ReplaceSuperblock {
                    request_id,
                    session,
                    block,
                    encoded,
                } => {
                    output[REPLACE_PAYLOAD_OFFSET..REPLACE_PAYLOAD_OFFSET + SUPERBLOCK_BYTES]
                        .copy_from_slice(&encoded);
                    (
                        BlockOpcode::ReplaceSuperblock,
                        0,
                        request_id,
                        session,
                        block,
                        0,
                        SUPERBLOCK_BYTES as u32,
                    )
                }
            };
        validate_common(request_id, session)?;
        validate_operation(opcode, capabilities, block, byte_length, payload_length)?;
        output[12] = opcode as u8;
        output[13] = capabilities;
        put_u64(output, 16, request_id);
        put_u32(output, 24, session.slot());
        put_u32(output, 28, session.generation());
        put_u64(output, 32, block);
        put_u32(output, 40, byte_length);
        put_u32(output, 44, payload_length);
        Ok(())
    }

    pub fn decode(input: &[u8]) -> Result<Self, BlockProtocolError> {
        if input.len() != BLOCK_REQUEST_BYTES {
            return Err(BlockProtocolError::InvalidLength);
        }
        if input[..8] != REQUEST_MAGIC
            || get_u16(input, 8)? != BLOCK_PROTOCOL_VERSION
            || get_u16(input, 10)? as usize != REQUEST_HEADER_BYTES
        {
            return Err(BlockProtocolError::Unsupported);
        }
        if input[14..16].iter().any(|byte| *byte != 0)
            || input[48..REQUEST_HEADER_BYTES]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(BlockProtocolError::NonCanonical);
        }
        let opcode = match input[12] {
            1 => BlockOpcode::Read,
            2 => BlockOpcode::Write,
            3 => BlockOpcode::Flush,
            4 => BlockOpcode::ReplaceSuperblock,
            _ => return Err(BlockProtocolError::Unsupported),
        };
        let capabilities = input[13];
        let request_id = get_u64(input, 16)?;
        let session = BlockSessionHandle::from_parts(get_u32(input, 24)?, get_u32(input, 28)?)
            .ok_or(BlockProtocolError::InvalidRequest)?;
        let block = get_u64(input, 32)?;
        let byte_length = get_u32(input, 40)?;
        let payload_length = get_u32(input, 44)?;
        validate_common(request_id, session)?;
        validate_operation(opcode, capabilities, block, byte_length, payload_length)?;

        match opcode {
            BlockOpcode::Read | BlockOpcode::Write => {
                if input[REQUEST_HEADER_BYTES..].iter().any(|byte| *byte != 0) {
                    return Err(BlockProtocolError::NonCanonical);
                }
                if opcode == BlockOpcode::Read {
                    Ok(Self::Read {
                        request_id,
                        session,
                        block,
                        byte_length,
                    })
                } else {
                    Ok(Self::Write {
                        request_id,
                        session,
                        block,
                        byte_length,
                    })
                }
            }
            BlockOpcode::Flush => {
                if input[REQUEST_HEADER_BYTES..].iter().any(|byte| *byte != 0) {
                    return Err(BlockProtocolError::NonCanonical);
                }
                Ok(Self::Flush {
                    request_id,
                    session,
                })
            }
            BlockOpcode::ReplaceSuperblock => {
                if input[REPLACE_PAYLOAD_OFFSET + SUPERBLOCK_BYTES..]
                    .iter()
                    .any(|byte| *byte != 0)
                {
                    return Err(BlockProtocolError::NonCanonical);
                }
                let mut encoded = [0; SUPERBLOCK_BYTES];
                encoded.copy_from_slice(
                    &input[REPLACE_PAYLOAD_OFFSET..REPLACE_PAYLOAD_OFFSET + SUPERBLOCK_BYTES],
                );
                Ok(Self::ReplaceSuperblock {
                    request_id,
                    session,
                    block,
                    encoded,
                })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum BlockStatus {
    Ok = 0,
    Denied = 1,
    StaleHandle = 2,
    InvalidRequest = 3,
    Capacity = 4,
    UnknownDevice = 5,
    BackendFailure = 6,
    ReplayRejected = 7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockResponse {
    request_id: u64,
    status: BlockStatus,
    transferred: u32,
}

impl BlockResponse {
    pub fn new(request_id: u64, status: BlockStatus, transferred: u32) -> Option<Self> {
        if request_id == 0 || (status != BlockStatus::Ok && transferred != 0) {
            None
        } else {
            Some(Self {
                request_id,
                status,
                transferred,
            })
        }
    }

    pub const fn request_id(self) -> u64 {
        self.request_id
    }

    pub const fn status(self) -> BlockStatus {
        self.status
    }

    pub const fn transferred(self) -> u32 {
        self.transferred
    }

    pub fn encode(self, output: &mut [u8; BLOCK_RESPONSE_BYTES]) {
        *output = [0; BLOCK_RESPONSE_BYTES];
        output[..8].copy_from_slice(&RESPONSE_MAGIC);
        put_u16(output, 8, BLOCK_PROTOCOL_VERSION);
        put_u16(output, 10, BLOCK_RESPONSE_BYTES as u16);
        put_u16(output, 12, self.status as u16);
        put_u64(output, 16, self.request_id);
        put_u32(output, 24, self.transferred);
    }

    pub fn decode(input: &[u8]) -> Result<Self, BlockProtocolError> {
        if input.len() != BLOCK_RESPONSE_BYTES {
            return Err(BlockProtocolError::InvalidLength);
        }
        if input[..8] != RESPONSE_MAGIC
            || get_u16(input, 8)? != BLOCK_PROTOCOL_VERSION
            || get_u16(input, 10)? as usize != BLOCK_RESPONSE_BYTES
        {
            return Err(BlockProtocolError::Unsupported);
        }
        if input[14..16].iter().any(|byte| *byte != 0) || input[28..].iter().any(|byte| *byte != 0)
        {
            return Err(BlockProtocolError::NonCanonical);
        }
        let status = match get_u16(input, 12)? {
            0 => BlockStatus::Ok,
            1 => BlockStatus::Denied,
            2 => BlockStatus::StaleHandle,
            3 => BlockStatus::InvalidRequest,
            4 => BlockStatus::Capacity,
            5 => BlockStatus::UnknownDevice,
            6 => BlockStatus::BackendFailure,
            7 => BlockStatus::ReplayRejected,
            _ => return Err(BlockProtocolError::Unsupported),
        };
        Self::new(get_u64(input, 16)?, status, get_u32(input, 24)?)
            .ok_or(BlockProtocolError::InvalidResponse)
    }
}

pub enum BlockDispatchBuffer<'a> {
    None,
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

#[derive(Clone, Copy)]
struct ReplaySlot {
    generation: u32,
    last_request_id: u64,
    poisoned: bool,
}

impl ReplaySlot {
    const EMPTY: Self = Self {
        generation: 0,
        last_request_id: 0,
        poisoned: false,
    };
}

/// Bounded per-session replay state for the versioned block control protocol.
pub struct BlockProtocolDispatcher<const SESSIONS: usize> {
    replay: [ReplaySlot; SESSIONS],
}

pub(crate) enum BlockAdmission {
    Rejected(BlockResponse),
    Admitted(AdmittedBlockRequest),
}

pub(crate) struct AdmittedBlockRequest {
    request: BlockRequest,
}

impl<const SESSIONS: usize> Default for BlockProtocolDispatcher<SESSIONS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SESSIONS: usize> BlockProtocolDispatcher<SESSIONS> {
    pub const fn new() -> Self {
        Self {
            replay: [ReplaySlot::EMPTY; SESSIONS],
        }
    }

    /// Decodes and dispatches one block-service control request.
    ///
    /// # Safety
    ///
    /// `buffer` must have been obtained from the one shared-memory capability
    /// transferred with this exact authenticated IPC request. The caller must
    /// bind `principal` to the IPC sender rather than accepting it from request
    /// bytes. One dispatcher must remain bound to the service for its lifetime.
    pub unsafe fn dispatch<B: BlockServiceBackend, const DEVICES: usize>(
        &mut self,
        service: &BlockService<DEVICES, SESSIONS>,
        backend: &mut B,
        principal: StoragePrincipal,
        encoded: &[u8],
        buffer: BlockDispatchBuffer<'_>,
    ) -> Result<BlockResponse, BlockProtocolError> {
        let request = BlockRequest::decode(encoded)?;
        if !buffer_matches(request, &buffer) {
            return Err(BlockProtocolError::BufferMismatch);
        }
        match self.admit(service, principal, request)? {
            BlockAdmission::Rejected(response) => Ok(response),
            BlockAdmission::Admitted(admitted) => {
                self.dispatch_admitted(service, backend, principal, admitted, buffer)
            }
        }
    }

    pub(crate) fn admit<const DEVICES: usize>(
        &mut self,
        service: &BlockService<DEVICES, SESSIONS>,
        principal: StoragePrincipal,
        request: BlockRequest,
    ) -> Result<BlockAdmission, BlockProtocolError> {
        let request_id = request.request_id();
        if let Err(error) = service.validate_owner(request.session(), principal) {
            let response = BlockResponse::new(request_id, status_for(error), 0)
                .ok_or(BlockProtocolError::InvalidResponse)?;
            return Ok(BlockAdmission::Rejected(response));
        }
        let replay = self
            .replay
            .get_mut(request.session().slot() as usize)
            .ok_or(BlockProtocolError::InvalidRequest)?;
        if replay.generation != request.session().generation() {
            replay.generation = request.session().generation();
            replay.last_request_id = 0;
            replay.poisoned = false;
        }
        if request_id <= replay.last_request_id {
            let response = BlockResponse::new(request_id, BlockStatus::ReplayRejected, 0)
                .ok_or(BlockProtocolError::InvalidResponse)?;
            return Ok(BlockAdmission::Rejected(response));
        }
        if replay.poisoned {
            let response = BlockResponse::new(request_id, BlockStatus::BackendFailure, 0)
                .ok_or(BlockProtocolError::InvalidResponse)?;
            return Ok(BlockAdmission::Rejected(response));
        }
        replay.last_request_id = request_id;
        Ok(BlockAdmission::Admitted(AdmittedBlockRequest { request }))
    }

    pub(crate) fn dispatch_admitted<B: BlockServiceBackend, const DEVICES: usize>(
        &mut self,
        service: &BlockService<DEVICES, SESSIONS>,
        backend: &mut B,
        principal: StoragePrincipal,
        admitted: AdmittedBlockRequest,
        buffer: BlockDispatchBuffer<'_>,
    ) -> Result<BlockResponse, BlockProtocolError> {
        let request = admitted.request;
        if !buffer_matches(request, &buffer) {
            return Err(BlockProtocolError::BufferMismatch);
        }
        let request_id = request.request_id();
        if let Err(error) = service.validate_owner(request.session(), principal) {
            return BlockResponse::new(request_id, status_for(error), 0)
                .ok_or(BlockProtocolError::InvalidResponse);
        }
        let replay = self
            .replay
            .get_mut(request.session().slot() as usize)
            .ok_or(BlockProtocolError::InvalidRequest)?;
        if replay.generation != request.session().generation()
            || replay.last_request_id != request_id
            || replay.poisoned
        {
            return Err(BlockProtocolError::Replay);
        }
        let mutating = matches!(
            request,
            BlockRequest::Write { .. }
                | BlockRequest::Flush { .. }
                | BlockRequest::ReplaceSuperblock { .. }
        );
        let result = match (request, buffer) {
            (
                BlockRequest::Read {
                    session,
                    block,
                    byte_length,
                    ..
                },
                BlockDispatchBuffer::Read(output),
            ) => service
                .read_blocks(backend, session, principal, block, output)
                .map(|()| byte_length),
            (
                BlockRequest::Write {
                    session,
                    block,
                    byte_length,
                    ..
                },
                BlockDispatchBuffer::Write(input),
            ) => service
                .write_blocks(backend, session, principal, block, input)
                .map(|()| byte_length),
            (BlockRequest::Flush { session, .. }, BlockDispatchBuffer::None) => {
                service.flush(backend, session, principal).map(|()| 0)
            }
            (
                BlockRequest::ReplaceSuperblock {
                    session,
                    block,
                    encoded,
                    ..
                },
                BlockDispatchBuffer::None,
            ) => service
                .replace_superblock(backend, session, principal, block, &encoded)
                .map(|()| 0),
            _ => return Err(BlockProtocolError::BufferMismatch),
        };
        let (status, transferred) = match result {
            Ok(transferred) => (BlockStatus::Ok, transferred),
            Err(error) => {
                if mutating && matches!(&error, BlockServiceError::Backend(_)) {
                    replay.poisoned = true;
                }
                (status_for(error), 0)
            }
        };
        BlockResponse::new(request_id, status, transferred)
            .ok_or(BlockProtocolError::InvalidResponse)
    }
}

fn buffer_matches(request: BlockRequest, buffer: &BlockDispatchBuffer<'_>) -> bool {
    match (request, buffer) {
        (BlockRequest::Read { byte_length, .. }, BlockDispatchBuffer::Read(output)) => {
            output.len() == byte_length as usize
        }
        (BlockRequest::Write { byte_length, .. }, BlockDispatchBuffer::Write(input)) => {
            input.len() == byte_length as usize
        }
        (
            BlockRequest::Flush { .. } | BlockRequest::ReplaceSuperblock { .. },
            BlockDispatchBuffer::None,
        ) => true,
        _ => false,
    }
}

fn status_for<E>(error: BlockServiceError<E>) -> BlockStatus {
    match error {
        BlockServiceError::Denied | BlockServiceError::InvalidRights => BlockStatus::Denied,
        BlockServiceError::StaleHandle => BlockStatus::StaleHandle,
        BlockServiceError::Capacity => BlockStatus::Capacity,
        BlockServiceError::UnknownDevice => BlockStatus::UnknownDevice,
        BlockServiceError::DuplicateDevice
        | BlockServiceError::InvalidLength
        | BlockServiceError::InvalidRange => BlockStatus::InvalidRequest,
        BlockServiceError::Backend(_) => BlockStatus::BackendFailure,
    }
}

fn validate_common(request_id: u64, session: BlockSessionHandle) -> Result<(), BlockProtocolError> {
    if request_id == 0 || session.generation() == 0 {
        return Err(BlockProtocolError::InvalidRequest);
    }
    Ok(())
}

fn validate_operation(
    opcode: BlockOpcode,
    capabilities: u8,
    block: u64,
    byte_length: u32,
    payload_length: u32,
) -> Result<(), BlockProtocolError> {
    match opcode {
        BlockOpcode::Read | BlockOpcode::Write => {
            if capabilities != 1
                || byte_length == 0
                || byte_length as usize > MAX_BLOCK_TRANSFER_BYTES
                || payload_length != 0
            {
                return Err(BlockProtocolError::InvalidRequest);
            }
        }
        BlockOpcode::Flush => {
            if capabilities != 0 || block != 0 || byte_length != 0 || payload_length != 0 {
                return Err(BlockProtocolError::InvalidRequest);
            }
        }
        BlockOpcode::ReplaceSuperblock => {
            if capabilities != 0 || byte_length != 0 || payload_length != SUPERBLOCK_BYTES as u32 {
                return Err(BlockProtocolError::InvalidRequest);
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockProtocolError {
    InvalidLength,
    Truncated,
    Unsupported,
    NonCanonical,
    InvalidRequest,
    InvalidResponse,
    BufferMismatch,
    Replay,
}

fn get_u16(input: &[u8], offset: usize) -> Result<u16, BlockProtocolError> {
    let bytes = input
        .get(offset..offset + 2)
        .ok_or(BlockProtocolError::Truncated)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn get_u32(input: &[u8], offset: usize) -> Result<u32, BlockProtocolError> {
    let bytes = input
        .get(offset..offset + 4)
        .ok_or(BlockProtocolError::Truncated)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn get_u64(input: &[u8], offset: usize) -> Result<u64, BlockProtocolError> {
    let bytes = input
        .get(offset..offset + 8)
        .ok_or(BlockProtocolError::Truncated)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockDeviceDescriptor, BlockDeviceId, BlockRights};

    const BLOCK_SIZE: usize = 4096;
    const BLOCKS: usize = 8;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum BackendError {
        Failed,
        Range,
    }

    struct Backend {
        bytes: [u8; BLOCK_SIZE * BLOCKS],
        calls: usize,
        fail: bool,
    }

    impl Backend {
        fn range(
            &self,
            block: u64,
            length: usize,
        ) -> Result<core::ops::Range<usize>, BackendError> {
            let start = usize::try_from(block)
                .ok()
                .and_then(|value| value.checked_mul(BLOCK_SIZE))
                .ok_or(BackendError::Range)?;
            let end = start.checked_add(length).ok_or(BackendError::Range)?;
            if end > self.bytes.len() {
                return Err(BackendError::Range);
            }
            Ok(start..end)
        }
    }

    unsafe impl BlockServiceBackend for Backend {
        type Error = BackendError;

        fn read_blocks(
            &mut self,
            _device: BlockDeviceId,
            block: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            if self.fail {
                return Err(BackendError::Failed);
            }
            let range = self.range(block, output.len())?;
            output.copy_from_slice(&self.bytes[range]);
            self.calls += 1;
            Ok(())
        }

        fn write_blocks(
            &mut self,
            _device: BlockDeviceId,
            block: u64,
            input: &[u8],
        ) -> Result<(), Self::Error> {
            if self.fail {
                return Err(BackendError::Failed);
            }
            let range = self.range(block, input.len())?;
            self.bytes[range].copy_from_slice(input);
            self.calls += 1;
            Ok(())
        }

        fn flush(&mut self, _device: BlockDeviceId) -> Result<(), Self::Error> {
            if self.fail {
                return Err(BackendError::Failed);
            }
            self.calls += 1;
            Ok(())
        }

        fn replace_superblock(
            &mut self,
            _device: BlockDeviceId,
            block: u64,
            encoded: &[u8; SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            if self.fail {
                return Err(BackendError::Failed);
            }
            let range = self.range(block, BLOCK_SIZE)?;
            self.bytes[range.clone()].fill(0);
            self.bytes[range.start..range.start + SUPERBLOCK_BYTES].copy_from_slice(encoded);
            self.calls += 1;
            Ok(())
        }
    }

    fn owner(value: u64) -> StoragePrincipal {
        StoragePrincipal::new(value).unwrap()
    }

    fn fixture() -> (BlockService<1, 2>, BlockSessionHandle) {
        let device = BlockDeviceId::new(5).unwrap();
        let mut service = BlockService::new();
        service
            .register_device(
                BlockDeviceDescriptor::new(device, BLOCK_SIZE as u32, BLOCKS as u64).unwrap(),
            )
            .unwrap();
        let handle = service.grant(device, owner(1), BlockRights::ALL).unwrap();
        (service, handle)
    }

    #[test]
    fn every_request_and_response_has_one_canonical_round_trip() {
        let (_, session) = fixture();
        let requests = [
            BlockRequest::Read {
                request_id: 1,
                session,
                block: 2,
                byte_length: BLOCK_SIZE as u32,
            },
            BlockRequest::Write {
                request_id: 2,
                session,
                block: 3,
                byte_length: (2 * BLOCK_SIZE) as u32,
            },
            BlockRequest::Flush {
                request_id: 3,
                session,
            },
            BlockRequest::ReplaceSuperblock {
                request_id: 4,
                session,
                block: 1,
                encoded: [0x5a; SUPERBLOCK_BYTES],
            },
        ];
        for request in requests {
            let mut encoded = [0xcc; BLOCK_REQUEST_BYTES];
            request.encode(&mut encoded).unwrap();
            assert_eq!(BlockRequest::decode(&encoded).unwrap(), request);
        }
        assert_eq!(
            requests[0].buffer_access(),
            BlockBufferAccess::ServiceWrites
        );
        assert_eq!(requests[0].buffer_access().capability_count(), 1);
        assert_eq!(requests[1].buffer_access(), BlockBufferAccess::ServiceReads);
        assert_eq!(requests[2].buffer_access(), BlockBufferAccess::None);
        assert_eq!(requests[3].buffer_access().capability_count(), 0);

        for status in [
            BlockStatus::Ok,
            BlockStatus::Denied,
            BlockStatus::StaleHandle,
            BlockStatus::InvalidRequest,
            BlockStatus::Capacity,
            BlockStatus::UnknownDevice,
            BlockStatus::BackendFailure,
            BlockStatus::ReplayRejected,
        ] {
            let response =
                BlockResponse::new(9, status, u32::from(status == BlockStatus::Ok)).unwrap();
            let mut encoded = [0xcc; BLOCK_RESPONSE_BYTES];
            response.encode(&mut encoded);
            assert_eq!(BlockResponse::decode(&encoded).unwrap(), response);
        }
    }

    #[test]
    fn malformed_or_noncanonical_records_fail_before_dispatch() {
        let (_, session) = fixture();
        let request = BlockRequest::Read {
            request_id: 1,
            session,
            block: 0,
            byte_length: BLOCK_SIZE as u32,
        };
        let mut encoded = [0; BLOCK_REQUEST_BYTES];
        request.encode(&mut encoded).unwrap();
        encoded[100] = 1;
        assert_eq!(
            BlockRequest::decode(&encoded),
            Err(BlockProtocolError::NonCanonical)
        );
        request.encode(&mut encoded).unwrap();
        encoded[13] = 0;
        assert_eq!(
            BlockRequest::decode(&encoded),
            Err(BlockProtocolError::InvalidRequest)
        );
        request.encode(&mut encoded).unwrap();
        put_u32(&mut encoded, 40, MAX_BLOCK_TRANSFER_BYTES as u32 + 1);
        assert_eq!(
            BlockRequest::decode(&encoded),
            Err(BlockProtocolError::InvalidRequest)
        );
        assert_eq!(
            BlockRequest::decode(&encoded[..BLOCK_REQUEST_BYTES - 1]),
            Err(BlockProtocolError::InvalidLength)
        );
    }

    #[test]
    fn dispatch_binds_buffer_principal_rights_and_monotonic_request_id() {
        let (service, session) = fixture();
        let mut backend = Backend {
            bytes: [0x41; BLOCK_SIZE * BLOCKS],
            calls: 0,
            fail: false,
        };
        let mut dispatcher = BlockProtocolDispatcher::<2>::new();
        let request = BlockRequest::Read {
            request_id: 1,
            session,
            block: 0,
            byte_length: BLOCK_SIZE as u32,
        };
        let mut encoded = [0; BLOCK_REQUEST_BYTES];
        request.encode(&mut encoded).unwrap();
        let mut output = [0; BLOCK_SIZE];
        let response = unsafe {
            dispatcher.dispatch(
                &service,
                &mut backend,
                owner(1),
                &encoded,
                BlockDispatchBuffer::Read(&mut output),
            )
        }
        .unwrap();
        assert_eq!(
            (response.status(), response.transferred()),
            (BlockStatus::Ok, BLOCK_SIZE as u32)
        );
        assert_eq!(output, [0x41; BLOCK_SIZE]);
        let response = unsafe {
            dispatcher.dispatch(
                &service,
                &mut backend,
                owner(1),
                &encoded,
                BlockDispatchBuffer::Read(&mut output),
            )
        }
        .unwrap();
        assert_eq!(response.status(), BlockStatus::ReplayRejected);
        assert_eq!(backend.calls, 1);

        let next = BlockRequest::Read {
            request_id: 2,
            session,
            block: 0,
            byte_length: BLOCK_SIZE as u32,
        };
        next.encode(&mut encoded).unwrap();
        let denied = unsafe {
            dispatcher.dispatch(
                &service,
                &mut backend,
                owner(2),
                &encoded,
                BlockDispatchBuffer::Read(&mut output),
            )
        }
        .unwrap();
        assert_eq!(denied.status(), BlockStatus::Denied);
        let accepted = unsafe {
            dispatcher.dispatch(
                &service,
                &mut backend,
                owner(1),
                &encoded,
                BlockDispatchBuffer::Read(&mut output),
            )
        }
        .unwrap();
        assert_eq!(accepted.status(), BlockStatus::Ok);
        assert_eq!(backend.calls, 2);
    }

    #[test]
    fn buffer_mismatch_does_not_consume_id_but_backend_uncertainty_does() {
        let (service, session) = fixture();
        let mut backend = Backend {
            bytes: [0; BLOCK_SIZE * BLOCKS],
            calls: 0,
            fail: false,
        };
        let mut dispatcher = BlockProtocolDispatcher::<2>::new();
        let request = BlockRequest::Write {
            request_id: 7,
            session,
            block: 3,
            byte_length: BLOCK_SIZE as u32,
        };
        let mut encoded = [0; BLOCK_REQUEST_BYTES];
        request.encode(&mut encoded).unwrap();
        assert_eq!(
            unsafe {
                dispatcher.dispatch(
                    &service,
                    &mut backend,
                    owner(1),
                    &encoded,
                    BlockDispatchBuffer::None,
                )
            },
            Err(BlockProtocolError::BufferMismatch)
        );
        backend.fail = true;
        let response = unsafe {
            dispatcher.dispatch(
                &service,
                &mut backend,
                owner(1),
                &encoded,
                BlockDispatchBuffer::Write(&[0; BLOCK_SIZE]),
            )
        }
        .unwrap();
        assert_eq!(response.status(), BlockStatus::BackendFailure);
        backend.fail = false;
        let replay = unsafe {
            dispatcher.dispatch(
                &service,
                &mut backend,
                owner(1),
                &encoded,
                BlockDispatchBuffer::Write(&[0; BLOCK_SIZE]),
            )
        }
        .unwrap();
        assert_eq!(replay.status(), BlockStatus::ReplayRejected);
        assert_eq!(backend.calls, 0);
        let next = BlockRequest::Write {
            request_id: 8,
            session,
            block: 3,
            byte_length: BLOCK_SIZE as u32,
        };
        next.encode(&mut encoded).unwrap();
        let fail_stopped = unsafe {
            dispatcher.dispatch(
                &service,
                &mut backend,
                owner(1),
                &encoded,
                BlockDispatchBuffer::Write(&[0; BLOCK_SIZE]),
            )
        }
        .unwrap();
        assert_eq!(fail_stopped.status(), BlockStatus::BackendFailure);
        assert_eq!(backend.calls, 0);
    }
}
