use crate::block_protocol::BlockAdmission;
use crate::{
    BlockBufferAccess, BlockDispatchBuffer, BlockProtocolDispatcher, BlockProtocolError,
    BlockRequest, BlockResponse, BlockService, BlockServiceBackend, StoragePrincipal,
    BLOCK_REQUEST_BYTES, BLOCK_RESPONSE_BYTES,
};
use mrml_kernel::Capability;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedBlockEnvelope {
    pub payload_length: usize,
    pub capability_count: usize,
}

/// Narrow unsafe-boundary adapter implemented by the isolated userspace block
/// service. Implementations invoke only authenticated IPC receive/reply and the
/// capability-selected shared-buffer syscalls; they must not manufacture
/// principal identity or turn request bytes into authority. Every received
/// leaf capability must be released through the runtime's transitive
/// revocation path after the request has consumed it.
/// # Safety
///
/// `receive` must return only capability tokens transferred with that exact
/// authenticated message. Shared-buffer methods must invoke the kernel's exact
/// capability-selected operations without weakening rights or substituting a
/// mapping. `send_response` must target only the launch-bound reply peer.
pub unsafe trait BlockServiceSyscalls {
    type Error;

    fn receive(
        &mut self,
        payload: &mut [u8; BLOCK_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedBlockEnvelope, Self::Error>;

    fn read_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error>;

    fn write_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Self::Error>;

    fn send_response(&mut self, response: &[u8; BLOCK_RESPONSE_BYTES]) -> Result<(), Self::Error>;

    fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockServiceLoopError<E> {
    Syscall(E),
    Protocol(BlockProtocolError),
    InvalidEnvelope,
    ScratchTooSmall,
}

/// Stateful service-side receive loop. One instance remains bound to one
/// `BlockService` lifetime so replay and poison state cannot be reset between
/// requests. The authenticated principal and reply peer are launch-time state
/// owned by the syscall adapter, never fields in the block request.
pub struct BlockServiceLoop<const SESSIONS: usize> {
    dispatcher: BlockProtocolDispatcher<SESSIONS>,
}

impl<const SESSIONS: usize> Default for BlockServiceLoop<SESSIONS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SESSIONS: usize> BlockServiceLoop<SESSIONS> {
    pub const fn new() -> Self {
        Self {
            dispatcher: BlockProtocolDispatcher::new(),
        }
    }

    /// Receives and executes exactly one request. All caller-owned transport
    /// buffers are erased on every return path. Replay admission occurs before
    /// shared-buffer or device I/O; successful block reads are copied to shared
    /// memory before the response is sent.
    #[allow(clippy::too_many_arguments)]
    pub fn serve_one<const DEVICES: usize, D: BlockServiceBackend, S: BlockServiceSyscalls>(
        &mut self,
        service: &BlockService<DEVICES, SESSIONS>,
        device_backend: &mut D,
        syscalls: &mut S,
        principal: StoragePrincipal,
        request_buffer: &mut [u8; BLOCK_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        scratch: &mut [u8],
        response_buffer: &mut [u8; BLOCK_RESPONSE_BYTES],
    ) -> Result<(), BlockServiceLoopError<S::Error>> {
        request_buffer.fill(0);
        capability_tokens.fill(0);
        scratch.fill(0);
        response_buffer.fill(0);
        let result = self.serve_one_inner(
            service,
            device_backend,
            syscalls,
            principal,
            request_buffer,
            capability_tokens,
            scratch,
            response_buffer,
        );
        let release = (capability_tokens[0] != 0)
            .then(|| syscalls.release_received(Capability::from_token(capability_tokens[0])))
            .transpose()
            .map(|_| ())
            .map_err(BlockServiceLoopError::Syscall);
        request_buffer.fill(0);
        capability_tokens.fill(0);
        scratch.fill(0);
        response_buffer.fill(0);
        result.and(release)
    }

    #[allow(clippy::too_many_arguments)]
    fn serve_one_inner<const DEVICES: usize, D: BlockServiceBackend, S: BlockServiceSyscalls>(
        &mut self,
        service: &BlockService<DEVICES, SESSIONS>,
        device_backend: &mut D,
        syscalls: &mut S,
        principal: StoragePrincipal,
        request_buffer: &mut [u8; BLOCK_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        scratch: &mut [u8],
        response_buffer: &mut [u8; BLOCK_RESPONSE_BYTES],
    ) -> Result<(), BlockServiceLoopError<S::Error>> {
        let envelope = syscalls
            .receive(request_buffer, capability_tokens)
            .map_err(BlockServiceLoopError::Syscall)?;
        if envelope.payload_length != BLOCK_REQUEST_BYTES || envelope.capability_count > 1 {
            return Err(BlockServiceLoopError::InvalidEnvelope);
        }
        let request =
            BlockRequest::decode(request_buffer).map_err(BlockServiceLoopError::Protocol)?;
        let access = request.buffer_access();
        if envelope.capability_count != access.capability_count()
            || (envelope.capability_count == 0 && capability_tokens[0] != 0)
            || (envelope.capability_count == 1
                && (capability_tokens[0] == 0 || capability_tokens[0] >> 32 == 0))
        {
            return Err(BlockServiceLoopError::InvalidEnvelope);
        }
        let length = request.byte_length();
        if length > scratch.len() {
            return Err(BlockServiceLoopError::ScratchTooSmall);
        }
        let scratch = &mut scratch[..length];
        let admitted = match self
            .dispatcher
            .admit(service, principal, request)
            .map_err(BlockServiceLoopError::Protocol)?
        {
            BlockAdmission::Rejected(response) => {
                return Self::send(syscalls, response, response_buffer);
            }
            BlockAdmission::Admitted(admitted) => admitted,
        };
        let capability = Capability::from_token(capability_tokens[0]);
        let response = match access {
            BlockBufferAccess::None => self
                .dispatcher
                .dispatch_admitted(
                    service,
                    device_backend,
                    principal,
                    admitted,
                    BlockDispatchBuffer::None,
                )
                .map_err(BlockServiceLoopError::Protocol)?,
            BlockBufferAccess::ServiceReads => {
                syscalls
                    .read_shared(capability, 0, scratch)
                    .map_err(BlockServiceLoopError::Syscall)?;
                self.dispatcher
                    .dispatch_admitted(
                        service,
                        device_backend,
                        principal,
                        admitted,
                        BlockDispatchBuffer::Write(scratch),
                    )
                    .map_err(BlockServiceLoopError::Protocol)?
            }
            BlockBufferAccess::ServiceWrites => {
                let response = self
                    .dispatcher
                    .dispatch_admitted(
                        service,
                        device_backend,
                        principal,
                        admitted,
                        BlockDispatchBuffer::Read(scratch),
                    )
                    .map_err(BlockServiceLoopError::Protocol)?;
                if response.status() == crate::BlockStatus::Ok {
                    syscalls
                        .write_shared(capability, 0, scratch)
                        .map_err(BlockServiceLoopError::Syscall)?;
                }
                response
            }
        };
        Self::send(syscalls, response, response_buffer)
    }

    fn send<S: BlockServiceSyscalls>(
        syscalls: &mut S,
        response: BlockResponse,
        response_buffer: &mut [u8; BLOCK_RESPONSE_BYTES],
    ) -> Result<(), BlockServiceLoopError<S::Error>> {
        response.encode(response_buffer);
        syscalls
            .send_response(response_buffer)
            .map_err(BlockServiceLoopError::Syscall)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockDeviceDescriptor, BlockDeviceId, BlockRights, BlockStatus, SUPERBLOCK_BYTES};

    const BLOCK_SIZE: usize = 4096;
    const BLOCKS: usize = 2;
    const BUFFER_TOKEN: u64 = (1u64 << 32) | 7;

    struct DeviceBackend {
        bytes: [u8; BLOCK_SIZE * BLOCKS],
        calls: usize,
    }

    unsafe impl BlockServiceBackend for DeviceBackend {
        type Error = ();

        fn read_blocks(
            &mut self,
            _: BlockDeviceId,
            block: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            let start = usize::try_from(block).map_err(|_| ())? * BLOCK_SIZE;
            output.copy_from_slice(self.bytes.get(start..start + output.len()).ok_or(())?);
            self.calls += 1;
            Ok(())
        }

        fn write_blocks(
            &mut self,
            _: BlockDeviceId,
            block: u64,
            input: &[u8],
        ) -> Result<(), Self::Error> {
            let start = usize::try_from(block).map_err(|_| ())? * BLOCK_SIZE;
            self.bytes
                .get_mut(start..start + input.len())
                .ok_or(())?
                .copy_from_slice(input);
            self.calls += 1;
            Ok(())
        }

        fn flush(&mut self, _: BlockDeviceId) -> Result<(), Self::Error> {
            self.calls += 1;
            Ok(())
        }

        fn replace_superblock(
            &mut self,
            _: BlockDeviceId,
            block: u64,
            encoded: &[u8; SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            let start = usize::try_from(block).map_err(|_| ())? * BLOCK_SIZE;
            self.bytes[start..start + SUPERBLOCK_BYTES].copy_from_slice(encoded);
            self.calls += 1;
            Ok(())
        }
    }

    struct Syscalls {
        request: [u8; BLOCK_REQUEST_BYTES],
        payload_length: usize,
        capability_count: usize,
        token: u64,
        shared: [u8; BLOCK_SIZE],
        reads: usize,
        writes: usize,
        sends: usize,
        fail_read: bool,
        response: [u8; BLOCK_RESPONSE_BYTES],
    }

    impl Syscalls {
        fn request(request: BlockRequest, capability_count: usize) -> Self {
            let mut encoded = [0; BLOCK_REQUEST_BYTES];
            request.encode(&mut encoded).unwrap();
            Self {
                request: encoded,
                payload_length: BLOCK_REQUEST_BYTES,
                capability_count,
                token: if capability_count == 0 {
                    0
                } else {
                    BUFFER_TOKEN
                },
                shared: [0; BLOCK_SIZE],
                reads: 0,
                writes: 0,
                sends: 0,
                fail_read: false,
                response: [0; BLOCK_RESPONSE_BYTES],
            }
        }

        fn response(&self) -> BlockResponse {
            BlockResponse::decode(&self.response).unwrap()
        }
    }

    unsafe impl BlockServiceSyscalls for Syscalls {
        type Error = u8;

        fn receive(
            &mut self,
            payload: &mut [u8; BLOCK_REQUEST_BYTES],
            capability_tokens: &mut [u64; 1],
        ) -> Result<ReceivedBlockEnvelope, Self::Error> {
            payload.copy_from_slice(&self.request);
            capability_tokens[0] = self.token;
            Ok(ReceivedBlockEnvelope {
                payload_length: self.payload_length,
                capability_count: self.capability_count,
            })
        }

        fn read_shared(
            &mut self,
            capability: Capability,
            offset: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            self.reads += 1;
            if self.fail_read || capability.token() != BUFFER_TOKEN || offset != 0 {
                return Err(1);
            }
            output.copy_from_slice(&self.shared[..output.len()]);
            Ok(())
        }

        fn write_shared(
            &mut self,
            capability: Capability,
            offset: u64,
            input: &[u8],
        ) -> Result<(), Self::Error> {
            self.writes += 1;
            if capability.token() != BUFFER_TOKEN || offset != 0 {
                return Err(2);
            }
            self.shared[..input.len()].copy_from_slice(input);
            Ok(())
        }

        fn send_response(
            &mut self,
            response: &[u8; BLOCK_RESPONSE_BYTES],
        ) -> Result<(), Self::Error> {
            self.response = *response;
            self.sends += 1;
            Ok(())
        }

        fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error> {
            if capability.token() == BUFFER_TOKEN {
                Ok(())
            } else {
                Err(3)
            }
        }
    }

    fn principal(value: u64) -> StoragePrincipal {
        StoragePrincipal::new(value).unwrap()
    }

    fn service() -> (BlockService<1, 2>, crate::BlockSessionHandle) {
        let device = BlockDeviceId::new(7).unwrap();
        let mut service = BlockService::new();
        service
            .register_device(
                BlockDeviceDescriptor::new(device, BLOCK_SIZE as u32, BLOCKS as u64).unwrap(),
            )
            .unwrap();
        let session = service
            .grant(device, principal(1), BlockRights::ALL)
            .unwrap();
        (service, session)
    }

    fn buffers() -> (
        [u8; BLOCK_REQUEST_BYTES],
        [u64; 1],
        [u8; BLOCK_SIZE],
        [u8; BLOCK_RESPONSE_BYTES],
    ) {
        (
            [0xa5; BLOCK_REQUEST_BYTES],
            [u64::MAX; 1],
            [0xa5; BLOCK_SIZE],
            [0xa5; BLOCK_RESPONSE_BYTES],
        )
    }

    #[test]
    fn loop_orders_write_read_and_replay_before_bulk_io_and_erases_buffers() {
        let (service, session) = service();
        let mut device = DeviceBackend {
            bytes: [0; BLOCK_SIZE * BLOCKS],
            calls: 0,
        };
        let mut loop_state = BlockServiceLoop::<2>::new();
        let mut syscalls = Syscalls::request(
            BlockRequest::Write {
                request_id: 1,
                session,
                block: 0,
                byte_length: BLOCK_SIZE as u32,
            },
            1,
        );
        syscalls.shared.fill(0x5a);
        let (mut request, mut capabilities, mut scratch, mut response) = buffers();
        loop_state
            .serve_one(
                &service,
                &mut device,
                &mut syscalls,
                principal(1),
                &mut request,
                &mut capabilities,
                &mut scratch,
                &mut response,
            )
            .unwrap();
        assert_eq!(device.bytes[..BLOCK_SIZE], [0x5a; BLOCK_SIZE]);
        assert_eq!(
            (
                device.calls,
                syscalls.reads,
                syscalls.writes,
                syscalls.sends
            ),
            (1, 1, 0, 1)
        );
        assert_eq!(syscalls.response().status(), BlockStatus::Ok);
        assert!(request.iter().all(|byte| *byte == 0));
        assert_eq!(capabilities, [0]);
        assert!(scratch.iter().all(|byte| *byte == 0));
        assert!(response.iter().all(|byte| *byte == 0));

        loop_state
            .serve_one(
                &service,
                &mut device,
                &mut syscalls,
                principal(1),
                &mut request,
                &mut capabilities,
                &mut scratch,
                &mut response,
            )
            .unwrap();
        assert_eq!(syscalls.response().status(), BlockStatus::ReplayRejected);
        assert_eq!((device.calls, syscalls.reads, syscalls.sends), (1, 1, 2));

        device.bytes[BLOCK_SIZE..].fill(0x3c);
        syscalls = Syscalls::request(
            BlockRequest::Read {
                request_id: 2,
                session,
                block: 1,
                byte_length: BLOCK_SIZE as u32,
            },
            1,
        );
        loop_state
            .serve_one(
                &service,
                &mut device,
                &mut syscalls,
                principal(1),
                &mut request,
                &mut capabilities,
                &mut scratch,
                &mut response,
            )
            .unwrap();
        assert_eq!(syscalls.shared, [0x3c; BLOCK_SIZE]);
        assert_eq!(
            (
                device.calls,
                syscalls.reads,
                syscalls.writes,
                syscalls.sends
            ),
            (2, 0, 1, 1)
        );
        assert_eq!(syscalls.response().transferred(), BLOCK_SIZE as u32);
    }

    #[test]
    fn loop_rejects_envelopes_denial_and_copy_uncertainty_without_device_io() {
        let (service, session) = service();
        let mut device = DeviceBackend {
            bytes: [0; BLOCK_SIZE * BLOCKS],
            calls: 0,
        };
        let mut loop_state = BlockServiceLoop::<2>::new();
        let request_value = BlockRequest::Write {
            request_id: 10,
            session,
            block: 0,
            byte_length: BLOCK_SIZE as u32,
        };
        let mut syscalls = Syscalls::request(request_value, 0);
        let (mut request, mut capabilities, mut scratch, mut response) = buffers();
        assert_eq!(
            loop_state.serve_one(
                &service,
                &mut device,
                &mut syscalls,
                principal(1),
                &mut request,
                &mut capabilities,
                &mut scratch,
                &mut response,
            ),
            Err(BlockServiceLoopError::InvalidEnvelope)
        );
        assert_eq!((device.calls, syscalls.reads, syscalls.sends), (0, 0, 0));
        assert!(scratch.iter().all(|byte| *byte == 0));

        syscalls = Syscalls::request(request_value, 1);
        loop_state
            .serve_one(
                &service,
                &mut device,
                &mut syscalls,
                principal(2),
                &mut request,
                &mut capabilities,
                &mut scratch,
                &mut response,
            )
            .unwrap();
        assert_eq!(syscalls.response().status(), BlockStatus::Denied);
        assert_eq!((device.calls, syscalls.reads, syscalls.sends), (0, 0, 1));

        syscalls = Syscalls::request(
            BlockRequest::Write {
                request_id: 11,
                session,
                block: 0,
                byte_length: BLOCK_SIZE as u32,
            },
            1,
        );
        syscalls.fail_read = true;
        assert_eq!(
            loop_state.serve_one(
                &service,
                &mut device,
                &mut syscalls,
                principal(1),
                &mut request,
                &mut capabilities,
                &mut scratch,
                &mut response,
            ),
            Err(BlockServiceLoopError::Syscall(1))
        );
        assert_eq!((device.calls, syscalls.reads, syscalls.sends), (0, 1, 0));
        assert!(scratch.iter().all(|byte| *byte == 0));
        syscalls.fail_read = false;
        loop_state
            .serve_one(
                &service,
                &mut device,
                &mut syscalls,
                principal(1),
                &mut request,
                &mut capabilities,
                &mut scratch,
                &mut response,
            )
            .unwrap();
        assert_eq!(syscalls.response().status(), BlockStatus::ReplayRejected);
        assert_eq!((device.calls, syscalls.reads, syscalls.sends), (0, 1, 1));
    }
}
