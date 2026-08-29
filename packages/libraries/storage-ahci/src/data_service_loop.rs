//! Isolated canonical read/write dispatch for the AHCI provider.

use crate::{AhciBlockIoAdapter, AhciBlockIoBackend};
use mrml_interface_storage_block_provider_v1::{
    decode_read_request, decode_read_response, decode_write_request, decode_write_response,
    encode_read_request, encode_write_request, BlockProviderDevice, BlockProviderReadTransport,
    BlockProviderWriteTransport, BorrowedReadView, BorrowedWriteView, ProtocolError,
    READ_REQUEST_BYTES, READ_RESPONSE_BYTES, WRITE_REQUEST_BYTES, WRITE_RESPONSE_BYTES,
};
use mrml_kernel::Capability;

const _: () = assert!(READ_REQUEST_BYTES == WRITE_REQUEST_BYTES);
const _: () = assert!(READ_RESPONSE_BYTES == WRITE_RESPONSE_BYTES);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedAhciDataEnvelope {
    pub payload_length: usize,
    pub capability_count: usize,
}

/// Narrow syscall boundary for one isolated AHCI read/write request.
///
/// # Safety
///
/// `receive` must accept only the launch-bound storage-service endpoint.
/// Shared access must resolve only the exact transferred capability, and
/// release must enter transitive revocation before any response is sent.
pub unsafe trait AhciDataServiceSyscalls {
    type Error;

    fn receive(
        &mut self,
        request: &mut [u8; READ_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedAhciDataEnvelope, Self::Error>;

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

    fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error>;
    fn send_response(&mut self, response: &[u8; READ_RESPONSE_BYTES]) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciDataServiceLoopError<E> {
    Syscall(E),
    Protocol(ProtocolError),
    InvalidEnvelope,
    ScratchTooSmall,
}

pub struct AhciReadWriteServiceLoop<'a, B> {
    adapter: AhciBlockIoAdapter<'a, B>,
}

impl<'a, B> AhciReadWriteServiceLoop<'a, B> {
    pub const fn new(devices: &'a [BlockProviderDevice], backend: B) -> Self {
        Self {
            adapter: AhciBlockIoAdapter::new(devices, backend),
        }
    }

    pub fn into_backend(self) -> B {
        self.adapter.into_backend()
    }
}

impl<B: AhciBlockIoBackend> AhciReadWriteServiceLoop<'_, B> {
    pub fn serve_one<S: AhciDataServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; READ_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        scratch: &mut [u8],
        response_buffer: &mut [u8; READ_RESPONSE_BYTES],
    ) -> Result<(), AhciDataServiceLoopError<S::Error>> {
        request_buffer.fill(0);
        capability_tokens.fill(0);
        scratch.fill(0);
        response_buffer.fill(0);
        let result = self.serve_one_inner(
            syscalls,
            request_buffer,
            capability_tokens,
            scratch,
            response_buffer,
        );
        let release = (capability_tokens[0] != 0)
            .then(|| syscalls.release_received(Capability::from_token(capability_tokens[0])))
            .transpose()
            .map(|_| ())
            .map_err(AhciDataServiceLoopError::Syscall);
        let completion = match result.and(release) {
            Ok(()) => syscalls
                .send_response(response_buffer)
                .map_err(AhciDataServiceLoopError::Syscall),
            Err(error) => Err(error),
        };
        request_buffer.fill(0);
        capability_tokens.fill(0);
        scratch.fill(0);
        response_buffer.fill(0);
        completion
    }

    fn serve_one_inner<S: AhciDataServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; READ_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        scratch: &mut [u8],
        response_buffer: &mut [u8; READ_RESPONSE_BYTES],
    ) -> Result<(), AhciDataServiceLoopError<S::Error>> {
        let envelope = syscalls
            .receive(request_buffer, capability_tokens)
            .map_err(AhciDataServiceLoopError::Syscall)?;
        if envelope.payload_length != READ_REQUEST_BYTES
            || envelope.capability_count != 1
            || capability_tokens[0] == 0
            || capability_tokens[0] >> 32 == 0
        {
            return Err(AhciDataServiceLoopError::InvalidEnvelope);
        }
        let capability = Capability::from_token(capability_tokens[0]);

        if let Ok(request) = decode_read_request(request_buffer, u64::MAX) {
            let length = exact_scratch_length(request.output.length(), scratch.len())?;
            let local_output = BorrowedWriteView::within(0, length as u64, length as u64)
                .ok_or(AhciDataServiceLoopError::ScratchTooSmall)?;
            let local_request = encode_read_request(
                request.session,
                request.lba,
                request.sector_count,
                local_output,
            )
            .map_err(AhciDataServiceLoopError::Protocol)?;
            *response_buffer = self
                .adapter
                .read(&local_request, &mut scratch[..length])
                .map_err(AhciDataServiceLoopError::Protocol)?;
            if decode_read_response(response_buffer, length as u64)
                .map_err(AhciDataServiceLoopError::Protocol)?
                .is_ok()
            {
                syscalls
                    .write_shared(capability, request.output.offset(), &scratch[..length])
                    .map_err(AhciDataServiceLoopError::Syscall)?;
            }
            return Ok(());
        }

        let request = decode_write_request(request_buffer, u64::MAX)
            .map_err(AhciDataServiceLoopError::Protocol)?;
        let length = exact_scratch_length(request.input.length(), scratch.len())?;
        syscalls
            .read_shared(capability, request.input.offset(), &mut scratch[..length])
            .map_err(AhciDataServiceLoopError::Syscall)?;
        let local_input = BorrowedReadView::within(0, length as u64, length as u64)
            .ok_or(AhciDataServiceLoopError::ScratchTooSmall)?;
        let local_request = encode_write_request(
            request.session,
            request.lba,
            request.sector_count,
            local_input,
        )
        .map_err(AhciDataServiceLoopError::Protocol)?;
        *response_buffer = self
            .adapter
            .write(&local_request, &scratch[..length])
            .map_err(AhciDataServiceLoopError::Protocol)?;
        let _result = decode_write_response(response_buffer, length as u64)
            .map_err(AhciDataServiceLoopError::Protocol)?;
        Ok(())
    }
}

fn exact_scratch_length<E>(
    length: u64,
    available: usize,
) -> Result<usize, AhciDataServiceLoopError<E>> {
    let length = usize::try_from(length).map_err(|_| AhciDataServiceLoopError::ScratchTooSmall)?;
    if length == 0 || length > available {
        return Err(AhciDataServiceLoopError::ScratchTooSmall);
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AhciBlockIoError;
    use mrml_interface_storage_block_provider_v1::{
        encode_read_request, encode_write_request, OpaqueHandle,
    };

    const TOKEN: u64 = (9_u64 << 32) | 4;

    #[derive(Default)]
    struct Backend {
        reads: usize,
        writes: usize,
    }
    impl AhciBlockIoBackend for Backend {
        fn read(
            &mut self,
            _: BlockProviderDevice,
            _: u64,
            _: u32,
            output: &mut [u8],
        ) -> Result<(), AhciBlockIoError> {
            self.reads += 1;
            output.fill(0x5a);
            Ok(())
        }
        fn write(
            &mut self,
            _: BlockProviderDevice,
            _: u64,
            _: u32,
            input: &[u8],
        ) -> Result<(), AhciBlockIoError> {
            if input.iter().any(|byte| *byte != 0xa5) {
                return Err(AhciBlockIoError::IoFailure);
            }
            self.writes += 1;
            Ok(())
        }
    }

    struct Syscalls {
        request: [u8; READ_REQUEST_BYTES],
        shared: [u8; 1024],
        response: Option<[u8; 16]>,
        reads: usize,
        writes: usize,
        releases: usize,
    }
    unsafe impl AhciDataServiceSyscalls for Syscalls {
        type Error = ();
        fn receive(
            &mut self,
            request: &mut [u8; READ_REQUEST_BYTES],
            tokens: &mut [u64; 1],
        ) -> Result<ReceivedAhciDataEnvelope, ()> {
            *request = self.request;
            tokens[0] = TOKEN;
            Ok(ReceivedAhciDataEnvelope {
                payload_length: READ_REQUEST_BYTES,
                capability_count: 1,
            })
        }
        fn read_shared(
            &mut self,
            capability: Capability,
            offset: u64,
            output: &mut [u8],
        ) -> Result<(), ()> {
            assert_eq!(capability.token(), TOKEN);
            self.reads += 1;
            let start = offset as usize;
            output.copy_from_slice(&self.shared[start..start + output.len()]);
            Ok(())
        }
        fn write_shared(
            &mut self,
            capability: Capability,
            offset: u64,
            input: &[u8],
        ) -> Result<(), ()> {
            assert_eq!(capability.token(), TOKEN);
            self.writes += 1;
            let start = offset as usize;
            self.shared[start..start + input.len()].copy_from_slice(input);
            Ok(())
        }
        fn release_received(&mut self, capability: Capability) -> Result<(), ()> {
            assert_eq!(capability.token(), TOKEN);
            self.releases += 1;
            Ok(())
        }
        fn send_response(&mut self, response: &[u8; 16]) -> Result<(), ()> {
            self.response = Some(*response);
            Ok(())
        }
    }

    fn device() -> BlockProviderDevice {
        BlockProviderDevice {
            session: OpaqueHandle::new(3, 7).unwrap(),
            logical_block_bytes: 512,
            flags: 0,
            logical_block_count: 100,
            media_generation: 11,
        }
    }

    #[test]
    fn read_copies_out_then_releases_before_reply_and_wipes() {
        let devices = [device()];
        let request = encode_read_request(
            device().session,
            4,
            1,
            BorrowedWriteView::within(64, 512, 1024).unwrap(),
        )
        .unwrap();
        let mut syscalls = Syscalls {
            request,
            shared: [0; 1024],
            response: None,
            reads: 0,
            writes: 0,
            releases: 0,
        };
        let mut request_buffer = [0xaa; READ_REQUEST_BYTES];
        let mut tokens = [0xbb];
        let mut scratch = [0xcc; 512];
        let mut response = [0xdd; 16];
        let mut service = AhciReadWriteServiceLoop::new(&devices, Backend::default());
        service
            .serve_one(
                &mut syscalls,
                &mut request_buffer,
                &mut tokens,
                &mut scratch,
                &mut response,
            )
            .unwrap();
        assert_eq!(
            (syscalls.reads, syscalls.writes, syscalls.releases),
            (0, 1, 1)
        );
        assert!(syscalls.shared[64..576].iter().all(|byte| *byte == 0x5a));
        assert!(syscalls.response.is_some());
        assert_eq!(request_buffer, [0; READ_REQUEST_BYTES]);
        assert_eq!(tokens, [0]);
        assert_eq!(scratch, [0; 512]);
        assert_eq!(response, [0; 16]);
    }

    #[test]
    fn write_copies_in_once_and_never_writes_shared_memory() {
        let devices = [device()];
        let request = encode_write_request(
            device().session,
            4,
            1,
            BorrowedReadView::within(64, 512, 1024).unwrap(),
        )
        .unwrap();
        let mut shared = [0; 1024];
        shared[64..576].fill(0xa5);
        let mut syscalls = Syscalls {
            request,
            shared,
            response: None,
            reads: 0,
            writes: 0,
            releases: 0,
        };
        let mut service = AhciReadWriteServiceLoop::new(&devices, Backend::default());
        service
            .serve_one(
                &mut syscalls,
                &mut [0; READ_REQUEST_BYTES],
                &mut [0; 1],
                &mut [0; 512],
                &mut [0; 16],
            )
            .unwrap();
        assert_eq!(
            (syscalls.reads, syscalls.writes, syscalls.releases),
            (1, 0, 1)
        );
        let backend = service.into_backend();
        assert_eq!((backend.reads, backend.writes), (0, 1));
    }
}
