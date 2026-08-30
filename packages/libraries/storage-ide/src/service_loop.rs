use crate::IdeBlockProvider;
use mrml_interface_storage_block_provider_v1::{
    decode_enumerate_request, decode_enumerate_response, encode_enumerate_request,
    BlockProviderDevice, BlockProviderTransport, BorrowedWriteView, ProtocolError,
    ENUMERATE_REQUEST_BYTES, ENUMERATE_RESPONSE_BYTES,
};
use mrml_kernel::Capability;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedIdeEnvelope {
    pub payload_length: usize,
    pub capability_count: usize,
}

/// # Safety
///
/// Receive returns only authenticated transfers. Shared writes and release
/// resolve the exact received leaf; replies use immutable launch state only.
pub unsafe trait IdeServiceSyscalls {
    type Error;
    fn receive(
        &mut self,
        request: &mut [u8; ENUMERATE_REQUEST_BYTES],
        tokens: &mut [u64; 1],
    ) -> Result<ReceivedIdeEnvelope, Self::Error>;
    fn write_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Self::Error>;
    fn send_response(
        &mut self,
        response: &[u8; ENUMERATE_RESPONSE_BYTES],
    ) -> Result<(), Self::Error>;
    fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdeServiceLoopError<E> {
    Syscall(E),
    Protocol(ProtocolError),
    InvalidEnvelope,
    ScratchTooSmall,
}

pub struct IdeEnumerationServiceLoop<'a> {
    provider: IdeBlockProvider<'a>,
}

impl<'a> IdeEnumerationServiceLoop<'a> {
    pub const fn new(devices: &'a [BlockProviderDevice]) -> Self {
        Self {
            provider: IdeBlockProvider::new(devices),
        }
    }

    pub fn serve_one<S: IdeServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request: &mut [u8; ENUMERATE_REQUEST_BYTES],
        tokens: &mut [u64; 1],
        scratch: &mut [u8],
        response: &mut [u8; ENUMERATE_RESPONSE_BYTES],
    ) -> Result<(), IdeServiceLoopError<S::Error>> {
        request.fill(0);
        tokens.fill(0);
        scratch.fill(0);
        response.fill(0);
        let mut received_capability = None;
        let result = self.serve_inner(
            syscalls,
            request,
            tokens,
            scratch,
            response,
            &mut received_capability,
        );
        let release = received_capability
            .map(|capability| syscalls.release_received(capability))
            .transpose()
            .map(|_| ())
            .map_err(IdeServiceLoopError::Syscall);
        let completion = match result.and(release) {
            Ok(()) => syscalls
                .send_response(response)
                .map_err(IdeServiceLoopError::Syscall),
            Err(error) => Err(error),
        };
        request.fill(0);
        tokens.fill(0);
        scratch.fill(0);
        response.fill(0);
        completion
    }

    fn serve_inner<S: IdeServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; ENUMERATE_REQUEST_BYTES],
        tokens: &mut [u64; 1],
        scratch: &mut [u8],
        response: &mut [u8; ENUMERATE_RESPONSE_BYTES],
        received_capability: &mut Option<Capability>,
    ) -> Result<(), IdeServiceLoopError<S::Error>> {
        let envelope = syscalls
            .receive(request_buffer, tokens)
            .map_err(IdeServiceLoopError::Syscall)?;
        if envelope.payload_length != ENUMERATE_REQUEST_BYTES
            || envelope.capability_count != 1
            || tokens[0] == 0
            || tokens[0] >> 32 == 0
        {
            return Err(IdeServiceLoopError::InvalidEnvelope);
        }
        *received_capability = Some(Capability::from_token(tokens[0]));
        let request = decode_enumerate_request(request_buffer, u64::MAX)
            .map_err(IdeServiceLoopError::Protocol)?;
        let length = usize::try_from(request.output.length())
            .map_err(|_| IdeServiceLoopError::ScratchTooSmall)?;
        if length == 0 || length > scratch.len() {
            return Err(IdeServiceLoopError::ScratchTooSmall);
        }
        let output = BorrowedWriteView::within(0, length as u64, length as u64)
            .ok_or(IdeServiceLoopError::ScratchTooSmall)?;
        let local = encode_enumerate_request(output).map_err(IdeServiceLoopError::Protocol)?;
        *response = self
            .provider
            .enumerate(&local, &mut scratch[..length])
            .map_err(IdeServiceLoopError::Protocol)?;
        let written = match decode_enumerate_response(response, length as u64)
            .map_err(IdeServiceLoopError::Protocol)?
        {
            Ok(written) => {
                usize::try_from(written).map_err(|_| IdeServiceLoopError::ScratchTooSmall)?
            }
            Err(_) => return Ok(()),
        };
        syscalls
            .write_shared(
                Capability::from_token(tokens[0]),
                request.output.offset(),
                &scratch[..written],
            )
            .map_err(IdeServiceLoopError::Syscall)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_interface_storage_block_provider_v1::{
        encode_enumerate_request, OpaqueHandle, BLOCK_DEVICE_FLAG_FLUSH,
    };

    const TOKEN: u64 = (17_u64 << 32) | 6;
    struct Syscalls {
        request: [u8; ENUMERATE_REQUEST_BYTES],
        token: u64,
        memory: [u8; 128],
        response: Option<[u8; ENUMERATE_RESPONSE_BYTES]>,
        writes: usize,
        releases: usize,
        fail_write: bool,
        capability_count: usize,
    }

    unsafe impl IdeServiceSyscalls for Syscalls {
        type Error = ();
        fn receive(
            &mut self,
            request: &mut [u8; ENUMERATE_REQUEST_BYTES],
            tokens: &mut [u64; 1],
        ) -> Result<ReceivedIdeEnvelope, ()> {
            *request = self.request;
            tokens[0] = self.token;
            Ok(ReceivedIdeEnvelope {
                payload_length: ENUMERATE_REQUEST_BYTES,
                capability_count: self.capability_count,
            })
        }
        fn write_shared(
            &mut self,
            capability: Capability,
            offset: u64,
            input: &[u8],
        ) -> Result<(), ()> {
            assert_eq!(capability.token(), self.token);
            self.writes += 1;
            if self.fail_write {
                return Err(());
            }
            let start = usize::try_from(offset).map_err(|_| ())?;
            self.memory[start..start + input.len()].copy_from_slice(input);
            Ok(())
        }
        fn send_response(&mut self, response: &[u8; ENUMERATE_RESPONSE_BYTES]) -> Result<(), ()> {
            self.response = Some(*response);
            Ok(())
        }
        fn release_received(&mut self, capability: Capability) -> Result<(), ()> {
            assert_eq!(capability.token(), self.token);
            self.releases += 1;
            Ok(())
        }
    }

    fn devices() -> [BlockProviderDevice; 1] {
        [BlockProviderDevice {
            session: OpaqueHandle::new(2, 5).unwrap(),
            logical_block_bytes: 512,
            flags: BLOCK_DEVICE_FLAG_FLUSH,
            logical_block_count: 131_072,
            media_generation: 11,
        }]
    }
    fn syscalls() -> Syscalls {
        Syscalls {
            request: encode_enumerate_request(BorrowedWriteView::within(32, 48, 128).unwrap())
                .unwrap(),
            token: TOKEN,
            memory: [0xa5; 128],
            response: None,
            writes: 0,
            releases: 0,
            fail_write: false,
            capability_count: 1,
        }
    }

    #[test]
    fn copies_catalog_releases_replies_and_wipes_buffers() {
        let devices = devices();
        let mut syscalls = syscalls();
        let mut request = [0xaa; ENUMERATE_REQUEST_BYTES];
        let mut tokens = [u64::MAX; 1];
        let mut scratch = [0xcc; 64];
        let mut response = [0xdd; ENUMERATE_RESPONSE_BYTES];
        IdeEnumerationServiceLoop::new(&devices)
            .serve_one(
                &mut syscalls,
                &mut request,
                &mut tokens,
                &mut scratch,
                &mut response,
            )
            .unwrap();
        assert_eq!((syscalls.writes, syscalls.releases), (1, 1));
        assert_eq!(&syscalls.memory[32..40], b"MRMLBLK\0");
        assert!(syscalls.response.is_some());
        assert_eq!(
            (request, tokens, scratch, response),
            ([0; 88], [0], [0; 64], [0; 16])
        );
    }

    #[test]
    fn failures_never_reply_and_release_when_possible() {
        let devices = devices();
        let mut failed = syscalls();
        failed.fail_write = true;
        assert_eq!(
            IdeEnumerationServiceLoop::new(&devices).serve_one(
                &mut failed,
                &mut [0; ENUMERATE_REQUEST_BYTES],
                &mut [0; 1],
                &mut [0; 64],
                &mut [0; ENUMERATE_RESPONSE_BYTES],
            ),
            Err(IdeServiceLoopError::Syscall(()))
        );
        assert_eq!((failed.releases, failed.response), (1, None));
        for (token, capability_count) in [(0, 1), (7, 1), (TOKEN, 0)] {
            let mut invalid = syscalls();
            invalid.token = token;
            invalid.capability_count = capability_count;
            assert_eq!(
                IdeEnumerationServiceLoop::new(&devices).serve_one(
                    &mut invalid,
                    &mut [0; ENUMERATE_REQUEST_BYTES],
                    &mut [0; 1],
                    &mut [0; 64],
                    &mut [0; ENUMERATE_RESPONSE_BYTES],
                ),
                Err(IdeServiceLoopError::InvalidEnvelope)
            );
            assert_eq!(
                (invalid.writes, invalid.releases, invalid.response),
                (0, 0, None)
            );
        }
    }
}
