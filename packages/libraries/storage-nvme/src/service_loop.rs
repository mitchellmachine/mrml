use crate::NvmeBlockProvider;
use mrml_interface_storage_block_provider_v1::{
    decode_enumerate_request, decode_enumerate_response, encode_enumerate_request,
    BlockProviderDevice, BlockProviderTransport, BorrowedWriteView, ProtocolError,
    ENUMERATE_REQUEST_BYTES, ENUMERATE_RESPONSE_BYTES,
};
use mrml_kernel::Capability;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedNvmeEnvelope {
    pub payload_length: usize,
    pub capability_count: usize,
}

/// # Safety
///
/// Receive must return only exact authenticated transfers. Shared writes and
/// release must resolve the received leaf; replies use launch-bound state only.
pub unsafe trait NvmeServiceSyscalls {
    type Error;
    fn receive(
        &mut self,
        request: &mut [u8; ENUMERATE_REQUEST_BYTES],
        tokens: &mut [u64; 1],
    ) -> Result<ReceivedNvmeEnvelope, Self::Error>;
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
pub enum NvmeServiceLoopError<E> {
    Syscall(E),
    Protocol(ProtocolError),
    InvalidEnvelope,
    ScratchTooSmall,
}

pub struct NvmeEnumerationServiceLoop<'a> {
    provider: NvmeBlockProvider<'a>,
}

impl<'a> NvmeEnumerationServiceLoop<'a> {
    pub const fn new(devices: &'a [BlockProviderDevice]) -> Self {
        Self {
            provider: NvmeBlockProvider::new(devices),
        }
    }

    pub fn serve_one<S: NvmeServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request: &mut [u8; ENUMERATE_REQUEST_BYTES],
        tokens: &mut [u64; 1],
        scratch: &mut [u8],
        response: &mut [u8; ENUMERATE_RESPONSE_BYTES],
    ) -> Result<(), NvmeServiceLoopError<S::Error>> {
        request.fill(0);
        tokens.fill(0);
        scratch.fill(0);
        response.fill(0);
        let result = self.serve_inner(syscalls, request, tokens, scratch, response);
        let release = (tokens[0] != 0)
            .then(|| syscalls.release_received(Capability::from_token(tokens[0])))
            .transpose()
            .map(|_| ())
            .map_err(NvmeServiceLoopError::Syscall);
        let completion = match result.and(release) {
            Ok(()) => syscalls
                .send_response(response)
                .map_err(NvmeServiceLoopError::Syscall),
            Err(error) => Err(error),
        };
        request.fill(0);
        tokens.fill(0);
        scratch.fill(0);
        response.fill(0);
        completion
    }

    fn serve_inner<S: NvmeServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; ENUMERATE_REQUEST_BYTES],
        tokens: &mut [u64; 1],
        scratch: &mut [u8],
        response: &mut [u8; ENUMERATE_RESPONSE_BYTES],
    ) -> Result<(), NvmeServiceLoopError<S::Error>> {
        let envelope = syscalls
            .receive(request_buffer, tokens)
            .map_err(NvmeServiceLoopError::Syscall)?;
        if envelope.payload_length != ENUMERATE_REQUEST_BYTES
            || envelope.capability_count != 1
            || tokens[0] == 0
            || tokens[0] >> 32 == 0
        {
            return Err(NvmeServiceLoopError::InvalidEnvelope);
        }
        let request = decode_enumerate_request(request_buffer, u64::MAX)
            .map_err(NvmeServiceLoopError::Protocol)?;
        let length = usize::try_from(request.output.length())
            .map_err(|_| NvmeServiceLoopError::ScratchTooSmall)?;
        if length == 0 || length > scratch.len() {
            return Err(NvmeServiceLoopError::ScratchTooSmall);
        }
        let output = BorrowedWriteView::within(0, length as u64, length as u64)
            .ok_or(NvmeServiceLoopError::ScratchTooSmall)?;
        let local = encode_enumerate_request(output).map_err(NvmeServiceLoopError::Protocol)?;
        *response = self
            .provider
            .enumerate(&local, &mut scratch[..length])
            .map_err(NvmeServiceLoopError::Protocol)?;
        let written = match decode_enumerate_response(response, length as u64)
            .map_err(NvmeServiceLoopError::Protocol)?
        {
            Ok(written) => {
                usize::try_from(written).map_err(|_| NvmeServiceLoopError::ScratchTooSmall)?
            }
            Err(_) => return Ok(()),
        };
        syscalls
            .write_shared(
                Capability::from_token(tokens[0]),
                request.output.offset(),
                &scratch[..written],
            )
            .map_err(NvmeServiceLoopError::Syscall)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_interface_storage_block_provider_v1::{
        encode_enumerate_request, OpaqueHandle, BLOCK_DEVICE_FLAG_FLUSH,
    };

    const TOKEN: u64 = (13_u64 << 32) | 5;
    struct Syscalls {
        request: [u8; ENUMERATE_REQUEST_BYTES],
        token: u64,
        memory: [u8; 128],
        response: Option<[u8; ENUMERATE_RESPONSE_BYTES]>,
        writes: usize,
        releases: usize,
        fail_write: bool,
    }

    unsafe impl NvmeServiceSyscalls for Syscalls {
        type Error = ();
        fn receive(
            &mut self,
            request: &mut [u8; ENUMERATE_REQUEST_BYTES],
            tokens: &mut [u64; 1],
        ) -> Result<ReceivedNvmeEnvelope, ()> {
            *request = self.request;
            tokens[0] = self.token;
            Ok(ReceivedNvmeEnvelope {
                payload_length: ENUMERATE_REQUEST_BYTES,
                capability_count: 1,
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
            session: OpaqueHandle::new(6, 14).unwrap(),
            logical_block_bytes: 4096,
            flags: BLOCK_DEVICE_FLAG_FLUSH,
            logical_block_count: 262_144,
            media_generation: 21,
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
        }
    }

    #[test]
    fn copies_catalog_releases_leaf_replies_and_wipes_buffers() {
        let devices = devices();
        let mut syscalls = syscalls();
        let mut request = [0xaa; ENUMERATE_REQUEST_BYTES];
        let mut tokens = [u64::MAX; 1];
        let mut scratch = [0xcc; 64];
        let mut response = [0xdd; ENUMERATE_RESPONSE_BYTES];
        NvmeEnumerationServiceLoop::new(&devices)
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
        assert_eq!(request, [0; ENUMERATE_REQUEST_BYTES]);
        assert_eq!(tokens, [0]);
        assert_eq!(scratch, [0; 64]);
        assert_eq!(response, [0; ENUMERATE_RESPONSE_BYTES]);
    }

    #[test]
    fn failure_or_invalid_transfer_never_replies_and_releases_when_possible() {
        let devices = devices();
        let mut failed = syscalls();
        failed.fail_write = true;
        assert_eq!(
            NvmeEnumerationServiceLoop::new(&devices).serve_one(
                &mut failed,
                &mut [0; ENUMERATE_REQUEST_BYTES],
                &mut [0; 1],
                &mut [0; 64],
                &mut [0; ENUMERATE_RESPONSE_BYTES],
            ),
            Err(NvmeServiceLoopError::Syscall(()))
        );
        assert_eq!((failed.releases, failed.response), (1, None));
        let mut invalid = syscalls();
        invalid.token = 7;
        assert_eq!(
            NvmeEnumerationServiceLoop::new(&devices).serve_one(
                &mut invalid,
                &mut [0; ENUMERATE_REQUEST_BYTES],
                &mut [0; 1],
                &mut [0; 64],
                &mut [0; ENUMERATE_RESPONSE_BYTES],
            ),
            Err(NvmeServiceLoopError::InvalidEnvelope)
        );
        assert_eq!((invalid.writes, invalid.response), (0, None));
    }
}
