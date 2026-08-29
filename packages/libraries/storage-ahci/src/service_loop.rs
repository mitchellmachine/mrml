use crate::AhciBlockProvider;
use mrml_interface_storage_block_provider_v1::{
    decode_enumerate_request, decode_enumerate_response, encode_enumerate_request,
    BlockProviderDevice, BlockProviderTransport, BorrowedWriteView, ProtocolError,
    ENUMERATE_REQUEST_BYTES, ENUMERATE_RESPONSE_BYTES,
};
use mrml_kernel::Capability;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedAhciEnvelope {
    pub payload_length: usize,
    pub capability_count: usize,
}

/// Narrow runtime boundary for the isolated AHCI provider.
///
/// # Safety
///
/// `receive` must return only tokens transferred by the authenticated storage
/// service. Shared writes must resolve that exact received object; replies must
/// target only launch-bound state; release must enter transitive revocation.
pub unsafe trait AhciServiceSyscalls {
    type Error;

    fn receive(
        &mut self,
        request: &mut [u8; ENUMERATE_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedAhciEnvelope, Self::Error>;

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
pub enum AhciServiceLoopError<E> {
    Syscall(E),
    Protocol(ProtocolError),
    InvalidEnvelope,
    ScratchTooSmall,
}

pub struct AhciEnumerationServiceLoop<'a> {
    provider: AhciBlockProvider<'a>,
}

impl<'a> AhciEnumerationServiceLoop<'a> {
    pub const fn new(devices: &'a [BlockProviderDevice]) -> Self {
        Self {
            provider: AhciBlockProvider::new(devices),
        }
    }

    pub fn serve_one<S: AhciServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; ENUMERATE_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        scratch: &mut [u8],
        response_buffer: &mut [u8; ENUMERATE_RESPONSE_BYTES],
    ) -> Result<(), AhciServiceLoopError<S::Error>> {
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
            .map_err(AhciServiceLoopError::Syscall);
        let completion = match result.and(release) {
            Ok(()) => syscalls
                .send_response(response_buffer)
                .map_err(AhciServiceLoopError::Syscall),
            Err(error) => Err(error),
        };
        request_buffer.fill(0);
        capability_tokens.fill(0);
        scratch.fill(0);
        response_buffer.fill(0);
        completion
    }

    fn serve_one_inner<S: AhciServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; ENUMERATE_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        scratch: &mut [u8],
        response_buffer: &mut [u8; ENUMERATE_RESPONSE_BYTES],
    ) -> Result<(), AhciServiceLoopError<S::Error>> {
        let envelope = syscalls
            .receive(request_buffer, capability_tokens)
            .map_err(AhciServiceLoopError::Syscall)?;
        if envelope.payload_length != ENUMERATE_REQUEST_BYTES
            || envelope.capability_count != 1
            || capability_tokens[0] == 0
            || capability_tokens[0] >> 32 == 0
        {
            return Err(AhciServiceLoopError::InvalidEnvelope);
        }
        let request = decode_enumerate_request(request_buffer, u64::MAX)
            .map_err(AhciServiceLoopError::Protocol)?;
        let length = usize::try_from(request.output.length())
            .map_err(|_| AhciServiceLoopError::ScratchTooSmall)?;
        if length == 0 || length > scratch.len() {
            return Err(AhciServiceLoopError::ScratchTooSmall);
        }
        let local_output = BorrowedWriteView::within(0, length as u64, length as u64)
            .ok_or(AhciServiceLoopError::ScratchTooSmall)?;
        let local_request =
            encode_enumerate_request(local_output).map_err(AhciServiceLoopError::Protocol)?;
        *response_buffer = self
            .provider
            .enumerate(&local_request, &mut scratch[..length])
            .map_err(AhciServiceLoopError::Protocol)?;
        let written = match decode_enumerate_response(response_buffer, length as u64)
            .map_err(AhciServiceLoopError::Protocol)?
        {
            Ok(written) => written,
            Err(_) => return Ok(()),
        };
        let written =
            usize::try_from(written).map_err(|_| AhciServiceLoopError::ScratchTooSmall)?;
        syscalls
            .write_shared(
                Capability::from_token(capability_tokens[0]),
                request.output.offset(),
                &scratch[..written],
            )
            .map_err(AhciServiceLoopError::Syscall)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_interface_storage_block_provider_v1::{
        encode_enumerate_request, OpaqueHandle, BLOCK_DEVICE_FLAG_FLUSH,
    };

    const TOKEN: u64 = (9_u64 << 32) | 4;

    struct Syscalls {
        request: [u8; ENUMERATE_REQUEST_BYTES],
        token: u64,
        shared: [u8; 128],
        response: Option<[u8; ENUMERATE_RESPONSE_BYTES]>,
        writes: usize,
        releases: usize,
        fail_write: bool,
    }

    unsafe impl AhciServiceSyscalls for Syscalls {
        type Error = ();

        fn receive(
            &mut self,
            request: &mut [u8; ENUMERATE_REQUEST_BYTES],
            capability_tokens: &mut [u64; 1],
        ) -> Result<ReceivedAhciEnvelope, Self::Error> {
            *request = self.request;
            capability_tokens[0] = self.token;
            Ok(ReceivedAhciEnvelope {
                payload_length: ENUMERATE_REQUEST_BYTES,
                capability_count: 1,
            })
        }

        fn write_shared(
            &mut self,
            capability: Capability,
            offset: u64,
            input: &[u8],
        ) -> Result<(), Self::Error> {
            assert_eq!(capability.token(), self.token);
            self.writes += 1;
            if self.fail_write {
                return Err(());
            }
            let start = usize::try_from(offset).map_err(|_| ())?;
            self.shared
                .get_mut(start..start + input.len())
                .ok_or(())?
                .copy_from_slice(input);
            Ok(())
        }

        fn send_response(
            &mut self,
            response: &[u8; ENUMERATE_RESPONSE_BYTES],
        ) -> Result<(), Self::Error> {
            self.response = Some(*response);
            Ok(())
        }

        fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error> {
            assert_eq!(capability.token(), self.token);
            self.releases += 1;
            Ok(())
        }
    }

    fn devices() -> [BlockProviderDevice; 1] {
        [BlockProviderDevice {
            session: OpaqueHandle::new(4, 8).unwrap(),
            logical_block_bytes: 512,
            flags: BLOCK_DEVICE_FLAG_FLUSH,
            logical_block_count: 65_536,
            media_generation: 12,
        }]
    }

    fn syscalls() -> Syscalls {
        Syscalls {
            request: encode_enumerate_request(BorrowedWriteView::within(32, 48, 128).unwrap())
                .unwrap(),
            token: TOKEN,
            shared: [0xa5; 128],
            response: None,
            writes: 0,
            releases: 0,
            fail_write: false,
        }
    }

    #[test]
    fn serves_catalog_then_releases_before_reply_and_wipes_scratch() {
        let devices = devices();
        let mut syscalls = syscalls();
        let mut request = [0xaa; ENUMERATE_REQUEST_BYTES];
        let mut tokens = [0xbb; 1];
        let mut scratch = [0xcc; 64];
        let mut response = [0xdd; ENUMERATE_RESPONSE_BYTES];
        AhciEnumerationServiceLoop::new(&devices)
            .serve_one(
                &mut syscalls,
                &mut request,
                &mut tokens,
                &mut scratch,
                &mut response,
            )
            .unwrap();
        assert_eq!((syscalls.writes, syscalls.releases), (1, 1));
        assert_eq!(&syscalls.shared[32..40], b"MRMLBLK\0");
        assert!(syscalls.response.is_some());
        assert_eq!(request, [0; ENUMERATE_REQUEST_BYTES]);
        assert_eq!(tokens, [0; 1]);
        assert_eq!(scratch, [0; 64]);
        assert_eq!(response, [0; ENUMERATE_RESPONSE_BYTES]);
    }

    #[test]
    fn failed_copy_back_releases_leaf_without_reply() {
        let devices = devices();
        let mut syscalls = syscalls();
        syscalls.fail_write = true;
        let result = AhciEnumerationServiceLoop::new(&devices).serve_one(
            &mut syscalls,
            &mut [0; ENUMERATE_REQUEST_BYTES],
            &mut [0; 1],
            &mut [0; 64],
            &mut [0; ENUMERATE_RESPONSE_BYTES],
        );
        assert_eq!(result, Err(AhciServiceLoopError::Syscall(())));
        assert_eq!(syscalls.releases, 1);
        assert_eq!(syscalls.response, None);
    }

    #[test]
    fn rejects_untransferred_capability_before_copy_back() {
        let devices = devices();
        for token in [0, 7] {
            let mut syscalls = syscalls();
            syscalls.token = token;
            let result = AhciEnumerationServiceLoop::new(&devices).serve_one(
                &mut syscalls,
                &mut [0; ENUMERATE_REQUEST_BYTES],
                &mut [0; 1],
                &mut [0; 64],
                &mut [0; ENUMERATE_RESPONSE_BYTES],
            );
            assert_eq!(result, Err(AhciServiceLoopError::InvalidEnvelope));
            assert_eq!(syscalls.writes, 0);
            assert_eq!(syscalls.response, None);
        }
    }
}
