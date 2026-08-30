use crate::Fat32Provider;
use mrml_interface_storage_filesystem_v3::{
    decode_probe_request, encode_probe_request, BorrowedReadView, FilesystemTransport,
    ProtocolError, PROBE_REQUEST_BYTES, PROBE_RESPONSE_BYTES,
};
use mrml_kernel::Capability;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedFat32Envelope {
    pub payload_length: usize,
    pub capability_count: usize,
}

/// Narrow runtime boundary for the isolated FAT32 provider.
///
/// # Safety
///
/// `receive` must return only capability tokens transferred by the exact
/// authenticated caller. Shared reads must resolve the exact received object;
/// replies must target only launch-bound state; release must enter transitive
/// revocation for the received leaf.
pub unsafe trait Fat32ServiceSyscalls {
    type Error;

    fn receive(
        &mut self,
        request: &mut [u8; PROBE_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedFat32Envelope, Self::Error>;

    fn read_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error>;

    fn send_response(&mut self, response: &[u8; PROBE_RESPONSE_BYTES]) -> Result<(), Self::Error>;

    fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fat32ServiceLoopError<E> {
    Syscall(E),
    Protocol(ProtocolError),
    InvalidEnvelope,
    ScratchTooSmall,
}

pub struct Fat32ServiceLoop {
    provider: Fat32Provider,
}

impl Fat32ServiceLoop {
    pub const fn new() -> Self {
        Self {
            provider: Fat32Provider,
        }
    }

    pub fn serve_one<S: Fat32ServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; PROBE_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        scratch: &mut [u8],
        response_buffer: &mut [u8; PROBE_RESPONSE_BYTES],
    ) -> Result<(), Fat32ServiceLoopError<S::Error>> {
        request_buffer.fill(0);
        capability_tokens.fill(0);
        scratch.fill(0);
        response_buffer.fill(0);
        let mut received_capability = None;
        let result = self.serve_one_inner(
            syscalls,
            request_buffer,
            capability_tokens,
            scratch,
            response_buffer,
            &mut received_capability,
        );
        let release = received_capability
            .map(|capability| syscalls.release_received(capability))
            .transpose()
            .map(|_| ())
            .map_err(Fat32ServiceLoopError::Syscall);
        let completion = match result.and(release) {
            Ok(()) => syscalls
                .send_response(response_buffer)
                .map_err(Fat32ServiceLoopError::Syscall),
            Err(error) => Err(error),
        };
        request_buffer.fill(0);
        capability_tokens.fill(0);
        scratch.fill(0);
        response_buffer.fill(0);
        completion
    }

    fn serve_one_inner<S: Fat32ServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; PROBE_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        scratch: &mut [u8],
        response_buffer: &mut [u8; PROBE_RESPONSE_BYTES],
        received_capability: &mut Option<Capability>,
    ) -> Result<(), Fat32ServiceLoopError<S::Error>> {
        let envelope = syscalls
            .receive(request_buffer, capability_tokens)
            .map_err(Fat32ServiceLoopError::Syscall)?;
        if envelope.payload_length != PROBE_REQUEST_BYTES
            || envelope.capability_count != 1
            || capability_tokens[0] == 0
            || capability_tokens[0] >> 32 == 0
        {
            return Err(Fat32ServiceLoopError::InvalidEnvelope);
        }
        let capability = Capability::from_token(capability_tokens[0]);
        *received_capability = Some(capability);
        let request = decode_probe_request(request_buffer, u64::MAX)
            .map_err(Fat32ServiceLoopError::Protocol)?;
        let length = usize::try_from(request.header.length())
            .map_err(|_| Fat32ServiceLoopError::ScratchTooSmall)?;
        if length == 0 || length > scratch.len() {
            return Err(Fat32ServiceLoopError::ScratchTooSmall);
        }
        syscalls
            .read_shared(capability, request.header.offset(), &mut scratch[..length])
            .map_err(Fat32ServiceLoopError::Syscall)?;
        let local_header = BorrowedReadView::within(0, length as u64, length as u64)
            .ok_or(Fat32ServiceLoopError::ScratchTooSmall)?;
        let local_request = encode_probe_request(request.volume, local_header)
            .map_err(Fat32ServiceLoopError::Protocol)?;
        *response_buffer = self
            .provider
            .probe(&local_request, &mut scratch[..length])
            .map_err(Fat32ServiceLoopError::Protocol)?;
        Ok(())
    }
}

impl Default for Fat32ServiceLoop {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_interface_storage_filesystem_v3::{
        decode_probe_response, encode_probe_request, OpaqueHandle, ProbeError,
    };

    const TOKEN: u64 = (9_u64 << 32) | 4;

    struct Syscalls {
        request: [u8; PROBE_REQUEST_BYTES],
        token: u64,
        shared: [u8; 1024],
        response: Option<[u8; PROBE_RESPONSE_BYTES]>,
        capability_count: usize,
        reads: usize,
        releases: usize,
        fail_read: bool,
    }

    unsafe impl Fat32ServiceSyscalls for Syscalls {
        type Error = ();

        fn receive(
            &mut self,
            request: &mut [u8; PROBE_REQUEST_BYTES],
            capability_tokens: &mut [u64; 1],
        ) -> Result<ReceivedFat32Envelope, Self::Error> {
            *request = self.request;
            capability_tokens[0] = self.token;
            Ok(ReceivedFat32Envelope {
                payload_length: PROBE_REQUEST_BYTES,
                capability_count: self.capability_count,
            })
        }

        fn read_shared(
            &mut self,
            capability: Capability,
            offset: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            assert_eq!(capability.token(), self.token);
            self.reads += 1;
            if self.fail_read {
                return Err(());
            }
            let start = usize::try_from(offset).map_err(|_| ())?;
            output.copy_from_slice(self.shared.get(start..start + output.len()).ok_or(())?);
            Ok(())
        }

        fn send_response(
            &mut self,
            response: &[u8; PROBE_RESPONSE_BYTES],
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

    fn syscalls() -> Syscalls {
        let header = BorrowedReadView::within(64, 512, 1024).unwrap();
        let request = encode_probe_request(OpaqueHandle::new(3, 8).unwrap(), header).unwrap();
        let mut shared = [0; 1024];
        shared[64..576].copy_from_slice(&crate::tests::boot_sector());
        Syscalls {
            request,
            token: TOKEN,
            shared,
            response: None,
            capability_count: 1,
            reads: 0,
            releases: 0,
            fail_read: false,
        }
    }

    #[test]
    fn serves_canonical_probe_and_releases_received_leaf() {
        let mut syscalls = syscalls();
        let mut request = [0xaa; PROBE_REQUEST_BYTES];
        let mut tokens = [0xbb; 1];
        let mut scratch = [0xcc; 4096];
        let mut response = [0xdd; PROBE_RESPONSE_BYTES];
        Fat32ServiceLoop::new()
            .serve_one(
                &mut syscalls,
                &mut request,
                &mut tokens,
                &mut scratch,
                &mut response,
            )
            .unwrap();
        assert_eq!(
            decode_probe_response(&syscalls.response.unwrap()),
            Ok(Ok(100))
        );
        assert_eq!((syscalls.reads, syscalls.releases), (1, 1));
        assert_eq!(request, [0; PROBE_REQUEST_BYTES]);
        assert_eq!(tokens, [0; 1]);
        assert_eq!(scratch, [0; 4096]);
        assert_eq!(response, [0; PROBE_RESPONSE_BYTES]);
    }

    #[test]
    fn unsupported_media_returns_typed_response() {
        let mut syscalls = syscalls();
        syscalls.shared.fill(0);
        let mut request = [0; PROBE_REQUEST_BYTES];
        let mut tokens = [0; 1];
        let mut scratch = [0; 4096];
        let mut response = [0; PROBE_RESPONSE_BYTES];
        Fat32ServiceLoop::new()
            .serve_one(
                &mut syscalls,
                &mut request,
                &mut tokens,
                &mut scratch,
                &mut response,
            )
            .unwrap();
        assert_eq!(
            decode_probe_response(&syscalls.response.unwrap()),
            Ok(Err(ProbeError::UnsupportedFilesystem))
        );
        assert_eq!(syscalls.releases, 1);
    }

    #[test]
    fn failed_shared_read_releases_leaf_without_reply() {
        let mut syscalls = syscalls();
        syscalls.fail_read = true;
        let mut request = [0; PROBE_REQUEST_BYTES];
        let mut tokens = [0; 1];
        let mut scratch = [0; 4096];
        let mut response = [0; PROBE_RESPONSE_BYTES];
        assert_eq!(
            Fat32ServiceLoop::new().serve_one(
                &mut syscalls,
                &mut request,
                &mut tokens,
                &mut scratch,
                &mut response,
            ),
            Err(Fat32ServiceLoopError::Syscall(()))
        );
        assert_eq!(syscalls.releases, 1);
        assert_eq!(syscalls.response, None);
        assert_eq!(scratch, [0; 4096]);
    }

    #[test]
    fn rejects_untransferred_or_malformed_envelope_before_shared_read() {
        for (token, capability_count) in [(0, 1), (7, 1), (TOKEN, 0)] {
            let mut syscalls = syscalls();
            syscalls.token = token;
            syscalls.capability_count = capability_count;
            let mut request = [0; PROBE_REQUEST_BYTES];
            let mut tokens = [0; 1];
            let mut scratch = [0; 4096];
            let mut response = [0; PROBE_RESPONSE_BYTES];
            assert_eq!(
                Fat32ServiceLoop::new().serve_one(
                    &mut syscalls,
                    &mut request,
                    &mut tokens,
                    &mut scratch,
                    &mut response,
                ),
                Err(Fat32ServiceLoopError::InvalidEnvelope)
            );
            assert_eq!(syscalls.reads, 0);
            assert_eq!(syscalls.releases, 0);
            assert_eq!(syscalls.response, None);
        }
    }
}
