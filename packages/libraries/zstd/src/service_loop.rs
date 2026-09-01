use crate::ComponentProvider;
use mrml_interface_zstd_v3::{
    decode_decompress_request, decode_decompress_response, ProtocolError, ZstdTransport,
    DECOMPRESS_REQUEST_BYTES, DECOMPRESS_RESPONSE_BYTES,
};
use mrml_kernel::Capability;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedZstdEnvelope {
    pub payload_length: usize,
    pub capability_count: usize,
}

/// Narrow runtime boundary implemented by an isolated Zstd service process or
/// microVM. Sender identity and the reply peer are launch-bound runtime state,
/// never values decoded from component data.
///
/// # Safety
///
/// `receive` must return only the capability token transferred with that exact
/// authenticated request. Shared-buffer operations must use the kernel's exact
/// capability-selected object without substitution. `send_response` must target
/// only the launch-bound caller. `release_received` must enter the runtime's
/// transitive revocation path for the exact received leaf.
pub unsafe trait ZstdServiceSyscalls {
    type Error;

    fn receive(
        &mut self,
        request: &mut [u8; DECOMPRESS_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedZstdEnvelope, Self::Error>;

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

    fn send_response(
        &mut self,
        response: &[u8; DECOMPRESS_RESPONSE_BYTES],
    ) -> Result<(), Self::Error>;

    fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZstdServiceLoopError<E> {
    Syscall(E),
    Protocol(ProtocolError),
    InvalidEnvelope,
    ScratchTooSmall,
}

pub struct ZstdServiceLoop {
    provider: ComponentProvider,
}

impl Default for ZstdServiceLoop {
    fn default() -> Self {
        Self::new()
    }
}

impl ZstdServiceLoop {
    pub const fn new() -> Self {
        Self {
            provider: ComponentProvider,
        }
    }

    /// Receives and completes exactly one ABI-3 call. All caller-owned wire and
    /// scratch buffers are erased on every return path, and every received leaf
    /// is released even when protocol or backend processing fails.
    pub fn serve_one<S: ZstdServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; DECOMPRESS_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        scratch: &mut [u8],
        response_buffer: &mut [u8; DECOMPRESS_RESPONSE_BYTES],
    ) -> Result<(), ZstdServiceLoopError<S::Error>> {
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
            .map_err(ZstdServiceLoopError::Syscall);
        let completion = match result.and(release) {
            Ok(()) => syscalls
                .send_response(response_buffer)
                .map_err(ZstdServiceLoopError::Syscall),
            Err(error) => Err(error),
        };
        request_buffer.fill(0);
        capability_tokens.fill(0);
        scratch.fill(0);
        response_buffer.fill(0);
        completion
    }

    fn serve_one_inner<S: ZstdServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; DECOMPRESS_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        scratch: &mut [u8],
        response_buffer: &mut [u8; DECOMPRESS_RESPONSE_BYTES],
        received_capability: &mut Option<Capability>,
    ) -> Result<(), ZstdServiceLoopError<S::Error>> {
        let envelope = syscalls
            .receive(request_buffer, capability_tokens)
            .map_err(ZstdServiceLoopError::Syscall)?;
        if envelope.payload_length != DECOMPRESS_REQUEST_BYTES
            || envelope.capability_count != 1
            || capability_tokens[0] == 0
            || capability_tokens[0] >> 32 == 0
        {
            return Err(ZstdServiceLoopError::InvalidEnvelope);
        }
        let capability = Capability::from_token(capability_tokens[0]);
        *received_capability = Some(capability);
        let request = decode_decompress_request(request_buffer, u64::MAX)
            .map_err(ZstdServiceLoopError::Protocol)?;
        let input_end = request
            .input
            .offset()
            .checked_add(request.input.length())
            .ok_or(ZstdServiceLoopError::Protocol(
                ProtocolError::InvalidRequest,
            ))?;
        let output_end = request
            .output
            .offset()
            .checked_add(request.output.length())
            .ok_or(ZstdServiceLoopError::Protocol(
                ProtocolError::InvalidRequest,
            ))?;
        let extent = usize::try_from(input_end.max(output_end))
            .map_err(|_| ZstdServiceLoopError::ScratchTooSmall)?;
        if extent == 0 || extent > scratch.len() {
            return Err(ZstdServiceLoopError::ScratchTooSmall);
        }
        let input_start = usize::try_from(request.input.offset())
            .map_err(|_| ZstdServiceLoopError::ScratchTooSmall)?;
        let input_end =
            usize::try_from(input_end).map_err(|_| ZstdServiceLoopError::ScratchTooSmall)?;
        syscalls
            .read_shared(
                capability,
                request.input.offset(),
                &mut scratch[input_start..input_end],
            )
            .map_err(ZstdServiceLoopError::Syscall)?;
        *response_buffer = self
            .provider
            .call(request_buffer, &mut scratch[..extent])
            .map_err(ZstdServiceLoopError::Protocol)?;
        if let Ok(written) =
            decode_decompress_response(response_buffer).map_err(ZstdServiceLoopError::Protocol)?
        {
            if written > request.output.length() {
                return Err(ZstdServiceLoopError::Protocol(
                    ProtocolError::InvalidResponse,
                ));
            }
            if written != 0 {
                let output_start = usize::try_from(request.output.offset())
                    .map_err(|_| ZstdServiceLoopError::ScratchTooSmall)?;
                let output_end = output_start
                    .checked_add(
                        usize::try_from(written)
                            .map_err(|_| ZstdServiceLoopError::ScratchTooSmall)?,
                    )
                    .ok_or(ZstdServiceLoopError::ScratchTooSmall)?;
                syscalls
                    .write_shared(
                        capability,
                        request.output.offset(),
                        &scratch[output_start..output_end],
                    )
                    .map_err(ZstdServiceLoopError::Syscall)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_interface_zstd_v3::{
        decode_decompress_response, encode_decompress_request, BorrowedReadView, BorrowedWriteView,
        DecompressError,
    };

    const TOKEN: u64 = (7_u64 << 32) | 3;
    const FRAME: [u8; 10] = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 5, 0x2b, 0, 0, b'x'];

    struct Syscalls {
        request: [u8; DECOMPRESS_REQUEST_BYTES],
        token: u64,
        memory: [u8; 128],
        response: Option<[u8; DECOMPRESS_RESPONSE_BYTES]>,
        reads: usize,
        writes: usize,
        releases: usize,
        fail_release: bool,
        capability_count: usize,
    }

    unsafe impl ZstdServiceSyscalls for Syscalls {
        type Error = ();

        fn receive(
            &mut self,
            request: &mut [u8; DECOMPRESS_REQUEST_BYTES],
            capability_tokens: &mut [u64; 1],
        ) -> Result<ReceivedZstdEnvelope, Self::Error> {
            *request = self.request;
            capability_tokens[0] = self.token;
            Ok(ReceivedZstdEnvelope {
                payload_length: DECOMPRESS_REQUEST_BYTES,
                capability_count: self.capability_count,
            })
        }

        fn read_shared(
            &mut self,
            capability: Capability,
            offset: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            if capability.token() != self.token {
                return Err(());
            }
            let start = usize::try_from(offset).map_err(|_| ())?;
            output.copy_from_slice(self.memory.get(start..start + output.len()).ok_or(())?);
            self.reads += 1;
            Ok(())
        }

        fn write_shared(
            &mut self,
            capability: Capability,
            offset: u64,
            input: &[u8],
        ) -> Result<(), Self::Error> {
            if capability.token() != self.token {
                return Err(());
            }
            let start = usize::try_from(offset).map_err(|_| ())?;
            self.memory
                .get_mut(start..start + input.len())
                .ok_or(())?
                .copy_from_slice(input);
            self.writes += 1;
            Ok(())
        }

        fn send_response(
            &mut self,
            response: &[u8; DECOMPRESS_RESPONSE_BYTES],
        ) -> Result<(), Self::Error> {
            self.response = Some(*response);
            Ok(())
        }

        fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error> {
            if capability.token() != self.token {
                return Err(());
            }
            self.releases += 1;
            if self.fail_release {
                Err(())
            } else {
                Ok(())
            }
        }
    }

    fn syscalls() -> Syscalls {
        let request = encode_decompress_request(
            BorrowedReadView::within(0, FRAME.len() as u64, 128).unwrap(),
            BorrowedWriteView::within(64, 32, 128).unwrap(),
        )
        .unwrap();
        let mut memory = [0xa5; 128];
        memory[..FRAME.len()].copy_from_slice(&FRAME);
        Syscalls {
            request,
            token: TOKEN,
            memory,
            response: None,
            reads: 0,
            writes: 0,
            releases: 0,
            fail_release: false,
            capability_count: 1,
        }
    }

    fn buffers() -> (
        [u8; DECOMPRESS_REQUEST_BYTES],
        [u64; 1],
        [u8; 128],
        [u8; DECOMPRESS_RESPONSE_BYTES],
    ) {
        (
            [0xcc; DECOMPRESS_REQUEST_BYTES],
            [u64::MAX; 1],
            [0xcc; 128],
            [0xcc; DECOMPRESS_RESPONSE_BYTES],
        )
    }

    #[test]
    fn service_loop_uses_one_capability_replies_and_erases_every_buffer() {
        let mut syscalls = syscalls();
        let (mut request, mut tokens, mut scratch, mut response) = buffers();
        ZstdServiceLoop::new()
            .serve_one(
                &mut syscalls,
                &mut request,
                &mut tokens,
                &mut scratch,
                &mut response,
            )
            .unwrap();
        assert_eq!(&syscalls.memory[64..69], b"xxxxx");
        assert_eq!(
            decode_decompress_response(&syscalls.response.unwrap()),
            Ok(Ok(5))
        );
        assert_eq!(
            (syscalls.reads, syscalls.writes, syscalls.releases),
            (1, 1, 1)
        );
        assert_eq!(request, [0; DECOMPRESS_REQUEST_BYTES]);
        assert_eq!(tokens, [0]);
        assert_eq!(scratch, [0; 128]);
        assert_eq!(response, [0; DECOMPRESS_RESPONSE_BYTES]);
    }

    #[test]
    fn invalid_frame_replies_without_output_write_and_still_releases() {
        let mut syscalls = syscalls();
        syscalls.memory[0] ^= 0xff;
        let (mut request, mut tokens, mut scratch, mut response) = buffers();
        ZstdServiceLoop::new()
            .serve_one(
                &mut syscalls,
                &mut request,
                &mut tokens,
                &mut scratch,
                &mut response,
            )
            .unwrap();
        assert_eq!(
            decode_decompress_response(&syscalls.response.unwrap()),
            Ok(Err((DecompressError::InvalidFrame, 0)))
        );
        assert_eq!(
            (syscalls.reads, syscalls.writes, syscalls.releases),
            (1, 0, 1)
        );
        assert_eq!(&syscalls.memory[64..69], &[0xa5; 5]);
        assert_eq!(request, [0; DECOMPRESS_REQUEST_BYTES]);
        assert_eq!(tokens, [0]);
        assert_eq!(scratch, [0; 128]);
        assert_eq!(response, [0; DECOMPRESS_RESPONSE_BYTES]);
    }

    #[test]
    fn malformed_envelope_and_small_scratch_never_touch_shared_memory() {
        let mut malformed = syscalls();
        malformed.token = 3;
        let (mut request, mut tokens, mut scratch, mut response) = buffers();
        assert_eq!(
            ZstdServiceLoop::new().serve_one(
                &mut malformed,
                &mut request,
                &mut tokens,
                &mut scratch,
                &mut response,
            ),
            Err(ZstdServiceLoopError::InvalidEnvelope)
        );
        assert_eq!(
            (malformed.reads, malformed.writes, malformed.releases),
            (0, 0, 0)
        );

        let mut undeclared = syscalls();
        undeclared.capability_count = 0;
        assert_eq!(
            ZstdServiceLoop::new().serve_one(
                &mut undeclared,
                &mut request,
                &mut tokens,
                &mut scratch,
                &mut response,
            ),
            Err(ZstdServiceLoopError::InvalidEnvelope)
        );
        assert_eq!(
            (undeclared.reads, undeclared.writes, undeclared.releases),
            (0, 0, 0)
        );

        let mut bounded = syscalls();
        let mut small = [0xcc; 68];
        assert_eq!(
            ZstdServiceLoop::new().serve_one(
                &mut bounded,
                &mut request,
                &mut tokens,
                &mut small,
                &mut response,
            ),
            Err(ZstdServiceLoopError::ScratchTooSmall)
        );
        assert_eq!((bounded.reads, bounded.writes, bounded.releases), (0, 0, 1));
        assert_eq!(small, [0; 68]);
    }

    #[test]
    fn revocation_failure_suppresses_response_and_erases_buffers() {
        let mut syscalls = syscalls();
        syscalls.fail_release = true;
        let (mut request, mut tokens, mut scratch, mut response) = buffers();
        assert_eq!(
            ZstdServiceLoop::new().serve_one(
                &mut syscalls,
                &mut request,
                &mut tokens,
                &mut scratch,
                &mut response,
            ),
            Err(ZstdServiceLoopError::Syscall(()))
        );
        assert!(syscalls.response.is_none());
        assert_eq!(syscalls.releases, 1);
        assert_eq!(request, [0; DECOMPRESS_REQUEST_BYTES]);
        assert_eq!(tokens, [0]);
        assert_eq!(scratch, [0; 128]);
        assert_eq!(response, [0; DECOMPRESS_RESPONSE_BYTES]);
    }
}
