//! Capability-free flush/reset dispatch for the isolated AHCI provider.

use crate::{AhciBlockControlAdapter, AhciBlockControlBackend};
use mrml_interface_storage_block_provider_v1::{
    BlockProviderControlTransport, BlockProviderDevice, FLUSH_REQUEST_BYTES, FLUSH_RESPONSE_BYTES,
    ProtocolError, RESET_REQUEST_BYTES, RESET_RESPONSE_BYTES, decode_flush_request,
    decode_reset_request,
};

const _: () = assert!(FLUSH_REQUEST_BYTES == RESET_REQUEST_BYTES);
const _: () = assert!(FLUSH_RESPONSE_BYTES == RESET_RESPONSE_BYTES);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedAhciControlEnvelope {
    pub payload_length: usize,
    pub capability_count: usize,
}

/// Narrow syscall boundary for buffer-free AHCI control operations.
///
/// # Safety
///
/// `receive` and `send_response` must remain bound to the authenticated launch
/// endpoint. No capability may be accepted with a control request.
pub unsafe trait AhciControlServiceSyscalls {
    type Error;
    fn receive(
        &mut self,
        request: &mut [u8; FLUSH_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedAhciControlEnvelope, Self::Error>;
    fn send_response(&mut self, response: &[u8; FLUSH_RESPONSE_BYTES]) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciControlServiceLoopError<E> {
    Syscall(E),
    Protocol(ProtocolError),
    InvalidEnvelope,
}

pub struct AhciControlServiceLoop<'a, B> {
    adapter: AhciBlockControlAdapter<'a, B>,
}

impl<'a, B> AhciControlServiceLoop<'a, B> {
    pub const fn new(devices: &'a [BlockProviderDevice], backend: B) -> Self {
        Self {
            adapter: AhciBlockControlAdapter::new(devices, backend),
        }
    }
    pub fn into_backend(self) -> B {
        self.adapter.into_backend()
    }
}

impl<B: AhciBlockControlBackend> AhciControlServiceLoop<'_, B> {
    pub fn serve_one<S: AhciControlServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; FLUSH_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        response_buffer: &mut [u8; FLUSH_RESPONSE_BYTES],
    ) -> Result<(), AhciControlServiceLoopError<S::Error>> {
        request_buffer.fill(0);
        capability_tokens.fill(0);
        response_buffer.fill(0);
        let result =
            self.serve_one_inner(syscalls, request_buffer, capability_tokens, response_buffer);
        let completion = match result {
            Ok(()) => syscalls
                .send_response(response_buffer)
                .map_err(AhciControlServiceLoopError::Syscall),
            Err(error) => Err(error),
        };
        request_buffer.fill(0);
        capability_tokens.fill(0);
        response_buffer.fill(0);
        completion
    }

    fn serve_one_inner<S: AhciControlServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; FLUSH_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        response_buffer: &mut [u8; FLUSH_RESPONSE_BYTES],
    ) -> Result<(), AhciControlServiceLoopError<S::Error>> {
        let envelope = syscalls
            .receive(request_buffer, capability_tokens)
            .map_err(AhciControlServiceLoopError::Syscall)?;
        if envelope.payload_length != FLUSH_REQUEST_BYTES
            || envelope.capability_count != 0
            || capability_tokens[0] != 0
        {
            return Err(AhciControlServiceLoopError::InvalidEnvelope);
        }
        if decode_flush_request(request_buffer).is_ok() {
            *response_buffer = self
                .adapter
                .flush(request_buffer)
                .map_err(AhciControlServiceLoopError::Protocol)?;
            return Ok(());
        }
        decode_reset_request(request_buffer).map_err(AhciControlServiceLoopError::Protocol)?;
        *response_buffer = self
            .adapter
            .reset(request_buffer)
            .map_err(AhciControlServiceLoopError::Protocol)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AhciBlockControlError;
    use mrml_interface_storage_block_provider_v1::{
        BLOCK_DEVICE_FLAG_FLUSH, BLOCK_DEVICE_FLAG_RESET, OpaqueHandle, decode_flush_response,
        decode_reset_response, encode_flush_request, encode_reset_request,
    };

    #[derive(Default)]
    struct Backend {
        flushes: usize,
        resets: usize,
    }
    impl AhciBlockControlBackend for Backend {
        fn flush(&mut self, _: BlockProviderDevice) -> Result<u64, AhciBlockControlError> {
            self.flushes += 1;
            Ok(41)
        }
        fn reset(&mut self, _: BlockProviderDevice) -> Result<u64, AhciBlockControlError> {
            self.resets += 1;
            Ok(12)
        }
    }

    struct Syscalls {
        request: [u8; FLUSH_REQUEST_BYTES],
        token: u64,
        count: usize,
        response: Option<[u8; 16]>,
    }
    unsafe impl AhciControlServiceSyscalls for Syscalls {
        type Error = ();
        fn receive(
            &mut self,
            request: &mut [u8; FLUSH_REQUEST_BYTES],
            tokens: &mut [u64; 1],
        ) -> Result<ReceivedAhciControlEnvelope, ()> {
            *request = self.request;
            tokens[0] = self.token;
            Ok(ReceivedAhciControlEnvelope {
                payload_length: FLUSH_REQUEST_BYTES,
                capability_count: self.count,
            })
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
            flags: BLOCK_DEVICE_FLAG_FLUSH | BLOCK_DEVICE_FLAG_RESET,
            logical_block_count: 100,
            media_generation: 11,
        }
    }

    #[test]
    fn dispatches_buffer_free_flush_and_reset_and_wipes() {
        let devices = [device()];
        let mut service = AhciControlServiceLoop::new(&devices, Backend::default());
        for (request, reset) in [
            (encode_flush_request(device().session), false),
            (encode_reset_request(device().session), true),
        ] {
            let mut syscalls = Syscalls {
                request,
                token: 0,
                count: 0,
                response: None,
            };
            let mut request_buffer = [0xaa; FLUSH_REQUEST_BYTES];
            let mut tokens = [0xbb];
            let mut response = [0xcc; 16];
            service
                .serve_one(
                    &mut syscalls,
                    &mut request_buffer,
                    &mut tokens,
                    &mut response,
                )
                .unwrap();
            if reset {
                assert_eq!(
                    decode_reset_response(&syscalls.response.unwrap()),
                    Ok(Ok(12))
                );
            } else {
                assert_eq!(
                    decode_flush_response(&syscalls.response.unwrap()),
                    Ok(Ok(41))
                );
            }
            assert_eq!(request_buffer, [0; FLUSH_REQUEST_BYTES]);
            assert_eq!(tokens, [0]);
            assert_eq!(response, [0; 16]);
        }
        let backend = service.into_backend();
        assert_eq!((backend.flushes, backend.resets), (1, 1));
    }

    #[test]
    fn rejects_any_transferred_capability_without_reply() {
        let devices = [device()];
        let mut service = AhciControlServiceLoop::new(&devices, Backend::default());
        let mut syscalls = Syscalls {
            request: encode_flush_request(device().session),
            token: (2_u64 << 32) | 1,
            count: 1,
            response: None,
        };
        let result = service.serve_one(
            &mut syscalls,
            &mut [0; FLUSH_REQUEST_BYTES],
            &mut [0; 1],
            &mut [0; 16],
        );
        assert_eq!(result, Err(AhciControlServiceLoopError::InvalidEnvelope));
        assert!(syscalls.response.is_none());
    }
}
