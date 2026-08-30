//! Unified isolated dispatch for the generation-1 AHCI block-provider endpoint.

use crate::{
    AhciBlockControlBackend, AhciBlockIoBackend, AhciControlServiceLoop,
    AhciControlServiceLoopError, AhciControlServiceSyscalls, AhciDataServiceLoopError,
    AhciDataServiceSyscalls, AhciEnumerationServiceLoop, AhciReadWriteServiceLoop,
    AhciServiceLoopError, AhciServiceSyscalls, ReceivedAhciControlEnvelope,
    ReceivedAhciDataEnvelope, ReceivedAhciEnvelope,
};
use mrml_interface_storage_block_provider_v1::{
    BlockProviderDevice, ENUMERATE_REQUEST_BYTES, ENUMERATE_RESPONSE_BYTES, FLUSH_REQUEST_BYTES,
    FLUSH_RESPONSE_BYTES, READ_REQUEST_BYTES, READ_RESPONSE_BYTES,
};
use mrml_kernel::Capability;

pub const AHCI_DISPATCH_REQUEST_BYTES: usize = READ_REQUEST_BYTES;
const _: () = assert!(ENUMERATE_REQUEST_BYTES < AHCI_DISPATCH_REQUEST_BYTES);
const _: () = assert!(FLUSH_REQUEST_BYTES < AHCI_DISPATCH_REQUEST_BYTES);
const _: () = assert!(ENUMERATE_RESPONSE_BYTES == READ_RESPONSE_BYTES);
const _: () = assert!(FLUSH_RESPONSE_BYTES == READ_RESPONSE_BYTES);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedAhciDispatchEnvelope {
    pub payload_length: usize,
    pub capability_count: usize,
}

/// One launch-bound syscall surface shared by all block-provider operations.
///
/// # Safety
///
/// `receive` must return only bytes and capability tokens from one authenticated
/// message. Shared-buffer operations and release must resolve only an exact
/// received leaf. Responses must target only immutable launch state.
pub unsafe trait AhciDispatchSyscalls {
    type Error;

    fn receive(
        &mut self,
        request: &mut [u8; AHCI_DISPATCH_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedAhciDispatchEnvelope, Self::Error>;

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

    fn send_response(
        &mut self,
        response: &[u8; READ_RESPONSE_BYTES],
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciDispatchServiceError<E> {
    Receive(E),
    InvalidEnvelope,
    Enumeration(AhciServiceLoopError<E>),
    Data(AhciDataServiceLoopError<E>),
    Control(AhciControlServiceLoopError<E>),
}

pub struct AhciDispatchService<'a, B> {
    devices: &'a [BlockProviderDevice],
    backend: B,
}

impl<'a, B> AhciDispatchService<'a, B> {
    pub const fn new(devices: &'a [BlockProviderDevice], backend: B) -> Self {
        Self { devices, backend }
    }

    pub fn into_backend(self) -> B {
        self.backend
    }
}

impl<B: AhciBlockIoBackend + AhciBlockControlBackend> AhciDispatchService<'_, B> {
    pub fn serve_one<S: AhciDispatchSyscalls>(
        &mut self,
        syscalls: &mut S,
        request: &mut [u8; AHCI_DISPATCH_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        scratch: &mut [u8],
    ) -> Result<(), AhciDispatchServiceError<S::Error>> {
        request.fill(0);
        capability_tokens.fill(0);
        scratch.fill(0);
        let result = (|| {
            let envelope = syscalls
                .receive(request, capability_tokens)
                .map_err(AhciDispatchServiceError::Receive)?;
            if envelope.payload_length > request.len() || envelope.capability_count > 1 {
                return Err(AhciDispatchServiceError::InvalidEnvelope);
            }
            let token = capability_tokens[0];
            match envelope.payload_length {
                ENUMERATE_REQUEST_BYTES => {
                    let mut typed_request = [0; ENUMERATE_REQUEST_BYTES];
                    typed_request.copy_from_slice(&request[..ENUMERATE_REQUEST_BYTES]);
                    let mut response = [0; ENUMERATE_RESPONSE_BYTES];
                    let mut replay = PreReceivedSyscalls {
                        syscalls,
                        payload: *request,
                        payload_length: envelope.payload_length,
                        token,
                        capability_count: envelope.capability_count,
                    };
                    let result = AhciEnumerationServiceLoop::new(self.devices)
                        .serve_one(
                            &mut replay,
                            &mut typed_request,
                            capability_tokens,
                            scratch,
                            &mut response,
                        )
                        .map_err(AhciDispatchServiceError::Enumeration);
                    typed_request.fill(0);
                    response.fill(0);
                    result
                }
                READ_REQUEST_BYTES => {
                    let mut typed_request = *request;
                    let mut response = [0; READ_RESPONSE_BYTES];
                    let mut replay = PreReceivedSyscalls {
                        syscalls,
                        payload: *request,
                        payload_length: envelope.payload_length,
                        token,
                        capability_count: envelope.capability_count,
                    };
                    let result = AhciReadWriteServiceLoop::new(self.devices, &mut self.backend)
                        .serve_one(
                            &mut replay,
                            &mut typed_request,
                            capability_tokens,
                            scratch,
                            &mut response,
                        )
                        .map_err(AhciDispatchServiceError::Data);
                    typed_request.fill(0);
                    response.fill(0);
                    result
                }
                FLUSH_REQUEST_BYTES => {
                    let mut typed_request = [0; FLUSH_REQUEST_BYTES];
                    typed_request.copy_from_slice(&request[..FLUSH_REQUEST_BYTES]);
                    let mut response = [0; FLUSH_RESPONSE_BYTES];
                    let mut replay = PreReceivedSyscalls {
                        syscalls,
                        payload: *request,
                        payload_length: envelope.payload_length,
                        token,
                        capability_count: envelope.capability_count,
                    };
                    let result = AhciControlServiceLoop::new(self.devices, &mut self.backend)
                        .serve_one(
                            &mut replay,
                            &mut typed_request,
                            capability_tokens,
                            &mut response,
                        )
                        .map_err(AhciDispatchServiceError::Control);
                    typed_request.fill(0);
                    response.fill(0);
                    result
                }
                _ => Err(AhciDispatchServiceError::InvalidEnvelope),
            }
        })();
        request.fill(0);
        capability_tokens.fill(0);
        scratch.fill(0);
        result
    }
}

struct PreReceivedSyscalls<'a, S> {
    syscalls: &'a mut S,
    payload: [u8; AHCI_DISPATCH_REQUEST_BYTES],
    payload_length: usize,
    token: u64,
    capability_count: usize,
}

impl<S: AhciDispatchSyscalls> PreReceivedSyscalls<'_, S> {
    fn copy_request<const N: usize>(&self, request: &mut [u8; N]) {
        request.copy_from_slice(&self.payload[..N]);
    }
}

unsafe impl<S: AhciDispatchSyscalls> AhciServiceSyscalls for PreReceivedSyscalls<'_, S> {
    type Error = S::Error;

    fn receive(
        &mut self,
        request: &mut [u8; ENUMERATE_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedAhciEnvelope, Self::Error> {
        self.copy_request(request);
        capability_tokens[0] = self.token;
        Ok(ReceivedAhciEnvelope {
            payload_length: self.payload_length,
            capability_count: self.capability_count,
        })
    }

    fn write_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Self::Error> {
        self.syscalls.write_shared(capability, offset, input)
    }

    fn send_response(
        &mut self,
        response: &[u8; ENUMERATE_RESPONSE_BYTES],
    ) -> Result<(), Self::Error> {
        self.syscalls.send_response(response)
    }

    fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error> {
        self.syscalls.release_received(capability)
    }
}

unsafe impl<S: AhciDispatchSyscalls> AhciDataServiceSyscalls for PreReceivedSyscalls<'_, S> {
    type Error = S::Error;

    fn receive(
        &mut self,
        request: &mut [u8; READ_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedAhciDataEnvelope, Self::Error> {
        self.copy_request(request);
        capability_tokens[0] = self.token;
        Ok(ReceivedAhciDataEnvelope {
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
        self.syscalls.read_shared(capability, offset, output)
    }

    fn write_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Self::Error> {
        self.syscalls.write_shared(capability, offset, input)
    }

    fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error> {
        self.syscalls.release_received(capability)
    }

    fn send_response(&mut self, response: &[u8; READ_RESPONSE_BYTES]) -> Result<(), Self::Error> {
        self.syscalls.send_response(response)
    }
}

unsafe impl<S: AhciDispatchSyscalls> AhciControlServiceSyscalls for PreReceivedSyscalls<'_, S> {
    type Error = S::Error;

    fn receive(
        &mut self,
        request: &mut [u8; FLUSH_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedAhciControlEnvelope, Self::Error> {
        self.copy_request(request);
        capability_tokens[0] = self.token;
        Ok(ReceivedAhciControlEnvelope {
            payload_length: self.payload_length,
            capability_count: self.capability_count,
        })
    }

    fn send_response(&mut self, response: &[u8; FLUSH_RESPONSE_BYTES]) -> Result<(), Self::Error> {
        self.syscalls.send_response(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AhciBlockControlError, AhciBlockIoError};
    use mrml_interface_storage_block_provider_v1::{
        decode_enumerate_response, decode_flush_response, decode_read_response,
        decode_reset_response, decode_write_response, encode_enumerate_request,
        encode_flush_request, encode_read_request, encode_reset_request, encode_write_request,
        BorrowedReadView, BorrowedWriteView, OpaqueHandle, BLOCK_DEVICE_FLAG_FLUSH,
        BLOCK_DEVICE_FLAG_RESET,
    };

    const TOKEN: u64 = (19_u64 << 32) | 3;

    #[derive(Default)]
    struct Backend {
        reads: usize,
        writes: usize,
        flushes: usize,
        resets: usize,
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

    impl AhciBlockControlBackend for Backend {
        fn flush(&mut self, _: BlockProviderDevice) -> Result<u64, AhciBlockControlError> {
            self.flushes += 1;
            Ok(31)
        }

        fn reset(&mut self, _: BlockProviderDevice) -> Result<u64, AhciBlockControlError> {
            self.resets += 1;
            Ok(17)
        }
    }

    struct Syscalls {
        request: [u8; AHCI_DISPATCH_REQUEST_BYTES],
        payload_length: usize,
        capability_count: usize,
        token: u64,
        shared: [u8; 1024],
        response: Option<[u8; READ_RESPONSE_BYTES]>,
        reads: usize,
        writes: usize,
        releases: usize,
    }

    unsafe impl AhciDispatchSyscalls for Syscalls {
        type Error = ();

        fn receive(
            &mut self,
            request: &mut [u8; AHCI_DISPATCH_REQUEST_BYTES],
            capability_tokens: &mut [u64; 1],
        ) -> Result<ReceivedAhciDispatchEnvelope, Self::Error> {
            *request = self.request;
            capability_tokens[0] = self.token;
            Ok(ReceivedAhciDispatchEnvelope {
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
            assert_eq!(capability.token(), TOKEN);
            let start = usize::try_from(offset).map_err(|_| ())?;
            output.copy_from_slice(self.shared.get(start..start + output.len()).ok_or(())?);
            self.reads += 1;
            Ok(())
        }

        fn write_shared(
            &mut self,
            capability: Capability,
            offset: u64,
            input: &[u8],
        ) -> Result<(), Self::Error> {
            assert_eq!(capability.token(), TOKEN);
            let start = usize::try_from(offset).map_err(|_| ())?;
            self.shared
                .get_mut(start..start + input.len())
                .ok_or(())?
                .copy_from_slice(input);
            self.writes += 1;
            Ok(())
        }

        fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error> {
            assert_eq!(capability.token(), TOKEN);
            self.releases += 1;
            Ok(())
        }

        fn send_response(
            &mut self,
            response: &[u8; READ_RESPONSE_BYTES],
        ) -> Result<(), Self::Error> {
            self.response = Some(*response);
            Ok(())
        }
    }

    fn device() -> BlockProviderDevice {
        BlockProviderDevice {
            session: OpaqueHandle::new(4, 9).unwrap(),
            logical_block_bytes: 512,
            flags: BLOCK_DEVICE_FLAG_FLUSH | BLOCK_DEVICE_FLAG_RESET,
            logical_block_count: 100,
            media_generation: 12,
        }
    }

    fn syscalls<const N: usize>(request: [u8; N], capability_count: usize) -> Syscalls {
        let mut dispatch = [0; AHCI_DISPATCH_REQUEST_BYTES];
        dispatch[..N].copy_from_slice(&request);
        Syscalls {
            request: dispatch,
            payload_length: N,
            capability_count,
            token: if capability_count == 0 { 0 } else { TOKEN },
            shared: [0; 1024],
            response: None,
            reads: 0,
            writes: 0,
            releases: 0,
        }
    }

    #[test]
    fn one_endpoint_routes_every_canonical_operation_through_one_backend_owner() {
        let devices = [device()];
        let mut service = AhciDispatchService::new(&devices, Backend::default());
        let enumerate = encode_enumerate_request(BorrowedWriteView::within(0, 48, 1024).unwrap())
            .unwrap();
        let mut call = syscalls(enumerate, 1);
        service
            .serve_one(
                &mut call,
                &mut [0xaa; AHCI_DISPATCH_REQUEST_BYTES],
                &mut [u64::MAX],
                &mut [0xcc; 512],
            )
            .unwrap();
        assert_eq!(decode_enumerate_response(&call.response.unwrap(), 48), Ok(Ok(48)));
        assert_eq!((call.writes, call.releases), (1, 1));

        let read = encode_read_request(
            device().session,
            2,
            1,
            BorrowedWriteView::within(64, 512, 1024).unwrap(),
        )
        .unwrap();
        let mut call = syscalls(read, 1);
        service
            .serve_one(
                &mut call,
                &mut [0; AHCI_DISPATCH_REQUEST_BYTES],
                &mut [0],
                &mut [0; 512],
            )
            .unwrap();
        assert_eq!(decode_read_response(&call.response.unwrap(), 512), Ok(Ok(512)));
        assert!(call.shared[64..576].iter().all(|byte| *byte == 0x5a));
        assert_eq!((call.reads, call.writes, call.releases), (0, 1, 1));

        let write = encode_write_request(
            device().session,
            3,
            1,
            BorrowedReadView::within(64, 512, 1024).unwrap(),
        )
        .unwrap();
        let mut call = syscalls(write, 1);
        call.shared[64..576].fill(0xa5);
        service
            .serve_one(
                &mut call,
                &mut [0; AHCI_DISPATCH_REQUEST_BYTES],
                &mut [0],
                &mut [0; 512],
            )
            .unwrap();
        assert_eq!(decode_write_response(&call.response.unwrap(), 512), Ok(Ok(512)));
        assert_eq!((call.reads, call.writes, call.releases), (1, 0, 1));

        let mut call = syscalls(encode_flush_request(device().session), 0);
        service
            .serve_one(
                &mut call,
                &mut [0; AHCI_DISPATCH_REQUEST_BYTES],
                &mut [0],
                &mut [0; 512],
            )
            .unwrap();
        assert_eq!(decode_flush_response(&call.response.unwrap()), Ok(Ok(31)));
        assert_eq!(call.releases, 0);

        let mut call = syscalls(encode_reset_request(device().session), 0);
        service
            .serve_one(
                &mut call,
                &mut [0; AHCI_DISPATCH_REQUEST_BYTES],
                &mut [0],
                &mut [0; 512],
            )
            .unwrap();
        assert_eq!(decode_reset_response(&call.response.unwrap()), Ok(Ok(17)));
        assert_eq!(call.releases, 0);

        let backend = service.into_backend();
        assert_eq!(
            (backend.reads, backend.writes, backend.flushes, backend.resets),
            (1, 1, 1, 1)
        );
    }

    #[test]
    fn unknown_or_overcounted_envelope_never_dispatches_releases_or_replies() {
        let devices = [device()];
        for (payload_length, capability_count, token) in [
            (AHCI_DISPATCH_REQUEST_BYTES - 1, 1, TOKEN),
            (AHCI_DISPATCH_REQUEST_BYTES + 1, 1, TOKEN),
            (ENUMERATE_REQUEST_BYTES, 2, TOKEN),
        ] {
            let mut call = syscalls([0; AHCI_DISPATCH_REQUEST_BYTES], capability_count);
            call.payload_length = payload_length;
            call.token = token;
            let mut request = [0xaa; AHCI_DISPATCH_REQUEST_BYTES];
            let mut tokens = [u64::MAX];
            let mut scratch = [0xcc; 512];
            assert_eq!(
                AhciDispatchService::new(&devices, Backend::default()).serve_one(
                    &mut call,
                    &mut request,
                    &mut tokens,
                    &mut scratch,
                ),
                Err(AhciDispatchServiceError::InvalidEnvelope)
            );
            assert_eq!((call.reads, call.writes, call.releases), (0, 0, 0));
            assert!(call.response.is_none());
            assert_eq!(request, [0; AHCI_DISPATCH_REQUEST_BYTES]);
            assert_eq!(tokens, [0]);
            assert_eq!(scratch, [0; 512]);
        }
    }
}
