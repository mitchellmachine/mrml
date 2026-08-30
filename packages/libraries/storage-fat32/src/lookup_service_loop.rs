use crate::{Fat32BlockMountBackend, Fat32LookupProvider};
use mrml_interface_storage_block_provider_v1::BlockProviderReadTransport;
use mrml_interface_storage_filesystem_v2::{
    decode_lookup_request, encode_lookup_request, BorrowedReadView, FilesystemLookupTransport,
    ProtocolError, LOOKUP_REQUEST_BYTES, LOOKUP_RESPONSE_BYTES,
};
use mrml_kernel::Capability;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedFat32LookupEnvelope {
    pub payload_length: usize,
    pub capability_count: usize,
}

/// Runtime boundary for one isolated FAT32 lookup invocation.
///
/// # Safety
///
/// `receive_lookup` must return only a name-buffer capability transferred by the
/// exact authenticated caller. `read_shared` must resolve that exact received
/// object, `release_received` must enter transitive revocation for it, and the
/// response must target only the launch-bound caller.
pub unsafe trait Fat32LookupServiceSyscalls {
    type Error;

    fn receive_lookup(
        &mut self,
        request: &mut [u8; LOOKUP_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedFat32LookupEnvelope, Self::Error>;

    fn read_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error>;

    fn send_lookup_response(
        &mut self,
        response: &[u8; LOOKUP_RESPONSE_BYTES],
    ) -> Result<(), Self::Error>;

    fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fat32LookupServiceLoopError<E> {
    Syscall(E),
    Protocol(ProtocolError),
    InvalidEnvelope,
    ScratchTooSmall,
}

pub struct Fat32LookupServiceLoop<'a, 'b, T, const N: usize, const O: usize = 64> {
    provider: Fat32LookupProvider<'a, Fat32BlockMountBackend<'b, T>, N, O>,
}

impl<'a, 'b, T, const N: usize, const O: usize> Fat32LookupServiceLoop<'a, 'b, T, N, O> {
    pub const fn new(
        provider: Fat32LookupProvider<'a, Fat32BlockMountBackend<'b, T>, N, O>,
    ) -> Self {
        Self { provider }
    }

    pub fn into_provider(self) -> Fat32LookupProvider<'a, Fat32BlockMountBackend<'b, T>, N, O> {
        self.provider
    }
}

impl<T: BlockProviderReadTransport, const N: usize, const O: usize>
    Fat32LookupServiceLoop<'_, '_, T, N, O>
{
    pub fn serve_one<S: Fat32LookupServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; LOOKUP_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        name_scratch: &mut [u8],
        response_buffer: &mut [u8; LOOKUP_RESPONSE_BYTES],
    ) -> Result<(), Fat32LookupServiceLoopError<S::Error>> {
        request_buffer.fill(0);
        capability_tokens.fill(0);
        name_scratch.fill(0);
        response_buffer.fill(0);
        let mut received_capability = None;
        let result = self.serve_one_inner(
            syscalls,
            request_buffer,
            capability_tokens,
            name_scratch,
            response_buffer,
            &mut received_capability,
        );
        let release = received_capability
            .map(|capability| syscalls.release_received(capability))
            .transpose()
            .map(|_| ())
            .map_err(Fat32LookupServiceLoopError::Syscall);
        let completion = match result.and(release) {
            Ok(()) => syscalls
                .send_lookup_response(response_buffer)
                .map_err(Fat32LookupServiceLoopError::Syscall),
            Err(error) => Err(error),
        };
        request_buffer.fill(0);
        capability_tokens.fill(0);
        name_scratch.fill(0);
        response_buffer.fill(0);
        completion
    }

    fn serve_one_inner<S: Fat32LookupServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; LOOKUP_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        name_scratch: &mut [u8],
        response_buffer: &mut [u8; LOOKUP_RESPONSE_BYTES],
        received_capability: &mut Option<Capability>,
    ) -> Result<(), Fat32LookupServiceLoopError<S::Error>> {
        let envelope = syscalls
            .receive_lookup(request_buffer, capability_tokens)
            .map_err(Fat32LookupServiceLoopError::Syscall)?;
        if envelope.payload_length != LOOKUP_REQUEST_BYTES
            || envelope.capability_count != 1
            || capability_tokens[0] == 0
            || capability_tokens[0] >> 32 == 0
        {
            return Err(Fat32LookupServiceLoopError::InvalidEnvelope);
        }
        let capability = Capability::from_token(capability_tokens[0]);
        *received_capability = Some(capability);
        let request = decode_lookup_request(request_buffer, u64::MAX)
            .map_err(Fat32LookupServiceLoopError::Protocol)?;
        let length = usize::try_from(request.name.length())
            .map_err(|_| Fat32LookupServiceLoopError::ScratchTooSmall)?;
        if length == 0 || length > name_scratch.len() {
            return Err(Fat32LookupServiceLoopError::ScratchTooSmall);
        }
        syscalls
            .read_shared(
                capability,
                request.name.offset(),
                &mut name_scratch[..length],
            )
            .map_err(Fat32LookupServiceLoopError::Syscall)?;
        let local_name = BorrowedReadView::within(0, length as u64, length as u64)
            .ok_or(Fat32LookupServiceLoopError::ScratchTooSmall)?;
        let local_request = encode_lookup_request(
            request.volume,
            request.generation,
            request.directory,
            local_name,
        )
        .map_err(Fat32LookupServiceLoopError::Protocol)?;
        *response_buffer = self
            .provider
            .lookup(&local_request, &mut name_scratch[..length])
            .map_err(Fat32LookupServiceLoopError::Protocol)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Fat32BlockBinding, Fat32MountedProvider};
    use mrml_interface_storage_block_provider_v1::{
        encode_read_response, OpaqueHandle as BlockOpaqueHandle,
        ProtocolError as BlockProtocolError, ReadError, READ_REQUEST_BYTES, READ_RESPONSE_BYTES,
    };
    use mrml_interface_storage_filesystem_v2::{encode_lookup_request, OpaqueHandle};

    const TOKEN: u64 = (9_u64 << 32) | 4;

    struct Transport;

    impl BlockProviderReadTransport for Transport {
        fn read(
            &mut self,
            _request: &[u8; READ_REQUEST_BYTES],
            _memory: &mut [u8],
        ) -> Result<[u8; READ_RESPONSE_BYTES], BlockProtocolError> {
            Ok(encode_read_response(Err(ReadError::IoFailure)))
        }
    }

    struct Syscalls {
        request: [u8; LOOKUP_REQUEST_BYTES],
        token: u64,
        envelope: ReceivedFat32LookupEnvelope,
        shared: [u8; 16],
        reads: usize,
        releases: usize,
        response: Option<[u8; LOOKUP_RESPONSE_BYTES]>,
        fail_read: bool,
    }

    unsafe impl Fat32LookupServiceSyscalls for Syscalls {
        type Error = ();

        fn receive_lookup(
            &mut self,
            request: &mut [u8; LOOKUP_REQUEST_BYTES],
            capability_tokens: &mut [u64; 1],
        ) -> Result<ReceivedFat32LookupEnvelope, Self::Error> {
            *request = self.request;
            capability_tokens[0] = self.token;
            Ok(self.envelope)
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

        fn send_lookup_response(
            &mut self,
            response: &[u8; LOOKUP_RESPONSE_BYTES],
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

    fn fixture<'a, 'b>(
        block_scratch: &'b mut [u8; 4096],
        directory_scratch: &'a mut [u8; 4096],
    ) -> (Fat32LookupServiceLoop<'a, 'b, Transport, 1, 4>, Syscalls) {
        let volume = OpaqueHandle::new(4, 7).unwrap();
        let session = BlockOpaqueHandle::new(9, 11).unwrap();
        // SAFETY: The fixture defines the session as the exact backing for volume.
        let binding = unsafe { Fat32BlockBinding::new(volume, session, 4096).unwrap() };
        let backend = Fat32BlockMountBackend::new(binding, Transport, block_scratch).unwrap();
        let provider = Fat32MountedProvider::<_, 1, 4>::new(backend);
        let lookup = Fat32LookupProvider::new(provider, directory_scratch);
        let name = BorrowedReadView::within(2, 10, 16).unwrap();
        let request =
            encode_lookup_request(volume, 1, OpaqueHandle::new(0, 1).unwrap(), name).unwrap();
        let mut shared = [0; 16];
        shared[2..12].copy_from_slice(b"KERNEL.MRP");
        (
            Fat32LookupServiceLoop::new(lookup),
            Syscalls {
                request,
                token: TOKEN,
                envelope: ReceivedFat32LookupEnvelope {
                    payload_length: LOOKUP_REQUEST_BYTES,
                    capability_count: 1,
                },
                shared,
                reads: 0,
                releases: 0,
                response: None,
                fail_read: false,
            },
        )
    }

    #[test]
    fn malformed_lookup_envelope_never_reads_releases_or_replies() {
        let mut block_scratch = [0xaa; 4096];
        let mut directory_scratch = [0xbb; 4096];
        let (mut service, mut syscalls) = fixture(&mut block_scratch, &mut directory_scratch);
        syscalls.envelope.capability_count = 0;
        let mut request = [0; LOOKUP_REQUEST_BYTES];
        let mut tokens = [0; 1];
        let mut name = [0; 16];
        let mut response = [0; LOOKUP_RESPONSE_BYTES];
        assert_eq!(
            service.serve_one(
                &mut syscalls,
                &mut request,
                &mut tokens,
                &mut name,
                &mut response,
            ),
            Err(Fat32LookupServiceLoopError::InvalidEnvelope)
        );
        assert_eq!((syscalls.reads, syscalls.releases), (0, 0));
        assert_eq!(syscalls.response, None);
        assert_eq!(name, [0; 16]);
    }

    #[test]
    fn failed_lookup_shared_copy_releases_validated_leaf_without_reply() {
        let mut block_scratch = [0xaa; 4096];
        let mut directory_scratch = [0xbb; 4096];
        let (mut service, mut syscalls) = fixture(&mut block_scratch, &mut directory_scratch);
        syscalls.fail_read = true;
        let mut request = [0; LOOKUP_REQUEST_BYTES];
        let mut tokens = [0; 1];
        let mut name = [0; 16];
        let mut response = [0; LOOKUP_RESPONSE_BYTES];
        assert_eq!(
            service.serve_one(
                &mut syscalls,
                &mut request,
                &mut tokens,
                &mut name,
                &mut response,
            ),
            Err(Fat32LookupServiceLoopError::Syscall(()))
        );
        assert_eq!((syscalls.reads, syscalls.releases), (1, 1));
        assert_eq!(syscalls.response, None);
        assert_eq!(name, [0; 16]);
    }

    #[test]
    fn short_lookup_name_scratch_releases_without_provider_dispatch() {
        let mut block_scratch = [0xaa; 4096];
        let mut directory_scratch = [0xbb; 4096];
        let (mut service, mut syscalls) = fixture(&mut block_scratch, &mut directory_scratch);
        let mut request = [0; LOOKUP_REQUEST_BYTES];
        let mut tokens = [0; 1];
        let mut name = [0; 9];
        let mut response = [0; LOOKUP_RESPONSE_BYTES];
        assert_eq!(
            service.serve_one(
                &mut syscalls,
                &mut request,
                &mut tokens,
                &mut name,
                &mut response,
            ),
            Err(Fat32LookupServiceLoopError::ScratchTooSmall)
        );
        assert_eq!((syscalls.reads, syscalls.releases), (0, 1));
        assert_eq!(syscalls.response, None);
        assert_eq!(name, [0; 9]);
    }
}
