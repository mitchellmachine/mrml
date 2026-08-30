use crate::{Fat32BlockMountBackend, Fat32ReadProvider};
use mrml_interface_storage_block_provider_v1::BlockProviderReadTransport;
use mrml_interface_storage_filesystem_v3::{
    decode_read_request, decode_read_response, encode_read_request, BorrowedWriteView,
    FilesystemReadTransport, ProtocolError, READ_REQUEST_BYTES, READ_RESPONSE_BYTES,
};
use mrml_kernel::Capability;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedFat32ReadEnvelope {
    pub payload_length: usize,
    pub capability_count: usize,
}

/// Runtime boundary for one isolated FAT32 file read.
///
/// # Safety
///
/// Receive must be launch-bound. `write_shared` must resolve only the exact
/// transferred writable-buffer capability, release must enter transitive
/// revocation, and reply must target only the authenticated caller.
pub unsafe trait Fat32ReadServiceSyscalls {
    type Error;

    fn receive_read(
        &mut self,
        request: &mut [u8; READ_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedFat32ReadEnvelope, Self::Error>;

    fn write_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Self::Error>;

    fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error>;

    fn send_read_response(
        &mut self,
        response: &[u8; READ_RESPONSE_BYTES],
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fat32ReadServiceLoopError<E> {
    Syscall(E),
    Protocol(ProtocolError),
    InvalidEnvelope,
    ScratchTooSmall,
}

pub struct Fat32ReadServiceLoop<'a, 'b, 'c, T, const N: usize, const O: usize = 64, const C: usize = 64>
{
    provider: Fat32ReadProvider<'a, 'b, Fat32BlockMountBackend<'c, T>, N, O, C>,
}

impl<'a, 'b, 'c, T, const N: usize, const O: usize, const C: usize>
    Fat32ReadServiceLoop<'a, 'b, 'c, T, N, O, C>
{
    pub const fn new(
        provider: Fat32ReadProvider<'a, 'b, Fat32BlockMountBackend<'c, T>, N, O, C>,
    ) -> Self {
        Self { provider }
    }

    pub fn into_provider(
        self,
    ) -> Fat32ReadProvider<'a, 'b, Fat32BlockMountBackend<'c, T>, N, O, C> {
        self.provider
    }
}

impl<T: BlockProviderReadTransport, const N: usize, const O: usize, const C: usize>
    Fat32ReadServiceLoop<'_, '_, '_, T, N, O, C>
{
    pub fn serve_one<S: Fat32ReadServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; READ_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        output_scratch: &mut [u8],
        response_buffer: &mut [u8; READ_RESPONSE_BYTES],
    ) -> Result<(), Fat32ReadServiceLoopError<S::Error>> {
        request_buffer.fill(0);
        capability_tokens.fill(0);
        output_scratch.fill(0);
        response_buffer.fill(0);
        let mut received = None;
        let result = self.serve_one_inner(
            syscalls,
            request_buffer,
            capability_tokens,
            output_scratch,
            response_buffer,
            &mut received,
        );
        let release = received
            .map(|capability| syscalls.release_received(capability))
            .transpose()
            .map(|_| ())
            .map_err(Fat32ReadServiceLoopError::Syscall);
        let completion = match result.and(release) {
            Ok(()) => syscalls
                .send_read_response(response_buffer)
                .map_err(Fat32ReadServiceLoopError::Syscall),
            Err(error) => Err(error),
        };
        request_buffer.fill(0);
        capability_tokens.fill(0);
        output_scratch.fill(0);
        response_buffer.fill(0);
        completion
    }

    fn serve_one_inner<S: Fat32ReadServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; READ_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        output_scratch: &mut [u8],
        response_buffer: &mut [u8; READ_RESPONSE_BYTES],
        received: &mut Option<Capability>,
    ) -> Result<(), Fat32ReadServiceLoopError<S::Error>> {
        let envelope = syscalls
            .receive_read(request_buffer, capability_tokens)
            .map_err(Fat32ReadServiceLoopError::Syscall)?;
        if envelope.payload_length != READ_REQUEST_BYTES
            || envelope.capability_count != 1
            || capability_tokens[0] == 0
            || capability_tokens[0] >> 32 == 0
        {
            return Err(Fat32ReadServiceLoopError::InvalidEnvelope);
        }
        let capability = Capability::from_token(capability_tokens[0]);
        *received = Some(capability);
        let request = decode_read_request(request_buffer, u64::MAX)
            .map_err(Fat32ReadServiceLoopError::Protocol)?;
        let length = usize::try_from(request.output.length())
            .map_err(|_| Fat32ReadServiceLoopError::ScratchTooSmall)?;
        if length == 0 || length > output_scratch.len() {
            return Err(Fat32ReadServiceLoopError::ScratchTooSmall);
        }
        let local_output = BorrowedWriteView::within(0, length as u64, length as u64)
            .ok_or(Fat32ReadServiceLoopError::ScratchTooSmall)?;
        let local_request = encode_read_request(
            request.volume,
            request.generation,
            request.file,
            request.offset,
            local_output,
        )
        .map_err(Fat32ReadServiceLoopError::Protocol)?;
        *response_buffer = self
            .provider
            .read(&local_request, &mut output_scratch[..length])
            .map_err(Fat32ReadServiceLoopError::Protocol)?;
        if decode_read_response(response_buffer, length as u64)
            .map_err(Fat32ReadServiceLoopError::Protocol)?
            .is_ok()
        {
            syscalls
                .write_shared(capability, request.output.offset(), &output_scratch[..length])
                .map_err(Fat32ReadServiceLoopError::Syscall)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Fat32BlockBinding, Fat32MountedProvider, Fat32ShortDirectoryEntry};
    use mrml_interface_storage_block_provider_v1::{
        decode_read_request as decode_block_read_request,
        encode_read_response as encode_block_read_response, OpaqueHandle as BlockOpaqueHandle,
        ProtocolError as BlockProtocolError, ReadError as BlockReadError,
        READ_REQUEST_BYTES as BLOCK_READ_REQUEST_BYTES,
        READ_RESPONSE_BYTES as BLOCK_READ_RESPONSE_BYTES,
    };
    use mrml_interface_storage_filesystem_v3::{
        decode_read_response, encode_read_request, BorrowedWriteView, OpaqueHandle, ReadError,
    };

    const TOKEN: u64 = (9_u64 << 32) | 4;
    const WRITE: u8 = 1;
    const RELEASE: u8 = 2;
    const SEND: u8 = 3;

    struct Transport {
        session: BlockOpaqueHandle,
    }

    impl BlockProviderReadTransport for Transport {
        fn read(
            &mut self,
            request: &[u8; BLOCK_READ_REQUEST_BYTES],
            memory: &mut [u8],
        ) -> Result<[u8; BLOCK_READ_RESPONSE_BYTES], BlockProtocolError> {
            let request = decode_block_read_request(request, memory.len() as u64)?;
            assert_eq!(request.session, self.session);
            memory.fill(0);
            match request.lba {
                0 => memory[..512].copy_from_slice(&crate::tests::boot_sector()),
                4 | 132 => memory[20..24].copy_from_slice(&0x0fff_ffff_u32.to_le_bytes()),
                263 => {
                    for (index, byte) in memory.iter_mut().enumerate() {
                        *byte = index as u8;
                    }
                }
                _ => return Ok(encode_block_read_response(Err(BlockReadError::IoFailure))),
            }
            Ok(encode_block_read_response(Ok(memory.len() as u64)))
        }
    }

    struct Syscalls {
        request: [u8; READ_REQUEST_BYTES],
        token: u64,
        envelope: ReceivedFat32ReadEnvelope,
        shared: [u8; 16],
        response: Option<[u8; READ_RESPONSE_BYTES]>,
        operations: [u8; 3],
        count: usize,
    }

    unsafe impl Fat32ReadServiceSyscalls for Syscalls {
        type Error = ();

        fn receive_read(
            &mut self,
            request: &mut [u8; READ_REQUEST_BYTES],
            capability_tokens: &mut [u64; 1],
        ) -> Result<ReceivedFat32ReadEnvelope, Self::Error> {
            *request = self.request;
            capability_tokens[0] = self.token;
            Ok(self.envelope)
        }

        fn write_shared(
            &mut self,
            capability: Capability,
            offset: u64,
            input: &[u8],
        ) -> Result<(), Self::Error> {
            assert_eq!(capability.token(), self.token);
            self.operations[self.count] = WRITE;
            self.count += 1;
            let start = usize::try_from(offset).map_err(|_| ())?;
            self.shared
                .get_mut(start..start + input.len())
                .ok_or(())?
                .copy_from_slice(input);
            Ok(())
        }

        fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error> {
            assert_eq!(capability.token(), self.token);
            self.operations[self.count] = RELEASE;
            self.count += 1;
            Ok(())
        }

        fn send_read_response(
            &mut self,
            response: &[u8; READ_RESPONSE_BYTES],
        ) -> Result<(), Self::Error> {
            self.operations[self.count] = SEND;
            self.count += 1;
            self.response = Some(*response);
            Ok(())
        }
    }

    fn fixture<'a, 'b, 'c>(
        block_scratch: &'c mut [u8; 4096],
        staging: &'a mut [u8; 16],
        cluster_scratch: &'b mut [u8; 4096],
    ) -> (Fat32ReadServiceLoop<'a, 'b, 'c, Transport, 1, 1, 1>, Syscalls) {
        let volume = OpaqueHandle::new(4, 7).unwrap();
        let session = BlockOpaqueHandle::new(9, 11).unwrap();
        // SAFETY: This fixture defines the exact session backing this volume.
        let binding = unsafe { Fat32BlockBinding::new(volume, session, 4096).unwrap() };
        let backend = Fat32BlockMountBackend::new(binding, Transport { session }, block_scratch)
            .unwrap();
        let mut provider = Fat32MountedProvider::<_, 1, 1>::new(backend);
        let mounted = provider.mount(volume).unwrap();
        let entry = Fat32ShortDirectoryEntry {
            short_name: *b"KERNEL  MRP",
            long_name: None,
            attributes: 0x20,
            first_cluster: 5,
            file_size: 4096,
        };
        let object = provider
            .identify_root_entry(volume, mounted.generation, mounted.root, entry)
            .unwrap();
        let handle = provider
            .reserve_open(volume, mounted.generation, mounted.root, object)
            .and_then(|reservation| provider.activate_open(reservation))
            .unwrap();
        let output = BorrowedWriteView::within(4, 8, 16).unwrap();
        let request = encode_read_request(volume, mounted.generation, handle, 3, output).unwrap();
        (
            Fat32ReadServiceLoop::new(Fat32ReadProvider::new(
                provider,
                staging,
                cluster_scratch,
            )),
            Syscalls {
                request,
                token: TOKEN,
                envelope: ReceivedFat32ReadEnvelope {
                    payload_length: READ_REQUEST_BYTES,
                    capability_count: 1,
                },
                shared: [0xcc; 16],
                response: None,
                operations: [0; 3],
                count: 0,
            },
        )
    }

    #[test]
    fn successful_read_copies_then_releases_then_replies_and_erases() {
        let mut block_scratch = [0xaa; 4096];
        let mut staging = [0xbb; 16];
        let mut cluster_scratch = [0xcc; 4096];
        let (mut service, mut syscalls) =
            fixture(&mut block_scratch, &mut staging, &mut cluster_scratch);
        let mut request = [0xdd; READ_REQUEST_BYTES];
        let mut tokens = [0; 1];
        let mut output = [0xee; 16];
        let mut response = [0xff; READ_RESPONSE_BYTES];
        service
            .serve_one(
                &mut syscalls,
                &mut request,
                &mut tokens,
                &mut output,
                &mut response,
            )
            .unwrap();
        assert_eq!(syscalls.operations, [WRITE, RELEASE, SEND]);
        assert_eq!(&syscalls.shared[..4], &[0xcc; 4]);
        assert_eq!(&syscalls.shared[4..12], &[3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(&syscalls.shared[12..], &[0xcc; 4]);
        assert_eq!(
            decode_read_response(&syscalls.response.unwrap(), 8),
            Ok(Ok(8))
        );
        assert_eq!(request, [0; READ_REQUEST_BYTES]);
        assert_eq!(tokens, [0; 1]);
        assert_eq!(output, [0; 16]);
        assert_eq!(response, [0; READ_RESPONSE_BYTES]);
    }

    #[test]
    fn invalid_envelope_never_releases_copies_or_replies() {
        let mut block_scratch = [0; 4096];
        let mut staging = [0; 16];
        let mut cluster_scratch = [0; 4096];
        let (mut service, mut syscalls) =
            fixture(&mut block_scratch, &mut staging, &mut cluster_scratch);
        syscalls.envelope.capability_count = 0;
        assert_eq!(
            service.serve_one(
                &mut syscalls,
                &mut [0; READ_REQUEST_BYTES],
                &mut [0; 1],
                &mut [0; 16],
                &mut [0; READ_RESPONSE_BYTES],
            ),
            Err(Fat32ReadServiceLoopError::InvalidEnvelope)
        );
        assert_eq!(syscalls.count, 0);
        assert_eq!(syscalls.response, None);
    }

    #[test]
    fn stale_provider_handle_releases_and_replies_without_copy() {
        let mut block_scratch = [0; 4096];
        let mut staging = [0; 16];
        let mut cluster_scratch = [0; 4096];
        let (mut service, mut syscalls) =
            fixture(&mut block_scratch, &mut staging, &mut cluster_scratch);
        syscalls.request[92..96].copy_from_slice(&99_u32.to_le_bytes());
        service
            .serve_one(
                &mut syscalls,
                &mut [0; READ_REQUEST_BYTES],
                &mut [0; 1],
                &mut [0; 16],
                &mut [0; READ_RESPONSE_BYTES],
            )
            .unwrap();
        assert_eq!(&syscalls.operations[..syscalls.count], &[RELEASE, SEND]);
        assert_eq!(syscalls.shared, [0xcc; 16]);
        assert_eq!(
            decode_read_response(&syscalls.response.unwrap(), 8),
            Ok(Err(ReadError::StaleObject))
        );
    }
}
