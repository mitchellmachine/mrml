use crate::{Fat32BlockMountBackend, Fat32MountedProvider, Fat32Provider};
use mrml_interface_storage_block_provider_v1::BlockProviderReadTransport;
use mrml_interface_storage_filesystem_v3::{
    FilesystemMountTransport, FilesystemOpenTransport, FilesystemOperation, FilesystemTransport,
    FilesystemUnmountTransport, LOOKUP_REQUEST_BYTES, LOOKUP_RESPONSE_BYTES, MOUNT_REQUEST_BYTES,
    MOUNT_RESPONSE_BYTES, OPEN_REQUEST_BYTES, OPEN_RESPONSE_BYTES, PROBE_REQUEST_BYTES,
    PROBE_RESPONSE_BYTES, ProtocolError, READ_REQUEST_BYTES, READ_RESPONSE_BYTES,
    UNMOUNT_REQUEST_BYTES, UNMOUNT_RESPONSE_BYTES, decode_lookup_request, decode_probe_request,
    decode_read_request, decode_request_operation,
};
use mrml_kernel::Capability;

pub const FAT32_DISPATCH_REQUEST_BYTES: usize = READ_REQUEST_BYTES;
pub const FAT32_DISPATCH_RESPONSE_BYTES: usize = MOUNT_RESPONSE_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedFat32DispatchEnvelope {
    pub payload_length: usize,
    pub capability_count: usize,
}

/// Unified runtime boundary for the isolated FAT32 service entry.
///
/// # Safety
///
/// Receive and reply must remain bound to the authenticated launch caller.
/// Shared access must resolve only the exact transferred capability, and
/// release must enter transitive revocation for that received leaf.
pub unsafe trait Fat32DispatchSyscalls {
    type Error;

    fn receive_dispatch(
        &mut self,
        request: &mut [u8; FAT32_DISPATCH_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedFat32DispatchEnvelope, Self::Error>;

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

    fn send_dispatch_response(&mut self, response: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fat32DispatchServiceError<E> {
    Syscall(E),
    Protocol(ProtocolError),
    InvalidEnvelope,
    ScratchTooSmall,
    UnsupportedOperation,
}

pub struct Fat32DispatchService<
    'a,
    'b,
    'c,
    T,
    const N: usize,
    const O: usize = 64,
    const C: usize = 64,
> {
    provider: Fat32MountedProvider<Fat32BlockMountBackend<'a, T>, N, O>,
    cluster_scratch: &'b mut [u8],
    staging: &'c mut [u8],
}

impl<'a, 'b, 'c, T, const N: usize, const O: usize, const C: usize>
    Fat32DispatchService<'a, 'b, 'c, T, N, O, C>
{
    pub fn new(
        provider: Fat32MountedProvider<Fat32BlockMountBackend<'a, T>, N, O>,
        cluster_scratch: &'b mut [u8],
        staging: &'c mut [u8],
    ) -> Self {
        cluster_scratch.fill(0);
        staging.fill(0);
        Self {
            provider,
            cluster_scratch,
            staging,
        }
    }

    pub fn into_provider(self) -> Fat32MountedProvider<Fat32BlockMountBackend<'a, T>, N, O> {
        self.provider
    }
}

impl<T: BlockProviderReadTransport, const N: usize, const O: usize, const C: usize>
    Fat32DispatchService<'_, '_, '_, T, N, O, C>
{
    pub fn serve_one<S: Fat32DispatchSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; FAT32_DISPATCH_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        shared_scratch: &mut [u8],
        response_buffer: &mut [u8; FAT32_DISPATCH_RESPONSE_BYTES],
    ) -> Result<(), Fat32DispatchServiceError<S::Error>> {
        request_buffer.fill(0);
        capability_tokens.fill(0);
        shared_scratch.fill(0);
        response_buffer.fill(0);
        let mut received = None;
        let result = self.serve_one_inner(
            syscalls,
            request_buffer,
            capability_tokens,
            shared_scratch,
            response_buffer,
            &mut received,
        );
        let release = received
            .map(|capability| syscalls.release_received(capability))
            .transpose()
            .map(|_| ())
            .map_err(Fat32DispatchServiceError::Syscall);
        let result = result.and_then(|response_length| release.map(|()| response_length));
        let completion = match result {
            Ok(response_length) => syscalls
                .send_dispatch_response(&response_buffer[..response_length])
                .map_err(Fat32DispatchServiceError::Syscall),
            Err(error) => Err(error),
        };
        request_buffer.fill(0);
        capability_tokens.fill(0);
        shared_scratch.fill(0);
        response_buffer.fill(0);
        completion
    }

    fn serve_one_inner<S: Fat32DispatchSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; FAT32_DISPATCH_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
        shared_scratch: &mut [u8],
        response_buffer: &mut [u8; FAT32_DISPATCH_RESPONSE_BYTES],
        received: &mut Option<Capability>,
    ) -> Result<usize, Fat32DispatchServiceError<S::Error>> {
        let envelope = syscalls
            .receive_dispatch(request_buffer, capability_tokens)
            .map_err(Fat32DispatchServiceError::Syscall)?;
        if envelope.payload_length > request_buffer.len() || envelope.capability_count > 1 {
            return Err(Fat32DispatchServiceError::InvalidEnvelope);
        }
        if envelope.capability_count == 1 {
            if capability_tokens[0] == 0 || capability_tokens[0] >> 32 == 0 {
                return Err(Fat32DispatchServiceError::InvalidEnvelope);
            }
            *received = Some(Capability::from_token(capability_tokens[0]));
        }
        let operation = decode_request_operation(&request_buffer[..envelope.payload_length])
            .map_err(Fat32DispatchServiceError::Protocol)?;
        let expected_capabilities = match operation {
            FilesystemOperation::Probe
            | FilesystemOperation::Lookup
            | FilesystemOperation::Read => 1,
            FilesystemOperation::Mount
            | FilesystemOperation::Unmount
            | FilesystemOperation::Open => 0,
            _ => return Err(Fat32DispatchServiceError::UnsupportedOperation),
        };
        if envelope.capability_count != expected_capabilities {
            return Err(Fat32DispatchServiceError::InvalidEnvelope);
        }
        match operation {
            FilesystemOperation::Probe => {
                let request: &[u8; PROBE_REQUEST_BYTES] = request_buffer[..PROBE_REQUEST_BYTES]
                    .try_into()
                    .map_err(|_| Fat32DispatchServiceError::InvalidEnvelope)?;
                let decoded = decode_probe_request(request, u64::MAX)
                    .map_err(Fat32DispatchServiceError::Protocol)?;
                let length = usize::try_from(decoded.header.length())
                    .map_err(|_| Fat32DispatchServiceError::ScratchTooSmall)?;
                let scratch = shared_scratch
                    .get_mut(..length)
                    .ok_or(Fat32DispatchServiceError::ScratchTooSmall)?;
                syscalls
                    .read_shared(received.unwrap(), decoded.header.offset(), scratch)
                    .map_err(Fat32DispatchServiceError::Syscall)?;
                let local = mrml_interface_storage_filesystem_v3::BorrowedReadView::within(
                    0,
                    length as u64,
                    length as u64,
                )
                .ok_or(Fat32DispatchServiceError::ScratchTooSmall)?;
                let local_request = mrml_interface_storage_filesystem_v3::encode_probe_request(
                    decoded.volume,
                    local,
                )
                .map_err(Fat32DispatchServiceError::Protocol)?;
                let response = Fat32Provider
                    .probe(&local_request, scratch)
                    .map_err(Fat32DispatchServiceError::Protocol)?;
                response_buffer[..PROBE_RESPONSE_BYTES].copy_from_slice(&response);
                Ok(PROBE_RESPONSE_BYTES)
            }
            FilesystemOperation::Mount => {
                let request: &[u8; MOUNT_REQUEST_BYTES] = request_buffer[..MOUNT_REQUEST_BYTES]
                    .try_into()
                    .map_err(|_| Fat32DispatchServiceError::InvalidEnvelope)?;
                let response =
                    FilesystemMountTransport::mount(&mut self.provider, request, &mut [])
                        .map_err(Fat32DispatchServiceError::Protocol)?;
                response_buffer[..MOUNT_RESPONSE_BYTES].copy_from_slice(&response);
                Ok(MOUNT_RESPONSE_BYTES)
            }
            FilesystemOperation::Unmount => {
                let request: &[u8; UNMOUNT_REQUEST_BYTES] = request_buffer[..UNMOUNT_REQUEST_BYTES]
                    .try_into()
                    .map_err(|_| Fat32DispatchServiceError::InvalidEnvelope)?;
                let response = FilesystemUnmountTransport::unmount(&mut self.provider, request)
                    .map_err(Fat32DispatchServiceError::Protocol)?;
                response_buffer[..UNMOUNT_RESPONSE_BYTES].copy_from_slice(&response);
                Ok(UNMOUNT_RESPONSE_BYTES)
            }
            FilesystemOperation::Lookup => {
                let request: &[u8; LOOKUP_REQUEST_BYTES] = request_buffer[..LOOKUP_REQUEST_BYTES]
                    .try_into()
                    .map_err(|_| Fat32DispatchServiceError::InvalidEnvelope)?;
                let decoded = decode_lookup_request(request, u64::MAX)
                    .map_err(Fat32DispatchServiceError::Protocol)?;
                let length = usize::try_from(decoded.name.length())
                    .map_err(|_| Fat32DispatchServiceError::ScratchTooSmall)?;
                let scratch = shared_scratch
                    .get_mut(..length)
                    .ok_or(Fat32DispatchServiceError::ScratchTooSmall)?;
                syscalls
                    .read_shared(received.unwrap(), decoded.name.offset(), scratch)
                    .map_err(Fat32DispatchServiceError::Syscall)?;
                let local = mrml_interface_storage_filesystem_v3::BorrowedReadView::within(
                    0,
                    length as u64,
                    length as u64,
                )
                .ok_or(Fat32DispatchServiceError::ScratchTooSmall)?;
                let local_request = mrml_interface_storage_filesystem_v3::encode_lookup_request(
                    decoded.volume,
                    decoded.generation,
                    decoded.directory,
                    local,
                )
                .map_err(Fat32DispatchServiceError::Protocol)?;
                let response = self
                    .provider
                    .lookup_with_scratch(&local_request, scratch, self.cluster_scratch)
                    .map_err(Fat32DispatchServiceError::Protocol)?;
                response_buffer[..LOOKUP_RESPONSE_BYTES].copy_from_slice(&response);
                Ok(LOOKUP_RESPONSE_BYTES)
            }
            FilesystemOperation::Open => {
                let request: &[u8; OPEN_REQUEST_BYTES] = request_buffer[..OPEN_REQUEST_BYTES]
                    .try_into()
                    .map_err(|_| Fat32DispatchServiceError::InvalidEnvelope)?;
                let response = self
                    .provider
                    .open(request)
                    .map_err(Fat32DispatchServiceError::Protocol)?;
                response_buffer[..OPEN_RESPONSE_BYTES].copy_from_slice(&response);
                Ok(OPEN_RESPONSE_BYTES)
            }
            FilesystemOperation::Read => {
                let request: &[u8; READ_REQUEST_BYTES] = request_buffer[..READ_REQUEST_BYTES]
                    .try_into()
                    .map_err(|_| Fat32DispatchServiceError::InvalidEnvelope)?;
                let decoded = decode_read_request(request, u64::MAX)
                    .map_err(Fat32DispatchServiceError::Protocol)?;
                let length = usize::try_from(decoded.output.length())
                    .map_err(|_| Fat32DispatchServiceError::ScratchTooSmall)?;
                let scratch = shared_scratch
                    .get_mut(..length)
                    .ok_or(Fat32DispatchServiceError::ScratchTooSmall)?;
                let local = mrml_interface_storage_filesystem_v3::BorrowedWriteView::within(
                    0,
                    length as u64,
                    length as u64,
                )
                .ok_or(Fat32DispatchServiceError::ScratchTooSmall)?;
                let local_request = mrml_interface_storage_filesystem_v3::encode_read_request(
                    decoded.volume,
                    decoded.generation,
                    decoded.file,
                    decoded.offset,
                    local,
                )
                .map_err(Fat32DispatchServiceError::Protocol)?;
                let response = self
                    .provider
                    .read_with_scratch::<C>(
                        &local_request,
                        scratch,
                        self.staging,
                        self.cluster_scratch,
                    )
                    .map_err(Fat32DispatchServiceError::Protocol)?;
                if mrml_interface_storage_filesystem_v3::decode_read_response(
                    &response,
                    length as u64,
                )
                .map_err(Fat32DispatchServiceError::Protocol)?
                .is_ok()
                {
                    syscalls
                        .write_shared(received.unwrap(), decoded.output.offset(), scratch)
                        .map_err(Fat32DispatchServiceError::Syscall)?;
                }
                response_buffer[..READ_RESPONSE_BYTES].copy_from_slice(&response);
                Ok(READ_RESPONSE_BYTES)
            }
            _ => Err(Fat32DispatchServiceError::UnsupportedOperation),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FAT32_BOOT_SECTOR_BYTES, Fat32BlockBinding};
    use mrml_interface_storage_block_provider_v1::{
        OpaqueHandle as BlockOpaqueHandle, ProtocolError as BlockProtocolError,
        READ_REQUEST_BYTES as BLOCK_READ_REQUEST_BYTES,
        READ_RESPONSE_BYTES as BLOCK_READ_RESPONSE_BYTES,
        decode_read_request as decode_block_read_request,
        encode_read_response as encode_block_read_response,
    };
    use mrml_interface_storage_filesystem_v3::{
        BorrowedReadView, OpaqueHandle, decode_mount_response, decode_probe_response,
        decode_unmount_response, encode_mount_request, encode_probe_request,
        encode_unmount_request,
    };

    const TOKEN: u64 = (9_u64 << 32) | 4;

    struct Transport;

    impl BlockProviderReadTransport for Transport {
        fn read(
            &mut self,
            request: &[u8; BLOCK_READ_REQUEST_BYTES],
            memory: &mut [u8],
        ) -> Result<[u8; BLOCK_READ_RESPONSE_BYTES], BlockProtocolError> {
            let request = decode_block_read_request(request, memory.len() as u64)?;
            let bytes = crate::tests::boot_sector();
            memory.copy_from_slice(&bytes);
            Ok(encode_block_read_response(Ok(request.output.length())))
        }
    }

    struct Syscalls {
        request: [u8; FAT32_DISPATCH_REQUEST_BYTES],
        payload_length: usize,
        capability_count: usize,
        shared: [u8; FAT32_BOOT_SECTOR_BYTES],
        response: [u8; FAT32_DISPATCH_RESPONSE_BYTES],
        response_length: usize,
        reads: usize,
        writes: usize,
        releases: usize,
    }

    unsafe impl Fat32DispatchSyscalls for Syscalls {
        type Error = ();

        fn receive_dispatch(
            &mut self,
            request: &mut [u8; FAT32_DISPATCH_REQUEST_BYTES],
            capability_tokens: &mut [u64; 1],
        ) -> Result<ReceivedFat32DispatchEnvelope, Self::Error> {
            *request = self.request;
            if self.capability_count == 1 {
                capability_tokens[0] = TOKEN;
            }
            Ok(ReceivedFat32DispatchEnvelope {
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
            self.reads += 1;
            let start = usize::try_from(offset).map_err(|_| ())?;
            output.copy_from_slice(self.shared.get(start..start + output.len()).ok_or(())?);
            Ok(())
        }

        fn write_shared(
            &mut self,
            capability: Capability,
            _offset: u64,
            _input: &[u8],
        ) -> Result<(), Self::Error> {
            assert_eq!(capability.token(), TOKEN);
            self.writes += 1;
            Ok(())
        }

        fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error> {
            assert_eq!(capability.token(), TOKEN);
            self.releases += 1;
            Ok(())
        }

        fn send_dispatch_response(&mut self, response: &[u8]) -> Result<(), Self::Error> {
            self.response[..response.len()].copy_from_slice(response);
            self.response_length = response.len();
            Ok(())
        }
    }

    fn syscalls(request: &[u8], capability_count: usize) -> Syscalls {
        let mut buffer = [0; FAT32_DISPATCH_REQUEST_BYTES];
        buffer[..request.len()].copy_from_slice(request);
        Syscalls {
            request: buffer,
            payload_length: request.len(),
            capability_count,
            shared: crate::tests::boot_sector(),
            response: [0; FAT32_DISPATCH_RESPONSE_BYTES],
            response_length: 0,
            reads: 0,
            writes: 0,
            releases: 0,
        }
    }

    #[test]
    fn dispatch_routes_probe_and_releases_before_publishing() {
        let volume = OpaqueHandle::new(3, 8).unwrap();
        let block_session = BlockOpaqueHandle::new(5, 7).unwrap();
        let binding = unsafe { Fat32BlockBinding::new(volume, block_session, 512).unwrap() };
        let mut block_scratch = [0; 512];
        let backend = Fat32BlockMountBackend::new(binding, Transport, &mut block_scratch).unwrap();
        let provider = Fat32MountedProvider::<_, 1, 1>::new(backend);
        let mut cluster_scratch = [0; 512];
        let mut staging = [0; 512];
        let mut service =
            Fat32DispatchService::<_, 1, 1, 1>::new(provider, &mut cluster_scratch, &mut staging);
        let request =
            encode_probe_request(volume, BorrowedReadView::within(0, 512, 512).unwrap()).unwrap();
        let mut syscalls = syscalls(&request, 1);
        let mut request_buffer = [0; FAT32_DISPATCH_REQUEST_BYTES];
        let mut tokens = [0; 1];
        let mut shared_scratch = [0; 512];
        let mut response = [0; FAT32_DISPATCH_RESPONSE_BYTES];
        service
            .serve_one(
                &mut syscalls,
                &mut request_buffer,
                &mut tokens,
                &mut shared_scratch,
                &mut response,
            )
            .unwrap();
        assert_eq!(
            decode_probe_response(
                syscalls.response[..PROBE_RESPONSE_BYTES]
                    .try_into()
                    .unwrap()
            ),
            Ok(Ok(100))
        );
        assert_eq!((syscalls.reads, syscalls.releases), (1, 1));
        assert_eq!(syscalls.response_length, PROBE_RESPONSE_BYTES);
        assert_eq!(request_buffer, [0; FAT32_DISPATCH_REQUEST_BYTES]);
        assert_eq!(shared_scratch, [0; 512]);
        assert_eq!(response, [0; FAT32_DISPATCH_RESPONSE_BYTES]);
    }

    #[test]
    fn dispatch_preserves_one_mount_lifecycle_across_calls() {
        let volume = OpaqueHandle::new(3, 8).unwrap();
        let block_session = BlockOpaqueHandle::new(5, 7).unwrap();
        let binding = unsafe { Fat32BlockBinding::new(volume, block_session, 512).unwrap() };
        let mut block_scratch = [0; 512];
        let backend = Fat32BlockMountBackend::new(binding, Transport, &mut block_scratch).unwrap();
        let provider = Fat32MountedProvider::<_, 1, 1>::new(backend);
        let mut cluster_scratch = [0; 512];
        let mut staging = [0; 512];
        let mut service =
            Fat32DispatchService::<_, 1, 1, 1>::new(provider, &mut cluster_scratch, &mut staging);
        let mount =
            encode_mount_request(volume, BorrowedReadView::within(0, 0, 0).unwrap()).unwrap();
        let mut mount_syscalls = syscalls(&mount, 0);
        let mut request_buffer = [0; FAT32_DISPATCH_REQUEST_BYTES];
        let mut tokens = [0; 1];
        let mut shared_scratch = [0; 512];
        let mut response = [0; FAT32_DISPATCH_RESPONSE_BYTES];
        service
            .serve_one(
                &mut mount_syscalls,
                &mut request_buffer,
                &mut tokens,
                &mut shared_scratch,
                &mut response,
            )
            .unwrap();
        let mounted = decode_mount_response(
            mount_syscalls.response[..MOUNT_RESPONSE_BYTES]
                .try_into()
                .unwrap(),
        )
        .unwrap()
        .unwrap();
        let unmount = encode_unmount_request(volume, mounted.generation).unwrap();
        let mut unmount_syscalls = syscalls(&unmount, 0);
        service
            .serve_one(
                &mut unmount_syscalls,
                &mut request_buffer,
                &mut tokens,
                &mut shared_scratch,
                &mut response,
            )
            .unwrap();
        assert!(
            decode_unmount_response(
                unmount_syscalls.response[..UNMOUNT_RESPONSE_BYTES]
                    .try_into()
                    .unwrap()
            )
            .unwrap()
            .is_ok()
        );
        let mut stale = syscalls(&unmount, 0);
        service
            .serve_one(
                &mut stale,
                &mut request_buffer,
                &mut tokens,
                &mut shared_scratch,
                &mut response,
            )
            .unwrap();
        assert!(
            decode_unmount_response(stale.response[..UNMOUNT_RESPONSE_BYTES].try_into().unwrap())
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn malformed_dispatch_releases_only_a_structurally_valid_received_leaf() {
        let volume = OpaqueHandle::new(3, 8).unwrap();
        let block_session = BlockOpaqueHandle::new(5, 7).unwrap();
        let binding = unsafe { Fat32BlockBinding::new(volume, block_session, 512).unwrap() };
        let mut block_scratch = [0; 512];
        let backend = Fat32BlockMountBackend::new(binding, Transport, &mut block_scratch).unwrap();
        let provider = Fat32MountedProvider::<_, 1, 1>::new(backend);
        let mut cluster_scratch = [0; 512];
        let mut staging = [0; 512];
        let mut service =
            Fat32DispatchService::<_, 1, 1, 1>::new(provider, &mut cluster_scratch, &mut staging);
        let mut syscalls = syscalls(&[0; PROBE_REQUEST_BYTES], 1);
        let mut request_buffer = [0; FAT32_DISPATCH_REQUEST_BYTES];
        let mut tokens = [0; 1];
        let mut shared_scratch = [0; 512];
        let mut response = [0; FAT32_DISPATCH_RESPONSE_BYTES];
        assert_eq!(
            service.serve_one(
                &mut syscalls,
                &mut request_buffer,
                &mut tokens,
                &mut shared_scratch,
                &mut response,
            ),
            Err(Fat32DispatchServiceError::Protocol(
                ProtocolError::InvalidHeader
            ))
        );
        assert_eq!(syscalls.releases, 1);
        assert_eq!(syscalls.response_length, 0);
    }
}
