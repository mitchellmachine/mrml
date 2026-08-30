use crate::{Fat32BlockMountBackend, Fat32MountedProvider};
use mrml_interface_storage_block_provider_v1::BlockProviderReadTransport;
use mrml_interface_storage_filesystem_v3::{
    FilesystemMountTransport, ProtocolError, MOUNT_REQUEST_BYTES, MOUNT_RESPONSE_BYTES,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedFat32MountEnvelope {
    pub payload_length: usize,
    pub capability_count: usize,
}

/// Narrow runtime boundary for canonical FAT32 mount calls.
///
/// Mount options are currently required to be empty, so this operation accepts
/// no transferred capability. The provider's block session is installed in its
/// runtime-proven binding before this loop is constructed.
///
/// # Safety
///
/// `receive_mount` must receive only from the launch-bound endpoint, and
/// `send_mount_response` must reply only to that authenticated caller.
pub unsafe trait Fat32MountServiceSyscalls {
    type Error;

    fn receive_mount(
        &mut self,
        request: &mut [u8; MOUNT_REQUEST_BYTES],
    ) -> Result<ReceivedFat32MountEnvelope, Self::Error>;

    fn send_mount_response(
        &mut self,
        response: &[u8; MOUNT_RESPONSE_BYTES],
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fat32MountServiceLoopError<E> {
    Syscall(E),
    Protocol(ProtocolError),
    InvalidEnvelope,
}

pub struct Fat32MountServiceLoop<'a, T, const N: usize> {
    provider: Fat32MountedProvider<Fat32BlockMountBackend<'a, T>, N>,
}

impl<'a, T, const N: usize> Fat32MountServiceLoop<'a, T, N> {
    pub const fn new(
        provider: Fat32MountedProvider<Fat32BlockMountBackend<'a, T>, N>,
    ) -> Self {
        Self { provider }
    }

    pub fn into_provider(self) -> Fat32MountedProvider<Fat32BlockMountBackend<'a, T>, N> {
        self.provider
    }
}

impl<T: BlockProviderReadTransport, const N: usize> Fat32MountServiceLoop<'_, T, N> {
    pub fn serve_one<S: Fat32MountServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; MOUNT_REQUEST_BYTES],
        response_buffer: &mut [u8; MOUNT_RESPONSE_BYTES],
    ) -> Result<(), Fat32MountServiceLoopError<S::Error>> {
        request_buffer.fill(0);
        response_buffer.fill(0);
        let result = (|| {
            let envelope = syscalls
                .receive_mount(request_buffer)
                .map_err(Fat32MountServiceLoopError::Syscall)?;
            if envelope.payload_length != MOUNT_REQUEST_BYTES || envelope.capability_count != 0 {
                return Err(Fat32MountServiceLoopError::InvalidEnvelope);
            }
            *response_buffer = FilesystemMountTransport::mount(
                &mut self.provider,
                request_buffer,
                &mut [],
            )
            .map_err(Fat32MountServiceLoopError::Protocol)?;
            syscalls
                .send_mount_response(response_buffer)
                .map_err(Fat32MountServiceLoopError::Syscall)
        })();
        request_buffer.fill(0);
        response_buffer.fill(0);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Fat32BlockBinding, FAT32_BOOT_SECTOR_BYTES};
    use mrml_interface_storage_block_provider_v1::{
        decode_read_request, encode_read_response, OpaqueHandle as BlockOpaqueHandle,
        ProtocolError as BlockProtocolError, READ_REQUEST_BYTES, READ_RESPONSE_BYTES,
    };
    use mrml_interface_storage_filesystem_v3::{
        decode_mount_response, encode_mount_request, BorrowedReadView, MountError, OpaqueHandle,
    };

    struct BlockTransport {
        session: BlockOpaqueHandle,
        stale: bool,
    }

    impl BlockProviderReadTransport for BlockTransport {
        fn read(
            &mut self,
            request: &[u8; READ_REQUEST_BYTES],
            memory: &mut [u8],
        ) -> Result<[u8; READ_RESPONSE_BYTES], BlockProtocolError> {
            let request = decode_read_request(request, memory.len() as u64)?;
            assert_eq!(request.session, self.session);
            if self.stale {
                return Ok(encode_read_response(Err(
                    mrml_interface_storage_block_provider_v1::ReadError::StaleObject,
                )));
            }
            memory[..FAT32_BOOT_SECTOR_BYTES].copy_from_slice(&crate::tests::boot_sector());
            Ok(encode_read_response(Ok(memory.len() as u64)))
        }
    }

    struct Syscalls {
        request: [u8; MOUNT_REQUEST_BYTES],
        envelope: ReceivedFat32MountEnvelope,
        response: Option<[u8; MOUNT_RESPONSE_BYTES]>,
    }

    unsafe impl Fat32MountServiceSyscalls for Syscalls {
        type Error = ();

        fn receive_mount(
            &mut self,
            request: &mut [u8; MOUNT_REQUEST_BYTES],
        ) -> Result<ReceivedFat32MountEnvelope, Self::Error> {
            *request = self.request;
            Ok(self.envelope)
        }

        fn send_mount_response(
            &mut self,
            response: &[u8; MOUNT_RESPONSE_BYTES],
        ) -> Result<(), Self::Error> {
            self.response = Some(*response);
            Ok(())
        }
    }

    fn fixture<'a>(
        stale: bool,
        scratch: &'a mut [u8; 4096],
    ) -> (Fat32MountServiceLoop<'a, BlockTransport, 1>, Syscalls) {
        let volume = OpaqueHandle::new(4, 7).unwrap();
        let session = BlockOpaqueHandle::new(9, 11).unwrap();
        // SAFETY: The fixture defines this session as the exact backing for volume.
        let binding = unsafe { Fat32BlockBinding::new(volume, session, 4096).unwrap() };
        let backend = Fat32BlockMountBackend::new(
            binding,
            BlockTransport { session, stale },
            scratch,
        )
        .unwrap();
        let request = encode_mount_request(
            volume,
            BorrowedReadView::within(0, 0, 0).unwrap(),
        )
        .unwrap();
        (
            Fat32MountServiceLoop::new(Fat32MountedProvider::new(backend)),
            Syscalls {
                request,
                envelope: ReceivedFat32MountEnvelope {
                    payload_length: MOUNT_REQUEST_BYTES,
                    capability_count: 0,
                },
                response: None,
            },
        )
    }

    #[test]
    fn mount_loop_publishes_response_then_erases_local_buffers() {
        let mut scratch = [0xaa; 4096];
        let (mut service, mut syscalls) = fixture(false, &mut scratch);
        let mut request = [0xaa; MOUNT_REQUEST_BYTES];
        let mut response = [0xbb; MOUNT_RESPONSE_BYTES];
        service
            .serve_one(&mut syscalls, &mut request, &mut response)
            .unwrap();
        let mounted = decode_mount_response(&syscalls.response.unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(mounted.generation, 1);
        assert_eq!(mounted.root, OpaqueHandle::new(0, 1).unwrap());
        assert_eq!(request, [0; MOUNT_REQUEST_BYTES]);
        assert_eq!(response, [0; MOUNT_RESPONSE_BYTES]);
    }

    #[test]
    fn mount_loop_rejects_nonzero_capability_count_without_reply() {
        let mut scratch = [0xaa; 4096];
        let (mut service, mut syscalls) = fixture(false, &mut scratch);
        syscalls.envelope.capability_count = 1;
        let mut request = [0; MOUNT_REQUEST_BYTES];
        let mut response = [0; MOUNT_RESPONSE_BYTES];
        assert_eq!(
            service.serve_one(&mut syscalls, &mut request, &mut response),
            Err(Fat32MountServiceLoopError::InvalidEnvelope)
        );
        assert_eq!(syscalls.response, None);
    }

    #[test]
    fn mount_loop_returns_typed_stale_response() {
        let mut scratch = [0xaa; 4096];
        let (mut service, mut syscalls) = fixture(true, &mut scratch);
        let mut request = [0; MOUNT_REQUEST_BYTES];
        let mut response = [0; MOUNT_RESPONSE_BYTES];
        service
            .serve_one(&mut syscalls, &mut request, &mut response)
            .unwrap();
        assert_eq!(
            decode_mount_response(&syscalls.response.unwrap()),
            Ok(Err(MountError::StaleObject))
        );
    }
}
