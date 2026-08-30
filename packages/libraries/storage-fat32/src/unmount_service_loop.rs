use crate::Fat32MountedProvider;
use mrml_interface_storage_filesystem_v2::{
    FilesystemUnmountTransport, ProtocolError, UNMOUNT_REQUEST_BYTES, UNMOUNT_RESPONSE_BYTES,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedFat32UnmountEnvelope {
    pub payload_length: usize,
    pub capability_count: usize,
}

/// Narrow runtime boundary for canonical FAT32 unmount calls.
///
/// # Safety
///
/// `receive_unmount` must receive only from the launch-bound endpoint, and
/// `send_unmount_response` must reply only to that authenticated caller. No
/// capability may be accepted for this identity-only lifecycle operation.
pub unsafe trait Fat32UnmountServiceSyscalls {
    type Error;

    fn receive_unmount(
        &mut self,
        request: &mut [u8; UNMOUNT_REQUEST_BYTES],
    ) -> Result<ReceivedFat32UnmountEnvelope, Self::Error>;

    fn send_unmount_response(
        &mut self,
        response: &[u8; UNMOUNT_RESPONSE_BYTES],
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fat32UnmountServiceLoopError<E> {
    Syscall(E),
    Protocol(ProtocolError),
    InvalidEnvelope,
}

pub struct Fat32UnmountServiceLoop<B, const N: usize> {
    provider: Fat32MountedProvider<B, N>,
}

impl<B, const N: usize> Fat32UnmountServiceLoop<B, N> {
    pub const fn new(provider: Fat32MountedProvider<B, N>) -> Self {
        Self { provider }
    }

    pub fn into_provider(self) -> Fat32MountedProvider<B, N> {
        self.provider
    }

    pub fn serve_one<S: Fat32UnmountServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; UNMOUNT_REQUEST_BYTES],
        response_buffer: &mut [u8; UNMOUNT_RESPONSE_BYTES],
    ) -> Result<(), Fat32UnmountServiceLoopError<S::Error>> {
        request_buffer.fill(0);
        response_buffer.fill(0);
        let result = (|| {
            let envelope = syscalls
                .receive_unmount(request_buffer)
                .map_err(Fat32UnmountServiceLoopError::Syscall)?;
            if envelope.payload_length != UNMOUNT_REQUEST_BYTES || envelope.capability_count != 0 {
                return Err(Fat32UnmountServiceLoopError::InvalidEnvelope);
            }
            *response_buffer =
                FilesystemUnmountTransport::unmount(&mut self.provider, request_buffer)
                    .map_err(Fat32UnmountServiceLoopError::Protocol)?;
            syscalls
                .send_unmount_response(response_buffer)
                .map_err(Fat32UnmountServiceLoopError::Syscall)
        })();
        request_buffer.fill(0);
        response_buffer.fill(0);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Fat32MountBackend, FAT32_BOOT_SECTOR_BYTES};
    use mrml_interface_storage_filesystem_v2::{
        decode_unmount_response, encode_unmount_request, OpaqueHandle, UnmountError,
    };

    struct Backend;

    unsafe impl Fat32MountBackend for Backend {
        type Error = ();

        fn read_boot_sector(
            &mut self,
            _volume: OpaqueHandle,
            output: &mut [u8; FAT32_BOOT_SECTOR_BYTES],
        ) -> Result<(), Self::Error> {
            *output = crate::tests::boot_sector();
            Ok(())
        }
    }

    struct Syscalls {
        request: [u8; UNMOUNT_REQUEST_BYTES],
        envelope: ReceivedFat32UnmountEnvelope,
        response: Option<[u8; UNMOUNT_RESPONSE_BYTES]>,
    }

    unsafe impl Fat32UnmountServiceSyscalls for Syscalls {
        type Error = ();

        fn receive_unmount(
            &mut self,
            request: &mut [u8; UNMOUNT_REQUEST_BYTES],
        ) -> Result<ReceivedFat32UnmountEnvelope, Self::Error> {
            *request = self.request;
            Ok(self.envelope)
        }

        fn send_unmount_response(
            &mut self,
            response: &[u8; UNMOUNT_RESPONSE_BYTES],
        ) -> Result<(), Self::Error> {
            self.response = Some(*response);
            Ok(())
        }
    }

    fn fixture() -> (Fat32UnmountServiceLoop<Backend, 1>, Syscalls) {
        let volume = OpaqueHandle::new(4, 7).unwrap();
        let mut provider = Fat32MountedProvider::<_, 1>::new(Backend);
        let mounted = provider.mount(volume).unwrap();
        (
            Fat32UnmountServiceLoop::new(provider),
            Syscalls {
                request: encode_unmount_request(volume, mounted.generation).unwrap(),
                envelope: ReceivedFat32UnmountEnvelope {
                    payload_length: UNMOUNT_REQUEST_BYTES,
                    capability_count: 0,
                },
                response: None,
            },
        )
    }

    #[test]
    fn unmount_loop_removes_exact_record_and_erases_local_buffers() {
        let (mut service, mut syscalls) = fixture();
        let mut request = [0xaa; UNMOUNT_REQUEST_BYTES];
        let mut response = [0xbb; UNMOUNT_RESPONSE_BYTES];
        service
            .serve_one(&mut syscalls, &mut request, &mut response)
            .unwrap();
        assert_eq!(
            decode_unmount_response(&syscalls.response.unwrap()),
            Ok(Ok(1))
        );
        assert_eq!(request, [0; UNMOUNT_REQUEST_BYTES]);
        assert_eq!(response, [0; UNMOUNT_RESPONSE_BYTES]);

        syscalls.response = None;
        service
            .serve_one(&mut syscalls, &mut request, &mut response)
            .unwrap();
        assert_eq!(
            decode_unmount_response(&syscalls.response.unwrap()),
            Ok(Err(UnmountError::StaleObject))
        );
    }

    #[test]
    fn unmount_loop_rejects_wrong_payload_or_capability_count_without_reply() {
        for (payload_length, capability_count) in
            [(UNMOUNT_REQUEST_BYTES - 1, 0), (UNMOUNT_REQUEST_BYTES, 1)]
        {
            let (mut service, mut syscalls) = fixture();
            syscalls.envelope = ReceivedFat32UnmountEnvelope {
                payload_length,
                capability_count,
            };
            let mut request = [0; UNMOUNT_REQUEST_BYTES];
            let mut response = [0; UNMOUNT_RESPONSE_BYTES];
            assert_eq!(
                service.serve_one(&mut syscalls, &mut request, &mut response),
                Err(Fat32UnmountServiceLoopError::InvalidEnvelope)
            );
            assert_eq!(syscalls.response, None);
        }
    }
}
