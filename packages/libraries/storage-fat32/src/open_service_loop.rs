use crate::Fat32MountedProvider;
use mrml_interface_storage_filesystem_v3::{
    FilesystemOpenTransport, OPEN_REQUEST_BYTES, OPEN_RESPONSE_BYTES, ProtocolError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedFat32OpenEnvelope {
    pub payload_length: usize,
    pub capability_count: usize,
}

/// Runtime boundary for one isolated FAT32 open invocation.
///
/// # Safety
///
/// Receive and reply must use only the launch-bound authenticated caller. This
/// identity-only provider call accepts no transferred capabilities.
pub unsafe trait Fat32OpenServiceSyscalls {
    type Error;

    fn receive_open(
        &mut self,
        request: &mut [u8; OPEN_REQUEST_BYTES],
    ) -> Result<ReceivedFat32OpenEnvelope, Self::Error>;

    fn send_open_response(
        &mut self,
        response: &[u8; OPEN_RESPONSE_BYTES],
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fat32OpenServiceLoopError<E> {
    Syscall(E),
    Protocol(ProtocolError),
    InvalidEnvelope,
}

pub struct Fat32OpenServiceLoop<B, const N: usize, const O: usize = 64> {
    provider: Fat32MountedProvider<B, N, O>,
}

impl<B, const N: usize, const O: usize> Fat32OpenServiceLoop<B, N, O> {
    pub const fn new(provider: Fat32MountedProvider<B, N, O>) -> Self {
        Self { provider }
    }

    pub fn into_provider(self) -> Fat32MountedProvider<B, N, O> {
        self.provider
    }

    pub fn serve_one<S: Fat32OpenServiceSyscalls>(
        &mut self,
        syscalls: &mut S,
        request_buffer: &mut [u8; OPEN_REQUEST_BYTES],
        response_buffer: &mut [u8; OPEN_RESPONSE_BYTES],
    ) -> Result<(), Fat32OpenServiceLoopError<S::Error>> {
        request_buffer.fill(0);
        response_buffer.fill(0);
        let result = (|| {
            let envelope = syscalls
                .receive_open(request_buffer)
                .map_err(Fat32OpenServiceLoopError::Syscall)?;
            if envelope.payload_length != OPEN_REQUEST_BYTES || envelope.capability_count != 0 {
                return Err(Fat32OpenServiceLoopError::InvalidEnvelope);
            }
            *response_buffer = FilesystemOpenTransport::open(&mut self.provider, request_buffer)
                .map_err(Fat32OpenServiceLoopError::Protocol)?;
            syscalls
                .send_open_response(response_buffer)
                .map_err(Fat32OpenServiceLoopError::Syscall)
        })();
        request_buffer.fill(0);
        response_buffer.fill(0);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Fat32MountBackend, Fat32ShortDirectoryEntry, FAT32_BOOT_SECTOR_BYTES};
    use mrml_interface_storage_filesystem_v3::{
        decode_open_response, encode_open_request, OpaqueHandle, OpenError,
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
        request: [u8; OPEN_REQUEST_BYTES],
        envelope: ReceivedFat32OpenEnvelope,
        response: Option<[u8; OPEN_RESPONSE_BYTES]>,
    }

    unsafe impl Fat32OpenServiceSyscalls for Syscalls {
        type Error = ();

        fn receive_open(
            &mut self,
            request: &mut [u8; OPEN_REQUEST_BYTES],
        ) -> Result<ReceivedFat32OpenEnvelope, Self::Error> {
            *request = self.request;
            Ok(self.envelope)
        }

        fn send_open_response(
            &mut self,
            response: &[u8; OPEN_RESPONSE_BYTES],
        ) -> Result<(), Self::Error> {
            self.response = Some(*response);
            Ok(())
        }
    }

    fn fixture() -> (Fat32OpenServiceLoop<Backend, 1, 1>, Syscalls) {
        let volume = OpaqueHandle::new(4, 7).unwrap();
        let mut provider = Fat32MountedProvider::<_, 1, 1>::new(Backend);
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
        (
            Fat32OpenServiceLoop::new(provider),
            Syscalls {
                request: encode_open_request(volume, mounted.generation, mounted.root, object)
                    .unwrap(),
                envelope: ReceivedFat32OpenEnvelope {
                    payload_length: OPEN_REQUEST_BYTES,
                    capability_count: 0,
                },
                response: None,
            },
        )
    }

    #[test]
    fn open_loop_returns_handle_and_erases_buffers() {
        let (mut service, mut syscalls) = fixture();
        let mut request = [0xaa; OPEN_REQUEST_BYTES];
        let mut response = [0xbb; OPEN_RESPONSE_BYTES];
        service
            .serve_one(&mut syscalls, &mut request, &mut response)
            .unwrap();
        assert!(decode_open_response(&syscalls.response.unwrap())
            .unwrap()
            .is_ok());
        assert_eq!(request, [0; OPEN_REQUEST_BYTES]);
        assert_eq!(response, [0; OPEN_RESPONSE_BYTES]);
        syscalls.response = None;
        service
            .serve_one(&mut syscalls, &mut request, &mut response)
            .unwrap();
        assert_eq!(
            decode_open_response(&syscalls.response.unwrap()),
            Ok(Err(OpenError::Capacity))
        );
    }

    #[test]
    fn open_loop_rejects_wrong_envelopes_without_reply() {
        for (payload_length, capability_count) in
            [(OPEN_REQUEST_BYTES - 1, 0), (OPEN_REQUEST_BYTES, 1)]
        {
            let (mut service, mut syscalls) = fixture();
            syscalls.envelope = ReceivedFat32OpenEnvelope {
                payload_length,
                capability_count,
            };
            assert_eq!(
                service.serve_one(
                    &mut syscalls,
                    &mut [0; OPEN_REQUEST_BYTES],
                    &mut [0; OPEN_RESPONSE_BYTES],
                ),
                Err(Fat32OpenServiceLoopError::InvalidEnvelope)
            );
            assert_eq!(syscalls.response, None);
        }
    }
}
