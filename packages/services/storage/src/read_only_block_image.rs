//! Immutable, in-memory backing for the canonical block-provider read ABI.

use mrml_interface_storage_block_provider_v1::{
    BlockProviderReadTransport, OpaqueHandle, ProtocolError, READ_REQUEST_BYTES,
    READ_RESPONSE_BYTES, ReadError, ReadRequest, decode_read_request, encode_read_response,
};
use mrml_kernel::{
    CapabilitySpace, GuestMemory, IpcSharedBufferBackend, IpcSharedBufferError,
    IpcSharedBufferIoError, ReceivedMessage, Rights, SharedMemoryBindings,
    SharedWriteCopyBindingId, SharedWriteCopyBindings, TaskId, VmId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOnlyBlockDispatchError<E> {
    WrongSender,
    Protocol(ProtocolError),
    Buffer(IpcSharedBufferIoError<E>),
}

/// An already admitted, immutable image and its exact block session.
///
/// The owner must supply the image and authenticated session. This object is
/// only a data-plane adapter: a wire token never authenticates an IPC sender
/// or authorizes a shared-memory copy. The service must enforce those
/// boundaries before passing the request and local scratch here.
pub struct ReadOnlyBlockImage<'a> {
    image: &'a [u8],
    sector_bytes: usize,
    session: OpaqueHandle,
}

impl<'a> ReadOnlyBlockImage<'a> {
    pub fn new(image: &'a [u8], sector_bytes: usize, session: OpaqueHandle) -> Option<Self> {
        if !matches!(sector_bytes, 512 | 1024 | 2048 | 4096)
            || image.is_empty()
            || !image.len().is_multiple_of(sector_bytes)
        {
            return None;
        }
        Some(Self {
            image,
            sector_bytes,
            session,
        })
    }

    pub fn sector_count(&self) -> usize {
        self.image.len() / self.sector_bytes
    }

    /// Serve the canonical READ operation through one exact non-mapped write projection.
    ///
    /// Call with a message dequeued from the launch-bound receiver and that
    /// receiver's live task, capability space and binding. The route owner
    /// must separately handle received-capability release and reply delivery.
    /// Neither the sender nor the projection can be selected by wire bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_write_copy<
        const CAPS: usize,
        const MAPPINGS: usize,
        const SOURCE_BINDINGS: usize,
        const COPY_BINDINGS: usize,
        B: IpcSharedBufferBackend,
    >(
        &self,
        expected_sender: TaskId,
        received: &ReceivedMessage,
        receiver_space: &CapabilitySpace<CAPS>,
        source_bindings: &SharedMemoryBindings<SOURCE_BINDINGS>,
        copy_bindings: &SharedWriteCopyBindings<COPY_BINDINGS>,
        copy_binding: SharedWriteCopyBindingId,
        memory: &GuestMemory<MAPPINGS>,
        vm: VmId,
        receiver_task: TaskId,
        backend: &mut B,
    ) -> Result<[u8; READ_RESPONSE_BYTES], ReadOnlyBlockDispatchError<B::Error>> {
        if received.sender() != expected_sender {
            return Err(ReadOnlyBlockDispatchError::WrongSender);
        }
        let message = received.message();
        let request = message
            .payload()
            .try_into()
            .map_err(|_| ReadOnlyBlockDispatchError::Protocol(ProtocolError::InvalidRequest))?;
        let denied = |error| {
            ReadOnlyBlockDispatchError::Buffer(IpcSharedBufferIoError::Authorization(error))
        };
        let authority = message
            .authorize_single_capability(receiver_space, Rights::MAP.union(Rights::WRITE))
            .map_err(IpcSharedBufferError::Ipc)
            .map_err(denied)?;
        let resource = copy_bindings
            .resolve(
                copy_binding,
                source_bindings,
                receiver_space,
                authority.capability(),
                memory,
                vm,
                receiver_task,
            )
            .map_err(IpcSharedBufferError::Binding)
            .map_err(denied)?;
        let request = decode_read_request(request, resource.bytes())
            .map_err(ReadOnlyBlockDispatchError::Protocol)?;
        let source = match self.source_bytes(request) {
            Ok(source) => source,
            Err(error) => return Ok(encode_read_response(Err(error))),
        };
        message
            .write_single_shared_copy(
                receiver_space,
                source_bindings,
                copy_bindings,
                copy_binding,
                memory,
                vm,
                receiver_task,
                request.output.offset(),
                source,
                backend,
            )
            .map_err(ReadOnlyBlockDispatchError::Buffer)?;
        Ok(encode_read_response(Ok(request.output.length())))
    }

    fn source_bytes(&self, request: ReadRequest) -> Result<&[u8], ReadError> {
        if request.session != self.session {
            return Err(ReadError::StaleObject);
        }
        let length = usize::try_from(request.sector_count)
            .ok()
            .and_then(|count| count.checked_mul(self.sector_bytes))
            .filter(|length| *length as u64 == request.output.length())
            .ok_or(ReadError::InvalidRequest)?;
        let start = usize::try_from(request.lba)
            .ok()
            .and_then(|lba| lba.checked_mul(self.sector_bytes))
            .ok_or(ReadError::InvalidRequest)?;
        let end = start.checked_add(length).ok_or(ReadError::InvalidRequest)?;
        self.image.get(start..end).ok_or(ReadError::InvalidRequest)
    }

    fn read_range(
        &self,
        request: &[u8; READ_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<Result<u64, ReadError>, ProtocolError> {
        let decoded = decode_read_request(request, memory.len() as u64)?;
        let source = match self.source_bytes(decoded) {
            Ok(source) => source,
            Err(error) => return Ok(Err(error)),
        };
        let output = usize::try_from(decoded.output.offset())
            .ok()
            .and_then(|start| memory.get_mut(start..start.checked_add(source.len())?));
        let Some(output) = output else {
            return Ok(Err(ReadError::InvalidRequest));
        };
        output.copy_from_slice(source);
        Ok(Ok(decoded.output.length()))
    }
}

impl BlockProviderReadTransport for ReadOnlyBlockImage<'_> {
    fn read(
        &mut self,
        request: &[u8; READ_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; READ_RESPONSE_BYTES], ProtocolError> {
        self.read_range(request, memory).map(encode_read_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_interface_storage_block_provider_v1::{
        BorrowedWriteView, decode_read_response, encode_read_request,
    };

    #[test]
    fn copies_only_the_exact_borrowed_range_from_the_admitted_session() {
        let mut image = [0x22; 1024];
        image[512..].fill(0x55);
        let session = OpaqueHandle::new(1, 2).unwrap();
        let mut provider = ReadOnlyBlockImage::new(&image, 512, session).unwrap();
        assert_eq!(provider.sector_count(), 2);
        let mut memory = [0xaa; 524];
        let output = BorrowedWriteView::within(5, 512, memory.len() as u64).unwrap();
        let request = encode_read_request(session, 1, 1, output).unwrap();
        let response = provider.read(&request, &mut memory).unwrap();
        assert_eq!(decode_read_response(&response, 512), Ok(Ok(512)));
        assert_eq!(memory[..5], [0xaa; 5]);
        assert_eq!(memory[5..517], [0x55; 512]);
        assert_eq!(memory[517..], [0xaa; 7]);
    }

    #[test]
    fn stale_sessions_and_bad_extents_do_not_publish_bytes() {
        let image = [0x33; 1024];
        let session = OpaqueHandle::new(1, 2).unwrap();
        assert!(ReadOnlyBlockImage::new(&image[..513], 512, session).is_none());
        let mut provider = ReadOnlyBlockImage::new(&image, 512, session).unwrap();
        let mut memory = [0xaa; 1024];
        let view = BorrowedWriteView::within(0, 512, 1024).unwrap();
        for (handle, lba, sectors, expected) in [
            (
                OpaqueHandle::new(1, 1).unwrap(),
                0,
                1,
                ReadError::StaleObject,
            ),
            (session, 2, 1, ReadError::InvalidRequest),
            (session, u64::MAX, 1, ReadError::InvalidRequest),
            (session, 0, 2, ReadError::InvalidRequest),
        ] {
            let request = encode_read_request(handle, lba, sectors, view).unwrap();
            let response = provider.read(&request, &mut memory).unwrap();
            assert_eq!(decode_read_response(&response, 512), Ok(Err(expected)));
            assert_eq!(memory, [0xaa; 1024]);
        }
        let mut wrong_operation = encode_read_request(session, 0, 1, view).unwrap();
        wrong_operation[52..56].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(
            provider.read(&wrong_operation, &mut memory),
            Err(ProtocolError::InvalidHeader)
        );
        assert_eq!(memory, [0xaa; 1024]);
    }
}
