use crate::ComponentProvider;
use mrml_interface_zstd_v3::{
    decode_decompress_request, decode_decompress_response, ProtocolError, ZstdTransport,
    DECOMPRESS_REQUEST_BYTES, DECOMPRESS_RESPONSE_BYTES,
};
use mrml_kernel::{
    CapabilitySpace, GuestMemory, IpcSharedBufferBackend, IpcSharedBufferError,
    IpcSharedBufferIoError, Message, Rights, SharedMemoryBindings, TaskId, VmId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZstdKernelTransportError<E> {
    InvalidEnvelope,
    Protocol(ProtocolError),
    Authorization(IpcSharedBufferError),
    Buffer(IpcSharedBufferIoError<E>),
    ScratchTooSmall,
}

/// Service-side composition of the canonical Zstd ABI-3 call with MRML's
/// existing authenticated IPC and capability-selected shared-buffer path.
///
/// The launch control plane binds the provider generation, receiver task, VM,
/// and shared `MemoryObject`. This data-plane adapter accepts no name, path,
/// provider selector, placement selector, or authority-bearing payload field.
pub struct ZstdKernelTransport {
    provider: ComponentProvider,
}

impl Default for ZstdKernelTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ZstdKernelTransport {
    pub const fn new() -> Self {
        Self {
            provider: ComponentProvider,
        }
    }

    /// Dispatches one already-received request. `vm` and `task` must be the
    /// authenticated receive context selected by the kernel, never values from
    /// the request. Scratch is private to the provider and erased on every path.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch<
        const CAPS: usize,
        const MAPPINGS: usize,
        const BINDINGS: usize,
        B: IpcSharedBufferBackend,
    >(
        &mut self,
        message: &Message,
        receiver_space: &CapabilitySpace<CAPS>,
        bindings: &SharedMemoryBindings<BINDINGS>,
        memory: &GuestMemory<MAPPINGS>,
        vm: VmId,
        task: TaskId,
        scratch: &mut [u8],
        backend: &mut B,
    ) -> Result<[u8; DECOMPRESS_RESPONSE_BYTES], ZstdKernelTransportError<B::Error>> {
        let result = self.dispatch_inner(
            message,
            receiver_space,
            bindings,
            memory,
            vm,
            task,
            scratch,
            backend,
        );
        scratch.fill(0);
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_inner<
        const CAPS: usize,
        const MAPPINGS: usize,
        const BINDINGS: usize,
        B: IpcSharedBufferBackend,
    >(
        &mut self,
        message: &Message,
        receiver_space: &CapabilitySpace<CAPS>,
        bindings: &SharedMemoryBindings<BINDINGS>,
        memory: &GuestMemory<MAPPINGS>,
        vm: VmId,
        task: TaskId,
        scratch: &mut [u8],
        backend: &mut B,
    ) -> Result<[u8; DECOMPRESS_RESPONSE_BYTES], ZstdKernelTransportError<B::Error>> {
        let request_bytes: &[u8; DECOMPRESS_REQUEST_BYTES] = message
            .payload()
            .try_into()
            .map_err(|_| ZstdKernelTransportError::InvalidEnvelope)?;
        let request = decode_decompress_request(request_bytes, u64::MAX)
            .map_err(ZstdKernelTransportError::Protocol)?;
        let input_end = request
            .input
            .offset()
            .checked_add(request.input.length())
            .ok_or(ZstdKernelTransportError::Protocol(
                ProtocolError::InvalidRequest,
            ))?;
        let output_end = request
            .output
            .offset()
            .checked_add(request.output.length())
            .ok_or(ZstdKernelTransportError::Protocol(
                ProtocolError::InvalidRequest,
            ))?;
        let extent = usize::try_from(input_end.max(output_end))
            .map_err(|_| ZstdKernelTransportError::ScratchTooSmall)?;
        if extent == 0 || extent > scratch.len() {
            return Err(ZstdKernelTransportError::ScratchTooSmall);
        }
        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        message
            .resolve_selected_shared_buffer(receiver_space, rights, bindings, memory, vm, task)
            .map_err(ZstdKernelTransportError::Authorization)?;

        let input_start = usize::try_from(request.input.offset())
            .map_err(|_| ZstdKernelTransportError::ScratchTooSmall)?;
        let input_end =
            usize::try_from(input_end).map_err(|_| ZstdKernelTransportError::ScratchTooSmall)?;
        message
            .read_selected_shared_buffer(
                receiver_space,
                rights,
                bindings,
                memory,
                vm,
                task,
                request.input.offset(),
                &mut scratch[input_start..input_end],
                backend,
            )
            .map_err(ZstdKernelTransportError::Buffer)?;

        let response = self
            .provider
            .call(request_bytes, &mut scratch[..extent])
            .map_err(ZstdKernelTransportError::Protocol)?;
        if let Ok(written) =
            decode_decompress_response(&response).map_err(ZstdKernelTransportError::Protocol)?
        {
            if written > request.output.length() {
                return Err(ZstdKernelTransportError::Protocol(
                    ProtocolError::InvalidResponse,
                ));
            }
            if written != 0 {
                let output_start = usize::try_from(request.output.offset())
                    .map_err(|_| ZstdKernelTransportError::ScratchTooSmall)?;
                let output_end = output_start
                    .checked_add(
                        usize::try_from(written)
                            .map_err(|_| ZstdKernelTransportError::ScratchTooSmall)?,
                    )
                    .ok_or(ZstdKernelTransportError::ScratchTooSmall)?;
                message
                    .write_selected_shared_buffer(
                        receiver_space,
                        rights,
                        bindings,
                        memory,
                        vm,
                        task,
                        request.output.offset(),
                        &scratch[output_start..output_end],
                        backend,
                    )
                    .map_err(ZstdKernelTransportError::Buffer)?;
            }
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_interface_zstd_v3::{
        encode_decompress_request, BorrowedReadView, BorrowedWriteView, DecompressError,
    };
    use mrml_kernel::arch::x86_64::UserContext;
    use mrml_kernel::{
        Endpoint, GuestRegion, HostResourceHandle, KernelScheduler, ObjectId, PhysAddr, Priority,
        SharedAccess, SharedEndpoint, TaskRuntime, VmTable,
    };

    const PAGE_BYTES: usize = 4096;
    const FRAME: [u8; 10] = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 5, 0x2b, 0, 0, b'x'];

    struct BufferBackend {
        handle: HostResourceHandle,
        bytes: [u8; PAGE_BYTES],
        reads: usize,
        writes: usize,
    }

    unsafe impl IpcSharedBufferBackend for BufferBackend {
        type Error = ();

        fn read(
            &mut self,
            handle: HostResourceHandle,
            offset: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            if handle != self.handle {
                return Err(());
            }
            let start = usize::try_from(offset).map_err(|_| ())?;
            output.copy_from_slice(self.bytes.get(start..start + output.len()).ok_or(())?);
            self.reads += 1;
            Ok(())
        }

        fn write(
            &mut self,
            handle: HostResourceHandle,
            offset: u64,
            input: &[u8],
        ) -> Result<(), Self::Error> {
            if handle != self.handle {
                return Err(());
            }
            let start = usize::try_from(offset).map_err(|_| ())?;
            self.bytes
                .get_mut(start..start + input.len())
                .ok_or(())?
                .copy_from_slice(input);
            self.writes += 1;
            Ok(())
        }
    }

    struct Fixture {
        vm: VmId,
        task: TaskId,
        wrong_task: TaskId,
        memory: GuestMemory<1>,
        bindings: SharedMemoryBindings<1>,
        receiver: CapabilitySpace<1>,
        message: Message,
        backend: BufferBackend,
    }

    fn fixture(vm_marker: u64) -> Fixture {
        let vm = VmTable::<1>::new().create(vm_marker).unwrap();
        let mut scheduler = KernelScheduler::<2>::new(1_000, 1).unwrap();
        let task = scheduler.create(Priority::NORMAL).unwrap();
        let wrong_task = scheduler.create(Priority::NORMAL).unwrap();
        let mut memory = GuestMemory::<1>::new();
        let mapping = memory
            .map(GuestRegion::new(0x4000, PhysAddr::new(0x8000).unwrap(), 1, true, false).unwrap())
            .unwrap();
        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        let mut source = CapabilitySpace::<1>::new();
        let root = source
            .insert(ObjectId(70 + vm_marker), rights.union(Rights::DELEGATE))
            .unwrap();
        let handle = HostResourceHandle::new(170 + vm_marker).unwrap();
        let mut bindings = SharedMemoryBindings::new();
        bindings
            .bind(
                &source,
                root,
                &memory,
                SharedEndpoint::for_task(vm, task, mapping, SharedAccess::ReadWrite),
                handle,
            )
            .unwrap();
        let request = encode_decompress_request(
            BorrowedReadView::within(0, FRAME.len() as u64, PAGE_BYTES as u64).unwrap(),
            BorrowedWriteView::within(64, 32, PAGE_BYTES as u64).unwrap(),
        )
        .unwrap();
        let mut receiver = CapabilitySpace::new();
        let message =
            Message::transfer(&request, &[(root, rights)], &source, &mut receiver).unwrap();
        let mut backend = BufferBackend {
            handle,
            bytes: [0xa5; PAGE_BYTES],
            reads: 0,
            writes: 0,
        };
        backend.bytes[..FRAME.len()].copy_from_slice(&FRAME);
        Fixture {
            vm,
            task,
            wrong_task,
            memory,
            bindings,
            receiver,
            message,
            backend,
        }
    }

    fn dispatch(fixture: &mut Fixture) -> [u8; DECOMPRESS_RESPONSE_BYTES] {
        let mut scratch = [0xcc; 128];
        let response = ZstdKernelTransport::new()
            .dispatch(
                &fixture.message,
                &fixture.receiver,
                &fixture.bindings,
                &fixture.memory,
                fixture.vm,
                fixture.task,
                &mut scratch,
                &mut fixture.backend,
            )
            .unwrap();
        assert_eq!(scratch, [0; 128]);
        response
    }

    #[test]
    fn distinct_vm_task_bindings_use_identical_bounded_interface_bytes() {
        let mut native = fixture(1);
        let mut microvm = fixture(2);
        assert_eq!(native.message.payload(), microvm.message.payload());
        assert_eq!(
            decode_decompress_response(&dispatch(&mut native)),
            Ok(Ok(5))
        );
        assert_eq!(
            decode_decompress_response(&dispatch(&mut microvm)),
            Ok(Ok(5))
        );
        assert_eq!(&native.backend.bytes[64..69], b"xxxxx");
        assert_eq!(&microvm.backend.bytes[64..69], b"xxxxx");
        assert_eq!((native.backend.reads, native.backend.writes), (1, 1));
        assert_eq!((microvm.backend.reads, microvm.backend.writes), (1, 1));
    }

    #[test]
    fn task_runtime_delivers_exact_request_and_attenuated_buffer_authority() {
        let mut runtime = TaskRuntime::<2, 3>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(
                Priority::NORMAL,
                UserContext::new(
                    PhysAddr::new(0x20_0000).unwrap(),
                    0x40_0000,
                    0x0000_7000_0000_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let receiver = runtime
            .create(
                Priority::NORMAL,
                UserContext::new(
                    PhysAddr::new(0x30_0000).unwrap(),
                    0x50_0000,
                    0x0000_7000_0000_1000,
                )
                .unwrap(),
            )
            .unwrap();
        let endpoint_object = ObjectId(0x301);
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        let buffer_root = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(ObjectId(0x302), rights.union(Rights::DELEGATE))
            .unwrap();

        let vm = VmTable::<1>::new().create(0x303).unwrap();
        let mut memory = GuestMemory::<1>::new();
        let mapping = memory
            .map(GuestRegion::new(0x4000, PhysAddr::new(0x8000).unwrap(), 1, true, false).unwrap())
            .unwrap();
        let handle = HostResourceHandle::new(0x304).unwrap();
        let mut bindings = SharedMemoryBindings::<1>::new();
        bindings
            .bind(
                runtime.capabilities_mut(sender).unwrap(),
                buffer_root,
                &memory,
                SharedEndpoint::for_task(vm, receiver, mapping, SharedAccess::ReadWrite),
                handle,
            )
            .unwrap();
        let request = encode_decompress_request(
            BorrowedReadView::within(0, FRAME.len() as u64, PAGE_BYTES as u64).unwrap(),
            BorrowedWriteView::within(64, 32, PAGE_BYTES as u64).unwrap(),
        )
        .unwrap();
        let mut endpoint = Endpoint::new(endpoint_object);
        assert_eq!(
            runtime
                .deliver_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    &request,
                    &[(buffer_root, rights)],
                )
                .unwrap(),
            1
        );
        let message = runtime.receive_ipc(receiver).unwrap();
        assert_eq!(message.payload(), request);
        let received = message.capabilities().next().unwrap();
        assert_eq!(
            runtime
                .capabilities_mut(receiver)
                .unwrap()
                .authorize(received, rights),
            Ok(ObjectId(0x302))
        );

        let mut backend = BufferBackend {
            handle,
            bytes: [0xa5; PAGE_BYTES],
            reads: 0,
            writes: 0,
        };
        backend.bytes[..FRAME.len()].copy_from_slice(&FRAME);
        let mut scratch = [0xcc; 128];
        let response = ZstdKernelTransport::new()
            .dispatch(
                &message,
                runtime.capabilities_mut(receiver).unwrap(),
                &bindings,
                &memory,
                vm,
                receiver,
                &mut scratch,
                &mut backend,
            )
            .unwrap();
        assert_eq!(decode_decompress_response(&response), Ok(Ok(5)));
        assert_eq!(&backend.bytes[64..69], b"xxxxx");
        assert_eq!((backend.reads, backend.writes), (1, 1));
        assert_eq!(scratch, [0; 128]);
    }

    #[test]
    fn wrong_task_revocation_and_small_scratch_fail_before_output_write() {
        let mut fixture_state = fixture(3);
        let mut scratch = [0xcc; 128];
        assert!(matches!(
            ZstdKernelTransport::new().dispatch(
                &fixture_state.message,
                &fixture_state.receiver,
                &fixture_state.bindings,
                &fixture_state.memory,
                fixture_state.vm,
                fixture_state.wrong_task,
                &mut scratch,
                &mut fixture_state.backend,
            ),
            Err(ZstdKernelTransportError::Authorization(_))
        ));
        assert_eq!(
            (fixture_state.backend.reads, fixture_state.backend.writes),
            (0, 0)
        );
        assert_eq!(scratch, [0; 128]);

        let capability = fixture_state.message.capabilities().next().unwrap();
        fixture_state.receiver.revoke(capability).unwrap();
        assert!(matches!(
            ZstdKernelTransport::new().dispatch(
                &fixture_state.message,
                &fixture_state.receiver,
                &fixture_state.bindings,
                &fixture_state.memory,
                fixture_state.vm,
                fixture_state.task,
                &mut scratch,
                &mut fixture_state.backend,
            ),
            Err(ZstdKernelTransportError::Authorization(_))
        ));
        assert_eq!(
            (fixture_state.backend.reads, fixture_state.backend.writes),
            (0, 0)
        );

        let mut fresh = fixture(4);
        let mut small = [0xcc; 68];
        assert_eq!(
            ZstdKernelTransport::new().dispatch(
                &fresh.message,
                &fresh.receiver,
                &fresh.bindings,
                &fresh.memory,
                fresh.vm,
                fresh.task,
                &mut small,
                &mut fresh.backend,
            ),
            Err(ZstdKernelTransportError::ScratchTooSmall)
        );
        assert_eq!((fresh.backend.reads, fresh.backend.writes), (0, 0));
        assert_eq!(small, [0; 68]);
    }

    #[test]
    fn invalid_frame_returns_typed_error_without_writing_shared_output() {
        let mut fixture = fixture(5);
        fixture.backend.bytes[0] ^= 0xff;
        let response = dispatch(&mut fixture);
        assert_eq!(
            decode_decompress_response(&response),
            Ok(Err((DecompressError::InvalidFrame, 0)))
        );
        assert_eq!((fixture.backend.reads, fixture.backend.writes), (1, 0));
        assert_eq!(&fixture.backend.bytes[64..69], &[0xa5; 5]);
    }
}
