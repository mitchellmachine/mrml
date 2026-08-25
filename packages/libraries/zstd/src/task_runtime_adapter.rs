use crate::{ReceivedZstdEnvelope, ZstdServiceSyscalls};
use mrml_interface_zstd_v3::{DECOMPRESS_REQUEST_BYTES, DECOMPRESS_RESPONSE_BYTES};
use mrml_kernel::{
    Capability, ControlEvent, Endpoint, GuestMemory, IpcSharedBufferBackend,
    IpcSharedBufferIoError, ReceivedMessage, Rights, SharedMemoryBindings, TaskId, TaskRuntime,
    TaskRuntimeError, VmId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZstdTaskRuntimeAdapterError<E> {
    Runtime(TaskRuntimeError),
    Buffer(IpcSharedBufferIoError<E>),
    PeerDied,
    UnexpectedSender,
    InvalidEnvelope,
    MissingRequest,
    CapabilityMismatch,
}

/// Hosted composition proof for the exact runtime operations a native service
/// or microVM adapter must perform. Caller, provider, VM, and reply authority
/// are immutable launch-time state.
pub struct ZstdTaskRuntimeAdapter<
    'a,
    const TASKS: usize,
    const CAPS: usize,
    const MAPPINGS: usize,
    const BINDINGS: usize,
    B: IpcSharedBufferBackend,
> {
    runtime: &'a mut TaskRuntime<TASKS, CAPS>,
    caller: TaskId,
    provider: TaskId,
    vm: VmId,
    reply_endpoint: &'a mut Endpoint,
    reply_capability: Capability,
    bindings: &'a SharedMemoryBindings<BINDINGS>,
    memory: &'a GuestMemory<MAPPINGS>,
    backend: &'a mut B,
    received: Option<ReceivedMessage>,
    reply_ready: bool,
}

impl<
    'a,
    const TASKS: usize,
    const CAPS: usize,
    const MAPPINGS: usize,
    const BINDINGS: usize,
    B: IpcSharedBufferBackend,
> ZstdTaskRuntimeAdapter<'a, TASKS, CAPS, MAPPINGS, BINDINGS, B>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime: &'a mut TaskRuntime<TASKS, CAPS>,
        caller: TaskId,
        provider: TaskId,
        vm: VmId,
        reply_endpoint: &'a mut Endpoint,
        reply_capability: Capability,
        bindings: &'a SharedMemoryBindings<BINDINGS>,
        memory: &'a GuestMemory<MAPPINGS>,
        backend: &'a mut B,
    ) -> Result<Self, ZstdTaskRuntimeAdapterError<B::Error>> {
        if caller == provider {
            return Err(ZstdTaskRuntimeAdapterError::UnexpectedSender);
        }
        Ok(Self {
            runtime,
            caller,
            provider,
            vm,
            reply_endpoint,
            reply_capability,
            bindings,
            memory,
            backend,
            received: None,
            reply_ready: false,
        })
    }

    fn reject_received(
        &mut self,
        received: ReceivedMessage,
        error: ZstdTaskRuntimeAdapterError<B::Error>,
    ) -> Result<ReceivedZstdEnvelope, ZstdTaskRuntimeAdapterError<B::Error>> {
        for capability in received.message().capabilities() {
            self.runtime
                .revoke_capability(self.provider, capability)
                .map_err(ZstdTaskRuntimeAdapterError::Runtime)?;
        }
        Err(error)
    }
}

unsafe impl<
    const TASKS: usize,
    const CAPS: usize,
    const MAPPINGS: usize,
    const BINDINGS: usize,
    B: IpcSharedBufferBackend,
> ZstdServiceSyscalls for ZstdTaskRuntimeAdapter<'_, TASKS, CAPS, MAPPINGS, BINDINGS, B>
{
    type Error = ZstdTaskRuntimeAdapterError<B::Error>;

    fn receive(
        &mut self,
        request: &mut [u8; DECOMPRESS_REQUEST_BYTES],
        capability_tokens: &mut [u64; 1],
    ) -> Result<ReceivedZstdEnvelope, Self::Error> {
        if self.received.is_some() {
            return Err(ZstdTaskRuntimeAdapterError::InvalidEnvelope);
        }
        let received = match self
            .runtime
            .receive_control(self.provider)
            .map_err(ZstdTaskRuntimeAdapterError::Runtime)?
        {
            ControlEvent::Message(message) => message,
            ControlEvent::PeerDied(_) => return Err(ZstdTaskRuntimeAdapterError::PeerDied),
        };
        if received.sender() != self.caller {
            return self.reject_received(received, ZstdTaskRuntimeAdapterError::UnexpectedSender);
        }
        let message = received.message();
        if message.payload().len() != DECOMPRESS_REQUEST_BYTES || message.capability_count() != 1 {
            return self.reject_received(received, ZstdTaskRuntimeAdapterError::InvalidEnvelope);
        }
        let capability = message
            .capabilities()
            .next()
            .ok_or(ZstdTaskRuntimeAdapterError::InvalidEnvelope)?;
        request.copy_from_slice(message.payload());
        capability_tokens[0] = capability.token();
        self.received = Some(received);
        self.reply_ready = false;
        Ok(ReceivedZstdEnvelope {
            payload_length: DECOMPRESS_REQUEST_BYTES,
            capability_count: 1,
        })
    }

    fn read_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        let Self {
            runtime,
            provider,
            vm,
            bindings,
            memory,
            backend,
            received,
            ..
        } = self;
        let message = received
            .as_ref()
            .map(ReceivedMessage::message)
            .ok_or(ZstdTaskRuntimeAdapterError::MissingRequest)?;
        if message.capabilities().next() != Some(capability) {
            return Err(ZstdTaskRuntimeAdapterError::CapabilityMismatch);
        }
        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        message
            .read_selected_shared_buffer(
                runtime
                    .capabilities_mut(*provider)
                    .map_err(ZstdTaskRuntimeAdapterError::Runtime)?,
                rights,
                bindings,
                memory,
                *vm,
                *provider,
                offset,
                output,
                *backend,
            )
            .map_err(ZstdTaskRuntimeAdapterError::Buffer)
    }

    fn write_shared(
        &mut self,
        capability: Capability,
        offset: u64,
        input: &[u8],
    ) -> Result<(), Self::Error> {
        let Self {
            runtime,
            provider,
            vm,
            bindings,
            memory,
            backend,
            received,
            ..
        } = self;
        let message = received
            .as_ref()
            .map(ReceivedMessage::message)
            .ok_or(ZstdTaskRuntimeAdapterError::MissingRequest)?;
        if message.capabilities().next() != Some(capability) {
            return Err(ZstdTaskRuntimeAdapterError::CapabilityMismatch);
        }
        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        message
            .write_selected_shared_buffer(
                runtime
                    .capabilities_mut(*provider)
                    .map_err(ZstdTaskRuntimeAdapterError::Runtime)?,
                rights,
                bindings,
                memory,
                *vm,
                *provider,
                offset,
                input,
                *backend,
            )
            .map_err(ZstdTaskRuntimeAdapterError::Buffer)
    }

    fn send_response(
        &mut self,
        response: &[u8; DECOMPRESS_RESPONSE_BYTES],
    ) -> Result<(), Self::Error> {
        if !self.reply_ready {
            return Err(ZstdTaskRuntimeAdapterError::UnexpectedSender);
        }
        self.runtime
            .deliver_ipc(
                self.provider,
                self.caller,
                self.reply_endpoint,
                self.reply_capability,
                response,
                &[],
            )
            .map_err(ZstdTaskRuntimeAdapterError::Runtime)?;
        self.reply_ready = false;
        Ok(())
    }

    fn release_received(&mut self, capability: Capability) -> Result<(), Self::Error> {
        let received = self
            .received
            .as_ref()
            .ok_or(ZstdTaskRuntimeAdapterError::MissingRequest)?;
        if received.message().capabilities().next() != Some(capability) {
            return Err(ZstdTaskRuntimeAdapterError::CapabilityMismatch);
        }
        self.runtime
            .revoke_capability(self.provider, capability)
            .map_err(ZstdTaskRuntimeAdapterError::Runtime)?;
        self.received = None;
        self.reply_ready = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ZstdServiceLoop, ZstdServiceLoopError};
    use mrml_interface_zstd_v3::{
        BorrowedReadView, BorrowedWriteView, decode_decompress_response, encode_decompress_request,
    };
    use mrml_kernel::arch::x86_64::UserContext;
    use mrml_kernel::{
        GuestRegion, HostResourceHandle, ObjectId, PhysAddr, Priority, SharedAccess,
        SharedEndpoint, VmTable,
    };

    const PAGE_BYTES: usize = 4096;
    const FRAME: [u8; 10] = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 5, 0x2b, 0, 0, b'x'];

    struct BufferBackend {
        handle: HostResourceHandle,
        bytes: [u8; PAGE_BYTES],
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
            Ok(())
        }
    }

    fn context(root: u64, entry: u64, stack: u64) -> UserContext {
        UserContext::new(PhysAddr::new(root).unwrap(), entry, stack).unwrap()
    }

    #[test]
    fn full_task_runtime_call_replies_to_authenticated_caller_and_revokes_leaf() {
        let mut runtime = TaskRuntime::<2, 4>::new(1_000, 1).unwrap();
        let caller = runtime
            .create(
                Priority::NORMAL,
                context(0x20_0000, 0x40_0000, 0x0000_7000_0000_0000),
            )
            .unwrap();
        let provider = runtime
            .create(
                Priority::NORMAL,
                context(0x30_0000, 0x50_0000, 0x0000_7000_0000_1000),
            )
            .unwrap();
        let request_object = ObjectId(0x401);
        let request_capability = runtime
            .capabilities_mut(caller)
            .unwrap()
            .insert(request_object, Rights::SIGNAL)
            .unwrap();
        let reply_object = ObjectId(0x402);
        let reply_capability = runtime
            .capabilities_mut(provider)
            .unwrap()
            .insert(reply_object, Rights::SIGNAL)
            .unwrap();
        let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
        let buffer_root = runtime
            .capabilities_mut(caller)
            .unwrap()
            .insert(ObjectId(0x403), rights.union(Rights::DELEGATE))
            .unwrap();
        let vm = VmTable::<1>::new().create(0x404).unwrap();
        let mut memory = GuestMemory::<1>::new();
        let mapping = memory
            .map(GuestRegion::new(0x4000, PhysAddr::new(0x8000).unwrap(), 1, true, false).unwrap())
            .unwrap();
        let handle = HostResourceHandle::new(0x405).unwrap();
        let mut bindings = SharedMemoryBindings::<1>::new();
        bindings
            .bind(
                runtime.capabilities_mut(caller).unwrap(),
                buffer_root,
                &memory,
                SharedEndpoint::for_task(vm, provider, mapping, SharedAccess::ReadWrite),
                handle,
            )
            .unwrap();
        let request = encode_decompress_request(
            BorrowedReadView::within(0, FRAME.len() as u64, PAGE_BYTES as u64).unwrap(),
            BorrowedWriteView::within(64, 32, PAGE_BYTES as u64).unwrap(),
        )
        .unwrap();
        let mut request_channel = Endpoint::new(request_object);
        runtime
            .deliver_ipc(
                caller,
                provider,
                &mut request_channel,
                request_capability,
                &request,
                &[(buffer_root, rights)],
            )
            .unwrap();

        let mut backend = BufferBackend {
            handle,
            bytes: [0xa5; PAGE_BYTES],
        };
        backend.bytes[..FRAME.len()].copy_from_slice(&FRAME);
        let mut reply_channel = Endpoint::new(reply_object);
        let mut request_buffer = [0xcc; DECOMPRESS_REQUEST_BYTES];
        let mut capability_tokens = [u64::MAX; 1];
        let mut scratch = [0xcc; 128];
        let mut response_buffer = [0xcc; DECOMPRESS_RESPONSE_BYTES];
        ZstdServiceLoop::new()
            .serve_one(
                &mut ZstdTaskRuntimeAdapter::new(
                    &mut runtime,
                    caller,
                    provider,
                    vm,
                    &mut reply_channel,
                    reply_capability,
                    &bindings,
                    &memory,
                    &mut backend,
                )
                .unwrap(),
                &mut request_buffer,
                &mut capability_tokens,
                &mut scratch,
                &mut response_buffer,
            )
            .unwrap();

        let ControlEvent::Message(reply) = runtime.receive_control(caller).unwrap() else {
            panic!("expected reply");
        };
        assert_eq!(reply.sender(), provider);
        assert_eq!(reply.sequence(), 1);
        assert_eq!(reply.message().capability_count(), 0);
        let response: &[u8; DECOMPRESS_RESPONSE_BYTES] =
            reply.message().payload().try_into().unwrap();
        assert_eq!(decode_decompress_response(response), Ok(Ok(5)));
        assert_eq!(&backend.bytes[64..69], b"xxxxx");
        assert_eq!(request_buffer, [0; DECOMPRESS_REQUEST_BYTES]);
        assert_eq!(capability_tokens, [0]);
        assert_eq!(scratch, [0; 128]);
        assert_eq!(response_buffer, [0; DECOMPRESS_RESPONSE_BYTES]);
    }

    #[test]
    fn unexpected_sender_is_rejected_and_transferred_leaf_is_revoked() {
        let mut runtime = TaskRuntime::<3, 3>::new(1_000, 1).unwrap();
        let caller = runtime
            .create(
                Priority::NORMAL,
                context(0x20_0000, 0x40_0000, 0x0000_7000_0000_0000),
            )
            .unwrap();
        let provider = runtime
            .create(
                Priority::NORMAL,
                context(0x30_0000, 0x50_0000, 0x0000_7000_0000_1000),
            )
            .unwrap();
        let attacker = runtime
            .create(
                Priority::NORMAL,
                context(0x40_0000, 0x60_0000, 0x0000_7000_0000_2000),
            )
            .unwrap();
        let request_object = ObjectId(0x411);
        let request_capability = runtime
            .capabilities_mut(attacker)
            .unwrap()
            .insert(request_object, Rights::SIGNAL)
            .unwrap();
        let delegated = runtime
            .capabilities_mut(attacker)
            .unwrap()
            .insert(ObjectId(0x412), Rights::READ.union(Rights::DELEGATE))
            .unwrap();
        let mut request_channel = Endpoint::new(request_object);
        runtime
            .deliver_ipc(
                attacker,
                provider,
                &mut request_channel,
                request_capability,
                &[0; DECOMPRESS_REQUEST_BYTES],
                &[(delegated, Rights::READ)],
            )
            .unwrap();
        let reply_object = ObjectId(0x413);
        let reply_capability = runtime
            .capabilities_mut(provider)
            .unwrap()
            .insert(reply_object, Rights::SIGNAL)
            .unwrap();
        let vm = VmTable::<1>::new().create(0x414).unwrap();
        let memory = GuestMemory::<1>::new();
        let bindings = SharedMemoryBindings::<1>::new();
        let handle = HostResourceHandle::new(0x415).unwrap();
        let mut backend = BufferBackend {
            handle,
            bytes: [0; PAGE_BYTES],
        };
        let mut reply_channel = Endpoint::new(reply_object);
        let mut request_buffer = [0xcc; DECOMPRESS_REQUEST_BYTES];
        let mut capability_tokens = [u64::MAX; 1];
        let mut scratch = [0xcc; 128];
        let mut response_buffer = [0xcc; DECOMPRESS_RESPONSE_BYTES];
        assert_eq!(
            ZstdServiceLoop::new().serve_one(
                &mut ZstdTaskRuntimeAdapter::new(
                    &mut runtime,
                    caller,
                    provider,
                    vm,
                    &mut reply_channel,
                    reply_capability,
                    &bindings,
                    &memory,
                    &mut backend,
                )
                .unwrap(),
                &mut request_buffer,
                &mut capability_tokens,
                &mut scratch,
                &mut response_buffer,
            ),
            Err(ZstdServiceLoopError::Syscall(
                ZstdTaskRuntimeAdapterError::UnexpectedSender
            ))
        );
        assert_eq!(request_buffer, [0; DECOMPRESS_REQUEST_BYTES]);
        assert_eq!(capability_tokens, [0]);
        assert_eq!(scratch, [0; 128]);
        assert_eq!(response_buffer, [0; DECOMPRESS_RESPONSE_BYTES]);
        let provider_space = runtime.capabilities_mut(provider).unwrap();
        assert!(provider_space.insert(ObjectId(0x416), Rights::READ).is_ok());
        assert!(provider_space.insert(ObjectId(0x417), Rights::READ).is_ok());
    }
}
