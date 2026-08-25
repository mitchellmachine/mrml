use crate::block_protocol::BlockAdmission;
use crate::{
    BlockBufferAccess, BlockDispatchBuffer, BlockProtocolDispatcher, BlockProtocolError,
    BlockRequest, BlockResponse, BlockService, BlockServiceBackend, StoragePrincipal,
};
use mrml_kernel::{
    CapabilitySpace, GuestMemory, IpcSharedBufferBackend, IpcSharedBufferError,
    IpcSharedBufferIoError, Message, Rights, SharedMemoryBindings, TaskId, VmId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockKernelTransportError<E> {
    Protocol(BlockProtocolError),
    Authorization(IpcSharedBufferError),
    Buffer(IpcSharedBufferIoError<E>),
    ScratchTooSmall,
}

/// Service-side composition of authenticated kernel IPC with the block
/// protocol dispatcher. This type remains outside the privileged kernel.
pub struct BlockKernelTransport<const SESSIONS: usize> {
    dispatcher: BlockProtocolDispatcher<SESSIONS>,
}

impl<const SESSIONS: usize> Default for BlockKernelTransport<SESSIONS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SESSIONS: usize> BlockKernelTransport<SESSIONS> {
    pub const fn new() -> Self {
        Self {
            dispatcher: BlockProtocolDispatcher::new(),
        }
    }

    /// Dispatches one already-received kernel message. `principal`, `vm`, and
    /// `task` must come from authenticated kernel receive context, never from
    /// the message payload. Scratch is erased before return on every path.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch<
        const DEVICES: usize,
        const CAPS: usize,
        const MAPPINGS: usize,
        const BINDINGS: usize,
        D: BlockServiceBackend,
        I: IpcSharedBufferBackend,
    >(
        &mut self,
        service: &BlockService<DEVICES, SESSIONS>,
        device_backend: &mut D,
        ipc_backend: &mut I,
        principal: StoragePrincipal,
        message: &Message,
        receiver_space: &CapabilitySpace<CAPS>,
        bindings: &SharedMemoryBindings<BINDINGS>,
        memory: &GuestMemory<MAPPINGS>,
        vm: VmId,
        task: TaskId,
        scratch: &mut [u8],
    ) -> Result<BlockResponse, BlockKernelTransportError<I::Error>> {
        let result = self.dispatch_inner(
            service,
            device_backend,
            ipc_backend,
            principal,
            message,
            receiver_space,
            bindings,
            memory,
            vm,
            task,
            scratch,
        );
        scratch.fill(0);
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_inner<
        const DEVICES: usize,
        const CAPS: usize,
        const MAPPINGS: usize,
        const BINDINGS: usize,
        D: BlockServiceBackend,
        I: IpcSharedBufferBackend,
    >(
        &mut self,
        service: &BlockService<DEVICES, SESSIONS>,
        device_backend: &mut D,
        ipc_backend: &mut I,
        principal: StoragePrincipal,
        message: &Message,
        receiver_space: &CapabilitySpace<CAPS>,
        bindings: &SharedMemoryBindings<BINDINGS>,
        memory: &GuestMemory<MAPPINGS>,
        vm: VmId,
        task: TaskId,
        scratch: &mut [u8],
    ) -> Result<BlockResponse, BlockKernelTransportError<I::Error>> {
        let request =
            BlockRequest::decode(message.payload()).map_err(BlockKernelTransportError::Protocol)?;
        let length = request.byte_length();
        if length > scratch.len() {
            return Err(BlockKernelTransportError::ScratchTooSmall);
        }
        let scratch = &mut scratch[..length];
        let owner_valid = service.validate_owner(request.session(), principal).is_ok();

        let access = request.buffer_access();
        match access {
            BlockBufferAccess::None => {
                message.authorize_no_capabilities().map_err(|error| {
                    BlockKernelTransportError::Authorization(IpcSharedBufferError::Ipc(error))
                })?;
            }
            BlockBufferAccess::ServiceReads => {
                if owner_valid {
                    message
                        .resolve_selected_shared_buffer(
                            receiver_space,
                            Rights::MAP.union(Rights::READ),
                            bindings,
                            memory,
                            vm,
                            task,
                        )
                        .map_err(BlockKernelTransportError::Authorization)?;
                } else {
                    message
                        .authorize_single_capability(
                            receiver_space,
                            Rights::MAP.union(Rights::READ),
                        )
                        .map_err(|error| {
                            BlockKernelTransportError::Authorization(IpcSharedBufferError::Ipc(
                                error,
                            ))
                        })?;
                }
            }
            BlockBufferAccess::ServiceWrites => {
                let rights = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
                if owner_valid {
                    message
                        .resolve_selected_shared_buffer(
                            receiver_space,
                            rights,
                            bindings,
                            memory,
                            vm,
                            task,
                        )
                        .map_err(BlockKernelTransportError::Authorization)?;
                } else {
                    message
                        .authorize_single_capability(receiver_space, rights)
                        .map_err(|error| {
                            BlockKernelTransportError::Authorization(IpcSharedBufferError::Ipc(
                                error,
                            ))
                        })?;
                }
            }
        }

        let admitted = match self
            .dispatcher
            .admit(service, principal, request)
            .map_err(BlockKernelTransportError::Protocol)?
        {
            BlockAdmission::Rejected(response) => return Ok(response),
            BlockAdmission::Admitted(admitted) => admitted,
        };
        match access {
            BlockBufferAccess::None => self
                .dispatcher
                .dispatch_admitted(
                    service,
                    device_backend,
                    principal,
                    admitted,
                    BlockDispatchBuffer::None,
                )
                .map_err(BlockKernelTransportError::Protocol),
            BlockBufferAccess::ServiceReads => {
                message
                    .read_selected_shared_buffer(
                        receiver_space,
                        Rights::MAP.union(Rights::READ),
                        bindings,
                        memory,
                        vm,
                        task,
                        0,
                        scratch,
                        ipc_backend,
                    )
                    .map_err(BlockKernelTransportError::Buffer)?;
                self.dispatcher
                    .dispatch_admitted(
                        service,
                        device_backend,
                        principal,
                        admitted,
                        BlockDispatchBuffer::Write(scratch),
                    )
                    .map_err(BlockKernelTransportError::Protocol)
            }
            BlockBufferAccess::ServiceWrites => {
                let response = self
                    .dispatcher
                    .dispatch_admitted(
                        service,
                        device_backend,
                        principal,
                        admitted,
                        BlockDispatchBuffer::Read(scratch),
                    )
                    .map_err(BlockKernelTransportError::Protocol)?;
                if response.status() == crate::BlockStatus::Ok {
                    message
                        .write_selected_shared_buffer(
                            receiver_space,
                            Rights::MAP.union(Rights::READ).union(Rights::WRITE),
                            bindings,
                            memory,
                            vm,
                            task,
                            0,
                            scratch,
                            ipc_backend,
                        )
                        .map_err(BlockKernelTransportError::Buffer)?;
                }
                Ok(response)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BLOCK_REQUEST_BYTES, BlockDeviceDescriptor, BlockDeviceId, BlockRights, BlockStatus,
        SUPERBLOCK_BYTES,
    };
    use mrml_kernel::{
        Capability, GuestRegion, HostResourceHandle, KernelScheduler, ObjectId, PhysAddr, Priority,
        SharedAccess, SharedEndpoint, VmTable,
    };

    const BLOCK_SIZE: usize = 4096;
    const BLOCKS: usize = 2;

    struct DeviceBackend {
        bytes: [u8; BLOCK_SIZE * BLOCKS],
        calls: usize,
        fail: bool,
    }

    unsafe impl BlockServiceBackend for DeviceBackend {
        type Error = ();

        fn read_blocks(
            &mut self,
            _device: BlockDeviceId,
            block: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            if self.fail {
                return Err(());
            }
            let start = usize::try_from(block).map_err(|_| ())? * BLOCK_SIZE;
            output.copy_from_slice(self.bytes.get(start..start + output.len()).ok_or(())?);
            self.calls += 1;
            Ok(())
        }

        fn write_blocks(
            &mut self,
            _device: BlockDeviceId,
            block: u64,
            input: &[u8],
        ) -> Result<(), Self::Error> {
            if self.fail {
                return Err(());
            }
            let start = usize::try_from(block).map_err(|_| ())? * BLOCK_SIZE;
            self.bytes
                .get_mut(start..start + input.len())
                .ok_or(())?
                .copy_from_slice(input);
            self.calls += 1;
            Ok(())
        }

        fn flush(&mut self, _device: BlockDeviceId) -> Result<(), Self::Error> {
            if self.fail {
                Err(())
            } else {
                self.calls += 1;
                Ok(())
            }
        }

        fn replace_superblock(
            &mut self,
            _device: BlockDeviceId,
            block: u64,
            encoded: &[u8; SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            if self.fail {
                return Err(());
            }
            let start = usize::try_from(block).map_err(|_| ())? * BLOCK_SIZE;
            self.bytes[start..start + SUPERBLOCK_BYTES].copy_from_slice(encoded);
            self.calls += 1;
            Ok(())
        }
    }

    struct BufferBackend {
        handle: HostResourceHandle,
        bytes: [u8; BLOCK_SIZE],
        calls: usize,
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
            self.calls += 1;
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
            self.calls += 1;
            Ok(())
        }
    }

    fn owner(value: u64) -> StoragePrincipal {
        StoragePrincipal::new(value).unwrap()
    }

    fn service() -> (BlockService<1, 2>, crate::BlockSessionHandle) {
        let device = BlockDeviceId::new(7).unwrap();
        let mut service = BlockService::new();
        service
            .register_device(
                BlockDeviceDescriptor::new(device, BLOCK_SIZE as u32, BLOCKS as u64).unwrap(),
            )
            .unwrap();
        let session = service.grant(device, owner(1), BlockRights::ALL).unwrap();
        (service, session)
    }

    struct KernelFixture {
        vm: VmId,
        task: TaskId,
        memory: GuestMemory<1>,
        bindings: SharedMemoryBindings<1>,
        source: CapabilitySpace<1>,
        root: Capability,
        receiver: CapabilitySpace<1>,
        rights: Rights,
        host: HostResourceHandle,
    }

    fn kernel_fixture(access: SharedAccess, object: u64, host: u64) -> KernelFixture {
        let vm = VmTable::<1>::new().create(1).unwrap();
        let mut scheduler = KernelScheduler::<1>::new(1_000, 1).unwrap();
        let task = scheduler.create(Priority::NORMAL).unwrap();
        let mut memory = GuestMemory::new();
        let mapping = memory
            .map(GuestRegion::new(0x4000, PhysAddr::new(0x8000).unwrap(), 1, true, false).unwrap())
            .unwrap();
        let rights = match access {
            SharedAccess::ReadOnly => Rights::MAP.union(Rights::READ),
            SharedAccess::ReadWrite => Rights::MAP.union(Rights::READ).union(Rights::WRITE),
        };
        let mut source = CapabilitySpace::new();
        let root = source
            .insert(
                ObjectId(object),
                rights.union(Rights::CONTROL).union(Rights::DELEGATE),
            )
            .unwrap();
        let host = HostResourceHandle::new(host).unwrap();
        let mut bindings = SharedMemoryBindings::new();
        bindings
            .bind(
                &source,
                root,
                &memory,
                SharedEndpoint::for_task(vm, task, mapping, access),
                host,
            )
            .unwrap();
        KernelFixture {
            vm,
            task,
            memory,
            bindings,
            source,
            root,
            receiver: CapabilitySpace::new(),
            rights,
            host,
        }
    }

    fn message(request: BlockRequest, fixture: &mut KernelFixture) -> Message {
        let mut encoded = [0; BLOCK_REQUEST_BYTES];
        request.encode(&mut encoded).unwrap();
        Message::transfer(
            &encoded,
            &[(fixture.root, fixture.rights)],
            &fixture.source,
            &mut fixture.receiver,
        )
        .unwrap()
    }

    fn backends(host: HostResourceHandle) -> (DeviceBackend, BufferBackend) {
        (
            DeviceBackend {
                bytes: [0; BLOCK_SIZE * BLOCKS],
                calls: 0,
                fail: false,
            },
            BufferBackend {
                handle: host,
                bytes: [0; BLOCK_SIZE],
                calls: 0,
            },
        )
    }

    #[test]
    fn admitted_write_copies_only_the_authorized_buffer_and_erases_scratch() {
        let (service, session) = service();
        let mut fixture = kernel_fixture(SharedAccess::ReadOnly, 41, 141);
        let message = message(
            BlockRequest::Write {
                request_id: 1,
                session,
                block: 0,
                byte_length: BLOCK_SIZE as u32,
            },
            &mut fixture,
        );
        let (mut device, mut buffer) = backends(fixture.host);
        buffer.bytes.fill(0x5a);
        let mut scratch = [0xcc; BLOCK_SIZE];
        let response = BlockKernelTransport::<2>::new()
            .dispatch(
                &service,
                &mut device,
                &mut buffer,
                owner(1),
                &message,
                &fixture.receiver,
                &fixture.bindings,
                &fixture.memory,
                fixture.vm,
                fixture.task,
                &mut scratch,
            )
            .unwrap();
        assert_eq!(response.status(), BlockStatus::Ok);
        assert_eq!(device.bytes[..BLOCK_SIZE], [0x5a; BLOCK_SIZE]);
        assert_eq!(device.calls, 1);
        assert_eq!(buffer.calls, 1);
        assert_eq!(scratch, [0; BLOCK_SIZE]);
    }

    #[test]
    fn admitted_read_writes_only_the_authorized_buffer_and_erases_scratch() {
        let (service, session) = service();
        let mut fixture = kernel_fixture(SharedAccess::ReadWrite, 42, 142);
        let message = message(
            BlockRequest::Read {
                request_id: 1,
                session,
                block: 1,
                byte_length: BLOCK_SIZE as u32,
            },
            &mut fixture,
        );
        let (mut device, mut buffer) = backends(fixture.host);
        device.bytes[BLOCK_SIZE..].fill(0xa5);
        let mut scratch = [0xcc; BLOCK_SIZE];
        let response = BlockKernelTransport::<2>::new()
            .dispatch(
                &service,
                &mut device,
                &mut buffer,
                owner(1),
                &message,
                &fixture.receiver,
                &fixture.bindings,
                &fixture.memory,
                fixture.vm,
                fixture.task,
                &mut scratch,
            )
            .unwrap();
        assert_eq!(response.status(), BlockStatus::Ok);
        assert_eq!(buffer.bytes, [0xa5; BLOCK_SIZE]);
        assert_eq!(device.calls, 1);
        assert_eq!(buffer.calls, 1);
        assert_eq!(scratch, [0; BLOCK_SIZE]);
    }

    #[test]
    fn denied_replayed_and_poisoned_requests_touch_no_bulk_buffer() {
        let (service, session) = service();
        let mut fixture = kernel_fixture(SharedAccess::ReadOnly, 43, 143);
        let first = message(
            BlockRequest::Write {
                request_id: 1,
                session,
                block: 0,
                byte_length: BLOCK_SIZE as u32,
            },
            &mut fixture,
        );
        let (mut device, mut buffer) = backends(fixture.host);
        buffer.bytes.fill(7);
        let mut scratch = [0xcc; BLOCK_SIZE];
        let mut transport = BlockKernelTransport::<2>::new();

        let denied = transport
            .dispatch(
                &service,
                &mut device,
                &mut buffer,
                owner(2),
                &first,
                &fixture.receiver,
                &fixture.bindings,
                &fixture.memory,
                fixture.vm,
                fixture.task,
                &mut scratch,
            )
            .unwrap();
        assert_eq!(denied.status(), BlockStatus::Denied);
        assert_eq!((device.calls, buffer.calls), (0, 0));

        device.fail = true;
        let failed = transport
            .dispatch(
                &service,
                &mut device,
                &mut buffer,
                owner(1),
                &first,
                &fixture.receiver,
                &fixture.bindings,
                &fixture.memory,
                fixture.vm,
                fixture.task,
                &mut scratch,
            )
            .unwrap();
        assert_eq!(failed.status(), BlockStatus::BackendFailure);
        assert_eq!((device.calls, buffer.calls), (0, 1));

        let replay = transport
            .dispatch(
                &service,
                &mut device,
                &mut buffer,
                owner(1),
                &first,
                &fixture.receiver,
                &fixture.bindings,
                &fixture.memory,
                fixture.vm,
                fixture.task,
                &mut scratch,
            )
            .unwrap();
        assert_eq!(replay.status(), BlockStatus::ReplayRejected);
        assert_eq!((device.calls, buffer.calls), (0, 1));

        fixture
            .receiver
            .revoke(first.capabilities().next().unwrap())
            .unwrap();
        let second = message(
            BlockRequest::Write {
                request_id: 2,
                session,
                block: 0,
                byte_length: BLOCK_SIZE as u32,
            },
            &mut fixture,
        );
        let poisoned = transport
            .dispatch(
                &service,
                &mut device,
                &mut buffer,
                owner(1),
                &second,
                &fixture.receiver,
                &fixture.bindings,
                &fixture.memory,
                fixture.vm,
                fixture.task,
                &mut scratch,
            )
            .unwrap();
        assert_eq!(poisoned.status(), BlockStatus::BackendFailure);
        assert_eq!((device.calls, buffer.calls), (0, 1));
        assert_eq!(scratch, [0; BLOCK_SIZE]);
    }

    #[test]
    fn revoked_destination_authority_fails_before_device_or_buffer_access() {
        let (service, session) = service();
        let mut fixture = kernel_fixture(SharedAccess::ReadWrite, 44, 144);
        let message = message(
            BlockRequest::Read {
                request_id: 1,
                session,
                block: 0,
                byte_length: BLOCK_SIZE as u32,
            },
            &mut fixture,
        );
        fixture
            .receiver
            .revoke(message.capabilities().next().unwrap())
            .unwrap();
        let (mut device, mut buffer) = backends(fixture.host);
        let mut scratch = [0xcc; BLOCK_SIZE];
        assert_eq!(
            BlockKernelTransport::<2>::new().dispatch(
                &service,
                &mut device,
                &mut buffer,
                owner(1),
                &message,
                &fixture.receiver,
                &fixture.bindings,
                &fixture.memory,
                fixture.vm,
                fixture.task,
                &mut scratch,
            ),
            Err(BlockKernelTransportError::Authorization(
                IpcSharedBufferError::Ipc(mrml_kernel::IpcError::Unauthorized)
            ))
        );
        assert_eq!((device.calls, buffer.calls), (0, 0));
        assert_eq!(scratch, [0; BLOCK_SIZE]);
    }
}
