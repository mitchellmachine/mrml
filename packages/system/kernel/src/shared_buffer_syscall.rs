use crate::{
    GuestMemory, IpcSharedBufferBackend, IpcSharedBufferError, IpcSharedBufferIoError, Message,
    Rights, SharedBindingError, SharedMemoryBindings, SharedWriteCopyBindingId,
    SharedWriteCopyBindings, SyscallRequest, TaskId, TaskRuntime, TaskRuntimeError, VmId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedBufferUserAccess {
    Read,
    Write,
}

/// Validates and copies one current task's ordinary userspace memory.
///
/// # Safety
///
/// Validation must cover the complete range in the requested direction and
/// keep that exact task mapping stable through the corresponding executor copy,
/// including any intervening opaque-resource operation.
/// Copies must complete exactly or return an error, must not redirect to
/// another task or range, and must report stale, short, or indeterminate work.
pub unsafe trait SharedBufferUserCopy {
    type Error;

    fn validate(
        &mut self,
        task: TaskId,
        address: u64,
        length: usize,
        access: SharedBufferUserAccess,
    ) -> Result<(), Self::Error>;

    fn read(&mut self, task: TaskId, address: u64, output: &mut [u8]) -> Result<(), Self::Error>;

    fn write(&mut self, task: TaskId, address: u64, input: &[u8]) -> Result<(), Self::Error>;

    fn cancel(&mut self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedBufferSyscallError<S, U> {
    Unsupported,
    Runtime(TaskRuntimeError),
    Authorization(IpcSharedBufferError),
    Buffer(IpcSharedBufferIoError<S>),
    UserValidation(U),
    UserCopy(U),
    ScratchTooSmall,
}

pub struct SharedBufferSyscallExecutor;

impl SharedBufferSyscallExecutor {
    #[allow(clippy::too_many_arguments)]
    pub fn execute<
        const TASKS: usize,
        const CAPS: usize,
        const MAPPINGS: usize,
        const BINDINGS: usize,
        S: IpcSharedBufferBackend,
        U: SharedBufferUserCopy,
    >(
        request: SyscallRequest,
        runtime: &TaskRuntime<TASKS, CAPS>,
        task: TaskId,
        vm: VmId,
        bindings: &SharedMemoryBindings<BINDINGS>,
        memory: &GuestMemory<MAPPINGS>,
        shared: &mut S,
        user: &mut U,
        scratch: &mut [u8],
    ) -> Result<(), SharedBufferSyscallError<S::Error, U::Error>> {
        let result = Self::execute_inner(
            request, runtime, task, vm, bindings, memory, shared, user, scratch,
        );
        user.cancel();
        scratch.fill(0);
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_inner<
        const TASKS: usize,
        const CAPS: usize,
        const MAPPINGS: usize,
        const BINDINGS: usize,
        S: IpcSharedBufferBackend,
        U: SharedBufferUserCopy,
    >(
        request: SyscallRequest,
        runtime: &TaskRuntime<TASKS, CAPS>,
        task: TaskId,
        vm: VmId,
        bindings: &SharedMemoryBindings<BINDINGS>,
        memory: &GuestMemory<MAPPINGS>,
        shared: &mut S,
        user: &mut U,
        scratch: &mut [u8],
    ) -> Result<(), SharedBufferSyscallError<S::Error, U::Error>> {
        let (capability, offset, address, length, user_access, rights, service_writes) =
            match request {
                SyscallRequest::ReadSharedBuffer {
                    capability,
                    offset,
                    output_address,
                    length,
                } => (
                    capability,
                    offset,
                    output_address,
                    length as usize,
                    SharedBufferUserAccess::Write,
                    Rights::MAP.union(Rights::READ),
                    false,
                ),
                SyscallRequest::WriteSharedBuffer {
                    capability,
                    offset,
                    input_address,
                    length,
                } => (
                    capability,
                    offset,
                    input_address,
                    length as usize,
                    SharedBufferUserAccess::Read,
                    Rights::MAP.union(Rights::READ).union(Rights::WRITE),
                    true,
                ),
                _ => return Err(SharedBufferSyscallError::Unsupported),
            };
        if length == 0 || length > scratch.len() {
            return Err(SharedBufferSyscallError::ScratchTooSmall);
        }
        user.validate(task, address, length, user_access)
            .map_err(SharedBufferSyscallError::UserValidation)?;
        let capabilities = runtime
            .capabilities(task)
            .map_err(SharedBufferSyscallError::Runtime)?;
        let rights = if !service_writes && capabilities.authorize_exact(capability, rights).is_err()
        {
            let read_write = Rights::MAP.union(Rights::READ).union(Rights::WRITE);
            capabilities
                .authorize_exact(capability, read_write)
                .map(|_| read_write)
                .unwrap_or(rights)
        } else {
            rights
        };
        let message = Message::new(&[], &[capability]).map_err(|error| {
            SharedBufferSyscallError::Authorization(IpcSharedBufferError::Ipc(error))
        })?;
        message
            .resolve_selected_shared_buffer(capabilities, rights, bindings, memory, vm, task)
            .map_err(SharedBufferSyscallError::Authorization)?;
        let scratch = &mut scratch[..length];
        if service_writes {
            user.read(task, address, scratch)
                .map_err(SharedBufferSyscallError::UserCopy)?;
            message
                .write_selected_shared_buffer(
                    capabilities,
                    rights,
                    bindings,
                    memory,
                    vm,
                    task,
                    offset,
                    scratch,
                    shared,
                )
                .map_err(SharedBufferSyscallError::Buffer)
        } else {
            message
                .read_selected_shared_buffer(
                    capabilities,
                    rights,
                    bindings,
                    memory,
                    vm,
                    task,
                    offset,
                    scratch,
                    shared,
                )
                .map_err(SharedBufferSyscallError::Buffer)?;
            user.write(task, address, scratch)
                .map_err(SharedBufferSyscallError::UserCopy)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedWriteCopySyscallError<S, U> {
    Unsupported,
    Runtime(TaskRuntimeError),
    Authorization(SharedBindingError),
    Buffer(IpcSharedBufferIoError<S>),
    UserValidation(U),
    UserCopy(U),
    ScratchTooSmall,
}

/// Executes the write half of the shared-buffer ABI through an exact
/// non-mapped provider projection.
pub struct SharedWriteCopySyscallExecutor;

impl SharedWriteCopySyscallExecutor {
    #[allow(clippy::too_many_arguments)]
    pub fn execute<
        const TASKS: usize,
        const CAPS: usize,
        const MAPPINGS: usize,
        const SOURCE_BINDINGS: usize,
        const COPY_BINDINGS: usize,
        S: IpcSharedBufferBackend,
        U: SharedBufferUserCopy,
    >(
        request: SyscallRequest,
        runtime: &TaskRuntime<TASKS, CAPS>,
        task: TaskId,
        vm: VmId,
        source_bindings: &SharedMemoryBindings<SOURCE_BINDINGS>,
        copy_bindings: &SharedWriteCopyBindings<COPY_BINDINGS>,
        copy_binding: SharedWriteCopyBindingId,
        memory: &GuestMemory<MAPPINGS>,
        shared: &mut S,
        user: &mut U,
        scratch: &mut [u8],
    ) -> Result<(), SharedWriteCopySyscallError<S::Error, U::Error>> {
        let result = Self::execute_inner(
            request,
            runtime,
            task,
            vm,
            source_bindings,
            copy_bindings,
            copy_binding,
            memory,
            shared,
            user,
            scratch,
        );
        user.cancel();
        scratch.fill(0);
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_inner<
        const TASKS: usize,
        const CAPS: usize,
        const MAPPINGS: usize,
        const SOURCE_BINDINGS: usize,
        const COPY_BINDINGS: usize,
        S: IpcSharedBufferBackend,
        U: SharedBufferUserCopy,
    >(
        request: SyscallRequest,
        runtime: &TaskRuntime<TASKS, CAPS>,
        task: TaskId,
        vm: VmId,
        source_bindings: &SharedMemoryBindings<SOURCE_BINDINGS>,
        copy_bindings: &SharedWriteCopyBindings<COPY_BINDINGS>,
        copy_binding: SharedWriteCopyBindingId,
        memory: &GuestMemory<MAPPINGS>,
        shared: &mut S,
        user: &mut U,
        scratch: &mut [u8],
    ) -> Result<(), SharedWriteCopySyscallError<S::Error, U::Error>> {
        let SyscallRequest::WriteSharedBuffer {
            capability,
            offset,
            input_address,
            length,
        } = request
        else {
            return Err(SharedWriteCopySyscallError::Unsupported);
        };
        let length =
            usize::try_from(length).map_err(|_| SharedWriteCopySyscallError::ScratchTooSmall)?;
        if length == 0 || length > scratch.len() {
            return Err(SharedWriteCopySyscallError::ScratchTooSmall);
        }
        user.validate(task, input_address, length, SharedBufferUserAccess::Read)
            .map_err(SharedWriteCopySyscallError::UserValidation)?;
        let capabilities = runtime
            .capabilities(task)
            .map_err(SharedWriteCopySyscallError::Runtime)?;
        let resource = copy_bindings
            .resolve(
                copy_binding,
                source_bindings,
                capabilities,
                capability,
                memory,
                vm,
                task,
            )
            .map_err(SharedWriteCopySyscallError::Authorization)?;
        let length_u64 = u64::try_from(length)
            .map_err(|_| SharedWriteCopySyscallError::Buffer(IpcSharedBufferIoError::OutOfRange))?;
        offset
            .checked_add(length_u64)
            .filter(|end| *end <= resource.bytes())
            .ok_or(SharedWriteCopySyscallError::Buffer(
                IpcSharedBufferIoError::OutOfRange,
            ))?;
        let scratch = &mut scratch[..length];
        user.read(task, input_address, scratch)
            .map_err(SharedWriteCopySyscallError::UserCopy)?;
        shared
            .write(resource.handle(), offset, scratch)
            .map_err(IpcSharedBufferIoError::Backend)
            .map_err(SharedWriteCopySyscallError::Buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::UserContext;
    use crate::{
        GuestRegion, HostResourceHandle, ObjectId, PhysAddr, Priority, SharedAccess,
        SharedEndpoint, VmTable,
    };

    const BYTES: usize = 4096;
    const USER_ADDRESS: u64 = 0x6000;

    struct SharedBackend {
        handle: HostResourceHandle,
        bytes: [u8; BYTES],
        calls: usize,
        fail: bool,
    }

    unsafe impl IpcSharedBufferBackend for SharedBackend {
        type Error = ();

        fn read(
            &mut self,
            handle: HostResourceHandle,
            offset: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            self.calls += 1;
            if self.fail || handle != self.handle {
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
            self.calls += 1;
            if self.fail || handle != self.handle {
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

    struct UserBackend {
        task: TaskId,
        bytes: [u8; BYTES],
        validations: usize,
        copies: usize,
        reject: bool,
    }

    unsafe impl SharedBufferUserCopy for UserBackend {
        type Error = ();

        fn validate(
            &mut self,
            task: TaskId,
            address: u64,
            length: usize,
            _access: SharedBufferUserAccess,
        ) -> Result<(), Self::Error> {
            self.validations += 1;
            if self.reject || task != self.task || address != USER_ADDRESS || length > BYTES {
                Err(())
            } else {
                Ok(())
            }
        }

        fn read(
            &mut self,
            task: TaskId,
            address: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            if task != self.task || address != USER_ADDRESS {
                return Err(());
            }
            output.copy_from_slice(&self.bytes[..output.len()]);
            self.copies += 1;
            Ok(())
        }

        fn write(&mut self, task: TaskId, address: u64, input: &[u8]) -> Result<(), Self::Error> {
            if task != self.task || address != USER_ADDRESS {
                return Err(());
            }
            self.bytes[..input.len()].copy_from_slice(input);
            self.copies += 1;
            Ok(())
        }

        fn cancel(&mut self) {}
    }

    struct Fixture {
        runtime: TaskRuntime<1, 1>,
        task: TaskId,
        vm: VmId,
        memory: GuestMemory<1>,
        bindings: SharedMemoryBindings<1>,
        capability: crate::Capability,
        handle: HostResourceHandle,
    }

    fn fixture(access: SharedAccess) -> Fixture {
        let context = UserContext::new(
            PhysAddr::new(0x20_0000).unwrap(),
            0x40_0000,
            0x0000_7000_0000_0000,
        )
        .unwrap();
        let mut runtime = TaskRuntime::new(1_000, 1).unwrap();
        let task = runtime.create(Priority::NORMAL, context).unwrap();
        let rights = match access {
            SharedAccess::ReadOnly => Rights::MAP.union(Rights::READ),
            SharedAccess::ReadWrite => Rights::MAP.union(Rights::READ).union(Rights::WRITE),
        };
        let capability = runtime
            .capabilities_mut(task)
            .unwrap()
            .insert(ObjectId(51), rights)
            .unwrap();
        let vm = VmTable::<1>::new().create(1).unwrap();
        let mut memory = GuestMemory::new();
        let mapping = memory
            .map(GuestRegion::new(0x4000, PhysAddr::new(0x8000).unwrap(), 1, true, false).unwrap())
            .unwrap();
        let handle = HostResourceHandle::new(151).unwrap();
        let mut bindings = SharedMemoryBindings::new();
        bindings
            .bind(
                runtime.capabilities(task).unwrap(),
                capability,
                &memory,
                SharedEndpoint::for_task(vm, task, mapping, access),
                handle,
            )
            .unwrap();
        Fixture {
            runtime,
            task,
            vm,
            memory,
            bindings,
            capability,
            handle,
        }
    }

    fn backends(fixture: &Fixture) -> (SharedBackend, UserBackend) {
        (
            SharedBackend {
                handle: fixture.handle,
                bytes: [0; BYTES],
                calls: 0,
                fail: false,
            },
            UserBackend {
                task: fixture.task,
                bytes: [0; BYTES],
                validations: 0,
                copies: 0,
                reject: false,
            },
        )
    }

    #[test]
    fn read_shared_buffer_copies_to_validated_user_memory_and_erases_scratch() {
        let fixture = fixture(SharedAccess::ReadOnly);
        let (mut shared, mut user) = backends(&fixture);
        shared.bytes[11..15].copy_from_slice(b"read");
        let mut scratch = [0xcc; 8];
        SharedBufferSyscallExecutor::execute(
            SyscallRequest::ReadSharedBuffer {
                capability: fixture.capability,
                offset: 11,
                output_address: USER_ADDRESS,
                length: 4,
            },
            &fixture.runtime,
            fixture.task,
            fixture.vm,
            &fixture.bindings,
            &fixture.memory,
            &mut shared,
            &mut user,
            &mut scratch,
        )
        .unwrap();
        assert_eq!(&user.bytes[..4], b"read");
        assert_eq!((user.validations, user.copies, shared.calls), (1, 1, 1));
        assert_eq!(scratch, [0; 8]);
    }

    #[test]
    fn read_accepts_only_exact_read_or_exact_read_write_authority() {
        let mut fixture = fixture(SharedAccess::ReadWrite);
        let (mut shared, mut user) = backends(&fixture);
        shared.bytes[7..11].copy_from_slice(b"data");
        let mut scratch = [0xcc; 8];
        SharedBufferSyscallExecutor::execute(
            SyscallRequest::ReadSharedBuffer {
                capability: fixture.capability,
                offset: 7,
                output_address: USER_ADDRESS,
                length: 4,
            },
            &fixture.runtime,
            fixture.task,
            fixture.vm,
            &fixture.bindings,
            &fixture.memory,
            &mut shared,
            &mut user,
            &mut scratch,
        )
        .unwrap();
        assert_eq!(&user.bytes[..4], b"data");
        assert_eq!((user.validations, user.copies, shared.calls), (1, 1, 1));
        assert_eq!(scratch, [0; 8]);

        fixture
            .runtime
            .capabilities_mut(fixture.task)
            .unwrap()
            .revoke(fixture.capability)
            .unwrap();
        let overbroad = fixture
            .runtime
            .capabilities_mut(fixture.task)
            .unwrap()
            .insert(
                ObjectId(51),
                Rights::MAP
                    .union(Rights::READ)
                    .union(Rights::WRITE)
                    .union(Rights::CONTROL),
            )
            .unwrap();
        let (mut shared, mut user) = backends(&fixture);
        let mut scratch = [0xcc; 8];
        assert!(matches!(
            SharedBufferSyscallExecutor::execute(
                SyscallRequest::ReadSharedBuffer {
                    capability: overbroad,
                    offset: 7,
                    output_address: USER_ADDRESS,
                    length: 4,
                },
                &fixture.runtime,
                fixture.task,
                fixture.vm,
                &fixture.bindings,
                &fixture.memory,
                &mut shared,
                &mut user,
                &mut scratch,
            ),
            Err(SharedBufferSyscallError::Authorization(_))
        ));
        assert_eq!((user.copies, shared.calls), (0, 0));
        assert_eq!(scratch, [0; 8]);
    }

    #[test]
    fn write_shared_buffer_copies_from_validated_user_memory_and_erases_scratch() {
        let fixture = fixture(SharedAccess::ReadWrite);
        let (mut shared, mut user) = backends(&fixture);
        user.bytes[..5].copy_from_slice(b"write");
        let mut scratch = [0xcc; 8];
        SharedBufferSyscallExecutor::execute(
            SyscallRequest::WriteSharedBuffer {
                capability: fixture.capability,
                offset: 13,
                input_address: USER_ADDRESS,
                length: 5,
            },
            &fixture.runtime,
            fixture.task,
            fixture.vm,
            &fixture.bindings,
            &fixture.memory,
            &mut shared,
            &mut user,
            &mut scratch,
        )
        .unwrap();
        assert_eq!(&shared.bytes[13..18], b"write");
        assert_eq!((user.validations, user.copies, shared.calls), (1, 1, 1));
        assert_eq!(scratch, [0; 8]);
    }

    #[test]
    fn write_copy_syscall_uses_exact_write_authority_without_provider_mapping() {
        let context = UserContext::new(
            PhysAddr::new(0x20_0000).unwrap(),
            0x40_0000,
            0x0000_7000_0000_0000,
        )
        .unwrap();
        let mut runtime = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
        let task = runtime.create(Priority::NORMAL, context).unwrap();
        let object = ObjectId(52);
        let write = runtime
            .capabilities_mut(task)
            .unwrap()
            .insert(object, Rights::MAP.union(Rights::WRITE))
            .unwrap();
        let vm = VmTable::<1>::new().create(1).unwrap();
        let mut memory = GuestMemory::<1>::new();
        let mapping = memory
            .map(GuestRegion::new(0x4000, PhysAddr::new(0x9000).unwrap(), 1, true, false).unwrap())
            .unwrap();
        let mut controller = crate::CapabilitySpace::<2>::new();
        let mapped = controller
            .insert(
                object,
                Rights::MAP
                    .union(Rights::READ)
                    .union(Rights::WRITE)
                    .union(Rights::CONTROL),
            )
            .unwrap();
        let control = controller.insert(object, Rights::CONTROL).unwrap();
        let handle = HostResourceHandle::new(152).unwrap();
        let mut source_bindings = SharedMemoryBindings::<1>::new();
        let source = source_bindings
            .bind(
                &controller,
                mapped,
                &memory,
                SharedEndpoint::new(vm, mapping, SharedAccess::ReadWrite),
                handle,
            )
            .unwrap();
        let mut copy_bindings = SharedWriteCopyBindings::<1>::new();
        let copy = copy_bindings
            .bind(
                &source_bindings,
                source,
                &controller,
                control,
                runtime.capabilities(task).unwrap(),
                write,
                &memory,
                vm,
                task,
            )
            .unwrap();
        let mut shared = SharedBackend {
            handle,
            bytes: [0; BYTES],
            calls: 0,
            fail: false,
        };
        let mut user = UserBackend {
            task,
            bytes: [0; BYTES],
            validations: 0,
            copies: 0,
            reject: false,
        };
        user.bytes[..5].copy_from_slice(b"exact");
        let mut scratch = [0xcc; 8];
        SharedWriteCopySyscallExecutor::execute(
            SyscallRequest::WriteSharedBuffer {
                capability: write,
                offset: 21,
                input_address: USER_ADDRESS,
                length: 5,
            },
            &runtime,
            task,
            vm,
            &source_bindings,
            &copy_bindings,
            copy,
            &memory,
            &mut shared,
            &mut user,
            &mut scratch,
        )
        .unwrap();
        assert_eq!(&shared.bytes[21..26], b"exact");
        assert_eq!((user.validations, user.copies, shared.calls), (1, 1, 1));
        assert_eq!(scratch, [0; 8]);

        assert_eq!(
            SharedWriteCopySyscallExecutor::execute(
                SyscallRequest::WriteSharedBuffer {
                    capability: write,
                    offset: crate::PAGE_SIZE - 1,
                    input_address: USER_ADDRESS,
                    length: 5,
                },
                &runtime,
                task,
                vm,
                &source_bindings,
                &copy_bindings,
                copy,
                &memory,
                &mut shared,
                &mut user,
                &mut scratch,
            ),
            Err(SharedWriteCopySyscallError::Buffer(
                IpcSharedBufferIoError::OutOfRange
            ))
        );
        assert_eq!((user.copies, shared.calls), (1, 1));
        assert_eq!(scratch, [0; 8]);
    }

    #[test]
    fn invalid_user_memory_and_revoked_authority_fail_before_bulk_copy() {
        let mut fixture = fixture(SharedAccess::ReadOnly);
        let (mut shared, mut user) = backends(&fixture);
        let request = SyscallRequest::ReadSharedBuffer {
            capability: fixture.capability,
            offset: 0,
            output_address: USER_ADDRESS,
            length: 4,
        };
        let mut tiny = [0xcc; 2];
        assert_eq!(
            SharedBufferSyscallExecutor::execute(
                request,
                &fixture.runtime,
                fixture.task,
                fixture.vm,
                &fixture.bindings,
                &fixture.memory,
                &mut shared,
                &mut user,
                &mut tiny,
            ),
            Err(SharedBufferSyscallError::ScratchTooSmall)
        );
        assert_eq!(tiny, [0; 2]);
        assert_eq!((user.validations, user.copies, shared.calls), (0, 0, 0));

        let mut scratch = [0xcc; 8];
        user.reject = true;
        assert_eq!(
            SharedBufferSyscallExecutor::execute(
                request,
                &fixture.runtime,
                fixture.task,
                fixture.vm,
                &fixture.bindings,
                &fixture.memory,
                &mut shared,
                &mut user,
                &mut scratch,
            ),
            Err(SharedBufferSyscallError::UserValidation(()))
        );
        assert_eq!((user.copies, shared.calls), (0, 0));
        assert_eq!(scratch, [0; 8]);

        user.reject = false;
        shared.fail = true;
        assert_eq!(
            SharedBufferSyscallExecutor::execute(
                request,
                &fixture.runtime,
                fixture.task,
                fixture.vm,
                &fixture.bindings,
                &fixture.memory,
                &mut shared,
                &mut user,
                &mut scratch,
            ),
            Err(SharedBufferSyscallError::Buffer(
                IpcSharedBufferIoError::Backend(())
            ))
        );
        assert_eq!(user.copies, 0);
        assert_eq!(shared.calls, 1);
        assert_eq!(scratch, [0; 8]);

        shared.fail = false;
        fixture
            .runtime
            .revoke_capability(fixture.task, fixture.capability)
            .unwrap();
        assert_eq!(
            SharedBufferSyscallExecutor::execute(
                request,
                &fixture.runtime,
                fixture.task,
                fixture.vm,
                &fixture.bindings,
                &fixture.memory,
                &mut shared,
                &mut user,
                &mut scratch,
            ),
            Err(SharedBufferSyscallError::Authorization(
                IpcSharedBufferError::Ipc(crate::IpcError::Unauthorized)
            ))
        );
        assert_eq!((user.copies, shared.calls), (0, 1));
        assert_eq!(scratch, [0; 8]);
    }
}
