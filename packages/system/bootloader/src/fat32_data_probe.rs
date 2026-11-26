//! Diagnostic-only coordinator and immutable media for the signed FAT32 data probe.
use super::*;
use mrml_interface_storage_block_provider_v1 as block;
use mrml_interface_storage_filesystem_v3 as fs;

const DEPENDENCY: ObjectId = ObjectId(0xf322);
const BLOCK_PAGE: ObjectId = ObjectId(0xf323);
const FILE_PAGE: ObjectId = ObjectId(0xf324);
const MEDIA: &[u8; 4132] = include_bytes!("fat32_probe_sectors.bin");
const NAME: &[u8] = b"PROBE.TXT";
const EXPECTED: &[u8] = b"MRML FAT32 recovery fixture\n";
const COPY_OFFSET: usize = 13;
const CANARY: u8 = 0xa7;
type Runtime = TaskRuntime<SERVICE_TASK_CAPACITY, SERVICE_CAPABILITY_CAPACITY>;

#[cfg(feature = "fat32-restart-probe")]
pub(super) struct RestartEraser<F>(pub(super) F);

#[cfg(feature = "fat32-restart-probe")]
impl<F> ServiceAddressSpaceEraser for RestartEraser<F>
where
    F: FnMut(mrml_kernel::TaskId, UserContext) -> Result<(), ()>,
{
    type Error = ();

    fn erase(&mut self, task: mrml_kernel::TaskId, context: UserContext) -> Result<(), ()> {
        (self.0)(task, context)
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Ready,
    Mount,
    Lookup(u64, fs::OpaqueHandle),
    Open(u64),
    Read(u64, fs::OpaqueHandle),
    Stale(u64, fs::OpaqueHandle, bool),
    Done,
}

pub(super) struct HostedFat32Data {
    filesystem: mrml_kernel::TaskId,
    #[cfg(feature = "fat32-restart-probe")]
    entry: u64,
    caller: mrml_kernel::TaskId,
    block: mrml_kernel::TaskId,
    fs_signal: Capability,
    endpoint_object: ObjectId,
    first_file: Option<(u64, fs::OpaqueHandle)>,
    completed_file: Option<(u64, fs::OpaqueHandle)>,
    block_signal: Capability,
    block_read: Capability,
    block_transfer: Capability,
    file_root: Capability,
    delegated: Option<Capability>,
    file_copy_done: bool,
    block_copy: Option<(usize, usize)>,
    caller_endpoint: Endpoint,
    dependency_endpoint: Endpoint,
    fs_page: [u8; 4096],
    block_page: [u8; 4096],
    phase: Phase,
}

impl HostedFat32Data {
    pub(super) fn install(
        runtime: &mut Runtime,
        filesystem: mrml_kernel::TaskId,
        caller: mrml_kernel::TaskId,
        block: mrml_kernel::TaskId,
    ) -> Option<Self> {
        let context = runtime.context(filesystem).ok()?;
        #[cfg(feature = "fat32-restart-probe")]
        let entry = context.instruction_pointer();
        let block_read = Capability::from_token(context.rbp);
        let block_transfer = Capability::from_token(context.rsi);
        runtime
            .authorize_capability_exact(
                filesystem,
                block_read,
                Rights::MAP.union(Rights::READ),
                BLOCK_PAGE,
            )
            .ok()?;
        runtime
            .authorize_capability_exact(
                filesystem,
                block_transfer,
                Rights::MAP.union(Rights::WRITE).union(Rights::DELEGATE),
                BLOCK_PAGE,
            )
            .ok()?;
        let caller_caps = runtime.capabilities_mut(caller).ok()?;
        let fs_signal = caller_caps
            .insert(FAT32_READY_ENDPOINT, Rights::SIGNAL)
            .ok()?;
        let file_root = caller_caps
            .insert(
                FILE_PAGE,
                Rights::MAP
                    .union(Rights::READ)
                    .union(Rights::WRITE)
                    .union(Rights::DELEGATE),
            )
            .ok()?;
        let block_signal = runtime
            .capabilities_mut(block)
            .ok()?
            .insert(DEPENDENCY, Rights::SIGNAL)
            .ok()?;
        // The compact file encodes a little-endian sector count followed by
        // strictly increasing LBA/sector records. Nothing comes from a host disk.
        let sectors = u32::from_le_bytes(MEDIA[..4].try_into().ok()?);
        let mut previous = None;
        for record in MEDIA[4..].chunks_exact(516) {
            let lba = u32::from_le_bytes(record[..4].try_into().ok()?);
            if lba >= sectors || previous.is_some_and(|old| old >= lba) {
                return None;
            }
            previous = Some(lba);
        }
        Some(Self {
            filesystem,
            #[cfg(feature = "fat32-restart-probe")]
            entry,
            caller,
            block,
            fs_signal,
            endpoint_object: FAT32_READY_ENDPOINT,
            first_file: None,
            completed_file: None,
            block_signal,
            block_read,
            block_transfer,
            file_root,
            delegated: None,
            file_copy_done: false,
            block_copy: None,
            caller_endpoint: Endpoint::new(FAT32_READY_ENDPOINT),
            dependency_endpoint: Endpoint::new(DEPENDENCY),
            fs_page: [CANARY; 4096],
            block_page: [0; 4096],
            phase: Phase::Ready,
        })
    }

    pub(super) fn stage(&self) -> u32 {
        match self.phase {
            Phase::Ready => 0,
            Phase::Mount => 1,
            Phase::Lookup(..) => 2,
            Phase::Open(_) => 3,
            Phase::Read(..) => 4,
            Phase::Stale(_, _, false) => 5,
            Phase::Stale(_, _, true) => 6,
            Phase::Done => 7,
        }
    }

    fn send_fs(
        &mut self,
        runtime: &mut Runtime,
        request: &[u8],
        rights: Option<Rights>,
    ) -> Option<()> {
        let transfer = rights.map(|rights| [(self.file_root, rights)]);
        runtime
            .deliver_ipc(
                self.caller,
                self.filesystem,
                &mut self.caller_endpoint,
                self.fs_signal,
                request,
                transfer.as_ref().map_or(&[], |items| &items[..]),
            )
            .ok()?;
        self.file_copy_done = false;
        self.delegated = None;
        Some(())
    }

    pub(super) fn received(
        &mut self,
        runtime: &Runtime,
        received: &mrml_kernel::ReceivedMessage,
    ) -> Option<()> {
        let message = received.message();
        if received.sender() == self.block {
            if self.block_copy.is_none() {
                return None;
            }
            message.authorize_no_capabilities().ok()?;
            return Some(());
        }
        if received.sender() != self.caller || self.delegated.is_some() {
            return None;
        }
        let rights = match self.phase {
            Phase::Lookup(..) => Some(Rights::MAP.union(Rights::READ)),
            Phase::Read(..) | Phase::Stale(..) => Some(Rights::MAP.union(Rights::WRITE)),
            Phase::Mount | Phase::Open(_) => None,
            _ => return None,
        };
        if let Some(rights) = rights {
            let grant = message
                .authorize_single_capability(runtime.capabilities(self.filesystem).ok()?, rights)
                .ok()?;
            if grant.object() != FILE_PAGE {
                return None;
            }
            self.delegated = Some(grant.capability());
        } else {
            message.authorize_no_capabilities().ok()?;
        }
        Some(())
    }

    pub(super) fn release_allowed(&self, token: Capability) -> bool {
        (self.file_copy_done || matches!(self.phase, Phase::Stale(..)))
            && self.delegated == Some(token)
    }

    pub(super) fn copy(
        &mut self,
        runtime: &Runtime,
        request: SyscallRequest,
        user: &mut impl mrml_kernel::SharedBufferUserCopy,
    ) -> Option<()> {
        use mrml_kernel::SharedBufferUserAccess;
        let task = self.filesystem;
        match request {
            SyscallRequest::ReadSharedBuffer {
                capability,
                offset,
                output_address,
                length,
            } if capability == self.block_read => {
                let (start, count) = self.block_copy?;
                if (offset, length) != (start as u64, count as u32) {
                    return None;
                }
                runtime
                    .authorize_capability_exact(
                        task,
                        capability,
                        Rights::MAP.union(Rights::READ),
                        BLOCK_PAGE,
                    )
                    .ok()?;
                user.validate(task, output_address, count, SharedBufferUserAccess::Write)
                    .ok()?;
                user.write(task, output_address, &self.block_page[start..start + count])
                    .ok()?;
                self.block_page.fill(0);
                self.block_copy = None;
            }
            SyscallRequest::ReadSharedBuffer {
                capability,
                offset,
                output_address,
                length,
            } if matches!(self.phase, Phase::Lookup(..)) && Some(capability) == self.delegated => {
                if self.file_copy_done
                    || (offset, length) != (COPY_OFFSET as u64, NAME.len() as u32)
                {
                    return None;
                }
                runtime
                    .authorize_capability_exact(
                        task,
                        capability,
                        Rights::MAP.union(Rights::READ),
                        FILE_PAGE,
                    )
                    .ok()?;
                user.validate(
                    task,
                    output_address,
                    NAME.len(),
                    SharedBufferUserAccess::Write,
                )
                .ok()?;
                user.write(
                    task,
                    output_address,
                    &self.fs_page[COPY_OFFSET..COPY_OFFSET + NAME.len()],
                )
                .ok()?;
                self.file_copy_done = true;
            }
            SyscallRequest::WriteSharedBuffer {
                capability,
                offset,
                input_address,
                length,
            } if matches!(self.phase, Phase::Read(..)) && Some(capability) == self.delegated => {
                if self.file_copy_done
                    || (offset, length) != (COPY_OFFSET as u64, EXPECTED.len() as u32)
                {
                    return None;
                }
                runtime
                    .authorize_capability_exact(
                        task,
                        capability,
                        Rights::MAP.union(Rights::WRITE),
                        FILE_PAGE,
                    )
                    .ok()?;
                user.validate(
                    task,
                    input_address,
                    EXPECTED.len(),
                    SharedBufferUserAccess::Read,
                )
                .ok()?;
                user.read(
                    task,
                    input_address,
                    &mut self.fs_page[COPY_OFFSET..COPY_OFFSET + EXPECTED.len()],
                )
                .ok()?;
                self.file_copy_done = true;
            }
            _ => return None,
        }
        Some(())
    }

    pub(super) fn send(
        &mut self,
        runtime: &mut Runtime,
        boot: &HostedFat32Ready,
        receiver: mrml_kernel::TaskId,
        signal: Capability,
        payload: &[u8],
        transfers: &[(Capability, Rights)],
    ) -> Option<(u64, bool)> {
        if !boot.copied
            || runtime
                .capabilities(self.filesystem)
                .ok()?
                .authorize(boot.startup, Rights::NONE)
                .is_ok()
        {
            return None;
        }
        if receiver == self.block {
            return self
                .serve_block(runtime, signal, payload, transfers)
                .map(|seq| (seq, false));
        }
        if receiver != self.caller || !transfers.is_empty() || self.block_copy.is_some() {
            return None;
        }
        runtime
            .authorize_capability_exact(
                self.filesystem,
                signal,
                Rights::SIGNAL,
                self.endpoint_object,
            )
            .ok()?;
        if matches!(
            self.phase,
            Phase::Lookup(..) | Phase::Read(..) | Phase::Stale(..)
        ) {
            if (!matches!(self.phase, Phase::Stale(..)) && !self.file_copy_done)
                || runtime
                    .capabilities(self.filesystem)
                    .ok()?
                    .authorize(self.delegated?, Rights::NONE)
                    .is_ok()
            {
                return None;
            }
        }
        let seq = runtime
            .deliver_ipc(
                self.filesystem,
                self.caller,
                &mut self.caller_endpoint,
                signal,
                payload,
                &[],
            )
            .ok()?;
        let received = runtime
            .receive_ipc_envelope_bounded(self.caller, MAX_INLINE_PAYLOAD, 0)
            .ok()?;
        if received.sender() != self.filesystem || received.sequence() != seq {
            return None;
        }
        let wire = received.message().payload();
        let volume = fs::OpaqueHandle::new(2, 6)?;
        match self.phase {
            Phase::Ready => {
                if fs::FilesystemProviderReady::decode(wire) != Ok(boot.expected) {
                    return None;
                }
                let empty = fs::BorrowedReadView::within(0, 0, 0)?;
                self.send_fs(
                    runtime,
                    &fs::encode_mount_request(volume, empty).ok()?,
                    None,
                )?;
                self.phase = Phase::Mount;
            }
            Phase::Mount => {
                let mounted = fs::decode_mount_response(wire.try_into().ok()?)
                    .ok()?
                    .ok()?;
                self.fs_page[COPY_OFFSET..COPY_OFFSET + NAME.len()].copy_from_slice(NAME);
                let name =
                    fs::BorrowedReadView::within(COPY_OFFSET as u64, NAME.len() as u64, 4096)?;
                let request =
                    fs::encode_lookup_request(volume, mounted.generation, mounted.root, name)
                        .ok()?;
                self.send_fs(runtime, &request, Some(Rights::MAP.union(Rights::READ)))?;
                self.phase = Phase::Lookup(mounted.generation, mounted.root);
            }
            Phase::Lookup(generation, root) => {
                let file = fs::decode_lookup_response(wire.try_into().ok()?)
                    .ok()?
                    .ok()?;
                let request = fs::encode_open_request(volume, generation, root, file).ok()?;
                self.send_fs(runtime, &request, None)?;
                self.phase = Phase::Open(generation);
            }
            Phase::Open(generation) => {
                let file = fs::decode_open_response(wire.try_into().ok()?).ok()?.ok()?;
                if let Some((old_mount, old_file)) = self.first_file {
                    if (generation == old_mount) || (file == old_file) {
                        return None;
                    }
                    self.send_read(runtime, old_mount, old_file)?;
                    self.phase = Phase::Stale(generation, file, false);
                } else {
                    self.send_read(runtime, generation, file)?;
                    self.phase = Phase::Read(generation, file);
                }
            }
            Phase::Stale(generation, file, fresh_mount) => {
                if fs::decode_read_response(wire.try_into().ok()?, EXPECTED.len() as u64)
                    != Ok(Err(fs::ReadError::StaleObject))
                    || self.file_copy_done
                    || self.fs_page.iter().any(|&byte| byte != CANARY)
                {
                    return None;
                }
                if fresh_mount {
                    self.send_read(runtime, generation, file)?;
                    self.phase = Phase::Read(generation, file);
                } else {
                    self.send_read(runtime, generation, self.first_file?.1)?;
                    self.phase = Phase::Stale(generation, file, true);
                }
            }
            Phase::Read(generation, file) => {
                if fs::decode_read_response(wire.try_into().ok()?, EXPECTED.len() as u64)
                    != Ok(Ok(EXPECTED.len() as u64))
                    || &self.fs_page[COPY_OFFSET..COPY_OFFSET + EXPECTED.len()] != EXPECTED
                    || self.fs_page[..COPY_OFFSET]
                        .iter()
                        .any(|&byte| byte != CANARY)
                    || self.fs_page[COPY_OFFSET + EXPECTED.len()..]
                        .iter()
                        .any(|&byte| byte != CANARY)
                {
                    return None;
                }
                self.completed_file = Some((generation, file));
                self.phase = Phase::Done;
                return Some((seq, true));
            }
            Phase::Done => return None,
        }
        Some((seq, false))
    }

    fn send_read(
        &mut self,
        runtime: &mut Runtime,
        generation: u64,
        file: fs::OpaqueHandle,
    ) -> Option<()> {
        self.fs_page.fill(CANARY);
        let view = fs::BorrowedWriteView::within(COPY_OFFSET as u64, EXPECTED.len() as u64, 4096)?;
        let request =
            fs::encode_read_request(fs::OpaqueHandle::new(2, 6)?, generation, file, 0, view)
                .ok()?;
        self.send_fs(runtime, &request, Some(Rights::MAP.union(Rights::WRITE)))
    }

    #[cfg(feature = "fat32-restart-probe")]
    pub(super) fn block_task(&self) -> mrml_kernel::TaskId {
        self.block
    }

    #[cfg(feature = "fat32-restart-probe")]
    pub(super) fn restore_entry(&self) -> u64 {
        self.entry
    }

    #[cfg(feature = "fat32-restart-probe")]
    pub(super) fn should_restart(&self) -> bool {
        self.first_file.is_none() && self.completed_file.is_some()
    }

    #[cfg(feature = "fat32-restart-probe")]
    pub(super) fn rebind_after_retirement(
        &mut self,
        runtime: &mut Runtime,
        replacement: mrml_kernel::TaskId,
        endpoint_object: ObjectId,
    ) -> Option<()> {
        let retired = self.filesystem;
        let revoked = self.fs_signal;
        if !self.should_restart()
            || replacement == retired
            || runtime.context(retired).is_ok()
            || endpoint_object == self.endpoint_object
        {
            return None;
        }
        runtime.revoke_capability(self.caller, revoked).ok()?;
        // Test real IPC rather than only comparing tokens, including the
        // stale caller leaf presented to the still-live replacement task.
        if !matches!(
            runtime.deliver_ipc(
                self.caller,
                replacement,
                &mut self.caller_endpoint,
                revoked,
                b"retired-route",
                &[]
            ),
            Err(mrml_kernel::TaskRuntimeError::Ipc(_))
        ) {
            return None;
        }
        let signal = runtime
            .capabilities_mut(self.caller)
            .ok()?
            .insert(endpoint_object, Rights::SIGNAL)
            .ok()?;
        let context = runtime.context(replacement).ok()?;
        self.block_read = Capability::from_token(context.rbp);
        self.block_transfer = Capability::from_token(context.rsi);
        self.fs_signal = signal;
        self.endpoint_object = endpoint_object;
        self.filesystem = replacement;
        self.caller_endpoint = Endpoint::new(endpoint_object);
        if !matches!(
            runtime.deliver_ipc(self.caller, retired, &mut self.caller_endpoint, signal, b"retired-task", &[]),
            Err(error) if error.is_precommit_send_denial()
        ) {
            return None;
        }
        self.first_file = self.completed_file.take();
        self.phase = Phase::Ready;
        self.delegated = None;
        self.file_copy_done = false;
        self.block_copy = None;
        self.block_page.fill(0);
        self.fs_page.fill(0);
        Some(())
    }

    fn serve_block(
        &mut self,
        runtime: &mut Runtime,
        signal: Capability,
        payload: &[u8],
        transfers: &[(Capability, Rights)],
    ) -> Option<u64> {
        if !matches!(
            self.phase,
            Phase::Mount | Phase::Lookup(..) | Phase::Read(..)
        ) || self.block_copy.is_some()
            || transfers != [(self.block_transfer, Rights::MAP.union(Rights::WRITE))]
        {
            return None;
        }
        runtime
            .authorize_capability_exact(self.filesystem, signal, Rights::SIGNAL, DEPENDENCY)
            .ok()?;
        let wire = block::decode_read_request(payload.try_into().ok()?, 4096).ok()?;
        let count = usize::try_from(wire.sector_count).ok()?.checked_mul(512)?;
        let start = usize::try_from(wire.output.offset()).ok()?;
        let sectors = u32::from_le_bytes(MEDIA[..4].try_into().ok()?);
        if wire.session != block::OpaqueHandle::new(8, 10)?
            || count as u64 != wire.output.length()
            || wire.lba.checked_add(u64::from(wire.sector_count))? > u64::from(sectors)
        {
            return None;
        }
        let seq = runtime
            .deliver_ipc(
                self.filesystem,
                self.block,
                &mut self.dependency_endpoint,
                signal,
                payload,
                transfers,
            )
            .ok()?;
        let message = runtime
            .receive_ipc_envelope_bounded(self.block, block::READ_REQUEST_BYTES, 1)
            .ok()?;
        if message.sender() != self.filesystem || message.sequence() != seq {
            return None;
        }
        let leaf = message
            .message()
            .authorize_single_capability(
                runtime.capabilities(self.block).ok()?,
                Rights::MAP.union(Rights::WRITE),
            )
            .ok()?;
        if leaf.object() != BLOCK_PAGE {
            return None;
        }
        self.block_page.fill(0);
        let lba_end = wire.lba + u64::from(wire.sector_count);
        for record in MEDIA[4..].chunks_exact(516) {
            let lba = u64::from(u32::from_le_bytes(record[..4].try_into().ok()?));
            if (wire.lba..lba_end).contains(&lba) {
                let position = start + usize::try_from(lba - wire.lba).ok()? * 512;
                self.block_page[position..position + 512].copy_from_slice(&record[4..]);
            }
        }
        runtime
            .revoke_capability(self.block, leaf.capability())
            .ok()?;
        self.block_copy = Some((start, count));
        runtime
            .deliver_ipc(
                self.block,
                self.filesystem,
                &mut self.dependency_endpoint,
                self.block_signal,
                &block::encode_read_response(Ok(count as u64)),
                &[],
            )
            .ok()?;
        Some(seq)
    }
}
