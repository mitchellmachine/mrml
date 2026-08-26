use crate::{SUPERBLOCK_BYTES, StorageBlockDevice, StoragePrincipal};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockDeviceId(u64);

impl BlockDeviceId {
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockDeviceDescriptor {
    id: BlockDeviceId,
    block_size: u32,
    block_count: u64,
}

impl BlockDeviceDescriptor {
    pub const fn new(id: BlockDeviceId, block_size: u32, block_count: u64) -> Option<Self> {
        if block_size < 4096
            || block_size > 65_536
            || !block_size.is_power_of_two()
            || block_count == 0
        {
            return None;
        }
        Some(Self {
            id,
            block_size,
            block_count,
        })
    }

    pub const fn id(self) -> BlockDeviceId {
        self.id
    }

    pub const fn block_size(self) -> u32 {
        self.block_size
    }

    pub const fn block_count(self) -> u64 {
        self.block_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockRights(u8);

impl BlockRights {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const FLUSH: Self = Self(1 << 2);
    pub const REPLACE_SUPERBLOCK: Self = Self(1 << 3);
    pub const ALL: Self =
        Self(Self::READ.0 | Self::WRITE.0 | Self::FLUSH.0 | Self::REPLACE_SUPERBLOCK.0);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    pub const fn is_valid(self) -> bool {
        self.0 != 0 && self.0 & !Self::ALL.0 == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockSessionHandle {
    slot: u32,
    generation: u32,
}

impl BlockSessionHandle {
    /// Reconstructs an opaque session token received from a trusted service
    /// grant. The token is not sufficient authority: every operation also
    /// authenticates the exact owning principal and live service generation.
    pub const fn from_token(token: u64) -> Option<Self> {
        Self::from_parts(token as u32, (token >> 32) as u32)
    }

    pub const fn token(self) -> u64 {
        (self.generation as u64) << 32 | self.slot as u64
    }

    pub(crate) const fn from_parts(slot: u32, generation: u32) -> Option<Self> {
        if generation == 0 {
            None
        } else {
            Some(Self { slot, generation })
        }
    }

    pub const fn slot(self) -> u32 {
        self.slot
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }
}

#[derive(Clone, Copy)]
struct Session {
    generation: u32,
    occupied: bool,
    device: BlockDeviceId,
    owner: Option<StoragePrincipal>,
    rights: BlockRights,
    parent: Option<BlockSessionHandle>,
}

impl Session {
    const EMPTY: Self = Self {
        generation: 1,
        occupied: false,
        device: BlockDeviceId(1),
        owner: None,
        rights: BlockRights::READ,
        parent: None,
    };
}

/// Fixed-capacity capability boundary for native block devices.
pub struct BlockService<const DEVICES: usize, const SESSIONS: usize> {
    devices: [Option<BlockDeviceDescriptor>; DEVICES],
    sessions: [Session; SESSIONS],
}

impl<const DEVICES: usize, const SESSIONS: usize> Default for BlockService<DEVICES, SESSIONS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const DEVICES: usize, const SESSIONS: usize> BlockService<DEVICES, SESSIONS> {
    pub const fn new() -> Self {
        Self {
            devices: [None; DEVICES],
            sessions: [Session::EMPTY; SESSIONS],
        }
    }

    /// Supervisor-only device registration; the returned identity grants no I/O authority.
    pub fn register_device(
        &mut self,
        descriptor: BlockDeviceDescriptor,
    ) -> Result<(), BlockServiceError<core::convert::Infallible>> {
        if self
            .devices
            .iter()
            .flatten()
            .any(|current| current.id == descriptor.id)
        {
            return Err(BlockServiceError::DuplicateDevice);
        }
        let slot = self
            .devices
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(BlockServiceError::Capacity)?;
        *slot = Some(descriptor);
        Ok(())
    }

    /// Supervisor-only initial grant. Device identity alone cannot call this operation.
    pub fn grant(
        &mut self,
        device: BlockDeviceId,
        owner: StoragePrincipal,
        rights: BlockRights,
    ) -> Result<BlockSessionHandle, BlockServiceError<core::convert::Infallible>> {
        self.descriptor(device)?;
        if !rights.is_valid() {
            return Err(BlockServiceError::InvalidRights);
        }
        self.insert_session(device, owner, rights, None)
    }

    pub fn derive(
        &mut self,
        parent: BlockSessionHandle,
        parent_owner: StoragePrincipal,
        owner: StoragePrincipal,
        rights: BlockRights,
    ) -> Result<BlockSessionHandle, BlockServiceError<core::convert::Infallible>> {
        if !rights.is_valid() {
            return Err(BlockServiceError::InvalidRights);
        }
        let parent_session = self.session(parent)?;
        if parent_session.owner != Some(parent_owner) || !parent_session.rights.contains(rights) {
            return Err(BlockServiceError::Denied);
        }
        self.insert_session(parent_session.device, owner, rights, Some(parent))
    }

    pub fn revoke(
        &mut self,
        handle: BlockSessionHandle,
        owner: StoragePrincipal,
    ) -> Result<usize, BlockServiceError<core::convert::Infallible>> {
        if self.session(handle)?.owner != Some(owner) {
            return Err(BlockServiceError::Denied);
        }
        Ok(self.revoke_tree(handle))
    }

    /// Supervisor-only removal. Every session for the removed device is retired.
    pub fn remove_device(
        &mut self,
        device: BlockDeviceId,
    ) -> Result<usize, BlockServiceError<core::convert::Infallible>> {
        let slot = self
            .devices
            .iter_mut()
            .find(|slot| slot.is_some_and(|current| current.id == device))
            .ok_or(BlockServiceError::UnknownDevice)?;
        *slot = None;
        let mut revoked = 0;
        for session in &mut self.sessions {
            if session.occupied && session.device == device {
                retire(session);
                revoked += 1;
            }
        }
        Ok(revoked)
    }

    pub(crate) fn validate_owner(
        &self,
        handle: BlockSessionHandle,
        owner: StoragePrincipal,
    ) -> Result<(), BlockServiceError<core::convert::Infallible>> {
        let session = self.session(handle)?;
        if session.owner != Some(owner) {
            return Err(BlockServiceError::Denied);
        }
        self.descriptor(session.device)?;
        Ok(())
    }

    /// Atomically registers one bounded platform-discovered device set. The
    /// descriptors identify devices and geometry but grant no session or I/O
    /// authority. Every duplicate, collision, or capacity failure is detected
    /// before the first registry slot changes.
    pub fn register_devices_atomic(
        &mut self,
        descriptors: &[BlockDeviceDescriptor],
    ) -> Result<usize, BlockServiceError<core::convert::Infallible>> {
        if descriptors.len() > self.devices.iter().filter(|slot| slot.is_none()).count() {
            return Err(BlockServiceError::Capacity);
        }
        for (index, descriptor) in descriptors.iter().copied().enumerate() {
            if self
                .devices
                .iter()
                .flatten()
                .any(|current| current.id == descriptor.id)
                || descriptors[..index]
                    .iter()
                    .any(|current| current.id == descriptor.id)
            {
                return Err(BlockServiceError::DuplicateDevice);
            }
        }
        for descriptor in descriptors.iter().copied() {
            let slot = self
                .devices
                .iter_mut()
                .find(|slot| slot.is_none())
                .expect("registration capacity was completely preflighted");
            *slot = Some(descriptor);
        }
        Ok(descriptors.len())
    }

    /// Returns non-authorizing geometry for the exact live session after
    /// authenticating its owner. The descriptor identifies the bound device;
    /// every I/O operation still checks its independent right.
    pub fn session_descriptor(
        &self,
        handle: BlockSessionHandle,
        owner: StoragePrincipal,
    ) -> Result<BlockDeviceDescriptor, BlockServiceError<core::convert::Infallible>> {
        let session = self.session(handle)?;
        if session.owner != Some(owner) {
            return Err(BlockServiceError::Denied);
        }
        self.descriptor(session.device)
    }

    pub fn read_blocks<B: BlockServiceBackend>(
        &self,
        backend: &mut B,
        handle: BlockSessionHandle,
        owner: StoragePrincipal,
        block: u64,
        output: &mut [u8],
    ) -> Result<(), BlockServiceError<B::Error>> {
        let descriptor = self.authorize(handle, owner, BlockRights::READ)?;
        validate_transfer(descriptor, block, output.len())?;
        backend
            .read_blocks(descriptor.id, block, output)
            .map_err(BlockServiceError::Backend)
    }

    pub fn write_blocks<B: BlockServiceBackend>(
        &self,
        backend: &mut B,
        handle: BlockSessionHandle,
        owner: StoragePrincipal,
        block: u64,
        input: &[u8],
    ) -> Result<(), BlockServiceError<B::Error>> {
        let descriptor = self.authorize(handle, owner, BlockRights::WRITE)?;
        validate_transfer(descriptor, block, input.len())?;
        backend
            .write_blocks(descriptor.id, block, input)
            .map_err(BlockServiceError::Backend)
    }

    pub fn flush<B: BlockServiceBackend>(
        &self,
        backend: &mut B,
        handle: BlockSessionHandle,
        owner: StoragePrincipal,
    ) -> Result<(), BlockServiceError<B::Error>> {
        let descriptor = self.authorize(handle, owner, BlockRights::FLUSH)?;
        backend
            .flush(descriptor.id)
            .map_err(BlockServiceError::Backend)
    }

    pub fn replace_superblock<B: BlockServiceBackend>(
        &self,
        backend: &mut B,
        handle: BlockSessionHandle,
        owner: StoragePrincipal,
        block: u64,
        encoded: &[u8; SUPERBLOCK_BYTES],
    ) -> Result<(), BlockServiceError<B::Error>> {
        let descriptor = self.authorize(handle, owner, BlockRights::REPLACE_SUPERBLOCK)?;
        if block >= descriptor.block_count {
            return Err(BlockServiceError::InvalidRange);
        }
        backend
            .replace_superblock(descriptor.id, block, encoded)
            .map_err(BlockServiceError::Backend)
    }

    fn authorize<E>(
        &self,
        handle: BlockSessionHandle,
        owner: StoragePrincipal,
        right: BlockRights,
    ) -> Result<BlockDeviceDescriptor, BlockServiceError<E>> {
        let session = self.session(handle).map_err(map_infallible)?;
        if session.owner != Some(owner) || !session.rights.contains(right) {
            return Err(BlockServiceError::Denied);
        }
        self.descriptor(session.device).map_err(map_infallible)
    }

    fn descriptor<E>(
        &self,
        device: BlockDeviceId,
    ) -> Result<BlockDeviceDescriptor, BlockServiceError<E>> {
        self.devices
            .iter()
            .flatten()
            .find(|descriptor| descriptor.id == device)
            .copied()
            .ok_or(BlockServiceError::UnknownDevice)
    }

    fn session<E>(&self, handle: BlockSessionHandle) -> Result<Session, BlockServiceError<E>> {
        let index = usize::try_from(handle.slot).map_err(|_| BlockServiceError::StaleHandle)?;
        let session = self
            .sessions
            .get(index)
            .copied()
            .ok_or(BlockServiceError::StaleHandle)?;
        if !session.occupied || session.generation != handle.generation {
            return Err(BlockServiceError::StaleHandle);
        }
        Ok(session)
    }

    fn insert_session(
        &mut self,
        device: BlockDeviceId,
        owner: StoragePrincipal,
        rights: BlockRights,
        parent: Option<BlockSessionHandle>,
    ) -> Result<BlockSessionHandle, BlockServiceError<core::convert::Infallible>> {
        let (index, session) = self
            .sessions
            .iter_mut()
            .enumerate()
            .find(|(_, session)| !session.occupied && session.generation != u32::MAX)
            .ok_or(BlockServiceError::Capacity)?;
        session.occupied = true;
        session.device = device;
        session.owner = Some(owner);
        session.rights = rights;
        session.parent = parent;
        Ok(BlockSessionHandle {
            slot: u32::try_from(index).map_err(|_| BlockServiceError::Capacity)?,
            generation: session.generation,
        })
    }

    fn revoke_tree(&mut self, root: BlockSessionHandle) -> usize {
        let mut revoked = [None; SESSIONS];
        let mut count = 0;
        revoked[count] = Some(root);
        count += 1;
        let root_index = root.slot as usize;
        retire(&mut self.sessions[root_index]);
        let mut cursor = 0;
        while cursor < count {
            let parent = revoked[cursor].unwrap();
            for (index, session) in self.sessions.iter_mut().enumerate() {
                if session.occupied && session.parent == Some(parent) {
                    let child = BlockSessionHandle {
                        slot: index as u32,
                        generation: session.generation,
                    };
                    retire(session);
                    revoked[count] = Some(child);
                    count += 1;
                }
            }
            cursor += 1;
        }
        count
    }
}

fn retire(session: &mut Session) {
    session.occupied = false;
    session.owner = None;
    session.parent = None;
    session.generation = session.generation.saturating_add(1);
}

fn validate_transfer<E>(
    descriptor: BlockDeviceDescriptor,
    block: u64,
    length: usize,
) -> Result<(), BlockServiceError<E>> {
    if length == 0 || !length.is_multiple_of(descriptor.block_size as usize) {
        return Err(BlockServiceError::InvalidLength);
    }
    let blocks = u64::try_from(length / descriptor.block_size as usize)
        .map_err(|_| BlockServiceError::InvalidRange)?;
    let end = block
        .checked_add(blocks)
        .ok_or(BlockServiceError::InvalidRange)?;
    if end > descriptor.block_count {
        return Err(BlockServiceError::InvalidRange);
    }
    Ok(())
}

fn map_infallible<E>(error: BlockServiceError<core::convert::Infallible>) -> BlockServiceError<E> {
    match error {
        BlockServiceError::Capacity => BlockServiceError::Capacity,
        BlockServiceError::DuplicateDevice => BlockServiceError::DuplicateDevice,
        BlockServiceError::UnknownDevice => BlockServiceError::UnknownDevice,
        BlockServiceError::InvalidRights => BlockServiceError::InvalidRights,
        BlockServiceError::StaleHandle => BlockServiceError::StaleHandle,
        BlockServiceError::Denied => BlockServiceError::Denied,
        BlockServiceError::InvalidLength => BlockServiceError::InvalidLength,
        BlockServiceError::InvalidRange => BlockServiceError::InvalidRange,
        BlockServiceError::Backend(never) => match never {},
    }
}

/// Physical/hosted device boundary owned by the isolated block service.
///
/// # Safety
///
/// Implementations must perform complete exact transfers for the supplied
/// device and range, keep device identities isolated, make prior writes durable
/// before `flush` succeeds, and atomically replace the complete superblock
/// record or report an error.
pub unsafe trait BlockServiceBackend {
    type Error;

    fn read_blocks(
        &mut self,
        device: BlockDeviceId,
        block: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error>;
    fn write_blocks(
        &mut self,
        device: BlockDeviceId,
        block: u64,
        input: &[u8],
    ) -> Result<(), Self::Error>;
    fn flush(&mut self, device: BlockDeviceId) -> Result<(), Self::Error>;
    fn replace_superblock(
        &mut self,
        device: BlockDeviceId,
        block: u64,
        encoded: &[u8; SUPERBLOCK_BYTES],
    ) -> Result<(), Self::Error>;
}

pub struct ServicedBlockDevice<
    'a,
    B: BlockServiceBackend,
    const DEVICES: usize,
    const SESSIONS: usize,
> {
    service: &'a BlockService<DEVICES, SESSIONS>,
    backend: &'a mut B,
    handle: BlockSessionHandle,
    owner: StoragePrincipal,
}

impl<'a, B: BlockServiceBackend, const DEVICES: usize, const SESSIONS: usize>
    ServicedBlockDevice<'a, B, DEVICES, SESSIONS>
{
    pub fn new(
        service: &'a BlockService<DEVICES, SESSIONS>,
        backend: &'a mut B,
        handle: BlockSessionHandle,
        owner: StoragePrincipal,
    ) -> Result<Self, BlockServiceError<core::convert::Infallible>> {
        service.validate_owner(handle, owner)?;
        Ok(Self {
            service,
            backend,
            handle,
            owner,
        })
    }
}

unsafe impl<B: BlockServiceBackend, const DEVICES: usize, const SESSIONS: usize> StorageBlockDevice
    for ServicedBlockDevice<'_, B, DEVICES, SESSIONS>
{
    type Error = BlockServiceError<B::Error>;

    fn read_blocks(&mut self, block: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        self.service
            .read_blocks(self.backend, self.handle, self.owner, block, output)
    }

    fn write_blocks(&mut self, block: u64, input: &[u8]) -> Result<(), Self::Error> {
        self.service
            .write_blocks(self.backend, self.handle, self.owner, block, input)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.service.flush(self.backend, self.handle, self.owner)
    }

    fn replace_superblock(
        &mut self,
        block: u64,
        encoded: &[u8; SUPERBLOCK_BYTES],
    ) -> Result<(), Self::Error> {
        self.service
            .replace_superblock(self.backend, self.handle, self.owner, block, encoded)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockServiceError<E> {
    Capacity,
    DuplicateDevice,
    UnknownDevice,
    InvalidRights,
    StaleHandle,
    Denied,
    InvalidLength,
    InvalidRange,
    Backend(E),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AllocationWriteBackend, BlockVolume, CowMetadataImage, MetadataPointer,
        RecoveryMetadataBackend, VolumeHeader, VolumeId,
    };
    use mrml_crypto::Sha3_256;

    const BLOCK_SIZE: usize = 4096;
    const BLOCKS: usize = 16;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum BackendError {
        WrongDevice,
        Range,
        Failed,
    }

    struct Backend {
        bytes: [u8; BLOCK_SIZE * BLOCKS],
        device: BlockDeviceId,
        calls: usize,
        flushes: usize,
        replacements: usize,
        fail: bool,
    }

    impl Backend {
        fn new(device: BlockDeviceId) -> Self {
            Self {
                bytes: [0; BLOCK_SIZE * BLOCKS],
                device,
                calls: 0,
                flushes: 0,
                replacements: 0,
                fail: false,
            }
        }

        fn range(
            &self,
            device: BlockDeviceId,
            block: u64,
            length: usize,
        ) -> Result<core::ops::Range<usize>, BackendError> {
            if device != self.device {
                return Err(BackendError::WrongDevice);
            }
            let start = usize::try_from(block)
                .ok()
                .and_then(|value| value.checked_mul(BLOCK_SIZE))
                .ok_or(BackendError::Range)?;
            let end = start.checked_add(length).ok_or(BackendError::Range)?;
            if end > self.bytes.len() {
                return Err(BackendError::Range);
            }
            Ok(start..end)
        }
    }

    unsafe impl BlockServiceBackend for Backend {
        type Error = BackendError;

        fn read_blocks(
            &mut self,
            device: BlockDeviceId,
            block: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            if self.fail {
                return Err(BackendError::Failed);
            }
            let range = self.range(device, block, output.len())?;
            output.copy_from_slice(&self.bytes[range]);
            self.calls += 1;
            Ok(())
        }

        fn write_blocks(
            &mut self,
            device: BlockDeviceId,
            block: u64,
            input: &[u8],
        ) -> Result<(), Self::Error> {
            if self.fail {
                return Err(BackendError::Failed);
            }
            let range = self.range(device, block, input.len())?;
            self.bytes[range].copy_from_slice(input);
            self.calls += 1;
            Ok(())
        }

        fn flush(&mut self, device: BlockDeviceId) -> Result<(), Self::Error> {
            if self.fail {
                return Err(BackendError::Failed);
            }
            if device != self.device {
                return Err(BackendError::WrongDevice);
            }
            self.flushes += 1;
            Ok(())
        }

        fn replace_superblock(
            &mut self,
            device: BlockDeviceId,
            block: u64,
            encoded: &[u8; SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            if self.fail {
                return Err(BackendError::Failed);
            }
            let range = self.range(device, block, BLOCK_SIZE)?;
            self.bytes[range.clone()].fill(0);
            self.bytes[range.start..range.start + SUPERBLOCK_BYTES].copy_from_slice(encoded);
            self.replacements += 1;
            Ok(())
        }
    }

    fn device() -> BlockDeviceId {
        BlockDeviceId::new(7).unwrap()
    }

    fn descriptor() -> BlockDeviceDescriptor {
        BlockDeviceDescriptor::new(device(), BLOCK_SIZE as u32, BLOCKS as u64).unwrap()
    }

    fn owner(value: u64) -> StoragePrincipal {
        StoragePrincipal::new(value).unwrap()
    }

    fn service() -> BlockService<2, 8> {
        let mut service = BlockService::new();
        service.register_device(descriptor()).unwrap();
        service
    }

    fn digest(input: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(input);
        hasher.finalize()
    }

    #[test]
    fn identity_never_authorizes_and_derived_rights_only_attenuate() {
        let mut service = service();
        let parent = service.grant(device(), owner(1), BlockRights::ALL).unwrap();
        let reader = service
            .derive(parent, owner(1), owner(2), BlockRights::READ)
            .unwrap();
        assert_eq!(
            service.derive(reader, owner(2), owner(3), BlockRights::WRITE),
            Err(BlockServiceError::Denied)
        );
        assert_eq!(
            service.derive(parent, owner(2), owner(3), BlockRights::READ),
            Err(BlockServiceError::Denied)
        );
        let mut backend = Backend::new(device());
        let mut output = [0; BLOCK_SIZE];
        service
            .read_blocks(&mut backend, reader, owner(2), 0, &mut output)
            .unwrap();
        assert_eq!(
            service.write_blocks(&mut backend, reader, owner(2), 0, &output),
            Err(BlockServiceError::Denied)
        );
        assert_eq!(
            service.read_blocks(&mut backend, reader, owner(1), 0, &mut output),
            Err(BlockServiceError::Denied)
        );
        assert_eq!(backend.calls, 1);
    }

    #[test]
    fn platform_device_set_registration_is_atomic_and_non_authorizing() {
        let first = descriptor();
        let second = BlockDeviceDescriptor::new(
            BlockDeviceId::new(8).unwrap(),
            BLOCK_SIZE as u32,
            BLOCKS as u64,
        )
        .unwrap();
        let third = BlockDeviceDescriptor::new(
            BlockDeviceId::new(9).unwrap(),
            BLOCK_SIZE as u32,
            BLOCKS as u64,
        )
        .unwrap();
        let fourth = BlockDeviceDescriptor::new(
            BlockDeviceId::new(10).unwrap(),
            BLOCK_SIZE as u32,
            BLOCKS as u64,
        )
        .unwrap();
        let mut service = BlockService::<3, 4>::new();
        service.register_device(first).unwrap();

        assert_eq!(
            service.register_devices_atomic(&[second, second]),
            Err(BlockServiceError::DuplicateDevice)
        );
        assert_eq!(
            service.grant(second.id(), owner(1), BlockRights::READ),
            Err(BlockServiceError::UnknownDevice)
        );
        assert_eq!(
            service.register_devices_atomic(&[second, third, fourth]),
            Err(BlockServiceError::Capacity)
        );
        assert_eq!(
            service.grant(second.id(), owner(1), BlockRights::READ),
            Err(BlockServiceError::UnknownDevice)
        );
        assert_eq!(
            service.register_devices_atomic(&[second, first]),
            Err(BlockServiceError::DuplicateDevice)
        );
        assert_eq!(
            service.grant(second.id(), owner(1), BlockRights::READ),
            Err(BlockServiceError::UnknownDevice)
        );

        assert_eq!(service.register_devices_atomic(&[second, third]), Ok(2));
        let session = service
            .grant(second.id(), owner(1), BlockRights::READ)
            .unwrap();
        assert_eq!(service.session_descriptor(session, owner(1)), Ok(second));
    }

    #[test]
    fn revocation_is_transitive_and_stale_generations_never_revive() {
        let mut service = service();
        let root = service.grant(device(), owner(1), BlockRights::ALL).unwrap();
        let child = service
            .derive(root, owner(1), owner(2), BlockRights::READ)
            .unwrap();
        let grandchild = service
            .derive(child, owner(2), owner(3), BlockRights::READ)
            .unwrap();
        assert_eq!(service.revoke(root, owner(1)).unwrap(), 3);
        let replacement = service
            .grant(device(), owner(1), BlockRights::READ)
            .unwrap();
        assert_eq!(replacement.slot(), root.slot());
        assert_ne!(replacement.generation(), root.generation());
        let mut backend = Backend::new(device());
        assert_eq!(
            service.read_blocks(&mut backend, grandchild, owner(3), 0, &mut [0; BLOCK_SIZE]),
            Err(BlockServiceError::StaleHandle)
        );
        assert_eq!(backend.calls, 0);
    }

    #[test]
    fn malformed_transfers_and_missing_rights_fail_before_backend() {
        let mut service = service();
        let writer = service
            .grant(
                device(),
                owner(1),
                BlockRights::WRITE.union(BlockRights::FLUSH),
            )
            .unwrap();
        let mut backend = Backend::new(device());
        assert_eq!(
            service.write_blocks(&mut backend, writer, owner(1), 0, &[0; 1]),
            Err(BlockServiceError::InvalidLength)
        );
        assert_eq!(
            service.write_blocks(
                &mut backend,
                writer,
                owner(1),
                BLOCKS as u64,
                &[0; BLOCK_SIZE],
            ),
            Err(BlockServiceError::InvalidRange)
        );
        assert_eq!(
            service.replace_superblock(&mut backend, writer, owner(1), 1, &[0; SUPERBLOCK_BYTES]),
            Err(BlockServiceError::Denied)
        );
        assert_eq!(backend.calls + backend.replacements, 0);
    }

    #[test]
    fn device_removal_revokes_every_session_and_backend_errors_stay_errors() {
        let mut service = service();
        let first = service
            .grant(device(), owner(1), BlockRights::READ)
            .unwrap();
        let second = service
            .grant(device(), owner(2), BlockRights::READ)
            .unwrap();
        let mut backend = Backend::new(device());
        backend.fail = true;
        assert_eq!(
            service.read_blocks(&mut backend, first, owner(1), 0, &mut [0; BLOCK_SIZE]),
            Err(BlockServiceError::Backend(BackendError::Failed))
        );
        assert_eq!(service.remove_device(device()).unwrap(), 2);
        assert_eq!(
            service.read_blocks(&mut backend, second, owner(2), 0, &mut [0; BLOCK_SIZE]),
            Err(BlockServiceError::StaleHandle)
        );
    }

    #[test]
    fn serviced_device_runs_the_exact_block_volume_adapter() {
        let mut service = service();
        let handle = service.grant(device(), owner(1), BlockRights::ALL).unwrap();
        let mut backend = Backend::new(device());
        let encoded = [0x5a; BLOCK_SIZE];
        let image = CowMetadataImage::new(MetadataPointer::new(8, 1).unwrap(), digest(&encoded));
        let serviced = ServicedBlockDevice::new(&service, &mut backend, handle, owner(1)).unwrap();
        let header = VolumeHeader::new(
            VolumeId::new([3; 16]).unwrap(),
            BLOCK_SIZE as u32,
            BLOCKS as u64,
            1,
            2,
        )
        .unwrap();
        let mut scratch = [0; BLOCK_SIZE];
        let mut volume = BlockVolume::new(header, 1, serviced, &mut scratch).unwrap();
        AllocationWriteBackend::stage_allocation_image(&mut volume, image, &encoded).unwrap();
        AllocationWriteBackend::flush_allocation_image(&mut volume).unwrap();
        let mut recovered = [0; BLOCK_SIZE];
        RecoveryMetadataBackend::read_metadata(
            &mut volume,
            MetadataPointer::new(8, 1).unwrap(),
            &mut recovered,
        )
        .unwrap();
        assert_eq!(recovered, encoded);
        drop(volume);
        assert_eq!((backend.calls, backend.flushes), (3, 1));
    }
}
