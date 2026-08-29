//! Hosted-only evidence path for recovered Total MicroVM admission.
//!
//! This module deliberately uses the normal configuration checkpoint, exact
//! file-generation, authenticated authority-checkpoint, boot-bound monotonic
//! recovery, dependent validation, service-publication, and active-release
//! binding APIs. Its fixed in-memory backends are controlled-probe mechanics;
//! they are not durable storage, owner-presence, TPM, firmware, or physical
//! rollback evidence.

use super::{
    ConfigTransaction, ConfigUpdate, ConfigValue, ConfigurationService, IsolationPolicySetting,
    OwnerIsolationSelection, PERSISTED_RESTART_POLICY_BYTES, PersistedRestartPolicy,
    RecoveredDeploymentTotalControlPlane, RecoveredInstalledStableTotalSystemSelection,
    RuntimeDomainPolicyBinding, SettingId, SettingSchema, StableConfigurationRecoveryValidator,
    StableServiceRecoveryValidator, reacquire_handoff_installed_recovery_device,
    recover_selected_runtime_assignment, recover_serviced_stable_total_system_selection,
};
use mrml_crypto::Sha3_256;
use mrml_deployment::{
    DEPLOYMENT_RECOVERY_STATE_BYTES, DeploymentRecoveryStateStore, DeploymentService,
    GenerationCandidate, encode_deployment_recovery_state_with_release,
    encode_deployment_release_checkpoint,
};
#[cfg(test)]
use mrml_kernel::InstalledRecoverySource;
use mrml_kernel::arch::x86_64::UserContext;
use mrml_kernel::{
    BootHandoff, BootRecoveryEnvelope, CapabilitySpace, InstalledRecoveryBootIdentity, ObjectId,
    Priority, Rights, ServiceSupervisor, TaskRuntime,
};
use mrml_package_format::MAX_SYSTEM_RELEASE_BYTES;
use mrml_storage::{
    AUTHORITY_RECOVERY_STATE_BYTES, AllocationImage, AllocationKind, AllocationRecord,
    AuthorityCheckpointProofIssuer, AuthorityRecoveryStateStore, BlockDeviceDescriptor,
    BlockDeviceId, BlockService, BlockServiceBackend, BootRecoveryAdmission, DirectoryEntry,
    DirectoryImage, DirectoryMetadata, ExtentImage, ExtentRecord, FileMetadata, FileReadBackend,
    MetadataPointer, ObjectIdAllocatorImage, OwnerApprovedAuthorityCheckpoint,
    PlatformBlockDeviceDescriptor, PlatformBlockDeviceIdentity, PlatformBlockTransport,
    SUPERBLOCK_BYTES, StorageAuthorityTable, StorageName, StorageObjectId, StorageObjectKind,
    StoragePrincipal, StorageRecoveryGrant, StorageRights, Superblock, VolumeHeader, VolumeId,
    authority_checkpoint_digest, encode_authority_checkpoint,
    recover_selected_validate_and_commit_stable_authorities,
};

const BLOCK_BYTES: usize = 4096;
const MAX_HOSTED_RELEASE_BYTES: usize = 512 * 1024;
const MAX_RELEASE_BLOCKS: usize = MAX_HOSTED_RELEASE_BYTES.div_ceil(BLOCK_BYTES);
const RELEASE_BLOCK_BASE: u64 = 33;
const CONFIGURATION_GENERATION: u64 = 2;
const ROOT_GENERATION: u64 = 14;
const POLICY_GENERATION: u64 = 1;
const ACCEPTED_AUTHORITY_EPOCH: u64 = 8;
const ACCEPTED_HANDLE_GENERATION: u32 = 1;
const CHECKPOINT_AUTHORITY_EPOCH: u64 = 9;
const CHECKPOINT_HANDLE_GENERATION: u32 = 2;

/// Recovered policy domain for the intentionally co-located hosted ZIM/Zstd
/// component pair. Both runners consume this value rather than restating a
/// detached launch identity.
pub const HOSTED_TOTAL_COMPONENT_DOMAIN: ObjectId = ObjectId(0x5a49_4d5f_5a53_5444);
pub const HOSTED_TOTAL_SECONDARY_DOMAIN: ObjectId = ObjectId(0x5a49_4d5f_4445_504c);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedRecoveryProbeError {
    MissingRecoveryState,
    MissingInstalledIdentity,
    RecoveryRootMismatch,
    Configuration,
    StorageLayout,
    InstalledDevice,
    StableSelection,
    ReleaseLayout,
    AllocationLayout,
    AuthorityCheckpoint,
    Recovery,
    ServicePublication,
    Deployment,
    Admission,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedRecoveryProbeBuildError<E> {
    Probe(HostedRecoveryProbeError),
    ReleaseBuilder(E),
}

impl<E> From<HostedRecoveryProbeError> for HostedRecoveryProbeBuildError<E> {
    fn from(error: HostedRecoveryProbeError) -> Self {
        Self::Probe(error)
    }
}

struct CheckpointBackend {
    object: StorageObjectId,
    bytes: [u8; BLOCK_BYTES],
}

struct DeploymentFileBackend {
    object: StorageObjectId,
    generation: u64,
    bytes: [u8; BLOCK_BYTES],
}

struct DeploymentReleaseBackend<'a> {
    object: StorageObjectId,
    generation: u64,
    bytes: &'a [u8],
}

unsafe impl FileReadBackend for DeploymentReleaseBackend<'_> {
    type Error = ();

    fn read_verified_extent(
        &mut self,
        record: ExtentRecord,
        byte_offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        let physical_block = record.physical_block().ok_or(())?;
        let block_count = usize::try_from(record.block_count()).map_err(|_| ())?;
        if record.file() != self.object
            || record.metadata_generation() != self.generation
            || physical_block != RELEASE_BLOCK_BASE
            || block_count == 0
            || block_count > MAX_RELEASE_BLOCKS
        {
            return Err(());
        }
        let extent_bytes = block_count.checked_mul(BLOCK_BYTES).ok_or(())?;
        if self.bytes.len() > extent_bytes || extent_bytes > MAX_HOSTED_RELEASE_BYTES {
            return Err(());
        }
        if record.content_digest() != padded_extent_digest(self.bytes, extent_bytes).ok_or(())? {
            return Err(());
        }
        let within = usize::try_from(byte_offset).map_err(|_| ())?;
        let end = within.checked_add(output.len()).ok_or(())?;
        output.copy_from_slice(self.bytes.get(within..end).ok_or(())?);
        Ok(())
    }
}

unsafe impl FileReadBackend for DeploymentFileBackend {
    type Error = ();

    fn read_verified_extent(
        &mut self,
        record: ExtentRecord,
        byte_offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        if record.file() != self.object
            || record.metadata_generation() != self.generation
            || record.content_digest() != digest(&self.bytes)
        {
            return Err(());
        }
        let start = usize::try_from(byte_offset).map_err(|_| ())?;
        let end = start.checked_add(output.len()).ok_or(())?;
        output.copy_from_slice(self.bytes.get(start..end).ok_or(())?);
        Ok(())
    }
}

struct DeploymentStateStore {
    bytes: [u8; DEPLOYMENT_RECOVERY_STATE_BYTES],
}

impl DeploymentRecoveryStateStore for DeploymentStateStore {
    type Error = ();

    fn load_authenticated(
        &self,
        output: &mut [u8; DEPLOYMENT_RECOVERY_STATE_BYTES],
    ) -> Result<(), Self::Error> {
        *output = self.bytes;
        Ok(())
    }

    fn compare_and_store(
        &mut self,
        expected: &[u8; DEPLOYMENT_RECOVERY_STATE_BYTES],
        replacement: &[u8; DEPLOYMENT_RECOVERY_STATE_BYTES],
    ) -> Result<(), Self::Error> {
        if self.bytes != *expected {
            return Err(());
        }
        self.bytes = *replacement;
        Ok(())
    }
}

unsafe impl FileReadBackend for CheckpointBackend {
    type Error = ();

    fn read_verified_extent(
        &mut self,
        record: ExtentRecord,
        byte_offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        if record.file() != self.object
            || record.metadata_generation() != CONFIGURATION_GENERATION
            || record.content_digest() != digest(&self.bytes)
        {
            return Err(());
        }
        let start = usize::try_from(byte_offset).map_err(|_| ())?;
        let end = start.checked_add(output.len()).ok_or(())?;
        output.copy_from_slice(self.bytes.get(start..end).ok_or(())?);
        Ok(())
    }
}

struct ReachableMetadataBackend {
    fail_block: Option<u64>,
    header: [u8; BLOCK_BYTES],
    primary: [u8; BLOCK_BYTES],
    secondary: [u8; BLOCK_BYTES],
    root: [u8; BLOCK_BYTES],
    entries: [u8; BLOCK_BYTES],
    configuration: [u8; BLOCK_BYTES],
    configuration_extents: [u8; BLOCK_BYTES],
    authority: [u8; BLOCK_BYTES],
    authority_extents: [u8; BLOCK_BYTES],
    deployment: [u8; BLOCK_BYTES],
    deployment_extents: [u8; BLOCK_BYTES],
    release: [u8; BLOCK_BYTES],
    release_extents: [u8; BLOCK_BYTES],
    allocation: [u8; BLOCK_BYTES],
    object_ids: [u8; BLOCK_BYTES],
}

unsafe impl BlockServiceBackend for ReachableMetadataBackend {
    type Error = ();

    fn read_blocks(
        &mut self,
        device: BlockDeviceId,
        block: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        if device != recovery_device() || self.fail_block == Some(block) {
            return Err(());
        }
        let source = match block {
            0 => &self.header,
            1 => &self.primary,
            2 => &self.secondary,
            10 => &self.root,
            11 => &self.entries,
            12 => &self.configuration,
            13 => &self.configuration_extents,
            14 => &self.authority,
            15 => &self.authority_extents,
            16 => &self.deployment,
            17 => &self.deployment_extents,
            18 => &self.release,
            19 => &self.release_extents,
            20 => &self.allocation,
            21 => &self.object_ids,
            _ => return Err(()),
        };
        if output.len() != source.len() {
            return Err(());
        }
        output.copy_from_slice(source);
        Ok(())
    }

    fn write_blocks(
        &mut self,
        _device: BlockDeviceId,
        _block: u64,
        _input: &[u8],
    ) -> Result<(), Self::Error> {
        Err(())
    }

    fn flush(&mut self, _device: BlockDeviceId) -> Result<(), Self::Error> {
        Err(())
    }

    fn replace_superblock(
        &mut self,
        _device: BlockDeviceId,
        _block: u64,
        _encoded: &[u8; SUPERBLOCK_BYTES],
    ) -> Result<(), Self::Error> {
        Err(())
    }
}

struct RecoveryStateStore {
    bytes: [u8; AUTHORITY_RECOVERY_STATE_BYTES],
}

impl RecoveryStateStore {
    fn new_bound(
        epoch: u64,
        handle_generation: u32,
        volume: VolumeId,
        root_generation: u64,
    ) -> Self {
        let mut bytes = [0; AUTHORITY_RECOVERY_STATE_BYTES];
        bytes[..16].copy_from_slice(b"MRML-AUTHSTATE1\0");
        bytes[16..24].copy_from_slice(&epoch.to_le_bytes());
        bytes[24..28].copy_from_slice(&handle_generation.to_le_bytes());
        bytes[32..48].copy_from_slice(&volume.bytes());
        bytes[48..56].copy_from_slice(&root_generation.to_le_bytes());
        Self { bytes }
    }
}

impl AuthorityRecoveryStateStore for RecoveryStateStore {
    type Error = ();

    fn load_authenticated(
        &self,
        output: &mut [u8; AUTHORITY_RECOVERY_STATE_BYTES],
    ) -> Result<(), Self::Error> {
        output.copy_from_slice(&self.bytes);
        Ok(())
    }

    fn compare_and_store(
        &mut self,
        expected: &[u8; AUTHORITY_RECOVERY_STATE_BYTES],
        replacement: &[u8; AUTHORITY_RECOVERY_STATE_BYTES],
    ) -> Result<(), Self::Error> {
        if self.bytes != *expected {
            return Err(());
        }
        self.bytes.copy_from_slice(replacement);
        Ok(())
    }
}

fn volume() -> VolumeId {
    VolumeId::new([0x51; 16]).unwrap()
}

fn header() -> VolumeHeader {
    VolumeHeader::new(volume(), BLOCK_BYTES as u32, 100, 1, 2).unwrap()
}

fn recovery_device() -> BlockDeviceId {
    BlockDeviceId::new(1).unwrap()
}

fn recovery_block_service() -> Result<BlockService<1, 1>, HostedRecoveryProbeError> {
    let mut service = BlockService::<1, 1>::new();
    let descriptors = [BlockDeviceDescriptor::new(
        recovery_device(),
        BLOCK_BYTES as u32,
        header().block_count(),
    )
    .ok_or(HostedRecoveryProbeError::StorageLayout)?];
    let platform = [PlatformBlockDeviceDescriptor::new(
        descriptors[0],
        PlatformBlockDeviceIdentity::new(PlatformBlockTransport::Hosted, [0x42; 32], 1, 1)
            .ok_or(HostedRecoveryProbeError::StorageLayout)?,
    )];
    service
        .register_platform_devices_atomic(&platform)
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?;
    Ok(service)
}

#[cfg(test)]
fn installed_boot_identity(
    root_generation: u64,
) -> Result<InstalledRecoveryBootIdentity, HostedRecoveryProbeError> {
    InstalledRecoveryBootIdentity::new(
        InstalledRecoverySource::Hosted,
        [0x42; 32],
        1,
        1,
        BLOCK_BYTES as u32,
        header().block_count(),
        volume().bytes(),
        header().primary_superblock(),
        root_generation,
    )
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)
}

fn object(local: u64) -> StorageObjectId {
    StorageObjectId::new(volume(), local).unwrap()
}

fn principal() -> StoragePrincipal {
    StoragePrincipal::new(7).unwrap()
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha3_256::new();
    digest.update(bytes);
    digest.finalize()
}

fn padded_extent_digest(bytes: &[u8], extent_bytes: usize) -> Option<[u8; 32]> {
    let padding = extent_bytes.checked_sub(bytes.len())?;
    let zeros = [0; BLOCK_BYTES];
    let mut digest = Sha3_256::new();
    digest.update(bytes);
    let mut remaining = padding;
    while remaining != 0 {
        let length = remaining.min(zeros.len());
        digest.update(&zeros[..length]);
        remaining -= length;
    }
    Some(digest.finalize())
}

fn build_reachable_total_device(
    root_generation: u64,
    configuration_length: usize,
    configuration_bytes: &[u8; BLOCK_BYTES],
    authority_length: usize,
    authority_bytes: &[u8; BLOCK_BYTES],
    deployment_length: usize,
    deployment_bytes: &[u8; BLOCK_BYTES],
    release_bytes: &[u8],
    fail_block: Option<u64>,
) -> Result<ReachableMetadataBackend, HostedRecoveryProbeError> {
    if deployment_length == 0
        || deployment_length > BLOCK_BYTES
        || release_bytes.is_empty()
        || release_bytes.len() > MAX_HOSTED_RELEASE_BYTES
        || release_bytes.len() > MAX_SYSTEM_RELEASE_BYTES
    {
        return Err(HostedRecoveryProbeError::StorageLayout);
    }
    let root = object(1);
    let configuration = object(9);
    let authority = object(10);
    let deployment = object(11);
    let release = object(12);
    let root_pointer = MetadataPointer::new(10, 1).unwrap();
    let entries_pointer = MetadataPointer::new(11, 1).unwrap();
    let configuration_extents_pointer = MetadataPointer::new(13, 1).unwrap();
    let authority_extents_pointer = MetadataPointer::new(15, 1).unwrap();
    let deployment_extents_pointer = MetadataPointer::new(17, 1).unwrap();
    let release_extents_pointer = MetadataPointer::new(19, 1).unwrap();
    let allocation_pointer = MetadataPointer::new(20, 1).unwrap();
    let object_ids_pointer = MetadataPointer::new(21, 1).unwrap();
    let candidate = Superblock::new(
        header(),
        root_generation,
        root_generation
            .checked_sub(1)
            .ok_or(HostedRecoveryProbeError::StorageLayout)?,
        root,
        root_pointer,
        allocation_pointer,
    )
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)?;

    let mut root_bytes = [0; BLOCK_BYTES];
    DirectoryMetadata::new(header(), root, 2, None, 4, entries_pointer)
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?
        .encode(
            (&mut root_bytes[..mrml_storage::DIRECTORY_METADATA_BYTES])
                .try_into()
                .unwrap(),
        );
    let entries = [
        DirectoryEntry::new(
            StorageName::new("configuration").unwrap(),
            configuration,
            StorageObjectKind::File,
            CONFIGURATION_GENERATION,
        )
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
        DirectoryEntry::new(
            StorageName::new("authority-checkpoint").unwrap(),
            authority,
            StorageObjectKind::File,
            CONFIGURATION_GENERATION,
        )
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
        DirectoryEntry::new(
            StorageName::new("deployment-checkpoint").unwrap(),
            deployment,
            StorageObjectKind::File,
            CONFIGURATION_GENERATION,
        )
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
        DirectoryEntry::new(
            StorageName::new("system-release").unwrap(),
            release,
            StorageObjectKind::File,
            CONFIGURATION_GENERATION,
        )
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
    ];
    let mut entry_bytes = [0; BLOCK_BYTES];
    DirectoryImage::<4>::build(header(), root, 2, entries_pointer, &entries)
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?
        .encode(&mut entry_bytes)
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?;

    let mut configuration_metadata = [0; BLOCK_BYTES];
    FileMetadata::new(
        header(),
        configuration,
        CONFIGURATION_GENERATION,
        u64::try_from(configuration_length).map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
        1,
        configuration_extents_pointer,
        digest(&configuration_bytes[..configuration_length]),
    )
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)?
    .encode(
        (&mut configuration_metadata[..mrml_storage::FILE_METADATA_BYTES])
            .try_into()
            .unwrap(),
    );
    let configuration_extent = ExtentRecord::data(
        configuration,
        CONFIGURATION_GENERATION,
        0,
        1,
        30,
        digest(configuration_bytes),
    )
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)?;
    let mut configuration_extents = [0; BLOCK_BYTES];
    ExtentImage::<1>::build(
        header(),
        configuration,
        CONFIGURATION_GENERATION,
        u64::try_from(configuration_length).map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
        configuration_extents_pointer,
        &[configuration_extent],
    )
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)?
    .encode(&mut configuration_extents)
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)?;

    let mut authority_metadata = [0; BLOCK_BYTES];
    FileMetadata::new(
        header(),
        authority,
        CONFIGURATION_GENERATION,
        u64::try_from(authority_length).map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
        1,
        authority_extents_pointer,
        digest(&authority_bytes[..authority_length]),
    )
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)?
    .encode(
        (&mut authority_metadata[..mrml_storage::FILE_METADATA_BYTES])
            .try_into()
            .unwrap(),
    );
    let authority_extent = ExtentRecord::data(
        authority,
        CONFIGURATION_GENERATION,
        0,
        1,
        31,
        digest(authority_bytes),
    )
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)?;
    let mut authority_extents = [0; BLOCK_BYTES];
    ExtentImage::<1>::build(
        header(),
        authority,
        CONFIGURATION_GENERATION,
        u64::try_from(authority_length).map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
        authority_extents_pointer,
        &[authority_extent],
    )
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)?
    .encode(&mut authority_extents)
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)?;

    let mut deployment_metadata = [0; BLOCK_BYTES];
    FileMetadata::new(
        header(),
        deployment,
        CONFIGURATION_GENERATION,
        u64::try_from(deployment_length).map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
        1,
        deployment_extents_pointer,
        digest(&deployment_bytes[..deployment_length]),
    )
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)?
    .encode(
        (&mut deployment_metadata[..mrml_storage::FILE_METADATA_BYTES])
            .try_into()
            .unwrap(),
    );
    let deployment_extent = ExtentRecord::data(
        deployment,
        CONFIGURATION_GENERATION,
        0,
        1,
        32,
        digest(deployment_bytes),
    )
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)?;
    let mut deployment_extents = [0; BLOCK_BYTES];
    ExtentImage::<1>::build(
        header(),
        deployment,
        CONFIGURATION_GENERATION,
        u64::try_from(deployment_length).map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
        deployment_extents_pointer,
        &[deployment_extent],
    )
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)?
    .encode(&mut deployment_extents)
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)?;

    let release_block_count = release_bytes.len().div_ceil(BLOCK_BYTES);
    if RELEASE_BLOCK_BASE
        .checked_add(
            u64::try_from(release_block_count)
                .map_err(|_| HostedRecoveryProbeError::ReleaseLayout)?,
        )
        .is_none_or(|end| end > header().block_count())
    {
        return Err(HostedRecoveryProbeError::ReleaseLayout);
    }
    let padded_release_length = release_block_count
        .checked_mul(BLOCK_BYTES)
        .ok_or(HostedRecoveryProbeError::StorageLayout)?;
    let mut release_metadata = [0; BLOCK_BYTES];
    FileMetadata::new(
        header(),
        release,
        CONFIGURATION_GENERATION,
        u64::try_from(release_bytes.len()).map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
        1,
        release_extents_pointer,
        digest(release_bytes),
    )
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)?
    .encode(
        (&mut release_metadata[..mrml_storage::FILE_METADATA_BYTES])
            .try_into()
            .unwrap(),
    );
    let release_extent = ExtentRecord::data(
        release,
        CONFIGURATION_GENERATION,
        0,
        u32::try_from(release_block_count).map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
        33,
        padded_extent_digest(release_bytes, padded_release_length)
            .ok_or(HostedRecoveryProbeError::ReleaseLayout)?,
    )
    .map_err(|_| HostedRecoveryProbeError::ReleaseLayout)?;
    let mut release_extents = [0; BLOCK_BYTES];
    ExtentImage::<1>::build(
        header(),
        release,
        CONFIGURATION_GENERATION,
        u64::try_from(release_bytes.len()).map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
        release_extents_pointer,
        &[release_extent],
    )
    .map_err(|_| HostedRecoveryProbeError::ReleaseLayout)?
    .encode(&mut release_extents)
    .map_err(|_| HostedRecoveryProbeError::ReleaseLayout)?;

    let records = [
        AllocationRecord::new(root, 2, 10, 1, AllocationKind::ObjectMetadata).unwrap(),
        AllocationRecord::new(root, 2, 11, 1, AllocationKind::DirectoryEntries).unwrap(),
        AllocationRecord::new(
            configuration,
            CONFIGURATION_GENERATION,
            12,
            1,
            AllocationKind::ObjectMetadata,
        )
        .unwrap(),
        AllocationRecord::new(
            configuration,
            CONFIGURATION_GENERATION,
            13,
            1,
            AllocationKind::FileExtents,
        )
        .unwrap(),
        AllocationRecord::new(
            authority,
            CONFIGURATION_GENERATION,
            14,
            1,
            AllocationKind::ObjectMetadata,
        )
        .unwrap(),
        AllocationRecord::new(
            authority,
            CONFIGURATION_GENERATION,
            15,
            1,
            AllocationKind::FileExtents,
        )
        .unwrap(),
        AllocationRecord::new(
            deployment,
            CONFIGURATION_GENERATION,
            16,
            1,
            AllocationKind::ObjectMetadata,
        )
        .unwrap(),
        AllocationRecord::new(
            deployment,
            CONFIGURATION_GENERATION,
            17,
            1,
            AllocationKind::FileExtents,
        )
        .unwrap(),
        AllocationRecord::new(
            release,
            CONFIGURATION_GENERATION,
            18,
            1,
            AllocationKind::ObjectMetadata,
        )
        .unwrap(),
        AllocationRecord::new(
            release,
            CONFIGURATION_GENERATION,
            19,
            1,
            AllocationKind::FileExtents,
        )
        .unwrap(),
        AllocationRecord::new(
            root,
            root_generation,
            20,
            1,
            AllocationKind::AllocationMetadata,
        )
        .unwrap(),
        AllocationRecord::new(
            root,
            root_generation,
            21,
            1,
            AllocationKind::ObjectIdAllocatorMetadata,
        )
        .unwrap(),
        AllocationRecord::new(
            configuration,
            CONFIGURATION_GENERATION,
            30,
            1,
            AllocationKind::FileData,
        )
        .unwrap(),
        AllocationRecord::new(
            authority,
            CONFIGURATION_GENERATION,
            31,
            1,
            AllocationKind::FileData,
        )
        .unwrap(),
        AllocationRecord::new(
            deployment,
            CONFIGURATION_GENERATION,
            32,
            1,
            AllocationKind::FileData,
        )
        .unwrap(),
        AllocationRecord::new(
            release,
            CONFIGURATION_GENERATION,
            33,
            u32::try_from(release_block_count)
                .map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
            AllocationKind::FileData,
        )
        .unwrap(),
    ];
    let mut allocation = [0; BLOCK_BYTES];
    AllocationImage::<16>::build(header(), root_generation, allocation_pointer, &records)
        .map_err(|_| HostedRecoveryProbeError::AllocationLayout)?
        .encode(&mut allocation)
        .map_err(|_| HostedRecoveryProbeError::AllocationLayout)?;
    let mut object_ids = [0; BLOCK_BYTES];
    ObjectIdAllocatorImage::build(header(), root_generation, Some(13), object_ids_pointer)
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?
        .encode(&mut object_ids)
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?;

    let mut primary = [0; BLOCK_BYTES];
    candidate.encode(
        (&mut primary[..SUPERBLOCK_BYTES])
            .try_into()
            .expect("canonical superblock prefix"),
    );
    let mut header_block = [0; BLOCK_BYTES];
    let mut encoded_header = [0; mrml_storage::VOLUME_HEADER_BYTES];
    header().encode(&mut encoded_header);
    header_block[..encoded_header.len()].copy_from_slice(&encoded_header);
    Ok(ReachableMetadataBackend {
        fail_block,
        header: header_block,
        primary,
        secondary: [0; BLOCK_BYTES],
        root: root_bytes,
        entries: entry_bytes,
        configuration: configuration_metadata,
        configuration_extents,
        authority: authority_metadata,
        authority_extents,
        deployment: deployment_metadata,
        deployment_extents,
        release: release_metadata,
        release_extents,
        allocation,
        object_ids,
    })
}

#[cfg(test)]
fn build_reachable_device(
    root_generation: u64,
    configuration_length: usize,
    configuration_bytes: &[u8; BLOCK_BYTES],
    authority_length: usize,
    authority_bytes: &[u8; BLOCK_BYTES],
    fail_block: Option<u64>,
) -> Result<ReachableMetadataBackend, HostedRecoveryProbeError> {
    let deployment = [0x44; BLOCK_BYTES];
    build_reachable_total_device(
        root_generation,
        configuration_length,
        configuration_bytes,
        authority_length,
        authority_bytes,
        1,
        &deployment,
        &[0x52],
        fail_block,
    )
}

fn recover_reachable_files<'a>(
    service: &'a mut BlockService<1, 1>,
    backend: &'a mut ReachableMetadataBackend,
    boot: InstalledRecoveryBootIdentity,
    volume_scratch: &'a mut [u8],
) -> Result<
    RecoveredInstalledStableTotalSystemSelection<'a, ReachableMetadataBackend, 1, 1, 1, 5>,
    HostedRecoveryProbeError,
> {
    let installed = reacquire_handoff_installed_recovery_device(
        service,
        backend,
        boot,
        principal(),
        volume_scratch,
    )
    .map_err(|_| HostedRecoveryProbeError::InstalledDevice)?;
    let mut primary_read = [0; BLOCK_BYTES];
    let mut secondary_read = [0; BLOCK_BYTES];
    let mut metadata_scratch = [0; BLOCK_BYTES];
    let recovered = recover_serviced_stable_total_system_selection::<_, 1, 1, 16, 4, 1, 5>(
        service,
        backend,
        installed,
        volume_scratch,
        &mut primary_read,
        &mut secondary_read,
        &mut metadata_scratch,
        object(9),
        object(10),
        object(11),
        object(12),
    )
    .map_err(|_| HostedRecoveryProbeError::StableSelection)?;
    if recovered.selected().volume() != VolumeId::new(boot.volume()).unwrap()
        || recovered.selected().root_generation() != boot.root_generation()
    {
        return Err(HostedRecoveryProbeError::RecoveryRootMismatch);
    }
    Ok(recovered)
}

/// Builds one hosted, authenticated recovery transaction and atomically binds
/// its committed persistent policy plus decoded loader override to `release`.
///
/// # Safety
///
/// The caller must use this only as a controlled hosted probe. This function
/// synthesizes the owner-approved checkpoint proof for its private in-memory
/// fixture; it is not an owner-presence or production recovery boundary.
pub unsafe fn recover_total_control_plane<const DOMAINS: usize>(
    handoff: &BootHandoff,
    release_bytes: &[u8],
    expected_release_key: &[u8; 64],
    release_output: &mut [u8],
) -> Result<
    RecoveredDeploymentTotalControlPlane<1, 4, 2, 1, DOMAINS>,
    HostedRecoveryProbeBuildError<()>,
> {
    unsafe {
        recover_total_control_plane_with_domain_policy::<DOMAINS>(
            handoff,
            release_bytes,
            expected_release_key,
            release_output,
            false,
        )
    }
}

/// Builds the same retained hosted recovery owner while requiring the two
/// authenticated release members to bind to distinct policy-owned domains.
/// This is a control-plane prerequisite only; callers must still construct,
/// commit, execute, and retire both backend guests before claiming Total mode.
///
/// # Safety
///
/// The caller must obey the controlled-hosted-fixture restrictions documented
/// by [`recover_total_control_plane`].
pub unsafe fn recover_distinct_total_control_plane(
    handoff: &BootHandoff,
    release_bytes: &[u8],
    expected_release_key: &[u8; 64],
    release_output: &mut [u8],
) -> Result<RecoveredDeploymentTotalControlPlane<1, 4, 2, 1, 2>, HostedRecoveryProbeBuildError<()>>
{
    unsafe {
        recover_total_control_plane_with_domain_policy::<2>(
            handoff,
            release_bytes,
            expected_release_key,
            release_output,
            true,
        )
    }
}

unsafe fn recover_total_control_plane_with_domain_policy<const DOMAINS: usize>(
    handoff: &BootHandoff,
    release_bytes: &[u8],
    expected_release_key: &[u8; 64],
    release_output: &mut [u8],
    distinct_domains: bool,
) -> Result<
    RecoveredDeploymentTotalControlPlane<1, 4, 2, 1, DOMAINS>,
    HostedRecoveryProbeBuildError<()>,
> {
    if DOMAINS == 0 || DOMAINS > 2 {
        return Err(HostedRecoveryProbeError::Admission.into());
    }
    let recovery = handoff
        .recovery_state()
        .ok_or(HostedRecoveryProbeError::MissingRecoveryState)
        .map_err(HostedRecoveryProbeBuildError::Probe)?;
    if recovery.accepted_volume() != Some(volume().bytes())
        || recovery.accepted_root_generation() != ROOT_GENERATION
    {
        return Err(HostedRecoveryProbeBuildError::Probe(
            HostedRecoveryProbeError::RecoveryRootMismatch,
        ));
    }
    let installed = handoff
        .installed_recovery()
        .ok_or(HostedRecoveryProbeError::MissingInstalledIdentity)
        .map_err(HostedRecoveryProbeBuildError::Probe)?;
    if installed.volume() != volume().bytes() || installed.root_generation() != ROOT_GENERATION {
        return Err(HostedRecoveryProbeBuildError::Probe(
            HostedRecoveryProbeError::RecoveryRootMismatch,
        ));
    }

    // Build the deployment evidence before the installed graph so the exact
    // checkpoint and signed release bytes become objects in that graph. The
    // later recovery path is then unable to substitute parallel file states.
    let deployment_root = ObjectId(0x4445_504c_4f59);
    let mut deployment_capabilities = CapabilitySpace::<2>::new();
    let control = deployment_capabilities
        .insert(deployment_root, Rights::CONTROL)
        .map_err(|_| HostedRecoveryProbeError::Deployment)?;
    let inspect = deployment_capabilities
        .insert(deployment_root, Rights::READ)
        .map_err(|_| HostedRecoveryProbeError::Deployment)?;
    let mut deployment_service = DeploymentService::<1>::new(deployment_root)
        .map_err(|_| HostedRecoveryProbeError::Deployment)?;
    let release_object = object(12);
    let candidate = deployment_service
        .stage(
            &deployment_capabilities,
            control,
            GenerationCandidate::from_system_release(
                release_bytes,
                expected_release_key,
                release_object.local(),
                CONFIGURATION_GENERATION,
            )
            .map_err(|_| HostedRecoveryProbeError::Deployment)?,
        )
        .map_err(|_| HostedRecoveryProbeError::Deployment)?;
    let prepared = deployment_service
        .prepare_activation(&deployment_capabilities, control, candidate, None)
        .map_err(|_| HostedRecoveryProbeError::Deployment)?;
    let active = deployment_service
        .commit_activation(&deployment_capabilities, control, prepared)
        .map_err(|_| HostedRecoveryProbeError::Deployment)?;
    let active_release = deployment_service
        .active_release(&deployment_capabilities, inspect)
        .map_err(|_| HostedRecoveryProbeError::Deployment)?
        .ok_or(HostedRecoveryProbeError::Deployment)?;
    let checkpoint_object = object(11);
    let deployment_checkpoint =
        encode_deployment_release_checkpoint(deployment_root, active_release)
            .map_err(|_| HostedRecoveryProbeError::Deployment)?;
    let deployment_state_store = DeploymentStateStore {
        bytes: encode_deployment_recovery_state_with_release(
            1,
            deployment_root,
            active,
            Some(active_release),
            checkpoint_object,
            CONFIGURATION_GENERATION,
        )
        .map_err(|_| HostedRecoveryProbeError::Deployment)?,
    };
    let mut checkpoint_backend = DeploymentFileBackend {
        object: checkpoint_object,
        generation: CONFIGURATION_GENERATION,
        bytes: [0; BLOCK_BYTES],
    };
    checkpoint_backend.bytes[..deployment_checkpoint.len()].copy_from_slice(&deployment_checkpoint);
    let mut release_backend = DeploymentReleaseBackend {
        object: release_object,
        generation: CONFIGURATION_GENERATION,
        bytes: release_bytes,
    };
    let root_object = ObjectId(0x4852_5052_4f42_0001);
    let setting_object = ObjectId(0x4852_5052_4f42_0002);
    let service_object = ObjectId(0x4852_5052_4f42_0003);
    let restart_setting = SettingId::new(1).unwrap();
    let restart_schema = SettingSchema::bytes(
        restart_setting,
        setting_object,
        PERSISTED_RESTART_POLICY_BYTES as u8,
    )
    .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let system =
        IsolationPolicySetting::system(SettingId::new(2).unwrap(), ObjectId(0x4852_5052_4f42_0004))
            .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let component = IsolationPolicySetting::component(
        SettingId::new(3).unwrap(),
        HOSTED_TOTAL_COMPONENT_DOMAIN,
        mrml_kernel::IsolationPlacement::NativeService,
    )
    .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let secondary_component = IsolationPolicySetting::component(
        SettingId::new(4).unwrap(),
        HOSTED_TOTAL_SECONDARY_DOMAIN,
        mrml_kernel::IsolationPlacement::NativeService,
    )
    .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let mut configuration = ConfigurationService::<4, 2>::new(
        root_object,
        &[
            restart_schema,
            system.schema().unwrap(),
            component.schema().unwrap(),
            secondary_component.schema().unwrap(),
        ],
    )
    .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let mut capabilities = CapabilitySpace::<10>::new();
    let root_control = capabilities
        .insert(root_object, Rights::CONTROL)
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let root_read = capabilities
        .insert(root_object, Rights::READ)
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let restart_write = capabilities
        .insert(setting_object, Rights::WRITE)
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let restart_read = capabilities
        .insert(setting_object, Rights::READ)
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let system_write = capabilities
        .insert(system.object(), Rights::WRITE)
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let system_read = capabilities
        .insert(system.object(), Rights::READ)
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let component_write = capabilities
        .insert(component.object(), Rights::WRITE)
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let component_read = capabilities
        .insert(component.object(), Rights::READ)
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let secondary_component_write = capabilities
        .insert(secondary_component.object(), Rights::WRITE)
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let secondary_component_read = capabilities
        .insert(secondary_component.object(), Rights::READ)
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let restart = PersistedRestartPolicy::new(service_object, 3, 5, 20)
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let mut encoded_restart = [0; PERSISTED_RESTART_POLICY_BYTES];
    restart.encode(&mut encoded_restart);
    let mut update = ConfigTransaction::<4>::new(0);
    update
        .push(ConfigUpdate::new(
            restart_setting,
            restart_write,
            ConfigValue::bytes(&encoded_restart)
                .map_err(|_| HostedRecoveryProbeError::Configuration)?,
        ))
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    system
        .stage(&mut update, system_write, OwnerIsolationSelection::Balanced)
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    component
        .stage(
            &mut update,
            component_write,
            OwnerIsolationSelection::Native,
        )
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    secondary_component
        .stage(
            &mut update,
            secondary_component_write,
            OwnerIsolationSelection::Native,
        )
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    configuration
        .commit(&capabilities, root_control, &update)
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;

    let mut configuration_bytes = [0; BLOCK_BYTES];
    let checkpoint = configuration
        .export_checkpoint(&capabilities, root_read, &mut configuration_bytes)
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let configuration_object = object(9);
    let mut configuration_backend = CheckpointBackend {
        object: configuration_object,
        bytes: configuration_bytes,
    };

    let grants = [StorageRecoveryGrant::root(
        principal(),
        configuration_object,
        StorageObjectKind::File,
        StorageRights::READ,
    )];
    let mut authority_bytes = [0; 128];
    let authority_length = encode_authority_checkpoint(
        CHECKPOINT_AUTHORITY_EPOCH,
        volume(),
        ROOT_GENERATION,
        CHECKPOINT_HANDLE_GENERATION,
        &grants,
        &mut authority_bytes,
    )
    .map_err(|_| HostedRecoveryProbeError::AuthorityCheckpoint)?;
    let authority_digest = authority_checkpoint_digest(&authority_bytes[..authority_length])
        .map_err(|_| HostedRecoveryProbeError::AuthorityCheckpoint)?;
    // SAFETY: the public function's safety contract restricts this synthesized
    // approval to the private, controlled hosted fixture described above.
    let owner_approval = unsafe {
        OwnerApprovedAuthorityCheckpoint::new(
            CHECKPOINT_AUTHORITY_EPOCH,
            volume(),
            ROOT_GENERATION,
            CHECKPOINT_HANDLE_GENERATION,
            authority_digest,
        )
    };
    let mut issuer = AuthorityCheckpointProofIssuer::new(owner_approval);
    let authority_object = object(10);
    let mut authority_backend = CheckpointBackend {
        object: authority_object,
        bytes: [0; BLOCK_BYTES],
    };
    authority_backend.bytes[..authority_length]
        .copy_from_slice(&authority_bytes[..authority_length]);
    let mut recovery_device_backend = build_reachable_total_device(
        ROOT_GENERATION,
        checkpoint.length,
        &configuration_backend.bytes,
        authority_length,
        &authority_backend.bytes,
        deployment_checkpoint.len(),
        &checkpoint_backend.bytes,
        release_bytes,
        None,
    )?;
    let mut recovery_block_service = recovery_block_service()?;
    let mut volume_scratch = [0; BLOCK_BYTES];
    let reachable = recover_reachable_files(
        &mut recovery_block_service,
        &mut recovery_device_backend,
        installed,
        &mut volume_scratch,
    )?;
    let selected = reachable.selected();
    let mut bootstrap = StorageAuthorityTable::<1>::new();
    let bootstrap_file = bootstrap
        .insert(
            authority_object,
            StorageObjectKind::File,
            StorageRights::READ,
            principal(),
        )
        .map_err(|_| HostedRecoveryProbeError::AuthorityCheckpoint)?;
    let mut state_store = RecoveryStateStore::new_bound(
        ACCEPTED_AUTHORITY_EPOCH,
        ACCEPTED_HANDLE_GENERATION,
        volume(),
        ROOT_GENERATION,
    );
    let mut boot_store = BootRecoveryAdmission::new(recovery)
        .map_err(|_| HostedRecoveryProbeError::Recovery)?
        .bind(&mut state_store);

    let mut runtime = TaskRuntime::<1, 1>::new(1_000, 1)
        .map_err(|_| HostedRecoveryProbeError::ServicePublication)?;
    let task = runtime
        .create(
            Priority::NORMAL,
            UserContext::new(
                mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
                0x40_0000,
                0x7000_0000,
            )
            .unwrap(),
        )
        .map_err(|_| HostedRecoveryProbeError::ServicePublication)?;
    let mut supervisor = ServiceSupervisor::<1>::new();
    let mut recovered_bytes = [0; BLOCK_BYTES];
    let configuration_validator =
        StableConfigurationRecoveryValidator::<4, 2, _, _, _>::new_selected(
            selected.configuration(),
            0,
            principal(),
            &capabilities,
            root_control,
            restart_read,
            restart_setting,
            service_object,
            &mut recovered_bytes,
            &mut configuration_backend,
        );
    let mut validator =
        StableServiceRecoveryValidator::new(configuration_validator, &supervisor, task);
    let mut authority_scratch = [0; 128];
    let (authorities, prepared_service) =
        recover_selected_validate_and_commit_stable_authorities::<1, 1, 1, _, _, _>(
            selected.authority_checkpoint(),
            &bootstrap,
            bootstrap_file,
            principal(),
            &mut issuer,
            &mut authority_scratch,
            &mut authority_backend,
            &mut boot_store,
            &mut validator,
        )
        .map_err(|_| HostedRecoveryProbeError::Recovery)?;
    drop(boot_store);
    let recovered = prepared_service
        .commit(authorities, &mut supervisor)
        .map_err(|_| HostedRecoveryProbeError::ServicePublication)?;
    if recovered.configuration().revision() != POLICY_GENERATION {
        return Err(HostedRecoveryProbeBuildError::Probe(
            HostedRecoveryProbeError::Configuration,
        ));
    }
    let delivered = BootRecoveryEnvelope::new(
        recovery,
        handoff.installed_recovery(),
        handoff.installed_recovery_sata_route(),
        handoff.isolation_override(),
    )
    .map_err(|_| HostedRecoveryProbeBuildError::Probe(HostedRecoveryProbeError::Admission))?;
    let recovered = recovered
        .bind_delivered_boot(delivered)
        .map_err(|_| HostedRecoveryProbeBuildError::Probe(HostedRecoveryProbeError::Admission))?;

    let mut checkpoint_authority = StorageAuthorityTable::<1>::new();
    let checkpoint_handle = checkpoint_authority
        .insert(
            checkpoint_object,
            StorageObjectKind::File,
            StorageRights::READ,
            principal(),
        )
        .map_err(|_| HostedRecoveryProbeError::Deployment)?;
    let mut release_authority = StorageAuthorityTable::<1>::new();
    let release_handle = release_authority
        .insert(
            release_object,
            StorageObjectKind::File,
            StorageRights::READ,
            principal(),
        )
        .map_err(|_| HostedRecoveryProbeError::Deployment)?;
    let deployment = recover_selected_runtime_assignment::<1, DOMAINS, 2, 1, 1, 1, _, _, _>(
        deployment_root,
        selected,
        &checkpoint_authority,
        checkpoint_handle,
        &release_authority,
        release_handle,
        principal(),
        &deployment_state_store,
        &mut checkpoint_backend,
        &mut release_backend,
        &deployment_capabilities,
        inspect,
        release_output,
        POLICY_GENERATION,
    )
    .map_err(|_| HostedRecoveryProbeError::Deployment)?;
    if deployment.assignment().expected_len() != DOMAINS {
        return Err(HostedRecoveryProbeError::Deployment.into());
    }
    let bindings: [RuntimeDomainPolicyBinding<'_>; DOMAINS] = core::array::from_fn(|index| {
        let (setting, access) = if distinct_domains && index == 1 {
            (secondary_component, secondary_component_read)
        } else {
            (component, component_read)
        };
        RuntimeDomainPolicyBinding::new(
            deployment
                .assignment()
                .package_at(index)
                .expect("complete hosted runtime inventory"),
            setting,
            access,
        )
        .expect("validated hosted component binding")
    });
    let total = recovered
        .build_recovered_deployment_total_control_plane(
            reachable.installed(),
            &capabilities,
            system,
            system_read,
            component,
            component_read,
            deployment,
            &bindings,
        )
        .map_err(|_| HostedRecoveryProbeError::Admission)?;
    if distinct_domains {
        let mut entries = total.installed_admission().release().release().entries();
        let first = entries.next().ok_or(HostedRecoveryProbeError::Admission)?;
        let second = entries.next().ok_or(HostedRecoveryProbeError::Admission)?;
        if entries.next().is_some()
            || first.domain() == second.domain()
            || first.domain() != HOSTED_TOTAL_COMPONENT_DOMAIN
            || second.domain() != HOSTED_TOTAL_SECONDARY_DOMAIN
        {
            return Err(HostedRecoveryProbeError::Admission.into());
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        SelectedStableSystemRecovery, SelectedStableSystemRecoveryError,
        SelectedStableTotalSystemRecovery,
    };

    #[test]
    fn stable_system_selection_requires_distinct_files_from_one_exact_root() {
        let configuration = [0x31; BLOCK_BYTES];
        let authority = [0x41; BLOCK_BYTES];
        let mut current_scratch = [0; BLOCK_BYTES];
        let mut previous_scratch = [0; BLOCK_BYTES];
        let mut current_backend =
            build_reachable_device(14, 1, &configuration, 1, &authority, None).unwrap();
        let mut previous_backend =
            build_reachable_device(13, 1, &configuration, 1, &authority, None).unwrap();
        let mut current_service = recovery_block_service().unwrap();
        let mut previous_service = recovery_block_service().unwrap();
        let current = recover_reachable_files(
            &mut current_service,
            &mut current_backend,
            installed_boot_identity(14).unwrap(),
            &mut current_scratch,
        )
        .unwrap();
        assert_eq!(current.installed().descriptor().id(), recovery_device());
        assert_eq!(
            current.installed().platform_identity().unwrap().transport(),
            PlatformBlockTransport::Hosted
        );
        assert_eq!(current.installed().header().volume(), volume());
        assert_eq!(
            current.installed().active_superblock(),
            header().primary_superblock()
        );
        let previous = recover_reachable_files(
            &mut previous_service,
            &mut previous_backend,
            installed_boot_identity(13).unwrap(),
            &mut previous_scratch,
        )
        .unwrap();
        let selected = current.selected();
        let configuration_selection = selected.configuration();
        assert_eq!(selected.volume(), volume());
        assert_eq!(selected.root_generation(), 14);
        assert!(matches!(
            SelectedStableSystemRecovery::new(configuration_selection, configuration_selection),
            Err(SelectedStableSystemRecoveryError::DuplicateObject)
        ));
        assert!(matches!(
            SelectedStableSystemRecovery::new(
                configuration_selection,
                previous.selected().authority_checkpoint(),
            ),
            Err(SelectedStableSystemRecoveryError::RootMismatch)
        ));
        let deployment_selection = current
            .recovered
            .selected
            .reachable()
            .select_file(object(11))
            .unwrap();
        let release_selection = current
            .recovered
            .selected
            .reachable()
            .select_file(object(12))
            .unwrap();
        let total = SelectedStableTotalSystemRecovery::new(
            configuration_selection,
            selected.authority_checkpoint(),
            deployment_selection,
            release_selection,
        )
        .unwrap();
        assert_eq!(total.volume(), volume());
        assert_eq!(total.root_generation(), 14);
        assert_eq!(total.deployment_checkpoint().object(), object(11));
        assert_eq!(total.system_release().object(), object(12));
        assert!(matches!(
            SelectedStableTotalSystemRecovery::new(
                configuration_selection,
                selected.authority_checkpoint(),
                deployment_selection,
                configuration_selection,
            ),
            Err(SelectedStableSystemRecoveryError::DuplicateObject)
        ));
        assert!(matches!(
            SelectedStableTotalSystemRecovery::new(
                configuration_selection,
                previous.selected().authority_checkpoint(),
                deployment_selection,
                release_selection,
            ),
            Err(SelectedStableSystemRecoveryError::RootMismatch)
        ));
        let mut failed_scratch = [0; BLOCK_BYTES];
        let mut failed_backend = build_reachable_device(
            14,
            1,
            &configuration,
            1,
            &authority,
            Some(header().secondary_superblock()),
        )
        .unwrap();
        let mut failed_service = recovery_block_service().unwrap();
        assert!(
            recover_reachable_files(
                &mut failed_service,
                &mut failed_backend,
                installed_boot_identity(14).unwrap(),
                &mut failed_scratch,
            )
            .is_err()
        );
    }
}
