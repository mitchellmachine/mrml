//! Hosted-only evidence path for recovered Total MicroVM admission.
//!
//! This module deliberately uses the normal configuration checkpoint, exact
//! file-generation, authenticated authority-checkpoint, boot-bound monotonic
//! recovery, dependent validation, service-publication, and active-release
//! binding APIs. Its synthetic memory and file-backed volumes are controlled
//! probe mechanics; they are not owner-presence, TPM, firmware, or physical
//! rollback evidence.

use core::cell::RefCell;

use super::{
    ConfigTransaction, ConfigUpdate, ConfigValue, ConfigurationService, IsolationPolicySetting,
    OwnerIsolationSelection, PERSISTED_RESTART_POLICY_BYTES, PersistedRestartPolicy,
    RecoveredDeploymentTotalControlPlane, RecoveredInstalledStableTotalSystemSelection,
    RuntimeDomainPolicyBinding, SettingId, SettingSchema, StableConfigurationRecoveryValidator,
    StableServiceRecoveryValidator, reacquire_handoff_installed_recovery_device,
    recover_selected_runtime_assignment_shared_backend,
    recover_serviced_stable_total_system_selection,
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
    Priority, Rights, ServiceSupervisor, TaskRuntime, TrustRoot, VerifiedExecutable,
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
const RELEASE_BLOCK_BASE: u64 = 33;
const MAX_HOSTED_SERVICE_BLOCKS: usize = 32;

/// Geometry of the synthetic recovery volume in the hosted runners.
pub const HOSTED_RECOVERY_BLOCK_COUNT: u64 = RELEASE_BLOCK_BASE
    + (MAX_HOSTED_RELEASE_BYTES.div_ceil(BLOCK_BYTES) + 2 * MAX_HOSTED_SERVICE_BLOCKS) as u64;
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
    DiskImage,
    InstalledDevice,
    StableSelection,
    ServiceExecutable,
    ReleaseLayout,
    AllocationLayout,
    AuthorityCheckpoint,
    Recovery,
    ServicePublication,
    Deployment,
    DeploymentRead(
        mrml_deployment::RecoveredRuntimeAssignmentError<
            mrml_storage::BlockVolumeError<mrml_storage::BlockServiceError<()>>,
            mrml_storage::BlockVolumeError<mrml_storage::BlockServiceError<()>>,
            (),
        >,
    ),
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

struct SharedCheckpointReader<'a, B>(&'a RefCell<B>);

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

// SAFETY: all verification and copying are delegated to the same selected
// volume. The two readers access it sequentially and reject overlap.
unsafe impl<B: FileReadBackend> FileReadBackend for SharedCheckpointReader<'_, B> {
    type Error = ();

    fn read_verified_extent(
        &mut self,
        record: ExtentRecord,
        byte_offset: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        self.0
            .try_borrow_mut()
            .map_err(|_| ())?
            .read_verified_extent(record, byte_offset, output)
            .map_err(|_| ())
    }
}

struct ReachableMetadataBackend<'data> {
    fail_block: Option<u64>,
    disk: Option<&'data mut dyn HostedRecoveryImageFile>,
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
    services: [[u8; BLOCK_BYTES]; 2],
    service_extents: [[u8; BLOCK_BYTES]; 2],
    service_data_start: [u64; 2],
    service_data: [&'data [u8]; 2],
    release_data: &'data [u8],
    deployment_data: [u8; BLOCK_BYTES],
    configuration_data: [u8; BLOCK_BYTES],
    authority_data: [u8; BLOCK_BYTES],
}

impl<'disk> ReachableMetadataBackend<'disk> {
    fn install_disk(
        &mut self,
        file: &'disk mut dyn HostedRecoveryImageFile,
    ) -> Result<(), HostedRecoveryProbeError> {
        let error = |_| HostedRecoveryProbeError::DiskImage;
        if file.regular_file_len().map_err(error)? != 0 || self.disk.is_some() {
            return Err(HostedRecoveryProbeError::DiskImage);
        }
        let mut block = [0; BLOCK_BYTES];
        for index in 0..HOSTED_RECOVERY_BLOCK_COUNT {
            if !self.fixture_block(index, &mut block) {
                block.fill(0);
            }
            file.write_at(index * BLOCK_BYTES as u64, &block)
                .map_err(error)?;
        }
        file.sync_all().map_err(error)?;
        self.use_existing_disk(file)
    }

    fn use_existing_disk(
        &mut self,
        file: &'disk mut dyn HostedRecoveryImageFile,
    ) -> Result<(), HostedRecoveryProbeError> {
        if file
            .regular_file_len()
            .map_err(|_| HostedRecoveryProbeError::DiskImage)?
            != HOSTED_RECOVERY_BLOCK_COUNT * BLOCK_BYTES as u64
            || self.disk.is_some()
        {
            return Err(HostedRecoveryProbeError::DiskImage);
        }
        self.disk = Some(file);
        Ok(())
    }

    fn fixture_block(&self, block: u64, output: &mut [u8; BLOCK_BYTES]) -> bool {
        for (base, data) in self
            .service_data_start
            .into_iter()
            .zip(self.service_data)
            .chain(core::iter::once((RELEASE_BLOCK_BASE, self.release_data)))
        {
            if (base..base + data.len().div_ceil(BLOCK_BYTES) as u64).contains(&block) {
                let start = (block - base) as usize * BLOCK_BYTES;
                let end = (start + BLOCK_BYTES).min(data.len());
                let bytes = &data[start..end];
                output.fill(0);
                output[..bytes.len()].copy_from_slice(bytes);
                return true;
            }
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
            22 => &self.services[0],
            23 => &self.service_extents[0],
            24 => &self.services[1],
            25 => &self.service_extents[1],
            30 => &self.configuration_data,
            31 => &self.authority_data,
            32 => &self.deployment_data,
            _ => return false,
        };
        output.copy_from_slice(source);
        true
    }
}

// SAFETY: this read-only probe serves one exact device, bounded to its
// announced geometry. With a disk installed, every read is from that handle;
// I/O errors and short reads never fall back to the generation buffers.
unsafe impl BlockServiceBackend for ReachableMetadataBackend<'_> {
    type Error = ();

    fn read_blocks(
        &mut self,
        device: BlockDeviceId,
        block: u64,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        if device != recovery_device()
            || block >= HOSTED_RECOVERY_BLOCK_COUNT
            || self.fail_block == Some(block)
        {
            return Err(());
        }
        let output: &mut [u8; BLOCK_BYTES] = output.try_into().map_err(|_| ())?;
        if let Some(file) = self.disk.as_mut() {
            return file.read_at(block * BLOCK_BYTES as u64, output);
        }
        self.fixture_block(block, output).then_some(()).ok_or(())
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
    VolumeHeader::new(
        volume(),
        BLOCK_BYTES as u32,
        HOSTED_RECOVERY_BLOCK_COUNT,
        1,
        2,
    )
    .unwrap()
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

fn build_reachable_total_device<'data>(
    root_generation: u64,
    configuration_length: usize,
    configuration_bytes: &[u8; BLOCK_BYTES],
    authority_length: usize,
    authority_bytes: &[u8; BLOCK_BYTES],
    deployment_length: usize,
    deployment_bytes: &[u8; BLOCK_BYTES],
    release_bytes: &'data [u8],
    service_data: [&'data [u8]; 2],
    fail_block: Option<u64>,
) -> Result<ReachableMetadataBackend<'data>, HostedRecoveryProbeError> {
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
    let services = [object(13), object(14)];
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
    DirectoryMetadata::new(header(), root, 2, None, 6, entries_pointer)
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
        DirectoryEntry::new(
            StorageName::new("service-probe").unwrap(),
            services[0],
            StorageObjectKind::File,
            CONFIGURATION_GENERATION,
        )
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
        DirectoryEntry::new(
            StorageName::new("service-secondary").unwrap(),
            services[1],
            StorageObjectKind::File,
            CONFIGURATION_GENERATION,
        )
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
    ];
    let mut entry_bytes = [0; BLOCK_BYTES];
    DirectoryImage::<6>::build(header(), root, 2, entries_pointer, &entries)
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

    let service_blocks = service_data.map(|bytes| bytes.len().div_ceil(BLOCK_BYTES));
    if service_blocks
        .iter()
        .any(|count| !(1..=MAX_HOSTED_SERVICE_BLOCKS).contains(count))
    {
        return Err(HostedRecoveryProbeError::StorageLayout);
    }
    let second_start = header().block_count() - service_blocks[1] as u64;
    let service_data_start = [second_start - service_blocks[0] as u64, second_start];
    let release_block_count = release_bytes.len().div_ceil(BLOCK_BYTES);
    if RELEASE_BLOCK_BASE
        .checked_add(
            u64::try_from(release_block_count)
                .map_err(|_| HostedRecoveryProbeError::ReleaseLayout)?,
        )
        .is_none_or(|end| end > service_data_start[0])
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

    let mut service_metadata = [[0; BLOCK_BYTES]; 2];
    let mut service_extents = [[0; BLOCK_BYTES]; 2];
    let service_metadata_blocks = [22, 24];
    for i in 0..2 {
        let service = services[i];
        let data = service_data[i];
        let count = service_blocks[i];
        let ptr = MetadataPointer::new(service_metadata_blocks[i] + 1, 1).unwrap();
        FileMetadata::new(
            header(),
            service,
            CONFIGURATION_GENERATION,
            data.len() as u64,
            1,
            ptr,
            digest(data),
        )
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?
        .encode(
            (&mut service_metadata[i][..mrml_storage::FILE_METADATA_BYTES])
                .try_into()
                .unwrap(),
        );
        let extent = ExtentRecord::data(
            service,
            CONFIGURATION_GENERATION,
            0,
            count as u32,
            service_data_start[i],
            padded_extent_digest(data, count * BLOCK_BYTES).unwrap(),
        )
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?;
        ExtentImage::<1>::build(
            header(),
            service,
            CONFIGURATION_GENERATION,
            data.len() as u64,
            ptr,
            &[extent],
        )
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?
        .encode(&mut service_extents[i])
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?;
    }

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
            services[0],
            CONFIGURATION_GENERATION,
            22,
            1,
            AllocationKind::ObjectMetadata,
        )
        .unwrap(),
        AllocationRecord::new(
            services[0],
            CONFIGURATION_GENERATION,
            23,
            1,
            AllocationKind::FileExtents,
        )
        .unwrap(),
        AllocationRecord::new(
            services[1],
            CONFIGURATION_GENERATION,
            24,
            1,
            AllocationKind::ObjectMetadata,
        )
        .unwrap(),
        AllocationRecord::new(
            services[1],
            CONFIGURATION_GENERATION,
            25,
            1,
            AllocationKind::FileExtents,
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
        AllocationRecord::new(
            services[0],
            CONFIGURATION_GENERATION,
            service_data_start[0],
            service_blocks[0] as u32,
            AllocationKind::FileData,
        )
        .unwrap(),
        AllocationRecord::new(
            services[1],
            CONFIGURATION_GENERATION,
            service_data_start[1],
            service_blocks[1] as u32,
            AllocationKind::FileData,
        )
        .unwrap(),
    ];
    let mut allocation = [0; BLOCK_BYTES];
    AllocationImage::<24>::build(header(), root_generation, allocation_pointer, &records)
        .map_err(|_| HostedRecoveryProbeError::AllocationLayout)?
        .encode(&mut allocation)
        .map_err(|_| HostedRecoveryProbeError::AllocationLayout)?;
    let mut object_ids = [0; BLOCK_BYTES];
    ObjectIdAllocatorImage::build(header(), root_generation, Some(15), object_ids_pointer)
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
        disk: None,
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
        services: service_metadata,
        service_extents,
        service_data_start,
        service_data,
        release_data: release_bytes,
        deployment_data: *deployment_bytes,
        configuration_data: *configuration_bytes,
        authority_data: *authority_bytes,
    })
}

#[cfg(test)]
fn build_reachable_device<'disk>(
    root_generation: u64,
    configuration_length: usize,
    configuration_bytes: &[u8; BLOCK_BYTES],
    authority_length: usize,
    authority_bytes: &[u8; BLOCK_BYTES],
    fail_block: Option<u64>,
) -> Result<ReachableMetadataBackend<'disk>, HostedRecoveryProbeError> {
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
        [&[0x53], &[0x54]],
        fail_block,
    )
}

fn recover_reachable_files<'a, 'data>(
    service: &'a mut BlockService<1, 1>,
    backend: &'a mut ReachableMetadataBackend<'data>,
    boot: InstalledRecoveryBootIdentity,
    volume_scratch: &'a mut [u8],
) -> Result<
    RecoveredInstalledStableTotalSystemSelection<'a, ReachableMetadataBackend<'data>, 1, 1, 1, 7>,
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
    let recovered = recover_serviced_stable_total_system_selection::<_, 1, 1, 24, 6, 1, 7>(
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
    recover_total_control_plane_with_domain_policy::<DOMAINS>(
        handoff,
        release_bytes,
        expected_release_key,
        release_output,
        false,
        None,
        None,
    )
    .map(|(owner, _)| owner)
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
    recover_total_control_plane_with_domain_policy::<2>(
        handoff,
        release_bytes,
        expected_release_key,
        release_output,
        true,
        None,
        None,
    )
    .map(|(owner, _)| owner)
}

/// One installed service in the controlled probe. The trust root is supplied
/// from outside the recovery volume, not derived from the signed container.
pub struct HostedInstalledService<'src, 'out> {
    pub signed_bytes: &'src [u8],
    pub root: &'src TrustRoot,
    pub output: &'out mut [u8],
}

/// Hosted file operations remain outside the no-std configuration crate.
/// Every successful read or write transfers the entire slice synchronously.
pub trait HostedRecoveryImageFile {
    fn regular_file_len(&self) -> Result<u64, ()>;
    fn read_at(&mut self, offset: u64, bytes: &mut [u8]) -> Result<(), ()>;
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), ()>;
    fn sync_all(&self) -> Result<(), ()>;
}

/// Selects an exact file handle for the hosted probe, never a raw device.
pub enum HostedRecoveryDisk<'file> {
    /// Serialize a fixture into a new, empty regular file and sync it.
    WriteFixture(&'file mut dyn HostedRecoveryImageFile),
    /// Read a previously written image without changing it.
    Existing(&'file mut dyn HostedRecoveryImageFile),
}

/// Recovers the distinct-domain owner and two independently authenticated
/// service executables from the same selected block volume. Release
/// executable-set preflight and live launch remain the caller's responsibility.
/// All block reads use the supplied regular file; no in-memory fallback is allowed.
///
/// # Safety
///
/// Only for the controlled hosted fixture documented by
/// [`recover_total_control_plane`], not an owner approval or boot boundary.
/// Supply a trusted regular-file adapter and keep the image stable throughout
/// recovery; never pass a physical device.
pub unsafe fn recover_distinct_total_control_plane_with_installed_services<'out>(
    handoff: &BootHandoff,
    release_bytes: &[u8],
    expected_release_key: &[u8; 64],
    release_output: &mut [u8],
    services: [HostedInstalledService<'_, 'out>; 2],
    image: HostedRecoveryDisk<'_>,
) -> Result<
    (
        RecoveredDeploymentTotalControlPlane<1, 4, 2, 1, 2>,
        [VerifiedExecutable<'out>; 2],
    ),
    HostedRecoveryProbeBuildError<()>,
> {
    let (owner, executables) = recover_total_control_plane_with_domain_policy::<2>(
        handoff,
        release_bytes,
        expected_release_key,
        release_output,
        true,
        Some(services),
        Some(image),
    )?;
    Ok((
        owner,
        executables.ok_or(HostedRecoveryProbeError::ServiceExecutable)?,
    ))
}

fn recover_total_control_plane_with_domain_policy<'out, const DOMAINS: usize>(
    handoff: &BootHandoff,
    release_bytes: &[u8],
    expected_release_key: &[u8; 64],
    release_output: &mut [u8],
    distinct_domains: bool,
    services: Option<[HostedInstalledService<'_, 'out>; 2]>,
    image: Option<HostedRecoveryDisk<'_>>,
) -> Result<
    (
        RecoveredDeploymentTotalControlPlane<1, 4, 2, 1, DOMAINS>,
        Option<[VerifiedExecutable<'out>; 2]>,
    ),
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
    let mut checkpoint_block = [0; BLOCK_BYTES];
    checkpoint_block[..deployment_checkpoint.len()].copy_from_slice(&deployment_checkpoint);
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
        .stage(
            &mut update,
            system_write,
            OwnerIsolationSelection::TotalMicrovm,
        )
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    component
        .stage(
            &mut update,
            component_write,
            OwnerIsolationSelection::Microvm,
        )
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    secondary_component
        .stage(
            &mut update,
            secondary_component_write,
            OwnerIsolationSelection::Microvm,
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
    let mut authority_block = [0; BLOCK_BYTES];
    authority_block[..authority_length].copy_from_slice(&authority_bytes[..authority_length]);
    let service_data = services
        .as_ref()
        .map_or([&[0x53][..], &[0x54][..]], |pair| {
            [pair[0].signed_bytes, pair[1].signed_bytes]
        });
    let mut recovery_device_backend = build_reachable_total_device(
        ROOT_GENERATION,
        checkpoint.length,
        &configuration_bytes,
        authority_length,
        &authority_block,
        deployment_checkpoint.len(),
        &checkpoint_block,
        release_bytes,
        service_data,
        None,
    )?;
    match image {
        Some(HostedRecoveryDisk::WriteFixture(image)) => {
            recovery_device_backend.install_disk(image)?
        }
        Some(HostedRecoveryDisk::Existing(image)) => {
            recovery_device_backend.use_existing_disk(image)?
        }
        None => {}
    }
    let mut recovery_block_service = recovery_block_service()?;
    let mut volume_scratch = [0; BLOCK_BYTES];
    let mut reachable = recover_reachable_files(
        &mut recovery_block_service,
        &mut recovery_device_backend,
        installed,
        &mut volume_scratch,
    )?;
    let executables = if let Some([first, second]) = services {
        let requests = [
            (object(13), CONFIGURATION_GENERATION),
            (object(14), CONFIGURATION_GENERATION),
        ];
        reachable
            .select_service_files(requests)
            .map_err(|_| HostedRecoveryProbeError::ServiceExecutable)?;
        let mut reads = StorageAuthorityTable::<2>::new();
        let mut recover_service =
            |request: (StorageObjectId, u64), service: HostedInstalledService<'_, 'out>| {
                let handle = reads
                    .insert(
                        request.0,
                        StorageObjectKind::File,
                        StorageRights::READ,
                        principal(),
                    )
                    .map_err(|_| HostedRecoveryProbeError::ServiceExecutable)?;
                reachable
                    .read_verified_service_executable(
                        request,
                        &reads,
                        handle,
                        principal(),
                        service.root,
                        service.output,
                    )
                    .map_err(|_| HostedRecoveryProbeError::ServiceExecutable)
            };
        Some([
            recover_service(requests[0], first)?,
            recover_service(requests[1], second)?,
        ])
    } else {
        None
    };
    let (installed_selection, recovered_blocks) = reachable.into_parts();
    let (selected_root, block_volume) = recovered_blocks.into_parts();
    let selected = selected_root.selected();
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
    let shared_volume = RefCell::new(block_volume);
    let mut configuration_reader = SharedCheckpointReader(&shared_volume);
    let mut authority_reader = SharedCheckpointReader(&shared_volume);
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
            &mut configuration_reader,
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
            &mut authority_reader,
            &mut boot_store,
            &mut validator,
        )
        .map_err(|_| HostedRecoveryProbeError::Recovery)?;
    let mut block_volume = shared_volume.into_inner();
    drop(boot_store);
    let recovered = prepared_service
        .commit(authorities, &capabilities, &mut supervisor, &runtime)
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
    let deployment =
        recover_selected_runtime_assignment_shared_backend::<1, DOMAINS, 2, 1, 1, 1, _, _>(
            deployment_root,
            selected,
            &checkpoint_authority,
            checkpoint_handle,
            &release_authority,
            release_handle,
            principal(),
            &deployment_state_store,
            &mut block_volume,
            &deployment_capabilities,
            inspect,
            release_output,
            POLICY_GENERATION,
        )
        .map_err(HostedRecoveryProbeError::DeploymentRead)?;
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
            installed_selection,
            &capabilities,
            system,
            system_read,
            component,
            component_read,
            deployment,
            &deployment_capabilities,
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
    Ok((total, executables))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use mrml_crypto::Sha3_512;
    use mrml_kernel::{ArtifactKind, SIGNED_ARTIFACT_OVERHEAD_BYTES, TrustRoot};
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};

    fn signed_recovery_service_fixture(marker: u8) -> (std::vec::Vec<u8>, TrustRoot) {
        use mrml_crypto::{
            LAMPORT_PRIVATE_KEY_BYTES, LAMPORT_PUBLIC_KEY_BYTES, LAMPORT_SIGNATURE_BYTES,
            lamport_public_key, lamport_sign,
        };
        use mrml_kernel::{SIGNED_ARTIFACT_HEADER_BYTES, artifact_statement};

        let mut image = [0u8; 1024];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        image[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        image[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        image[0x96..0x98].copy_from_slice(&2u16.to_le_bytes());
        let optional = 0x98;
        image[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        image[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        image[optional + 24..optional + 32]
            .copy_from_slice(&(0xffff_8001_4000_0000u64).to_le_bytes());
        image[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        image[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        image[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        image[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
        image[optional + 70..optional + 72].copy_from_slice(&0x100u16.to_le_bytes());
        let section = optional + 240;
        image[section..section + 5].copy_from_slice(b".text");
        image[section + 8..section + 12].copy_from_slice(&9u32.to_le_bytes());
        image[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        image[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        image[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        image[section + 36..section + 40].copy_from_slice(&0x6000_0000u32.to_le_bytes());
        // Two inert marker writes to the hosted test adapter, then halt.
        image[0x200..0x209].copy_from_slice(&[
            0xb0,
            marker,
            0xe6,
            0xe9,
            0xb0,
            marker + 2,
            0xe6,
            0xe9,
            0xf4,
        ]);

        let private = std::vec![marker; LAMPORT_PRIVATE_KEY_BYTES];
        let mut public = std::vec![0; LAMPORT_PUBLIC_KEY_BYTES];
        let mut signature = std::vec![0; LAMPORT_SIGNATURE_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        let root = TrustRoot::new(ArtifactKind::ServiceImage, Sha3_512::digest(&public), 1);
        let digest = Sha3_512::digest(&image);
        let statement =
            artifact_statement(ArtifactKind::ServiceImage, 1, image.len() as u64, digest);
        lamport_sign(&private, &statement, &mut signature).unwrap();
        let mut signed = std::vec![0; SIGNED_ARTIFACT_OVERHEAD_BYTES + image.len()];
        signed[..16].copy_from_slice(b"MRML-SIGNED-v1\0\0");
        signed[16] = ArtifactKind::ServiceImage as u8;
        signed[24..32].copy_from_slice(&1u64.to_le_bytes());
        signed[32..40].copy_from_slice(&(image.len() as u64).to_le_bytes());
        signed[40..104].copy_from_slice(&digest);
        let signature_at = SIGNED_ARTIFACT_HEADER_BYTES + public.len();
        signed[SIGNED_ARTIFACT_HEADER_BYTES..signature_at].copy_from_slice(&public);
        signed[signature_at..SIGNED_ARTIFACT_OVERHEAD_BYTES].copy_from_slice(&signature);
        signed[SIGNED_ARTIFACT_OVERHEAD_BYTES..].copy_from_slice(&image);
        (signed, root)
    }

    impl HostedRecoveryImageFile for File {
        fn regular_file_len(&self) -> Result<u64, ()> {
            let metadata = self.metadata().map_err(|_| ())?;
            metadata.is_file().then_some(metadata.len()).ok_or(())
        }

        fn read_at(&mut self, offset: u64, bytes: &mut [u8]) -> Result<(), ()> {
            self.seek(SeekFrom::Start(offset)).map_err(|_| ())?;
            self.read_exact(bytes).map_err(|_| ())
        }

        fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), ()> {
            self.seek(SeekFrom::Start(offset)).map_err(|_| ())?;
            self.write_all(bytes).map_err(|_| ())
        }

        fn sync_all(&self) -> Result<(), ()> {
            File::sync_all(self).map_err(|_| ())
        }
    }

    #[test]
    fn installed_disk_reads_fail_closed_when_service_blocks_change_or_disappear() {
        // Keep the original file object selected, even when another handle
        // changes or truncates it. Never recover from the pristine seed bytes.
        struct ImagePath(std::path::PathBuf);
        impl Drop for ImagePath {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let (mut image, _path) = (0..100)
            .find_map(|serial| {
                let path = std::env::temp_dir().join(std::format!(
                    "mrml-config-blocks-{}-{serial}.img",
                    std::process::id()
                ));
                match File::options()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)
                {
                    Ok(image) => Some((image, ImagePath(path))),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => panic!("could not create probe image: {error}"),
                }
            })
            .expect("no unused probe image path");
        let mut other = image.try_clone().unwrap();
        let data = [0x42; BLOCK_BYTES];
        let mut backend = build_reachable_device(14, 1, &data, 1, &data, None).unwrap();
        let offset = backend.service_data_start[0] * BLOCK_BYTES as u64;
        backend.install_disk(&mut image).unwrap();
        assert_eq!(
            other.metadata().unwrap().len(),
            HOSTED_RECOVERY_BLOCK_COUNT * BLOCK_BYTES as u64
        );

        let mut scratch = [0; BLOCK_BYTES];
        let mut block = recovery_block_service().unwrap();
        let boot = installed_boot_identity(14).unwrap();
        let mut selected =
            recover_reachable_files(&mut block, &mut backend, boot, &mut scratch).unwrap();
        let request = (object(13), CONFIGURATION_GENERATION);
        let mut table = StorageAuthorityTable::<1>::new();
        let handle = table
            .insert(
                request.0,
                StorageObjectKind::File,
                StorageRights::READ,
                principal(),
            )
            .unwrap();
        let mut out = [0];
        assert_eq!(
            selected
                .read_service_file(request, &table, handle, principal(), 0, &mut out)
                .unwrap(),
            1
        );
        assert_eq!(out, [0x53]);

        other.seek(SeekFrom::Start(offset)).unwrap();
        other.write_all(&[0xa5]).unwrap();
        other.sync_all().unwrap();
        assert!(matches!(
            selected.read_service_file(request, &table, handle, principal(), 0, &mut out),
            Err(crate::InstalledServiceFileReadError::Read(
                mrml_storage::FileReadError::Backend(
                    mrml_storage::BlockVolumeError::DigestMismatch
                )
            ))
        ));
        other.set_len(offset).unwrap();
        assert!(matches!(
            selected.read_service_file(request, &table, handle, principal(), 0, &mut out),
            Err(crate::InstalledServiceFileReadError::Read(
                mrml_storage::FileReadError::Backend(mrml_storage::BlockVolumeError::Device(
                    mrml_storage::BlockServiceError::Backend(())
                ))
            ))
        ));
        drop(selected);
        backend.disk = None;
        assert_eq!(
            backend.use_existing_disk(&mut other),
            Err(HostedRecoveryProbeError::DiskImage)
        );
    }

    #[test]
    fn installed_service_reader_verifies_the_exact_signed_executable() {
        use crate::InstalledServiceExecutableError as Error;
        let (signed, key) = signed_recovery_service_fixture(0x71);
        let data = [0x42; BLOCK_BYTES];
        let mut backend = build_reachable_total_device(
            14,
            1,
            &data,
            1,
            &data,
            1,
            &data,
            &[0x52],
            [&signed, &[0x54]],
            None,
        )
        .unwrap();
        let mut scratch = [0; BLOCK_BYTES];
        let mut block = recovery_block_service().unwrap();
        let mut recovered = recover_reachable_files(
            &mut block,
            &mut backend,
            installed_boot_identity(14).unwrap(),
            &mut scratch,
        )
        .unwrap();
        let mut table = StorageAuthorityTable::<2>::new();
        let requested = (object(13), CONFIGURATION_GENERATION);
        let handle = table
            .insert(
                requested.0,
                StorageObjectKind::File,
                StorageRights::READ,
                principal(),
            )
            .unwrap();
        let wrong = table
            .insert(
                object(12),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(),
            )
            .unwrap();
        let mut buffer = std::vec![0xff; signed.len() + 1];
        assert!(matches!(
            recovered.read_verified_service_executable(
                requested,
                &table,
                handle,
                principal(),
                &key,
                &mut buffer[..signed.len() - 1]
            ),
            Err(Error::BufferTooSmall)
        ));
        assert!(matches!(
            recovered.read_verified_service_executable(
                requested,
                &table,
                wrong,
                principal(),
                &key,
                &mut buffer
            ),
            Err(Error::File(crate::InstalledServiceFileReadError::Read(
                mrml_storage::FileReadError::WrongFile
            )))
        ));
        let wrong_key = TrustRoot::new(ArtifactKind::ServiceImage, [0x20; 64], 1);
        assert!(matches!(
            recovered.read_verified_service_executable(
                requested,
                &table,
                handle,
                principal(),
                &wrong_key,
                &mut buffer
            ),
            Err(Error::Executable(
                mrml_kernel::ExecutableArtifactError::Signature(
                    mrml_kernel::ArtifactError::UntrustedPublicKey
                )
            ))
        ));
        let newer_floor = TrustRoot::new(
            ArtifactKind::ServiceImage,
            Sha3_512::digest(
                &signed[mrml_kernel::SIGNED_ARTIFACT_HEADER_BYTES
                    ..mrml_kernel::SIGNED_ARTIFACT_HEADER_BYTES
                        + mrml_crypto::LAMPORT_PUBLIC_KEY_BYTES],
            ),
            2,
        );
        assert!(matches!(
            recovered.read_verified_service_executable(
                requested,
                &table,
                handle,
                principal(),
                &newer_floor,
                &mut buffer,
            ),
            Err(Error::Executable(
                mrml_kernel::ExecutableArtifactError::Signature(
                    mrml_kernel::ArtifactError::RollbackDetected
                )
            ))
        ));
        let executable = recovered
            .read_verified_service_executable(
                requested,
                &table,
                handle,
                principal(),
                &key,
                &mut buffer,
            )
            .unwrap();
        assert_eq!(executable.artifact().kind(), ArtifactKind::ServiceImage);
        assert_eq!(executable.artifact().version(), 1);
        assert_eq!(
            *executable.artifact().digest(),
            Sha3_512::digest(&signed[SIGNED_ARTIFACT_OVERHEAD_BYTES..])
        );
        assert_eq!(&buffer[..signed.len()], signed.as_slice());
        assert_eq!(buffer[signed.len()], 0xff);
    }
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
        let mut current = recover_reachable_files(
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
        // A separately recovered graph with the same volume and generation
        // cannot contribute checkpoint files to this selection.
        let mut clone_scratch = [0; BLOCK_BYTES];
        let mut clone_backend =
            build_reachable_device(14, 1, &configuration, 1, &authority, None).unwrap();
        let mut clone_service = recovery_block_service().unwrap();
        let cloned = recover_reachable_files(
            &mut clone_service,
            &mut clone_backend,
            installed_boot_identity(14).unwrap(),
            &mut clone_scratch,
        )
        .unwrap();
        let selected = current.selected();
        let configuration_selection = selected.configuration();
        let cloned_selection = cloned.selected();
        assert_eq!(selected.volume(), cloned_selection.volume());
        assert_eq!(
            selected.root_generation(),
            cloned_selection.root_generation()
        );
        assert!(
            !configuration_selection.same_recovered_root(&cloned_selection.authority_checkpoint())
        );
        assert!(matches!(
            SelectedStableSystemRecovery::new(
                configuration_selection,
                cloned_selection.authority_checkpoint(),
            ),
            Err(SelectedStableSystemRecoveryError::RootMismatch)
        ));
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
        use crate::InstalledServiceFileSelectionError as ServiceError;
        let request = (object(13), CONFIGURATION_GENERATION);
        let [file] = current.select_service_files([request]).unwrap();
        assert_eq!(file.object(), object(13));
        assert_eq!(file.generation(), CONFIGURATION_GENERATION);
        assert!(file.same_recovered_root(&total.system_release()));
        assert!(matches!(
            current.select_service_files([]),
            Err(ServiceError::Empty)
        ));
        assert!(matches!(
            current.select_service_files([request, request]),
            Err(ServiceError::DuplicateFile)
        ));
        assert!(matches!(
            current.select_service_files([request, (object(15), CONFIGURATION_GENERATION)]),
            Err(ServiceError::MissingFile)
        ));
        assert!(matches!(
            current.select_service_files([(object(13), CONFIGURATION_GENERATION + 1)]),
            Err(ServiceError::StaleFileGeneration)
        ));
        for id in 9..=12 {
            assert!(matches!(
                current.select_service_files([(object(id), CONFIGURATION_GENERATION)]),
                Err(ServiceError::ControlFile)
            ));
        }
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
        assert!(matches!(
            SelectedStableTotalSystemRecovery::new(
                configuration_selection,
                selected.authority_checkpoint(),
                deployment_selection,
                cloned_selection.system_release(),
            ),
            Err(SelectedStableSystemRecoveryError::RootMismatch)
        ));
        use crate::InstalledServiceFileReadError;
        let mut file_authority = StorageAuthorityTable::<2>::new();
        let handle = file_authority
            .insert(
                object(13),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(),
            )
            .unwrap();
        let wrong_file = file_authority
            .insert(
                object(12),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(),
            )
            .unwrap();
        let mut bytes = [0xffu8; 1];
        assert!(matches!(
            current.read_service_file(
                request,
                &file_authority,
                wrong_file,
                principal(),
                0,
                &mut bytes
            ),
            Err(InstalledServiceFileReadError::Read(
                mrml_storage::FileReadError::WrongFile
            ))
        ));
        assert_eq!(bytes, [0xff]);
        assert_eq!(
            current
                .read_service_file(request, &file_authority, handle, principal(), 0, &mut bytes)
                .unwrap(),
            1
        );
        assert_eq!(bytes, [0x53]);
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
