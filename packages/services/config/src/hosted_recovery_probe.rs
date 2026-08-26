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
    OwnerIsolationSelection, PersistedRestartPolicy, RecoveredTotalAdmission,
    RecoveredTotalAdmissionBuildError, SettingId, SettingSchema,
    StableConfigurationRecoveryValidator, StableServiceRecoveryValidator,
    PERSISTED_RESTART_POLICY_BYTES,
};
use mrml_crypto::Sha3_256;
use mrml_kernel::arch::x86_64::UserContext;
use mrml_kernel::{
    ActivatedReleaseTotalMicrovmInventory, BootHandoff, CapabilitySpace, ObjectId, Priority,
    Rights, ServiceSupervisor, TaskRuntime,
};
use mrml_storage::{
    authority_checkpoint_digest, encode_authority_checkpoint, recover_reachable_state,
    recover_selected_validate_and_commit_stable_authorities, AllocationImage, AllocationKind,
    AllocationRecord, AuthorityCheckpointProofIssuer, AuthorityRecoveryStateStore,
    BootRecoveryAdmission, DirectoryEntry, DirectoryImage, DirectoryMetadata, ExtentImage,
    ExtentRecord, FileMetadata, FileReadBackend, MetadataPointer, ObjectIdAllocatorImage,
    OwnerApprovedAuthorityCheckpoint, RecoveredReachableState, RecoveryMetadataBackend,
    StorageAuthorityTable, StorageName, StorageObjectId, StorageObjectKind, StoragePrincipal,
    StorageRecoveryGrant, StorageRights, Superblock, VolumeHeader, VolumeId,
    AUTHORITY_RECOVERY_STATE_BYTES, SUPERBLOCK_BYTES,
};

const BLOCK_BYTES: usize = 4096;
const CONFIGURATION_GENERATION: u64 = 2;
const ROOT_GENERATION: u64 = 14;
const POLICY_GENERATION: u64 = 1;
const ACCEPTED_AUTHORITY_EPOCH: u64 = 8;
const ACCEPTED_HANDLE_GENERATION: u32 = 1;
const CHECKPOINT_AUTHORITY_EPOCH: u64 = 9;
const CHECKPOINT_HANDLE_GENERATION: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedRecoveryProbeError {
    MissingRecoveryState,
    RecoveryRootMismatch,
    Configuration,
    StorageLayout,
    AuthorityCheckpoint,
    Recovery,
    ServicePublication,
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
    root: [u8; BLOCK_BYTES],
    entries: [u8; BLOCK_BYTES],
    configuration: [u8; BLOCK_BYTES],
    configuration_extents: [u8; BLOCK_BYTES],
    authority: [u8; BLOCK_BYTES],
    authority_extents: [u8; BLOCK_BYTES],
    allocation: [u8; BLOCK_BYTES],
    object_ids: [u8; BLOCK_BYTES],
}

unsafe impl RecoveryMetadataBackend for ReachableMetadataBackend {
    type Error = ();

    fn read_metadata(
        &mut self,
        pointer: MetadataPointer,
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        let source = match pointer.block() {
            10 => &self.root,
            11 => &self.entries,
            12 => &self.configuration,
            13 => &self.configuration_extents,
            14 => &self.authority,
            15 => &self.authority_extents,
            20 => &self.allocation,
            21 => &self.object_ids,
            _ => return Err(()),
        };
        if pointer.blocks() != 1 || output.len() != source.len() {
            return Err(());
        }
        output.copy_from_slice(source);
        Ok(())
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

fn recover_reachable_files(
    configuration_length: usize,
    configuration_bytes: &[u8; BLOCK_BYTES],
    authority_length: usize,
    authority_bytes: &[u8; BLOCK_BYTES],
) -> Result<RecoveredReachableState<1, 3>, HostedRecoveryProbeError> {
    let root = object(1);
    let configuration = object(9);
    let authority = object(10);
    let root_pointer = MetadataPointer::new(10, 1).unwrap();
    let entries_pointer = MetadataPointer::new(11, 1).unwrap();
    let configuration_extents_pointer = MetadataPointer::new(13, 1).unwrap();
    let authority_extents_pointer = MetadataPointer::new(15, 1).unwrap();
    let allocation_pointer = MetadataPointer::new(20, 1).unwrap();
    let object_ids_pointer = MetadataPointer::new(21, 1).unwrap();
    let candidate = Superblock::new(
        header(),
        ROOT_GENERATION,
        ROOT_GENERATION - 1,
        root,
        root_pointer,
        allocation_pointer,
    )
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)?;

    let mut root_bytes = [0; BLOCK_BYTES];
    DirectoryMetadata::new(header(), root, 2, None, 2, entries_pointer)
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
    ];
    let mut entry_bytes = [0; BLOCK_BYTES];
    DirectoryImage::<2>::build(header(), root, 2, entries_pointer, &entries)
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
            root,
            ROOT_GENERATION,
            20,
            1,
            AllocationKind::AllocationMetadata,
        )
        .unwrap(),
        AllocationRecord::new(
            root,
            ROOT_GENERATION,
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
    ];
    let mut allocation = [0; BLOCK_BYTES];
    AllocationImage::<10>::build(header(), ROOT_GENERATION, allocation_pointer, &records)
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?
        .encode(&mut allocation)
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?;
    let mut object_ids = [0; BLOCK_BYTES];
    ObjectIdAllocatorImage::build(header(), ROOT_GENERATION, Some(11), object_ids_pointer)
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?
        .encode(&mut object_ids)
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?;

    let backend = ReachableMetadataBackend {
        root: root_bytes,
        entries: entry_bytes,
        configuration: configuration_metadata,
        configuration_extents,
        authority: authority_metadata,
        authority_extents,
        allocation,
        object_ids,
    };
    let mut primary = [0; SUPERBLOCK_BYTES];
    candidate.encode(&mut primary);
    let mut scratch = [0; BLOCK_BYTES];
    recover_reachable_state::<_, 10, 2, 1, 3>(
        header(),
        &primary,
        &[0; SUPERBLOCK_BYTES],
        backend,
        &mut scratch,
    )
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)
}

/// Builds one hosted, authenticated recovery transaction and atomically binds
/// its committed persistent policy plus decoded loader override to `release`.
///
/// # Safety
///
/// The caller must use this only as a controlled hosted probe. This function
/// synthesizes the owner-approved checkpoint proof for its private in-memory
/// fixture; it is not an owner-presence or production recovery boundary.
pub unsafe fn recover_total_admission_with<const DOMAINS: usize, F, E>(
    handoff: &BootHandoff,
    build_release: F,
) -> Result<RecoveredTotalAdmission<DOMAINS>, HostedRecoveryProbeBuildError<E>>
where
    F: FnOnce(u64) -> Result<ActivatedReleaseTotalMicrovmInventory<DOMAINS>, E>,
{
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
        ObjectId(0x4852_5052_4f42_0005),
        mrml_kernel::IsolationPlacement::NativeService,
    )
    .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let mut configuration = ConfigurationService::<3, 2>::new(
        root_object,
        &[
            restart_schema,
            system.schema().unwrap(),
            component.schema().unwrap(),
        ],
    )
    .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let mut capabilities = CapabilitySpace::<4>::new();
    let root = capabilities
        .insert(root_object, Rights::CONTROL.union(Rights::READ))
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let restart_access = capabilities
        .insert(setting_object, Rights::READ.union(Rights::WRITE))
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let system_access = capabilities
        .insert(system.object(), Rights::READ.union(Rights::WRITE))
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let component_access = capabilities
        .insert(component.object(), Rights::READ.union(Rights::WRITE))
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let restart = PersistedRestartPolicy::new(service_object, 3, 5, 20)
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    let mut encoded_restart = [0; PERSISTED_RESTART_POLICY_BYTES];
    restart.encode(&mut encoded_restart);
    let mut update = ConfigTransaction::<3>::new(0);
    update
        .push(ConfigUpdate::new(
            restart_setting,
            restart_access,
            ConfigValue::bytes(&encoded_restart)
                .map_err(|_| HostedRecoveryProbeError::Configuration)?,
        ))
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    system
        .stage(
            &mut update,
            system_access,
            OwnerIsolationSelection::Balanced,
        )
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    component
        .stage(
            &mut update,
            component_access,
            OwnerIsolationSelection::Native,
        )
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;
    configuration
        .commit(&capabilities, root, &update)
        .map_err(|_| HostedRecoveryProbeError::Configuration)?;

    let mut configuration_bytes = [0; BLOCK_BYTES];
    let checkpoint = configuration
        .export_checkpoint(&capabilities, root, &mut configuration_bytes)
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
    let reachable = recover_reachable_files(
        checkpoint.length,
        &configuration_backend.bytes,
        authority_length,
        &authority_backend.bytes,
    )?;
    let configuration_selection = reachable
        .select_file(configuration_object)
        .ok_or(HostedRecoveryProbeError::StorageLayout)?;
    let authority_selection = reachable
        .select_file(authority_object)
        .ok_or(HostedRecoveryProbeError::StorageLayout)?;
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
        StableConfigurationRecoveryValidator::<3, 2, _, _, _>::new_selected(
            configuration_selection,
            0,
            principal(),
            &capabilities,
            root,
            restart_access,
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
            authority_selection,
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
        return Err(HostedRecoveryProbeError::Configuration.into());
    }
    match recovered.build_total_boot_admission(
        &capabilities,
        system,
        system_access,
        component,
        component_access,
        handoff,
        build_release,
    ) {
        Ok(total) => Ok(total),
        Err(RecoveredTotalAdmissionBuildError::Policy(_)) => {
            Err(HostedRecoveryProbeError::Admission.into())
        }
        Err(RecoveredTotalAdmissionBuildError::ReleaseBuilder(error)) => {
            Err(HostedRecoveryProbeBuildError::ReleaseBuilder(error))
        }
    }
}
