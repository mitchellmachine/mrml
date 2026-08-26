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
    RecoveredTotalAdmission, SettingId, SettingSchema, StableConfigurationRecoveryValidator,
    StableServiceRecoveryValidator,
};
use mrml_crypto::Sha3_256;
use mrml_kernel::arch::x86_64::UserContext;
use mrml_kernel::{
    ActivatedReleaseTotalMicrovmInventory, BootHandoff, CapabilitySpace, ObjectId, Priority,
    Rights, ServiceSupervisor, TaskRuntime,
};
use mrml_storage::{
    AUTHORITY_RECOVERY_STATE_BYTES, AuthorityCheckpointProofIssuer, AuthorityRecoveryStateStore,
    BootRecoveryAdmission, ExtentMap, ExtentRecord, FileReadBackend, FileState,
    OwnerApprovedAuthorityCheckpoint, StorageAuthorityTable, StorageObjectId, StorageObjectKind,
    StoragePrincipal, StorageRecoveryGrant, StorageRights, VolumeHeader, VolumeId,
    authority_checkpoint_digest, encode_authority_checkpoint,
    recover_validate_and_commit_stable_authorities,
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
    UnsupportedBoundRecoveryRoot,
    Configuration,
    StorageLayout,
    AuthorityCheckpoint,
    Recovery,
    ServicePublication,
    Admission,
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

struct RecoveryStateStore {
    bytes: [u8; AUTHORITY_RECOVERY_STATE_BYTES],
}

impl RecoveryStateStore {
    fn new(epoch: u64, handle_generation: u32) -> Self {
        let mut bytes = [0; AUTHORITY_RECOVERY_STATE_BYTES];
        bytes[..16].copy_from_slice(b"MRML-AUTHSTATE1\0");
        bytes[16..24].copy_from_slice(&epoch.to_le_bytes());
        bytes[24..28].copy_from_slice(&handle_generation.to_le_bytes());
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

fn checkpoint_file(
    object: StorageObjectId,
    length: usize,
    bytes: &[u8; BLOCK_BYTES],
) -> Result<FileState<1>, HostedRecoveryProbeError> {
    let extent = ExtentRecord::data(object, CONFIGURATION_GENERATION, 0, 1, 11, digest(bytes))
        .map_err(|_| HostedRecoveryProbeError::StorageLayout)?;
    let extents = ExtentMap::build(
        header(),
        object,
        CONFIGURATION_GENERATION,
        u64::try_from(length).map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
        &[extent],
    )
    .map_err(|_| HostedRecoveryProbeError::StorageLayout)?;
    FileState::new(
        object,
        CONFIGURATION_GENERATION,
        u64::try_from(length).map_err(|_| HostedRecoveryProbeError::StorageLayout)?,
        extents,
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
pub unsafe fn recover_total_admission<const DOMAINS: usize>(
    handoff: &BootHandoff,
    release: ActivatedReleaseTotalMicrovmInventory<DOMAINS>,
) -> Result<RecoveredTotalAdmission<DOMAINS>, HostedRecoveryProbeError> {
    let recovery = handoff
        .recovery_state()
        .ok_or(HostedRecoveryProbeError::MissingRecoveryState)?;
    if recovery.accepted_volume().is_some() || recovery.accepted_root_generation() != 0 {
        return Err(HostedRecoveryProbeError::UnsupportedBoundRecoveryRoot);
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
    let configuration_file = checkpoint_file(
        configuration_object,
        checkpoint.length,
        &configuration_bytes,
    )?;
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
    let authority_file =
        checkpoint_file(authority_object, authority_length, &authority_backend.bytes)?;
    let mut bootstrap = StorageAuthorityTable::<1>::new();
    let bootstrap_file = bootstrap
        .insert(
            authority_object,
            StorageObjectKind::File,
            StorageRights::READ,
            principal(),
        )
        .map_err(|_| HostedRecoveryProbeError::AuthorityCheckpoint)?;
    let mut state_store =
        RecoveryStateStore::new(ACCEPTED_AUTHORITY_EPOCH, ACCEPTED_HANDLE_GENERATION);
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
    let configuration_validator = StableConfigurationRecoveryValidator::<3, 2, _, _, _>::new(
        &configuration_file,
        0,
        principal(),
        CONFIGURATION_GENERATION,
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
        recover_validate_and_commit_stable_authorities::<1, 1, 1, _, _, _>(
            &authority_file,
            &bootstrap,
            bootstrap_file,
            principal(),
            CONFIGURATION_GENERATION,
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
        return Err(HostedRecoveryProbeError::Configuration);
    }
    recovered
        .bind_total_boot_admission(
            &capabilities,
            system,
            system_access,
            component,
            component_access,
            handoff,
            release,
        )
        .map_err(|_| HostedRecoveryProbeError::Admission)
}
