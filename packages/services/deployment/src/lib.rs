#![no_std]

//! Bounded SystemGeneration candidate and activation control plane.
//!
//! Generation numbers, digests, and storage identities are data. Only an exact
//! live capability for the service root authorizes staging, activation, or
//! inspection. Activation is a two-phase, one-use transaction; stale tokens
//! never select or resurrect a generation.

use core::array;

use mrml_crypto::Sha3_256;
use mrml_kernel::{
    ActivatedReleaseTotalMicrovmInventory, Capability, CapabilitySpace, ObjectId,
    ReleaseInventoryError, Rights, RuntimeDomainAssignmentPlan,
};
use mrml_package_format::{
    ActivatedSystemGeneration, ActivatedSystemGenerationError, ActivatedSystemRelease,
    InterfaceCatalogError, InterfaceCatalogView, MAX_SYSTEM_RELEASE_BYTES,
    SystemGenerationDecodeError, SystemGenerationView, SystemReleaseError, SystemReleaseIdentity,
    parse_system_release,
};
use mrml_storage::{
    ExtentMap, FileMetadata, FileReadBackend, FileReadError, FileState, FileWriteBackend,
    FileWriteCommitError, FileWriteError, MAX_FILE_READ_BYTES, MetadataPointer, PreparedFileWrite,
    StorageAuthorityTable, StorageHandle, StoragePrincipal, StorageTransaction, TransactionError,
    TransactionReceipt,
};

pub const DEPLOYMENT_CHECKPOINT_BYTES: usize = 424;
pub const DEPLOYMENT_RECOVERY_STATE_BYTES: usize = 256;
const LEGACY_DEPLOYMENT_CHECKPOINT_BYTES: usize = 224;
const LEGACY_DEPLOYMENT_CHECKPOINT_MAGIC: [u8; 8] = *b"MRMLDA2\0";
const LEGACY_DEPLOYMENT_CHECKPOINT_VERSION: u16 = 2;
const DEPLOYMENT_CHECKPOINT_MAGIC: [u8; 8] = *b"MRMLDA3\0";
const DEPLOYMENT_CHECKPOINT_VERSION: u16 = 3;
const DEPLOYMENT_RECOVERY_STATE_MAGIC: [u8; 16] = *b"MRML-DEPLSTATE2\0";

/// A capability-derived assignment transaction bound to the activated release
/// observed at preparation. Sealing rechecks both the exact inspection handle
/// and that same active release against the live deployment service.
pub struct PreparedRuntimeAssignment<'a, const DOMAINS: usize> {
    assignment: RuntimeDomainAssignmentPlan<'a, DOMAINS>,
    inspect: Capability,
    active: ActivatedSystemRelease,
}

impl<'a, const DOMAINS: usize> PreparedRuntimeAssignment<'a, DOMAINS> {
    pub const fn assignment(&self) -> &RuntimeDomainAssignmentPlan<'a, DOMAINS> {
        &self.assignment
    }

    pub fn assignment_mut(&mut self) -> &mut RuntimeDomainAssignmentPlan<'a, DOMAINS> {
        &mut self.assignment
    }

    pub fn seal<const CANDIDATES: usize, const CAPS: usize>(
        self,
        service: &DeploymentService<CANDIDATES>,
        capabilities: &CapabilitySpace<CAPS>,
    ) -> Result<ActivatedReleaseTotalMicrovmInventory<DOMAINS>, RuntimeAssignmentSealError> {
        service
            .authorize(capabilities, self.inspect, Rights::READ)
            .map_err(RuntimeAssignmentSealError::Deployment)?;
        if service.active_release != Some(self.active) {
            return Err(RuntimeAssignmentSealError::Deployment(
                DeploymentError::StaleActiveGeneration,
            ));
        }
        self.assignment
            .seal()
            .map_err(RuntimeAssignmentSealError::Release)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAssignmentSealError {
    Deployment(DeploymentError),
    Release(ReleaseInventoryError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationCandidate {
    generation: u64,
    generation_digest: [u8; 64],
    interface_catalog_digest: [u8; 64],
    source_object: u64,
    source_generation: u64,
    release_identity: Option<SystemReleaseIdentity>,
}

impl GenerationCandidate {
    pub const fn new(
        generation: u64,
        generation_digest: [u8; 64],
        interface_catalog_digest: [u8; 64],
        source_object: u64,
        source_generation: u64,
    ) -> Result<Self, DeploymentError> {
        if generation == 0 || source_generation == 0 {
            return Err(DeploymentError::InvalidGeneration);
        }
        if source_object == 0 {
            return Err(DeploymentError::InvalidSource);
        }
        if all_zero(&generation_digest) || all_zero(&interface_catalog_digest) {
            return Err(DeploymentError::InvalidDigest);
        }
        Ok(Self {
            generation,
            generation_digest,
            interface_catalog_digest,
            source_object,
            source_generation,
            release_identity: None,
        })
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn release_identity(self) -> Option<SystemReleaseIdentity> {
        self.release_identity
    }

    /// Constructs a candidate only from the complete canonical runtime records
    /// that recovery and component resolution will later consume. Callers
    /// cannot supply detached digests or reuse one generation number for
    /// different catalog bytes through this path.
    pub fn from_canonical_records(
        generation_bytes: &[u8],
        interface_catalog_bytes: &[u8],
        source_object: u64,
        source_generation: u64,
    ) -> Result<Self, DeploymentError> {
        let generation = SystemGenerationView::decode(generation_bytes)
            .map_err(DeploymentError::InvalidGenerationRecord)?;
        let catalog = InterfaceCatalogView::decode(interface_catalog_bytes)
            .map_err(DeploymentError::InvalidInterfaceCatalog)?;
        if generation.generation() != catalog.generation() {
            return Err(DeploymentError::GenerationRecordMismatch);
        }
        Self::new(
            generation.generation(),
            generation.digest(),
            catalog.digest(),
            source_object,
            source_generation,
        )
    }

    /// Admits only a cryptographically valid general SystemRelease from the
    /// signer identity selected by the caller's control-plane policy, then
    /// derives the candidate from the exact enclosed canonical records.
    pub fn from_system_release(
        release_bytes: &[u8],
        expected_key_id: &[u8; 64],
        source_object: u64,
        source_generation: u64,
    ) -> Result<Self, DeploymentError> {
        let release =
            parse_system_release(release_bytes).map_err(DeploymentError::InvalidSystemRelease)?;
        if release.key_id() != *expected_key_id {
            return Err(DeploymentError::SystemReleaseSignerMismatch);
        }
        let mut candidate = Self::new(
            release.generation().generation(),
            release.generation().digest(),
            release.interface_catalog().digest(),
            source_object,
            source_generation,
        )?;
        candidate.release_identity = Some(release.identity());
        Ok(candidate)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateId {
    slot: u16,
    slot_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedActivation {
    candidate: CandidateId,
    expected_activation_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValidatedActivation {
    slot: usize,
    active: ActivatedSystemGeneration,
    active_release: Option<ActivatedSystemRelease>,
    next_activation_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateState {
    Staged,
    Prepared,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CandidateSlot {
    slot_generation: u64,
    state: CandidateState,
    candidate: GenerationCandidate,
}

pub struct DeploymentService<const CANDIDATES: usize> {
    root: ObjectId,
    active: Option<ActivatedSystemGeneration>,
    active_release: Option<ActivatedSystemRelease>,
    candidates: [Option<CandidateSlot>; CANDIDATES],
    next_slot_generation: u64,
    next_activation_sequence: u64,
}

impl<const CANDIDATES: usize> DeploymentService<CANDIDATES> {
    pub fn new(root: ObjectId) -> Result<Self, DeploymentError> {
        if root.0 == 0 || CANDIDATES == 0 || CANDIDATES > u16::MAX as usize {
            return Err(DeploymentError::InvalidService);
        }
        Ok(Self {
            root,
            active: None,
            active_release: None,
            candidates: array::from_fn(|_| None),
            next_slot_generation: 1,
            next_activation_sequence: 1,
        })
    }

    pub fn stage<const N: usize>(
        &mut self,
        capabilities: &CapabilitySpace<N>,
        control: Capability,
        candidate: GenerationCandidate,
    ) -> Result<CandidateId, DeploymentError> {
        self.authorize(capabilities, control, Rights::CONTROL)?;
        if self
            .active
            .is_some_and(|active| candidate.generation <= active.generation())
        {
            return Err(DeploymentError::RollbackRequiresSeparateAuthorization);
        }
        if self.candidates.iter().flatten().any(|slot| {
            slot.candidate.generation == candidate.generation
                || slot.candidate.generation_digest == candidate.generation_digest
        }) {
            return Err(DeploymentError::DuplicateCandidate);
        }
        let slot = self
            .candidates
            .iter()
            .position(Option::is_none)
            .ok_or(DeploymentError::Capacity)?;
        let slot_generation = self.next_slot_generation;
        self.next_slot_generation = slot_generation
            .checked_add(1)
            .ok_or(DeploymentError::GenerationExhausted)?;
        self.candidates[slot] = Some(CandidateSlot {
            slot_generation,
            state: CandidateState::Staged,
            candidate,
        });
        Ok(CandidateId {
            slot: slot as u16,
            slot_generation,
        })
    }

    pub fn prepare_activation<const N: usize>(
        &mut self,
        capabilities: &CapabilitySpace<N>,
        control: Capability,
        candidate: CandidateId,
        expected_active: Option<(u64, u64)>,
    ) -> Result<PreparedActivation, DeploymentError> {
        self.authorize(capabilities, control, Rights::CONTROL)?;
        let actual_active = self
            .active
            .map(|active| (active.generation(), active.activation_sequence()));
        if actual_active != expected_active {
            return Err(DeploymentError::StaleActiveGeneration);
        }
        self.next_activation_sequence
            .checked_add(1)
            .ok_or(DeploymentError::GenerationExhausted)?;
        let slot = self.slot_mut(candidate)?;
        if slot.state != CandidateState::Staged {
            return Err(DeploymentError::InvalidCandidate);
        }
        slot.state = CandidateState::Prepared;
        Ok(PreparedActivation {
            candidate,
            expected_activation_sequence: self.next_activation_sequence,
        })
    }

    pub fn commit_activation<const N: usize>(
        &mut self,
        capabilities: &CapabilitySpace<N>,
        control: Capability,
        prepared: PreparedActivation,
    ) -> Result<ActivatedSystemGeneration, DeploymentError> {
        let validated = self.validate_activation(capabilities, control, prepared)?;
        Ok(self.publish_validated_activation(validated))
    }

    fn validate_activation<const N: usize>(
        &self,
        capabilities: &CapabilitySpace<N>,
        control: Capability,
        prepared: PreparedActivation,
    ) -> Result<ValidatedActivation, DeploymentError> {
        self.authorize(capabilities, control, Rights::CONTROL)?;
        let slot_index = prepared.candidate.slot as usize;
        let active = self.preview_activation(prepared)?;
        let active_release = self.preview_release(prepared)?;
        let next_activation_sequence = self
            .next_activation_sequence
            .checked_add(1)
            .ok_or(DeploymentError::GenerationExhausted)?;
        Ok(ValidatedActivation {
            slot: slot_index,
            active,
            active_release,
            next_activation_sequence,
        })
    }

    fn publish_validated_activation(
        &mut self,
        validated: ValidatedActivation,
    ) -> ActivatedSystemGeneration {
        self.next_activation_sequence = validated.next_activation_sequence;
        self.candidates[validated.slot] = None;
        self.active = Some(validated.active);
        self.active_release = validated.active_release;
        validated.active
    }

    pub fn preview_activation(
        &self,
        prepared: PreparedActivation,
    ) -> Result<ActivatedSystemGeneration, DeploymentError> {
        if prepared.expected_activation_sequence != self.next_activation_sequence {
            return Err(DeploymentError::StaleActivation);
        }
        self.next_activation_sequence
            .checked_add(1)
            .ok_or(DeploymentError::GenerationExhausted)?;
        let slot = self.slot(prepared.candidate)?;
        if slot.state != CandidateState::Prepared {
            return Err(DeploymentError::InvalidCandidate);
        }
        ActivatedSystemGeneration::new(
            slot.candidate.generation,
            slot.candidate.generation_digest,
            slot.candidate.interface_catalog_digest,
            self.next_activation_sequence,
            slot.candidate.source_object,
            slot.candidate.source_generation,
        )
        .map_err(DeploymentError::InvalidActivation)
    }

    fn preview_release(
        &self,
        prepared: PreparedActivation,
    ) -> Result<Option<ActivatedSystemRelease>, DeploymentError> {
        let active = self.preview_activation(prepared)?;
        let slot = self.slot(prepared.candidate)?;
        Ok(slot
            .candidate
            .release_identity
            .map(|release| ActivatedSystemRelease::new(active, release)))
    }

    pub fn recover(root: ObjectId, checkpoint: &[u8]) -> Result<Self, DeploymentError> {
        let (checkpoint_root, active, active_release) =
            decode_deployment_checkpoint_release(checkpoint)?;
        if checkpoint_root != root.0 {
            return Err(DeploymentError::InvalidCheckpoint);
        }
        let next_activation_sequence = active
            .activation_sequence()
            .checked_add(1)
            .ok_or(DeploymentError::GenerationExhausted)?;
        let mut service = Self::new(root)?;
        service.active = Some(active);
        service.active_release = active_release;
        service.next_activation_sequence = next_activation_sequence;
        Ok(service)
    }

    pub fn active<const N: usize>(
        &self,
        capabilities: &CapabilitySpace<N>,
        inspect: Capability,
    ) -> Result<Option<ActivatedSystemGeneration>, DeploymentError> {
        self.authorize(capabilities, inspect, Rights::READ)?;
        Ok(self.active)
    }

    pub fn active_release<const N: usize>(
        &self,
        capabilities: &CapabilitySpace<N>,
        inspect: Capability,
    ) -> Result<Option<ActivatedSystemRelease>, DeploymentError> {
        self.authorize(capabilities, inspect, Rights::READ)?;
        Ok(self.active_release)
    }

    /// Starts complete runtime-domain enumeration only from the currently
    /// activated SystemRelease and its capability-authorized inspection path.
    /// The caller supplies canonical release bytes but cannot substitute the
    /// activated identity or signer. Package metadata and assignments remain
    /// non-authorizing; launch admission still checks every resulting route.
    pub fn begin_runtime_assignment<'a, const DOMAINS: usize, const CAPS: usize>(
        &self,
        capabilities: &CapabilitySpace<CAPS>,
        inspect: Capability,
        release_bytes: &'a [u8],
        policy_generation: u64,
    ) -> Result<PreparedRuntimeAssignment<'a, DOMAINS>, DeploymentError> {
        self.authorize(capabilities, inspect, Rights::READ)?;
        let active = self
            .active_release
            .ok_or(DeploymentError::MissingActiveRelease)?;
        let assignment = RuntimeDomainAssignmentPlan::new(
            release_bytes,
            active.release().key_id(),
            active,
            policy_generation,
        )
        .map_err(DeploymentError::ReleaseInventory)?;
        Ok(PreparedRuntimeAssignment {
            assignment,
            inspect,
            active,
        })
    }

    /// Reads the exact activated release source through storage authority and
    /// begins complete runtime assignment from those verified bytes. Deployment
    /// authority is checked before storage access. Reads are bounded and may be
    /// chunked because a maximum canonical release can exceed one storage read.
    #[allow(clippy::too_many_arguments)]
    pub fn read_active_runtime_assignment<
        'a,
        const DOMAINS: usize,
        const CAPS: usize,
        const EXTENTS: usize,
        const AUTHORITIES: usize,
        B: FileReadBackend,
    >(
        &self,
        capabilities: &CapabilitySpace<CAPS>,
        inspect: Capability,
        file_state: &FileState<EXTENTS>,
        storage_authority: &StorageAuthorityTable<AUTHORITIES>,
        file: StorageHandle,
        principal: StoragePrincipal,
        output: &'a mut [u8],
        backend: &mut B,
        policy_generation: u64,
    ) -> Result<PreparedRuntimeAssignment<'a, DOMAINS>, DeploymentStorageError<B::Error>> {
        self.authorize(capabilities, inspect, Rights::READ)
            .map_err(DeploymentStorageError::Deployment)?;
        let active = self
            .active_release
            .ok_or(DeploymentStorageError::Deployment(
                DeploymentError::MissingActiveRelease,
            ))?;
        let generation = active.generation();
        let length = usize::try_from(file_state.length())
            .map_err(|_| DeploymentStorageError::InvalidBinding)?;
        if file_state.object().local() != generation.source_object()
            || file_state.generation() != generation.source_generation()
            || length == 0
            || length > MAX_SYSTEM_RELEASE_BYTES
            || output.len() < length
        {
            return Err(DeploymentStorageError::InvalidBinding);
        }
        output.fill(0);
        let mut offset = 0usize;
        while offset < length {
            let end = offset.saturating_add(MAX_FILE_READ_BYTES).min(length);
            if let Err(error) = file_state.read(
                storage_authority,
                file,
                principal,
                offset as u64,
                &mut output[offset..end],
                backend,
            ) {
                output.fill(0);
                return Err(DeploymentStorageError::Read(error));
            }
            offset = end;
        }
        let assignment = RuntimeDomainAssignmentPlan::new(
            &output[..length],
            active.release().key_id(),
            active,
            policy_generation,
        )
        .map_err(|error| {
            DeploymentStorageError::Deployment(DeploymentError::ReleaseInventory(error))
        })?;
        Ok(PreparedRuntimeAssignment {
            assignment,
            inspect,
            active,
        })
    }

    fn authorize<const N: usize>(
        &self,
        capabilities: &CapabilitySpace<N>,
        capability: Capability,
        rights: Rights,
    ) -> Result<(), DeploymentError> {
        if capabilities.authorize_exact(capability, rights).ok() != Some(self.root) {
            return Err(DeploymentError::Unauthorized);
        }
        Ok(())
    }

    fn slot(&self, candidate: CandidateId) -> Result<&CandidateSlot, DeploymentError> {
        self.candidates
            .get(candidate.slot as usize)
            .and_then(Option::as_ref)
            .filter(|slot| slot.slot_generation == candidate.slot_generation)
            .ok_or(DeploymentError::InvalidCandidate)
    }

    fn slot_mut(&mut self, candidate: CandidateId) -> Result<&mut CandidateSlot, DeploymentError> {
        self.candidates
            .get_mut(candidate.slot as usize)
            .and_then(Option::as_mut)
            .filter(|slot| slot.slot_generation == candidate.slot_generation)
            .ok_or(DeploymentError::InvalidCandidate)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentError {
    InvalidService,
    InvalidGeneration,
    InvalidGenerationRecord(SystemGenerationDecodeError),
    InvalidInterfaceCatalog(InterfaceCatalogError),
    GenerationRecordMismatch,
    InvalidSystemRelease(SystemReleaseError),
    SystemReleaseSignerMismatch,
    InvalidDigest,
    InvalidSource,
    Unauthorized,
    Capacity,
    DuplicateCandidate,
    InvalidCandidate,
    StaleActiveGeneration,
    StaleActivation,
    RollbackRequiresSeparateAuthorization,
    GenerationExhausted,
    InvalidActivation(ActivatedSystemGenerationError),
    MissingActiveRelease,
    ReleaseInventory(ReleaseInventoryError),
    InvalidCheckpoint,
    InvalidRecoveryState,
}

pub fn encode_deployment_checkpoint(
    root: ObjectId,
    active: ActivatedSystemGeneration,
) -> Result<[u8; DEPLOYMENT_CHECKPOINT_BYTES], DeploymentError> {
    encode_deployment_checkpoint_state(root, active, None)
}

pub fn encode_deployment_release_checkpoint(
    root: ObjectId,
    active: ActivatedSystemRelease,
) -> Result<[u8; DEPLOYMENT_CHECKPOINT_BYTES], DeploymentError> {
    encode_deployment_checkpoint_state(root, active.generation(), Some(active.release()))
}

fn encode_deployment_checkpoint_state(
    root: ObjectId,
    active: ActivatedSystemGeneration,
    release: Option<SystemReleaseIdentity>,
) -> Result<[u8; DEPLOYMENT_CHECKPOINT_BYTES], DeploymentError> {
    if root.0 == 0 {
        return Err(DeploymentError::InvalidService);
    }
    let mut bytes = [0; DEPLOYMENT_CHECKPOINT_BYTES];
    bytes[..8].copy_from_slice(&DEPLOYMENT_CHECKPOINT_MAGIC);
    bytes[8..10].copy_from_slice(&DEPLOYMENT_CHECKPOINT_VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&(DEPLOYMENT_CHECKPOINT_BYTES as u16).to_le_bytes());
    bytes[12..16].copy_from_slice(&(DEPLOYMENT_CHECKPOINT_BYTES as u32).to_le_bytes());
    bytes[16..24].copy_from_slice(&root.0.to_le_bytes());
    bytes[24..32].copy_from_slice(&active.generation().to_le_bytes());
    bytes[32..40].copy_from_slice(&active.activation_sequence().to_le_bytes());
    bytes[40..48].copy_from_slice(&active.source_object().to_le_bytes());
    bytes[48..56].copy_from_slice(&active.source_generation().to_le_bytes());
    bytes[56..120].copy_from_slice(active.generation_digest());
    bytes[120..184].copy_from_slice(active.interface_catalog_digest());
    let mut flags = 0u64;
    if let Some(release) = release {
        flags |= 1;
        bytes[184..248].copy_from_slice(release.content_digest());
        bytes[248..312].copy_from_slice(release.key_id());
        if let Some(runtime) = release.runtime_inventory_digest() {
            flags |= 2;
            bytes[312..376].copy_from_slice(runtime);
        }
    }
    bytes[376..384].copy_from_slice(&flags.to_le_bytes());
    let digest = Sha3_256::digest(&bytes);
    bytes[384..416].copy_from_slice(&digest);
    Ok(bytes)
}

pub fn decode_deployment_checkpoint(
    bytes: &[u8],
) -> Result<(u64, ActivatedSystemGeneration), DeploymentError> {
    let (root, active, _) = decode_deployment_checkpoint_release(bytes)?;
    Ok((root, active))
}

pub fn decode_deployment_checkpoint_release(
    bytes: &[u8],
) -> Result<
    (
        u64,
        ActivatedSystemGeneration,
        Option<ActivatedSystemRelease>,
    ),
    DeploymentError,
> {
    if bytes.len() == LEGACY_DEPLOYMENT_CHECKPOINT_BYTES {
        let (root, active) = decode_legacy_deployment_checkpoint(bytes)?;
        return Ok((root, active, None));
    }
    if bytes.len() != DEPLOYMENT_CHECKPOINT_BYTES
        || bytes[..8] != DEPLOYMENT_CHECKPOINT_MAGIC
        || read_u16(bytes, 8)? != DEPLOYMENT_CHECKPOINT_VERSION
        || read_u16(bytes, 10)? as usize != DEPLOYMENT_CHECKPOINT_BYTES
        || read_u32(bytes, 12)? as usize != DEPLOYMENT_CHECKPOINT_BYTES
        || bytes[416..].iter().any(|byte| *byte != 0)
    {
        return Err(DeploymentError::InvalidCheckpoint);
    }
    let mut expected = [0; DEPLOYMENT_CHECKPOINT_BYTES];
    expected.copy_from_slice(bytes);
    let mut claimed = [0; 32];
    claimed.copy_from_slice(&expected[384..416]);
    expected[384..416].fill(0);
    if Sha3_256::digest(&expected) != claimed {
        return Err(DeploymentError::InvalidCheckpoint);
    }
    let mut generation_digest = [0; 64];
    generation_digest.copy_from_slice(&bytes[56..120]);
    let mut interface_catalog_digest = [0; 64];
    interface_catalog_digest.copy_from_slice(&bytes[120..184]);
    let active = ActivatedSystemGeneration::new(
        read_u64(bytes, 24)?,
        generation_digest,
        interface_catalog_digest,
        read_u64(bytes, 32)?,
        read_u64(bytes, 40)?,
        read_u64(bytes, 48)?,
    )
    .map_err(DeploymentError::InvalidActivation)?;
    let flags = read_u64(bytes, 376)?;
    let release = match flags {
        0 => {
            if bytes[184..376].iter().any(|byte| *byte != 0) {
                return Err(DeploymentError::InvalidCheckpoint);
            }
            None
        }
        1 | 3 => {
            let mut content_digest = [0; 64];
            content_digest.copy_from_slice(&bytes[184..248]);
            let mut key_id = [0; 64];
            key_id.copy_from_slice(&bytes[248..312]);
            let runtime_inventory_digest = if flags == 3 {
                let mut digest = [0; 64];
                digest.copy_from_slice(&bytes[312..376]);
                Some(digest)
            } else {
                if bytes[312..376].iter().any(|byte| *byte != 0) {
                    return Err(DeploymentError::InvalidCheckpoint);
                }
                None
            };
            let identity = SystemReleaseIdentity::from_digests(
                content_digest,
                key_id,
                runtime_inventory_digest,
            )
            .ok_or(DeploymentError::InvalidCheckpoint)?;
            Some(ActivatedSystemRelease::new(active, identity))
        }
        _ => return Err(DeploymentError::InvalidCheckpoint),
    };
    Ok((read_u64(bytes, 16)?, active, release))
}

fn decode_legacy_deployment_checkpoint(
    bytes: &[u8],
) -> Result<(u64, ActivatedSystemGeneration), DeploymentError> {
    if bytes.len() != LEGACY_DEPLOYMENT_CHECKPOINT_BYTES
        || bytes[..8] != LEGACY_DEPLOYMENT_CHECKPOINT_MAGIC
        || read_u16(bytes, 8)? != LEGACY_DEPLOYMENT_CHECKPOINT_VERSION
        || read_u16(bytes, 10)? as usize != LEGACY_DEPLOYMENT_CHECKPOINT_BYTES
        || read_u32(bytes, 12)? as usize != LEGACY_DEPLOYMENT_CHECKPOINT_BYTES
        || bytes[216..].iter().any(|byte| *byte != 0)
    {
        return Err(DeploymentError::InvalidCheckpoint);
    }
    let mut expected = [0; LEGACY_DEPLOYMENT_CHECKPOINT_BYTES];
    expected.copy_from_slice(bytes);
    let mut claimed = [0; 32];
    claimed.copy_from_slice(&expected[184..216]);
    expected[184..216].fill(0);
    if Sha3_256::digest(&expected) != claimed {
        return Err(DeploymentError::InvalidCheckpoint);
    }
    let mut generation_digest = [0; 64];
    generation_digest.copy_from_slice(&bytes[56..120]);
    let mut interface_catalog_digest = [0; 64];
    interface_catalog_digest.copy_from_slice(&bytes[120..184]);
    let active = ActivatedSystemGeneration::new(
        read_u64(bytes, 24)?,
        generation_digest,
        interface_catalog_digest,
        read_u64(bytes, 32)?,
        read_u64(bytes, 40)?,
        read_u64(bytes, 48)?,
    )
    .map_err(DeploymentError::InvalidActivation)?;
    Ok((read_u64(bytes, 16)?, active))
}

pub struct PreparedStableActivation<const EXTENTS: usize> {
    file: PreparedFileWrite<EXTENTS>,
    activation: PreparedActivation,
    active: ActivatedSystemGeneration,
    active_release: Option<ActivatedSystemRelease>,
}

impl<const EXTENTS: usize> PreparedStableActivation<EXTENTS> {
    pub const fn active(&self) -> ActivatedSystemGeneration {
        self.active
    }

    pub fn admit<const PARTICIPANTS: usize, const WRITES: usize>(
        &self,
        transaction: &mut StorageTransaction<PARTICIPANTS, WRITES>,
    ) -> Result<(), TransactionError> {
        transaction.admit_file(&self.file)
    }

    pub fn commit<
        const CANDIDATES: usize,
        const PARTICIPANTS: usize,
        const CAPS: usize,
        const AUTHORITIES: usize,
    >(
        self,
        service: &mut DeploymentService<CANDIDATES>,
        capabilities: &CapabilitySpace<CAPS>,
        control: Capability,
        storage_authority: &StorageAuthorityTable<AUTHORITIES>,
        receipt: &mut TransactionReceipt<PARTICIPANTS>,
    ) -> Result<StableActivation<EXTENTS>, (Self, StableActivationCommitError)> {
        let validated = match service.validate_activation(capabilities, control, self.activation) {
            Ok(validated) => validated,
            Err(error) => {
                return Err((self, StableActivationCommitError::Deployment(error)));
            }
        };
        if validated.active != self.active {
            return Err((self, StableActivationCommitError::StaleActivation));
        }
        if validated.active_release != self.active_release {
            return Err((self, StableActivationCommitError::StaleActivation));
        }
        let Self {
            file,
            activation,
            active,
            active_release,
        } = self;
        let file = match file.commit_transaction_authorized(storage_authority, receipt) {
            Ok(file) => file,
            Err((file, error)) => {
                return Err((
                    Self {
                        file,
                        activation,
                        active,
                        active_release,
                    },
                    StableActivationCommitError::Storage(error),
                ));
            }
        };
        let active = service.publish_validated_activation(validated);
        Ok(StableActivation {
            file,
            active,
            active_release,
        })
    }

    pub fn commit_authenticated<
        const CANDIDATES: usize,
        const PARTICIPANTS: usize,
        const CAPS: usize,
        const AUTHORITIES: usize,
        S: DeploymentRecoveryStateStore,
    >(
        self,
        service: &mut DeploymentService<CANDIDATES>,
        capabilities: &CapabilitySpace<CAPS>,
        control: Capability,
        storage_authority: &StorageAuthorityTable<AUTHORITIES>,
        receipt: &mut TransactionReceipt<PARTICIPANTS>,
        state_store: &mut S,
    ) -> Result<StableActivation<EXTENTS>, AuthenticatedActivationCommitError<S::Error>> {
        let validated = service
            .validate_activation(capabilities, control, self.activation)
            .map_err(AuthenticatedActivationCommitError::Deployment)?;
        if validated.active != self.active {
            return Err(AuthenticatedActivationCommitError::StaleActivation);
        }
        if validated.active_release != self.active_release {
            return Err(AuthenticatedActivationCommitError::StaleActivation);
        }
        let mut expected = [0; DEPLOYMENT_RECOVERY_STATE_BYTES];
        state_store
            .load_authenticated(&mut expected)
            .map_err(AuthenticatedActivationCommitError::StateStore)?;
        let current = decode_deployment_recovery_state(&expected)
            .map_err(AuthenticatedActivationCommitError::Deployment)?;
        if !current.matches_active(service.active) {
            return Err(AuthenticatedActivationCommitError::RecoveryStateMismatch);
        }
        let replacement = encode_deployment_recovery_state_with_release(
            current.epoch().checked_add(1).ok_or(
                AuthenticatedActivationCommitError::Deployment(
                    DeploymentError::GenerationExhausted,
                ),
            )?,
            service.root,
            self.active,
            self.active_release,
            self.file.object(),
            self.file.generation(),
        )
        .map_err(AuthenticatedActivationCommitError::Deployment)?;
        let file = self
            .file
            .commit_transaction_authorized(storage_authority, receipt)
            .map_err(|(_, error)| AuthenticatedActivationCommitError::Storage(error))?;
        state_store
            .compare_and_store(&expected, &replacement)
            .map_err(AuthenticatedActivationCommitError::StateStore)?;
        let active = service.publish_validated_activation(validated);
        Ok(StableActivation {
            file,
            active,
            active_release: self.active_release,
        })
    }
}

pub struct StableActivation<const EXTENTS: usize> {
    file: FileState<EXTENTS>,
    active: ActivatedSystemGeneration,
    active_release: Option<ActivatedSystemRelease>,
}

impl<const EXTENTS: usize> StableActivation<EXTENTS> {
    pub const fn file(&self) -> &FileState<EXTENTS> {
        &self.file
    }

    pub const fn active(&self) -> ActivatedSystemGeneration {
        self.active
    }

    pub const fn active_release(&self) -> Option<ActivatedSystemRelease> {
        self.active_release
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StableActivationCommitError {
    StaleActivation,
    Storage(FileWriteCommitError),
    Deployment(DeploymentError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedActivationCommitError<E> {
    StaleActivation,
    RecoveryStateMismatch,
    Storage(FileWriteCommitError),
    Deployment(DeploymentError),
    StateStore(E),
}

pub trait DeploymentRecoveryStateStore {
    type Error;

    /// Loads one authenticated rollback-resistant state record. Missing,
    /// unauthenticated, or ambiguous state must fail closed.
    fn load_authenticated(
        &self,
        output: &mut [u8; DEPLOYMENT_RECOVERY_STATE_BYTES],
    ) -> Result<(), Self::Error>;

    /// Atomically replaces exactly `expected`; stale state must be rejected.
    fn compare_and_store(
        &mut self,
        expected: &[u8; DEPLOYMENT_RECOVERY_STATE_BYTES],
        replacement: &[u8; DEPLOYMENT_RECOVERY_STATE_BYTES],
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeploymentRecoveryState {
    epoch: u64,
    active: Option<ActivatedSystemGeneration>,
    volume: Option<mrml_storage::VolumeId>,
    file_object: u64,
    file_generation: u64,
    checkpoint_digest: [u8; 32],
}

impl DeploymentRecoveryState {
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    pub const fn active(self) -> Option<ActivatedSystemGeneration> {
        self.active
    }

    pub const fn volume(self) -> Option<mrml_storage::VolumeId> {
        self.volume
    }

    pub const fn file_object(self) -> u64 {
        self.file_object
    }

    pub const fn file_generation(self) -> u64 {
        self.file_generation
    }

    pub const fn checkpoint_digest(self) -> [u8; 32] {
        self.checkpoint_digest
    }

    pub fn matches_active(self, active: Option<ActivatedSystemGeneration>) -> bool {
        self.active == active
    }

    fn matches_file<const N: usize>(&self, file: &FileState<N>) -> bool {
        self.volume == Some(file.object().volume())
            && self.file_object == file.object().local()
            && self.file_generation == file.generation()
    }
}

pub fn encode_empty_deployment_recovery_state(
    epoch: u64,
) -> Result<[u8; DEPLOYMENT_RECOVERY_STATE_BYTES], DeploymentError> {
    if epoch == 0 {
        return Err(DeploymentError::InvalidRecoveryState);
    }
    let mut bytes = [0; DEPLOYMENT_RECOVERY_STATE_BYTES];
    bytes[..16].copy_from_slice(&DEPLOYMENT_RECOVERY_STATE_MAGIC);
    bytes[16..24].copy_from_slice(&epoch.to_le_bytes());
    Ok(bytes)
}

pub fn encode_deployment_recovery_state(
    epoch: u64,
    root: ObjectId,
    active: ActivatedSystemGeneration,
    file: mrml_storage::StorageObjectId,
    file_generation: u64,
) -> Result<[u8; DEPLOYMENT_RECOVERY_STATE_BYTES], DeploymentError> {
    encode_deployment_recovery_state_with_release(epoch, root, active, None, file, file_generation)
}

pub fn encode_deployment_recovery_state_with_release(
    epoch: u64,
    root: ObjectId,
    active: ActivatedSystemGeneration,
    active_release: Option<ActivatedSystemRelease>,
    file: mrml_storage::StorageObjectId,
    file_generation: u64,
) -> Result<[u8; DEPLOYMENT_RECOVERY_STATE_BYTES], DeploymentError> {
    if epoch == 0 || file_generation == 0 {
        return Err(DeploymentError::InvalidRecoveryState);
    }
    if active_release.is_some_and(|release| release.generation() != active) {
        return Err(DeploymentError::InvalidRecoveryState);
    }
    let mut bytes = [0; DEPLOYMENT_RECOVERY_STATE_BYTES];
    bytes[..16].copy_from_slice(&DEPLOYMENT_RECOVERY_STATE_MAGIC);
    bytes[16..24].copy_from_slice(&epoch.to_le_bytes());
    bytes[24..32].copy_from_slice(&active.activation_sequence().to_le_bytes());
    bytes[32..40].copy_from_slice(&active.generation().to_le_bytes());
    bytes[40..56].copy_from_slice(&file.volume().bytes());
    bytes[56..64].copy_from_slice(&file.local().to_le_bytes());
    bytes[64..72].copy_from_slice(&file_generation.to_le_bytes());
    bytes[72..136].copy_from_slice(active.generation_digest());
    bytes[136..200].copy_from_slice(active.interface_catalog_digest());
    let checkpoint = match active_release {
        Some(release) => encode_deployment_release_checkpoint(root, release)?,
        None => encode_deployment_checkpoint(root, active)?,
    };
    bytes[200..232].copy_from_slice(&Sha3_256::digest(&checkpoint));
    bytes[232..240].copy_from_slice(&active.source_object().to_le_bytes());
    bytes[240..248].copy_from_slice(&active.source_generation().to_le_bytes());
    Ok(bytes)
}

pub fn decode_deployment_recovery_state(
    bytes: &[u8; DEPLOYMENT_RECOVERY_STATE_BYTES],
) -> Result<DeploymentRecoveryState, DeploymentError> {
    if bytes[..16] != DEPLOYMENT_RECOVERY_STATE_MAGIC || bytes[248..].iter().any(|byte| *byte != 0)
    {
        return Err(DeploymentError::InvalidRecoveryState);
    }
    let epoch = read_u64(bytes, 16)?;
    if epoch == 0 {
        return Err(DeploymentError::InvalidRecoveryState);
    }
    let sequence = read_u64(bytes, 24)?;
    let generation = read_u64(bytes, 32)?;
    let volume_bytes: [u8; 16] = bytes[40..56]
        .try_into()
        .map_err(|_| DeploymentError::InvalidRecoveryState)?;
    let file_object = read_u64(bytes, 56)?;
    let file_generation = read_u64(bytes, 64)?;
    let mut generation_digest = [0; 64];
    generation_digest.copy_from_slice(&bytes[72..136]);
    let mut interface_catalog_digest = [0; 64];
    interface_catalog_digest.copy_from_slice(&bytes[136..200]);
    let mut checkpoint_digest = [0; 32];
    checkpoint_digest.copy_from_slice(&bytes[200..232]);
    let source_object = read_u64(bytes, 232)?;
    let source_generation = read_u64(bytes, 240)?;
    if sequence == 0 && generation == 0 {
        if volume_bytes.iter().any(|byte| *byte != 0)
            || file_object != 0
            || file_generation != 0
            || generation_digest.iter().any(|byte| *byte != 0)
            || interface_catalog_digest.iter().any(|byte| *byte != 0)
            || checkpoint_digest.iter().any(|byte| *byte != 0)
            || source_object != 0
            || source_generation != 0
        {
            return Err(DeploymentError::InvalidRecoveryState);
        }
        return Ok(DeploymentRecoveryState {
            epoch,
            active: None,
            volume: None,
            file_object: 0,
            file_generation: 0,
            checkpoint_digest,
        });
    }
    let volume = mrml_storage::VolumeId::new(volume_bytes)
        .map_err(|_| DeploymentError::InvalidRecoveryState)?;
    let active = ActivatedSystemGeneration::new(
        generation,
        generation_digest,
        interface_catalog_digest,
        sequence,
        source_object,
        source_generation,
    )
    .map_err(|_| DeploymentError::InvalidRecoveryState)?;
    Ok(DeploymentRecoveryState {
        epoch,
        active: Some(active),
        volume: Some(volume),
        file_object,
        file_generation,
        checkpoint_digest,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentStorageError<E> {
    Deployment(DeploymentError),
    InvalidBinding,
    Read(FileReadError<E>),
    Write(FileWriteError<E>),
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_stable_activation<
    const CANDIDATES: usize,
    const CURRENT_EXTENTS: usize,
    const NEXT_EXTENTS: usize,
    const AUTHORITIES: usize,
    B: FileWriteBackend,
>(
    service: &DeploymentService<CANDIDATES>,
    prepared: PreparedActivation,
    current_file: &FileState<CURRENT_EXTENTS>,
    storage_authority: &StorageAuthorityTable<AUTHORITIES>,
    file: StorageHandle,
    principal: StoragePrincipal,
    next_extents: ExtentMap<NEXT_EXTENTS>,
    next_metadata: FileMetadata,
    file_metadata_pointer: MetadataPointer,
    protected_metadata: &[MetadataPointer],
    backend: &mut B,
) -> Result<PreparedStableActivation<NEXT_EXTENTS>, DeploymentStorageError<B::Error>> {
    let active = service
        .preview_activation(prepared)
        .map_err(DeploymentStorageError::Deployment)?;
    let active_release = service
        .preview_release(prepared)
        .map_err(DeploymentStorageError::Deployment)?;
    let checkpoint = match active_release {
        Some(release) => encode_deployment_release_checkpoint(service.root, release),
        None => encode_deployment_checkpoint(service.root, active),
    }
    .map_err(DeploymentStorageError::Deployment)?;
    let mut content = Sha3_256::new();
    content.update(&checkpoint);
    if next_metadata.object() != current_file.object()
        || next_metadata.generation() != current_file.generation().checked_add(1).unwrap_or(0)
        || next_metadata.length() != DEPLOYMENT_CHECKPOINT_BYTES as u64
        || next_metadata.content_digest() != content.finalize()
    {
        return Err(DeploymentStorageError::InvalidBinding);
    }
    let file = current_file
        .prepare_write(
            storage_authority,
            file,
            principal,
            0,
            &checkpoint,
            DEPLOYMENT_CHECKPOINT_BYTES as u64,
            next_extents,
            next_metadata,
            file_metadata_pointer,
            protected_metadata,
            backend,
        )
        .map_err(DeploymentStorageError::Write)?;
    Ok(PreparedStableActivation {
        file,
        activation: prepared,
        active,
        active_release,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn recover_stable_activation<
    const CANDIDATES: usize,
    const EXTENTS: usize,
    const AUTHORITIES: usize,
    B: FileReadBackend,
>(
    root: ObjectId,
    file_state: &FileState<EXTENTS>,
    storage_authority: &StorageAuthorityTable<AUTHORITIES>,
    file: StorageHandle,
    principal: StoragePrincipal,
    expected_file_generation: u64,
    backend: &mut B,
) -> Result<DeploymentService<CANDIDATES>, DeploymentStorageError<B::Error>> {
    if expected_file_generation == 0
        || file_state.generation() != expected_file_generation
        || (file_state.length() != DEPLOYMENT_CHECKPOINT_BYTES as u64
            && file_state.length() != LEGACY_DEPLOYMENT_CHECKPOINT_BYTES as u64)
    {
        return Err(DeploymentStorageError::InvalidBinding);
    }
    let mut checkpoint = [0; DEPLOYMENT_CHECKPOINT_BYTES];
    let checkpoint_length = file_state.length() as usize;
    file_state
        .read(
            storage_authority,
            file,
            principal,
            0,
            &mut checkpoint[..checkpoint_length],
            backend,
        )
        .map_err(DeploymentStorageError::Read)?;
    DeploymentService::recover(root, &checkpoint[..checkpoint_length])
        .map_err(DeploymentStorageError::Deployment)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedActivationRecoveryError<StorageError, StateError> {
    Storage(DeploymentStorageError<StorageError>),
    StateStore(StateError),
    InvalidRecoveryState,
}

pub struct RecoveredRuntimeAssignment<'a, const CANDIDATES: usize, const DOMAINS: usize> {
    service: DeploymentService<CANDIDATES>,
    recovery: DeploymentRecoveryState,
    assignment: PreparedRuntimeAssignment<'a, DOMAINS>,
}

/// Authenticated deployment recovery retained beside the exact activated
/// runtime inventory produced from its selected SystemRelease. This owner is
/// non-authorizing; configuration, resource, route, and launch capabilities
/// remain mandatory.
pub struct RecoveredDeploymentOwner<const CANDIDATES: usize> {
    service: DeploymentService<CANDIDATES>,
    recovery: DeploymentRecoveryState,
}

impl<const CANDIDATES: usize> RecoveredDeploymentOwner<CANDIDATES> {
    pub const fn service(&self) -> &DeploymentService<CANDIDATES> {
        &self.service
    }

    pub const fn recovery(&self) -> DeploymentRecoveryState {
        self.recovery
    }

    pub fn into_parts(self) -> (DeploymentService<CANDIDATES>, DeploymentRecoveryState) {
        (self.service, self.recovery)
    }
}

pub struct RecoveredDeploymentRuntimeInventory<const CANDIDATES: usize, const DOMAINS: usize> {
    owner: RecoveredDeploymentOwner<CANDIDATES>,
    release: ActivatedReleaseTotalMicrovmInventory<DOMAINS>,
}

impl<const CANDIDATES: usize, const DOMAINS: usize>
    RecoveredDeploymentRuntimeInventory<CANDIDATES, DOMAINS>
{
    pub const fn owner(&self) -> &RecoveredDeploymentOwner<CANDIDATES> {
        &self.owner
    }

    pub const fn release(&self) -> &ActivatedReleaseTotalMicrovmInventory<DOMAINS> {
        &self.release
    }

    pub fn into_parts(
        self,
    ) -> (
        RecoveredDeploymentOwner<CANDIDATES>,
        ActivatedReleaseTotalMicrovmInventory<DOMAINS>,
    ) {
        (self.owner, self.release)
    }
}

impl<'a, const CANDIDATES: usize, const DOMAINS: usize>
    RecoveredRuntimeAssignment<'a, CANDIDATES, DOMAINS>
{
    pub const fn service(&self) -> &DeploymentService<CANDIDATES> {
        &self.service
    }

    pub const fn recovery(&self) -> DeploymentRecoveryState {
        self.recovery
    }

    pub const fn assignment(&self) -> &RuntimeDomainAssignmentPlan<'a, DOMAINS> {
        self.assignment.assignment()
    }

    pub fn assignment_mut(&mut self) -> &mut RuntimeDomainAssignmentPlan<'a, DOMAINS> {
        self.assignment.assignment_mut()
    }

    /// Seals every assigned package while retaining the authenticated
    /// deployment owner and recovery evidence that selected the release.
    pub fn seal<const CAPS: usize>(
        self,
        capabilities: &CapabilitySpace<CAPS>,
    ) -> Result<RecoveredDeploymentRuntimeInventory<CANDIDATES, DOMAINS>, RuntimeAssignmentSealError>
    {
        let release = self.assignment.seal(&self.service, capabilities)?;
        Ok(RecoveredDeploymentRuntimeInventory {
            owner: RecoveredDeploymentOwner {
                service: self.service,
                recovery: self.recovery,
            },
            release,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveredRuntimeAssignmentError<CheckpointError, ReleaseError, StateError> {
    Recovery(AuthenticatedActivationRecoveryError<CheckpointError, StateError>),
    Release(DeploymentStorageError<ReleaseError>),
}

#[allow(clippy::too_many_arguments)]
pub fn recover_authenticated_activation<
    const CANDIDATES: usize,
    const EXTENTS: usize,
    const AUTHORITIES: usize,
    B: FileReadBackend,
    S: DeploymentRecoveryStateStore,
>(
    root: ObjectId,
    file_state: &FileState<EXTENTS>,
    storage_authority: &StorageAuthorityTable<AUTHORITIES>,
    file: StorageHandle,
    principal: StoragePrincipal,
    state_store: &S,
    backend: &mut B,
) -> Result<DeploymentService<CANDIDATES>, AuthenticatedActivationRecoveryError<B::Error, S::Error>>
{
    recover_authenticated_activation_with_state(
        root,
        file_state,
        storage_authority,
        file,
        principal,
        state_store,
        backend,
    )
    .map(|(service, _)| service)
}

#[allow(clippy::too_many_arguments)]
fn recover_authenticated_activation_with_state<
    const CANDIDATES: usize,
    const EXTENTS: usize,
    const AUTHORITIES: usize,
    B: FileReadBackend,
    S: DeploymentRecoveryStateStore,
>(
    root: ObjectId,
    file_state: &FileState<EXTENTS>,
    storage_authority: &StorageAuthorityTable<AUTHORITIES>,
    file: StorageHandle,
    principal: StoragePrincipal,
    state_store: &S,
    backend: &mut B,
) -> Result<
    (DeploymentService<CANDIDATES>, DeploymentRecoveryState),
    AuthenticatedActivationRecoveryError<B::Error, S::Error>,
> {
    let mut encoded_state = [0; DEPLOYMENT_RECOVERY_STATE_BYTES];
    state_store
        .load_authenticated(&mut encoded_state)
        .map_err(AuthenticatedActivationRecoveryError::StateStore)?;
    let state = decode_deployment_recovery_state(&encoded_state)
        .map_err(|_| AuthenticatedActivationRecoveryError::InvalidRecoveryState)?;
    if !state.matches_file(file_state) {
        return Err(AuthenticatedActivationRecoveryError::InvalidRecoveryState);
    }
    let service = recover_stable_activation::<CANDIDATES, _, _, _>(
        root,
        file_state,
        storage_authority,
        file,
        principal,
        state.file_generation,
        backend,
    )
    .map_err(AuthenticatedActivationRecoveryError::Storage)?;
    let active = service
        .active
        .ok_or(AuthenticatedActivationRecoveryError::InvalidRecoveryState)?;
    let checkpoint = match service.active_release {
        Some(release) => encode_deployment_release_checkpoint(root, release),
        None => encode_deployment_checkpoint(root, active),
    }
    .map_err(|_| AuthenticatedActivationRecoveryError::InvalidRecoveryState)?;
    if state.active != Some(active) || state.checkpoint_digest != Sha3_256::digest(&checkpoint) {
        return Err(AuthenticatedActivationRecoveryError::InvalidRecoveryState);
    }
    Ok((service, state))
}

/// Recovers the authenticated deployment checkpoint and reads the exact active
/// SystemRelease source into one retained owner. No detached active identity is
/// exposed between recovery and complete runtime enumeration.
#[allow(clippy::too_many_arguments)]
pub fn recover_and_read_runtime_assignment<
    'a,
    const CANDIDATES: usize,
    const DOMAINS: usize,
    const CAPS: usize,
    const CHECKPOINT_EXTENTS: usize,
    const RELEASE_EXTENTS: usize,
    const CHECKPOINT_AUTHORITIES: usize,
    const RELEASE_AUTHORITIES: usize,
    CB: FileReadBackend,
    RB: FileReadBackend,
    S: DeploymentRecoveryStateStore,
>(
    root: ObjectId,
    checkpoint_file: &FileState<CHECKPOINT_EXTENTS>,
    checkpoint_authority: &StorageAuthorityTable<CHECKPOINT_AUTHORITIES>,
    checkpoint_handle: StorageHandle,
    release_file: &FileState<RELEASE_EXTENTS>,
    release_authority: &StorageAuthorityTable<RELEASE_AUTHORITIES>,
    release_handle: StorageHandle,
    principal: StoragePrincipal,
    state_store: &S,
    checkpoint_backend: &mut CB,
    release_backend: &mut RB,
    capabilities: &CapabilitySpace<CAPS>,
    inspect: Capability,
    output: &'a mut [u8],
    policy_generation: u64,
) -> Result<
    RecoveredRuntimeAssignment<'a, CANDIDATES, DOMAINS>,
    RecoveredRuntimeAssignmentError<CB::Error, RB::Error, S::Error>,
> {
    let (service, recovery) =
        recover_authenticated_activation_with_state::<CANDIDATES, _, _, _, _>(
            root,
            checkpoint_file,
            checkpoint_authority,
            checkpoint_handle,
            principal,
            state_store,
            checkpoint_backend,
        )
        .map_err(RecoveredRuntimeAssignmentError::Recovery)?;
    let assignment = service
        .read_active_runtime_assignment::<DOMAINS, CAPS, _, _, _>(
            capabilities,
            inspect,
            release_file,
            release_authority,
            release_handle,
            principal,
            output,
            release_backend,
            policy_generation,
        )
        .map_err(RecoveredRuntimeAssignmentError::Release)?;
    Ok(RecoveredRuntimeAssignment {
        service,
        recovery,
        assignment,
    })
}

/// Recovers the authenticated deployment checkpoint and then reads its exact
/// active SystemRelease through one shared storage backend. This is the normal
/// form for two selected files that reside on the same recovered volume; the
/// reads remain sequential and each file retains an independent capability.
#[allow(clippy::too_many_arguments)]
pub fn recover_and_read_runtime_assignment_shared_backend<
    'a,
    const CANDIDATES: usize,
    const DOMAINS: usize,
    const CAPS: usize,
    const CHECKPOINT_EXTENTS: usize,
    const RELEASE_EXTENTS: usize,
    const CHECKPOINT_AUTHORITIES: usize,
    const RELEASE_AUTHORITIES: usize,
    B: FileReadBackend,
    S: DeploymentRecoveryStateStore,
>(
    root: ObjectId,
    checkpoint_file: &FileState<CHECKPOINT_EXTENTS>,
    checkpoint_authority: &StorageAuthorityTable<CHECKPOINT_AUTHORITIES>,
    checkpoint_handle: StorageHandle,
    release_file: &FileState<RELEASE_EXTENTS>,
    release_authority: &StorageAuthorityTable<RELEASE_AUTHORITIES>,
    release_handle: StorageHandle,
    principal: StoragePrincipal,
    state_store: &S,
    backend: &mut B,
    capabilities: &CapabilitySpace<CAPS>,
    inspect: Capability,
    output: &'a mut [u8],
    policy_generation: u64,
) -> Result<
    RecoveredRuntimeAssignment<'a, CANDIDATES, DOMAINS>,
    RecoveredRuntimeAssignmentError<B::Error, B::Error, S::Error>,
> {
    let (service, recovery) =
        recover_authenticated_activation_with_state::<CANDIDATES, _, _, _, _>(
            root,
            checkpoint_file,
            checkpoint_authority,
            checkpoint_handle,
            principal,
            state_store,
            backend,
        )
        .map_err(RecoveredRuntimeAssignmentError::Recovery)?;
    let assignment = service
        .read_active_runtime_assignment::<DOMAINS, CAPS, _, _, _>(
            capabilities,
            inspect,
            release_file,
            release_authority,
            release_handle,
            principal,
            output,
            backend,
            policy_generation,
        )
        .map_err(RecoveredRuntimeAssignmentError::Release)?;
    Ok(RecoveredRuntimeAssignment {
        service,
        recovery,
        assignment,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DeploymentError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(DeploymentError::InvalidCheckpoint)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DeploymentError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(DeploymentError::InvalidCheckpoint)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, DeploymentError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(DeploymentError::InvalidCheckpoint)
}

const fn all_zero(value: &[u8; 64]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_crypto::{
        LAMPORT_PRIVATE_KEY_BYTES, LAMPORT_PUBLIC_KEY_BYTES, LAMPORT_SIGNATURE_BYTES,
    };
    use mrml_package_format::{
        ComponentInterfaceProvider, ComponentInterfaceRequirement, ComponentProviderForms,
        RuntimeInventoryRecord, RuntimeIsolationClass, RuntimeIsolationPlacement,
        SYSTEM_RELEASE_HEADER_BYTES, SYSTEM_RELEASE_RUNTIME_HEADER_BYTES,
        SystemGenerationDigestRecord, encode_interface_catalog, encode_runtime_inventory,
        encode_system_generation, encode_system_release,
        encode_system_release_with_runtime_inventory,
    };
    use mrml_storage::{
        CowMetadataImage, CowMetadataWrite, CowPublicationBackend, CowPublicationPlan,
        ExtentRecord, StorageAuthorityError, StorageObjectId, StorageObjectKind, StorageRights,
        StorageTransactionId, Superblock, VolumeHeader, VolumeId,
    };

    const BLOCK_BYTES: usize = 4096;

    fn volume() -> VolumeId {
        VolumeId::new([0x61; 16]).unwrap()
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
        Sha3_256::digest(bytes)
    }

    struct StableBackend {
        bytes: [u8; BLOCK_BYTES],
    }

    unsafe impl FileWriteBackend for StableBackend {
        type Error = u8;

        fn stage_new_extent(
            &mut self,
            file: StorageObjectId,
            old_generation: u64,
            old_length: u64,
            next: ExtentRecord,
            new_length: u64,
            patch_offset: u64,
            patch: &[u8],
        ) -> Result<(), Self::Error> {
            if file != object(9)
                || old_generation != 1
                || old_length != 0
                || next.file() != file
                || next.metadata_generation() != 2
                || next.physical_block() != Some(10)
                || next.block_count() != 1
                || patch_offset != 0
                || new_length as usize != patch.len()
            {
                return Err(1);
            }
            self.bytes.fill(0);
            self.bytes[..patch.len()].copy_from_slice(patch);
            if next.content_digest() != digest(&self.bytes) {
                return Err(2);
            }
            Ok(())
        }

        fn flush_new_file_data(
            &mut self,
            file: StorageObjectId,
            generation: u64,
            length: u64,
            content_digest: [u8; 32],
        ) -> Result<(), Self::Error> {
            if file != object(9)
                || generation != 2
                || length != DEPLOYMENT_CHECKPOINT_BYTES as u64
                || content_digest != digest(&self.bytes[..DEPLOYMENT_CHECKPOINT_BYTES])
            {
                return Err(3);
            }
            Ok(())
        }
    }

    unsafe impl FileReadBackend for StableBackend {
        type Error = u8;

        fn read_verified_extent(
            &mut self,
            record: ExtentRecord,
            byte_offset: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            if record.file() != object(9)
                || record.metadata_generation() != 2
                || record.content_digest() != digest(&self.bytes)
            {
                return Err(4);
            }
            let start = byte_offset as usize;
            let end = start.checked_add(output.len()).ok_or(4)?;
            output.copy_from_slice(self.bytes.get(start..end).ok_or(4)?);
            Ok(())
        }
    }

    struct PublicationBackend;

    unsafe impl CowPublicationBackend for PublicationBackend {
        type Error = ();

        fn verify_new_metadata(&mut self, _: CowMetadataWrite) -> Result<(), Self::Error> {
            Ok(())
        }

        fn flush_new_metadata(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn replace_superblock(
            &mut self,
            block: u64,
            _: &[u8; mrml_storage::SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            (block == 2).then_some(()).ok_or(())
        }

        fn flush_superblock(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct RecoveryStateStore {
        bytes: [u8; DEPLOYMENT_RECOVERY_STATE_BYTES],
    }

    impl RecoveryStateStore {
        fn empty() -> Self {
            Self {
                bytes: encode_empty_deployment_recovery_state(1).unwrap(),
            }
        }
    }

    impl DeploymentRecoveryStateStore for RecoveryStateStore {
        type Error = u8;

        fn load_authenticated(
            &self,
            output: &mut [u8; DEPLOYMENT_RECOVERY_STATE_BYTES],
        ) -> Result<(), Self::Error> {
            output.copy_from_slice(&self.bytes);
            Ok(())
        }

        fn compare_and_store(
            &mut self,
            expected: &[u8; DEPLOYMENT_RECOVERY_STATE_BYTES],
            replacement: &[u8; DEPLOYMENT_RECOVERY_STATE_BYTES],
        ) -> Result<(), Self::Error> {
            if self.bytes != *expected {
                return Err(1);
            }
            self.bytes.copy_from_slice(replacement);
            Ok(())
        }
    }

    fn stable_layout(
        checkpoint: &[u8; DEPLOYMENT_CHECKPOINT_BYTES],
    ) -> (
        FileState<0>,
        ExtentMap<1>,
        FileMetadata,
        [CowMetadataImage; 2],
    ) {
        let current = FileState::new(
            object(9),
            1,
            0,
            ExtentMap::<0>::build(header(), object(9), 1, 0, &[]).unwrap(),
        )
        .unwrap();
        let mut block = [0; BLOCK_BYTES];
        block[..checkpoint.len()].copy_from_slice(checkpoint);
        let record = ExtentRecord::data(object(9), 2, 0, 1, 10, digest(&block)).unwrap();
        let next =
            ExtentMap::build(header(), object(9), 2, checkpoint.len() as u64, &[record]).unwrap();
        let metadata = FileMetadata::new(
            header(),
            object(9),
            2,
            checkpoint.len() as u64,
            1,
            MetadataPointer::new(20, 1).unwrap(),
            digest(checkpoint),
        )
        .unwrap();
        let mut encoded_metadata = [0; BLOCK_BYTES];
        metadata.encode(
            (&mut encoded_metadata[..mrml_storage::FILE_METADATA_BYTES])
                .try_into()
                .unwrap(),
        );
        let mut encoded_extents = [0; BLOCK_BYTES];
        record.encode(
            (&mut encoded_extents[..mrml_storage::EXTENT_RECORD_BYTES])
                .try_into()
                .unwrap(),
        );
        (
            current,
            next,
            metadata,
            [
                CowMetadataImage::new(
                    MetadataPointer::new(21, 1).unwrap(),
                    digest(&encoded_metadata),
                ),
                CowMetadataImage::new(
                    MetadataPointer::new(20, 1).unwrap(),
                    digest(&encoded_extents),
                ),
            ],
        )
    }

    fn publication_plan(images: [CowMetadataImage; 2]) -> CowPublicationPlan<4> {
        let active = Superblock::new(
            header(),
            1,
            0,
            object(1),
            MetadataPointer::new(30, 1).unwrap(),
            MetadataPointer::new(31, 1).unwrap(),
        )
        .unwrap();
        let root =
            CowMetadataWrite::new(MetadataPointer::new(40, 1).unwrap(), 2, [0x40; 32]).unwrap();
        let allocation =
            CowMetadataWrite::new(MetadataPointer::new(41, 1).unwrap(), 2, [0x41; 32]).unwrap();
        CowPublicationPlan::build(
            header(),
            1,
            active,
            object(1),
            root.pointer(),
            allocation.pointer(),
            &[
                images[0].bind(2).unwrap(),
                images[1].bind(2).unwrap(),
                root,
                allocation,
            ],
            &[
                MetadataPointer::new(30, 1).unwrap(),
                MetadataPointer::new(31, 1).unwrap(),
            ],
        )
        .unwrap()
    }

    fn authority() -> (CapabilitySpace<3>, Capability, Capability) {
        let mut capabilities = CapabilitySpace::new();
        let control = capabilities
            .insert(ObjectId(0x4445_504c_4f59), Rights::CONTROL)
            .unwrap();
        let inspect = capabilities
            .insert(ObjectId(0x4445_504c_4f59), Rights::READ)
            .unwrap();
        (capabilities, control, inspect)
    }

    fn candidate(generation: u64, marker: u8) -> GenerationCandidate {
        GenerationCandidate::new(
            generation,
            [marker; 64],
            [marker.wrapping_add(1); 64],
            0x700,
            generation + 10,
        )
        .unwrap()
    }

    const TEST_RUNTIME_RELEASE_BYTES: usize = SYSTEM_RELEASE_RUNTIME_HEADER_BYTES
        + 128
        + 256
        + 256
        + LAMPORT_PUBLIC_KEY_BYTES
        + LAMPORT_SIGNATURE_BYTES;
    const TEST_RUNTIME_EXTENT_BLOCKS: usize = TEST_RUNTIME_RELEASE_BYTES.div_ceil(BLOCK_BYTES);
    const TEST_RUNTIME_EXTENT_BYTES: usize = TEST_RUNTIME_EXTENT_BLOCKS * BLOCK_BYTES;

    struct RuntimeReleaseBackend {
        bytes: [u8; TEST_RUNTIME_EXTENT_BYTES],
        reads: usize,
        fail: bool,
    }

    unsafe impl FileReadBackend for RuntimeReleaseBackend {
        type Error = u8;

        fn read_verified_extent(
            &mut self,
            record: ExtentRecord,
            byte_offset: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            self.reads += 1;
            if self.fail
                || record.file() != object(0x700)
                || record.metadata_generation() != 2
                || record.physical_block() != Some(40)
                || record.block_count() as usize != TEST_RUNTIME_EXTENT_BLOCKS
                || record.content_digest() != digest(&self.bytes)
            {
                return Err(1);
            }
            let start = usize::try_from(byte_offset).map_err(|_| 2)?;
            let end = start.checked_add(output.len()).ok_or(2)?;
            output.copy_from_slice(self.bytes.get(start..end).ok_or(2)?);
            Ok(())
        }
    }

    struct SharedRuntimeBackend {
        checkpoint: [u8; BLOCK_BYTES],
        release: [u8; TEST_RUNTIME_EXTENT_BYTES],
        checkpoint_reads: usize,
        release_reads: usize,
    }

    unsafe impl FileReadBackend for SharedRuntimeBackend {
        type Error = u8;

        fn read_verified_extent(
            &mut self,
            record: ExtentRecord,
            byte_offset: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            let bytes = if record.file() == object(9) {
                self.checkpoint_reads += 1;
                if record.metadata_generation() != 2
                    || record.content_digest() != digest(&self.checkpoint)
                {
                    return Err(1);
                }
                &self.checkpoint[..]
            } else if record.file() == object(0x700) {
                self.release_reads += 1;
                if record.metadata_generation() != 2
                    || record.physical_block() != Some(40)
                    || record.block_count() as usize != TEST_RUNTIME_EXTENT_BLOCKS
                    || record.content_digest() != digest(&self.release)
                {
                    return Err(2);
                }
                &self.release[..]
            } else {
                return Err(3);
            };
            let start = usize::try_from(byte_offset).map_err(|_| 4)?;
            let end = start.checked_add(output.len()).ok_or(4)?;
            output.copy_from_slice(bytes.get(start..end).ok_or(4)?);
            Ok(())
        }
    }

    fn signed_runtime_candidate() -> (
        GenerationCandidate,
        SystemReleaseIdentity,
        [u8; TEST_RUNTIME_RELEASE_BYTES],
        usize,
    ) {
        let artifact_digest = [0x2f; 64];
        let records = [SystemGenerationDigestRecord {
            package_id: "org.mrml.zstd",
            version: 3,
            artifact_digest: &artifact_digest,
        }];
        let mut generation = [0; 128];
        let generation_length = encode_system_generation(7, &records, &mut generation).unwrap();
        let provider = ComponentInterfaceProvider::exact(
            "org.mrml.zstd",
            "org.mrml.interface.compression.zstd",
            3,
            [0x6a; 32],
            ComponentProviderForms::MICROVM,
        )
        .unwrap();
        let requirement = ComponentInterfaceRequirement::exact(
            "org.mrml.zstd",
            "org.mrml.interface.compression.zstd",
            3,
            [0x6a; 32],
        )
        .unwrap();
        let mut catalog = [0; 256];
        let catalog_length =
            encode_interface_catalog(7, &[requirement], &[provider], &mut catalog).unwrap();
        let runtime_record = RuntimeInventoryRecord {
            package_id: "org.mrml.zstd",
            version: 3,
            artifact_digest: &artifact_digest,
            class: RuntimeIsolationClass::MicrovmEligible,
            must_run: true,
            preferred: RuntimeIsolationPlacement::NativeService,
            minimum: RuntimeIsolationPlacement::NativeService,
            maximum: RuntimeIsolationPlacement::Microvm,
            supported: RuntimeIsolationPlacement::NativeService.bit()
                | RuntimeIsolationPlacement::Microvm.bit(),
            reason: "",
        };
        let mut runtime = [0; 256];
        let runtime_length = encode_runtime_inventory(7, &[runtime_record], &mut runtime).unwrap();
        let private = [0x5a; LAMPORT_PRIVATE_KEY_BYTES];
        let mut release = [0; TEST_RUNTIME_RELEASE_BYTES];
        let release_length = encode_system_release_with_runtime_inventory(
            &generation[..generation_length],
            &catalog[..catalog_length],
            &runtime[..runtime_length],
            &private,
            &mut release,
        )
        .unwrap();
        let parsed = parse_system_release(&release[..release_length]).unwrap();
        let candidate = GenerationCandidate::from_system_release(
            &release[..release_length],
            &parsed.key_id(),
            0x700,
            2,
        )
        .unwrap();
        (candidate, parsed.identity(), release, release_length)
    }

    #[test]
    fn signed_runtime_identity_survives_activation_checkpoint_and_recovery() {
        let (mut capabilities, control, inspect) = authority();
        let root = ObjectId(0x4445_504c_4f59);
        let (candidate, identity, release, release_length) = signed_runtime_candidate();
        assert!(identity.has_runtime_inventory());
        let mut service = DeploymentService::<1>::new(root).unwrap();
        assert!(matches!(
            service.begin_runtime_assignment::<1, 3>(
                &capabilities,
                inspect,
                &release[..release_length],
                4,
            ),
            Err(DeploymentError::MissingActiveRelease)
        ));
        let id = service.stage(&capabilities, control, candidate).unwrap();
        let prepared = service
            .prepare_activation(&capabilities, control, id, None)
            .unwrap();
        capabilities.revoke(control).unwrap();
        assert_eq!(
            service.commit_activation(&capabilities, control, prepared),
            Err(DeploymentError::Unauthorized)
        );
        let replacement = capabilities
            .insert(ObjectId(0x4445_504c_4f59), Rights::CONTROL)
            .unwrap();
        let active = service
            .commit_activation(&capabilities, replacement, prepared)
            .unwrap();
        let activated_release = service
            .active_release(&capabilities, inspect)
            .unwrap()
            .unwrap();
        assert_eq!(activated_release.generation(), active);
        assert_eq!(activated_release.release(), identity);

        let mut revoked_assignment = service
            .begin_runtime_assignment::<1, 3>(&capabilities, inspect, &release[..release_length], 4)
            .unwrap();
        let mut packages = revoked_assignment.assignment().packages();
        assert_eq!(packages.next(), Some("org.mrml.zstd"));
        assert_eq!(packages.next(), None);
        drop(packages);
        revoked_assignment
            .assignment_mut()
            .assign_from_policy(|record| {
                mrml_kernel::RuntimeDomainAssignment::new(record.package_id, ObjectId(0x5a53_5444))
            })
            .unwrap();
        capabilities.revoke(inspect).unwrap();
        assert!(matches!(
            revoked_assignment.seal(&service, &capabilities),
            Err(RuntimeAssignmentSealError::Deployment(
                DeploymentError::Unauthorized
            ))
        ));
        let inspect = capabilities.insert(root, Rights::READ).unwrap();
        let mut assignment = service
            .begin_runtime_assignment::<1, 3>(&capabilities, inspect, &release[..release_length], 4)
            .unwrap();
        assignment
            .assignment_mut()
            .assign_from_policy(|record| {
                mrml_kernel::RuntimeDomainAssignment::new(record.package_id, ObjectId(0x5a53_5444))
            })
            .unwrap();
        let inventory = assignment.seal(&service, &capabilities).unwrap();
        assert_eq!(inventory.active_release(), activated_release);
        assert_eq!(inventory.policy_generation(), 4);
        assert_eq!(inventory.release().len(), 1);

        let mut release_extent = [0; TEST_RUNTIME_EXTENT_BYTES];
        release_extent[..release_length].copy_from_slice(&release[..release_length]);
        let release_record = ExtentRecord::data(
            object(0x700),
            2,
            0,
            TEST_RUNTIME_EXTENT_BLOCKS as u32,
            40,
            digest(&release_extent),
        )
        .unwrap();
        let release_file = FileState::new(
            object(0x700),
            2,
            release_length as u64,
            ExtentMap::<1>::build(
                header(),
                object(0x700),
                2,
                release_length as u64,
                &[release_record],
            )
            .unwrap(),
        )
        .unwrap();
        let mut release_authority = StorageAuthorityTable::<1>::new();
        let release_handle = release_authority
            .insert(
                object(0x700),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(),
            )
            .unwrap();
        let mut release_backend = RuntimeReleaseBackend {
            bytes: release_extent,
            reads: 0,
            fail: false,
        };
        let mut short_output = [0xa5; TEST_RUNTIME_RELEASE_BYTES];
        assert!(matches!(
            service.read_active_runtime_assignment::<1, 3, 1, 1, _>(
                &capabilities,
                inspect,
                &release_file,
                &release_authority,
                release_handle,
                principal(),
                &mut short_output[..release_length - 1],
                &mut release_backend,
                4,
            ),
            Err(DeploymentStorageError::InvalidBinding)
        ));
        assert_eq!(release_backend.reads, 0);

        let mut read_output = [0xa5; TEST_RUNTIME_RELEASE_BYTES];
        let mut read_assignment = service
            .read_active_runtime_assignment::<1, 3, 1, 1, _>(
                &capabilities,
                inspect,
                &release_file,
                &release_authority,
                release_handle,
                principal(),
                &mut read_output,
                &mut release_backend,
                4,
            )
            .unwrap();
        read_assignment
            .assignment_mut()
            .assign_from_policy(|record| {
                mrml_kernel::RuntimeDomainAssignment::new(record.package_id, ObjectId(0x5a53_5444))
            })
            .unwrap();
        let read_inventory = read_assignment.seal(&service, &capabilities).unwrap();
        assert_eq!(read_inventory.active_release(), activated_release);
        assert_eq!(release_backend.reads, 1);

        let mut stale_assignment = service
            .begin_runtime_assignment::<1, 3>(&capabilities, inspect, &release[..release_length], 4)
            .unwrap();
        stale_assignment
            .assignment_mut()
            .assign_from_policy(|record| {
                mrml_kernel::RuntimeDomainAssignment::new(record.package_id, ObjectId(0x5a53_5444))
            })
            .unwrap();
        service.active_release = None;
        assert!(matches!(
            stale_assignment.seal(&service, &capabilities),
            Err(RuntimeAssignmentSealError::Deployment(
                DeploymentError::StaleActiveGeneration
            ))
        ));
        service.active_release = Some(activated_release);

        let mut failed_output = [0xa5; TEST_RUNTIME_RELEASE_BYTES];
        release_backend.fail = true;
        assert!(matches!(
            service.read_active_runtime_assignment::<1, 3, 1, 1, _>(
                &capabilities,
                inspect,
                &release_file,
                &release_authority,
                release_handle,
                principal(),
                &mut failed_output,
                &mut release_backend,
                4,
            ),
            Err(DeploymentStorageError::Read(_))
        ));
        assert!(failed_output.iter().all(|byte| *byte == 0));

        let wrong_inspect = capabilities.insert(ObjectId(9), Rights::READ).unwrap();
        assert!(matches!(
            service.begin_runtime_assignment::<1, 3>(
                &capabilities,
                wrong_inspect,
                &release[..release_length],
                4,
            ),
            Err(DeploymentError::Unauthorized)
        ));

        let mut substituted_release = release;
        substituted_release[SYSTEM_RELEASE_RUNTIME_HEADER_BYTES] ^= 1;
        assert!(matches!(
            service.begin_runtime_assignment::<1, 3>(
                &capabilities,
                inspect,
                &substituted_release[..release_length],
                4,
            ),
            Err(DeploymentError::ReleaseInventory(_))
        ));

        let checkpoint = encode_deployment_release_checkpoint(root, activated_release).unwrap();
        let recovery_state = encode_deployment_recovery_state_with_release(
            9,
            root,
            active,
            Some(activated_release),
            object(9),
            2,
        )
        .unwrap();
        assert_eq!(
            decode_deployment_recovery_state(&recovery_state)
                .unwrap()
                .checkpoint_digest,
            Sha3_256::digest(&checkpoint)
        );
        let mut checkpoint_block = [0; BLOCK_BYTES];
        checkpoint_block[..checkpoint.len()].copy_from_slice(&checkpoint);
        let checkpoint_record =
            ExtentRecord::data(object(9), 2, 0, 1, 10, digest(&checkpoint_block)).unwrap();
        let checkpoint_file = FileState::new(
            object(9),
            2,
            checkpoint.len() as u64,
            ExtentMap::<1>::build(
                header(),
                object(9),
                2,
                checkpoint.len() as u64,
                &[checkpoint_record],
            )
            .unwrap(),
        )
        .unwrap();
        let mut checkpoint_authority = StorageAuthorityTable::<1>::new();
        let checkpoint_handle = checkpoint_authority
            .insert(
                object(9),
                StorageObjectKind::File,
                StorageRights::READ,
                principal(),
            )
            .unwrap();
        let state_store = RecoveryStateStore {
            bytes: recovery_state,
        };
        let mut shared_backend = SharedRuntimeBackend {
            checkpoint: checkpoint_block,
            release: release_extent,
            checkpoint_reads: 0,
            release_reads: 0,
        };
        let mut shared_output = [0xa5; TEST_RUNTIME_RELEASE_BYTES];
        let mut shared_assignment =
            recover_and_read_runtime_assignment_shared_backend::<1, 1, 3, 1, 1, 1, 1, _, _>(
                root,
                &checkpoint_file,
                &checkpoint_authority,
                checkpoint_handle,
                &release_file,
                &release_authority,
                release_handle,
                principal(),
                &state_store,
                &mut shared_backend,
                &capabilities,
                inspect,
                &mut shared_output,
                4,
            )
            .unwrap();
        assert_eq!(
            shared_assignment
                .service()
                .active_release(&capabilities, inspect),
            Ok(Some(activated_release))
        );
        assert_eq!(shared_backend.checkpoint_reads, 1);
        assert_eq!(shared_backend.release_reads, 1);
        shared_assignment
            .assignment_mut()
            .assign_from_policy(|record| {
                mrml_kernel::RuntimeDomainAssignment::new(
                    record.package_id,
                    ObjectId(0x5256_4f4b_4544),
                )
            })
            .unwrap();
        capabilities.revoke(inspect).unwrap();
        assert!(matches!(
            shared_assignment.seal(&capabilities),
            Err(RuntimeAssignmentSealError::Deployment(
                DeploymentError::Unauthorized
            ))
        ));
        let inspect = capabilities.insert(root, Rights::READ).unwrap();
        let mut checkpoint_backend = StableBackend {
            bytes: checkpoint_block,
        };
        release_backend.fail = false;
        let mut recovered_output = [0xa5; TEST_RUNTIME_RELEASE_BYTES];
        let mut recovered_assignment =
            recover_and_read_runtime_assignment::<1, 1, 3, 1, 1, 1, 1, _, _, _>(
                root,
                &checkpoint_file,
                &checkpoint_authority,
                checkpoint_handle,
                &release_file,
                &release_authority,
                release_handle,
                principal(),
                &state_store,
                &mut checkpoint_backend,
                &mut release_backend,
                &capabilities,
                inspect,
                &mut recovered_output,
                4,
            )
            .unwrap();
        assert_eq!(
            recovered_assignment
                .service()
                .active_release(&capabilities, inspect),
            Ok(Some(activated_release))
        );
        let retained_recovery = recovered_assignment.recovery();
        assert_eq!(retained_recovery.epoch(), 9);
        assert_eq!(retained_recovery.active(), Some(active));
        assert_eq!(retained_recovery.volume(), Some(volume()));
        assert_eq!(retained_recovery.file_object(), object(9).local());
        assert_eq!(retained_recovery.file_generation(), 2);
        assert_eq!(
            retained_recovery.checkpoint_digest(),
            Sha3_256::digest(&checkpoint)
        );
        recovered_assignment
            .assignment_mut()
            .assign_from_policy(|record| {
                mrml_kernel::RuntimeDomainAssignment::new(record.package_id, ObjectId(0x5a53_5444))
            })
            .unwrap();
        let recovered_inventory = recovered_assignment.seal(&capabilities).unwrap();
        assert_eq!(recovered_inventory.owner().recovery(), retained_recovery);
        assert_eq!(
            recovered_inventory
                .owner()
                .service()
                .active_release(&capabilities, inspect),
            Ok(Some(activated_release))
        );
        assert_eq!(
            recovered_inventory.release().active_release(),
            activated_release
        );
        let (decoded_root, decoded_active, decoded_release) =
            decode_deployment_checkpoint_release(&checkpoint).unwrap();
        assert_eq!(decoded_root, root.0);
        assert_eq!(decoded_active, active);
        assert_eq!(decoded_release, Some(activated_release));
        let recovered = DeploymentService::<1>::recover(root, &checkpoint).unwrap();
        assert_eq!(
            recovered.active_release(&capabilities, inspect),
            Ok(Some(activated_release))
        );

        let mut corrupted = checkpoint;
        corrupted[312] ^= 1;
        assert_eq!(
            decode_deployment_checkpoint_release(&corrupted),
            Err(DeploymentError::InvalidCheckpoint)
        );
    }

    #[test]
    fn legacy_generation_checkpoint_recovers_without_release_identity() {
        let root = ObjectId(0x4445_504c_4f59);
        let active =
            ActivatedSystemGeneration::new(8, [0x51; 64], [0x52; 64], 3, 0x700, 18).unwrap();
        let mut legacy = [0; LEGACY_DEPLOYMENT_CHECKPOINT_BYTES];
        legacy[..8].copy_from_slice(&LEGACY_DEPLOYMENT_CHECKPOINT_MAGIC);
        legacy[8..10].copy_from_slice(&LEGACY_DEPLOYMENT_CHECKPOINT_VERSION.to_le_bytes());
        legacy[10..12].copy_from_slice(&(LEGACY_DEPLOYMENT_CHECKPOINT_BYTES as u16).to_le_bytes());
        legacy[12..16].copy_from_slice(&(LEGACY_DEPLOYMENT_CHECKPOINT_BYTES as u32).to_le_bytes());
        legacy[16..24].copy_from_slice(&root.0.to_le_bytes());
        legacy[24..32].copy_from_slice(&active.generation().to_le_bytes());
        legacy[32..40].copy_from_slice(&active.activation_sequence().to_le_bytes());
        legacy[40..48].copy_from_slice(&active.source_object().to_le_bytes());
        legacy[48..56].copy_from_slice(&active.source_generation().to_le_bytes());
        legacy[56..120].copy_from_slice(active.generation_digest());
        legacy[120..184].copy_from_slice(active.interface_catalog_digest());
        let digest = Sha3_256::digest(&legacy);
        legacy[184..216].copy_from_slice(&digest);

        let (_, decoded, release) = decode_deployment_checkpoint_release(&legacy).unwrap();
        assert_eq!(decoded, active);
        assert_eq!(release, None);
        let recovered = DeploymentService::<1>::recover(root, &legacy).unwrap();
        let (capabilities, _, inspect) = authority();
        assert_eq!(recovered.active(&capabilities, inspect), Ok(Some(active)));
        assert_eq!(recovered.active_release(&capabilities, inspect), Ok(None));
    }

    #[test]
    fn canonical_records_derive_both_activation_roots_and_reject_cross_generation_pairing() {
        let records = [SystemGenerationDigestRecord {
            package_id: "org.mrml.zstd",
            version: 3,
            artifact_digest: &[0x2f; 64],
        }];
        let mut generation = [0; 128];
        let generation_length = encode_system_generation(7, &records, &mut generation).unwrap();
        let requirement = ComponentInterfaceRequirement::exact(
            "org.mrml.zstd",
            "org.mrml.interface.compression.zstd",
            3,
            [0x6a; 32],
        )
        .unwrap();
        let provider = ComponentInterfaceProvider::exact(
            "org.mrml.zstd",
            "org.mrml.interface.compression.zstd",
            3,
            [0x6a; 32],
            ComponentProviderForms::MICROVM,
        )
        .unwrap();
        let mut catalog = [0; 256];
        let catalog_length =
            encode_interface_catalog(7, &[requirement], &[provider], &mut catalog).unwrap();
        let candidate = GenerationCandidate::from_canonical_records(
            &generation[..generation_length],
            &catalog[..catalog_length],
            0x700,
            2,
        )
        .unwrap();
        assert_eq!(candidate.generation(), 7);

        let private = [0x5a; LAMPORT_PRIVATE_KEY_BYTES];
        let mut release = [0; SYSTEM_RELEASE_HEADER_BYTES
            + 128
            + 256
            + LAMPORT_PUBLIC_KEY_BYTES
            + LAMPORT_SIGNATURE_BYTES];
        let release_length = encode_system_release(
            &generation[..generation_length],
            &catalog[..catalog_length],
            &private,
            &mut release,
        )
        .unwrap();
        let parsed_release = parse_system_release(&release[..release_length]).unwrap();
        let expected_key_id = parsed_release.key_id();
        let signed_candidate = GenerationCandidate::from_system_release(
            &release[..release_length],
            &expected_key_id,
            0x700,
            2,
        )
        .unwrap();
        assert_eq!(signed_candidate.generation, candidate.generation);
        assert_eq!(
            signed_candidate.generation_digest,
            candidate.generation_digest
        );
        assert_eq!(
            signed_candidate.interface_catalog_digest,
            candidate.interface_catalog_digest
        );
        assert_eq!(candidate.release_identity(), None);
        let identity = signed_candidate.release_identity().unwrap();
        assert_eq!(identity, parsed_release.identity());
        assert_eq!(identity.content_digest(), &parsed_release.content_digest());
        assert_eq!(identity.key_id(), &expected_key_id);
        assert!(!identity.has_runtime_inventory());
        assert_eq!(
            GenerationCandidate::from_system_release(
                &release[..release_length],
                &[0x99; 64],
                0x700,
                2,
            ),
            Err(DeploymentError::SystemReleaseSignerMismatch)
        );
        release[SYSTEM_RELEASE_HEADER_BYTES] ^= 1;
        assert!(matches!(
            GenerationCandidate::from_system_release(
                &release[..release_length],
                &expected_key_id,
                0x700,
                2,
            ),
            Err(DeploymentError::InvalidSystemRelease(_))
        ));

        catalog[8..16].copy_from_slice(&8u64.to_le_bytes());
        assert_eq!(
            GenerationCandidate::from_canonical_records(
                &generation[..generation_length],
                &catalog[..catalog_length],
                0x700,
                2,
            ),
            Err(DeploymentError::GenerationRecordMismatch)
        );
    }

    #[test]
    fn activation_is_capability_authorized_two_phase_and_one_use() {
        let (mut capabilities, control, inspect) = authority();
        let overbroad = capabilities
            .insert(
                ObjectId(0x4445_504c_4f59),
                Rights::CONTROL.union(Rights::READ),
            )
            .unwrap();
        let mut service = DeploymentService::<2>::new(ObjectId(0x4445_504c_4f59)).unwrap();
        assert_eq!(
            service.stage(&capabilities, overbroad, candidate(7, 0x41)),
            Err(DeploymentError::Unauthorized)
        );
        assert_eq!(
            service.active(&capabilities, overbroad),
            Err(DeploymentError::Unauthorized)
        );
        let id = service
            .stage(&capabilities, control, candidate(8, 0x51))
            .unwrap();
        assert_eq!(service.active(&capabilities, inspect), Ok(None));
        let prepared = service
            .prepare_activation(&capabilities, control, id, None)
            .unwrap();
        let active = service
            .commit_activation(&capabilities, control, prepared)
            .unwrap();
        assert_eq!(active.generation(), 8);
        assert_eq!(active.generation_digest(), &[0x51; 64]);
        assert_eq!(active.interface_catalog_digest(), &[0x52; 64]);
        assert_eq!(service.active(&capabilities, inspect), Ok(Some(active)));
        assert_eq!(
            service.commit_activation(&capabilities, control, prepared),
            Err(DeploymentError::StaleActivation)
        );
    }

    #[test]
    fn activation_sequence_exhaustion_precedes_preparation_and_publication() {
        let (capabilities, control, _) = authority();
        let mut service = DeploymentService::<1>::new(ObjectId(0x4445_504c_4f59)).unwrap();
        let candidate = service
            .stage(&capabilities, control, candidate(8, 0x51))
            .unwrap();
        service.next_activation_sequence = u64::MAX;
        assert_eq!(
            service.prepare_activation(&capabilities, control, candidate, None),
            Err(DeploymentError::GenerationExhausted)
        );

        service.next_activation_sequence = 1;
        service
            .prepare_activation(&capabilities, control, candidate, None)
            .unwrap();
        service.next_activation_sequence = u64::MAX;
        let exhausted = PreparedActivation {
            candidate,
            expected_activation_sequence: u64::MAX,
        };
        assert_eq!(
            service.preview_activation(exhausted),
            Err(DeploymentError::GenerationExhausted)
        );
    }

    #[test]
    fn stale_authority_candidate_and_active_state_fail_without_activation() {
        let (mut capabilities, control, inspect) = authority();
        let wrong = capabilities.insert(ObjectId(9), Rights::CONTROL).unwrap();
        let mut service = DeploymentService::<2>::new(ObjectId(0x4445_504c_4f59)).unwrap();
        assert_eq!(
            service.stage(&capabilities, wrong, candidate(8, 0x51)),
            Err(DeploymentError::Unauthorized)
        );
        let id = service
            .stage(&capabilities, control, candidate(8, 0x51))
            .unwrap();
        assert_eq!(
            service.prepare_activation(&capabilities, control, id, Some((7, 1))),
            Err(DeploymentError::StaleActiveGeneration)
        );
        let prepared = service
            .prepare_activation(&capabilities, control, id, None)
            .unwrap();
        let active = service
            .commit_activation(&capabilities, control, prepared)
            .unwrap();
        assert_eq!(
            service.stage(&capabilities, control, candidate(7, 0x50)),
            Err(DeploymentError::RollbackRequiresSeparateAuthorization)
        );
        assert_eq!(service.active(&capabilities, inspect), Ok(Some(active)));
    }

    #[test]
    fn activation_publishes_with_one_storage_receipt_and_recovers_exact_file_generation() {
        let (capabilities, control, inspect) = authority();
        let root = ObjectId(0x4445_504c_4f59);
        let mut service = DeploymentService::<2>::new(root).unwrap();
        let id = service
            .stage(&capabilities, control, candidate(8, 0x51))
            .unwrap();
        let prepared = service
            .prepare_activation(&capabilities, control, id, None)
            .unwrap();
        let preview = service.preview_activation(prepared).unwrap();
        let checkpoint = encode_deployment_checkpoint(root, preview).unwrap();
        let (current, next, metadata, images) = stable_layout(&checkpoint);
        let mut authority = StorageAuthorityTable::<1>::new();
        let file = authority
            .insert(
                object(9),
                StorageObjectKind::File,
                StorageRights::READ
                    .union(StorageRights::WRITE)
                    .union(StorageRights::RESIZE),
                principal(),
            )
            .unwrap();
        let mut backend = StableBackend {
            bytes: [0; BLOCK_BYTES],
        };
        let stable = prepare_stable_activation(
            &service,
            prepared,
            &current,
            &authority,
            file,
            principal(),
            next,
            metadata,
            MetadataPointer::new(21, 1).unwrap(),
            &[],
            &mut backend,
        )
        .unwrap();
        assert_eq!(service.active(&capabilities, inspect), Ok(None));
        let mut transaction =
            StorageTransaction::<1, 2>::new(StorageTransactionId::new(70).unwrap(), 2).unwrap();
        stable.admit(&mut transaction).unwrap();
        let mut receipt = transaction
            .publish(&publication_plan(images), &mut PublicationBackend)
            .unwrap();
        let mut recovery_state = RecoveryStateStore {
            bytes: encode_empty_deployment_recovery_state(u64::MAX).unwrap(),
        };
        assert!(matches!(
            stable.commit_authenticated(
                &mut service,
                &capabilities,
                control,
                &authority,
                &mut receipt,
                &mut recovery_state,
            ),
            Err(AuthenticatedActivationCommitError::Deployment(
                DeploymentError::GenerationExhausted
            ))
        ));
        assert_eq!(receipt.remaining(), 1);
        assert_eq!(service.active(&capabilities, inspect), Ok(None));

        let (_, next, metadata, images) = stable_layout(&checkpoint);
        let stable = prepare_stable_activation(
            &service,
            prepared,
            &current,
            &authority,
            file,
            principal(),
            next,
            metadata,
            MetadataPointer::new(21, 1).unwrap(),
            &[],
            &mut backend,
        )
        .unwrap();
        let mut transaction =
            StorageTransaction::<1, 2>::new(StorageTransactionId::new(69).unwrap(), 2).unwrap();
        stable.admit(&mut transaction).unwrap();
        let mut receipt = transaction
            .publish(&publication_plan(images), &mut PublicationBackend)
            .unwrap();
        let mut recovery_state = RecoveryStateStore::empty();
        authority.revoke(file, principal()).unwrap();
        let retained = match stable.commit(
            &mut service,
            &capabilities,
            control,
            &authority,
            &mut receipt,
        ) {
            Err((
                prepared,
                StableActivationCommitError::Storage(FileWriteCommitError::Authority(
                    StorageAuthorityError::InvalidHandle,
                )),
            )) => prepared,
            _ => panic!("revoked storage authority did not retain stable activation"),
        };
        assert_eq!(retained.active(), preview);
        assert_eq!(receipt.remaining(), 1);
        assert_eq!(service.active(&capabilities, inspect), Ok(None));

        let file = authority
            .insert(
                object(9),
                StorageObjectKind::File,
                StorageRights::READ
                    .union(StorageRights::WRITE)
                    .union(StorageRights::RESIZE),
                principal(),
            )
            .unwrap();
        let (_, next, metadata, images) = stable_layout(&checkpoint);
        let stable = prepare_stable_activation(
            &service,
            prepared,
            &current,
            &authority,
            file,
            principal(),
            next,
            metadata,
            MetadataPointer::new(21, 1).unwrap(),
            &[],
            &mut backend,
        )
        .unwrap();
        let mut transaction =
            StorageTransaction::<1, 2>::new(StorageTransactionId::new(71).unwrap(), 2).unwrap();
        stable.admit(&mut transaction).unwrap();
        let mut receipt = transaction
            .publish(&publication_plan(images), &mut PublicationBackend)
            .unwrap();
        let stable = stable
            .commit_authenticated(
                &mut service,
                &capabilities,
                control,
                &authority,
                &mut receipt,
                &mut recovery_state,
            )
            .unwrap();
        assert_eq!(receipt.remaining(), 0);
        assert_eq!(stable.active(), preview);
        assert_eq!(service.active(&capabilities, inspect), Ok(Some(preview)));

        let recovered = recover_authenticated_activation::<2, _, _, _, _>(
            root,
            stable.file(),
            &authority,
            file,
            principal(),
            &recovery_state,
            &mut backend,
        )
        .unwrap();
        assert_eq!(recovered.active(&capabilities, inspect), Ok(Some(preview)));

        let accepted = recovery_state.bytes;
        recovery_state.bytes = encode_deployment_recovery_state(
            3,
            root,
            stable.active(),
            stable.file().object(),
            stable.file().generation() + 1,
        )
        .unwrap();
        assert!(matches!(
            recover_authenticated_activation::<2, _, _, _, _>(
                root,
                stable.file(),
                &authority,
                file,
                principal(),
                &recovery_state,
                &mut backend,
            ),
            Err(AuthenticatedActivationRecoveryError::InvalidRecoveryState)
        ));

        recovery_state.bytes = accepted;
        backend.bytes[0] ^= 1;
        assert!(matches!(
            recover_authenticated_activation::<2, _, _, _, _>(
                root,
                stable.file(),
                &authority,
                file,
                principal(),
                &recovery_state,
                &mut backend,
            ),
            Err(AuthenticatedActivationRecoveryError::Storage(
                DeploymentStorageError::Read(FileReadError::Backend(4))
            ))
        ));
    }
}
