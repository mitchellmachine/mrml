#![no_std]

//! Bounded SystemGeneration candidate and activation control plane.
//!
//! Generation numbers, digests, and storage identities are data. Only an exact
//! live capability for the service root authorizes staging, activation, or
//! inspection. Activation is a two-phase, one-use transaction; stale tokens
//! never select or resurrect a generation.

use core::array;

use mrml_crypto::Sha3_256;
use mrml_kernel::{Capability, CapabilitySpace, ObjectId, Rights};
use mrml_package_format::{
    ActivatedSystemGeneration, ActivatedSystemGenerationError, InterfaceCatalogError,
    InterfaceCatalogView, SystemGenerationDecodeError, SystemGenerationView, SystemReleaseError,
    parse_system_release,
};
use mrml_storage::{
    ExtentMap, FileMetadata, FileReadBackend, FileReadError, FileState, FileWriteBackend,
    FileWriteError, MetadataPointer, PreparedFileWrite, StorageAuthorityTable, StorageHandle,
    StoragePrincipal, StorageTransaction, TransactionError, TransactionReceipt,
};

pub const DEPLOYMENT_CHECKPOINT_BYTES: usize = 224;
pub const DEPLOYMENT_RECOVERY_STATE_BYTES: usize = 256;
const DEPLOYMENT_CHECKPOINT_MAGIC: [u8; 8] = *b"MRMLDA2\0";
const DEPLOYMENT_CHECKPOINT_VERSION: u16 = 2;
const DEPLOYMENT_RECOVERY_STATE_MAGIC: [u8; 16] = *b"MRML-DEPLSTATE2\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationCandidate {
    generation: u64,
    generation_digest: [u8; 64],
    interface_catalog_digest: [u8; 64],
    source_object: u64,
    source_generation: u64,
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
        })
    }

    pub const fn generation(self) -> u64 {
        self.generation
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
        Self::new(
            release.generation().generation(),
            release.generation().digest(),
            release.interface_catalog().digest(),
            source_object,
            source_generation,
        )
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

    pub fn commit_activation(
        &mut self,
        prepared: PreparedActivation,
    ) -> Result<ActivatedSystemGeneration, DeploymentError> {
        if prepared.expected_activation_sequence != self.next_activation_sequence {
            return Err(DeploymentError::StaleActivation);
        }
        let slot_index = prepared.candidate.slot as usize;
        let slot = self.slot(prepared.candidate)?;
        if slot.state != CandidateState::Prepared {
            return Err(DeploymentError::InvalidCandidate);
        }
        let candidate = slot.candidate;
        let active = ActivatedSystemGeneration::new(
            candidate.generation,
            candidate.generation_digest,
            candidate.interface_catalog_digest,
            self.next_activation_sequence,
            candidate.source_object,
            candidate.source_generation,
        )
        .map_err(DeploymentError::InvalidActivation)?;
        self.next_activation_sequence = self
            .next_activation_sequence
            .checked_add(1)
            .ok_or(DeploymentError::GenerationExhausted)?;
        self.candidates[slot_index] = None;
        self.active = Some(active);
        Ok(active)
    }

    pub fn preview_activation(
        &self,
        prepared: PreparedActivation,
    ) -> Result<ActivatedSystemGeneration, DeploymentError> {
        if prepared.expected_activation_sequence != self.next_activation_sequence {
            return Err(DeploymentError::StaleActivation);
        }
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

    pub fn recover(root: ObjectId, checkpoint: &[u8]) -> Result<Self, DeploymentError> {
        let (checkpoint_root, active) = decode_deployment_checkpoint(checkpoint)?;
        if checkpoint_root != root.0 {
            return Err(DeploymentError::InvalidCheckpoint);
        }
        let next_activation_sequence = active
            .activation_sequence()
            .checked_add(1)
            .ok_or(DeploymentError::GenerationExhausted)?;
        let mut service = Self::new(root)?;
        service.active = Some(active);
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

    fn authorize<const N: usize>(
        &self,
        capabilities: &CapabilitySpace<N>,
        capability: Capability,
        rights: Rights,
    ) -> Result<(), DeploymentError> {
        if capabilities.authorize(capability, rights).ok() != Some(self.root) {
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
    InvalidCheckpoint,
    InvalidRecoveryState,
}

pub fn encode_deployment_checkpoint(
    root: ObjectId,
    active: ActivatedSystemGeneration,
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
    let digest = Sha3_256::digest(&bytes);
    bytes[184..216].copy_from_slice(&digest);
    Ok(bytes)
}

pub fn decode_deployment_checkpoint(
    bytes: &[u8],
) -> Result<(u64, ActivatedSystemGeneration), DeploymentError> {
    if bytes.len() != DEPLOYMENT_CHECKPOINT_BYTES
        || bytes[..8] != DEPLOYMENT_CHECKPOINT_MAGIC
        || read_u16(bytes, 8)? != DEPLOYMENT_CHECKPOINT_VERSION
        || read_u16(bytes, 10)? as usize != DEPLOYMENT_CHECKPOINT_BYTES
        || read_u32(bytes, 12)? as usize != DEPLOYMENT_CHECKPOINT_BYTES
        || bytes[216..].iter().any(|byte| *byte != 0)
    {
        return Err(DeploymentError::InvalidCheckpoint);
    }
    let mut expected = [0; DEPLOYMENT_CHECKPOINT_BYTES];
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

    pub fn commit<const CANDIDATES: usize, const PARTICIPANTS: usize>(
        self,
        service: &mut DeploymentService<CANDIDATES>,
        receipt: &mut TransactionReceipt<PARTICIPANTS>,
    ) -> Result<StableActivation<EXTENTS>, StableActivationCommitError> {
        if service.preview_activation(self.activation) != Ok(self.active) {
            return Err(StableActivationCommitError::StaleActivation);
        }
        let file = self
            .file
            .commit_transaction(receipt)
            .map_err(StableActivationCommitError::Transaction)?;
        let active = service
            .commit_activation(self.activation)
            .map_err(StableActivationCommitError::Deployment)?;
        if active != self.active {
            return Err(StableActivationCommitError::StaleActivation);
        }
        Ok(StableActivation { file, active })
    }

    pub fn commit_authenticated<
        const CANDIDATES: usize,
        const PARTICIPANTS: usize,
        S: DeploymentRecoveryStateStore,
    >(
        self,
        service: &mut DeploymentService<CANDIDATES>,
        receipt: &mut TransactionReceipt<PARTICIPANTS>,
        state_store: &mut S,
    ) -> Result<StableActivation<EXTENTS>, AuthenticatedActivationCommitError<S::Error>> {
        if service.preview_activation(self.activation) != Ok(self.active) {
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
        let file = self
            .file
            .commit_transaction(receipt)
            .map_err(AuthenticatedActivationCommitError::Transaction)?;
        let replacement = encode_deployment_recovery_state(
            current.epoch().checked_add(1).ok_or(
                AuthenticatedActivationCommitError::Deployment(
                    DeploymentError::GenerationExhausted,
                ),
            )?,
            service.root,
            self.active,
            file.object(),
            file.generation(),
        )
        .map_err(AuthenticatedActivationCommitError::Deployment)?;
        state_store
            .compare_and_store(&expected, &replacement)
            .map_err(AuthenticatedActivationCommitError::StateStore)?;
        let active = service
            .commit_activation(self.activation)
            .map_err(AuthenticatedActivationCommitError::Deployment)?;
        if active != self.active {
            return Err(AuthenticatedActivationCommitError::StaleActivation);
        }
        Ok(StableActivation { file, active })
    }
}

pub struct StableActivation<const EXTENTS: usize> {
    file: FileState<EXTENTS>,
    active: ActivatedSystemGeneration,
}

impl<const EXTENTS: usize> StableActivation<EXTENTS> {
    pub const fn file(&self) -> &FileState<EXTENTS> {
        &self.file
    }

    pub const fn active(&self) -> ActivatedSystemGeneration {
        self.active
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StableActivationCommitError {
    StaleActivation,
    Transaction(TransactionError),
    Deployment(DeploymentError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedActivationCommitError<E> {
    StaleActivation,
    RecoveryStateMismatch,
    Transaction(TransactionError),
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
    if epoch == 0 || file_generation == 0 {
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
    bytes[200..232].copy_from_slice(&Sha3_256::digest(&encode_deployment_checkpoint(
        root, active,
    )?));
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
    let checkpoint = encode_deployment_checkpoint(service.root, active)
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
        || file_state.length() != DEPLOYMENT_CHECKPOINT_BYTES as u64
    {
        return Err(DeploymentStorageError::InvalidBinding);
    }
    let mut checkpoint = [0; DEPLOYMENT_CHECKPOINT_BYTES];
    file_state
        .read(
            storage_authority,
            file,
            principal,
            0,
            &mut checkpoint,
            backend,
        )
        .map_err(DeploymentStorageError::Read)?;
    DeploymentService::recover(root, &checkpoint).map_err(DeploymentStorageError::Deployment)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedActivationRecoveryError<StorageError, StateError> {
    Storage(DeploymentStorageError<StorageError>),
    StateStore(StateError),
    InvalidRecoveryState,
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
    if state.active != Some(active)
        || state.checkpoint_digest
            != Sha3_256::digest(
                &encode_deployment_checkpoint(root, active)
                    .map_err(|_| AuthenticatedActivationRecoveryError::InvalidRecoveryState)?,
            )
    {
        return Err(AuthenticatedActivationRecoveryError::InvalidRecoveryState);
    }
    Ok(service)
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
        SYSTEM_RELEASE_HEADER_BYTES, SystemGenerationDigestRecord, encode_interface_catalog,
        encode_system_generation, encode_system_release,
    };
    use mrml_storage::{
        CowMetadataImage, CowMetadataWrite, CowPublicationBackend, CowPublicationPlan,
        ExtentRecord, StorageObjectId, StorageObjectKind, StorageRights, StorageTransactionId,
        Superblock, VolumeHeader, VolumeId,
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
        assert_eq!(signed_candidate, candidate);
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
        let (capabilities, control, inspect) = authority();
        let mut service = DeploymentService::<2>::new(ObjectId(0x4445_504c_4f59)).unwrap();
        let id = service
            .stage(&capabilities, control, candidate(8, 0x51))
            .unwrap();
        assert_eq!(service.active(&capabilities, inspect), Ok(None));
        let prepared = service
            .prepare_activation(&capabilities, control, id, None)
            .unwrap();
        let active = service.commit_activation(prepared).unwrap();
        assert_eq!(active.generation(), 8);
        assert_eq!(active.generation_digest(), &[0x51; 64]);
        assert_eq!(active.interface_catalog_digest(), &[0x52; 64]);
        assert_eq!(service.active(&capabilities, inspect), Ok(Some(active)));
        assert_eq!(
            service.commit_activation(prepared),
            Err(DeploymentError::StaleActivation)
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
        let active = service.commit_activation(prepared).unwrap();
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
        let mut recovery_state = RecoveryStateStore::empty();
        let stable = stable
            .commit_authenticated(&mut service, &mut receipt, &mut recovery_state)
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
