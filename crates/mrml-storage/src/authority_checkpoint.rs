use crate::{
    ExtentMap, FileMetadata, FileReadBackend, FileReadError, FileState, FileWriteBackend,
    FileWriteError, MetadataPointer, PreparedFileWrite, ReachableFileSelection,
    StorageAuthorityError, StorageAuthorityTable, StorageHandle, StorageObjectId,
    StorageObjectKind, StoragePrincipal, StorageRights, StorageTransaction, TransactionError,
    TransactionReceipt, VolumeId,
};
use core::array;
use mrml_crypto::Sha3_256;

pub const AUTHORITY_CHECKPOINT_HEADER_BYTES: usize = 80;
pub const AUTHORITY_CHECKPOINT_GRANT_BYTES: usize = 48;
pub const AUTHORITY_RECOVERY_STATE_BYTES: usize = 64;
const DIGEST_OFFSET: usize = 48;
const DIGEST_BYTES: usize = 32;
const MAGIC: [u8; 4] = *b"MRAC";
const VERSION: u8 = 1;
const RECOVERY_STATE_MAGIC: [u8; 16] = *b"MRML-AUTHSTATE1\0";

/// Backend contract for authenticated, monotonic storage-authority recovery
/// state. Implementations must authenticate reads and make compare-and-store
/// atomic across power loss. Ordinary files do not satisfy this contract.
pub trait AuthorityRecoveryStateStore {
    type Error;

    fn load_authenticated(
        &self,
        output: &mut [u8; AUTHORITY_RECOVERY_STATE_BYTES],
    ) -> Result<(), Self::Error>;

    fn compare_and_store(
        &mut self,
        expected: &[u8; AUTHORITY_RECOVERY_STATE_BYTES],
        replacement: &[u8; AUTHORITY_RECOVERY_STATE_BYTES],
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityCheckpoint {
    length: usize,
    digest: [u8; DIGEST_BYTES],
    epoch: u64,
    root_generation: u64,
    handle_generation: u32,
    grant_count: usize,
}

impl AuthorityCheckpoint {
    pub const fn length(self) -> usize {
        self.length
    }

    pub const fn digest(self) -> [u8; DIGEST_BYTES] {
        self.digest
    }

    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    pub const fn root_generation(self) -> u64 {
        self.root_generation
    }

    pub const fn handle_generation(self) -> u32 {
        self.handle_generation
    }

    pub const fn grant_count(self) -> usize {
        self.grant_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageRecoveryGrant {
    principal: StoragePrincipal,
    object: StorageObjectId,
    kind: StorageObjectKind,
    rights: StorageRights,
    parent: Option<usize>,
}

impl StorageRecoveryGrant {
    pub const fn root(
        principal: StoragePrincipal,
        object: StorageObjectId,
        kind: StorageObjectKind,
        rights: StorageRights,
    ) -> Self {
        Self {
            principal,
            object,
            kind,
            rights,
            parent: None,
        }
    }

    pub const fn derived(
        principal: StoragePrincipal,
        object: StorageObjectId,
        kind: StorageObjectKind,
        rights: StorageRights,
        parent: usize,
    ) -> Self {
        Self {
            principal,
            object,
            kind,
            rights,
            parent: Some(parent),
        }
    }
}

/// Authenticated rollback state supplied by the platform recovery boundary.
/// Safe code cannot choose a lower accepted epoch or handle generation.
pub struct AuthenticatedAuthorityRecoveryState {
    accepted_epoch: u64,
    accepted_handle_generation: u32,
    accepted_volume: Option<VolumeId>,
    accepted_root_generation: u64,
}

impl AuthenticatedAuthorityRecoveryState {
    /// # Safety
    ///
    /// Both values must come from authenticated rollback-resistant state for
    /// the same storage authority domain. Missing state must fail closed rather
    /// than being represented as zero by convenience.
    pub const unsafe fn new(accepted_epoch: u64, accepted_handle_generation: u32) -> Self {
        Self {
            accepted_epoch,
            accepted_handle_generation,
            accepted_volume: None,
            accepted_root_generation: 0,
        }
    }

    /// # Safety
    ///
    /// Every value must come from one authenticated rollback-resistant record
    /// for the same storage authority domain.
    pub const unsafe fn new_bound(
        accepted_epoch: u64,
        accepted_handle_generation: u32,
        accepted_volume: VolumeId,
        accepted_root_generation: u64,
    ) -> Self {
        Self {
            accepted_epoch,
            accepted_handle_generation,
            accepted_volume: Some(accepted_volume),
            accepted_root_generation,
        }
    }

    fn decode_authenticated(
        input: &[u8; AUTHORITY_RECOVERY_STATE_BYTES],
    ) -> Result<Self, AuthorityCheckpointError> {
        if input[..16] != RECOVERY_STATE_MAGIC
            || input[28..32].iter().any(|byte| *byte != 0)
            || input[56..].iter().any(|byte| *byte != 0)
        {
            return Err(AuthorityCheckpointError::MalformedRecoveryState);
        }
        let accepted_epoch = u64::from_le_bytes(input[16..24].try_into().unwrap());
        let accepted_handle_generation = u32::from_le_bytes(input[24..28].try_into().unwrap());
        let volume_bytes: [u8; 16] = input[32..48].try_into().unwrap();
        let accepted_root_generation = u64::from_le_bytes(input[48..56].try_into().unwrap());
        if accepted_epoch == 0 || accepted_handle_generation == 0 {
            return Err(AuthorityCheckpointError::MalformedRecoveryState);
        }
        let accepted_volume = if volume_bytes.iter().all(|byte| *byte == 0) {
            if accepted_root_generation != 0 {
                return Err(AuthorityCheckpointError::MalformedRecoveryState);
            }
            None
        } else {
            if accepted_root_generation == 0 {
                return Err(AuthorityCheckpointError::MalformedRecoveryState);
            }
            Some(
                VolumeId::new(volume_bytes)
                    .map_err(|_| AuthorityCheckpointError::MalformedRecoveryState)?,
            )
        };
        Ok(Self {
            accepted_epoch,
            accepted_handle_generation,
            accepted_volume,
            accepted_root_generation,
        })
    }

    fn encode(&self) -> [u8; AUTHORITY_RECOVERY_STATE_BYTES] {
        let mut output = [0; AUTHORITY_RECOVERY_STATE_BYTES];
        output[..16].copy_from_slice(&RECOVERY_STATE_MAGIC);
        output[16..24].copy_from_slice(&self.accepted_epoch.to_le_bytes());
        output[24..28].copy_from_slice(&self.accepted_handle_generation.to_le_bytes());
        if let Some(volume) = self.accepted_volume {
            output[32..48].copy_from_slice(&volume.bytes());
            output[48..56].copy_from_slice(&self.accepted_root_generation.to_le_bytes());
        }
        output
    }
}

/// Exact owner-approved durable-grant policy admitted by trusted recovery.
/// Names, identities, signatures, and checkpoint bytes remain data until this
/// boundary has authenticated the complete policy and selected storage root.
pub struct OwnerApprovedAuthorityCheckpoint {
    epoch: u64,
    volume: VolumeId,
    root_generation: u64,
    handle_generation: u32,
    digest: [u8; DIGEST_BYTES],
}

impl OwnerApprovedAuthorityCheckpoint {
    /// # Safety
    ///
    /// The caller must authenticate explicit owner approval for the complete
    /// durable-grant policy, bind it to the selected reachable volume root and
    /// rollback state, and serialize issuance for this authority domain.
    pub const unsafe fn new(
        epoch: u64,
        volume: VolumeId,
        root_generation: u64,
        handle_generation: u32,
        digest: [u8; DIGEST_BYTES],
    ) -> Self {
        Self {
            epoch,
            volume,
            root_generation,
            handle_generation,
            digest,
        }
    }
}

/// One-use issuer that converts exact canonical bytes plus an owner-approved
/// admission into the non-forgeable proof consumed by reconstruction.
pub struct AuthorityCheckpointProofIssuer {
    admission: Option<OwnerApprovedAuthorityCheckpoint>,
}

impl AuthorityCheckpointProofIssuer {
    pub const fn new(admission: OwnerApprovedAuthorityCheckpoint) -> Self {
        Self {
            admission: Some(admission),
        }
    }

    pub fn issue<const N: usize>(
        &mut self,
        input: &[u8],
    ) -> Result<AuthenticatedAuthorityCheckpoint, AuthorityCheckpointError> {
        let admission = self
            .admission
            .as_ref()
            .ok_or(AuthorityCheckpointError::ProofAlreadyIssued)?;
        let decoded = decode::<N>(input)?;
        if decoded.epoch != admission.epoch
            || decoded.volume != admission.volume
            || decoded.root_generation != admission.root_generation
            || decoded.handle_generation != admission.handle_generation
            || decoded.digest != admission.digest
        {
            return Err(AuthorityCheckpointError::PolicyMismatch);
        }
        let admission = self
            .admission
            .take()
            .ok_or(AuthorityCheckpointError::ProofAlreadyIssued)?;
        Ok(AuthenticatedAuthorityCheckpoint {
            epoch: admission.epoch,
            volume: admission.volume,
            root_generation: admission.root_generation,
            handle_generation: admission.handle_generation,
            digest: admission.digest,
        })
    }

    fn preflight_guard(
        &self,
        guard: &AuthorityRecoveryGuard,
    ) -> Result<(), AuthorityCheckpointError> {
        let admission = self
            .admission
            .as_ref()
            .ok_or(AuthorityCheckpointError::ProofAlreadyIssued)?;
        if admission.epoch == 0
            || admission.handle_generation == 0
            || admission.epoch <= guard.accepted_epoch
            || admission.handle_generation <= guard.accepted_handle_generation
        {
            return Err(AuthorityCheckpointError::AuthenticationMismatch);
        }
        Ok(())
    }

    fn preflight_selection<const E: usize>(
        &self,
        selection: ReachableFileSelection<'_, E>,
    ) -> Result<(), AuthorityCheckpointError> {
        let admission = self
            .admission
            .as_ref()
            .ok_or(AuthorityCheckpointError::ProofAlreadyIssued)?;
        if selection.volume() != admission.volume
            || selection.root_generation() != admission.root_generation
        {
            return Err(AuthorityCheckpointError::AuthenticationMismatch);
        }
        Ok(())
    }
}

/// Exact authenticated recovery authorization. Checkpoint bytes and their
/// digest are data, not authority. Only `AuthorityCheckpointProofIssuer` can
/// construct this consumed, non-clonable proof.
pub struct AuthenticatedAuthorityCheckpoint {
    epoch: u64,
    volume: VolumeId,
    root_generation: u64,
    handle_generation: u32,
    digest: [u8; DIGEST_BYTES],
}

pub struct RecoveredStorageAuthorities<const N: usize> {
    table: StorageAuthorityTable<N>,
    handles: [Option<StorageHandle>; N],
    count: usize,
    epoch: u64,
    volume: VolumeId,
    root_generation: u64,
}

/// Fresh authority released only after its authenticated monotonic recovery
/// state has been atomically advanced. Safe code cannot construct this wrapper
/// around pre-commit reconstruction.
pub struct CommittedRecoveredStorageAuthorities<const N: usize> {
    recovered: RecoveredStorageAuthorities<N>,
}

/// Validation performed against freshly reconstructed authority before its
/// rollback state is committed and before either result is released. An
/// implementation may inspect and use the temporary table only to validate
/// dependent recovery state; it must not persist handles, publish authority,
/// or cause externally visible mutation.
///
/// # Safety
///
/// On every return path, the implementation must leave no usable copy or
/// derivative of the temporary table or handles outside its returned output.
/// The output itself must not carry storage authority. Failure must leave no
/// externally visible state that depends on the uncommitted authority.
pub unsafe trait AuthorityRecoveryValidator<const N: usize> {
    type Output;
    type Error;

    fn validate(
        &mut self,
        recovered: &RecoveredStorageAuthorities<N>,
    ) -> Result<Self::Output, Self::Error>;
}

pub type AuthorityRecoveryValidationResult<
    const N: usize,
    Output,
    StorageError,
    StateError,
    ValidationError,
> = Result<
    (CommittedRecoveredStorageAuthorities<N>, Output),
    AuthorityRecoveryValidationError<StorageError, StateError, ValidationError>,
>;

/// Durable-grant checkpoint staged into one fresh stable-file generation. The
/// successor remains inactive until its exact transaction receipt is consumed.
pub struct PreparedStableAuthorities<const EXTENTS: usize> {
    file: PreparedFileWrite<EXTENTS>,
    checkpoint: AuthorityCheckpoint,
}

impl<const EXTENTS: usize> PreparedStableAuthorities<EXTENTS> {
    pub const fn checkpoint(&self) -> AuthorityCheckpoint {
        self.checkpoint
    }

    pub fn admit<const PARTICIPANTS: usize, const WRITES: usize>(
        &self,
        transaction: &mut StorageTransaction<PARTICIPANTS, WRITES>,
    ) -> Result<(), TransactionError> {
        transaction.admit_file(&self.file)
    }

    pub fn commit<const PARTICIPANTS: usize>(
        self,
        receipt: &mut TransactionReceipt<PARTICIPANTS>,
    ) -> Result<StableAuthorities<EXTENTS>, TransactionError> {
        let file = self.file.commit_transaction(receipt)?;
        Ok(StableAuthorities {
            file,
            checkpoint: self.checkpoint,
        })
    }
}

pub struct StableAuthorities<const EXTENTS: usize> {
    file: FileState<EXTENTS>,
    checkpoint: AuthorityCheckpoint,
}

impl<const EXTENTS: usize> StableAuthorities<EXTENTS> {
    pub const fn file(&self) -> &FileState<EXTENTS> {
        &self.file
    }

    pub const fn checkpoint(&self) -> AuthorityCheckpoint {
        self.checkpoint
    }
}

impl<const N: usize> RecoveredStorageAuthorities<N> {
    pub const fn authority_table(&self) -> &StorageAuthorityTable<N> {
        &self.table
    }

    pub const fn handle(&self, index: usize) -> Option<StorageHandle> {
        if index < self.count {
            self.handles[index]
        } else {
            None
        }
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn volume(&self) -> VolumeId {
        self.volume
    }

    pub const fn root_generation(&self) -> u64 {
        self.root_generation
    }

    pub fn into_parts(
        self,
    ) -> (
        StorageAuthorityTable<N>,
        [Option<StorageHandle>; N],
        usize,
        u64,
    ) {
        (self.table, self.handles, self.count, self.epoch)
    }
}

impl<const N: usize> CommittedRecoveredStorageAuthorities<N> {
    pub const fn authority_table(&self) -> &StorageAuthorityTable<N> {
        self.recovered.authority_table()
    }

    pub const fn handle(&self, index: usize) -> Option<StorageHandle> {
        self.recovered.handle(index)
    }

    pub const fn len(&self) -> usize {
        self.recovered.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.recovered.is_empty()
    }

    pub const fn epoch(&self) -> u64 {
        self.recovered.epoch()
    }

    pub const fn volume(&self) -> VolumeId {
        self.recovered.volume()
    }

    pub const fn root_generation(&self) -> u64 {
        self.recovered.root_generation()
    }

    pub fn into_parts(
        self,
    ) -> (
        StorageAuthorityTable<N>,
        [Option<StorageHandle>; N],
        usize,
        u64,
    ) {
        self.recovered.into_parts()
    }
}

/// Volatile replay guard initialized from authenticated rollback-resistant
/// recovery state. Updating this guard is atomic with successful in-memory
/// reconstruction; persisting it remains the caller's recovery obligation.
pub struct AuthorityRecoveryGuard {
    accepted_epoch: u64,
    accepted_handle_generation: u32,
    accepted_volume: Option<VolumeId>,
    accepted_root_generation: u64,
}

impl AuthorityRecoveryGuard {
    pub const fn from_authenticated_state(state: AuthenticatedAuthorityRecoveryState) -> Self {
        Self {
            accepted_epoch: state.accepted_epoch,
            accepted_handle_generation: state.accepted_handle_generation,
            accepted_volume: state.accepted_volume,
            accepted_root_generation: state.accepted_root_generation,
        }
    }

    pub const fn accepted_epoch(&self) -> u64 {
        self.accepted_epoch
    }

    pub const fn accepted_handle_generation(&self) -> u32 {
        self.accepted_handle_generation
    }

    pub const fn accepted_volume(&self) -> Option<VolumeId> {
        self.accepted_volume
    }

    pub const fn accepted_root_generation(&self) -> u64 {
        self.accepted_root_generation
    }

    pub fn recover<const N: usize>(
        &mut self,
        input: &[u8],
        proof: AuthenticatedAuthorityCheckpoint,
    ) -> Result<RecoveredStorageAuthorities<N>, AuthorityCheckpointError> {
        let decoded = decode::<N>(input)?;
        if decoded.epoch == 0
            || decoded.root_generation == 0
            || decoded.epoch <= self.accepted_epoch
            || decoded.handle_generation == 0
            || decoded.handle_generation <= self.accepted_handle_generation
            || decoded.epoch != proof.epoch
            || decoded.volume != proof.volume
            || decoded.root_generation != proof.root_generation
            || decoded.handle_generation != proof.handle_generation
            || decoded.digest != proof.digest
            || self
                .accepted_volume
                .is_some_and(|volume| volume != decoded.volume)
            || (self.accepted_volume.is_some()
                && decoded.root_generation < self.accepted_root_generation)
        {
            return Err(AuthorityCheckpointError::AuthenticationMismatch);
        }

        let mut table =
            StorageAuthorityTable::<N>::from_recovery_generation(decoded.handle_generation)?;
        let mut handles = [None; N];
        for index in 0..decoded.count {
            let grant = decoded.grants[index].ok_or(AuthorityCheckpointError::Malformed)?;
            let handle = if let Some(parent) = grant.parent {
                let parent_handle = handles[parent].ok_or(AuthorityCheckpointError::Malformed)?;
                let parent_grant =
                    decoded.grants[parent].ok_or(AuthorityCheckpointError::Malformed)?;
                if parent_grant.object != grant.object || parent_grant.kind != grant.kind {
                    return Err(AuthorityCheckpointError::AuthorityAmplification);
                }
                table.derive(
                    parent_handle,
                    parent_grant.principal,
                    grant.principal,
                    grant.rights,
                )?
            } else {
                table.insert(grant.object, grant.kind, grant.rights, grant.principal)?
            };
            handles[index] = Some(handle);
        }
        self.accepted_epoch = decoded.epoch;
        self.accepted_handle_generation = decoded.handle_generation;
        self.accepted_volume = Some(decoded.volume);
        self.accepted_root_generation = decoded.root_generation;
        Ok(RecoveredStorageAuthorities {
            table,
            handles,
            count: decoded.count,
            epoch: decoded.epoch,
            volume: decoded.volume,
            root_generation: decoded.root_generation,
        })
    }
}

pub fn encode_authority_checkpoint(
    epoch: u64,
    volume: VolumeId,
    root_generation: u64,
    handle_generation: u32,
    grants: &[StorageRecoveryGrant],
    output: &mut [u8],
) -> Result<usize, AuthorityCheckpointError> {
    if epoch == 0
        || root_generation == 0
        || handle_generation == 0
        || grants.len() > u16::MAX as usize
    {
        return Err(AuthorityCheckpointError::Malformed);
    }
    let length = checkpoint_length(grants.len())?;
    if output.len() < length {
        return Err(AuthorityCheckpointError::BufferTooSmall);
    }
    for (index, grant) in grants.iter().enumerate() {
        if grant.object.volume() != volume {
            return Err(AuthorityCheckpointError::Malformed);
        }
        validate_grant(grant, index, grants)?;
    }
    output[..length].fill(0);
    output[..4].copy_from_slice(&MAGIC);
    output[4] = VERSION;
    output[6..8].copy_from_slice(&(AUTHORITY_CHECKPOINT_HEADER_BYTES as u16).to_le_bytes());
    output[8..16].copy_from_slice(&epoch.to_le_bytes());
    output[16..32].copy_from_slice(&volume.bytes());
    output[32..40].copy_from_slice(&root_generation.to_le_bytes());
    output[40..42].copy_from_slice(&(grants.len() as u16).to_le_bytes());
    output[42..46].copy_from_slice(&handle_generation.to_le_bytes());

    for (index, grant) in grants.iter().enumerate() {
        let start = AUTHORITY_CHECKPOINT_HEADER_BYTES + index * AUTHORITY_CHECKPOINT_GRANT_BYTES;
        output[start..start + 8].copy_from_slice(&grant.principal.value().to_le_bytes());
        output[start + 8..start + 16].copy_from_slice(&grant.object.local().to_le_bytes());
        output[start + 16] = grant.kind as u8;
        let parent = match grant.parent {
            Some(parent) => {
                u16::try_from(parent + 1).map_err(|_| AuthorityCheckpointError::Malformed)?
            }
            None => 0,
        };
        output[start + 18..start + 20].copy_from_slice(&parent.to_le_bytes());
        output[start + 20..start + 24].copy_from_slice(&grant.rights.bits().to_le_bytes());
    }
    let digest = checkpoint_digest(&output[..length]);
    output[DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_BYTES].copy_from_slice(&digest);
    Ok(length)
}

pub fn authority_checkpoint_digest(
    input: &[u8],
) -> Result<[u8; DIGEST_BYTES], AuthorityCheckpointError> {
    if input.len() < AUTHORITY_CHECKPOINT_HEADER_BYTES {
        return Err(AuthorityCheckpointError::Malformed);
    }
    Ok(checkpoint_digest(input))
}

/// Encodes an explicit owner-approved durable-grant policy and stages it as the
/// complete content of the next capability-authorized stable file generation.
/// The handle-generation value is derived from the live table high-water mark;
/// callers cannot request reuse of an older token generation.
#[allow(clippy::too_many_arguments)]
pub fn prepare_stable_authorities<
    const CURRENT_EXTENTS: usize,
    const NEXT_EXTENTS: usize,
    const AUTHORITIES: usize,
    B: FileWriteBackend,
>(
    epoch: u64,
    root_generation: u64,
    grants: &[StorageRecoveryGrant],
    current_file: &FileState<CURRENT_EXTENTS>,
    storage_authority: &StorageAuthorityTable<AUTHORITIES>,
    file: StorageHandle,
    principal: StoragePrincipal,
    next_extents: ExtentMap<NEXT_EXTENTS>,
    next_metadata: FileMetadata,
    file_metadata_pointer: MetadataPointer,
    protected_metadata: &[MetadataPointer],
    output: &mut [u8],
    backend: &mut B,
) -> Result<PreparedStableAuthorities<NEXT_EXTENTS>, AuthorityStorageError<B::Error>> {
    let length = checkpoint_length(grants.len()).map_err(AuthorityStorageError::Checkpoint)?;
    let checkpoint_length =
        u64::try_from(length).map_err(|_| AuthorityStorageError::InvalidBinding)?;
    let requested = if checkpoint_length == current_file.length() {
        StorageRights::WRITE
    } else {
        StorageRights::WRITE.union(StorageRights::RESIZE)
    };
    let authorized = storage_authority
        .authorize(file, principal, StorageObjectKind::File, requested)
        .map_err(FileWriteError::Authority)
        .map_err(AuthorityStorageError::Write)?;
    if authorized != current_file.object() {
        return Err(AuthorityStorageError::Write(FileWriteError::WrongFile));
    }
    let handle_generation = storage_authority
        .next_recovery_generation()
        .map_err(AuthorityCheckpointError::Authority)
        .map_err(AuthorityStorageError::Checkpoint)?;
    let encoded_length = encode_authority_checkpoint(
        epoch,
        current_file.object().volume(),
        root_generation,
        handle_generation,
        grants,
        output,
    )
    .map_err(AuthorityStorageError::Checkpoint)?;
    if encoded_length != length {
        return Err(AuthorityStorageError::InvalidBinding);
    }
    let digest = checkpoint_digest(&output[..length]);
    let checkpoint = AuthorityCheckpoint {
        length,
        digest,
        epoch,
        root_generation,
        handle_generation,
        grant_count: grants.len(),
    };
    let mut content = Sha3_256::new();
    content.update(&output[..length]);
    if next_metadata.object() != current_file.object()
        || next_metadata.generation() != current_file.generation().checked_add(1).unwrap_or(0)
        || next_metadata.length() != checkpoint_length
        || next_metadata.content_digest() != content.finalize()
    {
        return Err(AuthorityStorageError::InvalidBinding);
    }
    let file = current_file
        .prepare_write(
            storage_authority,
            file,
            principal,
            0,
            &output[..length],
            checkpoint_length,
            next_extents,
            next_metadata,
            file_metadata_pointer,
            protected_metadata,
            backend,
        )
        .map_err(AuthorityStorageError::Write)?;
    Ok(PreparedStableAuthorities { file, checkpoint })
}

/// Reads only the exact checkpoint file generation already selected by
/// authenticated reachable recovery. `bootstrap_authority` is an explicit
/// trusted recovery capability used solely to read this policy file; names and
/// the checkpoint itself cannot manufacture that authority.
#[allow(clippy::too_many_arguments)]
pub fn recover_stable_authorities<
    const GRANTS: usize,
    const EXTENTS: usize,
    const BOOTSTRAP_AUTHORITIES: usize,
    B: FileReadBackend,
>(
    file_state: &FileState<EXTENTS>,
    bootstrap_authority: &StorageAuthorityTable<BOOTSTRAP_AUTHORITIES>,
    file: StorageHandle,
    principal: StoragePrincipal,
    expected_file_generation: u64,
    guard: &mut AuthorityRecoveryGuard,
    issuer: &mut AuthorityCheckpointProofIssuer,
    input: &mut [u8],
    backend: &mut B,
) -> Result<RecoveredStorageAuthorities<GRANTS>, AuthorityStorageError<B::Error>> {
    input.fill(0);
    issuer
        .preflight_guard(guard)
        .map_err(AuthorityStorageError::Checkpoint)?;
    if expected_file_generation == 0 || file_state.generation() != expected_file_generation {
        return Err(AuthorityStorageError::InvalidBinding);
    }
    let maximum = checkpoint_length(GRANTS).map_err(AuthorityStorageError::Checkpoint)?;
    let length = usize::try_from(file_state.length())
        .ok()
        .filter(|length| {
            *length >= AUTHORITY_CHECKPOINT_HEADER_BYTES
                && *length <= input.len()
                && *length <= maximum
        })
        .ok_or(AuthorityStorageError::InvalidBinding)?;
    file_state
        .read(
            bootstrap_authority,
            file,
            principal,
            0,
            &mut input[..length],
            backend,
        )
        .map_err(AuthorityStorageError::Read)?;
    let result = issuer
        .issue::<GRANTS>(&input[..length])
        .and_then(|proof| guard.recover::<GRANTS>(&input[..length], proof))
        .map_err(AuthorityStorageError::Checkpoint);
    input.fill(0);
    result
}

/// Stable authority recovery bound to a file state retained from the exact
/// reachable root authenticated by the owner-approved admission.
#[allow(clippy::too_many_arguments)]
pub fn recover_selected_stable_authorities<
    const GRANTS: usize,
    const EXTENTS: usize,
    const BOOTSTRAP_AUTHORITIES: usize,
    B: FileReadBackend,
>(
    selection: ReachableFileSelection<'_, EXTENTS>,
    bootstrap_authority: &StorageAuthorityTable<BOOTSTRAP_AUTHORITIES>,
    file: StorageHandle,
    principal: StoragePrincipal,
    guard: &mut AuthorityRecoveryGuard,
    issuer: &mut AuthorityCheckpointProofIssuer,
    input: &mut [u8],
    backend: &mut B,
) -> Result<RecoveredStorageAuthorities<GRANTS>, AuthorityStorageError<B::Error>> {
    issuer
        .preflight_selection(selection)
        .map_err(AuthorityStorageError::Checkpoint)?;
    recover_stable_authorities(
        selection.file_state(),
        bootstrap_authority,
        file,
        principal,
        selection.generation(),
        guard,
        issuer,
        input,
        backend,
    )
}

/// Recovers durable grants only after loading authenticated rollback state and
/// atomically advancing it to the accepted checkpoint. Reconstructed handles
/// are not released if the monotonic store reports conflict or uncertainty.
#[allow(clippy::too_many_arguments)]
pub fn recover_stable_authorities_and_commit<
    const GRANTS: usize,
    const EXTENTS: usize,
    const BOOTSTRAP_AUTHORITIES: usize,
    B: FileReadBackend,
    S: AuthorityRecoveryStateStore,
>(
    file_state: &FileState<EXTENTS>,
    bootstrap_authority: &StorageAuthorityTable<BOOTSTRAP_AUTHORITIES>,
    file: StorageHandle,
    principal: StoragePrincipal,
    expected_file_generation: u64,
    issuer: &mut AuthorityCheckpointProofIssuer,
    input: &mut [u8],
    backend: &mut B,
    state_store: &mut S,
) -> Result<
    CommittedRecoveredStorageAuthorities<GRANTS>,
    AuthorityRecoveryCommitError<B::Error, S::Error>,
> {
    let mut encoded_state = [0; AUTHORITY_RECOVERY_STATE_BYTES];
    state_store
        .load_authenticated(&mut encoded_state)
        .map_err(AuthorityRecoveryCommitError::State)?;
    let state = AuthenticatedAuthorityRecoveryState::decode_authenticated(&encoded_state)
        .map_err(AuthorityRecoveryCommitError::Checkpoint)?;
    let mut guard = AuthorityRecoveryGuard::from_authenticated_state(state);
    let recovered = recover_stable_authorities(
        file_state,
        bootstrap_authority,
        file,
        principal,
        expected_file_generation,
        &mut guard,
        issuer,
        input,
        backend,
    )
    .map_err(AuthorityRecoveryCommitError::Storage)?;
    let replacement = AuthenticatedAuthorityRecoveryState {
        accepted_epoch: guard.accepted_epoch,
        accepted_handle_generation: guard.accepted_handle_generation,
        accepted_volume: guard.accepted_volume,
        accepted_root_generation: guard.accepted_root_generation,
    }
    .encode();
    state_store
        .compare_and_store(&encoded_state, &replacement)
        .map_err(AuthorityRecoveryCommitError::State)?;
    Ok(CommittedRecoveredStorageAuthorities { recovered })
}

#[allow(clippy::too_many_arguments)]
pub fn recover_selected_stable_authorities_and_commit<
    const GRANTS: usize,
    const EXTENTS: usize,
    const BOOTSTRAP_AUTHORITIES: usize,
    B: FileReadBackend,
    S: AuthorityRecoveryStateStore,
>(
    selection: ReachableFileSelection<'_, EXTENTS>,
    bootstrap_authority: &StorageAuthorityTable<BOOTSTRAP_AUTHORITIES>,
    file: StorageHandle,
    principal: StoragePrincipal,
    issuer: &mut AuthorityCheckpointProofIssuer,
    input: &mut [u8],
    backend: &mut B,
    state_store: &mut S,
) -> Result<
    CommittedRecoveredStorageAuthorities<GRANTS>,
    AuthorityRecoveryCommitError<B::Error, S::Error>,
> {
    issuer
        .preflight_selection(selection)
        .map_err(AuthorityRecoveryCommitError::Checkpoint)?;
    recover_stable_authorities_and_commit(
        selection.file_state(),
        bootstrap_authority,
        file,
        principal,
        selection.generation(),
        issuer,
        input,
        backend,
        state_store,
    )
}

/// Reconstructs authority into private temporary state, validates dependent
/// recovery through that state, and atomically advances authenticated rollback
/// state before releasing either result. Validation failure or uncertain state
/// persistence drops both temporary results and leaves the prior accepted state
/// unchanged.
#[allow(clippy::too_many_arguments)]
pub fn recover_validate_and_commit_stable_authorities<
    const GRANTS: usize,
    const EXTENTS: usize,
    const BOOTSTRAP_AUTHORITIES: usize,
    B: FileReadBackend,
    S: AuthorityRecoveryStateStore,
    V: AuthorityRecoveryValidator<GRANTS>,
>(
    file_state: &FileState<EXTENTS>,
    bootstrap_authority: &StorageAuthorityTable<BOOTSTRAP_AUTHORITIES>,
    file: StorageHandle,
    principal: StoragePrincipal,
    expected_file_generation: u64,
    issuer: &mut AuthorityCheckpointProofIssuer,
    input: &mut [u8],
    backend: &mut B,
    state_store: &mut S,
    validator: &mut V,
) -> AuthorityRecoveryValidationResult<GRANTS, V::Output, B::Error, S::Error, V::Error> {
    let mut encoded_state = [0; AUTHORITY_RECOVERY_STATE_BYTES];
    state_store
        .load_authenticated(&mut encoded_state)
        .map_err(AuthorityRecoveryValidationError::State)?;
    let state = AuthenticatedAuthorityRecoveryState::decode_authenticated(&encoded_state)
        .map_err(AuthorityRecoveryValidationError::Checkpoint)?;
    let mut guard = AuthorityRecoveryGuard::from_authenticated_state(state);
    let recovered = recover_stable_authorities(
        file_state,
        bootstrap_authority,
        file,
        principal,
        expected_file_generation,
        &mut guard,
        issuer,
        input,
        backend,
    )
    .map_err(AuthorityRecoveryValidationError::Storage)?;
    let validated = validator
        .validate(&recovered)
        .map_err(AuthorityRecoveryValidationError::Validation)?;
    let replacement = AuthenticatedAuthorityRecoveryState {
        accepted_epoch: guard.accepted_epoch,
        accepted_handle_generation: guard.accepted_handle_generation,
        accepted_volume: guard.accepted_volume,
        accepted_root_generation: guard.accepted_root_generation,
    }
    .encode();
    state_store
        .compare_and_store(&encoded_state, &replacement)
        .map_err(AuthorityRecoveryValidationError::State)?;
    Ok((
        CommittedRecoveredStorageAuthorities { recovered },
        validated,
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn recover_selected_validate_and_commit_stable_authorities<
    const GRANTS: usize,
    const EXTENTS: usize,
    const BOOTSTRAP_AUTHORITIES: usize,
    B: FileReadBackend,
    S: AuthorityRecoveryStateStore,
    V: AuthorityRecoveryValidator<GRANTS>,
>(
    selection: ReachableFileSelection<'_, EXTENTS>,
    bootstrap_authority: &StorageAuthorityTable<BOOTSTRAP_AUTHORITIES>,
    file: StorageHandle,
    principal: StoragePrincipal,
    issuer: &mut AuthorityCheckpointProofIssuer,
    input: &mut [u8],
    backend: &mut B,
    state_store: &mut S,
    validator: &mut V,
) -> AuthorityRecoveryValidationResult<GRANTS, V::Output, B::Error, S::Error, V::Error> {
    issuer
        .preflight_selection(selection)
        .map_err(AuthorityRecoveryValidationError::Checkpoint)?;
    recover_validate_and_commit_stable_authorities(
        selection.file_state(),
        bootstrap_authority,
        file,
        principal,
        selection.generation(),
        issuer,
        input,
        backend,
        state_store,
        validator,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityStorageError<E> {
    Checkpoint(AuthorityCheckpointError),
    InvalidBinding,
    Read(FileReadError<E>),
    Write(FileWriteError<E>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityRecoveryCommitError<StorageError, StateError> {
    Checkpoint(AuthorityCheckpointError),
    State(StateError),
    Storage(AuthorityStorageError<StorageError>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityRecoveryValidationError<StorageError, StateError, ValidationError> {
    Checkpoint(AuthorityCheckpointError),
    State(StateError),
    Storage(AuthorityStorageError<StorageError>),
    Validation(ValidationError),
}

struct Decoded<const N: usize> {
    epoch: u64,
    volume: VolumeId,
    root_generation: u64,
    handle_generation: u32,
    digest: [u8; DIGEST_BYTES],
    grants: [Option<StorageRecoveryGrant>; N],
    count: usize,
}

fn decode<const N: usize>(input: &[u8]) -> Result<Decoded<N>, AuthorityCheckpointError> {
    if input.len() < AUTHORITY_CHECKPOINT_HEADER_BYTES
        || input[..4] != MAGIC
        || input[4] != VERSION
        || input[5] != 0
        || u16::from_le_bytes([input[6], input[7]]) as usize != AUTHORITY_CHECKPOINT_HEADER_BYTES
        || input[46..48].iter().any(|byte| *byte != 0)
    {
        return Err(AuthorityCheckpointError::Malformed);
    }
    let count = u16::from_le_bytes([input[40], input[41]]) as usize;
    if count > N || input.len() != checkpoint_length(count)? {
        return Err(AuthorityCheckpointError::CapacityMismatch);
    }
    let digest: [u8; DIGEST_BYTES] = input[DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_BYTES]
        .try_into()
        .map_err(|_| AuthorityCheckpointError::Malformed)?;
    if checkpoint_digest(input) != digest {
        return Err(AuthorityCheckpointError::DigestMismatch);
    }
    let volume = VolumeId::new(
        input[16..32]
            .try_into()
            .map_err(|_| AuthorityCheckpointError::Malformed)?,
    )?;
    let epoch = u64::from_le_bytes(
        input[8..16]
            .try_into()
            .map_err(|_| AuthorityCheckpointError::Malformed)?,
    );
    let root_generation = u64::from_le_bytes(
        input[32..40]
            .try_into()
            .map_err(|_| AuthorityCheckpointError::Malformed)?,
    );
    let handle_generation = u32::from_le_bytes(
        input[42..46]
            .try_into()
            .map_err(|_| AuthorityCheckpointError::Malformed)?,
    );
    let mut grants: [Option<StorageRecoveryGrant>; N] = array::from_fn(|_| None);
    for index in 0..count {
        let start = AUTHORITY_CHECKPOINT_HEADER_BYTES + index * AUTHORITY_CHECKPOINT_GRANT_BYTES;
        if input[start + 17] != 0 || input[start + 24..start + 48].iter().any(|byte| *byte != 0) {
            return Err(AuthorityCheckpointError::Malformed);
        }
        let principal = StoragePrincipal::new(u64::from_le_bytes(
            input[start..start + 8]
                .try_into()
                .map_err(|_| AuthorityCheckpointError::Malformed)?,
        ))?;
        let object = StorageObjectId::new(
            volume,
            u64::from_le_bytes(
                input[start + 8..start + 16]
                    .try_into()
                    .map_err(|_| AuthorityCheckpointError::Malformed)?,
            ),
        )?;
        let kind = match input[start + 16] {
            1 => StorageObjectKind::Volume,
            2 => StorageObjectKind::Directory,
            3 => StorageObjectKind::File,
            _ => return Err(AuthorityCheckpointError::Malformed),
        };
        let rights = StorageRights::from_bits(
            kind,
            u32::from_le_bytes(
                input[start + 20..start + 24]
                    .try_into()
                    .map_err(|_| AuthorityCheckpointError::Malformed)?,
            ),
        )?;
        let encoded_parent = u16::from_le_bytes([input[start + 18], input[start + 19]]) as usize;
        let parent = if encoded_parent == 0 {
            None
        } else {
            Some(encoded_parent - 1)
        };
        let grant = StorageRecoveryGrant {
            principal,
            object,
            kind,
            rights,
            parent,
        };
        validate_grant(&grant, index, &grants[..index])?;
        grants[index] = Some(grant);
    }
    Ok(Decoded {
        epoch,
        volume,
        root_generation,
        handle_generation,
        digest,
        grants,
        count,
    })
}

fn validate_grant(
    grant: &StorageRecoveryGrant,
    index: usize,
    grants: &[impl GrantEntry],
) -> Result<(), AuthorityCheckpointError> {
    StorageRights::from_bits(grant.kind, grant.rights.bits())?;
    if let Some(parent) = grant.parent {
        if parent >= index {
            return Err(AuthorityCheckpointError::InvalidLineage);
        }
        let parent_grant = grants[parent]
            .grant()
            .ok_or(AuthorityCheckpointError::InvalidLineage)?;
        if parent_grant.object != grant.object
            || parent_grant.kind != grant.kind
            || !parent_grant.rights.contains(StorageRights::DELEGATE)
            || !parent_grant.rights.contains(grant.rights)
        {
            return Err(AuthorityCheckpointError::AuthorityAmplification);
        }
    }
    Ok(())
}

trait GrantEntry {
    fn grant(&self) -> Option<&StorageRecoveryGrant>;
}

impl GrantEntry for StorageRecoveryGrant {
    fn grant(&self) -> Option<&StorageRecoveryGrant> {
        Some(self)
    }
}

impl GrantEntry for Option<StorageRecoveryGrant> {
    fn grant(&self) -> Option<&StorageRecoveryGrant> {
        self.as_ref()
    }
}

fn checkpoint_length(count: usize) -> Result<usize, AuthorityCheckpointError> {
    AUTHORITY_CHECKPOINT_HEADER_BYTES
        .checked_add(
            count
                .checked_mul(AUTHORITY_CHECKPOINT_GRANT_BYTES)
                .ok_or(AuthorityCheckpointError::Malformed)?,
        )
        .ok_or(AuthorityCheckpointError::Malformed)
}

fn checkpoint_digest(input: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut digest = Sha3_256::new();
    digest.update(&input[..DIGEST_OFFSET]);
    digest.update(&[0; DIGEST_BYTES]);
    digest.update(&input[DIGEST_OFFSET + DIGEST_BYTES..]);
    digest.finalize()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityCheckpointError {
    BufferTooSmall,
    Malformed,
    CapacityMismatch,
    DigestMismatch,
    AuthenticationMismatch,
    PolicyMismatch,
    ProofAlreadyIssued,
    MalformedRecoveryState,
    InvalidLineage,
    AuthorityAmplification,
    Authority(StorageAuthorityError),
}

impl From<StorageAuthorityError> for AuthorityCheckpointError {
    fn from(value: StorageAuthorityError) -> Self {
        Self::Authority(value)
    }
}

impl From<crate::StorageIdentityError> for AuthorityCheckpointError {
    fn from(_: crate::StorageIdentityError) -> Self {
        Self::Malformed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CowMetadataImage, CowMetadataWrite, CowPublicationBackend, CowPublicationPlan,
        ExtentRecord, StorageTransactionId, Superblock, VolumeHeader,
    };

    fn volume() -> VolumeId {
        VolumeId::new([0x41; 16]).unwrap()
    }

    fn object(local: u64) -> StorageObjectId {
        StorageObjectId::new(volume(), local).unwrap()
    }

    fn principal(value: u64) -> StoragePrincipal {
        StoragePrincipal::new(value).unwrap()
    }

    const BLOCK_BYTES: usize = 4096;

    fn header() -> VolumeHeader {
        VolumeHeader::new(volume(), BLOCK_BYTES as u32, 100, 1, 2).unwrap()
    }

    fn digest(bytes: &[u8]) -> [u8; 32] {
        let mut digest = Sha3_256::new();
        digest.update(bytes);
        digest.finalize()
    }

    struct StableBackend {
        bytes: [u8; BLOCK_BYTES],
        writes: usize,
        reads: usize,
        fail_read: bool,
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
            if file != object(90)
                || old_generation != 1
                || old_length != 0
                || next.physical_block() != Some(10)
                || patch_offset != 0
                || usize::try_from(new_length).ok() != Some(patch.len())
            {
                return Err(1);
            }
            self.bytes.fill(0);
            self.bytes[..patch.len()].copy_from_slice(patch);
            if next.content_digest() != digest(&self.bytes) {
                return Err(2);
            }
            self.writes += 1;
            Ok(())
        }

        fn flush_new_file_data(
            &mut self,
            file: StorageObjectId,
            generation: u64,
            length: u64,
            content_digest: [u8; 32],
        ) -> Result<(), Self::Error> {
            let length = usize::try_from(length).map_err(|_| 3)?;
            if file != object(90)
                || generation != 2
                || content_digest != digest(&self.bytes[..length])
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
            self.reads += 1;
            if self.fail_read || record.content_digest() != digest(&self.bytes) {
                return Err(4);
            }
            let start = usize::try_from(byte_offset).map_err(|_| 4)?;
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
            _: &[u8; crate::SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            (block == 2).then_some(()).ok_or(())
        }
        fn flush_superblock(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct RecoveryStateBackend {
        state: [u8; AUTHORITY_RECOVERY_STATE_BYTES],
        fail_load: bool,
        force_conflict: bool,
    }

    struct DependentValidator {
        fail: bool,
        calls: usize,
    }

    unsafe impl<const N: usize> AuthorityRecoveryValidator<N> for DependentValidator {
        type Output = StorageObjectId;
        type Error = u8;

        fn validate(
            &mut self,
            recovered: &RecoveredStorageAuthorities<N>,
        ) -> Result<Self::Output, Self::Error> {
            self.calls += 1;
            let handle = recovered.handle(0).ok_or(1)?;
            let object = recovered
                .authority_table()
                .authorize(
                    handle,
                    principal(11),
                    StorageObjectKind::Directory,
                    StorageRights::OPEN_CHILD,
                )
                .map_err(|_| 2)?;
            if self.fail {
                return Err(3);
            }
            Ok(object)
        }
    }

    impl RecoveryStateBackend {
        fn new(epoch: u64, handle_generation: u32) -> Self {
            Self {
                state: AuthenticatedAuthorityRecoveryState {
                    accepted_epoch: epoch,
                    accepted_handle_generation: handle_generation,
                    accepted_volume: None,
                    accepted_root_generation: 0,
                }
                .encode(),
                fail_load: false,
                force_conflict: false,
            }
        }
    }

    impl AuthorityRecoveryStateStore for RecoveryStateBackend {
        type Error = u8;

        fn load_authenticated(
            &self,
            output: &mut [u8; AUTHORITY_RECOVERY_STATE_BYTES],
        ) -> Result<(), Self::Error> {
            if self.fail_load {
                return Err(1);
            }
            output.copy_from_slice(&self.state);
            Ok(())
        }

        fn compare_and_store(
            &mut self,
            expected: &[u8; AUTHORITY_RECOVERY_STATE_BYTES],
            replacement: &[u8; AUTHORITY_RECOVERY_STATE_BYTES],
        ) -> Result<(), Self::Error> {
            if self.force_conflict || self.state != *expected {
                return Err(3);
            }
            self.state.copy_from_slice(replacement);
            Ok(())
        }
    }

    fn stable_layout(
        checkpoint: &[u8],
    ) -> (
        FileState<0>,
        ExtentMap<1>,
        FileMetadata,
        [CowMetadataImage; 2],
    ) {
        let header = header();
        let current_extents = ExtentMap::<0>::build(header, object(90), 1, 0, &[]).unwrap();
        let current = FileState::new(object(90), 1, 0, current_extents).unwrap();
        let mut block = [0; BLOCK_BYTES];
        block[..checkpoint.len()].copy_from_slice(checkpoint);
        let record = ExtentRecord::data(object(90), 2, 0, 1, 10, digest(&block)).unwrap();
        let next =
            ExtentMap::build(header, object(90), 2, checkpoint.len() as u64, &[record]).unwrap();
        let metadata = FileMetadata::new(
            header,
            object(90),
            2,
            checkpoint.len() as u64,
            1,
            MetadataPointer::new(20, 1).unwrap(),
            digest(checkpoint),
        )
        .unwrap();
        let mut encoded_metadata = [0; BLOCK_BYTES];
        metadata.encode(
            (&mut encoded_metadata[..crate::FILE_METADATA_BYTES])
                .try_into()
                .unwrap(),
        );
        let mut encoded_extents = [0; BLOCK_BYTES];
        record.encode(
            (&mut encoded_extents[..crate::EXTENT_RECORD_BYTES])
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

    fn proof(
        bytes: &[u8],
        epoch: u64,
        root_generation: u64,
        handle_generation: u32,
    ) -> AuthenticatedAuthorityCheckpoint {
        let digest = authority_checkpoint_digest(bytes).unwrap();
        let admission = unsafe {
            OwnerApprovedAuthorityCheckpoint::new(
                epoch,
                volume(),
                root_generation,
                handle_generation,
                digest,
            )
        };
        AuthorityCheckpointProofIssuer::new(admission)
            .issue::<16>(bytes)
            .unwrap()
    }

    fn guard(epoch: u64, handle_generation: u32) -> AuthorityRecoveryGuard {
        let state = unsafe { AuthenticatedAuthorityRecoveryState::new(epoch, handle_generation) };
        AuthorityRecoveryGuard::from_authenticated_state(state)
    }

    #[test]
    fn stable_checkpoint_publishes_once_and_recovers_only_selected_generation() {
        let grants = [StorageRecoveryGrant::root(
            principal(11),
            object(7),
            StorageObjectKind::Directory,
            StorageRights::LOOKUP.union(StorageRights::OPEN_CHILD),
        )];
        let mut authority = StorageAuthorityTable::<2>::new();
        let file = authority
            .insert(
                object(90),
                StorageObjectKind::File,
                StorageRights::READ
                    .union(StorageRights::WRITE)
                    .union(StorageRights::RESIZE),
                principal(7),
            )
            .unwrap();
        let mut expected =
            [0; AUTHORITY_CHECKPOINT_HEADER_BYTES + AUTHORITY_CHECKPOINT_GRANT_BYTES];
        encode_authority_checkpoint(9, volume(), 14, 2, &grants, &mut expected).unwrap();
        let (current, next, metadata, images) = stable_layout(&expected);
        let mut backend = StableBackend {
            bytes: [0; BLOCK_BYTES],
            writes: 0,
            reads: 0,
            fail_read: false,
        };
        let (denied_current, denied_next, denied_metadata, _) = stable_layout(&expected);
        let mut denied_authority = StorageAuthorityTable::<1>::new();
        let denied_file = denied_authority
            .insert(
                object(90),
                StorageObjectKind::File,
                StorageRights::WRITE,
                principal(7),
            )
            .unwrap();
        let mut denied_output = [0xa5; 256];
        assert!(matches!(
            prepare_stable_authorities(
                9,
                14,
                &grants,
                &denied_current,
                &denied_authority,
                denied_file,
                principal(7),
                denied_next,
                denied_metadata,
                MetadataPointer::new(21, 1).unwrap(),
                &[],
                &mut denied_output,
                &mut backend,
            ),
            Err(AuthorityStorageError::Write(FileWriteError::Authority(_)))
        ));
        assert!(denied_output.iter().all(|byte| *byte == 0xa5));
        assert_eq!(backend.writes, 0);

        let mut output = [0xa5; 256];
        let prepared = prepare_stable_authorities(
            9,
            14,
            &grants,
            &current,
            &authority,
            file,
            principal(7),
            next,
            metadata,
            MetadataPointer::new(21, 1).unwrap(),
            &[],
            &mut output,
            &mut backend,
        )
        .unwrap();
        assert_eq!(
            prepared.checkpoint().digest(),
            authority_checkpoint_digest(&expected).unwrap()
        );
        assert_eq!(prepared.checkpoint().handle_generation(), 2);
        assert_eq!(backend.writes, 1);

        let mut transaction =
            StorageTransaction::<1, 2>::new(StorageTransactionId::new(80).unwrap(), 2).unwrap();
        prepared.admit(&mut transaction).unwrap();
        let mut receipt = transaction
            .publish(&publication_plan(images), &mut PublicationBackend)
            .unwrap();
        let stable = prepared.commit(&mut receipt).unwrap();
        assert_eq!(receipt.remaining(), 0);
        assert_eq!(stable.file().generation(), 2);
        assert_eq!(stable.checkpoint().epoch(), 9);

        let mut guard = guard(8, 1);
        let admission = unsafe {
            OwnerApprovedAuthorityCheckpoint::new(
                9,
                volume(),
                14,
                2,
                authority_checkpoint_digest(&expected).unwrap(),
            )
        };
        let mut issuer = AuthorityCheckpointProofIssuer::new(admission);
        let mut recovered_bytes = [0xa5; 256];
        assert_eq!(
            recover_stable_authorities::<2, _, _, _>(
                stable.file(),
                &authority,
                file,
                principal(7),
                1,
                &mut guard,
                &mut issuer,
                &mut recovered_bytes,
                &mut backend,
            )
            .map(|_| ()),
            Err(AuthorityStorageError::InvalidBinding)
        );
        assert_eq!((guard.accepted_epoch(), backend.reads), (8, 0));
        assert!(recovered_bytes.iter().all(|byte| *byte == 0));

        backend.fail_read = true;
        assert!(matches!(
            recover_stable_authorities::<2, _, _, _>(
                stable.file(),
                &authority,
                file,
                principal(7),
                2,
                &mut guard,
                &mut issuer,
                &mut recovered_bytes,
                &mut backend,
            ),
            Err(AuthorityStorageError::Read(FileReadError::Backend(4)))
        ));
        assert_eq!(guard.accepted_epoch(), 8);
        assert!(recovered_bytes.iter().all(|byte| *byte == 0));
        backend.fail_read = false;
        let admission = unsafe {
            OwnerApprovedAuthorityCheckpoint::new(
                9,
                volume(),
                14,
                2,
                authority_checkpoint_digest(&expected).unwrap(),
            )
        };
        let mut issuer = AuthorityCheckpointProofIssuer::new(admission);
        let mut recovery_state = RecoveryStateBackend::new(8, 1);
        recovery_state.force_conflict = true;
        assert!(matches!(
            recover_stable_authorities_and_commit::<2, _, _, _, _>(
                stable.file(),
                &authority,
                file,
                principal(7),
                2,
                &mut issuer,
                &mut recovered_bytes,
                &mut backend,
                &mut recovery_state,
            ),
            Err(AuthorityRecoveryCommitError::State(3))
        ));
        let unchanged =
            AuthenticatedAuthorityRecoveryState::decode_authenticated(&recovery_state.state)
                .unwrap();
        assert_eq!(
            (
                unchanged.accepted_epoch,
                unchanged.accepted_handle_generation
            ),
            (8, 1)
        );

        let admission = unsafe {
            OwnerApprovedAuthorityCheckpoint::new(
                9,
                volume(),
                14,
                2,
                authority_checkpoint_digest(&expected).unwrap(),
            )
        };
        let mut issuer = AuthorityCheckpointProofIssuer::new(admission);
        recovery_state.force_conflict = false;
        let mut validator = DependentValidator {
            fail: true,
            calls: 0,
        };
        assert!(matches!(
            recover_validate_and_commit_stable_authorities::<2, _, _, _, _, _>(
                stable.file(),
                &authority,
                file,
                principal(7),
                2,
                &mut issuer,
                &mut recovered_bytes,
                &mut backend,
                &mut recovery_state,
                &mut validator,
            ),
            Err(AuthorityRecoveryValidationError::Validation(3))
        ));
        assert_eq!(validator.calls, 1);
        let unchanged =
            AuthenticatedAuthorityRecoveryState::decode_authenticated(&recovery_state.state)
                .unwrap();
        assert_eq!(
            (
                unchanged.accepted_epoch,
                unchanged.accepted_handle_generation
            ),
            (8, 1)
        );

        let admission = unsafe {
            OwnerApprovedAuthorityCheckpoint::new(
                9,
                volume(),
                14,
                2,
                authority_checkpoint_digest(&expected).unwrap(),
            )
        };
        let mut issuer = AuthorityCheckpointProofIssuer::new(admission);
        validator.fail = false;
        recovery_state.force_conflict = true;
        assert!(matches!(
            recover_validate_and_commit_stable_authorities::<2, _, _, _, _, _>(
                stable.file(),
                &authority,
                file,
                principal(7),
                2,
                &mut issuer,
                &mut recovered_bytes,
                &mut backend,
                &mut recovery_state,
                &mut validator,
            ),
            Err(AuthorityRecoveryValidationError::State(3))
        ));
        assert_eq!(validator.calls, 2);
        let unchanged =
            AuthenticatedAuthorityRecoveryState::decode_authenticated(&recovery_state.state)
                .unwrap();
        assert_eq!(
            (
                unchanged.accepted_epoch,
                unchanged.accepted_handle_generation
            ),
            (8, 1)
        );

        let admission = unsafe {
            OwnerApprovedAuthorityCheckpoint::new(
                9,
                volume(),
                14,
                2,
                authority_checkpoint_digest(&expected).unwrap(),
            )
        };
        let mut issuer = AuthorityCheckpointProofIssuer::new(admission);
        recovery_state.force_conflict = false;
        let (recovered, validated) =
            recover_validate_and_commit_stable_authorities::<2, _, _, _, _, _>(
                stable.file(),
                &authority,
                file,
                principal(7),
                2,
                &mut issuer,
                &mut recovered_bytes,
                &mut backend,
                &mut recovery_state,
                &mut validator,
            )
            .unwrap();
        assert_eq!(validated, object(7));
        assert_eq!(validator.calls, 3);
        let committed =
            AuthenticatedAuthorityRecoveryState::decode_authenticated(&recovery_state.state)
                .unwrap();
        assert_eq!(
            (
                committed.accepted_epoch,
                committed.accepted_handle_generation,
                committed.accepted_volume,
                committed.accepted_root_generation,
            ),
            (9, 2, Some(volume()), 14)
        );
        let (table, handles, count, _) = recovered.into_parts();
        assert!(recovered_bytes.iter().all(|byte| *byte == 0));
        assert_eq!(count, 1);
        assert_eq!(
            table.authorize(
                handles[0].unwrap(),
                principal(11),
                StorageObjectKind::Directory,
                StorageRights::OPEN_CHILD,
            ),
            Ok(object(7))
        );
    }

    #[test]
    fn authenticated_recovery_state_rejects_corruption_and_store_conflict() {
        let mut malformed = RecoveryStateBackend::new(8, 1).state;
        malformed[28] = 1;
        assert!(matches!(
            AuthenticatedAuthorityRecoveryState::decode_authenticated(&malformed),
            Err(AuthorityCheckpointError::MalformedRecoveryState)
        ));
        malformed = RecoveryStateBackend::new(8, 1).state;
        malformed[48..56].copy_from_slice(&7u64.to_le_bytes());
        assert!(matches!(
            AuthenticatedAuthorityRecoveryState::decode_authenticated(&malformed),
            Err(AuthorityCheckpointError::MalformedRecoveryState)
        ));
        malformed = RecoveryStateBackend::new(8, 1).state;
        malformed[16..24].fill(0);
        assert!(matches!(
            AuthenticatedAuthorityRecoveryState::decode_authenticated(&malformed),
            Err(AuthorityCheckpointError::MalformedRecoveryState)
        ));

        let mut store = RecoveryStateBackend::new(8, 1);
        store.force_conflict = true;
        let replacement = AuthenticatedAuthorityRecoveryState {
            accepted_epoch: 9,
            accepted_handle_generation: 2,
            accepted_volume: Some(volume()),
            accepted_root_generation: 14,
        }
        .encode();
        let expected = RecoveryStateBackend::new(8, 1).state;
        assert_eq!(store.compare_and_store(&expected, &replacement), Err(3));
        let current =
            AuthenticatedAuthorityRecoveryState::decode_authenticated(&store.state).unwrap();
        assert_eq!(
            (current.accepted_epoch, current.accepted_handle_generation),
            (8, 1)
        );
    }

    #[test]
    fn authenticated_checkpoint_reconstructs_fresh_attenuated_lineage() {
        let root_rights = StorageRights::READ
            .union(StorageRights::WRITE)
            .union(StorageRights::DELEGATE);
        let grants = [
            StorageRecoveryGrant::root(
                principal(1),
                object(7),
                StorageObjectKind::File,
                root_rights,
            ),
            StorageRecoveryGrant::derived(
                principal(2),
                object(7),
                StorageObjectKind::File,
                StorageRights::READ.union(StorageRights::DELEGATE),
                0,
            ),
            StorageRecoveryGrant::derived(
                principal(3),
                object(7),
                StorageObjectKind::File,
                StorageRights::READ,
                1,
            ),
        ];
        let mut encoded =
            [0xa5; AUTHORITY_CHECKPOINT_HEADER_BYTES + 3 * AUTHORITY_CHECKPOINT_GRANT_BYTES];
        let length =
            encode_authority_checkpoint(9, volume(), 14, 20, &grants, &mut encoded).unwrap();
        assert_eq!(length, encoded.len());
        let mut guard = guard(8, 19);
        let recovered = guard
            .recover::<4>(&encoded, proof(&encoded, 9, 14, 20))
            .unwrap();
        assert_eq!(recovered.volume(), volume());
        assert_eq!(recovered.root_generation(), 14);
        let (mut table, handles, count, epoch) = recovered.into_parts();
        assert_eq!((count, epoch, guard.accepted_epoch()), (3, 9, 9));
        assert_eq!(guard.accepted_handle_generation(), 20);
        assert_eq!(
            table.authorize(
                handles[2].unwrap(),
                principal(3),
                StorageObjectKind::File,
                StorageRights::READ,
            ),
            Ok(object(7))
        );
        assert_eq!(table.revoke(handles[0].unwrap(), principal(1)), Ok(3));
        assert_eq!(table.next_recovery_generation(), Ok(22));
        assert_eq!(
            table.authorize(
                handles[2].unwrap(),
                principal(3),
                StorageObjectKind::File,
                StorageRights::READ,
            ),
            Err(StorageAuthorityError::InvalidHandle)
        );

        let stale = handles[2].unwrap();
        encode_authority_checkpoint(10, volume(), 15, 22, &grants, &mut encoded).unwrap();
        let recovered = guard
            .recover::<4>(&encoded, proof(&encoded, 10, 15, 22))
            .unwrap();
        let (next_table, next_handles, _, _) = recovered.into_parts();
        assert_ne!(stale.token(), next_handles[2].unwrap().token());
        assert_eq!(
            next_table.authorize(
                stale,
                principal(3),
                StorageObjectKind::File,
                StorageRights::READ,
            ),
            Err(StorageAuthorityError::InvalidHandle)
        );
    }

    #[test]
    fn authenticated_guard_rejects_root_regression_and_cross_volume_substitution() {
        let state = unsafe { AuthenticatedAuthorityRecoveryState::new_bound(8, 19, volume(), 14) };
        let mut guard = AuthorityRecoveryGuard::from_authenticated_state(state);
        let mut encoded = [0; AUTHORITY_CHECKPOINT_HEADER_BYTES];
        encode_authority_checkpoint(9, volume(), 13, 20, &[], &mut encoded).unwrap();
        assert!(matches!(
            guard.recover::<1>(&encoded, proof(&encoded, 9, 13, 20)),
            Err(AuthorityCheckpointError::AuthenticationMismatch)
        ));

        let other_volume = VolumeId::new([8; 16]).unwrap();
        encode_authority_checkpoint(9, other_volume, 15, 20, &[], &mut encoded).unwrap();
        let admission = unsafe {
            OwnerApprovedAuthorityCheckpoint::new(
                9,
                other_volume,
                15,
                20,
                authority_checkpoint_digest(&encoded).unwrap(),
            )
        };
        let proof = AuthorityCheckpointProofIssuer::new(admission)
            .issue::<1>(&encoded)
            .unwrap();
        assert!(matches!(
            guard.recover::<1>(&encoded, proof),
            Err(AuthorityCheckpointError::AuthenticationMismatch)
        ));
        assert_eq!(guard.accepted_epoch(), 8);
        assert_eq!(guard.accepted_handle_generation(), 19);
        assert_eq!(guard.accepted_volume(), Some(volume()));
        assert_eq!(guard.accepted_root_generation(), 14);
    }

    #[test]
    fn corruption_substitution_and_replay_never_advance_guard() {
        let grants = [StorageRecoveryGrant::root(
            principal(1),
            object(2),
            StorageObjectKind::Directory,
            StorageRights::LOOKUP,
        )];
        let mut encoded = [0; AUTHORITY_CHECKPOINT_HEADER_BYTES + AUTHORITY_CHECKPOINT_GRANT_BYTES];
        encode_authority_checkpoint(5, volume(), 6, 30, &grants, &mut encoded).unwrap();
        let digest = authority_checkpoint_digest(&encoded).unwrap();
        let mut corrupt = encoded;
        corrupt[AUTHORITY_CHECKPOINT_HEADER_BYTES + 8] ^= 1;
        let mut guard = guard(4, 29);
        let admission =
            unsafe { OwnerApprovedAuthorityCheckpoint::new(5, volume(), 6, 30, digest) };
        let mut corrupt_issuer = AuthorityCheckpointProofIssuer::new(admission);
        assert_eq!(
            corrupt_issuer.issue::<2>(&corrupt).map(|_| ()),
            Err(AuthorityCheckpointError::DigestMismatch)
        );
        assert_eq!(guard.accepted_epoch(), 4);

        let wrong_root =
            unsafe { OwnerApprovedAuthorityCheckpoint::new(5, volume(), 7, 30, digest) };
        let mut wrong_root_issuer = AuthorityCheckpointProofIssuer::new(wrong_root);
        assert_eq!(
            wrong_root_issuer.issue::<2>(&encoded).map(|_| ()),
            Err(AuthorityCheckpointError::PolicyMismatch)
        );
        assert_eq!(guard.accepted_epoch(), 4);
        let admission =
            unsafe { OwnerApprovedAuthorityCheckpoint::new(5, volume(), 6, 30, digest) };
        let mut issuer = AuthorityCheckpointProofIssuer::new(admission);
        let issued = issuer.issue::<2>(&encoded).unwrap();
        assert_eq!(
            issuer.issue::<2>(&encoded).map(|_| ()),
            Err(AuthorityCheckpointError::ProofAlreadyIssued)
        );
        guard.recover::<2>(&encoded, issued).unwrap();
        assert_eq!(guard.accepted_epoch(), 5);
        assert_eq!(
            guard
                .recover::<2>(&encoded, proof(&encoded, 5, 6, 30))
                .map(|_| ()),
            Err(AuthorityCheckpointError::AuthenticationMismatch)
        );
        assert_eq!(guard.accepted_epoch(), 5);
    }

    #[test]
    fn codec_rejects_amplification_lineage_hidden_data_and_capacity() {
        let root = StorageRecoveryGrant::root(
            principal(1),
            object(3),
            StorageObjectKind::File,
            StorageRights::READ.union(StorageRights::DELEGATE),
        );
        let amplified = StorageRecoveryGrant::derived(
            principal(2),
            object(3),
            StorageObjectKind::File,
            StorageRights::WRITE,
            0,
        );
        let mut encoded =
            [0xa5; AUTHORITY_CHECKPOINT_HEADER_BYTES + 2 * AUTHORITY_CHECKPOINT_GRANT_BYTES];
        assert_eq!(
            encode_authority_checkpoint(1, volume(), 1, 40, &[root, amplified], &mut encoded),
            Err(AuthorityCheckpointError::AuthorityAmplification)
        );
        assert!(encoded.iter().all(|byte| *byte == 0xa5));
        let forward = StorageRecoveryGrant::derived(
            principal(2),
            object(3),
            StorageObjectKind::File,
            StorageRights::READ,
            1,
        );
        assert_eq!(
            encode_authority_checkpoint(1, volume(), 1, 40, &[root, forward], &mut encoded),
            Err(AuthorityCheckpointError::InvalidLineage)
        );
        assert!(encoded.iter().all(|byte| *byte == 0xa5));

        encode_authority_checkpoint(2, volume(), 2, 40, &[root], &mut encoded[..128]).unwrap();
        let mut canonical =
            [0; AUTHORITY_CHECKPOINT_HEADER_BYTES + AUTHORITY_CHECKPOINT_GRANT_BYTES];
        canonical.copy_from_slice(
            &encoded[..AUTHORITY_CHECKPOINT_HEADER_BYTES + AUTHORITY_CHECKPOINT_GRANT_BYTES],
        );
        canonical[AUTHORITY_CHECKPOINT_HEADER_BYTES + 24] = 1;
        let digest = checkpoint_digest(&canonical);
        canonical[DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_BYTES].copy_from_slice(&digest);
        let guard = guard(1, 39);
        let hidden_admission =
            unsafe { OwnerApprovedAuthorityCheckpoint::new(2, volume(), 2, 40, digest) };
        let mut hidden_issuer = AuthorityCheckpointProofIssuer::new(hidden_admission);
        assert_eq!(
            hidden_issuer.issue::<1>(&canonical).map(|_| ()),
            Err(AuthorityCheckpointError::Malformed)
        );
        assert_eq!(guard.accepted_epoch(), 1);
        let capacity_admission = unsafe {
            OwnerApprovedAuthorityCheckpoint::new(
                2,
                volume(),
                2,
                40,
                authority_checkpoint_digest(&encoded[..128]).unwrap(),
            )
        };
        let mut capacity_issuer = AuthorityCheckpointProofIssuer::new(capacity_admission);
        assert_eq!(
            capacity_issuer.issue::<0>(&encoded[..128]).map(|_| ()),
            Err(AuthorityCheckpointError::CapacityMismatch)
        );
    }
}
