#![no_std]

//! Capability-native stable object and metadata foundation for MRML storage.
//!
//! Names and stable object IDs identify resources but never authorize access.
//! The storage service owns bounded generational handles, canonical metadata,
//! COW transactions, and a capability-controlled exact-block service boundary.
//! Physical device drivers and durability evidence remain later layers.

mod allocation;
mod authority;
mod authority_checkpoint;
mod block;
mod block_protocol;
mod block_provider_health;
mod block_service;
mod cow;
mod create;
mod directory;
mod extent;
mod file;
mod format;
mod identity;
mod kernel_transport;
mod object_id_allocator;
mod recovery;
mod recovery_journal;
mod release_journal;
mod service_loop;
mod storage_module;
mod transaction;

pub use allocation::{
    AllocationChange, AllocationError, AllocationImage, AllocationIndex, AllocationKind,
    AllocationRecord, AllocationUpdateError, AllocationWriteBackend, PreparedAllocationUpdate,
    ALLOCATION_IMAGE_HEADER_BYTES, ALLOCATION_RECORD_BYTES, MAX_ALLOCATION_BLOCKS,
};
pub use authority::{
    StorageAuthorityError, StorageAuthorityReservation, StorageAuthorityTable, StorageHandle,
    StorageObjectKind, StoragePrincipal, StorageRights,
};
pub use authority_checkpoint::{
    AUTHORITY_CHECKPOINT_GRANT_BYTES, AUTHORITY_CHECKPOINT_HEADER_BYTES,
    AUTHORITY_RECOVERY_STATE_BYTES, AuthenticatedAuthorityCheckpoint,
    AuthenticatedAuthorityRecoveryState, AuthorityCheckpoint, AuthorityCheckpointError,
    AuthorityCheckpointProofIssuer, AuthorityRecoveryCommitError, AuthorityRecoveryCommitFailure,
    AuthorityRecoveryGuard, AuthorityRecoveryStateStore, AuthorityRecoveryValidationError,
    AuthorityRecoveryValidationResult, AuthorityRecoveryValidator, AuthorityStorageError,
    BootBoundRecoveryStateStore, BootRecoveryAdmission, BootRecoveryStateError,
    CanonicalAuthorityRecoveryState, CommittedRecoveredStorageAuthorities,
    OwnerApprovedAuthorityCheckpoint, PendingAuthorityResolutionError,
    PendingRecoveredStorageAuthorities, PendingValidatedStorageAuthorities,
    PreparedStableAuthorities, RecoveredStorageAuthorities, StableAuthorities,
    StorageRecoveryGrant, authority_checkpoint_digest,
    decode_canonical_authority_recovery_state, encode_authority_checkpoint,
    prepare_stable_authorities, recover_selected_stable_authorities,
    recover_selected_stable_authorities_and_commit,
    recover_selected_validate_and_commit_stable_authorities, recover_stable_authorities,
    recover_stable_authorities_and_commit, recover_validate_and_commit_stable_authorities,
    validate_authenticated_authority_recovery_state,
};
pub use block::{BlockFileSession, BlockVolume, BlockVolumeError, StorageBlockDevice};
pub use block_protocol::{
    BlockBufferAccess, BlockDispatchBuffer, BlockOpcode, BlockProtocolDispatcher,
    BlockProtocolError, BlockRequest, BlockResponse, BlockStatus, BLOCK_PROTOCOL_VERSION,
    BLOCK_REQUEST_BYTES, BLOCK_RESPONSE_BYTES, MAX_BLOCK_TRANSFER_BYTES,
};
pub use block_provider_health::{
    healthcheck_block_provider, BlockProviderHealthError, BlockProviderHealthReceipt,
    BlockProviderModuleSupervisor, ValidatedBlockProviderBackend,
};
pub use block_service::{
    canonical_uefi_block_stable_id, parse_canonical_uefi_sata_block_route, BlockDeviceDescriptor,
    BlockDeviceId, BlockRights, BlockService, BlockServiceBackend, BlockServiceError,
    BlockSessionGrant, BlockSessionHandle, CanonicalUefiBlockDevicePathError,
    CanonicalUefiHardDriveMedia, CanonicalUefiPciHop, CanonicalUefiSataBlockRoute,
    CanonicalUefiSataRouteError, ExactNativeBlockCorrelationError,
    ExactNativeBlockCorrelationVerifier, InstalledRecoveryBlockSession,
    InstalledRecoverySessionError, NativeBlockCorrelationError, NativeBlockCorrelationVerifier,
    NativeSataBlockRoute, NativeSataRouteError, PlatformBlockDeviceDescriptor,
    PlatformBlockDeviceIdentity, PlatformBlockTransport, SataNativeBlockCorrelationError,
    SataNativeBlockCorrelationVerifier, ServicedBlockDevice,
    MAX_CANONICAL_UEFI_BLOCK_DEVICE_PATH_BYTES, MAX_CANONICAL_UEFI_PCI_HOPS,
};
pub use cow::{
    CowMetadataImage, CowMetadataWrite, CowPlanError, CowPublicationBackend, CowPublicationPlan,
    CowPublishError,
};
pub use create::{
    CommittedCreate, CreateCommitError, InitialDirectoryState, InitialObjectState, PreparedCreate,
    PreparedCreateError, PreparedInitialObject,
};
pub use directory::{
    prepare_initial_directory, prove_directory_move_ancestry, prove_directory_mutation_ancestry,
    CommittedDirectoryMovePlan, DirectoryAncestryBackend, DirectoryAncestryError,
    DirectoryAncestryProof, DirectoryClosureError, DirectoryError, DirectoryImage,
    DirectoryImageError, DirectoryMoveStageError, DirectoryMoveSuccessor,
    DirectoryMoveSuccessorPlan, DirectoryMutationProof, DirectoryMutationSuccessorPlan,
    DirectoryState, DirectorySuccessorBackend, DirectorySuccessorClosure, DirectorySuccessorError,
    DirectorySuccessorLayout, DirectoryUpdateError, DirectoryWriteBackend,
    PreparedDirectoryMovePlan, PreparedDirectoryUpdate, PreparedInitialDirectory,
    StorageObjectAllocator, DIRECTORY_IMAGE_HEADER_BYTES,
};
pub use extent::{
    ExtentError, ExtentImage, ExtentKind, ExtentLocation, ExtentMap, ExtentRecord,
    EXTENT_IMAGE_HEADER_BYTES, EXTENT_RECORD_BYTES, MAX_EXTENT_BLOCKS,
};
pub use file::{
    FileReadBackend, FileReadError, FileState, FileStateError, FileWriteBackend,
    FileWriteCommitError, FileWriteError, FileWritePublishError, InitialFileError,
    InitialFileWriteBackend, MAX_FILE_READ_BYTES, MAX_FILE_WRITE_BYTES,
    MAX_PROTECTED_METADATA_RANGES, PreparedFileWrite, PreparedInitialFile, prepare_initial_file,
};
pub use format::{
    DirectoryEntry, DirectoryMetadata, FileMetadata, MetadataError, MetadataPointer, StorageName,
    Superblock, VolumeHeader, DIRECTORY_ENTRY_BYTES, DIRECTORY_METADATA_BYTES, FILE_METADATA_BYTES,
    MAX_METADATA_BLOCKS, MAX_STORAGE_NAME_BYTES, SUPERBLOCK_BYTES, VOLUME_HEADER_BYTES,
};
pub use identity::{StorageIdentityError, StorageObjectId, VolumeId};
pub use kernel_transport::{BlockKernelTransport, BlockKernelTransportError};
pub use object_id_allocator::{
    ObjectIdAllocatorError, ObjectIdAllocatorImage, ObjectIdAllocatorUpdateError,
    ObjectIdAllocatorWriteBackend, PreparedObjectIdReservation, OBJECT_ID_ALLOCATOR_HEADER_BYTES,
};
pub use recovery::{
    recover_reachable_state, recover_reachable_superblock, recover_superblock,
    CandidateValidationError, CowRecoveryValidator, ReachableFileSelection,
    ReachableRecoveryValidator, RecoveredReachableState, RecoveredSuperblock, RecoveryError,
    RecoveryMetadataBackend,
};
pub use recovery_journal::{
    AuthenticatedRecoveryJournal, RecoveryJournalBackend, RecoveryJournalError,
    RECOVERY_JOURNAL_SLOT_BYTES,
};
pub use release_journal::{
    AuthenticatedReleaseStateJournal, ReleaseStateJournalBackend, ReleaseStateJournalError,
    RELEASE_STATE_JOURNAL_SLOT_BYTES,
};
pub use service_loop::{
    BlockServiceLoop, BlockServiceLoopError, BlockServiceSyscalls, ReceivedBlockEnvelope,
};
pub use storage_module::{
    StorageModuleBackend, StorageModuleBinding, StorageModuleClass, StorageModuleError,
    StorageModuleRegistry, StorageModuleState,
};
pub use transaction::{
    StorageTransaction, StorageTransactionId, TransactionError, TransactionParticipant,
    TransactionPublishError, TransactionReceipt, TransactionResource,
};
