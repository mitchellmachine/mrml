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
mod filesystem_mount;
mod filesystem_open;
mod filesystem_provider_launch;
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
    ALLOCATION_IMAGE_HEADER_BYTES, ALLOCATION_RECORD_BYTES, AllocationChange, AllocationError,
    AllocationImage, AllocationIndex, AllocationKind, AllocationRecord, AllocationUpdateError,
    AllocationWriteBackend, MAX_ALLOCATION_BLOCKS, PreparedAllocationUpdate,
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
    StorageRecoveryGrant, authority_checkpoint_digest, decode_canonical_authority_recovery_state,
    encode_authority_checkpoint, prepare_stable_authorities, recover_selected_stable_authorities,
    recover_selected_stable_authorities_and_commit,
    recover_selected_validate_and_commit_stable_authorities, recover_stable_authorities,
    recover_stable_authorities_and_commit, recover_validate_and_commit_stable_authorities,
    validate_authenticated_authority_recovery_state,
};
pub use block::{BlockFileSession, BlockVolume, BlockVolumeError, StorageBlockDevice};
pub use block_protocol::{
    BLOCK_PROTOCOL_VERSION, BLOCK_REQUEST_BYTES, BLOCK_RESPONSE_BYTES, BlockBufferAccess,
    BlockDispatchBuffer, BlockOpcode, BlockProtocolDispatcher, BlockProtocolError, BlockRequest,
    BlockResponse, BlockStatus, MAX_BLOCK_TRANSFER_BYTES,
};
pub use block_provider_health::{
    BlockProviderHealthError, BlockProviderHealthReceipt, BlockProviderModuleSupervisor,
    ValidatedBlockProviderBackend, healthcheck_block_provider,
};
pub use block_service::{
    BlockDeviceDescriptor, BlockDeviceId, BlockRights, BlockService, BlockServiceBackend,
    BlockServiceError, BlockSessionGrant, BlockSessionHandle, CanonicalUefiBlockDevicePathError,
    CanonicalUefiHardDriveMedia, CanonicalUefiPciHop, CanonicalUefiSataBlockRoute,
    CanonicalUefiSataRouteError, ExactNativeBlockCorrelationError,
    ExactNativeBlockCorrelationVerifier, InstalledRecoveryBlockSession,
    InstalledRecoverySessionError, MAX_CANONICAL_UEFI_BLOCK_DEVICE_PATH_BYTES,
    MAX_CANONICAL_UEFI_PCI_HOPS, NativeBlockCorrelationError, NativeBlockCorrelationVerifier,
    NativeSataBlockRoute, NativeSataRouteError, PlatformBlockDeviceDescriptor,
    PlatformBlockDeviceIdentity, PlatformBlockTransport, SataNativeBlockCorrelationError,
    SataNativeBlockCorrelationVerifier, ServicedBlockDevice, canonical_uefi_block_stable_id,
    parse_canonical_uefi_sata_block_route,
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
    CommittedDirectoryMovePlan, DIRECTORY_IMAGE_HEADER_BYTES, DirectoryAncestryBackend,
    DirectoryAncestryError, DirectoryAncestryProof, DirectoryClosureError, DirectoryError,
    DirectoryImage, DirectoryImageError, DirectoryMoveStageError, DirectoryMoveSuccessor,
    DirectoryMoveSuccessorPlan, DirectoryMutationProof, DirectoryMutationSuccessorPlan,
    DirectoryState, DirectorySuccessorBackend, DirectorySuccessorClosure, DirectorySuccessorError,
    DirectorySuccessorLayout, DirectoryUpdateError, DirectoryWriteBackend,
    PreparedDirectoryMovePlan, PreparedDirectoryUpdate, PreparedInitialDirectory,
    StorageObjectAllocator, prepare_initial_directory, prove_directory_move_ancestry,
    prove_directory_mutation_ancestry,
};
pub use extent::{
    EXTENT_IMAGE_HEADER_BYTES, EXTENT_RECORD_BYTES, ExtentError, ExtentImage, ExtentKind,
    ExtentLocation, ExtentMap, ExtentRecord, MAX_EXTENT_BLOCKS,
};
pub use file::{
    FileReadBackend, FileReadError, FileState, FileStateError, FileWriteBackend,
    FileWriteCommitError, FileWriteError, FileWritePublishError, InitialFileError,
    InitialFileWriteBackend, MAX_FILE_READ_BYTES, MAX_FILE_WRITE_BYTES,
    MAX_PROTECTED_METADATA_RANGES, PreparedFileWrite, PreparedInitialFile, prepare_initial_file,
};
pub use filesystem_mount::{
    FILESYSTEM_BOOT_SECTOR_BYTES, FilesystemBootSectorError, FilesystemBootSectorReader,
};
pub use filesystem_open::{
    AuthenticatedFilesystemLookup, FilesystemOpenBroker, FilesystemOpenError, FilesystemOpenKind,
    FilesystemOpenReservation,
};
pub use filesystem_provider_launch::{
    ActiveNativeFilesystemProvider, CleanedFaultedNativeFilesystemProvider,
    CleanedNativeFilesystemProviderFaultDispatchFailure,
    CleanedNativeFilesystemProviderRetirementDispatchFailure,
    CleanedNativeFilesystemProviderViolationDispatchFailure,
    CleanedRetiredNativeFilesystemProvider, CleanedViolatingNativeFilesystemProvider,
    DispatchedFaultedNativeFilesystemProvider, DispatchedRetiredNativeFilesystemProvider,
    DispatchedViolatingNativeFilesystemProvider, FaultedNativeFilesystemProvider,
    FaultedNativeFilesystemProviderTeardownFailure, FilesystemProviderLaunchBackend,
    FilesystemProviderLaunchError, FilesystemProviderLaunchReceipt,
    FilesystemProviderTeardownBackend, FilesystemProviderTeardownError,
    NativeFilesystemProviderActivationError, NativeFilesystemProviderActivationFailure,
    NativeFilesystemProviderActiveRetirementError, NativeFilesystemProviderInstance,
    NativeFilesystemProviderLaunchError, NativeFilesystemProviderLaunchPreflightError,
    NativeFilesystemProviderLaunchSpec, NativeFilesystemProviderLaunchSpecError,
    NativeFilesystemProviderRestartError, NativeFilesystemProviderRestartFailure,
    NativeFilesystemProviderRetirement, NativeFilesystemProviderRetirementError,
    NativeFilesystemProviderStopCause,
    NativeFilesystemProviderSupervisedFaultFailure,
    NativeFilesystemProviderSupervisedRetirementFailure,
    NativeFilesystemProviderSupervisedViolationFailure, NativeFilesystemProviderTeardownBackend,
    ResourceReleasedFaultedNativeFilesystemProvider,
    ResourceReleasedNativeFilesystemProviderFaultCleanupFailure,
    ResourceReleasedNativeFilesystemProviderRetirementCleanupFailure,
    ResourceReleasedNativeFilesystemProviderViolationCleanupFailure,
    ResourceReleasedRetiredNativeFilesystemProvider,
    ResourceReleasedViolatingNativeFilesystemProvider, RestartableStoppedNativeFilesystemProvider,
    RestartedNativeFilesystemProvider, RetiredNativeFilesystemProvider,
    RetiredNativeFilesystemProviderTeardownFailure, ViolatingNativeFilesystemProvider,
    ViolatingNativeFilesystemProviderTeardownFailure, activate_native_filesystem_provider,
    complete_resource_released_native_filesystem_provider_fault_cleanup,
    complete_resource_released_native_filesystem_provider_retirement_cleanup,
    complete_resource_released_native_filesystem_provider_violation_cleanup,
    dispatch_cleaned_native_filesystem_provider_fault,
    dispatch_cleaned_native_filesystem_provider_retirement,
    dispatch_cleaned_native_filesystem_provider_violation,
    fault_current_supervised_native_filesystem_provider, launch_filesystem_provider,
    launch_native_filesystem_provider, restart_and_activate_native_filesystem_provider,
    retire_current_native_filesystem_provider,
    retire_current_native_filesystem_provider_on_active_x86_64,
    retire_current_supervised_native_filesystem_provider,
    teardown_faulted_native_filesystem_provider, teardown_filesystem_provider,
    teardown_retired_native_filesystem_provider, teardown_violating_native_filesystem_provider,
    violate_current_supervised_native_filesystem_provider,
};
pub use format::{
    DIRECTORY_ENTRY_BYTES, DIRECTORY_METADATA_BYTES, DirectoryEntry, DirectoryMetadata,
    FILE_METADATA_BYTES, FileMetadata, MAX_METADATA_BLOCKS, MAX_STORAGE_NAME_BYTES, MetadataError,
    MetadataPointer, SUPERBLOCK_BYTES, StorageName, Superblock, VOLUME_HEADER_BYTES, VolumeHeader,
};
pub use identity::{StorageIdentityError, StorageObjectId, VolumeId};
pub use kernel_transport::{BlockKernelTransport, BlockKernelTransportError};
pub use object_id_allocator::{
    OBJECT_ID_ALLOCATOR_HEADER_BYTES, ObjectIdAllocatorError, ObjectIdAllocatorImage,
    ObjectIdAllocatorUpdateError, ObjectIdAllocatorWriteBackend, PreparedObjectIdReservation,
};
pub use recovery::{
    CandidateValidationError, CowRecoveryValidator, ReachableFileSelection,
    ReachableRecoveryValidator, RecoveredReachableState, RecoveredSuperblock, RecoveryError,
    RecoveryMetadataBackend, recover_reachable_state, recover_reachable_superblock,
    recover_superblock,
};
pub use recovery_journal::{
    AuthenticatedRecoveryJournal, RECOVERY_JOURNAL_SLOT_BYTES, RecoveryJournalBackend,
    RecoveryJournalError,
};
pub use release_journal::{
    AuthenticatedReleaseStateJournal, RELEASE_STATE_JOURNAL_SLOT_BYTES, ReleaseStateJournalBackend,
    ReleaseStateJournalError,
};
pub use service_loop::{
    BlockServiceLoop, BlockServiceLoopError, BlockServiceSyscalls, ReceivedBlockEnvelope,
};
pub use storage_module::{
    FILESYSTEM_BLOCK_ASSOCIATION_HANDOFF_BYTES, FilesystemBlockAssociation,
    FilesystemBlockAssociationError, FilesystemBlockAssociationHandoff,
    FilesystemBlockAssociationHandoffError, StorageModuleBackend, StorageModuleBinding,
    StorageModuleClass, StorageModuleError, StorageModuleRegistry, StorageModuleState,
};
pub use transaction::{
    StorageTransaction, StorageTransactionId, TransactionError, TransactionParticipant,
    TransactionPublishError, TransactionReceipt, TransactionResource,
};
