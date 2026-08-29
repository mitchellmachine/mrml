#![no_std]

//! Capability-native stable object and metadata foundation for MRML storage.
//!
//! Names and stable object IDs identify resources but never authorize access.
//! The storage service owns bounded generational handles, canonical metadata,
//! COW transactions, and a capability-controlled exact-block service boundary.
//! Physical device drivers and durability evidence remain later layers.

mod allocation;
mod ahci_controller;
mod ahci_dma;
mod ahci_discovery;
mod ahci_mapping;
mod ahci_port;
mod authority;
mod authority_checkpoint;
mod block;
mod block_protocol;
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
mod transaction;

pub use allocation::{
    ALLOCATION_IMAGE_HEADER_BYTES, ALLOCATION_RECORD_BYTES, AllocationChange, AllocationError,
    AllocationImage, AllocationIndex, AllocationKind, AllocationRecord, AllocationUpdateError,
    AllocationWriteBackend, MAX_ALLOCATION_BLOCKS, PreparedAllocationUpdate,
};
pub use ahci_controller::{
    AHCI_CAP_OFFSET, AHCI_GHC_OFFSET, AHCI_PI_OFFSET, AHCI_RESET_POLL_LIMIT,
    AHCI_VERSION_OFFSET, AhciControllerError, AhciControllerSnapshot, AhciRegisterIo,
    NativeAhciRegisterIo, reset_ahci_controller,
};
pub use ahci_dma::{
    AHCI_COMMAND_LIST_ALIGNMENT, AHCI_COMMAND_LIST_BYTES, AHCI_COMMAND_TABLE_ALIGNMENT,
    AHCI_COMMAND_TABLE_BYTES_PER_SLOT, AHCI_RECEIVED_FIS_ALIGNMENT, AHCI_RECEIVED_FIS_BYTES,
    AhciDmaRegion, AhciPortDmaBackend, AhciPortDmaError, AhciPortDmaLayout,
    AhciPortDmaRequest, AhciPortDmaRevocationError, InstalledAhciPortDma,
    prepare_ahci_port_dma, revoke_ahci_port_dma,
};
pub use ahci_discovery::{
    AHCI_ABAR_MINIMUM_BYTES, AHCI_PCI_CLASS, AHCI_PCI_PROGRAMMING_INTERFACE,
    AHCI_PCI_SUBCLASS, AhciAbarDescriptor, AhciDiscoveryError, AhciPciFunctionSnapshot,
    PciFunctionLocation,
};
pub use ahci_mapping::{
    AHCI_MMIO_PAGE_BYTES, AhciAbarMapping, AhciAbarMappingBackend, AhciAbarMappingError,
    map_ahci_abar,
};
pub use ahci_port::{
    AHCI_ATAPI_SIGNATURE, AHCI_ENCLOSURE_MANAGEMENT_SIGNATURE, AHCI_MAX_PORTS,
    AHCI_PORT_BASE_OFFSET, AHCI_PORT_COMMAND_ISSUE_OFFSET, AHCI_PORT_COMMAND_OFFSET,
    AHCI_PORT_INTERRUPT_ENABLE_OFFSET, AHCI_PORT_MULTIPLIER_SIGNATURE,
    AHCI_PORT_SATA_ACTIVE_OFFSET, AHCI_PORT_SATA_STATUS_OFFSET, AHCI_PORT_SIGNATURE_OFFSET,
    AHCI_PORT_STRIDE_BYTES, AHCI_SATA_SIGNATURE, AhciPortDeviceKind,
    AhciPortDiscoveryError, AhciPortError, AhciPortLinkSpeed, AhciPortLinkState,
    AhciPortPowerState, AhciPortSnapshot, AhciPortSnapshotSet, discover_ahci_ports,
};
pub use authority::{
    StorageAuthorityError, StorageAuthorityReservation, StorageAuthorityTable, StorageHandle,
    StorageObjectKind, StoragePrincipal, StorageRights,
};
pub use authority_checkpoint::{
    AUTHORITY_CHECKPOINT_GRANT_BYTES, AUTHORITY_CHECKPOINT_HEADER_BYTES,
    AUTHORITY_RECOVERY_STATE_BYTES, AuthenticatedAuthorityCheckpoint,
    AuthenticatedAuthorityRecoveryState, AuthorityCheckpoint, AuthorityCheckpointError,
    AuthorityCheckpointProofIssuer, AuthorityRecoveryCommitError, AuthorityRecoveryGuard,
    AuthorityRecoveryStateStore, AuthorityRecoveryValidationError,
    AuthorityRecoveryValidationResult, AuthorityRecoveryValidator, AuthorityStorageError,
    BootBoundRecoveryStateStore, BootRecoveryAdmission, BootRecoveryStateError,
    CanonicalAuthorityRecoveryState, CommittedRecoveredStorageAuthorities,
    OwnerApprovedAuthorityCheckpoint, PreparedStableAuthorities, RecoveredStorageAuthorities,
    StableAuthorities, StorageRecoveryGrant, authority_checkpoint_digest,
    decode_canonical_authority_recovery_state, encode_authority_checkpoint,
    prepare_stable_authorities, recover_selected_stable_authorities,
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
    FileReadBackend, FileReadError, FileState, FileStateError, FileWriteBackend, FileWriteError,
    FileWritePublishError, InitialFileError, InitialFileWriteBackend, MAX_FILE_READ_BYTES,
    MAX_FILE_WRITE_BYTES, MAX_PROTECTED_METADATA_RANGES, PreparedFileWrite, PreparedInitialFile,
    prepare_initial_file,
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
pub use transaction::{
    StorageTransaction, StorageTransactionId, TransactionError, TransactionParticipant,
    TransactionPublishError, TransactionReceipt, TransactionResource,
};
