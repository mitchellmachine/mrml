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
mod service_loop;
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
    AuthenticatedAuthorityCheckpoint, AuthorityCheckpoint, AuthorityCheckpointError,
    AuthorityRecoveryGuard, AuthorityStorageError, PreparedStableAuthorities,
    RecoveredStorageAuthorities, StableAuthorities, StorageRecoveryGrant,
    authority_checkpoint_digest, encode_authority_checkpoint, prepare_stable_authorities,
    recover_stable_authorities,
};
pub use block::{BlockFileSession, BlockVolume, BlockVolumeError, StorageBlockDevice};
pub use block_protocol::{
    BLOCK_PROTOCOL_VERSION, BLOCK_REQUEST_BYTES, BLOCK_RESPONSE_BYTES, BlockBufferAccess,
    BlockDispatchBuffer, BlockOpcode, BlockProtocolDispatcher, BlockProtocolError, BlockRequest,
    BlockResponse, BlockStatus, MAX_BLOCK_TRANSFER_BYTES,
};
pub use block_service::{
    BlockDeviceDescriptor, BlockDeviceId, BlockRights, BlockService, BlockServiceBackend,
    BlockServiceError, BlockSessionHandle, ServicedBlockDevice,
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
    CandidateValidationError, CowRecoveryValidator, ReachableRecoveryValidator,
    RecoveredSuperblock, RecoveryError, RecoveryMetadataBackend, recover_reachable_superblock,
    recover_superblock,
};
pub use service_loop::{
    BlockServiceLoop, BlockServiceLoopError, BlockServiceSyscalls, ReceivedBlockEnvelope,
};
pub use transaction::{
    StorageTransaction, StorageTransactionId, TransactionError, TransactionParticipant,
    TransactionPublishError, TransactionReceipt, TransactionResource,
};
