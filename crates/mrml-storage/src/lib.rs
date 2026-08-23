#![no_std]

//! Capability-native stable object and metadata foundation for MRML storage.
//!
//! Names and stable object IDs identify resources but never authorize access.
//! The storage service owns bounded generational handles and canonical metadata;
//! allocation, COW mutation, transactions, and device I/O are later layers.

mod allocation;
mod authority;
mod cow;
mod directory;
mod extent;
mod file;
mod format;
mod identity;
mod recovery;
mod transaction;

pub use allocation::{
    ALLOCATION_RECORD_BYTES, AllocationError, AllocationIndex, AllocationKind, AllocationRecord,
    MAX_ALLOCATION_BLOCKS,
};
pub use authority::{
    StorageAuthorityError, StorageAuthorityTable, StorageHandle, StorageObjectKind,
    StoragePrincipal, StorageRights,
};
pub use cow::{
    CowMetadataImage, CowMetadataWrite, CowPlanError, CowPublicationBackend, CowPublicationPlan,
    CowPublishError,
};
pub use directory::{DirectoryError, DirectoryState, StorageObjectAllocator};
pub use extent::{
    EXTENT_RECORD_BYTES, ExtentError, ExtentKind, ExtentLocation, ExtentMap, ExtentRecord,
    MAX_EXTENT_BLOCKS,
};
pub use file::{
    FileReadBackend, FileReadError, FileState, FileStateError, FileWriteBackend, FileWriteError,
    FileWritePublishError, MAX_FILE_READ_BYTES, MAX_FILE_WRITE_BYTES,
    MAX_PROTECTED_METADATA_RANGES, PreparedFileWrite,
};
pub use format::{
    DIRECTORY_ENTRY_BYTES, DIRECTORY_METADATA_BYTES, DirectoryEntry, DirectoryMetadata,
    FILE_METADATA_BYTES, FileMetadata, MAX_METADATA_BLOCKS, MAX_STORAGE_NAME_BYTES, MetadataError,
    MetadataPointer, SUPERBLOCK_BYTES, StorageName, Superblock, VOLUME_HEADER_BYTES, VolumeHeader,
};
pub use identity::{StorageIdentityError, StorageObjectId, VolumeId};
pub use recovery::{
    CandidateValidationError, CowRecoveryValidator, RecoveredSuperblock, RecoveryError,
    recover_superblock,
};
pub use transaction::{
    StorageTransaction, StorageTransactionId, TransactionError, TransactionParticipant,
    TransactionPublishError, TransactionReceipt,
};
