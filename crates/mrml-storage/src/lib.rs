#![no_std]

//! Capability-native stable object and metadata foundation for MRML storage.
//!
//! Names and stable object IDs identify resources but never authorize access.
//! The storage service owns bounded generational handles and canonical metadata;
//! allocation, COW mutation, transactions, and device I/O are later layers.

mod authority;
mod cow;
mod extent;
mod format;
mod identity;

pub use authority::{
    StorageAuthorityError, StorageAuthorityTable, StorageHandle, StorageObjectKind,
    StoragePrincipal, StorageRights,
};
pub use cow::{
    CowMetadataWrite, CowPlanError, CowPublicationBackend, CowPublicationPlan, CowPublishError,
};
pub use extent::{
    EXTENT_RECORD_BYTES, ExtentError, ExtentKind, ExtentLocation, ExtentMap, ExtentRecord,
    MAX_EXTENT_BLOCKS,
};
pub use format::{
    DIRECTORY_ENTRY_BYTES, DIRECTORY_METADATA_BYTES, DirectoryEntry, DirectoryMetadata,
    FILE_METADATA_BYTES, FileMetadata, MAX_METADATA_BLOCKS, MAX_STORAGE_NAME_BYTES, MetadataError,
    MetadataPointer, SUPERBLOCK_BYTES, StorageName, Superblock, VOLUME_HEADER_BYTES, VolumeHeader,
};
pub use identity::{StorageIdentityError, StorageObjectId, VolumeId};
