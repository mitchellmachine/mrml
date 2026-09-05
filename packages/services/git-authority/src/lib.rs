#![feature(peer_credentials_unix_socket)]

mod authority;
mod candidate;
mod channel;
mod generation;
#[cfg(target_os = "linux")]
mod unix;

pub use authority::{AuthorityDispatchError, ProductionAuthority, ProductionAuthorityCatalog};
pub use candidate::{CandidateStoreError, LinuxAuthorityCandidateStore};
pub use channel::{
    AUTHORITY_CAPABILITY_BYTES, AUTHORITY_HEADER_BYTES, AuthorityCapability, AuthorityError,
    AuthorityFrame, AuthorityFrameKind, AuthorityOperation, AuthorityPeer, AuthorityReplayWindow,
    MAX_AUTHORITY_PAYLOAD_BYTES, decode_frame, encode_frame,
};
pub use generation::{
    AuthorityGenerationStore, GenerationStoreError, LinuxAuthorityGenerationCatalog,
    LinuxAuthorityGenerationStore, MemoryAuthorityGenerationStore,
};
pub use mrml_git::{AuthorityCandidateContext, AuthorityCandidateRecord, AuthorityCandidateStatus};
#[cfg(target_os = "linux")]
pub use unix::{AuthorityListener, AuthoritySession, UnixAuthorityError};
