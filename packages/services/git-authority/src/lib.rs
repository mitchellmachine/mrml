#![feature(peer_credentials_unix_socket)]

mod authority;
mod candidate;
mod channel;
mod generation;
#[cfg(target_os = "linux")]
mod unix;

pub use authority::{AuthorityDispatchError, ProductionAuthority};
pub use candidate::{
    CandidateStoreError, LinuxAuthorityCandidateStore,
};
pub use mrml_git::{
    AuthorityCandidateContext, AuthorityCandidateRecord, AuthorityCandidateStatus,
};
pub use channel::{
    decode_frame, encode_frame, AuthorityCapability, AuthorityError, AuthorityFrame,
    AuthorityFrameKind, AuthorityOperation, AuthorityPeer, AuthorityReplayWindow,
    AUTHORITY_CAPABILITY_BYTES, AUTHORITY_HEADER_BYTES, MAX_AUTHORITY_PAYLOAD_BYTES,
};
pub use generation::{
    AuthorityGenerationStore, GenerationStoreError, LinuxAuthorityGenerationStore,
    MemoryAuthorityGenerationStore,
};
#[cfg(target_os = "linux")]
pub use unix::{AuthorityListener, AuthoritySession, UnixAuthorityError};
