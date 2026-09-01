#![feature(peer_credentials_unix_socket)]

mod channel;
#[cfg(target_os = "linux")]
mod unix;

pub use channel::{
    decode_frame, encode_frame, AuthorityCapability, AuthorityError, AuthorityFrame,
    AuthorityFrameKind, AuthorityOperation, AuthorityPeer, AuthorityReplayWindow,
    AUTHORITY_CAPABILITY_BYTES, AUTHORITY_HEADER_BYTES, MAX_AUTHORITY_PAYLOAD_BYTES,
};
#[cfg(target_os = "linux")]
pub use unix::{AuthorityListener, AuthoritySession, UnixAuthorityError};
