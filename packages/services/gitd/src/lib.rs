mod authority_rpc;
mod config;

pub use authority_rpc::{GitAuthorityChannelClient, GitAuthorityChannelError};
pub use config::{GitdConfig, GitdConfigError, parse_gitd_config};
