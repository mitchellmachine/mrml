mod authority_rpc;
mod config;

pub use authority_rpc::{GitAuthorityChannelClient, GitAuthorityChannelError};
pub use config::{GitdConfig, GitdConfigError, load_gitd_config, parse_gitd_config};
