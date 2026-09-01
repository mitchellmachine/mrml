mod auth_store;
mod authority_rpc;
mod catalog;
mod certd_rpc;
mod config;
mod startup;

pub use auth_store::{AuthenticationStoreError, load_gitd_authentication};
pub use authority_rpc::{GitAuthorityChannelClient, GitAuthorityChannelError};
pub use catalog::{
    DeploymentCatalog, DeploymentCatalogError, DeploymentProfile, DeploymentRepository,
    DeploymentRepositoryProfile, load_deployment_catalog, parse_deployment_catalog,
    verify_repository_admission,
};
pub use certd_rpc::{GitdCertdChannelClient, GitdCertdChannelError, GitdIdentitySnapshot};
pub use config::{GitdConfig, GitdConfigError, load_gitd_config, parse_gitd_config};
pub use startup::{
    AdmittedRepository, RepositoryAdmissionError, RepositoryRecoveryError,
    RepositoryRecoverySummary, RepositoryStoragePaths, StartupValidationError,
    admit_catalog_repository, recover_admitted_repository, validate_storage_layout,
};
