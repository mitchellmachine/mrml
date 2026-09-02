mod auth_store;
mod authority_rpc;
mod backend;
mod catalog;
mod certd_rpc;
mod composition;
mod config;
mod http2_stream;
mod http2_workers;
mod http3_reactor;
mod http3_stream;
mod http3_workers;
mod identity;
mod listener;
mod startup;
mod tls_identity;

pub use auth_store::{
    AuthenticationStoreError, initialize_empty_token_store, issue_access_token,
    load_gitd_authentication, revoke_access_token,
};
pub use authority_rpc::{GitAuthorityChannelClient, GitAuthorityChannelError};
pub use backend::{GitdRepositorySet, SharedGitdRepositorySet};
pub use catalog::{
    DeploymentCatalog, DeploymentCatalogError, DeploymentProfile, DeploymentRepository,
    DeploymentRepositoryProfile, load_deployment_catalog, parse_deployment_catalog,
    verify_repository_admission,
};
pub use certd_rpc::{GitdCertdChannelClient, GitdCertdChannelError, GitdIdentitySnapshot};
pub use composition::{GitdComposedService, GitdCompositionError, compose_gitd_service};
pub use config::{GitdConfig, GitdConfigError, load_gitd_config, parse_gitd_config};
pub use http2_stream::{
    GitdHttp2StreamError, serve_gitd_http2_connection, serve_gitd_http2_connection_with_drain,
    serve_smart_git_http2,
};
pub use http2_workers::{GitdHttp2WorkerError, GitdHttp2WorkerMetrics, GitdHttp2WorkerPool};
pub use http3_reactor::{GitdHttp3Reactor, GitdHttp3ReactorError, GitdHttp3ReactorStep};
pub use http3_stream::{
    GitdHttp3StreamError, serve_gitd_http3_connection, serve_gitd_http3_connection_with_drain,
    serve_smart_git_http3,
};
pub use http3_workers::{
    GitdHttp3LifecycleEvent, GitdHttp3WorkerError, GitdHttp3WorkerMetrics, GitdHttp3WorkerPool,
};
pub use identity::{
    GitdIdentityValidationError, ValidatedGitdIdentity, prove_identity_signing_route,
    validate_identity_snapshot,
};
pub use listener::{GitdBoundListeners, GitdListenerError, load_quic_retry_key};
pub use startup::{
    AdmittedRepository, RepositoryAdmissionError, RepositoryRecoveryError,
    RepositoryRecoverySummary, RepositoryStoragePaths, StartupValidationError,
    admit_catalog_repository, recover_admitted_repository, validate_storage_layout,
};
pub use tls_identity::{
    GitdCertdSigningRoute, GitdCertdTlsSigningKey, GitdTlsConfigStore, GitdTlsRefreshError,
    build_certd_tls_server_config, build_certd_tls_server_config_with_route,
    refresh_certd_tls_config,
};
