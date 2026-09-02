mod auth_store;
mod authority_rpc;
mod backend;
mod catalog;
mod certd_rpc;
mod composition;
mod config;
mod core_adapter;
mod http2_stream;
mod http2_workers;
mod http3_reactor;
mod http3_stream;
mod http3_workers;
mod identity;
mod listener;
mod production_receive;
mod startup;
mod tls_identity;

pub use auth_store::{
    initialize_empty_token_store, issue_access_token, load_gitd_authentication,
    revoke_access_token, AuthenticationStoreError,
};
pub use authority_rpc::{GitAuthorityChannelClient, GitAuthorityChannelError};
pub use backend::{GitdRepositorySet, SharedGitdRepositorySet};
pub use catalog::{
    load_deployment_catalog, parse_deployment_catalog, verify_repository_admission,
    DeploymentCatalog, DeploymentCatalogError, DeploymentProfile, DeploymentRepository,
    DeploymentRepositoryProfile,
};
pub use certd_rpc::{GitdCertdChannelClient, GitdCertdChannelError, GitdIdentitySnapshot};
pub use composition::{compose_gitd_service, GitdComposedService, GitdCompositionError};
pub use config::{load_gitd_config, parse_gitd_config, GitdConfig, GitdConfigError};
pub use core_adapter::GitdCoreAdapter;
pub use http2_stream::{
    serve_gitd_http2_connection, serve_gitd_http2_connection_with_drain, serve_smart_git_http2,
    GitdHttp2StreamError,
};
pub use http2_workers::{GitdHttp2WorkerError, GitdHttp2WorkerMetrics, GitdHttp2WorkerPool};
pub use http3_reactor::{GitdHttp3Reactor, GitdHttp3ReactorError, GitdHttp3ReactorStep};
pub use http3_stream::{
    serve_gitd_http3_connection, serve_gitd_http3_connection_with_drain, serve_smart_git_http3,
    GitdHttp3StreamError,
};
pub use http3_workers::{
    GitdHttp3LifecycleEvent, GitdHttp3WorkerError, GitdHttp3WorkerMetrics, GitdHttp3WorkerPool,
};
pub use identity::{
    prove_identity_signing_route, validate_identity_snapshot, GitdIdentityValidationError,
    ValidatedGitdIdentity,
};
pub use listener::{load_quic_retry_key, GitdBoundListeners, GitdListenerError};
pub use production_receive::ProductionReceiveRepository;
pub use startup::{
    admit_catalog_repository, initialize_catalog_protected_policy, initialize_catalog_repository,
    inspect_admitted_repository_recovery, recover_admitted_repository, validate_storage_layout,
    AdmittedRepository, ProtectedPolicyInitializationError, RepositoryAdmissionError,
    RepositoryInitializationError, RepositoryRecoveryError, RepositoryRecoveryStatus,
    RepositoryRecoverySummary, RepositoryStoragePaths, StartupValidationError,
};
pub use tls_identity::{
    build_certd_tls_server_config, build_certd_tls_server_config_with_route,
    refresh_certd_tls_config, GitdCertdSigningRoute, GitdCertdTlsSigningKey, GitdTlsConfigStore,
    GitdTlsRefreshError,
};
