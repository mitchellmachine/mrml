mod auth_store;
mod authority_rpc;
mod backend;
mod backup_archive;
mod backup_volume;
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
mod tcp_admission;
#[cfg(test)]
mod tcp_listener_tests;
mod tls_identity;
#[cfg(test)]
mod tls_refresh_tests;

pub use auth_store::{
    AuthenticationStoreError, RetainedAuthenticationStore, initialize_empty_token_store,
    issue_access_token, load_gitd_authentication, reload_gitd_authentication, revoke_access_token,
};
pub use authority_rpc::{GitAuthorityChannelClient, GitAuthorityChannelError};
pub use backend::{GitdRepositorySet, SharedGitdRepositorySet};
pub use backup_archive::{
    BackupArchiveError, backup_payload_inventory_length, restore_backup_archive,
    verify_backup_archive, write_backup_archive,
};
pub use backup_volume::{
    BACKUP_VOLUME_ORDER, BackupVolumeError, collect_backup_inventory, collect_backup_volume,
};
pub use catalog::{
    DeploymentCatalog, DeploymentCatalogError, DeploymentProfile, DeploymentRepository,
    DeploymentRepositoryProfile, load_deployment_catalog, parse_deployment_catalog,
    verify_repository_admission,
};
pub use certd_rpc::{GitdCertdChannelClient, GitdCertdChannelError, GitdIdentitySnapshot};
pub use composition::{GitdComposedService, GitdCompositionError, compose_gitd_service};
pub use config::{GitdConfig, GitdConfigError, load_gitd_config, parse_gitd_config};
pub use core_adapter::GitdCoreAdapter;
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
pub use production_receive::ProductionReceiveRepository;
pub use startup::{
    AdmittedRepository, ProtectedPolicyInitializationError, RepositoryAdmissionError,
    RepositoryInitializationError, RepositoryRecoveryError, RepositoryRecoveryStatus,
    RepositoryRecoverySummary, RepositoryStorageCapabilities, RepositoryStoragePaths,
    StartupValidationError, admit_catalog_repository, initialize_catalog_protected_policy,
    initialize_catalog_repository, inspect_admitted_repository_recovery,
    recover_admitted_protected_repository, recover_admitted_repository, validate_storage_layout,
};
pub use tcp_admission::{
    AdmittedTcpSocket, TcpAdmissionController, TcpAdmissionError, TcpAdmissionLimits,
    TcpAdmissionMetrics, TcpConnectionPermit, TcpHandshakePermit, TcpSourceIdentity,
};
pub use tls_identity::{
    GitdCertdSigningRoute, GitdCertdTlsSigningKey, GitdTlsConfigStore, GitdTlsRefreshError,
    GitdTlsRefreshMetrics, build_certd_tls_server_config, build_certd_tls_server_config_with_route,
    gitd_alpn_protocols, refresh_certd_tls_config, wait_for_certificate_poll,
};
