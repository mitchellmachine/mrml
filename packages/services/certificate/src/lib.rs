#![no_std]
#![cfg_attr(target_os = "linux", feature(peer_credentials_unix_socket))]

mod acme_operation_journal;
mod administration;
mod backup;
mod backup_export;
mod backup_transfer;
mod caa;
mod catalog_lifecycle_provider;
mod certd_candidate_protocol;
mod certd_channel;
#[cfg(target_os = "linux")]
mod certd_channel_unix;
#[cfg(target_os = "linux")]
mod certd_config;
mod certd_identifier_set;
mod certd_jws_protocol;
mod certd_key_protocol;
mod certificate;
mod challenge_dns;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod challenge_dns_hosted;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod challenge_http;
mod challenge_publisher;
mod challenge_service;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod challenge_tls_alpn_hosted;
mod constrained_acme_signing;
mod deployment_journal;
#[cfg(target_os = "linux")]
mod dns01_cloudflare;
mod dns01_provider;
mod dns_propagation;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod dns_propagation_hosted;
mod durable;
mod durable_capability;
mod durable_catalog;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod durable_hosted;
#[cfg(target_os = "linux")]
mod hosted_component_backup;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod hosted_daemon;
#[cfg(target_os = "linux")]
mod hosted_key_store;
#[cfg(target_os = "linux")]
mod hosted_secret;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod hot_reload;
mod identity;
mod identity_service;
mod keyed_authenticator;
mod lifecycle_service;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod lifecycle_transport_hosted;
mod manager;
mod native_service;
mod p256_signer;
mod renewal_executor;
mod renewal_journal;
mod revocation;
mod scheduler;
mod sealed_key_capability;
mod service_loop;
mod status;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod tls_signing_adapter;

pub use acme_operation_journal::{
    AcmeOperationJournal, AcmeOperationJournalError, AcmeOperationStage,
    ACME_OPERATION_JOURNAL_BYTES,
};
pub use administration::{
    decode_administration_request, encode_administration_request, AdministrationClass,
    AdministrationCodecError, AdministrationRequest, CanonicalAdministrationProvider,
    ADMINISTRATION_HEADER_BYTES, MAX_ADMINISTRATION_PAYLOAD_BYTES,
};
pub use backup::{
    create_backup, create_recoverable_backup, prepare_sealed_key_record, restore_backup,
    restore_sealed_key_record, untrusted_backup_container_digest, verify_backup, BackupDescriptor,
    BackupError, BackupRestoreTarget, SealedKeyProvider, BACKUP_VERSION, MAX_BACKUP_BYTES,
    MAX_BACKUP_RECORDS, MAX_SEALED_KEY_BYTES,
};
pub use backup_export::{
    decode_backup_export_command, decode_backup_export_receipt, encode_backup_export_command,
    encode_backup_export_receipt, BackupExportCommand, BackupExportError, BackupExportReceipt,
    BackupExportSession, BackupExportSource, BACKUP_EXPORT_COMMAND_BYTES,
    BACKUP_EXPORT_RECEIPT_BYTES, MAX_BACKUP_EXPORT_CHUNK,
};
pub use backup_transfer::{
    decode_backup_transfer_command, decode_backup_transfer_receipt, encode_backup_transfer_command,
    encode_backup_transfer_receipt, BackupTransferCommand, BackupTransferError,
    BackupTransferLifecycle, BackupTransferProgress, BackupTransferPurpose, BackupTransferReceipt,
    BackupTransferReceiptState, BackupUploadSession, BACKUP_TRANSFER_HEADER_BYTES,
    BACKUP_TRANSFER_RECEIPT_BYTES, MAX_BACKUP_TRANSFER_CHUNK, MAX_BACKUP_WIRE_CHUNK,
};
pub use caa::{CaaChallengeMethod, CaaError, CaaPolicy, MAX_CAA_RECORDS, MAX_CAA_RECORD_BYTES};
pub use catalog_lifecycle_provider::{
    CatalogLifecycleProvider, CertificateLifecycleSupplementalProvider,
};
pub use certd_candidate_protocol::{
    decode_certd_candidate_request, encode_certd_candidate_request, CertdActivationRequest,
    CertdCandidateProtocolError, CertdCandidateRequest, CertdCandidateStage, CertdCandidateState,
    CERTD_ACTIVATION_REQUEST_BYTES, CERTD_CANDIDATE_STATE_BYTES, MAX_CERTD_CANDIDATE_CHAIN_BYTES,
};
pub use certd_channel::{
    decode_certd_channel_request, encode_certd_channel_request, CertdChannelCapability,
    CertdChannelError, CertdChannelOperation, CertdChannelPolicy, CertdChannelRequest,
    CertdChannelRole, CertdPeerIdentity, CertdReplayWindow, CERTD_CHANNEL_CAPABILITY_BYTES,
    CERTD_CHANNEL_HEADER_BYTES, MAX_CERTD_CHANNEL_PAYLOAD_BYTES,
};
#[cfg(target_os = "linux")]
pub use certd_channel_unix::{
    UnixCertdChannelError, UnixCertdListener, UnixCertdSession, CERTD_CHANNEL_IO_TIMEOUT_MILLIS,
    MAX_CERTD_CHANNEL_CONNECTIONS_PER_RUN,
};
#[cfg(target_os = "linux")]
pub use certd_config::{
    parse_certd_config, CertdConfig, CertdConfigError,
    CertdDirectoryClass, MAX_CERTD_CONFIG_BYTES,
};
pub use certd_identifier_set::certd_identifier_set_digest;
pub use certd_jws_protocol::{
    decode_certd_jws_request, encode_certd_jws_request, CertdJwsProtocolError,
    CERTD_JWS_REQUEST_HEADER_BYTES, MAX_CERTD_JWS_PAYLOAD_BYTES,
};
pub use certd_key_protocol::{
    decode_certd_account_key_request, decode_certd_tls_key_request,
    encode_certd_account_key_request, encode_certd_tls_key_request, encode_certd_tls_key_response,
    CertdAccountKeyRequest, CertdKeyProtocolError, CertdTlsKeyRequest,
    CERTD_ACCOUNT_KEY_REQUEST_BYTES, CERTD_P256_PUBLIC_KEY_BYTES, CERTD_TLS_KEY_REQUEST_BYTES,
    CERTD_TLS_KEY_RESPONSE_BYTES,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use certificate::HostedCertificateChainVerifier;
pub use certificate::{
    retrieve_and_select_certificate_chain, retrieve_and_verify_certificate,
    retrieve_certificate_chain, select_alternate_chain, AlternateChainPolicy,
    CertificateChainVerifier, CertificateRetrievalError, CertificateValidationError,
    CertificateValidationPolicy, PemCertificateChain, RetrievedCertificate,
    SelectedCertificateChain, VerifiedCertificateReceipt, MAX_ALTERNATE_CHAINS, MAX_CERTIFICATES,
    MAX_CERTIFICATE_CHAIN_BYTES, MAX_CERTIFICATE_DER_BYTES, MAX_IDENTITY_NAMES,
};
pub use challenge_dns::{
    AuthoritativeChallengeZone, DnsChallengeError, MAX_DNS_PACKET, MAX_DNS_TXT_RECORDS,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use challenge_dns_hosted::{
    HostedDnsChallengeError, HostedDnsChallengeSockets, DNS_IO_TIMEOUT_MILLIS,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use challenge_http::{
    HostedHttp01Challenge, HostedHttp01Error, HTTP01_READ_TIMEOUT_MILLIS,
    HTTP01_WRITE_TIMEOUT_MILLIS,
};
pub use challenge_publisher::DnsChallengePublisher;
pub use challenge_service::{
    dispatch_challenge_call, CertificateChallengeProvider, ChallengeDispatchError,
    PreparedChallenge,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use challenge_tls_alpn_hosted::{
    HostedTlsAlpn01Challenge, HostedTlsAlpn01Error, TemporaryTlsAlpnSigningKey,
    TLS_ALPN01_READ_TIMEOUT_MILLIS, TLS_ALPN01_WRITE_TIMEOUT_MILLIS,
};
pub use constrained_acme_signing::{
    write_constrained_acme_jws, AcmeJwsOperation, ConstrainedAcmeJwsError,
    ConstrainedAcmeJwsPolicy, ConstrainedAcmeJwsRequest,
};
pub use deployment_journal::{
    commit_or_resolve_deployment, DeploymentJournalError, DurableDeploymentReceipt,
    DurableDeploymentStage, DEPLOYMENT_PAYLOAD_VERSION,
};
#[cfg(target_os = "linux")]
pub use dns01_cloudflare::CloudflareDns01Provider;
pub use dns01_provider::{
    dns01_publication_binding, Dns01Provider, Dns01ProviderError, Dns01PublicationReceipt,
    Dns01PublicationRequest, Dns01RecordName, Dns01TxtValue, DNS01_TXT_VALUE_BYTES,
    MAX_DNS01_PROVIDER_RECORD_ID_BYTES, MAX_DNS01_RECORD_NAME_BYTES,
};
pub use dns_propagation::{
    DnsObservationClass, DnsObservationRoute, DnsPropagationError, DnsPropagationObserver,
    DnsPropagationPolicy, DnsPropagationQuery, DnsPropagationReceipt, DnsTxtObservationReceipt,
    DnsTxtObservationRequest, MAX_PROPAGATION_ATTEMPTS,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use dns_propagation_hosted::{
    HostedDnsObservationEndpoint, HostedDnsPropagationError, HostedDnsPropagationQuery,
};
pub use durable::{
    CommittedStoreReceipt, DurableAuthenticator, DurableError, DurableNamespace, DurableObjectId,
    DurableRecord, DurableRecordKind, DurableStateStore, DurableTransaction, PreparedStoreReceipt,
    SecretHandle, TransactionState, DURABLE_RECORD_VERSION, MAX_DURABLE_PAYLOAD,
    MAX_DURABLE_RECORD_BYTES,
};
pub use durable_capability::{CapabilityDurableStateStore, CertificateDurableStorageCapability};
pub use durable_catalog::{
    reconstruct_durable_catalog, DurableCatalogEntry, DurableCatalogError,
    MAX_DURABLE_CATALOG_RECORDS,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use durable_hosted::HostedDurableStateStore;
#[cfg(target_os = "linux")]
pub use hosted_component_backup::{
    create_hosted_backup_manifest, create_hosted_component_backup, restore_hosted_component_backup,
    verify_hosted_backup_manifest, verify_hosted_component_backup, HostedBackupDescriptor,
    HostedBackupError, HostedBackupRole, HostedBackupSource, HOSTED_BACKUP_MANIFEST_BYTES,
    MAX_HOSTED_BACKUP_BYTES, MAX_HOSTED_BACKUP_FILES, MAX_HOSTED_BACKUP_FILE_BYTES,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use hosted_daemon::{
    run_hosted_lifecycle_daemon, HostedLifecycleDaemonError, HostedLifecycleSessionService,
    HostedLifecycleSupervisor, HostedLifecycleSupervisorEvent, ReconstructingLifecycleService,
    MAX_HOSTED_LIFECYCLE_SESSIONS_PER_RUN,
};
#[cfg(target_os = "linux")]
pub use hosted_key_store::{
    HostedP256KeyDescriptor, HostedP256KeyError, HostedP256KeyRole, HostedP256KeyStore,
};
#[cfg(target_os = "linux")]
pub use hosted_secret::{
    load_durable_authenticator, HostedSecret, HostedSecretError, MAX_HOSTED_SECRET_BYTES,
    PRODUCTION_SECRET_MODE,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use hot_reload::{
    HostedCandidateHandshakeTester, HostedSigningRouteResolver, HostedTlsIdentityDeploymentTarget,
    HostedTlsIdentityPublication, PublishedTlsIdentity, TlsIdentityHealth,
};
pub use identity::{
    ActivationReceipt, ApprovedTls13CertificateVerify, CandidateDeploymentRetirementReceipt,
    CandidateDeploymentRetirementTarget, CandidateKeyRetirementReceipt,
    CandidateKeyRetirementTarget, DeploymentState, IdentityConsumerCapability,
    IdentityDeploymentTarget, IdentityError, IdentityManager, PreparedIdentityReceipt,
    RecoveredIdentityMaterial, TestedIdentityReceipt, TlsCertificateSigningKey,
    TlsIdentityDescriptor, TlsIdentityId, TlsKeyIdentity, TlsSigningRoute,
};
pub use identity_service::{dispatch_identity_call, CertificateIdentityProvider};
pub use keyed_authenticator::{HmacSha256DurableAuthenticator, DURABLE_AUTHENTICATION_KEY_BYTES};
pub use lifecycle_service::{
    dispatch_lifecycle_call, CertificateLifecycleAuthorizer, CertificateLifecycleProvider,
    LifecycleDispatchError,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use lifecycle_transport_hosted::{
    HostedLifecycleClient, HostedLifecycleServer, HostedLifecycleSessionCapability,
    HostedLifecycleTransportError, MAX_HOSTED_LIFECYCLE_MEMORY,
};
pub use manager::{
    CertificateManager, CertificateManagerError, ManagedIdentityStatus, RenewalLease,
    MAX_MANAGED_IDENTITIES,
};
pub use mrml_acme::{write_pkcs10_csr, MAX_CSR_BYTES, MAX_CSR_IDENTIFIERS};
pub use mrml_crypto::p256_public_key_is_valid;
pub use native_service::{
    CertificateNativeRoute, CertificateNativeServiceError, CertificateNativeServiceLoop,
    CertificateNativeSyscalls, CertificateRawSyscall, CertificateSyscallFrame,
    CertificateUserspaceSyscallError, CertificateUserspaceSyscalls, ReceivedCertificateCall,
    MAX_CERTIFICATE_CALL_BYTES, MAX_CERTIFICATE_SHARED_BYTES,
};
pub use p256_signer::{AccountP256SigningKey, CertificateP256SigningKey};
pub use renewal_executor::{
    execute_due_renewal, resolve_uncertain_renewal, validate_recovered_renewal_material,
    IssuedRenewalCandidate, RenewalExecutionError, RenewalIssuer, RenewalRecoveryError,
    RenewalRecoveryMaterialRole,
};
pub use renewal_journal::{
    commit_or_resolve_renewal, DurableRenewalCheckpointSink, DurableRenewalStage,
    RenewalCandidateBinding, RenewalCheckpointSink, RenewalJournal, RenewalJournalError,
    RENEWAL_PAYLOAD_VERSION,
};
pub use revocation::{
    AcmeRevocationAuthority, AcmeRevocationSigningIdentity, AutomaticRevocationCause,
    PreparedRevocation, RevocationAuthentication, RevocationAuthority, RevocationAuthorization,
    RevocationCredentialPolicy, RevocationError, RevocationLifecycle, RevocationReason,
    RevocationReceipt, RevocationState,
};
pub use scheduler::{
    ExpiryHealth, RenewalEntropy, RenewalPolicy, RenewalSchedule, RenewalSource,
    ReplacementBinding, SchedulerError, RENEWAL_SCHEDULE_BYTES,
};
pub use sealed_key_capability::{
    CapabilitySealedKeyProvider, RestoreKeyCapabilityReceipt, SealKeyCapabilityReceipt,
    SealedKeyCapabilityBackend,
};
pub use service_loop::{
    dispatch_signing_call, serve_native_challenge_once, serve_native_identity_once,
    serve_native_lifecycle_once, serve_native_signing_once, CertificateSigningProvider,
    CertificateSigningServiceError,
};
pub use status::{
    decode_managed_identity_status, encode_managed_identity_status, ManagedStatusCodecError,
    MAX_MANAGED_STATUS_BYTES,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use tls_signing_adapter::IdentityTlsSigningAdapter;
