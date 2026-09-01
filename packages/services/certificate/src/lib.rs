#![no_std]

mod administration;
mod backup;
mod backup_export;
mod backup_transfer;
mod caa;
mod catalog_lifecycle_provider;
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
mod deployment_journal;
mod dns_propagation;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod dns_propagation_hosted;
mod durable;
mod durable_capability;
mod durable_catalog;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod durable_hosted;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod hot_reload;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod hosted_daemon;
#[cfg(target_os = "linux")]
mod hosted_secret;
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

pub use administration::{
    ADMINISTRATION_HEADER_BYTES, AdministrationClass, AdministrationCodecError,
    AdministrationRequest, CanonicalAdministrationProvider, MAX_ADMINISTRATION_PAYLOAD_BYTES,
    decode_administration_request, encode_administration_request,
};
pub use backup::{
    BACKUP_VERSION, BackupDescriptor, BackupError, BackupRestoreTarget, MAX_BACKUP_BYTES,
    MAX_BACKUP_RECORDS, MAX_SEALED_KEY_BYTES, SealedKeyProvider, create_backup,
    create_recoverable_backup, prepare_sealed_key_record, restore_backup,
    restore_sealed_key_record, untrusted_backup_container_digest, verify_backup,
};
pub use backup_export::{
    BACKUP_EXPORT_COMMAND_BYTES, BACKUP_EXPORT_RECEIPT_BYTES, BackupExportCommand,
    BackupExportError, BackupExportReceipt, BackupExportSession, BackupExportSource,
    MAX_BACKUP_EXPORT_CHUNK, decode_backup_export_command, decode_backup_export_receipt,
    encode_backup_export_command, encode_backup_export_receipt,
};
pub use backup_transfer::{
    BACKUP_TRANSFER_HEADER_BYTES, BACKUP_TRANSFER_RECEIPT_BYTES, BackupTransferCommand,
    BackupTransferError, BackupTransferLifecycle, BackupTransferProgress, BackupTransferPurpose,
    BackupTransferReceipt, BackupTransferReceiptState, BackupUploadSession,
    MAX_BACKUP_TRANSFER_CHUNK, MAX_BACKUP_WIRE_CHUNK, decode_backup_transfer_command,
    decode_backup_transfer_receipt, encode_backup_transfer_command, encode_backup_transfer_receipt,
};
pub use caa::{CaaChallengeMethod, CaaError, CaaPolicy, MAX_CAA_RECORD_BYTES, MAX_CAA_RECORDS};
pub use catalog_lifecycle_provider::{
    CatalogLifecycleProvider, CertificateLifecycleSupplementalProvider,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use certificate::HostedCertificateChainVerifier;
pub use certificate::{
    AlternateChainPolicy, CertificateChainVerifier, CertificateRetrievalError,
    CertificateValidationError, CertificateValidationPolicy, MAX_ALTERNATE_CHAINS,
    MAX_CERTIFICATE_CHAIN_BYTES, MAX_CERTIFICATE_DER_BYTES, MAX_CERTIFICATES, MAX_IDENTITY_NAMES,
    PemCertificateChain, RetrievedCertificate, SelectedCertificateChain,
    VerifiedCertificateReceipt, retrieve_and_select_certificate_chain,
    retrieve_and_verify_certificate, select_alternate_chain,
};
pub use challenge_dns::{
    AuthoritativeChallengeZone, DnsChallengeError, MAX_DNS_PACKET, MAX_DNS_TXT_RECORDS,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use challenge_dns_hosted::{
    DNS_IO_TIMEOUT_MILLIS, HostedDnsChallengeError, HostedDnsChallengeSockets,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use challenge_http::{
    HTTP01_READ_TIMEOUT_MILLIS, HTTP01_WRITE_TIMEOUT_MILLIS, HostedHttp01Challenge,
    HostedHttp01Error,
};
pub use challenge_publisher::DnsChallengePublisher;
pub use challenge_service::{
    CertificateChallengeProvider, ChallengeDispatchError, PreparedChallenge,
    dispatch_challenge_call,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use challenge_tls_alpn_hosted::{
    HostedTlsAlpn01Challenge, HostedTlsAlpn01Error, TLS_ALPN01_READ_TIMEOUT_MILLIS,
    TLS_ALPN01_WRITE_TIMEOUT_MILLIS, TemporaryTlsAlpnSigningKey,
};
pub use deployment_journal::{
    DEPLOYMENT_PAYLOAD_VERSION, DeploymentJournalError, DurableDeploymentReceipt,
    DurableDeploymentStage, commit_or_resolve_deployment,
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
    CommittedStoreReceipt, DURABLE_RECORD_VERSION, DurableAuthenticator, DurableError,
    DurableNamespace, DurableObjectId, DurableRecord, DurableRecordKind, DurableStateStore,
    DurableTransaction, MAX_DURABLE_PAYLOAD, MAX_DURABLE_RECORD_BYTES, PreparedStoreReceipt,
    SecretHandle, TransactionState,
};
pub use durable_capability::{CapabilityDurableStateStore, CertificateDurableStorageCapability};
pub use durable_catalog::{
    DurableCatalogEntry, DurableCatalogError, MAX_DURABLE_CATALOG_RECORDS,
    reconstruct_durable_catalog,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use durable_hosted::HostedDurableStateStore;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use hot_reload::{
    HostedCandidateHandshakeTester, HostedSigningRouteResolver, HostedTlsIdentityDeploymentTarget,
    HostedTlsIdentityPublication, PublishedTlsIdentity, TlsIdentityHealth,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use hosted_daemon::{
    HostedLifecycleDaemonError, HostedLifecycleSessionService, HostedLifecycleSupervisor,
    HostedLifecycleSupervisorEvent, MAX_HOSTED_LIFECYCLE_SESSIONS_PER_RUN,
    ReconstructingLifecycleService, run_hosted_lifecycle_daemon,
};
#[cfg(target_os = "linux")]
pub use hosted_secret::{
    HostedSecret, HostedSecretError, MAX_HOSTED_SECRET_BYTES, PRODUCTION_SECRET_MODE,
    load_durable_authenticator,
};
pub use identity::{
    ActivationReceipt, ApprovedTls13CertificateVerify, CandidateDeploymentRetirementReceipt,
    CandidateDeploymentRetirementTarget, CandidateKeyRetirementReceipt,
    CandidateKeyRetirementTarget, DeploymentState, IdentityConsumerCapability,
    IdentityDeploymentTarget, IdentityError, IdentityManager, PreparedIdentityReceipt,
    RecoveredIdentityMaterial, TestedIdentityReceipt, TlsCertificateSigningKey,
    TlsIdentityDescriptor, TlsIdentityId, TlsKeyIdentity, TlsSigningRoute,
};
pub use identity_service::{CertificateIdentityProvider, dispatch_identity_call};
pub use keyed_authenticator::{
    DURABLE_AUTHENTICATION_KEY_BYTES, HmacSha256DurableAuthenticator,
};
pub use lifecycle_service::{
    CertificateLifecycleAuthorizer, CertificateLifecycleProvider, LifecycleDispatchError,
    dispatch_lifecycle_call,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use lifecycle_transport_hosted::{
    HostedLifecycleClient, HostedLifecycleServer, HostedLifecycleSessionCapability,
    HostedLifecycleTransportError, MAX_HOSTED_LIFECYCLE_MEMORY,
};
pub use manager::{
    CertificateManager, CertificateManagerError, MAX_MANAGED_IDENTITIES, ManagedIdentityStatus,
    RenewalLease,
};
pub use native_service::{
    CertificateNativeRoute, CertificateNativeServiceError, CertificateNativeServiceLoop,
    CertificateNativeSyscalls, CertificateRawSyscall, CertificateSyscallFrame,
    CertificateUserspaceSyscallError, CertificateUserspaceSyscalls, MAX_CERTIFICATE_CALL_BYTES,
    MAX_CERTIFICATE_SHARED_BYTES, ReceivedCertificateCall,
};
pub use p256_signer::{AccountP256SigningKey, CertificateP256SigningKey};
pub use renewal_executor::{
    IssuedRenewalCandidate, RenewalExecutionError, RenewalIssuer, RenewalRecoveryError,
    RenewalRecoveryMaterialRole, execute_due_renewal, resolve_uncertain_renewal,
    validate_recovered_renewal_material,
};
pub use renewal_journal::{
    DurableRenewalCheckpointSink, DurableRenewalStage, RENEWAL_PAYLOAD_VERSION,
    RenewalCandidateBinding, RenewalCheckpointSink, RenewalJournal, RenewalJournalError,
    commit_or_resolve_renewal,
};
pub use revocation::{
    AcmeRevocationAuthority, AcmeRevocationSigningIdentity, AutomaticRevocationCause,
    PreparedRevocation, RevocationAuthentication, RevocationAuthority, RevocationAuthorization,
    RevocationCredentialPolicy, RevocationError, RevocationLifecycle, RevocationReason,
    RevocationReceipt, RevocationState,
};
pub use scheduler::{
    ExpiryHealth, RenewalEntropy, RenewalPolicy, RenewalSchedule, RenewalSource,
    ReplacementBinding, SchedulerError,
};
pub use sealed_key_capability::{
    CapabilitySealedKeyProvider, RestoreKeyCapabilityReceipt, SealKeyCapabilityReceipt,
    SealedKeyCapabilityBackend,
};
pub use service_loop::{
    CertificateSigningProvider, CertificateSigningServiceError, dispatch_signing_call,
    serve_native_challenge_once, serve_native_identity_once, serve_native_lifecycle_once,
    serve_native_signing_once,
};
pub use status::{
    MAX_MANAGED_STATUS_BYTES, ManagedStatusCodecError, decode_managed_identity_status,
    encode_managed_identity_status,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use tls_signing_adapter::IdentityTlsSigningAdapter;
