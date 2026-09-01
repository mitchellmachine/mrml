#![no_std]

mod backup;
mod caa;
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
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod durable_hosted;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod hot_reload;
mod identity;
mod identity_service;
mod lifecycle_service;
mod manager;
mod native_service;
mod p256_signer;
mod renewal_executor;
mod renewal_journal;
mod revocation;
mod scheduler;
mod service_loop;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod tls_signing_adapter;

pub use backup::{
    create_backup, create_recoverable_backup, prepare_sealed_key_record, restore_backup,
    restore_sealed_key_record, verify_backup, BackupDescriptor, BackupError, BackupRestoreTarget,
    SealedKeyProvider, BACKUP_VERSION, MAX_BACKUP_BYTES, MAX_BACKUP_RECORDS, MAX_SEALED_KEY_BYTES,
};
pub use caa::{CaaChallengeMethod, CaaError, CaaPolicy, MAX_CAA_RECORDS, MAX_CAA_RECORD_BYTES};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use certificate::HostedCertificateChainVerifier;
pub use certificate::{
    retrieve_and_select_certificate_chain, retrieve_and_verify_certificate, select_alternate_chain,
    AlternateChainPolicy, CertificateChainVerifier, CertificateRetrievalError,
    CertificateValidationError, CertificateValidationPolicy, PemCertificateChain,
    RetrievedCertificate, SelectedCertificateChain, VerifiedCertificateReceipt,
    MAX_ALTERNATE_CHAINS, MAX_CERTIFICATES, MAX_CERTIFICATE_CHAIN_BYTES, MAX_CERTIFICATE_DER_BYTES,
    MAX_IDENTITY_NAMES,
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
pub use deployment_journal::{
    commit_or_resolve_deployment, DeploymentJournalError, DurableDeploymentReceipt,
    DurableDeploymentStage, DEPLOYMENT_PAYLOAD_VERSION,
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
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use durable_hosted::HostedDurableStateStore;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use hot_reload::{
    HostedCandidateHandshakeTester, HostedSigningRouteResolver, HostedTlsIdentityDeploymentTarget,
    HostedTlsIdentityPublication, PublishedTlsIdentity,
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
pub use lifecycle_service::{
    dispatch_lifecycle_call, CertificateLifecycleAuthorizer, CertificateLifecycleProvider,
    LifecycleDispatchError,
};
pub use manager::{
    CertificateManager, CertificateManagerError, RenewalLease, MAX_MANAGED_IDENTITIES,
};
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
    ReplacementBinding, SchedulerError,
};
pub use service_loop::{
    dispatch_signing_call, serve_native_challenge_once, serve_native_identity_once,
    serve_native_lifecycle_once, serve_native_signing_once, CertificateSigningProvider,
    CertificateSigningServiceError,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use tls_signing_adapter::IdentityTlsSigningAdapter;
