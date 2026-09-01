#![no_std]

mod backup;
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
mod dns_propagation;
mod durable;
mod identity;
mod identity_service;
mod lifecycle_service;
mod native_service;
mod p256_signer;
mod revocation;
mod scheduler;
mod service_loop;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod tls_signing_adapter;

pub use backup::{
    BACKUP_VERSION, BackupDescriptor, BackupError, BackupRestoreTarget, MAX_BACKUP_BYTES,
    MAX_BACKUP_RECORDS, MAX_SEALED_KEY_BYTES, SealedKeyProvider, create_backup,
    create_recoverable_backup, prepare_sealed_key_record, restore_backup,
    restore_sealed_key_record, verify_backup,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use certificate::HostedCertificateChainVerifier;
pub use certificate::{
    AlternateChainPolicy, CertificateChainVerifier, CertificateRetrievalError,
    CertificateValidationError, CertificateValidationPolicy, MAX_ALTERNATE_CHAINS,
    MAX_CERTIFICATE_CHAIN_BYTES, MAX_CERTIFICATE_DER_BYTES, MAX_CERTIFICATES, MAX_IDENTITY_NAMES,
    PemCertificateChain, RetrievedCertificate, SelectedCertificateChain,
    VerifiedCertificateReceipt, retrieve_and_verify_certificate, select_alternate_chain,
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
pub use dns_propagation::{
    DnsObservationClass, DnsObservationRoute, DnsPropagationError, DnsPropagationObserver,
    DnsPropagationPolicy, DnsPropagationQuery, DnsPropagationReceipt, DnsTxtObservationReceipt,
    DnsTxtObservationRequest, MAX_PROPAGATION_ATTEMPTS,
};
pub use durable::{
    CommittedStoreReceipt, DURABLE_RECORD_VERSION, DurableAuthenticator, DurableError,
    DurableNamespace, DurableObjectId, DurableRecord, DurableRecordKind, DurableStateStore,
    DurableTransaction, MAX_DURABLE_PAYLOAD, MAX_DURABLE_RECORD_BYTES, PreparedStoreReceipt,
    SecretHandle, TransactionState,
};
pub use identity::{
    ActivationReceipt, ApprovedTls13CertificateVerify, DeploymentState, IdentityConsumerCapability,
    IdentityDeploymentTarget, IdentityError, IdentityManager, PreparedIdentityReceipt,
    TestedIdentityReceipt, TlsCertificateSigningKey, TlsIdentityDescriptor, TlsIdentityId,
    TlsKeyIdentity, TlsSigningRoute,
};
pub use identity_service::{CertificateIdentityProvider, dispatch_identity_call};
pub use lifecycle_service::{
    CertificateLifecycleAuthorizer, CertificateLifecycleProvider, LifecycleDispatchError,
    dispatch_lifecycle_call,
};
pub use native_service::{
    CertificateNativeRoute, CertificateNativeServiceError, CertificateNativeServiceLoop,
    CertificateNativeSyscalls, CertificateRawSyscall, CertificateSyscallFrame,
    CertificateUserspaceSyscallError, CertificateUserspaceSyscalls, MAX_CERTIFICATE_CALL_BYTES,
    MAX_CERTIFICATE_SHARED_BYTES, ReceivedCertificateCall,
};
pub use p256_signer::{AccountP256SigningKey, CertificateP256SigningKey};
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
    CertificateSigningProvider, CertificateSigningServiceError, dispatch_signing_call,
    serve_native_challenge_once, serve_native_identity_once, serve_native_lifecycle_once,
    serve_native_signing_once,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use tls_signing_adapter::IdentityTlsSigningAdapter;
