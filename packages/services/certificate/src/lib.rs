#![no_std]

mod certificate;
mod challenge_dns;
mod challenge_publisher;
mod identity;
mod scheduler;
mod revocation;
mod durable;

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use certificate::HostedCertificateChainVerifier;
pub use certificate::{
    CertificateChainVerifier, CertificateValidationError, CertificateValidationPolicy,
    MAX_CERTIFICATE_CHAIN_BYTES, MAX_CERTIFICATE_DER_BYTES, MAX_CERTIFICATES, MAX_IDENTITY_NAMES,
    PemCertificateChain, VerifiedCertificateReceipt,
};
pub use challenge_dns::{
    AuthoritativeChallengeZone, DnsChallengeError, MAX_DNS_PACKET, MAX_DNS_TXT_RECORDS,
};
pub use challenge_publisher::DnsChallengePublisher;
pub use identity::{
    ActivationReceipt, ApprovedTls13CertificateVerify, DeploymentState, IdentityConsumerCapability,
    IdentityDeploymentTarget, IdentityError, IdentityManager, PreparedIdentityReceipt,
    TestedIdentityReceipt, TlsCertificateSigningKey, TlsIdentityDescriptor, TlsIdentityId,
    TlsKeyIdentity, TlsSigningRoute,
};
pub use scheduler::{
    ExpiryHealth, RenewalEntropy, RenewalPolicy, RenewalSchedule, RenewalSource,
    ReplacementBinding, SchedulerError,
};
pub use revocation::{
    AutomaticRevocationCause, PreparedRevocation, RevocationAuthentication, RevocationAuthority,
    RevocationAuthorization, RevocationCredentialPolicy, RevocationError, RevocationLifecycle,
    RevocationReason, RevocationReceipt, RevocationState,
};
pub use durable::{
    CommittedStoreReceipt, DURABLE_RECORD_VERSION, DurableAuthenticator, DurableError,
    DurableNamespace, DurableObjectId, DurableRecord, DurableRecordKind, DurableStateStore,
    DurableTransaction, MAX_DURABLE_PAYLOAD, MAX_DURABLE_RECORD_BYTES, PreparedStoreReceipt,
    SecretHandle, TransactionState,
};
