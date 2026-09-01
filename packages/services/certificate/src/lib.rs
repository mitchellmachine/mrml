#![no_std]

mod backup;
mod certificate;
mod challenge_dns;
mod challenge_publisher;
mod durable;
mod identity;
mod revocation;
mod scheduler;

pub use backup::{
    create_backup, restore_backup, verify_backup, BackupDescriptor, BackupError,
    BackupRestoreTarget, BACKUP_VERSION, MAX_BACKUP_BYTES, MAX_BACKUP_RECORDS,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use certificate::HostedCertificateChainVerifier;
pub use certificate::{
    select_alternate_chain, AlternateChainPolicy, CertificateChainVerifier,
    CertificateValidationError, CertificateValidationPolicy, PemCertificateChain,
    SelectedCertificateChain, VerifiedCertificateReceipt, MAX_ALTERNATE_CHAINS, MAX_CERTIFICATES,
    MAX_CERTIFICATE_CHAIN_BYTES, MAX_CERTIFICATE_DER_BYTES, MAX_IDENTITY_NAMES,
};
pub use challenge_dns::{
    AuthoritativeChallengeZone, DnsChallengeError, MAX_DNS_PACKET, MAX_DNS_TXT_RECORDS,
};
pub use challenge_publisher::DnsChallengePublisher;
pub use durable::{
    CommittedStoreReceipt, DurableAuthenticator, DurableError, DurableNamespace, DurableObjectId,
    DurableRecord, DurableRecordKind, DurableStateStore, DurableTransaction, PreparedStoreReceipt,
    SecretHandle, TransactionState, DURABLE_RECORD_VERSION, MAX_DURABLE_PAYLOAD,
    MAX_DURABLE_RECORD_BYTES,
};
pub use identity::{
    ActivationReceipt, ApprovedTls13CertificateVerify, DeploymentState, IdentityConsumerCapability,
    IdentityDeploymentTarget, IdentityError, IdentityManager, PreparedIdentityReceipt,
    TestedIdentityReceipt, TlsCertificateSigningKey, TlsIdentityDescriptor, TlsIdentityId,
    TlsKeyIdentity, TlsSigningRoute,
};
pub use revocation::{
    AutomaticRevocationCause, PreparedRevocation, RevocationAuthentication, RevocationAuthority,
    RevocationAuthorization, RevocationCredentialPolicy, RevocationError, RevocationLifecycle,
    RevocationReason, RevocationReceipt, RevocationState,
};
pub use scheduler::{
    ExpiryHealth, RenewalEntropy, RenewalPolicy, RenewalSchedule, RenewalSource,
    ReplacementBinding, SchedulerError,
};
