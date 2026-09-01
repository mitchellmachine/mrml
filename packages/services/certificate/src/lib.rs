#![no_std]

mod certificate;
mod challenge_dns;
mod challenge_publisher;

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
