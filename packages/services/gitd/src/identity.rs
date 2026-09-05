use mrml_crypto::Sha256;
use mrml_tls::{Certificate, ECDSA_SECP256R1_SHA256, verify_server_chain};

use crate::{GitdCertdChannelClient, GitdIdentitySnapshot};

const PUBLICATION_DOMAIN: &[u8] = b"MRML-GITD-TLS-IDENTITY-PUBLICATION-V1\0";
const PROOF_DOMAIN: &[u8] = b"MRML-GITD-TLS-IDENTITY-PROOF-V1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitdIdentityValidationError {
    Generation,
    Certificate(mrml_tls::CertificateError),
    Hostname,
    Validity,
    Spki,
    Algorithm,
    Publication,
    Signing,
}

pub struct ValidatedGitdIdentity {
    snapshot: GitdIdentitySnapshot,
    validity: (u64, u64),
}

impl ValidatedGitdIdentity {
    pub fn snapshot(&self) -> &GitdIdentitySnapshot {
        &self.snapshot
    }

    pub fn into_snapshot(self) -> GitdIdentitySnapshot {
        self.snapshot
    }

    /// Intersection of all presented certificate validity intervals.
    pub fn validity_interval(&self) -> (u64, u64) {
        self.validity
    }
}

pub fn validate_identity_snapshot(
    snapshot: GitdIdentitySnapshot,
    previous_generation: Option<u64>,
) -> Result<ValidatedGitdIdentity, GitdIdentityValidationError> {
    if previous_generation.is_some_and(|previous| snapshot.identity_generation <= previous) {
        return Err(GitdIdentityValidationError::Generation);
    }
    let chain: Vec<&[u8]> = snapshot
        .certificate_chain
        .iter()
        .map(Vec::as_slice)
        .collect();
    verify_server_chain(&snapshot.server_name, &chain)
        .map_err(GitdIdentityValidationError::Certificate)?;
    let mut validity = (0, u64::MAX);
    for encoded in &chain {
        let certificate =
            Certificate::parse(encoded).map_err(GitdIdentityValidationError::Certificate)?;
        certificate
            .require_no_tls_features()
            .map_err(GitdIdentityValidationError::Certificate)?;
        validity.0 = validity.0.max(certificate.not_before());
        validity.1 = validity.1.min(certificate.not_after());
    }
    let leaf = Certificate::parse(snapshot.certificate_chain.first().ok_or(
        GitdIdentityValidationError::Certificate(mrml_tls::CertificateError::Malformed),
    )?)
    .map_err(GitdIdentityValidationError::Certificate)?;
    leaf.verify_hostname(&snapshot.server_name)
        .map_err(|_| GitdIdentityValidationError::Hostname)?;
    if leaf.not_before() != snapshot.not_before_unix_seconds
        || leaf.not_after() != snapshot.not_after_unix_seconds
    {
        return Err(GitdIdentityValidationError::Validity);
    }
    if leaf.spki_sha256() != snapshot.leaf_spki_sha256 {
        return Err(GitdIdentityValidationError::Spki);
    }
    if snapshot.signature_schemes.as_slice() != [ECDSA_SECP256R1_SHA256] {
        return Err(GitdIdentityValidationError::Algorithm);
    }
    if publication_digest(&snapshot)? != snapshot.publication_digest {
        return Err(GitdIdentityValidationError::Publication);
    }
    Ok(ValidatedGitdIdentity { snapshot, validity })
}

pub fn prove_identity_signing_route(
    certd: &mut GitdCertdChannelClient,
    identity: &ValidatedGitdIdentity,
    logical_request_id: u64,
) -> Result<(), GitdIdentityValidationError> {
    let snapshot = identity.snapshot();
    let mut digest = Sha256::new();
    digest.update(PROOF_DOMAIN);
    digest.update(&snapshot.identity_generation.to_be_bytes());
    digest.update(&snapshot.publication_digest);
    digest.update(snapshot.server_name.as_bytes());
    let transcript_digest = digest.finalize();
    let signature = certd
        .sign_tls13_certificate_verify(
            snapshot.identity_generation,
            ECDSA_SECP256R1_SHA256,
            transcript_digest,
            logical_request_id,
        )
        .map_err(|_| GitdIdentityValidationError::Signing)?;
    let leaf = Certificate::parse(&snapshot.certificate_chain[0])
        .map_err(GitdIdentityValidationError::Certificate)?;
    leaf.verify_tls13_server_certificate_verify(
        &transcript_digest,
        ECDSA_SECP256R1_SHA256,
        &signature,
    )
    .map_err(|_| GitdIdentityValidationError::Signing)
}

fn publication_digest(
    snapshot: &GitdIdentitySnapshot,
) -> Result<[u8; 32], GitdIdentityValidationError> {
    let name_length = u16::try_from(snapshot.server_name.len())
        .map_err(|_| GitdIdentityValidationError::Publication)?;
    let chain_count = u8::try_from(snapshot.certificate_chain.len())
        .map_err(|_| GitdIdentityValidationError::Publication)?;
    let scheme_count = u8::try_from(snapshot.signature_schemes.len())
        .map_err(|_| GitdIdentityValidationError::Publication)?;
    let mut digest = Sha256::new();
    digest.update(PUBLICATION_DOMAIN);
    digest.update(&name_length.to_be_bytes());
    digest.update(snapshot.server_name.as_bytes());
    digest.update(&snapshot.identity_generation.to_be_bytes());
    digest.update(&[chain_count]);
    for certificate in &snapshot.certificate_chain {
        let length = u32::try_from(certificate.len())
            .map_err(|_| GitdIdentityValidationError::Publication)?;
        digest.update(&length.to_be_bytes());
        digest.update(certificate);
    }
    digest.update(&snapshot.leaf_spki_sha256);
    digest.update(&snapshot.not_before_unix_seconds.to_be_bytes());
    digest.update(&snapshot.not_after_unix_seconds.to_be_bytes());
    digest.update(&[scheme_count]);
    for scheme in &snapshot.signature_schemes {
        digest.update(&scheme.to_be_bytes());
    }
    Ok(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_and_malformed_certificate_fail_before_publication() {
        let snapshot = GitdIdentitySnapshot {
            server_name: "git.example.com".into(),
            identity_generation: 7,
            certificate_chain: vec![vec![0x30, 0]],
            leaf_spki_sha256: [1; 32],
            not_before_unix_seconds: 1,
            not_after_unix_seconds: 2,
            signature_schemes: vec![ECDSA_SECP256R1_SHA256],
            publication_digest: [2; 32],
        };
        assert!(matches!(
            validate_identity_snapshot(snapshot.clone(), Some(7)),
            Err(GitdIdentityValidationError::Generation)
        ));
        assert!(matches!(
            validate_identity_snapshot(snapshot, Some(6)),
            Err(GitdIdentityValidationError::Certificate(_))
        ));
    }
}
