use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use mrml_tls::{
    ECDSA_SECP256R1_SHA256, MAX_TLS13_SIGNATURE_BYTES, TlsError, TlsServerConfig,
    TlsServerSigningKey,
};

use crate::{GitdCertdChannelClient, ValidatedGitdIdentity};

pub struct GitdCertdTlsSigningKey {
    certd: Mutex<GitdCertdChannelClient>,
    identity_generation: u64,
    next_logical_request_id: AtomicU64,
}

impl GitdCertdTlsSigningKey {
    pub fn new(
        certd: GitdCertdChannelClient,
        identity_generation: u64,
        next_logical_request_id: u64,
    ) -> Result<Self, TlsError> {
        if identity_generation == 0 || next_logical_request_id == 0 {
            return Err(TlsError::Certificate);
        }
        Ok(Self {
            certd: Mutex::new(certd),
            identity_generation,
            next_logical_request_id: AtomicU64::new(next_logical_request_id),
        })
    }
}

impl TlsServerSigningKey for GitdCertdTlsSigningKey {
    fn signature_scheme(&self) -> u16 {
        ECDSA_SECP256R1_SHA256
    }

    fn sign_certificate_verify_transcript(
        &self,
        transcript_digest: &[u8; 32],
        output: &mut [u8; MAX_TLS13_SIGNATURE_BYTES],
    ) -> Result<usize, TlsError> {
        let request_id = self
            .next_logical_request_id
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            })
            .map_err(|_| TlsError::SequenceExhausted)?;
        let signature = self
            .certd
            .lock()
            .map_err(|_| TlsError::AuthenticationFailed)?
            .sign_tls13_certificate_verify(
                self.identity_generation,
                ECDSA_SECP256R1_SHA256,
                *transcript_digest,
                request_id,
            )
            .map_err(|_| TlsError::AuthenticationFailed)?;
        let destination = output
            .get_mut(..signature.len())
            .ok_or(TlsError::AuthenticationFailed)?;
        destination.copy_from_slice(&signature);
        Ok(signature.len())
    }
}

pub fn build_certd_tls_server_config(
    identity: ValidatedGitdIdentity,
    certd: GitdCertdChannelClient,
    next_logical_request_id: u64,
) -> Result<TlsServerConfig, TlsError> {
    let snapshot = identity.into_snapshot();
    let chain: Vec<&[u8]> = snapshot
        .certificate_chain
        .iter()
        .map(Vec::as_slice)
        .collect();
    let signer =
        GitdCertdTlsSigningKey::new(certd, snapshot.identity_generation, next_logical_request_id)?;
    TlsServerConfig::from_der_chain(&chain)?
        .require_server_name(&snapshot.server_name)
        .map(|config| config.with_signing_key(signer))
}
