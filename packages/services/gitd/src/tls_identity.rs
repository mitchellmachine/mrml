use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

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

struct GitdTlsConfigState {
    generation: u64,
    config: Arc<TlsServerConfig>,
}

pub struct GitdTlsConfigStore {
    state: RwLock<GitdTlsConfigState>,
}

impl GitdTlsConfigStore {
    pub fn new(generation: u64, config: TlsServerConfig) -> Result<Self, TlsError> {
        if generation == 0 {
            return Err(TlsError::Certificate);
        }
        Ok(Self {
            state: RwLock::new(GitdTlsConfigState {
                generation,
                config: Arc::new(config),
            }),
        })
    }

    pub fn snapshot(&self) -> Result<(u64, Arc<TlsServerConfig>), TlsError> {
        let state = self
            .state
            .read()
            .map_err(|_| TlsError::AuthenticationFailed)?;
        Ok((state.generation, state.config.clone()))
    }

    pub fn install(&self, generation: u64, config: TlsServerConfig) -> Result<(), TlsError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| TlsError::AuthenticationFailed)?;
        if generation <= state.generation {
            return Err(TlsError::Certificate);
        }
        *state = GitdTlsConfigState {
            generation,
            config: Arc::new(config),
        };
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_config_store_rejects_zero_and_rollback_generations() {
        let config = TlsServerConfig::from_der_chain(&[b"certificate"]).unwrap();
        assert!(GitdTlsConfigStore::new(0, config).is_err());
        let config = TlsServerConfig::from_der_chain(&[b"certificate"]).unwrap();
        let store = GitdTlsConfigStore::new(7, config).unwrap();
        assert_eq!(store.snapshot().unwrap().0, 7);
        let rollback = TlsServerConfig::from_der_chain(&[b"certificate"]).unwrap();
        assert!(store.install(7, rollback).is_err());
        let replacement = TlsServerConfig::from_der_chain(&[b"certificate"]).unwrap();
        store.install(8, replacement).unwrap();
        assert_eq!(store.snapshot().unwrap().0, 8);
    }
}
