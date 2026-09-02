use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use mrml_tls::{
    ECDSA_SECP256R1_SHA256, MAX_TLS13_SIGNATURE_BYTES, TlsError, TlsServerConfig,
    TlsServerSigningKey,
};

use crate::{
    GitdCertdChannelClient, GitdIdentityValidationError, ValidatedGitdIdentity,
    prove_identity_signing_route, validate_identity_snapshot,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitdTlsRefreshError {
    Channel,
    Generation,
    Identity(GitdIdentityValidationError),
    Tls,
}

pub struct GitdCertdTlsSigningKey {
    route: GitdCertdSigningRoute,
    identity_generation: u64,
}

#[derive(Clone)]
pub struct GitdCertdSigningRoute {
    certd: Arc<Mutex<GitdCertdChannelClient>>,
    next_logical_request_id: Arc<AtomicU64>,
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
        let route = GitdCertdSigningRoute::new(certd, next_logical_request_id)?;
        route.signer(identity_generation)
    }
}

impl GitdCertdSigningRoute {
    pub fn new(
        certd: GitdCertdChannelClient,
        next_logical_request_id: u64,
    ) -> Result<Self, TlsError> {
        if next_logical_request_id == 0 {
            return Err(TlsError::Certificate);
        }
        Ok(Self {
            certd: Arc::new(Mutex::new(certd)),
            next_logical_request_id: Arc::new(AtomicU64::new(next_logical_request_id)),
        })
    }

    fn signer(&self, identity_generation: u64) -> Result<GitdCertdTlsSigningKey, TlsError> {
        if identity_generation == 0 {
            return Err(TlsError::Certificate);
        }
        Ok(GitdCertdTlsSigningKey {
            route: self.clone(),
            identity_generation,
        })
    }

    fn allocate_logical_request_id(&self) -> Result<u64, TlsError> {
        self.next_logical_request_id
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            })
            .map_err(|_| TlsError::SequenceExhausted)
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
        let request_id = self.route.allocate_logical_request_id()?;
        let signature = self
            .route
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
    let route = GitdCertdSigningRoute::new(certd, next_logical_request_id)?;
    build_certd_tls_server_config_with_route(identity, &route)
}

pub fn build_certd_tls_server_config_with_route(
    identity: ValidatedGitdIdentity,
    route: &GitdCertdSigningRoute,
) -> Result<TlsServerConfig, TlsError> {
    let snapshot = identity.into_snapshot();
    let chain: Vec<&[u8]> = snapshot
        .certificate_chain
        .iter()
        .map(Vec::as_slice)
        .collect();
    let signer = route.signer(snapshot.identity_generation)?;
    TlsServerConfig::from_der_chain(&chain)?
        .require_server_name(&snapshot.server_name)
        .map(|config| config.with_signing_key(signer))?
        .with_protocols(&["h2", "h3"])
}

pub fn refresh_certd_tls_config(
    server_name: &str,
    route: &GitdCertdSigningRoute,
    store: &GitdTlsConfigStore,
    timeout_milliseconds: u32,
) -> Result<bool, GitdTlsRefreshError> {
    let current_generation = store.snapshot().map_err(|_| GitdTlsRefreshError::Tls)?.0;
    let mut certd = route
        .certd
        .lock()
        .map_err(|_| GitdTlsRefreshError::Channel)?;
    let Some(observed_generation) = certd
        .wait_for_identity_generation(current_generation, timeout_milliseconds)
        .map_err(|_| GitdTlsRefreshError::Channel)?
    else {
        return Ok(false);
    };
    let identity = certd
        .get_identity_snapshot(server_name)
        .map_err(|_| GitdTlsRefreshError::Channel)?;
    let identity = validate_identity_snapshot(identity, Some(current_generation))
        .map_err(GitdTlsRefreshError::Identity)?;
    if identity.snapshot().identity_generation != observed_generation {
        return Err(GitdTlsRefreshError::Generation);
    }
    let logical_request_id = route
        .allocate_logical_request_id()
        .map_err(|_| GitdTlsRefreshError::Tls)?;
    prove_identity_signing_route(&mut certd, &identity, logical_request_id)
        .map_err(GitdTlsRefreshError::Identity)?;
    drop(certd);
    let config = build_certd_tls_server_config_with_route(identity, route)
        .map_err(|_| GitdTlsRefreshError::Tls)?;
    store
        .install(observed_generation, config)
        .map_err(|_| GitdTlsRefreshError::Generation)?;
    Ok(true)
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
