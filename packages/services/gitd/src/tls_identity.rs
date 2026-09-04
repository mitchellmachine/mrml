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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GitdTlsRefreshMetrics {
    pub attempts: u64,
    pub timeouts: u64,
    pub activations: u64,
    pub channel_failures: u64,
    pub validation_failures: u64,
}

pub struct GitdCertdTlsSigningKey {
    route: GitdCertdSigningRoute,
    identity_generation: u64,
}

#[derive(Clone)]
pub struct GitdCertdSigningRoute {
    signing_certd: Arc<Mutex<GitdCertdChannelClient>>,
    refresh_certd: Arc<Mutex<GitdCertdChannelClient>>,
    next_logical_request_id: Arc<AtomicU64>,
}

struct GitdTlsConfigState {
    generation: u64,
    config: Arc<TlsServerConfig>,
    accepting_handshakes: bool,
}

pub struct GitdTlsConfigStore {
    state: RwLock<GitdTlsConfigState>,
    refresh_attempts: AtomicU64,
    refresh_timeouts: AtomicU64,
    refresh_activations: AtomicU64,
    refresh_channel_failures: AtomicU64,
    refresh_validation_failures: AtomicU64,
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
                accepting_handshakes: true,
            }),
            refresh_attempts: AtomicU64::new(0),
            refresh_timeouts: AtomicU64::new(0),
            refresh_activations: AtomicU64::new(0),
            refresh_channel_failures: AtomicU64::new(0),
            refresh_validation_failures: AtomicU64::new(0),
        })
    }

    pub fn snapshot(&self) -> Result<(u64, Arc<TlsServerConfig>), TlsError> {
        let state = self
            .state
            .read()
            .map_err(|_| TlsError::AuthenticationFailed)?;
        if !state.accepting_handshakes {
            return Err(TlsError::Certificate);
        }
        Ok((state.generation, state.config.clone()))
    }

    pub fn block_new_handshakes(&self) -> Result<(), TlsError> {
        self.state
            .write()
            .map_err(|_| TlsError::AuthenticationFailed)?
            .accepting_handshakes = false;
        Ok(())
    }

    pub fn refresh_metrics(&self) -> GitdTlsRefreshMetrics {
        GitdTlsRefreshMetrics {
            attempts: self.refresh_attempts.load(Ordering::Acquire),
            timeouts: self.refresh_timeouts.load(Ordering::Acquire),
            activations: self.refresh_activations.load(Ordering::Acquire),
            channel_failures: self.refresh_channel_failures.load(Ordering::Acquire),
            validation_failures: self.refresh_validation_failures.load(Ordering::Acquire),
        }
    }

    fn current_generation(&self) -> Result<u64, TlsError> {
        self.state
            .read()
            .map(|state| state.generation)
            .map_err(|_| TlsError::AuthenticationFailed)
    }

    fn allow_current_handshakes(&self) -> Result<(), TlsError> {
        self.state
            .write()
            .map_err(|_| TlsError::AuthenticationFailed)?
            .accepting_handshakes = true;
        Ok(())
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
            accepting_handshakes: true,
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
        let refresh_certd = certd.clone();
        Ok(Self {
            signing_certd: Arc::new(Mutex::new(certd)),
            refresh_certd: Arc::new(Mutex::new(refresh_certd)),
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
            .signing_certd
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
    saturating_increment(&store.refresh_attempts);
    let result = refresh_certd_tls_config_inner(
        server_name,
        route,
        store,
        timeout_milliseconds,
    );
    match result {
        Ok(true) => saturating_increment(&store.refresh_activations),
        Ok(false) => saturating_increment(&store.refresh_timeouts),
        Err(GitdTlsRefreshError::Channel) => {
            saturating_increment(&store.refresh_channel_failures)
        }
        Err(_) => saturating_increment(&store.refresh_validation_failures),
    }
    result
}

fn refresh_certd_tls_config_inner(
    server_name: &str,
    route: &GitdCertdSigningRoute,
    store: &GitdTlsConfigStore,
    timeout_milliseconds: u32,
) -> Result<bool, GitdTlsRefreshError> {
    let current_generation = store
        .current_generation()
        .map_err(|_| GitdTlsRefreshError::Tls)?;
    let mut certd = route
        .refresh_certd
        .lock()
        .map_err(|_| GitdTlsRefreshError::Channel)?;
    let Some(observed_generation) = certd
        .wait_for_identity_generation(current_generation, timeout_milliseconds)
        .map_err(|_| GitdTlsRefreshError::Channel)?
    else {
        store
            .allow_current_handshakes()
            .map_err(|_| GitdTlsRefreshError::Tls)?;
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

fn saturating_increment(counter: &AtomicU64) {
    let _ = counter.try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
        Some(value.saturating_add(1))
    });
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
        assert_eq!(store.refresh_metrics(), GitdTlsRefreshMetrics::default());
        store.block_new_handshakes().unwrap();
        assert!(store.snapshot().is_err());
        let rollback = TlsServerConfig::from_der_chain(&[b"certificate"]).unwrap();
        assert!(store.install(7, rollback).is_err());
        assert!(store.snapshot().is_err());
        let replacement = TlsServerConfig::from_der_chain(&[b"certificate"]).unwrap();
        store.install(8, replacement).unwrap();
        assert_eq!(store.snapshot().unwrap().0, 8);
    }
}
