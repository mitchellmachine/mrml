use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use mrml_certificate::{CertdChannelCapability, CertdPeerIdentity};
use mrml_crypto::erase_secret_bytes;
use mrml_git::RemoteProtectedReceiveAuthority;
use mrml_git_authority::{AuthorityCapability, AuthorityPeer};
use mrml_gitd::{
    admit_catalog_repository, build_certd_tls_server_config_with_route, compose_gitd_service,
    initialize_catalog_repository, initialize_empty_token_store,
    inspect_admitted_repository_recovery, issue_access_token, load_deployment_catalog,
    load_gitd_authentication, load_gitd_config, load_quic_retry_key, prove_identity_signing_route,
    recover_admitted_repository, refresh_certd_tls_config, reload_gitd_authentication,
    revoke_access_token,
    validate_identity_snapshot, validate_storage_layout, GitAuthorityChannelClient,
    GitdBoundListeners, GitdCertdChannelClient, GitdCertdSigningRoute, GitdCompositionError,
    GitdHttp2WorkerPool, GitdHttp3Reactor, GitdHttp3WorkerPool, GitdTlsConfigStore,
};
use mrml_http::{AccessScopes, RepositoryIdentity};
use mrml_openpgp::{parse_public_key_v6_ascii, MAX_OPENPGP_PUBLIC_KEY_BYTES};

const O_NOFOLLOW: i32 = 0x20_000;
const O_DIRECTORY: i32 = 0x1_0000;
const LOCK_EX: i32 = 2;
const REQUEST_ID_LEASE_SIZE: u64 = 1 << 32;

unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}

fn main() {
    if run().is_err() {
        eprintln!("mrml-gitd: health check failed closed");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ()> {
    let arguments: Vec<String> = std::env::args().collect();
    if let [_, command, config_path, repository, openpgp_path, ml_dsa_path, valid_from, valid_until] =
        arguments.as_slice()
    {
        if command != "initialize-protected-policy" {
            return Err(());
        }
        let config = load_gitd_config(Path::new(config_path)).map_err(|_| ())?;
        let catalog = load_deployment_catalog(&config).map_err(|_| ())?;
        let entry = catalog
            .repositories
            .iter()
            .find(|entry| entry.repository.as_str() == repository)
            .ok_or(())?;
        let openpgp_bytes = read_public_file(
            openpgp_path,
            config.authority_uid,
            1,
            MAX_OPENPGP_PUBLIC_KEY_BYTES,
        )?;
        let mut scratch = vec![0; MAX_OPENPGP_PUBLIC_KEY_BYTES];
        let openpgp = parse_public_key_v6_ascii(&openpgp_bytes, &mut scratch).map_err(|_| ())?;
        let ml_dsa_bytes = read_public_file(
            ml_dsa_path,
            config.authority_uid,
            mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES,
            mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES,
        )?;
        let mut ml_dsa = [0; mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES];
        ml_dsa.copy_from_slice(&ml_dsa_bytes);
        let tip = mrml_gitd::initialize_catalog_protected_policy(
            &config,
            entry,
            &openpgp,
            &ml_dsa,
            valid_from.parse().map_err(|_| ())?,
            valid_until.parse().map_err(|_| ())?,
        )
        .map_err(|_| ())?;
        println!(
            "repository={} protected_tip={} trust_generation={} revocation_generation={}",
            entry.repository.as_str(),
            tip.to_hex(),
            entry.trust_generation.0,
            entry.revocation_generation.0
        );
        return Ok(());
    }
    if let [_, command, config] = arguments.as_slice() {
        if command == "listener-health" {
            let config = load_gitd_config(Path::new(config)).map_err(|_| ())?;
            let connection = mrml_tls::TlsClientStream::connect_resolved_with_alpn(
                &config.server_name,
                [127, 0, 0, 1],
                config.listen_port,
                &["h2"],
            )
            .map_err(|_| ())?;
            if connection.negotiated_protocol() != Some("h2") {
                return Err(());
            }
            println!("ready");
            return Ok(());
        }
        if command == "recovery-status" {
            let config = load_gitd_config(Path::new(config)).map_err(|_| ())?;
            validate_storage_layout(&config).map_err(|_| ())?;
            let catalog = load_deployment_catalog(&config).map_err(|_| ())?;
            load_gitd_authentication(&config, &catalog).map_err(|_| ())?;
            let mut receipt = 0u32;
            let mut complete = 0u32;
            let mut discard = 0u32;
            let mut reverify = 0u32;
            let mut uncertain = 0u32;
            for repository in &catalog.repositories {
                let admitted = admit_catalog_repository(&config, repository).map_err(|_| ())?;
                let status = inspect_admitted_repository_recovery(&config, &admitted).map_err(
                    |error| {
                        eprintln!("component=mrml-gitd event=recovery_inspection_failed category={error:?}");
                    },
                )?;
                receipt = receipt.checked_add(status.recover_receipt).ok_or(())?;
                complete = complete.checked_add(status.mark_complete).ok_or(())?;
                discard = discard
                    .checked_add(status.discard_before_activation)
                    .ok_or(())?;
                reverify = reverify
                    .checked_add(status.reverify_before_activation)
                    .ok_or(())?;
                uncertain = uncertain.checked_add(status.manual_uncertain).ok_or(())?;
            }
            println!(
                "recovery-status-v1 receipt={receipt} complete={complete} discard={discard} reverify={reverify} uncertain={uncertain}"
            );
            return Ok(());
        }
        if command != "validate-config" {
            return Err(());
        }
        let config = load_gitd_config(Path::new(config)).map_err(|error| {
            eprintln!("component=mrml-gitd event=validation_configuration_failed category={error:?}");
        })?;
        operational_event("validation_configuration_loaded");
        validate_storage_layout(&config).map_err(|_| ())?;
        operational_event("validation_storage_layout_valid");
        let catalog = load_deployment_catalog(&config).map_err(|_| ())?;
        operational_event("validation_catalog_authenticated");
        load_gitd_authentication(&config, &catalog).map_err(|_| ())?;
        operational_event("validation_authentication_loaded");
        for repository in &catalog.repositories {
            admit_catalog_repository(&config, repository).map_err(|_| ())?;
        }
        operational_event("validation_repositories_admitted");
        println!("valid");
        return Ok(());
    }
    if let [_, command, token_store, pepper, expected_uid] = arguments.as_slice() {
        let expected_uid = expected_uid.parse().map_err(|_| ())?;
        if command == "initialize-token-store" {
            initialize_empty_token_store(Path::new(token_store), Path::new(pepper), expected_uid)
                .map_err(|_| ())?;
            println!("initialized");
            return Ok(());
        }
        if command == "revoke-token" {
            let mut encoded = Vec::new();
            std::io::Read::read_to_end(&mut std::io::stdin().take(66), &mut encoded)
                .map_err(|_| ())?;
            while encoded
                .last()
                .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
            {
                encoded.pop();
            }
            let token = core::str::from_utf8(&encoded).map_err(|_| ())?;
            if token.len() != 64 {
                erase_secret_bytes(&mut encoded);
                return Err(());
            }
            let removed = revoke_access_token(
                Path::new(token_store),
                Path::new(pepper),
                expected_uid,
                token,
            );
            erase_secret_bytes(&mut encoded);
            if !removed.map_err(|_| ())? {
                return Err(());
            }
            println!("revoked");
            return Ok(());
        }
        return Err(());
    }
    if let [_, command, token_store, pepper, expected_uid, repository, scopes, valid_from, expires_at, revocation_generation, label] =
        arguments.as_slice()
    {
        if command != "issue-token" {
            return Err(());
        }
        let mut token = issue_access_token(
            Path::new(token_store),
            Path::new(pepper),
            expected_uid.parse().map_err(|_| ())?,
            RepositoryIdentity::parse(repository).map_err(|_| ())?,
            parse_scopes(scopes)?,
            valid_from.parse().map_err(|_| ())?,
            expires_at.parse().map_err(|_| ())?,
            revocation_generation.parse().map_err(|_| ())?,
            label,
        )
        .map_err(|_| ())?;
        token.expose_once(|value| println!("{value}")).ok_or(())?;
        return Ok(());
    }
    if let [_, command, config_path, signer_identity] = arguments.as_slice() {
        if command == "initialize-repository" {
            let config = load_gitd_config(Path::new(config_path)).map_err(|_| ())?;
            let catalog = load_deployment_catalog(&config).map_err(|_| ())?;
            let entry = catalog
                .repositories
                .iter()
                .find(|entry| entry.repository.as_str() == signer_identity)
                .ok_or(())?;
            let tip = initialize_catalog_repository(&config, entry).map_err(|_| ())?;
            println!(
                "repository={} initial_tip={} repository_generation={} trust_generation={} revocation_generation={}",
                entry.repository.as_str(),
                tip.to_hex(),
                entry.repository_generation.0,
                entry.trust_generation.0,
                entry.revocation_generation.0
            );
            return Ok(());
        }
        if command == "serve" {
            return serve(Path::new(config_path), signer_identity);
        }
        if command != "dependencies-health" && command != "recover-safe" {
            return Err(());
        }
        let config = load_gitd_config(Path::new(config_path)).map_err(|_| ())?;
        validate_storage_layout(&config).map_err(|_| ())?;
        let catalog = load_deployment_catalog(&config).map_err(|_| ())?;
        load_gitd_authentication(&config, &catalog).map_err(|_| ())?;
        for repository in &catalog.repositories {
            admit_catalog_repository(&config, repository).map_err(|_| ())?;
        }
        let authority_capability =
            load_authority_capability(config.authority_capability.as_path(), config.gitd_uid)?;
        let certd_capability =
            load_certd_capability(config.certd_capability.as_path(), config.gitd_uid)?;
        let (
            (authority_request_id, authority_request_id_limit),
            (certd_request_id, certd_request_id_limit),
        ) = reserve_request_id_leases(
            &config.state_root,
            config.gitd_uid,
            config.next_authority_request_id,
            config.next_certd_request_id,
        )?;
        let mut authority = GitAuthorityChannelClient::new(
            config.authority_socket.as_path(),
            authority_capability,
            AuthorityPeer {
                uid: config.gitd_uid,
                gid: config.gitd_gid,
            },
            AuthorityPeer {
                uid: config.authority_uid,
                gid: config.authority_gid,
            },
            parse_signer_identity(signer_identity)?,
            authority_request_id,
        )
        .map_err(|_| ())?
        .with_request_id_limit(authority_request_id_limit)
        .map_err(|_| ())?;
        let mut certd = GitdCertdChannelClient::new(
            config.certd_socket.as_path(),
            certd_capability,
            CertdPeerIdentity {
                uid: config.gitd_uid,
                gid: config.gitd_gid,
            },
            CertdPeerIdentity {
                uid: config.certd_uid,
                gid: config.certd_gid,
            },
            certd_request_id,
        )
        .map_err(|_| ())?
        .with_request_id_limit(certd_request_id_limit)
        .map_err(|_| ())?;
        authority.health().map_err(|_| ())?;
        certd.health().map_err(|_| ())?;
        let identity = certd
            .get_identity_snapshot(&config.server_name)
            .map_err(|_| ())?;
        let identity = validate_identity_snapshot(identity, None).map_err(|_| ())?;
        prove_identity_signing_route(&mut certd, &identity, 1).map_err(|_| ())?;
        let mut receipt_authority = RemoteProtectedReceiveAuthority::new(authority);
        for repository in &catalog.repositories {
            let admitted = admit_catalog_repository(&config, repository).map_err(|_| ())?;
            recover_admitted_repository(&config, repository, &admitted, &mut receipt_authority)
                .map_err(|_| ())?;
        }
        println!(
            "{}",
            if command == "recover-safe" {
                "safe-recovery-complete"
            } else {
                "dependencies-ready"
            }
        );
        return Ok(());
    }
    let [_, command, socket, capability_path, own_uid, own_gid, authority_uid, authority_gid, signer_identity, request_id] =
        arguments.as_slice()
    else {
        eprintln!(
            "usage: mrml-gitd validate-config CONFIG | listener-health CONFIG | recovery-status CONFIG | initialize-repository CONFIG REPOSITORY | initialize-protected-policy CONFIG REPOSITORY OPENPGP_PUBLIC ML_DSA_PUBLIC VALID_FROM VALID_UNTIL | initialize-token-store TOKEN_STORE PEPPER EXPECTED_UID | issue-token TOKEN_STORE PEPPER EXPECTED_UID REPOSITORY SCOPES VALID_FROM EXPIRES_AT REVOCATION_GENERATION LABEL | revoke-token TOKEN_STORE PEPPER EXPECTED_UID < TOKEN | dependencies-health CONFIG SIGNER_IDENTITY_HEX | recover-safe CONFIG SIGNER_IDENTITY_HEX | serve CONFIG SIGNER_IDENTITY_HEX | authority-health SOCKET CAPABILITY OWN_UID OWN_GID AUTHORITY_UID AUTHORITY_GID SIGNER_IDENTITY_HEX REQUEST_ID"
        );
        std::process::exit(64);
    };
    if command != "authority-health" {
        return Err(());
    }
    let authority_peer = parse_peer(authority_uid, authority_gid)?;
    let mut bytes = read_capability(capability_path, authority_peer.uid)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    erase_secret_bytes(&mut bytes);
    let capability = AuthorityCapability::new(key).map_err(|_| ())?;
    erase_secret_bytes(&mut key);
    let mut client = GitAuthorityChannelClient::new(
        Path::new(socket),
        capability,
        parse_peer(own_uid, own_gid)?,
        authority_peer,
        parse_signer_identity(signer_identity)?,
        request_id.parse().map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    client.health().map_err(|_| ())?;
    println!("ready");
    Ok(())
}

fn parse_scopes(input: &str) -> Result<AccessScopes, ()> {
    match input {
        "read" => Ok(AccessScopes::READ),
        "write" => Ok(AccessScopes::READ.union(AccessScopes::WRITE)),
        "admin" => Ok(AccessScopes::READ
            .union(AccessScopes::WRITE)
            .union(AccessScopes::ADMINISTER)),
        _ => Err(()),
    }
}

fn serve(config_path: &Path, signer_identity: &str) -> Result<(), ()> {
    let _termination_signals = TerminationSignals::install()?;
    let config = load_gitd_config(config_path).map_err(|_| ())?;
    validate_storage_layout(&config).map_err(|_| ())?;
    let catalog = load_deployment_catalog(&config).map_err(|_| ())?;
    operational_event("startup_configuration_valid");
    let authority_capability =
        load_authority_capability(config.authority_capability.as_path(), config.gitd_uid)?;
    let certd_capability =
        load_certd_capability(config.certd_capability.as_path(), config.gitd_uid)?;
    let (
        (authority_request_id, authority_request_id_limit),
        (certd_request_id, certd_request_id_limit),
    ) = reserve_request_id_leases(
        &config.state_root,
        config.gitd_uid,
        config.next_authority_request_id,
        config.next_certd_request_id,
    )?;
    let mut authority = GitAuthorityChannelClient::new(
        config.authority_socket.as_path(),
        authority_capability,
        AuthorityPeer {
            uid: config.gitd_uid,
            gid: config.gitd_gid,
        },
        AuthorityPeer {
            uid: config.authority_uid,
            gid: config.authority_gid,
        },
        parse_signer_identity(signer_identity)?,
        authority_request_id,
    )
    .map_err(|_| ())?
    .with_request_id_limit(authority_request_id_limit)
    .map_err(|_| ())?;
    let mut certd = GitdCertdChannelClient::new(
        config.certd_socket.as_path(),
        certd_capability,
        CertdPeerIdentity {
            uid: config.gitd_uid,
            gid: config.gitd_gid,
        },
        CertdPeerIdentity {
            uid: config.certd_uid,
            gid: config.certd_gid,
        },
        certd_request_id,
    )
    .map_err(|_| ())?
    .with_request_id_limit(certd_request_id_limit)
    .map_err(|_| ())?;
    authority.health().map_err(|_| ())?;
    certd.health().map_err(|_| ())?;
    operational_event("startup_dependencies_authenticated");
    let identity = certd
        .get_identity_snapshot(&config.server_name)
        .map_err(|_| ())?;
    let identity = validate_identity_snapshot(identity, None).map_err(|_| ())?;
    prove_identity_signing_route(&mut certd, &identity, 1).map_err(|_| ())?;
    let signing_route = GitdCertdSigningRoute::new(certd, 2).map_err(|_| ())?;
    let identity_generation = identity.snapshot().identity_generation;
    let tls_config =
        build_certd_tls_server_config_with_route(identity, &signing_route).map_err(|_| ())?;
    let tls = Arc::new(GitdTlsConfigStore::new(identity_generation, tls_config).map_err(|_| ())?);
    operational_event("startup_identity_authenticated");

    let receipt_authority = RemoteProtectedReceiveAuthority::new(authority);
    let service = compose_gitd_service(&config, &catalog, receipt_authority, 16 * 1024 * 1024)
        .map_err(|error| {
            operational_event(match error {
                GitdCompositionError::Authentication(_) => "startup_authentication_failed",
                GitdCompositionError::Admission(_) => "startup_repository_admission_failed",
                GitdCompositionError::Recovery(_) => "startup_repository_recovery_failed",
                GitdCompositionError::Backend => "startup_backend_failed",
                GitdCompositionError::Cache => "startup_cache_failed",
            });
        })?;
    operational_event("startup_recovery_complete");
    let operational_health = service.operational_health();
    let authentication = service.authentication();
    let maximum_connections = usize::try_from(config.max_connections).map_err(|_| ())?;
    if !(4..=65_536).contains(&maximum_connections) {
        return Err(());
    }
    let http2_maximum = maximum_connections / 2;
    let http3_maximum = maximum_connections - http2_maximum;
    let http2_workers = http2_maximum.min(16).min(http2_maximum / 2).max(1);
    let http3_workers = http3_maximum.min(16).min(http3_maximum / 2).max(1);
    let http2_queue = http2_maximum.checked_sub(http2_workers).ok_or(())?;
    let http3_queue = http3_maximum.checked_sub(http3_workers).ok_or(())?;
    if http2_queue == 0 || http3_queue == 0 {
        return Err(());
    }

    let retry_key = load_quic_retry_key(&config.quic_retry_key, config.gitd_uid).map_err(|_| ())?;
    let mut listeners = GitdBoundListeners::bind(
        [0, 0, 0, 0],
        config.listen_port,
        u32::try_from(http3_maximum).map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    listeners
        .configure_public_quic(
            retry_key,
            config.quic_retry_generation,
            u32::try_from(http3_maximum).map_err(|_| ())?,
        )
        .map_err(|_| ())?;
    let http2 = GitdHttp2WorkerPool::new(
        &service,
        tls.clone(),
        http2_workers,
        http2_queue,
        http2_maximum,
        8 * 1024 * 1024,
        config.max_body_bytes,
        u64::from(config.drain_seconds)
            .checked_mul(1_000)
            .ok_or(())?,
    )
    .map_err(|_| ())?;
    let http3 = GitdHttp3WorkerPool::new(
        &service,
        tls.clone(),
        http3_workers,
        http3_queue,
        http3_maximum,
        8 * 1024 * 1024,
        config.max_body_bytes,
    )
    .map_err(|_| ())?;
    let reactor = GitdHttp3Reactor::new(http3, 256 * 1024, 64).map_err(|_| ())?;
    let (tcp, mut quic) = listeners.into_parts();
    operational_event("startup_listeners_bound");
    let fatal = Arc::new(AtomicBool::new(false));
    let terminating = Arc::new(AtomicBool::new(false));
    let rotation_stop = Arc::new(AtomicBool::new(false));
    let authentication_stop = Arc::new(AtomicBool::new(false));
    let rotation_fatal = fatal.clone();
    let rotation_health = operational_health.clone();
    let worker_rotation_stop = rotation_stop.clone();
    let rotation_tls = tls.clone();
    let rotation_route = signing_route.clone();
    let rotation_server_name = config.server_name.clone();
    let rotation_worker = mrml_runtime::spawn_joinable(move || {
        while !worker_rotation_stop.load(Ordering::Acquire) {
            if refresh_certd_tls_config(
                &rotation_server_name,
                &rotation_route,
                &rotation_tls,
                1_000,
            )
            .is_err()
            {
                rotation_health.fail();
                rotation_fatal.store(true, Ordering::Release);
                break;
            }
        }
    })
    .map_err(|_| ())?;
    let reload_stop = authentication_stop.clone();
    let reload_health = operational_health.clone();
    let reload_config = config.clone();
    let reload_catalog = catalog.clone();
    let authentication_worker = mrml_runtime::spawn_joinable(move || {
        while !reload_stop.load(Ordering::Acquire) {
            std::thread::sleep(std::time::Duration::from_millis(1_000));
            if reload_stop.load(Ordering::Acquire) {
                break;
            }
            match reload_gitd_authentication(
                &authentication,
                &reload_config,
                &reload_catalog,
            ) {
                Ok(changed) => {
                    reload_health.recover_readiness();
                    if changed {
                        operational_event("authentication_generation_activated");
                    }
                }
                Err(_) => {
                    reload_health.degrade();
                    operational_event("authentication_reload_failed");
                }
            }
        }
    })
    .map_err(|_| ())?;
    let worker_fatal = fatal.clone();
    let worker_terminating = terminating.clone();
    let tcp_health = operational_health.clone();
    let _tcp_worker = mrml_runtime::spawn_joinable(move || {
        loop {
            let socket = match tcp.accept() {
                Ok(socket) => socket,
                Err(_) => break,
            };
            if worker_fatal.load(Ordering::Acquire) || worker_terminating.load(Ordering::Acquire) {
                break;
            }
            if http2.submit(socket).is_err() {
                break;
            }
        }
        tcp_health.fail();
        worker_fatal.store(true, Ordering::Release);
    })
    .map_err(|_| ())?;
    operational_health.mark_ready();
    operational_event("ready");
    loop {
        if TERMINATION_SIGNALLED.load(Ordering::Acquire) {
            terminating.store(true, Ordering::Release);
        }
        if terminating.load(Ordering::Acquire) {
            operational_event("shutdown_signal_received");
            operational_health.begin_drain();
            rotation_stop.store(true, Ordering::Release);
            authentication_stop.store(true, Ordering::Release);
            let _ = mrml_runtime::TcpStream::connect([127, 0, 0, 1], config.listen_port);
            let quic_result = reactor.shutdown(&mut quic);
            let rotation_result = rotation_worker.join();
            let authentication_result = authentication_worker.join();
            let tcp_result = _tcp_worker.join();
            return if quic_result.is_ok()
                && rotation_result
                && authentication_result
                && tcp_result
            {
                operational_event("shutdown_complete");
                Ok(())
            } else {
                operational_event("shutdown_incomplete");
                Err(())
            };
        }
        if fatal.load(Ordering::Acquire) {
            operational_event("fatal_dependency_failure");
            operational_health.begin_drain();
            let _ = reactor.shutdown(&mut quic);
            rotation_stop.store(true, Ordering::Release);
            authentication_stop.store(true, Ordering::Release);
            let _ = rotation_worker.join();
            let _ = authentication_worker.join();
            return Err(());
        }
        if reactor.step(&mut quic).is_err() {
            if TERMINATION_SIGNALLED.load(Ordering::Acquire) {
                terminating.store(true, Ordering::Release);
                continue;
            }
            operational_health.fail();
            operational_event("fatal_http3_failure");
            let _ = reactor.shutdown(&mut quic);
            fatal.store(true, Ordering::Release);
            rotation_stop.store(true, Ordering::Release);
            authentication_stop.store(true, Ordering::Release);
            let _ = rotation_worker.join();
            let _ = authentication_worker.join();
            return Err(());
        }
    }
}

fn operational_event(event: &'static str) {
    eprintln!("component=mrml-gitd event={event}");
}

static TERMINATION_SIGNALLED: AtomicBool = AtomicBool::new(false);

struct TerminationSignals;

impl TerminationSignals {
    fn install() -> Result<Self, ()> {
        const SIGINT: i32 = 2;
        const SIGTERM: i32 = 15;
        const SIG_ERR: usize = usize::MAX;
        TERMINATION_SIGNALLED.store(false, Ordering::Release);
        let handler = termination_signal_handler as *const () as usize;
        if unsafe { signal(SIGINT, handler) } == SIG_ERR
            || unsafe { signal(SIGTERM, handler) } == SIG_ERR
            || unsafe { siginterrupt(SIGINT, 1) } != 0
            || unsafe { siginterrupt(SIGTERM, 1) } != 0
        {
            return Err(());
        }
        Ok(Self)
    }
}

extern "C" fn termination_signal_handler(signal_number: i32) {
    if matches!(signal_number, 2 | 15) {
        TERMINATION_SIGNALLED.store(true, Ordering::Release);
    }
}

unsafe extern "C" {
    fn signal(signal_number: i32, handler: usize) -> usize;
    fn siginterrupt(signal_number: i32, interrupt: i32) -> i32;
}

fn parse_peer(uid: &str, gid: &str) -> Result<AuthorityPeer, ()> {
    let peer = AuthorityPeer {
        uid: uid.parse().map_err(|_| ())?,
        gid: gid.parse().map_err(|_| ())?,
    };
    if peer.uid == 0 || peer.gid == 0 {
        return Err(());
    }
    Ok(peer)
}

fn parse_signer_identity(input: &str) -> Result<[u8; 64], ()> {
    if input.len() != 128 || !input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(());
    }
    let mut output = [0u8; 64];
    for (index, destination) in output.iter_mut().enumerate() {
        *destination =
            (hex(input.as_bytes()[index * 2])? << 4) | hex(input.as_bytes()[index * 2 + 1])?;
    }
    if output == [0; 64] {
        return Err(());
    }
    Ok(output)
}

fn hex(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(()),
    }
}

fn reserve_request_id_leases(
    state_root: &Path,
    expected_owner: u32,
    authority_floor: u64,
    certd_floor: u64,
) -> Result<((u64, u64), (u64, u64)), ()> {
    if !state_root.is_absolute() || authority_floor == 0 || certd_floor == 0 {
        return Err(());
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(state_root)
        .map_err(|_| ())?;
    let metadata = directory.metadata().map_err(|_| ())?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_owner
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(());
    }
    // The directory lock serializes every cooperating Gitd process while both
    // channel high-water marks are advanced and made durable.
    if unsafe { flock(directory.as_raw_fd(), LOCK_EX) } != 0 {
        return Err(());
    }
    let authority = reserve_request_id_lease(
        state_root,
        "authority-request-id.v1",
        expected_owner,
        authority_floor,
    )?;
    let certd = reserve_request_id_lease(
        state_root,
        "certd-request-id.v1",
        expected_owner,
        certd_floor,
    )?;
    directory.sync_all().map_err(|_| ())?;
    Ok((authority, certd))
}

fn reserve_request_id_lease(
    state_root: &Path,
    name: &str,
    expected_owner: u32,
    configured_floor: u64,
) -> Result<(u64, u64), ()> {
    let path = state_root.join(name);
    let persisted = if path.exists() {
        read_request_id_high_watermark(&path, expected_owner)?
    } else {
        configured_floor
    };
    let start = persisted.max(configured_floor);
    let next = start.checked_add(REQUEST_ID_LEASE_SIZE).ok_or(())?;
    let temporary = state_root.join(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&temporary)
            .map_err(|_| ())?;
        writeln!(file, "{next}").map_err(|_| ())?;
        file.sync_all().map_err(|_| ())?;
        std::fs::rename(&temporary, &path).map_err(|_| ())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result?;
    Ok((start, next))
}

fn read_request_id_high_watermark(path: &Path, expected_owner: u32) -> Result<u64, ()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != expected_owner
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > 21
    {
        return Err(());
    }
    let mut encoded = String::new();
    file.read_to_string(&mut encoded).map_err(|_| ())?;
    let value = encoded.strip_suffix('\n').ok_or(())?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    let value = value.parse::<u64>().map_err(|_| ())?;
    (value != 0).then_some(value).ok_or(())
}

fn read_capability(path: &str, expected_owner: u32) -> Result<Vec<u8>, ()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    let mode = metadata.mode() & 0o777;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != expected_owner
        || !matches!(mode, 0o400 | 0o440 | 0o600)
        || metadata.len() != 32
    {
        return Err(());
    }
    let mut bytes = vec![0u8; 32];
    file.read_exact(&mut bytes).map_err(|_| ())?;
    Ok(bytes)
}

fn read_public_file(
    path: &str,
    expected_owner: u32,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, ()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if minimum == 0
        || minimum > maximum
        || !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o777 != 0o444
        || metadata.len() < minimum as u64
        || metadata.len() > maximum as u64
    {
        return Err(());
    }
    let mut bytes = vec![0; metadata.len() as usize];
    file.read_exact(&mut bytes).map_err(|_| ())?;
    Ok(bytes)
}

fn read_key(path: &Path, expected_owner: u32) -> Result<[u8; 32], ()> {
    let path = path.to_str().ok_or(())?;
    let mut bytes = read_capability(path, expected_owner)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    erase_secret_bytes(&mut bytes);
    Ok(key)
}

fn load_authority_capability(path: &Path, expected_owner: u32) -> Result<AuthorityCapability, ()> {
    let mut key = read_key(path, expected_owner)?;
    let capability = AuthorityCapability::new(key).map_err(|_| ());
    erase_secret_bytes(&mut key);
    capability
}

fn load_certd_capability(path: &Path, expected_owner: u32) -> Result<CertdChannelCapability, ()> {
    let mut key = read_key(path, expected_owner)?;
    let capability = CertdChannelCapability::new(key).map_err(|_| ());
    erase_secret_bytes(&mut key);
    capability
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn request_sequence_root(label: &str) -> (std::path::PathBuf, u32) {
        let root = std::env::temp_dir().join(format!(
            "mrml-gitd-request-sequence-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = std::fs::metadata(&root).unwrap().uid();
        (root, uid)
    }

    #[test]
    fn request_id_leases_advance_durably_across_restarts() {
        let (root, uid) = request_sequence_root("restart");
        assert_eq!(
            reserve_request_id_leases(&root, uid, 7, 11),
            Ok((
                (7, 7 + REQUEST_ID_LEASE_SIZE),
                (11, 11 + REQUEST_ID_LEASE_SIZE)
            ))
        );
        assert_eq!(
            reserve_request_id_leases(&root, uid, 7, 11),
            Ok((
                (7 + REQUEST_ID_LEASE_SIZE, 7 + 2 * REQUEST_ID_LEASE_SIZE),
                (11 + REQUEST_ID_LEASE_SIZE, 11 + 2 * REQUEST_ID_LEASE_SIZE)
            ))
        );
        assert_eq!(
            read_request_id_high_watermark(&root.join("authority-request-id.v1"), uid),
            Ok(7 + 2 * REQUEST_ID_LEASE_SIZE)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn request_id_leases_fail_closed_on_corrupt_or_linked_state() {
        let (root, uid) = request_sequence_root("invalid");
        let authority = root.join("authority-request-id.v1");
        std::fs::write(&authority, b"not-a-number\n").unwrap();
        std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(reserve_request_id_leases(&root, uid, 1, 1).is_err());
        std::fs::remove_file(&authority).unwrap();
        let target = root.join("target");
        std::fs::write(&target, b"9\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &authority).unwrap();
        assert!(reserve_request_id_leases(&root, uid, 1, 1).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn gitd_capability_copy_requires_its_local_file_owner() {
        let root = std::env::temp_dir().join(format!(
            "mrml-gitd-local-capability-owner-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let capability = root.join("channel.cap");
        std::fs::write(&capability, [0x51u8; 32]).unwrap();
        std::fs::set_permissions(&capability, std::fs::Permissions::from_mode(0o400)).unwrap();
        let gitd_uid = std::fs::metadata(&capability).unwrap().uid();
        assert!(load_certd_capability(&capability, gitd_uid).is_ok());
        assert!(load_certd_capability(&capability, gitd_uid.saturating_add(1)).is_err());
        std::fs::remove_file(capability).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn bootstrap_public_file_requires_exact_read_only_regular_file() {
        let root =
            std::env::temp_dir().join(format!("mrml-gitd-public-key-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let key = root.join("public.key");
        std::fs::write(&key, [7u8; 32]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o444)).unwrap();
        let uid = std::fs::metadata(&key).unwrap().uid();
        assert_eq!(
            read_public_file(key.to_str().unwrap(), uid, 32, 32).unwrap(),
            [7; 32]
        );
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_public_file(key.to_str().unwrap(), uid, 32, 32).is_err());
        let link = root.join("link.key");
        symlink(&key, &link).unwrap();
        assert!(read_public_file(link.to_str().unwrap(), uid, 1, 32).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
