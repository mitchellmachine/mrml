use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
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
    recover_admitted_repository, refresh_certd_tls_config, revoke_access_token,
    validate_identity_snapshot, validate_storage_layout, GitAuthorityChannelClient,
    GitdBoundListeners, GitdCertdChannelClient, GitdCertdSigningRoute, GitdHttp2WorkerPool,
    GitdHttp3Reactor, GitdHttp3WorkerPool, GitdTlsConfigStore,
};
use mrml_http::{AccessScopes, RepositoryIdentity};
use mrml_openpgp::{parse_public_key_v6_ascii, MAX_OPENPGP_PUBLIC_KEY_BYTES};

const O_NOFOLLOW: i32 = 0x20_000;

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
                let status =
                    inspect_admitted_repository_recovery(&config, &admitted).map_err(|_| ())?;
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
        let config = load_gitd_config(Path::new(config)).map_err(|_| ())?;
        validate_storage_layout(&config).map_err(|_| ())?;
        let catalog = load_deployment_catalog(&config).map_err(|_| ())?;
        load_gitd_authentication(&config, &catalog).map_err(|_| ())?;
        for repository in &catalog.repositories {
            admit_catalog_repository(&config, repository).map_err(|_| ())?;
        }
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
            load_authority_capability(config.authority_capability.as_path(), config.authority_uid)?;
        let certd_capability =
            load_certd_capability(config.certd_capability.as_path(), config.certd_uid)?;
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
            config.next_authority_request_id,
        )
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
            config.next_certd_request_id,
        )
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
    let termination_signals = TerminationSignals::block_current()?;
    let config = load_gitd_config(config_path).map_err(|_| ())?;
    validate_storage_layout(&config).map_err(|_| ())?;
    let catalog = load_deployment_catalog(&config).map_err(|_| ())?;
    operational_event("startup_configuration_valid");
    let authority_capability =
        load_authority_capability(config.authority_capability.as_path(), config.authority_uid)?;
    let certd_capability =
        load_certd_capability(config.certd_capability.as_path(), config.certd_uid)?;
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
        config.next_authority_request_id,
    )
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
        config.next_certd_request_id,
    )
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

    let receipt_authority = RemoteProtectedReceiveAuthority::new(authority);
    let service = compose_gitd_service(&config, &catalog, receipt_authority, 16 * 1024 * 1024)
        .map_err(|_| ())?;
    operational_event("startup_recovery_complete");
    let operational_health = service.operational_health();
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
    let signal_terminating = terminating.clone();
    let listen_port = config.listen_port;
    let _signal_worker = mrml_runtime::spawn_joinable(move || {
        if termination_signals.wait().is_ok() {
            signal_terminating.store(true, Ordering::Release);
            if let Ok(socket) = mrml_runtime::UdpSocket::bind([127, 0, 0, 1], 0) {
                let _ = socket.send_to(
                    &[0],
                    mrml_runtime::SocketAddress {
                        ip: [127, 0, 0, 1],
                        port: listen_port,
                    },
                );
            }
            let _ = mrml_runtime::TcpStream::connect([127, 0, 0, 1], listen_port);
        }
    })
    .map_err(|_| ())?;

    operational_health.mark_ready();
    operational_event("ready");
    loop {
        if terminating.load(Ordering::Acquire) {
            operational_event("shutdown_signal_received");
            operational_health.begin_drain();
            rotation_stop.store(true, Ordering::Release);
            let quic_result = reactor.shutdown(&mut quic);
            let rotation_result = rotation_worker.join();
            let tcp_result = _tcp_worker.join();
            return if quic_result.is_ok() && rotation_result && tcp_result {
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
            let _ = rotation_worker.join();
            return Err(());
        }
        if reactor.step(&mut quic).is_err() {
            if terminating.load(Ordering::Acquire) {
                continue;
            }
            operational_health.fail();
            operational_event("fatal_http3_failure");
            let _ = reactor.shutdown(&mut quic);
            fatal.store(true, Ordering::Release);
            rotation_stop.store(true, Ordering::Release);
            let _ = rotation_worker.join();
            return Err(());
        }
    }
}

fn operational_event(event: &'static str) {
    eprintln!("component=mrml-gitd event={event}");
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeSignalSet {
    bits: [u64; 16],
}

struct TerminationSignals {
    set: NativeSignalSet,
}

impl TerminationSignals {
    fn block_current() -> Result<Self, ()> {
        const SIG_BLOCK: i32 = 0;
        const SIGINT: i32 = 2;
        const SIGTERM: i32 = 15;
        let mut set = NativeSignalSet { bits: [0; 16] };
        // Linux x86_64 production adapter: block before worker creation so only
        // the dedicated synchronous waiter consumes termination signals.
        if unsafe { sigemptyset(&mut set) } != 0
            || unsafe { sigaddset(&mut set, SIGINT) } != 0
            || unsafe { sigaddset(&mut set, SIGTERM) } != 0
            || unsafe { pthread_sigmask(SIG_BLOCK, &set, core::ptr::null_mut()) } != 0
        {
            return Err(());
        }
        Ok(Self { set })
    }

    fn wait(self) -> Result<i32, ()> {
        let mut signal = 0;
        if unsafe { sigwait(&self.set, &mut signal) } == 0 && matches!(signal, 2 | 15) {
            Ok(signal)
        } else {
            Err(())
        }
    }
}

unsafe extern "C" {
    fn sigemptyset(set: *mut NativeSignalSet) -> i32;
    fn sigaddset(set: *mut NativeSignalSet, signal: i32) -> i32;
    fn pthread_sigmask(how: i32, set: *const NativeSignalSet, old: *mut NativeSignalSet) -> i32;
    fn sigwait(set: *const NativeSignalSet, signal: *mut i32) -> i32;
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
