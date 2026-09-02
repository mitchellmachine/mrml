use mrml_acme::{AcmeIdentifier, CaClass, write_key_change_inner_jws};
use mrml_certificate::{
    AccountP256SigningKey, AcmeJwsOperation, CERTD_CHANNEL_HEADER_BYTES, CertdAccountKeyRequest,
    CertdActivationRequest, CertdCandidateStage, CertdCandidateState, CertdChannelCapability,
    CertdChannelOperation, CertdChannelPolicy, CertdChannelRequest, CertdChannelRole, CertdConfig,
    CertdDirectoryClass, CertdPeerIdentity, CertdReplayWindow, CertdTlsKeyRequest,
    CertificateChainVerifier, CertificateP256SigningKey, CertificateValidationPolicy,
    ConstrainedAcmeJwsPolicy, DurableNamespace, DurableObjectId, DurableRecord, DurableRecordKind,
    DurableStateStore, HmacSha256DurableAuthenticator, HostedCertificateChainVerifier,
    HostedDurableStateStore, HostedP256KeyDescriptor, HostedP256KeyError, HostedP256KeyRole,
    HostedP256KeyStore, HostedSecret, MAX_CERTD_CHANNEL_PAYLOAD_BYTES, MAX_CERTD_CONFIG_BYTES,
    MAX_CERTIFICATE_CHAIN_BYTES, MAX_CERTIFICATES, MAX_CSR_BYTES, MAX_CSR_IDENTIFIERS,
    PRODUCTION_SECRET_MODE, PemCertificateChain, TlsCertificateSigningKey, TlsIdentityId,
    TlsKeyIdentity, TlsSigningRoute, UnixCertdListener, decode_certd_account_key_request,
    decode_certd_candidate_request, decode_certd_channel_request, decode_certd_jws_request,
    decode_certd_tls_key_request, encode_certd_candidate_request, encode_certd_channel_request,
    encode_certd_tls_key_response, parse_certd_config, write_constrained_acme_jws,
    write_pkcs10_csr,
};
use mrml_crypto::{Sha256, erase_secret_bytes, hmac_sha256};
use mrml_crypto::{ecdsa_p256_digest_verify_raw, encode_der_signature};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex};

const CERTD_UID: u32 = 21003;
const GITD_PEER: CertdPeerIdentity = CertdPeerIdentity {
    uid: 21001,
    gid: 21001,
};
const ACMED_PEER: CertdPeerIdentity = CertdPeerIdentity {
    uid: 21004,
    gid: 21004,
};
const CERTD_PEER: CertdPeerIdentity = CertdPeerIdentity {
    uid: CERTD_UID,
    gid: CERTD_UID,
};
const GITD_SOCKET: &str = "/run/mrml/certd-gitd/certd.sock";
const ACMED_SOCKET: &str = "/run/mrml/certd-acmed/certd.sock";
const UNLOCK_SECRET: &str = "/run/secrets/certd-unlock.key";
const KEY_STORE_ROOT: &str = "/var/lib/mrml/certd/keys";
const CANDIDATE_STATE_ROOT: &str = "/var/lib/mrml/certd/state";
const CANDIDATE_PATH: &str = "/var/lib/mrml/publications/candidate.bin";
const CANDIDATE_TEMP_PATH: &str = "/var/lib/mrml/publications/candidate.tmp";
const ACTIVE_PATH: &str = "/var/lib/mrml/publications/active.bin";
const ACTIVE_TEMP_PATH: &str = "/var/lib/mrml/publications/active.tmp";
const CONFIG_PATH: &str = "/etc/mrml/certd/config.json";
const TRUST_ROOTS_PATH: &str = "/etc/mrml/certd/acme-trust-roots.pem";
const GITD_CAPABILITY: &str = "/run/secrets/certd-gitd.cap";
const ACMED_CAPABILITY: &str = "/run/secrets/certd-acmed.cap";
const MAX_FRAME_BYTES: usize = CERTD_CHANNEL_HEADER_BYTES + MAX_CERTD_CHANNEL_PAYLOAD_BYTES;
const LINUX_O_NOFOLLOW: i32 = 0x20_000;
const IDENTITY_REQUEST_MAGIC: &[u8; 8] = b"MRGIDR01";
const IDENTITY_SNAPSHOT_MAGIC: &[u8; 8] = b"MRGIDS01";
const CERTIFICATE_VERIFY_REQUEST_MAGIC: &[u8; 8] = b"MRGSGN01";
const CERTIFICATE_VERIFY_RESPONSE_MAGIC: &[u8; 8] = b"MRGSGS01";
const GENERATION_WAIT_REQUEST_MAGIC: &[u8; 8] = b"MRGWAI01";
const GENERATION_WAIT_RESPONSE_MAGIC: &[u8; 8] = b"MRGWAS01";
const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
const MAX_GENERATION_WAIT_MILLISECONDS: u32 = 30_000;

struct CertdHostedState {
    config: CertdConfig,
    account_keys: Mutex<Vec<AccountP256SigningKey>>,
    certificate_keys: Mutex<Vec<CertificateP256SigningKey>>,
    trust_roots: PemCertificateChain,
    candidate: Mutex<Option<StagedCandidate>>,
    durable_authenticator: Mutex<HmacSha256DurableAuthenticator>,
    durable_state: Mutex<HostedDurableStateStore>,
}

struct StagedCandidate {
    chain: PemCertificateChain,
    identity_generation: u64,
    order_url_digest: [u8; 32],
    leaf_spki_digest: [u8; 32],
    not_before: u64,
    not_after: u64,
}

fn main() {
    if let Err(error) = application_main() {
        eprintln!("mrml-certd: {error}");
        std::process::exit(1);
    }
}

fn application_main() -> Result<(), &'static str> {
    let command = std::env::args().nth(1).unwrap_or_else(|| "serve".into());
    let config = load_config()?;
    match command.as_str() {
        "check-config" => {
            let (_authenticator, _key_store) = load_certd_storage()?;
            let _trust_roots = load_trust_roots(config)?;
            let _gitd = load_channel_capability(GITD_CAPABILITY)?;
            println!("mrml-certd configuration valid");
            Ok(())
        }
        "health" => check_hosted_health(config),
        "serve" => serve(config),
        _ => Err("usage: mrml-certd [serve|check-config|health]"),
    }
}

fn check_hosted_health(config: CertdConfig) -> Result<(), &'static str> {
    let executable = std::fs::read_link("/proc/1/exe").map_err(|_| "cannot inspect certd pid 1")?;
    if executable.file_name().and_then(|name| name.to_str()) != Some("mrml-certd") {
        return Err("mrml-certd is not container pid 1");
    }
    let (mut authenticator, key_store) = load_certd_storage()?;
    key_store
        .load_account(HostedP256KeyDescriptor {
            role: HostedP256KeyRole::AcmeAccount,
            object_id: config.account_identity,
            key_generation: config.account_generation,
            binding_generation: config.directory_generation,
            binding_digest: directory_binding(config),
        })
        .map_err(|_| "configured ACME account key is unavailable")?;
    key_store
        .load_certificate(
            HostedP256KeyDescriptor {
                role: HostedP256KeyRole::TlsIdentity,
                object_id: config.identity,
                key_generation: config.key_generation,
                binding_generation: config.policy_generation,
                binding_digest: config.identifier_set_digest,
            },
            TlsSigningRoute {
                identity: TlsIdentityId(config.identity),
                identity_generation: config.key_generation,
                key_identity: TlsKeyIdentity([0; 32]),
                route_generation: config.policy_generation,
                capability_id: route_capability(config, config.key_generation),
            },
        )
        .map_err(|_| "configured TLS key is unavailable")?;
    let state = HostedDurableStateStore::open(Path::new(CANDIDATE_STATE_ROOT))
        .map_err(|_| "cannot open certd candidate state")?;
    let object = DurableObjectId(config.identity);
    let mut encoded = [0u8; mrml_certificate::MAX_DURABLE_RECORD_BYTES];
    let length = state
        .load_authoritative(DurableNamespace::PublicState, object, &mut encoded)
        .map_err(|_| "cannot load active certificate state")?
        .ok_or("active certificate state is absent")?;
    let durable = DurableRecord::decode(&encoded[..length], &mut authenticator)
        .map_err(|_| "active certificate state authentication failed")?;
    let active = CertdCandidateState::decode(durable.payload())
        .map_err(|_| "invalid active certificate state")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system time precedes Unix epoch")?
        .as_secs();
    if durable.kind != DurableRecordKind::Certificate
        || durable.object != object
        || active.stage != CertdCandidateStage::Active
        || active.identity != config.identity
        || now < active.not_before
        || now >= active.not_after
    {
        return Err("no valid active certificate identity");
    }
    if active.key_generation != config.key_generation {
        key_store
            .load_certificate(
                HostedP256KeyDescriptor {
                    role: HostedP256KeyRole::TlsIdentity,
                    object_id: config.identity,
                    key_generation: active.key_generation,
                    binding_generation: config.policy_generation,
                    binding_digest: config.identifier_set_digest,
                },
                TlsSigningRoute {
                    identity: TlsIdentityId(config.identity),
                    identity_generation: active.key_generation,
                    key_identity: TlsKeyIdentity([0; 32]),
                    route_generation: config.policy_generation,
                    capability_id: route_capability(config, active.key_generation),
                },
            )
            .map_err(|_| "active TLS key is unavailable")?;
    }
    let publication = read_owned_publication(ACTIVE_PATH)?;
    if Sha256::digest(&publication) != active.request_digest {
        return Err("active certificate publication mismatch");
    }
    println!("mrml-certd ready generation={}", active.identity_generation);
    Ok(())
}

fn serve(config: CertdConfig) -> Result<(), &'static str> {
    let (durable_authenticator, key_store) = load_certd_storage()?;
    let trust_roots = load_trust_roots(config)?;
    let durable_state = HostedDurableStateStore::open(Path::new(CANDIDATE_STATE_ROOT))
        .map_err(|_| "cannot open certd candidate state")?;
    let state = Arc::new(load_or_create_keys(
        config,
        &key_store,
        trust_roots,
        durable_authenticator,
        durable_state,
    )?);
    let gitd_capability = load_channel_capability(GITD_CAPABILITY)?;
    let acmed_capability = load_channel_capability(ACMED_CAPABILITY)?;
    let gitd = UnixCertdListener::bind(
        Path::new(GITD_SOCKET),
        0o660,
        CertdChannelPolicy {
            role: CertdChannelRole::Gitd,
            peer: GITD_PEER,
        },
    )
    .map_err(|_| "cannot bind Gitd channel")?;
    let acmed = UnixCertdListener::bind(
        Path::new(ACMED_SOCKET),
        0o660,
        CertdChannelPolicy {
            role: CertdChannelRole::Acmed,
            peer: ACMED_PEER,
        },
    )
    .map_err(|_| "cannot bind ACME channel")?;

    std::thread::scope(|scope| {
        let gitd_state = Arc::clone(&state);
        scope.spawn(move || {
            serve_channel(
                gitd,
                gitd_capability,
                CertdChannelRole::Gitd,
                GITD_PEER,
                gitd_state,
            )
        });
        scope.spawn(move || {
            serve_channel(
                acmed,
                acmed_capability,
                CertdChannelRole::Acmed,
                ACMED_PEER,
                state,
            )
        });
    });
    Err("certd channel worker terminated")
}

fn serve_channel(
    listener: UnixCertdListener,
    capability: CertdChannelCapability,
    role: CertdChannelRole,
    expected_peer: CertdPeerIdentity,
    state: Arc<CertdHostedState>,
) {
    let mut replay = CertdReplayWindow::new();
    loop {
        let Ok(mut session) = listener.accept() else {
            break;
        };
        let mut frame = [0u8; MAX_FRAME_BYTES];
        let Ok(length) = session.read_frame(&mut frame) else {
            continue;
        };
        let Ok(request) = decode_certd_channel_request(
            &frame[..length],
            session.observed_peer(),
            CertdChannelPolicy {
                role,
                peer: expected_peer,
            },
            &capability,
            &mut replay,
        ) else {
            continue;
        };
        let operation = request.operation;
        let request_id = request.request_id;
        let mut response_payload = [0u8; MAX_CERTD_CHANNEL_PAYLOAD_BYTES];
        let Ok(response_length) = dispatch_channel_request(
            &state,
            role,
            operation,
            request.payload,
            &mut response_payload,
        ) else {
            continue;
        };
        let response = CertdChannelRequest {
            role,
            operation,
            request_id,
            peer: CERTD_PEER,
            payload: &response_payload[..response_length],
        };
        let Ok(written) = encode_certd_channel_request(response, &capability, &mut frame) else {
            continue;
        };
        let _ = session.write_frame(&frame[..written]);
    }
}

fn dispatch_channel_request(
    state: &CertdHostedState,
    role: CertdChannelRole,
    operation: CertdChannelOperation,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, ()> {
    match operation {
        CertdChannelOperation::Health => {
            if !payload.is_empty()
                || state.config.identity == [0; 16]
                || state.account_keys.is_poisoned()
                || state.certificate_keys.is_poisoned()
                || output.len() < 5
                || (role == CertdChannelRole::Gitd && load_active_candidate(state).is_err())
            {
                return Err(());
            }
            output[..5].copy_from_slice(b"ready");
            Ok(5)
        }
        CertdChannelOperation::GetIdentitySnapshot => {
            write_identity_snapshot(state, payload, output)
        }
        CertdChannelOperation::SignTls13CertificateVerify => {
            sign_gitd_certificate_verify(state, payload, output)
        }
        CertdChannelOperation::WaitForIdentityGeneration => {
            write_generation_wait(state, payload, output)
        }
        CertdChannelOperation::GetAcmeAccountPublicIdentity => {
            let request = decode_certd_account_key_request(payload).map_err(|_| ())?;
            require_account_request(state.config, request)?;
            let accounts = state.account_keys.lock().map_err(|_| ())?;
            let account = accounts
                .iter()
                .find(|key| key.account_generation() == request.account_generation)
                .ok_or(())?;
            let public = account.public_jwk().map_err(|_| ())?.sec1_uncompressed();
            if output.len() < public.len() {
                return Err(());
            }
            output[..public.len()].copy_from_slice(&public);
            Ok(public.len())
        }
        CertdChannelOperation::SignAcmeJws => {
            let request = decode_certd_jws_request(
                payload,
                state.config.directory_class == CertdDirectoryClass::LocalTest,
            )
            .map_err(|_| ())?;
            let current = request.account_generation == state.config.account_generation;
            let previous_for_rollover = request.operation == AcmeJwsOperation::KeyChange
                && request.account_generation.checked_add(1)
                    == Some(state.config.account_generation);
            if !current && !previous_for_rollover {
                return Err(());
            }
            let mut accounts = state.account_keys.lock().map_err(|_| ())?;
            let account = accounts
                .iter_mut()
                .find(|key| key.account_generation() == request.account_generation)
                .ok_or(())?;
            let public = account.public_jwk().map_err(|_| ())?;
            let jws = write_constrained_acme_jws(
                ConstrainedAcmeJwsPolicy {
                    directory_url: state.config.directory_url,
                    directory_generation: state.config.directory_generation,
                    account_generation: request.account_generation,
                    account_identity: state.config.account_identity,
                },
                request,
                &public,
                &mut *account,
                output,
            )
            .map_err(|_| ())?;
            Ok(jws.len())
        }
        CertdChannelOperation::CreateAccountRolloverInnerJws => {
            let request = decode_certd_jws_request(
                payload,
                state.config.directory_class == CertdDirectoryClass::LocalTest,
            )
            .map_err(|_| ())?;
            if request.operation != AcmeJwsOperation::KeyChange
                || request.directory_generation != state.config.directory_generation
                || request.account_generation != state.config.account_generation
                || request.account_identity != state.config.account_identity
                || request.payload != b"MRML account rollover inner v1"
            {
                return Err(());
            }
            let account_url = request.account_url.ok_or(())?;
            account_url
                .require_origin(state.config.directory_url.origin())
                .map_err(|_| ())?;
            request
                .protected_url
                .require_origin(state.config.directory_url.origin())
                .map_err(|_| ())?;
            let previous_generation = state.config.account_generation.checked_sub(1).ok_or(())?;
            let mut accounts = state.account_keys.lock().map_err(|_| ())?;
            let old_public = accounts
                .iter()
                .find(|key| key.account_generation() == previous_generation)
                .ok_or(())?
                .public_jwk()
                .map_err(|_| ())?;
            let new_key = accounts
                .iter_mut()
                .find(|key| key.account_generation() == state.config.account_generation)
                .ok_or(())?;
            let new_public = new_key.public_jwk().map_err(|_| ())?;
            new_key.authorize_generation(state.config.directory_generation, previous_generation);
            let result = write_key_change_inner_jws(
                &new_public,
                &old_public,
                &account_url,
                &request.protected_url,
                state.config.directory_generation,
                previous_generation,
                &mut *new_key,
                output,
            );
            new_key.authorize_generation(
                state.config.directory_generation,
                state.config.account_generation,
            );
            result.map(|jws| jws.len()).map_err(|_| ())
        }
        CertdChannelOperation::CreateTlsKeyGeneration => {
            let request = decode_certd_tls_key_request(payload).map_err(|_| ())?;
            require_tls_request(state.config, request)?;
            let mut certificates = state.certificate_keys.lock().map_err(|_| ())?;
            let certificate = certificates
                .iter_mut()
                .find(|key| key.key_generation() == state.config.key_generation)
                .ok_or(())?;
            let public = certificate
                .public_jwk()
                .map_err(|_| ())?
                .sec1_uncompressed();
            let response =
                encode_certd_tls_key_response(public, certificate.route().key_identity.0)
                    .map_err(|_| ())?;
            if output.len() < response.len() {
                return Err(());
            }
            output[..response.len()].copy_from_slice(&response);
            Ok(response.len())
        }
        CertdChannelOperation::CreateCertificateSigningRequest => {
            let request = decode_certd_tls_key_request(payload).map_err(|_| ())?;
            require_tls_request(state.config, request)?;
            let count = usize::from(state.config.identifier_count);
            let first = state.config.identifiers[0].ok_or(())?;
            let mut identifiers = [first; MAX_CSR_IDENTIFIERS];
            for (target, source) in identifiers
                .iter_mut()
                .zip(state.config.identifiers.iter().take(count))
            {
                *target = source.ok_or(())?;
            }
            let mut certificates = state.certificate_keys.lock().map_err(|_| ())?;
            let certificate = certificates
                .iter_mut()
                .find(|key| key.key_generation() == state.config.key_generation)
                .ok_or(())?;
            let public = certificate.public_jwk().map_err(|_| ())?;
            let csr = write_pkcs10_csr(
                &public,
                &identifiers[..count],
                state.config.wildcard_enabled,
                request.key_generation,
                request.policy_generation,
                &mut *certificate,
                output.get_mut(..MAX_CSR_BYTES).ok_or(())?,
            )
            .map_err(|_| ())?;
            Ok(csr.len())
        }
        CertdChannelOperation::StageCertificateCandidate => {
            let request = decode_certd_candidate_request(payload).map_err(|_| ())?;
            if request.identity != state.config.identity
                || request.directory_generation != state.config.directory_generation
                || request.account_generation != state.config.account_generation
                || request.key_generation != state.config.key_generation
                || request.policy_generation != state.config.policy_generation
                || request.profile != state.config.certificate_profile
            {
                return Err(());
            }
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| ())?
                .as_secs();
            let count = usize::from(state.config.identifier_count);
            let mut identifiers = [None; mrml_certificate::MAX_IDENTITY_NAMES];
            for (target, source) in identifiers
                .iter_mut()
                .zip(state.config.identifiers.iter().take(count))
            {
                *target = Some(AcmeIdentifier::Dns(source.ok_or(())?));
            }
            let mut certificates = state.certificate_keys.lock().map_err(|_| ())?;
            let certificate = certificates
                .iter_mut()
                .find(|key| key.key_generation() == state.config.key_generation)
                .ok_or(())?;
            let expected_key = certificate.public_jwk().map_err(|_| ())?;
            let mut approved_roots = [&[][..]; MAX_CERTIFICATES];
            for (index, root) in approved_roots
                .iter_mut()
                .enumerate()
                .take(state.trust_roots.count())
            {
                *root = state.trust_roots.certificate(index).ok_or(())?;
            }
            let ca_class = if state.config.directory_class
                == mrml_certificate::CertdDirectoryClass::PublicProduction
            {
                CaClass::Production
            } else {
                CaClass::Staging
            };
            let mut verifier = HostedCertificateChainVerifier {
                ca_class,
                trust_store_digest: state.config.trust_store_sha256,
                approved_roots: &approved_roots[..state.trust_roots.count()],
            };
            let verified = verifier
                .verify(
                    &request.chain,
                    &CertificateValidationPolicy {
                        policy_generation: state.config.policy_generation,
                        ca_class,
                        profile: state.config.certificate_profile,
                        order_url_digest: request.order_url_digest,
                        expected_key,
                        identifiers,
                        identifier_count: state.config.identifier_count,
                        allow_ip_identifiers: false,
                        now_unix,
                        maximum_validity_seconds: state.config.maximum_validity_seconds,
                        minimum_remaining_lifetime_seconds: state
                            .config
                            .minimum_remaining_lifetime_seconds,
                        maximum_chain_length: state.config.maximum_chain_length,
                        trust_store_digest: state.config.trust_store_sha256,
                    },
                )
                .map_err(|_| ())?;
            let approved = mrml_certificate::ApprovedTls13CertificateVerify::new(
                [0x5a; 32],
                certificate.route(),
            );
            let signature = certificate
                .sign_tls13_certificate_verify(&approved)
                .map_err(|_| ())?;
            if ecdsa_p256_digest_verify_raw(
                &expected_key.sec1_uncompressed(),
                approved.digest(),
                signature.as_bytes(),
            )
            .is_err()
            {
                return Err(());
            }
            let mut candidate = state.candidate.lock().map_err(|_| ())?;
            if let Some(existing) = candidate.as_ref() {
                if existing.chain.chain_digest() != verified.chain_digest
                    || existing.identity_generation != request.identity_generation
                    || existing.order_url_digest != request.order_url_digest
                    || existing.leaf_spki_digest != verified.leaf_spki_digest
                    || existing.not_before != verified.not_before
                    || existing.not_after != verified.not_after
                {
                    return Err(());
                }
            } else {
                persist_staged_candidate(
                    state,
                    payload,
                    verified.chain_digest,
                    verified.leaf_spki_digest,
                    verified.not_before,
                    verified.not_after,
                    request.order_url_digest,
                    request.identity_generation,
                    verified.ari_certificate_id,
                    now_unix,
                )
                .map_err(|_| ())?;
                *candidate = Some(StagedCandidate {
                    chain: request.chain,
                    identity_generation: request.identity_generation,
                    order_url_digest: request.order_url_digest,
                    leaf_spki_digest: verified.leaf_spki_digest,
                    not_before: verified.not_before,
                    not_after: verified.not_after,
                });
            }
            if output.len() < 32 {
                return Err(());
            }
            output[..32].copy_from_slice(&verified.chain_digest);
            Ok(32)
        }
        CertdChannelOperation::ActivateCertificateGeneration => {
            let request = CertdActivationRequest::decode(payload).map_err(|_| ())?;
            if request.identity != state.config.identity
                || request.directory_generation != state.config.directory_generation
                || request.account_generation != state.config.account_generation
                || request.key_generation != state.config.key_generation
                || request.policy_generation != state.config.policy_generation
            {
                return Err(());
            }
            activate_staged_candidate(state, request).map_err(|_| ())?;
            if output.len() < 32 {
                return Err(());
            }
            output[..32].copy_from_slice(&request.chain_digest);
            Ok(32)
        }
        CertdChannelOperation::GetCertificateLifecycleStatus => {
            if !payload.is_empty() {
                return Err(());
            }
            let (active, _) = load_active_candidate(state).map_err(|_| ())?;
            active.encode(output).map_err(|_| ())
        }
        CertdChannelOperation::GetActiveCertificateForRevocation => {
            if role != CertdChannelRole::Acmed || !payload.is_empty() {
                return Err(());
            }
            let (_, active) = load_active_candidate(state).map_err(|_| ())?;
            encode_certd_candidate_request(&active, output).map_err(|_| ())
        }
        _ => Err(()),
    }
}

fn write_identity_snapshot(
    state: &CertdHostedState,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, ()> {
    if payload.len() < 10 || payload.get(..8) != Some(IDENTITY_REQUEST_MAGIC) {
        return Err(());
    }
    let name_length = usize::from(u16::from_be_bytes(
        payload[8..10].try_into().map_err(|_| ())?,
    ));
    if payload.len() != 10usize.checked_add(name_length).ok_or(())? {
        return Err(());
    }
    let server_name = core::str::from_utf8(&payload[10..]).map_err(|_| ())?;
    if !configured_server_name(state.config, server_name) {
        return Err(());
    }
    let (candidate, request) = load_active_candidate(state).map_err(|_| ())?;
    let name_length = u16::try_from(server_name.len()).map_err(|_| ())?;
    let mut offset = 0usize;
    append(output, &mut offset, IDENTITY_SNAPSHOT_MAGIC)?;
    append(
        output,
        &mut offset,
        &candidate.identity_generation.to_be_bytes(),
    )?;
    append(output, &mut offset, &name_length.to_be_bytes())?;
    append(output, &mut offset, server_name.as_bytes())?;
    append(output, &mut offset, &[request.chain.count() as u8])?;
    for index in 0..request.chain.count() {
        let certificate = request.chain.certificate(index).ok_or(())?;
        let length = u32::try_from(certificate.len()).map_err(|_| ())?;
        append(output, &mut offset, &length.to_be_bytes())?;
        append(output, &mut offset, certificate)?;
    }
    append(output, &mut offset, &candidate.leaf_spki_digest)?;
    append(output, &mut offset, &candidate.not_before.to_be_bytes())?;
    append(output, &mut offset, &candidate.not_after.to_be_bytes())?;
    append(output, &mut offset, &[1])?;
    append(output, &mut offset, &ECDSA_SECP256R1_SHA256.to_be_bytes())?;
    append(output, &mut offset, &candidate.chain_digest)?;
    append(output, &mut offset, &[1])?;
    Ok(offset)
}

fn sign_gitd_certificate_verify(
    state: &CertdHostedState,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, ()> {
    if payload.len() != 58 || payload.get(..8) != Some(CERTIFICATE_VERIFY_REQUEST_MAGIC) {
        return Err(());
    }
    let generation = u64::from_be_bytes(payload[8..16].try_into().map_err(|_| ())?);
    let scheme = u16::from_be_bytes(payload[16..18].try_into().map_err(|_| ())?);
    let digest: [u8; 32] = payload[18..50].try_into().map_err(|_| ())?;
    let logical_request_id = u64::from_be_bytes(payload[50..58].try_into().map_err(|_| ())?);
    let (candidate, _) = load_active_candidate(state).map_err(|_| ())?;
    if generation != candidate.identity_generation
        || scheme != ECDSA_SECP256R1_SHA256
        || logical_request_id == 0
    {
        return Err(());
    }
    let mut certificates = state.certificate_keys.lock().map_err(|_| ())?;
    let certificate = certificates
        .iter_mut()
        .find(|key| key.key_generation() == candidate.key_generation)
        .ok_or(())?;
    let approved =
        mrml_certificate::ApprovedTls13CertificateVerify::new(digest, certificate.route());
    let signature = certificate
        .sign_tls13_certificate_verify(&approved)
        .map_err(|_| ())?;
    let mut der = [0u8; 72];
    let der = encode_der_signature(signature.as_bytes(), &mut der).map_err(|_| ())?;
    let der_length = u16::try_from(der.len()).map_err(|_| ())?;
    let mut offset = 0usize;
    append(output, &mut offset, CERTIFICATE_VERIFY_RESPONSE_MAGIC)?;
    append(output, &mut offset, &generation.to_be_bytes())?;
    append(output, &mut offset, &scheme.to_be_bytes())?;
    append(output, &mut offset, &logical_request_id.to_be_bytes())?;
    append(output, &mut offset, &der_length.to_be_bytes())?;
    append(output, &mut offset, der)?;
    Ok(offset)
}

fn write_generation_wait(
    state: &CertdHostedState,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, ()> {
    if payload.len() != 20 || payload.get(..8) != Some(GENERATION_WAIT_REQUEST_MAGIC) {
        return Err(());
    }
    let current_generation = u64::from_be_bytes(payload[8..16].try_into().map_err(|_| ())?);
    let timeout_milliseconds = u32::from_be_bytes(payload[16..20].try_into().map_err(|_| ())?);
    if current_generation == 0
        || timeout_milliseconds == 0
        || timeout_milliseconds > MAX_GENERATION_WAIT_MILLISECONDS
    {
        return Err(());
    }
    let (active, _) = load_active_candidate(state).map_err(|_| ())?;
    if active.identity_generation < current_generation {
        return Err(());
    }
    let changed = u8::from(active.identity_generation > current_generation);
    let mut offset = 0usize;
    append(output, &mut offset, GENERATION_WAIT_RESPONSE_MAGIC)?;
    append(
        output,
        &mut offset,
        &active.identity_generation.to_be_bytes(),
    )?;
    append(output, &mut offset, &[changed])?;
    Ok(offset)
}

fn load_active_candidate(
    state: &CertdHostedState,
) -> Result<(CertdCandidateState, mrml_certificate::CertdCandidateRequest), &'static str> {
    let object = DurableObjectId(state.config.identity);
    let durable_state = state
        .durable_state
        .lock()
        .map_err(|_| "candidate state poisoned")?;
    let mut authenticator = state
        .durable_authenticator
        .lock()
        .map_err(|_| "candidate authenticator poisoned")?;
    let mut encoded = [0u8; mrml_certificate::MAX_DURABLE_RECORD_BYTES];
    let length = durable_state
        .load_authoritative(DurableNamespace::PublicState, object, &mut encoded)
        .map_err(|_| "cannot load active state")?
        .ok_or("active state is absent")?;
    let record = DurableRecord::decode(&encoded[..length], &mut *authenticator)
        .map_err(|_| "cannot authenticate active state")?;
    let candidate =
        CertdCandidateState::decode(record.payload()).map_err(|_| "cannot decode active state")?;
    if record.kind != DurableRecordKind::Certificate
        || record.object != object
        || candidate.stage != CertdCandidateStage::Active
    {
        return Err("certificate is not active");
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system time is before the Unix epoch")?
        .as_secs();
    if now < candidate.not_before || now >= candidate.not_after {
        return Err("active certificate is outside its validity interval");
    }
    let bytes = read_owned_publication(ACTIVE_PATH)?;
    if Sha256::digest(&bytes) != candidate.request_digest {
        return Err("active publication substitution detected");
    }
    let request =
        decode_certd_candidate_request(&bytes).map_err(|_| "cannot decode active publication")?;
    if request.identity != candidate.identity
        || request.chain.chain_digest() != candidate.chain_digest
        || request.key_generation != candidate.key_generation
        || request.identity_generation != candidate.identity_generation
        || request.policy_generation != candidate.policy_generation
    {
        return Err("active publication binding mismatch");
    }
    let keys = state
        .certificate_keys
        .lock()
        .map_err(|_| "certificate key store poisoned")?;
    if !keys
        .iter()
        .any(|key| key.key_generation() == candidate.key_generation)
    {
        return Err("active certificate key generation is unavailable");
    }
    Ok((candidate, request))
}

fn configured_server_name(config: CertdConfig, server_name: &str) -> bool {
    config.identifiers.iter().flatten().any(|identifier| {
        let configured = identifier.as_str();
        configured == server_name
            || configured.strip_prefix("*.").is_some_and(|suffix| {
                server_name.strip_suffix(suffix).is_some_and(|prefix| {
                    !prefix.is_empty()
                        && prefix.ends_with('.')
                        && !prefix[..prefix.len() - 1].contains('.')
                })
            })
    })
}

fn append(output: &mut [u8], offset: &mut usize, bytes: &[u8]) -> Result<(), ()> {
    let end = offset.checked_add(bytes.len()).ok_or(())?;
    output
        .get_mut(*offset..end)
        .ok_or(())?
        .copy_from_slice(bytes);
    *offset = end;
    Ok(())
}

fn require_account_request(config: CertdConfig, request: CertdAccountKeyRequest) -> Result<(), ()> {
    if request.account_identity != config.account_identity
        || request.directory_generation != config.directory_generation
        || (request.account_generation != config.account_generation
            && request.account_generation.checked_add(1) != Some(config.account_generation))
    {
        Err(())
    } else {
        Ok(())
    }
}

fn require_tls_request(config: CertdConfig, request: CertdTlsKeyRequest) -> Result<(), ()> {
    if request.identity != config.identity
        || request.key_generation != config.key_generation
        || request.policy_generation != config.policy_generation
        || request.identifier_set_digest != config.identifier_set_digest
    {
        Err(())
    } else {
        Ok(())
    }
}

fn load_or_create_keys(
    config: CertdConfig,
    key_store: &HostedP256KeyStore,
    trust_roots: PemCertificateChain,
    durable_authenticator: HmacSha256DurableAuthenticator,
    durable_state: HostedDurableStateStore,
) -> Result<CertdHostedState, &'static str> {
    let mut account_keys = Vec::new();
    let first_retained_account_generation = config.account_generation.saturating_sub(63).max(1);
    for generation in first_retained_account_generation..=config.account_generation {
        let descriptor = HostedP256KeyDescriptor {
            role: HostedP256KeyRole::AcmeAccount,
            object_id: config.account_identity,
            key_generation: generation,
            binding_generation: config.directory_generation,
            binding_digest: directory_binding(config),
        };
        match key_store.load_account(descriptor) {
            Ok(key) => account_keys.push(key),
            Err(HostedP256KeyError::NotFound) if generation < config.account_generation => {}
            Err(HostedP256KeyError::NotFound) => {
                let key = key_store
                    .create_account(descriptor, fill_entropy)
                    .or_else(|error| {
                        if error == HostedP256KeyError::AlreadyExists {
                            key_store.load_account(descriptor)
                        } else {
                            Err(error)
                        }
                    })
                    .map_err(|_| "cannot create ACME account key")?;
                account_keys.push(key);
            }
            Err(_) => return Err("cannot load retained ACME account key"),
        }
    }
    let mut certificate_keys = Vec::new();
    let first_retained_generation = config.key_generation.saturating_sub(63).max(1);
    for generation in first_retained_generation..=config.key_generation {
        let descriptor = HostedP256KeyDescriptor {
            role: HostedP256KeyRole::TlsIdentity,
            object_id: config.identity,
            key_generation: generation,
            binding_generation: config.policy_generation,
            binding_digest: config.identifier_set_digest,
        };
        let route = TlsSigningRoute {
            identity: TlsIdentityId(config.identity),
            identity_generation: generation,
            key_identity: TlsKeyIdentity([0; 32]),
            route_generation: config.policy_generation,
            capability_id: route_capability(config, generation),
        };
        match key_store.load_certificate(descriptor, route) {
            Ok(key) => certificate_keys.push(key),
            Err(HostedP256KeyError::NotFound) if generation < config.key_generation => {}
            Err(HostedP256KeyError::NotFound) => {
                let key = key_store
                    .create_certificate(descriptor, route, fill_entropy)
                    .or_else(|error| {
                        if error == HostedP256KeyError::AlreadyExists {
                            key_store.load_certificate(descriptor, route)
                        } else {
                            Err(error)
                        }
                    })
                    .map_err(|_| "cannot create TLS certificate key")?;
                certificate_keys.push(key);
            }
            Err(_) => return Err("cannot load retained TLS certificate key"),
        }
    }
    Ok(CertdHostedState {
        config,
        account_keys: Mutex::new(account_keys),
        certificate_keys: Mutex::new(certificate_keys),
        trust_roots,
        candidate: Mutex::new(None),
        durable_authenticator: Mutex::new(durable_authenticator),
        durable_state: Mutex::new(durable_state),
    })
}

fn persist_staged_candidate(
    state: &CertdHostedState,
    request: &[u8],
    chain_digest: [u8; 32],
    leaf_spki_digest: [u8; 32],
    not_before: u64,
    not_after: u64,
    order_url_digest: [u8; 32],
    identity_generation: u64,
    ari_certificate_id: mrml_acme::AriCertificateId,
    created_at_unix: u64,
) -> Result<(), &'static str> {
    let object = DurableObjectId(state.config.identity);
    let mut durable_state = state
        .durable_state
        .lock()
        .map_err(|_| "candidate state poisoned")?;
    let mut authenticator = state
        .durable_authenticator
        .lock()
        .map_err(|_| "candidate authenticator poisoned")?;
    let mut existing_bytes = [0u8; mrml_certificate::MAX_DURABLE_RECORD_BYTES];
    let existing = durable_state
        .load_authoritative(DurableNamespace::PublicState, object, &mut existing_bytes)
        .map_err(|_| "cannot load candidate state")?;
    let (previous_record_generation, previous_identity_generation) = if let Some(length) = existing
    {
        let existing = DurableRecord::decode(&existing_bytes[..length], &mut *authenticator)
            .map_err(|_| "cannot authenticate candidate state")?;
        if existing.kind != DurableRecordKind::Certificate || existing.object != object {
            return Err("candidate durable record type mismatch");
        }
        let decoded = CertdCandidateState::decode(existing.payload())
            .map_err(|_| "cannot decode candidate state")?;
        let request_digest = Sha256::digest(request);
        if decoded.request_digest == request_digest {
            if decoded.identity_generation != identity_generation
                || decoded.chain_digest != chain_digest
                || decoded.order_url_digest != order_url_digest
            {
                return Err("candidate request digest binding mismatch");
            }
            let file = read_owned_publication(CANDIDATE_PATH)?;
            if Sha256::digest(&file) != request_digest || file != request {
                return Err("candidate publication substitution detected");
            }
            return Ok(());
        }
        if decoded.stage != CertdCandidateStage::Active
            || identity_generation
                != decoded
                    .identity_generation
                    .checked_add(1)
                    .ok_or("identity generation exhausted")?
        {
            return Err("different durable candidate already exists");
        }
        (existing.generation, decoded.identity_generation)
    } else {
        if identity_generation != state.config.key_generation {
            return Err("initial identity generation mismatch");
        }
        (0, 0)
    };
    let candidate_state = CertdCandidateState {
        stage: CertdCandidateStage::Staged,
        identity: state.config.identity,
        directory_generation: state.config.directory_generation,
        account_generation: state.config.account_generation,
        key_generation: state.config.key_generation,
        identity_generation,
        policy_generation: state.config.policy_generation,
        order_url_digest,
        chain_digest,
        leaf_spki_digest,
        not_before,
        not_after,
        request_digest: Sha256::digest(request),
        ari_certificate_id,
        created_at_unix,
        previous_identity_generation,
    };
    write_candidate_file(request)?;
    let mut payload = [0u8; mrml_certificate::MAX_DURABLE_PAYLOAD];
    let length = candidate_state
        .encode(&mut payload)
        .map_err(|_| "cannot encode candidate state")?;
    let durable = DurableRecord::prepare(
        DurableNamespace::PublicState,
        DurableRecordKind::Certificate,
        object,
        previous_record_generation,
        &payload[..length],
        &mut *authenticator,
    )
    .map_err(|_| "cannot authenticate candidate state")?;
    let prepared = durable_state
        .prepare(&durable)
        .map_err(|_| "cannot prepare candidate state")?;
    durable_state
        .commit(prepared)
        .map_err(|_| "candidate state commit uncertain")?;
    Ok(())
}

fn write_candidate_file(request: &[u8]) -> Result<(), &'static str> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(LINUX_O_NOFOLLOW)
        .open(CANDIDATE_TEMP_PATH)
        .map_err(|_| "cannot create candidate publication")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect candidate publication")?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != CERTD_UID
        || metadata.mode() & 0o777 != 0o600
    {
        return Err("unsafe candidate publication file");
    }
    file.write_all(request)
        .map_err(|_| "cannot write candidate publication")?;
    file.sync_all()
        .map_err(|_| "cannot sync candidate publication")?;
    std::fs::rename(CANDIDATE_TEMP_PATH, CANDIDATE_PATH)
        .map_err(|_| "cannot publish candidate file")?;
    std::fs::File::open("/var/lib/mrml/publications")
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "cannot sync candidate publication directory")
}

fn activate_staged_candidate(
    state: &CertdHostedState,
    request: CertdActivationRequest,
) -> Result<(), &'static str> {
    let object = DurableObjectId(state.config.identity);
    let mut durable_state = state
        .durable_state
        .lock()
        .map_err(|_| "candidate state poisoned")?;
    let mut authenticator = state
        .durable_authenticator
        .lock()
        .map_err(|_| "candidate authenticator poisoned")?;
    let mut encoded = [0u8; mrml_certificate::MAX_DURABLE_RECORD_BYTES];
    let length = durable_state
        .load_authoritative(DurableNamespace::PublicState, object, &mut encoded)
        .map_err(|_| "cannot load candidate state")?
        .ok_or("candidate state is absent")?;
    let existing = DurableRecord::decode(&encoded[..length], &mut *authenticator)
        .map_err(|_| "cannot authenticate candidate state")?;
    if existing.kind != DurableRecordKind::Certificate || existing.object != object {
        return Err("candidate durable record type mismatch");
    }
    let mut candidate = CertdCandidateState::decode(existing.payload())
        .map_err(|_| "cannot decode candidate state")?;
    if candidate.identity != request.identity
        || candidate.directory_generation != request.directory_generation
        || candidate.account_generation != request.account_generation
        || candidate.key_generation != request.key_generation
        || candidate.identity_generation != request.identity_generation
        || candidate.policy_generation != request.policy_generation
        || candidate.chain_digest != request.chain_digest
        || candidate.request_digest != request.request_digest
    {
        return Err("activation request does not bind staged candidate");
    }
    let publication = read_owned_publication(CANDIDATE_PATH)?;
    if Sha256::digest(&publication) != candidate.request_digest {
        return Err("candidate publication substitution detected");
    }
    if candidate.stage == CertdCandidateStage::Active {
        let active = read_owned_publication(ACTIVE_PATH)?;
        return if active == publication {
            Ok(())
        } else {
            Err("active publication substitution detected")
        };
    }
    write_active_publication(&publication, candidate.identity_generation)?;
    candidate.stage = CertdCandidateStage::Active;
    let mut payload = [0u8; mrml_certificate::MAX_DURABLE_PAYLOAD];
    let payload_length = candidate
        .encode(&mut payload)
        .map_err(|_| "cannot encode active candidate state")?;
    let active = DurableRecord::prepare(
        DurableNamespace::PublicState,
        DurableRecordKind::Certificate,
        object,
        existing.generation,
        &payload[..payload_length],
        &mut *authenticator,
    )
    .map_err(|_| "cannot authenticate active candidate state")?;
    let prepared = durable_state
        .prepare(&active)
        .map_err(|_| "cannot prepare active candidate state")?;
    durable_state
        .commit(prepared)
        .map_err(|_| "active candidate state commit uncertain")?;
    *state
        .candidate
        .lock()
        .map_err(|_| "candidate memory state poisoned")? = None;
    Ok(())
}

fn read_owned_publication(path: &str) -> Result<Vec<u8>, &'static str> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(LINUX_O_NOFOLLOW)
        .open(path)
        .map_err(|_| "cannot open certificate publication")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect certificate publication")?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != CERTD_UID
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > MAX_CERTD_CHANNEL_PAYLOAD_BYTES as u64
    {
        return Err("unsafe certificate publication file");
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::BufReader::new(file), &mut bytes)
        .map_err(|_| "cannot read certificate publication")?;
    Ok(bytes)
}

fn write_active_publication(publication: &[u8], generation: u64) -> Result<(), &'static str> {
    let generation_path = format!("/var/lib/mrml/publications/identity-{generation:016x}.bin");
    write_publication_file(&generation_path, publication, true)?;
    write_publication_file(ACTIVE_TEMP_PATH, publication, false)?;
    std::fs::rename(ACTIVE_TEMP_PATH, ACTIVE_PATH)
        .map_err(|_| "cannot activate certificate publication")?;
    std::fs::File::open("/var/lib/mrml/publications")
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "cannot sync active publication directory")
}

fn write_publication_file(
    path: &str,
    publication: &[u8],
    immutable: bool,
) -> Result<(), &'static str> {
    let mut options = std::fs::OpenOptions::new();
    options
        .write(true)
        .mode(0o600)
        .custom_flags(LINUX_O_NOFOLLOW);
    if immutable {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(publication)
                .map_err(|_| "cannot write certificate publication")?;
            file.sync_all()
                .map_err(|_| "cannot sync certificate publication")
        }
        Err(error) if immutable && error.kind() == std::io::ErrorKind::AlreadyExists => {
            if read_owned_publication(path)? == publication {
                Ok(())
            } else {
                Err("immutable certificate generation substitution detected")
            }
        }
        Err(_) => Err("cannot create certificate publication"),
    }
}

fn load_trust_roots(config: CertdConfig) -> Result<PemCertificateChain, &'static str> {
    let roots = HostedSecret::open(
        Path::new(TRUST_ROOTS_PATH),
        0,
        0o444,
        MAX_CERTIFICATE_CHAIN_BYTES,
    )
    .map_err(|_| "unsafe certd trust roots")?;
    if Sha256::digest(roots.expose()) != config.trust_store_sha256 {
        return Err("certd trust root digest mismatch");
    }
    PemCertificateChain::parse(roots.expose()).map_err(|_| "invalid certd trust roots")
}

fn fill_entropy(output: &mut [u8]) -> Result<(), mrml_crypto::P256Error> {
    mrml_runtime::fill_random(output).map_err(|_| mrml_crypto::P256Error::EntropyUnavailable)
}

fn directory_binding(config: CertdConfig) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"mrml-certd-account-directory-binding-v1\0");
    digest.update(&config.directory_generation.to_be_bytes());
    digest.update(config.directory_url.as_str().as_bytes());
    digest.finalize()
}

fn route_capability(config: CertdConfig, key_generation: u64) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"mrml-certd-tls-route-capability-v1\0");
    digest.update(&config.identity);
    digest.update(&key_generation.to_be_bytes());
    digest.update(&config.policy_generation.to_be_bytes());
    digest.update(&config.identifier_set_digest);
    let digest = digest.finalize();
    digest[..16].try_into().unwrap_or([0; 16])
}

fn load_config() -> Result<CertdConfig, &'static str> {
    let config = HostedSecret::open(Path::new(CONFIG_PATH), 0, 0o444, MAX_CERTD_CONFIG_BYTES)
        .map_err(|_| "unsafe certd config")?;
    let source = core::str::from_utf8(config.expose()).map_err(|_| "certd config is not UTF-8")?;
    parse_certd_config(source).map_err(|_| "invalid certd config")
}

fn load_certd_storage() -> Result<(HmacSha256DurableAuthenticator, HostedP256KeyStore), &'static str>
{
    let secret = HostedSecret::open(
        Path::new(UNLOCK_SECRET),
        CERTD_UID,
        PRODUCTION_SECRET_MODE,
        32,
    )
    .map_err(|_| "invalid certd unlock secret")?;
    let mut unlock_key: [u8; 32] = secret
        .expose()
        .try_into()
        .map_err(|_| "invalid certd unlock secret")?;
    let mut authentication_key =
        hmac_sha256(&unlock_key, &[b"mrml-certd-durable-authentication-key-v1"]);
    let authenticator = HmacSha256DurableAuthenticator::new(authentication_key);
    erase_secret_bytes(&mut authentication_key);
    let key_store = HostedP256KeyStore::open(Path::new(KEY_STORE_ROOT), CERTD_UID, &unlock_key)
        .map_err(|_| "cannot open certd key store");
    erase_secret_bytes(&mut unlock_key);
    Ok((authenticator, key_store?))
}

fn load_channel_capability(path: &'static str) -> Result<CertdChannelCapability, &'static str> {
    let secret = HostedSecret::open(Path::new(path), CERTD_UID, PRODUCTION_SECRET_MODE, 32)
        .map_err(|_| "invalid channel capability")?;
    let key: [u8; 32] = secret
        .expose()
        .try_into()
        .map_err(|_| "invalid channel capability")?;
    CertdChannelCapability::new(key).map_err(|_| "invalid channel capability")
}
