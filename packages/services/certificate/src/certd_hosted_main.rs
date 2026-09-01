use mrml_certificate::{
    AccountP256SigningKey, CERTD_CHANNEL_HEADER_BYTES, CertdAccountKeyRequest,
    CertdChannelCapability, CertdChannelOperation, CertdChannelPolicy, CertdChannelRequest,
    CertdChannelRole, CertdConfig, CertdDirectoryClass, CertdPeerIdentity, CertdReplayWindow,
    CertdTlsKeyRequest, CertificateP256SigningKey, ConstrainedAcmeJwsPolicy,
    HmacSha256DurableAuthenticator, HostedP256KeyDescriptor, HostedP256KeyError, HostedP256KeyRole,
    HostedP256KeyStore, HostedSecret, MAX_CERTD_CHANNEL_PAYLOAD_BYTES, MAX_CERTD_CONFIG_BYTES,
    MAX_CSR_BYTES, MAX_CSR_IDENTIFIERS, PRODUCTION_SECRET_MODE, TlsIdentityId, TlsKeyIdentity,
    TlsSigningRoute, UnixCertdListener, decode_certd_account_key_request,
    decode_certd_channel_request, decode_certd_jws_request, decode_certd_tls_key_request,
    encode_certd_channel_request, encode_certd_tls_key_response, parse_certd_config,
    write_constrained_acme_jws, write_pkcs10_csr,
};
use mrml_crypto::{Sha256, erase_secret_bytes, hmac_sha256};
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
const CONFIG_PATH: &str = "/etc/mrml/certd/config.json";
const GITD_CAPABILITY: &str = "/run/secrets/certd-gitd.cap";
const ACMED_CAPABILITY: &str = "/run/secrets/certd-acmed.cap";
const MAX_FRAME_BYTES: usize = CERTD_CHANNEL_HEADER_BYTES + MAX_CERTD_CHANNEL_PAYLOAD_BYTES;

struct CertdHostedState {
    config: CertdConfig,
    account_key: Mutex<AccountP256SigningKey>,
    certificate_key: Mutex<CertificateP256SigningKey>,
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
            let _gitd = load_channel_capability(GITD_CAPABILITY)?;
            let _acmed = load_channel_capability(ACMED_CAPABILITY)?;
            println!("mrml-certd configuration valid");
            Ok(())
        }
        "serve" => serve(config),
        _ => Err("usage: mrml-certd [serve|check-config]"),
    }
}

fn serve(config: CertdConfig) -> Result<(), &'static str> {
    let (_durable_authenticator, key_store) = load_certd_storage()?;
    let state = Arc::new(load_or_create_keys(config, &key_store)?);
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
        let Ok(response_length) =
            dispatch_channel_request(&state, operation, request.payload, &mut response_payload)
        else {
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
    operation: CertdChannelOperation,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, ()> {
    match operation {
        CertdChannelOperation::Health => {
            if !payload.is_empty()
                || state.config.identity == [0; 16]
                || state.account_key.is_poisoned()
                || state.certificate_key.is_poisoned()
                || output.len() < 5
            {
                return Err(());
            }
            output[..5].copy_from_slice(b"ready");
            Ok(5)
        }
        CertdChannelOperation::GetAcmeAccountPublicIdentity => {
            let request = decode_certd_account_key_request(payload).map_err(|_| ())?;
            require_account_request(state.config, request)?;
            let account = state.account_key.lock().map_err(|_| ())?;
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
            let mut account = state.account_key.lock().map_err(|_| ())?;
            let public = account.public_jwk().map_err(|_| ())?;
            let jws = write_constrained_acme_jws(
                ConstrainedAcmeJwsPolicy {
                    directory_url: state.config.directory_url,
                    directory_generation: state.config.directory_generation,
                    account_generation: state.config.account_generation,
                    account_identity: state.config.account_identity,
                },
                request,
                &public,
                &mut account,
                output,
            )
            .map_err(|_| ())?;
            Ok(jws.len())
        }
        CertdChannelOperation::CreateTlsKeyGeneration => {
            let request = decode_certd_tls_key_request(payload).map_err(|_| ())?;
            require_tls_request(state.config, request)?;
            let certificate = state.certificate_key.lock().map_err(|_| ())?;
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
            let mut certificate = state.certificate_key.lock().map_err(|_| ())?;
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
        _ => Err(()),
    }
}

fn require_account_request(config: CertdConfig, request: CertdAccountKeyRequest) -> Result<(), ()> {
    if request.account_identity != config.account_identity
        || request.directory_generation != config.directory_generation
        || request.account_generation != config.account_generation
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
) -> Result<CertdHostedState, &'static str> {
    let account_descriptor = HostedP256KeyDescriptor {
        role: HostedP256KeyRole::AcmeAccount,
        object_id: config.account_identity,
        key_generation: config.account_generation,
        binding_generation: config.directory_generation,
        binding_digest: directory_binding(config),
    };
    let account_key = match key_store.load_account(account_descriptor) {
        Ok(key) => key,
        Err(HostedP256KeyError::NotFound) => key_store
            .create_account(account_descriptor, fill_entropy)
            .or_else(|error| {
                if error == HostedP256KeyError::AlreadyExists {
                    key_store.load_account(account_descriptor)
                } else {
                    Err(error)
                }
            })
            .map_err(|_| "cannot create ACME account key")?,
        Err(_) => return Err("cannot load ACME account key"),
    };
    let certificate_descriptor = HostedP256KeyDescriptor {
        role: HostedP256KeyRole::TlsIdentity,
        object_id: config.identity,
        key_generation: config.key_generation,
        binding_generation: config.policy_generation,
        binding_digest: config.identifier_set_digest,
    };
    let route = TlsSigningRoute {
        identity: TlsIdentityId(config.identity),
        identity_generation: config.key_generation,
        key_identity: TlsKeyIdentity([0; 32]),
        route_generation: config.policy_generation,
        capability_id: route_capability(config),
    };
    let certificate_key = match key_store.load_certificate(certificate_descriptor, route) {
        Ok(key) => key,
        Err(HostedP256KeyError::NotFound) => key_store
            .create_certificate(certificate_descriptor, route, fill_entropy)
            .or_else(|error| {
                if error == HostedP256KeyError::AlreadyExists {
                    key_store.load_certificate(certificate_descriptor, route)
                } else {
                    Err(error)
                }
            })
            .map_err(|_| "cannot create TLS certificate key")?,
        Err(_) => return Err("cannot load TLS certificate key"),
    };
    Ok(CertdHostedState {
        config,
        account_key: Mutex::new(account_key),
        certificate_key: Mutex::new(certificate_key),
    })
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

fn route_capability(config: CertdConfig) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"mrml-certd-tls-route-capability-v1\0");
    digest.update(&config.identity);
    digest.update(&config.key_generation.to_be_bytes());
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
