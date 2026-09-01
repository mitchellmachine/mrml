use mrml_certificate::{
    CERTD_CHANNEL_HEADER_BYTES, CertdChannelCapability, CertdChannelOperation, CertdChannelPolicy,
    CertdChannelRequest, CertdChannelRole, CertdPeerIdentity, CertdReplayWindow,
    HmacSha256DurableAuthenticator, HostedP256KeyStore, HostedSecret,
    MAX_CERTD_CHANNEL_PAYLOAD_BYTES, PRODUCTION_SECRET_MODE, UnixCertdListener,
    decode_certd_channel_request, encode_certd_channel_request,
};
use mrml_crypto::{erase_secret_bytes, hmac_sha256};
use std::path::Path;
use std::sync::Arc;

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
const GITD_CAPABILITY: &str = "/run/secrets/certd-gitd.cap";
const ACMED_CAPABILITY: &str = "/run/secrets/certd-acmed.cap";
const MAX_FRAME_BYTES: usize = CERTD_CHANNEL_HEADER_BYTES + MAX_CERTD_CHANNEL_PAYLOAD_BYTES;

fn main() {
    if let Err(error) = application_main() {
        eprintln!("mrml-certd: {error}");
        std::process::exit(1);
    }
}

fn application_main() -> Result<(), &'static str> {
    let command = std::env::args().nth(1).unwrap_or_else(|| "serve".into());
    match command.as_str() {
        "check-config" => {
            let (_authenticator, _key_store) = load_certd_storage()?;
            let _gitd = load_channel_capability(GITD_CAPABILITY)?;
            let _acmed = load_channel_capability(ACMED_CAPABILITY)?;
            println!("mrml-certd configuration valid");
            Ok(())
        }
        "serve" => serve(),
        _ => Err("usage: mrml-certd [serve|check-config]"),
    }
}

fn serve() -> Result<(), &'static str> {
    let (_durable_authenticator, key_store) = load_certd_storage()?;
    let key_store = Arc::new(key_store);
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
        let gitd_key_store = Arc::clone(&key_store);
        scope.spawn(move || {
            serve_channel(
                gitd,
                gitd_capability,
                CertdChannelRole::Gitd,
                GITD_PEER,
                gitd_key_store,
            )
        });
        scope.spawn(move || {
            serve_channel(
                acmed,
                acmed_capability,
                CertdChannelRole::Acmed,
                ACMED_PEER,
                key_store,
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
    _key_store: Arc<HostedP256KeyStore>,
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
        if request.operation != CertdChannelOperation::Health || !request.payload.is_empty() {
            continue;
        }
        let response = CertdChannelRequest {
            role,
            operation: CertdChannelOperation::Health,
            request_id: request.request_id,
            peer: CERTD_PEER,
            payload: b"ready",
        };
        let Ok(written) = encode_certd_channel_request(response, &capability, &mut frame) else {
            continue;
        };
        let _ = session.write_frame(&frame[..written]);
    }
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
