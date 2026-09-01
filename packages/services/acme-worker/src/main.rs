use mrml_acmed::{parse_acmed_config, AcmedConfig, MAX_ACMED_CONFIG_BYTES};
use mrml_certificate::{
    decode_certd_channel_request, encode_certd_channel_request, load_durable_authenticator,
    CertdChannelCapability, CertdChannelOperation, CertdChannelPolicy, CertdChannelRequest,
    CertdChannelRole, CertdPeerIdentity, CertdReplayWindow, CloudflareDns01Provider,
    HostedDurableStateStore, HostedSecret, UnixCertdSession, CERTD_CHANNEL_HEADER_BYTES,
    MAX_CERTD_CHANNEL_PAYLOAD_BYTES, PRODUCTION_SECRET_MODE,
};
use std::path::Path;
use std::time::Duration;

const ACMED_UID: u32 = 21004;
const ACMED_PEER: CertdPeerIdentity = CertdPeerIdentity {
    uid: ACMED_UID,
    gid: ACMED_UID,
};
const CERTD_PEER: CertdPeerIdentity = CertdPeerIdentity {
    uid: 21003,
    gid: 21003,
};
const CONFIG_PATH: &str = "/etc/mrml/acmed/config.json";
const STATE_ROOT: &str = "/var/lib/mrml/acmed";
const STATE_KEY: &str = "/run/secrets/acmed-state.key";
const DNS_TOKEN: &str = "/run/secrets/cloudflare-api-token";
const CHANNEL_CAPABILITY: &str = "/run/secrets/certd-acmed.cap";
const CERTD_SOCKET: &str = "/run/mrml/certd-acmed/certd.sock";
const MAX_FRAME_BYTES: usize = CERTD_CHANNEL_HEADER_BYTES + MAX_CERTD_CHANNEL_PAYLOAD_BYTES;

fn main() {
    if let Err(error) = application_main() {
        eprintln!("mrml-acmed: {error}");
        std::process::exit(1);
    }
}

fn application_main() -> Result<(), &'static str> {
    let command = std::env::args().nth(1).unwrap_or_else(|| "serve".into());
    let config = load_config()?;
    let _state_authenticator = load_durable_authenticator(Path::new(STATE_KEY), ACMED_UID)
        .map_err(|_| "invalid acmed state authentication key")?;
    let _provider = CloudflareDns01Provider::open(
        Path::new(DNS_TOKEN),
        ACMED_UID,
        core::str::from_utf8(&config.zone_id).map_err(|_| "invalid zone ID")?,
        config.zone,
    )
    .map_err(|_| "invalid Cloudflare DNS provider configuration")?;
    let capability = load_channel_capability()?;
    match command.as_str() {
        "check-config" => {
            println!("mrml-acmed configuration valid");
            Ok(())
        }
        "serve" => serve(config, capability),
        _ => Err("usage: mrml-acmed [serve|check-config]"),
    }
}

fn serve(config: AcmedConfig, capability: CertdChannelCapability) -> Result<(), &'static str> {
    let _state = HostedDurableStateStore::open(Path::new(STATE_ROOT))
        .map_err(|_| "cannot open acmed durable state")?;
    let mut request_id = 1u64;
    loop {
        if certd_health(&capability, request_id).is_err() {
            eprintln!("mrml-acmed: certd health degraded");
        }
        request_id = request_id
            .checked_add(1)
            .ok_or("channel request ID exhausted")?;
        std::thread::sleep(Duration::from_secs(config.poll_interval_seconds));
    }
}

fn certd_health(capability: &CertdChannelCapability, request_id: u64) -> Result<(), &'static str> {
    let mut session =
        UnixCertdSession::connect(Path::new(CERTD_SOCKET)).map_err(|_| "certd unavailable")?;
    let mut frame = [0u8; MAX_FRAME_BYTES];
    let written = encode_certd_channel_request(
        CertdChannelRequest {
            role: CertdChannelRole::Acmed,
            operation: CertdChannelOperation::Health,
            request_id,
            peer: ACMED_PEER,
            payload: &[],
        },
        capability,
        &mut frame,
    )
    .map_err(|_| "cannot encode certd health request")?;
    session
        .write_frame(&frame[..written])
        .map_err(|_| "cannot send certd health request")?;
    let length = session
        .read_frame(&mut frame)
        .map_err(|_| "cannot read certd health response")?;
    let response = decode_certd_channel_request(
        &frame[..length],
        session.observed_peer(),
        CertdChannelPolicy {
            role: CertdChannelRole::Acmed,
            peer: CERTD_PEER,
        },
        capability,
        &mut CertdReplayWindow::new(),
    )
    .map_err(|_| "invalid certd health response")?;
    if response.operation != CertdChannelOperation::Health
        || response.request_id != request_id
        || response.payload != b"ready"
    {
        return Err("certd is not ready");
    }
    Ok(())
}

fn load_config() -> Result<AcmedConfig, &'static str> {
    let metadata = std::fs::symlink_metadata(CONFIG_PATH).map_err(|_| "missing acmed config")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("acmed config is not a regular file");
    }
    let bytes = std::fs::read(CONFIG_PATH).map_err(|_| "cannot read acmed config")?;
    if bytes.len() > MAX_ACMED_CONFIG_BYTES {
        return Err("acmed config exceeds limit");
    }
    let source = core::str::from_utf8(&bytes).map_err(|_| "acmed config is not UTF-8")?;
    parse_acmed_config(source).map_err(|_| "invalid acmed config")
}

fn load_channel_capability() -> Result<CertdChannelCapability, &'static str> {
    let secret = HostedSecret::open(
        Path::new(CHANNEL_CAPABILITY),
        ACMED_UID,
        PRODUCTION_SECRET_MODE,
        32,
    )
    .map_err(|_| "invalid certd channel capability")?;
    let key: [u8; 32] = secret
        .expose()
        .try_into()
        .map_err(|_| "invalid certd channel capability")?;
    CertdChannelCapability::new(key).map_err(|_| "invalid certd channel capability")
}
