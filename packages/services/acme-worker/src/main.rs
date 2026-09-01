use mrml_acmed::{AcmedConfig, MAX_ACMED_CONFIG_BYTES, parse_acmed_config};
use mrml_acme::{
    AcmeJwsEnvelopeWriter, AcmeUrl, JoseError, ProtectedKey, ReplayNonce,
};
use mrml_certificate::{
    CERTD_CHANNEL_HEADER_BYTES, CERTD_P256_PUBLIC_KEY_BYTES, CERTD_TLS_KEY_RESPONSE_BYTES,
    AcmeJwsOperation, CertdAccountKeyRequest, CertdChannelCapability, CertdChannelOperation,
    CertdChannelPolicy, CertdChannelRequest, CertdChannelRole, CertdPeerIdentity, CertdReplayWindow,
    CertdTlsKeyRequest, CloudflareDns01Provider, ConstrainedAcmeJwsRequest,
    HostedDurableStateStore, HostedSecret, MAX_CERTD_CHANNEL_PAYLOAD_BYTES, MAX_CSR_BYTES,
    PRODUCTION_SECRET_MODE, UnixCertdSession, decode_certd_channel_request,
    encode_certd_account_key_request, encode_certd_channel_request, encode_certd_jws_request,
    encode_certd_tls_key_request, load_durable_authenticator, p256_public_key_is_valid,
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

struct CertdEnvelopeWriter<'a> {
    capability: &'a CertdChannelCapability,
    account_identity: [u8; 16],
    configured_account_generation: u64,
    operation: AcmeJwsOperation,
    next_request_id: u64,
}

struct CertdBootstrap {
    account_public_key: [u8; CERTD_P256_PUBLIC_KEY_BYTES],
    tls_public_key: [u8; CERTD_P256_PUBLIC_KEY_BYTES],
    csr: [u8; MAX_CSR_BYTES],
    csr_length: usize,
    next_request_id: u64,
}

impl CertdEnvelopeWriter<'_> {
    fn request_account_generation(&self, supplied: u64) -> Result<u64, JoseError> {
        if self.operation == AcmeJwsOperation::NewAccount && supplied == 0 {
            return Ok(self.configured_account_generation);
        }
        if supplied != self.configured_account_generation {
            return Err(JoseError::SigningUnavailable);
        }
        Ok(supplied)
    }
}

impl AcmeJwsEnvelopeWriter for CertdEnvelopeWriter<'_> {
    fn write_acme_jws<'a>(
        &mut self,
        key: ProtectedKey<'_>,
        nonce: &ReplayNonce,
        url: &AcmeUrl,
        payload: &[u8],
        directory_generation: u64,
        account_generation: u64,
        output: &'a mut [u8],
    ) -> Result<&'a [u8], JoseError> {
        let account_generation = self.request_account_generation(account_generation)?;
        let account_url = match key {
            ProtectedKey::Jwk(_) if self.operation == AcmeJwsOperation::NewAccount => None,
            ProtectedKey::Kid(account_url) if self.operation != AcmeJwsOperation::NewAccount => {
                Some(*account_url)
            }
            _ => return Err(JoseError::SigningUnavailable),
        };
        let request = ConstrainedAcmeJwsRequest {
            operation: self.operation,
            directory_generation,
            account_generation,
            account_identity: self.account_identity,
            protected_url: *url,
            nonce: *nonce,
            account_url,
            payload,
        };
        let mut encoded = [0u8; MAX_CERTD_CHANNEL_PAYLOAD_BYTES];
        let request_length = encode_certd_jws_request(&request, &mut encoded).map_err(|error| {
            if matches!(
                error,
                mrml_certificate::CertdJwsProtocolError::OutputTooSmall
                    | mrml_certificate::CertdJwsProtocolError::PayloadTooLarge
            ) {
                JoseError::PayloadTooLarge
            } else {
                JoseError::SigningUnavailable
            }
        })?;
        let response_length = certd_call(
            self.capability,
            self.next_request_id,
            CertdChannelOperation::SignAcmeJws,
            &encoded[..request_length],
            output,
        )
        .map_err(|_| JoseError::SigningUnavailable)?;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(JoseError::SigningUnavailable)?;
        Ok(&output[..response_length])
    }
}

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
    let bootstrap = bootstrap_certd(&config, &capability)?;
    let _account_public_key = bootstrap.account_public_key;
    let _tls_public_key = bootstrap.tls_public_key;
    let _csr = &bootstrap.csr[..bootstrap.csr_length];
    let mut envelope_writer = CertdEnvelopeWriter {
        capability: &capability,
        account_identity: config.account_identity,
        configured_account_generation: config.account_generation,
        operation: AcmeJwsOperation::NewAccount,
        next_request_id: bootstrap.next_request_id,
    };
    loop {
        if certd_health(&capability, envelope_writer.next_request_id).is_err() {
            eprintln!("mrml-acmed: certd health degraded");
        }
        envelope_writer.next_request_id = envelope_writer
            .next_request_id
            .checked_add(1)
            .ok_or("channel request ID exhausted")?;
        std::thread::sleep(Duration::from_secs(config.poll_interval_seconds));
    }
}

fn certd_health(capability: &CertdChannelCapability, request_id: u64) -> Result<(), &'static str> {
    let mut response = [0u8; 16];
    let length = certd_call(
        capability,
        request_id,
        CertdChannelOperation::Health,
        &[],
        &mut response,
    )?;
    if &response[..length] != b"ready" {
        return Err("certd is not ready");
    }
    Ok(())
}

fn certd_call(
    capability: &CertdChannelCapability,
    request_id: u64,
    operation: CertdChannelOperation,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, &'static str> {
    let mut session =
        UnixCertdSession::connect(Path::new(CERTD_SOCKET)).map_err(|_| "certd unavailable")?;
    let mut frame = [0u8; MAX_FRAME_BYTES];
    let written = encode_certd_channel_request(
        CertdChannelRequest {
            role: CertdChannelRole::Acmed,
            operation,
            request_id,
            peer: ACMED_PEER,
            payload,
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
    if response.operation != operation || response.request_id != request_id {
        return Err("certd response binding mismatch");
    }
    if output.len() < response.payload.len() {
        return Err("certd response exceeds output");
    }
    output[..response.payload.len()].copy_from_slice(response.payload);
    Ok(response.payload.len())
}

fn bootstrap_certd(
    config: &AcmedConfig,
    capability: &CertdChannelCapability,
) -> Result<CertdBootstrap, &'static str> {
    let account_request = encode_certd_account_key_request(CertdAccountKeyRequest {
        account_identity: config.account_identity,
        directory_generation: config.directory_generation,
        account_generation: config.account_generation,
    })
    .map_err(|_| "invalid account key request")?;
    let mut account_public = [0u8; CERTD_P256_PUBLIC_KEY_BYTES];
    let length = certd_call(
        capability,
        1,
        CertdChannelOperation::GetAcmeAccountPublicIdentity,
        &account_request,
        &mut account_public,
    )?;
    if length != account_public.len() || !p256_public_key_is_valid(&account_public) {
        return Err("invalid certd account public key");
    }

    let tls_request = encode_certd_tls_key_request(CertdTlsKeyRequest {
        identity: config.identity,
        key_generation: config.key_generation,
        policy_generation: config.policy_generation,
        identifier_set_digest: config.identifier_set_digest,
    })
    .map_err(|_| "invalid TLS key request")?;
    let mut tls_response = [0u8; CERTD_TLS_KEY_RESPONSE_BYTES];
    let length = certd_call(
        capability,
        2,
        CertdChannelOperation::CreateTlsKeyGeneration,
        &tls_request,
        &mut tls_response,
    )?;
    if length != tls_response.len()
        || !p256_public_key_is_valid(&tls_response[..CERTD_P256_PUBLIC_KEY_BYTES])
        || tls_response[CERTD_P256_PUBLIC_KEY_BYTES..]
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err("invalid certd TLS key response");
    }

    let mut csr = [0u8; MAX_CSR_BYTES];
    let csr_length = certd_call(
        capability,
        3,
        CertdChannelOperation::CreateCertificateSigningRequest,
        &tls_request,
        &mut csr,
    )?;
    if csr_length < 4 || csr[0] != 0x30 {
        return Err("invalid certd certificate signing request");
    }
    let mut tls_public_key = [0u8; CERTD_P256_PUBLIC_KEY_BYTES];
    tls_public_key.copy_from_slice(&tls_response[..CERTD_P256_PUBLIC_KEY_BYTES]);
    Ok(CertdBootstrap {
        account_public_key: account_public,
        tls_public_key,
        csr,
        csr_length,
        next_request_id: 4,
    })
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
