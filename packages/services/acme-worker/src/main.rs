use mrml_acmed::{
    AcmedAccountPhase, AcmedAccountRecord, AcmedChannelRequestCounter, AcmedConfig,
    AcmedRequestIdReservation, AcmeDirectoryClass, MAX_ACMED_CONFIG_BYTES, parse_acmed_config,
};
use mrml_acme::{
    AccountCreateBuffers, AccountLifecycle, AccountPolicy, AccountRecoveryError, AcmeExchange,
    AcmeJwsEnvelopeWriter, AcmeUrl, CaClass, HostedAcmeTransport, JoseError, MAX_ACME_PAYLOAD_BYTES,
    MAX_DIRECTORY_BYTES, MAX_JWS_REQUEST_BYTES, P256Jwk, ProtectedKey, ReplayNonce,
    account_contacts_digest, execute_prepared_account_create, fetch_directory,
    recover_uncertain_account_creation,
};
use mrml_certificate::{
    CERTD_CHANNEL_HEADER_BYTES, CERTD_P256_PUBLIC_KEY_BYTES, CERTD_TLS_KEY_RESPONSE_BYTES,
    AcmeJwsOperation, CertdAccountKeyRequest, CertdChannelCapability, CertdChannelOperation,
    CertdChannelPolicy, CertdChannelRequest, CertdChannelRole, CertdPeerIdentity, CertdReplayWindow,
    CertdTlsKeyRequest, CloudflareDns01Provider, ConstrainedAcmeJwsRequest,
    DurableAuthenticator, DurableNamespace, DurableObjectId, DurableRecord, DurableRecordKind,
    DurableStateStore, HostedDurableStateStore, HostedSecret, MAX_CERTD_CHANNEL_PAYLOAD_BYTES,
    MAX_CSR_BYTES, MAX_DURABLE_PAYLOAD, MAX_DURABLE_RECORD_BYTES, PRODUCTION_SECRET_MODE,
    UnixCertdSession, decode_certd_channel_request,
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
    let state_authenticator = load_durable_authenticator(Path::new(STATE_KEY), ACMED_UID)
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
        "serve" => serve(config, capability, state_authenticator),
        _ => Err("usage: mrml-acmed [serve|check-config]"),
    }
}

fn serve(
    config: AcmedConfig,
    capability: CertdChannelCapability,
    mut state_authenticator: impl DurableAuthenticator,
) -> Result<(), &'static str> {
    let mut state = HostedDurableStateStore::open(Path::new(STATE_ROOT))
        .map_err(|_| "cannot open acmed durable state")?;
    let reservation = reserve_channel_request_ids(
        &config,
        &mut state,
        &mut state_authenticator,
    )?;
    let bootstrap = bootstrap_certd(&config, &capability, reservation.next)?;
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
    let _account = establish_account(
        &config,
        &bootstrap.account_public_key,
        &mut envelope_writer,
        &mut state,
        &mut state_authenticator,
    )?;
    loop {
        if envelope_writer.next_request_id > reservation.last {
            return Err("certd channel request ID reservation exhausted");
        }
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

fn reserve_channel_request_ids(
    config: &AcmedConfig,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<AcmedRequestIdReservation, &'static str> {
    let object = DurableObjectId(*b"acmed-channel-id");
    let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
    let loaded = state
        .load_authoritative(DurableNamespace::PublicState, object, &mut encoded)
        .map_err(|_| "cannot read certd request ID reservation")?;
    let (previous_generation, mut counter) = if let Some(length) = loaded {
        let record = DurableRecord::decode(&encoded[..length], authenticator)
            .map_err(|_| "certd request ID reservation authentication failed")?;
        if record.namespace != DurableNamespace::PublicState
            || record.kind != DurableRecordKind::AcmeResource
            || record.object != object
            || record.payload().len() != 32
        {
            return Err("invalid certd request ID reservation");
        }
        let counter = AcmedChannelRequestCounter::decode(record.payload())
            .map_err(|_| "invalid certd request ID reservation")?;
        if counter.account_identity != config.account_identity {
            return Err("certd request ID reservation identity mismatch");
        }
        (record.generation, counter)
    } else {
        (
            0,
            AcmedChannelRequestCounter::new(config.account_identity)
                .map_err(|_| "invalid certd request ID identity")?,
        )
    };
    let reservation = counter
        .reserve()
        .map_err(|_| "certd request ID space exhausted")?;
    let mut payload = [0u8; 32];
    let payload_length = counter
        .encode(&mut payload)
        .map_err(|_| "cannot encode certd request ID reservation")?;
    let record = DurableRecord::prepare(
        DurableNamespace::PublicState,
        DurableRecordKind::AcmeResource,
        object,
        previous_generation,
        &payload[..payload_length],
        authenticator,
    )
    .map_err(|_| "cannot authenticate certd request ID reservation")?;
    let prepared = state
        .prepare(&record)
        .map_err(|_| "cannot prepare certd request ID reservation")?;
    state
        .commit(prepared)
        .map_err(|_| "certd request ID reservation commit uncertain")?;
    Ok(reservation)
}

fn establish_account(
    config: &AcmedConfig,
    encoded_public_key: &[u8; CERTD_P256_PUBLIC_KEY_BYTES],
    signer: &mut CertdEnvelopeWriter<'_>,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<AccountLifecycle, &'static str> {
    let public_key = account_public_key(encoded_public_key)?;
    let mut exchange = AcmeExchange::new(config.directory_generation, config.directory_url);
    let mut transport = HostedAcmeTransport::new();
    let mut directory_response = [0u8; MAX_DIRECTORY_BYTES];
    let directory = fetch_directory(
        &config.directory_url,
        config.directory_generation,
        &mut exchange,
        &mut transport,
        &mut directory_response,
    )
    .map_err(|_| "cannot retrieve trusted ACME directory")?;
    let terms = config
        .terms_approval(&directory)
        .map_err(|_| "ACME terms approval does not match directory")?;
    let contacts: [&str; 0] = [];
    let contact_digest =
        account_contacts_digest(&contacts).map_err(|_| "invalid ACME account contacts")?;
    let policy = AccountPolicy {
        ca_class: match config.directory_class {
            AcmeDirectoryClass::PublicProduction => CaClass::Production,
            AcmeDirectoryClass::LocalTest | AcmeDirectoryClass::PublicStaging => CaClass::Staging,
        },
        policy_generation: config.policy_generation,
        contact_digest,
    };
    let loaded = load_account_record(config, state, authenticator)?;
    match loaded {
        Some((record, _durable_generation)) if record.phase == AcmedAccountPhase::Active => {
            record.require_policy(config).map_err(|_| "stale ACME account policy")?;
            if record.key_thumbprint != public_key.thumbprint().map_err(|_| "invalid account key")?
                || record.contact_digest != contact_digest
            {
                return Err("ACME account record binding mismatch");
            }
            AccountLifecycle::restore_active(
                &directory,
                policy.ca_class,
                record.account_generation,
                record.policy_generation,
                record.account_url.ok_or("active account URL missing")?,
                &public_key,
                contact_digest,
            )
            .map_err(|_| "cannot restore active ACME account")
        }
        Some((record, durable_generation))
            if record.phase == AcmedAccountPhase::RequestMayHaveBeenSent =>
        {
            if config.account_generation != 1 {
                return Err("initial ACME account recovery requires generation one");
            }
            record.require_policy(config).map_err(|_| "stale ACME account policy")?;
            if record.key_thumbprint != public_key.thumbprint().map_err(|_| "invalid account key")?
                || record.contact_digest != contact_digest
            {
                return Err("ACME account recovery binding mismatch");
            }
            let (mut lifecycle, receipt) = AccountLifecycle::prepare_create(
                &directory,
                policy,
                &public_key,
                terms.as_ref(),
                false,
            )
            .map_err(|_| "cannot prepare ACME account recovery")?;
            lifecycle
                .mark_uncertain()
                .map_err(|_| "cannot mark ACME account recovery uncertain")?;
            match recover_account(
                &mut lifecycle,
                receipt,
                &directory,
                &contacts,
                &public_key,
                &mut exchange,
                &mut transport,
                signer,
            ) {
                Ok(account_url) => {
                    persist_account_record(
                        config,
                        state,
                        authenticator,
                        durable_generation,
                        AcmedAccountPhase::Active,
                        public_key.thumbprint().map_err(|_| "invalid account key")?,
                        contact_digest,
                        Some(account_url),
                    )?;
                    Ok(lifecycle)
                }
                Err(AccountRecoveryError::Server(problem))
                    if problem.problem_type.as_str()
                        == "urn:ietf:params:acme:error:accountDoesNotExist" =>
                {
                    create_account(
                        config,
                        &directory,
                        policy,
                        terms.as_ref(),
                        &contacts,
                        &public_key,
                        &mut exchange,
                        &mut transport,
                        signer,
                        state,
                        authenticator,
                        durable_generation,
                    )
                }
                Err(_) => Err("ACME account recovery remains uncertain"),
            }
        }
        Some(_) => Err("unsupported ACME account durable phase"),
        None => {
            if config.account_generation != 1 {
                return Err("missing ACME account state for configured generation");
            }
            create_account(
                config,
                &directory,
                policy,
                terms.as_ref(),
                &contacts,
                &public_key,
                &mut exchange,
                &mut transport,
                signer,
                state,
                authenticator,
                0,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn create_account(
    config: &AcmedConfig,
    directory: &mrml_acme::AcmeDirectory,
    policy: AccountPolicy,
    terms: Option<&mrml_acme::OwnerTermsApproval>,
    contacts: &[&str],
    public_key: &P256Jwk,
    exchange: &mut AcmeExchange,
    transport: &mut HostedAcmeTransport,
    signer: &mut CertdEnvelopeWriter<'_>,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
    previous_durable_generation: u64,
) -> Result<AccountLifecycle, &'static str> {
    let (mut lifecycle, receipt) = AccountLifecycle::prepare_create(
        directory,
        policy,
        public_key,
        terms,
        false,
    )
    .map_err(|_| "cannot prepare ACME account creation")?;
    let pending_generation = persist_account_record(
        config,
        state,
        authenticator,
        previous_durable_generation,
        AcmedAccountPhase::RequestMayHaveBeenSent,
        public_key.thumbprint().map_err(|_| "invalid account key")?,
        policy.contact_digest,
        None,
    )?;
    let mut payload = [0u8; MAX_ACME_PAYLOAD_BYTES];
    let mut response = [0u8; MAX_DIRECTORY_BYTES];
    let mut jws = [0u8; MAX_JWS_REQUEST_BYTES];
    signer.operation = AcmeJwsOperation::NewAccount;
    let account_url = execute_prepared_account_create(
        &mut lifecycle,
        receipt,
        directory,
        contacts,
        None,
        public_key,
        exchange,
        transport,
        signer,
        AccountCreateBuffers {
            payload: &mut payload,
            response: &mut response,
            jws: &mut jws,
        },
    )
    .map_err(|_| "ACME account creation is uncertain or rejected")?;
    persist_account_record(
        config,
        state,
        authenticator,
        pending_generation,
        AcmedAccountPhase::Active,
        public_key.thumbprint().map_err(|_| "invalid account key")?,
        policy.contact_digest,
        Some(account_url),
    )?;
    Ok(lifecycle)
}

#[allow(clippy::too_many_arguments)]
fn recover_account(
    lifecycle: &mut AccountLifecycle,
    receipt: mrml_acme::PreparedAccountAction,
    directory: &mrml_acme::AcmeDirectory,
    contacts: &[&str],
    public_key: &P256Jwk,
    exchange: &mut AcmeExchange,
    transport: &mut HostedAcmeTransport,
    signer: &mut CertdEnvelopeWriter<'_>,
) -> Result<AcmeUrl, AccountRecoveryError<mrml_acme::HostedTransportError>> {
    let mut payload = [0u8; MAX_ACME_PAYLOAD_BYTES];
    let mut response = [0u8; MAX_DIRECTORY_BYTES];
    let mut jws = [0u8; MAX_JWS_REQUEST_BYTES];
    signer.operation = AcmeJwsOperation::NewAccount;
    recover_uncertain_account_creation(
        lifecycle,
        receipt,
        directory,
        contacts,
        public_key,
        exchange,
        transport,
        signer,
        AccountCreateBuffers {
            payload: &mut payload,
            response: &mut response,
            jws: &mut jws,
        },
    )
}

fn account_public_key(
    encoded: &[u8; CERTD_P256_PUBLIC_KEY_BYTES],
) -> Result<P256Jwk, &'static str> {
    if encoded[0] != 4 {
        return Err("invalid certd account public key encoding");
    }
    P256Jwk::from_coordinates(
        encoded[1..33]
            .try_into()
            .map_err(|_| "invalid certd account public key")?,
        encoded[33..65]
            .try_into()
            .map_err(|_| "invalid certd account public key")?,
    )
    .map_err(|_| "invalid certd account public key")
}

fn load_account_record(
    config: &AcmedConfig,
    state: &HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<Option<(AcmedAccountRecord, u64)>, &'static str> {
    let object = DurableObjectId(config.account_identity);
    let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
    let Some(length) = state
        .load_authoritative(DurableNamespace::PublicState, object, &mut encoded)
        .map_err(|_| "cannot read ACME account state")?
    else {
        return Ok(None);
    };
    let durable = DurableRecord::decode(&encoded[..length], authenticator)
        .map_err(|_| "ACME account state authentication failed")?;
    if durable.namespace != DurableNamespace::PublicState
        || durable.kind != DurableRecordKind::Account
        || durable.object != object
    {
        return Err("ACME account durable record type mismatch");
    }
    let record = AcmedAccountRecord::decode(
        durable.payload(),
        &config.directory_url,
        config.directory_class == AcmeDirectoryClass::LocalTest,
    )
    .map_err(|_| "invalid ACME account durable record")?;
    Ok(Some((record, durable.generation)))
}

#[allow(clippy::too_many_arguments)]
fn persist_account_record(
    config: &AcmedConfig,
    state: &mut impl DurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
    previous_generation: u64,
    phase: AcmedAccountPhase,
    key_thumbprint: mrml_acme::JwkThumbprint,
    contact_digest: [u8; 32],
    account_url: Option<AcmeUrl>,
) -> Result<u64, &'static str> {
    let account = AcmedAccountRecord {
        phase,
        directory_generation: config.directory_generation,
        account_generation: config.account_generation,
        policy_generation: config.policy_generation,
        account_identity: config.account_identity,
        key_thumbprint,
        contact_digest,
        account_url,
    };
    let mut payload = [0u8; MAX_DURABLE_PAYLOAD];
    let length = account
        .encode(&mut payload)
        .map_err(|_| "cannot encode ACME account state")?;
    let durable = DurableRecord::prepare(
        DurableNamespace::PublicState,
        DurableRecordKind::Account,
        DurableObjectId(config.account_identity),
        previous_generation,
        &payload[..length],
        authenticator,
    )
    .map_err(|_| "cannot authenticate ACME account state")?;
    let prepared = state
        .prepare(&durable)
        .map_err(|_| "cannot prepare ACME account state")?;
    let committed = state
        .commit(prepared)
        .map_err(|_| "ACME account state commit uncertain")?;
    Ok(committed.generation)
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
    first_request_id: u64,
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
        first_request_id,
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
        first_request_id
            .checked_add(1)
            .ok_or("channel request ID exhausted")?,
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
        first_request_id
            .checked_add(2)
            .ok_or("channel request ID exhausted")?,
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
        next_request_id: first_request_id
            .checked_add(3)
            .ok_or("channel request ID exhausted")?,
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
