use mrml_acme::{
    account_contacts_digest, dns01_txt_digest, execute_prepared_account_create,
    execute_prepared_finalize, execute_prepared_order_create, fetch_authorization, fetch_directory,
    fetch_renewal_info, parse_account_response, poll_order, post_jws, prepare_order_creation,
    recover_uncertain_account_creation, resolve_uncertain_account_action, revoke_certificate,
    trigger_propagated_dns01_challenge, write_key_authorization, AccountCreateBuffers,
    AccountLifecycle, AccountPolicy, AccountRecoveryError, AcmeExchange, AcmeIdentifier,
    AcmeJwsEnvelopeWriter, AcmeUrl, AuthorizationResource, AuthorizationState, CaClass,
    ChallengeKind, Dns01ActivationEvidence, HostedAcmeTransport, JoseError, OrderCreateBuffers,
    OrderLifecycle, P256Jwk, ParsedAccountStatus, ProtectedKey, ReplayNonce, RevocationOutcome,
    MAX_ACME_PAYLOAD_BYTES, MAX_AUTHORIZATIONS, MAX_CSR_IDENTIFIERS, MAX_DIRECTORY_BYTES,
    MAX_JWS_REQUEST_BYTES, MAX_KEY_AUTHORIZATION,
};
use mrml_acmed::{
    challenge_object_id, finalization_object_id, parse_acmed_config, renew_now_approval_digest,
    AcmeDirectoryClass, AcmedAccountPhase, AcmedAccountRecord, AcmedChallengePhase,
    AcmedChallengeRecord, AcmedChannelRequestCounter, AcmedConfig, AcmedFinalizationPhase,
    AcmedFinalizationRecord, AcmedOrderPhase, AcmedOrderRecord, AcmedRequestIdReservation,
    AcmedRevocationPhase, AcmedRevocationRecord, MAX_ACMED_CONFIG_BYTES,
};
use mrml_certificate::{
    create_hosted_component_backup, decode_certd_candidate_request, decode_certd_channel_request,
    encode_certd_account_key_request, encode_certd_candidate_request, encode_certd_channel_request,
    encode_certd_jws_request, encode_certd_tls_key_request, load_durable_authenticator,
    p256_public_key_is_valid, restore_hosted_component_backup, retrieve_certificate_chain,
    verify_hosted_component_backup, AcmeJwsOperation, CertdAccountKeyRequest,
    CertdActivationRequest, CertdCandidateRequest, CertdCandidateStage, CertdCandidateState,
    CertdChannelCapability, CertdChannelOperation, CertdChannelPolicy, CertdChannelRequest,
    CertdChannelRole, CertdPeerIdentity, CertdReplayWindow, CertdTlsKeyRequest,
    CloudflareDns01Provider, ConstrainedAcmeJwsRequest, Dns01Provider, Dns01PublicationRequest,
    DnsObservationClass, DnsObservationRoute, DnsPropagationObserver, DnsPropagationPolicy,
    DurableAuthenticator, DurableNamespace, DurableObjectId, DurableRecord, DurableRecordKind,
    DurableStateStore, HostedBackupRole, HostedBackupSource, HostedDnsObservationEndpoint,
    HostedDnsPropagationQuery, HostedDurableStateStore, HostedSecret, RenewalEntropy,
    RenewalSchedule, SchedulerError, TlsIdentityId, UnixCertdSession, CERTD_CHANNEL_HEADER_BYTES,
    CERTD_P256_PUBLIC_KEY_BYTES, CERTD_TLS_KEY_RESPONSE_BYTES, MAX_CERTD_CHANNEL_PAYLOAD_BYTES,
    MAX_CERTIFICATE_CHAIN_BYTES, MAX_CSR_BYTES, MAX_DURABLE_PAYLOAD, MAX_DURABLE_RECORD_BYTES,
    PRODUCTION_SECRET_MODE, RENEWAL_SCHEDULE_BYTES,
};
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
const BACKUP_CAPABILITY: &str = "/run/secrets/backup-auth.key";
const BACKUP_ROOT: &str = "/var/lib/mrml/backups";
const MAX_FRAME_BYTES: usize = CERTD_CHANNEL_HEADER_BYTES + MAX_CERTD_CHANNEL_PAYLOAD_BYTES;
const AUTHORITATIVE_DNS_ROUTE_CAPABILITY: u64 = 1;
const RECURSIVE_DNS_ROUTE_CAPABILITY: u64 = 2;

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
            if self.operation == AcmeJwsOperation::KeyChange
                && supplied.checked_add(1) == Some(self.configured_account_generation)
            {
                return Ok(supplied);
            }
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
    let capability = load_channel_capability()?;
    match command.as_str() {
        "check-config" => {
            let _provider = load_dns_provider(&config)?;
            println!("mrml-acmed configuration valid");
            Ok(())
        }
        "config-status" => {
            println!(
                "directory_generation={} account_generation={} key_generation={} policy_generation={}",
                config.directory_generation,
                config.account_generation,
                config.key_generation,
                config.policy_generation
            );
            Ok(())
        }
        "backup-create" => backup_component_command(true),
        "backup-verify" => backup_component_command(false),
        "backup-restore" => backup_restore_command(),
        "restore-check" => acmed_restore_check(config, state_authenticator),
        "health" => acmed_health(config, capability, state_authenticator),
        "status" => acmed_status(config, state_authenticator),
        "renew-now-preview" => renew_now_command(config, state_authenticator, false),
        "renew-now" => renew_now_command(config, state_authenticator, true),
        "dns-cleanup" => dns_cleanup_command(config, state_authenticator),
        "serve" => serve(
            config,
            capability,
            state_authenticator,
            load_dns_provider(&config)?,
        ),
        "revoke-preview" => revoke_command(config, capability, state_authenticator, false),
        "revoke" => revoke_command(config, capability, state_authenticator, true),
        _ => Err(
            "usage: mrml-acmed [serve|check-config|config-status|health|status|restore-check|backup-create GENERATION|backup-verify GENERATION|backup-restore GENERATION|renew-now-preview|renew-now APPROVAL_SHA256|dns-cleanup confirm-exact-records|revoke-preview REASON|revoke REASON APPROVAL_SHA256]",
        ),
    }
}

fn acmed_restore_check(
    config: AcmedConfig,
    mut authenticator: impl DurableAuthenticator,
) -> Result<(), &'static str> {
    if std::env::var("MRML_ACMED_OFFLINE_RESTORE").as_deref() != Ok("1") {
        return Err("restore validation requires the stopped-acmed one-shot context");
    }
    let mut state = HostedDurableStateStore::open(Path::new(STATE_ROOT))
        .map_err(|_| "cannot open restored acmed durable state")?;
    let (account, _) = load_account_record(&config, &state, &mut authenticator)?
        .ok_or("restored active ACME account state is absent")?;
    account
        .require_policy(&config)
        .map_err(|_| "restored ACME account policy is stale")?;
    if account.phase != AcmedAccountPhase::Active {
        return Err("restored ACME account is not active");
    }
    let (schedule, _) = load_renewal_schedule(&config, &mut state, &mut authenticator)?
        .ok_or("restored renewal schedule is absent")?;
    if schedule.identity != TlsIdentityId(config.identity)
        || schedule.policy_generation != config.policy_generation
    {
        return Err("restored renewal schedule policy is stale");
    }
    println!(
        "mrml-acmed restore valid identity_generation={} renew_at_unix={}",
        schedule.identity_generation, schedule.renew_at_unix
    );
    Ok(())
}

fn backup_restore_command() -> Result<(), &'static str> {
    if std::env::var("MRML_ACMED_OFFLINE_BACKUP").as_deref() != Ok("1") {
        return Err("backup operation requires the stopped-acmed one-shot context");
    }
    let generation = std::env::args()
        .nth(2)
        .ok_or("backup generation is required")?
        .parse::<u64>()
        .map_err(|_| "backup generation must be a nonzero decimal integer")?;
    if generation == 0 || std::env::args().nth(3).is_some() {
        return Err("backup generation must be a nonzero decimal integer");
    }
    let secret = HostedSecret::open(
        Path::new(BACKUP_CAPABILITY),
        ACMED_UID,
        PRODUCTION_SECRET_MODE,
        32,
    )
    .map_err(|_| "invalid acmed backup capability")?;
    let mut key: [u8; 32] = secret
        .expose()
        .try_into()
        .map_err(|_| "invalid acmed backup capability")?;
    let component =
        std::path::PathBuf::from(std::format!("{}/acmed-{}.mrb", BACKUP_ROOT, generation));
    let result = restore_hosted_component_backup(
        HostedBackupRole::Acmed,
        generation,
        ACMED_UID,
        &key,
        &component,
        Path::new("/restore"),
    );
    mrml_crypto::erase_secret_bytes(&mut key);
    let receipt = result.map_err(|_| "acmed clean-target restore failed")?;
    println!(
        "role=acmed generation={} restore_receipt={}",
        generation,
        hex(&receipt)
    );
    Ok(())
}

fn backup_component_command(create: bool) -> Result<(), &'static str> {
    if std::env::var("MRML_ACMED_OFFLINE_BACKUP").as_deref() != Ok("1") {
        return Err("backup operation requires the stopped-acmed one-shot context");
    }
    let generation = std::env::args()
        .nth(2)
        .ok_or("backup generation is required")?
        .parse::<u64>()
        .map_err(|_| "backup generation must be a nonzero decimal integer")?;
    if generation == 0 || std::env::args().nth(3).is_some() {
        return Err("backup generation must be a nonzero decimal integer");
    }
    let secret = HostedSecret::open(
        Path::new(BACKUP_CAPABILITY),
        ACMED_UID,
        PRODUCTION_SECRET_MODE,
        32,
    )
    .map_err(|_| "invalid acmed backup capability")?;
    let mut key: [u8; 32] = secret
        .expose()
        .try_into()
        .map_err(|_| "invalid acmed backup capability")?;
    let path = std::path::PathBuf::from(std::format!("{}/acmed-{}.mrb", BACKUP_ROOT, generation));
    let result = if create {
        create_hosted_component_backup(
            HostedBackupRole::Acmed,
            generation,
            ACMED_UID,
            &[
                HostedBackupSource {
                    source: Path::new(STATE_ROOT),
                    archive_name: "acmed/state",
                },
                HostedBackupSource {
                    source: Path::new("/var/lib/mrml/challenges"),
                    archive_name: "acmed/challenges",
                },
                HostedBackupSource {
                    source: Path::new(STATE_KEY),
                    archive_name: "secrets/acmed/acmed-state.key",
                },
                HostedBackupSource {
                    source: Path::new(CHANNEL_CAPABILITY),
                    archive_name: "secrets/channels/certd-acmed.cap.acmed",
                },
            ],
            &key,
            &path,
        )
    } else {
        verify_hosted_component_backup(HostedBackupRole::Acmed, &key, &path)
    };
    mrml_crypto::erase_secret_bytes(&mut key);
    let descriptor = result.map_err(|_| "acmed backup component operation failed")?;
    println!(
        "role=acmed generation={} files={} plaintext_sha256={}",
        descriptor.generation,
        descriptor.file_count,
        hex(&descriptor.plaintext_digest)
    );
    Ok(())
}

fn dns_cleanup_command(
    config: AcmedConfig,
    mut authenticator: impl DurableAuthenticator,
) -> Result<(), &'static str> {
    if std::env::args().nth(2).as_deref() != Some("confirm-exact-records")
        || std::env::args().nth(3).is_some()
    {
        return Err("dns-cleanup requires the exact confirm-exact-records argument");
    }
    if std::env::var("MRML_ACMED_OFFLINE_ADMIN").as_deref() != Ok("1") {
        return Err("dns-cleanup requires the stopped-worker one-shot administration context");
    }
    let mut state = HostedDurableStateStore::open(Path::new(STATE_ROOT))
        .map_err(|_| "cannot open acmed durable state")?;
    let mut provider = load_dns_provider(&config)?;
    cleanup_dns_challenges(&config, &mut provider, &mut state, &mut authenticator)?;
    println!("persisted DNS-01 records cleaned exactly");
    Ok(())
}

fn renew_now_command(
    config: AcmedConfig,
    mut authenticator: impl DurableAuthenticator,
    commit: bool,
) -> Result<(), &'static str> {
    if (!commit && std::env::args().nth(2).is_some())
        || (commit && std::env::args().nth(3).is_some())
    {
        return Err("unexpected renew-now argument");
    }
    if commit && std::env::var("MRML_ACMED_OFFLINE_ADMIN").as_deref() != Ok("1") {
        return Err("renew-now requires the stopped-worker one-shot administration context");
    }
    let mut state = HostedDurableStateStore::open(Path::new(STATE_ROOT))
        .map_err(|_| "cannot open acmed durable state")?;
    let (mut schedule, generation) =
        load_renewal_schedule(&config, &mut state, &mut authenticator)?
            .ok_or("no active renewal schedule")?;
    let approval = renew_now_approval_digest(&schedule, generation)
        .ok_or("cannot encode renewal approval binding")?;
    if !commit {
        println!(
            "identity_generation={} schedule_generation={} certificate_id={} current_renew_at_unix={} approval_sha256={}",
            schedule.identity_generation,
            generation,
            schedule.certificate_id.as_str(),
            schedule.renew_at_unix,
            hex(&approval)
        );
        return Ok(());
    }
    let supplied = parse_digest(
        &std::env::args()
            .nth(2)
            .ok_or("renew-now approval SHA-256 is required")?,
    )?;
    if supplied != approval {
        return Err("renew-now approval does not match the current authenticated schedule");
    }
    let now = unix_time()?.max(1);
    if now >= schedule.not_after_unix {
        return Err("cannot renew an already expired identity");
    }
    schedule.renew_at_unix = now;
    schedule.requery_ari_at_unix = now;
    schedule.failure_count = 0;
    let committed = store_renewal_schedule(
        renewal_schedule_object(config.identity),
        generation,
        schedule,
        &mut state,
        &mut authenticator,
    )?;
    println!("renewal scheduled immediately generation={committed}");
    Ok(())
}

fn acmed_status(
    config: AcmedConfig,
    mut authenticator: impl DurableAuthenticator,
) -> Result<(), &'static str> {
    let mut state = HostedDurableStateStore::open(Path::new(STATE_ROOT))
        .map_err(|_| "cannot open acmed durable state")?;
    let account = load_account_record(&config, &state, &mut authenticator)?;
    let renewal = load_renewal_schedule(&config, &mut state, &mut authenticator)?;
    let revocation = load_revocation_record(
        &config,
        revocation_object(config.identity),
        &state,
        &mut authenticator,
    )?;
    let (account_phase, account_generation) = account
        .map(|(record, _)| (record.phase as u8, record.account_generation))
        .unwrap_or((0, 0));
    let (identity_generation, renew_at, failures, health) = renewal
        .map(|(schedule, _)| {
            (
                schedule.identity_generation,
                schedule.renew_at_unix,
                schedule.failure_count,
                match schedule.health {
                    mrml_certificate::ExpiryHealth::Healthy => "healthy",
                    mrml_certificate::ExpiryHealth::Warning => "warning",
                    mrml_certificate::ExpiryHealth::Critical => "critical",
                    mrml_certificate::ExpiryHealth::Expired => "expired",
                },
            )
        })
        .unwrap_or((0, 0, 0, "unavailable"));
    let (revocation_phase, revocation_generation) = revocation
        .map(|(record, _)| (record.phase as u8, record.revocation_generation))
        .unwrap_or((0, 0));
    println!(
        "account_phase={account_phase} account_generation={account_generation} identity_generation={identity_generation} renew_at_unix={renew_at} renewal_failures={failures} health={health} revocation_phase={revocation_phase} revocation_generation={revocation_generation}"
    );
    Ok(())
}

fn acmed_health(
    config: AcmedConfig,
    _capability: CertdChannelCapability,
    mut authenticator: impl DurableAuthenticator,
) -> Result<(), &'static str> {
    let executable = std::fs::read_link("/proc/1/exe").map_err(|_| "cannot inspect acmed pid 1")?;
    if executable.file_name().and_then(|name| name.to_str()) != Some("mrml-acmed") {
        return Err("mrml-acmed is not container pid 1");
    }
    let _provider = load_dns_provider(&config)?;
    let mut state = HostedDurableStateStore::open(Path::new(STATE_ROOT))
        .map_err(|_| "cannot open acmed durable state")?;
    let (account, _) = load_account_record(&config, &state, &mut authenticator)?
        .ok_or("active ACME account state is absent")?;
    account
        .require_policy(&config)
        .map_err(|_| "stale ACME account health state")?;
    if account.phase != AcmedAccountPhase::Active {
        return Err("ACME account is not active");
    }
    let (_, _) = load_renewal_schedule(&config, &mut state, &mut authenticator)?
        .ok_or("active renewal schedule is absent")?;
    let session = UnixCertdSession::connect(Path::new(CERTD_SOCKET))
        .map_err(|_| "certd listener is unavailable")?;
    if session.observed_peer() != CERTD_PEER {
        return Err("certd peer identity mismatch");
    }
    println!("mrml-acmed ready");
    Ok(())
}

fn load_dns_provider(config: &AcmedConfig) -> Result<CloudflareDns01Provider, &'static str> {
    CloudflareDns01Provider::open(
        Path::new(DNS_TOKEN),
        ACMED_UID,
        core::str::from_utf8(&config.zone_id).map_err(|_| "invalid zone ID")?,
        config.zone,
    )
    .map_err(|_| "invalid Cloudflare DNS provider configuration")
}

fn revoke_command(
    config: AcmedConfig,
    capability: CertdChannelCapability,
    mut authenticator: impl DurableAuthenticator,
    submit: bool,
) -> Result<(), &'static str> {
    let reason_text = std::env::args()
        .nth(2)
        .ok_or("revocation reason is required")?;
    let reason = match reason_text.as_str() {
        "unspecified" => 0,
        "key-compromise" => 1,
        "affiliation-changed" => 3,
        "superseded" => 4,
        "cessation-of-operation" => 5,
        "privilege-withdrawn" => 9,
        _ => return Err("unsupported revocation reason"),
    };
    if (!submit && std::env::args().nth(3).is_some())
        || (submit && std::env::args().nth(4).is_some())
    {
        return Err("unexpected revocation argument");
    }
    if submit && std::env::var("MRML_ACMED_OFFLINE_ADMIN").as_deref() != Ok("1") {
        return Err("revocation requires the stopped-worker one-shot administration context");
    }
    let mut state = HostedDurableStateStore::open(Path::new(STATE_ROOT))
        .map_err(|_| "cannot open acmed durable state")?;
    let reservation = reserve_channel_request_ids(&config, &mut state, &mut authenticator)?;
    let bootstrap = bootstrap_certd(&config, &capability, reservation.next)?;
    let mut signer = CertdEnvelopeWriter {
        capability: &capability,
        account_identity: config.account_identity,
        configured_account_generation: config.account_generation,
        operation: AcmeJwsOperation::NewAccount,
        next_request_id: bootstrap.next_request_id,
    };
    let account = establish_account(
        &config,
        &bootstrap.account_public_key,
        &mut signer,
        &mut state,
        &mut authenticator,
    )?;
    let mut active_bytes = [0u8; MAX_CERTD_CHANNEL_PAYLOAD_BYTES];
    let active_length = certd_call(
        &capability,
        signer.next_request_id,
        CertdChannelOperation::GetActiveCertificateForRevocation,
        &[],
        &mut active_bytes,
    )?;
    signer.next_request_id = signer
        .next_request_id
        .checked_add(1)
        .ok_or("channel request ID exhausted")?;
    let active = decode_certd_candidate_request(&active_bytes[..active_length])
        .map_err(|_| "invalid active certificate publication")?;
    if active.identity != config.identity
        || active.account_generation != config.account_generation
        || active.policy_generation != config.policy_generation
    {
        return Err("active certificate policy mismatch");
    }
    let mut lifecycle_bytes = [0u8; mrml_certificate::CERTD_CANDIDATE_STATE_BYTES];
    let lifecycle_length = certd_call(
        &capability,
        signer.next_request_id,
        CertdChannelOperation::GetCertificateLifecycleStatus,
        &[],
        &mut lifecycle_bytes,
    )?;
    signer.next_request_id = signer
        .next_request_id
        .checked_add(1)
        .ok_or("channel request ID exhausted")?;
    let lifecycle = CertdCandidateState::decode(&lifecycle_bytes[..lifecycle_length])
        .map_err(|_| "invalid active certificate lifecycle state")?;
    if lifecycle.stage != CertdCandidateStage::Active
        || lifecycle.identity_generation != active.identity_generation
        || lifecycle.chain_digest != active.chain.chain_digest()
    {
        return Err("active certificate lifecycle binding mismatch");
    }
    let certificate_id = lifecycle.ari_certificate_id;
    let chain_digest = active.chain.chain_digest();
    let approval = revocation_approval_digest(
        config.identity,
        active.identity_generation,
        &certificate_id,
        chain_digest,
        reason,
    );
    if !submit {
        println!(
            "identity_generation={} certificate_id={} chain_sha256={} reason={} approval_sha256={}",
            active.identity_generation,
            certificate_id.as_str(),
            hex(&chain_digest),
            reason_text,
            hex(&approval)
        );
        return Ok(());
    }
    let supplied = parse_digest(
        &std::env::args()
            .nth(3)
            .ok_or("approval SHA-256 is required")?,
    )?;
    if supplied != approval {
        return Err("revocation approval does not match the active certificate preview");
    }
    submit_revocation(
        &config,
        &account,
        &active,
        certificate_id,
        chain_digest,
        reason,
        approval,
        &mut signer,
        &mut state,
        &mut authenticator,
    )?;
    println!("mrml-acmed revocation confirmed");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn submit_revocation(
    config: &AcmedConfig,
    account: &AccountLifecycle,
    active: &mrml_certificate::CertdCandidateRequest,
    certificate_id: mrml_acme::AriCertificateId,
    chain_digest: [u8; 32],
    reason: u8,
    authorization_digest: [u8; 32],
    signer: &mut CertdEnvelopeWriter<'_>,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<(), &'static str> {
    let object = revocation_object(config.identity);
    let loaded = load_revocation_record(config, object, state, authenticator)?;
    let was_absent = loaded.is_none();
    let (revocation_generation, previous_generation, phase) = match loaded {
        Some((record, generation)) => {
            if same_revocation_binding(
                &record,
                active.identity_generation,
                &certificate_id,
                chain_digest,
                reason,
                authorization_digest,
            ) {
                if record.phase == AcmedRevocationPhase::Revoked {
                    return Ok(());
                }
                (record.revocation_generation, generation, record.phase)
            } else if record.phase == AcmedRevocationPhase::Revoked {
                (
                    record
                        .revocation_generation
                        .checked_add(1)
                        .ok_or("revocation generation exhausted")?,
                    generation,
                    AcmedRevocationPhase::Prepared,
                )
            } else {
                return Err("different revocation transaction is unresolved");
            }
        }
        None => (1, 0, AcmedRevocationPhase::Prepared),
    };
    let prepared = AcmedRevocationRecord {
        phase: AcmedRevocationPhase::Prepared,
        directory_generation: config.directory_generation,
        account_generation: config.account_generation,
        policy_generation: config.policy_generation,
        identity: config.identity,
        identity_generation: active.identity_generation,
        revocation_generation,
        certificate_id,
        chain_digest,
        reason,
        authorization_digest,
        transaction_digest: [0; 32],
        revoked_at_unix: 0,
    };
    let prepared_generation = if was_absent || phase == AcmedRevocationPhase::Prepared {
        persist_revocation_record(object, previous_generation, &prepared, state, authenticator)?
    } else {
        previous_generation
    };
    let uncertain = AcmedRevocationRecord {
        phase: AcmedRevocationPhase::SubmissionMayHaveBeenSent,
        ..prepared
    };
    let uncertain_generation = if phase == AcmedRevocationPhase::SubmissionMayHaveBeenSent {
        previous_generation
    } else {
        persist_revocation_record(
            object,
            prepared_generation,
            &uncertain,
            state,
            authenticator,
        )?
    };
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
    .map_err(|_| "cannot retrieve ACME directory for revocation")?;
    signer.operation = AcmeJwsOperation::RevokeCertificate;
    let mut payload = [0u8; MAX_ACME_PAYLOAD_BYTES];
    let mut response = [0u8; MAX_DIRECTORY_BYTES];
    let mut jws = [0u8; MAX_JWS_REQUEST_BYTES];
    let certificate_der = active
        .chain
        .certificate(0)
        .ok_or("active leaf certificate is absent")?;
    let account_url = account
        .account_url
        .ok_or("active ACME account URL is absent")?;
    let outcome = revoke_certificate(
        &directory,
        certificate_der,
        Some(reason),
        ProtectedKey::Kid(&account_url),
        account.generation,
        &mut exchange,
        &mut transport,
        signer,
        &mut payload,
        &mut response,
        &mut jws,
    )
    .map_err(|_| "ACME revocation response is uncertain or rejected")?;
    let now = unix_time()?;
    let mut transaction = mrml_crypto::Sha256::new();
    transaction.update(b"MRML acmed revocation receipt v1\0");
    transaction.update(directory.revoke_cert.as_str().as_bytes());
    transaction.update(&mrml_crypto::Sha256::digest(certificate_der));
    transaction.update(&[reason]);
    transaction.update(&[match outcome {
        RevocationOutcome::Submitted => 1,
        RevocationOutcome::AlreadyRevoked => 2,
    }]);
    persist_revocation_record(
        object,
        uncertain_generation,
        &AcmedRevocationRecord {
            phase: AcmedRevocationPhase::Revoked,
            transaction_digest: transaction.finalize(),
            revoked_at_unix: now,
            ..uncertain
        },
        state,
        authenticator,
    )?;
    Ok(())
}

fn revocation_object(identity: [u8; 16]) -> DurableObjectId {
    let mut digest = mrml_crypto::Sha256::new();
    digest.update(b"MRML acmed revocation v1\0");
    digest.update(&identity);
    let digest = digest.finalize();
    DurableObjectId(digest[..16].try_into().unwrap_or([0; 16]))
}

fn revocation_approval_digest(
    identity: [u8; 16],
    identity_generation: u64,
    certificate_id: &mrml_acme::AriCertificateId,
    chain_digest: [u8; 32],
    reason: u8,
) -> [u8; 32] {
    let mut digest = mrml_crypto::Sha256::new();
    digest.update(b"MRML acmed owner revocation approval v1\0");
    digest.update(&identity);
    digest.update(&identity_generation.to_be_bytes());
    digest.update(certificate_id.as_str().as_bytes());
    digest.update(&chain_digest);
    digest.update(&[reason]);
    digest.finalize()
}

fn same_revocation_binding(
    record: &AcmedRevocationRecord,
    identity_generation: u64,
    certificate_id: &mrml_acme::AriCertificateId,
    chain_digest: [u8; 32],
    reason: u8,
    authorization_digest: [u8; 32],
) -> bool {
    record.identity_generation == identity_generation
        && record.certificate_id == *certificate_id
        && record.chain_digest == chain_digest
        && record.reason == reason
        && record.authorization_digest == authorization_digest
}

fn parse_digest(text: &str) -> Result<[u8; 32], &'static str> {
    if text.len() != 64 {
        return Err("approval SHA-256 must contain 64 lowercase hexadecimal characters");
    }
    let mut output = [0u8; 32];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8, &'static str> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("approval SHA-256 must be lowercase hexadecimal"),
    }
}

fn hex(value: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn load_revocation_record(
    config: &AcmedConfig,
    object: DurableObjectId,
    state: &HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<Option<(AcmedRevocationRecord, u64)>, &'static str> {
    let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
    let Some(length) = state
        .load_authoritative(DurableNamespace::PublicState, object, &mut encoded)
        .map_err(|_| "cannot load ACME revocation state")?
    else {
        return Ok(None);
    };
    let durable = DurableRecord::decode(&encoded[..length], authenticator)
        .map_err(|_| "ACME revocation state authentication failed")?;
    if durable.namespace != DurableNamespace::PublicState
        || durable.kind != DurableRecordKind::Revocation
        || durable.object != object
    {
        return Err("ACME revocation durable record type mismatch");
    }
    let record = AcmedRevocationRecord::decode(durable.payload())
        .map_err(|_| "invalid ACME revocation durable record")?;
    record
        .require_policy(config)
        .map_err(|_| "stale ACME revocation policy")?;
    Ok(Some((record, durable.generation)))
}

fn persist_revocation_record(
    object: DurableObjectId,
    previous_generation: u64,
    record: &AcmedRevocationRecord,
    state: &mut impl DurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<u64, &'static str> {
    let mut payload = [0u8; MAX_DURABLE_PAYLOAD];
    let length = record
        .encode(&mut payload)
        .map_err(|_| "cannot encode ACME revocation state")?;
    let durable = DurableRecord::prepare(
        DurableNamespace::PublicState,
        DurableRecordKind::Revocation,
        object,
        previous_generation,
        &payload[..length],
        authenticator,
    )
    .map_err(|_| "cannot authenticate ACME revocation state")?;
    let prepared = state
        .prepare(&durable)
        .map_err(|_| "cannot prepare ACME revocation state")?;
    let committed = state
        .commit(prepared)
        .map_err(|_| "ACME revocation state commit uncertain")?;
    Ok(committed.generation)
}

fn serve(
    config: AcmedConfig,
    capability: CertdChannelCapability,
    mut state_authenticator: impl DurableAuthenticator,
    mut provider: CloudflareDns01Provider,
) -> Result<(), &'static str> {
    let mut state = HostedDurableStateStore::open(Path::new(STATE_ROOT))
        .map_err(|_| "cannot open acmed durable state")?;
    let reservation = reserve_channel_request_ids(&config, &mut state, &mut state_authenticator)?;
    let bootstrap = bootstrap_certd(&config, &capability, reservation.next)?;
    let _account_public_key = bootstrap.account_public_key;
    let _tls_public_key = bootstrap.tls_public_key;
    let csr = &bootstrap.csr[..bootstrap.csr_length];
    let mut envelope_writer = CertdEnvelopeWriter {
        capability: &capability,
        account_identity: config.account_identity,
        configured_account_generation: config.account_generation,
        operation: AcmeJwsOperation::NewAccount,
        next_request_id: bootstrap.next_request_id,
    };
    let account = establish_account(
        &config,
        &bootstrap.account_public_key,
        &mut envelope_writer,
        &mut state,
        &mut state_authenticator,
    )?;
    let (mut order, mut authorization_resources, mut order_durable_generation) = establish_order(
        &config,
        &account,
        &mut envelope_writer,
        &mut state,
        &mut state_authenticator,
    )?;
    if let Some(rotation_schedule) = key_rotation_schedule(
        &config,
        &mut envelope_writer,
        &mut state,
        &mut state_authenticator,
    )? {
        let replacement = create_replacement_order(
            &config,
            &account,
            rotation_schedule,
            true,
            &mut envelope_writer,
            &mut state,
            &mut state_authenticator,
        )?;
        order = replacement.0;
        authorization_resources = replacement.1;
        order_durable_generation = replacement.2;
    }
    loop {
        if order.state != mrml_acme::OrderState::Valid {
            publish_dns_challenges(
                &config,
                &account,
                &mut order,
                &authorization_resources,
                &mut envelope_writer,
                &mut provider,
                &mut state,
                &mut state_authenticator,
            )?;
            order_durable_generation = poll_and_persist_order(
                &config,
                &account,
                &mut order,
                &authorization_resources,
                &mut envelope_writer,
                &mut state,
                &mut state_authenticator,
                order_durable_generation,
            )?;
        }
        if order.state == mrml_acme::OrderState::Ready {
            order_durable_generation = finalize_ready_order(
                &config,
                &account,
                &mut order,
                csr,
                &mut envelope_writer,
                &mut state,
                &mut state_authenticator,
                order_durable_generation,
            )?;
        }
        if order.state == mrml_acme::OrderState::Valid {
            retrieve_and_stage_certificate(&config, &account, &order, &mut envelope_writer)?;
            cleanup_dns_challenges(&config, &mut provider, &mut state, &mut state_authenticator)?;
            let schedule = persist_renewal_schedule(
                &config,
                &mut envelope_writer,
                &mut state,
                &mut state_authenticator,
            )?;
            if unix_time()? >= schedule.renew_at_unix {
                if schedule.failure_count >= config.order_retry_limit {
                    eprintln!(
                        "mrml-acmed event=renewal_retry_limit identity_generation={} failures={} health={:?}",
                        schedule.identity_generation, schedule.failure_count, schedule.health
                    );
                } else {
                    match create_replacement_order(
                        &config,
                        &account,
                        schedule,
                        false,
                        &mut envelope_writer,
                        &mut state,
                        &mut state_authenticator,
                    ) {
                        Ok(replacement) => {
                            order = replacement.0;
                            authorization_resources = replacement.1;
                            order_durable_generation = replacement.2;
                            continue;
                        }
                        Err(error) => {
                            let failed = record_renewal_failure(
                                &config,
                                schedule,
                                &mut state,
                                &mut state_authenticator,
                            )?;
                            eprintln!(
                                "mrml-acmed event=renewal_failed identity_generation={} failures={} health={:?} reason={error}",
                                failed.identity_generation, failed.failure_count, failed.health
                            );
                        }
                    }
                }
            }
        }
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

fn retrieve_and_stage_certificate(
    config: &AcmedConfig,
    account: &AccountLifecycle,
    order: &OrderLifecycle,
    signer: &mut CertdEnvelopeWriter<'_>,
) -> Result<[u8; 32], &'static str> {
    let count = usize::from(config.identifier_count);
    let mut identifiers = [None; MAX_CSR_IDENTIFIERS];
    for (index, identifier) in identifiers.iter_mut().enumerate().take(count) {
        *identifier = Some(AcmeIdentifier::Dns(
            config.identifiers[index].ok_or("missing configured identifier")?,
        ));
    }
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
    .map_err(|_| "cannot retrieve ACME directory for certificate retrieval")?;
    signer.operation = AcmeJwsOperation::Certificate;
    let mut response = [0u8; MAX_CERTIFICATE_CHAIN_BYTES];
    let mut jws = [0u8; MAX_JWS_REQUEST_BYTES];
    let chain = retrieve_certificate_chain(
        &directory,
        account,
        order,
        &identifiers[..count],
        &mut exchange,
        &mut transport,
        signer,
        &mut response,
        &mut jws,
    )
    .map_err(|_| "cannot retrieve bound ACME certificate chain")?;
    let chain_digest = chain.chain_digest();
    let order_url_digest = mrml_crypto::Sha256::digest(order.order_url.as_str().as_bytes());
    let identity_generation = next_identity_generation(config, order_url_digest, signer)?;
    let mut request = [0u8; MAX_CERTD_CHANNEL_PAYLOAD_BYTES];
    let request_length = encode_certd_candidate_request(
        &CertdCandidateRequest {
            identity: config.identity,
            directory_generation: config.directory_generation,
            account_generation: config.account_generation,
            key_generation: config.key_generation,
            identity_generation,
            policy_generation: config.policy_generation,
            order_url_digest,
            profile: config.certificate_profile,
            chain,
        },
        &mut request,
    )
    .map_err(|_| "certificate chain exceeds certd candidate channel policy")?;
    let mut stage_response = [0u8; 32];
    let response_length = certd_call(
        signer.capability,
        signer.next_request_id,
        CertdChannelOperation::StageCertificateCandidate,
        &request[..request_length],
        &mut stage_response,
    )?;
    signer.next_request_id = signer
        .next_request_id
        .checked_add(1)
        .ok_or("channel request ID exhausted")?;
    if response_length != 32 || stage_response != chain_digest {
        return Err("certd candidate stage receipt mismatch");
    }
    let activation = CertdActivationRequest {
        identity: config.identity,
        directory_generation: config.directory_generation,
        account_generation: config.account_generation,
        key_generation: config.key_generation,
        identity_generation,
        policy_generation: config.policy_generation,
        chain_digest,
        request_digest: mrml_crypto::Sha256::digest(&request[..request_length]),
    };
    let mut activation_request = [0u8; mrml_certificate::CERTD_ACTIVATION_REQUEST_BYTES];
    let activation_length = activation
        .encode(&mut activation_request)
        .map_err(|_| "cannot encode certd activation request")?;
    let mut activation_response = [0u8; 32];
    let response_length = certd_call(
        signer.capability,
        signer.next_request_id,
        CertdChannelOperation::ActivateCertificateGeneration,
        &activation_request[..activation_length],
        &mut activation_response,
    )?;
    signer.next_request_id = signer
        .next_request_id
        .checked_add(1)
        .ok_or("channel request ID exhausted")?;
    if response_length != 32 || activation_response != chain_digest {
        return Err("certd activation receipt mismatch");
    }
    Ok(chain_digest)
}

fn next_identity_generation(
    config: &AcmedConfig,
    order_url_digest: [u8; 32],
    signer: &mut CertdEnvelopeWriter<'_>,
) -> Result<u64, &'static str> {
    let mut status = [0u8; mrml_certificate::CERTD_CANDIDATE_STATE_BYTES];
    let result = certd_call(
        signer.capability,
        signer.next_request_id,
        CertdChannelOperation::GetCertificateLifecycleStatus,
        &[],
        &mut status,
    );
    signer.next_request_id = signer
        .next_request_id
        .checked_add(1)
        .ok_or("channel request ID exhausted")?;
    let Ok(length) = result else {
        return Ok(config.key_generation);
    };
    let active = CertdCandidateState::decode(&status[..length])
        .map_err(|_| "invalid certd lifecycle status")?;
    if active.stage != CertdCandidateStage::Active
        || active.identity != config.identity
        || active.key_generation != config.key_generation
        || active.policy_generation != config.policy_generation
    {
        return Err("certd lifecycle status policy mismatch");
    }
    if active.order_url_digest == order_url_digest {
        Ok(active.identity_generation)
    } else {
        active
            .identity_generation
            .checked_add(1)
            .ok_or("identity generation exhausted")
    }
}

fn cleanup_dns_challenges(
    config: &AcmedConfig,
    provider: &mut impl Dns01Provider,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<(), &'static str> {
    for index in 0..usize::from(config.identifier_count) {
        let identifier = config.identifiers[index].ok_or("missing configured identifier")?;
        let (record, mut durable_generation) =
            load_challenge_record(config, index as u8, identifier, state, authenticator)?
                .ok_or("missing DNS-01 challenge state during cleanup")?;
        let pending = match record.phase {
            AcmedChallengePhase::Accepted => {
                let pending = AcmedChallengeRecord {
                    phase: AcmedChallengePhase::CleanupPending,
                    ..record
                };
                durable_generation = persist_challenge_record(
                    config,
                    state,
                    authenticator,
                    durable_generation,
                    &pending,
                )?;
                pending
            }
            AcmedChallengePhase::CleanupPending => record,
            AcmedChallengePhase::Complete => continue,
            _ => return Err("DNS-01 cleanup attempted before challenge acceptance"),
        };
        let receipt = pending
            .publication_receipt()
            .map_err(|_| "invalid persisted DNS-01 cleanup receipt")?
            .ok_or("missing persisted DNS-01 cleanup receipt")?;
        provider
            .cleanup(receipt)
            .map_err(|_| "DNS-01 provider cleanup failed")?;
        persist_challenge_record(
            config,
            state,
            authenticator,
            durable_generation,
            &AcmedChallengeRecord {
                phase: AcmedChallengePhase::Complete,
                ..pending
            },
        )?;
    }
    Ok(())
}

struct HostedRenewalEntropy;

impl RenewalEntropy for HostedRenewalEntropy {
    fn random_u64(&mut self) -> Result<u64, SchedulerError> {
        let mut bytes = [0u8; 8];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .map_err(|_| SchedulerError::EntropyUnavailable)?;
        Ok(u64::from_be_bytes(bytes))
    }
}

fn renewal_schedule_object(identity: [u8; 16]) -> DurableObjectId {
    let mut digest = mrml_crypto::Sha256::new();
    digest.update(b"MRML acmed renewal schedule v1\0");
    digest.update(&identity);
    let digest = digest.finalize();
    let mut object = [0u8; 16];
    object.copy_from_slice(&digest[..16]);
    DurableObjectId(object)
}

fn persist_renewal_schedule(
    config: &AcmedConfig,
    signer: &mut CertdEnvelopeWriter<'_>,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<RenewalSchedule, &'static str> {
    let mut status = [0u8; mrml_certificate::CERTD_CANDIDATE_STATE_BYTES];
    let status_length = certd_call(
        signer.capability,
        signer.next_request_id,
        CertdChannelOperation::GetCertificateLifecycleStatus,
        &[],
        &mut status,
    )?;
    signer.next_request_id = signer
        .next_request_id
        .checked_add(1)
        .ok_or("channel request ID exhausted")?;
    let active = CertdCandidateState::decode(&status[..status_length])
        .map_err(|_| "invalid certd lifecycle status")?;
    if active.stage != CertdCandidateStage::Active
        || active.identity != config.identity
        || active.policy_generation != config.policy_generation
        || active.key_generation != config.key_generation
    {
        return Err("certd lifecycle status policy mismatch");
    }
    let object = renewal_schedule_object(config.identity);
    let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
    let existing = state
        .load_authoritative(DurableNamespace::PublicState, object, &mut encoded)
        .map_err(|_| "cannot load renewal schedule")?;
    let previous_generation = if let Some(length) = existing {
        let durable = DurableRecord::decode(&encoded[..length], authenticator)
            .map_err(|_| "renewal schedule authentication failed")?;
        if durable.namespace != DurableNamespace::PublicState
            || durable.kind != DurableRecordKind::AriSchedule
            || durable.object != object
        {
            return Err("renewal schedule durable record type mismatch");
        }
        let schedule = RenewalSchedule::decode(durable.payload())
            .map_err(|_| "invalid durable renewal schedule")?;
        if schedule.identity_generation == active.identity_generation
            && schedule.certificate_id == active.ari_certificate_id
            && schedule.not_after_unix == active.not_after
        {
            let now = unix_time()?;
            if now < schedule.requery_ari_at_unix || now >= schedule.renew_at_unix {
                return Ok(schedule);
            }
            let refreshed = refresh_renewal_schedule(config, active, schedule, now)?;
            store_renewal_schedule(object, durable.generation, refreshed, state, authenticator)?;
            return Ok(refreshed);
        }
        if schedule.identity_generation >= active.identity_generation {
            return Err("renewal schedule generation rollback rejected");
        }
        durable.generation
    } else {
        0
    };
    let schedule = RenewalSchedule::fallback_for_certificate(
        TlsIdentityId(config.identity),
        active.identity_generation,
        active.ari_certificate_id,
        active.not_before,
        active.not_after,
        config.renewal_policy,
        unix_time()?,
        &mut HostedRenewalEntropy,
    )
    .map_err(|_| "cannot construct renewal schedule")?;
    store_renewal_schedule(object, previous_generation, schedule, state, authenticator)?;
    Ok(schedule)
}

fn refresh_renewal_schedule(
    config: &AcmedConfig,
    active: CertdCandidateState,
    mut existing: RenewalSchedule,
    now: u64,
) -> Result<RenewalSchedule, &'static str> {
    existing
        .refresh_health(now, config.renewal_policy)
        .map_err(|_| "cannot refresh renewal health")?;
    let mut exchange = AcmeExchange::new(config.directory_generation, config.directory_url);
    let mut transport = HostedAcmeTransport::new();
    let mut directory_response = [0u8; MAX_DIRECTORY_BYTES];
    let directory = fetch_directory(
        &config.directory_url,
        config.directory_generation,
        &mut exchange,
        &mut transport,
        &mut directory_response,
    );
    if let Ok(directory) = directory {
        let mut response = [0u8; mrml_acme::MAX_ARI_RESPONSE_BYTES];
        if let Ok(info) = fetch_renewal_info(
            &directory,
            &active.ari_certificate_id,
            now,
            config.renewal_policy.critical_lead_seconds,
            &mut exchange,
            &mut transport,
            &mut response,
        ) {
            return RenewalSchedule::from_ari_for_certificate(
                TlsIdentityId(config.identity),
                active.identity_generation,
                active.ari_certificate_id,
                active.not_after,
                info,
                config.renewal_policy,
                now,
                &mut HostedRenewalEntropy,
            )
            .map_err(|_| "invalid ACME renewal information");
        }
    }
    existing.requery_ari_at_unix = now
        .checked_add(config.renewal_policy.ari_requery_min_seconds)
        .ok_or("ARI requery deadline overflow")?
        .min(existing.renew_at_unix);
    Ok(existing)
}

fn store_renewal_schedule(
    object: DurableObjectId,
    previous_generation: u64,
    schedule: RenewalSchedule,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<u64, &'static str> {
    let mut payload = [0u8; RENEWAL_SCHEDULE_BYTES];
    schedule
        .encode(&mut payload)
        .map_err(|_| "cannot encode renewal schedule")?;
    let durable = DurableRecord::prepare(
        DurableNamespace::PublicState,
        DurableRecordKind::AriSchedule,
        object,
        previous_generation,
        &payload,
        authenticator,
    )
    .map_err(|_| "cannot authenticate renewal schedule")?;
    let prepared = state
        .prepare(&durable)
        .map_err(|_| "cannot prepare renewal schedule")?;
    let committed = state
        .commit(prepared)
        .map_err(|_| "renewal schedule commit uncertain")?;
    Ok(committed.generation)
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
            if record.account_generation.checked_add(1) == Some(config.account_generation) {
                return rollover_account(
                    config,
                    record,
                    _durable_generation,
                    &directory,
                    &public_key,
                    contact_digest,
                    signer,
                    state,
                    authenticator,
                    &mut exchange,
                    &mut transport,
                );
            }
            record
                .require_policy(config)
                .map_err(|_| "stale ACME account policy")?;
            if record.key_thumbprint
                != public_key.thumbprint().map_err(|_| "invalid account key")?
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
            record
                .require_policy(config)
                .map_err(|_| "stale ACME account policy")?;
            if record.key_thumbprint
                != public_key.thumbprint().map_err(|_| "invalid account key")?
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
        Some((record, durable_generation))
            if record.phase == AcmedAccountPhase::RolloverMayHaveBeenSent =>
        {
            recover_account_rollover(
                config,
                record,
                durable_generation,
                &directory,
                &public_key,
                contact_digest,
                signer,
                state,
                authenticator,
                &mut exchange,
                &mut transport,
            )
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
fn rollover_account(
    config: &AcmedConfig,
    previous: AcmedAccountRecord,
    durable_generation: u64,
    directory: &mrml_acme::AcmeDirectory,
    new_public_key: &P256Jwk,
    contact_digest: [u8; 32],
    signer: &mut CertdEnvelopeWriter<'_>,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
    exchange: &mut AcmeExchange,
    transport: &mut HostedAcmeTransport,
) -> Result<AccountLifecycle, &'static str> {
    if previous.policy_generation != config.policy_generation
        || previous.account_identity != config.account_identity
        || previous.contact_digest != contact_digest
    {
        return Err("stale ACME account rollover policy");
    }
    let account_url = previous.account_url.ok_or("active account URL missing")?;
    let old_public_key = certd_account_public_key(config, previous.account_generation, signer)?;
    if old_public_key
        .thumbprint()
        .map_err(|_| "invalid previous ACME account key")?
        != previous.key_thumbprint
    {
        return Err("previous ACME account key binding mismatch");
    }
    let ca_class = match config.directory_class {
        AcmeDirectoryClass::PublicProduction => CaClass::Production,
        AcmeDirectoryClass::LocalTest | AcmeDirectoryClass::PublicStaging => CaClass::Staging,
    };
    let mut lifecycle = AccountLifecycle::restore_active(
        directory,
        ca_class,
        previous.account_generation,
        previous.policy_generation,
        account_url,
        &old_public_key,
        contact_digest,
    )
    .map_err(|_| "cannot restore account for rollover")?;
    let receipt = lifecycle
        .prepare_rollover(new_public_key, config.policy_generation)
        .map_err(|_| "cannot prepare account rollover")?;
    let new_thumbprint = new_public_key
        .thumbprint()
        .map_err(|_| "invalid replacement ACME account key")?;
    let pending_generation = persist_account_record(
        config,
        state,
        authenticator,
        durable_generation,
        AcmedAccountPhase::RolloverMayHaveBeenSent,
        new_thumbprint,
        contact_digest,
        Some(account_url),
    )?;
    let marker = b"MRML account rollover inner v1";
    let inner_request = ConstrainedAcmeJwsRequest {
        operation: AcmeJwsOperation::KeyChange,
        directory_generation: config.directory_generation,
        account_generation: config.account_generation,
        account_identity: config.account_identity,
        protected_url: directory.key_change,
        nonce: ReplayNonce::parse("mrml-account-rollover")
            .map_err(|_| "cannot construct account rollover request")?,
        account_url: Some(account_url),
        payload: marker,
    };
    let mut encoded = [0u8; MAX_CERTD_CHANNEL_PAYLOAD_BYTES];
    let encoded_length = encode_certd_jws_request(&inner_request, &mut encoded)
        .map_err(|_| "cannot encode account rollover inner request")?;
    let mut inner = [0u8; MAX_JWS_REQUEST_BYTES];
    let inner_length = certd_call(
        signer.capability,
        signer.next_request_id,
        CertdChannelOperation::CreateAccountRolloverInnerJws,
        &encoded[..encoded_length],
        &mut inner,
    )?;
    signer.next_request_id = signer
        .next_request_id
        .checked_add(1)
        .ok_or("channel request ID exhausted")?;
    signer.operation = AcmeJwsOperation::KeyChange;
    let mut response = [0u8; MAX_DIRECTORY_BYTES];
    let mut jws = [0u8; MAX_JWS_REQUEST_BYTES];
    let result = post_jws(
        exchange,
        transport,
        &directory.new_nonce,
        &directory.key_change,
        ProtectedKey::Kid(&account_url),
        &inner[..inner_length],
        previous.account_generation,
        signer,
        &mut response,
        &mut jws,
    )
    .map_err(|_| "ACME account rollover response is uncertain")?;
    if result.problem.is_some()
        || result.metadata.status != 200
        || result.metadata.response_type != mrml_acme::AcmeResponseType::Json
    {
        return Err("ACME account rollover response is uncertain or rejected");
    }
    let body = core::str::from_utf8(&response[..result.metadata.body_length])
        .map_err(|_| "invalid ACME account rollover response")?;
    let parsed = parse_account_response(body, account_url.origin())
        .map_err(|_| "invalid ACME account rollover response")?;
    if parsed.status != ParsedAccountStatus::Valid || parsed.contacts_digest != contact_digest {
        return Err("ACME account rollover response binding mismatch");
    }
    lifecycle
        .commit(receipt)
        .map_err(|_| "cannot commit ACME account rollover")?;
    persist_account_record(
        config,
        state,
        authenticator,
        pending_generation,
        AcmedAccountPhase::Active,
        new_thumbprint,
        contact_digest,
        Some(account_url),
    )?;
    Ok(lifecycle)
}

#[allow(clippy::too_many_arguments)]
fn recover_account_rollover(
    config: &AcmedConfig,
    record: AcmedAccountRecord,
    durable_generation: u64,
    directory: &mrml_acme::AcmeDirectory,
    new_public_key: &P256Jwk,
    contact_digest: [u8; 32],
    signer: &mut CertdEnvelopeWriter<'_>,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
    exchange: &mut AcmeExchange,
    transport: &mut HostedAcmeTransport,
) -> Result<AccountLifecycle, &'static str> {
    record
        .require_policy(config)
        .map_err(|_| "stale ACME account rollover policy")?;
    if record.key_thumbprint
        != new_public_key
            .thumbprint()
            .map_err(|_| "invalid replacement ACME account key")?
        || record.contact_digest != contact_digest
    {
        return Err("ACME account rollover recovery binding mismatch");
    }
    let previous_generation = config
        .account_generation
        .checked_sub(1)
        .ok_or("invalid ACME account rollover generation")?;
    let old_public_key = certd_account_public_key(config, previous_generation, signer)?;
    let account_url = record.account_url.ok_or("account rollover URL missing")?;
    let ca_class = match config.directory_class {
        AcmeDirectoryClass::PublicProduction => CaClass::Production,
        AcmeDirectoryClass::LocalTest | AcmeDirectoryClass::PublicStaging => CaClass::Staging,
    };
    let mut lifecycle = AccountLifecycle::restore_active(
        directory,
        ca_class,
        previous_generation,
        config.policy_generation,
        account_url,
        &old_public_key,
        contact_digest,
    )
    .map_err(|_| "cannot restore uncertain account rollover")?;
    let receipt = lifecycle
        .prepare_rollover(new_public_key, config.policy_generation)
        .map_err(|_| "cannot reconstruct account rollover")?;
    lifecycle
        .mark_uncertain()
        .map_err(|_| "cannot mark account rollover uncertain")?;
    signer.operation = AcmeJwsOperation::AccountUpdate;
    let mut response = [0u8; MAX_DIRECTORY_BYTES];
    let mut jws = [0u8; MAX_JWS_REQUEST_BYTES];
    let generation = resolve_uncertain_account_action(
        &mut lifecycle,
        receipt,
        directory,
        new_public_key,
        exchange,
        transport,
        signer,
        &mut response,
        &mut jws,
    )
    .map_err(|_| "ACME account rollover remains uncertain")?;
    if generation != config.account_generation {
        return Err("ACME account rollover was not committed by the CA");
    }
    persist_account_record(
        config,
        state,
        authenticator,
        durable_generation,
        AcmedAccountPhase::Active,
        record.key_thumbprint,
        contact_digest,
        Some(account_url),
    )?;
    Ok(lifecycle)
}

fn certd_account_public_key(
    config: &AcmedConfig,
    account_generation: u64,
    signer: &mut CertdEnvelopeWriter<'_>,
) -> Result<P256Jwk, &'static str> {
    let request = CertdAccountKeyRequest {
        account_identity: config.account_identity,
        directory_generation: config.directory_generation,
        account_generation,
    };
    let encoded = encode_certd_account_key_request(request)
        .map_err(|_| "cannot encode certd account key request")?;
    let mut response = [0u8; CERTD_P256_PUBLIC_KEY_BYTES];
    let response_length = certd_call(
        signer.capability,
        signer.next_request_id,
        CertdChannelOperation::GetAcmeAccountPublicIdentity,
        &encoded,
        &mut response,
    )?;
    signer.next_request_id = signer
        .next_request_id
        .checked_add(1)
        .ok_or("channel request ID exhausted")?;
    if response_length != response.len() {
        return Err("invalid certd account public key response");
    }
    account_public_key(&response)
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
    let (mut lifecycle, receipt) =
        AccountLifecycle::prepare_create(directory, policy, public_key, terms, false)
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

fn establish_order(
    config: &AcmedConfig,
    account: &AccountLifecycle,
    signer: &mut CertdEnvelopeWriter<'_>,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<
    (
        OrderLifecycle,
        [Option<AuthorizationResource>; MAX_AUTHORIZATIONS],
        u64,
    ),
    &'static str,
> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes Unix epoch")?
        .as_secs();
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
    .map_err(|_| "cannot retrieve ACME directory for order")?;
    let count = usize::from(config.identifier_count);
    let first = config.identifiers[0].ok_or("missing configured identifier")?;
    let mut identifier_storage = [AcmeIdentifier::Dns(first); MAX_CSR_IDENTIFIERS];
    for (slot, identifier) in identifier_storage
        .iter_mut()
        .zip(config.identifiers[..count].iter().flatten())
    {
        *slot = AcmeIdentifier::Dns(*identifier);
    }
    let identifiers = &identifier_storage[..count];
    match load_order_record(config, state, authenticator)? {
        Some((record, _)) if record.phase == AcmedOrderPhase::RequestMayHaveBeenSent => {
            record
                .require_policy(config)
                .map_err(|_| "stale ACME order policy")?;
            Err("ACME order response is uncertain; duplicate order creation refused")
        }
        Some((record, durable_generation)) if record.phase == AcmedOrderPhase::Created => {
            if record.require_policy(config).is_err()
                && !(record.state == Some(mrml_acme::OrderState::Valid)
                    && record.directory_generation == config.directory_generation
                    && record.account_generation.checked_add(1) == Some(config.account_generation)
                    && record.policy_generation == config.policy_generation
                    && record.identity == config.identity)
            {
                return Err("stale ACME order policy");
            }
            if usize::from(record.authorization_count) != count {
                return Err("ACME order authorization count mismatch");
            }
            let mut payload = [0u8; MAX_ACME_PAYLOAD_BYTES];
            let mut prepared = prepare_order_creation(
                &directory,
                account,
                identifiers,
                &config.certificate_profile,
                None,
                record.deadline_unix,
                config.order_retry_limit,
                false,
                &mut payload,
            )
            .map_err(|_| "cannot reconstruct ACME order request")?;
            if prepared.request_digest != record.request_digest {
                let (schedule, _) = load_renewal_schedule(config, state, authenticator)?
                    .ok_or("ACME order request binding mismatch")?;
                prepared = prepare_order_creation(
                    &directory,
                    account,
                    identifiers,
                    &config.certificate_profile,
                    Some(schedule.certificate_id.as_str()),
                    record.deadline_unix,
                    config.order_retry_limit,
                    false,
                    &mut payload,
                )
                .map_err(|_| "cannot reconstruct ACME replacement order request")?;
                if prepared.request_digest != record.request_digest {
                    return Err("ACME order request binding mismatch");
                }
            }
            let mut order = OrderLifecycle::create(
                &directory,
                account.generation,
                account.key,
                record.order_url.ok_or("created order URL missing")?,
                record.finalize_url.ok_or("created finalize URL missing")?,
                config.certificate_profile,
                identifiers,
                false,
                record.deadline_unix,
                config.order_retry_limit,
            )
            .map_err(|_| "cannot restore ACME order")?;
            order
                .apply_order_response(
                    1,
                    record.state.ok_or("created order state missing")?,
                    record.certificate_url,
                    now_unix,
                )
                .map_err(|_| "restored ACME order is stale or invalid")?;
            let mut resources = [None; MAX_AUTHORIZATIONS];
            for (slot, url) in resources
                .iter_mut()
                .zip(record.authorization_urls[..count].iter().flatten())
            {
                *slot = Some(
                    AuthorizationResource::bind(
                        &order.order_url,
                        *url,
                        directory.generation,
                        account.generation,
                    )
                    .map_err(|_| "invalid restored authorization resource")?,
                );
            }
            Ok((order, resources, durable_generation))
        }
        Some(_) => Err("unsupported ACME order durable phase"),
        None => {
            let deadline = now_unix
                .checked_add(config.order_lifetime_seconds)
                .ok_or("ACME order deadline overflow")?;
            let mut payload = [0u8; MAX_ACME_PAYLOAD_BYTES];
            let prepared = prepare_order_creation(
                &directory,
                account,
                identifiers,
                &config.certificate_profile,
                None,
                deadline,
                config.order_retry_limit,
                false,
                &mut payload,
            )
            .map_err(|_| "cannot prepare ACME order")?;
            let pending = AcmedOrderRecord {
                phase: AcmedOrderPhase::RequestMayHaveBeenSent,
                directory_generation: config.directory_generation,
                account_generation: config.account_generation,
                policy_generation: config.policy_generation,
                identity: config.identity,
                request_digest: prepared.request_digest,
                deadline_unix: deadline,
                state: None,
                order_url: None,
                finalize_url: None,
                certificate_url: None,
                authorization_urls: [None; MAX_AUTHORIZATIONS],
                authorization_count: 0,
            };
            let pending_generation =
                persist_order_record(config, state, authenticator, 0, &pending)?;
            let mut response = [0u8; MAX_DIRECTORY_BYTES];
            let mut jws = [0u8; MAX_JWS_REQUEST_BYTES];
            let mut resources = [None; MAX_AUTHORIZATIONS];
            signer.operation = AcmeJwsOperation::NewOrder;
            let order = execute_prepared_order_create(
                prepared,
                &directory,
                account,
                identifiers,
                config.certificate_profile,
                None,
                false,
                now_unix,
                &mut exchange,
                &mut transport,
                signer,
                OrderCreateBuffers {
                    payload: &mut payload,
                    response: &mut response,
                    jws: &mut jws,
                    authorizations: &mut resources[..count],
                },
            )
            .map_err(|_| "ACME order creation is uncertain or rejected")?;
            let mut authorization_urls = [None; MAX_AUTHORIZATIONS];
            for (slot, resource) in authorization_urls
                .iter_mut()
                .zip(resources[..count].iter().flatten())
            {
                *slot = Some(resource.url);
            }
            let created = AcmedOrderRecord {
                phase: AcmedOrderPhase::Created,
                directory_generation: config.directory_generation,
                account_generation: config.account_generation,
                policy_generation: config.policy_generation,
                identity: config.identity,
                request_digest: prepared.request_digest,
                deadline_unix: deadline,
                state: Some(order.state),
                order_url: Some(order.order_url),
                finalize_url: Some(order.finalize_url),
                certificate_url: order.certificate_url,
                authorization_urls,
                authorization_count: count as u8,
            };
            let created_generation =
                persist_order_record(config, state, authenticator, pending_generation, &created)?;
            Ok((order, resources, created_generation))
        }
    }
}

fn create_replacement_order(
    config: &AcmedConfig,
    account: &AccountLifecycle,
    schedule: RenewalSchedule,
    force_key_rotation: bool,
    signer: &mut CertdEnvelopeWriter<'_>,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<
    (
        OrderLifecycle,
        [Option<AuthorizationResource>; MAX_AUTHORIZATIONS],
        u64,
    ),
    &'static str,
> {
    if schedule.identity != TlsIdentityId(config.identity)
        || schedule.policy_generation != config.policy_generation
        || (!force_key_rotation && unix_time()? < schedule.renew_at_unix)
    {
        return Err("replacement order schedule mismatch");
    }
    let (prior, prior_generation) = load_order_record(config, state, authenticator)?
        .ok_or("missing completed order for renewal")?;
    if prior.phase != AcmedOrderPhase::Created || prior.state != Some(mrml_acme::OrderState::Valid)
    {
        return Err("replacement order requires a valid completed order");
    }
    let now = unix_time()?;
    let deadline = now
        .checked_add(config.order_lifetime_seconds)
        .ok_or("ACME replacement order deadline overflow")?;
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
    .map_err(|_| "cannot retrieve ACME directory for replacement order")?;
    let count = usize::from(config.identifier_count);
    let first = config.identifiers[0].ok_or("missing configured identifier")?;
    let mut identifier_storage = [AcmeIdentifier::Dns(first); MAX_CSR_IDENTIFIERS];
    for (slot, identifier) in identifier_storage
        .iter_mut()
        .zip(config.identifiers[..count].iter().flatten())
    {
        *slot = AcmeIdentifier::Dns(*identifier);
    }
    let identifiers = &identifier_storage[..count];
    let mut payload = [0u8; MAX_ACME_PAYLOAD_BYTES];
    let prepared = prepare_order_creation(
        &directory,
        account,
        identifiers,
        &config.certificate_profile,
        Some(schedule.certificate_id.as_str()),
        deadline,
        config.order_retry_limit,
        false,
        &mut payload,
    )
    .map_err(|_| "cannot prepare ACME replacement order")?;
    let pending = AcmedOrderRecord {
        phase: AcmedOrderPhase::RequestMayHaveBeenSent,
        directory_generation: config.directory_generation,
        account_generation: config.account_generation,
        policy_generation: config.policy_generation,
        identity: config.identity,
        request_digest: prepared.request_digest,
        deadline_unix: deadline,
        state: None,
        order_url: None,
        finalize_url: None,
        certificate_url: None,
        authorization_urls: [None; MAX_AUTHORIZATIONS],
        authorization_count: 0,
    };
    let pending_generation =
        persist_order_record(config, state, authenticator, prior_generation, &pending)?;
    let mut response = [0u8; MAX_DIRECTORY_BYTES];
    let mut jws = [0u8; MAX_JWS_REQUEST_BYTES];
    let mut resources = [None; MAX_AUTHORIZATIONS];
    signer.operation = AcmeJwsOperation::NewOrder;
    let order = execute_prepared_order_create(
        prepared,
        &directory,
        account,
        identifiers,
        config.certificate_profile,
        Some(schedule.certificate_id.as_str()),
        false,
        now,
        &mut exchange,
        &mut transport,
        signer,
        OrderCreateBuffers {
            payload: &mut payload,
            response: &mut response,
            jws: &mut jws,
            authorizations: &mut resources[..count],
        },
    )
    .map_err(|_| "ACME replacement order creation is uncertain or rejected")?;
    let mut authorization_urls = [None; MAX_AUTHORIZATIONS];
    for (slot, resource) in authorization_urls
        .iter_mut()
        .zip(resources[..count].iter().flatten())
    {
        *slot = Some(resource.url);
    }
    let created = AcmedOrderRecord {
        phase: AcmedOrderPhase::Created,
        directory_generation: config.directory_generation,
        account_generation: config.account_generation,
        policy_generation: config.policy_generation,
        identity: config.identity,
        request_digest: prepared.request_digest,
        deadline_unix: deadline,
        state: Some(order.state),
        order_url: Some(order.order_url),
        finalize_url: Some(order.finalize_url),
        certificate_url: order.certificate_url,
        authorization_urls,
        authorization_count: count as u8,
    };
    let created_generation =
        persist_order_record(config, state, authenticator, pending_generation, &created)?;
    Ok((order, resources, created_generation))
}

fn load_renewal_schedule(
    config: &AcmedConfig,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<Option<(RenewalSchedule, u64)>, &'static str> {
    let object = renewal_schedule_object(config.identity);
    let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
    let Some(length) = state
        .load_authoritative(DurableNamespace::PublicState, object, &mut encoded)
        .map_err(|_| "cannot load renewal schedule")?
    else {
        return Ok(None);
    };
    let durable = DurableRecord::decode(&encoded[..length], authenticator)
        .map_err(|_| "renewal schedule authentication failed")?;
    if durable.namespace != DurableNamespace::PublicState
        || durable.kind != DurableRecordKind::AriSchedule
        || durable.object != object
    {
        return Err("renewal schedule durable record type mismatch");
    }
    let schedule = RenewalSchedule::decode(durable.payload())
        .map_err(|_| "invalid durable renewal schedule")?;
    if schedule.identity != TlsIdentityId(config.identity)
        || schedule.policy_generation != config.policy_generation
    {
        return Err("renewal schedule policy mismatch");
    }
    Ok(Some((schedule, durable.generation)))
}

fn key_rotation_schedule(
    config: &AcmedConfig,
    signer: &mut CertdEnvelopeWriter<'_>,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<Option<RenewalSchedule>, &'static str> {
    let mut status = [0u8; mrml_certificate::CERTD_CANDIDATE_STATE_BYTES];
    let result = certd_call(
        signer.capability,
        signer.next_request_id,
        CertdChannelOperation::GetCertificateLifecycleStatus,
        &[],
        &mut status,
    );
    signer.next_request_id = signer
        .next_request_id
        .checked_add(1)
        .ok_or("channel request ID exhausted")?;
    let Ok(length) = result else {
        return Ok(None);
    };
    let active = CertdCandidateState::decode(&status[..length])
        .map_err(|_| "invalid certd lifecycle status")?;
    if active.stage != CertdCandidateStage::Active
        || active.identity != config.identity
        || active.policy_generation != config.policy_generation
    {
        return Err("certd lifecycle status policy mismatch");
    }
    if active.key_generation == config.key_generation {
        return Ok(None);
    }
    if active
        .key_generation
        .checked_add(1)
        .ok_or("TLS key generation exhausted")?
        != config.key_generation
    {
        return Err("TLS key rotation must advance exactly one generation");
    }
    let now = unix_time()?;
    let object = renewal_schedule_object(config.identity);
    let previous_generation = match load_renewal_schedule(config, state, authenticator)? {
        Some((schedule, generation)) => {
            if schedule.identity_generation != active.identity_generation
                || schedule.certificate_id != active.ari_certificate_id
                || schedule.not_after_unix != active.not_after
            {
                return Err("TLS key rotation renewal schedule mismatch");
            }
            if schedule.renew_at_unix <= now {
                return Ok(Some(schedule));
            }
            generation
        }
        None => 0,
    };
    let mut schedule = RenewalSchedule::fallback_for_certificate(
        TlsIdentityId(config.identity),
        active.identity_generation,
        active.ari_certificate_id,
        active.not_before,
        active.not_after,
        config.renewal_policy,
        now,
        &mut HostedRenewalEntropy,
    )
    .map_err(|_| "cannot construct TLS key rotation schedule")?;
    schedule.renew_at_unix = now;
    schedule.requery_ari_at_unix = now;
    store_renewal_schedule(object, previous_generation, schedule, state, authenticator)?;
    Ok(Some(schedule))
}

fn record_renewal_failure(
    config: &AcmedConfig,
    expected: RenewalSchedule,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<RenewalSchedule, &'static str> {
    let (mut schedule, generation) = load_renewal_schedule(config, state, authenticator)?
        .ok_or("missing renewal schedule during failure recording")?;
    if schedule != expected {
        return Err("renewal schedule changed during order attempt");
    }
    schedule
        .record_failure(
            unix_time()?,
            None,
            config.renewal_policy,
            &mut HostedRenewalEntropy,
        )
        .map_err(|_| "cannot advance renewal failure backoff")?;
    store_renewal_schedule(
        renewal_schedule_object(config.identity),
        generation,
        schedule,
        state,
        authenticator,
    )?;
    Ok(schedule)
}

#[allow(clippy::too_many_arguments)]
fn poll_and_persist_order(
    config: &AcmedConfig,
    account: &AccountLifecycle,
    order: &mut OrderLifecycle,
    resources: &[Option<AuthorizationResource>; MAX_AUTHORIZATIONS],
    signer: &mut CertdEnvelopeWriter<'_>,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
    durable_generation: u64,
) -> Result<u64, &'static str> {
    if matches!(
        order.state,
        mrml_acme::OrderState::Ready
            | mrml_acme::OrderState::Valid
            | mrml_acme::OrderState::Invalid
    ) {
        return Ok(durable_generation);
    }
    let count = usize::from(config.identifier_count);
    let mut identifiers =
        [AcmeIdentifier::Dns(config.identifiers[0].ok_or("missing configured identifier")?);
            MAX_CSR_IDENTIFIERS];
    let mut bound_resources =
        [resources[0].ok_or("missing ACME authorization resource")?; MAX_AUTHORIZATIONS];
    for index in 0..count {
        identifiers[index] =
            AcmeIdentifier::Dns(config.identifiers[index].ok_or("missing configured identifier")?);
        bound_resources[index] = resources[index].ok_or("missing ACME authorization resource")?;
    }
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
    .map_err(|_| "cannot retrieve ACME directory for order poll")?;
    signer.operation = AcmeJwsOperation::Order;
    let mut response = [0u8; MAX_DIRECTORY_BYTES];
    let mut jws = [0u8; MAX_JWS_REQUEST_BYTES];
    let response_generation = order
        .generation
        .checked_add(1)
        .ok_or("ACME order generation exhausted")?;
    poll_order(
        response_generation,
        unix_time()?,
        &identifiers[..count],
        &bound_resources[..count],
        &directory,
        account,
        order,
        &mut exchange,
        &mut transport,
        signer,
        &mut response,
        &mut jws,
    )
    .map_err(|_| "ACME order poll failed")?;
    let (existing, persisted) = load_order_record(config, state, authenticator)?
        .ok_or("missing durable ACME order during poll")?;
    if persisted != durable_generation {
        return Err("ACME order durable generation changed during poll");
    }
    let updated = AcmedOrderRecord {
        state: Some(order.state),
        certificate_url: order.certificate_url,
        ..existing
    };
    persist_order_record(config, state, authenticator, durable_generation, &updated)
}

#[allow(clippy::too_many_arguments)]
fn finalize_ready_order(
    config: &AcmedConfig,
    account: &AccountLifecycle,
    order: &mut OrderLifecycle,
    csr: &[u8],
    signer: &mut CertdEnvelopeWriter<'_>,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
    order_durable_generation: u64,
) -> Result<u64, &'static str> {
    let expected = AcmedFinalizationRecord {
        phase: AcmedFinalizationPhase::RequestMayHaveBeenSent,
        directory_generation: config.directory_generation,
        account_generation: config.account_generation,
        policy_generation: config.policy_generation,
        identity: config.identity,
        order_url_digest: mrml_crypto::Sha256::digest(order.order_url.as_str().as_bytes()),
        csr_digest: mrml_crypto::Sha256::digest(csr),
        key_generation: config.key_generation,
    };
    let finalization_generation = match load_finalization_record(config, state, authenticator)? {
        Some((record, generation)) => {
            let binding_matches = record.order_url_digest == expected.order_url_digest
                && record.csr_digest == expected.csr_digest
                && record.key_generation == expected.key_generation;
            if !binding_matches && record.phase == AcmedFinalizationPhase::ResponseAuthenticated {
                persist_finalization_record(config, state, authenticator, generation, &expected)?
            } else if !binding_matches {
                return Err("ACME finalization durable binding mismatch");
            } else if record.phase == AcmedFinalizationPhase::ResponseAuthenticated {
                let receipt = order
                    .prepare_finalize(csr)
                    .map_err(|_| "cannot reconstruct authenticated ACME finalization")?;
                order
                    .commit_finalize(receipt)
                    .map_err(|_| "cannot commit reconstructed ACME finalization")?;
                let (existing, persisted) = load_order_record(config, state, authenticator)?
                    .ok_or("missing durable ACME order after finalization")?;
                if persisted != order_durable_generation {
                    return Err("ACME order durable generation changed during finalization");
                }
                return persist_order_record(
                    config,
                    state,
                    authenticator,
                    order_durable_generation,
                    &AcmedOrderRecord {
                        state: Some(order.state),
                        ..existing
                    },
                );
            } else {
                generation
            }
        }
        None => persist_finalization_record(config, state, authenticator, 0, &expected)?,
    };
    let receipt = order
        .prepare_finalize(csr)
        .map_err(|_| "cannot prepare ACME finalization")?;
    let count = usize::from(config.identifier_count);
    let first = config.identifiers[0].ok_or("missing configured identifier")?;
    let mut identifiers = [AcmeIdentifier::Dns(first); MAX_CSR_IDENTIFIERS];
    for (index, identifier) in identifiers.iter_mut().enumerate().take(count) {
        *identifier =
            AcmeIdentifier::Dns(config.identifiers[index].ok_or("missing configured identifier")?);
    }
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
    .map_err(|_| "cannot retrieve ACME directory for finalization")?;
    signer.operation = AcmeJwsOperation::Finalize;
    let mut payload = [0u8; MAX_ACME_PAYLOAD_BYTES];
    let mut response = [0u8; MAX_DIRECTORY_BYTES];
    let mut jws = [0u8; MAX_JWS_REQUEST_BYTES];
    execute_prepared_finalize(
        receipt,
        csr,
        &identifiers[..count],
        unix_time()?,
        &directory,
        account,
        order,
        &mut exchange,
        &mut transport,
        signer,
        AccountCreateBuffers {
            payload: &mut payload,
            response: &mut response,
            jws: &mut jws,
        },
    )
    .map_err(|_| "ACME finalization response uncertain")?;
    persist_finalization_record(
        config,
        state,
        authenticator,
        finalization_generation,
        &AcmedFinalizationRecord {
            phase: AcmedFinalizationPhase::ResponseAuthenticated,
            ..expected
        },
    )?;
    let (existing, persisted) = load_order_record(config, state, authenticator)?
        .ok_or("missing durable ACME order after finalization")?;
    if persisted != order_durable_generation {
        return Err("ACME order durable generation changed during finalization");
    }
    persist_order_record(
        config,
        state,
        authenticator,
        order_durable_generation,
        &AcmedOrderRecord {
            state: Some(order.state),
            ..existing
        },
    )
}

fn load_finalization_record(
    config: &AcmedConfig,
    state: &HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<Option<(AcmedFinalizationRecord, u64)>, &'static str> {
    let object = DurableObjectId(finalization_object_id(config.identity));
    let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
    let Some(length) = state
        .load_authoritative(DurableNamespace::PublicState, object, &mut encoded)
        .map_err(|_| "cannot load ACME finalization state")?
    else {
        return Ok(None);
    };
    let durable = DurableRecord::decode(&encoded[..length], authenticator)
        .map_err(|_| "cannot authenticate ACME finalization state")?;
    if durable.namespace != DurableNamespace::PublicState
        || durable.kind != DurableRecordKind::AcmeOperation
        || durable.object != object
    {
        return Err("wrong ACME finalization durable record type");
    }
    let record = AcmedFinalizationRecord::decode(durable.payload())
        .map_err(|_| "cannot decode ACME finalization state")?;
    record
        .require_policy(config)
        .map_err(|_| "stale ACME finalization policy")?;
    Ok(Some((record, durable.generation)))
}

fn persist_finalization_record(
    config: &AcmedConfig,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
    previous_generation: u64,
    record: &AcmedFinalizationRecord,
) -> Result<u64, &'static str> {
    record
        .require_policy(config)
        .map_err(|_| "stale ACME finalization policy")?;
    let mut payload = [0u8; MAX_DURABLE_PAYLOAD];
    let length = record
        .encode(&mut payload)
        .map_err(|_| "cannot encode ACME finalization state")?;
    let durable = DurableRecord::prepare(
        DurableNamespace::PublicState,
        DurableRecordKind::AcmeOperation,
        DurableObjectId(record.object_id()),
        previous_generation,
        &payload[..length],
        authenticator,
    )
    .map_err(|_| "cannot authenticate ACME finalization state")?;
    let prepared = state
        .prepare(&durable)
        .map_err(|_| "cannot prepare ACME finalization state")?;
    state
        .commit(prepared)
        .map_err(|_| "ACME finalization state commit uncertain")
        .map(|receipt| receipt.generation)
}

fn load_order_record(
    config: &AcmedConfig,
    state: &HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<Option<(AcmedOrderRecord, u64)>, &'static str> {
    let object = DurableObjectId(config.identity);
    let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
    let Some(length) = state
        .load_authoritative(DurableNamespace::PublicState, object, &mut encoded)
        .map_err(|_| "cannot read ACME order state")?
    else {
        return Ok(None);
    };
    let durable = DurableRecord::decode(&encoded[..length], authenticator)
        .map_err(|_| "ACME order state authentication failed")?;
    if durable.namespace != DurableNamespace::PublicState
        || durable.kind != DurableRecordKind::Order
        || durable.object != object
    {
        return Err("ACME order durable record type mismatch");
    }
    let order = AcmedOrderRecord::decode(
        durable.payload(),
        &config.directory_url,
        config.directory_class == AcmeDirectoryClass::LocalTest,
    )
    .map_err(|_| "invalid ACME order durable record")?;
    Ok(Some((order, durable.generation)))
}

fn persist_order_record(
    config: &AcmedConfig,
    state: &mut impl DurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
    previous_generation: u64,
    order: &AcmedOrderRecord,
) -> Result<u64, &'static str> {
    order
        .require_policy(config)
        .map_err(|_| "stale ACME order policy")?;
    let mut payload = [0u8; MAX_DURABLE_PAYLOAD];
    let length = order
        .encode(&mut payload)
        .map_err(|_| "cannot encode ACME order state")?;
    let durable = DurableRecord::prepare(
        DurableNamespace::PublicState,
        DurableRecordKind::Order,
        DurableObjectId(config.identity),
        previous_generation,
        &payload[..length],
        authenticator,
    )
    .map_err(|_| "cannot authenticate ACME order state")?;
    let prepared = state
        .prepare(&durable)
        .map_err(|_| "cannot prepare ACME order state")?;
    let committed = state
        .commit(prepared)
        .map_err(|_| "ACME order state commit uncertain")?;
    Ok(committed.generation)
}

#[allow(clippy::too_many_arguments)]
fn publish_dns_challenges(
    config: &AcmedConfig,
    account: &AccountLifecycle,
    order: &mut OrderLifecycle,
    resources: &[Option<AuthorizationResource>; MAX_AUTHORIZATIONS],
    signer: &mut CertdEnvelopeWriter<'_>,
    provider: &mut impl Dns01Provider,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<(), &'static str> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes Unix epoch")?
        .as_secs();
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
    .map_err(|_| "cannot retrieve ACME directory for authorizations")?;
    for index in 0..usize::from(config.identifier_count) {
        let identifier = config.identifiers[index].ok_or("missing configured identifier")?;
        let resource = resources[index].ok_or("missing ACME authorization resource")?;
        let mut response = [0u8; MAX_DIRECTORY_BYTES];
        let mut jws = [0u8; MAX_JWS_REQUEST_BYTES];
        signer.operation = AcmeJwsOperation::Authorization;
        let authorization = fetch_authorization(
            resource,
            AcmeIdentifier::Dns(identifier),
            Some(ChallengeKind::Dns01),
            1,
            now_unix,
            &directory,
            account,
            order,
            &mut exchange,
            &mut transport,
            signer,
            &mut response,
            &mut jws,
        )
        .map_err(|_| "cannot fetch bound ACME authorization")?;
        if !matches!(
            authorization.status,
            AuthorizationState::Pending
                | AuthorizationState::Processing
                | AuthorizationState::Valid
        ) {
            return Err("ACME authorization is not pending, processing, or valid");
        }
        let challenge = authorization
            .challenges()
            .find(|challenge| challenge.kind == ChallengeKind::Dns01)
            .ok_or("ACME DNS-01 challenge missing")?;
        let mut key_authorization = [0u8; MAX_KEY_AUTHORIZATION];
        let key_authorization_length =
            write_key_authorization(&challenge.token, account.key, &mut key_authorization)
                .map_err(|_| "cannot construct DNS-01 key authorization")?;
        let key_authorization_digest =
            dns01_txt_digest(&key_authorization[..key_authorization_length]);
        let object = challenge_object_id(config.identity, index as u8, identifier);
        let expected = AcmedChallengeRecord {
            phase: AcmedChallengePhase::Selected,
            authorization_index: index as u8,
            directory_generation: config.directory_generation,
            account_generation: config.account_generation,
            policy_generation: config.policy_generation,
            identity: config.identity,
            operation_id: object,
            challenge_generation: 1,
            identifier,
            authorization_url: resource.url,
            challenge_url: challenge.url,
            token: challenge.token,
            key_authorization_digest,
            provider_record_id: [0; mrml_certificate::MAX_DNS01_PROVIDER_RECORD_ID_BYTES],
            provider_record_id_length: 0,
            provider_binding_digest: [0; 32],
        };
        let loaded = load_challenge_record(config, index as u8, identifier, state, authenticator)?;
        let (record, durable_generation) = match loaded {
            Some((record, generation)) => {
                if !same_challenge_binding(&record, &expected) {
                    if record.phase != AcmedChallengePhase::Complete {
                        return Err("ACME challenge durable binding mismatch");
                    }
                    let next_generation = persist_challenge_record(
                        config,
                        state,
                        authenticator,
                        generation,
                        &expected,
                    )?;
                    (expected, next_generation)
                } else {
                    (record, generation)
                }
            }
            None => {
                let generation =
                    persist_challenge_record(config, state, authenticator, 0, &expected)?;
                (expected, generation)
            }
        };
        match record.phase {
            AcmedChallengePhase::Selected => {
                let receipt = provider
                    .publish(Dns01PublicationRequest {
                        operation_id: record.operation_id,
                        generation: record.challenge_generation,
                        identifier: record.identifier,
                        key_authorization_digest: record.key_authorization_digest,
                    })
                    .map_err(|_| "DNS-01 provider publication failed")?;
                let published = AcmedChallengeRecord {
                    phase: AcmedChallengePhase::Published,
                    provider_record_id: receipt.provider_record_id,
                    provider_record_id_length: receipt.provider_record_id_length,
                    provider_binding_digest: receipt.binding_digest,
                    ..record
                };
                if published.publication_receipt().ok().flatten() != Some(receipt) {
                    return Err("DNS-01 provider receipt binding mismatch");
                }
                let published_generation = persist_challenge_record(
                    config,
                    state,
                    authenticator,
                    durable_generation,
                    &published,
                )?;
                let propagated_generation = observe_dns_propagation(
                    config,
                    state,
                    authenticator,
                    published_generation,
                    published,
                )?;
                submit_dns_challenge(
                    config,
                    account,
                    order,
                    resource,
                    *challenge,
                    &directory,
                    &mut exchange,
                    &mut transport,
                    signer,
                    state,
                    authenticator,
                    propagated_generation,
                    AcmedChallengeRecord {
                        phase: AcmedChallengePhase::Propagated,
                        ..published
                    },
                )?;
            }
            AcmedChallengePhase::Published => {
                let expected_receipt = record
                    .publication_receipt()
                    .map_err(|_| "invalid persisted DNS-01 receipt")?
                    .ok_or("missing persisted DNS-01 receipt")?;
                let observed = provider
                    .publish(Dns01PublicationRequest {
                        operation_id: record.operation_id,
                        generation: record.challenge_generation,
                        identifier: record.identifier,
                        key_authorization_digest: record.key_authorization_digest,
                    })
                    .map_err(|_| "DNS-01 provider reconciliation failed")?;
                if observed != expected_receipt {
                    return Err("DNS-01 provider record substitution detected");
                }
                let propagated_generation = observe_dns_propagation(
                    config,
                    state,
                    authenticator,
                    durable_generation,
                    record,
                )?;
                submit_dns_challenge(
                    config,
                    account,
                    order,
                    resource,
                    *challenge,
                    &directory,
                    &mut exchange,
                    &mut transport,
                    signer,
                    state,
                    authenticator,
                    propagated_generation,
                    AcmedChallengeRecord {
                        phase: AcmedChallengePhase::Propagated,
                        ..record
                    },
                )?;
            }
            AcmedChallengePhase::Propagated => {
                if matches!(
                    authorization.status,
                    AuthorizationState::Processing | AuthorizationState::Valid
                ) {
                    persist_challenge_record(
                        config,
                        state,
                        authenticator,
                        durable_generation,
                        &AcmedChallengeRecord {
                            phase: AcmedChallengePhase::Accepted,
                            ..record
                        },
                    )?;
                } else {
                    submit_dns_challenge(
                        config,
                        account,
                        order,
                        resource,
                        *challenge,
                        &directory,
                        &mut exchange,
                        &mut transport,
                        signer,
                        state,
                        authenticator,
                        durable_generation,
                        record,
                    )?;
                }
            }
            AcmedChallengePhase::SubmissionMayHaveBeenSent => {
                if matches!(
                    authorization.status,
                    AuthorizationState::Processing | AuthorizationState::Valid
                ) {
                    persist_challenge_record(
                        config,
                        state,
                        authenticator,
                        durable_generation,
                        &AcmedChallengeRecord {
                            phase: AcmedChallengePhase::Accepted,
                            ..record
                        },
                    )?;
                } else {
                    submit_dns_challenge(
                        config,
                        account,
                        order,
                        resource,
                        *challenge,
                        &directory,
                        &mut exchange,
                        &mut transport,
                        signer,
                        state,
                        authenticator,
                        durable_generation,
                        record,
                    )?;
                }
            }
            AcmedChallengePhase::Accepted => {}
            AcmedChallengePhase::CleanupPending | AcmedChallengePhase::Complete => {}
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn submit_dns_challenge(
    config: &AcmedConfig,
    account: &AccountLifecycle,
    order: &OrderLifecycle,
    resource: AuthorizationResource,
    challenge: mrml_acme::ParsedChallenge,
    directory: &mrml_acme::AcmeDirectory,
    exchange: &mut AcmeExchange,
    transport: &mut HostedAcmeTransport,
    signer: &mut CertdEnvelopeWriter<'_>,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
    durable_generation: u64,
    record: AcmedChallengeRecord,
) -> Result<u64, &'static str> {
    if !matches!(
        record.phase,
        AcmedChallengePhase::Propagated | AcmedChallengePhase::SubmissionMayHaveBeenSent
    ) {
        return Err("DNS challenge submission requires propagated evidence");
    }
    let uncertain = AcmedChallengeRecord {
        phase: AcmedChallengePhase::SubmissionMayHaveBeenSent,
        ..record
    };
    let pending_generation = if record.phase == AcmedChallengePhase::Propagated {
        persist_challenge_record(config, state, authenticator, durable_generation, &uncertain)?
    } else {
        durable_generation
    };
    signer.operation = AcmeJwsOperation::Challenge;
    let mut response = [0u8; MAX_DIRECTORY_BYTES];
    let mut jws = [0u8; MAX_JWS_REQUEST_BYTES];
    let submission = trigger_propagated_dns01_challenge(
        resource,
        challenge,
        Dns01ActivationEvidence {
            challenge_generation: record.challenge_generation,
            identifier: record.identifier,
            key_authorization_digest: record.key_authorization_digest,
            observed_unix: unix_time()?,
        },
        directory,
        account,
        order,
        exchange,
        transport,
        signer,
        &mut response,
        &mut jws,
    )
    .map_err(|_| "ACME DNS challenge submission uncertain")?;
    if submission.challenge_generation != record.challenge_generation
        || submission.challenge_url_digest
            != mrml_crypto::Sha256::digest(record.challenge_url.as_str().as_bytes())
    {
        return Err("ACME DNS challenge submission binding mismatch");
    }
    persist_challenge_record(
        config,
        state,
        authenticator,
        pending_generation,
        &AcmedChallengeRecord {
            phase: AcmedChallengePhase::Accepted,
            ..record
        },
    )
}

fn observe_dns_propagation(
    config: &AcmedConfig,
    state: &mut HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
    durable_generation: u64,
    record: AcmedChallengeRecord,
) -> Result<u64, &'static str> {
    if record.phase != AcmedChallengePhase::Published {
        return Err("DNS propagation requires a published challenge");
    }
    let authoritative_route = DnsObservationRoute {
        class: DnsObservationClass::Authoritative,
        capability_id: AUTHORITATIVE_DNS_ROUTE_CAPABILITY,
        route_generation: config.policy_generation,
    };
    let recursive_route = DnsObservationRoute {
        class: DnsObservationClass::RecursiveResolver,
        capability_id: RECURSIVE_DNS_ROUTE_CAPABILITY,
        route_generation: config.policy_generation,
    };
    let started_unix = unix_time()?;
    let deadline_unix = started_unix
        .checked_add(config.propagation_timeout_seconds)
        .ok_or("DNS propagation deadline overflow")?;
    let mut observer = DnsPropagationObserver::new(
        record.identifier,
        record.key_authorization_digest,
        record.challenge_generation,
        record.challenge_generation,
        DnsPropagationPolicy {
            authoritative: authoritative_route,
            resolver: recursive_route,
            maximum_attempts: config.propagation_attempts,
            deadline_unix,
        },
    )
    .map_err(|_| "invalid DNS propagation policy")?;
    let mut query = HostedDnsPropagationQuery::new(
        HostedDnsObservationEndpoint {
            route: authoritative_route,
            ipv4: config.authoritative_dns_ipv4,
            port: config.authoritative_dns_port,
        },
        HostedDnsObservationEndpoint {
            route: recursive_route,
            ipv4: config.recursive_dns_ipv4,
            port: config.recursive_dns_port,
        },
        started_unix,
    )
    .map_err(|_| "invalid DNS observation endpoints")?;
    for attempt in 0..config.propagation_attempts {
        let now_unix = unix_time()?;
        query
            .set_observed_time(now_unix)
            .map_err(|_| "invalid DNS observation time")?;
        if observer
            .poll(now_unix, &mut query)
            .map_err(|_| "DNS propagation observation failed")?
            .is_some()
        {
            let propagated = AcmedChallengeRecord {
                phase: AcmedChallengePhase::Propagated,
                ..record
            };
            return persist_challenge_record(
                config,
                state,
                authenticator,
                durable_generation,
                &propagated,
            );
        }
        if attempt + 1 < config.propagation_attempts {
            std::thread::sleep(Duration::from_secs(config.propagation_interval_seconds));
        }
    }
    Err("DNS propagation attempt limit reached")
}

fn unix_time() -> Result<u64, &'static str> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes Unix epoch")
        .map(|duration| duration.as_secs())
}

fn same_challenge_binding(left: &AcmedChallengeRecord, right: &AcmedChallengeRecord) -> bool {
    left.authorization_index == right.authorization_index
        && left.directory_generation == right.directory_generation
        && left.account_generation == right.account_generation
        && left.policy_generation == right.policy_generation
        && left.identity == right.identity
        && left.operation_id == right.operation_id
        && left.challenge_generation == right.challenge_generation
        && left.identifier == right.identifier
        && left.authorization_url == right.authorization_url
        && left.challenge_url == right.challenge_url
        && left.token == right.token
        && left.key_authorization_digest == right.key_authorization_digest
}

fn load_challenge_record(
    config: &AcmedConfig,
    authorization_index: u8,
    identifier: mrml_acme::DnsIdentifier,
    state: &HostedDurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
) -> Result<Option<(AcmedChallengeRecord, u64)>, &'static str> {
    let object = DurableObjectId(challenge_object_id(
        config.identity,
        authorization_index,
        identifier,
    ));
    let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
    let Some(length) = state
        .load_authoritative(DurableNamespace::PublicState, object, &mut encoded)
        .map_err(|_| "cannot read ACME challenge state")?
    else {
        return Ok(None);
    };
    let durable = DurableRecord::decode(&encoded[..length], authenticator)
        .map_err(|_| "ACME challenge state authentication failed")?;
    if durable.namespace != DurableNamespace::PublicState
        || durable.kind != DurableRecordKind::DnsPublication
        || durable.object != object
    {
        return Err("ACME challenge durable record type mismatch");
    }
    let record = AcmedChallengeRecord::decode(
        durable.payload(),
        &config.directory_url,
        config.directory_class == AcmeDirectoryClass::LocalTest,
        config.wildcard_enabled,
    )
    .map_err(|_| "invalid ACME challenge durable record")?;
    record
        .require_policy(config)
        .map_err(|_| "stale ACME challenge policy")?;
    Ok(Some((record, durable.generation)))
}

fn persist_challenge_record(
    config: &AcmedConfig,
    state: &mut impl DurableStateStore,
    authenticator: &mut impl DurableAuthenticator,
    previous_generation: u64,
    challenge: &AcmedChallengeRecord,
) -> Result<u64, &'static str> {
    challenge
        .require_policy(config)
        .map_err(|_| "stale ACME challenge policy")?;
    let object = DurableObjectId(challenge.durable_object_id());
    let mut payload = [0u8; MAX_DURABLE_PAYLOAD];
    let length = challenge
        .encode(&mut payload)
        .map_err(|_| "cannot encode ACME challenge state")?;
    let durable = DurableRecord::prepare(
        DurableNamespace::PublicState,
        DurableRecordKind::DnsPublication,
        object,
        previous_generation,
        &payload[..length],
        authenticator,
    )
    .map_err(|_| "cannot authenticate ACME challenge state")?;
    let prepared = state
        .prepare(&durable)
        .map_err(|_| "cannot prepare ACME challenge state")?;
    let committed = state
        .commit(prepared)
        .map_err(|_| "ACME challenge state commit uncertain")?;
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
