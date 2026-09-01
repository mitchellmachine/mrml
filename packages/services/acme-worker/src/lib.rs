#![no_std]

use mrml_acme::{
    AcmeDirectory, AcmeUrl, DnsIdentifier, JwkThumbprint, MAX_CSR_IDENTIFIERS, MAX_URL_BYTES,
    OwnerTermsApproval,
};
use mrml_certificate::certd_identifier_set_digest;
use mrml_json::Value;

pub const MAX_ACMED_CONFIG_BYTES: usize = 16 * 1024;
const ACCOUNT_RECORD_MAGIC: &[u8; 8] = b"MRMLACA1";
const ACCOUNT_RECORD_HEADER_BYTES: usize = 116;
const CHANNEL_REQUEST_MAGIC: &[u8; 8] = b"MRMLRID1";
pub const CHANNEL_REQUEST_RESERVATION: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcmedRequestIdReservation {
    pub next: u64,
    pub last: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AcmedChannelRequestCounter {
    pub account_identity: [u8; 16],
    pub last_reserved: u64,
}

impl AcmedChannelRequestCounter {
    pub fn new(account_identity: [u8; 16]) -> Result<Self, AcmedAccountRecordError> {
        if account_identity == [0; 16] {
            return Err(AcmedAccountRecordError::InvalidState);
        }
        Ok(Self {
            account_identity,
            last_reserved: 0,
        })
    }

    pub fn reserve(&mut self) -> Result<AcmedRequestIdReservation, AcmedAccountRecordError> {
        let next = self
            .last_reserved
            .checked_add(1)
            .ok_or(AcmedAccountRecordError::InvalidState)?;
        let last = self
            .last_reserved
            .checked_add(CHANNEL_REQUEST_RESERVATION)
            .ok_or(AcmedAccountRecordError::InvalidState)?;
        self.last_reserved = last;
        Ok(AcmedRequestIdReservation { next, last })
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, AcmedAccountRecordError> {
        if output.len() < 32
            || self.account_identity == [0; 16]
            || self.last_reserved == 0
            || self.last_reserved % CHANNEL_REQUEST_RESERVATION != 0
        {
            return Err(if output.len() < 32 {
                AcmedAccountRecordError::OutputTooSmall
            } else {
                AcmedAccountRecordError::InvalidState
            });
        }
        output[..32].fill(0);
        output[..8].copy_from_slice(CHANNEL_REQUEST_MAGIC);
        output[8..24].copy_from_slice(&self.account_identity);
        output[24..32].copy_from_slice(&self.last_reserved.to_be_bytes());
        Ok(32)
    }

    pub fn decode(input: &[u8]) -> Result<Self, AcmedAccountRecordError> {
        if input.len() != 32 || input.get(..8) != Some(CHANNEL_REQUEST_MAGIC) {
            return Err(AcmedAccountRecordError::Malformed);
        }
        let counter = Self {
            account_identity: input[8..24]
                .try_into()
                .map_err(|_| AcmedAccountRecordError::Malformed)?,
            last_reserved: read_u64(&input[24..32])?,
        };
        let mut canonical = [0u8; 32];
        counter.encode(&mut canonical)?;
        if canonical != input {
            return Err(AcmedAccountRecordError::Malformed);
        }
        Ok(counter)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AcmedAccountPhase {
    RequestMayHaveBeenSent = 1,
    Active = 2,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AcmedAccountRecord {
    pub phase: AcmedAccountPhase,
    pub directory_generation: u64,
    pub account_generation: u64,
    pub policy_generation: u64,
    pub account_identity: [u8; 16],
    pub key_thumbprint: JwkThumbprint,
    pub contact_digest: [u8; 32],
    pub account_url: Option<AcmeUrl>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmedAccountRecordError {
    InvalidState,
    OutputTooSmall,
    Malformed,
    PolicyMismatch,
}

impl AcmedAccountRecord {
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, AcmedAccountRecordError> {
        let url = self.account_url.as_ref().map(AcmeUrl::as_str).unwrap_or("");
        if self.directory_generation == 0
            || self.account_generation == 0
            || self.policy_generation == 0
            || self.account_identity == [0; 16]
            || self.key_thumbprint.0 == [0; 32]
            || (self.phase == AcmedAccountPhase::Active) != self.account_url.is_some()
            || url.len() > MAX_URL_BYTES
        {
            return Err(AcmedAccountRecordError::InvalidState);
        }
        let length = ACCOUNT_RECORD_HEADER_BYTES
            .checked_add(url.len())
            .ok_or(AcmedAccountRecordError::OutputTooSmall)?;
        if output.len() < length {
            return Err(AcmedAccountRecordError::OutputTooSmall);
        }
        output[..length].fill(0);
        output[..8].copy_from_slice(ACCOUNT_RECORD_MAGIC);
        output[8] = self.phase as u8;
        output[12..20].copy_from_slice(&self.directory_generation.to_be_bytes());
        output[20..28].copy_from_slice(&self.account_generation.to_be_bytes());
        output[28..36].copy_from_slice(&self.policy_generation.to_be_bytes());
        output[36..52].copy_from_slice(&self.account_identity);
        output[52..84].copy_from_slice(&self.key_thumbprint.0);
        output[84..116].copy_from_slice(&self.contact_digest);
        output[10..12].copy_from_slice(&(url.len() as u16).to_be_bytes());
        output[ACCOUNT_RECORD_HEADER_BYTES..length].copy_from_slice(url.as_bytes());
        Ok(length)
    }

    pub fn decode(
        input: &[u8],
        configured_directory: &AcmeUrl,
        allow_test_http: bool,
    ) -> Result<Self, AcmedAccountRecordError> {
        if input.len() < ACCOUNT_RECORD_HEADER_BYTES
            || input.get(..8) != Some(ACCOUNT_RECORD_MAGIC)
            || input[9] != 0
        {
            return Err(AcmedAccountRecordError::Malformed);
        }
        let phase = match input[8] {
            1 => AcmedAccountPhase::RequestMayHaveBeenSent,
            2 => AcmedAccountPhase::Active,
            _ => return Err(AcmedAccountRecordError::Malformed),
        };
        let url_length = usize::from(u16::from_be_bytes([input[10], input[11]]));
        if url_length > MAX_URL_BYTES
            || input.len() != ACCOUNT_RECORD_HEADER_BYTES + url_length
        {
            return Err(AcmedAccountRecordError::Malformed);
        }
        let directory_generation = read_u64(&input[12..20])?;
        let account_generation = read_u64(&input[20..28])?;
        let policy_generation = read_u64(&input[28..36])?;
        let account_identity = input[36..52]
            .try_into()
            .map_err(|_| AcmedAccountRecordError::Malformed)?;
        let key_thumbprint = JwkThumbprint(
            input[52..84]
                .try_into()
                .map_err(|_| AcmedAccountRecordError::Malformed)?,
        );
        let contact_digest = input[84..116]
            .try_into()
            .map_err(|_| AcmedAccountRecordError::Malformed)?;
        let account_url = if url_length == 0 {
            None
        } else {
            let text = core::str::from_utf8(&input[116..])
                .map_err(|_| AcmedAccountRecordError::Malformed)?;
            let url = AcmeUrl::parse(text, allow_test_http)
                .map_err(|_| AcmedAccountRecordError::Malformed)?;
            url.require_origin(configured_directory.origin())
                .map_err(|_| AcmedAccountRecordError::PolicyMismatch)?;
            Some(url)
        };
        let record = Self {
            phase,
            directory_generation,
            account_generation,
            policy_generation,
            account_identity,
            key_thumbprint,
            contact_digest,
            account_url,
        };
        let mut canonical = [0u8; ACCOUNT_RECORD_HEADER_BYTES + MAX_URL_BYTES];
        let length = record.encode(&mut canonical)?;
        if canonical[..length] != *input {
            return Err(AcmedAccountRecordError::Malformed);
        }
        Ok(record)
    }

    pub fn require_policy(&self, config: &AcmedConfig) -> Result<(), AcmedAccountRecordError> {
        if self.directory_generation != config.directory_generation
            || self.account_generation != config.account_generation
            || self.policy_generation != config.policy_generation
            || self.account_identity != config.account_identity
        {
            Err(AcmedAccountRecordError::PolicyMismatch)
        } else {
            Ok(())
        }
    }
}

fn read_u64(input: &[u8]) -> Result<u64, AcmedAccountRecordError> {
    Ok(u64::from_be_bytes(
        input
            .try_into()
            .map_err(|_| AcmedAccountRecordError::Malformed)?,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmeDirectoryClass {
    LocalTest,
    PublicStaging,
    PublicProduction,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AcmedConfig {
    pub directory_url: AcmeUrl,
    pub directory_generation: u64,
    pub directory_class: AcmeDirectoryClass,
    pub approved_terms_url: Option<AcmeUrl>,
    pub approved_terms_content_digest: Option<[u8; 32]>,
    pub zone_id: [u8; 32],
    pub zone: DnsIdentifier,
    pub identity: [u8; 16],
    pub account_identity: [u8; 16],
    pub account_generation: u64,
    pub key_generation: u64,
    pub policy_generation: u64,
    pub identifiers: [Option<DnsIdentifier>; MAX_CSR_IDENTIFIERS],
    pub identifier_count: u8,
    pub identifier_set_digest: [u8; 32],
    pub wildcard_enabled: bool,
    pub poll_interval_seconds: u64,
    pub global_concurrency: u8,
    pub per_identity_concurrency: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmedConfigError {
    Oversized,
    Malformed,
    UnknownField,
    MissingField,
    InvalidDirectory,
    InvalidTermsApproval,
    ProductionNotEnabled,
    InvalidZone,
    InvalidIdentity,
    InvalidBounds,
}

impl AcmedConfig {
    pub fn terms_approval(
        &self,
        directory: &AcmeDirectory,
    ) -> Result<Option<OwnerTermsApproval>, AcmedConfigError> {
        match (
            directory.terms_of_service.as_ref(),
            self.approved_terms_url.as_ref(),
            self.approved_terms_content_digest,
        ) {
            (None, None, None) => Ok(None),
            (Some(advertised), Some(approved), Some(digest)) if advertised == approved => {
                OwnerTermsApproval::from_content_digest(
                    directory.generation,
                    approved,
                    digest,
                )
                .map(Some)
                .map_err(|_| AcmedConfigError::InvalidTermsApproval)
            }
            _ => Err(AcmedConfigError::InvalidTermsApproval),
        }
    }
}

pub fn parse_acmed_config(source: &str) -> Result<AcmedConfig, AcmedConfigError> {
    if source.is_empty() || source.len() > MAX_ACMED_CONFIG_BYTES {
        return Err(AcmedConfigError::Oversized);
    }
    let value = mrml_json::parse(source).map_err(|_| AcmedConfigError::Malformed)?;
    let object = value.as_object().ok_or(AcmedConfigError::Malformed)?;
    const FIELDS: [&str; 18] = [
        "directory_url",
        "directory_generation",
        "directory_class",
        "production_enabled",
        "terms_of_service_url",
        "terms_content_sha256",
        "dns_provider",
        "zone_id",
        "zone",
        "identity",
        "account_identity",
        "account_generation",
        "key_generation",
        "policy_generation",
        "identifiers",
        "wildcard_enabled",
        "poll_interval_seconds",
        "global_concurrency",
    ];
    if object
        .iter()
        .any(|(key, _)| !FIELDS.contains(&key.as_str()))
    {
        return Err(AcmedConfigError::UnknownField);
    }
    if object.len() != FIELDS.len() {
        return Err(AcmedConfigError::MissingField);
    }
    let directory_class = match text(&value, "directory_class")? {
        "local-test" => AcmeDirectoryClass::LocalTest,
        "public-staging" => AcmeDirectoryClass::PublicStaging,
        "public-production" => AcmeDirectoryClass::PublicProduction,
        _ => return Err(AcmedConfigError::InvalidDirectory),
    };
    let production_enabled = value
        .get("production_enabled")
        .and_then(Value::as_bool)
        .ok_or(AcmedConfigError::MissingField)?;
    if (directory_class == AcmeDirectoryClass::PublicProduction) != production_enabled {
        return Err(AcmedConfigError::ProductionNotEnabled);
    }
    if text(&value, "dns_provider")? != "cloudflare" {
        return Err(AcmedConfigError::InvalidZone);
    }
    let directory_url = AcmeUrl::parse(
        text(&value, "directory_url")?,
        directory_class == AcmeDirectoryClass::LocalTest,
    )
    .map_err(|_| AcmedConfigError::InvalidDirectory)?;
    let directory_generation = number(&value, "directory_generation")?;
    if directory_generation == 0 {
        return Err(AcmedConfigError::InvalidBounds);
    }
    let approved_terms_url = optional_text(&value, "terms_of_service_url")?
        .map(|url| AcmeUrl::parse(url, directory_class == AcmeDirectoryClass::LocalTest))
        .transpose()
        .map_err(|_| AcmedConfigError::InvalidTermsApproval)?;
    let approved_terms_content_digest = optional_text(&value, "terms_content_sha256")?
        .map(parse_digest)
        .transpose()?;
    if approved_terms_url.is_some() != approved_terms_content_digest.is_some() {
        return Err(AcmedConfigError::InvalidTermsApproval);
    }
    let zone_id_text = text(&value, "zone_id")?;
    if !valid_hex(zone_id_text, 32) {
        return Err(AcmedConfigError::InvalidZone);
    }
    let mut zone_id = [0u8; 32];
    zone_id.copy_from_slice(zone_id_text.as_bytes());
    let zone = DnsIdentifier::parse(text(&value, "zone")?, false)
        .map_err(|_| AcmedConfigError::InvalidZone)?;
    if zone.is_wildcard() {
        return Err(AcmedConfigError::InvalidZone);
    }
    let identity = parse_identity(text(&value, "identity")?)?;
    let account_identity = parse_identity(text(&value, "account_identity")?)?;
    if identity == account_identity {
        return Err(AcmedConfigError::InvalidIdentity);
    }
    let account_generation = number(&value, "account_generation")?;
    let key_generation = number(&value, "key_generation")?;
    let policy_generation = number(&value, "policy_generation")?;
    if account_generation == 0 || key_generation == 0 || policy_generation == 0 {
        return Err(AcmedConfigError::InvalidBounds);
    }
    let wildcard_enabled = value
        .get("wildcard_enabled")
        .and_then(Value::as_bool)
        .ok_or(AcmedConfigError::MissingField)?;
    let list = value
        .get("identifiers")
        .and_then(Value::as_array)
        .ok_or(AcmedConfigError::MissingField)?;
    if list.is_empty() || list.len() > MAX_CSR_IDENTIFIERS {
        return Err(AcmedConfigError::InvalidIdentity);
    }
    let mut identifiers = [None; MAX_CSR_IDENTIFIERS];
    let mut previous: Option<DnsIdentifier> = None;
    for (index, item) in list.iter().enumerate() {
        let identifier = DnsIdentifier::parse(
            item.as_str().ok_or(AcmedConfigError::InvalidIdentity)?,
            wildcard_enabled,
        )
        .map_err(|_| AcmedConfigError::InvalidIdentity)?;
        if previous.is_some_and(|prior| prior.as_str() >= identifier.as_str()) {
            return Err(AcmedConfigError::InvalidIdentity);
        }
        identifiers[index] = Some(identifier);
        previous = Some(identifier);
    }
    let identifier_set_digest = certd_identifier_set_digest(&identifiers[..list.len()]);
    let poll_interval_seconds = number(&value, "poll_interval_seconds")?;
    let global_concurrency = u8::try_from(number(&value, "global_concurrency")?)
        .map_err(|_| AcmedConfigError::InvalidBounds)?;
    if !(5..=3_600).contains(&poll_interval_seconds) || !(1..=8).contains(&global_concurrency) {
        return Err(AcmedConfigError::InvalidBounds);
    }
    Ok(AcmedConfig {
        directory_url,
        directory_generation,
        directory_class,
        approved_terms_url,
        approved_terms_content_digest,
        zone_id,
        zone,
        identity,
        account_identity,
        account_generation,
        key_generation,
        policy_generation,
        identifiers,
        identifier_count: list.len() as u8,
        identifier_set_digest,
        wildcard_enabled,
        poll_interval_seconds,
        global_concurrency,
        per_identity_concurrency: 1,
    })
}

fn parse_identity(value: &str) -> Result<[u8; 16], AcmedConfigError> {
    if !valid_hex(value, 32) {
        return Err(AcmedConfigError::InvalidIdentity);
    }
    let mut identity = [0u8; 16];
    for (index, output) in identity.iter_mut().enumerate() {
        *output = decode_hex(&value.as_bytes()[index * 2..index * 2 + 2])?;
    }
    if identity == [0; 16] {
        Err(AcmedConfigError::InvalidIdentity)
    } else {
        Ok(identity)
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, AcmedConfigError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or(AcmedConfigError::MissingField)
}

fn number(value: &Value, key: &str) -> Result<u64, AcmedConfigError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(AcmedConfigError::MissingField)
}

fn optional_text<'a>(value: &'a Value, key: &str) -> Result<Option<&'a str>, AcmedConfigError> {
    let value = value.get(key).ok_or(AcmedConfigError::MissingField)?;
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_str()
        .filter(|text| !text.is_empty())
        .map(Some)
        .ok_or(AcmedConfigError::InvalidTermsApproval)
}

fn parse_digest(value: &str) -> Result<[u8; 32], AcmedConfigError> {
    if !valid_hex(value, 64) {
        return Err(AcmedConfigError::InvalidTermsApproval);
    }
    let mut digest = [0u8; 32];
    for (index, output) in digest.iter_mut().enumerate() {
        *output = decode_hex(&value.as_bytes()[index * 2..index * 2 + 2])?;
    }
    if digest == [0; 32] {
        Err(AcmedConfigError::InvalidTermsApproval)
    } else {
        Ok(digest)
    }
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn decode_hex(value: &[u8]) -> Result<u8, AcmedConfigError> {
    fn nibble(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            _ => None,
        }
    }
    Ok(
        nibble(value[0]).ok_or(AcmedConfigError::InvalidIdentity)? << 4
            | nibble(value[1]).ok_or(AcmedConfigError::InvalidIdentity)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_certificate::{
        DurableNamespace, DurableObjectId, DurableRecord, DurableRecordKind,
        HmacSha256DurableAuthenticator, MAX_DURABLE_RECORD_BYTES,
    };

    const STAGING: &str = r#"{"directory_url":"https://acme-staging-v02.api.letsencrypt.org/directory","directory_generation":1,"directory_class":"public-staging","production_enabled":false,"terms_of_service_url":"https://letsencrypt.org/documents/approved.pdf","terms_content_sha256":"1111111111111111111111111111111111111111111111111111111111111111","dns_provider":"cloudflare","zone_id":"0123456789abcdef0123456789abcdef","zone":"example.com","identity":"11111111111111111111111111111111","account_identity":"22222222222222222222222222222222","account_generation":1,"key_generation":1,"policy_generation":1,"identifiers":["example.com","www.example.com"],"wildcard_enabled":false,"poll_interval_seconds":30,"global_concurrency":2}"#;

    #[test]
    fn account_record_round_trips_only_exact_policy_bound_states() {
        let config = parse_acmed_config(STAGING).unwrap();
        let pending = AcmedAccountRecord {
            phase: AcmedAccountPhase::RequestMayHaveBeenSent,
            directory_generation: config.directory_generation,
            account_generation: config.account_generation,
            policy_generation: config.policy_generation,
            account_identity: config.account_identity,
            key_thumbprint: JwkThumbprint([3; 32]),
            contact_digest: [4; 32],
            account_url: None,
        };
        let mut encoded = [0u8; ACCOUNT_RECORD_HEADER_BYTES + MAX_URL_BYTES];
        let length = pending.encode(&mut encoded).unwrap();
        let decoded = AcmedAccountRecord::decode(
            &encoded[..length],
            &config.directory_url,
            false,
        )
        .unwrap();
        assert!(decoded == pending);
        decoded.require_policy(&config).unwrap();

        let active = AcmedAccountRecord {
            phase: AcmedAccountPhase::Active,
            account_url: Some(
                AcmeUrl::parse(
                    "https://acme-staging-v02.api.letsencrypt.org/acct/1",
                    false,
                )
                .unwrap(),
            ),
            ..pending
        };
        let length = active.encode(&mut encoded).unwrap();
        assert!(
            AcmedAccountRecord::decode(&encoded[..length], &config.directory_url, false).unwrap()
                == active
        );
        encoded[9] = 1;
        assert!(AcmedAccountRecord::decode(
            &encoded[..length],
            &config.directory_url,
            false,
        )
        .is_err());
    }

    #[test]
    fn account_record_rejects_cross_origin_and_phase_url_confusion() {
        let config = parse_acmed_config(STAGING).unwrap();
        let record = AcmedAccountRecord {
            phase: AcmedAccountPhase::Active,
            directory_generation: 1,
            account_generation: 1,
            policy_generation: 1,
            account_identity: config.account_identity,
            key_thumbprint: JwkThumbprint([3; 32]),
            contact_digest: [4; 32],
            account_url: Some(AcmeUrl::parse("https://other.example/acct/1", false).unwrap()),
        };
        let mut encoded = [0u8; ACCOUNT_RECORD_HEADER_BYTES + MAX_URL_BYTES];
        let length = record.encode(&mut encoded).unwrap();
        assert!(matches!(
            AcmedAccountRecord::decode(&encoded[..length], &config.directory_url, false),
            Err(AcmedAccountRecordError::PolicyMismatch)
        ));
        let confused = AcmedAccountRecord {
            phase: AcmedAccountPhase::RequestMayHaveBeenSent,
            ..record
        };
        assert!(matches!(
            confused.encode(&mut encoded),
            Err(AcmedAccountRecordError::InvalidState)
        ));
    }

    #[test]
    fn account_record_requires_keyed_durable_authentication() {
        let config = parse_acmed_config(STAGING).unwrap();
        let account = AcmedAccountRecord {
            phase: AcmedAccountPhase::RequestMayHaveBeenSent,
            directory_generation: 1,
            account_generation: 1,
            policy_generation: 1,
            account_identity: config.account_identity,
            key_thumbprint: JwkThumbprint([3; 32]),
            contact_digest: [4; 32],
            account_url: None,
        };
        let mut payload = [0u8; ACCOUNT_RECORD_HEADER_BYTES + MAX_URL_BYTES];
        let payload_length = account.encode(&mut payload).unwrap();
        let mut writer = HmacSha256DurableAuthenticator::new([0x51; 32]);
        let durable = DurableRecord::prepare(
            DurableNamespace::PublicState,
            DurableRecordKind::Account,
            DurableObjectId(config.account_identity),
            0,
            &payload[..payload_length],
            &mut writer,
        )
        .unwrap();
        let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
        let length = durable.encode(&mut encoded).unwrap();
        let mut correct = HmacSha256DurableAuthenticator::new([0x51; 32]);
        assert!(DurableRecord::decode(&encoded[..length], &mut correct).is_ok());
        let mut wrong = HmacSha256DurableAuthenticator::new([0x52; 32]);
        assert!(DurableRecord::decode(&encoded[..length], &mut wrong).is_err());
        encoded[length - 1] ^= 1;
        let mut correct = HmacSha256DurableAuthenticator::new([0x51; 32]);
        assert!(DurableRecord::decode(&encoded[..length], &mut correct).is_err());
    }

    #[test]
    fn channel_request_reservations_advance_across_restart_without_overlap() {
        let identity = [7; 16];
        let mut first = AcmedChannelRequestCounter::new(identity).unwrap();
        let reserved = first.reserve().unwrap();
        assert_eq!(reserved.next, 1);
        assert_eq!(reserved.last, CHANNEL_REQUEST_RESERVATION);
        let mut encoded = [0u8; 32];
        first.encode(&mut encoded).unwrap();
        let mut restarted = AcmedChannelRequestCounter::decode(&encoded).unwrap();
        let after_restart = restarted.reserve().unwrap();
        assert_eq!(after_restart.next, reserved.last + 1);
        assert!(after_restart.next > reserved.last);
        encoded[0] ^= 1;
        assert!(AcmedChannelRequestCounter::decode(&encoded).is_err());
    }

    #[test]
    fn staging_configuration_is_exact_and_bounded() {
        let config = parse_acmed_config(STAGING).unwrap();
        assert_eq!(config.directory_class, AcmeDirectoryClass::PublicStaging);
        assert_eq!(
            config.directory_url.origin().host,
            "acme-staging-v02.api.letsencrypt.org"
        );
        assert_eq!(config.per_identity_concurrency, 1);
        assert_eq!(config.identifier_count, 2);
        assert_ne!(config.identifier_set_digest, [0; 32]);
        assert!(config.approved_terms_url.is_some());
        assert_eq!(config.approved_terms_content_digest, Some([0x11; 32]));
        let directory = AcmeDirectory::parse(
            r#"{"newNonce":"https://acme-staging-v02.api.letsencrypt.org/nonce","newAccount":"https://acme-staging-v02.api.letsencrypt.org/account","newOrder":"https://acme-staging-v02.api.letsencrypt.org/order","revokeCert":"https://acme-staging-v02.api.letsencrypt.org/revoke","keyChange":"https://acme-staging-v02.api.letsencrypt.org/key-change","meta":{"termsOfService":"https://letsencrypt.org/documents/approved.pdf"}}"#,
            &config.directory_url,
            config.directory_generation,
        )
        .unwrap();
        assert!(config.terms_approval(&directory).unwrap().is_some());
        let changed = AcmeDirectory::parse(
            r#"{"newNonce":"https://acme-staging-v02.api.letsencrypt.org/nonce","newAccount":"https://acme-staging-v02.api.letsencrypt.org/account","newOrder":"https://acme-staging-v02.api.letsencrypt.org/order","revokeCert":"https://acme-staging-v02.api.letsencrypt.org/revoke","keyChange":"https://acme-staging-v02.api.letsencrypt.org/key-change","meta":{"termsOfService":"https://letsencrypt.org/documents/changed.pdf"}}"#,
            &config.directory_url,
            config.directory_generation,
        )
        .unwrap();
        assert!(matches!(
            config.terms_approval(&changed),
            Err(AcmedConfigError::InvalidTermsApproval)
        ));
    }

    #[test]
    fn production_requires_exact_explicit_enablement() {
        let production = STAGING
            .replace("public-staging", "public-production")
            .replace("production_enabled\":false", "production_enabled\":true");
        assert!(parse_acmed_config(&production).is_ok());
        let disabled =
            production.replace("production_enabled\":true", "production_enabled\":false");
        assert!(matches!(
            parse_acmed_config(&disabled),
            Err(AcmedConfigError::ProductionNotEnabled)
        ));
    }

    #[test]
    fn unknown_fields_invalid_ids_and_unsafe_bounds_fail_closed() {
        assert!(matches!(
            parse_acmed_config(&STAGING.replace("}", ",\"extra\":1}")),
            Err(AcmedConfigError::UnknownField)
        ));
        assert!(matches!(
            parse_acmed_config(
                &STAGING.replace("poll_interval_seconds\":30", "poll_interval_seconds\":0")
            ),
            Err(AcmedConfigError::InvalidBounds)
        ));
        assert!(matches!(
            parse_acmed_config(&STAGING.replace("0123456789abcdef", "0123456789ABCDEF")),
            Err(AcmedConfigError::InvalidZone)
        ));
        assert!(matches!(
            parse_acmed_config(&STAGING.replace(
                "\"terms_content_sha256\":\"1111111111111111111111111111111111111111111111111111111111111111\"",
                "\"terms_content_sha256\":null"
            )),
            Err(AcmedConfigError::InvalidTermsApproval)
        ));
    }
}
