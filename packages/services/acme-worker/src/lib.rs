#![no_std]

use mrml_acme::{AcmeUrl, DnsIdentifier, MAX_CSR_IDENTIFIERS};
use mrml_certificate::certd_identifier_set_digest;
use mrml_json::Value;

pub const MAX_ACMED_CONFIG_BYTES: usize = 16 * 1024;

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

    const STAGING: &str = r#"{"directory_url":"https://acme-staging-v02.api.letsencrypt.org/directory","directory_generation":1,"directory_class":"public-staging","production_enabled":false,"terms_of_service_url":"https://letsencrypt.org/documents/approved.pdf","terms_content_sha256":"1111111111111111111111111111111111111111111111111111111111111111","dns_provider":"cloudflare","zone_id":"0123456789abcdef0123456789abcdef","zone":"example.com","identity":"11111111111111111111111111111111","account_identity":"22222222222222222222222222222222","account_generation":1,"key_generation":1,"policy_generation":1,"identifiers":["example.com","www.example.com"],"wildcard_enabled":false,"poll_interval_seconds":30,"global_concurrency":2}"#;

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
