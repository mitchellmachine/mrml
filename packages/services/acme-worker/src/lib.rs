#![no_std]

use mrml_acme::{AcmeUrl, DnsIdentifier};
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
    pub zone_id: [u8; 32],
    pub zone: DnsIdentifier,
    pub identity: [u8; 16],
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
    const FIELDS: [&str; 10] = [
        "directory_url",
        "directory_generation",
        "directory_class",
        "production_enabled",
        "dns_provider",
        "zone_id",
        "zone",
        "identity",
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
    let identity_text = text(&value, "identity")?;
    if !valid_hex(identity_text, 32) {
        return Err(AcmedConfigError::InvalidIdentity);
    }
    let mut identity = [0u8; 16];
    for (index, output) in identity.iter_mut().enumerate() {
        *output = decode_hex(&identity_text.as_bytes()[index * 2..index * 2 + 2])?;
    }
    if identity == [0; 16] {
        return Err(AcmedConfigError::InvalidIdentity);
    }
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
        zone_id,
        zone,
        identity,
        poll_interval_seconds,
        global_concurrency,
        per_identity_concurrency: 1,
    })
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

    const STAGING: &str = r#"{"directory_url":"https://acme-staging-v02.api.letsencrypt.org/directory","directory_generation":1,"directory_class":"public-staging","production_enabled":false,"dns_provider":"cloudflare","zone_id":"0123456789abcdef0123456789abcdef","zone":"example.com","identity":"11111111111111111111111111111111","poll_interval_seconds":30,"global_concurrency":2}"#;

    #[test]
    fn staging_configuration_is_exact_and_bounded() {
        let config = parse_acmed_config(STAGING).unwrap();
        assert_eq!(config.directory_class, AcmeDirectoryClass::PublicStaging);
        assert_eq!(
            config.directory_url.origin().host,
            "acme-staging-v02.api.letsencrypt.org"
        );
        assert_eq!(config.per_identity_concurrency, 1);
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
    }
}
