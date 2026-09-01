use mrml_acme::{AcmeUrl, DnsIdentifier, MAX_CSR_IDENTIFIERS};
use mrml_crypto::Sha256;
use mrml_json::Value;

pub const MAX_CERTD_CONFIG_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertdDirectoryClass {
    LocalTest,
    PublicStaging,
    PublicProduction,
}

#[derive(Clone, Copy)]
pub struct CertdConfig {
    pub directory_url: AcmeUrl,
    pub directory_generation: u64,
    pub directory_class: CertdDirectoryClass,
    pub account_identity: [u8; 16],
    pub account_generation: u64,
    pub identity: [u8; 16],
    pub key_generation: u64,
    pub policy_generation: u64,
    pub identifiers: [Option<DnsIdentifier>; MAX_CSR_IDENTIFIERS],
    pub identifier_count: u8,
    pub identifier_set_digest: [u8; 32],
    pub wildcard_enabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertdConfigError {
    Oversized,
    Malformed,
    UnknownField,
    MissingField,
    InvalidDirectory,
    ProductionNotEnabled,
    InvalidIdentity,
    InvalidGeneration,
    InvalidIdentifiers,
    WildcardNotEnabled,
}

pub fn parse_certd_config(source: &str) -> Result<CertdConfig, CertdConfigError> {
    if source.is_empty() || source.len() > MAX_CERTD_CONFIG_BYTES {
        return Err(CertdConfigError::Oversized);
    }
    let value = mrml_json::parse(source).map_err(|_| CertdConfigError::Malformed)?;
    let object = value.as_object().ok_or(CertdConfigError::Malformed)?;
    const FIELDS: [&str; 12] = [
        "directory_url",
        "directory_generation",
        "directory_class",
        "production_enabled",
        "account_identity",
        "account_generation",
        "identity",
        "key_generation",
        "policy_generation",
        "identifiers",
        "wildcard_enabled",
        "key_algorithm",
    ];
    if object
        .iter()
        .any(|(key, _)| !FIELDS.contains(&key.as_str()))
    {
        return Err(CertdConfigError::UnknownField);
    }
    if object.len() != FIELDS.len() {
        return Err(CertdConfigError::MissingField);
    }
    if text(&value, "key_algorithm")? != "P-256" {
        return Err(CertdConfigError::Malformed);
    }
    let directory_class = match text(&value, "directory_class")? {
        "local-test" => CertdDirectoryClass::LocalTest,
        "public-staging" => CertdDirectoryClass::PublicStaging,
        "public-production" => CertdDirectoryClass::PublicProduction,
        _ => return Err(CertdConfigError::InvalidDirectory),
    };
    let production_enabled = value
        .get("production_enabled")
        .and_then(Value::as_bool)
        .ok_or(CertdConfigError::MissingField)?;
    if (directory_class == CertdDirectoryClass::PublicProduction) != production_enabled {
        return Err(CertdConfigError::ProductionNotEnabled);
    }
    let directory_url = AcmeUrl::parse(
        text(&value, "directory_url")?,
        directory_class == CertdDirectoryClass::LocalTest,
    )
    .map_err(|_| CertdConfigError::InvalidDirectory)?;
    let directory_generation = generation(&value, "directory_generation")?;
    let account_generation = generation(&value, "account_generation")?;
    let key_generation = generation(&value, "key_generation")?;
    let policy_generation = generation(&value, "policy_generation")?;
    let account_identity = identity(&value, "account_identity")?;
    let identity = identity(&value, "identity")?;
    if account_identity == identity {
        return Err(CertdConfigError::InvalidIdentity);
    }
    let wildcard_enabled = value
        .get("wildcard_enabled")
        .and_then(Value::as_bool)
        .ok_or(CertdConfigError::MissingField)?;
    let list = value
        .get("identifiers")
        .and_then(Value::as_array)
        .ok_or(CertdConfigError::MissingField)?;
    if list.is_empty() || list.len() > MAX_CSR_IDENTIFIERS {
        return Err(CertdConfigError::InvalidIdentifiers);
    }
    let mut identifiers = [None; MAX_CSR_IDENTIFIERS];
    let mut previous: Option<DnsIdentifier> = None;
    for (index, item) in list.iter().enumerate() {
        let text = item.as_str().ok_or(CertdConfigError::InvalidIdentifiers)?;
        let identifier = DnsIdentifier::parse(text, wildcard_enabled)
            .map_err(|_| CertdConfigError::InvalidIdentifiers)?;
        if identifier.is_wildcard() && !wildcard_enabled {
            return Err(CertdConfigError::WildcardNotEnabled);
        }
        if previous.is_some_and(|prior| prior.as_str() >= identifier.as_str()) {
            return Err(CertdConfigError::InvalidIdentifiers);
        }
        identifiers[index] = Some(identifier);
        previous = Some(identifier);
    }
    let identifier_set_digest = certd_identifier_set_digest(&identifiers[..list.len()]);
    Ok(CertdConfig {
        directory_url,
        directory_generation,
        directory_class,
        account_identity,
        account_generation,
        identity,
        key_generation,
        policy_generation,
        identifiers,
        identifier_count: list.len() as u8,
        identifier_set_digest,
        wildcard_enabled,
    })
}

pub fn certd_identifier_set_digest(identifiers: &[Option<DnsIdentifier>]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"mrml-certd-approved-identifier-set-v1\0");
    digest.update(&(identifiers.len() as u16).to_be_bytes());
    for identifier in identifiers.iter().flatten() {
        digest.update(&(identifier.as_str().len() as u16).to_be_bytes());
        digest.update(identifier.as_str().as_bytes());
    }
    digest.finalize()
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, CertdConfigError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or(CertdConfigError::MissingField)
}

fn generation(value: &Value, key: &str) -> Result<u64, CertdConfigError> {
    let generation = value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(CertdConfigError::MissingField)?;
    if generation == 0 {
        Err(CertdConfigError::InvalidGeneration)
    } else {
        Ok(generation)
    }
}

fn identity(value: &Value, key: &str) -> Result<[u8; 16], CertdConfigError> {
    let input = text(value, key)?.as_bytes();
    if input.len() != 32
        || input
            .iter()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(CertdConfigError::InvalidIdentity);
    }
    let mut output = [0u8; 16];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = nibble(input[index * 2])
            .and_then(|high| nibble(input[index * 2 + 1]).map(|low| high << 4 | low))
            .ok_or(CertdConfigError::InvalidIdentity)?;
    }
    if output == [0; 16] {
        Err(CertdConfigError::InvalidIdentity)
    } else {
        Ok(output)
    }
}

fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"{"directory_url":"https://acme-staging-v02.api.letsencrypt.org/directory","directory_generation":1,"directory_class":"public-staging","production_enabled":false,"account_identity":"11111111111111111111111111111111","account_generation":1,"identity":"22222222222222222222222222222222","key_generation":1,"policy_generation":1,"identifiers":["example.com","www.example.com"],"wildcard_enabled":false,"key_algorithm":"P-256"}"#;

    #[test]
    fn exact_policy_derives_stable_identifier_binding() {
        let config = parse_certd_config(CONFIG).unwrap();
        assert_eq!(config.identifier_count, 2);
        assert_eq!(config.identifiers[0].unwrap().as_str(), "example.com");
        assert_ne!(config.identifier_set_digest, [0; 32]);
    }

    #[test]
    fn unknown_fields_unsorted_names_and_implicit_production_fail_closed() {
        assert!(matches!(
            parse_certd_config(&CONFIG.replace("}", ",\"extra\":true}")),
            Err(CertdConfigError::UnknownField)
        ));
        assert!(matches!(
            parse_certd_config(&CONFIG.replace(
                "example.com\",\"www.example.com",
                "www.example.com\",\"example.com"
            )),
            Err(CertdConfigError::InvalidIdentifiers)
        ));
        let production = CONFIG.replace("public-staging", "public-production");
        assert!(matches!(
            parse_certd_config(&production),
            Err(CertdConfigError::ProductionNotEnabled)
        ));
    }

    #[test]
    fn wildcard_requires_explicit_policy_and_distinct_nonzero_identities() {
        assert!(matches!(
            parse_certd_config(&CONFIG.replace("www.example.com", "*.example.com")),
            Err(CertdConfigError::InvalidIdentifiers)
        ));
        assert!(matches!(
            parse_certd_config(&CONFIG.replace(
                "22222222222222222222222222222222",
                "11111111111111111111111111111111"
            )),
            Err(CertdConfigError::InvalidIdentity)
        ));
    }
}
