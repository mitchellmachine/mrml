pub const MAX_CAA_RECORD_BYTES: usize = 512;
pub const MAX_CAA_RECORDS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaaError {
    InvalidIssuer,
    InvalidAccountUri,
    InvalidChallengePolicy,
    OutputTooSmall,
    MalformedRecord,
    MissingIssueAuthorization,
    WildcardNotAuthorized,
    ChallengeNotAuthorized,
    AccountNotAuthorized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaaChallengeMethod {
    Http01,
    TlsAlpn01,
    Dns01,
}

impl CaaChallengeMethod {
    const fn name(self) -> &'static str {
        match self {
            Self::Http01 => "http-01",
            Self::TlsAlpn01 => "tls-alpn-01",
            Self::Dns01 => "dns-01",
        }
    }
}

#[derive(Clone, Copy)]
pub struct CaaPolicy<'a> {
    pub issuer_domain: &'a str,
    pub allow_http01: bool,
    pub allow_tls_alpn01: bool,
    pub allow_dns01: bool,
    pub allow_wildcard: bool,
    pub account_uri: Option<&'a str>,
}

impl CaaPolicy<'_> {
    pub fn validate(&self) -> Result<(), CaaError> {
        if !valid_dns_name(self.issuer_domain) {
            return Err(CaaError::InvalidIssuer);
        }
        if !self.allow_http01 && !self.allow_tls_alpn01 && !self.allow_dns01 {
            return Err(CaaError::InvalidChallengePolicy);
        }
        if self.allow_wildcard && !self.allow_dns01 {
            return Err(CaaError::InvalidChallengePolicy);
        }
        if self.account_uri.is_some_and(|uri| {
            uri.len() > 255
                || !uri.is_ascii()
                || !(uri.starts_with("https://") || uri.starts_with("http://"))
                || uri.bytes().any(|byte| byte.is_ascii_whitespace())
        }) {
            return Err(CaaError::InvalidAccountUri);
        }
        Ok(())
    }

    pub fn write_recommended_records(&self, output: &mut [u8]) -> Result<usize, CaaError> {
        self.validate()?;
        let mut cursor = 0;
        cursor = write(output, cursor, b"0 issue \"")?;
        cursor = write(output, cursor, self.issuer_domain.as_bytes())?;
        cursor = write(output, cursor, b"; validationmethods=")?;
        cursor = self.write_methods(output, cursor)?;
        if let Some(uri) = self.account_uri {
            cursor = write(output, cursor, b"; accounturi=")?;
            cursor = write(output, cursor, uri.as_bytes())?;
        }
        cursor = write(output, cursor, b"\"\n")?;
        cursor = write(output, cursor, b"0 issuewild \"")?;
        if self.allow_wildcard {
            cursor = write(output, cursor, self.issuer_domain.as_bytes())?;
            cursor = write(output, cursor, b"; validationmethods=dns-01")?;
            if let Some(uri) = self.account_uri {
                cursor = write(output, cursor, b"; accounturi=")?;
                cursor = write(output, cursor, uri.as_bytes())?;
            }
        } else {
            // An empty issuer explicitly denies wildcard issuance.
        }
        write(output, cursor, b"\"\n")
    }

    pub fn authorize_observed(
        &self,
        records: &[&str],
        wildcard: bool,
        challenge: CaaChallengeMethod,
    ) -> Result<(), CaaError> {
        self.validate()?;
        if records.is_empty() || records.len() > MAX_CAA_RECORDS {
            return Err(CaaError::MissingIssueAuthorization);
        }
        if wildcard && !self.allow_wildcard {
            return Err(CaaError::WildcardNotAuthorized);
        }
        if !self.method_allowed(challenge) || (wildcard && challenge != CaaChallengeMethod::Dns01) {
            return Err(CaaError::ChallengeNotAuthorized);
        }
        let required_tag = if wildcard { "issuewild" } else { "issue" };
        let mut matching_issuer = false;
        let mut matching_method = false;
        for record in records {
            let parsed = ParsedCaa::parse(record)?;
            if parsed.tag != required_tag || parsed.issuer != self.issuer_domain {
                continue;
            }
            matching_issuer = true;
            if !parsed.validation_methods(challenge.name()) {
                continue;
            }
            matching_method = true;
            match (self.account_uri, parsed.account_uri()) {
                (Some(expected), Some(observed)) if expected == observed => return Ok(()),
                (Some(_), _) => continue,
                (None, _) => return Ok(()),
            }
        }
        if !matching_issuer {
            Err(CaaError::MissingIssueAuthorization)
        } else if matching_method && self.account_uri.is_some() {
            Err(CaaError::AccountNotAuthorized)
        } else {
            Err(CaaError::ChallengeNotAuthorized)
        }
    }

    fn method_allowed(&self, method: CaaChallengeMethod) -> bool {
        match method {
            CaaChallengeMethod::Http01 => self.allow_http01,
            CaaChallengeMethod::TlsAlpn01 => self.allow_tls_alpn01,
            CaaChallengeMethod::Dns01 => self.allow_dns01,
        }
    }

    fn write_methods(&self, output: &mut [u8], mut cursor: usize) -> Result<usize, CaaError> {
        let mut separator = false;
        for (enabled, value) in [
            (self.allow_http01, b"http-01".as_slice()),
            (self.allow_tls_alpn01, b"tls-alpn-01".as_slice()),
            (self.allow_dns01, b"dns-01".as_slice()),
        ] {
            if enabled {
                if separator {
                    cursor = write(output, cursor, b",")?;
                }
                cursor = write(output, cursor, value)?;
                separator = true;
            }
        }
        Ok(cursor)
    }
}

struct ParsedCaa<'a> {
    tag: &'a str,
    issuer: &'a str,
    parameters: &'a str,
}

impl<'a> ParsedCaa<'a> {
    fn parse(record: &'a str) -> Result<Self, CaaError> {
        if record.len() > MAX_CAA_RECORD_BYTES || !record.is_ascii() {
            return Err(CaaError::MalformedRecord);
        }
        let mut fields = record.trim().splitn(3, char::is_whitespace);
        let flags = fields.next().ok_or(CaaError::MalformedRecord)?;
        let tag = fields.next().ok_or(CaaError::MalformedRecord)?;
        let value = fields.next().ok_or(CaaError::MalformedRecord)?.trim();
        if flags != "0"
            || !matches!(tag, "issue" | "issuewild")
            || value.len() < 2
            || !value.starts_with('"')
            || !value.ends_with('"')
        {
            return Err(CaaError::MalformedRecord);
        }
        let value = &value[1..value.len() - 1];
        let mut segments = value.split(';');
        let issuer = segments.next().unwrap_or("").trim();
        if !issuer.is_empty() && !valid_dns_name(issuer) {
            return Err(CaaError::MalformedRecord);
        }
        let parameters = value.find(';').map_or("", |index| &value[index..]);
        for parameter in segments {
            let parameter = parameter.trim();
            let (name, value) = parameter.split_once('=').ok_or(CaaError::MalformedRecord)?;
            if !matches!(name.trim(), "validationmethods" | "accounturi") || value.trim().is_empty()
            {
                return Err(CaaError::MalformedRecord);
            }
        }
        Ok(Self {
            tag,
            issuer,
            parameters,
        })
    }

    fn parameter(&self, expected: &str) -> Option<&str> {
        self.parameters
            .split(';')
            .filter_map(|parameter| parameter.trim().split_once('='))
            .find_map(|(name, value)| (name.trim() == expected).then_some(value.trim()))
    }

    fn validation_methods(&self, required: &str) -> bool {
        self.parameter("validationmethods")
            .is_some_and(|methods| methods.split(',').any(|method| method.trim() == required))
    }

    fn account_uri(&self) -> Option<&str> {
        self.parameter("accounturi")
    }
}

fn write(output: &mut [u8], cursor: usize, value: &[u8]) -> Result<usize, CaaError> {
    let end = cursor
        .checked_add(value.len())
        .ok_or(CaaError::OutputTooSmall)?;
    output
        .get_mut(cursor..end)
        .ok_or(CaaError::OutputTooSmall)?
        .copy_from_slice(value);
    Ok(end)
}

fn valid_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> CaaPolicy<'static> {
        CaaPolicy {
            issuer_domain: "letsencrypt.org",
            allow_http01: true,
            allow_tls_alpn01: true,
            allow_dns01: true,
            allow_wildcard: false,
            account_uri: Some("https://acme.example/acct/7"),
        }
    }

    #[test]
    fn renders_exact_non_wildcard_recommendation() {
        let mut output = [0; MAX_CAA_RECORD_BYTES];
        let written = policy().write_recommended_records(&mut output).unwrap();
        assert_eq!(
            core::str::from_utf8(&output[..written]).unwrap(),
            "0 issue \"letsencrypt.org; validationmethods=http-01,tls-alpn-01,dns-01; accounturi=https://acme.example/acct/7\"\n0 issuewild \"\"\n"
        );
    }

    #[test]
    fn observed_policy_binds_tag_method_and_account() {
        let records = [
            "0 issue \"letsencrypt.org; validationmethods=http-01,dns-01; accounturi=https://acme.example/acct/7\"",
            "0 issuewild \"\"",
        ];
        assert_eq!(
            policy().authorize_observed(&records, false, CaaChallengeMethod::Http01),
            Ok(())
        );
        assert_eq!(
            policy().authorize_observed(&records, false, CaaChallengeMethod::TlsAlpn01),
            Err(CaaError::ChallengeNotAuthorized)
        );
        assert_eq!(
            policy().authorize_observed(&records, true, CaaChallengeMethod::Dns01),
            Err(CaaError::WildcardNotAuthorized)
        );
    }

    #[test]
    fn wildcard_requires_dns01_and_explicit_issuewild() {
        let mut wildcard = policy();
        wildcard.allow_wildcard = true;
        let records = [
            "0 issuewild \"letsencrypt.org; validationmethods=dns-01; accounturi=https://acme.example/acct/7\"",
        ];
        assert_eq!(
            wildcard.authorize_observed(&records, true, CaaChallengeMethod::Dns01),
            Ok(())
        );
        assert_eq!(
            wildcard.authorize_observed(&records, true, CaaChallengeMethod::Http01),
            Err(CaaError::ChallengeNotAuthorized)
        );
    }

    #[test]
    fn rejects_unknown_parameters_and_invalid_policy() {
        assert_eq!(
            policy().authorize_observed(
                &["0 issue \"letsencrypt.org; unknown=x\""],
                false,
                CaaChallengeMethod::Http01,
            ),
            Err(CaaError::MalformedRecord)
        );
        let mut invalid = policy();
        invalid.allow_http01 = false;
        invalid.allow_tls_alpn01 = false;
        invalid.allow_dns01 = false;
        assert_eq!(invalid.validate(), Err(CaaError::InvalidChallengePolicy));
    }
}
