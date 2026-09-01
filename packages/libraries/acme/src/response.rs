use crate::directory::{Parser, Token};
use crate::{
    AcmeIdentifier, AcmeOrigin, AcmeUrl, ChallengeKind, ChallengeState, DirectoryError,
    DnsIdentifier, IpIdentifier, MAX_AUTHORIZATIONS, MAX_CHALLENGES_PER_AUTHORIZATION,
    MAX_DIRECTORY_BYTES, MAX_ORDER_IDENTIFIERS, OrderState,
};
use mrml_crypto::Sha256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseError {
    TooLarge,
    Malformed,
    DuplicateField,
    MissingField,
    TooManyItems,
    EndpointPolicy,
    IdentifierMismatch,
    ProfileMismatch,
    UnsupportedIdentifier,
    UnsupportedChallenge,
}

impl From<DirectoryError> for ResponseError {
    fn from(_: DirectoryError) -> Self {
        Self::Malformed
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ParsedOrderResponse {
    pub status: OrderState,
    pub finalize: AcmeUrl,
    pub certificate: Option<AcmeUrl>,
    authorizations: [Option<AcmeUrl>; MAX_AUTHORIZATIONS],
    authorization_count: u8,
}

impl ParsedOrderResponse {
    pub fn authorizations(&self) -> impl Iterator<Item = &AcmeUrl> {
        self.authorizations[..usize::from(self.authorization_count)]
            .iter()
            .flatten()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ParsedChallenge {
    pub kind: ChallengeKind,
    pub url: AcmeUrl,
    pub status: ChallengeState,
    pub token: crate::ChallengeToken,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ParsedAuthorizationResponse {
    pub identifier: AcmeIdentifier,
    pub wildcard: bool,
    pub status: crate::AuthorizationState,
    challenges: [Option<ParsedChallenge>; MAX_CHALLENGES_PER_AUTHORIZATION],
    challenge_count: u8,
}

impl ParsedAuthorizationResponse {
    pub fn challenges(&self) -> impl Iterator<Item = &ParsedChallenge> {
        self.challenges[..usize::from(self.challenge_count)]
            .iter()
            .flatten()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedAccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AccountContact {
    bytes: [u8; crate::MAX_ACCOUNT_CONTACT_BYTES],
    len: u16,
}

impl AccountContact {
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ParsedAccountResponse {
    pub status: ParsedAccountStatus,
    pub orders: Option<AcmeUrl>,
    pub contacts_digest: [u8; 32],
    contacts: [Option<AccountContact>; crate::MAX_ACCOUNT_CONTACTS],
    contact_count: u8,
}

impl ParsedAccountResponse {
    pub fn contacts(&self) -> impl Iterator<Item = &AccountContact> {
        self.contacts[..usize::from(self.contact_count)]
            .iter()
            .flatten()
    }
}

pub fn parse_account_response(
    source: &str,
    origin: AcmeOrigin<'_>,
) -> Result<ParsedAccountResponse, ResponseError> {
    if source.len() > MAX_DIRECTORY_BYTES {
        return Err(ResponseError::TooLarge);
    }
    let mut parser = Parser::new(source);
    parser.expect(Token::ObjectStart)?;
    let mut seen = 0u8;
    let mut status = None;
    let mut orders = None;
    let mut contacts: [Option<AccountContact>; crate::MAX_ACCOUNT_CONTACTS] =
        [None; crate::MAX_ACCOUNT_CONTACTS];
    let mut contact_count = 0u8;
    parser.object_fields(|parser, name| {
        let bit = match name {
            "status" => 1,
            "contact" => 2,
            "orders" => 4,
            _ => 0,
        };
        if bit != 0 && seen & bit != 0 {
            return Err(DirectoryError::DuplicateField);
        }
        seen |= bit;
        match name {
            "status" => {
                status = Some(match parser.string()? {
                    "valid" => ParsedAccountStatus::Valid,
                    "deactivated" => ParsedAccountStatus::Deactivated,
                    "revoked" => ParsedAccountStatus::Revoked,
                    _ => return Err(DirectoryError::Malformed),
                })
            }
            "orders" => orders = Some(parse_endpoint(parser, origin)?),
            "contact" => {
                parser.expect(Token::ArrayStart)?;
                match parser.next()? {
                    Some(Token::ArrayEnd) => {}
                    Some(token) => {
                        parser.put_back(token);
                        loop {
                            if usize::from(contact_count) >= crate::MAX_ACCOUNT_CONTACTS {
                                return Err(DirectoryError::TooManyProfiles);
                            }
                            let value = parser.string()?;
                            if value.is_empty()
                                || value.len() > crate::MAX_ACCOUNT_CONTACT_BYTES
                                || value.contains(['"', '\\'])
                                || value.bytes().any(|byte| byte < 0x20 || !byte.is_ascii())
                            {
                                return Err(DirectoryError::Malformed);
                            }
                            if contacts[..usize::from(contact_count)]
                                .iter()
                                .flatten()
                                .any(|existing| existing.as_str() == value)
                            {
                                return Err(DirectoryError::DuplicateField);
                            }
                            let mut bytes = [0; crate::MAX_ACCOUNT_CONTACT_BYTES];
                            bytes[..value.len()].copy_from_slice(value.as_bytes());
                            contacts[usize::from(contact_count)] = Some(AccountContact {
                                bytes,
                                len: value.len() as u16,
                            });
                            contact_count += 1;
                            match parser.next()? {
                                Some(Token::Comma) => {}
                                Some(Token::ArrayEnd) => break,
                                _ => return Err(DirectoryError::Malformed),
                            }
                        }
                    }
                    None => return Err(DirectoryError::Malformed),
                }
            }
            _ => parser.skip_value(1)?,
        }
        Ok(())
    })?;
    parser.finish()?;
    let mut digest = Sha256::new();
    digest.update(b"mrml-acme-account-contacts-v1\0");
    for contact in contacts[..usize::from(contact_count)].iter().flatten() {
        digest.update(&(contact.as_str().len() as u16).to_be_bytes());
        digest.update(contact.as_str().as_bytes());
    }
    Ok(ParsedAccountResponse {
        status: status.ok_or(ResponseError::MissingField)?,
        orders,
        contacts_digest: digest.finalize(),
        contacts,
        contact_count,
    })
}

pub fn parse_order_response(
    source: &str,
    origin: AcmeOrigin<'_>,
    expected_identifiers: &[AcmeIdentifier],
    expected_profile: &str,
) -> Result<ParsedOrderResponse, ResponseError> {
    if source.len() > MAX_DIRECTORY_BYTES {
        return Err(ResponseError::TooLarge);
    }
    if expected_identifiers.is_empty() || expected_identifiers.len() > MAX_ORDER_IDENTIFIERS {
        return Err(ResponseError::IdentifierMismatch);
    }
    let mut parser = Parser::new(source);
    parser.expect(Token::ObjectStart)?;
    let mut seen = 0u8;
    let mut status = None;
    let mut finalize = None;
    let mut certificate = None;
    let mut authorizations = [None; MAX_AUTHORIZATIONS];
    let mut authorization_count = 0u8;
    parser.object_fields(|parser, name| {
        let bit = match name {
            "status" => Some(1),
            "identifiers" => Some(2),
            "authorizations" => Some(4),
            "finalize" => Some(8),
            "certificate" => Some(16),
            "profile" => Some(32),
            _ => None,
        };
        if let Some(bit) = bit {
            if seen & bit != 0 {
                return Err(DirectoryError::DuplicateField);
            }
            seen |= bit;
        }
        match name {
            "status" => status = Some(parse_order_status(parser.string()?)?),
            "identifiers" => parse_identifiers(parser, expected_identifiers)?,
            "authorizations" => {
                parser.expect(Token::ArrayStart)?;
                match parser.next()? {
                    Some(Token::ArrayEnd) => {}
                    Some(token) => {
                        parser.put_back(token);
                        loop {
                            if usize::from(authorization_count) >= MAX_AUTHORIZATIONS {
                                return Err(DirectoryError::TooManyProfiles);
                            }
                            let url = AcmeUrl::parse(parser.string()?, false)
                                .map_err(|_| DirectoryError::EndpointPolicy)?;
                            url.require_origin(origin)
                                .map_err(|_| DirectoryError::EndpointPolicy)?;
                            if authorizations[..usize::from(authorization_count)]
                                .iter()
                                .flatten()
                                .any(|existing| existing == &url)
                            {
                                return Err(DirectoryError::DuplicateField);
                            }
                            authorizations[usize::from(authorization_count)] = Some(url);
                            authorization_count += 1;
                            match parser.next()? {
                                Some(Token::Comma) => {}
                                Some(Token::ArrayEnd) => break,
                                _ => return Err(DirectoryError::Malformed),
                            }
                        }
                    }
                    None => return Err(DirectoryError::Malformed),
                }
            }
            "finalize" => finalize = Some(parse_endpoint(parser, origin)?),
            "certificate" => certificate = Some(parse_endpoint(parser, origin)?),
            "profile" if parser.string()? != expected_profile => {
                return Err(DirectoryError::InvalidProfile);
            }
            "profile" => {}
            _ => parser.skip_value(1)?,
        }
        Ok(())
    })?;
    parser.finish()?;
    if seen & 0x2f != 0x2f || authorization_count != expected_identifiers.len() as u8 {
        return Err(ResponseError::MissingField);
    }
    Ok(ParsedOrderResponse {
        status: status.ok_or(ResponseError::MissingField)?,
        finalize: finalize.ok_or(ResponseError::MissingField)?,
        certificate,
        authorizations,
        authorization_count,
    })
}

pub fn parse_authorization_response(
    source: &str,
    origin: AcmeOrigin<'_>,
    expected_identifier: AcmeIdentifier,
) -> Result<ParsedAuthorizationResponse, ResponseError> {
    if source.len() > MAX_DIRECTORY_BYTES {
        return Err(ResponseError::TooLarge);
    }
    let mut parser = Parser::new(source);
    parser.expect(Token::ObjectStart)?;
    let mut seen = 0u8;
    let mut identifier = None;
    let mut status = None;
    let mut wildcard = false;
    let mut challenges: [Option<ParsedChallenge>; MAX_CHALLENGES_PER_AUTHORIZATION] =
        [None; MAX_CHALLENGES_PER_AUTHORIZATION];
    let mut challenge_count = 0u8;
    parser.object_fields(|parser, name| {
        let bit = match name {
            "identifier" => 1,
            "status" => 2,
            "challenges" => 4,
            "wildcard" => 8,
            "expires" => 16,
            _ => 0,
        };
        if bit != 0 && seen & bit != 0 {
            return Err(DirectoryError::DuplicateField);
        }
        seen |= bit;
        match name {
            "identifier" => identifier = Some(parse_identifier(parser)?),
            "status" => status = Some(parse_authorization_status(parser.string()?)?),
            "wildcard" => {
                wildcard = match parser.next()? {
                    Some(Token::Bool(value)) => value,
                    _ => return Err(DirectoryError::Malformed),
                }
            }
            "challenges" => {
                parser.expect(Token::ArrayStart)?;
                match parser.next()? {
                    Some(Token::ArrayEnd) => {}
                    Some(token) => {
                        parser.put_back(token);
                        loop {
                            if let Some(challenge) = parse_challenge(parser, origin)? {
                                if usize::from(challenge_count) >= MAX_CHALLENGES_PER_AUTHORIZATION
                                {
                                    return Err(DirectoryError::TooManyProfiles);
                                }
                                if challenges[..usize::from(challenge_count)]
                                    .iter()
                                    .flatten()
                                    .any(|existing| {
                                        existing.kind == challenge.kind
                                            || existing.url == challenge.url
                                    })
                                {
                                    return Err(DirectoryError::DuplicateField);
                                }
                                challenges[usize::from(challenge_count)] = Some(challenge);
                                challenge_count += 1;
                            }
                            match parser.next()? {
                                Some(Token::Comma) => {}
                                Some(Token::ArrayEnd) => break,
                                _ => return Err(DirectoryError::Malformed),
                            }
                        }
                    }
                    None => return Err(DirectoryError::Malformed),
                }
            }
            _ => parser.skip_value(1)?,
        }
        Ok(())
    })?;
    parser.finish()?;
    let response_identifier = identifier.ok_or(ResponseError::MissingField)?;
    let identifier_matches = match expected_identifier {
        AcmeIdentifier::Dns(expected) if expected.is_wildcard() => {
            let AcmeIdentifier::Dns(response) = response_identifier else {
                return Err(ResponseError::IdentifierMismatch);
            };
            expected
                .as_str()
                .strip_prefix("*.")
                .is_some_and(|base| base == response.as_str())
        }
        _ => response_identifier == expected_identifier,
    };
    if !identifier_matches || wildcard != expected_identifier.is_wildcard() {
        return Err(ResponseError::IdentifierMismatch);
    }
    if seen & 7 != 7 || challenge_count == 0 {
        return Err(ResponseError::MissingField);
    }
    Ok(ParsedAuthorizationResponse {
        identifier: expected_identifier,
        wildcard,
        status: status.ok_or(ResponseError::MissingField)?,
        challenges,
        challenge_count,
    })
}

fn parse_identifier(parser: &mut Parser<'_>) -> Result<AcmeIdentifier, DirectoryError> {
    parser.expect(Token::ObjectStart)?;
    let mut kind = None;
    let mut value = None;
    let mut seen = 0u8;
    parser.object_fields(|parser, name| {
        let bit = match name {
            "type" => 1,
            "value" => 2,
            _ => 0,
        };
        if bit != 0 && seen & bit != 0 {
            return Err(DirectoryError::DuplicateField);
        }
        seen |= bit;
        match name {
            "type" => kind = Some(parser.string()?),
            "value" => value = Some(parser.string()?),
            _ => parser.skip_value(2)?,
        }
        Ok(())
    })?;
    let value = value.ok_or(DirectoryError::Malformed)?;
    match kind {
        Some("dns") => DnsIdentifier::parse(value, false)
            .map(AcmeIdentifier::Dns)
            .map_err(|_| DirectoryError::InvalidCaaIdentity),
        Some("ip") => IpIdentifier::parse(value)
            .map(AcmeIdentifier::Ip)
            .map_err(|_| DirectoryError::InvalidCaaIdentity),
        _ => Err(DirectoryError::InvalidCaaIdentity),
    }
}

fn parse_challenge(
    parser: &mut Parser<'_>,
    origin: AcmeOrigin<'_>,
) -> Result<Option<ParsedChallenge>, DirectoryError> {
    parser.expect(Token::ObjectStart)?;
    let mut kind = None;
    let mut url = None;
    let mut status = None;
    let mut token = None;
    let mut seen = 0u8;
    parser.object_fields(|parser, name| {
        let bit = match name {
            "type" => 1,
            "url" => 2,
            "status" => 4,
            "token" => 8,
            _ => 0,
        };
        if bit != 0 && seen & bit != 0 {
            return Err(DirectoryError::DuplicateField);
        }
        seen |= bit;
        match name {
            "type" => kind = Some(parser.string()?),
            "url" => url = Some(parse_endpoint(parser, origin)?),
            "status" => status = Some(parse_challenge_status(parser.string()?)?),
            "token" => {
                token = Some(
                    crate::ChallengeToken::parse(parser.string()?)
                        .map_err(|_| DirectoryError::Malformed)?,
                )
            }
            _ => parser.skip_value(2)?,
        }
        Ok(())
    })?;
    let kind = match kind.ok_or(DirectoryError::Malformed)? {
        "http-01" => ChallengeKind::Http01,
        "tls-alpn-01" => ChallengeKind::TlsAlpn01,
        "dns-01" => ChallengeKind::Dns01,
        _ => return Ok(None),
    };
    if seen & 15 != 15 {
        return Err(DirectoryError::Malformed);
    }
    Ok(Some(ParsedChallenge {
        kind,
        url: url.ok_or(DirectoryError::Malformed)?,
        status: status.ok_or(DirectoryError::Malformed)?,
        token: token.ok_or(DirectoryError::Malformed)?,
    }))
}

fn parse_authorization_status(value: &str) -> Result<crate::AuthorizationState, DirectoryError> {
    Ok(match value {
        "pending" => crate::AuthorizationState::Pending,
        "processing" => crate::AuthorizationState::Processing,
        "valid" => crate::AuthorizationState::Valid,
        "invalid" => crate::AuthorizationState::Invalid,
        "deactivated" => crate::AuthorizationState::Deactivated,
        "expired" => crate::AuthorizationState::Expired,
        "revoked" => crate::AuthorizationState::Revoked,
        _ => return Err(DirectoryError::Malformed),
    })
}

fn parse_challenge_status(value: &str) -> Result<ChallengeState, DirectoryError> {
    Ok(match value {
        "pending" => ChallengeState::Pending,
        "processing" => ChallengeState::Processing,
        "valid" => ChallengeState::Valid,
        "invalid" => ChallengeState::Invalid,
        _ => return Err(DirectoryError::Malformed),
    })
}

fn parse_identifiers(
    parser: &mut Parser<'_>,
    expected: &[AcmeIdentifier],
) -> Result<(), DirectoryError> {
    parser.expect(Token::ArrayStart)?;
    for (index, expected) in expected.iter().enumerate() {
        if index != 0 {
            parser.expect(Token::Comma)?;
        }
        if parse_identifier(parser)? != *expected {
            return Err(DirectoryError::InvalidCaaIdentity);
        }
    }
    parser.expect(Token::ArrayEnd)
}

fn parse_endpoint(
    parser: &mut Parser<'_>,
    origin: AcmeOrigin<'_>,
) -> Result<AcmeUrl, DirectoryError> {
    let url = AcmeUrl::parse(parser.string()?, false)?;
    url.require_origin(origin)?;
    Ok(url)
}

fn parse_order_status(value: &str) -> Result<OrderState, DirectoryError> {
    Ok(match value {
        "pending" => OrderState::Pending,
        "ready" => OrderState::Ready,
        "processing" => OrderState::Processing,
        "valid" => OrderState::Valid,
        "invalid" => OrderState::Invalid,
        "deactivated" => OrderState::Deactivated,
        "expired" => OrderState::Expired,
        "revoked" => OrderState::Revoked,
        _ => return Err(DirectoryError::Malformed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_response_is_bounded_and_origin_bound() {
        let directory = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let parsed = parse_account_response(
            r#"{"status":"valid","contact":["mailto:owner@example.com"],"orders":"https://ca.example/orders/1"}"#,
            directory.origin(),
        )
        .unwrap();
        assert_eq!(parsed.status, ParsedAccountStatus::Valid);
        assert_eq!(
            parsed.contacts().next().unwrap().as_str(),
            "mailto:owner@example.com"
        );
        assert_ne!(parsed.contacts_digest, [0; 32]);
        assert!(
            parse_account_response(
                r#"{"status":"valid","orders":"https://other.example/orders/1"}"#,
                directory.origin(),
            )
            .is_err()
        );
        assert!(
            parse_account_response(
                r#"{"status":"valid","status":"deactivated"}"#,
                directory.origin(),
            )
            .is_err()
        );
    }

    #[test]
    fn order_response_binds_exact_names_profile_and_origin() {
        let names = [
            AcmeIdentifier::Dns(DnsIdentifier::parse("api.example", false).unwrap()),
            AcmeIdentifier::Dns(DnsIdentifier::parse("git.example", false).unwrap()),
        ];
        let directory = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let response = parse_order_response(
            r#"{"status":"pending","identifiers":[{"type":"dns","value":"api.example"},{"type":"dns","value":"git.example"}],"authorizations":["https://ca.example/a/1","https://ca.example/a/2"],"finalize":"https://ca.example/o/1/finalize","profile":"classic"}"#,
            directory.origin(),
            &names,
            "classic",
        )
        .unwrap();
        assert_eq!(response.status, OrderState::Pending);
        assert_eq!(response.authorizations().count(), 2);
        assert!(parse_order_response(
            r#"{"status":"pending","identifiers":[{"type":"dns","value":"api.example"},{"type":"dns","value":"other.example"}],"authorizations":["https://ca.example/a/1","https://ca.example/a/2"],"finalize":"https://ca.example/o/1/finalize","profile":"classic"}"#,
            directory.origin(), &names, "classic").is_err());
        assert!(parse_order_response(
            r#"{"status":"pending","identifiers":[{"type":"dns","value":"api.example"},{"type":"dns","value":"git.example"}],"authorizations":["https://evil.example/a/1","https://ca.example/a/2"],"finalize":"https://ca.example/o/1/finalize","profile":"classic"}"#,
            directory.origin(), &names, "classic").is_err());
    }

    #[test]
    fn authorization_response_binds_name_origin_and_supported_challenges() {
        let directory = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let identifier = AcmeIdentifier::Dns(DnsIdentifier::parse("git.example", false).unwrap());
        let parsed = parse_authorization_response(
            r#"{"identifier":{"type":"dns","value":"git.example"},"status":"pending","challenges":[{"type":"future-01","url":"https://ca.example/c/0","status":"pending","token":"ignored"},{"type":"http-01","url":"https://ca.example/c/1","status":"pending","token":"abc_123"},{"type":"dns-01","url":"https://ca.example/c/2","status":"processing","token":"def_456"}]}"#,
            directory.origin(),
            identifier,
        )
        .unwrap();
        assert_eq!(parsed.status, crate::AuthorizationState::Pending);
        assert_eq!(parsed.challenges().count(), 2);
        assert!(parse_authorization_response(
            r#"{"identifier":{"type":"dns","value":"other.example"},"status":"pending","challenges":[{"type":"http-01","url":"https://ca.example/c/1","status":"pending","token":"abc"}]}"#,
            directory.origin(), identifier).is_err());
        let wildcard = AcmeIdentifier::Dns(DnsIdentifier::parse("*.git.example", true).unwrap());
        assert!(parse_authorization_response(
            r#"{"identifier":{"type":"dns","value":"git.example"},"status":"pending","wildcard":true,"challenges":[{"type":"dns-01","url":"https://ca.example/c/2","status":"pending","token":"abc"}]}"#,
            directory.origin(), wildcard).is_ok());
        assert!(parse_authorization_response(
            r#"{"identifier":{"type":"dns","value":"git.example"},"status":"pending","challenges":[{"type":"http-01","url":"https://evil.example/c/1","status":"pending","token":"abc"}]}"#,
            directory.origin(), identifier).is_err());
    }

    #[test]
    fn typed_responses_bind_ip_kind_and_canonical_value() {
        let directory = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let identifiers = [
            AcmeIdentifier::Dns(DnsIdentifier::parse("git.example", false).unwrap()),
            AcmeIdentifier::Ip(IpIdentifier::parse("192.0.2.1").unwrap()),
            AcmeIdentifier::Ip(IpIdentifier::parse("2001:db8::1").unwrap()),
        ];
        assert!(
            parse_order_response(
                r#"{"status":"pending","identifiers":[{"type":"dns","value":"git.example"},{"type":"ip","value":"192.0.2.1"},{"type":"ip","value":"2001:db8::1"}],"authorizations":["https://ca.example/a/1","https://ca.example/a/2","https://ca.example/a/3"],"finalize":"https://ca.example/o/1/finalize","profile":"ip-enabled"}"#,
                directory.origin(),
                &identifiers,
                "ip-enabled",
            )
            .is_ok()
        );
        let expected_ip = identifiers[1];
        assert!(
            parse_authorization_response(
                r#"{"identifier":{"type":"ip","value":"192.0.2.1"},"status":"pending","challenges":[{"type":"http-01","url":"https://ca.example/c/1","status":"pending","token":"abc"}]}"#,
                directory.origin(),
                expected_ip,
            )
            .is_ok()
        );
        assert!(
            parse_authorization_response(
                r#"{"identifier":{"type":"dns","value":"192.0.2.1"},"status":"pending","challenges":[{"type":"http-01","url":"https://ca.example/c/1","status":"pending","token":"abc"}]}"#,
                directory.origin(),
                expected_ip,
            )
            .is_err()
        );
    }
}
