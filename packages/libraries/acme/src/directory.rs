use crate::{AcmeOrigin, AcmeUrl, CertificateProfile, DnsIdentifier, ProfileError, UrlError};

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Token<'a> {
    Null,
    Bool(bool),
    Number(&'a str),
    String(&'a str),
    ArrayStart,
    ArrayEnd,
    ObjectStart,
    ObjectEnd,
    Colon,
    Comma,
}

pub(crate) struct Tokens<'a> {
    source: &'a str,
    position: usize,
}

impl<'a> Tokens<'a> {
    pub(crate) const fn new(source: &'a str) -> Self {
        Self {
            source,
            position: 0,
        }
    }
    fn string(&mut self) -> Result<Token<'a>, ()> {
        let bytes = self.source.as_bytes();
        self.position += 1;
        let start = self.position;
        while let Some(&byte) = bytes.get(self.position) {
            match byte {
                b'"' => {
                    let value = &self.source[start..self.position];
                    self.position += 1;
                    return Ok(Token::String(value));
                }
                b'\\' => {
                    self.position += 1;
                    let escaped = *bytes.get(self.position).ok_or(())?;
                    if escaped == b'u' {
                        for _ in 0..4 {
                            self.position += 1;
                            if !bytes.get(self.position).is_some_and(u8::is_ascii_hexdigit) {
                                return Err(());
                            }
                        }
                    } else if !matches!(
                        escaped,
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
                    ) {
                        return Err(());
                    }
                    self.position += 1;
                }
                0..=0x1f => return Err(()),
                _ => self.position += 1,
            }
        }
        Err(())
    }
    fn number(&mut self) -> Result<Token<'a>, ()> {
        let bytes = self.source.as_bytes();
        let start = self.position;
        if bytes.get(self.position) == Some(&b'-') {
            self.position += 1;
        }
        if bytes.get(self.position) == Some(&b'0') {
            self.position += 1;
            if bytes.get(self.position).is_some_and(u8::is_ascii_digit) {
                return Err(());
            }
        } else {
            self.digits()?;
        }
        if bytes.get(self.position) == Some(&b'.') {
            self.position += 1;
            self.digits()?;
        }
        if matches!(bytes.get(self.position), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(bytes.get(self.position), Some(b'+' | b'-')) {
                self.position += 1;
            }
            self.digits()?;
        }
        Ok(Token::Number(&self.source[start..self.position]))
    }
    fn digits(&mut self) -> Result<(), ()> {
        let start = self.position;
        while self
            .source
            .as_bytes()
            .get(self.position)
            .is_some_and(u8::is_ascii_digit)
        {
            self.position += 1;
        }
        if self.position == start {
            Err(())
        } else {
            Ok(())
        }
    }
}

impl<'a> Iterator for Tokens<'a> {
    type Item = Result<Token<'a>, ()>;
    fn next(&mut self) -> Option<Self::Item> {
        let bytes = self.source.as_bytes();
        while matches!(bytes.get(self.position), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position += 1;
        }
        let byte = *bytes.get(self.position)?;
        let single = match byte {
            b'[' => Some(Token::ArrayStart),
            b']' => Some(Token::ArrayEnd),
            b'{' => Some(Token::ObjectStart),
            b'}' => Some(Token::ObjectEnd),
            b':' => Some(Token::Colon),
            b',' => Some(Token::Comma),
            _ => None,
        };
        if let Some(token) = single {
            self.position += 1;
            return Some(Ok(token));
        }
        if byte == b'"' {
            return Some(self.string());
        }
        if byte == b'-' || byte.is_ascii_digit() {
            return Some(self.number());
        }
        for (literal, token) in [
            ("null", Token::Null),
            ("true", Token::Bool(true)),
            ("false", Token::Bool(false)),
        ] {
            if self.source[self.position..].starts_with(literal) {
                self.position += literal.len();
                return Some(Ok(token));
            }
        }
        Some(Err(()))
    }
}

pub const MAX_DIRECTORY_BYTES: usize = 32 * 1024;
pub const MAX_DIRECTORY_PROFILES: usize = 16;
pub const MAX_CAA_IDENTITIES: usize = 8;
const MAX_DIRECTORY_TOKENS: usize = 512;
const MAX_JSON_DEPTH: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryError {
    TooLarge,
    Malformed,
    TooComplex,
    DuplicateField,
    MissingEndpoint,
    EndpointPolicy,
    TooManyProfiles,
    TooManyCaaIdentities,
    InvalidProfile,
    InvalidCaaIdentity,
    EscapedStringUnsupported,
}

impl From<UrlError> for DirectoryError {
    fn from(_: UrlError) -> Self {
        Self::EndpointPolicy
    }
}

impl From<ProfileError> for DirectoryError {
    fn from(_: ProfileError) -> Self {
        Self::InvalidProfile
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProfileAdvertisement {
    pub profile: CertificateProfile,
    pub description: AcmeUrl,
}

pub struct AcmeDirectory {
    pub generation: u64,
    pub new_nonce: AcmeUrl,
    pub new_account: AcmeUrl,
    pub new_order: AcmeUrl,
    pub new_authz: Option<AcmeUrl>,
    pub revoke_cert: AcmeUrl,
    pub key_change: AcmeUrl,
    pub renewal_info: Option<AcmeUrl>,
    pub terms_of_service: Option<AcmeUrl>,
    pub external_account_required: bool,
    profiles: [Option<ProfileAdvertisement>; MAX_DIRECTORY_PROFILES],
    profile_count: u8,
    caa_identities: [Option<DnsIdentifier>; MAX_CAA_IDENTITIES],
    caa_count: u8,
}

impl AcmeDirectory {
    pub fn profiles(&self) -> impl Iterator<Item = &ProfileAdvertisement> {
        self.profiles[..usize::from(self.profile_count)]
            .iter()
            .flatten()
    }
    pub fn caa_identities(&self) -> impl Iterator<Item = &DnsIdentifier> {
        self.caa_identities[..usize::from(self.caa_count)]
            .iter()
            .flatten()
    }

    pub fn parse(
        source: &str,
        directory_url: &AcmeUrl,
        generation: u64,
    ) -> Result<Self, DirectoryError> {
        if source.len() > MAX_DIRECTORY_BYTES {
            return Err(DirectoryError::TooLarge);
        }
        let mut parser = Parser::new(source);
        parser.expect(Token::ObjectStart)?;
        let mut endpoints = Endpoints::default();
        let mut metadata = Metadata::default();
        let origin = directory_url.origin();
        let mut seen = 0u16;
        parser.object_fields(|parser, name| {
            let bit = match name {
                "newNonce" => Some(1 << 0),
                "newAccount" => Some(1 << 1),
                "newOrder" => Some(1 << 2),
                "newAuthz" => Some(1 << 3),
                "revokeCert" => Some(1 << 4),
                "keyChange" => Some(1 << 5),
                "renewalInfo" => Some(1 << 6),
                "meta" => Some(1 << 7),
                _ => None,
            };
            if let Some(bit) = bit {
                if seen & bit != 0 {
                    return Err(DirectoryError::DuplicateField);
                }
                seen |= bit;
            }
            match name {
                "newNonce" => endpoints.new_nonce = Some(parser.endpoint(origin)?),
                "newAccount" => endpoints.new_account = Some(parser.endpoint(origin)?),
                "newOrder" => endpoints.new_order = Some(parser.endpoint(origin)?),
                "newAuthz" => endpoints.new_authz = Some(parser.endpoint(origin)?),
                "revokeCert" => endpoints.revoke_cert = Some(parser.endpoint(origin)?),
                "keyChange" => endpoints.key_change = Some(parser.endpoint(origin)?),
                "renewalInfo" => endpoints.renewal_info = Some(parser.endpoint(origin)?),
                "meta" => parser.metadata(&mut metadata, generation)?,
                _ => parser.skip_value(1)?,
            }
            Ok(())
        })?;
        parser.finish()?;
        Ok(Self {
            generation,
            new_nonce: endpoints.new_nonce.ok_or(DirectoryError::MissingEndpoint)?,
            new_account: endpoints
                .new_account
                .ok_or(DirectoryError::MissingEndpoint)?,
            new_order: endpoints.new_order.ok_or(DirectoryError::MissingEndpoint)?,
            new_authz: endpoints.new_authz,
            revoke_cert: endpoints
                .revoke_cert
                .ok_or(DirectoryError::MissingEndpoint)?,
            key_change: endpoints
                .key_change
                .ok_or(DirectoryError::MissingEndpoint)?,
            renewal_info: endpoints.renewal_info,
            terms_of_service: metadata.terms_of_service,
            external_account_required: metadata.external_account_required,
            profiles: metadata.profiles,
            profile_count: metadata.profile_count,
            caa_identities: metadata.caa_identities,
            caa_count: metadata.caa_count,
        })
    }
}

#[derive(Default)]
struct Endpoints {
    new_nonce: Option<AcmeUrl>,
    new_account: Option<AcmeUrl>,
    new_order: Option<AcmeUrl>,
    new_authz: Option<AcmeUrl>,
    revoke_cert: Option<AcmeUrl>,
    key_change: Option<AcmeUrl>,
    renewal_info: Option<AcmeUrl>,
}

struct Metadata {
    terms_of_service: Option<AcmeUrl>,
    external_account_required: bool,
    profiles: [Option<ProfileAdvertisement>; MAX_DIRECTORY_PROFILES],
    profile_count: u8,
    caa_identities: [Option<DnsIdentifier>; MAX_CAA_IDENTITIES],
    caa_count: u8,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            terms_of_service: None,
            external_account_required: false,
            profiles: [None; MAX_DIRECTORY_PROFILES],
            profile_count: 0,
            caa_identities: [None; MAX_CAA_IDENTITIES],
            caa_count: 0,
        }
    }
}

struct Parser<'a> {
    tokens: Tokens<'a>,
    pushed: Option<Token<'a>>,
    count: usize,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            tokens: Tokens::new(source),
            pushed: None,
            count: 0,
        }
    }
    fn next(&mut self) -> Result<Option<Token<'a>>, DirectoryError> {
        if let Some(token) = self.pushed.take() {
            return Ok(Some(token));
        }
        self.count += 1;
        if self.count > MAX_DIRECTORY_TOKENS {
            return Err(DirectoryError::TooComplex);
        }
        self.tokens
            .next()
            .transpose()
            .map_err(|_| DirectoryError::Malformed)
    }
    fn put_back(&mut self, token: Token<'a>) {
        self.pushed = Some(token);
    }
    fn expect(&mut self, expected: Token<'_>) -> Result<(), DirectoryError> {
        if self.next()? == Some(expected) {
            Ok(())
        } else {
            Err(DirectoryError::Malformed)
        }
    }
    fn string(&mut self) -> Result<&'a str, DirectoryError> {
        match self.next()? {
            Some(Token::String(value)) if value.contains('\\') => {
                Err(DirectoryError::EscapedStringUnsupported)
            }
            Some(Token::String(value)) => Ok(value),
            _ => Err(DirectoryError::Malformed),
        }
    }
    fn endpoint(&mut self, origin: AcmeOrigin<'_>) -> Result<AcmeUrl, DirectoryError> {
        let value = AcmeUrl::parse(self.string()?, false)?;
        value.require_origin(origin)?;
        Ok(value)
    }
    fn object_fields(
        &mut self,
        mut field: impl FnMut(&mut Self, &'a str) -> Result<(), DirectoryError>,
    ) -> Result<(), DirectoryError> {
        match self.next()? {
            Some(Token::ObjectEnd) => return Ok(()),
            Some(token) => self.put_back(token),
            None => return Err(DirectoryError::Malformed),
        }
        loop {
            let name = self.string()?;
            self.expect(Token::Colon)?;
            field(self, name)?;
            match self.next()? {
                Some(Token::Comma) => {}
                Some(Token::ObjectEnd) => return Ok(()),
                _ => return Err(DirectoryError::Malformed),
            }
        }
    }
    fn metadata(&mut self, output: &mut Metadata, generation: u64) -> Result<(), DirectoryError> {
        self.expect(Token::ObjectStart)?;
        let mut seen = 0u8;
        self.object_fields(|parser, name| {
            let bit = match name {
                "termsOfService" => Some(1),
                "externalAccountRequired" => Some(2),
                "profiles" => Some(4),
                "caaIdentities" => Some(8),
                _ => None,
            };
            if let Some(bit) = bit {
                if seen & bit != 0 {
                    return Err(DirectoryError::DuplicateField);
                }
                seen |= bit;
            }
            match name {
                "termsOfService" => {
                    output.terms_of_service = Some(AcmeUrl::parse(parser.string()?, false)?)
                }
                "externalAccountRequired" => {
                    output.external_account_required = match parser.next()? {
                        Some(Token::Bool(value)) => value,
                        _ => return Err(DirectoryError::Malformed),
                    }
                }
                "profiles" => parser.profiles(output, generation)?,
                "caaIdentities" => parser.caa_identities(output)?,
                _ => parser.skip_value(2)?,
            }
            Ok(())
        })
    }
    fn profiles(&mut self, output: &mut Metadata, generation: u64) -> Result<(), DirectoryError> {
        self.expect(Token::ObjectStart)?;
        self.object_fields(|parser, name| {
            if usize::from(output.profile_count) >= MAX_DIRECTORY_PROFILES {
                return Err(DirectoryError::TooManyProfiles);
            }
            if output.profiles[..usize::from(output.profile_count)]
                .iter()
                .flatten()
                .any(|item| item.profile.name() == name)
            {
                return Err(DirectoryError::DuplicateField);
            }
            let profile = CertificateProfile::parse(name, generation)?;
            let description = AcmeUrl::parse(parser.string()?, false)?;
            output.profiles[usize::from(output.profile_count)] = Some(ProfileAdvertisement {
                profile,
                description,
            });
            output.profile_count += 1;
            Ok(())
        })
    }
    fn caa_identities(&mut self, output: &mut Metadata) -> Result<(), DirectoryError> {
        self.expect(Token::ArrayStart)?;
        match self.next()? {
            Some(Token::ArrayEnd) => return Ok(()),
            Some(token) => self.put_back(token),
            None => return Err(DirectoryError::Malformed),
        }
        loop {
            if usize::from(output.caa_count) >= MAX_CAA_IDENTITIES {
                return Err(DirectoryError::TooManyCaaIdentities);
            }
            let identity = DnsIdentifier::parse(self.string()?, false)
                .map_err(|_| DirectoryError::InvalidCaaIdentity)?;
            if output.caa_identities[..usize::from(output.caa_count)]
                .iter()
                .flatten()
                .any(|existing| existing == &identity)
            {
                return Err(DirectoryError::DuplicateField);
            }
            output.caa_identities[usize::from(output.caa_count)] = Some(identity);
            output.caa_count += 1;
            match self.next()? {
                Some(Token::Comma) => {}
                Some(Token::ArrayEnd) => return Ok(()),
                _ => return Err(DirectoryError::Malformed),
            }
        }
    }
    fn skip_value(&mut self, depth: usize) -> Result<(), DirectoryError> {
        if depth > MAX_JSON_DEPTH {
            return Err(DirectoryError::TooComplex);
        }
        match self.next()?.ok_or(DirectoryError::Malformed)? {
            Token::ObjectStart => {
                match self.next()? {
                    Some(Token::ObjectEnd) => return Ok(()),
                    Some(token) => self.put_back(token),
                    None => return Err(DirectoryError::Malformed),
                }
                loop {
                    self.string()?;
                    self.expect(Token::Colon)?;
                    self.skip_value(depth + 1)?;
                    match self.next()? {
                        Some(Token::Comma) => {}
                        Some(Token::ObjectEnd) => break,
                        _ => return Err(DirectoryError::Malformed),
                    }
                }
                Ok(())
            }
            Token::ArrayStart => {
                match self.next()? {
                    Some(Token::ArrayEnd) => return Ok(()),
                    Some(token) => self.put_back(token),
                    None => return Err(DirectoryError::Malformed),
                }
                loop {
                    self.skip_value(depth + 1)?;
                    match self.next()? {
                        Some(Token::Comma) => {}
                        Some(Token::ArrayEnd) => break,
                        _ => return Err(DirectoryError::Malformed),
                    }
                }
                Ok(())
            }
            Token::String(value) if value.contains('\\') => {
                Err(DirectoryError::EscapedStringUnsupported)
            }
            Token::String(_) | Token::Number(_) | Token::Bool(_) | Token::Null => Ok(()),
            _ => Err(DirectoryError::Malformed),
        }
    }
    fn finish(&mut self) -> Result<(), DirectoryError> {
        if self.next()?.is_none() {
            Ok(())
        } else {
            Err(DirectoryError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn directory_url() -> AcmeUrl {
        AcmeUrl::parse("https://ca.example/directory", false).unwrap()
    }
    #[test]
    fn parses_exact_endpoints_ari_profiles_and_metadata() {
        let source = r#"{"newNonce":"https://ca.example/new-nonce","newAccount":"https://ca.example/new-account","newOrder":"https://ca.example/new-order","revokeCert":"https://ca.example/revoke","keyChange":"https://ca.example/key-change","renewalInfo":"https://ca.example/renewal-info","meta":{"termsOfService":"https://legal.example/terms","externalAccountRequired":true,"caaIdentities":["ca.example"],"profiles":{"classic":"https://docs.example/classic","shortlived":"https://docs.example/short"}}}"#;
        let directory = AcmeDirectory::parse(source, &directory_url(), 7).unwrap();
        assert_eq!(directory.generation, 7);
        assert!(directory.external_account_required);
        assert_eq!(directory.profiles().count(), 2);
        assert_eq!(
            directory.caa_identities().next().unwrap().as_str(),
            "ca.example"
        );
        assert_eq!(
            directory
                .profiles()
                .next()
                .unwrap()
                .profile
                .directory_generation(),
            7
        );
    }
    #[test]
    fn rejects_cross_origin_endpoints_duplicates_and_trailing_data() {
        let base = r#"{"newNonce":"https://evil.example/new-nonce","newAccount":"https://ca.example/new-account","newOrder":"https://ca.example/new-order","revokeCert":"https://ca.example/revoke","keyChange":"https://ca.example/key-change"}"#;
        assert!(matches!(
            AcmeDirectory::parse(base, &directory_url(), 1),
            Err(DirectoryError::EndpointPolicy)
        ));
        let duplicate = r#"{"newNonce":"https://ca.example/a","newNonce":"https://ca.example/b","newAccount":"https://ca.example/c","newOrder":"https://ca.example/d","revokeCert":"https://ca.example/e","keyChange":"https://ca.example/f"}"#;
        assert!(matches!(
            AcmeDirectory::parse(duplicate, &directory_url(), 1),
            Err(DirectoryError::DuplicateField)
        ));
        let trailing = r#"{"newNonce":"https://ca.example/a","newAccount":"https://ca.example/c","newOrder":"https://ca.example/d","revokeCert":"https://ca.example/e","keyChange":"https://ca.example/f"}null"#;
        assert!(AcmeDirectory::parse(trailing, &directory_url(), 1).is_err());
    }
}
