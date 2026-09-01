pub const MAX_URL_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UrlError {
    Empty,
    TooLong,
    HttpsRequired,
    CredentialsForbidden,
    FragmentForbidden,
    MissingHost,
    InvalidPort,
    OriginMismatch,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AcmeUrl {
    bytes: [u8; MAX_URL_BYTES],
    len: u16,
    host_start: u16,
    host_end: u16,
    port: u16,
    scheme: AcmeScheme,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmeScheme {
    Https,
    TestHttp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcmeOrigin<'a> {
    pub host: &'a str,
    pub port: u16,
    pub scheme: AcmeScheme,
}

impl AcmeUrl {
    pub fn parse(input: &str, allow_test_http: bool) -> Result<Self, UrlError> {
        if input.is_empty() {
            return Err(UrlError::Empty);
        }
        if input.len() > MAX_URL_BYTES {
            return Err(UrlError::TooLong);
        }
        if input.contains('#') {
            return Err(UrlError::FragmentForbidden);
        }
        let (authority_start, scheme) = if input.starts_with("https://") {
            (8, AcmeScheme::Https)
        } else if allow_test_http && input.starts_with("http://") {
            (7, AcmeScheme::TestHttp)
        } else {
            return Err(UrlError::HttpsRequired);
        };
        let authority_end = input[authority_start..]
            .find('/')
            .map(|n| authority_start + n)
            .unwrap_or(input.len());
        let authority = &input[authority_start..authority_end];
        if authority.is_empty() {
            return Err(UrlError::MissingHost);
        }
        if authority.contains('@') {
            return Err(UrlError::CredentialsForbidden);
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                let port = port.parse::<u16>().map_err(|_| UrlError::InvalidPort)?;
                if port == 0 {
                    return Err(UrlError::InvalidPort);
                }
                (host, port)
            }
            _ => (authority, if authority_start == 8 { 443 } else { 80 }),
        };
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err(UrlError::MissingHost);
        }
        let mut bytes = [0; MAX_URL_BYTES];
        bytes[..input.len()].copy_from_slice(input.as_bytes());
        Ok(Self {
            bytes,
            len: input.len() as u16,
            host_start: authority_start as u16,
            host_end: (authority_start + host.len()) as u16,
            port,
            scheme,
        })
    }
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("")
    }
    pub fn origin(&self) -> AcmeOrigin<'_> {
        AcmeOrigin {
            host: core::str::from_utf8(
                &self.bytes[usize::from(self.host_start)..usize::from(self.host_end)],
            )
            .unwrap_or(""),
            port: self.port,
            scheme: self.scheme,
        }
    }
    pub fn require_origin(&self, expected: AcmeOrigin<'_>) -> Result<(), UrlError> {
        let actual = self.origin();
        if actual.scheme == expected.scheme
            && actual.port == expected.port
            && actual.host.eq_ignore_ascii_case(expected.host)
        {
            Ok(())
        } else {
            Err(UrlError::OriginMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enforces_https_and_origin() {
        assert!(matches!(
            AcmeUrl::parse("http://ca.example/directory", false),
            Err(UrlError::HttpsRequired)
        ));
        let u = AcmeUrl::parse("https://ca.example/acme/new-order", false).unwrap();
        assert!(
            u.require_origin(AcmeOrigin {
                host: "CA.EXAMPLE",
                port: 443,
                scheme: AcmeScheme::Https,
            })
            .is_ok()
        );
        assert_eq!(
            u.require_origin(AcmeOrigin {
                host: "other.example",
                port: 443,
                scheme: AcmeScheme::Https,
            }),
            Err(UrlError::OriginMismatch)
        );
    }
    #[test]
    fn forbids_url_authority_confusion() {
        assert!(matches!(
            AcmeUrl::parse("https://owner@ca.example/x", false),
            Err(UrlError::CredentialsForbidden)
        ));
        assert!(matches!(
            AcmeUrl::parse("https://ca.example/x#y", false),
            Err(UrlError::FragmentForbidden)
        ));
        assert!(matches!(
            AcmeUrl::parse("https://ca.example:0/x", false),
            Err(UrlError::InvalidPort)
        ));
    }
}
