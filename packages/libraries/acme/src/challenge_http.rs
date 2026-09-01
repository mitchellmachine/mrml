use crate::{AcmeIdentifier, ChallengeToken, DnsIdentifier, MAX_DNS_NAME};

pub const MAX_HTTP01_REQUEST: usize = 4096;
pub const MAX_HTTP01_HEADERS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http01Error {
    Oversized,
    Malformed,
    WrongMethod,
    AmbiguousPath,
    MissingHost,
    DuplicateHost,
    WrongHost,
    WrongToken,
    TooManyHeaders,
}

pub fn validate_http01_request(
    request: &[u8],
    identifier: &DnsIdentifier,
    token: &ChallengeToken,
) -> Result<(), Http01Error> {
    validate_http01_identifier_request(request, &AcmeIdentifier::Dns(*identifier), token)
}

pub fn validate_http01_identifier_request(
    request: &[u8],
    identifier: &AcmeIdentifier,
    token: &ChallengeToken,
) -> Result<(), Http01Error> {
    if request.len() > MAX_HTTP01_REQUEST {
        return Err(Http01Error::Oversized);
    }
    let text = core::str::from_utf8(request).map_err(|_| Http01Error::Malformed)?;
    if !text.ends_with("\r\n\r\n") || text.contains('\0') {
        return Err(Http01Error::Malformed);
    }
    let mut lines = text[..text.len() - 2].split("\r\n");
    let line = lines.next().ok_or(Http01Error::Malformed)?;
    let mut parts = line.split(' ');
    if parts.next() != Some("GET") {
        return Err(Http01Error::WrongMethod);
    }
    let path = parts.next().ok_or(Http01Error::Malformed)?;
    if parts.next() != Some("HTTP/1.1") || parts.next().is_some() {
        return Err(Http01Error::Malformed);
    }
    if path.contains(['?', '#', '%']) || path.contains("//") {
        return Err(Http01Error::AmbiguousPath);
    }
    let supplied = path
        .strip_prefix("/.well-known/acme-challenge/")
        .ok_or(Http01Error::WrongToken)?;
    if !constant_time_equal(supplied.as_bytes(), token.as_str().as_bytes()) {
        return Err(Http01Error::WrongToken);
    }
    let mut host = None;
    let mut count = 0usize;
    for header in lines {
        if header.is_empty() {
            break;
        }
        count += 1;
        if count > MAX_HTTP01_HEADERS {
            return Err(Http01Error::TooManyHeaders);
        }
        let (name, value) = header.split_once(':').ok_or(Http01Error::Malformed)?;
        if name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return Err(Http01Error::DuplicateHost);
            }
            let value = value.trim();
            if value.contains('@') {
                return Err(Http01Error::WrongHost);
            }
            host = Some(value);
        }
    }
    let host = host.ok_or(Http01Error::MissingHost)?;
    let mut expected = [0u8; MAX_DNS_NAME];
    let expected = identifier
        .write_value(&mut expected)
        .map_err(|_| Http01Error::WrongHost)?;
    let matches = match identifier {
        AcmeIdentifier::Dns(_) => {
            host.eq_ignore_ascii_case(expected)
                || host
                    .strip_suffix(":80")
                    .is_some_and(|name| name.eq_ignore_ascii_case(expected))
        }
        AcmeIdentifier::Ip(identifier) if identifier.is_ipv4() => {
            host.eq_ignore_ascii_case(expected)
                || host
                    .strip_suffix(":80")
                    .is_some_and(|name| name.eq_ignore_ascii_case(expected))
        }
        AcmeIdentifier::Ip(identifier) if !identifier.is_ipv4() => {
            host.strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .is_some_and(|value| value.eq_ignore_ascii_case(expected))
                || host
                    .strip_prefix('[')
                    .and_then(|value| value.strip_suffix("]:80"))
                    .is_some_and(|value| value.eq_ignore_ascii_case(expected))
        }
        _ => false,
    };
    if !matches {
        return Err(Http01Error::WrongHost);
    }
    Ok(())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_exact_host_path_and_token() {
        let name = DnsIdentifier::parse("git.example", false).unwrap();
        let token = ChallengeToken::parse("abc_123").unwrap();
        assert_eq!(
            validate_http01_request(
                b"GET /.well-known/acme-challenge/abc_123 HTTP/1.1\r\nHost: git.example:80\r\n\r\n",
                &name,
                &token
            ),
            Ok(())
        );
        assert_eq!(
            validate_http01_request(
                b"GET /.well-known/acme-challenge/abc%5f123 HTTP/1.1\r\nHost: git.example\r\n\r\n",
                &name,
                &token
            ),
            Err(Http01Error::AmbiguousPath)
        );
        assert_eq!(
            validate_http01_request(
                b"GET /.well-known/acme-challenge/abc_123?x HTTP/1.1\r\nHost: git.example\r\n\r\n",
                &name,
                &token
            ),
            Err(Http01Error::AmbiguousPath)
        );
        assert_eq!(
            validate_http01_request(
                b"GET /.well-known/acme-challenge/abc_123 HTTP/1.1\r\nHost: other.example\r\n\r\n",
                &name,
                &token
            ),
            Err(Http01Error::WrongHost)
        );
    }

    #[test]
    fn ip_host_authority_is_exact_and_ipv6_is_bracketed() {
        let token = ChallengeToken::parse("abc_123").unwrap();
        let ipv4 = AcmeIdentifier::Ip(crate::IpIdentifier::parse("192.0.2.1").unwrap());
        assert!(
            validate_http01_identifier_request(
                b"GET /.well-known/acme-challenge/abc_123 HTTP/1.1\r\nHost: 192.0.2.1:80\r\n\r\n",
                &ipv4,
                &token,
            )
            .is_ok()
        );
        let ipv6 = AcmeIdentifier::Ip(crate::IpIdentifier::parse("2001:db8::1").unwrap());
        assert!(
            validate_http01_identifier_request(
                b"GET /.well-known/acme-challenge/abc_123 HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n",
                &ipv6,
                &token,
            )
            .is_ok()
        );
        assert!(
            validate_http01_identifier_request(
                b"GET /.well-known/acme-challenge/abc_123 HTTP/1.1\r\nHost: 2001:db8::1\r\n\r\n",
                &ipv6,
                &token,
            )
            .is_err()
        );
    }
}
