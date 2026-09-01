use crate::directory::{Token, Tokens};
use crate::{
    AcmeContentType, AcmeDirectory, AcmeExchange, AcmeHttpMethod, AcmeResponseType, AcmeTransport,
    AcmeTransportRequest, AcmeUrl, Base64UrlError, TransportError, encode_base64url,
};

pub const MAX_ARI_CERTIFICATE_ID: usize = 114;
pub const MAX_ARI_RESPONSE_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AriError {
    Reversed,
    Past,
    TooNarrow,
    Overflow,
    MissingAuthorityKeyIdentifier,
    InvalidSerial,
    OutputTooSmall,
    Malformed,
    DuplicateField,
    Oversized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AriFetchError<E> {
    NotAdvertised,
    DirectoryGenerationMismatch,
    UrlTooLong,
    Transport(TransportError<E>),
    RetryableStatus { status: u16, has_retry_after: bool },
    UnexpectedStatus,
    UnexpectedContentType,
    Encoding,
    Ari(AriError),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AriCertificateId {
    bytes: [u8; MAX_ARI_CERTIFICATE_ID],
    len: u8,
}
impl AriCertificateId {
    pub fn parse(source: &str) -> Result<Self, AriError> {
        let (authority, serial) = source.split_once('.').ok_or(AriError::Malformed)?;
        if authority.is_empty() || serial.is_empty() || serial.contains('.') {
            return Err(AriError::Malformed);
        }
        let mut authority_bytes = [0; 64];
        let authority_bytes = crate::decode_base64url(authority, &mut authority_bytes)
            .map_err(|_| AriError::Malformed)?;
        let mut serial_bytes = [0; 20];
        let serial_bytes =
            crate::decode_base64url(serial, &mut serial_bytes).map_err(|_| AriError::Malformed)?;
        let parsed = Self::derive(authority_bytes, serial_bytes)?;
        if parsed.as_str() != source {
            return Err(AriError::Malformed);
        }
        Ok(parsed)
    }

    pub fn derive(
        authority_key_identifier: &[u8],
        der_serial_contents: &[u8],
    ) -> Result<Self, AriError> {
        if authority_key_identifier.is_empty() || authority_key_identifier.len() > 64 {
            return Err(AriError::MissingAuthorityKeyIdentifier);
        }
        if der_serial_contents.is_empty() || der_serial_contents.len() > 20 {
            return Err(AriError::InvalidSerial);
        }
        let mut bytes = [0u8; MAX_ARI_CERTIFICATE_ID];
        let first = encode_base64url(authority_key_identifier, &mut bytes)
            .map_err(map_base64)?
            .len();
        bytes[first] = b'.';
        let second = encode_base64url(der_serial_contents, &mut bytes[first + 1..])
            .map_err(map_base64)?
            .len();
        Ok(Self {
            bytes,
            len: (first + 1 + second) as u8,
        })
    }
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("")
    }
}
fn map_base64(_: Base64UrlError) -> AriError {
    AriError::OutputTooSmall
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenewalInfo {
    pub suggested_window: RenewalWindow,
}
impl RenewalInfo {
    pub fn parse(source: &str, now: u64, minimum_width: u64) -> Result<Self, AriError> {
        if source.len() > MAX_ARI_RESPONSE_BYTES {
            return Err(AriError::Oversized);
        }
        let mut c = Cursor::new(source);
        c.expect(Token::ObjectStart)?;
        let mut window = None;
        let mut seen = false;
        match c.next()? {
            Some(Token::ObjectEnd) => {}
            Some(t) => c.back = Some(t),
            None => return Err(AriError::Malformed),
        }
        while c.back.is_some() {
            let key = c.string()?;
            c.expect(Token::Colon)?;
            if key == "suggestedWindow" {
                if seen {
                    return Err(AriError::DuplicateField);
                }
                seen = true;
                window = Some(parse_window(&mut c, now, minimum_width)?);
            } else {
                c.skip(1)?;
            }
            match c.next()? {
                Some(Token::Comma) => {
                    let t = c.next()?.ok_or(AriError::Malformed)?;
                    c.back = Some(t)
                }
                Some(Token::ObjectEnd) => break,
                _ => return Err(AriError::Malformed),
            }
        }
        if c.next()?.is_some() {
            return Err(AriError::Malformed);
        }
        Ok(Self {
            suggested_window: window.ok_or(AriError::Malformed)?,
        })
    }
}

pub fn fetch_renewal_info<T: AcmeTransport>(
    directory: &AcmeDirectory,
    certificate_id: &AriCertificateId,
    now: u64,
    minimum_width: u64,
    exchange: &mut AcmeExchange,
    transport: &mut T,
    response_body: &mut [u8],
) -> Result<RenewalInfo, AriFetchError<T::Error>> {
    if exchange.directory_generation() != directory.generation {
        return Err(AriFetchError::DirectoryGenerationMismatch);
    }
    let base = directory
        .renewal_info
        .as_ref()
        .ok_or(AriFetchError::NotAdvertised)?;
    let mut bytes = [0u8; crate::MAX_URL_BYTES];
    let separator = usize::from(!base.as_str().ends_with('/'));
    let length = base
        .as_str()
        .len()
        .checked_add(separator)
        .and_then(|value| value.checked_add(certificate_id.as_str().len()))
        .ok_or(AriFetchError::UrlTooLong)?;
    if length > bytes.len() {
        return Err(AriFetchError::UrlTooLong);
    }
    let base_length = base.as_str().len();
    bytes[..base_length].copy_from_slice(base.as_str().as_bytes());
    let mut at = base_length;
    if separator == 1 {
        bytes[at] = b'/';
        at += 1;
    }
    bytes[at..length].copy_from_slice(certificate_id.as_str().as_bytes());
    let text = core::str::from_utf8(&bytes[..length]).map_err(|_| AriFetchError::Encoding)?;
    let url = AcmeUrl::parse(text, false).map_err(|_| AriFetchError::UrlTooLong)?;
    url.require_origin(base.origin())
        .map_err(|_| AriFetchError::UrlTooLong)?;
    let metadata = exchange
        .execute(
            transport,
            AcmeTransportRequest {
                method: AcmeHttpMethod::Get,
                url: &url,
                content_type: AcmeContentType::Empty,
                body: &[],
            },
            response_body,
        )
        .map_err(AriFetchError::Transport)?;
    if matches!(metadata.status, 429 | 503) {
        return Err(AriFetchError::RetryableStatus {
            status: metadata.status,
            has_retry_after: metadata.has_retry_after,
        });
    }
    if metadata.status != 200 {
        return Err(AriFetchError::UnexpectedStatus);
    }
    if metadata.response_type != AcmeResponseType::Json {
        return Err(AriFetchError::UnexpectedContentType);
    }
    let response = core::str::from_utf8(&response_body[..metadata.body_length])
        .map_err(|_| AriFetchError::Encoding)?;
    RenewalInfo::parse(response, now, minimum_width).map_err(AriFetchError::Ari)
}

struct Cursor<'a> {
    tokens: Tokens<'a>,
    back: Option<Token<'a>>,
    count: u16,
}
impl<'a> Cursor<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            tokens: Tokens::new(s),
            back: None,
            count: 0,
        }
    }
    fn next(&mut self) -> Result<Option<Token<'a>>, AriError> {
        if let Some(t) = self.back.take() {
            return Ok(Some(t));
        }
        self.count = self.count.checked_add(1).ok_or(AriError::Overflow)?;
        if self.count > 128 {
            return Err(AriError::Oversized);
        }
        self.tokens
            .next()
            .transpose()
            .map_err(|_| AriError::Malformed)
    }
    fn expect(&mut self, t: Token<'a>) -> Result<(), AriError> {
        if self.next()? == Some(t) {
            Ok(())
        } else {
            Err(AriError::Malformed)
        }
    }
    fn string(&mut self) -> Result<&'a str, AriError> {
        match self.next()? {
            Some(Token::String(s)) if !s.contains('\\') => Ok(s),
            _ => Err(AriError::Malformed),
        }
    }
    fn skip(&mut self, depth: u8) -> Result<(), AriError> {
        if depth > 6 {
            return Err(AriError::Oversized);
        }
        match self.next()?.ok_or(AriError::Malformed)? {
            Token::ArrayStart => {
                match self.next()? {
                    Some(Token::ArrayEnd) => return Ok(()),
                    Some(t) => self.back = Some(t),
                    None => return Err(AriError::Malformed),
                }
                loop {
                    self.skip(depth + 1)?;
                    match self.next()? {
                        Some(Token::Comma) => {}
                        Some(Token::ArrayEnd) => break,
                        _ => return Err(AriError::Malformed),
                    }
                }
            }
            Token::ObjectStart => {
                match self.next()? {
                    Some(Token::ObjectEnd) => return Ok(()),
                    Some(t) => self.back = Some(t),
                    None => return Err(AriError::Malformed),
                }
                loop {
                    self.string()?;
                    self.expect(Token::Colon)?;
                    self.skip(depth + 1)?;
                    match self.next()? {
                        Some(Token::Comma) => {}
                        Some(Token::ObjectEnd) => break,
                        _ => return Err(AriError::Malformed),
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}
fn parse_window(c: &mut Cursor<'_>, now: u64, min: u64) -> Result<RenewalWindow, AriError> {
    c.expect(Token::ObjectStart)?;
    let mut start = None;
    let mut end = None;
    let mut seen = 0u8;
    match c.next()? {
        Some(Token::ObjectEnd) => return Err(AriError::Malformed),
        Some(t) => c.back = Some(t),
        None => return Err(AriError::Malformed),
    }
    loop {
        let key = c.string()?;
        c.expect(Token::Colon)?;
        let bit = match key {
            "start" => 1,
            "end" => 2,
            _ => 0,
        };
        if bit != 0 && seen & bit != 0 {
            return Err(AriError::DuplicateField);
        }
        seen |= bit;
        match key {
            "start" => start = Some(parse_rfc3339(c.string()?)?),
            "end" => end = Some(parse_rfc3339(c.string()?)?),
            _ => c.skip(1)?,
        }
        match c.next()? {
            Some(Token::Comma) => {}
            Some(Token::ObjectEnd) => break,
            _ => return Err(AriError::Malformed),
        }
    }
    RenewalWindow::validate(
        start.ok_or(AriError::Malformed)?,
        end.ok_or(AriError::Malformed)?,
        now,
        min,
    )
}
fn parse_rfc3339(value: &str) -> Result<u64, AriError> {
    let b = value.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return Err(AriError::Malformed);
    }
    fn n(b: &[u8]) -> Result<u32, AriError> {
        let mut v = 0u32;
        for x in b {
            if !x.is_ascii_digit() {
                return Err(AriError::Malformed);
            }
            v = v * 10 + u32::from(x - b'0');
        }
        Ok(v)
    }
    let year = n(&b[..4])?;
    let month = n(&b[5..7])?;
    let day = n(&b[8..10])?;
    let hour = n(&b[11..13])?;
    let minute = n(&b[14..16])?;
    let second = n(&b[17..19])?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(AriError::Malformed);
    }
    let mut y = i64::from(year);
    let m = i64::from(month);
    y -= i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let shifted = m + if m > 2 { -3 } else { 9 };
    let d =
        era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + (153 * shifted + 2) / 5 + i64::from(day)
            - 1
            - 719468;
    if d < 0 {
        return Err(AriError::Malformed);
    }
    Ok(d as u64 * 86400 + u64::from(hour) * 3600 + u64::from(minute) * 60 + u64::from(second))
}
fn days(y: u32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenewalWindow {
    pub start: u64,
    pub end: u64,
}
impl RenewalWindow {
    pub fn validate(start: u64, end: u64, now: u64, minimum_width: u64) -> Result<Self, AriError> {
        if end <= start {
            return Err(AriError::Reversed);
        }
        if end <= now {
            return Err(AriError::Past);
        }
        if end - start < minimum_width {
            return Err(AriError::TooNarrow);
        }
        Ok(Self {
            start: start.max(now),
            end,
        })
    }
    pub fn select(&self, random: u64) -> Result<u64, AriError> {
        let width = self.end.checked_sub(self.start).ok_or(AriError::Reversed)?;
        if width == 0 {
            return Err(AriError::TooNarrow);
        }
        Ok(self.start + (random % width))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeterministicAcmeAuthority, LOCAL_DIRECTORY_URL, LocalAuthorityFault, LocalJwsVerifier,
        P256Jwk,
    };
    #[test]
    fn rejects_bad_windows_and_selects_inside() {
        assert_eq!(
            RenewalWindow::validate(20, 10, 0, 1),
            Err(AriError::Reversed)
        );
        assert_eq!(RenewalWindow::validate(1, 2, 3, 1), Err(AriError::Past));
        let w = RenewalWindow::validate(10, 20, 12, 2).unwrap();
        assert_eq!(w.select(99), Ok(15));
    }
    #[test]
    fn rfc9773_identifier_preserves_der_serial_leading_zero() {
        let id = AriCertificateId::derive(
            &[
                0x69, 0x88, 0x5b, 0x6b, 0x87, 0x46, 0x40, 0x41, 0xe1, 0xb3, 0x7b, 0x84, 0x7b, 0xa0,
                0xae, 0x2c, 0xde, 0x01, 0xc8, 0xd4,
            ],
            &[0, 0x87, 0x65, 0x43, 0x21],
        )
        .unwrap();
        assert_eq!(id.as_str(), "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE");
    }

    #[test]
    fn certificate_identifier_round_trips_only_canonical_components() {
        let identifier = AriCertificateId::derive(&[1, 2, 3], &[0, 0x80]).unwrap();
        assert!(AriCertificateId::parse(identifier.as_str()).unwrap() == identifier);
        for malformed in ["", ".", "AQ..Ag", "AQ.Ag==", "AR.Ag"] {
            assert!(matches!(
                AriCertificateId::parse(malformed),
                Err(AriError::Malformed)
            ));
        }
    }
    #[test]
    fn parses_suggested_window_and_rejects_duplicates() {
        let info=RenewalInfo::parse(r#"{"suggestedWindow":{"start":"2026-09-02T00:00:00Z","end":"2026-09-03T00:00:00Z"},"explanationURL":"https://ca.example/why"}"#,0,60).unwrap();
        assert!(info.suggested_window.end > info.suggested_window.start);
        assert_eq!(
            RenewalInfo::parse(
                r#"{"suggestedWindow":{"start":"2026-09-02T00:00:00Z","start":"2026-09-03T00:00:00Z","end":"2026-09-04T00:00:00Z"}}"#,
                0,
                60
            ),
            Err(AriError::DuplicateField)
        );
    }

    struct Verifier;
    impl LocalJwsVerifier for Verifier {
        fn verify(&mut self, _: &P256Jwk, _: &[u8; 32], _: &[u8; 64]) -> bool {
            false
        }
    }
    #[test]
    fn fetches_certificate_specific_ari_from_current_directory_generation() {
        let directory_url = AcmeUrl::parse(LOCAL_DIRECTORY_URL, false).unwrap();
        let key = P256Jwk::from_coordinates(
            [
                0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
                0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
                0xd8, 0x98, 0xc2, 0x96,
            ],
            [
                0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
                0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
                0x37, 0xbf, 0x51, 0xf5,
            ],
        )
        .unwrap();
        let mut authority = DeterministicAcmeAuthority::new(Verifier, key);
        let mut exchange = AcmeExchange::new(7, directory_url);
        let mut response = [0u8; MAX_ARI_RESPONSE_BYTES];
        let directory = crate::fetch_directory(
            &directory_url,
            7,
            &mut exchange,
            &mut authority,
            &mut response,
        )
        .unwrap();
        let id = AriCertificateId::derive(
            &[
                0x92, 0x10, 0xe3, 0x57, 0xc1, 0x2d, 0x98, 0xb2, 0x1e, 0x56, 0x3b, 0xe7, 0xe9, 0x53,
                0xdf, 0xdd, 0xc7, 0xc3, 0x01, 0x15,
            ],
            &[2],
        )
        .unwrap();
        authority.inject(LocalAuthorityFault::RateLimitAriOnce);
        assert!(matches!(
            fetch_renewal_info(
                &directory,
                &id,
                0,
                86_400,
                &mut exchange,
                &mut authority,
                &mut response,
            ),
            Err(AriFetchError::RetryableStatus {
                status: 429,
                has_retry_after: true
            })
        ));
        let info = fetch_renewal_info(
            &directory,
            &id,
            0,
            86_400,
            &mut exchange,
            &mut authority,
            &mut response,
        )
        .unwrap();
        assert!(info.suggested_window.end > info.suggested_window.start);
        exchange.replace_directory(8, directory_url);
        assert!(matches!(
            fetch_renewal_info(
                &directory,
                &id,
                0,
                86_400,
                &mut exchange,
                &mut authority,
                &mut response,
            ),
            Err(AriFetchError::DirectoryGenerationMismatch)
        ));
    }
}
