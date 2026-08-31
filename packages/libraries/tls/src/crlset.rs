use crate::Certificate;
use mrml_runtime::Vector;

const MAX_HEADER: usize = 256 * 1024;
const MAX_ISSUERS: usize = 1_000_000;
const MAX_SERIALS_PER_ISSUER: usize = 1_000_000;
const MAX_SERIAL: usize = 127;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrlSetError {
    Truncated,
    HeaderTooLarge,
    UnsupportedVersion,
    InvalidHeader,
    InvalidBody,
    TooManyEntries,
    Stale,
    Rollback,
    Allocation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrlSetResult {
    Good,
    Revoked,
    Unknown,
}

struct IssuerRevocations {
    spki_hash: [u8; 32],
    serials: Vector<Vector<u8>>,
}

/// A bounded Chromium CRLSet import. Authenticity belongs to the component
/// updater: callers must verify the signed CRX/component identity before parse.
/// A CRLSet `Unknown` result never establishes certificate validity.
pub struct CrlSet {
    sequence: u64,
    not_after: Option<u64>,
    blocked_spkis: Vector<[u8; 32]>,
    issuers: Vector<IssuerRevocations>,
}

impl CrlSet {
    pub fn parse(bytes: &[u8], now: u64, minimum_sequence: u64) -> Result<Self, CrlSetError> {
        if bytes.len() < 2 {
            return Err(CrlSetError::Truncated);
        }
        let header_len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        if header_len > MAX_HEADER {
            return Err(CrlSetError::HeaderTooLarge);
        }
        let body_at = 2usize
            .checked_add(header_len)
            .ok_or(CrlSetError::Truncated)?;
        let header = core::str::from_utf8(bytes.get(2..body_at).ok_or(CrlSetError::Truncated)?)
            .map_err(|_| CrlSetError::InvalidHeader)?;
        if json_u64(header, "Version")? != 0 || json_string(header, "ContentType")? != "CRLSet" {
            return Err(CrlSetError::UnsupportedVersion);
        }
        let sequence = json_u64(header, "Sequence")?;
        if sequence < minimum_sequence {
            return Err(CrlSetError::Rollback);
        }
        let not_after = json_optional_u64(header, "NotAfter")?;
        if not_after.is_some_and(|deadline| now > deadline) {
            return Err(CrlSetError::Stale);
        }
        let mut blocked_spkis = Vector::new();
        for encoded in json_string_array(header, "BlockedSPKIs")? {
            let decoded = decode_base64(encoded.as_bytes())?;
            let hash: [u8; 32] = decoded[..]
                .try_into()
                .map_err(|_| CrlSetError::InvalidHeader)?;
            blocked_spkis
                .try_push(hash)
                .map_err(|_| CrlSetError::Allocation)?;
        }
        let mut issuers = Vector::new();
        let mut at = body_at;
        while at < bytes.len() {
            if issuers.len() >= MAX_ISSUERS || bytes.len() - at < 36 {
                return Err(if issuers.len() >= MAX_ISSUERS {
                    CrlSetError::TooManyEntries
                } else {
                    CrlSetError::InvalidBody
                });
            }
            let spki_hash = bytes[at..at + 32]
                .try_into()
                .map_err(|_| CrlSetError::InvalidBody)?;
            at += 32;
            let count = u32::from_le_bytes(
                bytes[at..at + 4]
                    .try_into()
                    .map_err(|_| CrlSetError::InvalidBody)?,
            ) as usize;
            at += 4;
            if count > MAX_SERIALS_PER_ISSUER {
                return Err(CrlSetError::TooManyEntries);
            }
            let mut serials = Vector::new();
            for _ in 0..count {
                let length = *bytes.get(at).ok_or(CrlSetError::InvalidBody)? as usize;
                at += 1;
                if length == 0 || length > MAX_SERIAL {
                    return Err(CrlSetError::InvalidBody);
                }
                let serial = bytes.get(at..at + length).ok_or(CrlSetError::InvalidBody)?;
                at += length;
                let mut owned = Vector::new();
                owned
                    .try_extend_from_slice(serial)
                    .map_err(|_| CrlSetError::Allocation)?;
                serials
                    .try_push(owned)
                    .map_err(|_| CrlSetError::Allocation)?;
            }
            issuers
                .try_push(IssuerRevocations { spki_hash, serials })
                .map_err(|_| CrlSetError::Allocation)?;
        }
        Ok(Self {
            sequence,
            not_after,
            blocked_spkis,
            issuers,
        })
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn not_after(&self) -> Option<u64> {
        self.not_after
    }

    pub fn check(&self, certificate: &Certificate<'_>, issuer: &Certificate<'_>) -> CrlSetResult {
        if self.blocked_spkis.contains(&certificate.spki_sha256()) {
            return CrlSetResult::Revoked;
        }
        let issuer_hash = issuer.spki_sha256();
        let Some(entry) = self
            .issuers
            .iter()
            .find(|entry| entry.spki_hash == issuer_hash)
        else {
            return CrlSetResult::Unknown;
        };
        if entry
            .serials
            .iter()
            .any(|serial| &serial[..] == certificate.serial())
        {
            CrlSetResult::Revoked
        } else {
            CrlSetResult::Good
        }
    }

    pub fn check_chain(&self, chain: &[Certificate<'_>]) -> CrlSetResult {
        if chain
            .iter()
            .any(|certificate| self.blocked_spkis.contains(&certificate.spki_sha256()))
        {
            return CrlSetResult::Revoked;
        }
        let Some((leaf, rest)) = chain.split_first() else {
            return CrlSetResult::Unknown;
        };
        let Some(issuer) = rest.first() else {
            return CrlSetResult::Unknown;
        };
        self.check(leaf, issuer)
    }
}

fn field_value<'a>(json: &'a str, name: &str) -> Result<&'a str, CrlSetError> {
    let mut needle = mrml_runtime::Text::from("\"");
    needle.push_str(name);
    needle.push_str("\"");
    let start = json
        .find(needle.as_str())
        .ok_or(CrlSetError::InvalidHeader)?
        + needle.len();
    let rest = json[start..].trim_start();
    let rest = rest
        .strip_prefix(':')
        .ok_or(CrlSetError::InvalidHeader)?
        .trim_start();
    Ok(rest)
}

fn json_u64(json: &str, name: &str) -> Result<u64, CrlSetError> {
    let value = field_value(json, name)?;
    let end = value
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    if end == 0 {
        return Err(CrlSetError::InvalidHeader);
    }
    value[..end].parse().map_err(|_| CrlSetError::InvalidHeader)
}

fn json_optional_u64(json: &str, name: &str) -> Result<Option<u64>, CrlSetError> {
    let needle = mrml_runtime::mrml_format!("\"{}\"", name);
    if !json.contains(needle.as_str()) {
        return Ok(None);
    }
    json_u64(json, name).map(Some)
}

fn json_string<'a>(json: &'a str, name: &str) -> Result<&'a str, CrlSetError> {
    let value = field_value(json, name)?;
    let value = value.strip_prefix('"').ok_or(CrlSetError::InvalidHeader)?;
    let end = value.find('"').ok_or(CrlSetError::InvalidHeader)?;
    if value[..end].contains('\\') {
        return Err(CrlSetError::InvalidHeader);
    }
    Ok(&value[..end])
}

fn json_string_array<'a>(json: &'a str, name: &str) -> Result<Vector<&'a str>, CrlSetError> {
    let needle = mrml_runtime::mrml_format!("\"{}\"", name);
    if !json.contains(needle.as_str()) {
        return Ok(Vector::new());
    }
    let mut value = field_value(json, name)?;
    value = value.strip_prefix('[').ok_or(CrlSetError::InvalidHeader)?;
    let end = value.find(']').ok_or(CrlSetError::InvalidHeader)?;
    value = &value[..end];
    let mut result = Vector::new();
    for item in value.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let item = item
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .ok_or(CrlSetError::InvalidHeader)?;
        if item.contains('\\') {
            return Err(CrlSetError::InvalidHeader);
        }
        result.try_push(item).map_err(|_| CrlSetError::Allocation)?;
    }
    Ok(result)
}

fn decode_base64(input: &[u8]) -> Result<Vector<u8>, CrlSetError> {
    if input.len() % 4 != 0 {
        return Err(CrlSetError::InvalidHeader);
    }
    let mut output = Vector::new();
    for chunk in input.chunks(4) {
        let mut values = [0u8; 4];
        let mut padding = 0;
        for (index, byte) in chunk.iter().copied().enumerate() {
            values[index] = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' if index >= 2 => {
                    padding += 1;
                    0
                }
                _ => return Err(CrlSetError::InvalidHeader),
            };
        }
        if padding > 2 || (padding != 0 && chunk[4 - padding..].iter().any(|b| *b != b'=')) {
            return Err(CrlSetError::InvalidHeader);
        }
        output
            .try_push((values[0] << 2) | (values[1] >> 4))
            .map_err(|_| CrlSetError::Allocation)?;
        if padding < 2 {
            output
                .try_push((values[1] << 4) | (values[2] >> 2))
                .map_err(|_| CrlSetError::Allocation)?;
        }
        if padding == 0 {
            output
                .try_push((values[2] << 6) | values[3])
                .map_err(|_| CrlSetError::Allocation)?;
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_stale_and_rollback_headers() {
        let header = br#"{"Version":0,"ContentType":"CRLSet","Sequence":7,"NotAfter":20}"#;
        let mut bytes = Vector::new();
        bytes
            .try_extend_from_slice(&(header.len() as u16).to_le_bytes())
            .unwrap();
        bytes.try_extend_from_slice(header).unwrap();
        assert!(matches!(
            CrlSet::parse(&bytes, 21, 7),
            Err(CrlSetError::Stale)
        ));
        assert!(matches!(
            CrlSet::parse(&bytes, 20, 8),
            Err(CrlSetError::Rollback)
        ));
        assert_eq!(CrlSet::parse(&bytes, 20, 7).unwrap().sequence(), 7);
    }

    #[test]
    fn rejects_unbounded_or_malformed_body() {
        let header = br#"{"Version":0,"ContentType":"CRLSet","Sequence":1}"#;
        let mut bytes = Vector::new();
        bytes
            .try_extend_from_slice(&(header.len() as u16).to_le_bytes())
            .unwrap();
        bytes.try_extend_from_slice(header).unwrap();
        bytes.push(0);
        assert!(matches!(
            CrlSet::parse(&bytes, 0, 0),
            Err(CrlSetError::InvalidBody)
        ));
    }
}
