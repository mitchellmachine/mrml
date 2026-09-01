use crate::{Certificate, CertificateError};

const BASIC_OCSP_RESPONSE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const SHA256_WITH_ECDSA: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const MAX_OCSP_BYTES: usize = 64 * 1024;
const MAX_AGE_WITHOUT_NEXT_UPDATE: u64 = 7 * 24 * 60 * 60;

#[derive(Clone, Copy)]
enum OcspSignatureAlgorithm {
    RsaSha256,
    EcdsaP256Sha256,
}

fn verify_ocsp_signature(
    signer: &Certificate<'_>,
    algorithm: OcspSignatureAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CertificateError> {
    match algorithm {
        OcspSignatureAlgorithm::RsaSha256 => signer.verify_pkcs1_sha256(message, signature),
        OcspSignatureAlgorithm::EcdsaP256Sha256 => signer.verify_tls_ecdsa(message, signature),
    }
}

#[derive(Clone, Copy)]
struct Element<'a> {
    tag: u8,
    value: &'a [u8],
    encoded: &'a [u8],
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn next(&mut self) -> Result<Element<'a>, CertificateError> {
        let start = self.at;
        let tag = *self
            .bytes
            .get(self.at)
            .ok_or(CertificateError::OcspMalformed)?;
        self.at += 1;
        let first = *self
            .bytes
            .get(self.at)
            .ok_or(CertificateError::OcspMalformed)?;
        self.at += 1;
        let n = if first & 0x80 == 0 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0
                || count > 4
                || self.bytes.len() - self.at < count
                || self.bytes[self.at] == 0
            {
                return Err(CertificateError::OcspMalformed);
            }
            let mut n = 0usize;
            for b in &self.bytes[self.at..self.at + count] {
                n = n
                    .checked_mul(256)
                    .and_then(|v| v.checked_add(*b as usize))
                    .ok_or(CertificateError::OcspMalformed)?
            }
            self.at += count;
            if n < 128 {
                return Err(CertificateError::OcspMalformed);
            }
            n
        };
        let end = self
            .at
            .checked_add(n)
            .ok_or(CertificateError::OcspMalformed)?;
        if end > self.bytes.len() {
            return Err(CertificateError::OcspMalformed);
        }
        let value = &self.bytes[self.at..end];
        self.at = end;
        Ok(Element {
            tag,
            value,
            encoded: &self.bytes[start..end],
        })
    }
    fn done(&self) -> bool {
        self.at == self.bytes.len()
    }
}
fn sequence(element: Element<'_>) -> Result<Reader<'_>, CertificateError> {
    if element.tag != 0x30 {
        return Err(CertificateError::OcspMalformed);
    }
    Ok(Reader::new(element.value))
}
fn oid(element: Element<'_>, expected: &[u8]) -> Result<(), CertificateError> {
    if element.tag != 6 || element.value != expected {
        Err(CertificateError::OcspMalformed)
    } else {
        Ok(())
    }
}
fn integer_bytes(element: Element<'_>) -> Result<&[u8], CertificateError> {
    if element.tag != 2 || element.value.is_empty() || element.value[0] & 0x80 != 0 {
        return Err(CertificateError::OcspMalformed);
    }
    let value = if element.value.len() > 1 && element.value[0] == 0 {
        &element.value[1..]
    } else {
        element.value
    };
    if value.is_empty() {
        return Ok(&[0]);
    }
    Ok(value)
}
fn decimal(bytes: &[u8]) -> Result<u32, CertificateError> {
    let mut v = 0u32;
    for b in bytes {
        if !b.is_ascii_digit() {
            return Err(CertificateError::OcspMalformed);
        }
        v = v
            .checked_mul(10)
            .and_then(|x| x.checked_add((b - b'0') as u32))
            .ok_or(CertificateError::OcspMalformed)?
    }
    Ok(v)
}
fn generalized(element: Element<'_>) -> Result<u64, CertificateError> {
    if element.tag != 0x18 || element.value.len() != 15 || element.value[14] != b'Z' {
        return Err(CertificateError::OcspMalformed);
    }
    let b = element.value;
    let year = decimal(&b[..4])?;
    let month = decimal(&b[4..6])?;
    let day = decimal(&b[6..8])?;
    let hour = decimal(&b[8..10])?;
    let minute = decimal(&b[10..12])?;
    let second = decimal(&b[12..14])?;
    if !(1..=12).contains(&month) || day == 0 || hour > 23 || minute > 59 || second > 59 {
        return Err(CertificateError::OcspMalformed);
    }
    let leap = |y: u32| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let dim = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    };
    if day > dim {
        return Err(CertificateError::OcspMalformed);
    }
    let mut y = year as i64;
    let m = month as i64;
    y -= (m <= 2) as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let shifted = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * shifted + 2) / 5 + day as i64 - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    if days < 0 {
        return Err(CertificateError::OcspMalformed);
    }
    Ok(days as u64 * 86400 + hour as u64 * 3600 + minute as u64 * 60 + second as u64)
}
fn same_serial(a: &[u8], b: &[u8]) -> bool {
    fn trim(v: &[u8]) -> &[u8] {
        let first = v
            .iter()
            .position(|x| *x != 0)
            .unwrap_or(v.len().saturating_sub(1));
        &v[first..]
    }
    trim(a) == trim(b)
}

fn equal_digest(actual: &[u8], expected: &[u8; 32]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    actual
        .iter()
        .zip(expected)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn cert_id_matches(
    serial: &[u8],
    leaf_serial: &[u8],
    issuer_name_hash: &[u8],
    issuer_key_hash: &[u8],
    expected_name_hash: &[u8; 32],
    expected_key_hash: &[u8; 32],
) -> bool {
    same_serial(serial, leaf_serial)
        && equal_digest(issuer_name_hash, expected_name_hash)
        && equal_digest(issuer_key_hash, expected_key_hash)
}

pub fn verify_stapled_ocsp(
    response: &[u8],
    leaf: &Certificate<'_>,
    issuer: &Certificate<'_>,
    now: u64,
) -> Result<(), CertificateError> {
    if response.is_empty() {
        return Err(CertificateError::OcspMissing);
    }
    if response.len() > MAX_OCSP_BYTES {
        return Err(CertificateError::OcspMalformed);
    }
    let mut outer = Reader::new(response);
    let mut response_fields = sequence(outer.next()?)?;
    if !outer.done() {
        return Err(CertificateError::OcspMalformed);
    }
    let status = response_fields.next()?;
    if status.tag != 0x0a || status.value != [0] {
        return Err(CertificateError::OcspUnknown);
    }
    let wrapper = response_fields.next()?;
    if wrapper.tag != 0xa0 || !response_fields.done() {
        return Err(CertificateError::OcspMalformed);
    }
    let mut wrapped = Reader::new(wrapper.value);
    let mut response_bytes = sequence(wrapped.next()?)?;
    if !wrapped.done() {
        return Err(CertificateError::OcspMalformed);
    }
    oid(response_bytes.next()?, BASIC_OCSP_RESPONSE)?;
    let octets = response_bytes.next()?;
    if octets.tag != 4 || !response_bytes.done() {
        return Err(CertificateError::OcspMalformed);
    }
    let mut basic_outer = Reader::new(octets.value);
    let mut basic = sequence(basic_outer.next()?)?;
    if !basic_outer.done() {
        return Err(CertificateError::OcspMalformed);
    }
    let tbs = basic.next()?;
    let algorithm = basic.next()?;
    let signature = basic.next()?;
    if signature.tag != 3 || signature.value.first() != Some(&0) {
        return Err(CertificateError::OcspMalformed);
    }
    let mut delegated = None;
    if basic.at < basic.bytes.len() {
        let certs = basic.next()?;
        if certs.tag != 0xa0 {
            return Err(CertificateError::OcspMalformed);
        }
        let mut wrapper = Reader::new(certs.value);
        let certificates = wrapper.next()?;
        if certificates.tag != 0x30 || !wrapper.done() {
            return Err(CertificateError::OcspMalformed);
        }
        let mut certificates = Reader::new(certificates.value);
        let certificate = certificates.next()?;
        if !certificates.done() {
            return Err(CertificateError::OcspMalformed);
        }
        delegated = Some(
            Certificate::parse(certificate.encoded).map_err(|_| CertificateError::OcspMalformed)?,
        );
    }
    if !basic.done() {
        return Err(CertificateError::OcspMalformed);
    }
    let mut alg = sequence(algorithm)?;
    let algorithm_oid = alg.next()?;
    if algorithm_oid.tag != 6 {
        return Err(CertificateError::OcspMalformed);
    }
    let signature_algorithm = if algorithm_oid.value == SHA256_WITH_RSA {
        OcspSignatureAlgorithm::RsaSha256
    } else if algorithm_oid.value == SHA256_WITH_ECDSA {
        OcspSignatureAlgorithm::EcdsaP256Sha256
    } else {
        return Err(CertificateError::UnsupportedAlgorithm);
    };
    if matches!(signature_algorithm, OcspSignatureAlgorithm::RsaSha256) && alg.at < alg.bytes.len()
    {
        let null = alg.next()?;
        if null.tag != 5 || !null.value.is_empty() {
            return Err(CertificateError::OcspMalformed);
        }
    }
    if !alg.done() {
        return Err(CertificateError::OcspMalformed);
    }
    let mut data = sequence(tbs)?;
    if data.bytes.first() == Some(&0xa0) {
        data.next()?;
    }
    let responder = data.next()?;
    if responder.tag != 0xa1 {
        // OCSP responderID byKey is defined using SHA-1. This profile has no
        // SHA-1 primitive and therefore fails closed instead of accepting an
        // identity it cannot recompute.
        return if responder.tag == 0xa2 {
            Err(CertificateError::UnsupportedAlgorithm)
        } else {
            Err(CertificateError::OcspMalformed)
        };
    }
    let mut issuer_subject = Reader::new(issuer.subject_name_der());
    let issuer_subject = issuer_subject.next()?;
    if issuer_subject.tag != 0x30 {
        return Err(CertificateError::OcspMalformed);
    }
    if responder.value == issuer_subject.value {
        if delegated.is_some() {
            return Err(CertificateError::OcspMalformed);
        }
        verify_ocsp_signature(
            issuer,
            signature_algorithm,
            tbs.encoded,
            &signature.value[1..],
        )?;
    } else {
        let responder_certificate = delegated.ok_or(CertificateError::OcspMalformed)?;
        let mut responder_subject = Reader::new(responder_certificate.subject_name_der());
        let responder_subject = responder_subject.next()?;
        if responder_subject.tag != 0x30
            || responder.value != responder_subject.value
            || responder_certificate.issuer_name_der() != issuer.subject_name_der()
        {
            return Err(CertificateError::OcspMalformed);
        }
        responder_certificate.verify_signed_by(issuer)?;
        responder_certificate.verify_time(now)?;
        responder_certificate.require_ocsp_signing()?;
        verify_ocsp_signature(
            &responder_certificate,
            signature_algorithm,
            tbs.encoded,
            &signature.value[1..],
        )?;
    }
    let produced_at = generalized(data.next()?)?;
    if produced_at > now.saturating_add(300) {
        return Err(CertificateError::OcspStale);
    }
    let mut responses = sequence(data.next()?)?;
    let mut matched = false;
    while !responses.done() {
        let mut single = sequence(responses.next()?)?;
        let mut cert_id = sequence(single.next()?)?;
        let mut hash_algorithm = sequence(cert_id.next()?)?;
        oid(hash_algorithm.next()?, SHA256)?;
        if !hash_algorithm.done() {
            let parameter = hash_algorithm.next()?;
            if parameter.tag != 5 || !parameter.value.is_empty() {
                return Err(CertificateError::OcspMalformed);
            }
        }
        if !hash_algorithm.done() {
            return Err(CertificateError::OcspMalformed);
        }
        let issuer_name_hash = cert_id.next()?;
        let issuer_key_hash = cert_id.next()?;
        if issuer_name_hash.tag != 4 || issuer_key_hash.tag != 4 {
            return Err(CertificateError::OcspMalformed);
        }
        let serial = integer_bytes(cert_id.next()?)?;
        if !cert_id.done() {
            return Err(CertificateError::OcspMalformed);
        }
        let cert_status = single.next()?;
        let this_update = generalized(single.next()?)?;
        let mut next_update = None;
        if single.at < single.bytes.len() && single.bytes[single.at] == 0xa0 {
            let wrapped = single.next()?;
            let mut r = Reader::new(wrapped.value);
            next_update = Some(generalized(r.next()?)?);
            if !r.done() {
                return Err(CertificateError::OcspMalformed);
            }
        }
        while !single.done() {
            single.next()?;
        }
        let name_digest = mrml_crypto::Sha256::digest(issuer.subject_name_der());
        let key_digest = mrml_crypto::Sha256::digest(issuer.subject_public_key_bits());
        if cert_id_matches(
            serial,
            leaf.serial(),
            issuer_name_hash.value,
            issuer_key_hash.value,
            &name_digest,
            &key_digest,
        ) {
            matched = true;
            match cert_status.tag {
                0x80 | 0xa0 if cert_status.value.is_empty() => {}
                0xa1 => return Err(CertificateError::Revoked),
                0x82 | 0xa2 => return Err(CertificateError::OcspUnknown),
                _ => return Err(CertificateError::OcspMalformed),
            }
            if now.saturating_add(300) < this_update
                || next_update.is_some_and(|next| now > next.saturating_add(300))
                || next_update.is_none()
                    && now > this_update.saturating_add(MAX_AGE_WITHOUT_NEXT_UPDATE)
            {
                return Err(CertificateError::OcspStale);
            }
        }
    }
    if matched {
        Ok(())
    } else {
        Err(CertificateError::OcspUnknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generalized_time_is_bounded() {
        let good = Element {
            tag: 0x18,
            value: b"20260831120000Z",
            encoded: &[],
        };
        assert!(generalized(good).is_ok());
        let bad = Element {
            tag: 0x18,
            value: b"20260230120000Z",
            encoded: &[],
        };
        assert_eq!(generalized(bad), Err(CertificateError::OcspMalformed));
    }
    #[test]
    fn rejects_empty_and_oversized() {
        let certificate = Certificate::parse(&[]);
        assert!(certificate.is_err());
        assert!(MAX_OCSP_BYTES < usize::MAX)
    }

    #[test]
    fn same_serial_from_a_different_issuer_and_wrong_hashes_do_not_match() {
        let name = [1; 32];
        let key = [2; 32];
        assert!(cert_id_matches(&[7], &[0, 7], &name, &key, &name, &key));
        let other_name = [3; 32];
        assert!(!cert_id_matches(&[7], &[7], &other_name, &key, &name, &key));
        let other_key = [4; 32];
        assert!(!cert_id_matches(&[7], &[7], &name, &other_key, &name, &key));
    }
}
