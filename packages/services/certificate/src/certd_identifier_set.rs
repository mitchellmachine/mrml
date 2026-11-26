use mrml_acme::DnsIdentifier;
use mrml_crypto::Sha256;

/// Reproduces the sealed certd policy binding on every platform. Callers
/// supply the same bounded, canonical identifier list used in the policy.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_certd_identifier_digest_matches_wire_golden() {
        let git = DnsIdentifier::parse("git.example", false).unwrap();
        let other = DnsIdentifier::parse("other.example", false).unwrap();
        let expected = [
            0xe2, 0x2e, 0x70, 0x19, 0xb3, 0xe3, 0xb5, 0xb5, 0x12, 0x46, 0x8c, 0x87, 0xd8, 0x32,
            0xf7, 0xcf, 0x56, 0xd1, 0x65, 0xa8, 0x08, 0x01, 0x94, 0x2a, 0x84, 0xc1, 0xef, 0x4e,
            0x06, 0x94, 0xe3, 0x66,
        ];
        assert_eq!(
            certd_identifier_set_digest(&[Some(git), Some(other)]),
            expected
        );
        assert_ne!(
            certd_identifier_set_digest(&[Some(other), Some(git)]),
            expected
        );
        assert_ne!(certd_identifier_set_digest(&[Some(git)]), expected);
    }
}
