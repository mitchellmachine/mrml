use mrml_acme::{CaClass, CertificateProfile, DnsIdentifier, P256Jwk};
use mrml_crypto::Sha256;

pub const MAX_CERTIFICATE_CHAIN_BYTES: usize = 65_536;
pub const MAX_CERTIFICATE_DER_BYTES: usize = 16_384;
pub const MAX_CERTIFICATES: usize = 8;
pub const MAX_IDENTITY_NAMES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateValidationError {
    Oversized,
    MalformedPem,
    InvalidBase64,
    TooManyCertificates,
    EmptyChain,
    InvalidPolicy,
    InvalidCertificate,
    PublicKeyMismatch,
    IdentifierMismatch,
    InvalidPurpose,
    InvalidValidity,
    UntrustedChain,
    StagingProductionMismatch,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Range {
    start: u16,
    len: u16,
}

pub struct PemCertificateChain {
    bytes: [u8; MAX_CERTIFICATE_CHAIN_BYTES],
    used: u16,
    ranges: [Option<Range>; MAX_CERTIFICATES],
    count: u8,
}

impl PemCertificateChain {
    pub fn parse(pem: &[u8]) -> Result<Self, CertificateValidationError> {
        if pem.len() > MAX_CERTIFICATE_CHAIN_BYTES {
            return Err(CertificateValidationError::Oversized);
        }
        let mut chain = Self {
            bytes: [0; MAX_CERTIFICATE_CHAIN_BYTES],
            used: 0,
            ranges: [None; MAX_CERTIFICATES],
            count: 0,
        };
        const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
        const END: &[u8] = b"-----END CERTIFICATE-----";
        let mut cursor = 0usize;
        while cursor < pem.len() {
            while pem.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                cursor += 1;
            }
            if cursor == pem.len() {
                break;
            }
            if pem.get(cursor..cursor + BEGIN.len()) != Some(BEGIN) {
                return Err(CertificateValidationError::MalformedPem);
            }
            cursor += BEGIN.len();
            let end = find_bytes(&pem[cursor..], END)
                .map(|offset| cursor + offset)
                .ok_or(CertificateValidationError::MalformedPem)?;
            if usize::from(chain.count) >= MAX_CERTIFICATES {
                return Err(CertificateValidationError::TooManyCertificates);
            }
            let start = usize::from(chain.used);
            let remaining = chain
                .bytes
                .get_mut(start..)
                .ok_or(CertificateValidationError::Oversized)?;
            let limit = remaining.len().min(MAX_CERTIFICATE_DER_BYTES);
            let written = decode_pem_base64(&pem[cursor..end], &mut remaining[..limit])?;
            if written == 0 || written > MAX_CERTIFICATE_DER_BYTES {
                return Err(CertificateValidationError::MalformedPem);
            }
            chain.ranges[usize::from(chain.count)] = Some(Range {
                start: start as u16,
                len: written as u16,
            });
            chain.count += 1;
            chain.used = chain
                .used
                .checked_add(written as u16)
                .ok_or(CertificateValidationError::Oversized)?;
            cursor = end + END.len();
        }
        if chain.count == 0 {
            return Err(CertificateValidationError::EmptyChain);
        }
        Ok(chain)
    }

    pub fn count(&self) -> usize {
        usize::from(self.count)
    }

    pub fn certificate(&self, index: usize) -> Option<&[u8]> {
        let range = self.ranges.get(index).copied().flatten()?;
        self.bytes
            .get(usize::from(range.start)..usize::from(range.start) + usize::from(range.len))
    }

    pub fn chain_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"mrml-certificate-chain-v1\0");
        for index in 0..self.count() {
            let certificate = self.certificate(index).unwrap_or(&[]);
            digest.update(&(certificate.len() as u32).to_be_bytes());
            digest.update(certificate);
        }
        digest.finalize()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CertificateValidationPolicy {
    pub policy_generation: u64,
    pub ca_class: CaClass,
    pub profile: CertificateProfile,
    pub order_url_digest: [u8; 32],
    pub expected_key: P256Jwk,
    pub identifiers: [Option<DnsIdentifier>; MAX_IDENTITY_NAMES],
    pub identifier_count: u8,
    pub now_unix: u64,
    pub maximum_validity_seconds: u64,
    pub maximum_chain_length: u8,
    pub trust_store_digest: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct VerifiedCertificateReceipt {
    pub policy_generation: u64,
    pub ca_class: CaClass,
    pub profile: CertificateProfile,
    pub order_url_digest: [u8; 32],
    pub chain_digest: [u8; 32],
    pub leaf_spki_digest: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub trust_store_digest: [u8; 32],
}

pub trait CertificateChainVerifier {
    fn verify(
        &mut self,
        chain: &PemCertificateChain,
        policy: &CertificateValidationPolicy,
    ) -> Result<VerifiedCertificateReceipt, CertificateValidationError>;
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub struct HostedCertificateChainVerifier<'a> {
    pub ca_class: CaClass,
    pub trust_store_digest: [u8; 32],
    pub approved_roots: &'a [&'a [u8]],
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl CertificateChainVerifier for HostedCertificateChainVerifier<'_> {
    fn verify(
        &mut self,
        chain: &PemCertificateChain,
        policy: &CertificateValidationPolicy,
    ) -> Result<VerifiedCertificateReceipt, CertificateValidationError> {
        if policy.ca_class != self.ca_class || policy.trust_store_digest != self.trust_store_digest
        {
            return Err(CertificateValidationError::StagingProductionMismatch);
        }
        if policy.identifier_count == 0
            || usize::from(policy.identifier_count) > MAX_IDENTITY_NAMES
            || policy.maximum_chain_length == 0
            || chain.count() > usize::from(policy.maximum_chain_length)
        {
            return Err(CertificateValidationError::InvalidPolicy);
        }
        let leaf_der = chain
            .certificate(0)
            .ok_or(CertificateValidationError::EmptyChain)?;
        let leaf = mrml_tls::Certificate::parse(leaf_der)
            .map_err(|_| CertificateValidationError::InvalidCertificate)?;
        leaf.require_server_auth()
            .map_err(|_| CertificateValidationError::InvalidPurpose)?;
        leaf.verify_time(policy.now_unix)
            .map_err(|_| CertificateValidationError::InvalidValidity)?;
        if leaf.not_after().saturating_sub(leaf.not_before()) > policy.maximum_validity_seconds {
            return Err(CertificateValidationError::InvalidValidity);
        }
        leaf.require_p256_public_key(&policy.expected_key.sec1_uncompressed())
            .map_err(|_| CertificateValidationError::PublicKeyMismatch)?;
        let mut names = [""; MAX_IDENTITY_NAMES];
        for (index, identifier) in policy.identifiers[..usize::from(policy.identifier_count)]
            .iter()
            .enumerate()
        {
            names[index] = identifier
                .as_ref()
                .ok_or(CertificateValidationError::InvalidPolicy)?
                .as_str();
        }
        for pair in names[..usize::from(policy.identifier_count)].windows(2) {
            if pair[0] >= pair[1] {
                return Err(CertificateValidationError::InvalidPolicy);
            }
        }
        leaf.require_exact_dns_names(&names[..usize::from(policy.identifier_count)])
            .map_err(|_| CertificateValidationError::IdentifierMismatch)?;
        let mut chain_refs = [&[][..]; MAX_CERTIFICATES];
        for (index, slot) in chain_refs.iter_mut().enumerate().take(chain.count()) {
            *slot = chain
                .certificate(index)
                .ok_or(CertificateValidationError::InvalidCertificate)?;
        }
        mrml_tls::verify_server_chain_at(
            &chain_refs[..chain.count()],
            self.approved_roots,
            policy.now_unix,
            usize::from(policy.maximum_chain_length),
        )
        .map_err(|_| CertificateValidationError::UntrustedChain)?;
        Ok(VerifiedCertificateReceipt {
            policy_generation: policy.policy_generation,
            ca_class: policy.ca_class,
            profile: policy.profile,
            order_url_digest: policy.order_url_digest,
            chain_digest: chain.chain_digest(),
            leaf_spki_digest: leaf.spki_sha256(),
            not_before: leaf.not_before(),
            not_after: leaf.not_after(),
            trust_store_digest: policy.trust_store_digest,
        })
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn decode_pem_base64(input: &[u8], output: &mut [u8]) -> Result<usize, CertificateValidationError> {
    let mut quartet = [0u8; 4];
    let mut used = 0usize;
    let mut written = 0usize;
    let mut ended = false;
    for byte in input.iter().copied() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if ended {
            return Err(CertificateValidationError::InvalidBase64);
        }
        quartet[used] = byte;
        used += 1;
        if used == 4 {
            let a = pem_value(quartet[0]).ok_or(CertificateValidationError::InvalidBase64)?;
            let b = pem_value(quartet[1]).ok_or(CertificateValidationError::InvalidBase64)?;
            let padding = usize::from(quartet[2] == b'=') + usize::from(quartet[3] == b'=');
            if padding > 2 || (quartet[2] == b'=' && quartet[3] != b'=') {
                return Err(CertificateValidationError::InvalidBase64);
            }
            let c = if quartet[2] == b'=' {
                0
            } else {
                pem_value(quartet[2]).ok_or(CertificateValidationError::InvalidBase64)?
            };
            let d = if quartet[3] == b'=' {
                0
            } else {
                pem_value(quartet[3]).ok_or(CertificateValidationError::InvalidBase64)?
            };
            if (padding == 2 && b & 0x0f != 0) || (padding == 1 && c & 0x03 != 0) {
                return Err(CertificateValidationError::InvalidBase64);
            }
            let value =
                (u32::from(a) << 18) | (u32::from(b) << 12) | (u32::from(c) << 6) | u32::from(d);
            for shift in [16, 8, 0].into_iter().take(3 - padding) {
                *output
                    .get_mut(written)
                    .ok_or(CertificateValidationError::Oversized)? = (value >> shift) as u8;
                written += 1;
            }
            ended = padding != 0;
            used = 0;
        }
    }
    if used != 0 {
        return Err(CertificateValidationError::InvalidBase64);
    }
    Ok(written)
}

fn pem_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pem_chain_is_bounded_strict_and_digest_ordered() {
        let chain=PemCertificateChain::parse(b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBAUG\n-----END CERTIFICATE-----\n").unwrap();
        assert_eq!(chain.count(), 2);
        assert_eq!(chain.certificate(0), Some(&[1, 2, 3][..]));
        assert_ne!(chain.chain_digest(), [0; 32]);
        assert!(
            PemCertificateChain::parse(
                b"-----BEGIN CERTIFICATE-----\nAQI=AAAA\n-----END CERTIFICATE-----"
            )
            .is_err()
        );
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn independently_generated_chain_binds_key_names_purpose_and_root() {
        let chain =
            PemCertificateChain::parse(include_bytes!("../tests/fixtures/pkix-leaf.pem")).unwrap();
        let root =
            PemCertificateChain::parse(include_bytes!("../tests/fixtures/pkix-root.pem")).unwrap();
        let root_der = root.certificate(0).unwrap();
        let leaf = mrml_tls::Certificate::parse(chain.certificate(0).unwrap()).unwrap();
        let mut identifiers = [None; MAX_IDENTITY_NAMES];
        identifiers[0] = Some(DnsIdentifier::parse("git.example", false).unwrap());
        identifiers[1] = Some(DnsIdentifier::parse("raw.example", false).unwrap());
        let key = P256Jwk::from_coordinates(
            [
                0x83, 0x28, 0x77, 0xd9, 0x3d, 0x62, 0x0b, 0x0e, 0xec, 0x22, 0x03, 0xcd, 0x56, 0x95,
                0x78, 0xb9, 0x34, 0xeb, 0xb3, 0xb7, 0x80, 0xbc, 0xe0, 0x4a, 0x8a, 0xff, 0xef, 0x63,
                0xa1, 0x68, 0x10, 0xb0,
            ],
            [
                0xf6, 0x0c, 0xee, 0x38, 0xea, 0x5e, 0x9f, 0xb2, 0x8b, 0xbf, 0x73, 0xc3, 0xef, 0xae,
                0xd0, 0x86, 0xb2, 0xdf, 0x73, 0xce, 0x30, 0x15, 0x45, 0x14, 0xde, 0x2b, 0x43, 0xf9,
                0xe8, 0x56, 0x1a, 0xed,
            ],
        )
        .unwrap();
        let policy = CertificateValidationPolicy {
            policy_generation: 4,
            ca_class: CaClass::Staging,
            profile: CertificateProfile::parse("classic", 7).unwrap(),
            order_url_digest: [3; 32],
            expected_key: key,
            identifiers,
            identifier_count: 2,
            now_unix: leaf.not_before(),
            maximum_validity_seconds: 366 * 86_400,
            maximum_chain_length: 3,
            trust_store_digest: [5; 32],
        };
        let roots = [root_der];
        let mut verifier = HostedCertificateChainVerifier {
            ca_class: CaClass::Staging,
            trust_store_digest: [5; 32],
            approved_roots: &roots,
        };
        let receipt = verifier.verify(&chain, &policy).unwrap();
        assert_eq!(receipt.chain_digest, chain.chain_digest());
        let mut wrong = policy;
        wrong.ca_class = CaClass::Production;
        assert!(matches!(
            verifier.verify(&chain, &wrong),
            Err(CertificateValidationError::StagingProductionMismatch)
        ));
        wrong = policy;
        wrong.identifiers[1] = Some(DnsIdentifier::parse("wrong.example", false).unwrap());
        assert!(matches!(
            verifier.verify(&chain, &wrong),
            Err(CertificateValidationError::IdentifierMismatch)
        ));
    }
}
