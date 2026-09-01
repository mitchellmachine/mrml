use crate::{DnsIdentifier, Es256Signature, P256Jwk};
use mrml_crypto::{encode_der_signature, Sha256};

pub const MAX_CSR_BYTES: usize = 4096;
pub const MAX_CSR_IDENTIFIERS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CsrError {
    NoIdentifiers,
    TooManyIdentifiers,
    DuplicateOrUnsortedIdentifier,
    WildcardPolicyRequired,
    DerTooLarge,
    SigningUnavailable,
    InvalidSignature,
}

pub struct ApprovedCsrDigest {
    digest: [u8; 32],
    pub key_generation: u64,
    pub policy_generation: u64,
    pub identifier_set_digest: [u8; 32],
}

impl ApprovedCsrDigest {
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

pub trait Pkcs10Signer {
    fn sign_pkcs10(&mut self, approved: &ApprovedCsrDigest) -> Result<Es256Signature, CsrError>;
}

fn length_bytes(length: usize, out: &mut [u8; 3]) -> Result<usize, CsrError> {
    if length < 128 {
        out[0] = length as u8;
        Ok(1)
    } else if length <= u8::MAX as usize {
        out[..2].copy_from_slice(&[0x81, length as u8]);
        Ok(2)
    } else if length <= u16::MAX as usize {
        out[0] = 0x82;
        out[1..].copy_from_slice(&(length as u16).to_be_bytes());
        Ok(3)
    } else {
        Err(CsrError::DerTooLarge)
    }
}

fn tlv(tag: u8, content: &[u8], output: &mut [u8]) -> Result<usize, CsrError> {
    let mut encoded_length = [0u8; 3];
    let length_len = length_bytes(content.len(), &mut encoded_length)?;
    let total = 1usize
        .checked_add(length_len)
        .and_then(|value| value.checked_add(content.len()))
        .ok_or(CsrError::DerTooLarge)?;
    if output.len() < total {
        return Err(CsrError::DerTooLarge);
    }
    output[0] = tag;
    output[1..1 + length_len].copy_from_slice(&encoded_length[..length_len]);
    output[1 + length_len..total].copy_from_slice(content);
    Ok(total)
}

struct Bytes<'a> {
    output: &'a mut [u8],
    length: usize,
}

impl<'a> Bytes<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self { output, length: 0 }
    }
    fn push(&mut self, bytes: &[u8]) -> Result<(), CsrError> {
        let end = self
            .length
            .checked_add(bytes.len())
            .ok_or(CsrError::DerTooLarge)?;
        self.output
            .get_mut(self.length..end)
            .ok_or(CsrError::DerTooLarge)?
            .copy_from_slice(bytes);
        self.length = end;
        Ok(())
    }
    fn push_tlv(&mut self, tag: u8, content: &[u8]) -> Result<(), CsrError> {
        let written = tlv(tag, content, &mut self.output[self.length..])?;
        self.length += written;
        Ok(())
    }
    fn as_slice(&self) -> &[u8] {
        &self.output[..self.length]
    }
}

const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_EXTENSION_REQUEST: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e,
];
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
const OID_ECDSA_SHA256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

fn identifier_digest(identifiers: &[DnsIdentifier]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"mrml-acme-csr-identifiers-v1\0");
    for identifier in identifiers {
        digest.update(&(identifier.as_str().len() as u16).to_be_bytes());
        digest.update(identifier.as_str().as_bytes());
    }
    digest.finalize()
}

fn certification_request_info(
    key: &P256Jwk,
    identifiers: &[DnsIdentifier],
    wildcard_authorized: bool,
    output: &mut [u8],
) -> Result<usize, CsrError> {
    if identifiers.is_empty() {
        return Err(CsrError::NoIdentifiers);
    }
    if identifiers.len() > MAX_CSR_IDENTIFIERS {
        return Err(CsrError::TooManyIdentifiers);
    }
    for pair in identifiers.windows(2) {
        if pair[0].as_str() >= pair[1].as_str() {
            return Err(CsrError::DuplicateOrUnsortedIdentifier);
        }
    }
    if !wildcard_authorized && identifiers.iter().any(DnsIdentifier::is_wildcard) {
        return Err(CsrError::WildcardPolicyRequired);
    }

    let mut names_content = [0u8; 2048];
    let mut names = Bytes::new(&mut names_content);
    for identifier in identifiers {
        names.push_tlv(0x82, identifier.as_str().as_bytes())?;
    }
    let mut general_names = [0u8; 2100];
    let general_names_len = tlv(0x30, names.as_slice(), &mut general_names)?;
    let mut extension_content = [0u8; 2200];
    let mut extension = Bytes::new(&mut extension_content);
    extension.push(OID_SUBJECT_ALT_NAME)?;
    extension.push_tlv(0x04, &general_names[..general_names_len])?;
    let mut extension_sequence = [0u8; 2250];
    let extension_len = tlv(0x30, extension.as_slice(), &mut extension_sequence)?;
    let mut extensions = [0u8; 2300];
    let extensions_len = tlv(0x30, &extension_sequence[..extension_len], &mut extensions)?;
    let mut values = [0u8; 2350];
    let values_len = tlv(0x31, &extensions[..extensions_len], &mut values)?;
    let mut attribute_content = [0u8; 2400];
    let mut attribute = Bytes::new(&mut attribute_content);
    attribute.push(OID_EXTENSION_REQUEST)?;
    attribute.push(&values[..values_len])?;
    let mut attribute_sequence = [0u8; 2450];
    let attribute_len = tlv(0x30, attribute.as_slice(), &mut attribute_sequence)?;
    let mut attributes = [0u8; 2500];
    let attributes_len = tlv(0xa0, &attribute_sequence[..attribute_len], &mut attributes)?;

    let mut algorithm_content = [0u8; 32];
    let mut algorithm = Bytes::new(&mut algorithm_content);
    algorithm.push(OID_EC_PUBLIC_KEY)?;
    algorithm.push(OID_PRIME256V1)?;
    let mut algorithm_sequence = [0u8; 40];
    let algorithm_len = tlv(0x30, algorithm.as_slice(), &mut algorithm_sequence)?;
    let mut public_bit_string = [0u8; 66];
    public_bit_string[1..].copy_from_slice(&key.sec1_uncompressed());
    let mut spki_content = [0u8; 120];
    let mut spki = Bytes::new(&mut spki_content);
    spki.push(&algorithm_sequence[..algorithm_len])?;
    spki.push_tlv(0x03, &public_bit_string)?;
    let mut spki_sequence = [0u8; 128];
    let spki_len = tlv(0x30, spki.as_slice(), &mut spki_sequence)?;

    let mut cri_content = [0u8; MAX_CSR_BYTES];
    let mut cri = Bytes::new(&mut cri_content);
    cri.push(&[0x02, 0x01, 0x00])?;
    cri.push(&[0x30, 0x00])?;
    cri.push(&spki_sequence[..spki_len])?;
    cri.push(&attributes[..attributes_len])?;
    tlv(0x30, cri.as_slice(), output)
}

pub fn write_pkcs10_csr<'a>(
    key: &P256Jwk,
    identifiers: &[DnsIdentifier],
    wildcard_authorized: bool,
    key_generation: u64,
    policy_generation: u64,
    signer: &mut impl Pkcs10Signer,
    output: &'a mut [u8],
) -> Result<&'a [u8], CsrError> {
    let mut cri = [0u8; MAX_CSR_BYTES];
    let cri_len = certification_request_info(key, identifiers, wildcard_authorized, &mut cri)?;
    let approved = ApprovedCsrDigest {
        digest: Sha256::digest(&cri[..cri_len]),
        key_generation,
        policy_generation,
        identifier_set_digest: identifier_digest(identifiers),
    };
    let signature = signer.sign_pkcs10(&approved)?;
    let mut signature_der = [0u8; 72];
    let signature_der = encode_der_signature(signature.as_bytes(), &mut signature_der)
        .map_err(|_| CsrError::InvalidSignature)?;
    let mut signature_bits = [0u8; 73];
    signature_bits[1..1 + signature_der.len()].copy_from_slice(signature_der);
    let mut algorithm = [0u8; 16];
    let algorithm_len = tlv(0x30, OID_ECDSA_SHA256, &mut algorithm)?;
    let mut content = [0u8; MAX_CSR_BYTES];
    let mut csr = Bytes::new(&mut content);
    csr.push(&cri[..cri_len])?;
    csr.push(&algorithm[..algorithm_len])?;
    csr.push_tlv(0x03, &signature_bits[..1 + signature_der.len()])?;
    let total = tlv(0x30, csr.as_slice(), output)?;
    Ok(&output[..total])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JoseError;

    struct Signer;
    impl Pkcs10Signer for Signer {
        fn sign_pkcs10(
            &mut self,
            approved: &ApprovedCsrDigest,
        ) -> Result<Es256Signature, CsrError> {
            assert_ne!(approved.digest(), &[0; 32]);
            Es256Signature::from_raw([1; 64]).map_err(|_: JoseError| CsrError::InvalidSignature)
        }
    }

    fn generator() -> P256Jwk {
        P256Jwk::from_coordinates(
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
        .unwrap()
    }

    #[test]
    fn emits_bounded_csr_with_exact_san_names() {
        let names = [
            DnsIdentifier::parse("git.mrml.ca", false).unwrap(),
            DnsIdentifier::parse("raw.mrml.ca", false).unwrap(),
        ];
        let mut output = [0u8; MAX_CSR_BYTES];
        let csr =
            write_pkcs10_csr(&generator(), &names, false, 4, 9, &mut Signer, &mut output).unwrap();
        assert_eq!(csr[0], 0x30);
        assert!(csr
            .windows(b"git.mrml.ca".len())
            .any(|window| window == b"git.mrml.ca"));
        assert!(csr
            .windows(b"raw.mrml.ca".len())
            .any(|window| window == b"raw.mrml.ca"));
    }

    #[test]
    fn rejects_duplicates_unsorted_names_and_unapproved_wildcards() {
        let a = DnsIdentifier::parse("a.example", false).unwrap();
        let b = DnsIdentifier::parse("b.example", false).unwrap();
        let wildcard = DnsIdentifier::parse("*.example", true).unwrap();
        let mut output = [0u8; MAX_CSR_BYTES];
        assert!(matches!(
            write_pkcs10_csr(&generator(), &[b, a], false, 1, 1, &mut Signer, &mut output),
            Err(CsrError::DuplicateOrUnsortedIdentifier)
        ));
        assert!(matches!(
            write_pkcs10_csr(&generator(), &[a, a], false, 1, 1, &mut Signer, &mut output),
            Err(CsrError::DuplicateOrUnsortedIdentifier)
        ));
        assert!(matches!(
            write_pkcs10_csr(
                &generator(),
                &[wildcard],
                false,
                1,
                1,
                &mut Signer,
                &mut output
            ),
            Err(CsrError::WildcardPolicyRequired)
        ));
    }
}
