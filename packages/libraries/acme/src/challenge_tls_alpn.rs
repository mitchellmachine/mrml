use crate::{DnsIdentifier, Es256Signature, P256Jwk};
use mrml_crypto::{Sha256, encode_der_signature};

pub const MAX_TLS_ALPN_CERTIFICATE: usize = 4096;
pub const ACME_TLS_ALPN_PROTOCOL: &[u8] = b"acme-tls/1";

const OID_ECDSA_SHA256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
const OID_ACME_IDENTIFIER: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsAlpnError {
    WildcardForbidden,
    InvalidValidity,
    InvalidSerial,
    DerTooLarge,
    SigningUnavailable,
    InvalidSignature,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsAlpnSelection {
    NotAcme,
    Challenge,
    Reject,
}

pub fn select_tls_alpn01(
    offered_protocols: &[&[u8]],
    sni: Option<&str>,
    active_identifier: Option<&DnsIdentifier>,
) -> TlsAlpnSelection {
    if !offered_protocols
        .iter()
        .any(|protocol| *protocol == ACME_TLS_ALPN_PROTOCOL)
    {
        return TlsAlpnSelection::NotAcme;
    }
    match (sni, active_identifier) {
        (Some(sni), Some(identifier)) if sni.eq_ignore_ascii_case(identifier.as_str()) => {
            TlsAlpnSelection::Challenge
        }
        _ => TlsAlpnSelection::Reject,
    }
}

pub struct ApprovedTlsAlpnCertificateDigest {
    digest: [u8; 32],
    pub challenge_generation: u64,
    pub key_generation: u64,
    pub key_authorization_digest: [u8; 32],
}

impl ApprovedTlsAlpnCertificateDigest {
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

pub trait TlsAlpnCertificateSigner {
    fn sign_tls_alpn_certificate(
        &mut self,
        approved: &ApprovedTlsAlpnCertificateDigest,
    ) -> Result<Es256Signature, TlsAlpnError>;
}

struct Writer<'a> {
    output: &'a mut [u8],
    len: usize,
}

impl<'a> Writer<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self { output, len: 0 }
    }
    fn push(&mut self, value: &[u8]) -> Result<(), TlsAlpnError> {
        let end = self
            .len
            .checked_add(value.len())
            .ok_or(TlsAlpnError::DerTooLarge)?;
        self.output
            .get_mut(self.len..end)
            .ok_or(TlsAlpnError::DerTooLarge)?
            .copy_from_slice(value);
        self.len = end;
        Ok(())
    }
    fn tlv(&mut self, tag: u8, value: &[u8]) -> Result<(), TlsAlpnError> {
        let mut length = [0u8; 3];
        let length_len = der_length(value.len(), &mut length)?;
        self.push(&[tag])?;
        self.push(&length[..length_len])?;
        self.push(value)
    }
    fn slice(&self) -> &[u8] {
        &self.output[..self.len]
    }
}

fn der_length(value: usize, output: &mut [u8; 3]) -> Result<usize, TlsAlpnError> {
    if value < 128 {
        output[0] = value as u8;
        Ok(1)
    } else if value <= usize::from(u8::MAX) {
        output[..2].copy_from_slice(&[0x81, value as u8]);
        Ok(2)
    } else if value <= usize::from(u16::MAX) {
        output[0] = 0x82;
        output[1..].copy_from_slice(&(value as u16).to_be_bytes());
        Ok(3)
    } else {
        Err(TlsAlpnError::DerTooLarge)
    }
}

fn wrap(tag: u8, value: &[u8], output: &mut [u8]) -> Result<usize, TlsAlpnError> {
    let mut writer = Writer::new(output);
    writer.tlv(tag, value)?;
    Ok(writer.len)
}

fn validate_time(value: &[u8; 15]) -> bool {
    value[0..14].iter().all(u8::is_ascii_digit) && value[14] == b'Z'
}

#[allow(clippy::too_many_arguments)]
pub fn write_tls_alpn01_certificate<'a>(
    key: &P256Jwk,
    identifier: &DnsIdentifier,
    key_authorization_digest: [u8; 32],
    serial: &[u8],
    not_before_generalized_time: &[u8; 15],
    not_after_generalized_time: &[u8; 15],
    challenge_generation: u64,
    key_generation: u64,
    signer: &mut impl TlsAlpnCertificateSigner,
    output: &'a mut [u8],
) -> Result<&'a [u8], TlsAlpnError> {
    if identifier.is_wildcard() {
        return Err(TlsAlpnError::WildcardForbidden);
    }
    if !validate_time(not_before_generalized_time)
        || !validate_time(not_after_generalized_time)
        || not_before_generalized_time >= not_after_generalized_time
    {
        return Err(TlsAlpnError::InvalidValidity);
    }
    if serial.is_empty() || serial.len() > 20 || serial[0] == 0 || serial[0] & 0x80 != 0 {
        return Err(TlsAlpnError::InvalidSerial);
    }

    let mut algorithm = [0u8; 24];
    let algorithm_len = wrap(0x30, OID_ECDSA_SHA256, &mut algorithm)?;

    let mut spki_algorithm_content = [0u8; 32];
    let mut spki_algorithm_writer = Writer::new(&mut spki_algorithm_content);
    spki_algorithm_writer.push(OID_EC_PUBLIC_KEY)?;
    spki_algorithm_writer.push(OID_PRIME256V1)?;
    let mut spki_algorithm = [0u8; 40];
    let spki_algorithm_len = wrap(0x30, spki_algorithm_writer.slice(), &mut spki_algorithm)?;
    let mut point = [0u8; 66];
    point[1..].copy_from_slice(&key.sec1_uncompressed());
    let mut spki_content = [0u8; 128];
    let mut spki_writer = Writer::new(&mut spki_content);
    spki_writer.push(&spki_algorithm[..spki_algorithm_len])?;
    spki_writer.tlv(0x03, &point)?;
    let mut spki = [0u8; 140];
    let spki_len = wrap(0x30, spki_writer.slice(), &mut spki)?;

    let mut san_names = [0u8; 260];
    let mut san_names_writer = Writer::new(&mut san_names);
    san_names_writer.tlv(0x82, identifier.as_str().as_bytes())?;
    let mut san_value = [0u8; 270];
    let san_value_len = wrap(0x30, san_names_writer.slice(), &mut san_value)?;
    let mut san_extension_content = [0u8; 320];
    let mut san_extension_writer = Writer::new(&mut san_extension_content);
    san_extension_writer.push(OID_SUBJECT_ALT_NAME)?;
    san_extension_writer.push(&[0x01, 0x01, 0xff])?;
    san_extension_writer.tlv(0x04, &san_value[..san_value_len])?;
    let mut san_extension = [0u8; 340];
    let san_extension_len = wrap(0x30, san_extension_writer.slice(), &mut san_extension)?;

    let mut acme_inner = [0u8; 40];
    let acme_inner_len = wrap(0x04, &key_authorization_digest, &mut acme_inner)?;
    let mut acme_extension_content = [0u8; 80];
    let mut acme_extension_writer = Writer::new(&mut acme_extension_content);
    acme_extension_writer.push(OID_ACME_IDENTIFIER)?;
    acme_extension_writer.push(&[0x01, 0x01, 0xff])?;
    acme_extension_writer.tlv(0x04, &acme_inner[..acme_inner_len])?;
    let mut acme_extension = [0u8; 100];
    let acme_extension_len = wrap(0x30, acme_extension_writer.slice(), &mut acme_extension)?;

    let mut extensions_content = [0u8; 512];
    let mut extensions_writer = Writer::new(&mut extensions_content);
    extensions_writer.push(&san_extension[..san_extension_len])?;
    extensions_writer.push(&acme_extension[..acme_extension_len])?;
    let mut extensions_sequence = [0u8; 540];
    let extensions_sequence_len = wrap(0x30, extensions_writer.slice(), &mut extensions_sequence)?;
    let mut extensions = [0u8; 560];
    let extensions_len = wrap(
        0xa3,
        &extensions_sequence[..extensions_sequence_len],
        &mut extensions,
    )?;

    let mut validity_content = [0u8; 40];
    let mut validity_writer = Writer::new(&mut validity_content);
    validity_writer.tlv(0x18, not_before_generalized_time)?;
    validity_writer.tlv(0x18, not_after_generalized_time)?;
    let mut validity = [0u8; 48];
    let validity_len = wrap(0x30, validity_writer.slice(), &mut validity)?;

    let mut tbs_content = [0u8; MAX_TLS_ALPN_CERTIFICATE];
    let mut tbs_writer = Writer::new(&mut tbs_content);
    tbs_writer.push(&[0xa0, 0x03, 0x02, 0x01, 0x02])?;
    tbs_writer.tlv(0x02, serial)?;
    tbs_writer.push(&algorithm[..algorithm_len])?;
    tbs_writer.push(&[0x30, 0x00])?;
    tbs_writer.push(&validity[..validity_len])?;
    tbs_writer.push(&[0x30, 0x00])?;
    tbs_writer.push(&spki[..spki_len])?;
    tbs_writer.push(&extensions[..extensions_len])?;
    let mut tbs = [0u8; MAX_TLS_ALPN_CERTIFICATE];
    let tbs_len = wrap(0x30, tbs_writer.slice(), &mut tbs)?;

    let approved = ApprovedTlsAlpnCertificateDigest {
        digest: Sha256::digest(&tbs[..tbs_len]),
        challenge_generation,
        key_generation,
        key_authorization_digest,
    };
    let signature = signer.sign_tls_alpn_certificate(&approved)?;
    let mut signature_der = [0u8; 72];
    let signature_der = encode_der_signature(signature.as_bytes(), &mut signature_der)
        .map_err(|_| TlsAlpnError::InvalidSignature)?;
    let mut signature_bits = [0u8; 73];
    signature_bits[1..1 + signature_der.len()].copy_from_slice(signature_der);
    let mut certificate_content = [0u8; MAX_TLS_ALPN_CERTIFICATE];
    let mut certificate_writer = Writer::new(&mut certificate_content);
    certificate_writer.push(&tbs[..tbs_len])?;
    certificate_writer.push(&algorithm[..algorithm_len])?;
    certificate_writer.tlv(0x03, &signature_bits[..signature_der.len() + 1])?;
    let certificate_len = wrap(0x30, certificate_writer.slice(), output)?;
    Ok(&output[..certificate_len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JoseError;
    struct Signer;
    impl TlsAlpnCertificateSigner for Signer {
        fn sign_tls_alpn_certificate(
            &mut self,
            approved: &ApprovedTlsAlpnCertificateDigest,
        ) -> Result<Es256Signature, TlsAlpnError> {
            assert_ne!(approved.digest(), &[0; 32]);
            Es256Signature::from_raw([1; 64]).map_err(|_: JoseError| TlsAlpnError::InvalidSignature)
        }
    }
    fn key() -> P256Jwk {
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
    fn emits_exact_critical_acme_identifier_and_san() {
        let mut output = [0u8; MAX_TLS_ALPN_CERTIFICATE];
        let cert = write_tls_alpn01_certificate(
            &key(),
            &DnsIdentifier::parse("git.example", false).unwrap(),
            [7; 32],
            &[1],
            b"20260901000000Z",
            b"20260901010000Z",
            3,
            4,
            &mut Signer,
            &mut output,
        )
        .unwrap();
        assert!(
            cert.windows(OID_ACME_IDENTIFIER.len())
                .any(|w| w == OID_ACME_IDENTIFIER)
        );
        assert!(
            cert.windows(b"git.example".len())
                .any(|w| w == b"git.example")
        );
        let mut encoded_digest = [7u8; 34];
        encoded_digest[..2].copy_from_slice(&[0x04, 0x20]);
        assert!(
            cert.windows(encoded_digest.len())
                .any(|w| w == encoded_digest)
        );
        assert!(cert.windows(3).filter(|w| *w == [0x01, 0x01, 0xff]).count() >= 2);
    }
    #[test]
    fn acme_alpn_never_falls_back_to_normal_identity() {
        let name = DnsIdentifier::parse("git.example", false).unwrap();
        assert_eq!(
            select_tls_alpn01(&[b"h2"], Some("git.example"), Some(&name)),
            TlsAlpnSelection::NotAcme
        );
        assert_eq!(
            select_tls_alpn01(&[ACME_TLS_ALPN_PROTOCOL], Some("git.example"), Some(&name)),
            TlsAlpnSelection::Challenge
        );
        assert_eq!(
            select_tls_alpn01(
                &[ACME_TLS_ALPN_PROTOCOL],
                Some("other.example"),
                Some(&name)
            ),
            TlsAlpnSelection::Reject
        );
        assert_eq!(
            select_tls_alpn01(&[ACME_TLS_ALPN_PROTOCOL], Some("git.example"), None),
            TlsAlpnSelection::Reject
        );
    }
}
