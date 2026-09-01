use crate::{
    CertificateProfile, DnsIdentifier, MAX_CSR_BYTES, MAX_ORDER_IDENTIFIERS, encode_base64url,
};
use mrml_crypto::Sha256;

pub const MAX_ACCOUNT_CONTACTS: usize = 8;
pub const MAX_ACCOUNT_CONTACT_BYTES: usize = 512;
pub const MAX_ACME_PAYLOAD_BYTES: usize = 24 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadError {
    OutputTooSmall,
    EmptyIdentifiers,
    TooManyIdentifiers,
    UnsortedIdentifiers,
    DuplicateIdentifier,
    TooManyContacts,
    InvalidContact,
    InvalidReason,
    OversizedCertificate,
    InvalidReplacement,
}

struct Writer<'a> {
    output: &'a mut [u8],
    used: usize,
}

impl<'a> Writer<'a> {
    fn new(output: &'a mut [u8]) -> Result<Self, PayloadError> {
        if output.len() > MAX_ACME_PAYLOAD_BYTES {
            return Err(PayloadError::OutputTooSmall);
        }
        Ok(Self { output, used: 0 })
    }
    fn push(&mut self, value: &[u8]) -> Result<(), PayloadError> {
        let end = self
            .used
            .checked_add(value.len())
            .ok_or(PayloadError::OutputTooSmall)?;
        self.output
            .get_mut(self.used..end)
            .ok_or(PayloadError::OutputTooSmall)?
            .copy_from_slice(value);
        self.used = end;
        Ok(())
    }
    fn finish(self) -> &'a str {
        core::str::from_utf8(&self.output[..self.used]).unwrap_or("")
    }
}

fn safe_json_string(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii() && byte >= 0x20 && !matches!(byte, b'"' | b'\\'))
}

pub fn write_new_account_payload<'a>(
    contacts: &[&str],
    terms_agreed: bool,
    only_return_existing: bool,
    external_account_binding: Option<&str>,
    output: &'a mut [u8],
) -> Result<&'a str, PayloadError> {
    if contacts.len() > MAX_ACCOUNT_CONTACTS {
        return Err(PayloadError::TooManyContacts);
    }
    if contacts
        .iter()
        .any(|contact| !safe_json_string(contact, MAX_ACCOUNT_CONTACT_BYTES))
        || contacts
            .iter()
            .enumerate()
            .any(|(index, contact)| contacts[..index].contains(contact))
    {
        return Err(PayloadError::InvalidContact);
    }
    let mut writer = Writer::new(output)?;
    writer.push(b"{\"contact\":[")?;
    for (index, contact) in contacts.iter().enumerate() {
        if index != 0 {
            writer.push(b",")?;
        }
        writer.push(b"\"")?;
        writer.push(contact.as_bytes())?;
        writer.push(b"\"")?;
    }
    writer.push(if terms_agreed {
        b"],\"termsOfServiceAgreed\":true,\"onlyReturnExisting\":"
    } else {
        b"],\"termsOfServiceAgreed\":false,\"onlyReturnExisting\":"
    })?;
    writer.push(if only_return_existing {
        b"true"
    } else {
        b"false"
    })?;
    if let Some(binding) = external_account_binding {
        if binding.is_empty() || binding.len() > MAX_ACME_PAYLOAD_BYTES / 2 {
            return Err(PayloadError::InvalidContact);
        }
        writer.push(b",\"externalAccountBinding\":")?;
        writer.push(binding.as_bytes())?;
    }
    writer.push(b"}")?;
    Ok(writer.finish())
}

pub fn account_contacts_digest(contacts: &[&str]) -> Result<[u8; 32], PayloadError> {
    if contacts.len() > MAX_ACCOUNT_CONTACTS
        || contacts
            .iter()
            .any(|contact| !safe_json_string(contact, MAX_ACCOUNT_CONTACT_BYTES))
        || contacts
            .iter()
            .enumerate()
            .any(|(index, contact)| contacts[..index].contains(contact))
    {
        return Err(PayloadError::InvalidContact);
    }
    let mut digest = Sha256::new();
    digest.update(b"mrml-acme-account-contacts-v1\0");
    for contact in contacts {
        digest.update(&(contact.len() as u16).to_be_bytes());
        digest.update(contact.as_bytes());
    }
    Ok(digest.finalize())
}

pub fn write_account_contacts_payload<'a>(
    contacts: &[&str],
    output: &'a mut [u8],
) -> Result<&'a str, PayloadError> {
    if contacts.len() > MAX_ACCOUNT_CONTACTS
        || contacts
            .iter()
            .any(|contact| !safe_json_string(contact, MAX_ACCOUNT_CONTACT_BYTES))
        || contacts
            .iter()
            .enumerate()
            .any(|(index, contact)| contacts[..index].contains(contact))
    {
        return Err(PayloadError::InvalidContact);
    }
    let mut writer = Writer::new(output)?;
    writer.push(b"{\"contact\":[")?;
    for (index, contact) in contacts.iter().enumerate() {
        if index != 0 {
            writer.push(b",")?;
        }
        writer.push(b"\"")?;
        writer.push(contact.as_bytes())?;
        writer.push(b"\"")?;
    }
    writer.push(b"]}")?;
    Ok(writer.finish())
}

pub fn write_account_status_payload(active: bool, output: &mut [u8]) -> Result<&str, PayloadError> {
    let value = if active {
        b"{\"status\":\"valid\"}".as_slice()
    } else {
        b"{\"status\":\"deactivated\"}".as_slice()
    };
    output
        .get_mut(..value.len())
        .ok_or(PayloadError::OutputTooSmall)?
        .copy_from_slice(value);
    core::str::from_utf8(&output[..value.len()]).map_err(|_| PayloadError::OutputTooSmall)
}

pub fn write_terms_agreement_payload(output: &mut [u8]) -> Result<&str, PayloadError> {
    const VALUE: &[u8] = b"{\"termsOfServiceAgreed\":true}";
    output
        .get_mut(..VALUE.len())
        .ok_or(PayloadError::OutputTooSmall)?
        .copy_from_slice(VALUE);
    core::str::from_utf8(&output[..VALUE.len()]).map_err(|_| PayloadError::OutputTooSmall)
}

pub fn write_preauthorization_payload<'a>(
    identifier: &DnsIdentifier,
    output: &'a mut [u8],
) -> Result<&'a str, PayloadError> {
    let mut writer = Writer::new(output)?;
    writer.push(b"{\"identifier\":{\"type\":\"dns\",\"value\":\"")?;
    writer.push(identifier.as_str().as_bytes())?;
    writer.push(b"\"}}")?;
    Ok(writer.finish())
}

pub fn write_new_order_payload<'a>(
    identifiers: &[DnsIdentifier],
    profile: &CertificateProfile,
    replaces: Option<&str>,
    output: &'a mut [u8],
) -> Result<&'a str, PayloadError> {
    if identifiers.is_empty() {
        return Err(PayloadError::EmptyIdentifiers);
    }
    if identifiers.len() > MAX_ORDER_IDENTIFIERS {
        return Err(PayloadError::TooManyIdentifiers);
    }
    for pair in identifiers.windows(2) {
        match pair[0].as_str().cmp(pair[1].as_str()) {
            core::cmp::Ordering::Less => {}
            core::cmp::Ordering::Equal => return Err(PayloadError::DuplicateIdentifier),
            core::cmp::Ordering::Greater => return Err(PayloadError::UnsortedIdentifiers),
        }
    }
    if replaces.is_some_and(|value| !safe_json_string(value, 512)) {
        return Err(PayloadError::InvalidReplacement);
    }
    let mut writer = Writer::new(output)?;
    writer.push(b"{\"identifiers\":[")?;
    for (index, identifier) in identifiers.iter().enumerate() {
        if index != 0 {
            writer.push(b",")?;
        }
        writer.push(b"{\"type\":\"dns\",\"value\":\"")?;
        writer.push(identifier.as_str().as_bytes())?;
        writer.push(b"\"}")?;
    }
    writer.push(b"],\"profile\":\"")?;
    writer.push(profile.name().as_bytes())?;
    writer.push(b"\"")?;
    if let Some(replaces) = replaces {
        writer.push(b",\"replaces\":\"")?;
        writer.push(replaces.as_bytes())?;
        writer.push(b"\"")?;
    }
    writer.push(b"}")?;
    Ok(writer.finish())
}

pub fn write_finalize_payload<'a>(
    csr_der: &[u8],
    output: &'a mut [u8],
) -> Result<&'a str, PayloadError> {
    if csr_der.is_empty() || csr_der.len() > MAX_CSR_BYTES {
        return Err(PayloadError::OversizedCertificate);
    }
    let mut writer = Writer::new(output)?;
    writer.push(b"{\"csr\":\"")?;
    let start = writer.used;
    let encoded = encode_base64url(csr_der, &mut writer.output[start..])
        .map_err(|_| PayloadError::OutputTooSmall)?;
    writer.used += encoded.len();
    writer.push(b"\"}")?;
    Ok(writer.finish())
}

pub fn write_revocation_payload<'a>(
    certificate_der: &[u8],
    reason: Option<u8>,
    output: &'a mut [u8],
) -> Result<&'a str, PayloadError> {
    if certificate_der.is_empty() || certificate_der.len() > 16 * 1024 {
        return Err(PayloadError::OversizedCertificate);
    }
    if reason.is_some_and(|reason| !matches!(reason, 0 | 1 | 3 | 4 | 5 | 6 | 8 | 9 | 10)) {
        return Err(PayloadError::InvalidReason);
    }
    let mut writer = Writer::new(output)?;
    writer.push(b"{\"certificate\":\"")?;
    let start = writer.used;
    let encoded = encode_base64url(certificate_der, &mut writer.output[start..])
        .map_err(|_| PayloadError::OutputTooSmall)?;
    writer.used += encoded.len();
    writer.push(b"\"")?;
    if let Some(reason) = reason {
        writer.push(b",\"reason\":")?;
        if reason == 10 {
            writer.push(b"10")?;
        } else {
            writer.push(&[b'0' + reason])?;
        }
    }
    writer.push(b"}")?;
    Ok(writer.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_and_order_payloads_are_deterministic_and_bounded() {
        let mut output = [0; 2048];
        assert_eq!(
            write_new_account_payload(
                &["mailto:owner@example.com"],
                true,
                false,
                None,
                &mut output
            )
            .unwrap(),
            r#"{"contact":["mailto:owner@example.com"],"termsOfServiceAgreed":true,"onlyReturnExisting":false}"#
        );
        let names = [
            DnsIdentifier::parse("api.example", false).unwrap(),
            DnsIdentifier::parse("git.example", false).unwrap(),
        ];
        let profile = CertificateProfile::parse("short-lived", 3).unwrap();
        assert_eq!(
            write_new_order_payload(&names, &profile, Some("ari-id"), &mut output).unwrap(),
            r#"{"identifiers":[{"type":"dns","value":"api.example"},{"type":"dns","value":"git.example"}],"profile":"short-lived","replaces":"ari-id"}"#
        );
        assert!(matches!(
            write_new_order_payload(&[names[1], names[0]], &profile, None, &mut output),
            Err(PayloadError::UnsortedIdentifiers)
        ));
    }

    #[test]
    fn finalization_and_revocation_use_unpadded_base64url() {
        let mut output = [0; 256];
        assert_eq!(
            write_finalize_payload(&[1, 2, 3], &mut output).unwrap(),
            r#"{"csr":"AQID"}"#
        );
        assert_eq!(
            write_revocation_payload(&[0xff, 0], Some(1), &mut output).unwrap(),
            r#"{"certificate":"_wA","reason":1}"#
        );
        assert!(matches!(
            write_revocation_payload(&[1], Some(2), &mut output),
            Err(PayloadError::InvalidReason)
        ));
        assert_eq!(
            write_preauthorization_payload(
                &DnsIdentifier::parse("git.example", false).unwrap(),
                &mut output,
            )
            .unwrap(),
            r#"{"identifier":{"type":"dns","value":"git.example"}}"#
        );
    }
}
