use mrml_acme::{DnsIdentifier, encode_base64url};
use mrml_crypto::Sha256;

pub const MAX_DNS01_RECORD_NAME_BYTES: usize = 253;
pub const DNS01_TXT_VALUE_BYTES: usize = 43;
pub const MAX_DNS01_PROVIDER_RECORD_ID_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dns01RecordName {
    bytes: [u8; MAX_DNS01_RECORD_NAME_BYTES],
    length: u8,
}

impl Dns01RecordName {
    pub fn for_identifier(identifier: DnsIdentifier) -> Result<Self, Dns01ProviderError> {
        let source = identifier
            .as_str()
            .strip_prefix("*.")
            .unwrap_or(identifier.as_str());
        let prefix = b"_acme-challenge.";
        let length = prefix
            .len()
            .checked_add(source.len())
            .ok_or(Dns01ProviderError::InvalidIdentifier)?;
        if length > MAX_DNS01_RECORD_NAME_BYTES {
            return Err(Dns01ProviderError::InvalidIdentifier);
        }
        let mut bytes = [0u8; MAX_DNS01_RECORD_NAME_BYTES];
        bytes[..prefix.len()].copy_from_slice(prefix);
        bytes[prefix.len()..length].copy_from_slice(source.as_bytes());
        Ok(Self {
            bytes,
            length: length as u8,
        })
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.length)])
            .expect("canonical DNS identifier remains ASCII")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dns01TxtValue(pub [u8; DNS01_TXT_VALUE_BYTES]);

impl Dns01TxtValue {
    pub fn from_key_authorization_digest(digest: [u8; 32]) -> Self {
        let mut value = [0u8; DNS01_TXT_VALUE_BYTES];
        let written = encode_base64url(&digest, &mut value)
            .expect("SHA-256 base64url has a fixed 43-byte representation");
        debug_assert_eq!(written.len(), DNS01_TXT_VALUE_BYTES);
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).expect("base64url is ASCII")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Dns01PublicationRequest {
    pub operation_id: [u8; 16],
    pub generation: u64,
    pub identifier: DnsIdentifier,
    pub key_authorization_digest: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Dns01PublicationReceipt {
    pub operation_id: [u8; 16],
    pub generation: u64,
    pub identifier: DnsIdentifier,
    pub key_authorization_digest: [u8; 32],
    pub name: Dns01RecordName,
    pub value: Dns01TxtValue,
    pub provider_record_id: [u8; MAX_DNS01_PROVIDER_RECORD_ID_BYTES],
    pub provider_record_id_length: u8,
    pub binding_digest: [u8; 32],
}

impl core::fmt::Debug for Dns01PublicationReceipt {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Dns01PublicationReceipt")
            .field("operation_id", &self.operation_id)
            .field("generation", &self.generation)
            .field("identifier", &"<canonical-dns-identifier>")
            .field("name", &self.name)
            .field("value", &self.value)
            .field("provider_record_id_length", &self.provider_record_id_length)
            .field("binding_digest", &self.binding_digest)
            .finish()
    }
}

impl Dns01PublicationReceipt {
    pub fn provider_record_id(&self) -> Result<&str, Dns01ProviderError> {
        let value = self
            .provider_record_id
            .get(..usize::from(self.provider_record_id_length))
            .ok_or(Dns01ProviderError::InvalidReceipt)?;
        if value.is_empty() || !value.is_ascii() {
            return Err(Dns01ProviderError::InvalidReceipt);
        }
        core::str::from_utf8(value).map_err(|_| Dns01ProviderError::InvalidReceipt)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Dns01ProviderError {
    InvalidIdentifier,
    InvalidRequest,
    InvalidReceipt,
    Capacity,
    ProviderUnavailable,
    RateLimited,
    AmbiguousRecord,
}

pub trait Dns01Provider {
    fn publish(
        &mut self,
        request: Dns01PublicationRequest,
    ) -> Result<Dns01PublicationReceipt, Dns01ProviderError>;

    fn cleanup(&mut self, receipt: Dns01PublicationReceipt) -> Result<(), Dns01ProviderError>;
}

pub fn dns01_publication_binding(
    request: Dns01PublicationRequest,
    name: Dns01RecordName,
    value: Dns01TxtValue,
    provider_record_id: &str,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"MRML DNS-01 provider publication v1");
    digest.update(&request.operation_id);
    digest.update(&request.generation.to_be_bytes());
    digest.update(request.identifier.as_str().as_bytes());
    digest.update(&request.key_authorization_digest);
    digest.update(name.as_str().as_bytes());
    digest.update(value.as_str().as_bytes());
    digest.update(provider_record_id.as_bytes());
    digest.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeProvider {
        active: [Option<Dns01PublicationReceipt>; 4],
        unrelated_txt_values: usize,
    }

    impl FakeProvider {
        fn new() -> Self {
            Self {
                active: [None; 4],
                unrelated_txt_values: 2,
            }
        }
    }

    impl Dns01Provider for FakeProvider {
        fn publish(
            &mut self,
            request: Dns01PublicationRequest,
        ) -> Result<Dns01PublicationReceipt, Dns01ProviderError> {
            if request.operation_id == [0; 16] || request.generation == 0 {
                return Err(Dns01ProviderError::InvalidRequest);
            }
            let name = Dns01RecordName::for_identifier(request.identifier)?;
            let value =
                Dns01TxtValue::from_key_authorization_digest(request.key_authorization_digest);
            if let Some(existing) = self.active.iter().flatten().find(|receipt| {
                receipt.operation_id == request.operation_id
                    && receipt.generation == request.generation
                    && receipt.name == name
                    && receipt.value == value
            }) {
                return Ok(*existing);
            }
            let slot = self
                .active
                .iter_mut()
                .find(|entry| entry.is_none())
                .ok_or(Dns01ProviderError::Capacity)?;
            let id = b"fake-record-1";
            let mut provider_record_id = [0u8; MAX_DNS01_PROVIDER_RECORD_ID_BYTES];
            provider_record_id[..id.len()].copy_from_slice(id);
            let receipt = Dns01PublicationReceipt {
                operation_id: request.operation_id,
                generation: request.generation,
                identifier: request.identifier,
                key_authorization_digest: request.key_authorization_digest,
                name,
                value,
                provider_record_id,
                provider_record_id_length: id.len() as u8,
                binding_digest: dns01_publication_binding(
                    request,
                    name,
                    value,
                    core::str::from_utf8(id).unwrap(),
                ),
            };
            *slot = Some(receipt);
            Ok(receipt)
        }

        fn cleanup(&mut self, receipt: Dns01PublicationReceipt) -> Result<(), Dns01ProviderError> {
            let expected = Dns01PublicationRequest {
                operation_id: receipt.operation_id,
                generation: receipt.generation,
                identifier: receipt.identifier,
                key_authorization_digest: receipt.key_authorization_digest,
            };
            let binding = dns01_publication_binding(
                expected,
                receipt.name,
                receipt.value,
                receipt.provider_record_id()?,
            );
            if binding != receipt.binding_digest {
                return Err(Dns01ProviderError::InvalidReceipt);
            }
            if let Some(slot) = self
                .active
                .iter_mut()
                .find(|entry| **entry == Some(receipt))
            {
                *slot = None;
            }
            Ok(())
        }
    }

    fn request(identifier: &str, wildcard: bool) -> Dns01PublicationRequest {
        Dns01PublicationRequest {
            operation_id: [3; 16],
            generation: 7,
            identifier: DnsIdentifier::parse(identifier, wildcard).unwrap(),
            key_authorization_digest: [9; 32],
        }
    }

    #[test]
    fn exact_value_wildcard_name_and_idempotent_cleanup_preserve_other_txt() {
        let mut provider = FakeProvider::new();
        let receipt = provider.publish(request("*.example.com", true)).unwrap();
        assert_eq!(receipt.name.as_str(), "_acme-challenge.example.com");
        assert_eq!(receipt.value.as_str().len(), DNS01_TXT_VALUE_BYTES);
        assert_eq!(
            provider.publish(request("*.example.com", true)).unwrap(),
            receipt
        );
        provider.cleanup(receipt).unwrap();
        provider.cleanup(receipt).unwrap();
        assert_eq!(provider.unrelated_txt_values, 2);
    }

    #[test]
    fn mutation_and_capacity_fail_closed() {
        let mut provider = FakeProvider::new();
        let receipt = provider.publish(request("git.example.com", false)).unwrap();
        let mut changed = receipt;
        changed.value.0[0] ^= 1;
        assert_eq!(
            provider.cleanup(changed),
            Err(Dns01ProviderError::InvalidReceipt)
        );
        let mut changed_identifier = receipt;
        changed_identifier.identifier =
            DnsIdentifier::parse("other.example.com", false).unwrap();
        assert_eq!(
            provider.cleanup(changed_identifier),
            Err(Dns01ProviderError::InvalidReceipt)
        );
        for index in 0..3 {
            let mut next = request("git.example.com", false);
            next.operation_id[0] = index + 4;
            provider.publish(next).unwrap();
        }
        let mut excess = request("git.example.com", false);
        excess.operation_id[0] = 9;
        assert_eq!(provider.publish(excess), Err(Dns01ProviderError::Capacity));
    }
}
