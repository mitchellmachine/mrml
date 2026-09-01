use crate::{DurableAuthenticator, DurableError};
use mrml_crypto::{erase_secret_bytes, hmac_sha256};

pub const DURABLE_AUTHENTICATION_KEY_BYTES: usize = 32;

/// HMAC-SHA-256 authentication for hosted production certificate records.
///
/// The fixed-size key prevents callers from substituting a password, an empty
/// value, or the public label used by the native probe authenticator.
pub struct HmacSha256DurableAuthenticator {
    key: [u8; DURABLE_AUTHENTICATION_KEY_BYTES],
}

impl HmacSha256DurableAuthenticator {
    pub const fn new(key: [u8; DURABLE_AUTHENTICATION_KEY_BYTES]) -> Self {
        Self { key }
    }

    fn tag(&self, record: &[u8]) -> [u8; 32] {
        hmac_sha256(&self.key, &[record])
    }
}

impl DurableAuthenticator for HmacSha256DurableAuthenticator {
    fn authenticate(&mut self, record: &[u8]) -> Result<[u8; 32], DurableError> {
        Ok(self.tag(record))
    }

    fn verify(&mut self, record: &[u8], tag: &[u8; 32]) -> Result<bool, DurableError> {
        let expected = self.tag(record);
        let mut difference = 0u8;
        for index in 0..expected.len() {
            difference |= expected[index] ^ tag[index];
        }
        Ok(difference == 0)
    }
}

impl Drop for HmacSha256DurableAuthenticator {
    fn drop(&mut self) {
        erase_secret_bytes(&mut self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DurableNamespace, DurableObjectId, DurableRecord, DurableRecordKind};

    #[test]
    fn durable_record_requires_the_same_secret_key() {
        let mut writer = HmacSha256DurableAuthenticator::new([0x11; 32]);
        let record = DurableRecord::prepare(
            DurableNamespace::PublicState,
            DurableRecordKind::Order,
            DurableObjectId([7; 16]),
            0,
            b"authenticated order",
            &mut writer,
        )
        .unwrap();
        let mut encoded = [0u8; crate::MAX_DURABLE_RECORD_BYTES];
        let length = record.encode(&mut encoded).unwrap();

        let mut reader = HmacSha256DurableAuthenticator::new([0x11; 32]);
        assert!(DurableRecord::decode(&encoded[..length], &mut reader).is_ok());

        let mut wrong_key = HmacSha256DurableAuthenticator::new([0x12; 32]);
        assert!(matches!(
            DurableRecord::decode(&encoded[..length], &mut wrong_key),
            Err(DurableError::AuthenticationFailed)
        ));
    }

    #[test]
    fn tampering_is_rejected() {
        let mut authenticator = HmacSha256DurableAuthenticator::new([0x42; 32]);
        let mut tag = authenticator.authenticate(b"record").unwrap();
        tag[31] ^= 1;
        assert!(!authenticator.verify(b"record", &tag).unwrap());
    }
}
