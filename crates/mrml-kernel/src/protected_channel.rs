use crate::{PROTECTION_REPORT_BYTES, ProtectionError, ProtectionReport};
use mrml_crypto::{Sha3_512, hmac_sha256};

pub const LAUNCH_REQUEST_BYTES: usize = 184;
pub const AUTHORITY_RECEIPT_BYTES: usize = 272;
const REQUEST_MAGIC: [u8; 8] = *b"MRMLLR01";
const RECEIPT_MAGIC: [u8; 8] = *b"MRMLAR01";
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedChannelError {
    Malformed,
    MissingNonce,
    MissingMeasurement,
    InvalidTag,
    Report(ProtectionError),
}

impl From<ProtectionError> for ProtectedChannelError {
    fn from(value: ProtectionError) -> Self {
        Self::Report(value)
    }
}

/// Canonical request transported by an untrusted WHP/VTL0 broker. The launch
/// authority must obtain policy independently; request bytes confer no trust.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchRequest {
    sequence: u64,
    nonce: [u8; 32],
    image_measurement: [u8; 64],
    policy_measurement: [u8; 64],
}

impl LaunchRequest {
    pub fn new(
        sequence: u64,
        nonce: [u8; 32],
        image_measurement: [u8; 64],
        policy_measurement: [u8; 64],
    ) -> Result<Self, ProtectedChannelError> {
        if nonce == [0; 32] {
            return Err(ProtectedChannelError::MissingNonce);
        }
        if image_measurement == [0; 64] || policy_measurement == [0; 64] {
            return Err(ProtectedChannelError::MissingMeasurement);
        }
        Ok(Self {
            sequence,
            nonce,
            image_measurement,
            policy_measurement,
        })
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub const fn nonce(self) -> [u8; 32] {
        self.nonce
    }

    pub const fn image_measurement(self) -> [u8; 64] {
        self.image_measurement
    }

    pub fn encode(self) -> [u8; LAUNCH_REQUEST_BYTES] {
        let mut output = [0; LAUNCH_REQUEST_BYTES];
        output[..8].copy_from_slice(&REQUEST_MAGIC);
        output[8..10].copy_from_slice(&VERSION.to_le_bytes());
        output[16..24].copy_from_slice(&self.sequence.to_le_bytes());
        output[24..56].copy_from_slice(&self.nonce);
        output[56..120].copy_from_slice(&self.image_measurement);
        output[120..184].copy_from_slice(&self.policy_measurement);
        output
    }

    pub fn decode(input: &[u8]) -> Result<Self, ProtectedChannelError> {
        if input.len() != LAUNCH_REQUEST_BYTES
            || input[..8] != REQUEST_MAGIC
            || input[8..10] != VERSION.to_le_bytes()
            || input[10..16].iter().any(|byte| *byte != 0)
        {
            return Err(ProtectedChannelError::Malformed);
        }
        let mut nonce = [0; 32];
        nonce.copy_from_slice(&input[24..56]);
        let mut image = [0; 64];
        image.copy_from_slice(&input[56..120]);
        let mut policy = [0; 64];
        policy.copy_from_slice(&input[120..184]);
        Self::new(
            u64::from_le_bytes(
                input[16..24]
                    .try_into()
                    .map_err(|_| ProtectedChannelError::Malformed)?,
            ),
            nonce,
            image,
            policy,
        )
    }

    fn digest(self) -> [u8; 64] {
        Sha3_512::digest(&self.encode())
    }
}

/// Authenticated authority output. The MAC key must remain in the VBS enclave
/// and a trusted verifier; placing it in an ordinary WHP guest forfeits the
/// hostile-host property. This receipt authenticates a decision, not execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityReceipt {
    request_digest: [u8; 64],
    report: ProtectionReport,
}

impl AuthorityReceipt {
    pub fn seal(
        key: &[u8; 32],
        request: LaunchRequest,
        report: ProtectionReport,
    ) -> Result<[u8; AUTHORITY_RECEIPT_BYTES], ProtectedChannelError> {
        if report.nonce() != request.nonce()
            || report.sequence() != request.sequence()
            || report.measurement() != request.image_measurement()
        {
            return Err(ProtectedChannelError::Malformed);
        }
        let request_digest = request.digest();
        let mut output = [0; AUTHORITY_RECEIPT_BYTES];
        output[..8].copy_from_slice(&RECEIPT_MAGIC);
        output[8..10].copy_from_slice(&VERSION.to_le_bytes());
        output[16..80].copy_from_slice(&request_digest);
        output[80..240].copy_from_slice(&report.encode());
        let tag = hmac_sha256(key, &[b"MRML-AUTHORITY-RECEIPT-v1\0", &output[..240]]);
        output[240..].copy_from_slice(&tag);
        Ok(output)
    }

    pub fn verify(
        key: &[u8; 32],
        request: LaunchRequest,
        input: &[u8],
    ) -> Result<Self, ProtectedChannelError> {
        if input.len() != AUTHORITY_RECEIPT_BYTES
            || input[..8] != RECEIPT_MAGIC
            || input[8..10] != VERSION.to_le_bytes()
            || input[10..16].iter().any(|byte| *byte != 0)
        {
            return Err(ProtectedChannelError::Malformed);
        }
        let expected = hmac_sha256(key, &[b"MRML-AUTHORITY-RECEIPT-v1\0", &input[..240]]);
        if !constant_time_equal_32(&expected, &input[240..]) {
            return Err(ProtectedChannelError::InvalidTag);
        }
        let request_digest = request.digest();
        if input[16..80] != request_digest {
            return Err(ProtectedChannelError::Malformed);
        }
        let report = ProtectionReport::decode(&input[80..80 + PROTECTION_REPORT_BYTES])?;
        if report.nonce() != request.nonce()
            || report.sequence() != request.sequence()
            || report.measurement() != request.image_measurement()
        {
            return Err(ProtectedChannelError::Malformed);
        }
        Ok(Self {
            request_digest,
            report,
        })
    }

    pub const fn report(self) -> ProtectionReport {
        self.report
    }
}

fn constant_time_equal_32(expected: &[u8; 32], candidate: &[u8]) -> bool {
    if candidate.len() != 32 {
        return false;
    }
    let mut difference = 0;
    for index in 0..32 {
        difference |= expected[index] ^ candidate[index];
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProtectionBackend, ProtectionClaims};

    const KEY: [u8; 32] = [0x39; 32];
    const NONCE: [u8; 32] = [0xa2; 32];
    const IMAGE: [u8; 64] = [0x51; 64];
    const POLICY: [u8; 64] = [0x72; 64];

    fn request(sequence: u64) -> LaunchRequest {
        LaunchRequest::new(sequence, NONCE, IMAGE, POLICY).unwrap()
    }

    fn report(sequence: u64) -> ProtectionReport {
        ProtectionReport::new(
            ProtectionBackend::VbsEnclave,
            ProtectionBackend::VbsEnclave.maximum_claims(),
            false,
            1,
            sequence,
            IMAGE,
            NONCE,
        )
        .unwrap()
    }

    #[test]
    fn request_encoding_is_canonical() {
        let encoded = request(4).encode();
        assert_eq!(LaunchRequest::decode(&encoded).unwrap(), request(4));
        let mut malformed = encoded;
        malformed[12] = 1;
        assert_eq!(
            LaunchRequest::decode(&malformed),
            Err(ProtectedChannelError::Malformed)
        );
    }

    #[test]
    fn receipt_binds_exact_request_and_report() {
        let encoded = AuthorityReceipt::seal(&KEY, request(4), report(4)).unwrap();
        let receipt = AuthorityReceipt::verify(&KEY, request(4), &encoded).unwrap();
        assert_eq!(receipt.report(), report(4));
        assert_eq!(
            AuthorityReceipt::verify(&KEY, request(5), &encoded),
            Err(ProtectedChannelError::Malformed)
        );
    }

    #[test]
    fn broker_tampering_fails_before_decoding_report() {
        let mut encoded = AuthorityReceipt::seal(&KEY, request(4), report(4)).unwrap();
        encoded[100] ^= 1;
        assert_eq!(
            AuthorityReceipt::verify(&KEY, request(4), &encoded),
            Err(ProtectedChannelError::InvalidTag)
        );
        encoded = AuthorityReceipt::seal(&KEY, request(4), report(4)).unwrap();
        encoded[250] ^= 1;
        assert_eq!(
            AuthorityReceipt::verify(&KEY, request(4), &encoded),
            Err(ProtectedChannelError::InvalidTag)
        );
    }

    #[test]
    fn report_cannot_be_rebound_to_another_launch() {
        assert_eq!(
            AuthorityReceipt::seal(&KEY, request(5), report(4)),
            Err(ProtectedChannelError::Malformed)
        );
        let weak = ProtectionReport::new(
            ProtectionBackend::Unprotected,
            ProtectionClaims::NONE,
            false,
            1,
            4,
            IMAGE,
            NONCE,
        )
        .unwrap();
        let encoded = AuthorityReceipt::seal(&KEY, request(4), weak).unwrap();
        assert_eq!(
            AuthorityReceipt::verify(&KEY, request(4), &encoded)
                .unwrap()
                .report()
                .backend(),
            ProtectionBackend::Unprotected
        );
    }
}
