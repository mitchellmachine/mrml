use crate::{
    PROTECTION_REPORT_BYTES, ProtectionAdmission, ProtectionError, ProtectionPolicy,
    ProtectionReport, ProtectionSession,
};
use mrml_crypto::{Sha3_512, hmac_sha256};

pub const LAUNCH_REQUEST_BYTES: usize = 184;
pub const AUTHORITY_RECEIPT_BYTES: usize = 272;
pub const VBS_AUTHORITY_CONTEXT_BYTES: usize = 48;
const REQUEST_MAGIC: [u8; 8] = *b"MRMLLR01";
const RECEIPT_MAGIC: [u8; 8] = *b"MRMLAR01";
const VBS_CONTEXT_MAGIC: [u8; 8] = *b"MRMLVC01";
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum VbsAuthorityOperation {
    IssueReceipt = 1,
    GenerateSealedKey = 2,
    LoadSealedKey = 3,
}

impl VbsAuthorityOperation {
    fn decode(value: u16) -> Result<Self, ProtectedChannelError> {
        match value {
            1 => Ok(Self::IssueReceipt),
            2 => Ok(Self::GenerateSealedKey),
            3 => Ok(Self::LoadSealedKey),
            _ => Err(ProtectedChannelError::Malformed),
        }
    }
}

/// Canonical x86_64 host/enclave call descriptor. Addresses are untrusted
/// integers until Vertdll validates them during an explicit boundary copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VbsAuthorityContext {
    operation: VbsAuthorityOperation,
    input_address: u64,
    input_bytes: u64,
    output_address: u64,
    output_bytes: u64,
}

impl VbsAuthorityContext {
    pub fn new(
        operation: VbsAuthorityOperation,
        input_address: u64,
        input_bytes: u64,
        output_address: u64,
        output_bytes: u64,
    ) -> Result<Self, ProtectedChannelError> {
        if input_address == 0 || input_bytes == 0 || output_address == 0 || output_bytes == 0 {
            return Err(ProtectedChannelError::Malformed);
        }
        Ok(Self {
            operation,
            input_address,
            input_bytes,
            output_address,
            output_bytes,
        })
    }

    pub const fn operation(self) -> VbsAuthorityOperation {
        self.operation
    }

    pub const fn input_address(self) -> u64 {
        self.input_address
    }

    pub const fn input_bytes(self) -> u64 {
        self.input_bytes
    }

    pub const fn output_address(self) -> u64 {
        self.output_address
    }

    pub const fn output_bytes(self) -> u64 {
        self.output_bytes
    }

    pub fn encode(self) -> [u8; VBS_AUTHORITY_CONTEXT_BYTES] {
        let mut encoded = [0; VBS_AUTHORITY_CONTEXT_BYTES];
        encoded[..8].copy_from_slice(&VBS_CONTEXT_MAGIC);
        encoded[8..10].copy_from_slice(&VERSION.to_le_bytes());
        encoded[10..12].copy_from_slice(&(self.operation as u16).to_le_bytes());
        encoded[16..24].copy_from_slice(&self.input_address.to_le_bytes());
        encoded[24..32].copy_from_slice(&self.input_bytes.to_le_bytes());
        encoded[32..40].copy_from_slice(&self.output_address.to_le_bytes());
        encoded[40..48].copy_from_slice(&self.output_bytes.to_le_bytes());
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ProtectedChannelError> {
        if encoded.len() != VBS_AUTHORITY_CONTEXT_BYTES
            || encoded[..8] != VBS_CONTEXT_MAGIC
            || encoded[8..10] != VERSION.to_le_bytes()
            || encoded[12..16].iter().any(|byte| *byte != 0)
        {
            return Err(ProtectedChannelError::Malformed);
        }
        let operation = VbsAuthorityOperation::decode(read_u16(encoded, 10)?)?;
        Self::new(
            operation,
            read_u64(encoded, 16)?,
            read_u64(encoded, 24)?,
            read_u64(encoded, 32)?,
            read_u64(encoded, 40)?,
        )
    }
}

fn read_u16(encoded: &[u8], offset: usize) -> Result<u16, ProtectedChannelError> {
    Ok(u16::from_le_bytes(
        encoded
            .get(offset..offset + 2)
            .ok_or(ProtectedChannelError::Malformed)?
            .try_into()
            .map_err(|_| ProtectedChannelError::Malformed)?,
    ))
}

fn read_u64(encoded: &[u8], offset: usize) -> Result<u64, ProtectedChannelError> {
    Ok(u64::from_le_bytes(
        encoded
            .get(offset..offset + 8)
            .ok_or(ProtectedChannelError::Malformed)?
            .try_into()
            .map_err(|_| ProtectedChannelError::Malformed)?,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedChannelError {
    Malformed,
    MissingNonce,
    MissingMeasurement,
    PolicyMeasurementMismatch,
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

    pub const fn policy_measurement(self) -> [u8; 64] {
        self.policy_measurement
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

    /// Authenticates the authority decision and immediately applies the exact
    /// backend/claim/version/measurement/session policy. Callers that gate a
    /// launch should prefer this over inspecting a verified report manually.
    pub fn verify_and_admit(
        key: &[u8; 32],
        request: LaunchRequest,
        input: &[u8],
        expected_policy_measurement: [u8; 64],
        session: &mut ProtectionSession,
        policy: ProtectionPolicy,
    ) -> Result<ProtectionAdmission, ProtectedChannelError> {
        let receipt = Self::verify(key, request, input)?;
        if expected_policy_measurement == [0; 64]
            || request.policy_measurement != expected_policy_measurement
        {
            return Err(ProtectedChannelError::PolicyMeasurementMismatch);
        }
        session
            .admit(receipt.report, policy)
            .map_err(ProtectedChannelError::Report)
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

    #[test]
    fn authenticated_receipt_still_requires_exact_backend_admission() {
        let bare = ProtectionReport::new(
            ProtectionBackend::BareMetalMonitor,
            ProtectionClaims::MEASURED,
            false,
            1,
            4,
            IMAGE,
            NONCE,
        )
        .unwrap();
        let bare_receipt = AuthorityReceipt::seal(&KEY, request(4), bare).unwrap();
        let policy = ProtectionPolicy::new(
            ProtectionBackend::VbsEnclave,
            ProtectionClaims::MEASURED,
            false,
            1,
            IMAGE,
        );
        let mut session = ProtectionSession::new(NONCE).unwrap();
        assert_eq!(
            AuthorityReceipt::verify_and_admit(
                &KEY,
                request(4),
                &bare_receipt,
                POLICY,
                &mut session,
                policy,
            ),
            Err(ProtectedChannelError::Report(
                ProtectionError::BackendMismatch
            ))
        );

        let vbs_receipt = AuthorityReceipt::seal(&KEY, request(4), report(4)).unwrap();
        assert_eq!(
            AuthorityReceipt::verify_and_admit(
                &KEY,
                request(4),
                &vbs_receipt,
                POLICY,
                &mut session,
                policy,
            )
            .unwrap()
            .backend(),
            ProtectionBackend::VbsEnclave
        );
    }

    #[test]
    fn authenticated_receipt_requires_independently_expected_policy() {
        let encoded = AuthorityReceipt::seal(&KEY, request(4), report(4)).unwrap();
        let policy = ProtectionPolicy::new(
            ProtectionBackend::VbsEnclave,
            ProtectionClaims::MEASURED,
            false,
            1,
            IMAGE,
        );
        let mut session = ProtectionSession::new(NONCE).unwrap();
        assert_eq!(
            AuthorityReceipt::verify_and_admit(
                &KEY,
                request(4),
                &encoded,
                [0x73; 64],
                &mut session,
                policy,
            ),
            Err(ProtectedChannelError::PolicyMeasurementMismatch)
        );
        assert_eq!(
            AuthorityReceipt::verify_and_admit(
                &KEY,
                request(4),
                &encoded,
                POLICY,
                &mut session,
                policy,
            )
            .unwrap()
            .sequence(),
            4
        );
    }

    #[test]
    fn vbs_context_is_canonical_and_operation_bound() {
        let context = VbsAuthorityContext::new(
            VbsAuthorityOperation::IssueReceipt,
            0x1000,
            LAUNCH_REQUEST_BYTES as u64,
            0x2000,
            AUTHORITY_RECEIPT_BYTES as u64,
        )
        .unwrap();
        let encoded = context.encode();
        assert_eq!(VbsAuthorityContext::decode(&encoded), Ok(context));
        let mut malformed = encoded;
        malformed[12] = 1;
        assert_eq!(
            VbsAuthorityContext::decode(&malformed),
            Err(ProtectedChannelError::Malformed)
        );
        malformed = encoded;
        malformed[10..12].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            VbsAuthorityContext::decode(&malformed),
            Err(ProtectedChannelError::Malformed)
        );
    }

    #[test]
    fn vbs_context_rejects_null_or_empty_buffers() {
        assert_eq!(
            VbsAuthorityContext::new(VbsAuthorityOperation::IssueReceipt, 0, 184, 2, 272),
            Err(ProtectedChannelError::Malformed)
        );
        assert_eq!(
            VbsAuthorityContext::new(VbsAuthorityOperation::IssueReceipt, 1, 184, 2, 0),
            Err(ProtectedChannelError::Malformed)
        );
    }
}
