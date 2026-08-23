use crate::{
    PROTECTION_REPORT_BYTES, ProtectionAdmission, ProtectionError, ProtectionPolicy,
    ProtectionReport, ProtectionSession,
};
use mrml_crypto::{Sha3_256, Sha3_512, hmac_sha256};

pub const LAUNCH_REQUEST_BYTES: usize = 184;
pub const AUTHORITY_RECEIPT_BYTES: usize = 272;
pub const VBS_AUTHORITY_CONTEXT_BYTES: usize = 48;
pub const VBS_ATTESTATION_DATA_BYTES: usize = 64;
pub const VBS_ATTESTATION_CHALLENGE_BYTES: usize = 32;
pub const VBS_ATTESTATION_REPORT_MAX_BYTES: usize = 64 * 1024;
pub const VBS_ATTESTATION_ENVELOPE_BYTES: usize = 8 + VBS_ATTESTATION_REPORT_MAX_BYTES;
pub const VBS_REPORT_PACKAGE_HEADER_BYTES: usize = 24;
pub const VBS_REPORT_SIGNED_STATEMENT_BYTES: usize = 224;
pub const VBS_ENCLAVE_IDENTITY_BYTES: usize = 152;
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
    IssueAttestationReport = 4,
    GenerateAttestationChallenge = 5,
    VerifyAttestationReport = 6,
}

impl VbsAuthorityOperation {
    fn decode(value: u16) -> Result<Self, ProtectedChannelError> {
        match value {
            1 => Ok(Self::IssueReceipt),
            2 => Ok(Self::GenerateSealedKey),
            3 => Ok(Self::LoadSealedKey),
            4 => Ok(Self::IssueAttestationReport),
            5 => Ok(Self::GenerateAttestationChallenge),
            6 => Ok(Self::VerifyAttestationReport),
            _ => Err(ProtectedChannelError::Malformed),
        }
    }
}

/// Exact 64-byte enclave-controlled statement embedded in a Windows VBS
/// attestation report. Windows authenticates the surrounding report; this type
/// binds the verifier's challenge to the exact MRML admission policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VbsAttestationData {
    verifier_nonce: [u8; 32],
    policy_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VbsAttestationEnvelope<'a> {
    report: &'a [u8],
}

/// Parsed but cryptographically unverified VBS report identity. None of these
/// fields are trustworthy until a separate VBS enclave successfully calls
/// `EnclaveVerifyAttestationReport` over the exact original report bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnverifiedVbsAttestationReport<'a> {
    report: &'a [u8],
    binding: VbsAttestationData,
    owner_id: [u8; 32],
    unique_id: [u8; 32],
    author_id: [u8; 32],
    family_id: [u8; 16],
    image_id: [u8; 16],
    enclave_security_version: u32,
    secure_kernel_security_version: u32,
    platform_security_version: u32,
    signature_scheme: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VbsAttestationExpectation {
    owner_id: [u8; 32],
    unique_id: [u8; 32],
    author_id: [u8; 32],
    family_id: [u8; 16],
    image_id: [u8; 16],
    minimum_enclave_security_version: u32,
    minimum_secure_kernel_security_version: u32,
    minimum_platform_security_version: u32,
}

impl VbsAttestationExpectation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_id: [u8; 32],
        unique_id: [u8; 32],
        author_id: [u8; 32],
        family_id: [u8; 16],
        image_id: [u8; 16],
        minimum_enclave_security_version: u32,
        minimum_secure_kernel_security_version: u32,
        minimum_platform_security_version: u32,
    ) -> Result<Self, ProtectedChannelError> {
        if unique_id == [0; 32]
            || author_id == [0; 32]
            || family_id == [0; 16]
            || image_id == [0; 16]
            || minimum_enclave_security_version == 0
            || minimum_secure_kernel_security_version == 0
            || minimum_platform_security_version == 0
        {
            return Err(ProtectedChannelError::AttestationIdentityMismatch);
        }
        Ok(Self {
            owner_id,
            unique_id,
            author_id,
            family_id,
            image_id,
            minimum_enclave_security_version,
            minimum_secure_kernel_security_version,
            minimum_platform_security_version,
        })
    }
}

impl<'a> UnverifiedVbsAttestationReport<'a> {
    pub fn parse(report: &'a [u8]) -> Result<Self, ProtectedChannelError> {
        let minimum = VBS_REPORT_PACKAGE_HEADER_BYTES
            .checked_add(VBS_REPORT_SIGNED_STATEMENT_BYTES)
            .and_then(|bytes| bytes.checked_add(1))
            .ok_or(ProtectedChannelError::Malformed)?;
        if report.len() < minimum || report.len() > VBS_ATTESTATION_REPORT_MAX_BYTES {
            return Err(ProtectedChannelError::Malformed);
        }
        let package_size = read_u32(report, 0)? as usize;
        let package_version = read_u32(report, 4)?;
        let signature_scheme = read_u32(report, 8)?;
        let statement_size = read_u32(report, 12)? as usize;
        let signature_size = read_u32(report, 16)? as usize;
        if package_size != report.len()
            || package_version != 1
            || signature_scheme == 0
            || statement_size != VBS_REPORT_SIGNED_STATEMENT_BYTES
            || signature_size == 0
            || read_u32(report, 20)? != 0
            || VBS_REPORT_PACKAGE_HEADER_BYTES
                .checked_add(statement_size)
                .and_then(|bytes| bytes.checked_add(signature_size))
                != Some(report.len())
        {
            return Err(ProtectedChannelError::Malformed);
        }
        let statement = &report[VBS_REPORT_PACKAGE_HEADER_BYTES
            ..VBS_REPORT_PACKAGE_HEADER_BYTES + VBS_REPORT_SIGNED_STATEMENT_BYTES];
        if read_u32(statement, 0)? as usize != statement.len() || read_u32(statement, 4)? != 1 {
            return Err(ProtectedChannelError::Malformed);
        }
        let binding = VbsAttestationData::decode(&statement[8..72])?;
        let identity = &statement[72..72 + VBS_ENCLAVE_IDENTITY_BYTES];
        let flags = read_u32(identity, 140)?;
        if flags != 0 || read_u32(identity, 144)? != 0 || read_u32(identity, 148)? != 0 {
            return Err(ProtectedChannelError::AttestationIdentityMismatch);
        }
        Ok(Self {
            report,
            binding,
            owner_id: copy_array(identity, 0)?,
            unique_id: copy_array(identity, 32)?,
            author_id: copy_array(identity, 64)?,
            family_id: copy_array(identity, 96)?,
            image_id: copy_array(identity, 112)?,
            enclave_security_version: read_u32(identity, 128)?,
            secure_kernel_security_version: read_u32(identity, 132)?,
            platform_security_version: read_u32(identity, 136)?,
            signature_scheme,
        })
    }

    pub const fn report(self) -> &'a [u8] {
        self.report
    }

    pub const fn binding(self) -> VbsAttestationData {
        self.binding
    }

    pub const fn owner_id(self) -> [u8; 32] {
        self.owner_id
    }

    pub const fn unique_id(self) -> [u8; 32] {
        self.unique_id
    }

    pub const fn author_id(self) -> [u8; 32] {
        self.author_id
    }

    pub const fn family_id(self) -> [u8; 16] {
        self.family_id
    }

    pub const fn image_id(self) -> [u8; 16] {
        self.image_id
    }

    pub const fn enclave_security_version(self) -> u32 {
        self.enclave_security_version
    }

    pub const fn secure_kernel_security_version(self) -> u32 {
        self.secure_kernel_security_version
    }

    pub const fn platform_security_version(self) -> u32 {
        self.platform_security_version
    }

    pub const fn signature_scheme(self) -> u32 {
        self.signature_scheme
    }

    /// Checks signed fields against verifier-owned expectations. This remains
    /// untrusted data unless the caller first obtained a successful Windows
    /// `EnclaveVerifyAttestationReport` result for `self.report()`.
    pub fn matches_expectation(
        self,
        expected_binding: VbsAttestationData,
        expected_identity: VbsAttestationExpectation,
    ) -> Result<(), ProtectedChannelError> {
        if self.binding != expected_binding {
            return Err(ProtectedChannelError::AttestationBindingMismatch);
        }
        if self.owner_id != expected_identity.owner_id
            || self.unique_id != expected_identity.unique_id
            || self.author_id != expected_identity.author_id
            || self.family_id != expected_identity.family_id
            || self.image_id != expected_identity.image_id
        {
            return Err(ProtectedChannelError::AttestationIdentityMismatch);
        }
        if self.enclave_security_version < expected_identity.minimum_enclave_security_version
            || self.secure_kernel_security_version
                < expected_identity.minimum_secure_kernel_security_version
            || self.platform_security_version < expected_identity.minimum_platform_security_version
        {
            return Err(ProtectedChannelError::AttestationSecurityVersionTooOld);
        }
        Ok(())
    }
}

impl<'a> VbsAttestationEnvelope<'a> {
    pub fn decode(input: &'a [u8]) -> Result<Self, ProtectedChannelError> {
        if input.len() != VBS_ATTESTATION_ENVELOPE_BYTES {
            return Err(ProtectedChannelError::Malformed);
        }
        let report_bytes = u64::from_le_bytes(
            input[..8]
                .try_into()
                .map_err(|_| ProtectedChannelError::Malformed)?,
        );
        let report_bytes =
            usize::try_from(report_bytes).map_err(|_| ProtectedChannelError::Malformed)?;
        if report_bytes == 0 || report_bytes > VBS_ATTESTATION_REPORT_MAX_BYTES {
            return Err(ProtectedChannelError::Malformed);
        }
        let report_end = 8usize
            .checked_add(report_bytes)
            .ok_or(ProtectedChannelError::Malformed)?;
        if input[report_end..].iter().any(|byte| *byte != 0) {
            return Err(ProtectedChannelError::Malformed);
        }
        Ok(Self {
            report: &input[8..report_end],
        })
    }

    pub const fn report(self) -> &'a [u8] {
        self.report
    }
}

impl VbsAttestationData {
    pub fn for_policy(
        verifier_nonce: [u8; 32],
        policy: ProtectionPolicy,
    ) -> Result<Self, ProtectedChannelError> {
        if verifier_nonce == [0; 32] {
            return Err(ProtectedChannelError::MissingNonce);
        }
        Ok(Self {
            verifier_nonce,
            policy_digest: Sha3_256::digest(&policy.encode()),
        })
    }

    pub const fn verifier_nonce(self) -> [u8; 32] {
        self.verifier_nonce
    }

    pub const fn policy_digest(self) -> [u8; 32] {
        self.policy_digest
    }

    pub fn encode(self) -> [u8; VBS_ATTESTATION_DATA_BYTES] {
        let mut output = [0; VBS_ATTESTATION_DATA_BYTES];
        output[..32].copy_from_slice(&self.verifier_nonce);
        output[32..].copy_from_slice(&self.policy_digest);
        output
    }

    pub fn decode(input: &[u8]) -> Result<Self, ProtectedChannelError> {
        if input.len() != VBS_ATTESTATION_DATA_BYTES {
            return Err(ProtectedChannelError::Malformed);
        }
        let mut verifier_nonce = [0; 32];
        verifier_nonce.copy_from_slice(&input[..32]);
        let mut policy_digest = [0; 32];
        policy_digest.copy_from_slice(&input[32..]);
        if verifier_nonce == [0; 32] {
            return Err(ProtectedChannelError::MissingNonce);
        }
        if policy_digest == [0; 32] {
            return Err(ProtectedChannelError::MissingMeasurement);
        }
        Ok(Self {
            verifier_nonce,
            policy_digest,
        })
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

fn read_u32(encoded: &[u8], offset: usize) -> Result<u32, ProtectedChannelError> {
    Ok(u32::from_le_bytes(
        encoded
            .get(offset..offset + 4)
            .ok_or(ProtectedChannelError::Malformed)?
            .try_into()
            .map_err(|_| ProtectedChannelError::Malformed)?,
    ))
}

fn copy_array<const BYTES: usize>(
    encoded: &[u8],
    offset: usize,
) -> Result<[u8; BYTES], ProtectedChannelError> {
    encoded
        .get(offset..offset + BYTES)
        .ok_or(ProtectedChannelError::Malformed)?
        .try_into()
        .map_err(|_| ProtectedChannelError::Malformed)
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
    AttestationIdentityMismatch,
    AttestationBindingMismatch,
    AttestationSecurityVersionTooOld,
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

/// Admission derived from a receipt authenticated by the configured launch
/// authority. This proves only which authority approved the exact request; it
/// does not, by itself, prove hardware-backed isolation or host integrity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedProtectionAdmission {
    admission: ProtectionAdmission,
    request_digest: [u8; 64],
    policy_measurement: [u8; 64],
}

impl AuthenticatedProtectionAdmission {
    pub const fn evidence_source(self) -> crate::ProtectionEvidenceSource {
        self.admission.evidence_source()
    }

    pub const fn backend(self) -> crate::ProtectionBackend {
        self.admission.backend()
    }

    pub const fn claims(self) -> crate::ProtectionClaims {
        self.admission.claims()
    }

    pub const fn debug_allowed(self) -> bool {
        self.admission.debug_allowed()
    }

    pub const fn security_version(self) -> u64 {
        self.admission.security_version()
    }

    pub const fn measurement(self) -> [u8; 64] {
        self.admission.measurement()
    }

    pub const fn nonce(self) -> [u8; 32] {
        self.admission.nonce()
    }

    pub const fn sequence(self) -> u64 {
        self.admission.sequence()
    }

    pub const fn request_digest(self) -> [u8; 64] {
        self.request_digest
    }

    pub const fn policy_measurement(self) -> [u8; 64] {
        self.policy_measurement
    }

    /// Secret release remains fail-closed unless the authenticated decision is
    /// non-debug and explicitly claims both measurement and sealed-key support.
    pub const fn permits_secret_release(self) -> bool {
        !self.admission.debug_allowed()
            && self
                .admission
                .claims()
                .contains(crate::ProtectionClaims::SEALED_KEYS)
            && self
                .admission
                .claims()
                .contains(crate::ProtectionClaims::MEASURED)
    }
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
    ) -> Result<AuthenticatedProtectionAdmission, ProtectedChannelError> {
        let receipt = Self::verify(key, request, input)?;
        if expected_policy_measurement == [0; 64]
            || request.policy_measurement != expected_policy_measurement
            || policy.commitment() != expected_policy_measurement
        {
            return Err(ProtectedChannelError::PolicyMeasurementMismatch);
        }
        let admission = session
            .admit_authority_receipt(receipt.report, policy)
            .map_err(ProtectedChannelError::Report)?;
        Ok(AuthenticatedProtectionAdmission {
            admission,
            request_digest: receipt.request_digest,
            policy_measurement: expected_policy_measurement,
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

    fn policy(allow_debug: bool) -> ProtectionPolicy {
        ProtectionPolicy::new(
            ProtectionBackend::VbsEnclave,
            ProtectionClaims::MEASURED,
            allow_debug,
            1,
            IMAGE,
        )
    }

    fn request_for_policy(sequence: u64, policy: ProtectionPolicy) -> LaunchRequest {
        LaunchRequest::new(sequence, NONCE, IMAGE, policy.commitment()).unwrap()
    }

    fn request(sequence: u64) -> LaunchRequest {
        request_for_policy(sequence, policy(false))
    }

    fn synthetic_vbs_report(binding: VbsAttestationData) -> [u8; 280] {
        let mut report = [0; 280];
        report[..4].copy_from_slice(&280u32.to_le_bytes());
        report[4..8].copy_from_slice(&1u32.to_le_bytes());
        report[8..12].copy_from_slice(&1u32.to_le_bytes());
        report[12..16].copy_from_slice(&(VBS_REPORT_SIGNED_STATEMENT_BYTES as u32).to_le_bytes());
        report[16..20].copy_from_slice(&32u32.to_le_bytes());
        let statement = &mut report[24..248];
        statement[..4].copy_from_slice(&(VBS_REPORT_SIGNED_STATEMENT_BYTES as u32).to_le_bytes());
        statement[4..8].copy_from_slice(&1u32.to_le_bytes());
        statement[8..72].copy_from_slice(&binding.encode());
        let identity = &mut statement[72..224];
        identity[..32].fill(0x10);
        identity[32..64].fill(0x20);
        identity[64..96].fill(0x30);
        identity[96..112].copy_from_slice(b"MRML-VBS-FAMILY!");
        identity[112..128].copy_from_slice(b"MRML-AUTHORITY!!");
        identity[128..132].copy_from_slice(&1u32.to_le_bytes());
        identity[132..136].copy_from_slice(&2u32.to_le_bytes());
        identity[136..140].copy_from_slice(&3u32.to_le_bytes());
        report[248..].fill(0xa5);
        report
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
        let policy = policy(false);
        let policy_measurement = policy.commitment();
        let mut session = ProtectionSession::new(NONCE).unwrap();
        assert_eq!(
            AuthorityReceipt::verify_and_admit(
                &KEY,
                request(4),
                &bare_receipt,
                policy_measurement,
                &mut session,
                policy,
            ),
            Err(ProtectedChannelError::Report(
                ProtectionError::BackendMismatch
            ))
        );

        let vbs_receipt = AuthorityReceipt::seal(&KEY, request(4), report(4)).unwrap();
        let admitted = AuthorityReceipt::verify_and_admit(
            &KEY,
            request(4),
            &vbs_receipt,
            policy_measurement,
            &mut session,
            policy,
        )
        .unwrap();
        assert_eq!(admitted.backend(), ProtectionBackend::VbsEnclave);
        assert_eq!(
            admitted.evidence_source(),
            crate::ProtectionEvidenceSource::AuthenticatedAuthorityReceipt
        );
        assert_eq!(
            admitted.request_digest(),
            Sha3_512::digest(&request(4).encode())
        );
        assert_eq!(admitted.policy_measurement(), policy_measurement);
        assert!(!admitted.debug_allowed());
        assert_eq!(admitted.security_version(), 1);
        assert!(!admitted.permits_secret_release());
    }

    #[test]
    fn authenticated_receipt_requires_independently_expected_policy() {
        let encoded = AuthorityReceipt::seal(&KEY, request(4), report(4)).unwrap();
        let policy = policy(false);
        let policy_measurement = policy.commitment();
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
                policy_measurement,
                &mut session,
                policy,
            )
            .unwrap()
            .sequence(),
            4
        );
    }

    #[test]
    fn authenticated_policy_identity_binds_exact_enforced_policy() {
        let approved = policy(false);
        let request = request_for_policy(4, approved);
        let encoded = AuthorityReceipt::seal(&KEY, request, report(4)).unwrap();
        let different = ProtectionPolicy::new(
            ProtectionBackend::VbsEnclave,
            ProtectionClaims::MEASURED,
            false,
            2,
            IMAGE,
        );
        let mut session = ProtectionSession::new(NONCE).unwrap();
        assert_eq!(
            AuthorityReceipt::verify_and_admit(
                &KEY,
                request,
                &encoded,
                approved.commitment(),
                &mut session,
                different,
            ),
            Err(ProtectedChannelError::PolicyMeasurementMismatch)
        );
        assert_eq!(
            AuthorityReceipt::verify_and_admit(
                &KEY,
                request,
                &encoded,
                approved.commitment(),
                &mut session,
                approved,
            )
            .unwrap()
            .sequence(),
            4
        );
    }

    #[test]
    fn authenticated_debug_admission_cannot_release_secrets() {
        let debug_report = ProtectionReport::new(
            ProtectionBackend::VbsEnclave,
            ProtectionBackend::VbsEnclave.maximum_claims(),
            true,
            1,
            4,
            IMAGE,
            NONCE,
        )
        .unwrap();
        let policy = policy(true);
        let request = request_for_policy(4, policy);
        let encoded = AuthorityReceipt::seal(&KEY, request, debug_report).unwrap();
        let mut session = ProtectionSession::new(NONCE).unwrap();
        let admitted = AuthorityReceipt::verify_and_admit(
            &KEY,
            request,
            &encoded,
            policy.commitment(),
            &mut session,
            policy,
        )
        .unwrap();
        assert!(admitted.debug_allowed());
        assert!(!admitted.permits_secret_release());
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
    fn vbs_attestation_data_binds_nonce_and_exact_policy() {
        let approved = policy(false);
        let data = VbsAttestationData::for_policy(NONCE, approved).unwrap();
        assert_eq!(data.verifier_nonce(), NONCE);
        assert_eq!(data.policy_digest(), Sha3_256::digest(&approved.encode()));
        assert_eq!(VbsAttestationData::decode(&data.encode()), Ok(data));
        assert_ne!(
            data,
            VbsAttestationData::for_policy(NONCE, policy(true)).unwrap()
        );
        assert_eq!(
            VbsAttestationData::for_policy([0; 32], approved),
            Err(ProtectedChannelError::MissingNonce)
        );
    }

    #[test]
    fn vbs_attestation_envelope_rejects_bad_length_and_nonzero_tail() {
        let mut encoded = [0; VBS_ATTESTATION_ENVELOPE_BYTES];
        encoded[..8].copy_from_slice(&3u64.to_le_bytes());
        encoded[8..11].copy_from_slice(b"vbs");
        assert_eq!(
            VbsAttestationEnvelope::decode(&encoded).unwrap().report(),
            b"vbs"
        );
        encoded[20] = 1;
        assert_eq!(
            VbsAttestationEnvelope::decode(&encoded),
            Err(ProtectedChannelError::Malformed)
        );
        encoded[20] = 0;
        encoded[..8].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(
            VbsAttestationEnvelope::decode(&encoded),
            Err(ProtectedChannelError::Malformed)
        );
    }

    #[test]
    fn unverified_vbs_report_parser_is_strict_and_preserves_identity() {
        let binding = VbsAttestationData::for_policy(NONCE, policy(false)).unwrap();
        let report = synthetic_vbs_report(binding);
        let parsed = UnverifiedVbsAttestationReport::parse(&report).unwrap();
        assert_eq!(parsed.report(), report);
        assert_eq!(parsed.binding(), binding);
        assert_eq!(parsed.owner_id(), [0x10; 32]);
        assert_eq!(parsed.unique_id(), [0x20; 32]);
        assert_eq!(parsed.author_id(), [0x30; 32]);
        assert_eq!(parsed.family_id(), *b"MRML-VBS-FAMILY!");
        assert_eq!(parsed.image_id(), *b"MRML-AUTHORITY!!");
        assert_eq!(parsed.enclave_security_version(), 1);
        assert_eq!(parsed.secure_kernel_security_version(), 2);
        assert_eq!(parsed.platform_security_version(), 3);
        assert_eq!(parsed.signature_scheme(), 1);
        let expected = VbsAttestationExpectation::new(
            [0x10; 32],
            [0x20; 32],
            [0x30; 32],
            *b"MRML-VBS-FAMILY!",
            *b"MRML-AUTHORITY!!",
            1,
            2,
            3,
        )
        .unwrap();
        assert_eq!(parsed.matches_expectation(binding, expected), Ok(()));
    }

    #[test]
    fn unverified_vbs_report_rejects_layout_and_debug_ambiguity() {
        let binding = VbsAttestationData::for_policy(NONCE, policy(false)).unwrap();
        let mut report = synthetic_vbs_report(binding);
        report[12..16].copy_from_slice(&225u32.to_le_bytes());
        assert_eq!(
            UnverifiedVbsAttestationReport::parse(&report),
            Err(ProtectedChannelError::Malformed)
        );
        report = synthetic_vbs_report(binding);
        report[24 + 72 + 140..24 + 72 + 144].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            UnverifiedVbsAttestationReport::parse(&report),
            Err(ProtectedChannelError::AttestationIdentityMismatch)
        );
    }

    #[test]
    fn unverified_vbs_report_expectation_rejects_rebinding_and_rollback() {
        let binding = VbsAttestationData::for_policy(NONCE, policy(false)).unwrap();
        let report = synthetic_vbs_report(binding);
        let parsed = UnverifiedVbsAttestationReport::parse(&report).unwrap();
        let expected = VbsAttestationExpectation::new(
            [0x10; 32],
            [0x20; 32],
            [0x30; 32],
            *b"MRML-VBS-FAMILY!",
            *b"MRML-AUTHORITY!!",
            1,
            2,
            4,
        )
        .unwrap();
        assert_eq!(
            parsed.matches_expectation(binding, expected),
            Err(ProtectedChannelError::AttestationSecurityVersionTooOld)
        );
        let other_binding = VbsAttestationData::for_policy([0xb3; 32], policy(false)).unwrap();
        assert_eq!(
            parsed.matches_expectation(other_binding, expected),
            Err(ProtectedChannelError::AttestationBindingMismatch)
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
