pub const PROTECTION_REPORT_BYTES: usize = 160;
const REPORT_MAGIC: [u8; 8] = *b"MRMLPX01";
const REPORT_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProtectionBackend {
    Unprotected = 0,
    VbsEnclave = 1,
    BareMetalMonitor = 2,
}

impl ProtectionBackend {
    const fn decode(value: u8) -> Result<Self, ProtectionError> {
        match value {
            0 => Ok(Self::Unprotected),
            1 => Ok(Self::VbsEnclave),
            2 => Ok(Self::BareMetalMonitor),
            _ => Err(ProtectionError::UnknownBackend),
        }
    }

    pub const fn maximum_claims(self) -> ProtectionClaims {
        match self {
            Self::Unprotected => ProtectionClaims::NONE,
            Self::VbsEnclave => ProtectionClaims::VTL0_ISOLATION.union(ProtectionClaims::MEASURED),
            Self::BareMetalMonitor => {
                ProtectionClaims::DOMAIN_ISOLATION.union(ProtectionClaims::MEASURED)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionClaims(u16);

impl ProtectionClaims {
    pub const NONE: Self = Self(0);
    pub const VTL0_ISOLATION: Self = Self(1 << 0);
    pub const HOST_VMM_ISOLATION: Self = Self(1 << 1);
    pub const PRIVATE_MEMORY: Self = Self(1 << 2);
    pub const MEASURED: Self = Self(1 << 3);
    pub const ATTESTED: Self = Self(1 << 4);
    pub const SEALED_KEYS: Self = Self(1 << 5);
    pub const DOMAIN_ISOLATION: Self = Self(1 << 6);
    pub const TRUSTED_IO: Self = Self(1 << 7);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    const fn bits(self) -> u16 {
        self.0
    }

    const fn from_bits(bits: u16) -> Result<Self, ProtectionError> {
        if bits & !0xff != 0 {
            return Err(ProtectionError::UnknownClaims);
        }
        Ok(Self(bits))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectionError {
    Malformed,
    UnknownBackend,
    UnknownClaims,
    UnsupportedClaim,
    MissingMeasurement,
    MissingNonce,
    Replay,
    SequenceExhausted,
    DebugDenied,
    SecurityVersionTooOld,
    MeasurementMismatch,
    InsufficientProtection,
    BackendMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionReport {
    backend: ProtectionBackend,
    claims: ProtectionClaims,
    debug_allowed: bool,
    security_version: u64,
    sequence: u64,
    measurement: [u8; 64],
    nonce: [u8; 32],
}

impl ProtectionReport {
    pub fn new(
        backend: ProtectionBackend,
        claims: ProtectionClaims,
        debug_allowed: bool,
        security_version: u64,
        sequence: u64,
        measurement: [u8; 64],
        nonce: [u8; 32],
    ) -> Result<Self, ProtectionError> {
        if !backend.maximum_claims().contains(claims) {
            return Err(ProtectionError::UnsupportedClaim);
        }
        if backend != ProtectionBackend::Unprotected && measurement == [0; 64] {
            return Err(ProtectionError::MissingMeasurement);
        }
        if nonce == [0; 32] {
            return Err(ProtectionError::MissingNonce);
        }
        Ok(Self {
            backend,
            claims,
            debug_allowed,
            security_version,
            sequence,
            measurement,
            nonce,
        })
    }

    pub const fn backend(self) -> ProtectionBackend {
        self.backend
    }

    pub const fn claims(self) -> ProtectionClaims {
        self.claims
    }

    pub const fn measurement(self) -> [u8; 64] {
        self.measurement
    }

    pub const fn nonce(self) -> [u8; 32] {
        self.nonce
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub const fn security_version(self) -> u64 {
        self.security_version
    }

    pub const fn debug_allowed(self) -> bool {
        self.debug_allowed
    }

    pub fn encode(self) -> [u8; PROTECTION_REPORT_BYTES] {
        let mut output = [0; PROTECTION_REPORT_BYTES];
        output[..8].copy_from_slice(&REPORT_MAGIC);
        output[8..10].copy_from_slice(&REPORT_VERSION.to_le_bytes());
        output[10] = self.backend as u8;
        output[11] = u8::from(self.debug_allowed);
        output[12..14].copy_from_slice(&self.claims.bits().to_le_bytes());
        output[16..24].copy_from_slice(&self.security_version.to_le_bytes());
        output[24..32].copy_from_slice(&self.sequence.to_le_bytes());
        output[32..96].copy_from_slice(&self.measurement);
        output[96..128].copy_from_slice(&self.nonce);
        output
    }

    pub fn decode(input: &[u8]) -> Result<Self, ProtectionError> {
        if input.len() != PROTECTION_REPORT_BYTES
            || input[..8] != REPORT_MAGIC
            || u16::from_le_bytes(input[8..10].try_into().unwrap_or([0; 2])) != REPORT_VERSION
            || input[11] > 1
            || input[14..16] != [0; 2]
            || input[128..].iter().any(|byte| *byte != 0)
        {
            return Err(ProtectionError::Malformed);
        }
        let backend = ProtectionBackend::decode(input[10])?;
        let claims = ProtectionClaims::from_bits(u16::from_le_bytes(
            input[12..14]
                .try_into()
                .map_err(|_| ProtectionError::Malformed)?,
        ))?;
        let mut measurement = [0; 64];
        measurement.copy_from_slice(&input[32..96]);
        let mut nonce = [0; 32];
        nonce.copy_from_slice(&input[96..128]);
        Self::new(
            backend,
            claims,
            input[11] != 0,
            u64::from_le_bytes(
                input[16..24]
                    .try_into()
                    .map_err(|_| ProtectionError::Malformed)?,
            ),
            u64::from_le_bytes(
                input[24..32]
                    .try_into()
                    .map_err(|_| ProtectionError::Malformed)?,
            ),
            measurement,
            nonce,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionPolicy {
    required_backend: ProtectionBackend,
    required_claims: ProtectionClaims,
    allow_debug: bool,
    minimum_security_version: u64,
    expected_measurement: [u8; 64],
}

impl ProtectionPolicy {
    pub const fn new(
        required_backend: ProtectionBackend,
        required_claims: ProtectionClaims,
        allow_debug: bool,
        minimum_security_version: u64,
        expected_measurement: [u8; 64],
    ) -> Self {
        Self {
            required_backend,
            required_claims,
            allow_debug,
            minimum_security_version,
            expected_measurement,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionAdmission {
    evidence_source: ProtectionEvidenceSource,
    backend: ProtectionBackend,
    claims: ProtectionClaims,
    measurement: [u8; 64],
    nonce: [u8; 32],
    sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectionEvidenceSource {
    SelfAssertedReport,
    AuthenticatedAuthorityReceipt,
}

impl ProtectionAdmission {
    pub const fn evidence_source(self) -> ProtectionEvidenceSource {
        self.evidence_source
    }

    pub const fn backend(self) -> ProtectionBackend {
        self.backend
    }

    pub const fn claims(self) -> ProtectionClaims {
        self.claims
    }

    pub const fn measurement(self) -> [u8; 64] {
        self.measurement
    }

    pub const fn nonce(self) -> [u8; 32] {
        self.nonce
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub const fn permits_secret_release(self) -> bool {
        matches!(
            self.evidence_source,
            ProtectionEvidenceSource::AuthenticatedAuthorityReceipt
        ) && self.claims.contains(ProtectionClaims::SEALED_KEYS)
            && self.claims.contains(ProtectionClaims::MEASURED)
    }
}

pub struct ProtectionSession {
    last_sequence: Option<u64>,
    nonce: [u8; 32],
}

impl ProtectionSession {
    pub fn new(nonce: [u8; 32]) -> Result<Self, ProtectionError> {
        if nonce == [0; 32] {
            return Err(ProtectionError::MissingNonce);
        }
        Ok(Self {
            last_sequence: None,
            nonce,
        })
    }

    pub fn admit(
        &mut self,
        report: ProtectionReport,
        policy: ProtectionPolicy,
    ) -> Result<ProtectionAdmission, ProtectionError> {
        self.admit_with_source(report, policy, ProtectionEvidenceSource::SelfAssertedReport)
    }

    pub(crate) fn admit_authority_receipt(
        &mut self,
        report: ProtectionReport,
        policy: ProtectionPolicy,
    ) -> Result<ProtectionAdmission, ProtectionError> {
        self.admit_with_source(
            report,
            policy,
            ProtectionEvidenceSource::AuthenticatedAuthorityReceipt,
        )
    }

    fn admit_with_source(
        &mut self,
        report: ProtectionReport,
        policy: ProtectionPolicy,
        evidence_source: ProtectionEvidenceSource,
    ) -> Result<ProtectionAdmission, ProtectionError> {
        if report.nonce != self.nonce {
            return Err(ProtectionError::MissingNonce);
        }
        if report.backend != policy.required_backend {
            return Err(ProtectionError::BackendMismatch);
        }
        if self
            .last_sequence
            .is_some_and(|last| report.sequence <= last)
        {
            return Err(ProtectionError::Replay);
        }
        if report.debug_allowed && !policy.allow_debug {
            return Err(ProtectionError::DebugDenied);
        }
        if report.security_version < policy.minimum_security_version {
            return Err(ProtectionError::SecurityVersionTooOld);
        }
        if report.measurement != policy.expected_measurement {
            return Err(ProtectionError::MeasurementMismatch);
        }
        if !report.claims.contains(policy.required_claims) {
            return Err(ProtectionError::InsufficientProtection);
        }
        let next = report
            .sequence
            .checked_add(1)
            .ok_or(ProtectionError::SequenceExhausted)?;
        self.last_sequence = Some(next - 1);
        Ok(ProtectionAdmission {
            evidence_source,
            backend: report.backend,
            claims: report.claims,
            measurement: report.measurement,
            nonce: report.nonce,
            sequence: report.sequence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEASUREMENT: [u8; 64] = [0x5a; 64];
    const NONCE: [u8; 32] = [0xa5; 32];

    fn vbs(sequence: u64) -> ProtectionReport {
        ProtectionReport::new(
            ProtectionBackend::VbsEnclave,
            ProtectionBackend::VbsEnclave.maximum_claims(),
            false,
            7,
            sequence,
            MEASUREMENT,
            NONCE,
        )
        .unwrap()
    }

    #[test]
    fn report_encoding_is_canonical_and_bounded() {
        let encoded = vbs(1).encode();
        assert_eq!(ProtectionReport::decode(&encoded), Ok(vbs(1)));
        let mut malformed = encoded;
        malformed[159] = 1;
        assert_eq!(
            ProtectionReport::decode(&malformed),
            Err(ProtectionError::Malformed)
        );
        assert_eq!(
            ProtectionReport::decode(&encoded[..159]),
            Err(ProtectionError::Malformed)
        );
    }

    #[test]
    fn vbs_cannot_claim_host_vmm_or_trusted_io_protection() {
        for forbidden in [
            ProtectionClaims::HOST_VMM_ISOLATION,
            ProtectionClaims::PRIVATE_MEMORY,
            ProtectionClaims::TRUSTED_IO,
        ] {
            assert_eq!(
                ProtectionReport::new(
                    ProtectionBackend::VbsEnclave,
                    ProtectionBackend::VbsEnclave
                        .maximum_claims()
                        .union(forbidden),
                    false,
                    1,
                    1,
                    MEASUREMENT,
                    NONCE,
                ),
                Err(ProtectionError::UnsupportedClaim)
            );
        }
    }

    #[test]
    fn admission_rejects_downgrade_debug_replay_and_wrong_measurement() {
        let required = ProtectionClaims::VTL0_ISOLATION.union(ProtectionClaims::MEASURED);
        let policy = ProtectionPolicy::new(
            ProtectionBackend::VbsEnclave,
            required,
            false,
            7,
            MEASUREMENT,
        );
        let mut session = ProtectionSession::new(NONCE).unwrap();
        let admitted = session.admit(vbs(4), policy).unwrap();
        assert_eq!(
            admitted.evidence_source(),
            ProtectionEvidenceSource::SelfAssertedReport
        );
        assert!(!admitted.permits_secret_release());
        assert_eq!(session.admit(vbs(4), policy), Err(ProtectionError::Replay));

        let debug = ProtectionReport::new(
            ProtectionBackend::VbsEnclave,
            required,
            true,
            7,
            5,
            MEASUREMENT,
            NONCE,
        )
        .unwrap();
        assert_eq!(
            session.admit(debug, policy),
            Err(ProtectionError::DebugDenied)
        );

        let weak_policy = ProtectionPolicy::new(
            ProtectionBackend::VbsEnclave,
            ProtectionClaims::HOST_VMM_ISOLATION,
            false,
            7,
            MEASUREMENT,
        );
        assert_eq!(
            session.admit(vbs(6), weak_policy),
            Err(ProtectionError::InsufficientProtection)
        );

        let wrong_measurement =
            ProtectionPolicy::new(ProtectionBackend::VbsEnclave, required, false, 7, [1; 64]);
        assert_eq!(
            session.admit(vbs(7), wrong_measurement),
            Err(ProtectionError::MeasurementMismatch)
        );
    }

    #[test]
    fn unprotected_mode_never_releases_secrets() {
        let report = ProtectionReport::new(
            ProtectionBackend::Unprotected,
            ProtectionClaims::NONE,
            false,
            0,
            1,
            [0; 64],
            NONCE,
        )
        .unwrap();
        let mut session = ProtectionSession::new(NONCE).unwrap();
        let admission = session
            .admit(
                report,
                ProtectionPolicy::new(
                    ProtectionBackend::Unprotected,
                    ProtectionClaims::NONE,
                    false,
                    0,
                    [0; 64],
                ),
            )
            .unwrap();
        assert!(!admission.permits_secret_release());
    }

    #[test]
    fn exact_backend_is_required_before_sequence_is_consumed() {
        let policy = ProtectionPolicy::new(
            ProtectionBackend::VbsEnclave,
            ProtectionClaims::MEASURED,
            false,
            1,
            MEASUREMENT,
        );
        let bare_metal = ProtectionReport::new(
            ProtectionBackend::BareMetalMonitor,
            ProtectionClaims::MEASURED,
            false,
            7,
            4,
            MEASUREMENT,
            NONCE,
        )
        .unwrap();
        let mut session = ProtectionSession::new(NONCE).unwrap();
        assert_eq!(
            session.admit(bare_metal, policy),
            Err(ProtectionError::BackendMismatch)
        );
        assert_eq!(
            session.admit(vbs(4), policy).unwrap().backend(),
            ProtectionBackend::VbsEnclave
        );
    }

    #[test]
    fn unimplemented_key_sealing_cannot_be_claimed() {
        for backend in [
            ProtectionBackend::VbsEnclave,
            ProtectionBackend::BareMetalMonitor,
        ] {
            assert_eq!(
                ProtectionReport::new(
                    backend,
                    backend
                        .maximum_claims()
                        .union(ProtectionClaims::SEALED_KEYS),
                    false,
                    1,
                    1,
                    MEASUREMENT,
                    NONCE,
                ),
                Err(ProtectionError::UnsupportedClaim)
            );
        }
    }
}
