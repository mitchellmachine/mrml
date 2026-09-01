use mrml_crypto::Sha256;

pub const ACME_OPERATION_JOURNAL_BYTES: usize = 304;
const MAGIC: &[u8; 8] = b"MRMLAOP1";
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AcmeOperationStage {
    RequestNotSent = 1,
    RequestMayHaveBeenSent = 2,
    ResponseAuthenticated = 3,
    OrderCreated = 4,
    ChallengeProvisioned = 5,
    ChallengeAccepted = 6,
    OrderReady = 7,
    CsrSubmitted = 8,
    CertificateRetrieved = 9,
    CandidateStaged = 10,
    CandidateActivated = 11,
    CleanupPending = 12,
    Complete = 13,
    Failed = 14,
    Uncertain = 15,
}

impl AcmeOperationStage {
    fn parse(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::RequestNotSent,
            2 => Self::RequestMayHaveBeenSent,
            3 => Self::ResponseAuthenticated,
            4 => Self::OrderCreated,
            5 => Self::ChallengeProvisioned,
            6 => Self::ChallengeAccepted,
            7 => Self::OrderReady,
            8 => Self::CsrSubmitted,
            9 => Self::CertificateRetrieved,
            10 => Self::CandidateStaged,
            11 => Self::CandidateActivated,
            12 => Self::CleanupPending,
            13 => Self::Complete,
            14 => Self::Failed,
            15 => Self::Uncertain,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcmeOperationJournal {
    pub operation_id: [u8; 16],
    pub operation_generation: u64,
    pub identity: [u8; 16],
    pub directory_generation: u64,
    pub account_generation: u64,
    pub stage: AcmeOperationStage,
    pub attempt_count: u16,
    pub next_attempt_unix: u64,
    pub directory_digest: [u8; 32],
    pub order_resource_digest: [u8; 32],
    pub authorization_resource_digest: [u8; 32],
    pub challenge_resource_digest: [u8; 32],
    pub dns_publication_digest: [u8; 32],
    pub csr_digest: [u8; 32],
    pub candidate_digest: [u8; 32],
    pub failure_code: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmeOperationJournalError {
    InvalidIdentity,
    InvalidGeneration,
    InvalidTransition,
    MissingBinding,
    AttemptOverflow,
    InvalidEncoding,
    OutputTooSmall,
}

impl AcmeOperationJournal {
    pub fn new(
        operation_id: [u8; 16],
        operation_generation: u64,
        identity: [u8; 16],
        directory_generation: u64,
        account_generation: u64,
        directory_bytes: &[u8],
    ) -> Result<Self, AcmeOperationJournalError> {
        if operation_id == [0; 16] || identity == [0; 16] {
            return Err(AcmeOperationJournalError::InvalidIdentity);
        }
        if operation_generation == 0 || directory_generation == 0 || account_generation == 0 {
            return Err(AcmeOperationJournalError::InvalidGeneration);
        }
        if directory_bytes.is_empty() {
            return Err(AcmeOperationJournalError::MissingBinding);
        }
        Ok(Self {
            operation_id,
            operation_generation,
            identity,
            directory_generation,
            account_generation,
            stage: AcmeOperationStage::RequestNotSent,
            attempt_count: 0,
            next_attempt_unix: 0,
            directory_digest: Sha256::digest(directory_bytes),
            order_resource_digest: [0; 32],
            authorization_resource_digest: [0; 32],
            challenge_resource_digest: [0; 32],
            dns_publication_digest: [0; 32],
            csr_digest: [0; 32],
            candidate_digest: [0; 32],
            failure_code: 0,
        })
    }

    pub fn advance(
        &mut self,
        next: AcmeOperationStage,
        binding: Option<&[u8]>,
    ) -> Result<(), AcmeOperationJournalError> {
        if !allowed(self.stage, next) {
            return Err(AcmeOperationJournalError::InvalidTransition);
        }
        let digest = match next {
            AcmeOperationStage::OrderCreated
            | AcmeOperationStage::ChallengeProvisioned
            | AcmeOperationStage::ChallengeAccepted
            | AcmeOperationStage::CsrSubmitted
            | AcmeOperationStage::CertificateRetrieved
            | AcmeOperationStage::CandidateStaged => Some(Sha256::digest(
                binding
                    .filter(|value| !value.is_empty())
                    .ok_or(AcmeOperationJournalError::MissingBinding)?,
            )),
            _ => None,
        };
        match next {
            AcmeOperationStage::OrderCreated => self.order_resource_digest = digest.unwrap(),
            AcmeOperationStage::ChallengeProvisioned => {
                self.dns_publication_digest = digest.unwrap()
            }
            AcmeOperationStage::ChallengeAccepted => {
                self.challenge_resource_digest = digest.unwrap()
            }
            AcmeOperationStage::CsrSubmitted => self.csr_digest = digest.unwrap(),
            AcmeOperationStage::CertificateRetrieved => {
                self.authorization_resource_digest = digest.unwrap()
            }
            AcmeOperationStage::CandidateStaged => self.candidate_digest = digest.unwrap(),
            _ => {}
        }
        self.stage = next;
        if !matches!(
            next,
            AcmeOperationStage::Failed | AcmeOperationStage::Uncertain
        ) {
            self.failure_code = 0;
        }
        Ok(())
    }

    pub fn schedule_retry(
        &mut self,
        next_attempt_unix: u64,
        uncertain: bool,
        failure_code: u16,
    ) -> Result<(), AcmeOperationJournalError> {
        if next_attempt_unix == 0 || failure_code == 0 || self.stage == AcmeOperationStage::Complete
        {
            return Err(AcmeOperationJournalError::InvalidTransition);
        }
        self.attempt_count = self
            .attempt_count
            .checked_add(1)
            .ok_or(AcmeOperationJournalError::AttemptOverflow)?;
        self.next_attempt_unix = next_attempt_unix;
        self.failure_code = failure_code;
        self.stage = if uncertain {
            AcmeOperationStage::Uncertain
        } else {
            AcmeOperationStage::Failed
        };
        Ok(())
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, AcmeOperationJournalError> {
        if output.len() < ACME_OPERATION_JOURNAL_BYTES {
            return Err(AcmeOperationJournalError::OutputTooSmall);
        }
        output[..ACME_OPERATION_JOURNAL_BYTES].fill(0);
        output[..8].copy_from_slice(MAGIC);
        output[8..10].copy_from_slice(&VERSION.to_be_bytes());
        output[10] = self.stage as u8;
        output[12..28].copy_from_slice(&self.operation_id);
        output[28..36].copy_from_slice(&self.operation_generation.to_be_bytes());
        output[36..52].copy_from_slice(&self.identity);
        output[52..60].copy_from_slice(&self.directory_generation.to_be_bytes());
        output[60..68].copy_from_slice(&self.account_generation.to_be_bytes());
        output[68..70].copy_from_slice(&self.attempt_count.to_be_bytes());
        output[70..72].copy_from_slice(&self.failure_code.to_be_bytes());
        output[72..80].copy_from_slice(&self.next_attempt_unix.to_be_bytes());
        for (index, digest) in [
            self.directory_digest,
            self.order_resource_digest,
            self.authorization_resource_digest,
            self.challenge_resource_digest,
            self.dns_publication_digest,
            self.csr_digest,
            self.candidate_digest,
        ]
        .iter()
        .enumerate()
        {
            let start = 80 + index * 32;
            output[start..start + 32].copy_from_slice(digest);
        }
        Ok(ACME_OPERATION_JOURNAL_BYTES)
    }

    pub fn decode(input: &[u8]) -> Result<Self, AcmeOperationJournalError> {
        if input.len() != ACME_OPERATION_JOURNAL_BYTES
            || &input[..8] != MAGIC
            || u16::from_be_bytes([input[8], input[9]]) != VERSION
            || input[11] != 0
        {
            return Err(AcmeOperationJournalError::InvalidEncoding);
        }
        let mut digests = [[0u8; 32]; 7];
        for (index, digest) in digests.iter_mut().enumerate() {
            let start = 80 + index * 32;
            digest.copy_from_slice(&input[start..start + 32]);
        }
        let journal = Self {
            operation_id: input[12..28]
                .try_into()
                .map_err(|_| AcmeOperationJournalError::InvalidEncoding)?,
            operation_generation: read_u64(&input[28..36])?,
            identity: input[36..52]
                .try_into()
                .map_err(|_| AcmeOperationJournalError::InvalidEncoding)?,
            directory_generation: read_u64(&input[52..60])?,
            account_generation: read_u64(&input[60..68])?,
            stage: AcmeOperationStage::parse(input[10])
                .ok_or(AcmeOperationJournalError::InvalidEncoding)?,
            attempt_count: u16::from_be_bytes([input[68], input[69]]),
            failure_code: u16::from_be_bytes([input[70], input[71]]),
            next_attempt_unix: read_u64(&input[72..80])?,
            directory_digest: digests[0],
            order_resource_digest: digests[1],
            authorization_resource_digest: digests[2],
            challenge_resource_digest: digests[3],
            dns_publication_digest: digests[4],
            csr_digest: digests[5],
            candidate_digest: digests[6],
        };
        journal.validate()?;
        Ok(journal)
    }

    fn validate(&self) -> Result<(), AcmeOperationJournalError> {
        if self.operation_id == [0; 16] || self.identity == [0; 16] {
            return Err(AcmeOperationJournalError::InvalidIdentity);
        }
        if self.operation_generation == 0
            || self.directory_generation == 0
            || self.account_generation == 0
        {
            return Err(AcmeOperationJournalError::InvalidGeneration);
        }
        if self.directory_digest == [0; 32]
            || (matches!(
                self.stage,
                AcmeOperationStage::Failed | AcmeOperationStage::Uncertain
            ) != (self.failure_code != 0 && self.next_attempt_unix != 0))
        {
            return Err(AcmeOperationJournalError::MissingBinding);
        }
        let required: Option<&[u8; 32]> = match self.stage {
            AcmeOperationStage::RequestNotSent
            | AcmeOperationStage::RequestMayHaveBeenSent
            | AcmeOperationStage::ResponseAuthenticated
            | AcmeOperationStage::Failed
            | AcmeOperationStage::Uncertain => None,
            AcmeOperationStage::OrderCreated => Some(&self.order_resource_digest),
            AcmeOperationStage::ChallengeProvisioned => Some(&self.dns_publication_digest),
            AcmeOperationStage::ChallengeAccepted | AcmeOperationStage::OrderReady => {
                Some(&self.challenge_resource_digest)
            }
            AcmeOperationStage::CsrSubmitted => Some(&self.csr_digest),
            AcmeOperationStage::CertificateRetrieved => Some(&self.authorization_resource_digest),
            AcmeOperationStage::CandidateStaged
            | AcmeOperationStage::CandidateActivated
            | AcmeOperationStage::CleanupPending
            | AcmeOperationStage::Complete => Some(&self.candidate_digest),
        };
        if required.is_some_and(|digest| *digest == [0; 32]) {
            return Err(AcmeOperationJournalError::MissingBinding);
        }
        Ok(())
    }
}

fn allowed(current: AcmeOperationStage, next: AcmeOperationStage) -> bool {
    matches!(
        (current, next),
        (
            AcmeOperationStage::RequestNotSent,
            AcmeOperationStage::RequestMayHaveBeenSent
        ) | (
            AcmeOperationStage::RequestMayHaveBeenSent,
            AcmeOperationStage::ResponseAuthenticated
        ) | (
            AcmeOperationStage::ResponseAuthenticated,
            AcmeOperationStage::OrderCreated
        ) | (
            AcmeOperationStage::OrderCreated,
            AcmeOperationStage::ChallengeProvisioned
        ) | (
            AcmeOperationStage::ChallengeProvisioned,
            AcmeOperationStage::ChallengeAccepted
        ) | (
            AcmeOperationStage::ChallengeAccepted,
            AcmeOperationStage::OrderReady
        ) | (
            AcmeOperationStage::OrderReady,
            AcmeOperationStage::CsrSubmitted
        ) | (
            AcmeOperationStage::CsrSubmitted,
            AcmeOperationStage::CertificateRetrieved
        ) | (
            AcmeOperationStage::CertificateRetrieved,
            AcmeOperationStage::CandidateStaged
        ) | (
            AcmeOperationStage::CandidateStaged,
            AcmeOperationStage::CandidateActivated
        ) | (
            AcmeOperationStage::CandidateActivated,
            AcmeOperationStage::CleanupPending
        ) | (
            AcmeOperationStage::CleanupPending,
            AcmeOperationStage::Complete
        ) | (
            AcmeOperationStage::Failed,
            AcmeOperationStage::CleanupPending
        ) | (
            AcmeOperationStage::Uncertain,
            AcmeOperationStage::ResponseAuthenticated
        )
    )
}

fn read_u64(bytes: &[u8]) -> Result<u64, AcmeOperationJournalError> {
    Ok(u64::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| AcmeOperationJournalError::InvalidEncoding)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal() -> AcmeOperationJournal {
        AcmeOperationJournal::new([1; 16], 1, [2; 16], 3, 4, b"directory").unwrap()
    }

    #[test]
    fn complete_issuance_sequence_round_trips_every_boundary() {
        let mut value = journal();
        for stage in [
            AcmeOperationStage::RequestMayHaveBeenSent,
            AcmeOperationStage::ResponseAuthenticated,
            AcmeOperationStage::OrderCreated,
            AcmeOperationStage::ChallengeProvisioned,
            AcmeOperationStage::ChallengeAccepted,
            AcmeOperationStage::OrderReady,
            AcmeOperationStage::CsrSubmitted,
            AcmeOperationStage::CertificateRetrieved,
            AcmeOperationStage::CandidateStaged,
            AcmeOperationStage::CandidateActivated,
            AcmeOperationStage::CleanupPending,
            AcmeOperationStage::Complete,
        ] {
            let binding = matches!(
                stage,
                AcmeOperationStage::OrderCreated
                    | AcmeOperationStage::ChallengeProvisioned
                    | AcmeOperationStage::ChallengeAccepted
                    | AcmeOperationStage::CsrSubmitted
                    | AcmeOperationStage::CertificateRetrieved
                    | AcmeOperationStage::CandidateStaged
            )
            .then_some(b"exact durable resource".as_slice());
            value.advance(stage, binding).unwrap();
            let mut encoded = [0u8; ACME_OPERATION_JOURNAL_BYTES];
            value.encode(&mut encoded).unwrap();
            assert_eq!(AcmeOperationJournal::decode(&encoded).unwrap(), value);
        }
    }

    #[test]
    fn lost_response_and_failure_require_explicit_reconciliation_or_cleanup() {
        let mut uncertain = journal();
        uncertain
            .advance(AcmeOperationStage::RequestMayHaveBeenSent, None)
            .unwrap();
        uncertain.schedule_retry(100, true, 7).unwrap();
        assert_eq!(uncertain.stage, AcmeOperationStage::Uncertain);
        uncertain
            .advance(AcmeOperationStage::ResponseAuthenticated, None)
            .unwrap();
        assert_eq!(uncertain.failure_code, 0);

        let mut failed = journal();
        failed.schedule_retry(200, false, 9).unwrap();
        failed
            .advance(AcmeOperationStage::CleanupPending, None)
            .unwrap();
        failed.advance(AcmeOperationStage::Complete, None).unwrap();
    }

    #[test]
    fn mutation_skips_and_missing_bindings_fail_closed() {
        let mut value = journal();
        assert_eq!(
            value.advance(AcmeOperationStage::OrderCreated, Some(b"order")),
            Err(AcmeOperationJournalError::InvalidTransition)
        );
        value
            .advance(AcmeOperationStage::RequestMayHaveBeenSent, None)
            .unwrap();
        value
            .advance(AcmeOperationStage::ResponseAuthenticated, None)
            .unwrap();
        assert_eq!(
            value.advance(AcmeOperationStage::OrderCreated, None),
            Err(AcmeOperationJournalError::MissingBinding)
        );
        let mut encoded = [0u8; ACME_OPERATION_JOURNAL_BYTES];
        value.encode(&mut encoded).unwrap();
        encoded[8] ^= 1;
        assert_eq!(
            AcmeOperationJournal::decode(&encoded),
            Err(AcmeOperationJournalError::InvalidEncoding)
        );
    }
}
