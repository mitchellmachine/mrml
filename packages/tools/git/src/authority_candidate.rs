//! Exact shared identities and states for protected receive candidates.

use crate::{
    QuarantineTransactionId, RepositoryGeneration, RepositoryIdentity, RevocationGeneration,
    TrustGeneration,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum AuthorityCandidateStatus {
    Receiving = 1,
    ProofsSealed = 2,
    Authorized = 3,
    ActivationStarted = 4,
    Activated = 5,
    ReceiptPersisted = 6,
    Completed = 7,
    Aborted = 8,
}

impl AuthorityCandidateStatus {
    pub const fn from_code(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Receiving,
            2 => Self::ProofsSealed,
            3 => Self::Authorized,
            4 => Self::ActivationStarted,
            5 => Self::Activated,
            6 => Self::ReceiptPersisted,
            7 => Self::Completed,
            8 => Self::Aborted,
            _ => return None,
        })
    }

    pub fn permits(self, next: Self) -> bool {
        next == Self::Aborted
            && matches!(
                self,
                Self::Receiving
                    | Self::ProofsSealed
                    | Self::Authorized
                    | Self::ActivationStarted
            )
            || matches!(
                (self, next),
                (Self::Receiving, Self::ProofsSealed)
                    | (Self::ProofsSealed, Self::Authorized)
                    | (Self::Authorized, Self::ActivationStarted)
                    | (Self::ActivationStarted, Self::Activated)
                    | (Self::Activated, Self::ReceiptPersisted)
                    | (Self::ReceiptPersisted, Self::Completed)
            )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityCandidateContext {
    pub id: QuarantineTransactionId,
    pub repository: RepositoryIdentity,
    pub current_generation: RepositoryGeneration,
    pub next_generation: RepositoryGeneration,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    pub policy_digest: [u8; 64],
    pub ref_update_digest: [u8; 64],
    pub introduced_commit_set_digest: [u8; 64],
    pub arrival_pack_digest: [u8; 64],
    pub proof_set_digest: [u8; 64],
    pub activation_digest: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityCandidateRecord {
    pub context: AuthorityCandidateContext,
    pub status: AuthorityCandidateStatus,
}
