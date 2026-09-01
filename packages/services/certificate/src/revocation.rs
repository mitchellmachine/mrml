use crate::{TlsIdentityId, TlsKeyIdentity};
use mrml_acme::{AriCertificateId, JwkThumbprint};
use mrml_crypto::Sha256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    PrivilegeWithdrawn = 9,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RevocationAuthentication {
    AccountKey {
        account_generation: u64,
        account_key: JwkThumbprint,
    },
    CertificateKey {
        key_identity: TlsKeyIdentity,
        key_generation: u64,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum AutomaticRevocationCause {
    ConfirmedKeyCompromise {
        incident_digest: [u8; 32],
    },
    ReplacementPolicy {
        replacement_certificate: AriCertificateId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationError {
    Unauthorized,
    InvalidState,
    ReceiptMismatch,
    SubmissionUncertain,
    ResolutionMismatch,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationState {
    Prepared,
    SubmissionUncertain,
    Revoked,
    NotRevoked,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RevocationAuthorization {
    pub policy_generation: u64,
    pub certificate_id: AriCertificateId,
    pub chain_digest: [u8; 32],
    pub reason: RevocationReason,
    pub owner_approval_digest: Option<[u8; 32]>,
    pub automatic_cause: Option<AutomaticRevocationCause>,
}

impl RevocationAuthorization {
    pub fn owner(
        policy_generation: u64,
        certificate_id: AriCertificateId,
        chain_digest: [u8; 32],
        reason: RevocationReason,
        preview: &[u8],
    ) -> Result<Self, RevocationError> {
        if preview.is_empty() {
            return Err(RevocationError::Unauthorized);
        }
        let mut d = Sha256::new();
        d.update(b"mrml-revocation-owner-preview-v1\0");
        d.update(preview);
        Ok(Self {
            policy_generation,
            certificate_id,
            chain_digest,
            reason,
            owner_approval_digest: Some(d.finalize()),
            automatic_cause: None,
        })
    }
    pub fn automatic(
        policy_generation: u64,
        certificate_id: AriCertificateId,
        chain_digest: [u8; 32],
        reason: RevocationReason,
        cause: AutomaticRevocationCause,
    ) -> Result<Self, RevocationError> {
        let allowed = matches!(
            (reason, cause),
            (
                RevocationReason::KeyCompromise,
                AutomaticRevocationCause::ConfirmedKeyCompromise { .. }
            ) | (
                RevocationReason::Superseded,
                AutomaticRevocationCause::ReplacementPolicy { .. }
            )
        );
        if !allowed
            || matches!(cause, AutomaticRevocationCause::ReplacementPolicy { replacement_certificate } if replacement_certificate == certificate_id)
        {
            return Err(RevocationError::Unauthorized);
        }
        Ok(Self {
            policy_generation,
            certificate_id,
            chain_digest,
            reason,
            owner_approval_digest: None,
            automatic_cause: Some(cause),
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RevocationCredentialPolicy {
    pub account: Option<(u64, JwkThumbprint)>,
    pub certificate: (TlsKeyIdentity, u64),
}
impl RevocationCredentialPolicy {
    fn authorizes(self, authentication: RevocationAuthentication) -> bool {
        match authentication {
            RevocationAuthentication::AccountKey {
                account_generation,
                account_key,
            } => self.account == Some((account_generation, account_key)),
            RevocationAuthentication::CertificateKey {
                key_identity,
                key_generation,
            } => self.certificate == (key_identity, key_generation),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PreparedRevocation {
    pub identity: TlsIdentityId,
    pub identity_generation: u64,
    pub revocation_generation: u64,
    pub certificate_id: AriCertificateId,
    pub chain_digest: [u8; 32],
    pub reason: RevocationReason,
    pub authentication: RevocationAuthentication,
    pub authorization_digest: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RevocationReceipt {
    pub prepared: PreparedRevocation,
    pub ca_transaction_digest: [u8; 32],
    pub revoked_at_unix: u64,
}

pub trait RevocationAuthority {
    fn submit(
        &mut self,
        prepared: PreparedRevocation,
    ) -> Result<RevocationReceipt, RevocationError>;
    fn authoritative(
        &mut self,
        prepared: PreparedRevocation,
    ) -> Result<Option<RevocationReceipt>, RevocationError>;
}

pub struct RevocationLifecycle {
    pub state: RevocationState,
    prepared: PreparedRevocation,
    receipt: Option<RevocationReceipt>,
}
impl RevocationLifecycle {
    pub fn prepare(
        identity: TlsIdentityId,
        identity_generation: u64,
        previous_revocation_generation: u64,
        authorization: RevocationAuthorization,
        authentication: RevocationAuthentication,
        credential_policy: RevocationCredentialPolicy,
    ) -> Result<Self, RevocationError> {
        if authorization.owner_approval_digest.is_none() == authorization.automatic_cause.is_none()
            || !credential_policy.authorizes(authentication)
        {
            return Err(RevocationError::Unauthorized);
        }
        let revocation_generation = previous_revocation_generation
            .checked_add(1)
            .ok_or(RevocationError::ArithmeticOverflow)?;
        let authorization_digest = authorization_digest(authorization);
        Ok(Self {
            state: RevocationState::Prepared,
            prepared: PreparedRevocation {
                identity,
                identity_generation,
                revocation_generation,
                certificate_id: authorization.certificate_id,
                chain_digest: authorization.chain_digest,
                reason: authorization.reason,
                authentication,
                authorization_digest,
            },
            receipt: None,
        })
    }
    pub fn submit(
        &mut self,
        authority: &mut impl RevocationAuthority,
    ) -> Result<RevocationReceipt, RevocationError> {
        if self.state != RevocationState::Prepared {
            return Err(RevocationError::InvalidState);
        }
        match authority.submit(self.prepared) {
            Ok(receipt) => self.commit(receipt),
            Err(RevocationError::SubmissionUncertain) => {
                self.state = RevocationState::SubmissionUncertain;
                Err(RevocationError::SubmissionUncertain)
            }
            Err(e) => Err(e),
        }
    }
    pub fn resolve(
        &mut self,
        authority: &mut impl RevocationAuthority,
    ) -> Result<RevocationState, RevocationError> {
        if self.state != RevocationState::SubmissionUncertain {
            return Err(RevocationError::InvalidState);
        }
        match authority.authoritative(self.prepared)? {
            Some(receipt) => {
                self.commit(receipt)?;
                Ok(RevocationState::Revoked)
            }
            None => {
                self.state = RevocationState::NotRevoked;
                Ok(self.state)
            }
        }
    }
    fn commit(&mut self, receipt: RevocationReceipt) -> Result<RevocationReceipt, RevocationError> {
        if receipt.prepared != self.prepared
            || receipt.revoked_at_unix == 0
            || receipt.ca_transaction_digest == [0; 32]
        {
            return Err(RevocationError::ReceiptMismatch);
        }
        self.receipt = Some(receipt);
        self.state = RevocationState::Revoked;
        Ok(receipt)
    }
    pub fn receipt(&self) -> Option<RevocationReceipt> {
        self.receipt
    }
}

fn authorization_digest(a: RevocationAuthorization) -> [u8; 32] {
    let mut d = Sha256::new();
    d.update(b"mrml-revocation-authorization-v1\0");
    d.update(&a.policy_generation.to_be_bytes());
    d.update(a.certificate_id.as_str().as_bytes());
    d.update(&a.chain_digest);
    d.update(&[a.reason as u8]);
    if let Some(x) = a.owner_approval_digest {
        d.update(&[1]);
        d.update(&x);
    }
    if let Some(c) = a.automatic_cause {
        d.update(&[2]);
        match c {
            AutomaticRevocationCause::ConfirmedKeyCompromise { incident_digest } => {
                d.update(&[1]);
                d.update(&incident_digest)
            }
            AutomaticRevocationCause::ReplacementPolicy {
                replacement_certificate,
            } => {
                d.update(&[2]);
                d.update(replacement_certificate.as_str().as_bytes())
            }
        }
    }
    d.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Authority {
        receipt: Option<RevocationReceipt>,
        uncertain: bool,
    }
    impl RevocationAuthority for Authority {
        fn submit(&mut self, p: PreparedRevocation) -> Result<RevocationReceipt, RevocationError> {
            let r = RevocationReceipt {
                prepared: p,
                ca_transaction_digest: [7; 32],
                revoked_at_unix: 9,
            };
            self.receipt = Some(r);
            if self.uncertain {
                Err(RevocationError::SubmissionUncertain)
            } else {
                Ok(r)
            }
        }
        fn authoritative(
            &mut self,
            _: PreparedRevocation,
        ) -> Result<Option<RevocationReceipt>, RevocationError> {
            Ok(self.receipt)
        }
    }
    #[test]
    fn uncertainty_resolves_without_guessing_or_destroying_identity() {
        let cert = AriCertificateId::derive(&[1], &[2]).unwrap();
        let auth = RevocationAuthorization::owner(
            3,
            cert,
            [4; 32],
            RevocationReason::CessationOfOperation,
            b"exact preview",
        )
        .unwrap();
        let credential_policy = RevocationCredentialPolicy {
            account: None,
            certificate: (TlsKeyIdentity([6; 32]), 8),
        };
        let mut lifecycle = RevocationLifecycle::prepare(
            TlsIdentityId([5; 16]),
            8,
            0,
            auth,
            RevocationAuthentication::CertificateKey {
                key_identity: TlsKeyIdentity([6; 32]),
                key_generation: 8,
            },
            credential_policy,
        )
        .unwrap();
        let mut ca = Authority {
            receipt: None,
            uncertain: true,
        };
        assert_eq!(
            lifecycle.submit(&mut ca).err(),
            Some(RevocationError::SubmissionUncertain)
        );
        assert_eq!(lifecycle.resolve(&mut ca), Ok(RevocationState::Revoked));
        assert!(lifecycle.receipt().is_some());
    }
    #[test]
    fn automatic_policy_is_narrow() {
        let cert = AriCertificateId::derive(&[1], &[2]).unwrap();
        assert!(matches!(
            RevocationAuthorization::automatic(
                1,
                cert,
                [3; 32],
                RevocationReason::CessationOfOperation,
                AutomaticRevocationCause::ConfirmedKeyCompromise {
                    incident_digest: [4; 32]
                }
            ),
            Err(RevocationError::Unauthorized)
        ));
    }
}
