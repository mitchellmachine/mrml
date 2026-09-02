use crate::{TlsIdentityId, TlsKeyIdentity};
use mrml_acme::{
    revoke_certificate, AcmeDirectory, AcmeExchange, AcmeJwsSigner, AcmeTransport, AcmeUrl,
    AriCertificateId, JwkThumbprint, P256Jwk, ProtectedKey, RevocationOutcome,
    RevokeCertificateError,
};
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

#[derive(Clone, Copy)]
pub enum AcmeRevocationSigningIdentity<'a> {
    Account {
        account_url: &'a AcmeUrl,
        account_generation: u64,
        account_key: JwkThumbprint,
    },
    Certificate {
        public_key: &'a P256Jwk,
        key_identity: TlsKeyIdentity,
        key_generation: u64,
    },
}

pub struct AcmeRevocationAuthority<'a, T, S> {
    pub directory: &'a AcmeDirectory,
    pub certificate_der: &'a [u8],
    pub certificate_id: AriCertificateId,
    pub chain_digest: [u8; 32],
    pub signing_identity: AcmeRevocationSigningIdentity<'a>,
    pub exchange: &'a mut AcmeExchange,
    pub transport: &'a mut T,
    pub signer: &'a mut S,
    pub payload_scratch: &'a mut [u8],
    pub response_body: &'a mut [u8],
    pub jws_scratch: &'a mut [u8],
    pub observed_at_unix: u64,
}

impl<T: AcmeTransport, S: AcmeJwsSigner> AcmeRevocationAuthority<'_, T, S> {
    fn submit_exact(
        &mut self,
        prepared: PreparedRevocation,
    ) -> Result<RevocationReceipt, RevocationError> {
        if prepared.certificate_id != self.certificate_id
            || prepared.chain_digest != self.chain_digest
            || self.certificate_der.is_empty()
            || self.observed_at_unix == 0
        {
            return Err(RevocationError::ResolutionMismatch);
        }
        let (protected_key, signing_generation) = match self.signing_identity {
            AcmeRevocationSigningIdentity::Account {
                account_url,
                account_generation,
                account_key,
            } if prepared.authentication
                == (RevocationAuthentication::AccountKey {
                    account_generation,
                    account_key,
                }) =>
            {
                (ProtectedKey::Kid(account_url), account_generation)
            }
            AcmeRevocationSigningIdentity::Certificate {
                public_key,
                key_identity,
                key_generation,
            } if prepared.authentication
                == (RevocationAuthentication::CertificateKey {
                    key_identity,
                    key_generation,
                }) =>
            {
                (ProtectedKey::Jwk(public_key), key_generation)
            }
            _ => return Err(RevocationError::Unauthorized),
        };
        let outcome = revoke_certificate(
            self.directory,
            self.certificate_der,
            Some(prepared.reason as u8),
            protected_key,
            signing_generation,
            self.exchange,
            self.transport,
            self.signer,
            self.payload_scratch,
            self.response_body,
            self.jws_scratch,
        )
        .map_err(|error| match error {
            RevokeCertificateError::Post(_)
            | RevokeCertificateError::UnexpectedStatus
            | RevokeCertificateError::UnexpectedResponse => RevocationError::SubmissionUncertain,
            RevokeCertificateError::Payload(_) | RevokeCertificateError::Server(_) => {
                RevocationError::ResolutionMismatch
            }
        })?;
        let mut digest = Sha256::new();
        digest.update(b"mrml-acme-revocation-transaction-v1\0");
        digest.update(self.directory.revoke_cert.as_str().as_bytes());
        digest.update(&Sha256::digest(self.certificate_der));
        digest.update(&[prepared.reason as u8]);
        digest.update(&[match outcome {
            RevocationOutcome::Submitted => 1,
            RevocationOutcome::AlreadyRevoked => 2,
        }]);
        Ok(RevocationReceipt {
            prepared,
            ca_transaction_digest: digest.finalize(),
            revoked_at_unix: self.observed_at_unix,
        })
    }
}

impl<T: AcmeTransport, S: AcmeJwsSigner> RevocationAuthority for AcmeRevocationAuthority<'_, T, S> {
    fn submit(
        &mut self,
        prepared: PreparedRevocation,
    ) -> Result<RevocationReceipt, RevocationError> {
        self.submit_exact(prepared)
    }

    fn authoritative(
        &mut self,
        prepared: PreparedRevocation,
    ) -> Result<Option<RevocationReceipt>, RevocationError> {
        match self.submit_exact(prepared) {
            Ok(receipt) => Ok(Some(receipt)),
            Err(RevocationError::ResolutionMismatch) => Ok(None),
            Err(error) => Err(error),
        }
    }
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
    use mrml_acme::{
        AcmeHttpMethod, AcmeTransportRequest, AcmeTransportResponse, ApprovedAcmeJwsDigest,
        Es256Signature, JoseError,
    };
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

    struct Signer;
    impl AcmeJwsSigner for Signer {
        fn sign_acme_jws(
            &mut self,
            _: &ApprovedAcmeJwsDigest,
        ) -> Result<Es256Signature, JoseError> {
            Es256Signature::from_raw([1; 64])
        }
    }

    struct AcmeTransportFixture {
        calls: u8,
    }
    impl AcmeTransport for AcmeTransportFixture {
        type Error = ();
        fn exchange(
            &mut self,
            request: AcmeTransportRequest<'_>,
            _: &mut [u8],
        ) -> Result<AcmeTransportResponse<'_>, Self::Error> {
            self.calls += 1;
            Ok(if request.method == AcmeHttpMethod::Head {
                AcmeTransportResponse {
                    status: 200,
                    effective_url: "https://ca.example/new-nonce",
                    replay_nonce: Some("revocation-nonce"),
                    retry_after: None,
                    location: None,
                    content_type: None,
                    body_length: 0,
                }
            } else {
                AcmeTransportResponse {
                    status: 200,
                    effective_url: "https://ca.example/revoke",
                    replay_nonce: Some("next-revocation-nonce"),
                    retry_after: None,
                    location: None,
                    content_type: None,
                    body_length: 0,
                }
            })
        }
    }

    #[test]
    fn acme_authority_binds_prepared_certificate_and_account_route() {
        let directory_url = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let directory = AcmeDirectory::parse(
            r#"{"newNonce":"https://ca.example/new-nonce","newAccount":"https://ca.example/new-account","newOrder":"https://ca.example/new-order","revokeCert":"https://ca.example/revoke","keyChange":"https://ca.example/key-change"}"#,
            &directory_url,
            7,
        )
        .unwrap();
        let account_url = AcmeUrl::parse("https://ca.example/account/1", true).unwrap();
        let account_key = JwkThumbprint([2; 32]);
        let certificate_der = [0x30, 1, 0];
        let certificate_id = AriCertificateId::derive(&[1], &[2]).unwrap();
        let prepared = PreparedRevocation {
            identity: TlsIdentityId([3; 16]),
            identity_generation: 4,
            revocation_generation: 5,
            certificate_id,
            chain_digest: [6; 32],
            reason: RevocationReason::KeyCompromise,
            authentication: RevocationAuthentication::AccountKey {
                account_generation: 8,
                account_key,
            },
            authorization_digest: [9; 32],
        };
        let mut exchange = AcmeExchange::new(7, directory_url);
        let mut transport = AcmeTransportFixture { calls: 0 };
        let mut signer = Signer;
        let mut payload = [0; 1024];
        let mut response = [0; 1024];
        let mut jws = [0; 8192];
        let mut authority = AcmeRevocationAuthority {
            directory: &directory,
            certificate_der: &certificate_der,
            certificate_id,
            chain_digest: [6; 32],
            signing_identity: AcmeRevocationSigningIdentity::Account {
                account_url: &account_url,
                account_generation: 8,
                account_key,
            },
            exchange: &mut exchange,
            transport: &mut transport,
            signer: &mut signer,
            payload_scratch: &mut payload,
            response_body: &mut response,
            jws_scratch: &mut jws,
            observed_at_unix: 10,
        };
        let receipt = authority.submit(prepared).unwrap();
        assert!(receipt.prepared == prepared);
        assert_ne!(receipt.ca_transaction_digest, [0; 32]);
        assert_eq!(receipt.revoked_at_unix, 10);
        assert!(jws.iter().all(|byte| *byte == 0));
    }
}
