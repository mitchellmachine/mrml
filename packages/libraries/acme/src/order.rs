use crate::{AcmeDirectory, AcmeUrl, CertificateProfile, DnsIdentifier, JwkThumbprint, OrderState};
use mrml_crypto::Sha256;

pub const MAX_ORDER_IDENTIFIERS: usize = 16;
pub const MAX_AUTHORIZATIONS: usize = 16;
pub const MAX_CHALLENGES_PER_AUTHORIZATION: usize = 8;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ChallengeKind {
    Http01,
    TlsAlpn01,
    Dns01,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationState {
    Pending,
    Processing,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeState {
    Pending,
    Processing,
    Valid,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderError {
    EmptyIdentifiers,
    TooManyIdentifiers,
    DuplicateIdentifier,
    UnsortedIdentifiers,
    DirectoryGenerationMismatch,
    AccountGenerationMismatch,
    ProfileGenerationMismatch,
    UrlPolicy,
    InvalidState,
    StaleResponse,
    Substitution,
    RetryLimit,
    DeadlineExceeded,
    AuthorizationIncomplete,
    WildcardRequiresDns01,
    ReceiptMismatch,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuthorizationBinding {
    pub url: AcmeUrl,
    pub url_digest: [u8; 32],
    pub identifier: DnsIdentifier,
    pub wildcard: bool,
    pub generation: u64,
    pub state: AuthorizationState,
    pub selected_challenge: Option<ChallengeKind>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PreparedFinalization {
    pub order_generation: u64,
    pub csr_digest: [u8; 32],
    pub finalize_url_digest: [u8; 32],
    pub account_key: JwkThumbprint,
}

pub struct OrderLifecycle {
    pub generation: u64,
    pub directory_generation: u64,
    pub account_generation: u64,
    pub account_key: JwkThumbprint,
    pub order_url: AcmeUrl,
    pub finalize_url: AcmeUrl,
    pub certificate_url: Option<AcmeUrl>,
    pub profile: CertificateProfile,
    pub state: OrderState,
    pub deadline_unix: u64,
    pub retries_remaining: u8,
    identifiers: [Option<DnsIdentifier>; MAX_ORDER_IDENTIFIERS],
    identifier_count: u8,
    authorizations: [Option<AuthorizationBinding>; MAX_AUTHORIZATIONS],
    authorization_count: u8,
    prepared: Option<PreparedFinalization>,
}

impl OrderLifecycle {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        directory: &AcmeDirectory,
        account_generation: u64,
        account_key: JwkThumbprint,
        order_url: AcmeUrl,
        finalize_url: AcmeUrl,
        profile: CertificateProfile,
        identifiers: &[DnsIdentifier],
        deadline_unix: u64,
        retry_limit: u8,
    ) -> Result<Self, OrderError> {
        validate_identifiers(identifiers)?;
        if profile.directory_generation() != directory.generation {
            return Err(OrderError::ProfileGenerationMismatch);
        }
        if order_url.origin() != directory.new_order.origin()
            || finalize_url.origin() != directory.new_order.origin()
        {
            return Err(OrderError::UrlPolicy);
        }
        let mut stored = [None; MAX_ORDER_IDENTIFIERS];
        for (slot, identifier) in stored.iter_mut().zip(identifiers) {
            *slot = Some(*identifier);
        }
        Ok(Self {
            generation: 1,
            directory_generation: directory.generation,
            account_generation,
            account_key,
            order_url,
            finalize_url,
            certificate_url: None,
            profile,
            state: OrderState::Pending,
            deadline_unix,
            retries_remaining: retry_limit,
            identifiers: stored,
            identifier_count: identifiers.len() as u8,
            authorizations: [None; MAX_AUTHORIZATIONS],
            authorization_count: 0,
            prepared: None,
        })
    }

    pub fn identifiers(&self) -> impl Iterator<Item = &DnsIdentifier> {
        self.identifiers[..usize::from(self.identifier_count)]
            .iter()
            .flatten()
    }

    pub fn authorizations(&self) -> impl Iterator<Item = &AuthorizationBinding> {
        self.authorizations[..usize::from(self.authorization_count)]
            .iter()
            .flatten()
    }

    pub fn authorization_by_url_digest(
        &self,
        url_digest: [u8; 32],
    ) -> Option<&AuthorizationBinding> {
        self.authorizations()
            .find(|authorization| authorization.url_digest == url_digest)
    }

    pub fn bind_authorization(
        &mut self,
        url: AcmeUrl,
        identifier: DnsIdentifier,
        wildcard: bool,
        generation: u64,
    ) -> Result<(), OrderError> {
        if self.state != OrderState::Pending {
            return Err(OrderError::InvalidState);
        }
        if url.origin() != self.order_url.origin() {
            return Err(OrderError::UrlPolicy);
        }
        if !self.identifiers().any(|expected| expected == &identifier)
            || wildcard != identifier.is_wildcard()
        {
            return Err(OrderError::Substitution);
        }
        if self
            .authorizations()
            .any(|existing| existing.identifier == identifier || existing.url == url)
        {
            return Err(OrderError::Substitution);
        }
        let index = usize::from(self.authorization_count);
        if index >= MAX_AUTHORIZATIONS {
            return Err(OrderError::TooManyIdentifiers);
        }
        self.authorizations[index] = Some(AuthorizationBinding {
            url,
            url_digest: Sha256::digest(url.as_str().as_bytes()),
            identifier,
            wildcard,
            generation,
            state: AuthorizationState::Pending,
            selected_challenge: None,
        });
        self.authorization_count += 1;
        Ok(())
    }

    pub fn update_authorization(
        &mut self,
        url_digest: [u8; 32],
        generation: u64,
        state: AuthorizationState,
        selected_challenge: Option<ChallengeKind>,
        now_unix: u64,
    ) -> Result<(), OrderError> {
        self.check_deadline(now_unix)?;
        let authorization = self.authorizations[..usize::from(self.authorization_count)]
            .iter_mut()
            .flatten()
            .find(|candidate| candidate.url_digest == url_digest)
            .ok_or(OrderError::Substitution)?;
        if generation < authorization.generation {
            return Err(OrderError::StaleResponse);
        }
        if authorization.wildcard && selected_challenge != Some(ChallengeKind::Dns01) {
            return Err(OrderError::WildcardRequiresDns01);
        }
        authorization.state = transition_authorization(authorization.state, state)?;
        authorization.generation = generation;
        authorization.selected_challenge = selected_challenge;
        Ok(())
    }

    pub fn apply_order_response(
        &mut self,
        response_generation: u64,
        state: OrderState,
        certificate_url: Option<AcmeUrl>,
        now_unix: u64,
    ) -> Result<(), OrderError> {
        self.check_deadline(now_unix)?;
        if response_generation < self.generation {
            return Err(OrderError::StaleResponse);
        }
        if let Some(url) = certificate_url {
            if url.origin() != self.order_url.origin() {
                return Err(OrderError::UrlPolicy);
            }
            self.certificate_url = Some(url);
        }
        self.state = self
            .state
            .transition(state)
            .map_err(|_| OrderError::InvalidState)?;
        self.generation = response_generation;
        Ok(())
    }

    pub fn consume_retry(&mut self, now_unix: u64) -> Result<(), OrderError> {
        self.check_deadline(now_unix)?;
        self.retries_remaining = self
            .retries_remaining
            .checked_sub(1)
            .ok_or(OrderError::RetryLimit)?;
        Ok(())
    }

    pub fn prepare_finalize(&mut self, csr_der: &[u8]) -> Result<PreparedFinalization, OrderError> {
        if self.state != OrderState::Ready || self.prepared.is_some() {
            return Err(OrderError::InvalidState);
        }
        if usize::from(self.authorization_count) != usize::from(self.identifier_count)
            || !self
                .authorizations()
                .all(|authorization| authorization.state == AuthorizationState::Valid)
        {
            return Err(OrderError::AuthorizationIncomplete);
        }
        let receipt = PreparedFinalization {
            order_generation: self
                .generation
                .checked_add(1)
                .ok_or(OrderError::ArithmeticOverflow)?,
            csr_digest: Sha256::digest(csr_der),
            finalize_url_digest: Sha256::digest(self.finalize_url.as_str().as_bytes()),
            account_key: self.account_key,
        };
        self.prepared = Some(receipt);
        Ok(receipt)
    }

    pub fn commit_finalize(&mut self, receipt: PreparedFinalization) -> Result<(), OrderError> {
        if self.prepared != Some(receipt)
            || receipt.order_generation != self.generation.checked_add(1).unwrap_or(0)
        {
            return Err(OrderError::ReceiptMismatch);
        }
        self.state = self
            .state
            .transition(OrderState::Processing)
            .map_err(|_| OrderError::InvalidState)?;
        self.generation = receipt.order_generation;
        self.prepared = None;
        Ok(())
    }

    pub fn abort_finalize(&mut self, receipt: PreparedFinalization) -> Result<(), OrderError> {
        if self.prepared != Some(receipt) || self.state != OrderState::Ready {
            return Err(OrderError::ReceiptMismatch);
        }
        self.prepared = None;
        Ok(())
    }

    fn check_deadline(&self, now_unix: u64) -> Result<(), OrderError> {
        if now_unix > self.deadline_unix {
            Err(OrderError::DeadlineExceeded)
        } else {
            Ok(())
        }
    }
}

fn validate_identifiers(identifiers: &[DnsIdentifier]) -> Result<(), OrderError> {
    if identifiers.is_empty() {
        return Err(OrderError::EmptyIdentifiers);
    }
    if identifiers.len() > MAX_ORDER_IDENTIFIERS {
        return Err(OrderError::TooManyIdentifiers);
    }
    for pair in identifiers.windows(2) {
        match pair[0].as_str().cmp(pair[1].as_str()) {
            core::cmp::Ordering::Less => {}
            core::cmp::Ordering::Equal => return Err(OrderError::DuplicateIdentifier),
            core::cmp::Ordering::Greater => return Err(OrderError::UnsortedIdentifiers),
        }
    }
    Ok(())
}

fn transition_authorization(
    current: AuthorizationState,
    next: AuthorizationState,
) -> Result<AuthorizationState, OrderError> {
    use AuthorizationState::*;
    match (current, next) {
        (Pending, Pending | Processing | Valid | Invalid | Deactivated | Expired | Revoked)
        | (Processing, Processing | Valid | Invalid | Deactivated | Expired | Revoked)
        | (Valid, Valid | Revoked)
        | (Invalid, Invalid)
        | (Deactivated, Deactivated)
        | (Expired, Expired)
        | (Revoked, Revoked) => Ok(next),
        _ => Err(OrderError::InvalidState),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory() -> AcmeDirectory {
        AcmeDirectory::parse(r#"{"newNonce":"https://ca.example/n","newAccount":"https://ca.example/a","newOrder":"https://ca.example/o","revokeCert":"https://ca.example/r","keyChange":"https://ca.example/k","meta":{"profiles":{"classic":"https://docs.example/classic"}}}"#,&AcmeUrl::parse("https://ca.example/d",false).unwrap(),7).unwrap()
    }
    fn thumbprint() -> JwkThumbprint {
        JwkThumbprint([9; 32])
    }
    fn url(path: &str) -> AcmeUrl {
        let mut bytes = [0u8; 80];
        let prefix = b"https://ca.example/";
        bytes[..prefix.len()].copy_from_slice(prefix);
        bytes[prefix.len()..prefix.len() + path.len()].copy_from_slice(path.as_bytes());
        AcmeUrl::parse(
            core::str::from_utf8(&bytes[..prefix.len() + path.len()]).unwrap(),
            false,
        )
        .unwrap()
    }
    #[test]
    fn rejects_authorization_substitution_and_wildcard_non_dns() {
        let d = directory();
        let names = [DnsIdentifier::parse("*.example", true).unwrap()];
        let mut order = OrderLifecycle::create(
            &d,
            2,
            thumbprint(),
            url("order/1"),
            url("finalize/1"),
            CertificateProfile::parse("classic", 7).unwrap(),
            &names,
            100,
            3,
        )
        .unwrap();
        order
            .bind_authorization(url("authz/1"), names[0], true, 1)
            .unwrap();
        let digest = order.authorizations().next().unwrap().url_digest;
        assert_eq!(
            order.update_authorization(
                digest,
                2,
                AuthorizationState::Valid,
                Some(ChallengeKind::Http01),
                1
            ),
            Err(OrderError::WildcardRequiresDns01)
        );
        assert_eq!(
            order.update_authorization(
                [4; 32],
                2,
                AuthorizationState::Valid,
                Some(ChallengeKind::Dns01),
                1
            ),
            Err(OrderError::Substitution)
        );
    }
    #[test]
    fn finalize_requires_exact_valid_authorizations_and_one_use_receipt() {
        let d = directory();
        let names = [DnsIdentifier::parse("git.example", false).unwrap()];
        let mut order = OrderLifecycle::create(
            &d,
            2,
            thumbprint(),
            url("order/1"),
            url("finalize/1"),
            CertificateProfile::parse("classic", 7).unwrap(),
            &names,
            100,
            3,
        )
        .unwrap();
        order
            .bind_authorization(url("authz/1"), names[0], false, 1)
            .unwrap();
        order
            .apply_order_response(2, OrderState::Ready, None, 1)
            .unwrap();
        assert!(matches!(
            order.prepare_finalize(b"csr"),
            Err(OrderError::AuthorizationIncomplete)
        ));
        let digest = order.authorizations().next().unwrap().url_digest;
        order
            .update_authorization(
                digest,
                2,
                AuthorizationState::Valid,
                Some(ChallengeKind::TlsAlpn01),
                1,
            )
            .unwrap();
        let receipt = order.prepare_finalize(b"csr").unwrap();
        order.commit_finalize(receipt).unwrap();
        assert_eq!(
            order.commit_finalize(receipt),
            Err(OrderError::ReceiptMismatch)
        );
    }
}
