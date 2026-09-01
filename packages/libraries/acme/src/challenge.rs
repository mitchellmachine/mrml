use crate::{AcmeUrl, ChallengeKind, DnsIdentifier, JwkThumbprint, encode_base64url};
use mrml_crypto::Sha256;

pub const MAX_CHALLENGE_TOKEN: usize = 128;
pub const MAX_KEY_AUTHORIZATION: usize = MAX_CHALLENGE_TOKEN + 1 + 43;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeError {
    EmptyToken,
    TokenTooLong,
    InvalidToken,
    OutputTooSmall,
    InvalidLifetime,
    InvalidState,
    ReceiptMismatch,
    StaleGeneration,
    WrongPublisher,
    WildcardRequiresDns01,
    NotYetActive,
    Expired,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationState {
    Prepared,
    Active,
    RemovalPrepared,
    RemovalUncertain,
    Removed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ChallengeToken {
    bytes: [u8; MAX_CHALLENGE_TOKEN],
    len: u8,
}

impl ChallengeToken {
    pub fn parse(value: &str) -> Result<Self, ChallengeError> {
        if value.is_empty() {
            return Err(ChallengeError::EmptyToken);
        }
        if value.len() > MAX_CHALLENGE_TOKEN {
            return Err(ChallengeError::TokenTooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ChallengeError::InvalidToken);
        }
        let mut bytes = [0; MAX_CHALLENGE_TOKEN];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Self {
            bytes,
            len: value.len() as u8,
        })
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ChallengePublicationRequest {
    pub challenge_generation: u64,
    pub order_url_digest: [u8; 32],
    pub authorization_url_digest: [u8; 32],
    pub identifier: DnsIdentifier,
    pub kind: ChallengeKind,
    pub token: ChallengeToken,
    pub key_authorization_digest: [u8; 32],
    pub not_before_unix: u64,
    pub expires_unix: u64,
    pub publisher_policy_generation: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PublicationReceipt {
    pub challenge_generation: u64,
    pub publisher_generation: u64,
    pub binding_digest: [u8; 32],
    pub kind: ChallengeKind,
}

pub trait ChallengePublisher {
    fn prepare(
        &mut self,
        request: ChallengePublicationRequest,
    ) -> Result<PublicationReceipt, ChallengeError>;
    fn activate(&mut self, receipt: PublicationReceipt) -> Result<(), ChallengeError>;
    fn prepare_removal(
        &mut self,
        receipt: PublicationReceipt,
    ) -> Result<PublicationReceipt, ChallengeError>;
    fn commit_removal(&mut self, receipt: PublicationReceipt) -> Result<(), ChallengeError>;
    fn authoritative_state(
        &mut self,
        receipt: PublicationReceipt,
    ) -> Result<PublicationState, ChallengeError>;
}

pub struct ChallengeLifecycle {
    pub request: ChallengePublicationRequest,
    pub state: PublicationState,
    receipt: Option<PublicationReceipt>,
}

impl ChallengeLifecycle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_generation: u64,
        order_url: &AcmeUrl,
        authorization_url: &AcmeUrl,
        identifier: DnsIdentifier,
        kind: ChallengeKind,
        token: ChallengeToken,
        account_key: JwkThumbprint,
        not_before_unix: u64,
        expires_unix: u64,
        publisher_policy_generation: u64,
    ) -> Result<Self, ChallengeError> {
        if expires_unix <= not_before_unix {
            return Err(ChallengeError::InvalidLifetime);
        }
        if identifier.is_wildcard() && kind != ChallengeKind::Dns01 {
            return Err(ChallengeError::WildcardRequiresDns01);
        }
        let mut key_authorization = [0u8; MAX_KEY_AUTHORIZATION];
        let len = write_key_authorization(&token, account_key, &mut key_authorization)?;
        Ok(Self {
            request: ChallengePublicationRequest {
                challenge_generation,
                order_url_digest: Sha256::digest(order_url.as_str().as_bytes()),
                authorization_url_digest: Sha256::digest(authorization_url.as_str().as_bytes()),
                identifier,
                kind,
                token,
                key_authorization_digest: Sha256::digest(&key_authorization[..len]),
                not_before_unix,
                expires_unix,
                publisher_policy_generation,
            },
            state: PublicationState::Prepared,
            receipt: None,
        })
    }

    pub fn publish(
        &mut self,
        publisher: &mut impl ChallengePublisher,
    ) -> Result<PublicationReceipt, ChallengeError> {
        if self.state != PublicationState::Prepared || self.receipt.is_some() {
            return Err(ChallengeError::InvalidState);
        }
        let receipt = publisher.prepare(self.request)?;
        validate_receipt(&self.request, receipt)?;
        publisher.activate(receipt)?;
        self.receipt = Some(receipt);
        self.state = PublicationState::Active;
        Ok(receipt)
    }

    pub fn require_active(&self, now_unix: u64) -> Result<PublicationReceipt, ChallengeError> {
        if self.state != PublicationState::Active {
            return Err(ChallengeError::InvalidState);
        }
        if now_unix < self.request.not_before_unix {
            return Err(ChallengeError::NotYetActive);
        }
        if now_unix >= self.request.expires_unix {
            return Err(ChallengeError::Expired);
        }
        self.receipt.ok_or(ChallengeError::InvalidState)
    }

    pub fn remove(
        &mut self,
        publisher: &mut impl ChallengePublisher,
    ) -> Result<(), ChallengeError> {
        if self.state != PublicationState::Active {
            return Err(ChallengeError::InvalidState);
        }
        let receipt = self.receipt.ok_or(ChallengeError::InvalidState)?;
        let removal = publisher.prepare_removal(receipt)?;
        if removal != receipt {
            return Err(ChallengeError::ReceiptMismatch);
        }
        self.state = PublicationState::RemovalPrepared;
        match publisher.commit_removal(removal) {
            Ok(()) => {
                self.state = PublicationState::Removed;
                self.receipt = None;
                Ok(())
            }
            Err(error) => {
                self.state = PublicationState::RemovalUncertain;
                Err(error)
            }
        }
    }

    pub fn resolve_removal(
        &mut self,
        publisher: &mut impl ChallengePublisher,
    ) -> Result<PublicationState, ChallengeError> {
        if self.state != PublicationState::RemovalUncertain {
            return Err(ChallengeError::InvalidState);
        }
        let receipt = self.receipt.ok_or(ChallengeError::InvalidState)?;
        match publisher.authoritative_state(receipt)? {
            PublicationState::Removed => {
                self.state = PublicationState::Removed;
                self.receipt = None;
            }
            PublicationState::Active | PublicationState::RemovalPrepared => {
                self.state = PublicationState::Active;
            }
            _ => return Err(ChallengeError::ReceiptMismatch),
        }
        Ok(self.state)
    }
}

pub fn write_key_authorization(
    token: &ChallengeToken,
    account_key: JwkThumbprint,
    output: &mut [u8],
) -> Result<usize, ChallengeError> {
    let token = token.as_str().as_bytes();
    let required = token
        .len()
        .checked_add(44)
        .ok_or(ChallengeError::ArithmeticOverflow)?;
    if output.len() < required {
        return Err(ChallengeError::OutputTooSmall);
    }
    output[..token.len()].copy_from_slice(token);
    output[token.len()] = b'.';
    let written = encode_base64url(&account_key.0, &mut output[token.len() + 1..])
        .map_err(|_| ChallengeError::OutputTooSmall)?;
    Ok(token.len() + 1 + written.len())
}

pub fn dns01_txt_digest(key_authorization: &[u8]) -> [u8; 32] {
    Sha256::digest(key_authorization)
}

fn validate_receipt(
    request: &ChallengePublicationRequest,
    receipt: PublicationReceipt,
) -> Result<(), ChallengeError> {
    if receipt.challenge_generation != request.challenge_generation || receipt.kind != request.kind
    {
        return Err(ChallengeError::ReceiptMismatch);
    }
    if receipt.binding_digest != publication_binding_digest(request) {
        return Err(ChallengeError::WrongPublisher);
    }
    Ok(())
}

pub fn publication_binding_digest(request: &ChallengePublicationRequest) -> [u8; 32] {
    let mut input = [0u8; 32 * 3 + 16];
    input[..32].copy_from_slice(&request.order_url_digest);
    input[32..64].copy_from_slice(&request.authorization_url_digest);
    input[64..96].copy_from_slice(&request.key_authorization_digest);
    input[96..104].copy_from_slice(&request.challenge_generation.to_be_bytes());
    input[104..112].copy_from_slice(&request.publisher_policy_generation.to_be_bytes());
    Sha256::digest(&input)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Publisher {
        generation: u64,
        fail_removal: bool,
        state: PublicationState,
    }
    impl ChallengePublisher for Publisher {
        fn prepare(
            &mut self,
            request: ChallengePublicationRequest,
        ) -> Result<PublicationReceipt, ChallengeError> {
            let mut input = [0u8; 112];
            input[..32].copy_from_slice(&request.order_url_digest);
            input[32..64].copy_from_slice(&request.authorization_url_digest);
            input[64..96].copy_from_slice(&request.key_authorization_digest);
            input[96..104].copy_from_slice(&request.challenge_generation.to_be_bytes());
            input[104..112].copy_from_slice(&request.publisher_policy_generation.to_be_bytes());
            Ok(PublicationReceipt {
                challenge_generation: request.challenge_generation,
                publisher_generation: self.generation,
                binding_digest: Sha256::digest(&input),
                kind: request.kind,
            })
        }
        fn activate(&mut self, _: PublicationReceipt) -> Result<(), ChallengeError> {
            self.state = PublicationState::Active;
            Ok(())
        }
        fn prepare_removal(
            &mut self,
            r: PublicationReceipt,
        ) -> Result<PublicationReceipt, ChallengeError> {
            Ok(r)
        }
        fn commit_removal(&mut self, _: PublicationReceipt) -> Result<(), ChallengeError> {
            if self.fail_removal {
                Err(ChallengeError::WrongPublisher)
            } else {
                self.state = PublicationState::Removed;
                Ok(())
            }
        }
        fn authoritative_state(
            &mut self,
            _: PublicationReceipt,
        ) -> Result<PublicationState, ChallengeError> {
            Ok(self.state)
        }
    }
    fn url(path: &str) -> AcmeUrl {
        let mut b = [0u8; 80];
        let p = b"https://ca.example/";
        b[..p.len()].copy_from_slice(p);
        b[p.len()..p.len() + path.len()].copy_from_slice(path.as_bytes());
        AcmeUrl::parse(
            core::str::from_utf8(&b[..p.len() + path.len()]).unwrap(),
            false,
        )
        .unwrap()
    }
    #[test]
    fn exact_binding_and_uncertain_removal_are_resolved() {
        let mut lifecycle = ChallengeLifecycle::new(
            3,
            &url("order/1"),
            &url("authz/1"),
            DnsIdentifier::parse("git.example", false).unwrap(),
            ChallengeKind::Http01,
            ChallengeToken::parse("abc_123").unwrap(),
            JwkThumbprint([7; 32]),
            10,
            20,
            4,
        )
        .unwrap();
        let mut publisher = Publisher {
            generation: 8,
            fail_removal: true,
            state: PublicationState::Prepared,
        };
        lifecycle.publish(&mut publisher).unwrap();
        assert!(lifecycle.require_active(15).is_ok());
        assert!(lifecycle.remove(&mut publisher).is_err());
        publisher.fail_removal = false;
        publisher.state = PublicationState::Removed;
        assert_eq!(
            lifecycle.resolve_removal(&mut publisher),
            Ok(PublicationState::Removed)
        );
    }
    #[test]
    fn wildcard_fails_closed_outside_dns01() {
        assert!(matches!(
            ChallengeLifecycle::new(
                1,
                &url("o"),
                &url("a"),
                DnsIdentifier::parse("*.example", true).unwrap(),
                ChallengeKind::TlsAlpn01,
                ChallengeToken::parse("abc").unwrap(),
                JwkThumbprint([1; 32]),
                1,
                2,
                1
            ),
            Err(ChallengeError::WildcardRequiresDns01)
        ));
    }
}
