use crate::{AuthoritativeChallengeZone, DnsChallengeError, MAX_DNS_TXT_RECORDS};
use mrml_acme::{
    AcmeIdentifier, ChallengeError, ChallengeKind, ChallengePublicationRequest, ChallengePublisher,
    PublicationReceipt, PublicationState, publication_binding_digest,
};

#[derive(Clone, Copy, Eq, PartialEq)]
struct Binding {
    request: ChallengePublicationRequest,
    receipt: PublicationReceipt,
    state: PublicationState,
}

pub struct DnsChallengePublisher {
    zone: AuthoritativeChallengeZone,
    generation: u64,
    bindings: [Option<Binding>; MAX_DNS_TXT_RECORDS],
}

impl DnsChallengePublisher {
    pub const fn new(zone: AuthoritativeChallengeZone, generation: u64) -> Self {
        Self {
            zone,
            generation,
            bindings: [None; MAX_DNS_TXT_RECORDS],
        }
    }

    pub fn zone(&self) -> &AuthoritativeChallengeZone {
        &self.zone
    }

    pub fn expire(&mut self, now_unix: u64) {
        self.zone.expire(now_unix);
        for slot in &mut self.bindings {
            if slot.is_some_and(|binding| now_unix >= binding.request.expires_unix) {
                *slot = None;
            }
        }
    }

    fn find_mut(&mut self, receipt: PublicationReceipt) -> Result<&mut Binding, ChallengeError> {
        self.bindings
            .iter_mut()
            .flatten()
            .find(|binding| binding.receipt == receipt)
            .ok_or(ChallengeError::ReceiptMismatch)
    }
}

impl ChallengePublisher for DnsChallengePublisher {
    fn prepare(
        &mut self,
        request: ChallengePublicationRequest,
    ) -> Result<PublicationReceipt, ChallengeError> {
        if request.kind != ChallengeKind::Dns01
            || !matches!(request.identifier, AcmeIdentifier::Dns(_))
        {
            return Err(ChallengeError::WrongPublisher);
        }
        if self.bindings.iter().flatten().any(|binding| {
            binding.request.challenge_generation == request.challenge_generation
                && binding.request.authorization_url_digest == request.authorization_url_digest
        }) {
            return Err(ChallengeError::StaleGeneration);
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(ChallengeError::ArithmeticOverflow)?;
        let receipt = PublicationReceipt {
            challenge_generation: request.challenge_generation,
            publisher_generation: self.generation,
            binding_digest: publication_binding_digest(&request),
            kind: request.kind,
        };
        let slot = self
            .bindings
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(ChallengeError::WrongPublisher)?;
        *slot = Some(Binding {
            request,
            receipt,
            state: PublicationState::Prepared,
        });
        Ok(receipt)
    }

    fn activate(&mut self, receipt: PublicationReceipt) -> Result<(), ChallengeError> {
        let binding = *self.find_mut(receipt)?;
        if binding.state != PublicationState::Prepared {
            return Err(ChallengeError::InvalidState);
        }
        let AcmeIdentifier::Dns(identifier) = binding.request.identifier else {
            return Err(ChallengeError::WrongPublisher);
        };
        self.zone
            .insert_txt(
                identifier,
                binding.request.key_authorization_digest,
                binding.request.challenge_generation,
                binding.request.expires_unix,
                binding.request.publisher_policy_generation,
            )
            .map_err(map_dns_error)?;
        self.find_mut(receipt)?.state = PublicationState::Active;
        Ok(())
    }

    fn prepare_removal(
        &mut self,
        receipt: PublicationReceipt,
    ) -> Result<PublicationReceipt, ChallengeError> {
        let binding = self.find_mut(receipt)?;
        if binding.state != PublicationState::Active {
            return Err(ChallengeError::InvalidState);
        }
        binding.state = PublicationState::RemovalPrepared;
        Ok(receipt)
    }

    fn commit_removal(&mut self, receipt: PublicationReceipt) -> Result<(), ChallengeError> {
        let binding = *self.find_mut(receipt)?;
        if binding.state != PublicationState::RemovalPrepared {
            return Err(ChallengeError::InvalidState);
        }
        let AcmeIdentifier::Dns(identifier) = binding.request.identifier else {
            return Err(ChallengeError::WrongPublisher);
        };
        if let Err(error) = self.zone.remove_txt(
            identifier,
            binding.request.key_authorization_digest,
            binding.request.challenge_generation,
        ) {
            self.find_mut(receipt)?.state = PublicationState::RemovalUncertain;
            return Err(map_dns_error(error));
        }
        let slot = self
            .bindings
            .iter_mut()
            .find(|slot| slot.is_some_and(|binding| binding.receipt == receipt))
            .ok_or(ChallengeError::ReceiptMismatch)?;
        *slot = None;
        Ok(())
    }

    fn authoritative_state(
        &mut self,
        receipt: PublicationReceipt,
    ) -> Result<PublicationState, ChallengeError> {
        Ok(self.find_mut(receipt)?.state)
    }
}

fn map_dns_error(error: DnsChallengeError) -> ChallengeError {
    match error {
        DnsChallengeError::StaleGeneration => ChallengeError::StaleGeneration,
        _ => ChallengeError::WrongPublisher,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_acme::{AcmeUrl, ChallengeLifecycle, ChallengeToken, DnsIdentifier, JwkThumbprint};
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
    fn shared_lifecycle_publishes_and_removes_exact_txt() {
        let zone = AuthoritativeChallengeZone::new(
            DnsIdentifier::parse("example", false).unwrap(),
            DnsIdentifier::parse("ns.example", false).unwrap(),
            [192, 0, 2, 1],
            1,
            5,
        );
        let mut publisher = DnsChallengePublisher::new(zone, 8);
        let mut lifecycle = ChallengeLifecycle::new(
            4,
            &url("o"),
            &url("a"),
            mrml_acme::AcmeIdentifier::Dns(DnsIdentifier::parse("git.example", false).unwrap()),
            ChallengeKind::Dns01,
            ChallengeToken::parse("token").unwrap(),
            JwkThumbprint([9; 32]),
            1,
            100,
            5,
        )
        .unwrap();
        lifecycle.publish(&mut publisher).unwrap();
        let mut q = [0u8; 512];
        q[..12].copy_from_slice(&[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let name = b"\x0f_acme-challenge\x03git\x07example\0";
        q[12..12 + name.len()].copy_from_slice(name);
        let mut n = 12 + name.len();
        q[n..n + 4].copy_from_slice(&[0, 16, 0, 1]);
        n += 4;
        let mut out = [0u8; 1232];
        publisher.zone().answer_udp(&q[..n], 2, &mut out).unwrap();
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), 1);
        lifecycle.remove(&mut publisher).unwrap();
        publisher.zone().answer_udp(&q[..n], 2, &mut out).unwrap();
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), 0);
    }
}
