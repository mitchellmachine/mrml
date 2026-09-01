use crate::{PemCertificateChain, VerifiedCertificateReceipt};
use mrml_acme::{AcmeIdentifier, CertificateProfile, Es256Signature};
use mrml_crypto::Sha256;

pub const MAX_IDENTITY_NAMES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    Unauthorized,
    InvalidState,
    GenerationMismatch,
    ReceiptMismatch,
    ChainMismatch,
    TestFailed,
    ActivationUncertain,
    ActivationNotCommitted,
    ResolutionMismatch,
    OutputTooSmall,
    SigningUnavailable,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TlsIdentityId(pub [u8; 16]);

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TlsKeyIdentity(pub [u8; 32]);

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TlsIdentityDescriptor {
    pub identity: TlsIdentityId,
    pub generation: u64,
    pub policy_generation: u64,
    pub identifiers: [Option<AcmeIdentifier>; MAX_IDENTITY_NAMES],
    pub identifier_count: u8,
    pub chain_digest: [u8; 32],
    pub leaf_spki_digest: [u8; 32],
    pub key_identity: TlsKeyIdentity,
    pub not_before: u64,
    pub not_after: u64,
    pub profile: CertificateProfile,
}

impl TlsIdentityDescriptor {
    pub fn binding_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"mrml-tls-identity-v2\0");
        digest.update(&self.identity.0);
        digest.update(&self.generation.to_be_bytes());
        digest.update(&self.policy_generation.to_be_bytes());
        digest.update(&self.chain_digest);
        digest.update(&self.leaf_spki_digest);
        digest.update(&self.key_identity.0);
        digest.update(&self.not_before.to_be_bytes());
        digest.update(&self.not_after.to_be_bytes());
        digest.update(&self.profile.directory_generation().to_be_bytes());
        digest.update(self.profile.name().as_bytes());
        for identifier in self.identifiers[..usize::from(self.identifier_count)]
            .iter()
            .flatten()
        {
            match identifier {
                AcmeIdentifier::Dns(name) => {
                    digest.update(b"dns\0");
                    digest.update(&(name.as_str().len() as u16).to_be_bytes());
                    digest.update(name.as_str().as_bytes());
                }
                AcmeIdentifier::Ip(address) => {
                    digest.update(b"ip\0");
                    digest.update(&(address.octets().len() as u16).to_be_bytes());
                    digest.update(address.octets());
                }
            }
        }
        digest.finalize()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IdentityConsumerCapability {
    pub identity: TlsIdentityId,
    pub policy_generation: u64,
    pub may_describe: bool,
    pub may_read_chain: bool,
    pub may_sign_tls13: bool,
    pub may_observe_generation: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TlsSigningRoute {
    pub identity: TlsIdentityId,
    pub identity_generation: u64,
    pub key_identity: TlsKeyIdentity,
    pub route_generation: u64,
    pub capability_id: [u8; 16],
}

pub struct ApprovedTls13CertificateVerify {
    digest: [u8; 32],
    pub identity: TlsIdentityId,
    pub identity_generation: u64,
    pub key_identity: TlsKeyIdentity,
    pub route_generation: u64,
}

impl ApprovedTls13CertificateVerify {
    pub fn new(transcript_digest: [u8; 32], route: TlsSigningRoute) -> Self {
        let mut digest = Sha256::new();
        digest.update(&[0x20; 64]);
        digest.update(b"TLS 1.3, server CertificateVerify\0");
        digest.update(&transcript_digest);
        Self {
            digest: digest.finalize(),
            identity: route.identity,
            identity_generation: route.identity_generation,
            key_identity: route.key_identity,
            route_generation: route.route_generation,
        }
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

pub trait TlsCertificateSigningKey {
    fn describe_public_key(
        &mut self,
        route: TlsSigningRoute,
        output: &mut [u8],
    ) -> Result<usize, IdentityError>;
    fn sign_tls13_certificate_verify(
        &mut self,
        approved: &ApprovedTls13CertificateVerify,
    ) -> Result<Es256Signature, IdentityError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentState {
    Prepared,
    Tested,
    ActivationUncertain,
    Active,
    Retained,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PreparedIdentityReceipt {
    pub identity: TlsIdentityId,
    pub generation: u64,
    pub descriptor_digest: [u8; 32],
    pub chain_digest: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TestedIdentityReceipt {
    pub prepared: PreparedIdentityReceipt,
    pub target_generation: u64,
    pub tls13_ok: bool,
    pub http3_quic_v2_ok: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ActivationReceipt {
    pub identity: TlsIdentityId,
    pub generation: u64,
    pub descriptor_digest: [u8; 32],
    pub previous_generation: Option<u64>,
    pub target_generation: u64,
}

struct IdentityGeneration {
    descriptor: TlsIdentityDescriptor,
    chain: PemCertificateChain,
    route: TlsSigningRoute,
    state: DeploymentState,
    prepared: PreparedIdentityReceipt,
    target_generation: u64,
}

pub trait IdentityDeploymentTarget {
    fn prepare(
        &mut self,
        descriptor: &TlsIdentityDescriptor,
        chain: &PemCertificateChain,
        route: TlsSigningRoute,
    ) -> Result<u64, IdentityError>;
    fn test_candidate(
        &mut self,
        prepared: PreparedIdentityReceipt,
        target_generation: u64,
    ) -> Result<TestedIdentityReceipt, IdentityError>;
    fn activate(
        &mut self,
        tested: TestedIdentityReceipt,
    ) -> Result<ActivationReceipt, IdentityError>;
    fn describe_active(
        &mut self,
        identity: TlsIdentityId,
    ) -> Result<(u64, [u8; 32]), IdentityError>;
}

pub struct IdentityManager {
    identity: TlsIdentityId,
    policy_generation: u64,
    active: Option<IdentityGeneration>,
    candidate: Option<IdentityGeneration>,
    retained: Option<IdentityGeneration>,
}

impl IdentityManager {
    pub const fn new(identity: TlsIdentityId, policy_generation: u64) -> Self {
        Self {
            identity,
            policy_generation,
            active: None,
            candidate: None,
            retained: None,
        }
    }

    pub const fn identity(&self) -> TlsIdentityId {
        self.identity
    }

    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    pub const fn has_deployment_state(&self) -> bool {
        self.active.is_some() || self.candidate.is_some() || self.retained.is_some()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_candidate(
        &mut self,
        verified: VerifiedCertificateReceipt,
        chain: PemCertificateChain,
        key_identity: TlsKeyIdentity,
        route_generation: u64,
        capability_id: [u8; 16],
        identifiers: [Option<AcmeIdentifier>; MAX_IDENTITY_NAMES],
        identifier_count: u8,
    ) -> Result<PreparedIdentityReceipt, IdentityError> {
        if self.candidate.is_some()
            || verified.policy_generation != self.policy_generation
            || verified.chain_digest != chain.chain_digest()
            || identifier_count == 0
            || usize::from(identifier_count) > MAX_IDENTITY_NAMES
            || identifiers[..usize::from(identifier_count)]
                .iter()
                .any(Option::is_none)
            || identifiers[..usize::from(identifier_count)]
                .windows(2)
                .any(|pair| pair[0].as_ref() >= pair[1].as_ref())
        {
            return Err(IdentityError::InvalidState);
        }
        let generation = self.active.as_ref().map_or(Ok(1), |active| {
            active
                .descriptor
                .generation
                .checked_add(1)
                .ok_or(IdentityError::ArithmeticOverflow)
        })?;
        let descriptor = TlsIdentityDescriptor {
            identity: self.identity,
            generation,
            policy_generation: self.policy_generation,
            identifiers,
            identifier_count,
            chain_digest: verified.chain_digest,
            leaf_spki_digest: verified.leaf_spki_digest,
            key_identity,
            not_before: verified.not_before,
            not_after: verified.not_after,
            profile: verified.profile,
        };
        let route = TlsSigningRoute {
            identity: self.identity,
            identity_generation: generation,
            key_identity,
            route_generation,
            capability_id,
        };
        let prepared = PreparedIdentityReceipt {
            identity: self.identity,
            generation,
            descriptor_digest: descriptor.binding_digest(),
            chain_digest: descriptor.chain_digest,
        };
        self.candidate = Some(IdentityGeneration {
            descriptor,
            chain,
            route,
            state: DeploymentState::Prepared,
            prepared,
            target_generation: 0,
        });
        Ok(prepared)
    }

    pub fn publish_candidate(
        &mut self,
        prepared: PreparedIdentityReceipt,
        target: &mut impl IdentityDeploymentTarget,
    ) -> Result<u64, IdentityError> {
        let candidate = self.candidate.as_mut().ok_or(IdentityError::InvalidState)?;
        if candidate.prepared != prepared
            || candidate.state != DeploymentState::Prepared
            || candidate.target_generation != 0
        {
            return Err(IdentityError::ReceiptMismatch);
        }
        let target_generation =
            target.prepare(&candidate.descriptor, &candidate.chain, candidate.route)?;
        if target_generation == 0 {
            return Err(IdentityError::ReceiptMismatch);
        }
        candidate.target_generation = target_generation;
        Ok(target_generation)
    }

    pub fn test_candidate(
        &mut self,
        prepared: PreparedIdentityReceipt,
        target: &mut impl IdentityDeploymentTarget,
    ) -> Result<TestedIdentityReceipt, IdentityError> {
        let candidate = self.candidate.as_mut().ok_or(IdentityError::InvalidState)?;
        if candidate.prepared != prepared || candidate.state != DeploymentState::Prepared {
            return Err(IdentityError::ReceiptMismatch);
        }
        let target_generation = candidate.target_generation;
        if target_generation == 0 {
            return Err(IdentityError::InvalidState);
        }
        let tested = target.test_candidate(prepared, target_generation)?;
        if tested.prepared != prepared
            || tested.target_generation != target_generation
            || !tested.tls13_ok
            || !tested.http3_quic_v2_ok
        {
            return Err(IdentityError::TestFailed);
        }
        candidate.state = DeploymentState::Tested;
        Ok(tested)
    }

    pub fn activate(
        &mut self,
        tested: TestedIdentityReceipt,
        target: &mut impl IdentityDeploymentTarget,
    ) -> Result<ActivationReceipt, IdentityError> {
        let candidate = self.candidate.as_mut().ok_or(IdentityError::InvalidState)?;
        if candidate.state != DeploymentState::Tested || candidate.prepared != tested.prepared {
            return Err(IdentityError::ReceiptMismatch);
        }
        match target.activate(tested) {
            Ok(receipt) => match self.commit_activation(receipt) {
                Ok(receipt) => Ok(receipt),
                Err(_) => {
                    self.candidate
                        .as_mut()
                        .ok_or(IdentityError::InvalidState)?
                        .state = DeploymentState::ActivationUncertain;
                    Err(IdentityError::ActivationUncertain)
                }
            },
            Err(IdentityError::ActivationUncertain) => {
                candidate.state = DeploymentState::ActivationUncertain;
                Err(IdentityError::ActivationUncertain)
            }
            Err(error) => Err(error),
        }
    }

    pub fn resolve_activation(
        &mut self,
        target: &mut impl IdentityDeploymentTarget,
    ) -> Result<ActivationReceipt, IdentityError> {
        let candidate = self.candidate.as_ref().ok_or(IdentityError::InvalidState)?;
        if candidate.state != DeploymentState::ActivationUncertain {
            return Err(IdentityError::InvalidState);
        }
        let (generation, digest) = target.describe_active(self.identity)?;
        if generation == candidate.descriptor.generation
            && digest == candidate.descriptor.binding_digest()
        {
            let receipt = ActivationReceipt {
                identity: self.identity,
                generation,
                descriptor_digest: digest,
                previous_generation: self
                    .active
                    .as_ref()
                    .map(|active| active.descriptor.generation),
                target_generation: candidate.target_generation,
            };
            self.commit_activation(receipt)
        } else if self.active.as_ref().is_some_and(|active| {
            active.descriptor.generation == generation
                && active.descriptor.binding_digest() == digest
        }) {
            self.candidate.as_mut().unwrap().state = DeploymentState::Tested;
            Err(IdentityError::ActivationNotCommitted)
        } else {
            Err(IdentityError::ResolutionMismatch)
        }
    }

    fn commit_activation(
        &mut self,
        receipt: ActivationReceipt,
    ) -> Result<ActivationReceipt, IdentityError> {
        let candidate = self.candidate.as_ref().ok_or(IdentityError::InvalidState)?;
        if receipt.identity != self.identity
            || receipt.generation != candidate.descriptor.generation
            || receipt.descriptor_digest != candidate.descriptor.binding_digest()
            || receipt.previous_generation
                != self
                    .active
                    .as_ref()
                    .map(|active| active.descriptor.generation)
            || receipt.target_generation != candidate.target_generation
        {
            return Err(IdentityError::ReceiptMismatch);
        }
        if let Some(mut old) = self.active.take() {
            old.state = DeploymentState::Retained;
            self.retained = Some(old);
        }
        let mut candidate = self.candidate.take().unwrap();
        candidate.state = DeploymentState::Active;
        self.active = Some(candidate);
        Ok(receipt)
    }

    fn authorize(
        &self,
        capability: IdentityConsumerCapability,
        right: bool,
    ) -> Result<(), IdentityError> {
        if capability.identity == self.identity
            && capability.policy_generation == self.policy_generation
            && right
        {
            Ok(())
        } else {
            Err(IdentityError::Unauthorized)
        }
    }
    pub fn describe(
        &self,
        capability: IdentityConsumerCapability,
    ) -> Result<TlsIdentityDescriptor, IdentityError> {
        self.authorize(capability, capability.may_describe)?;
        Ok(self
            .active
            .as_ref()
            .ok_or(IdentityError::InvalidState)?
            .descriptor)
    }
    pub fn read_chain(
        &self,
        capability: IdentityConsumerCapability,
        index: usize,
        output: &mut [u8],
    ) -> Result<usize, IdentityError> {
        self.authorize(capability, capability.may_read_chain)?;
        let certificate = self
            .active
            .as_ref()
            .ok_or(IdentityError::InvalidState)?
            .chain
            .certificate(index)
            .ok_or(IdentityError::InvalidState)?;
        if output.len() < certificate.len() {
            return Err(IdentityError::OutputTooSmall);
        }
        output[..certificate.len()].copy_from_slice(certificate);
        Ok(certificate.len())
    }
    pub fn acquire_signing_route(
        &self,
        capability: IdentityConsumerCapability,
    ) -> Result<TlsSigningRoute, IdentityError> {
        self.authorize(capability, capability.may_sign_tls13)?;
        Ok(self
            .active
            .as_ref()
            .ok_or(IdentityError::InvalidState)?
            .route)
    }
    pub fn generation_changed(
        &self,
        capability: IdentityConsumerCapability,
        observed: u64,
    ) -> Result<Option<u64>, IdentityError> {
        self.authorize(capability, capability.may_observe_generation)?;
        let current = self
            .active
            .as_ref()
            .ok_or(IdentityError::InvalidState)?
            .descriptor
            .generation;
        Ok((current != observed).then_some(current))
    }
    pub fn retire_retained(&mut self, generation: u64) -> Result<TlsKeyIdentity, IdentityError> {
        let retained = self.retained.as_ref().ok_or(IdentityError::InvalidState)?;
        if retained.descriptor.generation != generation {
            return Err(IdentityError::GenerationMismatch);
        }
        let key = retained.descriptor.key_identity;
        self.retained = None;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_acme::{CaClass, CertificateProfile};
    struct Target {
        generation: u64,
        active: Option<(u64, [u8; 32])>,
        uncertain: bool,
    }
    impl IdentityDeploymentTarget for Target {
        fn prepare(
            &mut self,
            _: &TlsIdentityDescriptor,
            _: &PemCertificateChain,
            _: TlsSigningRoute,
        ) -> Result<u64, IdentityError> {
            self.generation += 1;
            Ok(self.generation)
        }
        fn test_candidate(
            &mut self,
            p: PreparedIdentityReceipt,
            g: u64,
        ) -> Result<TestedIdentityReceipt, IdentityError> {
            Ok(TestedIdentityReceipt {
                prepared: p,
                target_generation: g,
                tls13_ok: true,
                http3_quic_v2_ok: true,
            })
        }
        fn activate(
            &mut self,
            t: TestedIdentityReceipt,
        ) -> Result<ActivationReceipt, IdentityError> {
            self.active = Some((t.prepared.generation, t.prepared.descriptor_digest));
            if self.uncertain {
                Err(IdentityError::ActivationUncertain)
            } else {
                Ok(ActivationReceipt {
                    identity: t.prepared.identity,
                    generation: t.prepared.generation,
                    descriptor_digest: t.prepared.descriptor_digest,
                    previous_generation: None,
                    target_generation: t.target_generation,
                })
            }
        }
        fn describe_active(&mut self, _: TlsIdentityId) -> Result<(u64, [u8; 32]), IdentityError> {
            self.active.ok_or(IdentityError::InvalidState)
        }
    }
    #[test]
    fn activation_uncertainty_resolves_and_capability_is_identity_scoped() {
        let chain = PemCertificateChain::parse(
            b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----",
        )
        .unwrap();
        let verified = VerifiedCertificateReceipt {
            policy_generation: 2,
            ca_class: CaClass::Staging,
            profile: CertificateProfile::parse("classic", 1).unwrap(),
            order_url_digest: [1; 32],
            chain_digest: chain.chain_digest(),
            leaf_spki_digest: [2; 32],
            not_before: 1,
            not_after: 100,
            trust_store_digest: [3; 32],
            ari_certificate_id: mrml_acme::AriCertificateId::derive(&[1], &[1]).unwrap(),
        };
        let id = TlsIdentityId([4; 16]);
        let mut manager = IdentityManager::new(id, 2);
        let mut names = [None; MAX_IDENTITY_NAMES];
        names[0] = Some(AcmeIdentifier::Dns(
            mrml_acme::DnsIdentifier::parse("git.example", false).unwrap(),
        ));
        names[1] = Some(AcmeIdentifier::Ip(
            mrml_acme::IpIdentifier::parse("192.0.2.1").unwrap(),
        ));
        let mut target = Target {
            generation: 0,
            active: None,
            uncertain: true,
        };
        let prepared = manager
            .prepare_candidate(
                verified,
                chain,
                TlsKeyIdentity([5; 32]),
                1,
                [6; 16],
                names,
                2,
            )
            .unwrap();
        let descriptor = manager.candidate.as_ref().unwrap().descriptor;
        assert_eq!(descriptor.identifier_count, 2);
        let mut substituted = descriptor;
        substituted.identifiers[1] = Some(AcmeIdentifier::Ip(
            mrml_acme::IpIdentifier::parse("192.0.2.2").unwrap(),
        ));
        assert_ne!(descriptor.binding_digest(), substituted.binding_digest());
        manager.publish_candidate(prepared, &mut target).unwrap();
        let tested = manager.test_candidate(prepared, &mut target).unwrap();
        assert!(matches!(
            manager.activate(tested, &mut target),
            Err(IdentityError::ActivationUncertain)
        ));
        manager.resolve_activation(&mut target).unwrap();
        let cap = IdentityConsumerCapability {
            identity: id,
            policy_generation: 2,
            may_describe: true,
            may_read_chain: false,
            may_sign_tls13: true,
            may_observe_generation: true,
        };
        assert_eq!(manager.describe(cap).unwrap().generation, 1);
        let mut wrong = cap;
        wrong.identity = TlsIdentityId([9; 16]);
        assert_eq!(
            manager.describe(wrong).err(),
            Some(IdentityError::Unauthorized)
        );
    }
}
