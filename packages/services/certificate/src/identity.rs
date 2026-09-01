use crate::{
    DurableDeploymentReceipt, DurableDeploymentStage, PemCertificateChain,
    VerifiedCertificateReceipt,
};
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

pub struct RecoveredIdentityMaterial {
    pub verified: VerifiedCertificateReceipt,
    pub chain: PemCertificateChain,
    pub route: TlsSigningRoute,
    pub identifiers: [Option<AcmeIdentifier>; MAX_IDENTITY_NAMES],
    pub identifier_count: u8,
    pub deployment: DurableDeploymentReceipt,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ActivationReceipt {
    pub identity: TlsIdentityId,
    pub generation: u64,
    pub descriptor_digest: [u8; 32],
    pub previous_generation: Option<u64>,
    pub target_generation: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CandidateKeyRetirementReceipt {
    pub identity: TlsIdentityId,
    pub identity_generation: u64,
    pub key_identity: TlsKeyIdentity,
    pub route_generation: u64,
}

pub trait CandidateKeyRetirementTarget {
    fn retire_candidate_key(
        &mut self,
        route: TlsSigningRoute,
    ) -> Result<CandidateKeyRetirementReceipt, IdentityError>;
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CandidateDeploymentRetirementReceipt {
    pub prepared: PreparedIdentityReceipt,
    pub target_generation: u64,
}

pub trait CandidateDeploymentRetirementTarget {
    fn retire_candidate_deployment(
        &mut self,
        prepared: PreparedIdentityReceipt,
        target_generation: u64,
    ) -> Result<CandidateDeploymentRetirementReceipt, IdentityError>;
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

    /// Restores a generation only from independently authenticated certificate,
    /// key-route, and deployment records. Callers must recover an active
    /// generation before a later candidate generation.
    pub fn restore_generation(
        &mut self,
        material: RecoveredIdentityMaterial,
    ) -> Result<PreparedIdentityReceipt, IdentityError> {
        let deployment = material.deployment;
        if deployment.identity != self.identity
            || deployment.identity_generation == 0
            || material.verified.policy_generation != self.policy_generation
            || material.verified.chain_digest != material.chain.chain_digest()
            || material.route.identity != self.identity
            || material.route.identity_generation != deployment.identity_generation
            || material.route.key_identity == TlsKeyIdentity([0; 32])
            || material.route.route_generation == 0
            || material.route.capability_id == [0; 16]
            || (deployment.stage == DurableDeploymentStage::CandidatePrepared
                && deployment.target_generation != 0)
            || (deployment.stage != DurableDeploymentStage::CandidatePrepared
                && deployment.target_generation == 0)
            || material.identifier_count == 0
            || usize::from(material.identifier_count) > MAX_IDENTITY_NAMES
            || material.identifiers[..usize::from(material.identifier_count)]
                .iter()
                .any(Option::is_none)
            || material.identifiers[..usize::from(material.identifier_count)]
                .windows(2)
                .any(|pair| pair[0].as_ref() >= pair[1].as_ref())
        {
            return Err(IdentityError::ReceiptMismatch);
        }
        let descriptor = TlsIdentityDescriptor {
            identity: self.identity,
            generation: deployment.identity_generation,
            policy_generation: self.policy_generation,
            identifiers: material.identifiers,
            identifier_count: material.identifier_count,
            chain_digest: material.verified.chain_digest,
            leaf_spki_digest: material.verified.leaf_spki_digest,
            key_identity: material.route.key_identity,
            not_before: material.verified.not_before,
            not_after: material.verified.not_after,
            profile: material.verified.profile,
        };
        let prepared = PreparedIdentityReceipt {
            identity: self.identity,
            generation: descriptor.generation,
            descriptor_digest: descriptor.binding_digest(),
            chain_digest: descriptor.chain_digest,
        };
        if deployment.descriptor_digest != prepared.descriptor_digest
            || deployment.chain_digest != prepared.chain_digest
        {
            return Err(IdentityError::ReceiptMismatch);
        }
        let state = match deployment.stage {
            DurableDeploymentStage::CandidatePrepared => DeploymentState::Prepared,
            DurableDeploymentStage::Published => DeploymentState::Prepared,
            DurableDeploymentStage::Tested => DeploymentState::Tested,
            DurableDeploymentStage::ActivationUncertain => DeploymentState::ActivationUncertain,
            DurableDeploymentStage::Active => DeploymentState::Active,
        };
        let generation = IdentityGeneration {
            descriptor,
            chain: material.chain,
            route: material.route,
            state,
            prepared,
            target_generation: deployment.target_generation,
        };
        if state == DeploymentState::Active {
            if self.active.is_some() || self.candidate.is_some() || self.retained.is_some() {
                return Err(IdentityError::InvalidState);
            }
            self.active = Some(generation);
        } else {
            let expected = self
                .active
                .as_ref()
                .ok_or(IdentityError::InvalidState)?
                .descriptor
                .generation
                .checked_add(1)
                .ok_or(IdentityError::ArithmeticOverflow)?;
            if self.candidate.is_some() {
                return Err(IdentityError::InvalidState);
            }
            if deployment.identity_generation != expected {
                return Err(IdentityError::GenerationMismatch);
            }
            self.candidate = Some(generation);
        }
        Ok(prepared)
    }

    pub(crate) fn active_descriptor(&self) -> Option<TlsIdentityDescriptor> {
        self.active.as_ref().map(|active| active.descriptor)
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

    pub fn retry_tested_activation(
        &mut self,
        target: &mut impl IdentityDeploymentTarget,
    ) -> Result<ActivationReceipt, IdentityError> {
        let candidate = self.candidate.as_ref().ok_or(IdentityError::InvalidState)?;
        if candidate.state != DeploymentState::Tested || candidate.target_generation == 0 {
            return Err(IdentityError::InvalidState);
        }
        self.activate(
            TestedIdentityReceipt {
                prepared: candidate.prepared,
                target_generation: candidate.target_generation,
                tls13_ok: true,
                http3_quic_v2_ok: true,
            },
            target,
        )
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

    pub fn confirm_active(
        &mut self,
        target: &mut impl IdentityDeploymentTarget,
    ) -> Result<ActivationReceipt, IdentityError> {
        let active = self.active.as_ref().ok_or(IdentityError::InvalidState)?;
        let (generation, digest) = target.describe_active(self.identity)?;
        if generation != active.descriptor.generation
            || digest != active.descriptor.binding_digest()
            || active.target_generation == 0
        {
            return Err(IdentityError::ResolutionMismatch);
        }
        Ok(ActivationReceipt {
            identity: self.identity,
            generation,
            descriptor_digest: digest,
            previous_generation: self
                .retained
                .as_ref()
                .map(|retained| retained.descriptor.generation),
            target_generation: active.target_generation,
        })
    }

    pub fn abort_candidate(
        &mut self,
        prepared: PreparedIdentityReceipt,
        deployment: &mut impl CandidateDeploymentRetirementTarget,
        keys: &mut impl CandidateKeyRetirementTarget,
    ) -> Result<CandidateKeyRetirementReceipt, IdentityError> {
        let candidate = self.candidate.as_ref().ok_or(IdentityError::InvalidState)?;
        if candidate.prepared != prepared || candidate.state == DeploymentState::ActivationUncertain
        {
            return Err(IdentityError::InvalidState);
        }
        let route = candidate.route;
        if candidate.target_generation != 0 {
            let deployment_receipt =
                deployment.retire_candidate_deployment(prepared, candidate.target_generation)?;
            if deployment_receipt.prepared != prepared
                || deployment_receipt.target_generation != candidate.target_generation
            {
                return Err(IdentityError::ReceiptMismatch);
            }
        }
        let receipt = keys.retire_candidate_key(route)?;
        if receipt.identity != route.identity
            || receipt.identity_generation != route.identity_generation
            || receipt.key_identity != route.key_identity
            || receipt.route_generation != route.route_generation
        {
            return Err(IdentityError::ReceiptMismatch);
        }
        self.candidate = None;
        Ok(receipt)
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
    struct Retirer {
        substitute: bool,
    }
    struct DeploymentRetirer;
    impl CandidateDeploymentRetirementTarget for DeploymentRetirer {
        fn retire_candidate_deployment(
            &mut self,
            prepared: PreparedIdentityReceipt,
            target_generation: u64,
        ) -> Result<CandidateDeploymentRetirementReceipt, IdentityError> {
            Ok(CandidateDeploymentRetirementReceipt {
                prepared,
                target_generation,
            })
        }
    }
    impl CandidateKeyRetirementTarget for Retirer {
        fn retire_candidate_key(
            &mut self,
            route: TlsSigningRoute,
        ) -> Result<CandidateKeyRetirementReceipt, IdentityError> {
            Ok(CandidateKeyRetirementReceipt {
                identity: route.identity,
                identity_generation: route.identity_generation,
                key_identity: route.key_identity,
                route_generation: route.route_generation + u64::from(self.substitute),
            })
        }
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

    #[test]
    fn candidate_abort_requires_exact_key_retirement_receipt() {
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
        let mut manager = IdentityManager::new(TlsIdentityId([4; 16]), 2);
        let mut identifiers = [None; MAX_IDENTITY_NAMES];
        identifiers[0] = Some(AcmeIdentifier::Dns(
            mrml_acme::DnsIdentifier::parse("git.example", false).unwrap(),
        ));
        let prepared = manager
            .prepare_candidate(
                verified,
                chain,
                TlsKeyIdentity([5; 32]),
                7,
                [6; 16],
                identifiers,
                1,
            )
            .unwrap();
        assert_eq!(
            manager
                .abort_candidate(
                    prepared,
                    &mut DeploymentRetirer,
                    &mut Retirer { substitute: true },
                )
                .err(),
            Some(IdentityError::ReceiptMismatch)
        );
        assert!(manager.candidate.is_some());
        let receipt = manager
            .abort_candidate(
                prepared,
                &mut DeploymentRetirer,
                &mut Retirer { substitute: false },
            )
            .unwrap();
        assert!(receipt.key_identity == TlsKeyIdentity([5; 32]));
        assert!(manager.candidate.is_none());
    }

    fn recovery_material(
        generation: u64,
        stage: DurableDeploymentStage,
    ) -> RecoveredIdentityMaterial {
        let identity = TlsIdentityId([4; 16]);
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
            not_after: 100 + generation,
            trust_store_digest: [3; 32],
            ari_certificate_id: mrml_acme::AriCertificateId::derive(&[generation as u8], &[1])
                .unwrap(),
        };
        let mut identifiers = [None; MAX_IDENTITY_NAMES];
        identifiers[0] = Some(AcmeIdentifier::Dns(
            mrml_acme::DnsIdentifier::parse("git.example", false).unwrap(),
        ));
        let route = TlsSigningRoute {
            identity,
            identity_generation: generation,
            key_identity: TlsKeyIdentity([generation as u8; 32]),
            route_generation: generation,
            capability_id: [generation as u8; 16],
        };
        let descriptor = TlsIdentityDescriptor {
            identity,
            generation,
            policy_generation: 2,
            identifiers,
            identifier_count: 1,
            chain_digest: verified.chain_digest,
            leaf_spki_digest: verified.leaf_spki_digest,
            key_identity: route.key_identity,
            not_before: verified.not_before,
            not_after: verified.not_after,
            profile: verified.profile,
        };
        RecoveredIdentityMaterial {
            verified,
            chain,
            route,
            identifiers,
            identifier_count: 1,
            deployment: DurableDeploymentReceipt {
                stage,
                identity,
                identity_generation: generation,
                descriptor_digest: descriptor.binding_digest(),
                chain_digest: descriptor.chain_digest,
                target_generation: if stage == DurableDeploymentStage::CandidatePrepared {
                    0
                } else {
                    generation
                },
                previous_identity_generation: (stage == DurableDeploymentStage::Active
                    && generation > 1)
                    .then_some(generation - 1),
                record_generation: generation,
            },
        }
    }

    #[test]
    fn restart_restores_exact_active_then_tested_candidate_generation() {
        let mut manager = IdentityManager::new(TlsIdentityId([4; 16]), 2);
        manager
            .restore_generation(recovery_material(1, DurableDeploymentStage::Active))
            .unwrap();
        let candidate = recovery_material(2, DurableDeploymentStage::Tested);
        let expected = candidate.deployment.descriptor_digest;
        let prepared = manager.restore_generation(candidate).unwrap();
        assert_eq!(prepared.descriptor_digest, expected);
        assert_eq!(manager.active_descriptor().unwrap().generation, 1);
        assert_eq!(
            manager.candidate.as_ref().unwrap().state,
            DeploymentState::Tested
        );
        assert_eq!(manager.candidate.as_ref().unwrap().target_generation, 2);
        assert_eq!(
            manager
                .restore_generation(recovery_material(2, DurableDeploymentStage::Tested))
                .err(),
            Some(IdentityError::InvalidState)
        );
    }

    #[test]
    fn restart_rejects_substituted_descriptor_binding() {
        let mut material = recovery_material(1, DurableDeploymentStage::Active);
        material.deployment.descriptor_digest[0] ^= 1;
        let mut manager = IdentityManager::new(TlsIdentityId([4; 16]), 2);
        assert_eq!(
            manager.restore_generation(material).err(),
            Some(IdentityError::ReceiptMismatch)
        );
        assert!(!manager.has_deployment_state());
    }
}
