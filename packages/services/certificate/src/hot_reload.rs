use crate::{
    ActivationReceipt, CandidateDeploymentRetirementReceipt, CandidateDeploymentRetirementTarget,
    IdentityDeploymentTarget, IdentityError, IdentityTlsSigningAdapter, PemCertificateChain,
    PreparedIdentityReceipt, TestedIdentityReceipt, TlsCertificateSigningKey,
    TlsIdentityDescriptor, TlsIdentityId, TlsSigningRoute,
};
use mrml_runtime::{Shared, SpinMutex};
use mrml_tls::TlsServerConfig;

#[derive(Clone)]
pub struct PublishedTlsIdentity {
    pub identity: TlsIdentityId,
    pub generation: u64,
    pub descriptor_digest: [u8; 32],
    pub config: Shared<TlsServerConfig>,
}

impl<R, T> CandidateDeploymentRetirementTarget for HostedTlsIdentityDeploymentTarget<R, T> {
    fn retire_candidate_deployment(
        &mut self,
        prepared: PreparedIdentityReceipt,
        target_generation: u64,
    ) -> Result<CandidateDeploymentRetirementReceipt, IdentityError> {
        let candidate = self.candidate.as_ref().ok_or(IdentityError::InvalidState)?;
        if candidate.prepared != prepared || candidate.target_generation != target_generation {
            return Err(IdentityError::ReceiptMismatch);
        }
        self.candidate = None;
        Ok(CandidateDeploymentRetirementReceipt {
            prepared,
            target_generation,
        })
    }
}

#[derive(Clone)]
pub struct HostedTlsIdentityPublication {
    active: Shared<SpinMutex<Option<PublishedTlsIdentity>>>,
}

impl HostedTlsIdentityPublication {
    pub fn snapshot(&self) -> Option<PublishedTlsIdentity> {
        self.active.lock().clone()
    }
}

pub trait HostedSigningRouteResolver {
    type Key: TlsCertificateSigningKey + Send + 'static;

    fn resolve(&mut self, route: TlsSigningRoute) -> Result<Self::Key, IdentityError>;
}

pub trait HostedCandidateHandshakeTester {
    fn test_tls13(&mut self, config: &TlsServerConfig) -> Result<(), IdentityError>;
    fn test_http3_quic_v2(&mut self, config: &TlsServerConfig) -> Result<(), IdentityError>;
}

struct Candidate {
    prepared: PreparedIdentityReceipt,
    target_generation: u64,
    config: Shared<TlsServerConfig>,
}

pub struct HostedTlsIdentityDeploymentTarget<R, T> {
    identity: TlsIdentityId,
    resolver: R,
    tester: T,
    publication: HostedTlsIdentityPublication,
    candidate: Option<Candidate>,
    retained: Option<PublishedTlsIdentity>,
    target_generation: u64,
}

impl<R, T> HostedTlsIdentityDeploymentTarget<R, T> {
    pub fn new(identity: TlsIdentityId, resolver: R, tester: T) -> Self {
        Self {
            identity,
            resolver,
            tester,
            publication: HostedTlsIdentityPublication {
                active: Shared::new(SpinMutex::new(None)),
            },
            candidate: None,
            retained: None,
            target_generation: 0,
        }
    }

    pub fn publication(&self) -> HostedTlsIdentityPublication {
        self.publication.clone()
    }

    pub fn retained_generation(&self) -> Option<u64> {
        self.retained.as_ref().map(|identity| identity.generation)
    }

    pub fn retire_retained(&mut self, generation: u64) -> Result<(), IdentityError> {
        if self.retained.as_ref().map(|identity| identity.generation) != Some(generation) {
            return Err(IdentityError::GenerationMismatch);
        }
        self.retained = None;
        Ok(())
    }
}

impl<R: HostedSigningRouteResolver, T: HostedCandidateHandshakeTester> IdentityDeploymentTarget
    for HostedTlsIdentityDeploymentTarget<R, T>
{
    fn prepare(
        &mut self,
        descriptor: &TlsIdentityDescriptor,
        chain: &PemCertificateChain,
        route: TlsSigningRoute,
    ) -> Result<u64, IdentityError> {
        if self.candidate.is_some()
            || descriptor.identity != self.identity
            || route.identity != self.identity
            || route.identity_generation != descriptor.generation
            || route.key_identity != descriptor.key_identity
            || descriptor.chain_digest != chain.chain_digest()
        {
            return Err(IdentityError::ReceiptMismatch);
        }
        let mut certificates = [&[][..]; crate::MAX_CERTIFICATES];
        for (index, output) in certificates.iter_mut().enumerate().take(chain.count()) {
            *output = chain
                .certificate(index)
                .ok_or(IdentityError::ChainMismatch)?;
        }
        let key = self.resolver.resolve(route)?;
        let config = TlsServerConfig::from_der_chain(&certificates[..chain.count()])
            .map_err(|_| IdentityError::ChainMismatch)?
            .with_signing_key(IdentityTlsSigningAdapter::new(route, key));
        self.target_generation = self
            .target_generation
            .checked_add(1)
            .ok_or(IdentityError::ArithmeticOverflow)?;
        self.candidate = Some(Candidate {
            prepared: PreparedIdentityReceipt {
                identity: descriptor.identity,
                generation: descriptor.generation,
                descriptor_digest: descriptor.binding_digest(),
                chain_digest: descriptor.chain_digest,
            },
            target_generation: self.target_generation,
            config: Shared::new(config),
        });
        Ok(self.target_generation)
    }

    fn test_candidate(
        &mut self,
        prepared: PreparedIdentityReceipt,
        target_generation: u64,
    ) -> Result<TestedIdentityReceipt, IdentityError> {
        let candidate = self.candidate.as_ref().ok_or(IdentityError::InvalidState)?;
        if candidate.prepared != prepared || candidate.target_generation != target_generation {
            return Err(IdentityError::ReceiptMismatch);
        }
        self.tester.test_tls13(&candidate.config)?;
        self.tester.test_http3_quic_v2(&candidate.config)?;
        Ok(TestedIdentityReceipt {
            prepared,
            target_generation,
            tls13_ok: true,
            http3_quic_v2_ok: true,
        })
    }

    fn activate(
        &mut self,
        tested: TestedIdentityReceipt,
    ) -> Result<ActivationReceipt, IdentityError> {
        let candidate = self.candidate.as_ref().ok_or(IdentityError::InvalidState)?;
        if candidate.prepared != tested.prepared
            || candidate.target_generation != tested.target_generation
            || !tested.tls13_ok
            || !tested.http3_quic_v2_ok
        {
            return Err(IdentityError::ReceiptMismatch);
        }
        let previous = self.publication.snapshot();
        let published = PublishedTlsIdentity {
            identity: self.identity,
            generation: tested.prepared.generation,
            descriptor_digest: tested.prepared.descriptor_digest,
            config: candidate.config.clone(),
        };
        *self.publication.active.lock() = Some(published);
        self.retained = previous;
        self.candidate = None;
        Ok(ActivationReceipt {
            identity: self.identity,
            generation: tested.prepared.generation,
            descriptor_digest: tested.prepared.descriptor_digest,
            previous_generation: self.retained_generation(),
            target_generation: tested.target_generation,
        })
    }

    fn describe_active(
        &mut self,
        identity: TlsIdentityId,
    ) -> Result<(u64, [u8; 32]), IdentityError> {
        let active = self
            .publication
            .snapshot()
            .ok_or(IdentityError::InvalidState)?;
        if active.identity != identity || identity != self.identity {
            return Err(IdentityError::Unauthorized);
        }
        Ok((active.generation, active.descriptor_digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApprovedTls13CertificateVerify, TlsKeyIdentity};
    use mrml_acme::Es256Signature;

    struct Key;
    impl TlsCertificateSigningKey for Key {
        fn describe_public_key(
            &mut self,
            _: TlsSigningRoute,
            _: &mut [u8],
        ) -> Result<usize, IdentityError> {
            Err(IdentityError::SigningUnavailable)
        }
        fn sign_tls13_certificate_verify(
            &mut self,
            _: &ApprovedTls13CertificateVerify,
        ) -> Result<Es256Signature, IdentityError> {
            Es256Signature::from_raw([1; 64]).map_err(|_| IdentityError::SigningUnavailable)
        }
    }
    struct Resolver;
    impl HostedSigningRouteResolver for Resolver {
        type Key = Key;
        fn resolve(&mut self, _: TlsSigningRoute) -> Result<Key, IdentityError> {
            Ok(Key)
        }
    }
    struct Tester {
        fail_http3: bool,
        tls_tests: u8,
        http3_tests: u8,
    }
    impl HostedCandidateHandshakeTester for Tester {
        fn test_tls13(&mut self, _: &TlsServerConfig) -> Result<(), IdentityError> {
            self.tls_tests += 1;
            Ok(())
        }
        fn test_http3_quic_v2(&mut self, _: &TlsServerConfig) -> Result<(), IdentityError> {
            self.http3_tests += 1;
            if self.fail_http3 {
                Err(IdentityError::TestFailed)
            } else {
                Ok(())
            }
        }
    }

    fn descriptor(generation: u64, chain_digest: [u8; 32]) -> TlsIdentityDescriptor {
        TlsIdentityDescriptor {
            identity: TlsIdentityId([1; 16]),
            generation,
            policy_generation: 1,
            identifiers: [None; crate::MAX_IDENTITY_NAMES],
            identifier_count: 0,
            chain_digest,
            leaf_spki_digest: [2; 32],
            key_identity: TlsKeyIdentity([3; 32]),
            not_before: 1,
            not_after: 2,
            profile: mrml_acme::CertificateProfile::parse("classic", 1).unwrap(),
        }
    }

    fn chain() -> PemCertificateChain {
        PemCertificateChain::parse(b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----")
            .unwrap()
    }

    fn route(generation: u64) -> TlsSigningRoute {
        TlsSigningRoute {
            identity: TlsIdentityId([1; 16]),
            identity_generation: generation,
            key_identity: TlsKeyIdentity([3; 32]),
            route_generation: generation,
            capability_id: [4; 16],
        }
    }

    #[test]
    fn failed_candidate_test_never_replaces_active_generation() {
        let chain = chain();
        let mut target = HostedTlsIdentityDeploymentTarget::new(
            TlsIdentityId([1; 16]),
            Resolver,
            Tester {
                fail_http3: true,
                tls_tests: 0,
                http3_tests: 0,
            },
        );
        let descriptor = descriptor(1, chain.chain_digest());
        let target_generation = target.prepare(&descriptor, &chain, route(1)).unwrap();
        let prepared = target.candidate.as_ref().unwrap().prepared;
        assert_eq!(
            target.test_candidate(prepared, target_generation).err(),
            Some(IdentityError::TestFailed)
        );
        assert!(target.publication().snapshot().is_none());
    }

    #[test]
    fn new_snapshots_advance_while_prior_generation_is_retained() {
        let chain = chain();
        let mut target = HostedTlsIdentityDeploymentTarget::new(
            TlsIdentityId([1; 16]),
            Resolver,
            Tester {
                fail_http3: false,
                tls_tests: 0,
                http3_tests: 0,
            },
        );
        let publication = target.publication();
        for generation in 1..=2 {
            let descriptor = descriptor(generation, chain.chain_digest());
            let target_generation = target
                .prepare(&descriptor, &chain, route(generation))
                .unwrap();
            let prepared = target.candidate.as_ref().unwrap().prepared;
            let tested = target.test_candidate(prepared, target_generation).unwrap();
            target.activate(tested).unwrap();
            assert_eq!(publication.snapshot().unwrap().generation, generation);
        }
        assert_eq!(target.retained_generation(), Some(1));
        target.retire_retained(1).unwrap();
        assert_eq!(target.retained_generation(), None);
    }
}
