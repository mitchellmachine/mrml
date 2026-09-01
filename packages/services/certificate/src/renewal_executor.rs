use crate::{
    ActivationReceipt, CandidateDeploymentRetirementTarget, CandidateKeyRetirementReceipt,
    CandidateKeyRetirementTarget, CertificateManager, CertificateManagerError,
    IdentityDeploymentTarget, IdentityError, MAX_IDENTITY_NAMES, PemCertificateChain,
    RenewalCheckpointSink, RenewalEntropy, RenewalJournal, RenewalJournalError, RenewalLease,
    RenewalPolicy, RenewalSchedule, ReplacementBinding, TlsIdentityId, TlsSigningRoute,
    VerifiedCertificateReceipt,
};
use mrml_acme::AcmeIdentifier;

pub struct IssuedRenewalCandidate {
    pub replacement: ReplacementBinding,
    pub verified: VerifiedCertificateReceipt,
    pub chain: PemCertificateChain,
    pub route: TlsSigningRoute,
    pub identifiers: [Option<AcmeIdentifier>; MAX_IDENTITY_NAMES],
    pub identifier_count: u8,
}

pub trait RenewalIssuer: CandidateKeyRetirementTarget {
    type Error;

    /// Produces one fully verified replacement backed by a newly generated
    /// use-only key. An error must either prove that no candidate key was
    /// created or retain enough durable issuer state to recover and retire it.
    fn issue_replacement(
        &mut self,
        lease: RenewalLease,
        previous: RenewalSchedule,
    ) -> Result<IssuedRenewalCandidate, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenewalExecutionError<E> {
    Manager(CertificateManagerError),
    Issuance(E),
    CandidateBinding,
    Schedule,
    Identity(IdentityError),
    Cleanup(IdentityError),
    ActivationUncertain,
    Journal(RenewalJournalError),
    PostActivationJournal(RenewalJournalError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenewalRecoveryError {
    Manager(CertificateManagerError),
    Identity(IdentityError),
    ActivationUncertain,
    ReplacementMismatch,
    Journal(RenewalJournalError),
    PostActivationJournal(RenewalJournalError),
}

#[allow(clippy::too_many_arguments)]
pub fn execute_due_renewal<I, D, E>(
    manager: &mut CertificateManager,
    identity: TlsIdentityId,
    now_unix: u64,
    lease_generation: u64,
    lease_seconds: u64,
    renewal_record_generation: u64,
    renewal_policy: RenewalPolicy,
    entropy: &mut E,
    issuer: &mut I,
    deployment: &mut D,
    checkpoints: &mut impl RenewalCheckpointSink,
) -> Result<ActivationReceipt, RenewalExecutionError<I::Error>>
where
    I: RenewalIssuer,
    D: IdentityDeploymentTarget + CandidateDeploymentRetirementTarget,
    E: RenewalEntropy,
{
    let previous = manager
        .renewal_schedule(identity)
        .map_err(RenewalExecutionError::Manager)?;
    let active = manager
        .get(identity)
        .map_err(RenewalExecutionError::Manager)?
        .active_descriptor()
        .ok_or(RenewalExecutionError::CandidateBinding)?;
    if active.generation != previous.identity_generation
        || active.policy_generation != previous.policy_generation
        || renewal_policy.generation != previous.policy_generation
    {
        return Err(RenewalExecutionError::CandidateBinding);
    }
    let lease = manager
        .begin_renewal(identity, now_unix, lease_generation, lease_seconds)
        .map_err(RenewalExecutionError::Manager)?;
    let mut journal = RenewalJournal::lease_acquired(lease, previous, renewal_record_generation)
        .map_err(RenewalExecutionError::Journal)?;
    journal = checkpoints
        .persist(journal)
        .map_err(RenewalExecutionError::Journal)?;
    let candidate = match issuer.issue_replacement(lease, previous) {
        Ok(candidate) => candidate,
        Err(error) => {
            persist_abort::<I::Error>(manager, lease, journal, checkpoints)?;
            return Err(RenewalExecutionError::Issuance(error));
        }
    };
    let expected_generation = match lease.identity_generation.checked_add(1) {
        Some(generation) => generation,
        None => {
            cleanup_unprepared(issuer, candidate.route).map_err(RenewalExecutionError::Cleanup)?;
            persist_abort::<I::Error>(manager, lease, journal, checkpoints)?;
            return Err(RenewalExecutionError::Manager(
                CertificateManagerError::ArithmeticOverflow,
            ));
        }
    };
    let binding_valid = candidate.replacement.previous_certificate_id == previous.certificate_id
        && candidate.replacement.replacement_order_url_digest
            == candidate.verified.order_url_digest
        && candidate.replacement.policy_generation == lease.policy_generation
        && candidate.verified.policy_generation == lease.policy_generation
        && candidate.verified.chain_digest == candidate.chain.chain_digest()
        && candidate.verified.ari_certificate_id != previous.certificate_id
        && candidate.verified.not_after > previous.not_after_unix
        && candidate.route.identity == lease.identity
        && candidate.route.identity_generation == expected_generation
        && candidate.route.key_identity != active.key_identity
        && candidate.route.route_generation != 0
        && candidate.route.capability_id != [0; 16];
    if !binding_valid {
        cleanup_unprepared(issuer, candidate.route).map_err(RenewalExecutionError::Cleanup)?;
        persist_abort::<I::Error>(manager, lease, journal, checkpoints)?;
        return Err(RenewalExecutionError::CandidateBinding);
    }
    let replacement_schedule = match RenewalSchedule::fallback(
        identity,
        expected_generation,
        &candidate.verified,
        renewal_policy,
        now_unix,
        entropy,
    ) {
        Ok(schedule) => schedule,
        Err(_) => {
            cleanup_unprepared(issuer, candidate.route).map_err(RenewalExecutionError::Cleanup)?;
            persist_abort::<I::Error>(manager, lease, journal, checkpoints)?;
            return Err(RenewalExecutionError::Schedule);
        }
    };
    let prepared = match manager.get_mut(identity).and_then(|identity_manager| {
        identity_manager
            .prepare_candidate(
                candidate.verified,
                candidate.chain,
                candidate.route.key_identity,
                candidate.route.route_generation,
                candidate.route.capability_id,
                candidate.identifiers,
                candidate.identifier_count,
            )
            .map_err(|_| CertificateManagerError::ReplacementMismatch)
    }) {
        Ok(prepared) => prepared,
        Err(error) => {
            cleanup_unprepared(issuer, candidate.route).map_err(RenewalExecutionError::Cleanup)?;
            persist_abort::<I::Error>(manager, lease, journal, checkpoints)?;
            return Err(RenewalExecutionError::Manager(error));
        }
    };
    if let Err(error) = manager.stage_renewal_replacement(lease, replacement_schedule) {
        manager
            .get_mut(identity)
            .map_err(RenewalExecutionError::Manager)?
            .abort_candidate(prepared, deployment, issuer)
            .map_err(RenewalExecutionError::Cleanup)?;
        persist_abort::<I::Error>(manager, lease, journal, checkpoints)?;
        return Err(RenewalExecutionError::Manager(error));
    }
    let staged_journal = journal
        .replacement_staged(replacement_schedule)
        .map_err(RenewalExecutionError::Journal)?;
    journal = match checkpoints.persist(staged_journal) {
        Ok(journal) => journal,
        Err(error) => {
            manager
                .get_mut(identity)
                .map_err(RenewalExecutionError::Manager)?
                .abort_candidate(prepared, deployment, issuer)
                .map_err(RenewalExecutionError::Cleanup)?;
            persist_abort::<I::Error>(manager, lease, journal, checkpoints)?;
            return Err(RenewalExecutionError::Journal(error));
        }
    };
    let operation = (|| {
        let identity_manager = manager
            .get_mut(identity)
            .map_err(RenewalExecutionError::Manager)?;
        identity_manager
            .publish_candidate(prepared, deployment)
            .map_err(RenewalExecutionError::Identity)?;
        let tested = identity_manager
            .test_candidate(prepared, deployment)
            .map_err(RenewalExecutionError::Identity)?;
        identity_manager
            .activate(tested, deployment)
            .map_err(|error| {
                if error == IdentityError::ActivationUncertain {
                    RenewalExecutionError::ActivationUncertain
                } else {
                    RenewalExecutionError::Identity(error)
                }
            })
    })();
    let activation = match operation {
        Ok(receipt) => receipt,
        Err(RenewalExecutionError::ActivationUncertain) => {
            let uncertain = journal
                .activation_uncertain()
                .map_err(RenewalExecutionError::PostActivationJournal)?;
            checkpoints
                .persist(uncertain)
                .map_err(RenewalExecutionError::PostActivationJournal)?;
            return Err(RenewalExecutionError::ActivationUncertain);
        }
        Err(error) => {
            manager
                .get_mut(identity)
                .map_err(RenewalExecutionError::Manager)?
                .abort_candidate(prepared, deployment, issuer)
                .map_err(RenewalExecutionError::Cleanup)?;
            persist_abort::<I::Error>(manager, lease, journal, checkpoints)?;
            return Err(error);
        }
    };
    let active_journal = journal
        .active()
        .map_err(RenewalExecutionError::PostActivationJournal)?;
    checkpoints
        .persist(active_journal)
        .map_err(RenewalExecutionError::PostActivationJournal)?;
    manager
        .commit_renewal(lease)
        .map_err(RenewalExecutionError::Manager)?;
    Ok(activation)
}

fn persist_abort<E>(
    manager: &mut CertificateManager,
    lease: RenewalLease,
    journal: RenewalJournal,
    checkpoints: &mut impl RenewalCheckpointSink,
) -> Result<(), RenewalExecutionError<E>> {
    checkpoints
        .persist(journal.aborted().map_err(RenewalExecutionError::Journal)?)
        .map_err(RenewalExecutionError::Journal)?;
    manager
        .finish_renewal(lease)
        .map_err(RenewalExecutionError::Manager)
}

pub fn resolve_uncertain_renewal(
    manager: &mut CertificateManager,
    mut journal: RenewalJournal,
    deployment: &mut impl IdentityDeploymentTarget,
    checkpoints: &mut impl RenewalCheckpointSink,
) -> Result<ActivationReceipt, RenewalRecoveryError> {
    let lease = journal.lease;
    let replacement = manager
        .staged_renewal_replacement(lease)
        .map_err(RenewalRecoveryError::Manager)?;
    if journal.previous
        != manager
            .renewal_schedule(lease.identity)
            .map_err(RenewalRecoveryError::Manager)?
        || journal.replacement != Some(replacement)
    {
        return Err(RenewalRecoveryError::ReplacementMismatch);
    }
    journal = match journal.stage {
        crate::DurableRenewalStage::ReplacementStaged => checkpoints
            .persist(
                journal
                    .activation_uncertain()
                    .map_err(RenewalRecoveryError::Journal)?,
            )
            .map_err(RenewalRecoveryError::Journal)?,
        crate::DurableRenewalStage::ActivationUncertain => journal,
        _ => return Err(RenewalRecoveryError::ReplacementMismatch),
    };
    let identity_manager = manager
        .get_mut(lease.identity)
        .map_err(RenewalRecoveryError::Manager)?;
    let resolved = if identity_manager
        .active_descriptor()
        .is_some_and(|active| active.generation == replacement.identity_generation)
    {
        identity_manager.confirm_active(deployment)
    } else {
        identity_manager.resolve_activation(deployment)
    };
    let activation = match resolved {
        Ok(receipt) => receipt,
        Err(IdentityError::ActivationNotCommitted) => manager
            .get_mut(lease.identity)
            .map_err(RenewalRecoveryError::Manager)?
            .retry_tested_activation(deployment)
            .map_err(|error| {
                if error == IdentityError::ActivationUncertain {
                    RenewalRecoveryError::ActivationUncertain
                } else {
                    RenewalRecoveryError::Identity(error)
                }
            })?,
        Err(IdentityError::ActivationUncertain) => {
            return Err(RenewalRecoveryError::ActivationUncertain);
        }
        Err(error) => return Err(RenewalRecoveryError::Identity(error)),
    };
    if activation.identity != lease.identity
        || activation.generation != replacement.identity_generation
    {
        return Err(RenewalRecoveryError::ReplacementMismatch);
    }
    checkpoints
        .persist(
            journal
                .active()
                .map_err(RenewalRecoveryError::PostActivationJournal)?,
        )
        .map_err(RenewalRecoveryError::PostActivationJournal)?;
    manager
        .commit_renewal(lease)
        .map_err(RenewalRecoveryError::Manager)?;
    Ok(activation)
}

fn cleanup_unprepared(
    target: &mut impl CandidateKeyRetirementTarget,
    route: TlsSigningRoute,
) -> Result<CandidateKeyRetirementReceipt, IdentityError> {
    let receipt = target.retire_candidate_key(route)?;
    if receipt.identity != route.identity
        || receipt.identity_generation != route.identity_generation
        || receipt.key_identity != route.key_identity
        || receipt.route_generation != route.route_generation
    {
        return Err(IdentityError::ReceiptMismatch);
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::{
        CandidateDeploymentRetirementReceipt, ExpiryHealth, PreparedIdentityReceipt, RenewalSource,
        TestedIdentityReceipt, TlsIdentityDescriptor, TlsKeyIdentity,
    };
    use mrml_acme::{AriCertificateId, CaClass, CertificateProfile, DnsIdentifier};

    struct Entropy;
    impl RenewalEntropy for Entropy {
        fn random_u64(&mut self) -> Result<u64, crate::SchedulerError> {
            Ok(7)
        }
    }

    #[derive(Clone, Copy)]
    struct Checkpoints {
        records: [Option<RenewalJournal>; 8],
        count: u8,
        fail_at: Option<u8>,
    }
    impl Checkpoints {
        const fn new(fail_at: Option<u8>) -> Self {
            Self {
                records: [None; 8],
                count: 0,
                fail_at,
            }
        }
        fn last(&self) -> RenewalJournal {
            self.records[usize::from(self.count - 1)].unwrap()
        }
    }
    impl RenewalCheckpointSink for Checkpoints {
        fn persist(
            &mut self,
            mut journal: RenewalJournal,
        ) -> Result<RenewalJournal, RenewalJournalError> {
            let call = self.count + 1;
            if self.fail_at == Some(call) {
                self.fail_at = None;
                return Err(RenewalJournalError::Durable(
                    crate::DurableError::StoreUnavailable,
                ));
            }
            journal.record_generation += 1;
            self.records[usize::from(self.count)] = Some(journal);
            self.count += 1;
            Ok(journal)
        }
    }

    struct Runtime {
        target_generation: u64,
        active: Option<(u64, [u8; 32])>,
        candidate: Option<(PreparedIdentityReceipt, u64)>,
        fail_test: bool,
        uncertain_once: bool,
    }
    impl Runtime {
        const fn new() -> Self {
            Self {
                target_generation: 0,
                active: None,
                candidate: None,
                fail_test: false,
                uncertain_once: false,
            }
        }
    }
    impl IdentityDeploymentTarget for Runtime {
        fn prepare(
            &mut self,
            descriptor: &TlsIdentityDescriptor,
            chain: &PemCertificateChain,
            route: TlsSigningRoute,
        ) -> Result<u64, IdentityError> {
            if self.candidate.is_some()
                || descriptor.chain_digest != chain.chain_digest()
                || descriptor.identity != route.identity
                || descriptor.generation != route.identity_generation
            {
                return Err(IdentityError::ReceiptMismatch);
            }
            self.target_generation += 1;
            self.candidate = Some((
                PreparedIdentityReceipt {
                    identity: descriptor.identity,
                    generation: descriptor.generation,
                    descriptor_digest: descriptor.binding_digest(),
                    chain_digest: descriptor.chain_digest,
                },
                self.target_generation,
            ));
            Ok(self.target_generation)
        }

        fn test_candidate(
            &mut self,
            prepared: PreparedIdentityReceipt,
            target_generation: u64,
        ) -> Result<TestedIdentityReceipt, IdentityError> {
            if self.candidate != Some((prepared, target_generation)) {
                return Err(IdentityError::ReceiptMismatch);
            }
            if self.fail_test {
                return Err(IdentityError::TestFailed);
            }
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
            if self.candidate != Some((tested.prepared, tested.target_generation)) {
                return Err(IdentityError::ReceiptMismatch);
            }
            if self.uncertain_once {
                self.uncertain_once = false;
                return Err(IdentityError::ActivationUncertain);
            }
            let previous_generation = self.active.map(|active| active.0);
            self.active = Some((
                tested.prepared.generation,
                tested.prepared.descriptor_digest,
            ));
            self.candidate = None;
            Ok(ActivationReceipt {
                identity: tested.prepared.identity,
                generation: tested.prepared.generation,
                descriptor_digest: tested.prepared.descriptor_digest,
                previous_generation,
                target_generation: tested.target_generation,
            })
        }

        fn describe_active(&mut self, _: TlsIdentityId) -> Result<(u64, [u8; 32]), IdentityError> {
            self.active.ok_or(IdentityError::InvalidState)
        }
    }
    impl CandidateDeploymentRetirementTarget for Runtime {
        fn retire_candidate_deployment(
            &mut self,
            prepared: PreparedIdentityReceipt,
            target_generation: u64,
        ) -> Result<CandidateDeploymentRetirementReceipt, IdentityError> {
            if self.candidate != Some((prepared, target_generation)) {
                return Err(IdentityError::ReceiptMismatch);
            }
            self.candidate = None;
            Ok(CandidateDeploymentRetirementReceipt {
                prepared,
                target_generation,
            })
        }
    }

    struct Issuer {
        identity: TlsIdentityId,
        retired: u8,
    }
    impl CandidateKeyRetirementTarget for Issuer {
        fn retire_candidate_key(
            &mut self,
            route: TlsSigningRoute,
        ) -> Result<CandidateKeyRetirementReceipt, IdentityError> {
            self.retired += 1;
            Ok(CandidateKeyRetirementReceipt {
                identity: route.identity,
                identity_generation: route.identity_generation,
                key_identity: route.key_identity,
                route_generation: route.route_generation,
            })
        }
    }
    impl RenewalIssuer for Issuer {
        type Error = u8;

        fn issue_replacement(
            &mut self,
            lease: RenewalLease,
            previous: RenewalSchedule,
        ) -> Result<IssuedRenewalCandidate, Self::Error> {
            let chain = chain();
            let verified = receipt(
                2_000,
                AriCertificateId::derive(&[9], &[9]).unwrap(),
                chain.chain_digest(),
                [9; 32],
            );
            let mut identifiers = [None; MAX_IDENTITY_NAMES];
            identifiers[0] = Some(AcmeIdentifier::Dns(
                DnsIdentifier::parse("git.example", false).unwrap(),
            ));
            Ok(IssuedRenewalCandidate {
                replacement: ReplacementBinding {
                    previous_certificate_id: previous.certificate_id,
                    replacement_order_url_digest: verified.order_url_digest,
                    policy_generation: lease.policy_generation,
                },
                verified,
                chain,
                route: TlsSigningRoute {
                    identity: self.identity,
                    identity_generation: lease.identity_generation + 1,
                    key_identity: TlsKeyIdentity([8; 32]),
                    route_generation: 2,
                    capability_id: [7; 16],
                },
                identifiers,
                identifier_count: 1,
            })
        }
    }

    fn chain() -> PemCertificateChain {
        PemCertificateChain::parse(b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----")
            .unwrap()
    }

    fn receipt(
        not_after: u64,
        certificate_id: AriCertificateId,
        chain_digest: [u8; 32],
        order_url_digest: [u8; 32],
    ) -> VerifiedCertificateReceipt {
        VerifiedCertificateReceipt {
            policy_generation: 1,
            ca_class: CaClass::Staging,
            profile: CertificateProfile::parse("classic", 1).unwrap(),
            order_url_digest,
            chain_digest,
            leaf_spki_digest: [3; 32],
            not_before: 100,
            not_after,
            trust_store_digest: [4; 32],
            ari_certificate_id: certificate_id,
        }
    }

    fn policy() -> RenewalPolicy {
        RenewalPolicy {
            generation: 1,
            fallback_elapsed_numerator: 2,
            fallback_elapsed_denominator: 3,
            minimum_renewal_lead_seconds: 100,
            warning_lead_seconds: 200,
            critical_lead_seconds: 50,
            initial_backoff_seconds: 10,
            maximum_backoff_seconds: 200,
            ari_requery_min_seconds: 20,
            ari_requery_max_seconds: 40,
        }
    }

    fn setup() -> (
        std::boxed::Box<CertificateManager>,
        Runtime,
        TlsIdentityId,
        RenewalSchedule,
    ) {
        let identity = TlsIdentityId([1; 16]);
        let mut manager = std::boxed::Box::new(CertificateManager::new());
        manager.enroll(identity, 1).unwrap();
        let mut runtime = Runtime::new();
        let chain = chain();
        let old_id = AriCertificateId::derive(&[1], &[1]).unwrap();
        let verified = receipt(1_000, old_id, chain.chain_digest(), [1; 32]);
        let mut identifiers = [None; MAX_IDENTITY_NAMES];
        identifiers[0] = Some(AcmeIdentifier::Dns(
            DnsIdentifier::parse("git.example", false).unwrap(),
        ));
        let prepared = manager
            .get_mut(identity)
            .unwrap()
            .prepare_candidate(
                verified,
                chain,
                TlsKeyIdentity([5; 32]),
                1,
                [6; 16],
                identifiers,
                1,
            )
            .unwrap();
        let identity_manager = manager.get_mut(identity).unwrap();
        identity_manager
            .publish_candidate(prepared, &mut runtime)
            .unwrap();
        let tested = identity_manager
            .test_candidate(prepared, &mut runtime)
            .unwrap();
        identity_manager.activate(tested, &mut runtime).unwrap();
        let schedule = RenewalSchedule {
            identity,
            identity_generation: 1,
            policy_generation: 1,
            certificate_id: old_id,
            source: RenewalSource::Ari,
            renew_at_unix: 200,
            requery_ari_at_unix: 180,
            not_after_unix: 1_000,
            failure_count: 0,
            health: ExpiryHealth::Healthy,
        };
        manager.install_renewal_schedule(schedule).unwrap();
        (manager, runtime, identity, schedule)
    }

    #[test]
    fn unattended_renewal_rotates_key_tests_activates_and_commits_schedule() {
        let (mut manager, mut runtime, identity, previous) = setup();
        let mut issuer = Issuer {
            identity,
            retired: 0,
        };
        let mut checkpoints = Checkpoints::new(None);
        let activation = execute_due_renewal(
            &mut manager,
            identity,
            200,
            1,
            60,
            0,
            policy(),
            &mut Entropy,
            &mut issuer,
            &mut runtime,
            &mut checkpoints,
        )
        .unwrap();
        assert_eq!(activation.generation, 2);
        assert_eq!(issuer.retired, 0);
        let replacement = manager.renewal_schedule(identity).unwrap();
        assert_eq!(replacement.identity_generation, 2);
        assert!(replacement.certificate_id != previous.certificate_id);
        assert_eq!(runtime.active.unwrap().0, 2);
        assert_eq!(checkpoints.count, 3);
        assert_eq!(
            checkpoints.records[0].unwrap().stage,
            crate::DurableRenewalStage::LeaseAcquired
        );
        assert_eq!(
            checkpoints.records[1].unwrap().stage,
            crate::DurableRenewalStage::ReplacementStaged
        );
        assert_eq!(
            checkpoints.records[2].unwrap().stage,
            crate::DurableRenewalStage::Active
        );
    }

    #[test]
    fn failed_candidate_test_retires_candidate_and_keeps_active_generation() {
        let (mut manager, mut runtime, identity, previous) = setup();
        runtime.fail_test = true;
        let mut issuer = Issuer {
            identity,
            retired: 0,
        };
        let mut checkpoints = Checkpoints::new(None);
        assert!(matches!(
            execute_due_renewal(
                &mut manager,
                identity,
                200,
                1,
                60,
                0,
                policy(),
                &mut Entropy,
                &mut issuer,
                &mut runtime,
                &mut checkpoints,
            ),
            Err(RenewalExecutionError::Identity(IdentityError::TestFailed))
        ));
        assert_eq!(issuer.retired, 1);
        assert!(runtime.candidate.is_none());
        assert_eq!(runtime.active.unwrap().0, 1);
        assert!(manager.renewal_schedule(identity).unwrap() == previous);
        assert!(manager.begin_renewal(identity, 200, 2, 60).is_ok());
        assert_eq!(
            checkpoints.last().stage,
            crate::DurableRenewalStage::Aborted
        );
    }

    #[test]
    fn uncertain_activation_is_authoritatively_resolved_then_committed() {
        let (mut manager, mut runtime, identity, _) = setup();
        runtime.uncertain_once = true;
        let mut issuer = Issuer {
            identity,
            retired: 0,
        };
        let mut checkpoints = Checkpoints::new(None);
        assert!(matches!(
            execute_due_renewal(
                &mut manager,
                identity,
                200,
                1,
                60,
                0,
                policy(),
                &mut Entropy,
                &mut issuer,
                &mut runtime,
                &mut checkpoints,
            ),
            Err(RenewalExecutionError::ActivationUncertain)
        ));
        let lease = RenewalLease {
            identity,
            identity_generation: 1,
            policy_generation: 1,
            lease_generation: 1,
            expires_at_unix: 260,
        };
        assert_eq!(
            manager
                .staged_renewal_replacement(lease)
                .unwrap()
                .identity_generation,
            2
        );
        let recovered = checkpoints.last();
        assert_eq!(
            recovered.stage,
            crate::DurableRenewalStage::ActivationUncertain
        );
        let activation =
            resolve_uncertain_renewal(&mut manager, recovered, &mut runtime, &mut checkpoints)
                .unwrap();
        assert_eq!(activation.generation, 2);
        assert_eq!(runtime.active.unwrap().0, 2);
        assert_eq!(
            manager
                .renewal_schedule(identity)
                .unwrap()
                .identity_generation,
            2
        );
    }

    #[test]
    fn staged_checkpoint_failure_aborts_before_publication() {
        let (mut manager, mut runtime, identity, previous) = setup();
        let mut issuer = Issuer {
            identity,
            retired: 0,
        };
        let mut checkpoints = Checkpoints::new(Some(2));
        assert!(matches!(
            execute_due_renewal(
                &mut manager,
                identity,
                200,
                1,
                60,
                0,
                policy(),
                &mut Entropy,
                &mut issuer,
                &mut runtime,
                &mut checkpoints,
            ),
            Err(RenewalExecutionError::Journal(
                RenewalJournalError::Durable(crate::DurableError::StoreUnavailable)
            ))
        ));
        assert_eq!(issuer.retired, 1);
        assert_eq!(runtime.active.unwrap().0, 1);
        assert!(runtime.candidate.is_none());
        assert!(manager.renewal_schedule(identity).unwrap() == previous);
        assert_eq!(
            checkpoints.last().stage,
            crate::DurableRenewalStage::Aborted
        );
        assert!(manager.begin_renewal(identity, 200, 2, 60).is_ok());
    }

    #[test]
    fn active_checkpoint_failure_recovers_without_reissuing_or_retiring_key() {
        let (mut manager, mut runtime, identity, previous) = setup();
        let mut issuer = Issuer {
            identity,
            retired: 0,
        };
        let mut checkpoints = Checkpoints::new(Some(3));
        assert!(matches!(
            execute_due_renewal(
                &mut manager,
                identity,
                200,
                1,
                60,
                0,
                policy(),
                &mut Entropy,
                &mut issuer,
                &mut runtime,
                &mut checkpoints,
            ),
            Err(RenewalExecutionError::PostActivationJournal(
                RenewalJournalError::Durable(crate::DurableError::StoreUnavailable)
            ))
        ));
        assert_eq!(runtime.active.unwrap().0, 2);
        assert_eq!(issuer.retired, 0);
        assert!(manager.renewal_schedule(identity).unwrap() == previous);
        let staged = checkpoints.last();
        assert_eq!(staged.stage, crate::DurableRenewalStage::ReplacementStaged);
        let activation =
            resolve_uncertain_renewal(&mut manager, staged, &mut runtime, &mut checkpoints)
                .unwrap();
        assert_eq!(activation.generation, 2);
        assert_eq!(
            manager
                .renewal_schedule(identity)
                .unwrap()
                .identity_generation,
            2
        );
        assert_eq!(checkpoints.last().stage, crate::DurableRenewalStage::Active);
    }
}
