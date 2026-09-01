use crate::{DurableRenewalStage, IdentityManager, RenewalJournal, RenewalSchedule, TlsIdentityId};

pub const MAX_MANAGED_IDENTITIES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateManagerError {
    DuplicateIdentity,
    IdentityUnavailable,
    CapacityExceeded,
    InvalidPolicyGeneration,
    IdentityInUse,
    ScheduleMismatch,
    RenewalNotDue,
    RenewalInProgress,
    LeaseMismatch,
    ReplacementMismatch,
    ArithmeticOverflow,
    RecoveryStateNotEmpty,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RenewalLease {
    pub identity: TlsIdentityId,
    pub identity_generation: u64,
    pub policy_generation: u64,
    pub lease_generation: u64,
    pub expires_at_unix: u64,
}

/// Bounded owner of independent certificate identity state machines.
///
/// This registry does not select an identity from SNI or multiplex identities
/// on a listener. Consumers must present the exact identity capability to the
/// corresponding `IdentityManager` through the certificate service ABI.
pub struct CertificateManager {
    identities: [Option<IdentityManager>; MAX_MANAGED_IDENTITIES],
    schedules: [Option<RenewalSchedule>; MAX_MANAGED_IDENTITIES],
    leases: [Option<RenewalLease>; MAX_MANAGED_IDENTITIES],
    pending_schedules: [Option<RenewalSchedule>; MAX_MANAGED_IDENTITIES],
    count: u8,
}

impl CertificateManager {
    pub const fn new() -> Self {
        Self {
            identities: [const { None }; MAX_MANAGED_IDENTITIES],
            schedules: [None; MAX_MANAGED_IDENTITIES],
            leases: [None; MAX_MANAGED_IDENTITIES],
            pending_schedules: [None; MAX_MANAGED_IDENTITIES],
            count: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.count as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn enroll(
        &mut self,
        identity: TlsIdentityId,
        policy_generation: u64,
    ) -> Result<&mut IdentityManager, CertificateManagerError> {
        if policy_generation == 0 {
            return Err(CertificateManagerError::InvalidPolicyGeneration);
        }
        if self
            .identities
            .iter()
            .flatten()
            .any(|manager| manager.identity() == identity)
        {
            return Err(CertificateManagerError::DuplicateIdentity);
        }
        let index = self
            .identities
            .iter()
            .position(Option::is_none)
            .ok_or(CertificateManagerError::CapacityExceeded)?;
        self.identities[index] = Some(IdentityManager::new(identity, policy_generation));
        self.count += 1;
        Ok(self.identities[index].as_mut().unwrap())
    }

    pub fn get(
        &self,
        identity: TlsIdentityId,
    ) -> Result<&IdentityManager, CertificateManagerError> {
        self.identities
            .iter()
            .flatten()
            .find(|manager| manager.identity() == identity)
            .ok_or(CertificateManagerError::IdentityUnavailable)
    }

    pub fn get_mut(
        &mut self,
        identity: TlsIdentityId,
    ) -> Result<&mut IdentityManager, CertificateManagerError> {
        self.identities
            .iter_mut()
            .flatten()
            .find(|manager| manager.identity() == identity)
            .ok_or(CertificateManagerError::IdentityUnavailable)
    }

    pub fn remove_empty(&mut self, identity: TlsIdentityId) -> Result<(), CertificateManagerError> {
        let index = self
            .identities
            .iter()
            .position(|slot| {
                slot.as_ref()
                    .is_some_and(|manager| manager.identity() == identity)
            })
            .ok_or(CertificateManagerError::IdentityUnavailable)?;
        if self.identities[index]
            .as_ref()
            .is_some_and(IdentityManager::has_deployment_state)
        {
            return Err(CertificateManagerError::IdentityInUse);
        }
        self.identities[index] = None;
        self.schedules[index] = None;
        self.leases[index] = None;
        self.pending_schedules[index] = None;
        self.count -= 1;
        Ok(())
    }

    pub fn install_renewal_schedule(
        &mut self,
        schedule: RenewalSchedule,
    ) -> Result<(), CertificateManagerError> {
        let index = self.index(schedule.identity)?;
        let manager = self.identities[index].as_ref().unwrap();
        if schedule.identity_generation == 0
            || schedule.policy_generation != manager.policy_generation()
        {
            return Err(CertificateManagerError::ScheduleMismatch);
        }
        if self.leases[index].is_some() || self.pending_schedules[index].is_some() {
            return Err(CertificateManagerError::RenewalInProgress);
        }
        self.schedules[index] = Some(schedule);
        Ok(())
    }

    pub fn renewal_schedule(
        &self,
        identity: TlsIdentityId,
    ) -> Result<RenewalSchedule, CertificateManagerError> {
        self.schedules[self.index(identity)?].ok_or(CertificateManagerError::ScheduleMismatch)
    }

    pub fn begin_renewal(
        &mut self,
        identity: TlsIdentityId,
        now_unix: u64,
        lease_generation: u64,
        lease_seconds: u64,
    ) -> Result<RenewalLease, CertificateManagerError> {
        if lease_generation == 0 || lease_seconds == 0 {
            return Err(CertificateManagerError::LeaseMismatch);
        }
        let index = self.index(identity)?;
        let schedule = self.schedules[index].ok_or(CertificateManagerError::ScheduleMismatch)?;
        if schedule.renew_at_unix > now_unix {
            return Err(CertificateManagerError::RenewalNotDue);
        }
        if self.pending_schedules[index].is_some()
            || self.leases[index].is_some_and(|lease| lease.expires_at_unix > now_unix)
        {
            return Err(CertificateManagerError::RenewalInProgress);
        }
        let lease = RenewalLease {
            identity,
            identity_generation: schedule.identity_generation,
            policy_generation: schedule.policy_generation,
            lease_generation,
            expires_at_unix: now_unix
                .checked_add(lease_seconds)
                .ok_or(CertificateManagerError::ArithmeticOverflow)?,
        };
        self.leases[index] = Some(lease);
        self.pending_schedules[index] = None;
        Ok(lease)
    }

    pub fn finish_renewal(&mut self, lease: RenewalLease) -> Result<(), CertificateManagerError> {
        let index = self.index(lease.identity)?;
        if self.leases[index] != Some(lease) {
            return Err(CertificateManagerError::LeaseMismatch);
        }
        self.leases[index] = None;
        self.pending_schedules[index] = None;
        Ok(())
    }

    pub fn stage_renewal_replacement(
        &mut self,
        lease: RenewalLease,
        replacement: RenewalSchedule,
    ) -> Result<(), CertificateManagerError> {
        let index = self.index(lease.identity)?;
        let previous = self.schedules[index].ok_or(CertificateManagerError::ScheduleMismatch)?;
        if self.leases[index] != Some(lease)
            || previous.identity != lease.identity
            || previous.identity_generation != lease.identity_generation
            || previous.policy_generation != lease.policy_generation
            || replacement.identity != lease.identity
            || replacement.policy_generation != lease.policy_generation
            || replacement.identity_generation
                != lease
                    .identity_generation
                    .checked_add(1)
                    .ok_or(CertificateManagerError::ArithmeticOverflow)?
            || replacement.certificate_id == previous.certificate_id
            || replacement.not_after_unix <= previous.not_after_unix
        {
            return Err(CertificateManagerError::ReplacementMismatch);
        }
        self.pending_schedules[index] = Some(replacement);
        Ok(())
    }

    pub fn staged_renewal_replacement(
        &self,
        lease: RenewalLease,
    ) -> Result<RenewalSchedule, CertificateManagerError> {
        let index = self.index(lease.identity)?;
        if self.leases[index] != Some(lease) {
            return Err(CertificateManagerError::LeaseMismatch);
        }
        self.pending_schedules[index].ok_or(CertificateManagerError::ReplacementMismatch)
    }

    pub fn commit_renewal(&mut self, lease: RenewalLease) -> Result<(), CertificateManagerError> {
        let index = self.index(lease.identity)?;
        if self.leases[index] != Some(lease) {
            return Err(CertificateManagerError::LeaseMismatch);
        }
        let replacement =
            self.pending_schedules[index].ok_or(CertificateManagerError::ReplacementMismatch)?;
        self.schedules[index] = Some(replacement);
        self.pending_schedules[index] = None;
        self.leases[index] = None;
        Ok(())
    }

    /// Reconstructs only the renewal coordinator's public transaction state.
    /// The identity generation and any candidate deployment are independently
    /// restored from their authenticated records before recovery is resumed.
    pub fn restore_renewal_transaction(
        &mut self,
        journal: RenewalJournal,
    ) -> Result<(), CertificateManagerError> {
        let index = self.index(journal.lease.identity)?;
        let identity = self.identities[index].as_ref().unwrap();
        if self.schedules[index].is_some()
            || self.leases[index].is_some()
            || self.pending_schedules[index].is_some()
        {
            return Err(CertificateManagerError::RecoveryStateNotEmpty);
        }
        if journal.previous.identity != journal.lease.identity
            || journal.previous.identity_generation != journal.lease.identity_generation
            || journal.previous.policy_generation != journal.lease.policy_generation
            || identity.policy_generation() != journal.lease.policy_generation
        {
            return Err(CertificateManagerError::ScheduleMismatch);
        }
        match journal.stage {
            DurableRenewalStage::LeaseAcquired => {
                if journal.replacement.is_some() || journal.candidate.is_some() {
                    return Err(CertificateManagerError::ReplacementMismatch);
                }
                self.schedules[index] = Some(journal.previous);
                self.leases[index] = Some(journal.lease);
            }
            DurableRenewalStage::ReplacementStaged
            | DurableRenewalStage::Published
            | DurableRenewalStage::Tested
            | DurableRenewalStage::ActivationUncertain => {
                let replacement = journal
                    .replacement
                    .ok_or(CertificateManagerError::ReplacementMismatch)?;
                if journal.candidate.is_none() {
                    return Err(CertificateManagerError::ReplacementMismatch);
                }
                validate_recovered_replacement(journal.lease, journal.previous, replacement)?;
                self.schedules[index] = Some(journal.previous);
                self.leases[index] = Some(journal.lease);
                self.pending_schedules[index] = Some(replacement);
            }
            DurableRenewalStage::Active => {
                let replacement = journal
                    .replacement
                    .ok_or(CertificateManagerError::ReplacementMismatch)?;
                if journal.candidate.is_none() {
                    return Err(CertificateManagerError::ReplacementMismatch);
                }
                validate_recovered_replacement(journal.lease, journal.previous, replacement)?;
                self.schedules[index] = Some(replacement);
            }
            DurableRenewalStage::Aborted => {
                self.schedules[index] = Some(journal.previous);
            }
        }
        Ok(())
    }

    fn index(&self, identity: TlsIdentityId) -> Result<usize, CertificateManagerError> {
        self.identities
            .iter()
            .position(|slot| {
                slot.as_ref()
                    .is_some_and(|manager| manager.identity() == identity)
            })
            .ok_or(CertificateManagerError::IdentityUnavailable)
    }
}

fn validate_recovered_replacement(
    lease: RenewalLease,
    previous: RenewalSchedule,
    replacement: RenewalSchedule,
) -> Result<(), CertificateManagerError> {
    if replacement.identity != lease.identity
        || replacement.policy_generation != lease.policy_generation
        || replacement.identity_generation
            != lease
                .identity_generation
                .checked_add(1)
                .ok_or(CertificateManagerError::ArithmeticOverflow)?
        || replacement.certificate_id == previous.certificate_id
        || replacement.not_after_unix <= previous.not_after_unix
    {
        return Err(CertificateManagerError::ReplacementMismatch);
    }
    Ok(())
}

impl Default for CertificateManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ExpiryHealth, PreparedIdentityReceipt, RenewalSource, TlsKeyIdentity, TlsSigningRoute,
    };
    use mrml_acme::AriCertificateId;

    #[test]
    fn identities_are_exact_independent_and_bounded() {
        let mut registry = CertificateManager::new();
        let first = TlsIdentityId([1; 16]);
        let second = TlsIdentityId([2; 16]);
        registry.enroll(first, 4).unwrap();
        registry.enroll(second, 7).unwrap();
        assert_eq!(registry.len(), 2);
        assert_eq!(registry.get(first).unwrap().policy_generation(), 4);
        assert_eq!(registry.get(second).unwrap().policy_generation(), 7);
        assert_eq!(
            registry.enroll(first, 8).err(),
            Some(CertificateManagerError::DuplicateIdentity)
        );
        assert_eq!(
            registry.get(TlsIdentityId([3; 16])).err(),
            Some(CertificateManagerError::IdentityUnavailable)
        );
        registry.remove_empty(first).unwrap();
        assert_eq!(registry.len(), 1);
        assert!(registry.get(second).is_ok());
    }

    #[test]
    fn capacity_and_zero_policy_fail_closed() {
        let mut registry = CertificateManager::new();
        assert_eq!(
            registry.enroll(TlsIdentityId([1; 16]), 0).err(),
            Some(CertificateManagerError::InvalidPolicyGeneration)
        );
        for index in 0..MAX_MANAGED_IDENTITIES {
            let mut id = [0; 16];
            id[0] = (index + 1) as u8;
            registry.enroll(TlsIdentityId(id), 1).unwrap();
        }
        assert_eq!(
            registry.enroll(TlsIdentityId([0xff; 16]), 1).err(),
            Some(CertificateManagerError::CapacityExceeded)
        );
    }

    fn schedule(identity: TlsIdentityId, renew_at_unix: u64) -> RenewalSchedule {
        RenewalSchedule {
            identity,
            identity_generation: 2,
            policy_generation: 4,
            certificate_id: AriCertificateId::derive(&[1], &[2]).unwrap(),
            source: RenewalSource::Ari,
            renew_at_unix,
            requery_ari_at_unix: renew_at_unix,
            not_after_unix: renew_at_unix + 1000,
            failure_count: 0,
            health: ExpiryHealth::Healthy,
        }
    }

    #[test]
    fn renewal_is_identity_scoped_due_and_single_flight() {
        let mut registry = CertificateManager::new();
        let first = TlsIdentityId([1; 16]);
        let second = TlsIdentityId([2; 16]);
        registry.enroll(first, 4).unwrap();
        registry.enroll(second, 4).unwrap();
        registry
            .install_renewal_schedule(schedule(first, 100))
            .unwrap();
        registry
            .install_renewal_schedule(schedule(second, 200))
            .unwrap();
        assert_eq!(
            registry.begin_renewal(first, 99, 1, 30).err(),
            Some(CertificateManagerError::RenewalNotDue)
        );
        let lease = registry.begin_renewal(first, 100, 1, 30).unwrap();
        assert_eq!(
            registry.begin_renewal(first, 100, 2, 30).err(),
            Some(CertificateManagerError::RenewalInProgress)
        );
        assert_eq!(
            registry.begin_renewal(second, 100, 1, 30).err(),
            Some(CertificateManagerError::RenewalNotDue)
        );
        registry.finish_renewal(lease).unwrap();
        assert!(registry.begin_renewal(first, 100, 2, 30).is_ok());
    }

    #[test]
    fn expired_lease_can_be_recovered_by_a_new_generation() {
        let mut registry = CertificateManager::new();
        let identity = TlsIdentityId([3; 16]);
        registry.enroll(identity, 4).unwrap();
        registry
            .install_renewal_schedule(schedule(identity, 50))
            .unwrap();
        registry.begin_renewal(identity, 50, 1, 10).unwrap();
        let recovered = registry.begin_renewal(identity, 60, 2, 10).unwrap();
        assert_eq!(recovered.lease_generation, 2);
    }

    #[test]
    fn renewal_commit_requires_exact_new_identity_and_certificate_generation() {
        let mut registry = CertificateManager::new();
        let identity = TlsIdentityId([7; 16]);
        registry.enroll(identity, 4).unwrap();
        let prior = schedule(identity, 50);
        registry.install_renewal_schedule(prior).unwrap();
        let lease = registry.begin_renewal(identity, 50, 1, 10).unwrap();
        let mut replacement = schedule(identity, 500);
        replacement.identity_generation = 3;
        replacement.certificate_id = AriCertificateId::derive(&[3], &[4]).unwrap();
        replacement.not_after_unix = prior.not_after_unix + 1000;
        let mut substituted = replacement;
        substituted.identity_generation = 4;
        assert_eq!(
            registry.stage_renewal_replacement(lease, substituted),
            Err(CertificateManagerError::ReplacementMismatch)
        );
        assert!(registry.renewal_schedule(identity).unwrap() == prior);
        registry
            .stage_renewal_replacement(lease, replacement)
            .unwrap();
        assert!(registry.staged_renewal_replacement(lease).unwrap() == replacement);
        registry.commit_renewal(lease).unwrap();
        assert!(registry.renewal_schedule(identity).unwrap() == replacement);
        assert_eq!(
            registry.finish_renewal(lease),
            Err(CertificateManagerError::LeaseMismatch)
        );
    }

    fn recovery_journal(stage: DurableRenewalStage) -> RenewalJournal {
        let identity = TlsIdentityId([9; 16]);
        let previous = schedule(identity, 50);
        let lease = RenewalLease {
            identity,
            identity_generation: previous.identity_generation,
            policy_generation: previous.policy_generation,
            lease_generation: 7,
            expires_at_unix: 80,
        };
        let leased = RenewalJournal::lease_acquired(lease, previous, 3).unwrap();
        if stage == DurableRenewalStage::LeaseAcquired {
            return leased;
        }
        let mut replacement = schedule(identity, 500);
        replacement.identity_generation = 3;
        replacement.certificate_id = AriCertificateId::derive(&[3], &[4]).unwrap();
        replacement.not_after_unix = previous.not_after_unix + 1_000;
        let route = TlsSigningRoute {
            identity,
            identity_generation: 3,
            key_identity: TlsKeyIdentity([8; 32]),
            route_generation: 2,
            capability_id: [7; 16],
        };
        let prepared = PreparedIdentityReceipt {
            identity,
            generation: 3,
            descriptor_digest: [5; 32],
            chain_digest: [6; 32],
        };
        let staged = leased
            .replacement_staged(replacement, route, prepared)
            .unwrap();
        match stage {
            DurableRenewalStage::ReplacementStaged => staged,
            DurableRenewalStage::Active => staged
                .published(4)
                .unwrap()
                .tested(crate::TestedIdentityReceipt {
                    prepared,
                    target_generation: 4,
                    tls13_ok: true,
                    http3_quic_v2_ok: true,
                })
                .unwrap()
                .active()
                .unwrap(),
            DurableRenewalStage::Aborted => staged.aborted().unwrap(),
            _ => panic!("unsupported recovery test stage"),
        }
    }

    #[test]
    fn authenticated_renewal_transaction_restores_exact_public_state() {
        for stage in [
            DurableRenewalStage::LeaseAcquired,
            DurableRenewalStage::ReplacementStaged,
            DurableRenewalStage::Active,
            DurableRenewalStage::Aborted,
        ] {
            let journal = recovery_journal(stage);
            let mut registry = CertificateManager::new();
            registry.enroll(journal.lease.identity, 4).unwrap();
            registry.restore_renewal_transaction(journal).unwrap();
            let expected = if stage == DurableRenewalStage::Active {
                journal.replacement.unwrap()
            } else {
                journal.previous
            };
            assert!(registry.renewal_schedule(journal.lease.identity).unwrap() == expected);
            if matches!(
                stage,
                DurableRenewalStage::LeaseAcquired | DurableRenewalStage::ReplacementStaged
            ) {
                assert!(registry.finish_renewal(journal.lease).is_ok());
            } else {
                assert_eq!(
                    registry.finish_renewal(journal.lease),
                    Err(CertificateManagerError::LeaseMismatch)
                );
            }
        }
    }

    #[test]
    fn recovery_refuses_to_overwrite_live_manager_state() {
        let journal = recovery_journal(DurableRenewalStage::ReplacementStaged);
        let mut registry = CertificateManager::new();
        registry.enroll(journal.lease.identity, 4).unwrap();
        registry.install_renewal_schedule(journal.previous).unwrap();
        assert_eq!(
            registry.restore_renewal_transaction(journal),
            Err(CertificateManagerError::RecoveryStateNotEmpty)
        );
        assert!(registry.renewal_schedule(journal.lease.identity).unwrap() == journal.previous);
    }
}
