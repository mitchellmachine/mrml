use crate::{PhysAddr, ProtectionBackend, ProtectionClaims, ProtectionError, ProtectionReport};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainId(u64);

impl DomainId {
    const fn new(index: usize, generation: u32) -> Self {
        Self(((generation as u64) << 32) | index as u64)
    }

    const fn index(self) -> usize {
        self.0 as u32 as usize
    }

    const fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }

    pub const fn token(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GranuleId(u64);

impl GranuleId {
    const fn new(index: usize, generation: u32) -> Self {
        Self(((generation as u64) << 32) | index as u64)
    }

    const fn index(self) -> usize {
        self.0 as u32 as usize
    }

    const fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }

    pub const fn token(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainState {
    Building,
    Measured,
    Runnable,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GranuleState {
    HostOwned,
    Delegated,
    Private,
    Shared,
    ScrubRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GranuleTransitionKind {
    Delegate,
    AssignPrivate,
    Share,
    MakePrivate,
    Reclaim,
    CompleteScrub,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GranuleTransition {
    granule: GranuleId,
    sequence: u32,
    kind: GranuleTransitionKind,
    physical: PhysAddr,
}

impl GranuleTransition {
    pub const fn granule(self) -> GranuleId {
        self.granule
    }

    pub const fn kind(self) -> GranuleTransitionKind {
        self.kind
    }

    pub const fn physical(self) -> PhysAddr {
        self.physical
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitorError {
    DomainTableFull,
    GranuleTableFull,
    StaleDomain,
    StaleGranule,
    DuplicateGranule,
    InvalidDomainState,
    InvalidGranuleState,
    WrongOwner,
    DomainHasGranules,
    SequenceExhausted,
    ScrubFailed,
    HardwareTransitionFailed,
    TransitionPending,
    StaleTransition,
    DomainHasPendingTransition,
    InvalidSecurityVersion,
    Report(ProtectionError),
}

#[derive(Clone, Copy)]
struct Domain {
    generation: u32,
    state: DomainState,
    measurement: [u8; 64],
}

#[derive(Clone, Copy)]
struct Granule {
    generation: u32,
    physical: PhysAddr,
    state: GranuleState,
    owner: Option<DomainId>,
    transition_sequence: u32,
    pending: Option<PendingTransition>,
}

#[derive(Clone, Copy)]
struct PendingTransition {
    sequence: u32,
    kind: GranuleTransitionKind,
    from_state: GranuleState,
    from_owner: Option<DomainId>,
    to_state: GranuleState,
    to_owner: Option<DomainId>,
}

/// Backend-neutral ownership state machine for protected domains. Hardware
/// adapters must apply the corresponding SLAT/IOMMU transition before calling
/// `complete_scrub` or exposing a newly transitioned granule.
pub struct ProtectedMonitor<const DOMAINS: usize, const GRANULES: usize> {
    domains: [Option<Domain>; DOMAINS],
    domain_generations: [u32; DOMAINS],
    granules: [Option<Granule>; GRANULES],
    granule_generations: [u32; GRANULES],
    security_version: u64,
    report_sequence: u64,
}

impl<const DOMAINS: usize, const GRANULES: usize> ProtectedMonitor<DOMAINS, GRANULES> {
    pub const fn new() -> Self {
        Self {
            domains: [None; DOMAINS],
            domain_generations: [0; DOMAINS],
            granules: [None; GRANULES],
            granule_generations: [0; GRANULES],
            security_version: 1,
            report_sequence: 0,
        }
    }

    pub fn with_security_version(security_version: u64) -> Result<Self, MonitorError> {
        if security_version == 0 {
            return Err(MonitorError::InvalidSecurityVersion);
        }
        let mut monitor = Self::new();
        monitor.security_version = security_version;
        Ok(monitor)
    }

    pub fn create_domain(&mut self) -> Result<DomainId, MonitorError> {
        let index = self
            .domains
            .iter()
            .position(Option::is_none)
            .ok_or(MonitorError::DomainTableFull)?;
        let generation = self.domain_generations[index]
            .checked_add(1)
            .ok_or(MonitorError::SequenceExhausted)?;
        self.domain_generations[index] = generation;
        self.domains[index] = Some(Domain {
            generation,
            state: DomainState::Building,
            measurement: [0; 64],
        });
        Ok(DomainId::new(index, generation))
    }

    pub fn seal_domain(&mut self, id: DomainId, measurement: [u8; 64]) -> Result<(), MonitorError> {
        if measurement == [0; 64] {
            return Err(MonitorError::InvalidDomainState);
        }
        if self.domain_has_pending_transition(id) {
            return Err(MonitorError::DomainHasPendingTransition);
        }
        let domain = self.domain_mut(id)?;
        if domain.state != DomainState::Building {
            return Err(MonitorError::InvalidDomainState);
        }
        domain.measurement = measurement;
        domain.state = DomainState::Measured;
        Ok(())
    }

    pub fn start_domain(&mut self, id: DomainId) -> Result<(), MonitorError> {
        if self.domain_has_pending_transition(id) {
            return Err(MonitorError::DomainHasPendingTransition);
        }
        let domain = self.domain_mut(id)?;
        if !matches!(domain.state, DomainState::Measured | DomainState::Stopped) {
            return Err(MonitorError::InvalidDomainState);
        }
        domain.state = DomainState::Runnable;
        Ok(())
    }

    pub fn stop_domain(&mut self, id: DomainId) -> Result<(), MonitorError> {
        if self.domain_has_pending_transition(id) {
            return Err(MonitorError::DomainHasPendingTransition);
        }
        let domain = self.domain_mut(id)?;
        if domain.state != DomainState::Runnable {
            return Err(MonitorError::InvalidDomainState);
        }
        domain.state = DomainState::Stopped;
        Ok(())
    }

    pub fn destroy_domain(&mut self, id: DomainId) -> Result<(), MonitorError> {
        if self.domain_has_pending_transition(id) {
            return Err(MonitorError::DomainHasPendingTransition);
        }
        let domain = self.domain(id)?;
        if domain.state == DomainState::Runnable {
            return Err(MonitorError::InvalidDomainState);
        }
        if self
            .granules
            .iter()
            .flatten()
            .any(|granule| granule.owner == Some(id))
        {
            return Err(MonitorError::DomainHasGranules);
        }
        self.domains[id.index()] = None;
        Ok(())
    }

    pub fn register_granule(&mut self, physical: PhysAddr) -> Result<GranuleId, MonitorError> {
        if self
            .granules
            .iter()
            .flatten()
            .any(|granule| granule.physical == physical)
        {
            return Err(MonitorError::DuplicateGranule);
        }
        let index = self
            .granules
            .iter()
            .position(Option::is_none)
            .ok_or(MonitorError::GranuleTableFull)?;
        let generation = self.granule_generations[index]
            .checked_add(1)
            .ok_or(MonitorError::SequenceExhausted)?;
        self.granule_generations[index] = generation;
        self.granules[index] = Some(Granule {
            generation,
            physical,
            state: GranuleState::HostOwned,
            owner: None,
            transition_sequence: 0,
            pending: None,
        });
        Ok(GranuleId::new(index, generation))
    }

    pub fn prepare_delegate(&mut self, id: GranuleId) -> Result<GranuleTransition, MonitorError> {
        self.prepare_transition(
            id,
            GranuleTransitionKind::Delegate,
            GranuleState::HostOwned,
            None,
            GranuleState::Delegated,
            None,
        )
    }

    pub fn prepare_assign_private(
        &mut self,
        granule_id: GranuleId,
        domain_id: DomainId,
    ) -> Result<GranuleTransition, MonitorError> {
        if self.domain(domain_id)?.state != DomainState::Building {
            return Err(MonitorError::InvalidDomainState);
        }
        self.prepare_transition(
            granule_id,
            GranuleTransitionKind::AssignPrivate,
            GranuleState::Delegated,
            None,
            GranuleState::Private,
            Some(domain_id),
        )
    }

    pub fn prepare_share(
        &mut self,
        id: GranuleId,
        owner: DomainId,
    ) -> Result<GranuleTransition, MonitorError> {
        self.domain(owner)?;
        self.prepare_transition(
            id,
            GranuleTransitionKind::Share,
            GranuleState::Private,
            Some(owner),
            GranuleState::Shared,
            Some(owner),
        )
    }

    pub fn prepare_make_private(
        &mut self,
        id: GranuleId,
        owner: DomainId,
    ) -> Result<GranuleTransition, MonitorError> {
        self.domain(owner)?;
        self.prepare_transition(
            id,
            GranuleTransitionKind::MakePrivate,
            GranuleState::Shared,
            Some(owner),
            GranuleState::Private,
            Some(owner),
        )
    }

    pub fn prepare_reclaim(
        &mut self,
        id: GranuleId,
        owner: DomainId,
    ) -> Result<GranuleTransition, MonitorError> {
        self.domain(owner)?;
        let state = self.granule(id)?.state;
        if !matches!(state, GranuleState::Private | GranuleState::Shared) {
            return Err(MonitorError::InvalidGranuleState);
        }
        self.prepare_transition(
            id,
            GranuleTransitionKind::Reclaim,
            state,
            Some(owner),
            GranuleState::ScrubRequired,
            None,
        )
    }

    pub fn prepare_complete_scrub(
        &mut self,
        id: GranuleId,
    ) -> Result<GranuleTransition, MonitorError> {
        self.prepare_transition(
            id,
            GranuleTransitionKind::CompleteScrub,
            GranuleState::ScrubRequired,
            None,
            GranuleState::HostOwned,
            None,
        )
    }

    pub fn complete_transition(
        &mut self,
        transition: GranuleTransition,
        hardware_succeeded: bool,
    ) -> Result<(), MonitorError> {
        let pending = self
            .granule(transition.granule)?
            .pending
            .ok_or(MonitorError::StaleTransition)?;
        if pending.sequence != transition.sequence || pending.kind != transition.kind {
            return Err(MonitorError::StaleTransition);
        }
        if !hardware_succeeded {
            self.granule_mut(transition.granule)?.pending = None;
            return Err(if pending.kind == GranuleTransitionKind::CompleteScrub {
                MonitorError::ScrubFailed
            } else {
                MonitorError::HardwareTransitionFailed
            });
        }
        if let Some(owner) = pending.to_owner {
            let domain = self.domain(owner)?;
            if pending.kind == GranuleTransitionKind::AssignPrivate
                && domain.state != DomainState::Building
            {
                return Err(MonitorError::InvalidDomainState);
            }
        }
        let granule = self.granule_mut(transition.granule)?;
        if granule.state != pending.from_state || granule.owner != pending.from_owner {
            return Err(MonitorError::StaleTransition);
        }
        granule.state = pending.to_state;
        granule.owner = pending.to_owner;
        granule.pending = None;
        Ok(())
    }

    pub fn granule_state(&self, id: GranuleId) -> Result<GranuleState, MonitorError> {
        Ok(self.granule(id)?.state)
    }

    pub fn domain_state(&self, id: DomainId) -> Result<DomainState, MonitorError> {
        Ok(self.domain(id)?.state)
    }

    /// Issues backend evidence only from live monitor-owned state. The report
    /// remains local evidence until an independent authority authenticates it.
    pub fn issue_report(
        &mut self,
        id: DomainId,
        nonce: [u8; 32],
    ) -> Result<ProtectionReport, MonitorError> {
        if self.domain_has_pending_transition(id) {
            return Err(MonitorError::DomainHasPendingTransition);
        }
        let domain = *self.domain(id)?;
        if !matches!(domain.state, DomainState::Measured | DomainState::Runnable) {
            return Err(MonitorError::InvalidDomainState);
        }
        let mut owns_private = false;
        let mut owns_shared = false;
        for granule in self
            .granules
            .iter()
            .flatten()
            .filter(|granule| granule.owner == Some(id))
        {
            owns_private |= granule.state == GranuleState::Private;
            owns_shared |= granule.state == GranuleState::Shared;
        }
        let mut claims = ProtectionClaims::MEASURED;
        if owns_private && !owns_shared {
            claims = claims.union(ProtectionClaims::DOMAIN_ISOLATION);
        }
        let sequence = self
            .report_sequence
            .checked_add(1)
            .ok_or(MonitorError::SequenceExhausted)?;
        let report = ProtectionReport::new(
            ProtectionBackend::BareMetalMonitor,
            claims,
            false,
            self.security_version,
            sequence,
            domain.measurement,
            nonce,
        )
        .map_err(MonitorError::Report)?;
        self.report_sequence = sequence;
        Ok(report)
    }

    fn prepare_transition(
        &mut self,
        id: GranuleId,
        kind: GranuleTransitionKind,
        from_state: GranuleState,
        from_owner: Option<DomainId>,
        to_state: GranuleState,
        to_owner: Option<DomainId>,
    ) -> Result<GranuleTransition, MonitorError> {
        let granule = self.granule_mut(id)?;
        if granule.pending.is_some() {
            return Err(MonitorError::TransitionPending);
        }
        if granule.state != from_state {
            return Err(MonitorError::InvalidGranuleState);
        }
        if granule.owner != from_owner {
            return Err(MonitorError::WrongOwner);
        }
        let sequence = granule
            .transition_sequence
            .checked_add(1)
            .ok_or(MonitorError::SequenceExhausted)?;
        granule.transition_sequence = sequence;
        granule.pending = Some(PendingTransition {
            sequence,
            kind,
            from_state,
            from_owner,
            to_state,
            to_owner,
        });
        Ok(GranuleTransition {
            granule: id,
            sequence,
            kind,
            physical: granule.physical,
        })
    }

    fn domain_has_pending_transition(&self, id: DomainId) -> bool {
        self.granules.iter().flatten().any(|granule| {
            granule.pending.is_some_and(|pending| {
                pending.from_owner == Some(id) || pending.to_owner == Some(id)
            })
        })
    }

    fn domain(&self, id: DomainId) -> Result<&Domain, MonitorError> {
        self.domains
            .get(id.index())
            .and_then(Option::as_ref)
            .filter(|domain| domain.generation == id.generation())
            .ok_or(MonitorError::StaleDomain)
    }

    fn domain_mut(&mut self, id: DomainId) -> Result<&mut Domain, MonitorError> {
        self.domains
            .get_mut(id.index())
            .and_then(Option::as_mut)
            .filter(|domain| domain.generation == id.generation())
            .ok_or(MonitorError::StaleDomain)
    }

    fn granule(&self, id: GranuleId) -> Result<&Granule, MonitorError> {
        self.granules
            .get(id.index())
            .and_then(Option::as_ref)
            .filter(|granule| granule.generation == id.generation())
            .ok_or(MonitorError::StaleGranule)
    }

    fn granule_mut(&mut self, id: GranuleId) -> Result<&mut Granule, MonitorError> {
        self.granules
            .get_mut(id.index())
            .and_then(Option::as_mut)
            .filter(|granule| granule.generation == id.generation())
            .ok_or(MonitorError::StaleGranule)
    }
}

impl<const DOMAINS: usize, const GRANULES: usize> Default for ProtectedMonitor<DOMAINS, GRANULES> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_requires_measurement_and_scrub_before_reuse() {
        let mut monitor = ProtectedMonitor::<2, 2>::new();
        let domain = monitor.create_domain().unwrap();
        let page = monitor
            .register_granule(PhysAddr::new(0x20_0000).unwrap())
            .unwrap();
        let transition = monitor.prepare_delegate(page).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        let transition = monitor.prepare_assign_private(page, domain).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        assert_eq!(
            monitor.start_domain(domain),
            Err(MonitorError::InvalidDomainState)
        );
        monitor.seal_domain(domain, [7; 64]).unwrap();
        monitor.start_domain(domain).unwrap();
        monitor.stop_domain(domain).unwrap();
        let transition = monitor.prepare_reclaim(page, domain).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        let scrub = monitor.prepare_complete_scrub(page).unwrap();
        assert_eq!(
            monitor.complete_transition(scrub, false),
            Err(MonitorError::ScrubFailed)
        );
        assert_eq!(
            monitor.granule_state(page).unwrap(),
            GranuleState::ScrubRequired
        );
        let scrub = monitor.prepare_complete_scrub(page).unwrap();
        monitor.complete_transition(scrub, true).unwrap();
        monitor.destroy_domain(domain).unwrap();
    }

    #[test]
    fn sharing_is_owner_checked_and_blocks_destruction() {
        let mut monitor = ProtectedMonitor::<2, 2>::new();
        let owner = monitor.create_domain().unwrap();
        let stranger = monitor.create_domain().unwrap();
        let page = monitor
            .register_granule(PhysAddr::new(0x30_0000).unwrap())
            .unwrap();
        let transition = monitor.prepare_delegate(page).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        let transition = monitor.prepare_assign_private(page, owner).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        assert_eq!(
            monitor.prepare_share(page, stranger),
            Err(MonitorError::WrongOwner)
        );
        let transition = monitor.prepare_share(page, owner).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        assert_eq!(
            monitor.destroy_domain(owner),
            Err(MonitorError::DomainHasGranules)
        );
    }

    #[test]
    fn stale_identifiers_never_reacquire_authority() {
        let mut monitor = ProtectedMonitor::<1, 1>::new();
        let first = monitor.create_domain().unwrap();
        monitor.destroy_domain(first).unwrap();
        let second = monitor.create_domain().unwrap();
        assert_ne!(first, second);
        assert_eq!(monitor.domain_state(first), Err(MonitorError::StaleDomain));
    }

    #[test]
    fn reports_derive_claims_only_from_live_owned_state() {
        let mut monitor = ProtectedMonitor::<1, 1>::with_security_version(7).unwrap();
        let domain = monitor.create_domain().unwrap();
        let granule = monitor
            .register_granule(PhysAddr::new(0x40_0000).unwrap())
            .unwrap();
        assert_eq!(
            monitor.issue_report(domain, [1; 32]),
            Err(MonitorError::InvalidDomainState)
        );
        let transition = monitor.prepare_delegate(granule).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        let transition = monitor.prepare_assign_private(granule, domain).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        monitor.seal_domain(domain, [0x81; 64]).unwrap();
        let private = monitor.issue_report(domain, [1; 32]).unwrap();
        assert_eq!(private.backend(), ProtectionBackend::BareMetalMonitor);
        assert_eq!(private.security_version(), 7);
        assert_eq!(private.sequence(), 1);
        assert_eq!(private.measurement(), [0x81; 64]);
        assert_eq!(
            private.claims(),
            ProtectionClaims::MEASURED.union(ProtectionClaims::DOMAIN_ISOLATION)
        );
        assert!(!private.debug_allowed());

        let transition = monitor.prepare_share(granule, domain).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        let shared = monitor.issue_report(domain, [2; 32]).unwrap();
        assert_eq!(shared.claims(), ProtectionClaims::MEASURED);
        assert_eq!(shared.sequence(), 2);
    }

    #[test]
    fn stopped_destroyed_and_stale_domains_cannot_issue_evidence() {
        let mut monitor = ProtectedMonitor::<1, 1>::new();
        let domain = monitor.create_domain().unwrap();
        monitor.seal_domain(domain, [0x91; 64]).unwrap();
        monitor.start_domain(domain).unwrap();
        monitor.stop_domain(domain).unwrap();
        assert_eq!(
            monitor.issue_report(domain, [3; 32]),
            Err(MonitorError::InvalidDomainState)
        );
        monitor.destroy_domain(domain).unwrap();
        assert_eq!(
            monitor.issue_report(domain, [3; 32]),
            Err(MonitorError::StaleDomain)
        );
    }

    #[test]
    fn invalid_nonce_does_not_consume_report_sequence() {
        let mut monitor = ProtectedMonitor::<1, 0>::new();
        let domain = monitor.create_domain().unwrap();
        monitor.seal_domain(domain, [0xa1; 64]).unwrap();
        assert_eq!(
            monitor.issue_report(domain, [0; 32]),
            Err(MonitorError::Report(ProtectionError::MissingNonce))
        );
        assert_eq!(monitor.issue_report(domain, [4; 32]).unwrap().sequence(), 1);
        assert!(matches!(
            ProtectedMonitor::<1, 0>::with_security_version(0),
            Err(MonitorError::InvalidSecurityVersion)
        ));
    }

    #[test]
    fn transition_ticket_changes_state_only_after_hardware_success() {
        let mut monitor = ProtectedMonitor::<1, 1>::new();
        let granule = monitor
            .register_granule(PhysAddr::new(0x50_0000).unwrap())
            .unwrap();
        let transition = monitor.prepare_delegate(granule).unwrap();
        assert_eq!(transition.kind(), GranuleTransitionKind::Delegate);
        assert_eq!(transition.physical().get(), 0x50_0000);
        assert_eq!(monitor.granule_state(granule), Ok(GranuleState::HostOwned));
        assert_eq!(
            monitor.prepare_delegate(granule),
            Err(MonitorError::TransitionPending)
        );
        assert_eq!(
            monitor.complete_transition(transition, false),
            Err(MonitorError::HardwareTransitionFailed)
        );
        assert_eq!(monitor.granule_state(granule), Ok(GranuleState::HostOwned));
        let retry = monitor.prepare_delegate(granule).unwrap();
        assert_ne!(retry, transition);
        monitor.complete_transition(retry, true).unwrap();
        assert_eq!(monitor.granule_state(granule), Ok(GranuleState::Delegated));
        assert_eq!(
            monitor.complete_transition(retry, true),
            Err(MonitorError::StaleTransition)
        );
    }

    #[test]
    fn forged_or_stale_ticket_cannot_complete_pending_transition() {
        let mut monitor = ProtectedMonitor::<1, 1>::new();
        let granule = monitor
            .register_granule(PhysAddr::new(0x60_0000).unwrap())
            .unwrap();
        let transition = monitor.prepare_delegate(granule).unwrap();
        let forged = GranuleTransition {
            sequence: transition.sequence.wrapping_add(1),
            ..transition
        };
        assert_eq!(
            monitor.complete_transition(forged, true),
            Err(MonitorError::StaleTransition)
        );
        assert_eq!(
            monitor.prepare_delegate(granule),
            Err(MonitorError::TransitionPending)
        );
        monitor.complete_transition(transition, true).unwrap();
    }

    #[test]
    fn pending_domain_transition_blocks_lifecycle_and_evidence() {
        let mut monitor = ProtectedMonitor::<1, 1>::new();
        let domain = monitor.create_domain().unwrap();
        let granule = monitor
            .register_granule(PhysAddr::new(0x70_0000).unwrap())
            .unwrap();
        let transition = monitor.prepare_delegate(granule).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        let assignment = monitor.prepare_assign_private(granule, domain).unwrap();
        assert_eq!(
            monitor.seal_domain(domain, [0xb1; 64]),
            Err(MonitorError::DomainHasPendingTransition)
        );
        assert_eq!(
            monitor.issue_report(domain, [5; 32]),
            Err(MonitorError::DomainHasPendingTransition)
        );
        monitor.complete_transition(assignment, true).unwrap();
        monitor.seal_domain(domain, [0xb1; 64]).unwrap();
    }
}
