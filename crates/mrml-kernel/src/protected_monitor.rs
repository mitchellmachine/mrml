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
        let domain = self.domain_mut(id)?;
        if domain.state != DomainState::Building {
            return Err(MonitorError::InvalidDomainState);
        }
        domain.measurement = measurement;
        domain.state = DomainState::Measured;
        Ok(())
    }

    pub fn start_domain(&mut self, id: DomainId) -> Result<(), MonitorError> {
        let domain = self.domain_mut(id)?;
        if !matches!(domain.state, DomainState::Measured | DomainState::Stopped) {
            return Err(MonitorError::InvalidDomainState);
        }
        domain.state = DomainState::Runnable;
        Ok(())
    }

    pub fn stop_domain(&mut self, id: DomainId) -> Result<(), MonitorError> {
        let domain = self.domain_mut(id)?;
        if domain.state != DomainState::Runnable {
            return Err(MonitorError::InvalidDomainState);
        }
        domain.state = DomainState::Stopped;
        Ok(())
    }

    pub fn destroy_domain(&mut self, id: DomainId) -> Result<(), MonitorError> {
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
        });
        Ok(GranuleId::new(index, generation))
    }

    pub fn delegate(&mut self, id: GranuleId) -> Result<(), MonitorError> {
        self.transition_unowned(id, GranuleState::HostOwned, GranuleState::Delegated)
    }

    pub fn assign_private(
        &mut self,
        granule_id: GranuleId,
        domain_id: DomainId,
    ) -> Result<(), MonitorError> {
        if self.domain(domain_id)?.state != DomainState::Building {
            return Err(MonitorError::InvalidDomainState);
        }
        let granule = self.granule_mut(granule_id)?;
        if granule.state != GranuleState::Delegated || granule.owner.is_some() {
            return Err(MonitorError::InvalidGranuleState);
        }
        granule.state = GranuleState::Private;
        granule.owner = Some(domain_id);
        Ok(())
    }

    pub fn share(&mut self, id: GranuleId, owner: DomainId) -> Result<(), MonitorError> {
        self.domain(owner)?;
        let granule = self.granule_mut(id)?;
        if granule.state != GranuleState::Private || granule.owner != Some(owner) {
            return Err(MonitorError::WrongOwner);
        }
        granule.state = GranuleState::Shared;
        Ok(())
    }

    pub fn make_private(&mut self, id: GranuleId, owner: DomainId) -> Result<(), MonitorError> {
        self.domain(owner)?;
        let granule = self.granule_mut(id)?;
        if granule.state != GranuleState::Shared || granule.owner != Some(owner) {
            return Err(MonitorError::WrongOwner);
        }
        granule.state = GranuleState::Private;
        Ok(())
    }

    pub fn reclaim(&mut self, id: GranuleId, owner: DomainId) -> Result<(), MonitorError> {
        self.domain(owner)?;
        let granule = self.granule_mut(id)?;
        if granule.owner != Some(owner)
            || !matches!(granule.state, GranuleState::Private | GranuleState::Shared)
        {
            return Err(MonitorError::WrongOwner);
        }
        granule.owner = None;
        granule.state = GranuleState::ScrubRequired;
        Ok(())
    }

    pub fn complete_scrub(
        &mut self,
        id: GranuleId,
        scrub_succeeded: bool,
    ) -> Result<(), MonitorError> {
        let granule = self.granule_mut(id)?;
        if granule.state != GranuleState::ScrubRequired || granule.owner.is_some() {
            return Err(MonitorError::InvalidGranuleState);
        }
        if !scrub_succeeded {
            return Err(MonitorError::ScrubFailed);
        }
        granule.state = GranuleState::HostOwned;
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

    fn transition_unowned(
        &mut self,
        id: GranuleId,
        from: GranuleState,
        to: GranuleState,
    ) -> Result<(), MonitorError> {
        let granule = self.granule_mut(id)?;
        if granule.state != from || granule.owner.is_some() {
            return Err(MonitorError::InvalidGranuleState);
        }
        granule.state = to;
        Ok(())
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
        monitor.delegate(page).unwrap();
        monitor.assign_private(page, domain).unwrap();
        assert_eq!(
            monitor.start_domain(domain),
            Err(MonitorError::InvalidDomainState)
        );
        monitor.seal_domain(domain, [7; 64]).unwrap();
        monitor.start_domain(domain).unwrap();
        monitor.stop_domain(domain).unwrap();
        monitor.reclaim(page, domain).unwrap();
        assert_eq!(
            monitor.complete_scrub(page, false),
            Err(MonitorError::ScrubFailed)
        );
        assert_eq!(
            monitor.granule_state(page).unwrap(),
            GranuleState::ScrubRequired
        );
        monitor.complete_scrub(page, true).unwrap();
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
        monitor.delegate(page).unwrap();
        monitor.assign_private(page, owner).unwrap();
        assert_eq!(monitor.share(page, stranger), Err(MonitorError::WrongOwner));
        monitor.share(page, owner).unwrap();
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
        monitor.delegate(granule).unwrap();
        monitor.assign_private(granule, domain).unwrap();
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

        monitor.share(granule, domain).unwrap();
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
}
