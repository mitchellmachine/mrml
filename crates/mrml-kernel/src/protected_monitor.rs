use crate::{
    AUTHORITY_RECEIPT_BYTES, AuthorityReceipt, LaunchRequest, PhysAddr, ProtectedChannelError,
    ProtectionBackend, ProtectionClaims, ProtectionError, ProtectionPolicy, ProtectionReport,
    ProtectionSession, ValidatedBoot,
};
use mrml_crypto::{Sha3_256, hmac_sha256};

#[cfg(target_arch = "x86_64")]
fn cpu_seed() -> Result<[u8; 32], MonitorError> {
    let features = core::arch::x86_64::__cpuid_count(7, 0);
    if features.ebx & (1 << 18) == 0 {
        return Err(MonitorError::HardwareEntropyUnavailable);
    }
    let mut output = [0; 32];
    let (chunks, remainder) = output.as_chunks_mut::<8>();
    debug_assert!(remainder.is_empty());
    for chunk in chunks {
        let mut accepted = None;
        for _ in 0..32 {
            let value: u64;
            let success: u8;
            // SAFETY: support was checked with CPUID. RDSEED touches no memory;
            // carry indicates whether the returned seed is valid.
            unsafe {
                core::arch::asm!(
                    "rdseed {value}",
                    "setc {success}",
                    value = out(reg) value,
                    success = out(reg_byte) success,
                    options(nomem, nostack)
                );
            }
            if success != 0 {
                accepted = Some(value);
                break;
            }
            core::hint::spin_loop();
        }
        let value = accepted.ok_or(MonitorError::HardwareEntropyUnavailable)?;
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    if output == [0; 32] {
        return Err(MonitorError::HardwareEntropyUnavailable);
    }
    Ok(output)
}

#[cfg(not(target_arch = "x86_64"))]
fn cpu_seed() -> Result<[u8; 32], MonitorError> {
    Err(MonitorError::HardwareEntropyUnavailable)
}

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
    HardwareUncertain,
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
    from_owner: Option<DomainId>,
    to_owner: Option<DomainId>,
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

    pub const fn from_owner(self) -> Option<DomainId> {
        self.from_owner
    }

    pub const fn to_owner(self) -> Option<DomainId> {
        self.to_owner
    }
}

/// Privileged adapter that applies one validated transition to EPT and IOMMU
/// Result reported by the privileged hardware transition implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GranuleHardwareOutcome {
    Applied,
    Rejected,
    FailStop,
}

#[cfg(test)]
impl From<bool> for GranuleHardwareOutcome {
    fn from(value: bool) -> Self {
        if value { Self::Applied } else { Self::Rejected }
    }
}

/// Applies ownership transitions to CPU and device translation hardware.
///
/// # Safety
///
/// Implementing this trait asserts hardware ordering and rollback invariants
/// that safe Rust cannot inspect. `Applied` means the exact transition is fully
/// applied and every required CPU and IOMMU translation invalidation completed.
/// Old access must be revoked before new access is granted. `CompleteScrub`
/// must additionally overwrite the complete granule before host access is
/// restored. `Rejected` means no new access remains visible and partial work
/// was rolled back or left more restrictive than the pre-transition state.
/// `FailStop` is mandatory when stale permissive translations or partially
/// granted access may remain.
pub unsafe trait GranuleHardware {
    fn apply_transition(&mut self, transition: GranuleTransition) -> GranuleHardwareOutcome;
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
    DomainHasUncertainGranule,
    HardwareStateUncertain,
    InvalidSecurityVersion,
    InvalidAuthorityKey,
    HardwareEntropyUnavailable,
    UnverifiedBootChain,
    AuthorityKeyAlreadyProvisioned,
    AuthorityKeyNotProvisioned,
    InvalidLaunchRequest,
    WorkloadKeyAlreadyProvisioned,
    WorkloadKeyNotProvisioned,
    SecretReleaseDenied,
    SecretAlreadyConsumed,
    InvalidChallenge,
    Report(ProtectionError),
    Receipt(ProtectedChannelError),
}

#[derive(Clone, Copy)]
struct Domain {
    generation: u32,
    state: DomainState,
    measurement: [u8; 64],
    workload_key: [u8; 32],
    workload_key_provisioned: bool,
    consumed_secret_sequence: u64,
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
    authority_key: [u8; 32],
    authority_key_provisioned: bool,
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
            authority_key: [0; 32],
            authority_key_provisioned: false,
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
            workload_key: [0; 32],
            workload_key_provisioned: false,
            consumed_secret_sequence: 0,
        });
        Ok(DomainId::new(index, generation))
    }

    /// Derives a launch-unique local receipt key internally from validated boot
    /// identity, loader entropy, and fresh post-entry CPU entropy.
    pub fn bootstrap_authority_key(&mut self, boot: &ValidatedBoot) -> Result<(), MonitorError> {
        if !boot.signed_chain_verified() {
            return Err(MonitorError::UnverifiedBootChain);
        }
        let cpu_entropy = cpu_seed()?;
        self.bootstrap_authority_key_inner(boot, cpu_entropy)
    }

    fn bootstrap_authority_key_inner(
        &mut self,
        boot: &ValidatedBoot,
        cpu_entropy: [u8; 32],
    ) -> Result<(), MonitorError> {
        if self.authority_key_provisioned {
            return Err(MonitorError::AuthorityKeyAlreadyProvisioned);
        }
        if self.domains.iter().any(Option::is_some) || self.granules.iter().any(Option::is_some) {
            return Err(MonitorError::InvalidDomainState);
        }
        if cpu_entropy == [0; 32] {
            return Err(MonitorError::HardwareEntropyUnavailable);
        }
        let mut digest = Sha3_256::new();
        digest.update(b"MRML-BARE-METAL-AUTHORITY-KEY-v1\0");
        digest.update(boot.entropy());
        digest.update(boot.image_measurement());
        digest.update(&boot.image_version().to_le_bytes());
        digest.update(&cpu_entropy);
        self.authority_key = digest.finalize();
        if self.authority_key == [0; 32] {
            return Err(MonitorError::InvalidAuthorityKey);
        }
        self.authority_key_provisioned = true;
        Ok(())
    }

    #[cfg(test)]
    fn bootstrap_authority_key_for_test(
        &mut self,
        boot: &ValidatedBoot,
        cpu_entropy: [u8; 32],
    ) -> Result<(), MonitorError> {
        self.bootstrap_authority_key_inner(boot, cpu_entropy)
    }

    pub fn seal_domain(&mut self, id: DomainId, measurement: [u8; 64]) -> Result<(), MonitorError> {
        if measurement == [0; 64] {
            return Err(MonitorError::InvalidDomainState);
        }
        if self.domain_has_pending_transition(id) {
            return Err(MonitorError::DomainHasPendingTransition);
        }
        if self.domain_has_uncertain_granule(id) {
            return Err(MonitorError::DomainHasUncertainGranule);
        }
        let domain = self.domain_mut(id)?;
        if domain.state != DomainState::Building {
            return Err(MonitorError::InvalidDomainState);
        }
        domain.measurement = measurement;
        domain.state = DomainState::Measured;
        Ok(())
    }

    /// Generates a launch-local workload key inside the monitor after the
    /// domain measurement and private ownership state are fixed. The key is
    /// never returned through the public API and is not persistent sealing.
    pub fn generate_domain_workload_key(&mut self, id: DomainId) -> Result<(), MonitorError> {
        let key = cpu_seed()?;
        self.install_domain_workload_key(id, key)
    }

    fn install_domain_workload_key(
        &mut self,
        id: DomainId,
        entropy: [u8; 32],
    ) -> Result<(), MonitorError> {
        if !self.authority_key_provisioned {
            return Err(MonitorError::AuthorityKeyNotProvisioned);
        }
        if entropy == [0; 32] {
            return Err(MonitorError::HardwareEntropyUnavailable);
        }
        if self.domain_has_pending_transition(id) {
            return Err(MonitorError::DomainHasPendingTransition);
        }
        if self.domain_has_uncertain_granule(id) {
            return Err(MonitorError::DomainHasUncertainGranule);
        }
        let has_private = self
            .granules
            .iter()
            .flatten()
            .any(|granule| granule.owner == Some(id) && granule.state == GranuleState::Private);
        let has_shared = self
            .granules
            .iter()
            .flatten()
            .any(|granule| granule.owner == Some(id) && granule.state == GranuleState::Shared);
        if !has_private || has_shared {
            return Err(MonitorError::SecretReleaseDenied);
        }
        let domain = *self.domain(id)?;
        if domain.state != DomainState::Measured {
            return Err(MonitorError::InvalidDomainState);
        }
        if domain.workload_key_provisioned {
            return Err(MonitorError::WorkloadKeyAlreadyProvisioned);
        }
        let mut digest = Sha3_256::new();
        digest.update(b"MRML-BARE-METAL-WORKLOAD-KEY-v1\0");
        digest.update(&self.authority_key);
        digest.update(&id.token().to_le_bytes());
        digest.update(&domain.measurement);
        digest.update(&entropy);
        let key = digest.finalize();
        if key == [0; 32] {
            return Err(MonitorError::InvalidAuthorityKey);
        }
        let domain = self.domain_mut(id)?;
        domain.workload_key = key;
        domain.workload_key_provisioned = true;
        Ok(())
    }

    #[cfg(test)]
    fn generate_domain_workload_key_for_test(
        &mut self,
        id: DomainId,
        key: [u8; 32],
    ) -> Result<(), MonitorError> {
        self.install_domain_workload_key(id, key)
    }

    pub fn start_domain(&mut self, id: DomainId) -> Result<(), MonitorError> {
        if self.domain_has_pending_transition(id) {
            return Err(MonitorError::DomainHasPendingTransition);
        }
        if self.domain_has_uncertain_granule(id) {
            return Err(MonitorError::DomainHasUncertainGranule);
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
        if self.domain_has_uncertain_granule(id) {
            return Err(MonitorError::DomainHasUncertainGranule);
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
        if self.domain_has_uncertain_granule(id) {
            return Err(MonitorError::DomainHasUncertainGranule);
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
        if let Some(domain) = self.domains[id.index()].as_mut() {
            for byte in &mut domain.workload_key {
                // SAFETY: the pointer is derived from an exclusive reference;
                // volatile writes prevent elision of secret erasure.
                unsafe { core::ptr::write_volatile(byte, 0) };
            }
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

    pub fn execute_transition<H: GranuleHardware>(
        &mut self,
        transition: GranuleTransition,
        hardware: &mut H,
    ) -> Result<(), MonitorError> {
        self.validate_transition(transition)?;
        let outcome = hardware.apply_transition(transition);
        self.complete_transition(transition, outcome)
    }

    fn complete_transition<O: Into<GranuleHardwareOutcome>>(
        &mut self,
        transition: GranuleTransition,
        outcome: O,
    ) -> Result<(), MonitorError> {
        let outcome = outcome.into();
        let pending = self.validate_transition(transition)?;
        if outcome == GranuleHardwareOutcome::FailStop {
            let granule = self.granule_mut(transition.granule)?;
            granule.pending = None;
            granule.state = GranuleState::HardwareUncertain;
            granule.owner = transition.to_owner.or(transition.from_owner);
            return Err(MonitorError::HardwareStateUncertain);
        }
        if outcome == GranuleHardwareOutcome::Rejected {
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
        let sequence = self
            .report_sequence
            .checked_add(1)
            .ok_or(MonitorError::SequenceExhausted)?;
        let report = self.build_report(id, nonce, sequence)?;
        self.report_sequence = sequence;
        Ok(report)
    }

    fn build_report(
        &self,
        id: DomainId,
        nonce: [u8; 32],
        sequence: u64,
    ) -> Result<ProtectionReport, MonitorError> {
        if self.domain_has_pending_transition(id) {
            return Err(MonitorError::DomainHasPendingTransition);
        }
        if self.domain_has_uncertain_granule(id) {
            return Err(MonitorError::DomainHasUncertainGranule);
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
            if domain.workload_key_provisioned {
                claims = claims.union(ProtectionClaims::SEALED_KEYS);
            }
        }
        ProtectionReport::new(
            ProtectionBackend::BareMetalMonitor,
            claims,
            false,
            self.security_version,
            sequence,
            domain.measurement,
            nonce,
        )
        .map_err(MonitorError::Report)
    }

    /// Authenticates a decision derived from the current live domain table and
    /// binds it to the caller's exact canonical request and approved policy.
    pub fn issue_authenticated_receipt(
        &mut self,
        id: DomainId,
        request: LaunchRequest,
        policy: ProtectionPolicy,
    ) -> Result<[u8; AUTHORITY_RECEIPT_BYTES], MonitorError> {
        if !self.authority_key_provisioned {
            return Err(MonitorError::AuthorityKeyNotProvisioned);
        }
        let next_sequence = self
            .report_sequence
            .checked_add(1)
            .ok_or(MonitorError::SequenceExhausted)?;
        let domain = self.domain(id)?;
        if request.sequence() != next_sequence
            || request.image_measurement() != domain.measurement
            || request.policy_measurement() != policy.commitment()
        {
            return Err(MonitorError::InvalidLaunchRequest);
        }
        let report = self.build_report(id, request.nonce(), next_sequence)?;
        let mut session = ProtectionSession::new(request.nonce()).map_err(MonitorError::Report)?;
        session
            .admit(report, policy)
            .map_err(MonitorError::Report)?;
        let receipt = AuthorityReceipt::seal(&self.authority_key, request, report)
            .map_err(MonitorError::Receipt)?;
        self.report_sequence = next_sequence;
        Ok(receipt)
    }

    /// Authenticates and admits the exact authority receipt, revalidates the
    /// live domain state, and consumes that sequence once before using the
    /// monitor-custodied workload key. Only the HMAC result leaves the monitor.
    pub fn consume_workload_secret(
        &mut self,
        id: DomainId,
        request: LaunchRequest,
        receipt: &[u8],
        policy: ProtectionPolicy,
        challenge: [u8; 32],
    ) -> Result<[u8; 32], MonitorError> {
        if challenge == [0; 32] {
            return Err(MonitorError::InvalidChallenge);
        }
        if !self.authority_key_provisioned {
            return Err(MonitorError::AuthorityKeyNotProvisioned);
        }
        let domain = *self.domain(id)?;
        if !domain.workload_key_provisioned {
            return Err(MonitorError::WorkloadKeyNotProvisioned);
        }
        if request.image_measurement() != domain.measurement
            || request.policy_measurement() != policy.commitment()
        {
            return Err(MonitorError::InvalidLaunchRequest);
        }
        let mut session = ProtectionSession::new(request.nonce()).map_err(MonitorError::Report)?;
        let admission = AuthorityReceipt::verify_and_admit(
            &self.authority_key,
            request,
            receipt,
            policy.commitment(),
            &mut session,
            policy,
        )
        .map_err(MonitorError::Receipt)?;
        if !admission.mode().is_bare_metal_vmx_root() || !admission.permits_secret_release() {
            return Err(MonitorError::SecretReleaseDenied);
        }
        let current = self.build_report(id, request.nonce(), request.sequence())?;
        if current.claims() != admission.claims()
            || current.measurement() != admission.measurement()
            || current.security_version() != admission.security_version()
            || current.debug_allowed()
        {
            return Err(MonitorError::SecretReleaseDenied);
        }
        let domain = self.domain_mut(id)?;
        if request.sequence() <= domain.consumed_secret_sequence {
            return Err(MonitorError::SecretAlreadyConsumed);
        }
        domain.consumed_secret_sequence = request.sequence();
        Ok(hmac_sha256(
            &domain.workload_key,
            &[
                b"MRML-BARE-METAL-WORKLOAD-SECRET-v1\0",
                &admission.request_digest(),
                &admission.policy_measurement(),
                &challenge,
            ],
        ))
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
            from_owner,
            to_owner,
        })
    }

    fn validate_transition(
        &self,
        transition: GranuleTransition,
    ) -> Result<PendingTransition, MonitorError> {
        let granule = self.granule(transition.granule)?;
        let pending = granule.pending.ok_or(MonitorError::StaleTransition)?;
        let expected = GranuleTransition {
            granule: transition.granule,
            sequence: pending.sequence,
            kind: pending.kind,
            physical: granule.physical,
            from_owner: pending.from_owner,
            to_owner: pending.to_owner,
        };
        if transition != expected {
            return Err(MonitorError::StaleTransition);
        }
        Ok(pending)
    }

    fn domain_has_pending_transition(&self, id: DomainId) -> bool {
        self.granules.iter().flatten().any(|granule| {
            granule.pending.is_some_and(|pending| {
                pending.from_owner == Some(id) || pending.to_owner == Some(id)
            })
        })
    }

    fn domain_has_uncertain_granule(&self, id: DomainId) -> bool {
        self.granules.iter().flatten().any(|granule| {
            granule.owner == Some(id) && granule.state == GranuleState::HardwareUncertain
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
    use crate::{BootEvidence, BootPolicy};

    fn validated_boot(entropy: [u8; 32], measurement: [u8; 64]) -> ValidatedBoot {
        let evidence = BootEvidence::new(entropy, measurement, 1, true, true, true).unwrap();
        BootPolicy::production(1).admit(&evidence).unwrap()
    }

    struct RecordingHardware {
        outcome: GranuleHardwareOutcome,
        calls: usize,
        last: Option<GranuleTransition>,
    }

    // SAFETY: this deterministic test adapter models an atomic hardware
    // transaction and records no partial state when configured to fail.
    unsafe impl GranuleHardware for RecordingHardware {
        fn apply_transition(&mut self, transition: GranuleTransition) -> GranuleHardwareOutcome {
            self.calls += 1;
            self.last = Some(transition);
            self.outcome
        }
    }

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
    fn monitor_receipt_authenticates_exact_live_domain_mode() {
        const MEASUREMENT: [u8; 64] = [0xb1; 64];
        const NONCE: [u8; 32] = [0xb2; 32];
        let mut monitor = ProtectedMonitor::<1, 1>::with_security_version(9).unwrap();
        monitor
            .bootstrap_authority_key_for_test(&validated_boot([0x41; 32], [0x42; 64]), [0x43; 32])
            .unwrap();
        let key = monitor.authority_key;
        let domain = monitor.create_domain().unwrap();
        let granule = monitor
            .register_granule(PhysAddr::new(0x70_0000).unwrap())
            .unwrap();
        let transition = monitor.prepare_delegate(granule).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        let transition = monitor.prepare_assign_private(granule, domain).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        monitor.seal_domain(domain, MEASUREMENT).unwrap();
        let claims = ProtectionClaims::MEASURED.union(ProtectionClaims::DOMAIN_ISOLATION);
        let policy = ProtectionPolicy::new(
            ProtectionBackend::BareMetalMonitor,
            claims,
            false,
            9,
            MEASUREMENT,
        );
        let request = LaunchRequest::new(1, NONCE, MEASUREMENT, policy.commitment()).unwrap();
        let receipt = monitor
            .issue_authenticated_receipt(domain, request, policy)
            .unwrap();
        let mut session = ProtectionSession::new(NONCE).unwrap();
        let admitted = AuthorityReceipt::verify_and_admit(
            &key,
            request,
            &receipt,
            policy.commitment(),
            &mut session,
            policy,
        )
        .unwrap();
        assert!(admitted.mode().is_bare_metal_vmx_root());
        assert_eq!(admitted.claims(), claims);
        assert!(!admitted.permits_secret_release());
    }

    #[test]
    fn monitor_releases_only_from_exact_authenticated_one_use_receipt() {
        const MEASUREMENT: [u8; 64] = [0xd1; 64];
        const NONCE: [u8; 32] = [0xd2; 32];
        const CHALLENGE: [u8; 32] = [0xd3; 32];
        const WORKLOAD_ENTROPY: [u8; 32] = [0xd4; 32];
        let mut monitor = ProtectedMonitor::<1, 1>::with_security_version(11).unwrap();
        monitor
            .bootstrap_authority_key_for_test(&validated_boot([0x71; 32], [0x72; 64]), [0x73; 32])
            .unwrap();
        let domain = monitor.create_domain().unwrap();
        let granule = monitor
            .register_granule(PhysAddr::new(0x80_0000).unwrap())
            .unwrap();
        let transition = monitor.prepare_delegate(granule).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        let transition = monitor.prepare_assign_private(granule, domain).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        monitor.seal_domain(domain, MEASUREMENT).unwrap();
        monitor
            .generate_domain_workload_key_for_test(domain, WORKLOAD_ENTROPY)
            .unwrap();
        let claims = ProtectionClaims::MEASURED
            .union(ProtectionClaims::DOMAIN_ISOLATION)
            .union(ProtectionClaims::SEALED_KEYS);
        let policy = ProtectionPolicy::new(
            ProtectionBackend::BareMetalMonitor,
            claims,
            false,
            11,
            MEASUREMENT,
        );
        let request = LaunchRequest::new(1, NONCE, MEASUREMENT, policy.commitment()).unwrap();
        let receipt = monitor
            .issue_authenticated_receipt(domain, request, policy)
            .unwrap();
        let mut key_digest = Sha3_256::new();
        key_digest.update(b"MRML-BARE-METAL-WORKLOAD-KEY-v1\0");
        key_digest.update(&monitor.authority_key);
        key_digest.update(&domain.token().to_le_bytes());
        key_digest.update(&MEASUREMENT);
        key_digest.update(&WORKLOAD_ENTROPY);
        let expected = hmac_sha256(
            &key_digest.finalize(),
            &[
                b"MRML-BARE-METAL-WORKLOAD-SECRET-v1\0",
                &mrml_crypto::Sha3_512::digest(&request.encode()),
                &policy.commitment(),
                &CHALLENGE,
            ],
        );
        assert_eq!(
            monitor
                .consume_workload_secret(domain, request, &receipt, policy, CHALLENGE)
                .unwrap(),
            expected
        );
        assert_eq!(
            monitor.consume_workload_secret(domain, request, &receipt, policy, CHALLENGE),
            Err(MonitorError::SecretAlreadyConsumed)
        );
    }

    #[test]
    fn secret_release_rejects_tampering_substitution_and_live_downgrade() {
        const MEASUREMENT: [u8; 64] = [0xe1; 64];
        let mut monitor = ProtectedMonitor::<1, 1>::new();
        monitor
            .bootstrap_authority_key_for_test(&validated_boot([0x81; 32], [0x82; 64]), [0x83; 32])
            .unwrap();
        let domain = monitor.create_domain().unwrap();
        assert_eq!(
            monitor.generate_domain_workload_key_for_test(domain, [0x84; 32]),
            Err(MonitorError::SecretReleaseDenied)
        );
        let granule = monitor
            .register_granule(PhysAddr::new(0x90_0000).unwrap())
            .unwrap();
        let transition = monitor.prepare_delegate(granule).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        let transition = monitor.prepare_assign_private(granule, domain).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        monitor.seal_domain(domain, MEASUREMENT).unwrap();
        monitor
            .generate_domain_workload_key_for_test(domain, [0x84; 32])
            .unwrap();
        let claims = ProtectionClaims::MEASURED
            .union(ProtectionClaims::DOMAIN_ISOLATION)
            .union(ProtectionClaims::SEALED_KEYS);
        let policy = ProtectionPolicy::new(
            ProtectionBackend::BareMetalMonitor,
            claims,
            false,
            1,
            MEASUREMENT,
        );
        let request = LaunchRequest::new(1, [0xe2; 32], MEASUREMENT, policy.commitment()).unwrap();
        let receipt = monitor
            .issue_authenticated_receipt(domain, request, policy)
            .unwrap();
        let mut tampered = receipt;
        tampered[AUTHORITY_RECEIPT_BYTES - 1] ^= 1;
        assert_eq!(
            monitor.consume_workload_secret(domain, request, &tampered, policy, [0xe3; 32]),
            Err(MonitorError::Receipt(ProtectedChannelError::InvalidTag))
        );
        let substituted = ProtectionPolicy::new(
            ProtectionBackend::BareMetalMonitor,
            claims,
            false,
            2,
            MEASUREMENT,
        );
        assert_eq!(
            monitor.consume_workload_secret(domain, request, &receipt, substituted, [0xe3; 32]),
            Err(MonitorError::InvalidLaunchRequest)
        );
        assert_eq!(
            monitor.consume_workload_secret(domain, request, &receipt, policy, [0; 32]),
            Err(MonitorError::InvalidChallenge)
        );
        let transition = monitor.prepare_share(granule, domain).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        assert_eq!(
            monitor.consume_workload_secret(domain, request, &receipt, policy, [0xe3; 32]),
            Err(MonitorError::SecretReleaseDenied)
        );
    }

    #[test]
    fn monitor_authority_rejects_late_keys_and_request_or_policy_substitution() {
        const MEASUREMENT: [u8; 64] = [0xc1; 64];
        let boot = validated_boot([0x51; 32], [0x52; 64]);
        let mut monitor = ProtectedMonitor::<1, 0>::new();
        assert_eq!(
            monitor.bootstrap_authority_key_for_test(&boot, [0; 32]),
            Err(MonitorError::HardwareEntropyUnavailable)
        );
        let domain = monitor.create_domain().unwrap();
        assert_eq!(
            monitor.bootstrap_authority_key_for_test(&boot, [0x53; 32]),
            Err(MonitorError::InvalidDomainState)
        );
        monitor.seal_domain(domain, MEASUREMENT).unwrap();
        let policy = ProtectionPolicy::new(
            ProtectionBackend::BareMetalMonitor,
            ProtectionClaims::MEASURED,
            false,
            1,
            MEASUREMENT,
        );
        let request = LaunchRequest::new(1, [0xc2; 32], MEASUREMENT, policy.commitment()).unwrap();
        assert_eq!(
            monitor.issue_authenticated_receipt(domain, request, policy),
            Err(MonitorError::AuthorityKeyNotProvisioned)
        );

        let mut monitor = ProtectedMonitor::<1, 0>::new();
        monitor
            .bootstrap_authority_key_for_test(&boot, [0x53; 32])
            .unwrap();
        assert_eq!(
            monitor.bootstrap_authority_key_for_test(&boot, [0x54; 32]),
            Err(MonitorError::AuthorityKeyAlreadyProvisioned)
        );
        let domain = monitor.create_domain().unwrap();
        monitor.seal_domain(domain, MEASUREMENT).unwrap();
        let wrong_sequence =
            LaunchRequest::new(2, [0xc2; 32], MEASUREMENT, policy.commitment()).unwrap();
        assert_eq!(
            monitor.issue_authenticated_receipt(domain, wrong_sequence, policy),
            Err(MonitorError::InvalidLaunchRequest)
        );
        let wrong_image =
            LaunchRequest::new(1, [0xc2; 32], [0xc3; 64], policy.commitment()).unwrap();
        assert_eq!(
            monitor.issue_authenticated_receipt(domain, wrong_image, policy),
            Err(MonitorError::InvalidLaunchRequest)
        );
        let substituted_policy = ProtectionPolicy::new(
            ProtectionBackend::BareMetalMonitor,
            ProtectionClaims::MEASURED,
            false,
            2,
            MEASUREMENT,
        );
        assert_eq!(
            monitor.issue_authenticated_receipt(domain, request, substituted_policy),
            Err(MonitorError::InvalidLaunchRequest)
        );
        let impossible_policy = ProtectionPolicy::new(
            ProtectionBackend::BareMetalMonitor,
            ProtectionClaims::MEASURED.union(ProtectionClaims::DOMAIN_ISOLATION),
            false,
            1,
            MEASUREMENT,
        );
        let impossible_request =
            LaunchRequest::new(1, [0xc2; 32], MEASUREMENT, impossible_policy.commitment()).unwrap();
        assert_eq!(
            monitor.issue_authenticated_receipt(domain, impossible_request, impossible_policy),
            Err(MonitorError::Report(
                ProtectionError::InsufficientProtection
            ))
        );
        assert!(
            monitor
                .issue_authenticated_receipt(domain, request, policy)
                .is_ok()
        );
        monitor.destroy_domain(domain).unwrap();
        let stale_request =
            LaunchRequest::new(2, [0xc4; 32], MEASUREMENT, policy.commitment()).unwrap();
        assert_eq!(
            monitor.issue_authenticated_receipt(domain, stale_request, policy),
            Err(MonitorError::StaleDomain)
        );
    }

    #[test]
    fn monitor_authority_key_binds_boot_identity_and_fresh_cpu_entropy() {
        let claim_only_boot = validated_boot([0x61; 32], [0x62; 64]);
        assert_eq!(
            ProtectedMonitor::<0, 0>::new().bootstrap_authority_key(&claim_only_boot),
            Err(MonitorError::UnverifiedBootChain)
        );
        let mut first = ProtectedMonitor::<0, 0>::new();
        first
            .bootstrap_authority_key_for_test(&validated_boot([0x61; 32], [0x62; 64]), [0x63; 32])
            .unwrap();
        let mut changed_boot = ProtectedMonitor::<0, 0>::new();
        changed_boot
            .bootstrap_authority_key_for_test(&validated_boot([0x61; 32], [0x64; 64]), [0x63; 32])
            .unwrap();
        let mut changed_cpu_seed = ProtectedMonitor::<0, 0>::new();
        changed_cpu_seed
            .bootstrap_authority_key_for_test(&validated_boot([0x61; 32], [0x62; 64]), [0x65; 32])
            .unwrap();
        assert_ne!(first.authority_key, changed_boot.authority_key);
        assert_ne!(first.authority_key, changed_cpu_seed.authority_key);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn cpu_seed_matches_advertised_rdseed_capability() {
        let supported = core::arch::x86_64::__cpuid_count(7, 0).ebx & (1 << 18) != 0;
        let seed = cpu_seed();
        if supported {
            assert!(seed.is_ok());
            assert_ne!(seed.unwrap(), [0; 32]);
        } else {
            assert_eq!(seed, Err(MonitorError::HardwareEntropyUnavailable));
        }
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

    #[test]
    fn public_execution_validates_before_dispatching_exact_ticket() {
        let mut monitor = ProtectedMonitor::<1, 1>::new();
        let granule = monitor
            .register_granule(PhysAddr::new(0x80_0000).unwrap())
            .unwrap();
        let transition = monitor.prepare_delegate(granule).unwrap();
        assert_eq!(transition.from_owner(), None);
        assert_eq!(transition.to_owner(), None);
        let mut hardware = RecordingHardware {
            outcome: GranuleHardwareOutcome::Applied,
            calls: 0,
            last: None,
        };
        let forged = GranuleTransition {
            physical: PhysAddr::new(0x81_0000).unwrap(),
            ..transition
        };
        assert_eq!(
            monitor.execute_transition(forged, &mut hardware),
            Err(MonitorError::StaleTransition)
        );
        assert_eq!(hardware.calls, 0);
        monitor
            .execute_transition(transition, &mut hardware)
            .unwrap();
        assert_eq!(hardware.calls, 1);
        assert_eq!(hardware.last, Some(transition));
        assert_eq!(
            monitor.execute_transition(transition, &mut hardware),
            Err(MonitorError::StaleTransition)
        );
        assert_eq!(hardware.calls, 1);
    }

    #[test]
    fn adapter_failure_is_consumed_without_policy_commit() {
        let mut monitor = ProtectedMonitor::<1, 1>::new();
        let granule = monitor
            .register_granule(PhysAddr::new(0x90_0000).unwrap())
            .unwrap();
        let transition = monitor.prepare_delegate(granule).unwrap();
        let mut hardware = RecordingHardware {
            outcome: GranuleHardwareOutcome::Rejected,
            calls: 0,
            last: None,
        };
        assert_eq!(
            monitor.execute_transition(transition, &mut hardware),
            Err(MonitorError::HardwareTransitionFailed)
        );
        assert_eq!(hardware.calls, 1);
        assert_eq!(monitor.granule_state(granule), Ok(GranuleState::HostOwned));
        assert_eq!(
            monitor.execute_transition(transition, &mut hardware),
            Err(MonitorError::StaleTransition)
        );
        assert_eq!(hardware.calls, 1);
    }

    #[test]
    fn uncertain_hardware_state_quarantines_granule_and_domain() {
        let mut monitor = ProtectedMonitor::<1, 1>::new();
        let domain = monitor.create_domain().unwrap();
        let granule = monitor
            .register_granule(PhysAddr::new(0xa0_0000).unwrap())
            .unwrap();
        let transition = monitor.prepare_delegate(granule).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        let transition = monitor.prepare_assign_private(granule, domain).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        monitor.seal_domain(domain, [0xc1; 64]).unwrap();
        let transition = monitor.prepare_share(granule, domain).unwrap();
        let mut hardware = RecordingHardware {
            outcome: GranuleHardwareOutcome::FailStop,
            calls: 0,
            last: None,
        };
        assert_eq!(
            monitor.execute_transition(transition, &mut hardware),
            Err(MonitorError::HardwareStateUncertain)
        );
        assert_eq!(
            monitor.granule_state(granule),
            Ok(GranuleState::HardwareUncertain)
        );
        assert_eq!(
            monitor.start_domain(domain),
            Err(MonitorError::DomainHasUncertainGranule)
        );
        assert_eq!(
            monitor.issue_report(domain, [6; 32]),
            Err(MonitorError::DomainHasUncertainGranule)
        );
        assert_eq!(
            monitor.prepare_reclaim(granule, domain),
            Err(MonitorError::InvalidGranuleState)
        );
    }

    #[test]
    fn uncertain_assignment_quarantines_the_target_domain() {
        let mut monitor = ProtectedMonitor::<1, 1>::new();
        let domain = monitor.create_domain().unwrap();
        let granule = monitor
            .register_granule(PhysAddr::new(0xb0_0000).unwrap())
            .unwrap();
        let transition = monitor.prepare_delegate(granule).unwrap();
        monitor.complete_transition(transition, true).unwrap();
        let transition = monitor.prepare_assign_private(granule, domain).unwrap();
        let mut hardware = RecordingHardware {
            outcome: GranuleHardwareOutcome::FailStop,
            calls: 0,
            last: None,
        };
        assert_eq!(
            monitor.execute_transition(transition, &mut hardware),
            Err(MonitorError::HardwareStateUncertain)
        );
        assert_eq!(
            monitor.seal_domain(domain, [0xc2; 64]),
            Err(MonitorError::DomainHasUncertainGranule)
        );
    }
}
