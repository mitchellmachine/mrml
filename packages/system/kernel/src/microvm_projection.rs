use crate::{
    Capability, CapabilityError, CapabilitySpace, CpuBudgetTable, CpuResourceError,
    IsolationApplicationSpec, IsolationPlacement, IsolationUnavailableReason, MemoryPoolTable,
    MicrovmGuestRam, MicrovmGuestRamError, ObjectId, PreparedMicrovmGuestRam, Rights,
    VcpuReservationId, prepare_microvm_guest_ram_recoverable,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MicrovmProjectionKind {
    InterfaceTransport = 0,
    VirtualGpu = 1,
    Network = 2,
    FilePortal = 3,
    Input = 4,
    Audio = 5,
    Device = 6,
    SecretOperation = 7,
    Ipc = 8,
}

impl MicrovmProjectionKind {
    const fn bit(self) -> u16 {
        1_u16 << self as u8
    }

    const fn unavailable_reason(self) -> IsolationUnavailableReason {
        match self {
            Self::InterfaceTransport => IsolationUnavailableReason::InterfaceTransport,
            Self::VirtualGpu => IsolationUnavailableReason::VirtualGpu,
            Self::Network
            | Self::FilePortal
            | Self::Input
            | Self::Audio
            | Self::Device
            | Self::SecretOperation
            | Self::Ipc => IsolationUnavailableReason::DeviceProjection,
        }
    }
}

const ALL_PROJECTION_BITS: u16 = (1 << 9) - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MicrovmProjectionIdentity {
    domain: ObjectId,
    system_generation: u64,
    policy_generation: u64,
}

impl MicrovmProjectionIdentity {
    pub const fn new(
        domain: ObjectId,
        system_generation: u64,
        policy_generation: u64,
    ) -> Result<Self, MicrovmProjectionError> {
        if domain.0 == 0 || system_generation == 0 || policy_generation == 0 {
            return Err(MicrovmProjectionError::InvalidIdentity);
        }
        Ok(Self {
            domain,
            system_generation,
            policy_generation,
        })
    }

    pub const fn domain(self) -> ObjectId {
        self.domain
    }

    pub const fn system_generation(self) -> u64 {
        self.system_generation
    }

    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MicrovmProjectionRequirements {
    identity: MicrovmProjectionIdentity,
    guest_ram_pages: u64,
    vcpus: u16,
    required: u16,
}

impl MicrovmProjectionRequirements {
    pub const fn new(
        identity: MicrovmProjectionIdentity,
        guest_ram_pages: u64,
        vcpus: u16,
        required: &[MicrovmProjectionKind],
    ) -> Result<Self, MicrovmProjectionError> {
        if guest_ram_pages == 0 || vcpus == 0 {
            return Err(MicrovmProjectionError::InvalidRequirement);
        }
        let mut mask = 0_u16;
        let mut index = 0;
        while index < required.len() {
            let bit = required[index].bit();
            if mask & bit != 0 {
                return Err(MicrovmProjectionError::DuplicateProjection);
            }
            mask |= bit;
            index += 1;
        }
        Ok(Self {
            identity,
            guest_ram_pages,
            vcpus,
            required: mask,
        })
    }

    pub const fn identity(self) -> MicrovmProjectionIdentity {
        self.identity
    }

    pub fn for_application(
        spec: IsolationApplicationSpec,
        guest_ram_pages: u64,
        vcpus: u16,
        required: &[MicrovmProjectionKind],
    ) -> Result<Self, MicrovmProjectionError> {
        if !matches!(spec.placement(), IsolationPlacement::Microvm) {
            return Err(MicrovmProjectionError::UnsupportedPlacement);
        }
        let identity = MicrovmProjectionIdentity::new(
            spec.domain(),
            spec.system_generation(),
            spec.policy_generation(),
        )?;
        Self::new(identity, guest_ram_pages, vcpus, required)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MicrovmProjectionDescriptor {
    kind: MicrovmProjectionKind,
    object: ObjectId,
    generation: u64,
    capability: Capability,
    rights: Rights,
}

impl MicrovmProjectionDescriptor {
    pub const fn new(
        kind: MicrovmProjectionKind,
        object: ObjectId,
        generation: u64,
        capability: Capability,
        rights: Rights,
    ) -> Result<Self, MicrovmProjectionError> {
        if object.0 == 0 || generation == 0 || rights.bits() == 0 {
            return Err(MicrovmProjectionError::InvalidDescriptor);
        }
        Ok(Self {
            kind,
            object,
            generation,
            capability,
            rights,
        })
    }

    pub const fn kind(self) -> MicrovmProjectionKind {
        self.kind
    }

    pub const fn object(self) -> ObjectId {
        self.object
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn capability(self) -> Capability {
        self.capability
    }

    pub const fn rights(self) -> Rights {
        self.rights
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MicrovmProjectionError {
    InvalidIdentity,
    InvalidRequirement,
    InvalidDescriptor,
    UnsupportedPlacement,
    DuplicateProjection,
    MissingProjection(MicrovmProjectionKind),
    UnexpectedProjection(MicrovmProjectionKind),
    GuestRamSizeMismatch,
    VcpuIdentityMismatch,
    VcpuCountMismatch,
    GuestRam(MicrovmGuestRamError),
    Vcpu(CpuResourceError),
    Capability(CapabilityError),
}

#[derive(Debug)]
pub struct MicrovmProjectionFailure<const N: usize> {
    pub reason: IsolationUnavailableReason,
    pub error: MicrovmProjectionError,
    pub guest_ram: MicrovmGuestRam,
    pub vcpus: VcpuReservationId,
    pub descriptors: [Option<MicrovmProjectionDescriptor>; N],
}

/// Linear control-plane result required before microVM backend construction.
/// Descriptor bytes identify only capabilities already checked against the
/// exact objects; they cannot create authority or select a native fallback.
pub struct MicrovmProjectionPlan<const N: usize> {
    requirements: MicrovmProjectionRequirements,
    guest_ram: PreparedMicrovmGuestRam,
    vcpus: VcpuReservationId,
    descriptors: [Option<MicrovmProjectionDescriptor>; N],
}

/// Immutable authority retained while the admitted microVM data plane is live.
///
/// Control planes establish authority; data planes should take the shortest
/// safe path. The descriptors in this state therefore identify only the exact
/// objects and generations admitted before backend construction. Data-plane
/// traffic cannot add descriptors or widen their rights.
pub struct ActiveMicrovmProjectionPlan<const N: usize> {
    requirements: MicrovmProjectionRequirements,
    guest_ram: crate::ActiveMicrovmGuestRam,
    vcpus: VcpuReservationId,
    descriptors: [Option<MicrovmProjectionDescriptor>; N],
}

impl<const N: usize> MicrovmProjectionPlan<N> {
    pub const fn requirements(&self) -> MicrovmProjectionRequirements {
        self.requirements
    }

    pub const fn guest_ram(&self) -> &PreparedMicrovmGuestRam {
        &self.guest_ram
    }

    pub fn guest_ram_mut(&mut self) -> &mut PreparedMicrovmGuestRam {
        &mut self.guest_ram
    }

    pub const fn vcpus(&self) -> VcpuReservationId {
        self.vcpus
    }

    pub fn descriptors(&self) -> impl Iterator<Item = MicrovmProjectionDescriptor> + '_ {
        self.descriptors.iter().flatten().copied()
    }

    pub fn into_parts(
        self,
    ) -> (
        PreparedMicrovmGuestRam,
        VcpuReservationId,
        [Option<MicrovmProjectionDescriptor>; N],
    ) {
        (self.guest_ram, self.vcpus, self.descriptors)
    }

    /// Seals the control-plane plan after native guest construction and opens
    /// its already-authorized data plane. No policy lookup occurs here and the
    /// returned state cannot widen or replace a projected capability.
    pub fn activate_data_plane(
        mut self,
    ) -> Result<ActiveMicrovmProjectionPlan<N>, MicrovmGuestRamError> {
        let pages = self.guest_ram.remaining_pages();
        self.guest_ram.consume_phase(pages)?;
        Ok(ActiveMicrovmProjectionPlan {
            requirements: self.requirements,
            guest_ram: self.guest_ram.complete()?,
            vcpus: self.vcpus,
            descriptors: self.descriptors,
        })
    }
}

impl<const N: usize> ActiveMicrovmProjectionPlan<N> {
    pub const fn requirements(&self) -> MicrovmProjectionRequirements {
        self.requirements
    }

    pub const fn guest_ram(&self) -> &crate::ActiveMicrovmGuestRam {
        &self.guest_ram
    }

    pub const fn vcpus(&self) -> VcpuReservationId {
        self.vcpus
    }

    pub fn descriptors(&self) -> impl Iterator<Item = MicrovmProjectionDescriptor> + '_ {
        self.descriptors.iter().flatten().copied()
    }

    /// Returns quantitative and projected authority only after the native guest
    /// and every backend mapping/queue using them are confirmed destroyed.
    pub unsafe fn retire(
        self,
    ) -> (
        MicrovmGuestRam,
        VcpuReservationId,
        [Option<MicrovmProjectionDescriptor>; N],
    ) {
        (
            unsafe { self.guest_ram.retire() },
            self.vcpus,
            self.descriptors,
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub fn admit_microvm_projection<
    const N: usize,
    const P: usize,
    const O: usize,
    const M: usize,
    const B: usize,
    const R: usize,
    const C: usize,
>(
    requirements: MicrovmProjectionRequirements,
    guest_ram: MicrovmGuestRam,
    guest_ram_capability: Capability,
    memory: &MemoryPoolTable<P, O, M>,
    vcpus: VcpuReservationId,
    cpu_budget_capability: Capability,
    cpu: &CpuBudgetTable<B, R>,
    descriptors: [Option<MicrovmProjectionDescriptor>; N],
    capabilities: &CapabilitySpace<C>,
) -> Result<MicrovmProjectionPlan<N>, MicrovmProjectionFailure<N>> {
    let fail = |reason, error, guest_ram| MicrovmProjectionFailure {
        reason,
        error,
        guest_ram,
        vcpus,
        descriptors,
    };
    if guest_ram.pages() != requirements.guest_ram_pages {
        return Err(fail(
            IsolationUnavailableReason::MemoryBudget,
            MicrovmProjectionError::GuestRamSizeMismatch,
            guest_ram,
        ));
    }
    let vcpu = match cpu.inspect_vcpu_reservation(vcpus, cpu_budget_capability, capabilities) {
        Ok(vcpu) => vcpu,
        Err(error) => {
            return Err(fail(
                IsolationUnavailableReason::VcpuBudget,
                MicrovmProjectionError::Vcpu(error),
                guest_ram,
            ));
        }
    };
    if vcpu.domain != requirements.identity.domain {
        return Err(fail(
            IsolationUnavailableReason::VcpuBudget,
            MicrovmProjectionError::VcpuIdentityMismatch,
            guest_ram,
        ));
    }
    if vcpu.parallelism != requirements.vcpus {
        return Err(fail(
            IsolationUnavailableReason::VcpuBudget,
            MicrovmProjectionError::VcpuCountMismatch,
            guest_ram,
        ));
    }
    let prepared = match prepare_microvm_guest_ram_recoverable(
        memory,
        guest_ram,
        guest_ram_capability,
        capabilities,
    ) {
        Ok(prepared) => prepared,
        Err((error, guest_ram)) => {
            return Err(fail(
                IsolationUnavailableReason::MemoryBudget,
                MicrovmProjectionError::GuestRam(error),
                guest_ram,
            ));
        }
    };

    let mut provided = 0_u16;
    for descriptor in descriptors.iter().flatten().copied() {
        let bit = descriptor.kind.bit();
        if provided & bit != 0 {
            let guest_ram = unsafe { prepared.abort() };
            return Err(fail(
                descriptor.kind.unavailable_reason(),
                MicrovmProjectionError::DuplicateProjection,
                guest_ram,
            ));
        }
        if let Err(error) = capabilities
            .authorize(descriptor.capability, descriptor.rights)
            .and_then(|object| {
                (object == descriptor.object)
                    .then_some(object)
                    .ok_or(CapabilityError::PermissionDenied)
            })
        {
            let guest_ram = unsafe { prepared.abort() };
            return Err(fail(
                descriptor.kind.unavailable_reason(),
                MicrovmProjectionError::Capability(error),
                guest_ram,
            ));
        }
        provided |= bit;
    }
    let missing = requirements.required & !provided & ALL_PROJECTION_BITS;
    if missing != 0 {
        let kind = first_projection_kind(missing);
        let guest_ram = unsafe { prepared.abort() };
        return Err(fail(
            kind.unavailable_reason(),
            MicrovmProjectionError::MissingProjection(kind),
            guest_ram,
        ));
    }
    let unexpected = provided & !requirements.required & ALL_PROJECTION_BITS;
    if unexpected != 0 {
        let kind = first_projection_kind(unexpected);
        let guest_ram = unsafe { prepared.abort() };
        return Err(fail(
            kind.unavailable_reason(),
            MicrovmProjectionError::UnexpectedProjection(kind),
            guest_ram,
        ));
    }

    Ok(MicrovmProjectionPlan {
        requirements,
        guest_ram: prepared,
        vcpus,
        descriptors,
    })
}

const fn first_projection_kind(mask: u16) -> MicrovmProjectionKind {
    match mask.trailing_zeros() {
        0 => MicrovmProjectionKind::InterfaceTransport,
        1 => MicrovmProjectionKind::VirtualGpu,
        2 => MicrovmProjectionKind::Network,
        3 => MicrovmProjectionKind::FilePortal,
        4 => MicrovmProjectionKind::Input,
        5 => MicrovmProjectionKind::Audio,
        6 => MicrovmProjectionKind::Device,
        7 => MicrovmProjectionKind::SecretOperation,
        _ => MicrovmProjectionKind::Ipc,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CpuBudgetId, CpuBudgetSpec, MemoryPoolId, MemoryResourceError, reserve_microvm_guest_ram,
    };

    const DOMAIN: ObjectId = ObjectId(0x9000);
    const POOL_RIGHTS: Rights = Rights::ALLOCATE
        .union(Rights::DELEGATE)
        .union(Rights::CONTROL)
        .union(Rights::MAP)
        .union(Rights::SHARE)
        .union(Rights::PIN)
        .union(Rights::INSPECT);

    struct Fixture {
        capabilities: CapabilitySpace<8>,
        memory: MemoryPoolTable<1, 1>,
        cpu: CpuBudgetTable<1, 1>,
        _pool: MemoryPoolId,
        _budget: CpuBudgetId,
        ram: MicrovmGuestRam,
        ram_capability: Capability,
        vcpus: VcpuReservationId,
        cpu_capability: Capability,
    }

    fn fixture(domain: ObjectId, pages: u64, vcpus: u16) -> Fixture {
        let mut capabilities = CapabilitySpace::<8>::new();
        let mut memory = MemoryPoolTable::<1, 1>::new(90).unwrap();
        let (pool, pool_capability) = memory
            .create_root(pages, 1, 0, POOL_RIGHTS, &mut capabilities)
            .unwrap();
        let (ram, ram_capability) =
            reserve_microvm_guest_ram(&mut memory, pool, pool_capability, pages, &mut capabilities)
                .unwrap();
        let mut cpu = CpuBudgetTable::<1, 1>::new(91).unwrap();
        let spec = CpuBudgetSpec::new(vcpus, 5_000, 10_000, 7, 0xff).unwrap();
        let (budget, cpu_capability) = cpu.create_root(spec, &mut capabilities).unwrap();
        let reservation = cpu
            .reserve_vcpus(budget, cpu_capability, domain, vcpus, &capabilities)
            .unwrap();
        Fixture {
            capabilities,
            memory,
            cpu,
            _pool: pool,
            _budget: budget,
            ram,
            ram_capability,
            vcpus: reservation,
            cpu_capability,
        }
    }

    fn requirements(
        domain: ObjectId,
        pages: u64,
        vcpus: u16,
        kinds: &[MicrovmProjectionKind],
    ) -> MicrovmProjectionRequirements {
        MicrovmProjectionRequirements::new(
            MicrovmProjectionIdentity::new(domain, 7, 11).unwrap(),
            pages,
            vcpus,
            kinds,
        )
        .unwrap()
    }

    fn descriptor(
        fixture: &mut Fixture,
        kind: MicrovmProjectionKind,
        object: ObjectId,
        rights: Rights,
    ) -> MicrovmProjectionDescriptor {
        let capability = fixture.capabilities.insert(object, rights).unwrap();
        MicrovmProjectionDescriptor::new(kind, object, 3, capability, rights).unwrap()
    }

    #[test]
    fn exact_resources_and_capabilities_create_one_linear_plan() {
        let mut fixture = fixture(DOMAIN, 16, 2);
        let interface = descriptor(
            &mut fixture,
            MicrovmProjectionKind::InterfaceTransport,
            ObjectId(0xa001),
            Rights::READ.union(Rights::SIGNAL),
        );
        let gpu = descriptor(
            &mut fixture,
            MicrovmProjectionKind::VirtualGpu,
            ObjectId(0xa002),
            Rights::READ.union(Rights::WRITE),
        );
        let required = requirements(
            DOMAIN,
            16,
            2,
            &[
                MicrovmProjectionKind::InterfaceTransport,
                MicrovmProjectionKind::VirtualGpu,
            ],
        );
        let plan = admit_microvm_projection(
            required,
            fixture.ram,
            fixture.ram_capability,
            &fixture.memory,
            fixture.vcpus,
            fixture.cpu_capability,
            &fixture.cpu,
            [Some(interface), Some(gpu)],
            &fixture.capabilities,
        )
        .unwrap();

        assert_eq!(plan.requirements().identity().domain(), DOMAIN);
        assert_eq!(plan.guest_ram().total_pages(), 16);
        assert_eq!(plan.vcpus(), fixture.vcpus);
        assert_eq!(plan.descriptors().count(), 2);
        let active = plan.activate_data_plane().unwrap();
        assert_eq!(active.guest_ram().pages(), 16);
        let (ram, vcpus, descriptors) = unsafe { active.retire() };
        assert_eq!(ram.pages(), 16);
        assert_eq!(vcpus, fixture.vcpus);
        assert_eq!(descriptors[1], Some(gpu));
    }

    #[test]
    fn missing_required_projection_returns_exact_resources_and_reason() {
        let mut fixture = fixture(DOMAIN, 8, 1);
        let interface = descriptor(
            &mut fixture,
            MicrovmProjectionKind::InterfaceTransport,
            ObjectId(0xa011),
            Rights::SIGNAL,
        );
        let result = admit_microvm_projection(
            requirements(
                DOMAIN,
                8,
                1,
                &[
                    MicrovmProjectionKind::InterfaceTransport,
                    MicrovmProjectionKind::VirtualGpu,
                ],
            ),
            fixture.ram,
            fixture.ram_capability,
            &fixture.memory,
            fixture.vcpus,
            fixture.cpu_capability,
            &fixture.cpu,
            [Some(interface), None],
            &fixture.capabilities,
        );
        let failure = result.err().unwrap();
        assert_eq!(failure.reason, IsolationUnavailableReason::VirtualGpu);
        assert_eq!(
            failure.error,
            MicrovmProjectionError::MissingProjection(MicrovmProjectionKind::VirtualGpu)
        );
        assert_eq!(failure.guest_ram.pages(), 8);
        assert_eq!(failure.vcpus, fixture.vcpus);
    }

    #[test]
    fn stale_or_wrong_projection_authority_fails_before_backend_phases() {
        let mut fixture = fixture(DOMAIN, 8, 1);
        let interface = descriptor(
            &mut fixture,
            MicrovmProjectionKind::InterfaceTransport,
            ObjectId(0xa021),
            Rights::SIGNAL,
        );
        fixture.capabilities.revoke(interface.capability()).unwrap();
        let result = admit_microvm_projection(
            requirements(DOMAIN, 8, 1, &[MicrovmProjectionKind::InterfaceTransport]),
            fixture.ram,
            fixture.ram_capability,
            &fixture.memory,
            fixture.vcpus,
            fixture.cpu_capability,
            &fixture.cpu,
            [Some(interface)],
            &fixture.capabilities,
        );
        let failure = result.err().unwrap();
        assert_eq!(
            failure.reason,
            IsolationUnavailableReason::InterfaceTransport
        );
        assert_eq!(
            failure.error,
            MicrovmProjectionError::Capability(CapabilityError::Invalid)
        );
        assert_eq!(failure.guest_ram.pages(), 8);
    }

    #[test]
    fn ram_and_vcpu_mismatch_are_typed_and_recoverable() {
        let first = fixture(DOMAIN, 8, 1);
        let result = admit_microvm_projection(
            requirements(DOMAIN, 9, 1, &[]),
            first.ram,
            first.ram_capability,
            &first.memory,
            first.vcpus,
            first.cpu_capability,
            &first.cpu,
            [],
            &first.capabilities,
        );
        let failure = result.err().unwrap();
        assert_eq!(failure.reason, IsolationUnavailableReason::MemoryBudget);
        assert_eq!(failure.error, MicrovmProjectionError::GuestRamSizeMismatch);

        let fixture = fixture(DOMAIN, 8, 1);
        let result = admit_microvm_projection(
            requirements(ObjectId(0x9001), 8, 1, &[]),
            fixture.ram,
            fixture.ram_capability,
            &fixture.memory,
            fixture.vcpus,
            fixture.cpu_capability,
            &fixture.cpu,
            [],
            &fixture.capabilities,
        );
        let failure = result.err().unwrap();
        assert_eq!(failure.reason, IsolationUnavailableReason::VcpuBudget);
        assert_eq!(failure.error, MicrovmProjectionError::VcpuIdentityMismatch);
    }

    #[test]
    fn recoverable_ram_validation_returns_exact_reservation() {
        let mut fixture = fixture(DOMAIN, 8, 1);
        fixture.capabilities.revoke(fixture.ram_capability).unwrap();
        let result = admit_microvm_projection(
            requirements(DOMAIN, 8, 1, &[]),
            fixture.ram,
            fixture.ram_capability,
            &fixture.memory,
            fixture.vcpus,
            fixture.cpu_capability,
            &fixture.cpu,
            [],
            &fixture.capabilities,
        );
        let failure = result.err().unwrap();
        assert_eq!(failure.reason, IsolationUnavailableReason::MemoryBudget);
        assert!(matches!(
            failure.error,
            MicrovmProjectionError::GuestRam(MicrovmGuestRamError::Capability(
                MemoryResourceError::Capability(CapabilityError::Invalid)
            ))
        ));
        assert_eq!(failure.guest_ram.pages(), 8);
    }

    #[test]
    fn application_requirements_bind_route_generations_and_reject_native() {
        let microvm = IsolationApplicationSpec::new(
            DOMAIN,
            ObjectId(0x9100),
            3,
            [0x5a; 64],
            7,
            11,
            IsolationPlacement::Microvm,
        )
        .unwrap();
        let requirements = MicrovmProjectionRequirements::for_application(
            microvm,
            8,
            1,
            &[MicrovmProjectionKind::InterfaceTransport],
        )
        .unwrap();
        assert_eq!(requirements.identity().domain(), DOMAIN);
        assert_eq!(requirements.identity().system_generation(), 7);
        assert_eq!(requirements.identity().policy_generation(), 11);

        let native = IsolationApplicationSpec::new(
            DOMAIN,
            ObjectId(0x9100),
            3,
            [0x5a; 64],
            7,
            11,
            IsolationPlacement::NativeProcess,
        )
        .unwrap();
        assert_eq!(
            MicrovmProjectionRequirements::for_application(native, 8, 1, &[]),
            Err(MicrovmProjectionError::UnsupportedPlacement)
        );
    }
}
