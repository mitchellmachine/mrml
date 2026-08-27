use crate::{
    Capability, CapabilitySpace, MAX_PE_SECTIONS, MemoryBackingKind, MemoryMappingId,
    MemoryObjectId, MemoryPoolId, MemoryPoolTable, MemoryResourceError, PAGE_SIZE, PeError,
    PeImage, PeLoadRegion, Rights,
};

const COMPONENT_EXECUTABLE_RIGHTS: Rights = Rights::READ
    .union(Rights::EXECUTE)
    .union(Rights::MAP)
    .union(Rights::SHARE)
    .union(Rights::PIN)
    .union(Rights::INSPECT)
    .union(Rights::CONTROL);

const MICROVM_GUEST_RAM_RIGHTS: Rights = Rights::READ
    .union(Rights::WRITE)
    .union(Rights::MAP)
    .union(Rights::PIN)
    .union(Rights::INSPECT)
    .union(Rights::CONTROL);

const MICROVM_CONTROL_MEMORY_RIGHTS: Rights = Rights::READ
    .union(Rights::WRITE)
    .union(Rights::INSPECT)
    .union(Rights::CONTROL);

const MICROVM_PAGE_PROJECTION_RIGHTS: Rights = Rights::READ
    .union(Rights::WRITE)
    .union(Rights::MAP)
    .union(Rights::INSPECT)
    .union(Rights::CONTROL);

const MICROVM_PEER_PAGE_RIGHTS: Rights = MICROVM_PAGE_PROJECTION_RIGHTS.union(Rights::SHARE);

const MICROVM_PEER_TARGET_RIGHTS: Rights = Rights::MAP
    .union(Rights::INSPECT)
    .union(Rights::CONTROL);

pub const MAX_COMPONENT_IMAGE_REGIONS: usize = MAX_PE_SECTIONS + 1;

/// Accounted immutable code pages for one independently serviced component.
///
/// This is a memory-resource identity, not a package or interface identity and
/// not authority. The accompanying capability is required for every mapping
/// operation. It deliberately carries no write authority, so admitted code can
/// only be shared as read/execute pages after a privileged loader has populated
/// and sealed its backing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentExecutablePages {
    object: MemoryObjectId,
    pages: u64,
}

/// Host-derived RAM commitment for one microVM generation.
///
/// Guest-physical addresses remain data. This object and its capability carry
/// the host commitment that a VMM adapter must consume before allocating or
/// mapping the corresponding native backing. It deliberately grants neither
/// execute, share, DMA, delegation, nor device authority.
#[derive(Debug, Eq, PartialEq)]
pub struct MicrovmGuestRam {
    object: MemoryObjectId,
    pages: u64,
}

/// Exact MRML-owned VMM control-structure storage for one guest generation.
/// This does not claim or authorize opaque host-hypervisor internal memory.
#[derive(Debug, Eq, PartialEq)]
pub struct MicrovmControlMemory {
    object: MemoryObjectId,
    pages: u64,
}

impl MicrovmControlMemory {
    pub const fn object(&self) -> MemoryObjectId {
        self.object
    }

    pub const fn pages(&self) -> u64 {
        self.pages
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MicrovmPageProjectionKind {
    SharedData,
    Resource,
}

/// One exact host-owned page and its bounded projection into a microVM.
///
/// The kind and guest virtual page identify the admitted projection; neither
/// value authorizes a host object or a mapping. The accompanying object and
/// target capabilities remain independently required for lifecycle operations.
#[derive(Debug, Eq, PartialEq)]
pub struct MicrovmPageProjection {
    object: MemoryObjectId,
    mapping: MemoryMappingId,
    kind: MicrovmPageProjectionKind,
    virtual_page: u64,
}

impl MicrovmPageProjection {
    pub const fn object(&self) -> MemoryObjectId {
        self.object
    }

    pub const fn mapping(&self) -> MemoryMappingId {
        self.mapping
    }

    pub const fn kind(&self) -> MicrovmPageProjectionKind {
        self.kind
    }

    pub const fn virtual_page(&self) -> u64 {
        self.virtual_page
    }
}

/// One exact shared page projected into two distinct microVM address spaces.
///
/// The retained target capabilities bind both object identity and capability
/// generation. Domain names, guest addresses and payload bytes remain data and
/// cannot substitute either target authority. Both mappings are writable and
/// non-executable; interface policy must separately authorize what may be sent.
#[derive(Debug, Eq, PartialEq)]
pub struct MicrovmPeerPageProjection {
    object: MemoryObjectId,
    first_mapping: MemoryMappingId,
    second_mapping: MemoryMappingId,
    first_target: crate::ObjectId,
    second_target: crate::ObjectId,
    first_target_capability: Capability,
    second_target_capability: Capability,
    first_virtual_page: u64,
    second_virtual_page: u64,
}

impl MicrovmPeerPageProjection {
    pub const fn object(&self) -> MemoryObjectId {
        self.object
    }

    pub const fn first_mapping(&self) -> MemoryMappingId {
        self.first_mapping
    }

    pub const fn second_mapping(&self) -> MemoryMappingId {
        self.second_mapping
    }

    pub const fn first_target(&self) -> crate::ObjectId {
        self.first_target
    }

    pub const fn second_target(&self) -> crate::ObjectId {
        self.second_target
    }

    pub const fn first_virtual_page(&self) -> u64 {
        self.first_virtual_page
    }

    pub const fn second_virtual_page(&self) -> u64 {
        self.second_virtual_page
    }

    /// Revalidates both exact target capability generations before a backend
    /// installs, removes or otherwise acts on either native mapping.
    pub fn validate_targets<const C: usize>(
        &self,
        first: Capability,
        second: Capability,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<(crate::ObjectId, crate::ObjectId), MemoryResourceError> {
        if first != self.first_target_capability || second != self.second_target_capability {
            return Err(MemoryResourceError::InvalidMapping);
        }
        let first_target = capabilities.authorize_exact(first, MICROVM_PEER_TARGET_RIGHTS)?;
        let second_target = capabilities.authorize_exact(second, MICROVM_PEER_TARGET_RIGHTS)?;
        if first_target != self.first_target || second_target != self.second_target {
            return Err(MemoryResourceError::InvalidMapping);
        }
        Ok((first_target, second_target))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentImagePageClass {
    ReadOnly,
    Executable,
    PrivateWritable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentImagePagePlan {
    read_only_pages: u64,
    executable_pages: u64,
    private_writable_pages: u64,
    private_unmapped_pages: u64,
    regions: u16,
}

impl ComponentImagePagePlan {
    pub const fn read_only_pages(self) -> u64 {
        self.read_only_pages
    }

    pub const fn executable_pages(self) -> u64 {
        self.executable_pages
    }

    pub const fn private_writable_pages(self) -> u64 {
        self.private_writable_pages
    }

    pub const fn private_unmapped_pages(self) -> u64 {
        self.private_unmapped_pages
    }

    pub const fn regions(self) -> u16 {
        self.regions
    }

    pub const fn total_pages(self) -> Option<u64> {
        match self.read_only_pages.checked_add(self.executable_pages) {
            Some(pages) => match pages.checked_add(self.private_writable_pages) {
                Some(pages) => pages.checked_add(self.private_unmapped_pages),
                None => None,
            },
            None => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AccountedComponentImageRegion {
    object: MemoryObjectId,
    capability: Capability,
    mapping: MemoryMappingId,
    class: ComponentImagePageClass,
    pages: u64,
    virtual_page: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct AccountedComponentImage {
    plan: ComponentImagePagePlan,
    regions: [Option<AccountedComponentImageRegion>; MAX_COMPONENT_IMAGE_REGIONS],
    unmapped_private: Option<(MemoryObjectId, Capability)>,
}

impl AccountedComponentImage {
    pub const fn plan(&self) -> ComponentImagePagePlan {
        self.plan
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentImageAccountingError {
    Image(PeError),
    Resource(MemoryResourceError),
    Arithmetic,
    InvalidRegion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentImageReleaseSummary {
    pub regions: u16,
    pub pages: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MicrovmGuestRamError {
    Capability(MemoryResourceError),
    PhaseEmpty,
    PhaseExceedsReservation,
    ReservationIncomplete,
}

#[derive(Debug, Eq, PartialEq)]
pub struct PreparedMicrovmGuestRam {
    reservation: MicrovmGuestRam,
    remaining_pages: u64,
}

impl PreparedMicrovmGuestRam {
    pub const fn total_pages(&self) -> u64 {
        self.reservation.pages
    }

    pub const fn remaining_pages(&self) -> u64 {
        self.remaining_pages
    }

    /// Consumes one exact native-allocation phase before that phase begins.
    pub fn consume_phase(&mut self, pages: u64) -> Result<(), MicrovmGuestRamError> {
        if pages == 0 {
            return Err(MicrovmGuestRamError::PhaseEmpty);
        }
        self.remaining_pages = self
            .remaining_pages
            .checked_sub(pages)
            .ok_or(MicrovmGuestRamError::PhaseExceedsReservation)?;
        Ok(())
    }

    pub fn complete(self) -> Result<ActiveMicrovmGuestRam, MicrovmGuestRamError> {
        if self.remaining_pages != 0 {
            return Err(MicrovmGuestRamError::ReservationIncomplete);
        }
        Ok(ActiveMicrovmGuestRam {
            reservation: self.reservation,
        })
    }

    /// Returns an unpublished reservation only after all native allocations
    /// from completed phases have been torn down.
    pub unsafe fn abort(self) -> MicrovmGuestRam {
        self.reservation
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ActiveMicrovmGuestRam {
    reservation: MicrovmGuestRam,
}

impl ActiveMicrovmGuestRam {
    pub const fn object(&self) -> MemoryObjectId {
        self.reservation.object
    }

    pub const fn pages(&self) -> u64 {
        self.reservation.pages
    }

    /// Returns the reservation only after complete native guest teardown.
    pub unsafe fn retire(self) -> MicrovmGuestRam {
        self.reservation
    }
}

impl MicrovmGuestRam {
    pub const fn object(&self) -> MemoryObjectId {
        self.object
    }

    pub const fn pages(&self) -> u64 {
        self.pages
    }
}

/// Reserves an exact private host commitment before a microVM backend allocates
/// guest RAM. Package metadata, a guest address, or a VMM handle cannot replace
/// the pool capability.
pub fn reserve_microvm_guest_ram<const P: usize, const O: usize, const M: usize, const C: usize>(
    table: &mut MemoryPoolTable<P, O, M>,
    pool: MemoryPoolId,
    pool_capability: Capability,
    pages: u64,
    capabilities: &mut CapabilitySpace<C>,
) -> Result<(MicrovmGuestRam, Capability), MemoryResourceError> {
    let (object, capability) = table.allocate_object(
        pool,
        pool_capability,
        pages,
        MemoryBackingKind::Guest,
        MICROVM_GUEST_RAM_RIGHTS,
        capabilities,
    )?;
    Ok((MicrovmGuestRam { object, pages }, capability))
}

pub fn reserve_microvm_control_memory<
    const P: usize,
    const O: usize,
    const M: usize,
    const C: usize,
>(
    table: &mut MemoryPoolTable<P, O, M>,
    pool: MemoryPoolId,
    pool_capability: Capability,
    pages: u64,
    capabilities: &mut CapabilitySpace<C>,
) -> Result<(MicrovmControlMemory, Capability), MemoryResourceError> {
    let (object, capability) = table.allocate_object(
        pool,
        pool_capability,
        pages,
        MemoryBackingKind::Anonymous,
        MICROVM_CONTROL_MEMORY_RIGHTS,
        capabilities,
    )?;
    Ok((MicrovmControlMemory { object, pages }, capability))
}

/// Returns MRML-owned control storage only after complete guest teardown.
pub unsafe fn release_microvm_control_memory<
    const P: usize,
    const O: usize,
    const M: usize,
    const C: usize,
>(
    table: &mut MemoryPoolTable<P, O, M>,
    reservation: MicrovmControlMemory,
    capability: Capability,
    capabilities: &mut CapabilitySpace<C>,
) -> Result<u64, MemoryResourceError> {
    table.release_object(reservation.object, capability, capabilities)
}

/// Charges one exact shared page and one guest mapping slot before a backend
/// publishes that projection. Allocation and mapping authority are distinct;
/// a kind or guest address cannot substitute for either capability.
pub fn reserve_microvm_page_projection<
    const P: usize,
    const O: usize,
    const M: usize,
    const C: usize,
>(
    table: &mut MemoryPoolTable<P, O, M>,
    pool: MemoryPoolId,
    pool_capability: Capability,
    target_capability: Capability,
    kind: MicrovmPageProjectionKind,
    virtual_page: u64,
    capabilities: &mut CapabilitySpace<C>,
) -> Result<(MicrovmPageProjection, Capability), MemoryResourceError> {
    let (object, object_capability) = table.allocate_object(
        pool,
        pool_capability,
        1,
        MemoryBackingKind::Shared,
        MICROVM_PAGE_PROJECTION_RIGHTS,
        capabilities,
    )?;
    let mapping = match table.reserve_mapping(
        object,
        object_capability,
        target_capability,
        virtual_page,
        0,
        1,
        Rights::READ.union(Rights::WRITE),
        capabilities,
    ) {
        Ok(mapping) => mapping,
        Err(error) => {
            if let Err(cleanup) = table.release_object(object, object_capability, capabilities) {
                return Err(cleanup);
            }
            return Err(error);
        }
    };
    Ok((
        MicrovmPageProjection {
            object,
            mapping,
            kind,
            virtual_page,
        },
        object_capability,
    ))
}

/// Atomically reserves one accounted shared page and exact read/write,
/// non-executable mappings into two distinct microVM targets.
///
/// Target capabilities must carry exactly the bounded mapping lifecycle rights;
/// an excessive capability is rejected rather than silently accepted. Failure
/// after the first reservation rolls it back before returning, so a caller can
/// never observe a half-published peer projection.
#[allow(clippy::too_many_arguments)]
pub fn reserve_microvm_peer_page_projection<
    const P: usize,
    const O: usize,
    const M: usize,
    const C: usize,
>(
    table: &mut MemoryPoolTable<P, O, M>,
    pool: MemoryPoolId,
    pool_capability: Capability,
    first_target_capability: Capability,
    second_target_capability: Capability,
    first_virtual_page: u64,
    second_virtual_page: u64,
    capabilities: &mut CapabilitySpace<C>,
) -> Result<(MicrovmPeerPageProjection, Capability), MemoryResourceError> {
    let first_target = capabilities.authorize_exact(
        first_target_capability,
        MICROVM_PEER_TARGET_RIGHTS,
    )?;
    let second_target = capabilities.authorize_exact(
        second_target_capability,
        MICROVM_PEER_TARGET_RIGHTS,
    )?;
    if first_target == second_target {
        return Err(MemoryResourceError::InvalidMapping);
    }

    let (object, object_capability) = table.allocate_object(
        pool,
        pool_capability,
        1,
        MemoryBackingKind::Shared,
        MICROVM_PEER_PAGE_RIGHTS,
        capabilities,
    )?;
    let access = Rights::READ.union(Rights::WRITE);
    let first_mapping = match table.reserve_mapping(
        object,
        object_capability,
        first_target_capability,
        first_virtual_page,
        0,
        1,
        access,
        capabilities,
    ) {
        Ok(mapping) => mapping,
        Err(error) => {
            table.release_object(object, object_capability, capabilities)?;
            return Err(error);
        }
    };
    let second_mapping = match table.reserve_mapping(
        object,
        object_capability,
        second_target_capability,
        second_virtual_page,
        0,
        1,
        access,
        capabilities,
    ) {
        Ok(mapping) => mapping,
        Err(error) => {
            // SAFETY: this reservation has not been installed in a backend or
            // published; no CPU, device, cached translation or peer can use it.
            unsafe {
                table.release_mapping(first_mapping, first_target_capability, capabilities)?;
            }
            table.release_object(object, object_capability, capabilities)?;
            return Err(error);
        }
    };
    Ok((
        MicrovmPeerPageProjection {
            object,
            first_mapping,
            second_mapping,
            first_target,
            second_target,
            first_target_capability,
            second_target_capability,
            first_virtual_page,
            second_virtual_page,
        },
        object_capability,
    ))
}

fn add_component_image_region(
    plan: &mut ComponentImagePagePlan,
    region: PeLoadRegion,
) -> Result<ComponentImagePageClass, ComponentImageAccountingError> {
    if region.pages() == 0
        || !region.readable()
        || region.writable() && region.executable()
        || u64::from(region.virtual_address()) % PAGE_SIZE != 0
    {
        return Err(ComponentImageAccountingError::InvalidRegion);
    }
    let pages = u64::from(region.pages());
    let class = if region.executable() {
        plan.executable_pages = plan
            .executable_pages
            .checked_add(pages)
            .ok_or(ComponentImageAccountingError::Arithmetic)?;
        ComponentImagePageClass::Executable
    } else if region.writable() {
        plan.private_writable_pages = plan
            .private_writable_pages
            .checked_add(pages)
            .ok_or(ComponentImageAccountingError::Arithmetic)?;
        ComponentImagePageClass::PrivateWritable
    } else {
        plan.read_only_pages = plan
            .read_only_pages
            .checked_add(pages)
            .ok_or(ComponentImageAccountingError::Arithmetic)?;
        ComponentImagePageClass::ReadOnly
    };
    plan.regions = plan
        .regions
        .checked_add(1)
        .ok_or(ComponentImageAccountingError::Arithmetic)?;
    Ok(class)
}

pub fn component_image_page_plan(
    image: &PeImage<'_>,
) -> Result<ComponentImagePagePlan, ComponentImageAccountingError> {
    let mut plan = ComponentImagePagePlan {
        read_only_pages: 0,
        executable_pages: 0,
        private_writable_pages: 0,
        private_unmapped_pages: 0,
        regions: 0,
    };
    for index in 0..image.load_region_count() {
        let region = image
            .load_region(index)
            .map_err(ComponentImageAccountingError::Image)?;
        add_component_image_region(&mut plan, region)?;
    }
    let mapped_pages = plan
        .total_pages()
        .filter(|pages| *pages != 0)
        .ok_or(ComponentImageAccountingError::Arithmetic)?;
    let image_pages = u64::from(image.image_size()) / PAGE_SIZE;
    plan.private_unmapped_pages = image_pages
        .checked_sub(mapped_pages)
        .ok_or(ComponentImageAccountingError::InvalidRegion)?;
    Ok(plan)
}

fn component_image_region_policy(
    class: ComponentImagePageClass,
) -> (MemoryBackingKind, Rights, Rights) {
    let base = Rights::READ
        .union(Rights::MAP)
        .union(Rights::INSPECT)
        .union(Rights::CONTROL);
    match class {
        ComponentImagePageClass::ReadOnly => (MemoryBackingKind::Shared, base, Rights::READ),
        ComponentImagePageClass::Executable => (
            MemoryBackingKind::Shared,
            base.union(Rights::EXECUTE),
            Rights::READ.union(Rights::EXECUTE),
        ),
        ComponentImagePageClass::PrivateWritable => (
            MemoryBackingKind::Anonymous,
            base.union(Rights::WRITE),
            Rights::READ.union(Rights::WRITE),
        ),
    }
}

fn rollback_component_image_regions<
    const P: usize,
    const O: usize,
    const M: usize,
    const C: usize,
>(
    table: &mut MemoryPoolTable<P, O, M>,
    regions: &mut [Option<AccountedComponentImageRegion>; MAX_COMPONENT_IMAGE_REGIONS],
    count: usize,
    target_capability: Capability,
    capabilities: &mut CapabilitySpace<C>,
) -> Result<(), MemoryResourceError> {
    for index in (0..count).rev() {
        let region = regions[index].ok_or(MemoryResourceError::InvalidMapping)?;
        unsafe {
            table.release_mapping(region.mapping, target_capability, capabilities)?;
        }
        table.release_object(region.object, region.capability, capabilities)?;
        regions[index] = None;
    }
    Ok(())
}

/// Reserves every verified PE load region as an exact object and guest mapping
/// before native image construction. Immutable read-only/executable regions
/// use shared backing; writable regions are private anonymous objects. W^X is
/// retained by the exact final mapping access and no package field authorizes
/// either the object or target address space.
pub fn reserve_component_image<const P: usize, const O: usize, const M: usize, const C: usize>(
    table: &mut MemoryPoolTable<P, O, M>,
    pool: MemoryPoolId,
    pool_capability: Capability,
    target_capability: Capability,
    image: &PeImage<'_>,
    load_base_virtual_page: u64,
    capabilities: &mut CapabilitySpace<C>,
) -> Result<AccountedComponentImage, ComponentImageAccountingError> {
    let plan = component_image_page_plan(image)?;
    let count = usize::from(plan.regions);
    if count > MAX_COMPONENT_IMAGE_REGIONS {
        return Err(ComponentImageAccountingError::InvalidRegion);
    }
    let mut regions = [None; MAX_COMPONENT_IMAGE_REGIONS];
    for index in 0..count {
        let load = image
            .load_region(index)
            .map_err(ComponentImageAccountingError::Image)?;
        let mut classified = ComponentImagePagePlan {
            read_only_pages: 0,
            executable_pages: 0,
            private_writable_pages: 0,
            private_unmapped_pages: 0,
            regions: 0,
        };
        let class = add_component_image_region(&mut classified, load)?;
        let (backing, object_rights, mapping_access) = component_image_region_policy(class);
        let pages = u64::from(load.pages());
        let virtual_page = load_base_virtual_page
            .checked_add(u64::from(load.virtual_address()) / PAGE_SIZE)
            .ok_or(ComponentImageAccountingError::Arithmetic)?;
        let (object, capability) = match table.allocate_object(
            pool,
            pool_capability,
            pages,
            backing,
            object_rights,
            capabilities,
        ) {
            Ok(value) => value,
            Err(error) => {
                rollback_component_image_regions(
                    table,
                    &mut regions,
                    index,
                    target_capability,
                    capabilities,
                )
                .map_err(ComponentImageAccountingError::Resource)?;
                return Err(ComponentImageAccountingError::Resource(error));
            }
        };
        let mapping = match table.reserve_mapping(
            object,
            capability,
            target_capability,
            virtual_page,
            0,
            pages,
            mapping_access,
            capabilities,
        ) {
            Ok(mapping) => mapping,
            Err(error) => {
                table
                    .release_object(object, capability, capabilities)
                    .map_err(ComponentImageAccountingError::Resource)?;
                rollback_component_image_regions(
                    table,
                    &mut regions,
                    index,
                    target_capability,
                    capabilities,
                )
                .map_err(ComponentImageAccountingError::Resource)?;
                return Err(ComponentImageAccountingError::Resource(error));
            }
        };
        regions[index] = Some(AccountedComponentImageRegion {
            object,
            capability,
            mapping,
            class,
            pages,
            virtual_page,
        });
    }
    let unmapped_private = if plan.private_unmapped_pages == 0 {
        None
    } else {
        match table.allocate_object(
            pool,
            pool_capability,
            plan.private_unmapped_pages,
            MemoryBackingKind::Anonymous,
            Rights::READ
                .union(Rights::WRITE)
                .union(Rights::INSPECT)
                .union(Rights::CONTROL),
            capabilities,
        ) {
            Ok(value) => Some(value),
            Err(error) => {
                rollback_component_image_regions(
                    table,
                    &mut regions,
                    count,
                    target_capability,
                    capabilities,
                )
                .map_err(ComponentImageAccountingError::Resource)?;
                return Err(ComponentImageAccountingError::Resource(error));
            }
        }
    };
    Ok(AccountedComponentImage {
        plan,
        regions,
        unmapped_private,
    })
}

/// Releases exact image mappings and objects only after native guest teardown.
///
/// # Safety
///
/// The caller must prove no CPU, backend, cached translation, or peer can use
/// any represented region. The exact target capability must remain live.
pub unsafe fn release_component_image<
    const P: usize,
    const O: usize,
    const M: usize,
    const C: usize,
>(
    table: &mut MemoryPoolTable<P, O, M>,
    mut image: AccountedComponentImage,
    target_capability: Capability,
    capabilities: &mut CapabilitySpace<C>,
) -> Result<ComponentImageReleaseSummary, MemoryResourceError> {
    let count = usize::from(image.plan.regions);
    let pages = image
        .plan
        .total_pages()
        .ok_or(MemoryResourceError::Arithmetic)?;
    rollback_component_image_regions(
        table,
        &mut image.regions,
        count,
        target_capability,
        capabilities,
    )?;
    if let Some((object, capability)) = image.unmapped_private.take() {
        table.release_object(object, capability, capabilities)?;
    }
    Ok(ComponentImageReleaseSummary {
        regions: image.plan.regions,
        pages,
    })
}

pub fn prepare_microvm_guest_ram<const P: usize, const O: usize, const M: usize, const C: usize>(
    table: &MemoryPoolTable<P, O, M>,
    reservation: MicrovmGuestRam,
    capability: Capability,
    capabilities: &CapabilitySpace<C>,
) -> Result<PreparedMicrovmGuestRam, MicrovmGuestRamError> {
    prepare_microvm_guest_ram_recoverable(table, reservation, capability, capabilities)
        .map_err(|(error, _reservation)| error)
}

/// Recoverable form used by fail-closed launch composition. Validation failure
/// returns the exact unpublished reservation so the caller can release or retry
/// it instead of losing quantitative authority.
pub fn prepare_microvm_guest_ram_recoverable<
    const P: usize,
    const O: usize,
    const M: usize,
    const C: usize,
>(
    table: &MemoryPoolTable<P, O, M>,
    reservation: MicrovmGuestRam,
    capability: Capability,
    capabilities: &CapabilitySpace<C>,
) -> Result<PreparedMicrovmGuestRam, (MicrovmGuestRamError, MicrovmGuestRam)> {
    if let Err(error) = table.object_physical_backing(reservation.object, capability, capabilities)
    {
        return Err((MicrovmGuestRamError::Capability(error), reservation));
    }
    match table.object_backing(reservation.object) {
        Ok(MemoryBackingKind::Guest) => {}
        Ok(_) => {
            return Err((
                MicrovmGuestRamError::Capability(MemoryResourceError::InvalidObject),
                reservation,
            ));
        }
        Err(error) => {
            return Err((MicrovmGuestRamError::Capability(error), reservation));
        }
    }
    let remaining_pages = reservation.pages;
    Ok(PreparedMicrovmGuestRam {
        reservation,
        remaining_pages,
    })
}

/// Returns the exact host commitment only after the VMM adapter has proved all
/// native guest mappings/backing are gone. The caller cannot partially release
/// a live generation.
pub unsafe fn release_microvm_guest_ram<
    const P: usize,
    const O: usize,
    const M: usize,
    const C: usize,
>(
    table: &mut MemoryPoolTable<P, O, M>,
    reservation: MicrovmGuestRam,
    capability: Capability,
    capabilities: &mut CapabilitySpace<C>,
) -> Result<u64, MemoryResourceError> {
    table.release_object(reservation.object, capability, capabilities)
}

impl ComponentExecutablePages {
    pub const fn object(self) -> MemoryObjectId {
        self.object
    }

    pub const fn pages(self) -> u64 {
        self.pages
    }
}

/// Charges immutable component code to an existing `MemoryPool` and creates
/// the corresponding shared `MemoryObject` authority.
pub fn account_component_executable<
    const P: usize,
    const O: usize,
    const M: usize,
    const C: usize,
>(
    table: &mut MemoryPoolTable<P, O, M>,
    pool: MemoryPoolId,
    pool_capability: Capability,
    pages: u64,
    capabilities: &mut CapabilitySpace<C>,
) -> Result<(ComponentExecutablePages, Capability), MemoryResourceError> {
    let (object, capability) = table.allocate_object(
        pool,
        pool_capability,
        pages,
        MemoryBackingKind::Shared,
        COMPONENT_EXECUTABLE_RIGHTS,
        capabilities,
    )?;
    Ok((ComponentExecutablePages { object, pages }, capability))
}

/// Reserves one complete read/execute projection of immutable component code.
///
/// The target capability independently authorizes the destination address
/// space. This function records policy/accounting only; a platform adapter must
/// install the exact native mapping before execution and retain the reservation
/// until native teardown and translation invalidation complete.
pub fn reserve_component_executable_mapping<
    const P: usize,
    const O: usize,
    const M: usize,
    const C: usize,
>(
    table: &mut MemoryPoolTable<P, O, M>,
    executable: ComponentExecutablePages,
    executable_capability: Capability,
    target_capability: Capability,
    virtual_page: u64,
    capabilities: &CapabilitySpace<C>,
) -> Result<MemoryMappingId, MemoryResourceError> {
    table.reserve_mapping(
        executable.object,
        executable_capability,
        target_capability,
        virtual_page,
        0,
        executable.pages,
        Rights::READ.union(Rights::EXECUTE),
        capabilities,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapabilityError, ObjectId};

    const POOL_RIGHTS: Rights = Rights::ALLOCATE
        .union(Rights::CONTROL)
        .union(Rights::INSPECT);

    #[test]
    fn shared_code_is_charged_once_and_mapped_read_execute_many_times() {
        let mut capabilities = CapabilitySpace::<8>::new();
        let mut table = MemoryPoolTable::<1, 1, 2>::new(21).unwrap();
        let (pool, pool_capability) = table
            .create_root(8, 2, 0, POOL_RIGHTS, &mut capabilities)
            .unwrap();
        let target_a = capabilities
            .insert(ObjectId(0x100), Rights::MAP.union(Rights::INSPECT))
            .unwrap();
        let target_b = capabilities
            .insert(ObjectId(0x200), Rights::MAP.union(Rights::INSPECT))
            .unwrap();

        let (code, code_capability) =
            account_component_executable(&mut table, pool, pool_capability, 3, &mut capabilities)
                .unwrap();
        let mapping_a = reserve_component_executable_mapping(
            &mut table,
            code,
            code_capability,
            target_a,
            0x400,
            &capabilities,
        )
        .unwrap();
        let mapping_b = reserve_component_executable_mapping(
            &mut table,
            code,
            code_capability,
            target_b,
            0x800,
            &capabilities,
        )
        .unwrap();

        let usage = table.usage(pool, pool_capability, &capabilities).unwrap();
        assert_eq!(usage.object_pages(), 3);
        assert_eq!(usage.active_mappings(), 2);
        assert_eq!(
            table.object_backing(code.object()),
            Ok(MemoryBackingKind::Shared)
        );
        assert_eq!(
            table
                .mapping_info(mapping_a, target_a, &capabilities)
                .unwrap()
                .access(),
            Rights::READ.union(Rights::EXECUTE)
        );
        assert_eq!(
            table
                .mapping_info(mapping_b, target_b, &capabilities)
                .unwrap()
                .object(),
            code.object()
        );
    }

    #[test]
    fn component_code_has_no_write_authority_and_stays_live_while_mapped() {
        let mut capabilities = CapabilitySpace::<6>::new();
        let mut table = MemoryPoolTable::<1, 1, 1>::new(22).unwrap();
        let (pool, pool_capability) = table
            .create_root(2, 1, 0, POOL_RIGHTS, &mut capabilities)
            .unwrap();
        let target = capabilities
            .insert(
                ObjectId(0x300),
                Rights::MAP.union(Rights::INSPECT).union(Rights::CONTROL),
            )
            .unwrap();
        let (code, code_capability) =
            account_component_executable(&mut table, pool, pool_capability, 2, &mut capabilities)
                .unwrap();

        assert_eq!(
            capabilities.authorize(code_capability, Rights::WRITE),
            Err(CapabilityError::PermissionDenied)
        );
        let mapping = reserve_component_executable_mapping(
            &mut table,
            code,
            code_capability,
            target,
            0x500,
            &capabilities,
        )
        .unwrap();
        assert_eq!(
            table.release_object(code.object(), code_capability, &mut capabilities),
            Err(MemoryResourceError::MappingsActive)
        );

        // This unit test has no native mapping. Its policy reservation may be
        // retired only under the unsafe contract after proving that fact.
        unsafe {
            table
                .release_mapping(mapping, target, &capabilities)
                .unwrap();
        }
        assert_eq!(
            table.release_object(code.object(), code_capability, &mut capabilities),
            Ok(2)
        );
    }

    #[test]
    fn package_metadata_cannot_allocate_without_pool_authority() {
        let mut capabilities = CapabilitySpace::<4>::new();
        let mut table = MemoryPoolTable::<1, 1, 1>::new(23).unwrap();
        let (pool, pool_capability) = table
            .create_root(1, 1, 0, POOL_RIGHTS, &mut capabilities)
            .unwrap();
        let metadata_only = capabilities
            .insert(ObjectId(0x400), Rights::INSPECT)
            .unwrap();

        assert!(matches!(
            account_component_executable(&mut table, pool, metadata_only, 1, &mut capabilities),
            Err(MemoryResourceError::Capability(
                CapabilityError::PermissionDenied
            ))
        ));
        assert_eq!(
            table
                .usage(pool, pool_capability, &capabilities)
                .unwrap()
                .object_pages(),
            0
        );
    }

    #[test]
    fn microvm_guest_ram_is_exact_private_non_executable_authority() {
        let mut capabilities = CapabilitySpace::<4>::new();
        let mut table = MemoryPoolTable::<1, 1>::new(24).unwrap();
        let (pool, pool_capability) = table
            .create_root(32, 1, 0, POOL_RIGHTS, &mut capabilities)
            .unwrap();
        let (ram, ram_capability) =
            reserve_microvm_guest_ram(&mut table, pool, pool_capability, 32, &mut capabilities)
                .unwrap();

        assert_eq!(ram.pages(), 32);
        assert_eq!(
            table.object_backing(ram.object()),
            Ok(MemoryBackingKind::Guest)
        );
        assert_eq!(
            capabilities.authorize(ram_capability, Rights::EXECUTE),
            Err(CapabilityError::PermissionDenied)
        );
        assert_eq!(
            capabilities.authorize(ram_capability, Rights::SHARE),
            Err(CapabilityError::PermissionDenied)
        );
        assert_eq!(
            capabilities.authorize(ram_capability, Rights::DELEGATE),
            Err(CapabilityError::PermissionDenied)
        );
        assert_eq!(
            table
                .usage(pool, pool_capability, &capabilities)
                .unwrap()
                .object_pages(),
            32
        );
        assert_eq!(
            unsafe {
                release_microvm_guest_ram(&mut table, ram, ram_capability, &mut capabilities)
            },
            Ok(32)
        );
        assert_eq!(
            table
                .usage(pool, pool_capability, &capabilities)
                .unwrap()
                .object_pages(),
            0
        );
    }

    #[test]
    fn microvm_guest_ram_requires_pool_authority_and_never_overcommits() {
        let mut capabilities = CapabilitySpace::<5>::new();
        let mut table = MemoryPoolTable::<1, 1>::new(25).unwrap();
        let (pool, pool_capability) = table
            .create_root(8, 1, 0, POOL_RIGHTS, &mut capabilities)
            .unwrap();
        let metadata = capabilities
            .insert(ObjectId(0x500), Rights::INSPECT)
            .unwrap();

        assert!(matches!(
            reserve_microvm_guest_ram(&mut table, pool, metadata, 8, &mut capabilities),
            Err(MemoryResourceError::Capability(
                CapabilityError::PermissionDenied
            ))
        ));
        assert_eq!(
            reserve_microvm_guest_ram(&mut table, pool, pool_capability, 9, &mut capabilities,),
            Err(MemoryResourceError::PoolExhausted)
        );
        assert_eq!(
            table
                .usage(pool, pool_capability, &capabilities)
                .unwrap()
                .object_pages(),
            0
        );
    }

    #[test]
    fn guest_ram_construction_is_linear_staged_and_exact() {
        let mut capabilities = CapabilitySpace::<3>::new();
        let mut table = MemoryPoolTable::<1, 1>::new(26).unwrap();
        let (pool, pool_capability) = table
            .create_root(12, 1, 0, POOL_RIGHTS, &mut capabilities)
            .unwrap();
        let (reservation, capability) =
            reserve_microvm_guest_ram(&mut table, pool, pool_capability, 12, &mut capabilities)
                .unwrap();
        let mut prepared =
            prepare_microvm_guest_ram(&table, reservation, capability, &capabilities).unwrap();
        assert_eq!(prepared.total_pages(), 12);
        assert_eq!(
            prepared.consume_phase(0),
            Err(MicrovmGuestRamError::PhaseEmpty)
        );
        prepared.consume_phase(5).unwrap();
        assert_eq!(prepared.remaining_pages(), 7);
        assert_eq!(
            prepared.consume_phase(8),
            Err(MicrovmGuestRamError::PhaseExceedsReservation)
        );
        prepared.consume_phase(3).unwrap();
        assert_eq!(
            prepared.complete(),
            Err(MicrovmGuestRamError::ReservationIncomplete)
        );
    }

    #[test]
    fn active_guest_ram_returns_only_after_exact_complete_construction() {
        let mut capabilities = CapabilitySpace::<3>::new();
        let mut table = MemoryPoolTable::<1, 1>::new(27).unwrap();
        let (pool, pool_capability) = table
            .create_root(6, 1, 0, POOL_RIGHTS, &mut capabilities)
            .unwrap();
        let (reservation, capability) =
            reserve_microvm_guest_ram(&mut table, pool, pool_capability, 6, &mut capabilities)
                .unwrap();
        let mut prepared =
            prepare_microvm_guest_ram(&table, reservation, capability, &capabilities).unwrap();
        prepared.consume_phase(2).unwrap();
        prepared.consume_phase(4).unwrap();
        let active = prepared.complete().unwrap();
        assert_eq!(active.pages(), 6);
        let reservation = unsafe { active.retire() };
        assert_eq!(
            unsafe {
                release_microvm_guest_ram(&mut table, reservation, capability, &mut capabilities)
            },
            Ok(6)
        );
    }

    #[test]
    fn vmm_control_memory_is_separate_nonmapped_nonexecutable_authority() {
        let mut capabilities = CapabilitySpace::<4>::new();
        let mut table = MemoryPoolTable::<1, 1>::new(28).unwrap();
        let (pool, pool_capability) = table
            .create_root(2, 1, 0, POOL_RIGHTS, &mut capabilities)
            .unwrap();
        let (control, capability) =
            reserve_microvm_control_memory(&mut table, pool, pool_capability, 2, &mut capabilities)
                .unwrap();
        assert_eq!(control.pages(), 2);
        assert_eq!(
            table.object_backing(control.object()),
            Ok(MemoryBackingKind::Anonymous)
        );
        for denied in [Rights::EXECUTE, Rights::MAP, Rights::PIN, Rights::SHARE] {
            assert_eq!(
                capabilities.authorize(capability, denied),
                Err(CapabilityError::PermissionDenied)
            );
        }
        assert_eq!(
            unsafe {
                release_microvm_control_memory(&mut table, control, capability, &mut capabilities)
            },
            Ok(2)
        );
    }

    #[test]
    fn microvm_page_projections_charge_exact_objects_and_mapping_slots() {
        let mut capabilities = CapabilitySpace::<8>::new();
        let mut table = MemoryPoolTable::<1, 3, 2>::new(29).unwrap();
        let (pool, pool_capability) = table
            .create_root(3, 2, 0, POOL_RIGHTS, &mut capabilities)
            .unwrap();
        let target = capabilities
            .insert(
                ObjectId(0x700),
                Rights::MAP.union(Rights::INSPECT).union(Rights::CONTROL),
            )
            .unwrap();
        let (shared, shared_capability) = reserve_microvm_page_projection(
            &mut table,
            pool,
            pool_capability,
            target,
            MicrovmPageProjectionKind::SharedData,
            0x6fe,
            &mut capabilities,
        )
        .unwrap();
        let (resource, resource_capability) = reserve_microvm_page_projection(
            &mut table,
            pool,
            pool_capability,
            target,
            MicrovmPageProjectionKind::Resource,
            0x6ff,
            &mut capabilities,
        )
        .unwrap();

        let usage = table.usage(pool, pool_capability, &capabilities).unwrap();
        assert_eq!(usage.object_pages(), 2);
        assert_eq!(usage.active_mappings(), 2);
        assert_eq!(shared.kind(), MicrovmPageProjectionKind::SharedData);
        assert_eq!(resource.virtual_page(), 0x6ff);
        assert_eq!(
            table.object_backing(shared.object()),
            Ok(MemoryBackingKind::Shared)
        );
        assert_eq!(
            table
                .mapping_info(shared.mapping(), target, &capabilities)
                .unwrap()
                .access(),
            Rights::READ.union(Rights::WRITE)
        );

        assert_eq!(
            reserve_microvm_page_projection(
                &mut table,
                pool,
                pool_capability,
                target,
                MicrovmPageProjectionKind::Resource,
                0x700,
                &mut capabilities,
            ),
            Err(MemoryResourceError::MappingLimitExceeded)
        );
        let usage = table.usage(pool, pool_capability, &capabilities).unwrap();
        assert_eq!(usage.object_pages(), 2);
        assert_eq!(usage.active_mappings(), 2);

        unsafe {
            table
                .release_mapping(shared.mapping(), target, &capabilities)
                .unwrap();
            table
                .release_mapping(resource.mapping(), target, &capabilities)
                .unwrap();
        }
        assert_eq!(
            table.release_object(shared.object(), shared_capability, &mut capabilities),
            Ok(1)
        );
        assert_eq!(
            table.release_object(resource.object(), resource_capability, &mut capabilities),
            Ok(1)
        );
        let usage = table.usage(pool, pool_capability, &capabilities).unwrap();
        assert_eq!(usage.object_pages(), 0);
        assert_eq!(usage.active_mappings(), 0);
    }

    #[test]
    fn peer_projection_binds_two_exact_capability_generations_and_never_executes() {
        let mut capabilities = CapabilitySpace::<8>::new();
        let mut table = MemoryPoolTable::<1, 1, 2>::new(30).unwrap();
        let (pool, pool_capability) = table
            .create_root(1, 2, 0, POOL_RIGHTS, &mut capabilities)
            .unwrap();
        let first_target = capabilities
            .insert(ObjectId(0x801), MICROVM_PEER_TARGET_RIGHTS)
            .unwrap();
        let second_target = capabilities
            .insert(ObjectId(0x802), MICROVM_PEER_TARGET_RIGHTS)
            .unwrap();

        let (projection, object_capability) = reserve_microvm_peer_page_projection(
            &mut table,
            pool,
            pool_capability,
            first_target,
            second_target,
            0x900,
            0xa00,
            &mut capabilities,
        )
        .unwrap();
        assert_eq!(projection.first_target(), ObjectId(0x801));
        assert_eq!(projection.second_target(), ObjectId(0x802));
        assert_eq!(projection.first_virtual_page(), 0x900);
        assert_eq!(projection.second_virtual_page(), 0xa00);
        assert!(
            capabilities
                .authorize_exact(object_capability, MICROVM_PEER_PAGE_RIGHTS)
                .is_ok()
        );
        assert_eq!(
            projection.validate_targets(first_target, second_target, &capabilities),
            Ok((ObjectId(0x801), ObjectId(0x802)))
        );
        for (mapping, target) in [
            (projection.first_mapping(), first_target),
            (projection.second_mapping(), second_target),
        ] {
            let info = table.mapping_info(mapping, target, &capabilities).unwrap();
            assert_eq!(info.object(), projection.object());
            assert_eq!(info.access(), Rights::READ.union(Rights::WRITE));
            assert!(!info.access().contains(Rights::EXECUTE));
        }

        capabilities.revoke(first_target).unwrap();
        let replacement = capabilities
            .insert(ObjectId(0x801), MICROVM_PEER_TARGET_RIGHTS)
            .unwrap();
        assert_ne!(first_target, replacement);
        assert_eq!(
            projection.validate_targets(replacement, second_target, &capabilities),
            Err(MemoryResourceError::InvalidMapping)
        );
    }

    #[test]
    fn peer_projection_rejects_wrong_rights_identity_and_rolls_back_second_mapping() {
        let mut capabilities = CapabilitySpace::<10>::new();
        let mut table = MemoryPoolTable::<1, 1, 1>::new(31).unwrap();
        let (pool, pool_capability) = table
            .create_root(1, 2, 0, POOL_RIGHTS, &mut capabilities)
            .unwrap();
        let first = capabilities
            .insert(ObjectId(0x811), MICROVM_PEER_TARGET_RIGHTS)
            .unwrap();
        let second = capabilities
            .insert(ObjectId(0x812), MICROVM_PEER_TARGET_RIGHTS)
            .unwrap();
        let insufficient = capabilities.insert(ObjectId(0x813), Rights::MAP).unwrap();
        let excessive = capabilities
            .insert(
                ObjectId(0x814),
                MICROVM_PEER_TARGET_RIGHTS.union(Rights::READ),
            )
            .unwrap();

        assert!(matches!(
            reserve_microvm_peer_page_projection(
                &mut table,
                pool,
                pool_capability,
                insufficient,
                second,
                1,
                2,
                &mut capabilities,
            ),
            Err(MemoryResourceError::Capability(CapabilityError::PermissionDenied))
        ));
        assert!(matches!(
            reserve_microvm_peer_page_projection(
                &mut table,
                pool,
                pool_capability,
                excessive,
                second,
                1,
                2,
                &mut capabilities,
            ),
            Err(MemoryResourceError::Capability(CapabilityError::PermissionDenied))
        ));
        assert_eq!(
            reserve_microvm_peer_page_projection(
                &mut table,
                pool,
                pool_capability,
                first,
                first,
                1,
                2,
                &mut capabilities,
            ),
            Err(MemoryResourceError::InvalidMapping)
        );

        assert_eq!(
            reserve_microvm_peer_page_projection(
                &mut table,
                pool,
                pool_capability,
                first,
                second,
                1,
                2,
                &mut capabilities,
            ),
            Err(MemoryResourceError::CapacityExhausted)
        );
        let usage = table.usage(pool, pool_capability, &capabilities).unwrap();
        assert_eq!(usage.object_pages(), 0);
        assert_eq!(usage.active_mappings(), 0);
    }

    #[test]
    fn component_image_plan_separates_rx_ro_and_private_rw_pages() {
        let mut plan = ComponentImagePagePlan {
            read_only_pages: 0,
            executable_pages: 0,
            private_writable_pages: 0,
            private_unmapped_pages: 0,
            regions: 0,
        };
        assert_eq!(
            add_component_image_region(&mut plan, PeLoadRegion::test_value(0, 1, false, false)),
            Ok(ComponentImagePageClass::ReadOnly)
        );
        assert_eq!(
            add_component_image_region(&mut plan, PeLoadRegion::test_value(0x1000, 2, false, true)),
            Ok(ComponentImagePageClass::Executable)
        );
        assert_eq!(
            add_component_image_region(&mut plan, PeLoadRegion::test_value(0x3000, 3, true, false)),
            Ok(ComponentImagePageClass::PrivateWritable)
        );
        assert_eq!(plan.read_only_pages(), 1);
        assert_eq!(plan.executable_pages(), 2);
        assert_eq!(plan.private_writable_pages(), 3);
        assert_eq!(plan.total_pages(), Some(6));
        assert_eq!(plan.regions(), 3);

        let before = plan;
        assert_eq!(
            add_component_image_region(&mut plan, PeLoadRegion::test_value(0x6000, 1, true, true)),
            Err(ComponentImageAccountingError::InvalidRegion)
        );
        assert_eq!(plan, before);
    }
}
