use crate::{
    Capability, CapabilitySpace, MemoryBackingKind, MemoryMappingId, MemoryObjectId, MemoryPoolId,
    MemoryPoolTable, MemoryResourceError, Rights,
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

pub fn prepare_microvm_guest_ram<const P: usize, const O: usize, const M: usize, const C: usize>(
    table: &MemoryPoolTable<P, O, M>,
    reservation: MicrovmGuestRam,
    capability: Capability,
    capabilities: &CapabilitySpace<C>,
) -> Result<PreparedMicrovmGuestRam, MicrovmGuestRamError> {
    table
        .object_physical_backing(reservation.object, capability, capabilities)
        .map_err(MicrovmGuestRamError::Capability)?;
    if table
        .object_backing(reservation.object)
        .map_err(MicrovmGuestRamError::Capability)?
        != MemoryBackingKind::Guest
    {
        return Err(MicrovmGuestRamError::Capability(
            MemoryResourceError::InvalidObject,
        ));
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
}
