use crate::{Capability, CapabilityError, CapabilitySpace, ObjectId, PAGE_SIZE, PhysAddr, Rights};

pub const HYPERCALL_BYTES: usize = 64;
pub const MAX_GUEST_REGIONS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmError {
    EmptyRegion,
    Unaligned,
    Overflow,
    RegionTableFull,
    GuestOverlap,
    HostAlias,
    WritableExecutable,
    Unmapped,
    PermissionDenied,
    MalformedHypercall,
    UnsupportedHypercall,
    Replay,
    SequenceExhausted,
    Capability(CapabilityError),
    WrongObject,
    VmTableFull,
    StaleVm,
    InvalidVmState,
    ExitBudgetExceeded,
    InvalidIo,
    IoDenied,
    IoPolicyFull,
    UnhandledExit,
    InterruptDenied,
    StaleMapping,
    ExecutionPoisoned,
    LifecycleBusy,
    ResourceCountOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmId(u64);

impl VmId {
    const fn new(index: u32, generation: u32) -> Self {
        Self(((generation as u64) << 32) | index as u64)
    }

    pub const fn token(self) -> u64 {
        self.0
    }
    const fn index(self) -> usize {
        self.0 as u32 as usize
    }
    const fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmState {
    Created,
    Loaded,
    Running,
    Stopped,
    Failed,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionPoisonReason {
    NativeUnmapUncertain,
    PageTableRemovalUncertain,
    TlbInvalidationUncertain,
    PeerWithdrawalUncertain,
    VcpuRetirementUncertain,
    BackendStateMismatch,
}

#[derive(Clone, Copy)]
struct VmSlot {
    generation: u32,
    state: VmState,
    exits: u64,
    exit_budget: u64,
    poison: Option<ExecutionPoisonReason>,
    active_workers: u16,
    live_mappings: u16,
    live_aliases: u16,
    pinned_ranges: u16,
    poisoned_destruction_confirmed: bool,
}

/// Fixed-capacity VM lifecycle table. IDs include a nonzero generation so a
/// handle retained after destruction cannot address a newly created VM.
pub struct VmTable<const N: usize> {
    slots: [Option<VmSlot>; N],
    generations: [u32; N],
}

impl<const N: usize> VmTable<N> {
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            generations: [0; N],
        }
    }

    pub fn create(&mut self, exit_budget: u64) -> Result<VmId, VmError> {
        if exit_budget == 0 {
            return Err(VmError::ExitBudgetExceeded);
        }
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(VmError::VmTableFull)?;
        let generation = self.generations[index]
            .checked_add(1)
            .ok_or(VmError::SequenceExhausted)?;
        self.generations[index] = generation;
        self.slots[index] = Some(VmSlot {
            generation,
            state: VmState::Created,
            exits: 0,
            exit_budget,
            poison: None,
            active_workers: 0,
            live_mappings: 0,
            live_aliases: 0,
            pinned_ranges: 0,
            poisoned_destruction_confirmed: false,
        });
        Ok(VmId::new(index as u32, generation))
    }

    pub fn state(&self, id: VmId) -> Result<VmState, VmError> {
        Ok(self.slot(id)?.state)
    }

    pub fn mark_loaded(&mut self, id: VmId) -> Result<(), VmError> {
        self.transition(id, VmState::Created, VmState::Loaded)
    }

    pub fn start(&mut self, id: VmId) -> Result<(), VmError> {
        let slot = self.slot_mut(id)?;
        if slot.poison.is_some() {
            return Err(VmError::ExecutionPoisoned);
        }
        if !matches!(slot.state, VmState::Loaded | VmState::Stopped) {
            return Err(VmError::InvalidVmState);
        }
        slot.exits = 0;
        slot.state = VmState::Running;
        Ok(())
    }

    pub fn account_exit(&mut self, id: VmId) -> Result<u64, VmError> {
        let slot = self.slot_mut(id)?;
        if slot.state != VmState::Running {
            return Err(VmError::InvalidVmState);
        }
        slot.exits = slot
            .exits
            .checked_add(1)
            .ok_or(VmError::ExitBudgetExceeded)?;
        if slot.exits > slot.exit_budget {
            slot.state = VmState::Failed;
            return Err(VmError::ExitBudgetExceeded);
        }
        Ok(slot.exit_budget - slot.exits)
    }

    pub fn stop(&mut self, id: VmId) -> Result<(), VmError> {
        self.transition(id, VmState::Running, VmState::Stopped)
    }

    pub fn fail(&mut self, id: VmId) -> Result<(), VmError> {
        self.slot_mut(id)?.state = VmState::Failed;
        Ok(())
    }

    pub fn destroy(&mut self, id: VmId) -> Result<(), VmError> {
        let slot = self.slot(id)?;
        if !matches!(
            slot.state,
            VmState::Stopped | VmState::Failed | VmState::Poisoned
        ) || slot.active_workers != 0
            || slot.live_mappings != 0
            || slot.live_aliases != 0
            || slot.pinned_ranges != 0
            || (slot.poison.is_some() && !slot.poisoned_destruction_confirmed)
        {
            return Err(VmError::LifecycleBusy);
        }
        self.slots[id.index()] = None;
        Ok(())
    }

    pub fn poison(&mut self, id: VmId, reason: ExecutionPoisonReason) -> Result<(), VmError> {
        let slot = self.slot_mut(id)?;
        if slot.poison.is_none() {
            slot.poison = Some(reason);
        }
        slot.state = VmState::Poisoned;
        slot.poisoned_destruction_confirmed = false;
        Ok(())
    }

    pub fn poison_reason(&self, id: VmId) -> Result<Option<ExecutionPoisonReason>, VmError> {
        Ok(self.slot(id)?.poison)
    }

    pub fn confirm_poisoned_native_destruction(&mut self, id: VmId) -> Result<(), VmError> {
        let slot = self.slot_mut(id)?;
        if slot.poison.is_none()
            || slot.active_workers != 0
            || slot.live_mappings != 0
            || slot.live_aliases != 0
            || slot.pinned_ranges != 0
        {
            return Err(VmError::LifecycleBusy);
        }
        slot.poisoned_destruction_confirmed = true;
        Ok(())
    }

    pub fn worker_started(&mut self, id: VmId) -> Result<(), VmError> {
        increment(&mut self.slot_mut(id)?.active_workers)
    }
    pub fn worker_retired(&mut self, id: VmId) -> Result<(), VmError> {
        decrement(&mut self.slot_mut(id)?.active_workers)
    }
    pub fn mapping_attached(&mut self, id: VmId) -> Result<(), VmError> {
        increment(&mut self.slot_mut(id)?.live_mappings)
    }
    pub fn mapping_retired(&mut self, id: VmId) -> Result<(), VmError> {
        decrement(&mut self.slot_mut(id)?.live_mappings)
    }
    pub fn alias_attached(&mut self, id: VmId) -> Result<(), VmError> {
        increment(&mut self.slot_mut(id)?.live_aliases)
    }
    pub fn alias_retired(&mut self, id: VmId) -> Result<(), VmError> {
        decrement(&mut self.slot_mut(id)?.live_aliases)
    }
    pub fn range_pinned(&mut self, id: VmId) -> Result<(), VmError> {
        increment(&mut self.slot_mut(id)?.pinned_ranges)
    }
    pub fn range_unpinned(&mut self, id: VmId) -> Result<(), VmError> {
        decrement(&mut self.slot_mut(id)?.pinned_ranges)
    }

    /// Installs a policy mapping and accounts it against the exact VM as one
    /// transaction. Counter failure rolls the mapping back before returning.
    pub fn map_region<const M: usize>(
        &mut self,
        id: VmId,
        memory: &mut GuestMemory<M>,
        region: GuestRegion,
    ) -> Result<GuestMappingId, VmError> {
        self.slot(id)?;
        let mapping = memory.map(region)?;
        if let Err(error) = self.mapping_attached(id) {
            if memory.unmap(mapping).is_err() {
                let _ = self.poison(id, ExecutionPoisonReason::PageTableRemovalUncertain);
            }
            return Err(error);
        }
        Ok(mapping)
    }

    /// Creates and accounts a shared alias. Neither the mapping nor either
    /// lifecycle count becomes observable unless the whole operation commits.
    pub fn map_alias<const M: usize>(
        &mut self,
        id: VmId,
        memory: &mut GuestMemory<M>,
        source: GuestMappingId,
        guest_start: u64,
    ) -> Result<GuestMappingId, VmError> {
        self.slot(id)?;
        let mapping = memory.map_shared_alias(source, guest_start)?;
        if let Err(error) = self.mapping_attached(id) {
            let _ = memory.unmap(mapping);
            return Err(error);
        }
        if let Err(error) = self.alias_attached(id) {
            let _ = self.mapping_retired(id);
            if memory.unmap(mapping).is_err() {
                let _ = self.poison(id, ExecutionPoisonReason::PageTableRemovalUncertain);
            }
            return Err(error);
        }
        Ok(mapping)
    }

    pub fn pin_range<const M: usize>(
        &mut self,
        id: VmId,
        memory: &GuestMemory<M>,
        range: GuestMappedRange,
    ) -> Result<(), VmError> {
        memory.resolve_range(range)?;
        self.range_pinned(id)
    }

    pub fn retire_mapping<const M: usize>(
        &mut self,
        id: VmId,
        memory: &mut GuestMemory<M>,
        mapping: GuestMappingId,
        alias: bool,
    ) -> Result<GuestRegion, VmError> {
        let region = memory.unmap(mapping)?;
        if alias {
            self.alias_retired(id)?;
        }
        self.mapping_retired(id)?;
        Ok(region)
    }

    fn transition(&mut self, id: VmId, from: VmState, to: VmState) -> Result<(), VmError> {
        let slot = self.slot_mut(id)?;
        if slot.state != from {
            return Err(VmError::InvalidVmState);
        }
        slot.state = to;
        Ok(())
    }

    fn slot(&self, id: VmId) -> Result<&VmSlot, VmError> {
        let slot = self
            .slots
            .get(id.index())
            .and_then(Option::as_ref)
            .ok_or(VmError::StaleVm)?;
        (slot.generation == id.generation())
            .then_some(slot)
            .ok_or(VmError::StaleVm)
    }

    fn slot_mut(&mut self, id: VmId) -> Result<&mut VmSlot, VmError> {
        let slot = self
            .slots
            .get_mut(id.index())
            .and_then(Option::as_mut)
            .ok_or(VmError::StaleVm)?;
        (slot.generation == id.generation())
            .then_some(slot)
            .ok_or(VmError::StaleVm)
    }
}

impl<const N: usize> Default for VmTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

fn increment(value: &mut u16) -> Result<(), VmError> {
    *value = value.checked_add(1).ok_or(VmError::ResourceCountOverflow)?;
    Ok(())
}

fn decrement(value: &mut u16) -> Result<(), VmError> {
    *value = value.checked_sub(1).ok_or(VmError::LifecycleBusy)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestAccess {
    Read,
    Write,
    Execute,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestRegion {
    guest_start: u64,
    host_start: PhysAddr,
    pages: u64,
    writable: bool,
    executable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestMappingId(u64);

impl GuestMappingId {
    pub const fn token(self) -> u64 {
        self.0
    }
}

/// Pointer-free description of a range within one exact live guest mapping.
/// Revocation or replacement makes the request stale before consumption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestMappedRange {
    mapping: GuestMappingId,
    offset: u64,
    length: u64,
    access: GuestAccess,
}

impl GuestMappedRange {
    pub const fn mapping(self) -> GuestMappingId {
        self.mapping
    }
    pub const fn offset(self) -> u64 {
        self.offset
    }
    pub const fn length(self) -> u64 {
        self.length
    }
    pub const fn access(self) -> GuestAccess {
        self.access
    }
}

#[derive(Clone, Copy)]
struct GuestMapping {
    id: GuestMappingId,
    region: GuestRegion,
}

impl GuestRegion {
    pub fn new(
        guest_start: u64,
        host_start: PhysAddr,
        pages: u64,
        writable: bool,
        executable: bool,
    ) -> Result<Self, VmError> {
        if pages == 0 {
            return Err(VmError::EmptyRegion);
        }
        if !guest_start.is_multiple_of(PAGE_SIZE) {
            return Err(VmError::Unaligned);
        }
        if writable && executable {
            return Err(VmError::WritableExecutable);
        }
        let length = pages.checked_mul(PAGE_SIZE).ok_or(VmError::Overflow)?;
        guest_start.checked_add(length).ok_or(VmError::Overflow)?;
        host_start
            .get()
            .checked_add(length)
            .ok_or(VmError::Overflow)?;
        Ok(Self {
            guest_start,
            host_start,
            pages,
            writable,
            executable,
        })
    }

    fn length(self) -> u64 {
        self.pages * PAGE_SIZE
    }

    pub const fn host_start(self) -> PhysAddr {
        self.host_start
    }

    pub const fn guest_start(self) -> u64 {
        self.guest_start
    }

    pub const fn pages(self) -> u64 {
        self.pages
    }

    pub const fn is_writable(self) -> bool {
        self.writable
    }

    pub const fn is_executable(self) -> bool {
        self.executable
    }
}

pub struct GuestMemory<const N: usize> {
    mappings: [Option<GuestMapping>; N],
    count: usize,
    next_id: u64,
}

impl<const N: usize> GuestMemory<N> {
    pub const fn new() -> Self {
        Self {
            mappings: [None; N],
            count: 0,
            next_id: 1,
        }
    }

    pub(crate) fn regions(&self) -> impl Iterator<Item = GuestRegion> + '_ {
        self.mappings[..self.count].iter().flatten().map(|mapping| mapping.region)
    }

    pub fn map(&mut self, region: GuestRegion) -> Result<GuestMappingId, VmError> {
        if N > MAX_GUEST_REGIONS || self.count == N {
            return Err(VmError::RegionTableFull);
        }
        let guest_end = region.guest_start + region.length();
        let host_end = region.host_start.get() + region.length();
        for existing in self.mappings[..self.count].iter().flatten().copied() {
            let existing = existing.region;
            if overlaps(
                region.guest_start,
                guest_end,
                existing.guest_start,
                existing.guest_start + existing.length(),
            ) {
                return Err(VmError::GuestOverlap);
            }
            if overlaps(
                region.host_start.get(),
                host_end,
                existing.host_start.get(),
                existing.host_start.get() + existing.length(),
            ) {
                return Err(VmError::HostAlias);
            }
        }
        let at = self.mappings[..self.count].partition_point(|entry| {
            entry.is_some_and(|value| value.region.guest_start < region.guest_start)
        });
        let id = GuestMappingId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(VmError::SequenceExhausted)?;
        self.mappings.copy_within(at..self.count, at + 1);
        self.mappings[at] = Some(GuestMapping { id, region });
        self.count += 1;
        Ok(id)
    }

    /// Creates a second guest mapping identity for one already-live host range.
    /// The caller must bind the returned identity through the same explicit
    /// shared-resource authority that justified the alias; arbitrary host
    /// aliases remain rejected by [`Self::map`].
    pub(crate) fn map_shared_alias(
        &mut self,
        source: GuestMappingId,
        guest_start: u64,
    ) -> Result<GuestMappingId, VmError> {
        if N > MAX_GUEST_REGIONS || self.count == N {
            return Err(VmError::RegionTableFull);
        }
        let source = self.region(source)?;
        let region = GuestRegion::new(
            guest_start,
            source.host_start(),
            source.pages(),
            source.is_writable(),
            source.is_executable(),
        )?;
        let guest_end = region.guest_start + region.length();
        for existing in self.mappings[..self.count].iter().flatten().copied() {
            let existing = existing.region;
            if overlaps(
                region.guest_start,
                guest_end,
                existing.guest_start,
                existing.guest_start + existing.length(),
            ) {
                return Err(VmError::GuestOverlap);
            }
        }
        let at = self.mappings[..self.count].partition_point(|entry| {
            entry.is_some_and(|value| value.region.guest_start < region.guest_start)
        });
        let id = GuestMappingId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(VmError::SequenceExhausted)?;
        self.mappings.copy_within(at..self.count, at + 1);
        self.mappings[at] = Some(GuestMapping { id, region });
        self.count += 1;
        Ok(id)
    }

    pub fn unmap(&mut self, id: GuestMappingId) -> Result<GuestRegion, VmError> {
        let at = self.mappings[..self.count]
            .iter()
            .position(|mapping| mapping.is_some_and(|mapping| mapping.id == id))
            .ok_or(VmError::StaleMapping)?;
        let region = self.mappings[at].unwrap().region;
        self.mappings.copy_within(at + 1..self.count, at);
        self.count -= 1;
        self.mappings[self.count] = None;
        Ok(region)
    }

    /// Returns the exact region represented by a still-live mapping identity.
    /// Mapping identities are never inferred from an address because doing so
    /// could silently rebind an external resource after layout changes.
    pub fn region(&self, id: GuestMappingId) -> Result<GuestRegion, VmError> {
        self.mappings[..self.count]
            .iter()
            .flatten()
            .find(|mapping| mapping.id == id)
            .map(|mapping| mapping.region)
            .ok_or(VmError::StaleMapping)
    }

    pub fn protect(
        &mut self,
        id: GuestMappingId,
        writable: bool,
        executable: bool,
    ) -> Result<(), VmError> {
        if writable && executable {
            return Err(VmError::WritableExecutable);
        }
        let mapping = self.mappings[..self.count]
            .iter_mut()
            .flatten()
            .find(|mapping| mapping.id == id)
            .ok_or(VmError::StaleMapping)?;
        mapping.region.writable = writable;
        mapping.region.executable = executable;
        Ok(())
    }

    pub fn prepare_range(
        &self,
        guest: u64,
        length: u64,
        access: GuestAccess,
    ) -> Result<GuestMappedRange, VmError> {
        if length == 0 {
            return Err(VmError::Unmapped);
        }
        let end = guest.checked_add(length).ok_or(VmError::Overflow)?;
        let mapping = self.mappings[..self.count]
            .iter()
            .flatten()
            .copied()
            .find(|mapping| {
                let region = mapping.region;
                guest >= region.guest_start && end <= region.guest_start + region.length()
            })
            .ok_or(VmError::Unmapped)?;
        let region = mapping.region;
        if (access == GuestAccess::Write && !region.writable)
            || (access == GuestAccess::Execute && !region.executable)
        {
            return Err(VmError::PermissionDenied);
        }
        Ok(GuestMappedRange {
            mapping: mapping.id,
            offset: guest - region.guest_start,
            length,
            access,
        })
    }

    // Kept crate-private for synchronous tool/GPU consumers; current dispatch
    // returns the pointer-free token before either service is implemented.
    #[allow(dead_code)]
    pub(crate) fn resolve_range(&self, range: GuestMappedRange) -> Result<u64, VmError> {
        let region = self.region(range.mapping)?;
        let end = range
            .offset
            .checked_add(range.length)
            .ok_or(VmError::Overflow)?;
        if range.length == 0 || end > region.length() {
            return Err(VmError::Unmapped);
        }
        if (range.access == GuestAccess::Write && !region.writable)
            || (range.access == GuestAccess::Execute && !region.executable)
        {
            return Err(VmError::PermissionDenied);
        }
        let address = region
            .host_start
            .get()
            .checked_add(range.offset)
            .ok_or(VmError::Overflow)?;
        Ok(address)
    }
}

impl<const N: usize> Default for GuestMemory<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum HypercallOperation {
    Yield = 1,
    ToolRequest = 2,
    GpuRequest = 3,
    Shutdown = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hypercall {
    operation: HypercallOperation,
    sequence: u64,
    capability: Capability,
    guest_address: u64,
    length: u32,
    argument: u64,
}

impl Hypercall {
    pub const fn yield_call(sequence: u64) -> Self {
        Self {
            operation: HypercallOperation::Yield,
            sequence,
            capability: Capability::from_token(0),
            guest_address: 0,
            length: 0,
            argument: 0,
        }
    }

    pub const fn shutdown(sequence: u64, capability: Capability) -> Self {
        Self {
            operation: HypercallOperation::Shutdown,
            sequence,
            capability,
            guest_address: 0,
            length: 0,
            argument: 0,
        }
    }

    pub fn request(
        operation: HypercallOperation,
        sequence: u64,
        capability: Capability,
        guest_address: u64,
        length: u32,
        argument: u64,
    ) -> Result<Self, VmError> {
        if !matches!(
            operation,
            HypercallOperation::ToolRequest | HypercallOperation::GpuRequest
        ) || length == 0
        {
            return Err(VmError::MalformedHypercall);
        }
        Ok(Self {
            operation,
            sequence,
            capability,
            guest_address,
            length,
            argument,
        })
    }

    pub fn decode(input: &[u8]) -> Result<Self, VmError> {
        if input.len() != HYPERCALL_BYTES
            || &input[..8] != b"MRMLHC01"
            || input[10..16].iter().any(|byte| *byte != 0)
            || input[52..].iter().any(|byte| *byte != 0)
        {
            return Err(VmError::MalformedHypercall);
        }
        let operation = match read_u16(input, 8) {
            1 => HypercallOperation::Yield,
            2 => HypercallOperation::ToolRequest,
            3 => HypercallOperation::GpuRequest,
            4 => HypercallOperation::Shutdown,
            _ => return Err(VmError::UnsupportedHypercall),
        };
        let length = read_u32(input, 40);
        if matches!(
            operation,
            HypercallOperation::ToolRequest | HypercallOperation::GpuRequest
        ) && length == 0
        {
            return Err(VmError::MalformedHypercall);
        }
        let capability = read_u64(input, 24);
        let guest_address = read_u64(input, 32);
        let argument = read_u64(input, 44);
        if matches!(operation, HypercallOperation::Yield)
            && (capability != 0 || guest_address != 0 || length != 0 || argument != 0)
        {
            return Err(VmError::MalformedHypercall);
        }
        if matches!(operation, HypercallOperation::Shutdown)
            && (guest_address != 0 || length != 0 || argument != 0)
        {
            return Err(VmError::MalformedHypercall);
        }
        Ok(Self {
            operation,
            sequence: read_u64(input, 16),
            capability: Capability::from_token(capability),
            guest_address,
            length,
            argument,
        })
    }

    pub const fn operation(self) -> HypercallOperation {
        self.operation
    }
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    pub const fn guest_address(self) -> u64 {
        self.guest_address
    }
    pub const fn length(self) -> u32 {
        self.length
    }
    pub const fn argument(self) -> u64 {
        self.argument
    }

    pub fn encode(self) -> [u8; HYPERCALL_BYTES] {
        let mut output = [0u8; HYPERCALL_BYTES];
        output[..8].copy_from_slice(b"MRMLHC01");
        output[8..10].copy_from_slice(&(self.operation as u16).to_le_bytes());
        output[16..24].copy_from_slice(&self.sequence.to_le_bytes());
        output[24..32].copy_from_slice(&self.capability.token().to_le_bytes());
        output[32..40].copy_from_slice(&self.guest_address.to_le_bytes());
        output[40..44].copy_from_slice(&self.length.to_le_bytes());
        output[44..52].copy_from_slice(&self.argument.to_le_bytes());
        output
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutedHypercall {
    Yield,
    Tool {
        range: GuestMappedRange,
        argument: u64,
    },
    Gpu {
        range: GuestMappedRange,
        argument: u64,
    },
    Shutdown,
}

/// A bounded, backend-independent description of why a virtual CPU stopped.
/// Platform adapters must reject exits they cannot faithfully translate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmExit {
    Hypercall {
        descriptor_address: u64,
    },
    GuestMemoryFault {
        guest_address: u64,
        access: GuestAccess,
    },
    Io {
        port: u16,
        size: u8,
        write: bool,
        value: u32,
    },
    Mmio {
        guest_address: u64,
        size: u8,
        write: bool,
        value: u64,
    },
    Halted,
    Interrupted,
    Unknown {
        reason: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmRunError<E> {
    Backend(E),
    Policy(VmError),
}

/// Narrow contract implemented by Hyper-V and KVM adapters. Guest memory is
/// copied through fixed-size caller-owned buffers; no backend-owned pointer is
/// allowed to cross into the policy core.
pub trait VmBackend {
    type Error;

    fn run(&mut self, vcpu: u32) -> Result<VmExit, Self::Error>;
    fn read_guest(&self, guest_address: u64, output: &mut [u8]) -> Result<(), Self::Error>;
    fn write_guest(&mut self, guest_address: u64, input: &[u8]) -> Result<(), Self::Error>;
    fn inject_interrupt(&mut self, vcpu: u32, vector: u8) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmDeadlineOutcome {
    Exit(VmExit),
    Expired,
}

/// Backend-neutral contract for one bounded vCPU entry. The backend must arm
/// cancellation before entering the vCPU, must not return until every
/// cancellation worker can no longer access native VM state, and must report
/// expiry even when an ordinary exit races the deadline. A zero deadline is
/// invalid and must cause no vCPU entry.
pub trait DeadlineVmBackend: VmBackend {
    fn run_with_deadline(
        &mut self,
        vcpu: u32,
        maximum_micros: u32,
    ) -> Result<VmDeadlineOutcome, Self::Error>;
}

/// Backend-neutral contract for applying one control-plane-authorized logical
/// CPU decision to a bounded vCPU entry. The backend must bind the runner before
/// guest entry, restore the runner's complete prior affinity before return, and
/// fail closed if either transition is uncertain. The placement is data, not
/// authority; callers must derive it from a live CPU runtime slice.
pub trait AffinityDeadlineVmBackend: DeadlineVmBackend {
    fn run_with_affinity_deadline(
        &mut self,
        vcpu: u32,
        logical_cpu: u8,
        maximum_micros: u32,
    ) -> Result<VmDeadlineOutcome, Self::Error>;
}

/// Applies one backend-neutral priority class already authorized by the CPU
/// control plane together with affinity and deadline enforcement. Priority 0 is
/// the initial host-normal class; unsupported values must fail before entry.
/// Implementations must restore the complete native scheduling state before
/// return and treat uncertain restoration as failure.
pub trait ScheduledDeadlineVmBackend: AffinityDeadlineVmBackend {
    fn run_with_scheduling_deadline(
        &mut self,
        vcpu: u32,
        logical_cpu: u8,
        priority: u8,
        maximum_micros: u32,
    ) -> Result<VmDeadlineOutcome, Self::Error>;
}

/// One backend-observed result from a concurrently scheduled vCPU. Elapsed
/// host-wall time is reported per runner so the CPU control plane can reconcile
/// each independently precharged slice; it is conservative hosted accounting,
/// not trusted guest CPU time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScheduledVcpuOutcome {
    outcome: VmDeadlineOutcome,
    elapsed_micros: u64,
}

impl ScheduledVcpuOutcome {
    pub const fn new(outcome: VmDeadlineOutcome, elapsed_micros: u64) -> Self {
        Self {
            outcome,
            elapsed_micros,
        }
    }

    pub const fn outcome(self) -> VmDeadlineOutcome {
        self.outcome
    }

    pub const fn elapsed_micros(self) -> u64 {
        self.elapsed_micros
    }
}

/// Backend-neutral contract for two concurrent bounded vCPU runners. Each
/// array position is the matching vCPU index. Both native scheduling states
/// must be applied before that runner's first entry and restored only after its
/// run and cancellation worker have retired. Failure or expiry never permits a
/// native fallback or an unbounded sibling runner.
pub trait ScheduledSmpVmBackend: VmBackend {
    fn run_smp_with_scheduling_deadlines(
        &mut self,
        logical_cpus: [u8; 2],
        priorities: [u8; 2],
        maximum_micros: [u32; 2],
    ) -> Result<[ScheduledVcpuOutcome; 2], Self::Error>;
}

/// Backend contract for completing one exact scalar input exit before another
/// vCPU entry. Implementations must bind completion to the still-pending exit's
/// vCPU, port, and width and must not report success after partial register or
/// native run-state mutation.
pub trait IoReadCompleter: VmBackend {
    fn complete_io_read(
        &mut self,
        vcpu: u32,
        port: u16,
        size: u8,
        value: u32,
    ) -> Result<(), Self::Error>;
}

/// Backend contract for retiring one exact MMIO write exit before another
/// vCPU entry. Implementations must bind completion to the still-pending
/// exit's vCPU, guest-physical address, width, and value. A caller may invoke
/// this only after the device path has accepted and durably consumed the
/// operation; failed device processing leaves the VM non-resumable.
pub trait MmioWriteCompleter: VmBackend {
    fn complete_mmio_write(
        &mut self,
        vcpu: u32,
        guest_address: u64,
        size: u8,
        value: u64,
    ) -> Result<(), Self::Error>;
}

/// Backend contract for retiring a complete native second-level mapping.
/// Implementations must prevent every vCPU from running if native teardown
/// fails or leaves the mapping state uncertain.
pub trait RevocableVmBackend: VmBackend {
    fn revoke_guest_mapping(&mut self, guest_address: u64, bytes: u64) -> Result<(), Self::Error>;
}

/// Minimal native mapping-retirement contract shared by hosted VMMs and
/// in-kernel service address spaces.
pub trait GuestMappingRevoker {
    type Error;

    fn revoke_guest_mapping(&mut self, guest_address: u64, bytes: u64) -> Result<(), Self::Error>;
}

impl<B: RevocableVmBackend> GuestMappingRevoker for B {
    type Error = B::Error;

    fn revoke_guest_mapping(&mut self, guest_address: u64, bytes: u64) -> Result<(), Self::Error> {
        RevocableVmBackend::revoke_guest_mapping(self, guest_address, bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingRevocationError<E> {
    Backend(E),
    Policy(VmError),
}

/// Retires native translation before invalidating the policy identity. A
/// backend failure deliberately leaves the policy mapping live so callers can
/// observe that revocation did not complete; the backend is responsible for
/// poisoning further execution when native state may be uncertain.
pub fn revoke_mapping_before_resume<B: GuestMappingRevoker, const N: usize>(
    backend: &mut B,
    memory: &mut GuestMemory<N>,
    id: GuestMappingId,
) -> Result<GuestRegion, MappingRevocationError<B::Error>> {
    let region = memory.region(id).map_err(MappingRevocationError::Policy)?;
    let bytes = region
        .pages()
        .checked_mul(PAGE_SIZE)
        .ok_or(MappingRevocationError::Policy(VmError::Overflow))?;
    backend
        .revoke_guest_mapping(region.guest_start(), bytes)
        .map_err(MappingRevocationError::Backend)?;
    memory.unmap(id).map_err(MappingRevocationError::Policy)
}

/// Production VM-aware retirement path. Native uncertainty poisons execution;
/// policy removal and lifecycle accounting commit only after native withdrawal.
pub fn revoke_tracked_mapping_before_resume<
    B: GuestMappingRevoker,
    const V: usize,
    const N: usize,
>(
    backend: &mut B,
    vms: &mut VmTable<V>,
    vm: VmId,
    memory: &mut GuestMemory<N>,
    id: GuestMappingId,
    alias: bool,
) -> Result<GuestRegion, MappingRevocationError<B::Error>> {
    let region = memory.region(id).map_err(MappingRevocationError::Policy)?;
    let bytes = region
        .pages()
        .checked_mul(PAGE_SIZE)
        .ok_or(MappingRevocationError::Policy(VmError::Overflow))?;
    if let Err(error) = backend.revoke_guest_mapping(region.guest_start(), bytes) {
        let _ = vms.poison(vm, ExecutionPoisonReason::NativeUnmapUncertain);
        return Err(MappingRevocationError::Backend(error));
    }
    vms.retire_mapping(vm, memory, id, alias).map_err(|error| {
        let _ = vms.poison(vm, ExecutionPoisonReason::PageTableRemovalUncertain);
        MappingRevocationError::Policy(error)
    })
}

pub fn decode_hypercall_exit<B: VmBackend>(
    backend: &B,
    exit: VmExit,
) -> Result<Option<Hypercall>, VmRunError<B::Error>> {
    let VmExit::Hypercall { descriptor_address } = exit else {
        return Ok(None);
    };
    let mut wire = [0u8; HYPERCALL_BYTES];
    backend
        .read_guest(descriptor_address, &mut wire)
        .map_err(VmRunError::Backend)?;
    Hypercall::decode(&wire)
        .map(Some)
        .map_err(VmRunError::Policy)
}

pub struct HypercallRouter {
    next_sequence: u64,
    tool_object: ObjectId,
    gpu_object: ObjectId,
    control_object: ObjectId,
}

impl HypercallRouter {
    pub const fn new(
        tool_object: ObjectId,
        gpu_object: ObjectId,
        control_object: ObjectId,
    ) -> Self {
        Self {
            next_sequence: 1,
            tool_object,
            gpu_object,
            control_object,
        }
    }

    pub fn route<const C: usize, const M: usize>(
        &mut self,
        call: Hypercall,
        capabilities: &CapabilitySpace<C>,
        memory: &GuestMemory<M>,
    ) -> Result<RoutedHypercall, VmError> {
        if call.sequence != self.next_sequence {
            return Err(VmError::Replay);
        }
        let routed = match call.operation {
            HypercallOperation::Yield => RoutedHypercall::Yield,
            HypercallOperation::ToolRequest => {
                require_object(
                    capabilities,
                    call.capability,
                    Rights::SIGNAL,
                    self.tool_object,
                )?;
                RoutedHypercall::Tool {
                    range: memory.prepare_range(
                        call.guest_address,
                        call.length as u64,
                        GuestAccess::Read,
                    )?,
                    argument: call.argument,
                }
            }
            HypercallOperation::GpuRequest => {
                require_object(
                    capabilities,
                    call.capability,
                    Rights::SIGNAL,
                    self.gpu_object,
                )?;
                RoutedHypercall::Gpu {
                    range: memory.prepare_range(
                        call.guest_address,
                        call.length as u64,
                        GuestAccess::Read,
                    )?,
                    argument: call.argument,
                }
            }
            HypercallOperation::Shutdown => {
                require_object(
                    capabilities,
                    call.capability,
                    Rights::SIGNAL,
                    self.control_object,
                )?;
                RoutedHypercall::Shutdown
            }
        };
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(VmError::SequenceExhausted)?;
        Ok(routed)
    }
}

fn require_object<const N: usize>(
    capabilities: &CapabilitySpace<N>,
    capability: Capability,
    rights: Rights,
    expected: ObjectId,
) -> Result<(), VmError> {
    let object = capabilities
        .authorize(capability, rights)
        .map_err(VmError::Capability)?;
    (object == expected)
        .then_some(())
        .ok_or(VmError::WrongObject)
}

const fn overlaps(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}
fn read_u16(input: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(input[at..at + 2].try_into().unwrap())
}
fn read_u32(input: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(input[at..at + 4].try_into().unwrap())
}
fn read_u64(input: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(input[at..at + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemoryBackend {
        wire: [u8; HYPERCALL_BYTES],
        base: u64,
    }

    impl VmBackend for MemoryBackend {
        type Error = ();

        fn run(&mut self, _vcpu: u32) -> Result<VmExit, Self::Error> {
            Ok(VmExit::Hypercall {
                descriptor_address: self.base,
            })
        }

        fn read_guest(&self, guest_address: u64, output: &mut [u8]) -> Result<(), Self::Error> {
            if guest_address != self.base || output.len() != self.wire.len() {
                return Err(());
            }
            output.copy_from_slice(&self.wire);
            Ok(())
        }

        fn write_guest(&mut self, _guest_address: u64, _input: &[u8]) -> Result<(), Self::Error> {
            Err(())
        }

        fn inject_interrupt(&mut self, _vcpu: u32, _vector: u8) -> Result<(), Self::Error> {
            Err(())
        }
    }

    struct RevocationBackend {
        fail: bool,
        request: Option<(u64, u64)>,
    }

    impl VmBackend for RevocationBackend {
        type Error = ();
        fn run(&mut self, _vcpu: u32) -> Result<VmExit, Self::Error> {
            Err(())
        }
        fn read_guest(&self, _address: u64, _output: &mut [u8]) -> Result<(), Self::Error> {
            Err(())
        }
        fn write_guest(&mut self, _address: u64, _input: &[u8]) -> Result<(), Self::Error> {
            Err(())
        }
        fn inject_interrupt(&mut self, _vcpu: u32, _vector: u8) -> Result<(), Self::Error> {
            Err(())
        }
    }

    impl RevocableVmBackend for RevocationBackend {
        fn revoke_guest_mapping(&mut self, address: u64, bytes: u64) -> Result<(), Self::Error> {
            self.request = Some((address, bytes));
            if self.fail { Err(()) } else { Ok(()) }
        }
    }

    struct ServiceMappingRevoker(Option<(u64, u64)>);

    impl GuestMappingRevoker for ServiceMappingRevoker {
        type Error = ();

        fn revoke_guest_mapping(&mut self, address: u64, bytes: u64) -> Result<(), Self::Error> {
            self.0 = Some((address, bytes));
            Ok(())
        }
    }

    #[test]
    fn guest_memory_rejects_aliases_crossings_and_wx() {
        assert_eq!(
            GuestRegion::new(0, PhysAddr::new(0).unwrap(), 1, true, true),
            Err(VmError::WritableExecutable)
        );
        let mut memory = GuestMemory::<3>::new();
        memory
            .map(GuestRegion::new(0x1000, PhysAddr::new(0x9000).unwrap(), 2, true, false).unwrap())
            .unwrap();
        let range = memory.prepare_range(0x1ff0, 32, GuestAccess::Read).unwrap();
        assert_eq!(memory.resolve_range(range), Ok(0x9ff0));
        assert_eq!(
            memory.prepare_range(0x2ff0, 32, GuestAccess::Read),
            Err(VmError::Unmapped)
        );
        assert_eq!(
            memory.map(
                GuestRegion::new(0x4000, PhysAddr::new(0xa000).unwrap(), 1, false, true).unwrap()
            ),
            Err(VmError::HostAlias)
        );
    }

    #[test]
    fn guest_mappings_are_revocable_and_permissions_are_wx_safe() {
        let mut memory = GuestMemory::<2>::new();
        let id = memory
            .map(GuestRegion::new(0x1000, PhysAddr::new(0x8000).unwrap(), 1, true, false).unwrap())
            .unwrap();
        let writable = memory.prepare_range(0x1000, 1, GuestAccess::Write).unwrap();
        assert_eq!(memory.resolve_range(writable), Ok(0x8000));
        memory.protect(id, false, true).unwrap();
        assert_eq!(
            memory.resolve_range(writable),
            Err(VmError::PermissionDenied)
        );
        let executable = memory
            .prepare_range(0x1000, 1, GuestAccess::Execute)
            .unwrap();
        assert_eq!(memory.resolve_range(executable), Ok(0x8000));
        assert_eq!(
            memory.protect(id, true, true),
            Err(VmError::WritableExecutable)
        );
        memory.unmap(id).unwrap();
        assert_eq!(memory.resolve_range(executable), Err(VmError::StaleMapping));
        assert_eq!(memory.unmap(id), Err(VmError::StaleMapping));
    }

    #[test]
    fn native_revocation_precedes_policy_identity_retirement() {
        let mut memory = GuestMemory::<1>::new();
        let id = memory
            .map(GuestRegion::new(0x4000, PhysAddr::new(0x9000).unwrap(), 2, true, false).unwrap())
            .unwrap();
        let mut backend = RevocationBackend {
            fail: false,
            request: None,
        };
        let region = revoke_mapping_before_resume(&mut backend, &mut memory, id).unwrap();
        assert_eq!(backend.request, Some((0x4000, 2 * PAGE_SIZE)));
        assert_eq!(region.guest_start(), 0x4000);
        assert_eq!(memory.region(id), Err(VmError::StaleMapping));
    }

    #[test]
    fn failed_native_revocation_preserves_policy_identity() {
        let mut memory = GuestMemory::<1>::new();
        let id = memory
            .map(GuestRegion::new(0x7000, PhysAddr::new(0xb000).unwrap(), 1, false, true).unwrap())
            .unwrap();
        let mut backend = RevocationBackend {
            fail: true,
            request: None,
        };
        assert_eq!(
            revoke_mapping_before_resume(&mut backend, &mut memory, id),
            Err(MappingRevocationError::Backend(()))
        );
        assert_eq!(backend.request, Some((0x7000, PAGE_SIZE)));
        assert_eq!(memory.region(id).unwrap().guest_start(), 0x7000);
    }

    #[test]
    fn shared_alias_has_independent_identity_but_exact_same_host_range() {
        let mut memory = GuestMemory::<2>::new();
        let source = memory
            .map(GuestRegion::new(0x4000, PhysAddr::new(0x9000).unwrap(), 1, true, false).unwrap())
            .unwrap();
        let alias = memory.map_shared_alias(source, 0x6000).unwrap();
        assert_ne!(source, alias);
        assert_eq!(memory.region(alias).unwrap().host_start().get(), 0x9000);
        assert_eq!(memory.region(alias).unwrap().guest_start(), 0x6000);
        assert_eq!(
            memory.map_shared_alias(source, 0x6000),
            Err(VmError::RegionTableFull)
        );
        assert_eq!(memory.unmap(alias).unwrap().guest_start(), 0x6000);
        assert_eq!(memory.region(source).unwrap().guest_start(), 0x4000);
    }

    #[test]
    fn policy_retirement_accepts_a_service_mapping_revoker_without_vmm_access() {
        let mut memory = GuestMemory::<1>::new();
        let id = memory
            .map(GuestRegion::new(0x9000, PhysAddr::new(0xc000).unwrap(), 1, true, false).unwrap())
            .unwrap();
        let mut revoker = ServiceMappingRevoker(None);
        assert!(revoke_mapping_before_resume(&mut revoker, &mut memory, id).is_ok());
        assert_eq!(revoker.0, Some((0x9000, PAGE_SIZE)));
        assert_eq!(memory.region(id), Err(VmError::StaleMapping));
    }

    #[test]
    fn partial_native_unmap_failure_poisons_execution_and_blocks_destruction() {
        let mut table = VmTable::<1>::new();
        let vm = table.create(4).unwrap();
        table.mark_loaded(vm).unwrap();
        let mut memory = GuestMemory::<1>::new();
        let mapping = table
            .map_region(
                vm,
                &mut memory,
                GuestRegion::new(0x9000, PhysAddr::new(0x20_000).unwrap(), 1, true, false).unwrap(),
            )
            .unwrap();
        let mut backend = RevocationBackend {
            fail: true,
            request: None,
        };

        assert_eq!(
            revoke_tracked_mapping_before_resume(
                &mut backend,
                &mut table,
                vm,
                &mut memory,
                mapping,
                false,
            ),
            Err(MappingRevocationError::Backend(()))
        );
        assert_eq!(
            table.poison_reason(vm),
            Ok(Some(ExecutionPoisonReason::NativeUnmapUncertain))
        );
        assert_eq!(table.start(vm), Err(VmError::ExecutionPoisoned));
        assert_eq!(table.destroy(vm), Err(VmError::LifecycleBusy));
        assert!(memory.region(mapping).is_ok());
    }

    #[test]
    fn tracked_mapping_alias_and_range_counts_gate_real_resource_operations() {
        let mut table = VmTable::<1>::new();
        let vm = table.create(4).unwrap();
        table.mark_loaded(vm).unwrap();
        let mut memory = GuestMemory::<2>::new();
        let mapping = table
            .map_region(
                vm,
                &mut memory,
                GuestRegion::new(0x1000, PhysAddr::new(0x8000).unwrap(), 1, true, false).unwrap(),
            )
            .unwrap();
        let alias = table.map_alias(vm, &mut memory, mapping, 0x3000).unwrap();
        let range = memory.prepare_range(0x3000, 16, GuestAccess::Read).unwrap();
        table.pin_range(vm, &memory, range).unwrap();
        table.start(vm).unwrap();
        table.stop(vm).unwrap();

        assert_eq!(table.destroy(vm), Err(VmError::LifecycleBusy));
        table.range_unpinned(vm).unwrap();
        table.retire_mapping(vm, &mut memory, alias, true).unwrap();
        table
            .retire_mapping(vm, &mut memory, mapping, false)
            .unwrap();
        table.destroy(vm).unwrap();
    }

    fn loaded_vm() -> (VmTable<1>, VmId) {
        let mut table = VmTable::<1>::new();
        let vm = table.create(4).unwrap();
        table.mark_loaded(vm).unwrap();
        (table, vm)
    }

    #[test]
    fn injected_cancel_failure_permanently_blocks_guest_execution() {
        let (mut table, vm) = loaded_vm();
        table
            .poison(vm, ExecutionPoisonReason::VcpuRetirementUncertain)
            .unwrap();
        assert_eq!(table.start(vm), Err(VmError::ExecutionPoisoned));
        assert_eq!(table.destroy(vm), Err(VmError::LifecycleBusy));
    }

    #[test]
    fn injected_join_failure_retains_worker_and_blocks_resource_destruction() {
        let (mut table, vm) = loaded_vm();
        table.worker_started(vm).unwrap();
        table
            .poison(vm, ExecutionPoisonReason::VcpuRetirementUncertain)
            .unwrap();
        assert_eq!(table.destroy(vm), Err(VmError::LifecycleBusy));
        assert_eq!(table.start(vm), Err(VmError::ExecutionPoisoned));
    }

    #[test]
    fn injected_worker_timeout_cannot_resume_or_destroy_live_worker_state() {
        let (mut table, vm) = loaded_vm();
        table.worker_started(vm).unwrap();
        table
            .poison(vm, ExecutionPoisonReason::VcpuRetirementUncertain)
            .unwrap();
        assert_eq!(table.start(vm), Err(VmError::ExecutionPoisoned));
        assert_eq!(table.destroy(vm), Err(VmError::LifecycleBusy));
    }

    #[test]
    fn injected_peer_withdrawal_failure_poisons_both_guests() {
        let (mut first, first_vm) = loaded_vm();
        let (mut second, second_vm) = loaded_vm();
        first
            .poison(first_vm, ExecutionPoisonReason::PeerWithdrawalUncertain)
            .unwrap();
        second
            .poison(second_vm, ExecutionPoisonReason::PeerWithdrawalUncertain)
            .unwrap();
        assert_eq!(first.start(first_vm), Err(VmError::ExecutionPoisoned));
        assert_eq!(second.start(second_vm), Err(VmError::ExecutionPoisoned));
        assert_eq!(first.destroy(first_vm), Err(VmError::LifecycleBusy));
        assert_eq!(second.destroy(second_vm), Err(VmError::LifecycleBusy));
    }

    #[test]
    fn injected_mapping_rollback_failure_keeps_mapping_and_destruction_blocked() {
        let (mut table, vm) = loaded_vm();
        table.mapping_attached(vm).unwrap();
        table
            .poison(vm, ExecutionPoisonReason::PageTableRemovalUncertain)
            .unwrap();
        assert_eq!(table.start(vm), Err(VmError::ExecutionPoisoned));
        assert_eq!(table.destroy(vm), Err(VmError::LifecycleBusy));
    }

    #[test]
    fn destruction_attempted_during_active_execution_is_rejected() {
        let (mut table, vm) = loaded_vm();
        table.start(vm).unwrap();
        table.worker_started(vm).unwrap();
        assert_eq!(table.destroy(vm), Err(VmError::LifecycleBusy));
        assert_eq!(table.state(vm), Ok(VmState::Running));
    }

    #[test]
    fn routing_requires_exact_sequence_capability_object_and_mapping() {
        let tool = ObjectId(11);
        let gpu = ObjectId(12);
        let control = ObjectId(13);
        let mut capabilities = CapabilitySpace::<4>::new();
        let tool_cap = capabilities.insert(tool, Rights::SIGNAL).unwrap();
        let gpu_cap = capabilities.insert(gpu, Rights::SIGNAL).unwrap();
        let mut memory = GuestMemory::<1>::new();
        let mapping = memory
            .map(GuestRegion::new(0x2000, PhysAddr::new(0x8000).unwrap(), 1, false, false).unwrap())
            .unwrap();
        let mut router = HypercallRouter::new(tool, gpu, control);
        let call = Hypercall {
            operation: HypercallOperation::ToolRequest,
            sequence: 1,
            capability: tool_cap,
            guest_address: 0x2080,
            length: 32,
            argument: 7,
        };
        let encoded = call.encode();
        let decoded = Hypercall::decode(&encoded).unwrap();
        assert_eq!(
            router.route(decoded, &capabilities, &memory),
            Ok(RoutedHypercall::Tool {
                range: GuestMappedRange {
                    mapping,
                    offset: 0x80,
                    length: 32,
                    access: GuestAccess::Read
                },
                argument: 7
            })
        );
        assert_eq!(
            router.route(decoded, &capabilities, &memory),
            Err(VmError::Replay)
        );
        let wrong = Hypercall {
            operation: HypercallOperation::ToolRequest,
            sequence: 2,
            capability: gpu_cap,
            ..call
        };
        assert_eq!(
            router.route(wrong, &capabilities, &memory),
            Err(VmError::WrongObject)
        );
    }

    #[test]
    fn decoder_rejects_reserved_bytes_unknown_operations_and_empty_requests() {
        let cap = Capability::from_token(1u64 << 32);
        let call = Hypercall {
            operation: HypercallOperation::GpuRequest,
            sequence: 1,
            capability: cap,
            guest_address: 0x1000,
            length: 1,
            argument: 0,
        };
        let mut encoded = call.encode();
        encoded[63] = 1;
        assert_eq!(
            Hypercall::decode(&encoded),
            Err(VmError::MalformedHypercall)
        );
        encoded = call.encode();
        encoded[8..10].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            Hypercall::decode(&encoded),
            Err(VmError::UnsupportedHypercall)
        );
        encoded = call.encode();
        encoded[40..44].fill(0);
        assert_eq!(
            Hypercall::decode(&encoded),
            Err(VmError::MalformedHypercall)
        );

        let yield_call = Hypercall {
            operation: HypercallOperation::Yield,
            sequence: 1,
            capability: cap,
            guest_address: 0,
            length: 0,
            argument: 0,
        };
        assert_eq!(
            Hypercall::decode(&yield_call.encode()),
            Err(VmError::MalformedHypercall)
        );
    }

    #[test]
    fn failed_authorization_does_not_consume_sequence() {
        let tool = ObjectId(1);
        let wrong = ObjectId(2);
        let mut capabilities = CapabilitySpace::<2>::new();
        let wrong_cap = capabilities.insert(wrong, Rights::SIGNAL).unwrap();
        let right_cap = capabilities.insert(tool, Rights::SIGNAL).unwrap();
        let mut memory = GuestMemory::<1>::new();
        let mapping = memory
            .map(GuestRegion::new(0x1000, PhysAddr::new(0x8000).unwrap(), 1, false, false).unwrap())
            .unwrap();
        let mut router = HypercallRouter::new(tool, ObjectId(3), ObjectId(4));
        let base = Hypercall {
            operation: HypercallOperation::ToolRequest,
            sequence: 1,
            capability: wrong_cap,
            guest_address: 0x1000,
            length: 1,
            argument: 0,
        };
        assert_eq!(
            router.route(base, &capabilities, &memory),
            Err(VmError::WrongObject)
        );
        assert_eq!(
            router.route(
                Hypercall {
                    capability: right_cap,
                    ..base
                },
                &capabilities,
                &memory
            ),
            Ok(RoutedHypercall::Tool {
                range: GuestMappedRange {
                    mapping,
                    offset: 0,
                    length: 1,
                    access: GuestAccess::Read
                },
                argument: 0
            })
        );
    }

    #[test]
    fn prepared_range_cannot_rebind_after_revocation_and_replacement() {
        let mut memory = GuestMemory::<1>::new();
        let original = memory
            .map(GuestRegion::new(0x1000, PhysAddr::new(0x8000).unwrap(), 1, true, false).unwrap())
            .unwrap();
        let request = memory.prepare_range(0x1080, 32, GuestAccess::Read).unwrap();
        memory.unmap(original).unwrap();
        let replacement = memory
            .map(GuestRegion::new(0x1000, PhysAddr::new(0xa000).unwrap(), 1, true, false).unwrap())
            .unwrap();
        assert_ne!(original, replacement);
        assert_eq!(memory.resolve_range(request), Err(VmError::StaleMapping));
    }

    #[test]
    fn backend_exit_copies_and_decodes_a_fixed_descriptor() {
        let call = Hypercall {
            operation: HypercallOperation::Yield,
            sequence: 1,
            capability: Capability::from_token(0),
            guest_address: 0,
            length: 0,
            argument: 0,
        };
        let backend = MemoryBackend {
            wire: call.encode(),
            base: 0x4000,
        };
        assert_eq!(
            decode_hypercall_exit(
                &backend,
                VmExit::Hypercall {
                    descriptor_address: 0x4000
                }
            ),
            Ok(Some(call))
        );
        assert_eq!(decode_hypercall_exit(&backend, VmExit::Halted), Ok(None));
        assert_eq!(
            decode_hypercall_exit(
                &backend,
                VmExit::Hypercall {
                    descriptor_address: 0x5000
                }
            ),
            Err(VmRunError::Backend(()))
        );
    }

    #[test]
    fn lifecycle_rejects_stale_ids_and_invalid_transitions() {
        let mut table = VmTable::<1>::new();
        let first = table.create(2).unwrap();
        assert_eq!(table.start(first), Err(VmError::InvalidVmState));
        table.mark_loaded(first).unwrap();
        table.start(first).unwrap();
        assert_eq!(table.account_exit(first), Ok(1));
        table.stop(first).unwrap();
        table.destroy(first).unwrap();
        let replacement = table.create(1).unwrap();
        assert_ne!(first.token(), replacement.token());
        assert_eq!(table.state(first), Err(VmError::StaleVm));
    }

    #[test]
    fn exit_budget_fail_stops_a_running_vm() {
        let mut table = VmTable::<1>::new();
        let id = table.create(1).unwrap();
        table.mark_loaded(id).unwrap();
        table.start(id).unwrap();
        assert_eq!(table.account_exit(id), Ok(0));
        assert_eq!(table.account_exit(id), Err(VmError::ExitBudgetExceeded));
        assert_eq!(table.state(id), Ok(VmState::Failed));
        assert_eq!(table.start(id), Err(VmError::InvalidVmState));
    }

    #[test]
    fn poison_is_irreversible_and_destruction_requires_retired_resources() {
        let mut table = VmTable::<1>::new();
        let id = table.create(2).unwrap();
        table.mark_loaded(id).unwrap();
        table.start(id).unwrap();
        table.worker_started(id).unwrap();
        table.mapping_attached(id).unwrap();
        table.alias_attached(id).unwrap();
        table.range_pinned(id).unwrap();
        table
            .poison(id, ExecutionPoisonReason::NativeUnmapUncertain)
            .unwrap();
        assert_eq!(table.start(id), Err(VmError::ExecutionPoisoned));
        table
            .poison(id, ExecutionPoisonReason::BackendStateMismatch)
            .unwrap();
        assert_eq!(
            table.poison_reason(id),
            Ok(Some(ExecutionPoisonReason::NativeUnmapUncertain))
        );
        assert_eq!(table.destroy(id), Err(VmError::LifecycleBusy));
        table.range_unpinned(id).unwrap();
        table.alias_retired(id).unwrap();
        table.mapping_retired(id).unwrap();
        table.worker_retired(id).unwrap();
        assert_eq!(table.destroy(id), Err(VmError::LifecycleBusy));
        table.confirm_poisoned_native_destruction(id).unwrap();
        table.destroy(id).unwrap();
        assert_eq!(table.state(id), Err(VmError::StaleVm));
    }

    #[test]
    fn destruction_rejects_running_vm_and_counter_underflow() {
        let mut table = VmTable::<1>::new();
        let id = table.create(1).unwrap();
        table.mark_loaded(id).unwrap();
        table.start(id).unwrap();
        assert_eq!(table.destroy(id), Err(VmError::LifecycleBusy));
        assert_eq!(table.worker_retired(id), Err(VmError::LifecycleBusy));
        table.stop(id).unwrap();
        table.destroy(id).unwrap();
    }

    #[test]
    fn scheduled_vcpu_outcome_retains_exact_runner_measurement() {
        let exit = VmExit::Io {
            port: 0x4d5c,
            size: 4,
            write: true,
            value: 2,
        };
        let outcome = ScheduledVcpuOutcome::new(VmDeadlineOutcome::Exit(exit), 4_321);
        assert_eq!(outcome.outcome(), VmDeadlineOutcome::Exit(exit));
        assert_eq!(outcome.elapsed_micros(), 4_321);
    }
}
