//! Backend-neutral PCI Type-0 configuration-state foundation.
//!
//! This module does not assign MRML a PCI identity and does not attach a PCI
//! function to a guest. It bounds the configuration mechanics needed before a
//! concrete VMM transport can do so. Configuration values are routing data;
//! native mappings, interrupts, DMA, and device authority remain separate.

pub const PCI_TYPE0_CONFIGURATION_BYTES: usize = 64;
pub const MAX_VIRTUAL_PCI_FUNCTIONS: usize = 8;
pub const PCI_CONFIGURATION_ADDRESS_PORT: u16 = 0x0cf8;
pub const PCI_CONFIGURATION_DATA_PORT: u16 = 0x0cfc;
pub const PCI_CONFIGURATION_IO_RULES: usize = 8;
pub const PCI_COMMAND_MEMORY_SPACE: u16 = 1 << 1;
pub const PCI_COMMAND_INTERRUPT_DISABLE: u16 = 1 << 10;
const PCI_COMMAND_SUPPORTED: u16 = PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_INTERRUPT_DISABLE;
const PCI_BAR_MEMORY_ADDRESS_MASK: u32 = 0xffff_fff0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualPciError {
    InvalidIdentity,
    InvalidBar,
    InvalidAccess,
    ReadOnly,
    UnsupportedCommand,
    InvalidState,
    StaleGeneration,
    GenerationExhausted,
    InvalidLocation,
    DuplicateLocation,
    CapacityExhausted,
    FunctionNotPresent,
    StaleAttachment,
    InvalidTransport,
    NativeResourceRejected,
    NativeResourceUncertain,
}

/// Exact segment/bus/device/function location. This identifies a routed
/// function but grants no configuration, mapping, interrupt, or device
/// authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualPciLocation {
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
}

impl VirtualPciLocation {
    pub fn new(segment: u16, bus: u8, device: u8, function: u8) -> Result<Self, VirtualPciError> {
        if device > 31 || function > 7 {
            return Err(VirtualPciError::InvalidLocation);
        }
        Ok(Self {
            segment,
            bus,
            device,
            function,
        })
    }

    pub const fn segment(self) -> u16 {
        self.segment
    }

    pub const fn bus(self) -> u8 {
        self.bus
    }

    pub const fn device(self) -> u8 {
        self.device
    }

    pub const fn function(self) -> u8 {
        self.function
    }
}

/// Host-side lifetime identity for one exact router slot. Possession is not a
/// capability; callers must already hold mutable access to the trusted router.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualPciAttachmentId {
    slot: u8,
    generation: u32,
}

/// Exact public identity of the attached configuration generation whose native
/// mappings, interrupts, DMA, queues, and device state must be retired before
/// configuration reset. This value identifies cleanup work; it grants no
/// authority by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualPciAttachedResources {
    attachment: VirtualPciAttachmentId,
    location: VirtualPciLocation,
    function_generation: u32,
    mmio_window: Option<VirtualPciMmioWindow>,
    command: u16,
}

/// Read-only description of one exact routed function generation. This is
/// trusted router state but still carries no authority to use the function or
/// any backend resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualPciAttachedFunction {
    resources: VirtualPciAttachedResources,
    identity: VirtualPciIdentity,
}

impl VirtualPciAttachedFunction {
    pub const fn resources(self) -> VirtualPciAttachedResources {
        self.resources
    }

    pub const fn identity(self) -> VirtualPciIdentity {
        self.identity
    }
}

impl VirtualPciAttachedResources {
    pub const fn attachment(self) -> VirtualPciAttachmentId {
        self.attachment
    }

    pub const fn location(self) -> VirtualPciLocation {
        self.location
    }

    pub const fn function_generation(self) -> u32 {
        self.function_generation
    }

    pub const fn mmio_window(self) -> Option<VirtualPciMmioWindow> {
        self.mmio_window
    }

    /// Current command-register data for this exact routed generation. This
    /// describes decode and interrupt masking; it grants neither authority.
    pub const fn command(self) -> u16 {
        self.command
    }
}

/// Failure from attached reset or detach composition. Configuration failures
/// occur before cleanup. A revocation failure preserves the complete
/// configuration state and must quarantine or fail the VM rather than resume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualPciResetError<E> {
    Configuration(VirtualPciError),
    Revocation(E),
}

/// Native cleanup boundary for one attached PCI function generation.
///
/// # Safety
///
/// Success must mean every mapping, interrupt, DMA binding, queue, cached
/// decision, device state, and derived handle associated with `resources` can
/// no longer be used. An implementation must return an error if cleanup is
/// partial or uncertain.
pub unsafe trait VirtualPciFunctionRevoker {
    type Error;

    fn revoke_function(
        &mut self,
        resources: VirtualPciAttachedResources,
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualPciNativeResourceError {
    /// The operation made no native-state change.
    Rejected,
    /// Native state may have changed partially or cannot be proven.
    Uncertain,
}

/// Native BAR mapping boundary for one exact attached function generation.
///
/// # Safety
///
/// `map_window` may succeed only when the complete assigned window is mapped
/// with the intended device semantics. `unmap_window` may succeed only when no
/// native mapping for that exact window remains usable. Partial or unknown
/// state must return `Uncertain`; callers must then quarantine or fail the VM.
pub unsafe trait VirtualPciMemoryMapper {
    fn map_window(
        &mut self,
        resources: VirtualPciAttachedResources,
    ) -> Result<(), VirtualPciNativeResourceError>;

    fn unmap_window(
        &mut self,
        resources: VirtualPciAttachedResources,
    ) -> Result<(), VirtualPciNativeResourceError>;
}

/// Native BAR mapping boundary that must mutate the same stopped backend whose
/// configuration exit is being retired.
///
/// # Safety
///
/// The mapper has the obligations of [`VirtualPciMemoryMapper`] and may use
/// `backend` only for the exact transition described by `resources`. Success
/// must leave backend translation state coherent before decode is published.
pub unsafe trait VirtualPciBackendMemoryMapper<B> {
    fn map_window(
        &mut self,
        backend: &mut B,
        resources: VirtualPciAttachedResources,
    ) -> Result<(), VirtualPciNativeResourceError>;

    fn unmap_window(
        &mut self,
        backend: &mut B,
        resources: VirtualPciAttachedResources,
    ) -> Result<(), VirtualPciNativeResourceError>;
}

struct DenyVirtualPciMemoryMapper;

unsafe impl VirtualPciMemoryMapper for DenyVirtualPciMemoryMapper {
    fn map_window(
        &mut self,
        _resources: VirtualPciAttachedResources,
    ) -> Result<(), VirtualPciNativeResourceError> {
        Err(VirtualPciNativeResourceError::Rejected)
    }

    fn unmap_window(
        &mut self,
        _resources: VirtualPciAttachedResources,
    ) -> Result<(), VirtualPciNativeResourceError> {
        Err(VirtualPciNativeResourceError::Uncertain)
    }
}

impl VirtualPciAttachmentId {
    pub const fn generation(self) -> u32 {
        self.generation
    }
}

/// Externally assigned PCI identity and class data. Construction validates
/// representation only; it does not prove registration, ownership, or device
/// authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualPciIdentity {
    vendor: u16,
    device: u16,
    revision: u8,
    programming_interface: u8,
    subclass: u8,
    class: u8,
    subsystem_vendor: u16,
    subsystem: u16,
}

impl VirtualPciIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vendor: u16,
        device: u16,
        revision: u8,
        programming_interface: u8,
        subclass: u8,
        class: u8,
        subsystem_vendor: u16,
        subsystem: u16,
    ) -> Result<Self, VirtualPciError> {
        if matches!(vendor, 0 | u16::MAX) || class == u8::MAX {
            return Err(VirtualPciError::InvalidIdentity);
        }
        Ok(Self {
            vendor,
            device,
            revision,
            programming_interface,
            subclass,
            class,
            subsystem_vendor,
            subsystem,
        })
    }

    pub const fn vendor(self) -> u16 {
        self.vendor
    }

    pub const fn device(self) -> u16 {
        self.device
    }

    pub const fn class(self) -> u8 {
        self.class
    }

    pub const fn subclass(self) -> u8 {
        self.subclass
    }

    pub const fn programming_interface(self) -> u8 {
        self.programming_interface
    }
}

/// One 32-bit, non-prefetchable memory BAR. The address is guest-selected
/// routing data; accepting it never creates a host mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualPciMemoryBar {
    size: u32,
    address: u32,
    probing: bool,
}

impl VirtualPciMemoryBar {
    pub fn new(size: u32) -> Result<Self, VirtualPciError> {
        if size < 16 || !size.is_power_of_two() {
            return Err(VirtualPciError::InvalidBar);
        }
        Ok(Self {
            size,
            address: 0,
            probing: false,
        })
    }

    pub const fn size(self) -> u32 {
        self.size
    }

    pub const fn address(self) -> u32 {
        self.address
    }

    const fn value(self) -> u32 {
        if self.probing {
            !(self.size - 1) & PCI_BAR_MEMORY_ADDRESS_MASK
        } else {
            self.address
        }
    }

    fn write(&mut self, value: u32) -> VirtualPciWriteOutcome {
        if value == u32::MAX {
            self.probing = true;
            return VirtualPciWriteOutcome::BarProbe;
        }
        self.probing = false;
        self.address = value & !(self.size - 1) & PCI_BAR_MEMORY_ADDRESS_MASK;
        VirtualPciWriteOutcome::BarAddress(self.address)
    }

    fn reset(&mut self) {
        self.address = 0;
        self.probing = false;
    }
}

/// Exact guest-selected MMIO window for one configuration generation. This is
/// routing data, not a mapping capability or proof that native mapping exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualPciMmioWindow {
    generation: u32,
    address: u32,
    size: u32,
}

impl VirtualPciMmioWindow {
    pub const fn generation(self) -> u32 {
        self.generation
    }

    pub const fn address(self) -> u32 {
        self.address
    }

    pub const fn size(self) -> u32 {
        self.size
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualPciWriteOutcome {
    Command(u16),
    BarProbe,
    BarAddress(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualPciIoOutcome {
    AddressRegister(u32),
    Read(u32),
    Write(VirtualPciWriteOutcome),
    AbsentRead(u32),
    AbsentWrite,
}

#[derive(Debug, Eq, PartialEq)]
pub enum VirtualPciRunError<E> {
    Policy(crate::VmError),
    Exit(crate::VmRunError<E>),
    Transport(VirtualPciError),
    Completion(E),
    InvalidExit,
}

/// Minimal conventional Type-0 header state. It intentionally has no
/// capability list, MSI/MSI-X, bus mastering, expansion ROM, legacy interrupt
/// pin, or additional BARs.
pub struct VirtualPciType0Function {
    identity: VirtualPciIdentity,
    generation: u32,
    command: u16,
    bar0: VirtualPciMemoryBar,
}

struct VirtualPciAttachment {
    location: VirtualPciLocation,
    function: VirtualPciType0Function,
}

/// Fixed-capacity backend-neutral configuration router. Native KVM/WHP exit
/// decoding remains outside this type; callers present an already decoded
/// exact location, offset, width, and value.
pub struct VirtualPciConfigurationRouter {
    slots: [Option<VirtualPciAttachment>; MAX_VIRTUAL_PCI_FUNCTIONS],
    generations: [u32; MAX_VIRTUAL_PCI_FUNCTIONS],
}

/// Conventional PCI Configuration Mechanism #1 selector/data-port state. This
/// decodes guest scalar I/O only; it neither authorizes the I/O exit nor grants
/// authority to any function selected by the address register.
pub struct VirtualPciConfigurationMechanismOne {
    address: u32,
}

impl Default for VirtualPciConfigurationMechanismOne {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualPciConfigurationMechanismOne {
    pub const fn new() -> Self {
        Self { address: 0 }
    }

    pub const fn address(&self) -> u32 {
        self.address
    }

    pub fn io_policy() -> Result<crate::IoPortPolicy<PCI_CONFIGURATION_IO_RULES>, crate::VmError> {
        let mut policy = crate::IoPortPolicy::deny_all();
        policy.allow(crate::IoPortRule::new(
            PCI_CONFIGURATION_ADDRESS_PORT,
            4,
            crate::IoDirection::Both,
        )?)?;
        for (port, size) in [
            (PCI_CONFIGURATION_DATA_PORT, 1),
            (PCI_CONFIGURATION_DATA_PORT, 2),
            (PCI_CONFIGURATION_DATA_PORT, 4),
            (PCI_CONFIGURATION_DATA_PORT + 1, 1),
            (PCI_CONFIGURATION_DATA_PORT + 2, 1),
            (PCI_CONFIGURATION_DATA_PORT + 2, 2),
            (PCI_CONFIGURATION_DATA_PORT + 3, 1),
        ] {
            policy.allow(crate::IoPortRule::new(
                port,
                size,
                crate::IoDirection::Both,
            )?)?;
        }
        Ok(policy)
    }

    pub fn access(
        &mut self,
        router: &mut VirtualPciConfigurationRouter,
        port: u16,
        size: u8,
        write: bool,
        value: u32,
    ) -> Result<VirtualPciIoOutcome, VirtualPciError> {
        self.access_with_mapper(
            router,
            port,
            size,
            write,
            value,
            &mut DenyVirtualPciMemoryMapper,
        )
    }

    pub fn access_with_mapper<M: VirtualPciMemoryMapper>(
        &mut self,
        router: &mut VirtualPciConfigurationRouter,
        port: u16,
        size: u8,
        write: bool,
        value: u32,
        mapper: &mut M,
    ) -> Result<VirtualPciIoOutcome, VirtualPciError> {
        if port == PCI_CONFIGURATION_ADDRESS_PORT {
            if size != 4 {
                return Err(VirtualPciError::InvalidTransport);
            }
            if write {
                if value & 0x7f00_0003 != 0 {
                    return Err(VirtualPciError::InvalidTransport);
                }
                self.address = value;
            }
            return Ok(VirtualPciIoOutcome::AddressRegister(self.address));
        }

        let port_offset = port
            .checked_sub(PCI_CONFIGURATION_DATA_PORT)
            .filter(|offset| *offset < 4)
            .ok_or(VirtualPciError::InvalidTransport)?;
        if !matches!(size, 1 | 2 | 4)
            || !port_offset.is_multiple_of(u16::from(size))
            || usize::from(port_offset) + usize::from(size) > 4
        {
            return Err(VirtualPciError::InvalidTransport);
        }
        let Some((location, register)) = self.selection(port_offset) else {
            return Ok(if write {
                VirtualPciIoOutcome::AbsentWrite
            } else {
                VirtualPciIoOutcome::AbsentRead(width_mask(size))
            });
        };
        if write {
            match router.write_with_mapper(location, register, size, value, mapper) {
                Ok(outcome) => Ok(VirtualPciIoOutcome::Write(outcome)),
                Err(VirtualPciError::FunctionNotPresent) => Ok(VirtualPciIoOutcome::AbsentWrite),
                Err(error) => Err(error),
            }
        } else {
            match router.read(location, register, size) {
                Ok(value) => Ok(VirtualPciIoOutcome::Read(value)),
                Err(VirtualPciError::FunctionNotPresent) => {
                    Ok(VirtualPciIoOutcome::AbsentRead(width_mask(size)))
                }
                Err(error) => Err(error),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn access_with_backend_mapper<B, M: VirtualPciBackendMemoryMapper<B>>(
        &mut self,
        backend: &mut B,
        router: &mut VirtualPciConfigurationRouter,
        port: u16,
        size: u8,
        write: bool,
        value: u32,
        mapper: &mut M,
    ) -> Result<VirtualPciIoOutcome, VirtualPciError> {
        if port == PCI_CONFIGURATION_ADDRESS_PORT {
            if size != 4 {
                return Err(VirtualPciError::InvalidTransport);
            }
            if write {
                if value & 0x7f00_0003 != 0 {
                    return Err(VirtualPciError::InvalidTransport);
                }
                self.address = value;
            }
            return Ok(VirtualPciIoOutcome::AddressRegister(self.address));
        }
        let port_offset = port
            .checked_sub(PCI_CONFIGURATION_DATA_PORT)
            .filter(|offset| *offset < 4)
            .ok_or(VirtualPciError::InvalidTransport)?;
        if !matches!(size, 1 | 2 | 4)
            || !port_offset.is_multiple_of(u16::from(size))
            || usize::from(port_offset) + usize::from(size) > 4
        {
            return Err(VirtualPciError::InvalidTransport);
        }
        let Some((location, register)) = self.selection(port_offset) else {
            return Ok(if write {
                VirtualPciIoOutcome::AbsentWrite
            } else {
                VirtualPciIoOutcome::AbsentRead(width_mask(size))
            });
        };
        if write {
            match router.write_with_backend_mapper(location, register, size, value, backend, mapper)
            {
                Ok(outcome) => Ok(VirtualPciIoOutcome::Write(outcome)),
                Err(VirtualPciError::FunctionNotPresent) => Ok(VirtualPciIoOutcome::AbsentWrite),
                Err(error) => Err(error),
            }
        } else {
            match router.read(location, register, size) {
                Ok(value) => Ok(VirtualPciIoOutcome::Read(value)),
                Err(VirtualPciError::FunctionNotPresent) => {
                    Ok(VirtualPciIoOutcome::AbsentRead(width_mask(size)))
                }
                Err(error) => Err(error),
            }
        }
    }

    fn selection(&self, port_offset: u16) -> Option<(VirtualPciLocation, u16)> {
        if self.address & (1 << 31) == 0 {
            return None;
        }
        let bus = ((self.address >> 16) & 0xff) as u8;
        let device = ((self.address >> 11) & 0x1f) as u8;
        let function = ((self.address >> 8) & 0x07) as u8;
        let register = ((self.address & 0xfc) as u16).checked_add(port_offset)?;
        let location = VirtualPciLocation::new(0, bus, device, function).ok()?;
        Some((location, register))
    }
}

const fn width_mask(size: u8) -> u32 {
    match size {
        1 => u8::MAX as u32,
        2 => u16::MAX as u32,
        4 => u32::MAX,
        _ => 0,
    }
}

/// Runs exactly one allowlisted Configuration Mechanism #1 transaction through
/// common VM policy. Scalar reads are completed through a backend contract
/// bound to the exact still-pending exit before this function returns.
#[allow(clippy::too_many_arguments)]
pub fn run_pci_configuration_once<B, const V: usize, const C: usize, const M: usize>(
    backend: &mut B,
    vcpu: u32,
    vms: &mut crate::VmTable<V>,
    vm: crate::VmId,
    hypercalls: &mut crate::HypercallRouter,
    capabilities: &crate::CapabilitySpace<C>,
    memory: &crate::GuestMemory<M>,
    transport: &mut VirtualPciConfigurationMechanismOne,
    router: &mut VirtualPciConfigurationRouter,
) -> Result<VirtualPciIoOutcome, VirtualPciRunError<B::Error>>
where
    B: crate::IoReadCompleter,
{
    run_pci_configuration_once_with_mapper(
        backend,
        vcpu,
        vms,
        vm,
        hypercalls,
        capabilities,
        memory,
        transport,
        router,
        &mut DenyVirtualPciMemoryMapper,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn run_pci_configuration_once_with_mapper<
    B,
    P,
    const V: usize,
    const C: usize,
    const M: usize,
>(
    backend: &mut B,
    vcpu: u32,
    vms: &mut crate::VmTable<V>,
    vm: crate::VmId,
    hypercalls: &mut crate::HypercallRouter,
    capabilities: &crate::CapabilitySpace<C>,
    memory: &crate::GuestMemory<M>,
    transport: &mut VirtualPciConfigurationMechanismOne,
    router: &mut VirtualPciConfigurationRouter,
    mapper: &mut P,
) -> Result<VirtualPciIoOutcome, VirtualPciRunError<B::Error>>
where
    B: crate::IoReadCompleter,
    P: VirtualPciMemoryMapper,
{
    let policy =
        VirtualPciConfigurationMechanismOne::io_policy().map_err(VirtualPciRunError::Policy)?;
    let disposition = crate::run_vm_once(
        backend,
        vcpu,
        vms,
        vm,
        hypercalls,
        capabilities,
        memory,
        &policy,
    )
    .map_err(VirtualPciRunError::Exit)?;
    let crate::ExitDisposition::Io {
        port,
        size,
        write,
        value,
    } = disposition
    else {
        let _ = vms.fail(vm);
        return Err(VirtualPciRunError::InvalidExit);
    };
    let outcome = transport
        .access_with_mapper(router, port, size, write, value, mapper)
        .map_err(|error| {
            let _ = vms.fail(vm);
            VirtualPciRunError::Transport(error)
        })?;
    if !write {
        let read = match outcome {
            VirtualPciIoOutcome::AddressRegister(value)
            | VirtualPciIoOutcome::Read(value)
            | VirtualPciIoOutcome::AbsentRead(value) => value,
            VirtualPciIoOutcome::Write(_) | VirtualPciIoOutcome::AbsentWrite => {
                let _ = vms.fail(vm);
                return Err(VirtualPciRunError::InvalidExit);
            }
        };
        backend
            .complete_io_read(vcpu, port, size, read)
            .map_err(|error| {
                let _ = vms.fail(vm);
                VirtualPciRunError::Completion(error)
            })?;
    }
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
pub fn run_pci_configuration_once_with_backend_mapper<
    B,
    P,
    const V: usize,
    const C: usize,
    const M: usize,
>(
    backend: &mut B,
    vcpu: u32,
    vms: &mut crate::VmTable<V>,
    vm: crate::VmId,
    hypercalls: &mut crate::HypercallRouter,
    capabilities: &crate::CapabilitySpace<C>,
    memory: &crate::GuestMemory<M>,
    transport: &mut VirtualPciConfigurationMechanismOne,
    router: &mut VirtualPciConfigurationRouter,
    mapper: &mut P,
) -> Result<VirtualPciIoOutcome, VirtualPciRunError<B::Error>>
where
    B: crate::IoReadCompleter,
    P: VirtualPciBackendMemoryMapper<B>,
{
    let policy =
        VirtualPciConfigurationMechanismOne::io_policy().map_err(VirtualPciRunError::Policy)?;
    let disposition = crate::run_vm_once(
        backend,
        vcpu,
        vms,
        vm,
        hypercalls,
        capabilities,
        memory,
        &policy,
    )
    .map_err(VirtualPciRunError::Exit)?;
    let crate::ExitDisposition::Io {
        port,
        size,
        write,
        value,
    } = disposition
    else {
        let _ = vms.fail(vm);
        return Err(VirtualPciRunError::InvalidExit);
    };
    let outcome = transport
        .access_with_backend_mapper(backend, router, port, size, write, value, mapper)
        .map_err(|error| {
            let _ = vms.fail(vm);
            VirtualPciRunError::Transport(error)
        })?;
    if !write {
        let read = match outcome {
            VirtualPciIoOutcome::AddressRegister(value)
            | VirtualPciIoOutcome::Read(value)
            | VirtualPciIoOutcome::AbsentRead(value) => value,
            VirtualPciIoOutcome::Write(_) | VirtualPciIoOutcome::AbsentWrite => {
                let _ = vms.fail(vm);
                return Err(VirtualPciRunError::InvalidExit);
            }
        };
        backend
            .complete_io_read(vcpu, port, size, read)
            .map_err(|error| {
                let _ = vms.fail(vm);
                VirtualPciRunError::Completion(error)
            })?;
    }
    Ok(outcome)
}

impl Default for VirtualPciConfigurationRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualPciConfigurationRouter {
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; MAX_VIRTUAL_PCI_FUNCTIONS],
            generations: [1; MAX_VIRTUAL_PCI_FUNCTIONS],
        }
    }

    pub fn attach(
        &mut self,
        location: VirtualPciLocation,
        function: VirtualPciType0Function,
    ) -> Result<VirtualPciAttachmentId, VirtualPciError> {
        if function.command() != 0 || function.bar0().address() != 0 || function.read(16, 4)? != 0 {
            return Err(VirtualPciError::InvalidState);
        }
        if self
            .slots
            .iter()
            .flatten()
            .any(|entry| entry.location == location)
        {
            return Err(VirtualPciError::DuplicateLocation);
        }
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(VirtualPciError::CapacityExhausted)?;
        let generation = self.generations[slot];
        self.slots[slot] = Some(VirtualPciAttachment { location, function });
        Ok(VirtualPciAttachmentId {
            slot: slot as u8,
            generation,
        })
    }

    pub fn describe_attachment(
        &self,
        id: VirtualPciAttachmentId,
    ) -> Result<VirtualPciAttachedFunction, VirtualPciError> {
        let entry = self.attachment(id)?;
        Ok(VirtualPciAttachedFunction {
            resources: VirtualPciAttachedResources {
                attachment: id,
                location: entry.location,
                function_generation: entry.function.generation(),
                mmio_window: entry.function.assigned_mmio_window(),
                command: entry.function.command(),
            },
            identity: entry.function.identity(),
        })
    }

    pub fn read(
        &self,
        location: VirtualPciLocation,
        offset: u16,
        size: u8,
    ) -> Result<u32, VirtualPciError> {
        self.function_at(location)?.read(offset, size)
    }

    pub fn write(
        &mut self,
        location: VirtualPciLocation,
        offset: u16,
        size: u8,
        value: u32,
    ) -> Result<VirtualPciWriteOutcome, VirtualPciError> {
        self.write_with_mapper(
            location,
            offset,
            size,
            value,
            &mut DenyVirtualPciMemoryMapper,
        )
    }

    pub fn write_with_mapper<M: VirtualPciMemoryMapper>(
        &mut self,
        location: VirtualPciLocation,
        offset: u16,
        size: u8,
        value: u32,
        mapper: &mut M,
    ) -> Result<VirtualPciWriteOutcome, VirtualPciError> {
        self.write_with_transition(location, offset, size, value, |mapping, resources| {
            if mapping {
                mapper.map_window(resources)
            } else {
                mapper.unmap_window(resources)
            }
        })
    }

    pub fn write_with_backend_mapper<B, M: VirtualPciBackendMemoryMapper<B>>(
        &mut self,
        location: VirtualPciLocation,
        offset: u16,
        size: u8,
        value: u32,
        backend: &mut B,
        mapper: &mut M,
    ) -> Result<VirtualPciWriteOutcome, VirtualPciError> {
        self.write_with_transition(location, offset, size, value, |mapping, resources| {
            if mapping {
                mapper.map_window(backend, resources)
            } else {
                mapper.unmap_window(backend, resources)
            }
        })
    }

    fn write_with_transition<F>(
        &mut self,
        location: VirtualPciLocation,
        offset: u16,
        size: u8,
        value: u32,
        transition: F,
    ) -> Result<VirtualPciWriteOutcome, VirtualPciError>
    where
        F: FnOnce(bool, VirtualPciAttachedResources) -> Result<(), VirtualPciNativeResourceError>,
    {
        let slot = self
            .slots
            .iter()
            .position(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|entry| entry.location == location)
            })
            .ok_or(VirtualPciError::FunctionNotPresent)?;
        if (offset, size) != (4, 2) {
            return self.slots[slot]
                .as_mut()
                .ok_or(VirtualPciError::FunctionNotPresent)?
                .function
                .write(offset, size, value);
        }

        let command = value as u16;
        if command & !PCI_COMMAND_SUPPORTED != 0 {
            return Err(VirtualPciError::UnsupportedCommand);
        }
        let entry = self.slots[slot]
            .as_ref()
            .ok_or(VirtualPciError::FunctionNotPresent)?;
        if command & PCI_COMMAND_MEMORY_SPACE != 0 && entry.function.bar0.address == 0 {
            return Err(VirtualPciError::InvalidState);
        }
        let old_decode = entry.function.command & PCI_COMMAND_MEMORY_SPACE != 0;
        let new_decode = command & PCI_COMMAND_MEMORY_SPACE != 0;
        if old_decode != new_decode {
            let resources = VirtualPciAttachedResources {
                attachment: VirtualPciAttachmentId {
                    slot: slot as u8,
                    generation: self.generations[slot],
                },
                location,
                function_generation: entry.function.generation,
                mmio_window: entry.function.assigned_mmio_window(),
                command: entry.function.command(),
            };
            let result = transition(new_decode, resources);
            result.map_err(|error| match error {
                VirtualPciNativeResourceError::Rejected => VirtualPciError::NativeResourceRejected,
                VirtualPciNativeResourceError::Uncertain => {
                    VirtualPciError::NativeResourceUncertain
                }
            })?;
        }
        self.slots[slot]
            .as_mut()
            .ok_or(VirtualPciError::FunctionNotPresent)?
            .function
            .write(offset, size, value)
    }

    pub fn reset_with_revoker<R: VirtualPciFunctionRevoker>(
        &mut self,
        id: VirtualPciAttachmentId,
        revoker: &mut R,
    ) -> Result<u32, VirtualPciResetError<R::Error>> {
        let entry = self
            .attachment(id)
            .map_err(VirtualPciResetError::Configuration)?;
        let next_generation = entry.function.generation().checked_add(1).ok_or(
            VirtualPciResetError::Configuration(VirtualPciError::GenerationExhausted),
        )?;
        let mmio_window = entry.function.assigned_mmio_window();
        let resources = VirtualPciAttachedResources {
            attachment: id,
            location: entry.location,
            function_generation: entry.function.generation(),
            mmio_window,
            command: entry.function.command(),
        };
        revoker
            .revoke_function(resources)
            .map_err(VirtualPciResetError::Revocation)?;
        let entry = self
            .attachment_mut(id)
            .map_err(VirtualPciResetError::Configuration)?;
        entry.function.command = 0;
        entry.function.bar0.reset();
        entry.function.generation = next_generation;
        Ok(next_generation)
    }

    pub fn detach_with_revoker<R: VirtualPciFunctionRevoker>(
        &mut self,
        id: VirtualPciAttachmentId,
        revoker: &mut R,
    ) -> Result<VirtualPciType0Function, VirtualPciResetError<R::Error>> {
        let slot = usize::from(id.slot);
        let entry = self
            .attachment(id)
            .map_err(VirtualPciResetError::Configuration)?;
        if entry.function.command() & PCI_COMMAND_MEMORY_SPACE != 0 {
            return Err(VirtualPciResetError::Configuration(
                VirtualPciError::InvalidState,
            ));
        }
        let generation =
            self.generations[slot]
                .checked_add(1)
                .ok_or(VirtualPciResetError::Configuration(
                    VirtualPciError::GenerationExhausted,
                ))?;
        let resources = VirtualPciAttachedResources {
            attachment: id,
            location: entry.location,
            function_generation: entry.function.generation(),
            mmio_window: entry.function.assigned_mmio_window(),
            command: entry.function.command(),
        };
        revoker
            .revoke_function(resources)
            .map_err(VirtualPciResetError::Revocation)?;
        let entry = self.slots[slot]
            .take()
            .ok_or(VirtualPciResetError::Configuration(
                VirtualPciError::StaleAttachment,
            ))?;
        self.generations[slot] = generation;
        Ok(entry.function)
    }

    fn function_at(
        &self,
        location: VirtualPciLocation,
    ) -> Result<&VirtualPciType0Function, VirtualPciError> {
        self.slots
            .iter()
            .flatten()
            .find(|entry| entry.location == location)
            .map(|entry| &entry.function)
            .ok_or(VirtualPciError::FunctionNotPresent)
    }

    fn attachment(
        &self,
        id: VirtualPciAttachmentId,
    ) -> Result<&VirtualPciAttachment, VirtualPciError> {
        let slot = usize::from(id.slot);
        if slot >= MAX_VIRTUAL_PCI_FUNCTIONS || self.generations[slot] != id.generation {
            return Err(VirtualPciError::StaleAttachment);
        }
        self.slots[slot]
            .as_ref()
            .ok_or(VirtualPciError::StaleAttachment)
    }

    fn attachment_mut(
        &mut self,
        id: VirtualPciAttachmentId,
    ) -> Result<&mut VirtualPciAttachment, VirtualPciError> {
        let slot = usize::from(id.slot);
        if slot >= MAX_VIRTUAL_PCI_FUNCTIONS || self.generations[slot] != id.generation {
            return Err(VirtualPciError::StaleAttachment);
        }
        self.slots[slot]
            .as_mut()
            .ok_or(VirtualPciError::StaleAttachment)
    }
}

impl VirtualPciType0Function {
    pub const fn new(identity: VirtualPciIdentity, bar0: VirtualPciMemoryBar) -> Self {
        Self {
            identity,
            generation: 1,
            command: 0,
            bar0,
        }
    }

    pub const fn identity(&self) -> VirtualPciIdentity {
        self.identity
    }

    pub const fn command(&self) -> u16 {
        self.command
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    pub const fn bar0(&self) -> VirtualPciMemoryBar {
        self.bar0
    }

    pub fn mmio_window(&self) -> Result<VirtualPciMmioWindow, VirtualPciError> {
        if self.command & PCI_COMMAND_MEMORY_SPACE == 0 || self.bar0.address == 0 {
            return Err(VirtualPciError::InvalidState);
        }
        Ok(VirtualPciMmioWindow {
            generation: self.generation,
            address: self.bar0.address,
            size: self.bar0.size,
        })
    }

    fn assigned_mmio_window(&self) -> Option<VirtualPciMmioWindow> {
        (self.bar0.address != 0).then_some(VirtualPciMmioWindow {
            generation: self.generation,
            address: self.bar0.address,
            size: self.bar0.size,
        })
    }

    pub fn validate_mmio_window(
        &self,
        window: VirtualPciMmioWindow,
    ) -> Result<(), VirtualPciError> {
        if window.generation != self.generation {
            return Err(VirtualPciError::StaleGeneration);
        }
        if self.mmio_window()? != window {
            return Err(VirtualPciError::InvalidState);
        }
        Ok(())
    }

    /// Returns configuration state to its disabled, unassigned form and
    /// advances the internal lifetime generation. This core is unattached and
    /// therefore retires no native mapping; a later attachment boundary must
    /// revoke native state before calling reset.
    pub fn reset(&mut self) -> Result<u32, VirtualPciError> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(VirtualPciError::GenerationExhausted)?;
        self.command = 0;
        self.bar0.reset();
        self.generation = generation;
        Ok(generation)
    }

    pub fn encode(&self, output: &mut [u8; PCI_TYPE0_CONFIGURATION_BYTES]) {
        output.fill(0);
        output[0..2].copy_from_slice(&self.identity.vendor.to_le_bytes());
        output[2..4].copy_from_slice(&self.identity.device.to_le_bytes());
        output[4..6].copy_from_slice(&self.command.to_le_bytes());
        output[8] = self.identity.revision;
        output[9] = self.identity.programming_interface;
        output[10] = self.identity.subclass;
        output[11] = self.identity.class;
        output[14] = 0;
        output[16..20].copy_from_slice(&self.bar0.value().to_le_bytes());
        output[44..46].copy_from_slice(&self.identity.subsystem_vendor.to_le_bytes());
        output[46..48].copy_from_slice(&self.identity.subsystem.to_le_bytes());
    }

    pub fn read(&self, offset: u16, size: u8) -> Result<u32, VirtualPciError> {
        let range = access_range(offset, size)?;
        let mut encoded = [0; PCI_TYPE0_CONFIGURATION_BYTES];
        self.encode(&mut encoded);
        let mut value = [0; 4];
        value[..range.len()].copy_from_slice(&encoded[range]);
        Ok(u32::from_le_bytes(value))
    }

    /// Applies one exact writable-field access transactionally. Unsupported
    /// command bits and all read-only/header-crossing writes fail without
    /// mutating command or BAR state.
    pub fn write(
        &mut self,
        offset: u16,
        size: u8,
        value: u32,
    ) -> Result<VirtualPciWriteOutcome, VirtualPciError> {
        let _ = access_range(offset, size)?;
        match (offset, size) {
            (4, 2) => {
                let command = value as u16;
                if command & !PCI_COMMAND_SUPPORTED != 0 {
                    return Err(VirtualPciError::UnsupportedCommand);
                }
                if command & PCI_COMMAND_MEMORY_SPACE != 0 && self.bar0.address == 0 {
                    return Err(VirtualPciError::InvalidState);
                }
                self.command = command;
                Ok(VirtualPciWriteOutcome::Command(command))
            }
            (16, 4) => {
                if self.command & PCI_COMMAND_MEMORY_SPACE != 0 {
                    return Err(VirtualPciError::InvalidState);
                }
                Ok(self.bar0.write(value))
            }
            _ => Err(VirtualPciError::ReadOnly),
        }
    }
}

fn access_range(offset: u16, size: u8) -> Result<core::ops::Range<usize>, VirtualPciError> {
    if !matches!(size, 1 | 2 | 4) || !offset.is_multiple_of(u16::from(size)) {
        return Err(VirtualPciError::InvalidAccess);
    }
    let start = usize::from(offset);
    let end = start
        .checked_add(usize::from(size))
        .filter(|end| *end <= PCI_TYPE0_CONFIGURATION_BYTES)
        .ok_or(VirtualPciError::InvalidAccess)?;
    Ok(start..end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> VirtualPciIdentity {
        VirtualPciIdentity::new(0x1234, 0x5678, 1, 2, 0x80, 1, 0x1234, 0x5679).unwrap()
    }

    #[derive(Default)]
    struct RecordingRevoker {
        fail: bool,
        calls: usize,
        last: Option<VirtualPciAttachedResources>,
    }

    unsafe impl VirtualPciFunctionRevoker for RecordingRevoker {
        type Error = ();

        fn revoke_function(
            &mut self,
            resources: VirtualPciAttachedResources,
        ) -> Result<(), Self::Error> {
            self.calls += 1;
            self.last = Some(resources);
            if self.fail { Err(()) } else { Ok(()) }
        }
    }

    #[derive(Default)]
    struct RecordingMapper {
        map_error: Option<VirtualPciNativeResourceError>,
        unmap_error: Option<VirtualPciNativeResourceError>,
        map_calls: usize,
        unmap_calls: usize,
        last_map: Option<VirtualPciAttachedResources>,
        last_unmap: Option<VirtualPciAttachedResources>,
    }

    unsafe impl VirtualPciMemoryMapper for RecordingMapper {
        fn map_window(
            &mut self,
            resources: VirtualPciAttachedResources,
        ) -> Result<(), VirtualPciNativeResourceError> {
            self.map_calls += 1;
            self.last_map = Some(resources);
            self.map_error.map_or(Ok(()), Err)
        }

        fn unmap_window(
            &mut self,
            resources: VirtualPciAttachedResources,
        ) -> Result<(), VirtualPciNativeResourceError> {
            self.unmap_calls += 1;
            self.last_unmap = Some(resources);
            self.unmap_error.map_or(Ok(()), Err)
        }
    }

    #[derive(Default)]
    struct RecordingBackendState {
        mapped: bool,
    }

    #[derive(Default)]
    struct RecordingBackendMapper {
        fail: bool,
        calls: usize,
    }

    unsafe impl VirtualPciBackendMemoryMapper<RecordingBackendState> for RecordingBackendMapper {
        fn map_window(
            &mut self,
            backend: &mut RecordingBackendState,
            _resources: VirtualPciAttachedResources,
        ) -> Result<(), VirtualPciNativeResourceError> {
            self.calls += 1;
            if self.fail {
                return Err(VirtualPciNativeResourceError::Uncertain);
            }
            if backend.mapped {
                return Err(VirtualPciNativeResourceError::Rejected);
            }
            backend.mapped = true;
            Ok(())
        }

        fn unmap_window(
            &mut self,
            backend: &mut RecordingBackendState,
            _resources: VirtualPciAttachedResources,
        ) -> Result<(), VirtualPciNativeResourceError> {
            self.calls += 1;
            if self.fail {
                return Err(VirtualPciNativeResourceError::Uncertain);
            }
            if !backend.mapped {
                return Err(VirtualPciNativeResourceError::Rejected);
            }
            backend.mapped = false;
            Ok(())
        }
    }

    #[test]
    fn identity_rejects_absent_vendor_and_reserved_class_only() {
        for vendor in [0, u16::MAX] {
            assert_eq!(
                VirtualPciIdentity::new(vendor, 1, 0, 0, 0, 1, 1, 1),
                Err(VirtualPciError::InvalidIdentity)
            );
        }
        assert_eq!(
            VirtualPciIdentity::new(1, 1, 0, 0, 0, u8::MAX, 1, 1),
            Err(VirtualPciError::InvalidIdentity)
        );
        assert!(VirtualPciIdentity::new(1, 0, 0, 0, 0, 1, 0, 0).is_ok());
    }

    #[test]
    fn type0_header_is_exact_and_zero_fills_unimplemented_fields() {
        let function =
            VirtualPciType0Function::new(identity(), VirtualPciMemoryBar::new(4096).unwrap());
        let mut encoded = [0xa5; PCI_TYPE0_CONFIGURATION_BYTES];
        function.encode(&mut encoded);
        assert_eq!(&encoded[0..4], &[0x34, 0x12, 0x78, 0x56]);
        assert_eq!(&encoded[8..12], &[1, 2, 0x80, 1]);
        assert_eq!(encoded[14], 0);
        assert_eq!(&encoded[16..20], &[0; 4]);
        assert_eq!(&encoded[44..48], &[0x34, 0x12, 0x79, 0x56]);
        for range in [6..8, 12..14, 15..16, 20..44, 48..64] {
            assert!(encoded[range].iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn bar_probe_reports_exact_mask_without_becoming_an_address() {
        let mut function =
            VirtualPciType0Function::new(identity(), VirtualPciMemoryBar::new(4096).unwrap());
        assert_eq!(
            function.write(16, 4, u32::MAX),
            Ok(VirtualPciWriteOutcome::BarProbe)
        );
        assert_eq!(function.read(16, 4), Ok(0xffff_f000));
        assert_eq!(function.bar0().address(), 0);
        assert_eq!(
            function.write(16, 4, 0x1234_5fff),
            Ok(VirtualPciWriteOutcome::BarAddress(0x1234_5000))
        );
        assert_eq!(function.read(16, 4), Ok(0x1234_5000));
    }

    #[test]
    fn command_denies_bus_mastering_and_is_transactional() {
        let mut function =
            VirtualPciType0Function::new(identity(), VirtualPciMemoryBar::new(4096).unwrap());
        function.write(16, 4, 0x1234_5000).unwrap();
        assert_eq!(
            function.write(
                4,
                2,
                u32::from(PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_INTERRUPT_DISABLE)
            ),
            Ok(VirtualPciWriteOutcome::Command(
                PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_INTERRUPT_DISABLE
            ))
        );
        assert_eq!(
            function.write(4, 2, 1 << 2),
            Err(VirtualPciError::UnsupportedCommand)
        );
        assert_eq!(
            function.command(),
            PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_INTERRUPT_DISABLE
        );
        assert_eq!(
            function.write(16, 4, 0x2000_0000),
            Err(VirtualPciError::InvalidState)
        );
        assert_eq!(function.bar0().address(), 0x1234_5000);
    }

    #[test]
    fn memory_decode_requires_assignment_and_reset_stales_window() {
        let mut function =
            VirtualPciType0Function::new(identity(), VirtualPciMemoryBar::new(4096).unwrap());
        assert_eq!(
            function.write(4, 2, u32::from(PCI_COMMAND_MEMORY_SPACE)),
            Err(VirtualPciError::InvalidState)
        );
        assert_eq!(function.mmio_window(), Err(VirtualPciError::InvalidState));
        function.write(16, 4, 0x2000_0fff).unwrap();
        function
            .write(4, 2, u32::from(PCI_COMMAND_MEMORY_SPACE))
            .unwrap();
        let window = function.mmio_window().unwrap();
        assert_eq!(window.generation(), 1);
        assert_eq!(window.address(), 0x2000_0000);
        assert_eq!(window.size(), 4096);
        assert_eq!(function.validate_mmio_window(window), Ok(()));

        assert_eq!(function.reset(), Ok(2));
        assert_eq!(function.command(), 0);
        assert_eq!(function.bar0().address(), 0);
        assert_eq!(function.read(16, 4), Ok(0));
        assert_eq!(
            function.validate_mmio_window(window),
            Err(VirtualPciError::StaleGeneration)
        );
    }

    #[test]
    fn reset_generation_exhaustion_preserves_live_configuration() {
        let mut function =
            VirtualPciType0Function::new(identity(), VirtualPciMemoryBar::new(4096).unwrap());
        function.write(16, 4, 0x2000_0000).unwrap();
        function
            .write(4, 2, u32::from(PCI_COMMAND_MEMORY_SPACE))
            .unwrap();
        function.generation = u32::MAX;
        let window = function.mmio_window().unwrap();
        assert_eq!(function.reset(), Err(VirtualPciError::GenerationExhausted));
        assert_eq!(function.command(), PCI_COMMAND_MEMORY_SPACE);
        assert_eq!(function.bar0().address(), 0x2000_0000);
        assert_eq!(function.validate_mmio_window(window), Ok(()));
    }

    #[test]
    fn malformed_and_read_only_writes_preserve_all_state() {
        let mut function =
            VirtualPciType0Function::new(identity(), VirtualPciMemoryBar::new(4096).unwrap());
        assert_eq!(
            function.write(17, 4, 0),
            Err(VirtualPciError::InvalidAccess)
        );
        assert_eq!(function.write(0, 4, 0), Err(VirtualPciError::ReadOnly));
        assert_eq!(function.write(16, 2, 0), Err(VirtualPciError::ReadOnly));
        assert_eq!(function.command(), 0);
        assert_eq!(function.bar0().address(), 0);
        assert_eq!(function.read(63, 2), Err(VirtualPciError::InvalidAccess));
    }

    #[test]
    fn bar_geometry_is_bounded() {
        for size in [0, 8, 24] {
            assert_eq!(
                VirtualPciMemoryBar::new(size),
                Err(VirtualPciError::InvalidBar)
            );
        }
        assert_eq!(VirtualPciMemoryBar::new(16).unwrap().size(), 16);
        assert_eq!(VirtualPciMemoryBar::new(1 << 31).unwrap().size(), 1 << 31);
    }

    fn location(device: u8) -> VirtualPciLocation {
        VirtualPciLocation::new(0, 0, device, 0).unwrap()
    }

    fn function(device: u16) -> VirtualPciType0Function {
        VirtualPciType0Function::new(
            VirtualPciIdentity::new(0x1234, device, 1, 2, 0x80, 1, 0x1234, device).unwrap(),
            VirtualPciMemoryBar::new(4096).unwrap(),
        )
    }

    #[test]
    fn locations_bound_device_and_function_numbers() {
        assert!(VirtualPciLocation::new(u16::MAX, u8::MAX, 31, 7).is_ok());
        assert_eq!(
            VirtualPciLocation::new(0, 0, 32, 0),
            Err(VirtualPciError::InvalidLocation)
        );
        assert_eq!(
            VirtualPciLocation::new(0, 0, 0, 8),
            Err(VirtualPciError::InvalidLocation)
        );
    }

    #[test]
    fn router_routes_only_one_exact_location_transactionally() {
        let mut router = VirtualPciConfigurationRouter::new();
        let first = location(1);
        let second = location(2);
        router.attach(first, function(1)).unwrap();
        router.attach(second, function(2)).unwrap();
        assert_eq!(router.read(first, 2, 2), Ok(1));
        assert_eq!(router.read(second, 2, 2), Ok(2));
        assert_eq!(
            router.read(location(3), 0, 2),
            Err(VirtualPciError::FunctionNotPresent)
        );
        assert_eq!(
            router.write(first, 17, 4, 0),
            Err(VirtualPciError::InvalidAccess)
        );
        assert_eq!(router.read(first, 16, 4), Ok(0));
        assert_eq!(router.read(second, 16, 4), Ok(0));
    }

    #[test]
    fn backend_mapper_couples_exact_native_state_to_decode_publication() {
        let mut router = VirtualPciConfigurationRouter::new();
        let routed = location(1);
        router.attach(routed, function(1)).unwrap();
        router.write(routed, 16, 4, 0x2000_0000).unwrap();
        let mut backend = RecordingBackendState::default();
        let mut mapper = RecordingBackendMapper {
            fail: true,
            calls: 0,
        };
        assert_eq!(
            router.write_with_backend_mapper(
                routed,
                4,
                2,
                u32::from(PCI_COMMAND_MEMORY_SPACE),
                &mut backend,
                &mut mapper,
            ),
            Err(VirtualPciError::NativeResourceUncertain)
        );
        assert!(!backend.mapped);
        assert_eq!(router.read(routed, 4, 2), Ok(0));
        mapper.fail = false;
        assert!(
            router
                .write_with_backend_mapper(
                    routed,
                    4,
                    2,
                    u32::from(PCI_COMMAND_MEMORY_SPACE),
                    &mut backend,
                    &mut mapper,
                )
                .is_ok()
        );
        assert!(backend.mapped);
        assert_eq!(
            router.read(routed, 4, 2),
            Ok(u32::from(PCI_COMMAND_MEMORY_SPACE))
        );
        assert!(
            router
                .write_with_backend_mapper(routed, 4, 2, 0, &mut backend, &mut mapper,)
                .is_ok()
        );
        assert!(!backend.mapped);
        assert_eq!(router.read(routed, 4, 2), Ok(0));
        assert_eq!(mapper.calls, 3);
    }

    #[test]
    fn router_rejects_duplicates_and_capacity_without_mutation() {
        let mut router = VirtualPciConfigurationRouter::new();
        let first = router.attach(location(0), function(1)).unwrap();
        assert_eq!(
            router.attach(location(0), function(2)),
            Err(VirtualPciError::DuplicateLocation)
        );
        for device in 1..MAX_VIRTUAL_PCI_FUNCTIONS as u8 {
            router
                .attach(location(device), function(u16::from(device) + 1))
                .unwrap();
        }
        assert_eq!(
            router.attach(location(MAX_VIRTUAL_PCI_FUNCTIONS as u8), function(9)),
            Err(VirtualPciError::CapacityExhausted)
        );
        assert_eq!(router.read(location(0), 2, 2), Ok(1));
        assert_eq!(first.generation(), 1);
    }

    #[test]
    fn router_attach_requires_reset_configuration_state() {
        let mut router = VirtualPciConfigurationRouter::new();
        let mut assigned = function(1);
        assigned.write(16, 4, 0x2000_0000).unwrap();
        assert!(matches!(
            router.attach(location(0), assigned),
            Err(VirtualPciError::InvalidState)
        ));

        let mut probing = function(2);
        probing.write(16, 4, u32::MAX).unwrap();
        assert!(matches!(
            router.attach(location(0), probing),
            Err(VirtualPciError::InvalidState)
        ));
        assert_eq!(
            router.read(location(0), 0, 2),
            Err(VirtualPciError::FunctionNotPresent)
        );
    }

    #[test]
    fn detach_requires_disabled_decode_and_stales_attachment_identity() {
        let mut router = VirtualPciConfigurationRouter::new();
        let mut revoker = RecordingRevoker::default();
        let routed = location(1);
        let old = router.attach(routed, function(1)).unwrap();
        router.write(routed, 16, 4, 0x2000_0000).unwrap();
        let mut mapper = RecordingMapper::default();
        router
            .write_with_mapper(
                routed,
                4,
                2,
                u32::from(PCI_COMMAND_MEMORY_SPACE),
                &mut mapper,
            )
            .unwrap();
        assert!(matches!(
            router.detach_with_revoker(old, &mut revoker),
            Err(VirtualPciResetError::Configuration(
                VirtualPciError::InvalidState
            ))
        ));
        assert_eq!(router.reset_with_revoker(old, &mut revoker), Ok(2));
        let detached = router.detach_with_revoker(old, &mut revoker).unwrap();
        assert_eq!(detached.generation(), 2);
        assert_eq!(
            router.reset_with_revoker(old, &mut revoker),
            Err(VirtualPciResetError::Configuration(
                VirtualPciError::StaleAttachment
            ))
        );
        assert_eq!(
            router.read(routed, 0, 2),
            Err(VirtualPciError::FunctionNotPresent)
        );

        let fresh = router.attach(routed, function(2)).unwrap();
        assert_eq!(fresh.generation(), 2);
        assert_eq!(router.read(routed, 2, 2), Ok(2));
        assert_eq!(
            router.reset_with_revoker(old, &mut revoker),
            Err(VirtualPciResetError::Configuration(
                VirtualPciError::StaleAttachment
            ))
        );
    }

    #[test]
    fn attached_reset_revokes_exact_resources_before_configuration_mutation() {
        let mut router = VirtualPciConfigurationRouter::new();
        let routed = location(2);
        let id = router.attach(routed, function(7)).unwrap();
        router.write(routed, 16, 4, 0x2345_6000).unwrap();
        let mut mapper = RecordingMapper::default();
        router
            .write_with_mapper(
                routed,
                4,
                2,
                u32::from(PCI_COMMAND_MEMORY_SPACE),
                &mut mapper,
            )
            .unwrap();
        let window = router
            .attachment(id)
            .unwrap()
            .function
            .mmio_window()
            .unwrap();
        let mut revoker = RecordingRevoker {
            fail: true,
            ..RecordingRevoker::default()
        };

        assert_eq!(
            router.reset_with_revoker(id, &mut revoker),
            Err(VirtualPciResetError::Revocation(()))
        );
        assert_eq!(
            router.read(routed, 4, 2),
            Ok(u32::from(PCI_COMMAND_MEMORY_SPACE))
        );
        assert_eq!(router.read(routed, 16, 4), Ok(0x2345_6000));
        assert_eq!(
            revoker.last,
            Some(VirtualPciAttachedResources {
                attachment: id,
                location: routed,
                function_generation: 1,
                mmio_window: Some(window),
                command: PCI_COMMAND_MEMORY_SPACE,
            })
        );

        let mut successful = VirtualPciConfigurationRouter::new();
        let successful_id = successful.attach(routed, function(7)).unwrap();
        successful.write(routed, 16, 4, 0x2345_6000).unwrap();
        let mut successful_mapper = RecordingMapper::default();
        successful
            .write_with_mapper(
                routed,
                4,
                2,
                u32::from(PCI_COMMAND_MEMORY_SPACE),
                &mut successful_mapper,
            )
            .unwrap();
        let successful_window = successful
            .attachment(successful_id)
            .unwrap()
            .function
            .mmio_window()
            .unwrap();
        let mut successful_revoker = RecordingRevoker::default();
        assert_eq!(
            successful.reset_with_revoker(successful_id, &mut successful_revoker),
            Ok(2)
        );
        assert_eq!(successful_revoker.calls, 1);
        assert_eq!(successful.read(routed, 4, 2), Ok(0));
        assert_eq!(successful.read(routed, 16, 4), Ok(0));
        assert_eq!(
            successful
                .attachment(successful_id)
                .unwrap()
                .function
                .validate_mmio_window(successful_window),
            Err(VirtualPciError::StaleGeneration)
        );
    }

    #[test]
    fn memory_decode_enable_requires_exact_confirmed_native_mapping() {
        let mut router = VirtualPciConfigurationRouter::new();
        let routed = location(5);
        let id = router.attach(routed, function(11)).unwrap();
        router.write(routed, 16, 4, 0x4567_8000).unwrap();
        assert_eq!(
            router.write(routed, 4, 2, u32::from(PCI_COMMAND_MEMORY_SPACE)),
            Err(VirtualPciError::NativeResourceRejected)
        );
        assert_eq!(router.read(routed, 4, 2), Ok(0));

        let mut rejected = RecordingMapper {
            map_error: Some(VirtualPciNativeResourceError::Uncertain),
            ..RecordingMapper::default()
        };
        assert_eq!(
            router.write_with_mapper(
                routed,
                4,
                2,
                u32::from(PCI_COMMAND_MEMORY_SPACE),
                &mut rejected,
            ),
            Err(VirtualPciError::NativeResourceUncertain)
        );
        assert_eq!(router.read(routed, 4, 2), Ok(0));
        let resources = rejected.last_map.unwrap();
        assert_eq!(resources.attachment(), id);
        assert_eq!(resources.location(), routed);
        assert_eq!(resources.function_generation(), 1);
        assert_eq!(resources.mmio_window().unwrap().address(), 0x4567_8000);

        let mut successful = VirtualPciConfigurationRouter::new();
        let successful_id = successful.attach(routed, function(11)).unwrap();
        successful.write(routed, 16, 4, 0x4567_8000).unwrap();
        let mut mapper = RecordingMapper::default();
        assert_eq!(
            successful.write_with_mapper(
                routed,
                4,
                2,
                u32::from(PCI_COMMAND_MEMORY_SPACE),
                &mut mapper,
            ),
            Ok(VirtualPciWriteOutcome::Command(PCI_COMMAND_MEMORY_SPACE))
        );
        assert_eq!(mapper.map_calls, 1);
        assert_eq!(mapper.last_map.unwrap().attachment(), successful_id);
        assert_eq!(successful.read(routed, 4, 2), Ok(2));
    }

    #[test]
    fn memory_decode_disable_requires_confirmed_unmapping_before_command_clear() {
        let routed = location(6);
        let mut router = VirtualPciConfigurationRouter::new();
        router.attach(routed, function(12)).unwrap();
        router.write(routed, 16, 4, 0x5678_9000).unwrap();
        let mut mapper = RecordingMapper::default();
        router
            .write_with_mapper(
                routed,
                4,
                2,
                u32::from(PCI_COMMAND_MEMORY_SPACE),
                &mut mapper,
            )
            .unwrap();
        mapper.unmap_error = Some(VirtualPciNativeResourceError::Uncertain);
        assert_eq!(
            router.write_with_mapper(routed, 4, 2, 0, &mut mapper),
            Err(VirtualPciError::NativeResourceUncertain)
        );
        assert_eq!(router.read(routed, 4, 2), Ok(2));
        assert_eq!(mapper.unmap_calls, 1);
        assert_eq!(
            mapper.last_unmap.unwrap().mmio_window().unwrap().address(),
            0x5678_9000
        );

        let mut successful = VirtualPciConfigurationRouter::new();
        successful.attach(routed, function(12)).unwrap();
        successful.write(routed, 16, 4, 0x5678_9000).unwrap();
        let mut successful_mapper = RecordingMapper::default();
        successful
            .write_with_mapper(
                routed,
                4,
                2,
                u32::from(PCI_COMMAND_MEMORY_SPACE),
                &mut successful_mapper,
            )
            .unwrap();
        assert_eq!(
            successful.write_with_mapper(routed, 4, 2, 0, &mut successful_mapper),
            Ok(VirtualPciWriteOutcome::Command(0))
        );
        assert_eq!(successful_mapper.unmap_calls, 1);
        assert_eq!(successful.read(routed, 4, 2), Ok(0));
        assert_eq!(successful.read(routed, 16, 4), Ok(0x5678_9000));
    }

    #[test]
    fn reset_preflight_failure_never_calls_native_revocation() {
        let mut router = VirtualPciConfigurationRouter::new();
        let id = router.attach(location(3), function(8)).unwrap();
        router.attachment_mut(id).unwrap().function.generation = u32::MAX;
        let mut revoker = RecordingRevoker::default();
        assert_eq!(
            router.reset_with_revoker(id, &mut revoker),
            Err(VirtualPciResetError::Configuration(
                VirtualPciError::GenerationExhausted
            ))
        );
        assert_eq!(revoker.calls, 0);
        assert_eq!(router.read(location(3), 2, 2), Ok(8));
    }

    #[test]
    fn detach_revocation_failure_preserves_attachment_and_generation() {
        let mut router = VirtualPciConfigurationRouter::new();
        let routed = location(4);
        let id = router.attach(routed, function(9)).unwrap();
        router.write(routed, 16, 4, 0x3456_7000).unwrap();
        let assigned = router
            .attachment(id)
            .unwrap()
            .function
            .assigned_mmio_window();
        let mut revoker = RecordingRevoker {
            fail: true,
            ..RecordingRevoker::default()
        };
        assert!(matches!(
            router.detach_with_revoker(id, &mut revoker),
            Err(VirtualPciResetError::Revocation(()))
        ));
        assert_eq!(router.read(routed, 2, 2), Ok(9));
        assert_eq!(revoker.last.unwrap().attachment(), id);
        assert_eq!(revoker.last.unwrap().location(), routed);
        assert_eq!(revoker.last.unwrap().function_generation(), 1);
        assert_eq!(revoker.last.unwrap().mmio_window(), assigned);

        let mut successful = VirtualPciConfigurationRouter::new();
        let successful_id = successful.attach(routed, function(9)).unwrap();
        let mut successful_revoker = RecordingRevoker::default();
        let detached = successful
            .detach_with_revoker(successful_id, &mut successful_revoker)
            .unwrap();
        assert_eq!(detached.identity().device(), 9);
        assert_eq!(
            successful.read(routed, 0, 2),
            Err(VirtualPciError::FunctionNotPresent)
        );
        let replacement = successful.attach(routed, function(10)).unwrap();
        assert_eq!(replacement.generation(), 2);
    }

    #[test]
    fn detach_generation_exhaustion_preserves_attachment() {
        let mut router = VirtualPciConfigurationRouter::new();
        let mut revoker = RecordingRevoker::default();
        let routed = location(1);
        let id = router.attach(routed, function(1)).unwrap();
        router.generations[usize::from(id.slot)] = u32::MAX;
        let exhausted = VirtualPciAttachmentId {
            slot: id.slot,
            generation: u32::MAX,
        };
        assert!(matches!(
            router.detach_with_revoker(exhausted, &mut revoker),
            Err(VirtualPciResetError::Configuration(
                VirtualPciError::GenerationExhausted
            ))
        ));
        assert_eq!(revoker.calls, 0);
        assert_eq!(router.read(routed, 2, 2), Ok(1));
        assert_eq!(router.reset_with_revoker(exhausted, &mut revoker), Ok(2));
    }

    const fn selector(bus: u8, device: u8, function: u8, register: u8) -> u32 {
        (1 << 31)
            | ((bus as u32) << 16)
            | ((device as u32) << 11)
            | ((function as u32) << 8)
            | ((register as u32) & 0xfc)
    }

    #[test]
    fn mechanism_one_policy_is_exact_and_deny_by_default() {
        let policy = VirtualPciConfigurationMechanismOne::io_policy().unwrap();
        assert!(policy.permits(PCI_CONFIGURATION_ADDRESS_PORT, 4, true));
        assert!(policy.permits(PCI_CONFIGURATION_ADDRESS_PORT, 4, false));
        for (port, size) in [
            (PCI_CONFIGURATION_DATA_PORT, 1),
            (PCI_CONFIGURATION_DATA_PORT, 2),
            (PCI_CONFIGURATION_DATA_PORT, 4),
            (PCI_CONFIGURATION_DATA_PORT + 1, 1),
            (PCI_CONFIGURATION_DATA_PORT + 2, 1),
            (PCI_CONFIGURATION_DATA_PORT + 2, 2),
            (PCI_CONFIGURATION_DATA_PORT + 3, 1),
        ] {
            assert!(policy.permits(port, size, true));
            assert!(policy.permits(port, size, false));
        }
        assert!(!policy.permits(PCI_CONFIGURATION_ADDRESS_PORT, 2, true));
        assert!(!policy.permits(PCI_CONFIGURATION_DATA_PORT + 1, 2, false));
        assert!(!policy.permits(PCI_CONFIGURATION_DATA_PORT + 4, 1, false));
    }

    #[test]
    fn mechanism_one_selects_and_routes_exact_function_fields() {
        let mut router = VirtualPciConfigurationRouter::new();
        let routed = VirtualPciLocation::new(0, 3, 5, 2).unwrap();
        router.attach(routed, function(0x5678)).unwrap();
        let mut transport = VirtualPciConfigurationMechanismOne::new();
        let selected = selector(3, 5, 2, 0);
        assert_eq!(
            transport.access(
                &mut router,
                PCI_CONFIGURATION_ADDRESS_PORT,
                4,
                true,
                selected
            ),
            Ok(VirtualPciIoOutcome::AddressRegister(selected))
        );
        assert_eq!(
            transport.access(
                &mut router,
                PCI_CONFIGURATION_ADDRESS_PORT,
                4,
                false,
                u32::MAX
            ),
            Ok(VirtualPciIoOutcome::AddressRegister(selected))
        );
        assert_eq!(
            transport.access(&mut router, PCI_CONFIGURATION_DATA_PORT, 2, false, 0),
            Ok(VirtualPciIoOutcome::Read(0x1234))
        );
        assert_eq!(
            transport.access(&mut router, PCI_CONFIGURATION_DATA_PORT + 2, 2, false, 0),
            Ok(VirtualPciIoOutcome::Read(0x5678))
        );
    }

    #[test]
    fn mechanism_one_routes_transactional_command_and_bar_writes() {
        let mut router = VirtualPciConfigurationRouter::new();
        let routed = VirtualPciLocation::new(0, 0, 1, 0).unwrap();
        router.attach(routed, function(1)).unwrap();
        let mut transport = VirtualPciConfigurationMechanismOne::new();
        transport
            .access(
                &mut router,
                PCI_CONFIGURATION_ADDRESS_PORT,
                4,
                true,
                selector(0, 1, 0, 16),
            )
            .unwrap();
        assert_eq!(
            transport.access(
                &mut router,
                PCI_CONFIGURATION_DATA_PORT,
                4,
                true,
                0x2000_0fff
            ),
            Ok(VirtualPciIoOutcome::Write(
                VirtualPciWriteOutcome::BarAddress(0x2000_0000)
            ))
        );
        transport
            .access(
                &mut router,
                PCI_CONFIGURATION_ADDRESS_PORT,
                4,
                true,
                selector(0, 1, 0, 4),
            )
            .unwrap();
        let mut mapper = RecordingMapper::default();
        assert_eq!(
            transport.access_with_mapper(
                &mut router,
                PCI_CONFIGURATION_DATA_PORT,
                2,
                true,
                u32::from(PCI_COMMAND_MEMORY_SPACE),
                &mut mapper,
            ),
            Ok(VirtualPciIoOutcome::Write(VirtualPciWriteOutcome::Command(
                PCI_COMMAND_MEMORY_SPACE
            )))
        );
        assert_eq!(
            router.read(routed, 4, 2),
            Ok(u32::from(PCI_COMMAND_MEMORY_SPACE))
        );
    }

    #[test]
    fn mechanism_one_absent_and_disabled_accesses_are_conventional_and_bounded() {
        let mut router = VirtualPciConfigurationRouter::new();
        let mut transport = VirtualPciConfigurationMechanismOne::new();
        for (port, size, mask) in [
            (PCI_CONFIGURATION_DATA_PORT, 1, u8::MAX as u32),
            (PCI_CONFIGURATION_DATA_PORT, 2, u16::MAX as u32),
            (PCI_CONFIGURATION_DATA_PORT, 4, u32::MAX),
        ] {
            assert_eq!(
                transport.access(&mut router, port, size, false, 0),
                Ok(VirtualPciIoOutcome::AbsentRead(mask))
            );
            assert_eq!(
                transport.access(&mut router, port, size, true, 0xa5),
                Ok(VirtualPciIoOutcome::AbsentWrite)
            );
        }
        transport
            .access(
                &mut router,
                PCI_CONFIGURATION_ADDRESS_PORT,
                4,
                true,
                selector(0, 31, 7, 0),
            )
            .unwrap();
        assert_eq!(
            transport.access(&mut router, PCI_CONFIGURATION_DATA_PORT + 3, 1, false, 0),
            Ok(VirtualPciIoOutcome::AbsentRead(u8::MAX as u32))
        );
    }

    #[test]
    fn mechanism_one_rejects_noncanonical_selectors_and_crossing_accesses() {
        let mut router = VirtualPciConfigurationRouter::new();
        let mut transport = VirtualPciConfigurationMechanismOne::new();
        for value in [1, 1 << 24, 1 << 30] {
            assert_eq!(
                transport.access(&mut router, PCI_CONFIGURATION_ADDRESS_PORT, 4, true, value),
                Err(VirtualPciError::InvalidTransport)
            );
            assert_eq!(transport.address(), 0);
        }
        for (port, size) in [
            (PCI_CONFIGURATION_ADDRESS_PORT, 2),
            (PCI_CONFIGURATION_DATA_PORT + 1, 2),
            (PCI_CONFIGURATION_DATA_PORT + 2, 4),
            (PCI_CONFIGURATION_DATA_PORT + 4, 1),
        ] {
            assert_eq!(
                transport.access(&mut router, port, size, false, 0),
                Err(VirtualPciError::InvalidTransport)
            );
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RunBackendError {
        Unused,
        Completion,
    }

    struct RunBackend {
        exit: crate::VmExit,
        completion: Option<(u32, u16, u8, u32)>,
        fail_completion: bool,
    }

    impl crate::VmBackend for RunBackend {
        type Error = RunBackendError;

        fn run(&mut self, _vcpu: u32) -> Result<crate::VmExit, Self::Error> {
            Ok(self.exit)
        }

        fn read_guest(&self, _guest_address: u64, _output: &mut [u8]) -> Result<(), Self::Error> {
            Err(RunBackendError::Unused)
        }

        fn write_guest(&mut self, _guest_address: u64, _input: &[u8]) -> Result<(), Self::Error> {
            Err(RunBackendError::Unused)
        }

        fn inject_interrupt(&mut self, _vcpu: u32, _vector: u8) -> Result<(), Self::Error> {
            Err(RunBackendError::Unused)
        }
    }

    impl crate::IoReadCompleter for RunBackend {
        fn complete_io_read(
            &mut self,
            vcpu: u32,
            port: u16,
            size: u8,
            value: u32,
        ) -> Result<(), Self::Error> {
            if self.fail_completion {
                return Err(RunBackendError::Completion);
            }
            self.completion = Some((vcpu, port, size, value));
            Ok(())
        }
    }

    fn running_vm() -> (crate::VmTable<1>, crate::VmId) {
        let mut vms = crate::VmTable::new();
        let vm = vms.create(8).unwrap();
        vms.mark_loaded(vm).unwrap();
        vms.start(vm).unwrap();
        (vms, vm)
    }

    #[test]
    fn common_runner_completes_exact_present_and_absent_reads() {
        let mut router = VirtualPciConfigurationRouter::new();
        router
            .attach(VirtualPciLocation::new(0, 0, 1, 0).unwrap(), function(1))
            .unwrap();
        let mut transport = VirtualPciConfigurationMechanismOne::new();
        transport
            .access(
                &mut router,
                PCI_CONFIGURATION_ADDRESS_PORT,
                4,
                true,
                selector(0, 1, 0, 0),
            )
            .unwrap();
        let capabilities = crate::CapabilitySpace::<0>::new();
        let memory = crate::GuestMemory::<0>::new();
        let mut hypercalls =
            crate::HypercallRouter::new(crate::ObjectId(1), crate::ObjectId(2), crate::ObjectId(3));
        let (mut vms, vm) = running_vm();
        let mut backend = RunBackend {
            exit: crate::VmExit::Io {
                port: PCI_CONFIGURATION_DATA_PORT,
                size: 2,
                write: false,
                value: 0,
            },
            completion: None,
            fail_completion: false,
        };
        assert_eq!(
            run_pci_configuration_once(
                &mut backend,
                7,
                &mut vms,
                vm,
                &mut hypercalls,
                &capabilities,
                &memory,
                &mut transport,
                &mut router,
            ),
            Ok(VirtualPciIoOutcome::Read(0x1234))
        );
        assert_eq!(
            backend.completion,
            Some((7, PCI_CONFIGURATION_DATA_PORT, 2, 0x1234))
        );
        assert_eq!(vms.state(vm), Ok(crate::VmState::Running));

        transport
            .access(
                &mut router,
                PCI_CONFIGURATION_ADDRESS_PORT,
                4,
                true,
                selector(0, 2, 0, 0),
            )
            .unwrap();
        backend.completion = None;
        assert_eq!(
            run_pci_configuration_once(
                &mut backend,
                7,
                &mut vms,
                vm,
                &mut hypercalls,
                &capabilities,
                &memory,
                &mut transport,
                &mut router,
            ),
            Ok(VirtualPciIoOutcome::AbsentRead(u16::MAX as u32))
        );
        assert_eq!(
            backend.completion,
            Some((7, PCI_CONFIGURATION_DATA_PORT, 2, u16::MAX as u32))
        );
    }

    #[test]
    fn common_runner_write_never_invokes_read_completion() {
        let mut router = VirtualPciConfigurationRouter::new();
        let mut transport = VirtualPciConfigurationMechanismOne::new();
        let selected = selector(0, 1, 0, 0);
        let mut backend = RunBackend {
            exit: crate::VmExit::Io {
                port: PCI_CONFIGURATION_ADDRESS_PORT,
                size: 4,
                write: true,
                value: selected,
            },
            completion: None,
            fail_completion: false,
        };
        let (mut vms, vm) = running_vm();
        assert_eq!(
            run_pci_configuration_once(
                &mut backend,
                0,
                &mut vms,
                vm,
                &mut crate::HypercallRouter::new(
                    crate::ObjectId(1),
                    crate::ObjectId(2),
                    crate::ObjectId(3),
                ),
                &crate::CapabilitySpace::<0>::new(),
                &crate::GuestMemory::<0>::new(),
                &mut transport,
                &mut router,
            ),
            Ok(VirtualPciIoOutcome::AddressRegister(selected))
        );
        assert_eq!(transport.address(), selected);
        assert_eq!(backend.completion, None);
    }

    #[test]
    fn common_runner_memory_decode_write_is_bound_to_native_mapping() {
        let routed = VirtualPciLocation::new(0, 0, 1, 0).unwrap();
        let mut router = VirtualPciConfigurationRouter::new();
        router.attach(routed, function(13)).unwrap();
        router.write(routed, 16, 4, 0x6789_a000).unwrap();
        let mut transport = VirtualPciConfigurationMechanismOne::new();
        transport
            .access(
                &mut router,
                PCI_CONFIGURATION_ADDRESS_PORT,
                4,
                true,
                selector(0, 1, 0, 4),
            )
            .unwrap();
        let mut backend = RunBackend {
            exit: crate::VmExit::Io {
                port: PCI_CONFIGURATION_DATA_PORT,
                size: 2,
                write: true,
                value: u32::from(PCI_COMMAND_MEMORY_SPACE),
            },
            completion: None,
            fail_completion: false,
        };
        let mut mapper = RecordingMapper::default();
        let (mut vms, vm) = running_vm();
        assert_eq!(
            run_pci_configuration_once_with_mapper(
                &mut backend,
                0,
                &mut vms,
                vm,
                &mut crate::HypercallRouter::new(
                    crate::ObjectId(1),
                    crate::ObjectId(2),
                    crate::ObjectId(3),
                ),
                &crate::CapabilitySpace::<0>::new(),
                &crate::GuestMemory::<0>::new(),
                &mut transport,
                &mut router,
                &mut mapper,
            ),
            Ok(VirtualPciIoOutcome::Write(VirtualPciWriteOutcome::Command(
                PCI_COMMAND_MEMORY_SPACE
            )))
        );
        assert_eq!(mapper.map_calls, 1);
        assert_eq!(router.read(routed, 4, 2), Ok(2));

        let mut rejected_router = VirtualPciConfigurationRouter::new();
        rejected_router.attach(routed, function(13)).unwrap();
        rejected_router.write(routed, 16, 4, 0x6789_a000).unwrap();
        let mut rejected_transport = VirtualPciConfigurationMechanismOne::new();
        rejected_transport
            .access(
                &mut rejected_router,
                PCI_CONFIGURATION_ADDRESS_PORT,
                4,
                true,
                selector(0, 1, 0, 4),
            )
            .unwrap();
        let mut rejected_mapper = RecordingMapper {
            map_error: Some(VirtualPciNativeResourceError::Rejected),
            ..RecordingMapper::default()
        };
        let (mut rejected_vms, rejected_vm) = running_vm();
        assert_eq!(
            run_pci_configuration_once_with_mapper(
                &mut backend,
                0,
                &mut rejected_vms,
                rejected_vm,
                &mut crate::HypercallRouter::new(
                    crate::ObjectId(1),
                    crate::ObjectId(2),
                    crate::ObjectId(3),
                ),
                &crate::CapabilitySpace::<0>::new(),
                &crate::GuestMemory::<0>::new(),
                &mut rejected_transport,
                &mut rejected_router,
                &mut rejected_mapper,
            ),
            Err(VirtualPciRunError::Transport(
                VirtualPciError::NativeResourceRejected
            ))
        );
        assert_eq!(rejected_router.read(routed, 4, 2), Ok(0));
        assert_eq!(rejected_vms.state(rejected_vm), Ok(crate::VmState::Failed));
    }

    #[test]
    fn common_runner_completion_failure_and_wrong_exit_fail_vm() {
        let mut router = VirtualPciConfigurationRouter::new();
        let mut transport = VirtualPciConfigurationMechanismOne::new();
        let mut backend = RunBackend {
            exit: crate::VmExit::Io {
                port: PCI_CONFIGURATION_DATA_PORT,
                size: 4,
                write: false,
                value: 0,
            },
            completion: None,
            fail_completion: true,
        };
        let capabilities = crate::CapabilitySpace::<0>::new();
        let memory = crate::GuestMemory::<0>::new();
        let mut hypercalls =
            crate::HypercallRouter::new(crate::ObjectId(1), crate::ObjectId(2), crate::ObjectId(3));
        let (mut vms, vm) = running_vm();
        assert_eq!(
            run_pci_configuration_once(
                &mut backend,
                0,
                &mut vms,
                vm,
                &mut hypercalls,
                &capabilities,
                &memory,
                &mut transport,
                &mut router,
            ),
            Err(VirtualPciRunError::Completion(RunBackendError::Completion))
        );
        assert_eq!(vms.state(vm), Ok(crate::VmState::Failed));

        let (mut vms, vm) = running_vm();
        backend.exit = crate::VmExit::Interrupted;
        backend.fail_completion = false;
        assert_eq!(
            run_pci_configuration_once(
                &mut backend,
                0,
                &mut vms,
                vm,
                &mut hypercalls,
                &capabilities,
                &memory,
                &mut transport,
                &mut router,
            ),
            Err(VirtualPciRunError::InvalidExit)
        );
        assert_eq!(vms.state(vm), Ok(crate::VmState::Failed));
    }
}
