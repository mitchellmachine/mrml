//! Authority-free validation of an enumerated AHCI PCI function.
//!
//! The platform PCI enumerator remains responsible for configuration-space
//! access and BAR sizing. This module accepts its immutable snapshot and emits
//! identity/geometry only; mapping or accessing the ABAR requires separate
//! capabilities and a later driver layer.

pub const AHCI_PCI_CLASS: u8 = 0x01;
pub const AHCI_PCI_SUBCLASS: u8 = 0x06;
pub const AHCI_PCI_PROGRAMMING_INTERFACE: u8 = 0x01;
pub const AHCI_ABAR_MINIMUM_BYTES: u64 = 0x1100;

const PCI_BAR_IO_SPACE: u32 = 1;
const PCI_MEMORY_BAR_TYPE_MASK: u32 = 0b110;
const PCI_MEMORY_BAR_32_BIT: u32 = 0;
const PCI_MEMORY_BAR_PREFETCHABLE: u32 = 0b1000;
const PCI_MEMORY_BAR_ADDRESS_MASK: u32 = 0xffff_fff0;

/// Values captured by an exclusive PCI enumerator around one conventional
/// BAR sizing transaction. Observation data never grants mapping or MMIO
/// authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciAbarSizeProbe {
    original: u32,
    size_mask: u32,
    restored: u32,
}

impl AhciAbarSizeProbe {
    pub const fn new(original: u32, size_mask: u32, restored: u32) -> Self {
        Self {
            original,
            size_mask,
            restored,
        }
    }

    /// Derives an exact 32-bit memory BAR extent only after exact restoration
    /// and a conventional contiguous size mask were observed.
    pub fn bytes(self) -> Result<u64, AhciAbarSizeProbeError> {
        if self.restored != self.original {
            return Err(AhciAbarSizeProbeError::RestorationMismatch);
        }
        if self.original & PCI_BAR_IO_SPACE != 0 {
            return Err(AhciAbarSizeProbeError::IoBar);
        }
        if self.original & PCI_MEMORY_BAR_TYPE_MASK != PCI_MEMORY_BAR_32_BIT {
            return Err(AhciAbarSizeProbeError::UnsupportedMemoryBar);
        }
        if self.original & PCI_MEMORY_BAR_PREFETCHABLE != 0 {
            return Err(AhciAbarSizeProbeError::PrefetchableBar);
        }
        let masked = self.size_mask & PCI_MEMORY_BAR_ADDRESS_MASK;
        let bytes = (!masked).wrapping_add(1) & PCI_MEMORY_BAR_ADDRESS_MASK;
        if bytes == 0
            || !bytes.is_power_of_two()
            || masked != (!(bytes - 1) & PCI_MEMORY_BAR_ADDRESS_MASK)
        {
            return Err(AhciAbarSizeProbeError::MalformedSizeMask);
        }
        let bytes = u64::from(bytes);
        if bytes < AHCI_ABAR_MINIMUM_BYTES {
            return Err(AhciAbarSizeProbeError::TooSmall);
        }
        let base = u64::from(self.original & PCI_MEMORY_BAR_ADDRESS_MASK);
        if base == 0 {
            return Err(AhciAbarSizeProbeError::MissingAbar);
        }
        if base & (bytes - 1) != 0 {
            return Err(AhciAbarSizeProbeError::MisalignedAbar);
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciAbarSizeProbeError {
    RestorationMismatch,
    IoBar,
    UnsupportedMemoryBar,
    PrefetchableBar,
    MalformedSizeMask,
    TooSmall,
    MissingAbar,
    MisalignedAbar,
}

const PCI_COMMAND_MEMORY_SPACE: u16 = 1 << 1;
const PCI_COMMAND_BUS_MASTER: u16 = 1 << 2;

/// Exclusive configuration-space mechanism for one assigned, quiescent AHCI
/// function. Implementations must use exact-width accesses and report no
/// success until the access has completed.
///
/// # Safety
///
/// The implementation must address only `location`, retain exclusive function
/// ownership, and ensure no device, firmware, or peer can race command/BAR5
/// accesses for the duration of a probe.
pub unsafe trait AhciPciBarProbeIo {
    type Error;

    fn read_command(&mut self, location: PciFunctionLocation) -> Result<u16, Self::Error>;
    fn write_command(
        &mut self,
        location: PciFunctionLocation,
        value: u16,
    ) -> Result<(), Self::Error>;
    fn read_abar(&mut self, location: PciFunctionLocation) -> Result<u32, Self::Error>;
    fn write_abar(&mut self, location: PciFunctionLocation, value: u32) -> Result<(), Self::Error>;
}

/// Linear owner for one exclusive, quiescent AHCI PCI function during BAR5
/// sizing. The backend is never exposed separately while a transaction may be
/// incompletely restored.
#[must_use = "exclusive PCI function ownership must be retained"]
pub struct ExclusiveAhciPciFunction<B> {
    snapshot: AhciPciFunctionSnapshot,
    backend: B,
}

impl<B: AhciPciBarProbeIo> ExclusiveAhciPciFunction<B> {
    /// Admits a read-only enumerator snapshot before any configuration write.
    /// `abar_bytes` must be zero because only this owner may establish it.
    ///
    /// # Safety
    ///
    /// `backend` must exclusively own the exact function in `snapshot`, the
    /// function must be quiescent, and no concurrent configuration access may
    /// occur until this owner is consumed.
    pub unsafe fn admit(
        snapshot: AhciPciFunctionSnapshot,
        backend: B,
    ) -> Result<Self, (AhciDiscoveryError, B)> {
        if snapshot.abar_bytes != 0 {
            return Err((AhciDiscoveryError::InvalidAbarSize, backend));
        }
        if let Err(error) = validate_ahci_snapshot_fixed(snapshot) {
            return Err((error, backend));
        }
        Ok(Self { snapshot, backend })
    }

    pub const fn location(&self) -> PciFunctionLocation {
        self.snapshot.location
    }

    /// Recovers the exclusive backend only while no probe is in flight. A
    /// failed uncertain transaction remains sealed in its failure owner.
    pub fn into_backend(self) -> B {
        self.backend
    }

    pub fn probe_abar(
        mut self,
    ) -> Result<ProbedAhciPciFunction<B>, AhciPciBarProbeFailure<B, B::Error>> {
        let location = self.snapshot.location;
        let original_abar = match self.backend.read_abar(location) {
            Ok(value) if value == self.snapshot.abar => value,
            Ok(_) => {
                return Err(AhciPciBarProbeFailure::clean(
                    self,
                    AhciPciBarProbeError::Drift,
                ));
            }
            Err(error) => {
                return Err(AhciPciBarProbeFailure::clean(
                    self,
                    AhciPciBarProbeError::Backend(error),
                ));
            }
        };
        let original_command = match self.backend.read_command(location) {
            Ok(value) => value,
            Err(error) => {
                return Err(AhciPciBarProbeFailure::clean(
                    self,
                    AhciPciBarProbeError::Backend(error),
                ));
            }
        };
        let disabled = original_command & !(PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER);
        if let Err(error) = self.backend.write_command(location, disabled) {
            return Err(AhciPciBarProbeFailure::uncertain(
                self,
                AhciPciBarProbeError::Backend(error),
            ));
        }
        match self.backend.read_command(location) {
            Ok(value) if value == disabled => {}
            Ok(_) => {
                return Err(restore_probe_failure(
                    self,
                    original_command,
                    original_abar,
                    AhciPciBarProbeError::DisableMismatch,
                ));
            }
            Err(error) => {
                return Err(restore_probe_failure(
                    self,
                    original_command,
                    original_abar,
                    AhciPciBarProbeError::Backend(error),
                ));
            }
        }
        if let Err(error) = self.backend.write_abar(location, u32::MAX) {
            return Err(restore_probe_failure(
                self,
                original_command,
                original_abar,
                AhciPciBarProbeError::Backend(error),
            ));
        }
        let size_mask = match self.backend.read_abar(location) {
            Ok(value) => value,
            Err(error) => {
                return Err(restore_probe_failure(
                    self,
                    original_command,
                    original_abar,
                    AhciPciBarProbeError::Backend(error),
                ));
            }
        };
        let restored = restore_exact(&mut self.backend, location, original_command, original_abar);
        match restored {
            Ok(true) => {}
            Ok(false) => {
                return Err(AhciPciBarProbeFailure::uncertain(
                    self,
                    AhciPciBarProbeError::RestorationMismatch,
                ));
            }
            Err(error) => {
                return Err(AhciPciBarProbeFailure::uncertain(
                    self,
                    AhciPciBarProbeError::RestorationBackend(error),
                ));
            }
        }
        let bytes = match AhciAbarSizeProbe::new(original_abar, size_mask, original_abar).bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(AhciPciBarProbeFailure::clean(
                    self,
                    AhciPciBarProbeError::Geometry(error),
                ));
            }
        };
        self.snapshot.abar_bytes = bytes;
        let descriptor = match AhciAbarDescriptor::validate(self.snapshot) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                return Err(AhciPciBarProbeFailure::clean(
                    self,
                    AhciPciBarProbeError::Discovery(error),
                ));
            }
        };
        Ok(ProbedAhciPciFunction {
            descriptor,
            owner: self,
        })
    }
}

pub struct ProbedAhciPciFunction<B> {
    descriptor: AhciAbarDescriptor,
    owner: ExclusiveAhciPciFunction<B>,
}

impl<B> ProbedAhciPciFunction<B> {
    pub const fn descriptor(&self) -> AhciAbarDescriptor {
        self.descriptor
    }

    pub fn into_owner(self) -> ExclusiveAhciPciFunction<B> {
        self.owner
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum AhciPciBarProbeError<E> {
    Backend(E),
    Drift,
    DisableMismatch,
    RestorationBackend(E),
    RestorationMismatch,
    Geometry(AhciAbarSizeProbeError),
    Discovery(AhciDiscoveryError),
}

pub struct AhciPciBarProbeFailure<B, E> {
    owner: ExclusiveAhciPciFunction<B>,
    error: AhciPciBarProbeError<E>,
    restored: bool,
}

impl<B, E> AhciPciBarProbeFailure<B, E> {
    fn clean(owner: ExclusiveAhciPciFunction<B>, error: AhciPciBarProbeError<E>) -> Self {
        Self {
            owner,
            error,
            restored: true,
        }
    }

    fn uncertain(owner: ExclusiveAhciPciFunction<B>, error: AhciPciBarProbeError<E>) -> Self {
        Self {
            owner,
            error,
            restored: false,
        }
    }

    pub const fn error(&self) -> &AhciPciBarProbeError<E> {
        &self.error
    }

    pub const fn restored(&self) -> bool {
        self.restored
    }

    pub fn into_retry(self) -> Result<ExclusiveAhciPciFunction<B>, Self> {
        if self.restored {
            Ok(self.owner)
        } else {
            Err(self)
        }
    }
}

fn restore_exact<B: AhciPciBarProbeIo>(
    backend: &mut B,
    location: PciFunctionLocation,
    command: u16,
    abar: u32,
) -> Result<bool, B::Error> {
    backend.write_abar(location, abar)?;
    let abar_matches = backend.read_abar(location)? == abar;
    backend.write_command(location, command)?;
    let command_matches = backend.read_command(location)? == command;
    Ok(abar_matches && command_matches)
}

fn restore_probe_failure<B: AhciPciBarProbeIo>(
    mut owner: ExclusiveAhciPciFunction<B>,
    command: u16,
    abar: u32,
    error: AhciPciBarProbeError<B::Error>,
) -> AhciPciBarProbeFailure<B, B::Error> {
    match restore_exact(&mut owner.backend, owner.snapshot.location, command, abar) {
        Ok(true) => AhciPciBarProbeFailure::clean(owner, error),
        Ok(false) => {
            AhciPciBarProbeFailure::uncertain(owner, AhciPciBarProbeError::RestorationMismatch)
        }
        Err(error) => AhciPciBarProbeFailure::uncertain(
            owner,
            AhciPciBarProbeError::RestorationBackend(error),
        ),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciFunctionLocation {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciFunctionLocation {
    pub const fn new(segment: u16, bus: u8, device: u8, function: u8) -> Option<Self> {
        if device > 31 || function > 7 {
            return None;
        }
        Some(Self {
            segment,
            bus,
            device,
            function,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciPciFunctionSnapshot {
    pub location: PciFunctionLocation,
    pub configuration_generation: u64,
    pub vendor_id: u16,
    pub device_id: u16,
    pub header_type: u8,
    pub class: u8,
    pub subclass: u8,
    pub programming_interface: u8,
    /// BAR5 as read before the enumerator's bounded size probe.
    pub abar: u32,
    /// Restored BAR5 size established by the enumerator's bounded size probe.
    pub abar_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AhciAbarDescriptor {
    pub location: PciFunctionLocation,
    pub configuration_generation: u64,
    pub vendor_id: u16,
    pub device_id: u16,
    pub physical_base: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciDiscoveryError {
    AbsentFunction,
    InvalidGeneration,
    UnsupportedHeader,
    NotAhci,
    IoBar,
    UnsupportedMemoryBar,
    PrefetchableBar,
    MissingAbar,
    InvalidAbarSize,
    MisalignedAbar,
}

impl AhciAbarDescriptor {
    pub fn identity_matches(self, other: Self) -> bool {
        self.location == other.location
            && self.configuration_generation == other.configuration_generation
            && self.vendor_id == other.vendor_id
            && self.device_id == other.device_id
    }

    pub fn validate(snapshot: AhciPciFunctionSnapshot) -> Result<Self, AhciDiscoveryError> {
        validate_ahci_snapshot_fixed(snapshot)?;
        let physical_base = u64::from(snapshot.abar & PCI_MEMORY_BAR_ADDRESS_MASK);
        if snapshot.abar_bytes < AHCI_ABAR_MINIMUM_BYTES || !snapshot.abar_bytes.is_power_of_two() {
            return Err(AhciDiscoveryError::InvalidAbarSize);
        }
        if physical_base & (snapshot.abar_bytes - 1) != 0 {
            return Err(AhciDiscoveryError::MisalignedAbar);
        }

        Ok(Self {
            location: snapshot.location,
            configuration_generation: snapshot.configuration_generation,
            vendor_id: snapshot.vendor_id,
            device_id: snapshot.device_id,
            physical_base,
            bytes: snapshot.abar_bytes,
        })
    }
}

fn validate_ahci_snapshot_fixed(
    snapshot: AhciPciFunctionSnapshot,
) -> Result<(), AhciDiscoveryError> {
    if snapshot.vendor_id == 0 || snapshot.vendor_id == u16::MAX {
        return Err(AhciDiscoveryError::AbsentFunction);
    }
    if snapshot.configuration_generation == 0 {
        return Err(AhciDiscoveryError::InvalidGeneration);
    }
    if snapshot.header_type & 0x7f != 0 {
        return Err(AhciDiscoveryError::UnsupportedHeader);
    }
    if (
        snapshot.class,
        snapshot.subclass,
        snapshot.programming_interface,
    ) != (
        AHCI_PCI_CLASS,
        AHCI_PCI_SUBCLASS,
        AHCI_PCI_PROGRAMMING_INTERFACE,
    ) {
        return Err(AhciDiscoveryError::NotAhci);
    }
    if snapshot.abar & PCI_BAR_IO_SPACE != 0 {
        return Err(AhciDiscoveryError::IoBar);
    }
    if snapshot.abar & PCI_MEMORY_BAR_TYPE_MASK != PCI_MEMORY_BAR_32_BIT {
        return Err(AhciDiscoveryError::UnsupportedMemoryBar);
    }
    if snapshot.abar & PCI_MEMORY_BAR_PREFETCHABLE != 0 {
        return Err(AhciDiscoveryError::PrefetchableBar);
    }

    let physical_base = u64::from(snapshot.abar & PCI_MEMORY_BAR_ADDRESS_MASK);
    if physical_base == 0 {
        return Err(AhciDiscoveryError::MissingAbar);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Config {
        command: u16,
        abar: u32,
        size_mask: u32,
        writes: usize,
        drift_restore: bool,
    }

    // SAFETY: this deterministic model addresses only the supplied function
    // and has no access outside its owned command/BAR values.
    unsafe impl AhciPciBarProbeIo for Config {
        type Error = ();

        fn read_command(&mut self, _: PciFunctionLocation) -> Result<u16, Self::Error> {
            Ok(self.command)
        }

        fn write_command(&mut self, _: PciFunctionLocation, value: u16) -> Result<(), Self::Error> {
            self.command = value;
            self.writes += 1;
            Ok(())
        }

        fn read_abar(&mut self, _: PciFunctionLocation) -> Result<u32, Self::Error> {
            Ok(if self.abar == u32::MAX {
                self.size_mask
            } else {
                self.abar
            })
        }

        fn write_abar(&mut self, _: PciFunctionLocation, value: u32) -> Result<(), Self::Error> {
            self.abar = if self.drift_restore && value != u32::MAX {
                value + 0x1000
            } else {
                value
            };
            self.writes += 1;
            Ok(())
        }
    }

    fn config(mask: u32) -> Config {
        Config {
            command: PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER | 1,
            abar: snapshot().abar,
            size_mask: mask,
            writes: 0,
            drift_restore: false,
        }
    }

    fn unprobed_snapshot() -> AhciPciFunctionSnapshot {
        let mut value = snapshot();
        value.abar_bytes = 0;
        value
    }

    fn snapshot() -> AhciPciFunctionSnapshot {
        AhciPciFunctionSnapshot {
            location: PciFunctionLocation::new(0, 0, 31, 2).unwrap(),
            configuration_generation: 7,
            vendor_id: 0x8086,
            device_id: 0x7a62,
            header_type: 0,
            class: AHCI_PCI_CLASS,
            subclass: AHCI_PCI_SUBCLASS,
            programming_interface: AHCI_PCI_PROGRAMMING_INTERFACE,
            abar: 0xf7f0_0000,
            abar_bytes: 0x2000,
        }
    }

    #[test]
    fn accepts_exact_conventional_ahci_function() {
        let descriptor = AhciAbarDescriptor::validate(snapshot()).unwrap();
        assert_eq!(descriptor.physical_base, 0xf7f0_0000);
        assert_eq!(descriptor.bytes, 0x2000);
        assert_eq!(descriptor.configuration_generation, 7);
    }

    #[test]
    fn rejects_other_mass_storage_interfaces() {
        for (class, subclass, interface) in [
            (0x01, 0x06, 0x00),
            (0x01, 0x08, 0x02),
            (0x01, 0x04, 0x00),
            (0x02, 0x00, 0x00),
        ] {
            let mut candidate = snapshot();
            candidate.class = class;
            candidate.subclass = subclass;
            candidate.programming_interface = interface;
            assert_eq!(
                AhciAbarDescriptor::validate(candidate),
                Err(AhciDiscoveryError::NotAhci)
            );
        }
    }

    #[test]
    fn rejects_absent_stale_or_non_type_zero_functions() {
        let mut candidate = snapshot();
        candidate.vendor_id = u16::MAX;
        assert_eq!(
            AhciAbarDescriptor::validate(candidate),
            Err(AhciDiscoveryError::AbsentFunction)
        );
        candidate = snapshot();
        candidate.configuration_generation = 0;
        assert_eq!(
            AhciAbarDescriptor::validate(candidate),
            Err(AhciDiscoveryError::InvalidGeneration)
        );
        candidate = snapshot();
        candidate.header_type = 1;
        assert_eq!(
            AhciAbarDescriptor::validate(candidate),
            Err(AhciDiscoveryError::UnsupportedHeader)
        );
    }

    #[test]
    fn rejects_unsafe_or_ambiguous_abar_geometry() {
        for (abar, bytes, error) in [
            (0xf7f0_0001, 0x2000, AhciDiscoveryError::IoBar),
            (
                0xf7f0_0004,
                0x2000,
                AhciDiscoveryError::UnsupportedMemoryBar,
            ),
            (0xf7f0_0008, 0x2000, AhciDiscoveryError::PrefetchableBar),
            (0, 0x2000, AhciDiscoveryError::MissingAbar),
            (0xf7f0_0000, 0x1000, AhciDiscoveryError::InvalidAbarSize),
            (0xf7f0_0000, 0x3000, AhciDiscoveryError::InvalidAbarSize),
            (0xf7f0_1000, 0x2000, AhciDiscoveryError::MisalignedAbar),
        ] {
            let mut candidate = snapshot();
            candidate.abar = abar;
            candidate.abar_bytes = bytes;
            assert_eq!(AhciAbarDescriptor::validate(candidate), Err(error));
        }
    }

    #[test]
    fn location_rejects_out_of_range_requester_fields() {
        assert!(PciFunctionLocation::new(0, 0, 31, 7).is_some());
        assert!(PciFunctionLocation::new(0, 0, 32, 0).is_none());
        assert!(PciFunctionLocation::new(0, 0, 0, 8).is_none());
    }

    #[test]
    fn abar_size_probe_requires_restoration_and_contiguous_geometry() {
        let original = 0xf7f0_0000;
        assert_eq!(
            AhciAbarSizeProbe::new(original, 0xffff_e000, original).bytes(),
            Ok(0x2000)
        );
        assert_eq!(
            AhciAbarSizeProbe::new(original, 0xffff_e000, original + 0x1000).bytes(),
            Err(AhciAbarSizeProbeError::RestorationMismatch)
        );
        assert_eq!(
            AhciAbarSizeProbe::new(original, 0xffff_d000, original).bytes(),
            Err(AhciAbarSizeProbeError::MalformedSizeMask)
        );
        assert_eq!(
            AhciAbarSizeProbe::new(original, 0xffff_f000, original).bytes(),
            Err(AhciAbarSizeProbeError::TooSmall)
        );
        assert_eq!(
            AhciAbarSizeProbe::new(original + 0x1000, 0xffff_e000, original + 0x1000).bytes(),
            Err(AhciAbarSizeProbeError::MisalignedAbar)
        );
    }

    #[test]
    fn abar_size_probe_rejects_nonconventional_encodings() {
        assert_eq!(
            AhciAbarSizeProbe::new(0xf7f0_0001, 0xffff_e001, 0xf7f0_0001).bytes(),
            Err(AhciAbarSizeProbeError::IoBar)
        );
        assert_eq!(
            AhciAbarSizeProbe::new(0xf7f0_0004, 0xffff_e004, 0xf7f0_0004).bytes(),
            Err(AhciAbarSizeProbeError::UnsupportedMemoryBar)
        );
        assert_eq!(
            AhciAbarSizeProbe::new(0xf7f0_0008, 0xffff_e008, 0xf7f0_0008).bytes(),
            Err(AhciAbarSizeProbeError::PrefetchableBar)
        );
        assert_eq!(
            AhciAbarSizeProbe::new(0, 0xffff_e000, 0).bytes(),
            Err(AhciAbarSizeProbeError::MissingAbar)
        );
    }

    #[test]
    fn exclusive_probe_disables_and_exactly_restores_configuration() {
        // SAFETY: the controlled backend exclusively models this exact,
        // quiescent function for the duration of the owner.
        let owner =
            unsafe { ExclusiveAhciPciFunction::admit(unprobed_snapshot(), config(0xffff_e000)) }
                .unwrap_or_else(|_| panic!("valid unprobed identity must admit"));
        let probed = owner
            .probe_abar()
            .unwrap_or_else(|_| panic!("exact probe and restoration must succeed"));
        assert_eq!(probed.descriptor().bytes, 0x2000);
        let backend = probed.into_owner().into_backend();
        assert_eq!(
            backend.command,
            PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER | 1
        );
        assert_eq!(backend.abar, snapshot().abar);
        assert_eq!(backend.writes, 4);
    }

    #[test]
    fn geometry_failure_returns_only_an_exactly_restored_retry_owner() {
        // SAFETY: the controlled backend exclusively models this exact,
        // quiescent function for the duration of the owner.
        let owner =
            unsafe { ExclusiveAhciPciFunction::admit(unprobed_snapshot(), config(0xffff_d000)) }
                .unwrap_or_else(|_| panic!("valid unprobed identity must admit"));
        let failure = owner
            .probe_abar()
            .err()
            .unwrap_or_else(|| panic!("malformed mask must fail"));
        assert!(failure.restored());
        assert_eq!(
            failure.error(),
            &AhciPciBarProbeError::Geometry(AhciAbarSizeProbeError::MalformedSizeMask)
        );
        let backend = match failure.into_retry() {
            Ok(owner) => owner.into_backend(),
            Err(_) => panic!("exactly restored failure must return its retry owner"),
        };
        assert_eq!(
            backend.command,
            PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER | 1
        );
        assert_eq!(backend.abar, snapshot().abar);
    }

    #[test]
    fn restoration_drift_seals_the_exclusive_owner() {
        let mut backend = config(0xffff_e000);
        backend.drift_restore = true;
        // SAFETY: the controlled backend exclusively models this exact,
        // quiescent function for the duration of the owner.
        let owner = unsafe { ExclusiveAhciPciFunction::admit(unprobed_snapshot(), backend) }
            .unwrap_or_else(|_| panic!("valid unprobed identity must admit"));
        let failure = owner
            .probe_abar()
            .err()
            .unwrap_or_else(|| panic!("restoration drift must fail"));
        assert!(!failure.restored());
        assert_eq!(failure.error(), &AhciPciBarProbeError::RestorationMismatch);
        assert!(failure.into_retry().is_err());
    }
}
