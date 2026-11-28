use crate::{
    BOOT_SUPERVISOR_SELECTION_BYTES, BootEvidence, BootSupervisorSelection, BootValidationError,
    FramebufferError, FramebufferInfo,
    INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES, INSTALLED_RECOVERY_SATA_ROUTE_BYTES,
    InstalledRecoveryBootIdentity, InstalledRecoverySataRoute, InstalledRecoverySource,
    MemoryError, MemoryKind, MemoryMap, MemoryRegion, PhysAddr, PixelFormat,
};

pub const HANDOFF_HEADER_BYTES: usize = 168;
pub const HANDOFF_REGION_BYTES: usize = 24;
pub const MAX_HANDOFF_REGIONS: usize = 128;
pub const MAX_HANDOFF_MADT_BYTES: usize = 8 * 1024;
pub const MAX_HANDOFF_DMA_ACPI_TABLE_BYTES: usize = 4 * 1024;
const DMA_ACPI_LENGTH_BYTES: usize = 4;
pub const BOOT_USB_PCI_RECORD_BYTES: usize = 40;
pub const PASSIVE_DXE_RECORD_BYTES: usize = 200;
const BOOT_DXE_DIAGNOSTIC_BYTES: usize = 8 + PASSIVE_DXE_RECORD_BYTES;
const SUPERVISOR_TRAILER_BYTES: usize = BOOT_SUPERVISOR_SELECTION_BYTES + 64;
const SUPERVISOR_HANDOFF_MAGIC: &[u8; 16] = b"MRML-HANDOFF-v2\0";
pub const HANDOFF_SERVICE_BYTES: usize = 160;
pub const HANDOFF_APPLICATION_BYTES: usize = 160;
pub const HANDOFF_RECOVERY_STATE_BYTES: usize = 40;
pub const MAX_HANDOFF_BYTES: usize = HANDOFF_HEADER_BYTES
    + MAX_HANDOFF_REGIONS * HANDOFF_REGION_BYTES
    + MAX_HANDOFF_MADT_BYTES
    + 16
    + HANDOFF_SERVICE_BYTES
    + HANDOFF_APPLICATION_BYTES
    + HANDOFF_RECOVERY_STATE_BYTES
    + INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES
    + INSTALLED_RECOVERY_SATA_ROUTE_BYTES
    + DMA_ACPI_LENGTH_BYTES
    + 2 * MAX_HANDOFF_DMA_ACPI_TABLE_BYTES
    + BOOT_USB_PCI_RECORD_BYTES
    + BOOT_DXE_DIAGNOSTIC_BYTES
    + SUPERVISOR_TRAILER_BYTES;

const FLAG_SECURE_BOOT: u16 = 1;
const FLAG_MEASURED_BOOT: u16 = 1 << 1;
const FLAG_ROLLBACK_PROTECTED: u16 = 1 << 2;
const FLAG_MADT_SNAPSHOT: u16 = 1 << 3;
const FLAG_AP_TRAMPOLINE: u16 = 1 << 4;
const FLAG_SERVICE_IMAGE: u16 = 1 << 5;
const FLAG_RECOVERY_STATE: u16 = 1 << 6;
const FLAG_COHERENT_RELEASE: u16 = 1 << 7;
const FLAG_APPLICATION_IMAGE: u16 = 1 << 8;
const FLAG_TOTAL_MICROVM_ONCE: u16 = 1 << 9;
const FLAG_INSTALLED_RECOVERY_IDENTITY: u16 = 1 << 10;
const FLAG_INSTALLED_RECOVERY_SATA_ROUTE: u16 = 1 << 11;
const FLAG_DMA_ACPI: u16 = 1 << 12;
const FLAG_USB_PCI_DIAGNOSTIC: u16 = 1 << 13;
const FLAG_DXE_DIAGNOSTIC: u16 = 1 << 14;
const FLAG_SUPERVISOR_SELECTION: u16 = 1 << 15;
const SUPERVISOR_EVIDENCE_FLAGS: u16 = FLAG_SECURE_BOOT
    | FLAG_MEASURED_BOOT
    | FLAG_ROLLBACK_PROTECTED
    | FLAG_COHERENT_RELEASE;
const KNOWN_FLAGS: u16 = FLAG_SECURE_BOOT
    | FLAG_MEASURED_BOOT
    | FLAG_ROLLBACK_PROTECTED
    | FLAG_MADT_SNAPSHOT
    | FLAG_AP_TRAMPOLINE
    | FLAG_SERVICE_IMAGE
    | FLAG_RECOVERY_STATE
    | FLAG_COHERENT_RELEASE
    | FLAG_APPLICATION_IMAGE
    | FLAG_TOTAL_MICROVM_ONCE
    | FLAG_INSTALLED_RECOVERY_IDENTITY
    | FLAG_INSTALLED_RECOVERY_SATA_ROUTE
    | FLAG_DMA_ACPI
    | FLAG_USB_PCI_DIAGNOSTIC
    | FLAG_DXE_DIAGNOSTIC;

/// Authority-free, nonpersistent isolation overlay requested by the trusted
/// loader for this boot. Runtime admission must still prove that Total mode is
/// effective; this request cannot grant capabilities or authorize fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootIsolationOverride {
    TotalMicrovmOnce,
}

/// Canonical rollback-state metadata handed off by the authenticated loader.
/// It is evidence data only and carries no recovery or storage authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryStateMetadata {
    accepted_epoch: u64,
    accepted_handle_generation: u32,
    accepted_volume: Option<[u8; 16]>,
    accepted_root_generation: u64,
}

impl RecoveryStateMetadata {
    pub fn new(
        accepted_epoch: u64,
        accepted_handle_generation: u32,
        accepted_volume: Option<[u8; 16]>,
        accepted_root_generation: u64,
    ) -> Result<Self, HandoffError> {
        if accepted_epoch == 0
            || accepted_handle_generation == 0
            || accepted_volume.is_some_and(|volume| volume.iter().all(|byte| *byte == 0))
            || accepted_volume.is_some() != (accepted_root_generation != 0)
        {
            return Err(HandoffError::NonCanonical);
        }
        Ok(Self {
            accepted_epoch,
            accepted_handle_generation,
            accepted_volume,
            accepted_root_generation,
        })
    }

    pub const fn accepted_epoch(self) -> u64 {
        self.accepted_epoch
    }

    pub const fn accepted_handle_generation(self) -> u32 {
        self.accepted_handle_generation
    }

    pub const fn accepted_volume(self) -> Option<[u8; 16]> {
        self.accepted_volume
    }

    pub const fn accepted_root_generation(self) -> u64 {
        self.accepted_root_generation
    }

    pub fn encode(self) -> [u8; HANDOFF_RECOVERY_STATE_BYTES] {
        let mut output = [0; HANDOFF_RECOVERY_STATE_BYTES];
        encode_recovery_state(self, &mut output);
        output
    }

    pub fn decode(input: &[u8; HANDOFF_RECOVERY_STATE_BYTES]) -> Result<Self, HandoffError> {
        decode_recovery_state(input, 0)
    }
}

/// The retained signed envelope, separate from legacy native launch storage.
/// This bounded descriptor is not itself authenticated or safe to dereference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedBootEnvelope {
    artifact_physical: PhysAddr,
    artifact_length: u64,
    version: u64,
    measurement: [u8; 64],
}

impl RetainedBootEnvelope {
    fn new_bounded(
        artifact_physical: PhysAddr,
        artifact_length: u64,
        version: u64,
        measurement: [u8; 64],
        maximum_image_bytes: u32,
    ) -> Result<Self, HandoffError> {
        checked_pages(artifact_physical, artifact_length.div_ceil(crate::PAGE_SIZE))?;
        if version == 0
            || artifact_length
                > u64::from(maximum_image_bytes) + crate::SIGNED_ARTIFACT_OVERHEAD_BYTES as u64
            || measurement == [0; 64]
        {
            return Err(HandoffError::NonCanonical);
        }
        Ok(Self {
            artifact_physical,
            artifact_length,
            version,
            measurement,
        })
    }

    pub const fn artifact_physical(self) -> PhysAddr {
        self.artifact_physical
    }

    pub const fn artifact_length(self) -> u64 {
        self.artifact_length
    }

    pub const fn version(self) -> u64 {
        self.version
    }

    pub const fn measurement(self) -> [u8; 64] {
        self.measurement
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceLaunch {
    envelope: RetainedBootEnvelope,
    image_physical: PhysAddr,
    image_pages: u64,
    image_virtual: u64,
    entry: u64,
    stack_physical: PhysAddr,
    stack_pages: u64,
    stack_top: u64,
    table_physical: PhysAddr,
    table_pages: u64,
}

impl ServiceLaunch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifact_physical: PhysAddr,
        artifact_length: u64,
        image_physical: PhysAddr,
        image_pages: u64,
        image_virtual: u64,
        entry: u64,
        stack_physical: PhysAddr,
        stack_pages: u64,
        stack_top: u64,
        table_physical: PhysAddr,
        table_pages: u64,
        version: u64,
        measurement: [u8; 64],
    ) -> Result<Self, HandoffError> {
        Self::new_bounded(
            artifact_physical,
            artifact_length,
            image_physical,
            image_pages,
            image_virtual,
            entry,
            stack_physical,
            stack_pages,
            stack_top,
            table_physical,
            table_pages,
            version,
            measurement,
            crate::MAX_SERVICE_IMAGE_BYTES,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_bounded(
        artifact_physical: PhysAddr,
        artifact_length: u64,
        image_physical: PhysAddr,
        image_pages: u64,
        image_virtual: u64,
        entry: u64,
        stack_physical: PhysAddr,
        stack_pages: u64,
        stack_top: u64,
        table_physical: PhysAddr,
        table_pages: u64,
        version: u64,
        measurement: [u8; 64],
        maximum_image_bytes: u32,
    ) -> Result<Self, HandoffError> {
        let artifact_pages = artifact_length.div_ceil(crate::PAGE_SIZE);
        let envelope = RetainedBootEnvelope::new_bounded(
            artifact_physical,
            artifact_length,
            version,
            measurement,
            maximum_image_bytes,
        )?;
        let image_bytes = checked_pages(image_physical, image_pages)?;
        let stack_bytes = checked_pages(stack_physical, stack_pages)?;
        let _ = checked_pages(table_physical, table_pages)?;
        let image_end = image_virtual
            .checked_add(image_bytes)
            .ok_or(HandoffError::NonCanonical)?;
        let stack_base = stack_top
            .checked_sub(stack_bytes)
            .ok_or(HandoffError::NonCanonical)?;
        if image_pages > u64::from(maximum_image_bytes).div_ceil(crate::PAGE_SIZE)
            || stack_pages > 256
            || !(4..=256).contains(&table_pages)
            || !user_page(image_virtual)
            || !user_address(entry)
            || entry < image_virtual
            || entry >= image_end
            || !user_page(stack_base)
            || !user_address(stack_top.saturating_sub(1))
            || ranges_overlap(image_virtual, image_end, stack_base, stack_top)
            || physical_ranges_overlap(image_physical, image_pages, stack_physical, stack_pages)
            || physical_ranges_overlap(image_physical, image_pages, table_physical, table_pages)
            || physical_ranges_overlap(stack_physical, stack_pages, table_physical, table_pages)
            || physical_ranges_overlap(
                artifact_physical,
                artifact_pages,
                image_physical,
                image_pages,
            )
            || physical_ranges_overlap(
                artifact_physical,
                artifact_pages,
                stack_physical,
                stack_pages,
            )
            || physical_ranges_overlap(
                artifact_physical,
                artifact_pages,
                table_physical,
                table_pages,
            )
        {
            return Err(HandoffError::NonCanonical);
        }
        Ok(Self {
            envelope,
            image_physical,
            image_pages,
            image_virtual,
            entry,
            stack_physical,
            stack_pages,
            stack_top,
            table_physical,
            table_pages,
        })
    }

    pub const fn envelope(self) -> RetainedBootEnvelope {
        self.envelope
    }

    pub const fn artifact_physical(self) -> PhysAddr {
        self.envelope.artifact_physical()
    }
    pub const fn artifact_length(self) -> u64 {
        self.envelope.artifact_length()
    }

    pub const fn image_physical(self) -> PhysAddr {
        self.image_physical
    }
    pub const fn image_pages(self) -> u64 {
        self.image_pages
    }
    pub const fn image_virtual(self) -> u64 {
        self.image_virtual
    }
    pub const fn entry(self) -> u64 {
        self.entry
    }
    pub const fn stack_physical(self) -> PhysAddr {
        self.stack_physical
    }
    pub const fn stack_pages(self) -> u64 {
        self.stack_pages
    }
    pub const fn stack_top(self) -> u64 {
        self.stack_top
    }
    pub const fn table_physical(self) -> PhysAddr {
        self.table_physical
    }
    pub const fn table_pages(self) -> u64 {
        self.table_pages
    }
    pub const fn version(self) -> u64 {
        self.envelope.version()
    }
    pub const fn measurement(self) -> [u8; 64] {
        self.envelope.measurement()
    }
}

/// Typed ordinary-application launch layout. The physical/virtual layout
/// mechanism is shared with service images, but this distinct type prevents an
/// application from acquiring service identity or lifecycle semantics merely
/// because both are bounded PE32+ user images.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationLaunch(ServiceLaunch);

impl ApplicationLaunch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifact_physical: PhysAddr,
        artifact_length: u64,
        image_physical: PhysAddr,
        image_pages: u64,
        image_virtual: u64,
        entry: u64,
        stack_physical: PhysAddr,
        stack_pages: u64,
        stack_top: u64,
        table_physical: PhysAddr,
        table_pages: u64,
        version: u64,
        measurement: [u8; 64],
    ) -> Result<Self, HandoffError> {
        ServiceLaunch::new_bounded(
            artifact_physical,
            artifact_length,
            image_physical,
            image_pages,
            image_virtual,
            entry,
            stack_physical,
            stack_pages,
            stack_top,
            table_physical,
            table_pages,
            version,
            measurement,
            crate::artifact::MAX_APPLICATION_IMAGE_BYTES,
        )
        .map(Self)
    }

    pub const fn artifact_physical(self) -> PhysAddr {
        self.0.artifact_physical()
    }
    pub const fn artifact_length(self) -> u64 {
        self.0.artifact_length()
    }
    pub const fn image_physical(self) -> PhysAddr {
        self.0.image_physical()
    }
    pub const fn image_pages(self) -> u64 {
        self.0.image_pages()
    }
    pub const fn image_virtual(self) -> u64 {
        self.0.image_virtual()
    }
    pub const fn entry(self) -> u64 {
        self.0.entry()
    }
    pub const fn stack_physical(self) -> PhysAddr {
        self.0.stack_physical()
    }
    pub const fn stack_pages(self) -> u64 {
        self.0.stack_pages()
    }
    pub const fn stack_top(self) -> u64 {
        self.0.stack_top()
    }
    pub const fn table_physical(self) -> PhysAddr {
        self.0.table_physical()
    }
    pub const fn table_pages(self) -> u64 {
        self.0.table_pages()
    }
    pub const fn version(self) -> u64 {
        self.0.version()
    }
    pub const fn measurement(self) -> [u8; 64] {
        self.0.measurement()
    }

    pub(crate) const fn executable_layout(self) -> ServiceLaunch {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffError {
    Truncated,
    BadMagic,
    NonCanonical,
    UnknownFlags,
    TooManyRegions,
    MissingAcpiRoot,
    InvalidFramebuffer(FramebufferError),
    FramebufferOutsideMmio,
    InvalidMemoryMap(MemoryError),
    InvalidBootEvidence(BootValidationError),
}

/// Authority-free status for the isolated firmware-copy diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootDxeDiagnostic {
    Incomplete,
    /// Only wire shape and USB requester/BAR binding have been checked.
    /// The receiver must still independently check ACPI layout and final map.
    Copied([u8; PASSIVE_DXE_RECORD_BYTES]),
}

/// Validated architecture-neutral data passed after UEFI boot services exit.
/// Firmware-owned structures must be normalized into this format first.
pub struct BootHandoff {
    evidence: BootEvidence,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    region_count: usize,
    boot_dma: Option<MemoryRegion>,
    madt_offset: usize,
    madt_length: usize,
    dma_acpi_lengths: Option<(usize, usize)>,
    usb_pci_record: Option<[u8; BOOT_USB_PCI_RECORD_BYTES]>,
    dxe_diagnostic: Option<BootDxeDiagnostic>,
    supervisor_selection: Option<BootSupervisorSelection>,
    ap_trampoline: Option<u64>,
    ap_stack_arena: Option<u64>,
    service: Option<ServiceLaunch>,
    application: Option<ApplicationLaunch>,
    recovery_state: Option<RecoveryStateMetadata>,
    installed_recovery: Option<InstalledRecoveryBootIdentity>,
    installed_recovery_sata_route: Option<InstalledRecoverySataRoute>,
    isolation_override: Option<BootIsolationOverride>,
}

impl BootHandoff {
    pub const fn evidence(&self) -> &BootEvidence {
        &self.evidence
    }

    pub const fn acpi_root(&self) -> u64 {
        self.acpi_root
    }

    pub const fn region_count(&self) -> usize {
        self.region_count
    }

    pub const fn boot_dma(&self) -> Option<MemoryRegion> {
        self.boot_dma
    }

    pub const fn framebuffer(&self) -> FramebufferInfo {
        self.framebuffer
    }

    pub fn madt<'a>(&self, encoded: &'a [u8]) -> Option<&'a [u8]> {
        (self.madt_length != 0)
            .then(|| &encoded[self.madt_offset..self.madt_offset + self.madt_length])
    }

    /// Returns checked firmware snapshots, not permission to access PCI or DMA.
    pub fn dma_acpi<'a>(&self, encoded: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
        let (dmar, mcfg) = self.dma_acpi_lengths?;
        let start = self.madt_offset + self.madt_length + DMA_ACPI_LENGTH_BYTES;
        Some((
            encoded.get(start..start + dmar)?,
            encoded.get(start + dmar..start + dmar + mcfg)?,
        ))
    }

    /// Copied, syntactically checked diagnostic bytes. They do not prove boot
    /// origin, hardware ownership, a usable mapping, or DMA containment.
    pub const fn usb_pci_record(&self) -> Option<&[u8; BOOT_USB_PCI_RECORD_BYTES]> {
        self.usb_pci_record.as_ref()
    }

    pub const fn boot_dxe_diagnostic(&self) -> Option<&BootDxeDiagnostic> {
        self.dxe_diagnostic.as_ref()
    }

    /// The trusted loader's measured selection, not a signature or a launch token.
    pub const fn supervisor_selection(&self) -> Option<BootSupervisorSelection> {
        self.supervisor_selection
    }

    pub const fn ap_trampoline(&self) -> Option<u64> {
        self.ap_trampoline
    }

    pub const fn ap_stack_arena(&self) -> Option<u64> {
        self.ap_stack_arena
    }

    pub const fn service(&self) -> Option<ServiceLaunch> {
        self.service
    }

    pub const fn application(&self) -> Option<ApplicationLaunch> {
        self.application
    }

    pub const fn recovery_state(&self) -> Option<RecoveryStateMetadata> {
        self.recovery_state
    }

    pub const fn installed_recovery(&self) -> Option<InstalledRecoveryBootIdentity> {
        self.installed_recovery
    }

    pub const fn installed_recovery_sata_route(&self) -> Option<InstalledRecoverySataRoute> {
        self.installed_recovery_sata_route
    }

    /// An installed UEFI recovery identity cannot enter the kernel without
    /// its matching route. Decoding also serves tooling that inspects a
    /// partial handoff, so the entry paths enforce this precondition.
    pub fn missing_installed_recovery_route(&self) -> bool {
        self.installed_recovery
            .is_some_and(|identity| identity.source() == InstalledRecoverySource::Uefi)
            && self.installed_recovery_sata_route.is_none()
    }

    pub const fn isolation_override(&self) -> Option<BootIsolationOverride> {
        self.isolation_override
    }

    /// Parses a bounded canonical handoff and emits validated regions in
    /// ascending address order. Callers can place them directly into fixed
    /// early-boot storage; the parser never allocates or dereferences firmware
    /// pointers.
    pub fn decode<F>(input: &[u8], emit: F) -> Result<Self, HandoffError>
    where
        F: FnMut(MemoryRegion),
    {
        Self::decode_profile::<true, _>(input, emit)
    }

    /// Normal boot accepts no QEMU USB PCI or copied DXE diagnostic records.
    /// The production specialization does not decode either record.
    pub fn decode_normal(input: &[u8]) -> Result<Self, HandoffError> {
        Self::decode_profile::<false, _>(input, |_| ())
    }

    fn decode_profile<const DIAGNOSTICS: bool, F>(
        input: &[u8],
        mut emit: F,
    ) -> Result<Self, HandoffError>
    where
        F: FnMut(MemoryRegion),
    {
        if input.len() < HANDOFF_HEADER_BYTES {
            return Err(HandoffError::Truncated);
        }
        let has_supervisor = &input[..16] == SUPERVISOR_HANDOFF_MAGIC;
        if !has_supervisor && &input[..16] != b"MRML-HANDOFF-v1\0" {
            return Err(HandoffError::BadMagic);
        }
        let encoded_length = read_u32(input, 16) as usize;
        let region_count = read_u16(input, 20) as usize;
        let flags = read_u16(input, 22);
        if !DIAGNOSTICS && flags & (FLAG_USB_PCI_DIAGNOSTIC | FLAG_DXE_DIAGNOSTIC) != 0 {
            return Err(HandoffError::UnknownFlags);
        }
        if flags & !(KNOWN_FLAGS | if has_supervisor { FLAG_SUPERVISOR_SELECTION } else { 0 })
            != 0
        {
            return Err(HandoffError::UnknownFlags);
        }
        if has_supervisor && flags & FLAG_SUPERVISOR_SELECTION == 0 {
            return Err(HandoffError::NonCanonical);
        }
        let supervisor_bytes = usize::from(has_supervisor) * SUPERVISOR_TRAILER_BYTES;
        if region_count == 0 || region_count > MAX_HANDOFF_REGIONS {
            return Err(HandoffError::TooManyRegions);
        }
        let regions_end = HANDOFF_HEADER_BYTES
            .checked_add(
                region_count
                    .checked_mul(HANDOFF_REGION_BYTES)
                    .ok_or(HandoffError::NonCanonical)?,
            )
            .ok_or(HandoffError::NonCanonical)?;
        let madt_length = read_u16(input, 165) as usize;
        if (flags & FLAG_MADT_SNAPSHOT != 0) != (madt_length != 0)
            || (flags & FLAG_AP_TRAMPOLINE != 0 && madt_length == 0)
            || madt_length > MAX_HANDOFF_MADT_BYTES
            || (madt_length != 0 && madt_length < 44)
            || input[167] != 0
        {
            return Err(HandoffError::NonCanonical);
        }
        // SMP resources are one indivisible pair: a low SIPI page followed by
        // the base of the bounded per-CPU privilege-stack arena.
        let service_bytes = usize::from(flags & FLAG_SERVICE_IMAGE != 0) * HANDOFF_SERVICE_BYTES;
        let service_offset = regions_end;
        let application_offset = service_offset
            .checked_add(service_bytes)
            .ok_or(HandoffError::NonCanonical)?;
        let application_bytes =
            usize::from(flags & FLAG_APPLICATION_IMAGE != 0) * HANDOFF_APPLICATION_BYTES;
        let recovery_offset = application_offset
            .checked_add(application_bytes)
            .ok_or(HandoffError::NonCanonical)?;
        let recovery_bytes =
            usize::from(flags & FLAG_RECOVERY_STATE != 0) * HANDOFF_RECOVERY_STATE_BYTES;
        let installed_recovery_offset = recovery_offset
            .checked_add(recovery_bytes)
            .ok_or(HandoffError::NonCanonical)?;
        let installed_recovery_bytes = usize::from(flags & FLAG_INSTALLED_RECOVERY_IDENTITY != 0)
            * INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES;
        let installed_recovery_route_offset = installed_recovery_offset
            .checked_add(installed_recovery_bytes)
            .ok_or(HandoffError::NonCanonical)?;
        let installed_recovery_route_bytes =
            usize::from(flags & FLAG_INSTALLED_RECOVERY_SATA_ROUTE != 0)
                * INSTALLED_RECOVERY_SATA_ROUTE_BYTES;
        let trampoline_offset = installed_recovery_route_offset
            .checked_add(installed_recovery_route_bytes)
            .ok_or(HandoffError::NonCanonical)?;
        let trampoline_bytes = usize::from(flags & FLAG_AP_TRAMPOLINE != 0) * 16;
        let madt_offset = trampoline_offset
            .checked_add(trampoline_bytes)
            .ok_or(HandoffError::NonCanonical)?;
        let madt_end = madt_offset
            .checked_add(madt_length)
            .ok_or(HandoffError::NonCanonical)?;
        let usb_bytes = usize::from(DIAGNOSTICS && flags & FLAG_USB_PCI_DIAGNOSTIC != 0)
            * BOOT_USB_PCI_RECORD_BYTES;
        let dxe_bytes = usize::from(DIAGNOSTICS && flags & FLAG_DXE_DIAGNOSTIC != 0)
            * BOOT_DXE_DIAGNOSTIC_BYTES;
        if (usb_bytes != 0 && flags & FLAG_DMA_ACPI == 0) || (dxe_bytes != 0 && usb_bytes == 0) {
            return Err(HandoffError::NonCanonical);
        }
        let (acpi_end, dma_acpi_lengths) = if flags & FLAG_DMA_ACPI == 0 {
            (madt_end, None)
        } else {
            let trailer = input.get(madt_end..).ok_or(HandoffError::NonCanonical)?;
            let counts = trailer
                .get(..DMA_ACPI_LENGTH_BYTES)
                .ok_or(HandoffError::NonCanonical)?;
            let dmar = usize::from(read_u16(counts, 0));
            let mcfg = usize::from(read_u16(counts, 2));
            let end = DMA_ACPI_LENGTH_BYTES + dmar + mcfg;
            if trailer.len() != end + usb_bytes + dxe_bytes + supervisor_bytes {
                return Err(HandoffError::NonCanonical);
            }
            validate_dma_acpi_tables(
                &trailer[DMA_ACPI_LENGTH_BYTES..DMA_ACPI_LENGTH_BYTES + dmar],
                &trailer[DMA_ACPI_LENGTH_BYTES + dmar..end],
            )?;
            (madt_end + end, Some((dmar, mcfg)))
        };
        let usb_end = acpi_end.checked_add(usb_bytes).ok_or(HandoffError::NonCanonical)?;
        let diagnostic_end = usb_end
            .checked_add(dxe_bytes)
            .ok_or(HandoffError::NonCanonical)?;
        let expected_length = diagnostic_end
            .checked_add(supervisor_bytes)
            .ok_or(HandoffError::NonCanonical)?;
        if encoded_length != expected_length || input.len() != expected_length {
            return Err(HandoffError::NonCanonical);
        }
        let usb_pci_record = if usb_bytes != 0 {
            let record: [u8; BOOT_USB_PCI_RECORD_BYTES] = input[acpi_end..usb_end]
                .try_into()
                .map_err(|_| HandoffError::NonCanonical)?;
            validate_usb_pci_record(&record)?;
            Some(record)
        } else {
            None
        };
        let dxe_diagnostic = if dxe_bytes != 0 {
            let slot = &input[usb_end..diagnostic_end];
            if slot[1..8] != [0; 7] {
                return Err(HandoffError::NonCanonical);
            }
            match slot[0] {
                0 if slot[8..].iter().all(|byte| *byte == 0) => Some(BootDxeDiagnostic::Incomplete),
                1 => {
                    let record = slot[8..].try_into().map_err(|_| HandoffError::NonCanonical)?;
                    validate_copied_dxe(&record, usb_pci_record.as_ref().ok_or(HandoffError::NonCanonical)?)?;
                    Some(BootDxeDiagnostic::Copied(record))
                }
                _ => return Err(HandoffError::NonCanonical),
            }
        } else {
            None
        };
        if madt_length != 0 {
            let madt = &input[madt_offset..madt_end];
            if &madt[..4] != b"APIC"
                || read_u32(madt, 4) as usize != madt_length
                || madt.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0
            {
                return Err(HandoffError::NonCanonical);
            }
        }

        let image_version = read_u64(input, 24);
        let entropy = input[32..64].try_into().unwrap();
        let image_measurement = input[64..128].try_into().unwrap();
        let acpi_address = read_u64(input, 128);
        if acpi_address == 0 {
            return Err(HandoffError::MissingAcpiRoot);
        }
        let acpi_root = acpi_address;
        let (ap_trampoline, ap_stack_arena) = if trampoline_bytes != 0 {
            let physical = read_u64(input, trampoline_offset);
            let stack_arena = read_u64(input, trampoline_offset + 8);
            if !(crate::PAGE_SIZE..0x10_0000).contains(&physical)
                || !physical.is_multiple_of(crate::PAGE_SIZE)
                || stack_arena == 0
                || !stack_arena.is_multiple_of(crate::PAGE_SIZE)
                || stack_arena >> 52 != 0
            {
                return Err(HandoffError::NonCanonical);
            }
            (Some(physical), Some(stack_arena))
        } else {
            (None, None)
        };
        let service = if service_bytes != 0 {
            Some(decode_service(input, service_offset)?)
        } else {
            None
        };
        let supervisor_selection = if has_supervisor {
            let (record, recorded_digest) = input[diagnostic_end..].split_at(BOOT_SUPERVISOR_SELECTION_BYTES);
            let selection = BootSupervisorSelection::decode(record)
                .map_err(|_| HandoffError::NonCanonical)?;
            validate_supervisor_selection(selection, flags, image_version, service)?;
            if mrml_crypto::Sha3_512::digest(record).as_slice() != recorded_digest {
                return Err(HandoffError::NonCanonical);
            }
            Some(selection)
        } else {
            None
        };
        let application = if application_bytes != 0 {
            Some(decode_application(input, application_offset)?)
        } else {
            None
        };
        let recovery_state = if recovery_bytes != 0 {
            Some(decode_recovery_state(input, recovery_offset)?)
        } else {
            None
        };
        let installed_recovery = if installed_recovery_bytes != 0 {
            Some(
                InstalledRecoveryBootIdentity::decode(
                    input[installed_recovery_offset..installed_recovery_route_offset]
                        .try_into()
                        .map_err(|_| HandoffError::NonCanonical)?,
                )
                .map_err(|_| HandoffError::NonCanonical)?,
            )
        } else {
            None
        };
        let installed_recovery_sata_route = if installed_recovery_route_bytes != 0 {
            Some(
                InstalledRecoverySataRoute::decode(
                    input[installed_recovery_route_offset..trampoline_offset]
                        .try_into()
                        .map_err(|_| HandoffError::NonCanonical)?,
                )
                .map_err(|_| HandoffError::NonCanonical)?,
            )
        } else {
            None
        };
        if installed_recovery.is_some_and(|installed| {
            recovery_state.is_none_or(|recovery| {
                recovery.accepted_volume() != Some(installed.volume())
                    || recovery.accepted_root_generation() != installed.root_generation()
            })
        }) {
            return Err(HandoffError::NonCanonical);
        }
        match (installed_recovery, installed_recovery_sata_route) {
            (Some(installed), Some(route)) => validate_installed_recovery_route(installed, route)?,
            (None, Some(_)) => return Err(HandoffError::NonCanonical),
            _ => {}
        }
        let isolation_override = (flags & FLAG_TOTAL_MICROVM_ONCE != 0)
            .then_some(BootIsolationOverride::TotalMicrovmOnce);
        let pixel_format = match input[164] {
            0 => PixelFormat::RedGreenBlueReserved,
            1 => PixelFormat::BlueGreenRedReserved,
            _ => {
                return Err(HandoffError::InvalidFramebuffer(
                    FramebufferError::UnsupportedPixelFormat,
                ));
            }
        };
        let framebuffer = FramebufferInfo::new(
            read_u64(input, 136),
            read_u64(input, 144),
            read_u32(input, 152),
            read_u32(input, 156),
            read_u32(input, 160),
            pixel_format,
        )
        .map_err(HandoffError::InvalidFramebuffer)?;

        let mut previous_start = 0u64;
        let mut previous_end = 0u64;
        let mut framebuffer_is_mmio = false;
        let mut boot_dma = None;
        for index in 0..region_count {
            let region = decode_region(input, index)?;
            record_boot_dma(&mut boot_dma, region)?;
            let start = region.start().get();
            if index != 0 && start < previous_start {
                return Err(HandoffError::InvalidMemoryMap(MemoryError::Unsorted));
            }
            if index != 0 && start < previous_end {
                return Err(HandoffError::InvalidMemoryMap(MemoryError::Overlap));
            }
            previous_start = start;
            previous_end = region.end();
            if region.kind() == MemoryKind::Mmio
                && region.start().get() <= framebuffer.base().get()
                && region.end() >= framebuffer.end()
            {
                framebuffer_is_mmio = true;
            }
        }
        if !framebuffer_is_mmio {
            return Err(HandoffError::FramebufferOutsideMmio);
        }
        if dma_acpi_lengths.is_some() && boot_dma.is_none() {
            return Err(HandoffError::NonCanonical);
        }
        if let Some(service) = service {
            for (start, pages) in [
                (
                    service.artifact_physical(),
                    service.artifact_length().div_ceil(crate::PAGE_SIZE),
                ),
                (service.image_physical(), service.image_pages()),
                (service.stack_physical(), service.stack_pages()),
                (service.table_physical(), service.table_pages()),
            ] {
                let end = start.get() + pages * crate::PAGE_SIZE;
                let contained = (0..region_count).any(|index| {
                    decode_region(input, index).is_ok_and(|region| {
                        matches!(region.kind(), MemoryKind::Kernel | MemoryKind::Reserved)
                            && region.start().get() <= start.get()
                            && region.end() >= end
                    })
                });
                if !contained {
                    return Err(HandoffError::NonCanonical);
                }
            }
        }
        if let Some(application) = application {
            for (start, pages) in launch_storage(application.0) {
                let end = start.get() + pages * crate::PAGE_SIZE;
                let contained = (0..region_count).any(|index| {
                    decode_region(input, index).is_ok_and(|region| {
                        matches!(region.kind(), MemoryKind::Kernel | MemoryKind::Reserved)
                            && region.start().get() <= start.get()
                            && region.end() >= end
                    })
                });
                if !contained {
                    return Err(HandoffError::NonCanonical);
                }
            }
        }
        if service
            .zip(application)
            .is_some_and(|(service, application)| {
                !launch_storage_is_disjoint(service, application.0)
            })
        {
            return Err(HandoffError::NonCanonical);
        }

        let evidence = BootEvidence::new(
            entropy,
            image_measurement,
            image_version,
            flags & FLAG_SECURE_BOOT != 0,
            flags & FLAG_MEASURED_BOOT != 0,
            flags & FLAG_ROLLBACK_PROTECTED != 0,
            flags & FLAG_COHERENT_RELEASE != 0,
        )
        .map_err(HandoffError::InvalidBootEvidence)?;
        for index in 0..region_count {
            emit(decode_region(input, index)?);
        }
        Ok(Self {
            evidence,
            acpi_root,
            framebuffer,
            region_count,
            boot_dma,
            madt_offset,
            madt_length,
            dma_acpi_lengths,
            usb_pci_record,
            dxe_diagnostic,
            supervisor_selection,
            ap_trampoline,
            ap_stack_arena,
            service,
            application,
            recovery_state,
            installed_recovery,
            installed_recovery_sata_route,
            isolation_override,
        })
    }
}

fn validate_dma_acpi_tables(dmar: &[u8], mcfg: &[u8]) -> Result<(), HandoffError> {
    for (table, signature, minimum) in [(dmar, b"DMAR", 48), (mcfg, b"MCFG", 44)] {
        if !(minimum..=MAX_HANDOFF_DMA_ACPI_TABLE_BYTES).contains(&table.len())
            || &table[..4] != signature
            || read_u32(table, 4) as usize != table.len()
            || table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0
        {
            return Err(HandoffError::NonCanonical);
        }
    }
    Ok(())
}

/// Appends snapshots to an already encoded handoff containing a boot DMA tag.
/// Failure does not modify the encoded handoff.
pub fn append_boot_dma_acpi(
    length: usize,
    dmar: &[u8],
    mcfg: &[u8],
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    validate_dma_acpi_tables(dmar, mcfg)?;
    let total = length
        .checked_add(DMA_ACPI_LENGTH_BYTES + dmar.len() + mcfg.len())
        .filter(|&total| total <= output.len() && total <= MAX_HANDOFF_BYTES)
        .ok_or(HandoffError::NonCanonical)?;
    let handoff = BootHandoff::decode(&output[..length], |_| {})?;
    if handoff.supervisor_selection().is_some()
        || handoff.boot_dma().is_none()
        || handoff.dma_acpi_lengths.is_some()
    {
        return Err(HandoffError::NonCanonical);
    }
    let flags = read_u16(output, 22) | FLAG_DMA_ACPI;
    output[22..24].copy_from_slice(&flags.to_le_bytes());
    output[16..20].copy_from_slice(&(total as u32).to_le_bytes());
    let start = length + DMA_ACPI_LENGTH_BYTES;
    output[length..length + 2].copy_from_slice(&(dmar.len() as u16).to_le_bytes());
    output[length + 2..start].copy_from_slice(&(mcfg.len() as u16).to_le_bytes());
    output[start..start + dmar.len()].copy_from_slice(dmar);
    output[start + dmar.len()..total].copy_from_slice(mcfg);
    Ok(total)
}

fn validate_usb_pci_record(record: &[u8; BOOT_USB_PCI_RECORD_BYTES]) -> Result<(), HandoffError> {
    let base = read_u64(record, 24);
    let bytes = u64::from(read_u32(record, 32));
    if &record[..8] != b"MRMLXHCI"
        || read_u16(record, 8) != 1
        || usize::from(read_u16(record, 10)) != BOOT_USB_PCI_RECORD_BYTES
        || record[36..] != [0; 4]
        || matches!(read_u16(record, 16), 0 | u16::MAX)
        || read_u32(record, 20) >> 8 != 0x0c0330
        || base == 0
        || bytes < 0x20
        || !bytes.is_power_of_two()
        || !base.is_multiple_of(bytes)
        || base.checked_add(bytes).is_none()
    {
        return Err(HandoffError::NonCanonical);
    }
    Ok(())
}

/// Append an opt-in USB diagnostic observation after the checked DMA ACPI
/// pair. No normal handoff producer calls this, and failure is nonmutating.
pub fn append_boot_usb_pci_record(
    length: usize,
    record: &[u8; BOOT_USB_PCI_RECORD_BYTES],
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    validate_usb_pci_record(record)?;
    let total = length
        .checked_add(BOOT_USB_PCI_RECORD_BYTES)
        .filter(|&size| size <= output.len() && size <= MAX_HANDOFF_BYTES)
        .ok_or(HandoffError::NonCanonical)?;
    let handoff = BootHandoff::decode(&output[..length], |_| {})?;
    if handoff.supervisor_selection().is_some()
        || handoff.dma_acpi_lengths.is_none()
        || handoff.usb_pci_record.is_some()
    {
        return Err(HandoffError::NonCanonical);
    }
    let flags = read_u16(output, 22) | FLAG_USB_PCI_DIAGNOSTIC;
    output[22..24].copy_from_slice(&flags.to_le_bytes());
    output[16..20].copy_from_slice(&(total as u32).to_le_bytes());
    output[length..total].copy_from_slice(record);
    Ok(total)
}

fn validate_copied_dxe(
    record: &[u8; PASSIVE_DXE_RECORD_BYTES],
    usb: &[u8; BOOT_USB_PCI_RECORD_BYTES],
) -> Result<(), HandoffError> {
    let count = usize::from(record[12]);
    let requester = read_u32(usb, 12);
    if &record[..8] != b"MRMLDXE\0"
        || read_u16(record, 8) != 1
        || usize::from(read_u16(record, 10)) != PASSIVE_DXE_RECORD_BYTES
        || !(1..=8).contains(&count)
        || record[13..16] != [0; 3]
        || record[21..24] != [0; 3]
        || read_u16(record, 16) != (requester >> 16) as u16
        || record[18] != (requester >> 8) as u8
        || record[19] != ((requester >> 3) & 31) as u8
        || record[20] != (requester & 7) as u8
        || read_u64(record, 56) != read_u64(usb, 24)
        || read_u64(record, 64).checked_mul(crate::PAGE_SIZE) != Some(u64::from(read_u32(usb, 32)))
        || record[72..].chunks_exact(16).take(count).any(|unit| unit[10..] != [0; 6])
        || record[72 + 16 * count..].iter().any(|byte| *byte != 0)
    {
        return Err(HandoffError::NonCanonical);
    }
    Ok(())
}

/// Appends the fixed diagnostic slot only after a canonical USB record and its
/// ACPI pair. Incomplete firmware evidence has no payload. This function does
/// not grant authority or certify that a copy came from a firmware service.
pub fn append_boot_dxe_diagnostic(
    length: usize,
    diagnostic: &BootDxeDiagnostic,
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    let total = length
        .checked_add(BOOT_DXE_DIAGNOSTIC_BYTES)
        .filter(|&size| size <= output.len() && size <= MAX_HANDOFF_BYTES)
        .ok_or(HandoffError::NonCanonical)?;
    let handoff = BootHandoff::decode(&output[..length], |_| {})?;
    let usb = handoff.usb_pci_record().ok_or(HandoffError::NonCanonical)?;
    if handoff.supervisor_selection().is_some() || handoff.boot_dxe_diagnostic().is_some() {
        return Err(HandoffError::NonCanonical);
    }
    if let BootDxeDiagnostic::Copied(record) = diagnostic {
        validate_copied_dxe(record, usb)?;
    }

    let flags = read_u16(output, 22) | FLAG_DXE_DIAGNOSTIC;
    output[22..24].copy_from_slice(&flags.to_le_bytes());
    output[16..20].copy_from_slice(&(total as u32).to_le_bytes());
    output[length..total].fill(0);
    if let BootDxeDiagnostic::Copied(record) = diagnostic {
        output[length] = 1;
        output[length + 8..total].copy_from_slice(record);
    }
    Ok(total)
}

fn validate_supervisor_selection(
    selection: BootSupervisorSelection,
    flags: u16,
    release: u64,
    service: Option<ServiceLaunch>,
) -> Result<(), HandoffError> {
    if flags & SUPERVISOR_EVIDENCE_FLAGS != SUPERVISOR_EVIDENCE_FLAGS
        || !service.is_some_and(|launch| selection.matches_envelope(release, launch.envelope()))
    {
        return Err(HandoffError::NonCanonical);
    }
    Ok(())
}

/// Transport the selection already matched against the enrolled loader's pin.
/// The trailing digest detects inconsistent bytes, not a hostile handoff writer.
/// The record goes last, after any ACPI and diagnostic records.
pub fn append_boot_supervisor_selection(
    length: usize,
    selection: BootSupervisorSelection,
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    let total = length
        .checked_add(SUPERVISOR_TRAILER_BYTES)
        .filter(|&size| size <= output.len() && size <= MAX_HANDOFF_BYTES)
        .ok_or(HandoffError::NonCanonical)?;
    let handoff = BootHandoff::decode(&output[..length], |_| {})?;
    if handoff.supervisor_selection().is_some() {
        return Err(HandoffError::NonCanonical);
    }
    let flags = read_u16(output, 22);
    validate_supervisor_selection(selection, flags, handoff.evidence().image_version(), handoff.service())?;
    let record = selection.encode();
    let recorded_digest = mrml_crypto::Sha3_512::digest(&record);
    output[length..length + record.len()].copy_from_slice(&record);
    output[length + record.len()..total].copy_from_slice(&recorded_digest);
    output[..16].copy_from_slice(SUPERVISOR_HANDOFF_MAGIC);
    output[22..24].copy_from_slice(&(flags | FLAG_SUPERVISOR_SELECTION).to_le_bytes());
    output[16..20].copy_from_slice(&(total as u32).to_le_bytes());
    Ok(total)
}

// Each argument is an independently validated field of the fixed wire format;
// grouping them would hide rather than reduce this trust-boundary surface.
#[allow(clippy::too_many_arguments)]
pub fn encode_handoff(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    encode_handoff_inner(
        image_version,
        entropy,
        image_measurement,
        secure_boot,
        measured_boot,
        rollback_protected,
        false,
        acpi_root,
        framebuffer,
        regions,
        None,
        None,
        None,
        None,
        None,
        output,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn encode_handoff_with_recovery(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    recovery_state: RecoveryStateMetadata,
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    encode_handoff_inner(
        image_version,
        entropy,
        image_measurement,
        secure_boot,
        measured_boot,
        rollback_protected,
        false,
        acpi_root,
        framebuffer,
        regions,
        None,
        None,
        None,
        None,
        Some(recovery_state),
        output,
    )
}

/// Encodes recovered boot state and the optional one-boot isolation request in
/// the same canonical handoff consumed by the kernel. The request remains
/// authority-free and does not itself prove that Total placement succeeded.
#[allow(clippy::too_many_arguments)]
pub fn encode_handoff_with_recovery_and_isolation(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    coherent_release: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    recovery_state: RecoveryStateMetadata,
    isolation_override: Option<BootIsolationOverride>,
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    let length = encode_handoff_inner(
        image_version,
        entropy,
        image_measurement,
        secure_boot,
        measured_boot,
        rollback_protected,
        coherent_release,
        acpi_root,
        framebuffer,
        regions,
        None,
        None,
        None,
        None,
        Some(recovery_state),
        output,
    )?;
    apply_isolation_override(isolation_override, output);
    Ok(length)
}

/// Encodes the recovery metadata, its exact non-authorizing installed-device
/// identity, and an optional one-boot isolation request without requiring an
/// unrelated service or SMP payload. The installed record must agree with the
/// authenticated volume/root metadata and is placed at the canonical tail.
#[allow(clippy::too_many_arguments)]
pub fn encode_handoff_with_recovery_isolation_and_installed(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    coherent_release: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    recovery_state: RecoveryStateMetadata,
    installed_recovery: InstalledRecoveryBootIdentity,
    isolation_override: Option<BootIsolationOverride>,
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    validate_installed_recovery(recovery_state, installed_recovery)?;
    let length = encode_handoff_with_recovery_and_isolation(
        image_version,
        entropy,
        image_measurement,
        secure_boot,
        measured_boot,
        rollback_protected,
        coherent_release,
        acpi_root,
        framebuffer,
        regions,
        recovery_state,
        isolation_override,
        output,
    )?;
    let installed_offset = HANDOFF_HEADER_BYTES
        .checked_add(
            regions
                .len()
                .checked_mul(HANDOFF_REGION_BYTES)
                .ok_or(HandoffError::NonCanonical)?,
        )
        .and_then(|offset| offset.checked_add(HANDOFF_RECOVERY_STATE_BYTES))
        .ok_or(HandoffError::NonCanonical)?;
    append_installed_recovery(length, installed_offset, installed_recovery, output)
}

/// Encodes recovery-only installed identity plus its exact firmware-extracted
/// SATA route. This is the service-free counterpart of the real loader path and
/// preserves the same adjacency, source, and stable-ID requirements.
#[allow(clippy::too_many_arguments)]
pub fn encode_handoff_with_recovery_isolation_installed_and_sata_route(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    coherent_release: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    recovery_state: RecoveryStateMetadata,
    installed_recovery: InstalledRecoveryBootIdentity,
    installed_recovery_sata_route: InstalledRecoverySataRoute,
    isolation_override: Option<BootIsolationOverride>,
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    validate_installed_recovery_route(installed_recovery, installed_recovery_sata_route)?;
    let length = encode_handoff_with_recovery_isolation_and_installed(
        image_version,
        entropy,
        image_measurement,
        secure_boot,
        measured_boot,
        rollback_protected,
        coherent_release,
        acpi_root,
        framebuffer,
        regions,
        recovery_state,
        installed_recovery,
        isolation_override,
        output,
    )?;
    let route_offset = HANDOFF_HEADER_BYTES
        .checked_add(
            regions
                .len()
                .checked_mul(HANDOFF_REGION_BYTES)
                .ok_or(HandoffError::NonCanonical)?,
        )
        .and_then(|offset| offset.checked_add(HANDOFF_RECOVERY_STATE_BYTES))
        .and_then(|offset| offset.checked_add(INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES))
        .ok_or(HandoffError::NonCanonical)?;
    append_installed_recovery_sata_route(
        length,
        route_offset,
        installed_recovery_sata_route,
        output,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn encode_handoff_with_madt(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    madt: &[u8],
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    if !(44..=MAX_HANDOFF_MADT_BYTES).contains(&madt.len())
        || &madt[..4] != b"APIC"
        || read_u32(madt, 4) as usize != madt.len()
        || madt.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0
    {
        return Err(HandoffError::NonCanonical);
    }
    encode_handoff_inner(
        image_version,
        entropy,
        image_measurement,
        secure_boot,
        measured_boot,
        rollback_protected,
        false,
        acpi_root,
        framebuffer,
        regions,
        Some(madt),
        None,
        None,
        None,
        None,
        output,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn encode_handoff_with_smp(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    ap_trampoline: u64,
    ap_stack_arena: u64,
    madt: &[u8],
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    if !(crate::PAGE_SIZE..0x10_0000).contains(&ap_trampoline)
        || !ap_trampoline.is_multiple_of(crate::PAGE_SIZE)
        || ap_stack_arena == 0
        || !ap_stack_arena.is_multiple_of(crate::PAGE_SIZE)
        || ap_stack_arena >> 52 != 0
        || !(44..=MAX_HANDOFF_MADT_BYTES).contains(&madt.len())
        || &madt[..4] != b"APIC"
        || read_u32(madt, 4) as usize != madt.len()
        || madt.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0
    {
        return Err(HandoffError::NonCanonical);
    }
    encode_handoff_inner(
        image_version,
        entropy,
        image_measurement,
        secure_boot,
        measured_boot,
        rollback_protected,
        false,
        acpi_root,
        framebuffer,
        regions,
        Some(madt),
        Some((ap_trampoline, ap_stack_arena)),
        None,
        None,
        None,
        output,
    )
}

/// Encodes SMP topology, recovered boot state, and the optional one-boot
/// isolation request as one canonical trusted-loader handoff.
#[allow(clippy::too_many_arguments)]
pub fn encode_handoff_with_smp_recovery_and_isolation(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    coherent_release: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    ap_trampoline: u64,
    ap_stack_arena: u64,
    recovery_state: RecoveryStateMetadata,
    isolation_override: Option<BootIsolationOverride>,
    madt: &[u8],
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    if !(crate::PAGE_SIZE..0x10_0000).contains(&ap_trampoline)
        || !ap_trampoline.is_multiple_of(crate::PAGE_SIZE)
        || ap_stack_arena == 0
        || !ap_stack_arena.is_multiple_of(crate::PAGE_SIZE)
        || ap_stack_arena >> 52 != 0
        || !(44..=MAX_HANDOFF_MADT_BYTES).contains(&madt.len())
        || &madt[..4] != b"APIC"
        || read_u32(madt, 4) as usize != madt.len()
        || madt.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0
    {
        return Err(HandoffError::NonCanonical);
    }
    let length = encode_handoff_inner(
        image_version,
        entropy,
        image_measurement,
        secure_boot,
        measured_boot,
        rollback_protected,
        coherent_release,
        acpi_root,
        framebuffer,
        regions,
        Some(madt),
        Some((ap_trampoline, ap_stack_arena)),
        None,
        None,
        Some(recovery_state),
        output,
    )?;
    apply_isolation_override(isolation_override, output);
    Ok(length)
}

/// Extends an SMP recovery handoff without a service launch record with the
/// exact installed source that produced the recovered state. The installed
/// identity is inserted before SMP/MADT bytes so both hosted and installed
/// Total-mode launchers consume the same canonical field ordering.
#[allow(clippy::too_many_arguments)]
pub fn encode_handoff_with_smp_recovery_isolation_and_installed(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    coherent_release: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    ap_trampoline: u64,
    ap_stack_arena: u64,
    recovery_state: RecoveryStateMetadata,
    installed_recovery: InstalledRecoveryBootIdentity,
    isolation_override: Option<BootIsolationOverride>,
    madt: &[u8],
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    validate_installed_recovery(recovery_state, installed_recovery)?;
    let length = encode_handoff_with_smp_recovery_and_isolation(
        image_version,
        entropy,
        image_measurement,
        secure_boot,
        measured_boot,
        rollback_protected,
        coherent_release,
        acpi_root,
        framebuffer,
        regions,
        ap_trampoline,
        ap_stack_arena,
        recovery_state,
        isolation_override,
        madt,
        output,
    )?;
    let installed_offset = HANDOFF_HEADER_BYTES
        .checked_add(
            regions
                .len()
                .checked_mul(HANDOFF_REGION_BYTES)
                .ok_or(HandoffError::NonCanonical)?,
        )
        .and_then(|offset| offset.checked_add(HANDOFF_RECOVERY_STATE_BYTES))
        .ok_or(HandoffError::NonCanonical)?;
    append_installed_recovery(length, installed_offset, installed_recovery, output)
}

#[allow(clippy::too_many_arguments)]
pub fn encode_handoff_with_application(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    application: ApplicationLaunch,
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    encode_handoff_inner(
        image_version,
        entropy,
        image_measurement,
        secure_boot,
        measured_boot,
        rollback_protected,
        false,
        acpi_root,
        framebuffer,
        regions,
        None,
        None,
        None,
        Some(application),
        None,
        output,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn encode_handoff_with_smp_and_service(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    ap_trampoline: u64,
    ap_stack_arena: u64,
    service: ServiceLaunch,
    madt: &[u8],
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    if !(crate::PAGE_SIZE..0x10_0000).contains(&ap_trampoline)
        || !ap_trampoline.is_multiple_of(crate::PAGE_SIZE)
        || ap_stack_arena == 0
        || !ap_stack_arena.is_multiple_of(crate::PAGE_SIZE)
        || ap_stack_arena >> 52 != 0
        || !(44..=MAX_HANDOFF_MADT_BYTES).contains(&madt.len())
        || &madt[..4] != b"APIC"
        || read_u32(madt, 4) as usize != madt.len()
        || madt.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0
    {
        return Err(HandoffError::NonCanonical);
    }
    encode_handoff_inner(
        image_version,
        entropy,
        image_measurement,
        secure_boot,
        measured_boot,
        rollback_protected,
        false,
        acpi_root,
        framebuffer,
        regions,
        Some(madt),
        Some((ap_trampoline, ap_stack_arena)),
        Some(service),
        None,
        None,
        output,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn encode_handoff_with_smp_and_application(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    ap_trampoline: u64,
    ap_stack_arena: u64,
    application: ApplicationLaunch,
    madt: &[u8],
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    if !(crate::PAGE_SIZE..0x10_0000).contains(&ap_trampoline)
        || !ap_trampoline.is_multiple_of(crate::PAGE_SIZE)
        || ap_stack_arena == 0
        || !ap_stack_arena.is_multiple_of(crate::PAGE_SIZE)
        || ap_stack_arena >> 52 != 0
        || !(44..=MAX_HANDOFF_MADT_BYTES).contains(&madt.len())
        || &madt[..4] != b"APIC"
        || read_u32(madt, 4) as usize != madt.len()
        || madt.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0
    {
        return Err(HandoffError::NonCanonical);
    }
    encode_handoff_inner(
        image_version,
        entropy,
        image_measurement,
        secure_boot,
        measured_boot,
        rollback_protected,
        false,
        acpi_root,
        framebuffer,
        regions,
        Some(madt),
        Some((ap_trampoline, ap_stack_arena)),
        None,
        Some(application),
        None,
        output,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn encode_handoff_with_smp_service_and_recovery(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    coherent_release: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    ap_trampoline: u64,
    ap_stack_arena: u64,
    service: ServiceLaunch,
    recovery_state: Option<RecoveryStateMetadata>,
    madt: &[u8],
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    if !(crate::PAGE_SIZE..0x10_0000).contains(&ap_trampoline)
        || !ap_trampoline.is_multiple_of(crate::PAGE_SIZE)
        || ap_stack_arena == 0
        || !ap_stack_arena.is_multiple_of(crate::PAGE_SIZE)
        || ap_stack_arena >> 52 != 0
        || !(44..=MAX_HANDOFF_MADT_BYTES).contains(&madt.len())
        || &madt[..4] != b"APIC"
        || read_u32(madt, 4) as usize != madt.len()
        || madt.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0
    {
        return Err(HandoffError::NonCanonical);
    }
    encode_handoff_inner(
        image_version,
        entropy,
        image_measurement,
        secure_boot,
        measured_boot,
        rollback_protected,
        coherent_release,
        acpi_root,
        framebuffer,
        regions,
        Some(madt),
        Some((ap_trampoline, ap_stack_arena)),
        Some(service),
        None,
        recovery_state,
        output,
    )
}

fn apply_isolation_override(isolation_override: Option<BootIsolationOverride>, output: &mut [u8]) {
    if isolation_override == Some(BootIsolationOverride::TotalMicrovmOnce) {
        let flags = read_u16(output, 22) | FLAG_TOTAL_MICROVM_ONCE;
        output[22..24].copy_from_slice(&flags.to_le_bytes());
    }
}

/// Encodes the ordinary authenticated loader handoff plus an optional strict
/// one-boot isolation request. The request is a flag within the same canonical
/// handoff; it is neither persistent policy nor evidence of runtime success.
#[allow(clippy::too_many_arguments)]
pub fn encode_handoff_with_smp_service_recovery_and_isolation(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    coherent_release: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    ap_trampoline: u64,
    ap_stack_arena: u64,
    service: ServiceLaunch,
    recovery_state: Option<RecoveryStateMetadata>,
    isolation_override: Option<BootIsolationOverride>,
    madt: &[u8],
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    let length = encode_handoff_with_smp_service_and_recovery(
        image_version,
        entropy,
        image_measurement,
        secure_boot,
        measured_boot,
        rollback_protected,
        coherent_release,
        acpi_root,
        framebuffer,
        regions,
        ap_trampoline,
        ap_stack_arena,
        service,
        recovery_state,
        madt,
        output,
    )?;
    apply_isolation_override(isolation_override, output);
    Ok(length)
}

/// Extends the ordinary loader handoff with the exact non-authorizing installed
/// recovery identity. The record is inserted before SMP/MADT data and is valid
/// only when its volume and selected root generation exactly match the
/// authenticated recovery journal metadata in the same handoff.
#[allow(clippy::too_many_arguments)]
pub fn encode_handoff_with_smp_service_recovery_isolation_and_installed(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    coherent_release: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    ap_trampoline: u64,
    ap_stack_arena: u64,
    service: ServiceLaunch,
    recovery_state: Option<RecoveryStateMetadata>,
    installed_recovery: Option<InstalledRecoveryBootIdentity>,
    isolation_override: Option<BootIsolationOverride>,
    madt: &[u8],
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    if let Some(installed) = installed_recovery {
        validate_installed_recovery(recovery_state.ok_or(HandoffError::NonCanonical)?, installed)?;
    }
    let length = encode_handoff_with_smp_service_recovery_and_isolation(
        image_version,
        entropy,
        image_measurement,
        secure_boot,
        measured_boot,
        rollback_protected,
        coherent_release,
        acpi_root,
        framebuffer,
        regions,
        ap_trampoline,
        ap_stack_arena,
        service,
        recovery_state,
        isolation_override,
        madt,
        output,
    )?;
    let Some(installed_recovery) = installed_recovery else {
        return Ok(length);
    };
    let installed_offset = HANDOFF_HEADER_BYTES
        .checked_add(
            regions
                .len()
                .checked_mul(HANDOFF_REGION_BYTES)
                .ok_or(HandoffError::NonCanonical)?,
        )
        .and_then(|offset| offset.checked_add(HANDOFF_SERVICE_BYTES))
        .and_then(|offset| {
            offset.checked_add(usize::from(recovery_state.is_some()) * HANDOFF_RECOVERY_STATE_BYTES)
        })
        .ok_or(HandoffError::NonCanonical)?;
    append_installed_recovery(length, installed_offset, installed_recovery, output)
}

/// Extends the installed-recovery handoff with the exact typed SATA route
/// extracted while firmware still owns device-path interpretation. The route
/// remains non-authorizing and must bind the same UEFI stable identity as the
/// adjacent installed-recovery record.
#[allow(clippy::too_many_arguments)]
pub fn encode_handoff_with_smp_service_recovery_isolation_installed_and_sata_route(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    coherent_release: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    ap_trampoline: u64,
    ap_stack_arena: u64,
    service: ServiceLaunch,
    recovery_state: Option<RecoveryStateMetadata>,
    installed_recovery: Option<InstalledRecoveryBootIdentity>,
    installed_recovery_sata_route: Option<InstalledRecoverySataRoute>,
    isolation_override: Option<BootIsolationOverride>,
    madt: &[u8],
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    match (installed_recovery, installed_recovery_sata_route) {
        (Some(installed), Some(route)) => validate_installed_recovery_route(installed, route)?,
        (None, Some(_)) => return Err(HandoffError::NonCanonical),
        _ => {}
    }
    let length = encode_handoff_with_smp_service_recovery_isolation_and_installed(
        image_version,
        entropy,
        image_measurement,
        secure_boot,
        measured_boot,
        rollback_protected,
        coherent_release,
        acpi_root,
        framebuffer,
        regions,
        ap_trampoline,
        ap_stack_arena,
        service,
        recovery_state,
        installed_recovery,
        isolation_override,
        madt,
        output,
    )?;
    let Some(route) = installed_recovery_sata_route else {
        return Ok(length);
    };
    let route_offset = HANDOFF_HEADER_BYTES
        .checked_add(
            regions
                .len()
                .checked_mul(HANDOFF_REGION_BYTES)
                .ok_or(HandoffError::NonCanonical)?,
        )
        .and_then(|offset| offset.checked_add(HANDOFF_SERVICE_BYTES))
        .and_then(|offset| {
            offset.checked_add(usize::from(recovery_state.is_some()) * HANDOFF_RECOVERY_STATE_BYTES)
        })
        .and_then(|offset| {
            offset.checked_add(
                usize::from(installed_recovery.is_some()) * INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES,
            )
        })
        .ok_or(HandoffError::NonCanonical)?;
    append_installed_recovery_sata_route(length, route_offset, route, output)
}

fn validate_installed_recovery(
    recovery_state: RecoveryStateMetadata,
    installed: InstalledRecoveryBootIdentity,
) -> Result<(), HandoffError> {
    if recovery_state.accepted_volume() != Some(installed.volume())
        || recovery_state.accepted_root_generation() != installed.root_generation()
    {
        Err(HandoffError::NonCanonical)
    } else {
        Ok(())
    }
}

fn validate_installed_recovery_route(
    installed: InstalledRecoveryBootIdentity,
    route: InstalledRecoverySataRoute,
) -> Result<(), HandoffError> {
    if installed.source() != InstalledRecoverySource::Uefi
        || installed.stable_id() != route.stable_id()
    {
        Err(HandoffError::NonCanonical)
    } else {
        Ok(())
    }
}

fn append_installed_recovery(
    length: usize,
    installed_offset: usize,
    installed_recovery: InstalledRecoveryBootIdentity,
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    let extended_length = length
        .checked_add(INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES)
        .ok_or(HandoffError::NonCanonical)?;
    if output.len() < extended_length {
        output[..length].fill(0);
        return Err(HandoffError::NonCanonical);
    }
    output.copy_within(
        installed_offset..length,
        installed_offset + INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES,
    );
    output[installed_offset..installed_offset + INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES]
        .copy_from_slice(&installed_recovery.encode());
    output[16..20].copy_from_slice(&(extended_length as u32).to_le_bytes());
    let flags = read_u16(output, 22) | FLAG_INSTALLED_RECOVERY_IDENTITY;
    output[22..24].copy_from_slice(&flags.to_le_bytes());
    Ok(extended_length)
}

fn append_installed_recovery_sata_route(
    length: usize,
    route_offset: usize,
    route: InstalledRecoverySataRoute,
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    let extended_length = length
        .checked_add(INSTALLED_RECOVERY_SATA_ROUTE_BYTES)
        .ok_or(HandoffError::NonCanonical)?;
    if output.len() < extended_length || route_offset > length {
        output[..length].fill(0);
        return Err(HandoffError::NonCanonical);
    }
    output.copy_within(
        route_offset..length,
        route_offset + INSTALLED_RECOVERY_SATA_ROUTE_BYTES,
    );
    output[route_offset..route_offset + INSTALLED_RECOVERY_SATA_ROUTE_BYTES]
        .copy_from_slice(&route.encode());
    output[16..20].copy_from_slice(&(extended_length as u32).to_le_bytes());
    let flags = read_u16(output, 22) | FLAG_INSTALLED_RECOVERY_SATA_ROUTE;
    output[22..24].copy_from_slice(&flags.to_le_bytes());
    Ok(extended_length)
}

#[allow(clippy::too_many_arguments)]
pub fn encode_handoff_with_smp_service_application_and_recovery(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    coherent_release: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    ap_trampoline: u64,
    ap_stack_arena: u64,
    service: ServiceLaunch,
    application: ApplicationLaunch,
    recovery_state: Option<RecoveryStateMetadata>,
    madt: &[u8],
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    if !(crate::PAGE_SIZE..0x10_0000).contains(&ap_trampoline)
        || !ap_trampoline.is_multiple_of(crate::PAGE_SIZE)
        || ap_stack_arena == 0
        || !ap_stack_arena.is_multiple_of(crate::PAGE_SIZE)
        || ap_stack_arena >> 52 != 0
        || !(44..=MAX_HANDOFF_MADT_BYTES).contains(&madt.len())
        || &madt[..4] != b"APIC"
        || read_u32(madt, 4) as usize != madt.len()
        || madt.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0
    {
        return Err(HandoffError::NonCanonical);
    }
    encode_handoff_inner(
        image_version,
        entropy,
        image_measurement,
        secure_boot,
        measured_boot,
        rollback_protected,
        coherent_release,
        acpi_root,
        framebuffer,
        regions,
        Some(madt),
        Some((ap_trampoline, ap_stack_arena)),
        Some(service),
        Some(application),
        recovery_state,
        output,
    )
}

#[allow(clippy::too_many_arguments)]
fn encode_handoff_inner(
    image_version: u64,
    entropy: [u8; 32],
    image_measurement: [u8; 64],
    secure_boot: bool,
    measured_boot: bool,
    rollback_protected: bool,
    coherent_release: bool,
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    regions: &[MemoryRegion],
    madt: Option<&[u8]>,
    ap_resources: Option<(u64, u64)>,
    service: Option<ServiceLaunch>,
    application: Option<ApplicationLaunch>,
    recovery_state: Option<RecoveryStateMetadata>,
    output: &mut [u8],
) -> Result<usize, HandoffError> {
    if regions.is_empty() || regions.len() > MAX_HANDOFF_REGIONS {
        return Err(HandoffError::TooManyRegions);
    }
    let regions_end = HANDOFF_HEADER_BYTES
        .checked_add(
            regions
                .len()
                .checked_mul(HANDOFF_REGION_BYTES)
                .ok_or(HandoffError::NonCanonical)?,
        )
        .ok_or(HandoffError::NonCanonical)?;
    let madt_length = madt.map_or(0, <[u8]>::len);
    let service_bytes = usize::from(service.is_some()) * HANDOFF_SERVICE_BYTES;
    let service_offset = regions_end;
    let application_offset = service_offset
        .checked_add(service_bytes)
        .ok_or(HandoffError::NonCanonical)?;
    let application_bytes = usize::from(application.is_some()) * HANDOFF_APPLICATION_BYTES;
    let recovery_offset = application_offset
        .checked_add(application_bytes)
        .ok_or(HandoffError::NonCanonical)?;
    let recovery_bytes = usize::from(recovery_state.is_some()) * HANDOFF_RECOVERY_STATE_BYTES;
    let trampoline_offset = recovery_offset
        .checked_add(recovery_bytes)
        .ok_or(HandoffError::NonCanonical)?;
    let madt_offset = trampoline_offset
        .checked_add(usize::from(ap_resources.is_some()) * 16)
        .ok_or(HandoffError::NonCanonical)?;
    let length = madt_offset
        .checked_add(madt_length)
        .ok_or(HandoffError::NonCanonical)?;
    if output.len() < length || image_version == 0 || acpi_root == 0 {
        return Err(HandoffError::NonCanonical);
    }
    MemoryMap::new(regions).map_err(HandoffError::InvalidMemoryMap)?;
    let mut boot_dma = None;
    for &region in regions {
        record_boot_dma(&mut boot_dma, region)?;
    }
    if !regions.iter().any(|region| {
        region.kind() == MemoryKind::Mmio
            && region.start().get() <= framebuffer.base().get()
            && region.end() >= framebuffer.end()
    }) {
        return Err(HandoffError::FramebufferOutsideMmio);
    }
    if service.is_some_and(|service| !service_storage_is_reserved(service, regions)) {
        return Err(HandoffError::NonCanonical);
    }
    if application.is_some_and(|application| !service_storage_is_reserved(application.0, regions))
        || service
            .zip(application)
            .is_some_and(|(service, application)| {
                !launch_storage_is_disjoint(service, application.0)
            })
    {
        return Err(HandoffError::NonCanonical);
    }
    BootEvidence::new(
        entropy,
        image_measurement,
        image_version,
        secure_boot,
        measured_boot,
        rollback_protected,
        coherent_release,
    )
    .map_err(HandoffError::InvalidBootEvidence)?;
    output[..length].fill(0);
    output[..16].copy_from_slice(b"MRML-HANDOFF-v1\0");
    output[16..20].copy_from_slice(&(length as u32).to_le_bytes());
    output[20..22].copy_from_slice(&(regions.len() as u16).to_le_bytes());
    let flags = ((secure_boot as u16) * FLAG_SECURE_BOOT)
        | ((measured_boot as u16) * FLAG_MEASURED_BOOT)
        | ((rollback_protected as u16) * FLAG_ROLLBACK_PROTECTED)
        | ((coherent_release as u16) * FLAG_COHERENT_RELEASE)
        | ((madt.is_some() as u16) * FLAG_MADT_SNAPSHOT)
        | ((ap_resources.is_some() as u16) * FLAG_AP_TRAMPOLINE)
        | ((service.is_some() as u16) * FLAG_SERVICE_IMAGE)
        | ((application.is_some() as u16) * FLAG_APPLICATION_IMAGE)
        | ((recovery_state.is_some() as u16) * FLAG_RECOVERY_STATE);
    output[22..24].copy_from_slice(&flags.to_le_bytes());
    output[24..32].copy_from_slice(&image_version.to_le_bytes());
    output[32..64].copy_from_slice(&entropy);
    output[64..128].copy_from_slice(&image_measurement);
    output[128..136].copy_from_slice(&acpi_root.to_le_bytes());
    output[136..144].copy_from_slice(&framebuffer.base().get().to_le_bytes());
    output[144..152].copy_from_slice(&framebuffer.byte_length().to_le_bytes());
    output[152..156].copy_from_slice(&framebuffer.width().to_le_bytes());
    output[156..160].copy_from_slice(&framebuffer.height().to_le_bytes());
    output[160..164].copy_from_slice(&framebuffer.stride().to_le_bytes());
    output[164] = match framebuffer.pixel_format() {
        PixelFormat::RedGreenBlueReserved => 0,
        PixelFormat::BlueGreenRedReserved => 1,
    };
    output[165..167].copy_from_slice(&(madt_length as u16).to_le_bytes());
    for (index, region) in regions.iter().copied().enumerate() {
        let offset = HANDOFF_HEADER_BYTES + index * HANDOFF_REGION_BYTES;
        output[offset..offset + 8].copy_from_slice(&region.start().get().to_le_bytes());
        output[offset + 8..offset + 16].copy_from_slice(&region.pages().to_le_bytes());
        output[offset + 16] = region.kind() as u8;
    }
    if let Some((physical, stack_arena)) = ap_resources {
        output[trampoline_offset..trampoline_offset + 8].copy_from_slice(&physical.to_le_bytes());
        output[trampoline_offset + 8..trampoline_offset + 16]
            .copy_from_slice(&stack_arena.to_le_bytes());
    }
    if let Some(service) = service {
        encode_service(service, &mut output[service_offset..application_offset]);
    }
    if let Some(application) = application {
        encode_application(
            application,
            &mut output[application_offset..recovery_offset],
        );
    }
    if let Some(recovery_state) = recovery_state {
        encode_recovery_state(
            recovery_state,
            &mut output[recovery_offset..trampoline_offset],
        );
    }
    if let Some(madt) = madt {
        output[madt_offset..length].copy_from_slice(madt);
    }
    Ok(length)
}

fn encode_service(service: ServiceLaunch, output: &mut [u8]) {
    let fields = [
        service.artifact_physical().get(),
        service.artifact_length(),
        service.image_physical().get(),
        service.image_pages(),
        service.image_virtual(),
        service.entry(),
        service.stack_physical().get(),
        service.stack_pages(),
        service.stack_top(),
        service.table_physical().get(),
        service.table_pages(),
        service.version(),
    ];
    for (index, value) in fields.into_iter().enumerate() {
        let offset = index * 8;
        output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    output[96..HANDOFF_SERVICE_BYTES].copy_from_slice(&service.measurement());
}

fn encode_application(application: ApplicationLaunch, output: &mut [u8]) {
    encode_service(application.0, output);
}

fn encode_recovery_state(state: RecoveryStateMetadata, output: &mut [u8]) {
    output[..8].copy_from_slice(&state.accepted_epoch().to_le_bytes());
    output[8..12].copy_from_slice(&state.accepted_handle_generation().to_le_bytes());
    if let Some(volume) = state.accepted_volume() {
        output[16..32].copy_from_slice(&volume);
    }
    output[32..40].copy_from_slice(&state.accepted_root_generation().to_le_bytes());
}

fn decode_recovery_state(
    input: &[u8],
    offset: usize,
) -> Result<RecoveryStateMetadata, HandoffError> {
    if input[offset + 12..offset + 16]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(HandoffError::NonCanonical);
    }
    let volume: [u8; 16] = input[offset + 16..offset + 32].try_into().unwrap();
    RecoveryStateMetadata::new(
        read_u64(input, offset),
        read_u32(input, offset + 8),
        (!volume.iter().all(|byte| *byte == 0)).then_some(volume),
        read_u64(input, offset + 32),
    )
}

fn decode_service(input: &[u8], offset: usize) -> Result<ServiceLaunch, HandoffError> {
    let measurement = input[offset + 96..offset + HANDOFF_SERVICE_BYTES]
        .try_into()
        .map_err(|_| HandoffError::NonCanonical)?;
    ServiceLaunch::new(
        PhysAddr::new(read_u64(input, offset)).map_err(HandoffError::InvalidMemoryMap)?,
        read_u64(input, offset + 8),
        PhysAddr::new(read_u64(input, offset + 16)).map_err(HandoffError::InvalidMemoryMap)?,
        read_u64(input, offset + 24),
        read_u64(input, offset + 32),
        read_u64(input, offset + 40),
        PhysAddr::new(read_u64(input, offset + 48)).map_err(HandoffError::InvalidMemoryMap)?,
        read_u64(input, offset + 56),
        read_u64(input, offset + 64),
        PhysAddr::new(read_u64(input, offset + 72)).map_err(HandoffError::InvalidMemoryMap)?,
        read_u64(input, offset + 80),
        read_u64(input, offset + 88),
        measurement,
    )
}

fn decode_application(input: &[u8], offset: usize) -> Result<ApplicationLaunch, HandoffError> {
    let measurement = input[offset + 96..offset + HANDOFF_APPLICATION_BYTES]
        .try_into()
        .map_err(|_| HandoffError::NonCanonical)?;
    ApplicationLaunch::new(
        PhysAddr::new(read_u64(input, offset)).map_err(HandoffError::InvalidMemoryMap)?,
        read_u64(input, offset + 8),
        PhysAddr::new(read_u64(input, offset + 16)).map_err(HandoffError::InvalidMemoryMap)?,
        read_u64(input, offset + 24),
        read_u64(input, offset + 32),
        read_u64(input, offset + 40),
        PhysAddr::new(read_u64(input, offset + 48)).map_err(HandoffError::InvalidMemoryMap)?,
        read_u64(input, offset + 56),
        read_u64(input, offset + 64),
        PhysAddr::new(read_u64(input, offset + 72)).map_err(HandoffError::InvalidMemoryMap)?,
        read_u64(input, offset + 80),
        read_u64(input, offset + 88),
        measurement,
    )
}

fn checked_pages(start: PhysAddr, pages: u64) -> Result<u64, HandoffError> {
    if pages == 0 || pages > u64::MAX / crate::PAGE_SIZE {
        return Err(HandoffError::NonCanonical);
    }
    let bytes = pages * crate::PAGE_SIZE;
    start
        .get()
        .checked_add(bytes)
        .filter(|end| *end >> 52 == 0)
        .ok_or(HandoffError::NonCanonical)?;
    Ok(bytes)
}

fn service_storage_is_reserved(service: ServiceLaunch, regions: &[MemoryRegion]) -> bool {
    launch_storage(service).into_iter().all(|(start, pages)| {
        let end = start.get() + pages * crate::PAGE_SIZE;
        regions.iter().any(|region| {
            matches!(region.kind(), MemoryKind::Kernel | MemoryKind::Reserved)
                && region.start().get() <= start.get()
                && region.end() >= end
        })
    })
}

fn launch_storage(service: ServiceLaunch) -> [(PhysAddr, u64); 4] {
    [
        (
            service.artifact_physical(),
            service.artifact_length().div_ceil(crate::PAGE_SIZE),
        ),
        (service.image_physical(), service.image_pages()),
        (service.stack_physical(), service.stack_pages()),
        (service.table_physical(), service.table_pages()),
    ]
}

fn launch_storage_is_disjoint(first: ServiceLaunch, second: ServiceLaunch) -> bool {
    launch_storage(first)
        .into_iter()
        .all(|(first_start, first_pages)| {
            launch_storage(second)
                .into_iter()
                .all(|(second_start, second_pages)| {
                    !physical_ranges_overlap(first_start, first_pages, second_start, second_pages)
                })
        })
}

const fn user_address(address: u64) -> bool {
    address != 0 && address <= 0x0000_7fff_ffff_ffff
}

const fn user_page(address: u64) -> bool {
    user_address(address) && address.is_multiple_of(crate::PAGE_SIZE)
}

const fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

fn physical_ranges_overlap(a: PhysAddr, a_pages: u64, b: PhysAddr, b_pages: u64) -> bool {
    let a_end = a.get() + a_pages * crate::PAGE_SIZE;
    let b_end = b.get() + b_pages * crate::PAGE_SIZE;
    ranges_overlap(a.get(), a_end, b.get(), b_end)
}

fn decode_region(input: &[u8], index: usize) -> Result<MemoryRegion, HandoffError> {
    let offset = HANDOFF_HEADER_BYTES + index * HANDOFF_REGION_BYTES;
    let start = read_u64(input, offset);
    let pages = read_u64(input, offset + 8);
    let kind = decode_kind(input[offset + 16])?;
    if input[offset + 17..offset + HANDOFF_REGION_BYTES]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(HandoffError::NonCanonical);
    }
    MemoryRegion::new(
        PhysAddr::new(start).map_err(HandoffError::InvalidMemoryMap)?,
        pages,
        kind,
    )
    .map_err(HandoffError::InvalidMemoryMap)
}

fn record_boot_dma(
    slot: &mut Option<MemoryRegion>,
    region: MemoryRegion,
) -> Result<(), HandoffError> {
    if region.kind() == MemoryKind::BootDma {
        if slot.is_some() || crate::BootDmaReservation::from_handoff_region(region).is_err() {
            return Err(HandoffError::NonCanonical);
        }
        *slot = Some(region);
    }
    Ok(())
}

fn decode_kind(value: u8) -> Result<MemoryKind, HandoffError> {
    match value {
        0 => Ok(MemoryKind::Free),
        1 => Ok(MemoryKind::Kernel),
        2 => Ok(MemoryKind::Firmware),
        3 => Ok(MemoryKind::Mmio),
        4 => Ok(MemoryKind::Acpi),
        5 => Ok(MemoryKind::Reserved),
        6 => Ok(MemoryKind::BootDma),
        _ => Err(HandoffError::NonCanonical),
    }
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(input[offset..offset + 2].try_into().unwrap())
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap())
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    const THREE_REGION_BYTES: usize = HANDOFF_HEADER_BYTES + 3 * HANDOFF_REGION_BYTES;

    fn valid_handoff() -> [u8; THREE_REGION_BYTES] {
        let mut encoded = [0u8; THREE_REGION_BYTES];
        encoded[..16].copy_from_slice(b"MRML-HANDOFF-v1\0");
        encoded[16..20].copy_from_slice(&(THREE_REGION_BYTES as u32).to_le_bytes());
        encoded[20..22].copy_from_slice(&3u16.to_le_bytes());
        encoded[22..24].copy_from_slice(
            &(FLAG_SECURE_BOOT
                | FLAG_MEASURED_BOOT
                | FLAG_ROLLBACK_PROTECTED
                | FLAG_COHERENT_RELEASE
                | FLAG_TOTAL_MICROVM_ONCE)
                .to_le_bytes(),
        );
        encoded[24..32].copy_from_slice(&7u64.to_le_bytes());
        encoded[32..64].fill(1);
        encoded[64..128].fill(2);
        encoded[128..136].copy_from_slice(&0x9000u64.to_le_bytes());
        encoded[136..144].copy_from_slice(&0xa0000u64.to_le_bytes());
        encoded[144..152].copy_from_slice(&0x1000u64.to_le_bytes());
        encoded[152..156].copy_from_slice(&16u32.to_le_bytes());
        encoded[156..160].copy_from_slice(&16u32.to_le_bytes());
        encoded[160..164].copy_from_slice(&16u32.to_le_bytes());
        encoded[164] = 1;
        encoded[168..176].copy_from_slice(&0x1000u64.to_le_bytes());
        encoded[176..184].copy_from_slice(&2u64.to_le_bytes());
        encoded[184] = 0;
        encoded[192..200].copy_from_slice(&0x3000u64.to_le_bytes());
        encoded[200..208].copy_from_slice(&1u64.to_le_bytes());
        encoded[208] = 1;
        encoded[216..224].copy_from_slice(&0xa0000u64.to_le_bytes());
        encoded[224..232].copy_from_slice(&1u64.to_le_bytes());
        encoded[232] = 3;
        encoded
    }

    #[test]
    fn decodes_canonical_bounded_handoff() {
        let encoded = valid_handoff();
        let mut starts = [0u64; 3];
        let mut count = 0;
        let handoff = BootHandoff::decode(&encoded, |region| {
            starts[count] = region.start().get();
            count += 1;
        })
        .unwrap();
        assert_eq!(handoff.region_count(), 3);
        assert_eq!(handoff.acpi_root(), 0x9000);
        assert_eq!(starts, [0x1000, 0x3000, 0xa0000]);
        assert_eq!(handoff.framebuffer().width(), 16);
        assert_eq!(handoff.evidence().image_measurement(), &[2; 64]);
        let mut round_trip = [0u8; THREE_REGION_BYTES];
        let mut regions = [decode_region(&encoded, 0).unwrap(); 3];
        for (index, region) in regions.iter_mut().enumerate() {
            *region = decode_region(&encoded, index).unwrap();
        }
        assert_eq!(
            encode_handoff(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                true,
                0x9008,
                handoff.framebuffer(),
                &regions,
                &mut round_trip
            ),
            Ok(THREE_REGION_BYTES)
        );
        assert_eq!(
            BootHandoff::decode(&round_trip, |_| {})
                .unwrap()
                .acpi_root(),
            0x9008
        );
    }

    #[test]
    fn boot_dma_acpi_pair_round_trips_and_corruption_is_rejected_before_emit() {
        let base = valid_handoff();
        let mut output = [0; THREE_REGION_BYTES + DMA_ACPI_LENGTH_BYTES + 48 + 44];
        output[..base.len()].copy_from_slice(&base);
        let table = |signature: &[u8; 4], bytes: &mut [u8]| {
            let length = bytes.len() as u32;
            bytes[..4].copy_from_slice(signature);
            bytes[4..8].copy_from_slice(&length.to_le_bytes());
            bytes[9] =
                0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
        };
        let (mut dmar, mut mcfg) = ([0; 48], [0; 44]);
        table(b"DMAR", &mut dmar);
        table(b"MCFG", &mut mcfg);
        assert_eq!(
            append_boot_dma_acpi(base.len(), &dmar, &mcfg, &mut output),
            Err(HandoffError::NonCanonical)
        );
        output[HANDOFF_HEADER_BYTES + HANDOFF_REGION_BYTES + 16] = MemoryKind::BootDma as u8;
        let total = append_boot_dma_acpi(base.len(), &dmar, &mcfg, &mut output).unwrap();
        assert_eq!(total, output.len());
        let decoded = BootHandoff::decode(&output, |_| {}).unwrap();
        assert_eq!(decoded.dma_acpi(&output), Some((&dmar[..], &mcfg[..])));
        let normal = BootHandoff::decode_normal(&output).unwrap();
        assert_eq!(normal.dma_acpi(&output), Some((&dmar[..], &mcfg[..])));
        assert_eq!(
            append_boot_dma_acpi(total, &dmar, &mcfg, &mut output),
            Err(HandoffError::NonCanonical)
        );
        output[total - 1] ^= 1;
        assert_eq!(
            BootHandoff::decode_normal(&output).err(),
            Some(HandoffError::NonCanonical)
        );
        assert_eq!(
            BootHandoff::decode(&output, |_| panic!("must validate before emit")).err(),
            Some(HandoffError::NonCanonical)
        );
    }

    #[test]
    fn boot_usb_pci_record_requires_companion_tables_and_canonical_final_slot() {
        const WIRE: &[u8; BOOT_USB_PCI_RECORD_BYTES] =
            b"MRMLXHCI\x01\x00\x28\x00\x00\x41\x00\x00\x36\x1b\x0d\x00\x01\x30\x03\x0c\x00\x00\x20\x81\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00";
        const ACPI_END: usize = THREE_REGION_BYTES + DMA_ACPI_LENGTH_BYTES + 48 + 44;
        const END: usize = ACPI_END + BOOT_USB_PCI_RECORD_BYTES;
        let base = valid_handoff();
        let mut output = [0; END + BOOT_USB_PCI_RECORD_BYTES];
        output[..base.len()].copy_from_slice(&base);
        assert_eq!(
            append_boot_usb_pci_record(base.len(), WIRE, &mut output),
            Err(HandoffError::NonCanonical)
        );
        assert_eq!(&output[..base.len()], &base);

        output[HANDOFF_HEADER_BYTES + HANDOFF_REGION_BYTES + 16] = MemoryKind::BootDma as u8;
        let (mut dmar, mut mcfg) = ([0u8; 48], [0u8; 44]);
        for (table, sig) in [(&mut dmar[..], b"DMAR"), (&mut mcfg[..], b"MCFG")] {
            let length = table.len() as u32;
            table[..4].copy_from_slice(sig);
            table[4..8].copy_from_slice(&length.to_le_bytes());
            table[9] = 0u8.wrapping_sub(table.iter().copied().fold(0, u8::wrapping_add));
        }
        assert_eq!(append_boot_dma_acpi(base.len(), &dmar, &mcfg, &mut output), Ok(ACPI_END));
        assert!(BootHandoff::decode(&output[..ACPI_END], |_| {}).unwrap().usb_pci_record().is_none());
        assert_eq!(append_boot_usb_pci_record(ACPI_END, WIRE, &mut output), Ok(END));
        let decoded = BootHandoff::decode(&output[..END], |_| {}).unwrap();
        assert_eq!(decoded.usb_pci_record(), Some(WIRE));
        assert_eq!(decoded.dma_acpi(&output), Some((&dmar[..], &mcfg[..])));

        let before = output;
        assert_eq!(append_boot_usb_pci_record(END, WIRE, &mut output), Err(HandoffError::NonCanonical));
        assert_eq!(output, before);
        for length in [ACPI_END, END - 1, END + 1, output.len()] {
            assert_eq!(
                BootHandoff::decode(&output[..length], |_| panic!("must validate before emit")).err(),
                Some(HandoffError::NonCanonical)
            );
        }
        for index in [0, 8, 10, 21, 24, 33, 39] {
            let mut corrupted = output;
            corrupted[ACPI_END + index] ^= if index == 33 { 1 } else { 0xff };
            assert_eq!(
                BootHandoff::decode(&corrupted[..END], |_| panic!("must validate before emit")).err(),
                Some(HandoffError::NonCanonical),
                "wire byte {index}"
            );
        }
        let mut bad_vendor = output;
        bad_vendor[ACPI_END + 16..ACPI_END + 18].fill(0);
        assert_eq!(BootHandoff::decode(&bad_vendor[..END], |_| panic!("invalid vendor")).err(),
            Some(HandoffError::NonCanonical));
        let mut orphan = output;
        let flags = read_u16(&orphan, 22) & !FLAG_DMA_ACPI;
        orphan[22..24].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(BootHandoff::decode(&orphan[..END], |_| panic!("orphan record")).err(),
            Some(HandoffError::NonCanonical));
    }

    #[test]
    fn dxe_diagnostic_slot_requires_usb_binding_and_distinguishes_incomplete() {
        let base = valid_handoff();
        let mut output = [0; 1024];
        output[..base.len()].copy_from_slice(&base);
        let missing = BootDxeDiagnostic::Incomplete;
        let invalid = Err(HandoffError::NonCanonical);
        assert_eq!(append_boot_dxe_diagnostic(base.len(), &missing, &mut output), invalid);
        assert_eq!(&output[..base.len()], &base);

        // Synthetic transport vectors only. The platform check, not this
        // parser, decides whether coordinates match independently parsed ACPI.
        output[HANDOFF_HEADER_BYTES + HANDOFF_REGION_BYTES + 16] = MemoryKind::BootDma as u8;
        let (mut dmar, mut mcfg) = ([0u8; 48], [0u8; 44]);
        for (table, sig) in [(&mut dmar[..], b"DMAR"), (&mut mcfg[..], b"MCFG")] {
            let length = table.len() as u32;
            table[..4].copy_from_slice(sig);
            table[4..8].copy_from_slice(&length.to_le_bytes());
            table[9] = 0u8.wrapping_sub(table.iter().copied().fold(0, u8::wrapping_add));
        }
        let acpi_end = append_boot_dma_acpi(base.len(), &dmar, &mcfg, &mut output).unwrap();
        assert_eq!(append_boot_dxe_diagnostic(acpi_end, &missing, &mut output), invalid);
        let wire = b"MRMLXHCI\x01\x00\x28\x00\x00\x41\x00\x00\x36\x1b\x0d\x00\x01\x30\x03\x0c\x00\x00\x20\x81\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00";
        let usb_end = append_boot_usb_pci_record(acpi_end, wire, &mut output).unwrap();
        assert_eq!(BootHandoff::decode(&output[..usb_end], |_| {}).unwrap().boot_dxe_diagnostic(), None);
        assert_eq!(
            BootHandoff::decode_normal(&output[..usb_end]).err(),
            Some(HandoffError::UnknownFlags)
        );

        let end = append_boot_dxe_diagnostic(usb_end, &missing, &mut output).unwrap();
        assert_eq!(BootHandoff::decode(&output[..end], |_| {}).unwrap().boot_dxe_diagnostic(), Some(&missing));
        let before = output;
        assert_eq!(append_boot_dxe_diagnostic(end, &missing, &mut output), invalid);
        assert_eq!(output, before);
        let rejects = |bytes: &[u8]| {
            assert_eq!(BootHandoff::decode(bytes, |_| panic!("reject before emit")).err(),
                Some(HandoffError::NonCanonical));
        };
        for offset in 0..BOOT_DXE_DIAGNOSTIC_BYTES {
            let mut changed = output;
            changed[usb_end + offset] = 2;
            rejects(&changed[..end]);
        }
        rejects(&output[..end - 1]);
        rejects(&output[..end + 1]);
        let mut orphan = output;
        let flags = read_u16(&orphan, 22) & !FLAG_USB_PCI_DIAGNOSTIC;
        orphan[22..24].copy_from_slice(&flags.to_le_bytes());
        rejects(&orphan[..end]);
        assert_eq!(
            BootHandoff::decode_normal(&orphan[..end]).err(),
            Some(HandoffError::UnknownFlags)
        );

        let mut record = [0; PASSIVE_DXE_RECORD_BYTES];
        record[..13].copy_from_slice(b"MRMLDXE\0\x01\x00\xc8\x00\x01");
        record[18] = 0x41;
        record[56..64].copy_from_slice(&0x8120_0000u64.to_le_bytes());
        record[64..72].copy_from_slice(&4u64.to_le_bytes());
        let copied = BootDxeDiagnostic::Copied(record);
        output[..usb_end].copy_from_slice(&before[..usb_end]);
        // Restore the preceding USB-only header for the independent copy case.
        output[22..24].copy_from_slice(&(read_u16(&before, 22) & !FLAG_DXE_DIAGNOSTIC).to_le_bytes());
        output[16..20].copy_from_slice(&(usb_end as u32).to_le_bytes());
        let end = append_boot_dxe_diagnostic(usb_end, &copied, &mut output).unwrap();
        assert_eq!(BootHandoff::decode(&output[..end], |_| {}).unwrap().boot_dxe_diagnostic(), Some(&copied));
        assert_eq!(
            BootHandoff::decode_normal(&output[..end]).err(),
            Some(HandoffError::UnknownFlags)
        );
        for offset in [0, 8, 10, 12, 13, 16, 18, 19, 20, 21, 56, 64, 82, 88, 199] {
            let mut changed = output;
            changed[usb_end + 8 + offset] ^= if offset == 12 { 0xff } else { 1 };
            rejects(&changed[..end]);
        }
    }

    #[test]
    fn boot_dma_tag_round_trips_and_rejects_duplicates() {
        let template = valid_handoff();
        let mut regions = core::array::from_fn::<_, 3, _>(|i| decode_region(&template, i).unwrap());
        let framebuffer = BootHandoff::decode(&template, |_| {})
            .unwrap()
            .framebuffer();
        regions[1] = MemoryRegion::new(regions[1].start(), 2, MemoryKind::BootDma).unwrap();
        let mut encoded = [0; THREE_REGION_BYTES];
        let encode = |regions: &[MemoryRegion], output: &mut [u8]| {
            encode_handoff(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                true,
                0x9008,
                framebuffer,
                regions,
                output,
            )
        };
        assert_eq!(encode(&regions, &mut encoded), Ok(THREE_REGION_BYTES));
        assert_eq!(
            BootHandoff::decode(&encoded, |_| {}).unwrap().boot_dma(),
            Some(regions[1])
        );
        let mut allocator = crate::FrameAllocator::new(MemoryMap::new(&regions).unwrap());
        assert_eq!(allocator.allocate().unwrap().get(), 0x1000);
        assert_eq!(allocator.allocate().unwrap().get(), 0x2000);
        assert_eq!(allocator.allocate(), Err(MemoryError::OutOfMemory));
        regions[0] = MemoryRegion::new(regions[0].start(), 1, MemoryKind::BootDma).unwrap();
        assert_eq!(
            encode(&regions, &mut encoded),
            Err(HandoffError::NonCanonical)
        );
        encoded[HANDOFF_HEADER_BYTES + 16] = MemoryKind::BootDma as u8;
        assert_eq!(
            BootHandoff::decode(&encoded, |_| {}).err(),
            Some(HandoffError::NonCanonical)
        );
    }

    #[test]
    fn rejects_lengths_flags_reserved_bytes_and_overlaps() {
        let mut encoded = valid_handoff();
        encoded[22..24].copy_from_slice(&0x8000u16.to_le_bytes());
        assert_eq!(
            BootHandoff::decode(&encoded, |_| {}).err(),
            Some(HandoffError::UnknownFlags)
        );

        let mut encoded = valid_handoff();
        encoded[185] = 1;
        assert_eq!(
            BootHandoff::decode(&encoded, |_| {}).err(),
            Some(HandoffError::NonCanonical)
        );

        let mut encoded = valid_handoff();
        encoded[192..200].copy_from_slice(&0x2000u64.to_le_bytes());
        let mut emitted = 0;
        assert_eq!(
            BootHandoff::decode(&encoded, |_| emitted += 1).err(),
            Some(HandoffError::InvalidMemoryMap(MemoryError::Overlap))
        );
        assert_eq!(emitted, 0);

        let encoded = valid_handoff();
        assert_eq!(
            BootHandoff::decode(&encoded[..encoded.len() - 1], |_| {}).err(),
            Some(HandoffError::NonCanonical)
        );
    }

    #[test]
    fn appended_madt_is_canonical_and_bound_to_the_length() {
        let encoded = valid_handoff();
        let handoff = BootHandoff::decode(&encoded, |_| {}).unwrap();
        let mut regions = [decode_region(&encoded, 0).unwrap(); 3];
        for (index, region) in regions.iter_mut().enumerate() {
            *region = decode_region(&encoded, index).unwrap();
        }
        let mut madt = [0u8; 52];
        madt[..4].copy_from_slice(b"APIC");
        madt[4..8].copy_from_slice(&52u32.to_le_bytes());
        madt[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        madt[44..].copy_from_slice(&[0, 8, 0, 1, 1, 0, 0, 0]);
        madt[9] = 0u8.wrapping_sub(madt.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
        let mut with_madt = [0u8; THREE_REGION_BYTES + 52];
        assert_eq!(
            encode_handoff_with_madt(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                true,
                0x9000,
                handoff.framebuffer(),
                &regions,
                &madt,
                &mut with_madt,
            ),
            Ok(with_madt.len())
        );
        let decoded = BootHandoff::decode(&with_madt, |_| {}).unwrap();
        assert_eq!(decoded.madt(&with_madt), Some(madt.as_slice()));
        let mut with_smp = [0u8; THREE_REGION_BYTES + 16 + 52];
        assert_eq!(
            encode_handoff_with_smp(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                true,
                0x9000,
                handoff.framebuffer(),
                &regions,
                0x8000,
                0x40_0000,
                &madt,
                &mut with_smp,
            ),
            Ok(with_smp.len())
        );
        let smp = BootHandoff::decode(&with_smp, |_| {}).unwrap();
        assert_eq!(smp.ap_trampoline(), Some(0x8000));
        assert_eq!(smp.ap_stack_arena(), Some(0x40_0000));
        assert_eq!(smp.madt(&with_smp), Some(madt.as_slice()));
        with_smp[THREE_REGION_BYTES + 8..THREE_REGION_BYTES + 16].fill(0);
        assert_eq!(
            BootHandoff::decode(&with_smp, |_| {}).err(),
            Some(HandoffError::NonCanonical)
        );
        with_madt[165] = 51;
        assert_eq!(
            BootHandoff::decode(&with_madt, |_| {}).err(),
            Some(HandoffError::NonCanonical)
        );
    }

    #[test]
    fn application_descriptor_is_typed_but_reuses_bounded_user_layout() {
        let application = ApplicationLaunch::new(
            PhysAddr::new(0x11_0000).unwrap(),
            1024,
            PhysAddr::new(0x10_0000).unwrap(),
            2,
            0x1_4000_0000,
            0x1_4000_0080,
            PhysAddr::new(0x10_4000).unwrap(),
            2,
            0x2_0000_2000,
            PhysAddr::new(0x10_8000).unwrap(),
            4,
            13,
            [0x4a; 64],
        )
        .unwrap();
        assert_eq!(application.version(), 13);
        assert_eq!(application.measurement(), [0x4a; 64]);
        assert_eq!(application.entry(), 0x1_4000_0080);
        assert_eq!(application.image_pages(), 2);
        assert!(
            ApplicationLaunch::new(
                PhysAddr::new(0x11_0000).unwrap(),
                1024,
                PhysAddr::new(0x10_0000).unwrap(),
                2,
                0x1_4000_0000,
                0x1_4000_0080,
                PhysAddr::new(0x10_4000).unwrap(),
                2,
                0x2_0000_2000,
                PhysAddr::new(0x10_8000).unwrap(),
                4,
                0,
                [0x4a; 64],
            )
            .is_err()
        );
    }

    #[test]
    fn service_and_application_round_trip_as_disjoint_typed_launches() {
        const LENGTH: usize = HANDOFF_HEADER_BYTES
            + 2 * HANDOFF_REGION_BYTES
            + HANDOFF_SERVICE_BYTES
            + HANDOFF_APPLICATION_BYTES
            + 16
            + 52;
        let regions = [
            MemoryRegion::new(PhysAddr::new(0xa0000).unwrap(), 1, MemoryKind::Mmio).unwrap(),
            MemoryRegion::new(PhysAddr::new(0x10_0000).unwrap(), 256, MemoryKind::Reserved)
                .unwrap(),
        ];
        let framebuffer = FramebufferInfo::new(
            0xa0000,
            0x1000,
            16,
            16,
            16,
            PixelFormat::BlueGreenRedReserved,
        )
        .unwrap();
        let service = ServiceLaunch::new(
            PhysAddr::new(0x11_0000).unwrap(),
            1024,
            PhysAddr::new(0x10_0000).unwrap(),
            2,
            0x1_4000_0000,
            0x1_4000_0080,
            PhysAddr::new(0x10_4000).unwrap(),
            2,
            0x2_0000_2000,
            PhysAddr::new(0x10_8000).unwrap(),
            4,
            11,
            [9; 64],
        )
        .unwrap();
        let application = ApplicationLaunch::new(
            PhysAddr::new(0x13_0000).unwrap(),
            1024,
            PhysAddr::new(0x12_0000).unwrap(),
            2,
            0x1_5000_0000,
            0x1_5000_0080,
            PhysAddr::new(0x12_4000).unwrap(),
            2,
            0x2_1000_2000,
            PhysAddr::new(0x12_8000).unwrap(),
            4,
            13,
            [0x4a; 64],
        )
        .unwrap();
        let mut madt = [0u8; 52];
        madt[..4].copy_from_slice(b"APIC");
        madt[4..8].copy_from_slice(&52u32.to_le_bytes());
        madt[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        madt[44..].copy_from_slice(&[0, 8, 0, 1, 1, 0, 0, 0]);
        madt[9] = 0u8.wrapping_sub(madt.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
        let mut encoded = [0; LENGTH];
        assert_eq!(
            encode_handoff_with_smp_service_application_and_recovery(
                17,
                [1; 32],
                [2; 64],
                true,
                true,
                true,
                true,
                0x9000,
                framebuffer,
                &regions,
                0x8000,
                0x40_0000,
                service,
                application,
                None,
                &madt,
                &mut encoded,
            ),
            Ok(LENGTH)
        );
        let decoded = BootHandoff::decode(&encoded, |_| {}).unwrap();
        assert_eq!(decoded.service(), Some(service));
        assert_eq!(decoded.application(), Some(application));

        const APPLICATION_ONLY_LENGTH: usize =
            HANDOFF_HEADER_BYTES + 2 * HANDOFF_REGION_BYTES + HANDOFF_APPLICATION_BYTES + 16 + 52;
        let mut application_only = [0; APPLICATION_ONLY_LENGTH];
        assert_eq!(
            encode_handoff_with_smp_and_application(
                17,
                [1; 32],
                [2; 64],
                true,
                true,
                true,
                0x9000,
                framebuffer,
                &regions,
                0x8000,
                0x40_0000,
                application,
                &madt,
                &mut application_only,
            ),
            Ok(APPLICATION_ONLY_LENGTH)
        );
        let decoded_application_only = BootHandoff::decode(&application_only, |_| {}).unwrap();
        assert_eq!(decoded_application_only.service(), None);
        assert_eq!(decoded_application_only.application(), Some(application));

        const NON_SMP_APPLICATION_LENGTH: usize =
            HANDOFF_HEADER_BYTES + 2 * HANDOFF_REGION_BYTES + HANDOFF_APPLICATION_BYTES;
        let mut non_smp_application = [0; NON_SMP_APPLICATION_LENGTH];
        assert_eq!(
            encode_handoff_with_application(
                17,
                [1; 32],
                [2; 64],
                true,
                true,
                true,
                0x9000,
                framebuffer,
                &regions,
                application,
                &mut non_smp_application,
            ),
            Ok(NON_SMP_APPLICATION_LENGTH)
        );
        let decoded_non_smp = BootHandoff::decode(&non_smp_application, |_| {}).unwrap();
        assert_eq!(decoded_non_smp.ap_trampoline(), None);
        assert_eq!(decoded_non_smp.madt(&non_smp_application), None);
        assert_eq!(decoded_non_smp.application(), Some(application));

        let mut malformed = encoded;
        let flags = read_u16(&malformed, 22) & !FLAG_APPLICATION_IMAGE;
        malformed[22..24].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(
            BootHandoff::decode(&malformed, |_| {}).err(),
            Some(HandoffError::NonCanonical)
        );
        let application_offset =
            HANDOFF_HEADER_BYTES + 2 * HANDOFF_REGION_BYTES + HANDOFF_SERVICE_BYTES;
        malformed = encoded;
        malformed[application_offset + 96..application_offset + HANDOFF_APPLICATION_BYTES].fill(0);
        assert_eq!(
            BootHandoff::decode(&malformed, |_| {}).err(),
            Some(HandoffError::NonCanonical)
        );

        let overlapping_application = ApplicationLaunch(service);
        assert_eq!(
            encode_handoff_with_smp_service_application_and_recovery(
                17,
                [1; 32],
                [2; 64],
                true,
                true,
                true,
                true,
                0x9000,
                framebuffer,
                &regions,
                0x8000,
                0x40_0000,
                service,
                overlapping_application,
                None,
                &madt,
                &mut encoded,
            ),
            Err(HandoffError::NonCanonical)
        );
    }

    #[test]
    fn supervisor_trailer_requires_exact_service_and_complete_boot_evidence() {
        let regions = [
            MemoryRegion::new(PhysAddr::new(0xa0000).unwrap(), 1, MemoryKind::Mmio).unwrap(),
            MemoryRegion::new(PhysAddr::new(0x10_0000).unwrap(), 64, MemoryKind::Reserved).unwrap(),
        ];
        let framebuffer = FramebufferInfo::new(
            0xa0000,
            0x1000,
            16,
            16,
            16,
            PixelFormat::BlueGreenRedReserved,
        )
        .unwrap();
        let phys = |at| PhysAddr::new(at).unwrap();
        let service = ServiceLaunch::new(
            phys(0x11_0000),
            1024,
            phys(0x10_0000),
            2,
            0x1_4000_0000,
            0x1_4000_0080,
            phys(0x10_4000),
            2,
            0x2_0000_2000,
            phys(0x10_8000),
            4,
            11,
            [9; 64],
        )
        .unwrap();
        let mut madt = [0u8; 44];
        madt[..4].copy_from_slice(b"APIC");
        madt[4..8].copy_from_slice(&44u32.to_le_bytes());
        madt[9] = 0u8.wrapping_sub(madt.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
        let mut encoded = [0; 1024];
        let length = encode_handoff_with_smp_service_and_recovery(
            11,
            [1; 32],
            [2; 64],
            true,
            true,
            true,
            true,
            0x9000,
            framebuffer,
            &regions,
            0x8000,
            0x40_0000,
            service,
            None,
            &madt,
            &mut encoded,
        )
        .unwrap();
        assert_eq!(
            BootHandoff::decode(&encoded[..length], |_| {})
                .unwrap()
                .supervisor_selection(),
            None
        );
        assert_eq!(
            BootHandoff::decode_normal(&encoded[..length])
                .unwrap()
                .supervisor_selection(),
            None
        );
        let selection = BootSupervisorSelection::new(11, [5; 64], [9; 64]).unwrap();
        for invalid in [
            BootSupervisorSelection::new(10, [5; 64], [9; 64]).unwrap(),
            BootSupervisorSelection::new(11, [5; 64], [8; 64]).unwrap(),
        ] {
            let original = encoded;
            assert_eq!(
                append_boot_supervisor_selection(length, invalid, &mut encoded),
                Err(HandoffError::NonCanonical)
            );
            assert_eq!(encoded, original);
        }
        let total = append_boot_supervisor_selection(length, selection, &mut encoded).unwrap();
        assert_eq!(total, length + SUPERVISOR_TRAILER_BYTES);
        let decoded = BootHandoff::decode(&encoded[..total], |_| {}).unwrap();
        assert_eq!(decoded.supervisor_selection(), Some(selection));
        assert_eq!(decoded.madt(&encoded), Some(madt.as_slice()));
        let normal = BootHandoff::decode_normal(&encoded[..total]).unwrap();
        assert_eq!(normal.supervisor_selection(), Some(selection));
        assert_eq!(normal.madt(&encoded), Some(madt.as_slice()));
        assert_eq!(
            append_boot_supervisor_selection(total, selection, &mut encoded),
            Err(HandoffError::NonCanonical)
        );
        assert!(BootHandoff::decode(&encoded[..total - 1], |_| {}).is_err());
        for offset in [length, length + 24, length + 88, total - 1] {
            let mut modified = encoded;
            modified[offset] ^= 1;
            assert_eq!(
                BootHandoff::decode_normal(&modified[..total]).err(),
                Some(HandoffError::NonCanonical)
            );
            let mut emitted = 0;
            assert_eq!(
                BootHandoff::decode(&modified[..total], |_| emitted += 1).err(),
                Some(HandoffError::NonCanonical)
            );
            assert_eq!(emitted, 0);
        }
        for flag in [
            FLAG_SECURE_BOOT,
            FLAG_MEASURED_BOOT,
            FLAG_ROLLBACK_PROTECTED,
            FLAG_COHERENT_RELEASE,
            FLAG_SUPERVISOR_SELECTION,
        ] {
            let mut modified = encoded;
            let flags = read_u16(&encoded, 22) & !flag;
            modified[22..24].copy_from_slice(&flags.to_le_bytes());
            assert_eq!(
                BootHandoff::decode(&modified[..total], |_| {}).err(),
                Some(HandoffError::NonCanonical)
            );
        }
    }

    #[test]
    fn authenticated_service_descriptor_round_trips_and_is_memory_bound() {
        const LENGTH: usize =
            HANDOFF_HEADER_BYTES + 2 * HANDOFF_REGION_BYTES + HANDOFF_SERVICE_BYTES + 16 + 52;
        let regions = [
            MemoryRegion::new(PhysAddr::new(0xa0000).unwrap(), 1, MemoryKind::Mmio).unwrap(),
            MemoryRegion::new(PhysAddr::new(0x10_0000).unwrap(), 64, MemoryKind::Reserved).unwrap(),
        ];
        let framebuffer = FramebufferInfo::new(
            0xa0000,
            0x1000,
            16,
            16,
            16,
            PixelFormat::BlueGreenRedReserved,
        )
        .unwrap();
        let service = ServiceLaunch::new(
            PhysAddr::new(0x11_0000).unwrap(),
            1024,
            PhysAddr::new(0x10_0000).unwrap(),
            2,
            0x1_4000_0000,
            0x1_4000_0080,
            PhysAddr::new(0x10_4000).unwrap(),
            2,
            0x2_0000_2000,
            PhysAddr::new(0x10_8000).unwrap(),
            4,
            11,
            [9; 64],
        )
        .unwrap();
        let mut madt = [0u8; 52];
        madt[..4].copy_from_slice(b"APIC");
        madt[4..8].copy_from_slice(&52u32.to_le_bytes());
        madt[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        madt[44..].copy_from_slice(&[0, 8, 0, 1, 1, 0, 0, 0]);
        madt[9] = 0u8.wrapping_sub(madt.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
        let mut encoded = [0u8; LENGTH];
        assert_eq!(
            encode_handoff_with_smp_and_service(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                true,
                0x9000,
                framebuffer,
                &regions,
                0x8000,
                0x40_0000,
                service,
                &madt,
                &mut encoded,
            ),
            Ok(LENGTH)
        );
        let decoded = BootHandoff::decode(&encoded, |_| {}).unwrap();
        assert_eq!(decoded.service(), Some(service));
        assert_eq!(decoded.madt(&encoded), Some(madt.as_slice()));

        // Moving the authenticated image into MMIO must invalidate the whole
        // handoff before any memory region is emitted.
        let service_offset = HANDOFF_HEADER_BYTES + 2 * HANDOFF_REGION_BYTES;
        encoded[service_offset..service_offset + 8].copy_from_slice(&0xa0000u64.to_le_bytes());
        let mut emitted = 0;
        assert_eq!(
            BootHandoff::decode(&encoded, |_| emitted += 1).err(),
            Some(HandoffError::NonCanonical)
        );
        assert_eq!(emitted, 0);

        const WITH_RECOVERY_LENGTH: usize = LENGTH + HANDOFF_RECOVERY_STATE_BYTES;
        let recovery = RecoveryStateMetadata::new(12, 7, Some([0x6a; 16]), 19).unwrap();
        let mut with_recovery = [0u8; WITH_RECOVERY_LENGTH];
        assert_eq!(
            encode_handoff_with_smp_service_and_recovery(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                false,
                true,
                0x9000,
                framebuffer,
                &regions,
                0x8000,
                0x40_0000,
                service,
                Some(recovery),
                &madt,
                &mut with_recovery,
            ),
            Ok(WITH_RECOVERY_LENGTH)
        );
        let decoded = BootHandoff::decode(&with_recovery, |_| {}).unwrap();
        assert_eq!(decoded.recovery_state(), Some(recovery));
        assert_eq!(decoded.isolation_override(), None);
        assert!(!decoded.evidence().rollback_protected());
        assert!(decoded.evidence().coherent_release());

        let mut with_isolation = [0u8; WITH_RECOVERY_LENGTH];
        assert_eq!(
            encode_handoff_with_smp_service_recovery_and_isolation(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                false,
                true,
                0x9000,
                framebuffer,
                &regions,
                0x8000,
                0x40_0000,
                service,
                Some(recovery),
                Some(BootIsolationOverride::TotalMicrovmOnce),
                &madt,
                &mut with_isolation,
            ),
            Ok(WITH_RECOVERY_LENGTH)
        );
        let decoded = BootHandoff::decode(&with_isolation, |_| {}).unwrap();
        assert_eq!(
            decoded.isolation_override(),
            Some(BootIsolationOverride::TotalMicrovmOnce)
        );
        assert_eq!(decoded.recovery_state(), Some(recovery));

        let installed = InstalledRecoveryBootIdentity::new(
            crate::InstalledRecoverySource::Uefi,
            [0x51; 32],
            3,
            9,
            4096,
            128,
            [0x6a; 16],
            2,
            19,
        )
        .unwrap();
        const WITH_INSTALLED_LENGTH: usize =
            WITH_RECOVERY_LENGTH + INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES;
        let mut with_installed = [0u8; WITH_INSTALLED_LENGTH];
        assert_eq!(
            encode_handoff_with_smp_service_recovery_isolation_and_installed(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                false,
                true,
                0x9000,
                framebuffer,
                &regions,
                0x8000,
                0x40_0000,
                service,
                Some(recovery),
                Some(installed),
                Some(BootIsolationOverride::TotalMicrovmOnce),
                &madt,
                &mut with_installed,
            ),
            Ok(WITH_INSTALLED_LENGTH)
        );
        let decoded = BootHandoff::decode(&with_installed, |_| {}).unwrap();
        assert_eq!(decoded.recovery_state(), Some(recovery));
        assert_eq!(decoded.installed_recovery(), Some(installed));
        assert_eq!(decoded.madt(&with_installed), Some(madt.as_slice()));
        assert_eq!(
            decoded.isolation_override(),
            Some(BootIsolationOverride::TotalMicrovmOnce)
        );

        let hops = [crate::InstalledRecoveryPciHop::new(5, 0).unwrap()];
        let media =
            crate::InstalledRecoveryHardDriveMedia::new(2, 2048, 4096, [0x6a; 16], 2, 2).unwrap();
        let sata_route = InstalledRecoverySataRoute::new(
            0x0a03_41d0,
            0,
            &hops,
            3,
            u16::MAX,
            0,
            Some(media),
            installed.stable_id(),
        )
        .unwrap();
        const WITH_SATA_ROUTE_LENGTH: usize =
            WITH_INSTALLED_LENGTH + INSTALLED_RECOVERY_SATA_ROUTE_BYTES;
        let mut with_sata_route = [0; WITH_SATA_ROUTE_LENGTH];
        assert_eq!(
            encode_handoff_with_smp_service_recovery_isolation_installed_and_sata_route(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                false,
                true,
                0x9000,
                framebuffer,
                &regions,
                0x8000,
                0x40_0000,
                service,
                Some(recovery),
                Some(installed),
                Some(sata_route),
                Some(BootIsolationOverride::TotalMicrovmOnce),
                &madt,
                &mut with_sata_route,
            ),
            Ok(WITH_SATA_ROUTE_LENGTH)
        );
        let decoded = BootHandoff::decode(&with_sata_route, |_| {}).unwrap();
        assert_eq!(decoded.installed_recovery(), Some(installed));
        assert_eq!(decoded.installed_recovery_sata_route(), Some(sata_route));
        assert_eq!(decoded.madt(&with_sata_route), Some(madt.as_slice()));

        let route_offset = HANDOFF_HEADER_BYTES
            + 2 * HANDOFF_REGION_BYTES
            + HANDOFF_SERVICE_BYTES
            + HANDOFF_RECOVERY_STATE_BYTES
            + INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES;
        let installed_offset = route_offset - INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES;
        let mut substituted = with_sata_route;
        substituted[route_offset + 96] ^= 1;
        assert_eq!(
            BootHandoff::decode(&substituted, |_| {}).err(),
            Some(HandoffError::NonCanonical)
        );
        let mut missing_installed = with_sata_route;
        let flags = read_u16(&missing_installed, 22) & !FLAG_INSTALLED_RECOVERY_IDENTITY;
        missing_installed[22..24].copy_from_slice(&flags.to_le_bytes());
        missing_installed.copy_within(route_offset.., installed_offset);
        let missing_installed_length =
            WITH_SATA_ROUTE_LENGTH - INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES;
        missing_installed[16..20].copy_from_slice(&(missing_installed_length as u32).to_le_bytes());
        assert_eq!(
            BootHandoff::decode(&missing_installed[..missing_installed_length], |_| {}).err(),
            Some(HandoffError::NonCanonical)
        );

        const RECOVERY_ONLY_INSTALLED_LENGTH: usize = HANDOFF_HEADER_BYTES
            + 2 * HANDOFF_REGION_BYTES
            + HANDOFF_RECOVERY_STATE_BYTES
            + INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES;
        let mut recovery_only = [0; RECOVERY_ONLY_INSTALLED_LENGTH];
        assert_eq!(
            encode_handoff_with_recovery_isolation_and_installed(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                false,
                true,
                0x9000,
                framebuffer,
                &regions,
                recovery,
                installed,
                Some(BootIsolationOverride::TotalMicrovmOnce),
                &mut recovery_only,
            ),
            Ok(RECOVERY_ONLY_INSTALLED_LENGTH)
        );
        let decoded = BootHandoff::decode(&recovery_only, |_| {}).unwrap();
        assert_eq!(decoded.service(), None);
        assert_eq!(decoded.ap_trampoline(), None);
        assert_eq!(decoded.recovery_state(), Some(recovery));
        assert_eq!(decoded.installed_recovery(), Some(installed));
        assert_eq!(decoded.madt(&recovery_only), None);

        let installed_offset = HANDOFF_HEADER_BYTES
            + 2 * HANDOFF_REGION_BYTES
            + HANDOFF_SERVICE_BYTES
            + HANDOFF_RECOVERY_STATE_BYTES;
        let mut malformed = with_installed;
        malformed[installed_offset + 72] ^= 1;
        assert_eq!(
            BootHandoff::decode(&malformed, |_| {}).err(),
            Some(HandoffError::NonCanonical)
        );
        let wrong_root = InstalledRecoveryBootIdentity::new(
            crate::InstalledRecoverySource::Uefi,
            [0x51; 32],
            3,
            9,
            4096,
            128,
            [0x6a; 16],
            2,
            20,
        )
        .unwrap();
        assert_eq!(
            encode_handoff_with_smp_service_recovery_isolation_and_installed(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                false,
                true,
                0x9000,
                framebuffer,
                &regions,
                0x8000,
                0x40_0000,
                service,
                Some(recovery),
                Some(wrong_root),
                None,
                &madt,
                &mut with_installed,
            ),
            Err(HandoffError::NonCanonical)
        );

        let recovery_offset =
            HANDOFF_HEADER_BYTES + 2 * HANDOFF_REGION_BYTES + HANDOFF_SERVICE_BYTES;
        with_recovery[recovery_offset + 12] = 1;
        let mut emitted = 0;
        assert_eq!(
            BootHandoff::decode(&with_recovery, |_| emitted += 1).err(),
            Some(HandoffError::NonCanonical)
        );
        assert_eq!(emitted, 0);
        with_recovery[recovery_offset + 12] = 0;
        with_recovery[recovery_offset + 32..recovery_offset + 40].fill(0);
        assert_eq!(
            BootHandoff::decode(&with_recovery, |_| {}).err(),
            Some(HandoffError::NonCanonical)
        );

        assert_eq!(
            RecoveryStateMetadata::new(1, 1, Some([0; 16]), 1),
            Err(HandoffError::NonCanonical)
        );
        assert_eq!(
            RecoveryStateMetadata::new(1, 1, None, 1),
            Err(HandoffError::NonCanonical)
        );
    }
}
