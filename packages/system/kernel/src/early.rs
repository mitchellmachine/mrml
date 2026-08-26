use crate::{
    BootHandoff, BootIsolationOverride, Color, FramebufferError, FramebufferInfo,
    FramebufferSurface, InstalledRecoveryBootIdentity, InstalledRecoverySataRoute,
    InstalledRecoverySource, MemoryError, MemoryKind, MemoryMap, MemoryRegion,
    RecoveryStateMetadata,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EarlyKernelError {
    MissingEntropy,
    MissingAcpi,
    InvalidMemoryMap(MemoryError),
    FramebufferOutsideMmio,
    MissingInstalledRecoveryRoute,
    Framebuffer(FramebufferError),
}

/// Architecture-neutral state admitted at the first kernel instruction after
/// firmware services have ended. Construction validates every borrowed region
/// before privileged kernel initialization can consume it.
pub struct EarlyKernelContext<'a> {
    entropy: [u8; 32],
    acpi_root: u64,
    framebuffer: FramebufferInfo,
    memory: MemoryMap<'a>,
    isolation_override: Option<BootIsolationOverride>,
    recovery_state: Option<RecoveryStateMetadata>,
    installed_recovery: Option<InstalledRecoveryBootIdentity>,
    installed_recovery_sata_route: Option<InstalledRecoverySataRoute>,
}

impl<'a> EarlyKernelContext<'a> {
    pub fn new(
        entropy: [u8; 32],
        acpi_root: u64,
        framebuffer: FramebufferInfo,
        regions: &'a [MemoryRegion],
    ) -> Result<Self, EarlyKernelError> {
        if entropy.iter().all(|byte| *byte == 0) {
            return Err(EarlyKernelError::MissingEntropy);
        }
        if acpi_root == 0 {
            return Err(EarlyKernelError::MissingAcpi);
        }
        let memory = MemoryMap::new(regions).map_err(EarlyKernelError::InvalidMemoryMap)?;
        if !regions.iter().any(|region| {
            region.kind() == MemoryKind::Mmio
                && region.start().get() <= framebuffer.base().get()
                && region.end() >= framebuffer.end()
        }) {
            return Err(EarlyKernelError::FramebufferOutsideMmio);
        }
        Ok(Self {
            entropy,
            acpi_root,
            framebuffer,
            memory,
            isolation_override: None,
            recovery_state: None,
            installed_recovery: None,
            installed_recovery_sata_route: None,
        })
    }

    /// Consumes the exact decoded loader handoff for early kernel state. The
    /// one-boot isolation request remains evidence only; later configuration
    /// and release admission must establish effective placement.
    pub fn from_handoff(
        handoff: &BootHandoff,
        regions: &'a [MemoryRegion],
    ) -> Result<Self, EarlyKernelError> {
        let mut context = Self::new(
            *handoff.evidence().entropy(),
            handoff.acpi_root(),
            handoff.framebuffer(),
            regions,
        )?;
        let installed_recovery = handoff.installed_recovery();
        let installed_recovery_sata_route = handoff.installed_recovery_sata_route();
        if installed_recovery
            .is_some_and(|identity| identity.source() == InstalledRecoverySource::Uefi)
            && installed_recovery_sata_route.is_none()
        {
            return Err(EarlyKernelError::MissingInstalledRecoveryRoute);
        }
        context.isolation_override = handoff.isolation_override();
        context.recovery_state = handoff.recovery_state();
        context.installed_recovery = installed_recovery;
        context.installed_recovery_sata_route = installed_recovery_sata_route;
        Ok(context)
    }

    pub const fn entropy(&self) -> &[u8; 32] {
        &self.entropy
    }
    pub const fn acpi_root(&self) -> u64 {
        self.acpi_root
    }
    pub fn memory(&self) -> &MemoryMap<'a> {
        &self.memory
    }

    /// Returns the canonical one-boot request carried by the decoded handoff.
    /// This identifies no capability and does not prove effective placement.
    pub const fn isolation_override(&self) -> Option<BootIsolationOverride> {
        self.isolation_override
    }

    /// Returns the exact recovery state decoded by the loader. This is
    /// provenance, not rollback authority; later recovery must still validate
    /// it against its authenticated monotonic state.
    pub const fn recovery_state(&self) -> Option<RecoveryStateMetadata> {
        self.recovery_state
    }

    /// Returns the exact authority-free installed identity retained from the
    /// canonical loader handoff.
    pub const fn installed_recovery(&self) -> Option<InstalledRecoveryBootIdentity> {
        self.installed_recovery
    }

    /// Returns the adjacent typed SATA route retained for a UEFI installed
    /// identity. Native discovery must still establish exact equality.
    pub const fn installed_recovery_sata_route(&self) -> Option<InstalledRecoverySataRoute> {
        self.installed_recovery_sata_route
    }

    /// Visible proof that execution crossed into validated kernel code. A
    /// later console replaces this solid bring-up marker with glyph rendering.
    pub fn render_booted(&self, bytes: &mut [u8]) -> Result<(), EarlyKernelError> {
        let mut surface = FramebufferSurface::new(self.framebuffer, bytes)
            .map_err(EarlyKernelError::Framebuffer)?;
        surface
            .fill_rectangle(
                0,
                0,
                self.framebuffer.width(),
                self.framebuffer.height(),
                Color {
                    red: 0x16,
                    green: 0x61,
                    blue: 0x3a,
                },
            )
            .map_err(EarlyKernelError::Framebuffer)?;
        let marker_width = self.framebuffer.width().min(64);
        let marker_height = self.framebuffer.height().min(8);
        surface
            .fill_rectangle(
                0,
                0,
                marker_width,
                marker_height,
                Color {
                    red: 0xf2,
                    green: 0xf2,
                    blue: 0xf2,
                },
            )
            .map_err(EarlyKernelError::Framebuffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BootIsolationOverride, InstalledRecoveryBootIdentity, InstalledRecoverySource, PAGE_SIZE,
        PhysAddr, PixelFormat, RecoveryStateMetadata,
        encode_handoff_with_recovery_isolation_and_installed,
    };

    #[test]
    fn early_entry_requires_mmio_and_renders_marker() {
        let framebuffer = FramebufferInfo::new(
            0xa0000,
            PAGE_SIZE,
            16,
            16,
            16,
            PixelFormat::RedGreenBlueReserved,
        )
        .unwrap();
        let regions = [
            MemoryRegion::new(PhysAddr::new(0x1000).unwrap(), 4, MemoryKind::Free).unwrap(),
            MemoryRegion::new(PhysAddr::new(0xa0000).unwrap(), 1, MemoryKind::Mmio).unwrap(),
        ];
        let context = EarlyKernelContext::new([1; 32], 0x1234, framebuffer, &regions).unwrap();
        let mut bytes = [0u8; PAGE_SIZE as usize];
        context.render_booted(&mut bytes).unwrap();
        assert_eq!(&bytes[..4], &[0xf2, 0xf2, 0xf2, 0]);
        assert_eq!(&bytes[8 * 16 * 4..8 * 16 * 4 + 4], &[0x16, 0x61, 0x3a, 0]);
    }

    #[test]
    fn decoded_handoff_retains_loader_isolation_and_recovery_identity() {
        let framebuffer = FramebufferInfo::new(
            0xa0000,
            PAGE_SIZE,
            16,
            16,
            16,
            PixelFormat::RedGreenBlueReserved,
        )
        .unwrap();
        let regions = [
            MemoryRegion::new(PhysAddr::new(0x1000).unwrap(), 4, MemoryKind::Free).unwrap(),
            MemoryRegion::new(PhysAddr::new(0xa0000).unwrap(), 1, MemoryKind::Mmio).unwrap(),
        ];
        let recovery = RecoveryStateMetadata::new(8, 1, Some([0x51; 16]), 14).unwrap();
        let installed = InstalledRecoveryBootIdentity::new(
            InstalledRecoverySource::Hosted,
            [0x31; 32],
            2,
            3,
            4096,
            4096,
            [0x51; 16],
            4,
            14,
        )
        .unwrap();
        let mut encoded = [0; 768];
        let length = encode_handoff_with_recovery_isolation_and_installed(
            1,
            [1; 32],
            [2; 64],
            true,
            true,
            true,
            true,
            0x1234,
            framebuffer,
            &regions,
            recovery,
            installed,
            Some(BootIsolationOverride::TotalMicrovmOnce),
            &mut encoded,
        )
        .unwrap();
        let handoff = BootHandoff::decode(&encoded[..length], |_| {}).unwrap();
        let context = EarlyKernelContext::from_handoff(&handoff, &regions).unwrap();
        assert_eq!(
            context.isolation_override(),
            Some(BootIsolationOverride::TotalMicrovmOnce)
        );
        assert_eq!(context.recovery_state(), Some(recovery));
        assert_eq!(context.installed_recovery(), Some(installed));
        assert_eq!(context.installed_recovery_sata_route(), None);
        assert_eq!(context.entropy(), handoff.evidence().entropy());
    }

    #[test]
    fn uefi_installed_identity_requires_adjacent_route_at_first_entry() {
        let framebuffer = FramebufferInfo::new(
            0xa0000,
            PAGE_SIZE,
            16,
            16,
            16,
            PixelFormat::RedGreenBlueReserved,
        )
        .unwrap();
        let regions = [
            MemoryRegion::new(PhysAddr::new(0x1000).unwrap(), 4, MemoryKind::Free).unwrap(),
            MemoryRegion::new(PhysAddr::new(0xa0000).unwrap(), 1, MemoryKind::Mmio).unwrap(),
        ];
        let recovery = RecoveryStateMetadata::new(8, 1, Some([0x51; 16]), 14).unwrap();
        let installed = InstalledRecoveryBootIdentity::new(
            InstalledRecoverySource::Uefi,
            [0x31; 32],
            2,
            3,
            4096,
            4096,
            [0x51; 16],
            4,
            14,
        )
        .unwrap();
        let mut encoded = [0; 768];
        let length = encode_handoff_with_recovery_isolation_and_installed(
            1,
            [1; 32],
            [2; 64],
            true,
            true,
            true,
            true,
            0x1234,
            framebuffer,
            &regions,
            recovery,
            installed,
            Some(BootIsolationOverride::TotalMicrovmOnce),
            &mut encoded,
        )
        .unwrap();
        let handoff = BootHandoff::decode(&encoded[..length], |_| {}).unwrap();
        assert!(matches!(
            EarlyKernelContext::from_handoff(&handoff, &regions),
            Err(EarlyKernelError::MissingInstalledRecoveryRoute)
        ));
    }
}
