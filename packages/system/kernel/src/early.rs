use crate::{
    BootHandoff, BootIsolationOverride, Color, FramebufferError, FramebufferInfo,
    FramebufferSurface, MemoryError, MemoryKind, MemoryMap, MemoryRegion,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EarlyKernelError {
    MissingEntropy,
    MissingAcpi,
    InvalidMemoryMap(MemoryError),
    FramebufferOutsideMmio,
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
        context.isolation_override = handoff.isolation_override();
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
        BootIsolationOverride, PAGE_SIZE, PhysAddr, PixelFormat, RecoveryStateMetadata,
        encode_handoff_with_recovery_and_isolation,
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
    fn decoded_handoff_retains_only_the_loader_isolation_request() {
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
        let mut encoded = [0; 512];
        let length = encode_handoff_with_recovery_and_isolation(
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
        assert_eq!(context.entropy(), handoff.evidence().entropy());
    }
}
