//! Native x86 PCI configuration mechanism-one adapter for one AHCI BAR probe.

use crate::{
    AhciDiscoveryError, AhciPciBarProbeIo, AhciPciFunctionSnapshot, ExclusiveAhciPciFunction,
    PciFunctionLocation,
};
use core::arch::asm;

const ADDRESS_PORT: u16 = 0x0cf8;
const DATA_PORT: u16 = 0x0cfc;
const COMMAND_OFFSET: u8 = 0x04;
const IDENTITY_OFFSET: u8 = 0x00;
const CLASS_OFFSET: u8 = 0x08;
const HEADER_OFFSET: u8 = 0x0c;
const ABAR_OFFSET: u8 = 0x24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAhciPciBarProbeError {
    UnsupportedSegment,
    WrongFunction,
}

/// Exclusive mechanism-one adapter for one segment-zero PCI function. Only
/// command-register and BAR5 accesses are exposed.
pub struct NativeAhciPciBarProbe {
    location: PciFunctionLocation,
}

impl NativeAhciPciBarProbe {
    /// # Safety
    ///
    /// The caller must own and quiesce this exact function, disable local
    /// interrupts, exclude configuration access by every other CPU, and ensure
    /// conventional x86 ports `0xCF8/0xCFC` address PCI segment zero.
    pub const unsafe fn new(
        location: PciFunctionLocation,
    ) -> Result<Self, NativeAhciPciBarProbeError> {
        if location.segment != 0 {
            return Err(NativeAhciPciBarProbeError::UnsupportedSegment);
        }
        Ok(Self { location })
    }

    pub const fn location(&self) -> PciFunctionLocation {
        self.location
    }

    /// Reads the authority-free identity tuple for the retained function and
    /// consumes this backend directly into the exclusive BAR transaction
    /// owner. The snapshot is never accepted as a substitute for this owner.
    pub fn into_exclusive(
        mut self,
        configuration_generation: u64,
    ) -> Result<ExclusiveAhciPciFunction<Self>, NativeAhciPciAdmissionFailure> {
        let identity = unsafe { self.read_dword(IDENTITY_OFFSET) };
        let class = unsafe { self.read_dword(CLASS_OFFSET) };
        let header = unsafe { self.read_dword(HEADER_OFFSET) };
        let abar = unsafe { self.read_dword(ABAR_OFFSET) };
        let snapshot = snapshot_from_registers(
            self.location,
            configuration_generation,
            identity,
            class,
            header,
            abar,
        );
        // SAFETY: `self` retains the exact exclusive/quiescent function and
        // mechanism-one exclusion established by `new`; the snapshot was read
        // synchronously from that same retained requester.
        unsafe { ExclusiveAhciPciFunction::admit(snapshot, self) }
            .map_err(|(error, backend)| NativeAhciPciAdmissionFailure { error, backend })
    }

    fn selector(
        &self,
        location: PciFunctionLocation,
        offset: u8,
    ) -> Result<u32, NativeAhciPciBarProbeError> {
        if location != self.location {
            return Err(NativeAhciPciBarProbeError::WrongFunction);
        }
        Ok(configuration_selector(location, offset))
    }

    unsafe fn read_dword(&mut self, offset: u8) -> u32 {
        let selector = configuration_selector(self.location, offset);
        unsafe { select(selector) };
        let value: u32;
        unsafe {
            asm!(
                "in eax, dx",
                in("dx") DATA_PORT,
                lateout("eax") value,
                options(nostack, preserves_flags)
            )
        };
        value
    }
}

pub struct NativeAhciPciAdmissionFailure {
    error: AhciDiscoveryError,
    backend: NativeAhciPciBarProbe,
}

impl NativeAhciPciAdmissionFailure {
    pub const fn error(&self) -> AhciDiscoveryError {
        self.error
    }

    pub fn into_backend(self) -> NativeAhciPciBarProbe {
        self.backend
    }
}

const fn snapshot_from_registers(
    location: PciFunctionLocation,
    configuration_generation: u64,
    identity: u32,
    class: u32,
    header: u32,
    abar: u32,
) -> AhciPciFunctionSnapshot {
    AhciPciFunctionSnapshot {
        location,
        configuration_generation,
        vendor_id: identity as u16,
        device_id: (identity >> 16) as u16,
        header_type: (header >> 16) as u8,
        class: (class >> 24) as u8,
        subclass: (class >> 16) as u8,
        programming_interface: (class >> 8) as u8,
        abar,
        abar_bytes: 0,
    }
}

const fn configuration_selector(location: PciFunctionLocation, offset: u8) -> u32 {
    1 << 31
        | (location.bus as u32) << 16
        | (location.device as u32) << 11
        | (location.function as u32) << 8
        | ((offset as u32) & 0xfc)
}

unsafe fn select(selector: u32) {
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") ADDRESS_PORT,
            in("eax") selector,
            options(nostack, preserves_flags)
        )
    }
}

// SAFETY: construction requires exclusive mechanism-one ownership, and every
// method exact-matches the retained function before touching either port.
unsafe impl AhciPciBarProbeIo for NativeAhciPciBarProbe {
    type Error = NativeAhciPciBarProbeError;

    fn read_command(&mut self, location: PciFunctionLocation) -> Result<u16, Self::Error> {
        let selector = self.selector(location, COMMAND_OFFSET)?;
        unsafe { select(selector) };
        let value: u16;
        unsafe {
            asm!(
                "in ax, dx",
                in("dx") DATA_PORT,
                lateout("ax") value,
                options(nostack, preserves_flags)
            )
        };
        Ok(value)
    }

    fn write_command(
        &mut self,
        location: PciFunctionLocation,
        value: u16,
    ) -> Result<(), Self::Error> {
        let selector = self.selector(location, COMMAND_OFFSET)?;
        unsafe { select(selector) };
        unsafe {
            asm!(
                "out dx, ax",
                in("dx") DATA_PORT,
                in("ax") value,
                options(nostack, preserves_flags)
            )
        };
        Ok(())
    }

    fn read_abar(&mut self, location: PciFunctionLocation) -> Result<u32, Self::Error> {
        let selector = self.selector(location, ABAR_OFFSET)?;
        unsafe { select(selector) };
        let value: u32;
        unsafe {
            asm!(
                "in eax, dx",
                in("dx") DATA_PORT,
                lateout("eax") value,
                options(nostack, preserves_flags)
            )
        };
        Ok(value)
    }

    fn write_abar(&mut self, location: PciFunctionLocation, value: u32) -> Result<(), Self::Error> {
        let selector = self.selector(location, ABAR_OFFSET)?;
        unsafe { select(selector) };
        unsafe {
            asm!(
                "out dx, eax",
                in("dx") DATA_PORT,
                in("eax") value,
                options(nostack, preserves_flags)
            )
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_encodes_exact_segment_zero_function() {
        let location = PciFunctionLocation::new(0, 0x7a, 31, 7).unwrap();
        assert_eq!(
            configuration_selector(location, COMMAND_OFFSET),
            0x807a_ff04
        );
        assert_eq!(configuration_selector(location, ABAR_OFFSET), 0x807a_ff24);
    }

    #[test]
    fn snapshot_decodes_exact_type_zero_identity_fields() {
        let location = PciFunctionLocation::new(0, 0, 31, 2).unwrap();
        let snapshot = snapshot_from_registers(
            location,
            9,
            0x7a62_8086,
            0x0106_0102,
            0x0080_0000,
            0xf7f0_0000,
        );
        assert_eq!(snapshot.location, location);
        assert_eq!(snapshot.configuration_generation, 9);
        assert_eq!(snapshot.vendor_id, 0x8086);
        assert_eq!(snapshot.device_id, 0x7a62);
        assert_eq!(snapshot.header_type, 0x80);
        assert_eq!(snapshot.class, 0x01);
        assert_eq!(snapshot.subclass, 0x06);
        assert_eq!(snapshot.programming_interface, 0x01);
        assert_eq!(snapshot.abar, 0xf7f0_0000);
        assert_eq!(snapshot.abar_bytes, 0);
    }

    #[test]
    fn segment_and_function_substitution_fail_before_io() {
        let unsupported = PciFunctionLocation::new(1, 0, 1, 0).unwrap();
        assert!(matches!(
            unsafe { NativeAhciPciBarProbe::new(unsupported) },
            Err(NativeAhciPciBarProbeError::UnsupportedSegment)
        ));
        let expected = PciFunctionLocation::new(0, 0, 1, 0).unwrap();
        // SAFETY: only the pure selector gate is called; wrong identity is
        // rejected before any port instruction can execute.
        let backend = unsafe { NativeAhciPciBarProbe::new(expected) }.unwrap();
        let wrong = PciFunctionLocation::new(0, 0, 2, 0).unwrap();
        assert_eq!(
            backend.selector(wrong, ABAR_OFFSET),
            Err(NativeAhciPciBarProbeError::WrongFunction)
        );
    }
}
