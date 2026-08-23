use core::sync::atomic::{Ordering, compiler_fence};

use crate::{GranuleHardwareOutcome, PhysAddr};

use super::DmaIsolation;

const ECAP_OFFSET: usize = 0x10;
const CCMD_OFFSET: usize = 0x28;
const COMMAND_PENDING: u64 = 1 << 63;
const GLOBAL_GRANULARITY: u64 = 1 << 60;
const CCMD_ACTUAL_SHIFT: u32 = 59;
const IOTLB_ACTUAL_SHIFT: u32 = 57;
const ACTUAL_MASK: u64 = 0b11;
const IOTLB_DRAIN_READS: u64 = 1 << 49;
const IOTLB_DRAIN_WRITES: u64 = 1 << 48;
const IOTLB_OFFSET_DELTA: usize = 8;
const VTD_PERMISSION_MASK: u64 = 0b11;
const VTD_LARGE_PAGE: u64 = 1 << 7;
const VTD_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtdError {
    InvalidRegisterLayout,
    InvalidLeaf,
    Busy,
    InvalidCompletion,
}

/// Narrow register boundary for one VT-d remapping hardware unit.
pub trait VtdRegisterIo {
    fn read64(&mut self, offset: usize) -> u64;
    fn write64(&mut self, offset: usize, value: u64);
}

/// Direct volatile MMIO register access for a mapped VT-d register page.
pub struct NativeVtdMmio {
    base: *mut u8,
    bytes: usize,
}

impl NativeVtdMmio {
    /// # Safety
    ///
    /// `base..base + bytes` must be a uniquely controlled, uncached kernel
    /// mapping of one enabled VT-d remapping unit for this object's lifetime.
    pub unsafe fn new(base: *mut u8, bytes: usize) -> Result<Self, VtdError> {
        if base.is_null() || bytes < 0x30 || !(base as usize).is_multiple_of(8) {
            return Err(VtdError::InvalidRegisterLayout);
        }
        Ok(Self { base, bytes })
    }
}

impl VtdRegisterIo for NativeVtdMmio {
    fn read64(&mut self, offset: usize) -> u64 {
        if offset > self.bytes.saturating_sub(8) || !offset.is_multiple_of(8) {
            return u64::MAX;
        }
        // SAFETY: construction establishes the mapped MMIO range; the bounds
        // and alignment checks above constrain this 64-bit register access.
        unsafe { self.base.add(offset).cast::<u64>().read_volatile() }
    }

    fn write64(&mut self, offset: usize, value: u64) {
        if offset > self.bytes.saturating_sub(8) || !offset.is_multiple_of(8) {
            return;
        }
        // SAFETY: same mapped-range invariant as `read64`.
        unsafe { self.base.add(offset).cast::<u64>().write_volatile(value) };
    }
}

/// Register-based global context-cache and IOTLB invalidation.
pub struct VtdInvalidator<R> {
    registers: R,
    iotlb_offset: usize,
    poll_limit: u32,
}

impl<R: VtdRegisterIo> VtdInvalidator<R> {
    pub fn new(mut registers: R, poll_limit: u32) -> Result<Self, VtdError> {
        let ecap = registers.read64(ECAP_OFFSET);
        let invalidation_base = ((ecap >> 8) & 0x3ff) as usize * 16;
        let iotlb_offset = invalidation_base
            .checked_add(IOTLB_OFFSET_DELTA)
            .ok_or(VtdError::InvalidRegisterLayout)?;
        if poll_limit == 0 || invalidation_base == 0 || !iotlb_offset.is_multiple_of(8) {
            return Err(VtdError::InvalidRegisterLayout);
        }
        Ok(Self {
            registers,
            iotlb_offset,
            poll_limit,
        })
    }

    fn wait_clear(&mut self, offset: usize) -> Result<u64, VtdError> {
        let mut remaining = self.poll_limit;
        while remaining != 0 {
            let value = self.registers.read64(offset);
            if value & COMMAND_PENDING == 0 {
                return Ok(value);
            }
            core::hint::spin_loop();
            remaining -= 1;
        }
        Err(VtdError::Busy)
    }

    pub fn ready(&mut self) -> Result<(), VtdError> {
        self.wait_clear(CCMD_OFFSET)?;
        self.wait_clear(self.iotlb_offset)?;
        Ok(())
    }

    pub fn invalidate_global(&mut self) -> Result<(), VtdError> {
        self.registers
            .write64(CCMD_OFFSET, COMMAND_PENDING | GLOBAL_GRANULARITY);
        let context = self.wait_clear(CCMD_OFFSET)?;
        if (context >> CCMD_ACTUAL_SHIFT) & ACTUAL_MASK == 0 {
            return Err(VtdError::InvalidCompletion);
        }

        self.registers.write64(
            self.iotlb_offset,
            COMMAND_PENDING | GLOBAL_GRANULARITY | IOTLB_DRAIN_READS | IOTLB_DRAIN_WRITES,
        );
        let iotlb = self.wait_clear(self.iotlb_offset)?;
        if (iotlb >> IOTLB_ACTUAL_SHIFT) & ACTUAL_MASK == 0 {
            return Err(VtdError::InvalidCompletion);
        }
        Ok(())
    }

    pub fn into_registers(self) -> R {
        self.registers
    }
}

/// One live second-level VT-d leaf coupled to its invalidation unit.
pub struct VtdDmaIsolation<'a, R> {
    physical: PhysAddr,
    leaf: &'a mut u64,
    invalidator: VtdInvalidator<R>,
}

impl<'a, R: VtdRegisterIo> VtdDmaIsolation<'a, R> {
    /// # Safety
    ///
    /// `leaf` must uniquely reference the live 4 KiB VT-d second-level leaf
    /// mapping `physical`, and `invalidator` must control every remapping unit
    /// through which a device can reach that granule.
    pub unsafe fn new(
        physical: PhysAddr,
        leaf: &'a mut u64,
        invalidator: VtdInvalidator<R>,
    ) -> Result<Self, VtdError> {
        if *leaf & VTD_LARGE_PAGE != 0 || *leaf & VTD_ADDRESS_MASK != physical.get() {
            return Err(VtdError::InvalidLeaf);
        }
        Ok(Self {
            physical,
            leaf,
            invalidator,
        })
    }

    pub fn into_parts(self) -> (&'a mut u64, VtdInvalidator<R>) {
        (self.leaf, self.invalidator)
    }
}

impl<R: VtdRegisterIo> DmaIsolation for VtdDmaIsolation<'_, R> {
    fn deny_and_invalidate(&mut self, physical: PhysAddr) -> GranuleHardwareOutcome {
        if physical != self.physical || self.invalidator.ready().is_err() {
            return GranuleHardwareOutcome::Rejected;
        }
        // SAFETY: construction requires the unique live leaf reference.
        unsafe {
            core::ptr::write_volatile(
                self.leaf,
                core::ptr::read_volatile(self.leaf) & !VTD_PERMISSION_MASK,
            )
        };
        compiler_fence(Ordering::SeqCst);
        if self.invalidator.invalidate_global().is_err() {
            GranuleHardwareOutcome::FailStop
        } else {
            GranuleHardwareOutcome::Applied
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Registers {
        values: [u64; 130],
        fail_iotlb: bool,
    }

    impl Registers {
        fn new(fail_iotlb: bool) -> Self {
            let mut values = [0; 130];
            values[ECAP_OFFSET / 8] = 0x20 << 8;
            Self { values, fail_iotlb }
        }
    }

    impl VtdRegisterIo for Registers {
        fn read64(&mut self, offset: usize) -> u64 {
            let value = self.values[offset / 8];
            if value & COMMAND_PENDING == 0 {
                return value;
            }
            if self.fail_iotlb && offset == 0x208 {
                return value;
            }
            let completed = if offset == CCMD_OFFSET {
                (value & !COMMAND_PENDING) | (1 << CCMD_ACTUAL_SHIFT)
            } else {
                (value & !COMMAND_PENDING) | (1 << IOTLB_ACTUAL_SHIFT)
            };
            self.values[offset / 8] = completed;
            completed
        }

        fn write64(&mut self, offset: usize, value: u64) {
            self.values[offset / 8] = value;
        }
    }

    #[test]
    fn deny_clears_dma_permissions_and_completes_both_invalidations() {
        let physical = PhysAddr::new(0x70_0000).unwrap();
        let mut leaf = physical.get() | VTD_PERMISSION_MASK;
        let invalidator = VtdInvalidator::new(Registers::new(false), 4).unwrap();
        let mut dma = unsafe { VtdDmaIsolation::new(physical, &mut leaf, invalidator).unwrap() };
        assert_eq!(
            dma.deny_and_invalidate(physical),
            GranuleHardwareOutcome::Applied
        );
        let (leaf, _) = dma.into_parts();
        assert_eq!(*leaf & VTD_PERMISSION_MASK, 0);
    }

    #[test]
    fn iotlb_timeout_after_leaf_write_is_fail_stop() {
        let physical = PhysAddr::new(0x80_0000).unwrap();
        let mut leaf = physical.get() | VTD_PERMISSION_MASK;
        let invalidator = VtdInvalidator::new(Registers::new(true), 2).unwrap();
        let mut dma = unsafe { VtdDmaIsolation::new(physical, &mut leaf, invalidator).unwrap() };
        assert_eq!(
            dma.deny_and_invalidate(physical),
            GranuleHardwareOutcome::FailStop
        );
    }
}
