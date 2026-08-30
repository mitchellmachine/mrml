//! x86-64 visibility transitions for platform-proven coherent AHCI data DMA.

use crate::{AhciDataBufferSync, AhciDataDmaRegion};
use core::sync::atomic::{compiler_fence, Ordering};

/// Exact-region adapter for a platform-proven cache-coherent x86-64 DMA map.
///
/// This adapter supplies compiler ordering only. It does not flush cache lines,
/// install an IOMMU mapping, authorize a device, or prove platform coherence.
pub struct AhciX86CoherentDataSync {
    region: AhciDataDmaRegion,
}

impl AhciX86CoherentDataSync {
    /// Admits one exact data region whose platform mapping is already coherent.
    ///
    /// # Safety
    ///
    /// The caller must prove that the exact physical extent is pinned, mapped
    /// to only the authorized AHCI requester, and hardware cache coherent for
    /// the complete adapter lifetime. Device reset and IOMMU revocation remain
    /// separate obligations. A generic x86-64 target is not sufficient proof.
    pub unsafe fn new(region: AhciDataDmaRegion) -> Option<Self> {
        if region.memory_object.0 == 0
            || region.allocation_generation == 0
            || region.physical_base == 0
            || region.bytes == 0
            || region.bytes > 1024 * 1024
            || region.physical_base.checked_add(region.bytes).is_none()
        {
            return None;
        }
        Some(Self { region })
    }

    fn exact(&self, requested: AhciDataDmaRegion) -> Result<(), ()> {
        if requested.memory_object != self.region.memory_object
            || requested.allocation_generation != self.region.allocation_generation
            || requested.physical_base != self.region.physical_base
            || requested.bytes == 0
            || requested.bytes > self.region.bytes
        {
            return Err(());
        }
        Ok(())
    }

    fn publish_to_device(&self, region: AhciDataDmaRegion) -> Result<(), ()> {
        self.exact(region)?;
        compiler_fence(Ordering::Release);
        Ok(())
    }

    fn observe_from_device(&self, region: AhciDataDmaRegion) -> Result<(), ()> {
        self.exact(region)?;
        compiler_fence(Ordering::Acquire);
        Ok(())
    }
}

impl AhciDataBufferSync for AhciX86CoherentDataSync {
    fn prepare_device_write(&mut self, region: AhciDataDmaRegion) -> Result<(), ()> {
        self.publish_to_device(region)
    }

    fn prepare_device_read(&mut self, region: AhciDataDmaRegion) -> Result<(), ()> {
        self.publish_to_device(region)
    }

    fn complete_device_write(&mut self, region: AhciDataDmaRegion) -> Result<(), ()> {
        self.observe_from_device(region)
    }

    fn complete_device_read(&mut self, region: AhciDataDmaRegion) -> Result<(), ()> {
        self.observe_from_device(region)
    }

    fn publish_sanitized(&mut self, region: AhciDataDmaRegion) -> Result<(), ()> {
        self.publish_to_device(region)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_kernel::ObjectId;

    fn region(bytes: u64) -> AhciDataDmaRegion {
        AhciDataDmaRegion {
            memory_object: ObjectId(9),
            allocation_generation: 7,
            physical_base: 0x4000,
            bytes,
        }
    }

    #[test]
    fn coherent_adapter_accepts_only_exact_identity_and_bounded_prefixes() {
        let full = region(4096);
        let mut sync = unsafe { AhciX86CoherentDataSync::new(full) }.unwrap();
        let prefix = region(512);
        assert_eq!(sync.prepare_device_read(prefix), Ok(()));
        assert_eq!(sync.complete_device_read(prefix), Ok(()));
        assert_eq!(sync.prepare_device_write(prefix), Ok(()));
        assert_eq!(sync.complete_device_write(prefix), Ok(()));
        assert_eq!(sync.publish_sanitized(prefix), Ok(()));

        for substituted in [
            AhciDataDmaRegion { memory_object: ObjectId(10), ..prefix },
            AhciDataDmaRegion { allocation_generation: 8, ..prefix },
            AhciDataDmaRegion { physical_base: 0x5000, ..prefix },
            AhciDataDmaRegion { bytes: 0, ..prefix },
            AhciDataDmaRegion { bytes: 4097, ..prefix },
        ] {
            assert_eq!(sync.prepare_device_read(substituted), Err(()));
        }
    }

    #[test]
    fn malformed_coherent_region_cannot_be_admitted() {
        for malformed in [
            AhciDataDmaRegion { memory_object: ObjectId(0), ..region(512) },
            AhciDataDmaRegion { allocation_generation: 0, ..region(512) },
            AhciDataDmaRegion { physical_base: 0, ..region(512) },
            region(0),
            region(1024 * 1024 + 1),
            AhciDataDmaRegion { physical_base: u64::MAX - 255, ..region(512) },
        ] {
            assert!(unsafe { AhciX86CoherentDataSync::new(malformed) }.is_none());
        }
    }
}
