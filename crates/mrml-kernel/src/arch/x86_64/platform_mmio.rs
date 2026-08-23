use crate::{MemoryKind, MemoryRegion, PAGE_SIZE, PhysAddr};

use super::{ActivePageTables, DmarTopology, Mapping, McfgTopology, PagePermissions, VirtAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformMmioError {
    ManifestFull,
    InvalidRange,
    Overlap,
    OutsideFirmwareMmio,
    MappingMismatch,
    PageTable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformMmioPurpose {
    VtdBootstrap {
        segment: u16,
    },
    PciEcam {
        segment: u16,
        start_bus: u8,
        end_bus: u8,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformMmioRequirement {
    physical: PhysAddr,
    pages: u64,
    purpose: PlatformMmioPurpose,
}

impl PlatformMmioRequirement {
    pub const fn physical(self) -> PhysAddr {
        self.physical
    }

    pub const fn pages(self) -> u64 {
        self.pages
    }

    pub const fn bytes(self) -> u64 {
        self.pages * PAGE_SIZE
    }

    pub const fn purpose(self) -> PlatformMmioPurpose {
        self.purpose
    }

    fn end(self) -> u64 {
        self.physical.get() + self.bytes()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PlatformMmioManifest<const RANGES: usize> {
    requirements: [Option<PlatformMmioRequirement>; RANGES],
    count: usize,
}

impl<const RANGES: usize> PlatformMmioManifest<RANGES> {
    pub fn from_topology<const UNITS: usize, const SCOPES: usize, const ALLOCATIONS: usize>(
        dmar: &DmarTopology<UNITS, SCOPES>,
        mcfg: &McfgTopology<ALLOCATIONS>,
        memory: &[MemoryRegion],
    ) -> Result<Self, PlatformMmioError> {
        let mut manifest = Self {
            requirements: [None; RANGES],
            count: 0,
        };
        for unit in dmar.units() {
            manifest.push(PlatformMmioRequirement {
                physical: unit.register_base,
                pages: 1,
                purpose: PlatformMmioPurpose::VtdBootstrap {
                    segment: unit.segment,
                },
            })?;
        }
        for allocation in mcfg.allocations() {
            let physical = PhysAddr::new(allocation.physical_start())
                .map_err(|_| PlatformMmioError::InvalidRange)?;
            let pages = u64::try_from(allocation.bytes())
                .map_err(|_| PlatformMmioError::InvalidRange)?
                / PAGE_SIZE;
            manifest.push(PlatformMmioRequirement {
                physical,
                pages,
                purpose: PlatformMmioPurpose::PciEcam {
                    segment: allocation.segment,
                    start_bus: allocation.start_bus,
                    end_bus: allocation.end_bus,
                },
            })?;
        }
        for requirement in manifest.iter() {
            if !memory.iter().any(|region| {
                region.kind() == MemoryKind::Mmio
                    && region.start().get() <= requirement.physical.get()
                    && region.end() >= requirement.end()
            }) {
                return Err(PlatformMmioError::OutsideFirmwareMmio);
            }
        }
        Ok(manifest)
    }

    pub fn iter(&self) -> impl Iterator<Item = PlatformMmioRequirement> + '_ {
        self.requirements[..self.count].iter().flatten().copied()
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn push(&mut self, requirement: PlatformMmioRequirement) -> Result<(), PlatformMmioError> {
        if requirement.pages == 0
            || requirement
                .physical
                .get()
                .checked_add(requirement.bytes())
                .is_none()
        {
            return Err(PlatformMmioError::InvalidRange);
        }
        if self.iter().any(|existing| {
            requirement.physical.get() < existing.end()
                && existing.physical.get() < requirement.end()
        }) {
            return Err(PlatformMmioError::Overlap);
        }
        if self.count == RANGES {
            return Err(PlatformMmioError::ManifestFull);
        }
        self.requirements[self.count] = Some(requirement);
        self.count += 1;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedPlatformMmio {
    requirement: PlatformMmioRequirement,
    virtual_start: VirtAddr,
}

impl VerifiedPlatformMmio {
    pub const fn requirement(self) -> PlatformMmioRequirement {
        self.requirement
    }

    pub const fn virtual_start(self) -> VirtAddr {
        self.virtual_start
    }

    pub const fn as_mut_ptr(self) -> *mut u8 {
        self.virtual_start.get() as *mut u8
    }
}

/// Verifies an already installed active mapping page by page before issuing a
/// token usable by native MMIO adapters.
pub fn verify_active_platform_mmio(
    active: &ActivePageTables,
    requirement: PlatformMmioRequirement,
    mapping: Mapping,
) -> Result<VerifiedPlatformMmio, PlatformMmioError> {
    if mapping.physical_start() != requirement.physical
        || mapping.pages() != requirement.pages
        || mapping.permissions() != PagePermissions::KERNEL_MMIO_READ_WRITE
    {
        return Err(PlatformMmioError::MappingMismatch);
    }
    for page in 0..requirement.pages {
        let offset = page
            .checked_mul(PAGE_SIZE)
            .ok_or(PlatformMmioError::InvalidRange)?;
        let virtual_address = VirtAddr::new(
            mapping
                .virtual_start()
                .get()
                .checked_add(offset)
                .ok_or(PlatformMmioError::InvalidRange)?,
        )
        .map_err(|_| PlatformMmioError::InvalidRange)?;
        let leaf = active
            .leaf(virtual_address)
            .map_err(|_| PlatformMmioError::PageTable)?
            .ok_or(PlatformMmioError::MappingMismatch)?;
        let expected = requirement
            .physical
            .get()
            .checked_add(offset)
            .ok_or(PlatformMmioError::InvalidRange)?;
        if leaf.physical().get() != expected || !leaf.writable() || leaf.executable() || leaf.user()
        {
            return Err(PlatformMmioError::MappingMismatch);
        }
    }
    Ok(VerifiedPlatformMmio {
        requirement,
        virtual_start: mapping.virtual_start(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finalize(table: &mut [u8]) {
        table[9] = 0;
        let sum = table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        table[9] = 0u8.wrapping_sub(sum);
    }

    fn dmar(register: u64) -> [u8; 64] {
        let mut table = [0u8; 64];
        table[..4].copy_from_slice(b"DMAR");
        table[4..8].copy_from_slice(&64u32.to_le_bytes());
        table[36] = 47;
        table[48..50].copy_from_slice(&0u16.to_le_bytes());
        table[50..52].copy_from_slice(&16u16.to_le_bytes());
        table[52] = 1;
        table[56..64].copy_from_slice(&register.to_le_bytes());
        finalize(&mut table);
        table
    }

    fn mcfg(base: u64) -> [u8; 60] {
        let mut table = [0u8; 60];
        table[..4].copy_from_slice(b"MCFG");
        table[4..8].copy_from_slice(&60u32.to_le_bytes());
        table[44..52].copy_from_slice(&base.to_le_bytes());
        finalize(&mut table);
        table
    }

    #[test]
    fn manifest_requires_firmware_mmio_coverage() {
        let dmar = DmarTopology::<1, 0>::parse(&dmar(0xfed9_0000)).unwrap();
        let mcfg = McfgTopology::<1>::parse(&mcfg(0xe000_0000)).unwrap();
        let memory = [
            MemoryRegion::new(PhysAddr::new(0xe000_0000).unwrap(), 256, MemoryKind::Mmio).unwrap(),
            MemoryRegion::new(PhysAddr::new(0xfed9_0000).unwrap(), 1, MemoryKind::Mmio).unwrap(),
        ];
        let manifest = PlatformMmioManifest::<2>::from_topology(&dmar, &mcfg, &memory).unwrap();
        assert_eq!(manifest.len(), 2);
        assert!(matches!(
            manifest.iter().next().unwrap().purpose(),
            PlatformMmioPurpose::VtdBootstrap { segment: 0 }
        ));

        let wrong_kind = [MemoryRegion::new(
            PhysAddr::new(0xe000_0000).unwrap(),
            256,
            MemoryKind::Reserved,
        )
        .unwrap()];
        assert_eq!(
            PlatformMmioManifest::<2>::from_topology(&dmar, &mcfg, &wrong_kind),
            Err(PlatformMmioError::OutsideFirmwareMmio)
        );
    }

    #[test]
    fn manifest_rejects_cross_purpose_physical_overlap() {
        let dmar = DmarTopology::<1, 0>::parse(&dmar(0xe000_0000)).unwrap();
        let mcfg = McfgTopology::<1>::parse(&mcfg(0xe000_0000)).unwrap();
        let memory =
            [
                MemoryRegion::new(PhysAddr::new(0xe000_0000).unwrap(), 256, MemoryKind::Mmio)
                    .unwrap(),
            ];
        assert_eq!(
            PlatformMmioManifest::<2>::from_topology(&dmar, &mcfg, &memory),
            Err(PlatformMmioError::Overlap)
        );
    }
}
