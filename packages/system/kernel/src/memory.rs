pub const PAGE_SIZE: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PhysAddr(u64);

impl PhysAddr {
    pub const fn new(address: u64) -> Result<Self, MemoryError> {
        if !address.is_multiple_of(PAGE_SIZE) {
            return Err(MemoryError::Unaligned);
        }
        Ok(Self(address))
    }
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MemoryKind {
    Free,
    Kernel,
    Firmware,
    Mmio,
    Acpi,
    Reserved,
    BootDma,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRegion {
    start: PhysAddr,
    pages: u64,
    kind: MemoryKind,
}

impl MemoryRegion {
    pub const fn new(start: PhysAddr, pages: u64, kind: MemoryKind) -> Result<Self, MemoryError> {
        if pages == 0 || pages > u64::MAX / PAGE_SIZE {
            return Err(MemoryError::InvalidLength);
        }
        if start.0.checked_add(pages * PAGE_SIZE).is_none() {
            return Err(MemoryError::Overflow);
        }
        Ok(Self { start, pages, kind })
    }
    pub const fn end(self) -> u64 {
        self.start.0 + self.pages * PAGE_SIZE
    }
    pub const fn start(self) -> PhysAddr {
        self.start
    }
    pub const fn pages(self) -> u64 {
        self.pages
    }
    pub const fn kind(self) -> MemoryKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryError {
    Empty,
    Unaligned,
    InvalidLength,
    Overflow,
    Unsorted,
    Overlap,
    OutOfMemory,
}

/// Validated normalized firmware memory map. No address may reach page-table
/// or allocator code before construction succeeds.
pub struct MemoryMap<'a> {
    regions: &'a [MemoryRegion],
}

impl<'a> MemoryMap<'a> {
    pub fn new(regions: &'a [MemoryRegion]) -> Result<Self, MemoryError> {
        if regions.is_empty() {
            return Err(MemoryError::Empty);
        }
        for pair in regions.windows(2) {
            if pair[0].start > pair[1].start {
                return Err(MemoryError::Unsorted);
            }
            if pair[0].end() > pair[1].start.get() {
                return Err(MemoryError::Overlap);
            }
        }
        Ok(Self { regions })
    }
    pub fn regions(&self) -> &'a [MemoryRegion] {
        self.regions
    }
}

/// Physically contiguous backing reserved for bounded early-boot DMA. The
/// monotonic allocator never reuses this range, including after the handle
/// is dropped. No CPU mapping, device mapping, zeroing or DMA authority is
/// implied by this handle.
#[must_use]
#[derive(Debug, Eq, PartialEq)]
pub struct BootDmaReservation {
    physical_base: PhysAddr,
    pages: u16,
}

impl BootDmaReservation {
    /// Interprets one dedicated loader-owned region. The tag keeps it out
    /// of free RAM and is metadata, not proof of exclusive ownership or DMA
    /// authority. Only the trusted boot owner may publish or initialize it.
    pub fn from_handoff_region(region: MemoryRegion) -> Result<Self, MemoryError> {
        if region.kind() != MemoryKind::BootDma
            || region.start().get() == 0
            || !(1..=256).contains(&region.pages())
            || region.end() > (1u64 << 52)
        {
            return Err(MemoryError::InvalidLength);
        }
        Ok(Self {
            physical_base: region.start(),
            pages: region.pages() as u16,
        })
    }

    pub const fn physical_base(&self) -> PhysAddr {
        self.physical_base
    }

    pub const fn pages(&self) -> u16 {
        self.pages
    }

    pub const fn bytes(&self) -> u64 {
        self.pages as u64 * PAGE_SIZE
    }
}

/// Initial monotonic allocator. Early boot never frees frames, eliminating
/// reuse ambiguity while page tables and core services are established.
pub struct FrameAllocator<'a> {
    map: MemoryMap<'a>,
    region_index: usize,
    page_index: u64,
}

impl<'a> FrameAllocator<'a> {
    pub const fn new(map: MemoryMap<'a>) -> Self {
        Self {
            map,
            region_index: 0,
            page_index: 0,
        }
    }
    pub fn allocate(&mut self) -> Result<PhysAddr, MemoryError> {
        while let Some(region) = self.map.regions.get(self.region_index).copied() {
            if region.kind != MemoryKind::Free || self.page_index >= region.pages {
                self.region_index += 1;
                self.page_index = 0;
                continue;
            }
            let offset = self
                .page_index
                .checked_mul(PAGE_SIZE)
                .ok_or(MemoryError::Overflow)?;
            let address = region
                .start
                .get()
                .checked_add(offset)
                .ok_or(MemoryError::Overflow)?;
            self.page_index += 1;
            return Ok(PhysAddr(address));
        }
        Err(MemoryError::OutOfMemory)
    }

    /// Reserves from ordinary firmware-classified free RAM. The null page is
    /// never used and the entire range must fit the VT-d physical address
    /// field and the caller-supplied, verified host address width. The
    /// platform remains responsible for zeroing and proving installed mappings.
    pub fn reserve_boot_dma(
        &mut self,
        pages: u16,
        physical_bits: u8,
    ) -> Result<BootDmaReservation, MemoryError> {
        if !(1..=256).contains(&pages) || !(32..=52).contains(&physical_bits) {
            return Err(MemoryError::InvalidLength);
        }
        let physical_base =
            self.allocate_contiguous_in(u64::from(pages), 1, PAGE_SIZE, 1 << physical_bits)?;
        Ok(BootDmaReservation {
            physical_base,
            pages,
        })
    }

    /// Allocates one physically contiguous run without crossing a normalized
    /// firmware region. Skipped alignment padding is intentionally consumed:
    /// early boot never frees or reuses frames, preventing alias ambiguity.
    pub fn allocate_contiguous(
        &mut self,
        pages: u64,
        alignment_pages: u64,
    ) -> Result<PhysAddr, MemoryError> {
        self.allocate_contiguous_in(pages, alignment_pages, 0, u64::MAX)
    }

    pub(crate) fn allocate_contiguous_in(
        &mut self,
        pages: u64,
        alignment_pages: u64,
        minimum: u64,
        limit: u64,
    ) -> Result<PhysAddr, MemoryError> {
        if pages == 0 {
            return Err(MemoryError::InvalidLength);
        }
        if alignment_pages == 0 || !alignment_pages.is_power_of_two() {
            return Err(MemoryError::Unaligned);
        }
        let alignment = alignment_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(MemoryError::Overflow)?;
        let bytes = pages.checked_mul(PAGE_SIZE).ok_or(MemoryError::Overflow)?;
        while let Some(region) = self.map.regions.get(self.region_index).copied() {
            let cursor = region.start.get() + self.page_index * PAGE_SIZE;
            if cursor >= limit {
                return Err(MemoryError::OutOfMemory);
            }
            if region.kind == MemoryKind::Free {
                let aligned = cursor
                    .max(minimum)
                    .checked_add(alignment - 1)
                    .map(|value| value & !(alignment - 1));
                if let Some((start, end)) =
                    aligned.and_then(|start| start.checked_add(bytes).map(|end| (start, end)))
                {
                    if end <= region.end() && end <= limit {
                        self.page_index = (end - region.start.get()) / PAGE_SIZE;
                        return PhysAddr::new(start);
                    }
                }
            }
            self.region_index += 1;
            self.page_index = 0;
        }
        Err(MemoryError::OutOfMemory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn region(start: u64, pages: u64, kind: MemoryKind) -> MemoryRegion {
        MemoryRegion::new(PhysAddr::new(start).unwrap(), pages, kind).unwrap()
    }
    #[test]
    fn rejects_unaligned_overlapping_and_unsorted_firmware_maps() {
        assert_eq!(PhysAddr::new(1), Err(MemoryError::Unaligned));
        let overlap = [
            region(0x1000, 2, MemoryKind::Free),
            region(0x2000, 1, MemoryKind::Reserved),
        ];
        assert!(matches!(
            MemoryMap::new(&overlap),
            Err(MemoryError::Overlap)
        ));
        let unsorted = [
            region(0x3000, 1, MemoryKind::Free),
            region(0x1000, 1, MemoryKind::Free),
        ];
        assert!(matches!(
            MemoryMap::new(&unsorted),
            Err(MemoryError::Unsorted)
        ));
        assert_eq!(
            MemoryRegion::new(PhysAddr::new(0).unwrap(), 0, MemoryKind::Free),
            Err(MemoryError::InvalidLength)
        );
    }
    #[test]
    fn allocator_uses_only_free_pages_and_stops_exactly_at_end() {
        let regions = [
            region(0, 2, MemoryKind::Firmware),
            region(0x2000, 2, MemoryKind::Free),
            region(0x4000, 1, MemoryKind::Mmio),
            region(0x5000, 1, MemoryKind::Free),
        ];
        let mut allocator = FrameAllocator::new(MemoryMap::new(&regions).unwrap());
        assert_eq!(allocator.allocate().unwrap().get(), 0x2000);
        assert_eq!(allocator.allocate().unwrap().get(), 0x3000);
        assert_eq!(allocator.allocate().unwrap().get(), 0x5000);
        assert_eq!(allocator.allocate(), Err(MemoryError::OutOfMemory));
    }

    #[test]
    fn boot_dma_excludes_page_zero_and_cannot_be_reused_after_drop() {
        let regions = [
            region(0, 5, MemoryKind::Free),
            region(0x5000, 4, MemoryKind::Mmio),
            region((1 << 52) - PAGE_SIZE, 4, MemoryKind::Free),
        ];
        let mut allocator = FrameAllocator::new(MemoryMap::new(&regions).unwrap());
        assert_eq!(
            allocator.reserve_boot_dma(257, 52),
            Err(MemoryError::InvalidLength)
        );
        {
            let lease = allocator.reserve_boot_dma(3, 52).unwrap();
            assert_eq!(lease.physical_base().get(), PAGE_SIZE);
            assert_eq!(lease.bytes(), PAGE_SIZE * 3);
        }
        assert_eq!(allocator.allocate().unwrap().get(), 0x4000);
        assert_eq!(
            allocator
                .reserve_boot_dma(1, 52)
                .unwrap()
                .physical_base()
                .get(),
            (1 << 52) - PAGE_SIZE
        );
        assert_eq!(
            allocator.reserve_boot_dma(1, 52),
            Err(MemoryError::OutOfMemory)
        );
    }

    #[test]
    fn boot_dma_respects_host_width_without_consuming_high_ram() {
        let regions = [region((1 << 32) - PAGE_SIZE, 3, MemoryKind::Free)];
        let mut allocator = FrameAllocator::new(MemoryMap::new(&regions).unwrap());
        assert_eq!(
            allocator.reserve_boot_dma(1, 64),
            Err(MemoryError::InvalidLength)
        );
        assert_eq!(
            allocator
                .reserve_boot_dma(1, 32)
                .unwrap()
                .physical_base()
                .get(),
            (1 << 32) - PAGE_SIZE
        );
        assert_eq!(
            allocator.reserve_boot_dma(1, 32),
            Err(MemoryError::OutOfMemory)
        );
        assert_eq!(allocator.allocate().unwrap().get(), 1 << 32);
    }

    #[test]
    fn contiguous_alignment_is_physical_not_region_relative() {
        let regions = [region(0x3000, 8, MemoryKind::Free)];
        let mut allocator = FrameAllocator::new(MemoryMap::new(&regions).unwrap());
        assert_eq!(allocator.allocate_contiguous(1, 4).unwrap().get(), 0x4000);
    }

    #[test]
    fn contiguous_allocator_aligns_and_never_crosses_regions() {
        let regions = [
            region(0, 3, MemoryKind::Free),
            region(0x3000, 1, MemoryKind::Reserved),
            region(0x4000, 8, MemoryKind::Free),
        ];
        let mut allocator = FrameAllocator::new(MemoryMap::new(&regions).unwrap());
        assert_eq!(allocator.allocate().unwrap().get(), 0);
        assert_eq!(allocator.allocate_contiguous(3, 2).unwrap().get(), 0x4000);
        assert_eq!(allocator.allocate_contiguous(2, 4).unwrap().get(), 0x8000);
        assert_eq!(
            allocator.allocate_contiguous(1, 3),
            Err(MemoryError::Unaligned)
        );
        assert_eq!(
            allocator.allocate_contiguous(8, 1),
            Err(MemoryError::OutOfMemory)
        );
    }
}
