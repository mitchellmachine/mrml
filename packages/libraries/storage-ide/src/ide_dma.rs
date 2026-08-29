//! Capability-bound classic bus-master IDE PRD and DMA ownership.

use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

pub const IDE_PRD_TABLE_BYTES: u64 = 4096;
pub const IDE_PRD_ENTRY_LIMIT: u16 = 32;
const IDE_DMA_MAX_BYTES: u64 = 1024 * 1024;
const PRD_BOUNDARY_BYTES: u64 = 65536;
const PRD_END_OF_TABLE: u32 = 1 << 31;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdeDmaDirection {
    DeviceReads,
    DeviceWrites,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdeDmaRegion {
    pub memory_object: ObjectId,
    pub allocation_generation: u64,
    pub physical_base: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdeDmaRequest {
    pub data_capability: Capability,
    pub prd_table_capability: Capability,
    pub data: IdeDmaRegion,
    pub prd_table: IdeDmaRegion,
    pub transfer_bytes: u64,
    pub direction: IdeDmaDirection,
    pub dma_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdeDmaLayout {
    pub data: IdeDmaRegion,
    pub prd_table: IdeDmaRegion,
    pub transfer_bytes: u64,
    pub direction: IdeDmaDirection,
    pub prd_entries: u16,
    pub dma_generation: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct PreparedIdeDma {
    layout: IdeDmaLayout,
}
impl PreparedIdeDma {
    pub const fn layout(&self) -> IdeDmaLayout {
        self.layout
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdeDmaError {
    DataCapability(CapabilityError),
    PrdCapability(CapabilityError),
    WrongObject,
    InvalidGeneration,
    InvalidData,
    InvalidPrdTable,
    OverlappingRegions,
    TooManyPrds,
    BackendRejected,
    MemoryRead,
    MemoryWrite,
    VerificationFailed,
}

#[derive(Debug, Eq, PartialEq)]
pub enum IdeDmaFailure {
    Untouched {
        request: IdeDmaRequest,
        error: IdeDmaError,
    },
    Quarantined {
        layout: IdeDmaLayout,
        error: IdeDmaError,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub struct IdeDmaRevocationError {
    pub owner: PreparedIdeDma,
}

pub trait IdeDmaBackend {
    /// Atomically pins/maps both regions and zero-verifies device-write data.
    fn install_zeroed(&mut self, layout: IdeDmaLayout) -> Result<(), ()>;
    /// Completes device stop and IOMMU invalidation before memory release.
    fn remove(&mut self, layout: IdeDmaLayout) -> Result<(), ()>;
}

pub trait IdeDmaMemoryIo {
    fn read_u32(&mut self, region: IdeDmaRegion, offset: u64) -> Result<u32, ()>;
    fn write_u32(&mut self, region: IdeDmaRegion, offset: u64, value: u32) -> Result<(), ()>;
}

pub fn prepare_ide_dma<const N: usize, B: IdeDmaBackend, I: IdeDmaMemoryIo>(
    capabilities: &CapabilitySpace<N>,
    request: IdeDmaRequest,
    backend: &mut B,
    memory: &mut I,
) -> Result<PreparedIdeDma, IdeDmaFailure> {
    validate(capabilities, request).map_err(|error| IdeDmaFailure::Untouched { request, error })?;
    let entries = prd_count(request.data.physical_base, request.transfer_bytes).ok_or(
        IdeDmaFailure::Untouched {
            request,
            error: IdeDmaError::TooManyPrds,
        },
    )?;
    let layout = IdeDmaLayout {
        data: request.data,
        prd_table: request.prd_table,
        transfer_bytes: request.transfer_bytes,
        direction: request.direction,
        prd_entries: entries,
        dma_generation: request.dma_generation,
    };
    backend
        .install_zeroed(layout)
        .map_err(|_| IdeDmaFailure::Untouched {
            request,
            error: IdeDmaError::BackendRejected,
        })?;
    for offset in (0..IDE_PRD_TABLE_BYTES).step_by(4) {
        if memory.read_u32(layout.prd_table, offset) != Ok(0) {
            return Err(quarantine(layout, IdeDmaError::VerificationFailed));
        }
    }
    let mut address = layout.data.physical_base;
    let mut remaining = layout.transfer_bytes;
    for index in 0..u64::from(entries) {
        let boundary = PRD_BOUNDARY_BYTES - (address & (PRD_BOUNDARY_BYTES - 1));
        let bytes = remaining.min(boundary);
        let count = if bytes == PRD_BOUNDARY_BYTES {
            0
        } else {
            bytes as u32
        };
        let flags = count
            | if index + 1 == u64::from(entries) {
                PRD_END_OF_TABLE
            } else {
                0
            };
        let offset = index * 8;
        if memory
            .write_u32(layout.prd_table, offset, address as u32)
            .is_err()
            || memory
                .write_u32(layout.prd_table, offset + 4, flags)
                .is_err()
        {
            return Err(quarantine(layout, IdeDmaError::MemoryWrite));
        }
        address += bytes;
        remaining -= bytes;
    }
    address = layout.data.physical_base;
    remaining = layout.transfer_bytes;
    for index in 0..u64::from(entries) {
        let boundary = PRD_BOUNDARY_BYTES - (address & (PRD_BOUNDARY_BYTES - 1));
        let bytes = remaining.min(boundary);
        let count = if bytes == PRD_BOUNDARY_BYTES {
            0
        } else {
            bytes as u32
        };
        let flags = count
            | if index + 1 == u64::from(entries) {
                PRD_END_OF_TABLE
            } else {
                0
            };
        let offset = index * 8;
        if memory.read_u32(layout.prd_table, offset) != Ok(address as u32)
            || memory.read_u32(layout.prd_table, offset + 4) != Ok(flags)
        {
            return Err(quarantine(layout, IdeDmaError::VerificationFailed));
        }
        address += bytes;
        remaining -= bytes;
    }
    Ok(PreparedIdeDma { layout })
}

pub fn revoke_ide_dma<B: IdeDmaBackend>(
    owner: PreparedIdeDma,
    backend: &mut B,
) -> Result<(), IdeDmaRevocationError> {
    if backend.remove(owner.layout).is_err() {
        return Err(IdeDmaRevocationError { owner });
    }
    Ok(())
}

fn validate<const N: usize>(
    capabilities: &CapabilitySpace<N>,
    request: IdeDmaRequest,
) -> Result<(), IdeDmaError> {
    if request.dma_generation == 0 {
        return Err(IdeDmaError::InvalidGeneration);
    }
    let data_rights = match request.direction {
        IdeDmaDirection::DeviceReads => Rights::PIN.union(Rights::MAP).union(Rights::READ),
        IdeDmaDirection::DeviceWrites => Rights::PIN
            .union(Rights::MAP)
            .union(Rights::READ)
            .union(Rights::WRITE),
    };
    let data = capabilities
        .authorize_exact(request.data_capability, data_rights)
        .map_err(IdeDmaError::DataCapability)?;
    let prd_rights = Rights::PIN
        .union(Rights::MAP)
        .union(Rights::READ)
        .union(Rights::WRITE);
    let prd = capabilities
        .authorize_exact(request.prd_table_capability, prd_rights)
        .map_err(IdeDmaError::PrdCapability)?;
    if data != request.data.memory_object || prd != request.prd_table.memory_object {
        return Err(IdeDmaError::WrongObject);
    }
    if request.data.allocation_generation == 0
        || request.data.physical_base == 0
        || request.data.physical_base & 1 != 0
        || request.transfer_bytes == 0
        || request.transfer_bytes > IDE_DMA_MAX_BYTES
        || request.data.bytes != request.transfer_bytes
        || request
            .data
            .physical_base
            .checked_add(request.data.bytes)
            .is_none_or(|end| end > 0x1_0000_0000)
    {
        return Err(IdeDmaError::InvalidData);
    }
    if request.prd_table.allocation_generation == 0
        || request.prd_table.physical_base == 0
        || request.prd_table.physical_base & 0xfff != 0
        || request.prd_table.bytes != IDE_PRD_TABLE_BYTES
        || request
            .prd_table
            .physical_base
            .checked_add(IDE_PRD_TABLE_BYTES)
            .is_none_or(|end| end > 0x1_0000_0000)
    {
        return Err(IdeDmaError::InvalidPrdTable);
    }
    if overlaps(request.data, request.prd_table)
        || request.data.memory_object == request.prd_table.memory_object
    {
        return Err(IdeDmaError::OverlappingRegions);
    }
    Ok(())
}

fn prd_count(mut address: u64, mut remaining: u64) -> Option<u16> {
    let mut count = 0_u16;
    while remaining != 0 {
        let boundary = PRD_BOUNDARY_BYTES - (address & (PRD_BOUNDARY_BYTES - 1));
        let bytes = remaining.min(boundary);
        address += bytes;
        remaining -= bytes;
        count = count.checked_add(1)?;
        if count > IDE_PRD_ENTRY_LIMIT {
            return None;
        }
    }
    Some(count)
}
const fn overlaps(left: IdeDmaRegion, right: IdeDmaRegion) -> bool {
    left.physical_base < right.physical_base + right.bytes
        && right.physical_base < left.physical_base + left.bytes
}
const fn quarantine(layout: IdeDmaLayout, error: IdeDmaError) -> IdeDmaFailure {
    IdeDmaFailure::Quarantined { layout, error }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Backend {
        installed: Option<IdeDmaLayout>,
        reject_install: bool,
        reject_remove: bool,
    }
    impl IdeDmaBackend for Backend {
        fn install_zeroed(&mut self, layout: IdeDmaLayout) -> Result<(), ()> {
            if self.reject_install {
                Err(())
            } else {
                self.installed = Some(layout);
                Ok(())
            }
        }
        fn remove(&mut self, layout: IdeDmaLayout) -> Result<(), ()> {
            if self.reject_remove || self.installed != Some(layout) {
                Err(())
            } else {
                self.installed = None;
                Ok(())
            }
        }
    }
    struct Memory {
        words: [u32; 1024],
        writes: usize,
        fail_write: Option<usize>,
        corrupt_read: bool,
    }
    impl Default for Memory {
        fn default() -> Self {
            Self {
                words: [0; 1024],
                writes: 0,
                fail_write: None,
                corrupt_read: false,
            }
        }
    }
    impl IdeDmaMemoryIo for Memory {
        fn read_u32(&mut self, _: IdeDmaRegion, offset: u64) -> Result<u32, ()> {
            let value = *self.words.get(offset as usize / 4).ok_or(())?;
            Ok(if self.corrupt_read && value != 0 {
                value ^ 1
            } else {
                value
            })
        }
        fn write_u32(&mut self, _: IdeDmaRegion, offset: u64, value: u32) -> Result<(), ()> {
            if self.fail_write == Some(self.writes) {
                return Err(());
            }
            self.writes += 1;
            *self.words.get_mut(offset as usize / 4).ok_or(())? = value;
            Ok(())
        }
    }
    fn fixture(
        direction: IdeDmaDirection,
        base: u64,
        bytes: u64,
    ) -> (CapabilitySpace<2>, IdeDmaRequest) {
        let mut caps = CapabilitySpace::new();
        let data_rights = match direction {
            IdeDmaDirection::DeviceReads => Rights::PIN.union(Rights::MAP).union(Rights::READ),
            IdeDmaDirection::DeviceWrites => Rights::PIN
                .union(Rights::MAP)
                .union(Rights::READ)
                .union(Rights::WRITE),
        };
        let data_capability = caps.insert(ObjectId(30), data_rights).unwrap();
        let prd_table_capability = caps
            .insert(
                ObjectId(31),
                Rights::PIN
                    .union(Rights::MAP)
                    .union(Rights::READ)
                    .union(Rights::WRITE),
            )
            .unwrap();
        (
            caps,
            IdeDmaRequest {
                data_capability,
                prd_table_capability,
                data: IdeDmaRegion {
                    memory_object: ObjectId(30),
                    allocation_generation: 2,
                    physical_base: base,
                    bytes,
                },
                prd_table: IdeDmaRegion {
                    memory_object: ObjectId(31),
                    allocation_generation: 3,
                    physical_base: 0x20_0000,
                    bytes: 4096,
                },
                transfer_bytes: bytes,
                direction,
                dma_generation: 4,
            },
        )
    }

    #[test]
    fn builds_full_one_mib_prdt_without_crossing_64k_boundaries() {
        let (caps, request) = fixture(IdeDmaDirection::DeviceWrites, 0x1_8000, 1024 * 1024);
        let mut backend = Backend::default();
        let mut memory = Memory::default();
        let owner = prepare_ide_dma(&caps, request, &mut backend, &mut memory).unwrap();
        assert_eq!(owner.layout().prd_entries, 17);
        assert_eq!(memory.words[0], 0x1_8000);
        assert_eq!(memory.words[1], 0x8000);
        assert_eq!(memory.words[32], 0x11_0000);
        assert_eq!(memory.words[33], PRD_END_OF_TABLE | 0x8000);
        assert_eq!(memory.writes, 34);
        assert_eq!(backend.installed, Some(owner.layout()));
    }

    #[test]
    fn exact_rights_geometry_overlap_and_backend_rejection_are_untouched() {
        let (mut caps, mut request) = fixture(IdeDmaDirection::DeviceReads, 0x1_0000, 4096);
        caps.revoke(request.data_capability).unwrap();
        request.data_capability = caps.insert(ObjectId(30), Rights::READ).unwrap();
        assert!(matches!(
            prepare_ide_dma(
                &caps,
                request,
                &mut Backend::default(),
                &mut Memory::default()
            ),
            Err(IdeDmaFailure::Untouched {
                error: IdeDmaError::DataCapability(_),
                ..
            })
        ));
        let (caps, mut request) = fixture(IdeDmaDirection::DeviceReads, 0x20_0000, 4096);
        request.prd_table.physical_base = request.data.physical_base;
        assert!(matches!(
            prepare_ide_dma(
                &caps,
                request,
                &mut Backend::default(),
                &mut Memory::default()
            ),
            Err(IdeDmaFailure::Untouched {
                error: IdeDmaError::OverlappingRegions,
                ..
            })
        ));
        let (caps, request) = fixture(IdeDmaDirection::DeviceReads, 0x1_0000, 4096);
        assert!(matches!(
            prepare_ide_dma(
                &caps,
                request,
                &mut Backend {
                    reject_install: true,
                    ..Backend::default()
                },
                &mut Memory::default()
            ),
            Err(IdeDmaFailure::Untouched {
                error: IdeDmaError::BackendRejected,
                ..
            })
        ));
    }

    #[test]
    fn partial_prdt_mutation_quarantines_and_revocation_retains_owner() {
        let (caps, request) = fixture(IdeDmaDirection::DeviceReads, 0x1_8000, 128 * 1024);
        let mut backend = Backend::default();
        let mut memory = Memory {
            fail_write: Some(2),
            ..Memory::default()
        };
        assert!(matches!(
            prepare_ide_dma(&caps, request, &mut backend, &mut memory),
            Err(IdeDmaFailure::Quarantined {
                error: IdeDmaError::MemoryWrite,
                ..
            })
        ));
        let (caps, request) = fixture(IdeDmaDirection::DeviceReads, 0x1_0000, 4096);
        let mut backend = Backend::default();
        let owner = prepare_ide_dma(&caps, request, &mut backend, &mut Memory::default()).unwrap();
        backend.reject_remove = true;
        let owner = revoke_ide_dma(owner, &mut backend).unwrap_err().owner;
        backend.reject_remove = false;
        assert_eq!(revoke_ide_dma(owner, &mut backend), Ok(()));
    }
}
