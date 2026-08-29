//! Capability-bound NVMe physical-region-page construction.

use crate::NvmeDmaRegion;
use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, Rights};

pub const NVME_MAX_PRP_TRANSFER_BYTES: u64 = 1024 * 1024;
pub const NVME_PRP_LIST_BYTES: u64 = 4096;
const PAGE_BYTES: u64 = 4096;
const PRP_LIST_ENTRIES: u64 = NVME_PRP_LIST_BYTES / 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmeTransferDirection {
    DeviceReads,
    DeviceWrites,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmePrpRequest {
    pub data_capability: Capability,
    pub prp_list_capability: Option<Capability>,
    pub data: NvmeDmaRegion,
    pub prp_list: Option<NvmeDmaRegion>,
    pub transfer_bytes: u64,
    pub direction: NvmeTransferDirection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedNvmePrps {
    request: NvmePrpRequest,
    pub prp1: u64,
    pub prp2: u64,
    pub data_page_count: u16,
}

impl PreparedNvmePrps {
    pub const fn request(&self) -> NvmePrpRequest {
        self.request
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmePrpError {
    DataCapability(CapabilityError),
    ListCapability(CapabilityError),
    WrongDataObject,
    WrongListObject,
    InvalidTransfer,
    InvalidDataRegion,
    MissingPrpList,
    UnexpectedPrpList,
    InvalidPrpList,
    OverlappingRegions,
    MemoryRead,
    DataNotZero,
    PrpListNotZero,
    MemoryWrite,
    VerificationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmePrpFailure {
    Untouched {
        request: NvmePrpRequest,
        error: NvmePrpError,
    },
    Quarantined {
        request: NvmePrpRequest,
        error: NvmePrpError,
    },
}

pub trait NvmePrpMemoryIo {
    fn read_u64(&mut self, region: NvmeDmaRegion, offset: u64) -> Result<u64, ()>;
    fn write_u64(&mut self, region: NvmeDmaRegion, offset: u64, value: u64) -> Result<(), ()>;
}

pub fn prepare_nvme_prps<const N: usize, M: NvmePrpMemoryIo>(
    capabilities: &CapabilitySpace<N>,
    request: NvmePrpRequest,
    memory: &mut M,
) -> Result<PreparedNvmePrps, NvmePrpFailure> {
    match prepare(capabilities, request, memory) {
        Ok(prepared) => Ok(prepared),
        Err((error, mutated)) => Err(if mutated {
            NvmePrpFailure::Quarantined { request, error }
        } else {
            NvmePrpFailure::Untouched { request, error }
        }),
    }
}

fn prepare<const N: usize, M: NvmePrpMemoryIo>(
    capabilities: &CapabilitySpace<N>,
    request: NvmePrpRequest,
    memory: &mut M,
) -> Result<PreparedNvmePrps, (NvmePrpError, bool)> {
    if request.transfer_bytes < 512
        || request.transfer_bytes > NVME_MAX_PRP_TRANSFER_BYTES
        || request.transfer_bytes % 512 != 0
    {
        return Err((NvmePrpError::InvalidTransfer, false));
    }
    let data_page_count = request.transfer_bytes.div_ceil(PAGE_BYTES);
    let mapped_data_bytes = data_page_count
        .checked_mul(PAGE_BYTES)
        .ok_or((NvmePrpError::InvalidTransfer, false))?;
    let data_rights = match request.direction {
        NvmeTransferDirection::DeviceReads => Rights::PIN.union(Rights::MAP).union(Rights::READ),
        NvmeTransferDirection::DeviceWrites => Rights::PIN
            .union(Rights::MAP)
            .union(Rights::READ)
            .union(Rights::WRITE),
    };
    let data_object = capabilities
        .authorize_exact(request.data_capability, data_rights)
        .map_err(|error| (NvmePrpError::DataCapability(error), false))?;
    if data_object != request.data.memory_object {
        return Err((NvmePrpError::WrongDataObject, false));
    }
    if request.data.allocation_generation == 0
        || request.data.physical_base == 0
        || request.data.physical_base % PAGE_BYTES != 0
        || request.data.bytes != mapped_data_bytes
        || request
            .data
            .physical_base
            .checked_add(request.data.bytes)
            .is_none()
    {
        return Err((NvmePrpError::InvalidDataRegion, false));
    }
    if request.direction == NvmeTransferDirection::DeviceWrites {
        let mut offset = 0;
        while offset < request.data.bytes {
            match memory.read_u64(request.data, offset) {
                Ok(0) => {}
                Ok(_) => return Err((NvmePrpError::DataNotZero, false)),
                Err(()) => return Err((NvmePrpError::MemoryRead, false)),
            }
            offset += 8;
        }
    }

    if data_page_count > u64::from(u16::MAX) {
        return Err((NvmePrpError::InvalidTransfer, false));
    }
    let needs_list = data_page_count > 2;
    if needs_list && (request.prp_list.is_none() || request.prp_list_capability.is_none()) {
        return Err((NvmePrpError::MissingPrpList, false));
    }
    if !needs_list && (request.prp_list.is_some() || request.prp_list_capability.is_some()) {
        return Err((NvmePrpError::UnexpectedPrpList, false));
    }

    let prp2 = if !needs_list {
        if data_page_count == 2 {
            request.data.physical_base + PAGE_BYTES
        } else {
            0
        }
    } else {
        let list = request.prp_list.unwrap();
        let list_capability = request.prp_list_capability.unwrap();
        let rights = Rights::PIN
            .union(Rights::MAP)
            .union(Rights::READ)
            .union(Rights::WRITE);
        let list_object = capabilities
            .authorize_exact(list_capability, rights)
            .map_err(|error| (NvmePrpError::ListCapability(error), false))?;
        if list_object != list.memory_object {
            return Err((NvmePrpError::WrongListObject, false));
        }
        if list.allocation_generation == 0
            || list.physical_base == 0
            || list.physical_base % PAGE_BYTES != 0
            || list.bytes != NVME_PRP_LIST_BYTES
            || list.physical_base.checked_add(list.bytes).is_none()
        {
            return Err((NvmePrpError::InvalidPrpList, false));
        }
        if overlaps(request.data, list) || data_page_count - 1 > PRP_LIST_ENTRIES {
            return Err((NvmePrpError::OverlappingRegions, false));
        }
        let mut offset = 0;
        while offset < list.bytes {
            match memory.read_u64(list, offset) {
                Ok(0) => {}
                Ok(_) => return Err((NvmePrpError::PrpListNotZero, false)),
                Err(()) => return Err((NvmePrpError::MemoryRead, false)),
            }
            offset += 8;
        }
        for index in 0..data_page_count - 1 {
            let entry = request.data.physical_base + (index + 1) * PAGE_BYTES;
            if memory.write_u64(list, index * 8, entry).is_err() {
                return Err((NvmePrpError::MemoryWrite, true));
            }
        }
        for index in 0..data_page_count - 1 {
            let expected = request.data.physical_base + (index + 1) * PAGE_BYTES;
            if memory.read_u64(list, index * 8) != Ok(expected) {
                return Err((NvmePrpError::VerificationFailed, true));
            }
        }
        list.physical_base
    };

    Ok(PreparedNvmePrps {
        request,
        prp1: request.data.physical_base,
        prp2,
        data_page_count: u16::try_from(data_page_count).unwrap(),
    })
}

fn overlaps(left: NvmeDmaRegion, right: NvmeDmaRegion) -> bool {
    left.physical_base < right.physical_base + right.bytes
        && right.physical_base < left.physical_base + left.bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_kernel::ObjectId;

    struct Memory {
        data: [u64; 131072],
        list: [u64; 512],
        writes: usize,
        fail_write: Option<usize>,
        corrupt_readback: bool,
    }

    impl Default for Memory {
        fn default() -> Self {
            Self {
                data: [0; 131072],
                list: [0; 512],
                writes: 0,
                fail_write: None,
                corrupt_readback: false,
            }
        }
    }

    impl NvmePrpMemoryIo for Memory {
        fn read_u64(&mut self, region: NvmeDmaRegion, offset: u64) -> Result<u64, ()> {
            let index = usize::try_from(offset / 8).map_err(|_| ())?;
            match region.memory_object.0 {
                100 => self.data.get(index).copied().ok_or(()),
                101 => {
                    let value = self.list.get(index).copied().ok_or(())?;
                    if self.corrupt_readback && self.writes != 0 && index == 0 {
                        Ok(value ^ 1)
                    } else {
                        Ok(value)
                    }
                }
                _ => Err(()),
            }
        }
        fn write_u64(&mut self, region: NvmeDmaRegion, offset: u64, value: u64) -> Result<(), ()> {
            if self.fail_write == Some(self.writes) {
                return Err(());
            }
            if region.memory_object != ObjectId(101) {
                return Err(());
            }
            let index = usize::try_from(offset / 8).map_err(|_| ())?;
            *self.list.get_mut(index).ok_or(())? = value;
            self.writes += 1;
            Ok(())
        }
    }

    fn fixture(
        bytes: u64,
        direction: NvmeTransferDirection,
    ) -> (CapabilitySpace<2>, NvmePrpRequest) {
        let data_rights = match direction {
            NvmeTransferDirection::DeviceReads => {
                Rights::PIN.union(Rights::MAP).union(Rights::READ)
            }
            NvmeTransferDirection::DeviceWrites => Rights::PIN
                .union(Rights::MAP)
                .union(Rights::READ)
                .union(Rights::WRITE),
        };
        let list_rights = Rights::PIN
            .union(Rights::MAP)
            .union(Rights::READ)
            .union(Rights::WRITE);
        let mut capabilities = CapabilitySpace::new();
        let data_capability = capabilities.insert(ObjectId(100), data_rights).unwrap();
        let needs_list = bytes > 8192;
        let prp_list_capability =
            needs_list.then(|| capabilities.insert(ObjectId(101), list_rights).unwrap());
        let request = NvmePrpRequest {
            data_capability,
            prp_list_capability,
            data: NvmeDmaRegion {
                memory_object: ObjectId(100),
                allocation_generation: 7,
                physical_base: 0x1_0000,
                bytes: bytes.div_ceil(4096) * 4096,
            },
            prp_list: needs_list.then_some(NvmeDmaRegion {
                memory_object: ObjectId(101),
                allocation_generation: 8,
                physical_base: 0x20_0000,
                bytes: 4096,
            }),
            transfer_bytes: bytes,
            direction,
        };
        (capabilities, request)
    }

    #[test]
    fn represents_one_and_two_page_transfers_without_a_list() {
        for (bytes, expected_prp2, pages) in [(512, 0, 1), (4096, 0, 1), (8192, 0x1_1000, 2)] {
            let (capabilities, request) = fixture(bytes, NvmeTransferDirection::DeviceReads);
            let prepared =
                prepare_nvme_prps(&capabilities, request, &mut Memory::default()).unwrap();
            assert_eq!(prepared.prp1, 0x1_0000);
            assert_eq!(prepared.prp2, expected_prp2);
            assert_eq!(prepared.data_page_count, pages);
        }
    }

    #[test]
    fn constructs_and_verifies_full_one_mib_prp_list() {
        let (capabilities, request) = fixture(
            NVME_MAX_PRP_TRANSFER_BYTES,
            NvmeTransferDirection::DeviceReads,
        );
        let mut memory = Memory::default();
        let prepared = prepare_nvme_prps(&capabilities, request, &mut memory).unwrap();
        assert_eq!(prepared.prp2, 0x20_0000);
        assert_eq!(prepared.data_page_count, 256);
        assert_eq!(memory.writes, 255);
        assert_eq!(memory.list[0], 0x1_1000);
        assert_eq!(memory.list[254], 0x10f_000);
        assert!(memory.list[255..].iter().all(|entry| *entry == 0));
    }

    #[test]
    fn device_write_requires_exact_zeroed_writable_data_authority() {
        let (capabilities, request) = fixture(4096, NvmeTransferDirection::DeviceWrites);
        let mut memory = Memory::default();
        memory.data[3] = 1;
        assert!(matches!(
            prepare_nvme_prps(&capabilities, request, &mut memory),
            Err(NvmePrpFailure::Untouched {
                error: NvmePrpError::DataNotZero,
                ..
            })
        ));
        memory.data[3] = 0;
        assert!(prepare_nvme_prps(&capabilities, request, &mut memory).is_ok());
    }

    #[test]
    fn list_presence_geometry_and_overlap_fail_before_mutation() {
        let (capabilities, mut request) = fixture(12288, NvmeTransferDirection::DeviceReads);
        request.prp_list = None;
        assert!(matches!(
            prepare_nvme_prps(&capabilities, request, &mut Memory::default()),
            Err(NvmePrpFailure::Untouched {
                error: NvmePrpError::MissingPrpList,
                ..
            })
        ));
        let (capabilities, mut request) = fixture(12288, NvmeTransferDirection::DeviceReads);
        request.prp_list.as_mut().unwrap().physical_base = request.data.physical_base;
        assert!(matches!(
            prepare_nvme_prps(&capabilities, request, &mut Memory::default()),
            Err(NvmePrpFailure::Untouched {
                error: NvmePrpError::OverlappingRegions,
                ..
            })
        ));
    }

    #[test]
    fn partial_list_write_or_bad_readback_quarantines_request() {
        let (capabilities, request) = fixture(12288, NvmeTransferDirection::DeviceReads);
        let mut memory = Memory {
            fail_write: Some(1),
            ..Memory::default()
        };
        assert!(matches!(
            prepare_nvme_prps(&capabilities, request, &mut memory),
            Err(NvmePrpFailure::Quarantined {
                error: NvmePrpError::MemoryWrite,
                ..
            })
        ));
        let (capabilities, request) = fixture(12288, NvmeTransferDirection::DeviceReads);
        let mut memory = Memory {
            corrupt_readback: true,
            ..Memory::default()
        };
        assert!(matches!(
            prepare_nvme_prps(&capabilities, request, &mut memory),
            Err(NvmePrpFailure::Quarantined {
                error: NvmePrpError::VerificationFailed,
                ..
            })
        ));
    }
}
