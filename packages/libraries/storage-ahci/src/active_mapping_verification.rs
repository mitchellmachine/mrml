//! Current-x86-root verification for frozen AHCI service mappings.

use crate::service_cpu_mapping::bound_mapping_requests;
use crate::{AHCI_MMIO_PAGE_BYTES, BoundAhciServiceLaunch};
use mrml_kernel::arch::x86_64::{
    ActivePageTables, AddressSpaceError, Mapping, PagePermissions, PageTableBuildError, VirtAddr,
};
use mrml_kernel::{NativeDeviceServiceTask, PhysAddr};

const ACTIVE_AHCI_MAPPING_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveAhciMappingVerificationError {
    CurrentPageTables(PageTableBuildError),
    WrongRoot,
    InvalidMapping {
        index: usize,
        error: AddressSpaceError,
    },
    Mapping {
        index: usize,
        error: PageTableBuildError,
    },
}

fn mapping(
    index: usize,
    virtual_base: u64,
    physical_base: u64,
    bytes: u64,
    permissions: PagePermissions,
) -> Result<Mapping, ActiveAhciMappingVerificationError> {
    let pages = bytes
        .checked_div(AHCI_MMIO_PAGE_BYTES)
        .filter(|_| bytes % AHCI_MMIO_PAGE_BYTES == 0)
        .ok_or(ActiveAhciMappingVerificationError::InvalidMapping {
            index,
            error: AddressSpaceError::InvalidMapping,
        })?;
    let virtual_start = VirtAddr::new(virtual_base).map_err(|_| {
        ActiveAhciMappingVerificationError::InvalidMapping {
            index,
            error: AddressSpaceError::InvalidMapping,
        }
    })?;
    let physical_start = PhysAddr::new(physical_base).map_err(|_| {
        ActiveAhciMappingVerificationError::InvalidMapping {
            index,
            error: AddressSpaceError::InvalidMapping,
        }
    })?;
    Mapping::new(virtual_start, physical_start, pages, permissions)
        .map_err(|error| ActiveAhciMappingVerificationError::InvalidMapping { index, error })
}

/// Exact-matches the ABAR and four CPU/DMA ranges against an already opened
/// active x86 page-table hierarchy.
pub fn verify_active_x86_ahci_mappings(
    tables: &ActivePageTables,
    native_task: NativeDeviceServiceTask<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
) -> Result<(), ActiveAhciMappingVerificationError> {
    if tables.root() != native_task.page_table_root() {
        return Err(ActiveAhciMappingVerificationError::WrongRoot);
    }
    let spec = launch.spec();
    let abar = spec.mapping();
    let mut mappings: [Option<Mapping>; ACTIVE_AHCI_MAPPING_COUNT] = [None; 5];
    mappings[0] = Some(mapping(
        0,
        abar.virtual_base,
        abar.physical_base,
        abar.bytes,
        PagePermissions::USER_MMIO_READ_WRITE,
    )?);
    for (offset, request) in bound_mapping_requests(launch).into_iter().enumerate() {
        let index = offset + 1;
        mappings[index] = Some(mapping(
            index,
            request.virtual_base(),
            request.physical_base(),
            request.mapped_bytes(),
            PagePermissions::USER_READ_WRITE,
        )?);
    }
    for (index, expected) in mappings.into_iter().enumerate() {
        let expected = expected.ok_or(ActiveAhciMappingVerificationError::InvalidMapping {
            index,
            error: AddressSpaceError::InvalidMapping,
        })?;
        tables
            .verify_mapped(native_task.page_table_root(), expected)
            .map_err(|error| ActiveAhciMappingVerificationError::Mapping { index, error })?;
    }
    Ok(())
}

/// Opens and verifies the current CR3 hierarchy for one frozen AHCI task.
///
/// # Safety
///
/// The caller must have interrupts disabled, hold the exact frozen task and
/// launch owners, keep every reachable page-table frame identity-mapped, and
/// exclude concurrent hierarchy mutation until this function returns.
pub unsafe fn verify_current_x86_ahci_mappings(
    native_task: NativeDeviceServiceTask<{ crate::AHCI_SERVICE_AUTHORITY_COUNT }>,
    launch: BoundAhciServiceLaunch,
) -> Result<(), ActiveAhciMappingVerificationError> {
    let tables = unsafe { ActivePageTables::current() }
        .map_err(ActiveAhciMappingVerificationError::CurrentPageTables)?;
    verify_active_x86_ahci_mappings(&tables, native_task, launch)
}
