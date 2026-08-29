//! Capability-bound ownership of the initial NVMe admin queue DMA pages.

use crate::NvmeControllerSnapshot;
use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

pub const NVME_QUEUE_PAGE_BYTES: u64 = 4096;
pub const NVME_ADMIN_QUEUE_DEPTH_LIMIT: u16 = 64;
pub const NVME_ADMIN_SUBMISSION_BYTES: u64 = 64;
pub const NVME_ADMIN_COMPLETION_BYTES: u64 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeDmaRegion {
    pub memory_object: ObjectId,
    pub allocation_generation: u64,
    pub physical_base: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeAdminQueueDmaRequest {
    pub controller_capability: Capability,
    pub submission_capability: Capability,
    pub completion_capability: Capability,
    pub submission: NvmeDmaRegion,
    pub completion: NvmeDmaRegion,
    pub dma_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeAdminQueueDmaLayout {
    pub controller_object: ObjectId,
    pub configuration_generation: u64,
    pub mapping_generation: u64,
    pub queue_depth: u16,
    pub submission: NvmeDmaRegion,
    pub completion: NvmeDmaRegion,
    pub dma_generation: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct InstalledNvmeAdminQueueDma {
    layout: NvmeAdminQueueDmaLayout,
}

impl InstalledNvmeAdminQueueDma {
    pub const fn layout(&self) -> NvmeAdminQueueDmaLayout {
        self.layout
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmeAdminQueueDmaError {
    ControllerCapability(CapabilityError),
    MemoryCapability(CapabilityError),
    WrongControllerObject,
    WrongMemoryObject,
    UnsupportedPageSize,
    QueueTooSmall,
    InvalidGeneration,
    InvalidRegion,
    OverlappingRegions,
    BackendRejected,
}

#[derive(Debug, Eq, PartialEq)]
pub struct NvmeAdminQueueDmaRevocationError {
    owner: InstalledNvmeAdminQueueDma,
}

impl NvmeAdminQueueDmaRevocationError {
    pub fn into_owner(self) -> InstalledNvmeAdminQueueDma {
        self.owner
    }
}

pub trait NvmeAdminQueueDmaBackend {
    /// Atomically pins, zero-verifies, and maps exactly both queue pages for the
    /// controller. Failure retains no mapping or device access.
    fn install_zeroed_layout(&mut self, layout: NvmeAdminQueueDmaLayout) -> Result<(), ()>;
    /// Completes device and IOMMU invalidation before releasing either page.
    fn remove_layout(&mut self, layout: NvmeAdminQueueDmaLayout) -> Result<(), ()>;
}

pub fn prepare_nvme_admin_queue_dma<const N: usize, B: NvmeAdminQueueDmaBackend>(
    capabilities: &CapabilitySpace<N>,
    controller_object: ObjectId,
    controller: NvmeControllerSnapshot,
    request: NvmeAdminQueueDmaRequest,
    backend: &mut B,
) -> Result<InstalledNvmeAdminQueueDma, NvmeAdminQueueDmaError> {
    let authorized = capabilities
        .authorize_exact(request.controller_capability, Rights::CONTROL)
        .map_err(NvmeAdminQueueDmaError::ControllerCapability)?;
    if authorized != controller_object {
        return Err(NvmeAdminQueueDmaError::WrongControllerObject);
    }
    if controller.minimum_page_bytes > NVME_QUEUE_PAGE_BYTES
        || controller.maximum_page_bytes < NVME_QUEUE_PAGE_BYTES
    {
        return Err(NvmeAdminQueueDmaError::UnsupportedPageSize);
    }
    let queue_depth = u16::try_from(
        controller
            .maximum_queue_entries
            .min(u32::from(NVME_ADMIN_QUEUE_DEPTH_LIMIT)),
    )
    .map_err(|_| NvmeAdminQueueDmaError::QueueTooSmall)?;
    if queue_depth < 2 {
        return Err(NvmeAdminQueueDmaError::QueueTooSmall);
    }
    if request.dma_generation == 0 {
        return Err(NvmeAdminQueueDmaError::InvalidGeneration);
    }

    let rights = Rights::PIN
        .union(Rights::MAP)
        .union(Rights::READ)
        .union(Rights::WRITE);
    authorize_region(
        capabilities,
        request.submission_capability,
        request.submission,
        rights,
    )?;
    authorize_region(
        capabilities,
        request.completion_capability,
        request.completion,
        rights,
    )?;
    validate_region(request.submission)?;
    validate_region(request.completion)?;
    if request.submission.memory_object == request.completion.memory_object
        || overlaps(request.submission, request.completion)
    {
        return Err(NvmeAdminQueueDmaError::OverlappingRegions);
    }

    let layout = NvmeAdminQueueDmaLayout {
        controller_object,
        configuration_generation: controller.configuration_generation,
        mapping_generation: controller.mapping_generation,
        queue_depth,
        submission: request.submission,
        completion: request.completion,
        dma_generation: request.dma_generation,
    };
    backend
        .install_zeroed_layout(layout)
        .map_err(|_| NvmeAdminQueueDmaError::BackendRejected)?;
    Ok(InstalledNvmeAdminQueueDma { layout })
}

pub fn revoke_nvme_admin_queue_dma<B: NvmeAdminQueueDmaBackend>(
    owner: InstalledNvmeAdminQueueDma,
    backend: &mut B,
) -> Result<(), NvmeAdminQueueDmaRevocationError> {
    if backend.remove_layout(owner.layout).is_err() {
        return Err(NvmeAdminQueueDmaRevocationError { owner });
    }
    Ok(())
}

fn authorize_region<const N: usize>(
    capabilities: &CapabilitySpace<N>,
    capability: Capability,
    region: NvmeDmaRegion,
    rights: Rights,
) -> Result<(), NvmeAdminQueueDmaError> {
    let object = capabilities
        .authorize_exact(capability, rights)
        .map_err(NvmeAdminQueueDmaError::MemoryCapability)?;
    if object != region.memory_object {
        return Err(NvmeAdminQueueDmaError::WrongMemoryObject);
    }
    Ok(())
}

fn validate_region(region: NvmeDmaRegion) -> Result<(), NvmeAdminQueueDmaError> {
    if region.allocation_generation == 0
        || region.physical_base == 0
        || region.physical_base % NVME_QUEUE_PAGE_BYTES != 0
        || region.bytes != NVME_QUEUE_PAGE_BYTES
        || region.physical_base.checked_add(region.bytes).is_none()
    {
        return Err(NvmeAdminQueueDmaError::InvalidRegion);
    }
    Ok(())
}

fn overlaps(left: NvmeDmaRegion, right: NvmeDmaRegion) -> bool {
    left.physical_base < right.physical_base + right.bytes
        && right.physical_base < left.physical_base + left.bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Backend {
        installed: Option<NvmeAdminQueueDmaLayout>,
        reject_install: bool,
        reject_remove: bool,
    }

    impl NvmeAdminQueueDmaBackend for Backend {
        fn install_zeroed_layout(&mut self, layout: NvmeAdminQueueDmaLayout) -> Result<(), ()> {
            if self.reject_install {
                return Err(());
            }
            self.installed = Some(layout);
            Ok(())
        }
        fn remove_layout(&mut self, layout: NvmeAdminQueueDmaLayout) -> Result<(), ()> {
            if self.reject_remove || self.installed != Some(layout) {
                return Err(());
            }
            self.installed = None;
            Ok(())
        }
    }

    fn fixture() -> (
        CapabilitySpace<3>,
        ObjectId,
        NvmeControllerSnapshot,
        NvmeAdminQueueDmaRequest,
    ) {
        let controller_object = ObjectId(71);
        let memory = [ObjectId(80), ObjectId(81)];
        let rights = Rights::PIN
            .union(Rights::MAP)
            .union(Rights::READ)
            .union(Rights::WRITE);
        let mut capabilities = CapabilitySpace::new();
        let controller_capability = capabilities
            .insert(controller_object, Rights::CONTROL)
            .unwrap();
        let submission_capability = capabilities.insert(memory[0], rights).unwrap();
        let completion_capability = capabilities.insert(memory[1], rights).unwrap();
        let controller = NvmeControllerSnapshot {
            configuration_generation: 11,
            mapping_generation: 9,
            version: 0x0002_0000,
            maximum_queue_entries: 128,
            contiguous_queues_required: true,
            timeout_500ms_units: 2,
            doorbell_stride_bytes: 4,
            minimum_page_bytes: 4096,
            maximum_page_bytes: 8192,
        };
        let request = NvmeAdminQueueDmaRequest {
            controller_capability,
            submission_capability,
            completion_capability,
            submission: NvmeDmaRegion {
                memory_object: memory[0],
                allocation_generation: 3,
                physical_base: 0x1000,
                bytes: 4096,
            },
            completion: NvmeDmaRegion {
                memory_object: memory[1],
                allocation_generation: 4,
                physical_base: 0x2000,
                bytes: 4096,
            },
            dma_generation: 12,
        };
        (capabilities, controller_object, controller, request)
    }

    #[test]
    fn installs_bounded_distinct_zeroed_admin_queue_pages() {
        let (capabilities, object, controller, request) = fixture();
        let mut backend = Backend::default();
        let owner =
            prepare_nvme_admin_queue_dma(&capabilities, object, controller, request, &mut backend)
                .unwrap();
        assert_eq!(owner.layout().queue_depth, 64);
        assert_eq!(backend.installed, Some(owner.layout()));
    }

    #[test]
    fn rejects_wrong_rights_objects_pages_and_overlap_before_backend() {
        let (capabilities, object, controller, request) = fixture();
        let mut candidate = request;
        candidate.completion_capability = request.submission_capability;
        assert!(matches!(
            prepare_nvme_admin_queue_dma(
                &capabilities,
                object,
                controller,
                candidate,
                &mut Backend::default()
            ),
            Err(NvmeAdminQueueDmaError::WrongMemoryObject)
        ));
        candidate = request;
        candidate.completion.physical_base = candidate.submission.physical_base;
        assert_eq!(
            prepare_nvme_admin_queue_dma(
                &capabilities,
                object,
                controller,
                candidate,
                &mut Backend::default()
            ),
            Err(NvmeAdminQueueDmaError::OverlappingRegions)
        );
        candidate = request;
        candidate.submission.bytes = 2048;
        assert_eq!(
            prepare_nvme_admin_queue_dma(
                &capabilities,
                object,
                controller,
                candidate,
                &mut Backend::default()
            ),
            Err(NvmeAdminQueueDmaError::InvalidRegion)
        );
    }

    #[test]
    fn rejects_unsupported_controller_limits_and_backend_failure() {
        let (capabilities, object, mut controller, request) = fixture();
        controller.minimum_page_bytes = 8192;
        assert_eq!(
            prepare_nvme_admin_queue_dma(
                &capabilities,
                object,
                controller,
                request,
                &mut Backend::default()
            ),
            Err(NvmeAdminQueueDmaError::UnsupportedPageSize)
        );
        controller.minimum_page_bytes = 4096;
        controller.maximum_queue_entries = 1;
        assert_eq!(
            prepare_nvme_admin_queue_dma(
                &capabilities,
                object,
                controller,
                request,
                &mut Backend::default()
            ),
            Err(NvmeAdminQueueDmaError::QueueTooSmall)
        );
        controller.maximum_queue_entries = 64;
        let mut backend = Backend {
            installed: None,
            reject_install: true,
            reject_remove: false,
        };
        assert_eq!(
            prepare_nvme_admin_queue_dma(&capabilities, object, controller, request, &mut backend),
            Err(NvmeAdminQueueDmaError::BackendRejected)
        );
    }

    #[test]
    fn revocation_retains_owner_until_backend_confirms_iommu_removal() {
        let (capabilities, object, controller, request) = fixture();
        let mut backend = Backend::default();
        let owner =
            prepare_nvme_admin_queue_dma(&capabilities, object, controller, request, &mut backend)
                .unwrap();
        backend.reject_remove = true;
        let failure = revoke_nvme_admin_queue_dma(owner, &mut backend).unwrap_err();
        let owner = failure.into_owner();
        backend.reject_remove = false;
        assert_eq!(revoke_nvme_admin_queue_dma(owner, &mut backend), Ok(()));
        assert_eq!(backend.installed, None);
    }
}
