//! Capability-bound ownership of one NVMe I/O queue pair's DMA pages.

use crate::{ActiveNvmeAdminQueues, NvmeDmaRegion, NvmeIoQueueGrant, NVME_QUEUE_PAGE_BYTES};
use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

pub const NVME_IO_QUEUE_DEPTH_LIMIT: u16 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeIoQueueDmaRequest {
    pub controller_capability: Capability,
    pub submission_capability: Capability,
    pub completion_capability: Capability,
    pub queue_id: u16,
    pub queue_depth: u16,
    pub submission: NvmeDmaRegion,
    pub completion: NvmeDmaRegion,
    pub dma_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeIoQueueDmaLayout {
    pub controller_object: ObjectId,
    pub configuration_generation: u64,
    pub mapping_generation: u64,
    pub queue_id: u16,
    pub queue_depth: u16,
    pub timeout_500ms_units: u16,
    pub doorbell_stride_bytes: u32,
    pub submission: NvmeDmaRegion,
    pub completion: NvmeDmaRegion,
    pub dma_generation: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct PreparedNvmeIoQueueDma {
    admin_queues: ActiveNvmeAdminQueues,
    layout: NvmeIoQueueDmaLayout,
}

impl PreparedNvmeIoQueueDma {
    pub const fn admin_queues(&self) -> &ActiveNvmeAdminQueues {
        &self.admin_queues
    }

    pub const fn layout(&self) -> NvmeIoQueueDmaLayout {
        self.layout
    }

    pub(crate) fn into_parts(self) -> (ActiveNvmeAdminQueues, NvmeIoQueueDmaLayout) {
        (self.admin_queues, self.layout)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmeIoQueueDmaError {
    ControllerCapability(CapabilityError),
    MemoryCapability(CapabilityError),
    WrongControllerObject,
    WrongMemoryObject,
    QueueId,
    QueueDepth,
    InvalidGeneration,
    InvalidRegion,
    OverlappingRegions,
    BackendRejected,
}

#[derive(Debug, Eq, PartialEq)]
pub struct NvmeIoQueueDmaFailure {
    pub grant: NvmeIoQueueGrant,
    pub error: NvmeIoQueueDmaError,
}

pub trait NvmeIoQueueDmaBackend {
    /// Atomically pins, zero-verifies, and installs the exact queue pair.
    fn install_zeroed_layout(&mut self, layout: NvmeIoQueueDmaLayout) -> Result<(), ()>;
    /// Removes the exact queue DMA mappings after device and IOMMU invalidation.
    fn remove_layout(&mut self, layout: NvmeIoQueueDmaLayout) -> Result<(), ()>;
}

pub fn prepare_nvme_io_queue_dma<const N: usize, B: NvmeIoQueueDmaBackend>(
    capabilities: &CapabilitySpace<N>,
    grant: NvmeIoQueueGrant,
    request: NvmeIoQueueDmaRequest,
    backend: &mut B,
) -> Result<PreparedNvmeIoQueueDma, NvmeIoQueueDmaFailure> {
    match prepare(capabilities, &grant, request, backend) {
        Ok(layout) => Ok(PreparedNvmeIoQueueDma {
            admin_queues: grant.queues,
            layout,
        }),
        Err(error) => Err(NvmeIoQueueDmaFailure { grant, error }),
    }
}

fn prepare<const N: usize, B: NvmeIoQueueDmaBackend>(
    capabilities: &CapabilitySpace<N>,
    grant: &NvmeIoQueueGrant,
    request: NvmeIoQueueDmaRequest,
    backend: &mut B,
) -> Result<NvmeIoQueueDmaLayout, NvmeIoQueueDmaError> {
    let admin = grant.queues.layout();
    let controller = capabilities
        .authorize_exact(request.controller_capability, Rights::CONTROL)
        .map_err(NvmeIoQueueDmaError::ControllerCapability)?;
    if controller != admin.controller_object {
        return Err(NvmeIoQueueDmaError::WrongControllerObject);
    }
    if request.queue_id == 0
        || request.queue_id > grant.submission_queues
        || request.queue_id > grant.completion_queues
    {
        return Err(NvmeIoQueueDmaError::QueueId);
    }
    if request.queue_depth < 2
        || request.queue_depth > NVME_IO_QUEUE_DEPTH_LIMIT
        || u64::from(request.queue_depth) * 64 > NVME_QUEUE_PAGE_BYTES
        || u64::from(request.queue_depth) * 16 > NVME_QUEUE_PAGE_BYTES
    {
        return Err(NvmeIoQueueDmaError::QueueDepth);
    }
    if request.dma_generation == 0 {
        return Err(NvmeIoQueueDmaError::InvalidGeneration);
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
        || overlaps(request.submission, admin.submission)
        || overlaps(request.submission, admin.completion)
        || overlaps(request.completion, admin.submission)
        || overlaps(request.completion, admin.completion)
    {
        return Err(NvmeIoQueueDmaError::OverlappingRegions);
    }
    let layout = NvmeIoQueueDmaLayout {
        controller_object: admin.controller_object,
        configuration_generation: admin.configuration_generation,
        mapping_generation: admin.mapping_generation,
        queue_id: request.queue_id,
        queue_depth: request.queue_depth,
        timeout_500ms_units: admin.timeout_500ms_units,
        doorbell_stride_bytes: admin.doorbell_stride_bytes,
        submission: request.submission,
        completion: request.completion,
        dma_generation: request.dma_generation,
    };
    backend
        .install_zeroed_layout(layout)
        .map_err(|_| NvmeIoQueueDmaError::BackendRejected)?;
    Ok(layout)
}

fn authorize_region<const N: usize>(
    capabilities: &CapabilitySpace<N>,
    capability: Capability,
    region: NvmeDmaRegion,
    rights: Rights,
) -> Result<(), NvmeIoQueueDmaError> {
    let object = capabilities
        .authorize_exact(capability, rights)
        .map_err(NvmeIoQueueDmaError::MemoryCapability)?;
    if object != region.memory_object {
        return Err(NvmeIoQueueDmaError::WrongMemoryObject);
    }
    Ok(())
}

fn validate_region(region: NvmeDmaRegion) -> Result<(), NvmeIoQueueDmaError> {
    if region.allocation_generation == 0
        || region.physical_base == 0
        || region.physical_base % NVME_QUEUE_PAGE_BYTES != 0
        || region.bytes != NVME_QUEUE_PAGE_BYTES
        || region.physical_base.checked_add(region.bytes).is_none()
    {
        return Err(NvmeIoQueueDmaError::InvalidRegion);
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
    use crate::{ActiveNvmeAdminQueues, NvmeAdminQueueDmaLayout};

    #[derive(Default)]
    struct Backend {
        installed: Option<NvmeIoQueueDmaLayout>,
        reject: bool,
    }

    impl NvmeIoQueueDmaBackend for Backend {
        fn install_zeroed_layout(&mut self, layout: NvmeIoQueueDmaLayout) -> Result<(), ()> {
            if self.reject {
                return Err(());
            }
            self.installed = Some(layout);
            Ok(())
        }
        fn remove_layout(&mut self, layout: NvmeIoQueueDmaLayout) -> Result<(), ()> {
            if self.installed != Some(layout) {
                return Err(());
            }
            self.installed = None;
            Ok(())
        }
    }

    fn fixture() -> (CapabilitySpace<3>, NvmeIoQueueGrant, NvmeIoQueueDmaRequest) {
        let rights = Rights::PIN
            .union(Rights::MAP)
            .union(Rights::READ)
            .union(Rights::WRITE);
        let mut capabilities = CapabilitySpace::new();
        let controller_capability = capabilities.insert(ObjectId(71), Rights::CONTROL).unwrap();
        let submission_capability = capabilities.insert(ObjectId(90), rights).unwrap();
        let completion_capability = capabilities.insert(ObjectId(91), rights).unwrap();
        let admin = NvmeAdminQueueDmaLayout {
            controller_object: ObjectId(71),
            configuration_generation: 11,
            mapping_generation: 9,
            queue_depth: 64,
            timeout_500ms_units: 1,
            doorbell_stride_bytes: 4,
            submission: NvmeDmaRegion {
                memory_object: ObjectId(80),
                allocation_generation: 1,
                physical_base: 0x1000,
                bytes: 4096,
            },
            completion: NvmeDmaRegion {
                memory_object: ObjectId(81),
                allocation_generation: 2,
                physical_base: 0x2000,
                bytes: 4096,
            },
            dma_generation: 3,
        };
        let grant = NvmeIoQueueGrant {
            queues: ActiveNvmeAdminQueues::from_state(admin),
            submission_queues: 2,
            completion_queues: 2,
        };
        let request = NvmeIoQueueDmaRequest {
            controller_capability,
            submission_capability,
            completion_capability,
            queue_id: 1,
            queue_depth: 64,
            submission: NvmeDmaRegion {
                memory_object: ObjectId(90),
                allocation_generation: 4,
                physical_base: 0x3000,
                bytes: 4096,
            },
            completion: NvmeDmaRegion {
                memory_object: ObjectId(91),
                allocation_generation: 5,
                physical_base: 0x4000,
                bytes: 4096,
            },
            dma_generation: 6,
        };
        (capabilities, grant, request)
    }

    #[test]
    fn installs_exact_distinct_zeroed_io_queue_pair_and_retains_admin_owner() {
        let (capabilities, grant, request) = fixture();
        let mut backend = Backend::default();
        let prepared =
            prepare_nvme_io_queue_dma(&capabilities, grant, request, &mut backend).unwrap();
        assert_eq!(prepared.layout().queue_id, 1);
        assert_eq!(prepared.layout().queue_depth, 64);
        assert_eq!(backend.installed, Some(prepared.layout()));
        assert_eq!(prepared.admin_queues().state(), (0, 0, true, 1));
    }

    #[test]
    fn rejects_ungranted_ids_and_unrepresentable_depths() {
        for (queue_id, depth, expected) in [
            (0, 64, NvmeIoQueueDmaError::QueueId),
            (3, 64, NvmeIoQueueDmaError::QueueId),
            (1, 1, NvmeIoQueueDmaError::QueueDepth),
            (1, 65, NvmeIoQueueDmaError::QueueDepth),
        ] {
            let (capabilities, grant, mut request) = fixture();
            request.queue_id = queue_id;
            request.queue_depth = depth;
            assert_eq!(
                prepare_nvme_io_queue_dma(&capabilities, grant, request, &mut Backend::default())
                    .unwrap_err()
                    .error,
                expected
            );
        }
    }

    #[test]
    fn rejects_overlap_substitution_and_bad_geometry_before_backend() {
        let (capabilities, grant, mut request) = fixture();
        request.completion.physical_base = request.submission.physical_base;
        assert_eq!(
            prepare_nvme_io_queue_dma(&capabilities, grant, request, &mut Backend::default())
                .unwrap_err()
                .error,
            NvmeIoQueueDmaError::OverlappingRegions
        );
        let (capabilities, grant, mut request) = fixture();
        request.completion_capability = request.submission_capability;
        assert_eq!(
            prepare_nvme_io_queue_dma(&capabilities, grant, request, &mut Backend::default())
                .unwrap_err()
                .error,
            NvmeIoQueueDmaError::WrongMemoryObject
        );
        let (capabilities, grant, mut request) = fixture();
        request.submission.bytes = 2048;
        assert_eq!(
            prepare_nvme_io_queue_dma(&capabilities, grant, request, &mut Backend::default())
                .unwrap_err()
                .error,
            NvmeIoQueueDmaError::InvalidRegion
        );
    }

    #[test]
    fn backend_rejection_returns_the_live_admin_grant_for_retry() {
        let (capabilities, grant, request) = fixture();
        let failure = prepare_nvme_io_queue_dma(
            &capabilities,
            grant,
            request,
            &mut Backend {
                installed: None,
                reject: true,
            },
        )
        .unwrap_err();
        assert_eq!(failure.error, NvmeIoQueueDmaError::BackendRejected);
        assert_eq!(failure.grant.queues.state(), (0, 0, true, 1));
    }
}
