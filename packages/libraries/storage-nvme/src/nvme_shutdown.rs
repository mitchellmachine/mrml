//! Ordered full NVMe provider teardown for restart without a kernel reboot.

use crate::{
    delete_nvme_io_queue_pair, disable_nvme_admin_queues, revoke_nvme_admin_queue_dma,
    unmap_nvme_controller_bar, ActiveNvmeIoQueues, NvmeAdminCommandMemoryIo,
    NvmeAdminQueueDmaBackend, NvmeAdminQueueDmaLayout, NvmeAdminQueueRegisterIo,
    NvmeControllerBarMapping, NvmeControllerBarMappingBackend, NvmeIoQueueDeleteError,
    NvmeIoQueueDmaBackend, NvmeIoQueueDmaLayout, NvmeQueueDisableError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeShutdownReceipt {
    pub controller_object: mrml_kernel::ObjectId,
    pub configuration_generation: u64,
    pub mapping_generation: u64,
    pub dma_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmeShutdownError {
    IdentityMismatch,
    IoQueue(NvmeIoQueueDeleteError),
    ControllerDisable(NvmeQueueDisableError),
    AdminDmaRemoval,
    MappingRemoval,
}

#[derive(Debug, Eq, PartialEq)]
pub enum NvmeShutdownFailure {
    Untouched {
        queues: ActiveNvmeIoQueues,
        mapping: NvmeControllerBarMapping,
        error: NvmeShutdownError,
    },
    Quarantined {
        admin_layout: NvmeAdminQueueDmaLayout,
        io_layout: Option<NvmeIoQueueDmaLayout>,
        mapping: NvmeControllerBarMapping,
        error: NvmeShutdownError,
    },
}

pub fn shutdown_nvme_provider<
    I: NvmeAdminCommandMemoryIo + NvmeAdminQueueRegisterIo,
    Q: NvmeIoQueueDmaBackend,
    A: NvmeAdminQueueDmaBackend,
    M: NvmeControllerBarMappingBackend,
>(
    queues: ActiveNvmeIoQueues,
    mapping: NvmeControllerBarMapping,
    io: &mut I,
    io_dma: &mut Q,
    admin_dma: &mut A,
    mappings: &mut M,
) -> Result<NvmeShutdownReceipt, NvmeShutdownFailure> {
    let io_layout = queues.layout();
    let admin_layout = queues.admin_queues().layout();
    if mapping.controller_object != admin_layout.controller_object
        || mapping.configuration_generation != admin_layout.configuration_generation
        || mapping.mapping_generation != admin_layout.mapping_generation
        || io_layout.controller_object != admin_layout.controller_object
        || io_layout.configuration_generation != admin_layout.configuration_generation
        || io_layout.mapping_generation != admin_layout.mapping_generation
    {
        return Err(NvmeShutdownFailure::Untouched {
            queues,
            mapping,
            error: NvmeShutdownError::IdentityMismatch,
        });
    }
    let admin = delete_nvme_io_queue_pair(queues, io, io_dma).map_err(|failure| {
        NvmeShutdownFailure::Quarantined {
            admin_layout: failure.admin_layout,
            io_layout: Some(failure.io_layout),
            mapping,
            error: NvmeShutdownError::IoQueue(failure.error),
        }
    })?;
    let owner = disable_nvme_admin_queues(admin, io).map_err(|failure| {
        NvmeShutdownFailure::Quarantined {
            admin_layout: failure.layout,
            io_layout: None,
            mapping,
            error: NvmeShutdownError::ControllerDisable(failure.error),
        }
    })?;
    let dma_generation = owner.layout().dma_generation;
    if let Err(failure) = revoke_nvme_admin_queue_dma(owner, admin_dma) {
        return Err(NvmeShutdownFailure::Quarantined {
            admin_layout: failure.into_owner().layout(),
            io_layout: None,
            mapping,
            error: NvmeShutdownError::AdminDmaRemoval,
        });
    }
    if unmap_nvme_controller_bar(mapping, mappings).is_err() {
        return Err(NvmeShutdownFailure::Quarantined {
            admin_layout,
            io_layout: None,
            mapping,
            error: NvmeShutdownError::MappingRemoval,
        });
    }
    Ok(NvmeShutdownReceipt {
        controller_object: mapping.controller_object,
        configuration_generation: mapping.configuration_generation,
        mapping_generation: mapping.mapping_generation,
        dma_generation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActiveNvmeAdminQueues, NvmeDmaRegion};
    use mrml_kernel::ObjectId;

    struct Io {
        submission: [u32; 1024],
        completion: [u32; 1024],
        submissions: usize,
        completions: usize,
        cc: u32,
        status: u32,
        delays: u32,
    }

    impl Default for Io {
        fn default() -> Self {
            Self {
                submission: [0; 1024],
                completion: [0; 1024],
                submissions: 0,
                completions: 0,
                cc: 1,
                status: 0,
                delays: 0,
            }
        }
    }

    impl NvmeAdminCommandMemoryIo for Io {
        fn read_u32(&mut self, region: NvmeDmaRegion, offset: u64) -> Result<u32, ()> {
            let index = usize::try_from(offset / 4).map_err(|_| ())?;
            match region.memory_object.0 {
                80 => self.submission.get(index).copied().ok_or(()),
                81 => self.completion.get(index).copied().ok_or(()),
                _ => Err(()),
            }
        }
        fn write_u32(&mut self, region: NvmeDmaRegion, offset: u64, value: u32) -> Result<(), ()> {
            if region.memory_object != ObjectId(80) {
                return Err(());
            }
            *self
                .submission
                .get_mut(usize::try_from(offset / 4).map_err(|_| ())?)
                .ok_or(())? = value;
            Ok(())
        }
        fn ring_doorbell(&mut self, offset: u64, _: u32) -> Result<(), ()> {
            match offset {
                0x1000 => {
                    let command = self.submissions;
                    let cid = (self.submission[command * 16] >> 16) & 0xffff;
                    self.completion[command * 4 + 2] = 0;
                    self.completion[command * 4 + 3] = cid | (1 << 16);
                    self.submissions += 1;
                    Ok(())
                }
                0x1004 => {
                    self.completions += 1;
                    Ok(())
                }
                _ => Err(()),
            }
        }
        fn delay_500_micros(&mut self) {
            self.delays += 1;
        }
    }

    impl NvmeAdminQueueRegisterIo for Io {
        fn read_u32(&mut self, offset: u64) -> Result<u32, ()> {
            match offset {
                crate::NVME_CC_OFFSET => Ok(self.cc),
                crate::NVME_CSTS_OFFSET => Ok(self.status),
                _ => Err(()),
            }
        }
        fn read_u64(&mut self, _: u64) -> Result<u64, ()> {
            Err(())
        }
        fn write_u32(&mut self, offset: u64, value: u32) -> Result<(), ()> {
            if offset != crate::NVME_CC_OFFSET {
                return Err(());
            }
            self.cc = value;
            Ok(())
        }
        fn write_u64(&mut self, _: u64, _: u64) -> Result<(), ()> {
            Err(())
        }
        fn delay_500_micros(&mut self) {
            self.delays += 1;
        }
    }

    struct IoDma(Option<NvmeIoQueueDmaLayout>);
    impl NvmeIoQueueDmaBackend for IoDma {
        fn install_zeroed_layout(&mut self, layout: NvmeIoQueueDmaLayout) -> Result<(), ()> {
            self.0 = Some(layout);
            Ok(())
        }
        fn remove_layout(&mut self, layout: NvmeIoQueueDmaLayout) -> Result<(), ()> {
            if self.0 != Some(layout) {
                return Err(());
            }
            self.0 = None;
            Ok(())
        }
    }

    struct AdminDma(Option<NvmeAdminQueueDmaLayout>, bool);
    impl NvmeAdminQueueDmaBackend for AdminDma {
        fn install_zeroed_layout(&mut self, layout: NvmeAdminQueueDmaLayout) -> Result<(), ()> {
            self.0 = Some(layout);
            Ok(())
        }
        fn remove_layout(&mut self, layout: NvmeAdminQueueDmaLayout) -> Result<(), ()> {
            if self.1 || self.0 != Some(layout) {
                return Err(());
            }
            self.0 = None;
            Ok(())
        }
    }

    struct Mappings(Option<NvmeControllerBarMapping>, bool);
    impl NvmeControllerBarMappingBackend for Mappings {
        fn map_read_write_nx(&mut self, mapping: NvmeControllerBarMapping) -> Result<(), ()> {
            self.0 = Some(mapping);
            Ok(())
        }
        fn unmap_read_write_nx(&mut self, mapping: NvmeControllerBarMapping) -> Result<(), ()> {
            if self.1 || self.0 != Some(mapping) {
                return Err(());
            }
            self.0 = None;
            Ok(())
        }
    }

    fn admin_layout() -> NvmeAdminQueueDmaLayout {
        NvmeAdminQueueDmaLayout {
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
        }
    }

    fn io_layout() -> NvmeIoQueueDmaLayout {
        NvmeIoQueueDmaLayout {
            controller_object: ObjectId(71),
            configuration_generation: 11,
            mapping_generation: 9,
            queue_id: 1,
            queue_depth: 64,
            timeout_500ms_units: 1,
            doorbell_stride_bytes: 4,
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
        }
    }

    fn mapping() -> NvmeControllerBarMapping {
        NvmeControllerBarMapping {
            controller_object: ObjectId(71),
            configuration_generation: 11,
            mapping_generation: 9,
            physical_base: 0x1_8000_0000,
            virtual_base: 0xffff_a000_0000_0000,
            bytes: 0x4000,
        }
    }

    fn queues() -> ActiveNvmeIoQueues {
        ActiveNvmeIoQueues::from_state(
            ActiveNvmeAdminQueues::from_state(admin_layout()),
            io_layout(),
        )
    }

    #[test]
    fn full_shutdown_orders_all_revocation_and_returns_exact_receipt() {
        let mut io = Io::default();
        let mut io_dma = IoDma(Some(io_layout()));
        let mut admin_dma = AdminDma(Some(admin_layout()), false);
        let mut mappings = Mappings(Some(mapping()), false);
        let receipt = shutdown_nvme_provider(
            queues(),
            mapping(),
            &mut io,
            &mut io_dma,
            &mut admin_dma,
            &mut mappings,
        )
        .unwrap();
        assert_eq!(receipt.controller_object, ObjectId(71));
        assert_eq!(receipt.dma_generation, 3);
        assert_eq!(io.submissions, 2);
        assert_eq!(io.completions, 2);
        assert_eq!(io.cc & 1, 0);
        assert_eq!(io_dma.0, None);
        assert_eq!(admin_dma.0, None);
        assert_eq!(mappings.0, None);
    }

    #[test]
    fn identity_mismatch_is_untouched_and_late_failures_are_phase_exact() {
        let mut wrong = mapping();
        wrong.mapping_generation += 1;
        let mut io = Io::default();
        let failure = shutdown_nvme_provider(
            queues(),
            wrong,
            &mut io,
            &mut IoDma(Some(io_layout())),
            &mut AdminDma(Some(admin_layout()), false),
            &mut Mappings(Some(wrong), false),
        )
        .unwrap_err();
        assert!(matches!(
            failure,
            NvmeShutdownFailure::Untouched {
                error: NvmeShutdownError::IdentityMismatch,
                ..
            }
        ));
        assert_eq!(io.submissions, 0);

        let mut io = Io::default();
        let failure = shutdown_nvme_provider(
            queues(),
            mapping(),
            &mut io,
            &mut IoDma(Some(io_layout())),
            &mut AdminDma(Some(admin_layout()), false),
            &mut Mappings(Some(mapping()), true),
        )
        .unwrap_err();
        assert!(matches!(
            failure,
            NvmeShutdownFailure::Quarantined {
                io_layout: None,
                error: NvmeShutdownError::MappingRemoval,
                ..
            }
        ));
    }
}
