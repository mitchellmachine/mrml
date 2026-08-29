//! Bounded admission and disable sequencing for one mapped NVMe controller.

use crate::NvmeControllerBarMapping;

pub const NVME_CAP_OFFSET: u64 = 0x00;
pub const NVME_VERSION_OFFSET: u64 = 0x08;
pub const NVME_CC_OFFSET: u64 = 0x14;
pub const NVME_CSTS_OFFSET: u64 = 0x1c;

const CC_ENABLE: u32 = 1;
const CSTS_READY: u32 = 1;
const CSTS_FATAL: u32 = 1 << 1;
const CAP_NVM_COMMAND_SET: u64 = 1 << 37;
const MAX_TIMEOUT_UNITS: u32 = 256;
const POLLS_PER_500_MS: u32 = 1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeControllerSnapshot {
    pub configuration_generation: u64,
    pub mapping_generation: u64,
    pub version: u32,
    pub maximum_queue_entries: u32,
    pub contiguous_queues_required: bool,
    pub timeout_500ms_units: u16,
    pub doorbell_stride_bytes: u32,
    pub minimum_page_bytes: u64,
    pub maximum_page_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmeControllerError {
    RegisterRead,
    RegisterWrite,
    InvalidVersion,
    UnsupportedCommandSet,
    InvalidPageRange,
    FatalStatus,
    DisableTimeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvmeControllerFailure {
    pub error: NvmeControllerError,
    pub controller_may_be_enabled: bool,
}

pub trait NvmeControllerRegisterIo {
    fn read_u32(&mut self, offset: u64) -> Result<u32, ()>;
    fn read_u64(&mut self, offset: u64) -> Result<u64, ()>;
    fn write_u32(&mut self, offset: u64, value: u32) -> Result<(), ()>;
    /// A bounded backend delay used only to avoid an unbounded readiness spin.
    fn delay_500_micros(&mut self);
}

pub fn disable_nvme_controller<I: NvmeControllerRegisterIo>(
    mapping: NvmeControllerBarMapping,
    io: &mut I,
) -> Result<NvmeControllerSnapshot, NvmeControllerFailure> {
    let cap = io
        .read_u64(NVME_CAP_OFFSET)
        .map_err(|_| failure(NvmeControllerError::RegisterRead, true))?;
    let version = io
        .read_u32(NVME_VERSION_OFFSET)
        .map_err(|_| failure(NvmeControllerError::RegisterRead, true))?;
    let snapshot = decode_snapshot(mapping, cap, version)?;
    let cc = io
        .read_u32(NVME_CC_OFFSET)
        .map_err(|_| failure(NvmeControllerError::RegisterRead, true))?;
    if cc & CC_ENABLE != 0 {
        io.write_u32(NVME_CC_OFFSET, cc & !CC_ENABLE)
            .map_err(|_| failure(NvmeControllerError::RegisterWrite, true))?;
    }

    let polls = u32::from(snapshot.timeout_500ms_units)
        .checked_mul(POLLS_PER_500_MS)
        .ok_or_else(|| failure(NvmeControllerError::DisableTimeout, true))?;
    for _ in 0..polls {
        let status = io
            .read_u32(NVME_CSTS_OFFSET)
            .map_err(|_| failure(NvmeControllerError::RegisterRead, true))?;
        if status & CSTS_FATAL != 0 {
            return Err(failure(NvmeControllerError::FatalStatus, true));
        }
        if status & CSTS_READY == 0 {
            return Ok(snapshot);
        }
        io.delay_500_micros();
    }
    Err(failure(NvmeControllerError::DisableTimeout, true))
}

fn decode_snapshot(
    mapping: NvmeControllerBarMapping,
    cap: u64,
    version: u32,
) -> Result<NvmeControllerSnapshot, NvmeControllerFailure> {
    if version >> 16 == 0 {
        return Err(failure(NvmeControllerError::InvalidVersion, true));
    }
    if cap & CAP_NVM_COMMAND_SET == 0 {
        return Err(failure(NvmeControllerError::UnsupportedCommandSet, true));
    }
    let minimum_page_shift = 12_u32 + u32::try_from((cap >> 48) & 0xf).unwrap();
    let maximum_page_shift = 12_u32 + u32::try_from((cap >> 52) & 0xf).unwrap();
    if minimum_page_shift > maximum_page_shift {
        return Err(failure(NvmeControllerError::InvalidPageRange, true));
    }
    let timeout_500ms_units = u16::try_from(((cap >> 24) & 0xff) + 1).unwrap();
    debug_assert!(u32::from(timeout_500ms_units) <= MAX_TIMEOUT_UNITS);
    Ok(NvmeControllerSnapshot {
        configuration_generation: mapping.configuration_generation,
        mapping_generation: mapping.mapping_generation,
        version,
        maximum_queue_entries: u32::try_from((cap & 0xffff) + 1).unwrap(),
        contiguous_queues_required: cap & (1 << 16) != 0,
        timeout_500ms_units,
        doorbell_stride_bytes: 4_u32 << u32::try_from((cap >> 32) & 0xf).unwrap(),
        minimum_page_bytes: 1_u64 << minimum_page_shift,
        maximum_page_bytes: 1_u64 << maximum_page_shift,
    })
}

const fn failure(
    error: NvmeControllerError,
    controller_may_be_enabled: bool,
) -> NvmeControllerFailure {
    NvmeControllerFailure {
        error,
        controller_may_be_enabled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_kernel::ObjectId;

    struct Registers {
        cap: u64,
        version: u32,
        cc: u32,
        status: [u32; 3],
        status_reads: usize,
        writes: [Option<(u64, u32)>; 1],
        delays: u32,
        fail_read: Option<u64>,
        fail_write: bool,
    }

    impl NvmeControllerRegisterIo for Registers {
        fn read_u32(&mut self, offset: u64) -> Result<u32, ()> {
            if self.fail_read == Some(offset) {
                return Err(());
            }
            match offset {
                NVME_VERSION_OFFSET => Ok(self.version),
                NVME_CC_OFFSET => Ok(self.cc),
                NVME_CSTS_OFFSET => {
                    let value = self.status[self.status_reads.min(self.status.len() - 1)];
                    self.status_reads += 1;
                    Ok(value)
                }
                _ => Err(()),
            }
        }
        fn read_u64(&mut self, offset: u64) -> Result<u64, ()> {
            if self.fail_read == Some(offset) || offset != NVME_CAP_OFFSET {
                Err(())
            } else {
                Ok(self.cap)
            }
        }
        fn write_u32(&mut self, offset: u64, value: u32) -> Result<(), ()> {
            if self.fail_write {
                return Err(());
            }
            self.writes[0] = Some((offset, value));
            self.cc = value;
            Ok(())
        }
        fn delay_500_micros(&mut self) {
            self.delays += 1;
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

    fn registers() -> Registers {
        Registers {
            cap: 63 | (1 << 16) | (1 << 24) | (2 << 32) | CAP_NVM_COMMAND_SET | (1 << 52),
            version: 0x0002_0000,
            cc: 1 | (6 << 16),
            status: [CSTS_READY, CSTS_READY, 0],
            status_reads: 0,
            writes: [None],
            delays: 0,
            fail_read: None,
            fail_write: false,
        }
    }

    #[test]
    fn disables_before_publishing_bounded_controller_properties() {
        let mut io = registers();
        let snapshot = disable_nvme_controller(mapping(), &mut io).unwrap();
        assert_eq!(io.writes[0], Some((NVME_CC_OFFSET, 6 << 16)));
        assert_eq!(io.delays, 2);
        assert_eq!(snapshot.maximum_queue_entries, 64);
        assert!(snapshot.contiguous_queues_required);
        assert_eq!(snapshot.timeout_500ms_units, 2);
        assert_eq!(snapshot.doorbell_stride_bytes, 16);
        assert_eq!(snapshot.minimum_page_bytes, 4096);
        assert_eq!(snapshot.maximum_page_bytes, 8192);
    }

    #[test]
    fn already_disabled_controller_requires_ready_clear_but_writes_nothing() {
        let mut io = registers();
        io.cc = 0;
        io.status = [0; 3];
        assert!(disable_nvme_controller(mapping(), &mut io).is_ok());
        assert_eq!(io.writes, [None]);
        assert_eq!(io.delays, 0);
    }

    #[test]
    fn rejects_version_command_set_page_range_fatal_and_timeout() {
        let mut invalid_version = registers();
        invalid_version.version = 0x0000_ffff;
        assert_eq!(
            disable_nvme_controller(mapping(), &mut invalid_version)
                .unwrap_err()
                .error,
            NvmeControllerError::InvalidVersion
        );
        let mut no_nvm = registers();
        no_nvm.cap &= !CAP_NVM_COMMAND_SET;
        assert_eq!(
            disable_nvme_controller(mapping(), &mut no_nvm)
                .unwrap_err()
                .error,
            NvmeControllerError::UnsupportedCommandSet
        );
        let mut pages = registers();
        pages.cap |= 2 << 48;
        pages.cap &= !(0xf << 52);
        assert_eq!(
            disable_nvme_controller(mapping(), &mut pages)
                .unwrap_err()
                .error,
            NvmeControllerError::InvalidPageRange
        );
        let mut fatal = registers();
        fatal.status = [CSTS_FATAL; 3];
        assert_eq!(
            disable_nvme_controller(mapping(), &mut fatal)
                .unwrap_err()
                .error,
            NvmeControllerError::FatalStatus
        );
        let mut timeout = registers();
        timeout.cap &= !(0xff << 24);
        timeout.status = [CSTS_READY; 3];
        assert_eq!(
            disable_nvme_controller(mapping(), &mut timeout)
                .unwrap_err()
                .error,
            NvmeControllerError::DisableTimeout
        );
        assert_eq!(timeout.delays, 1000);
    }

    #[test]
    fn register_failures_never_publish_a_snapshot() {
        for offset in [
            NVME_CAP_OFFSET,
            NVME_VERSION_OFFSET,
            NVME_CC_OFFSET,
            NVME_CSTS_OFFSET,
        ] {
            let mut io = registers();
            io.fail_read = Some(offset);
            assert_eq!(
                disable_nvme_controller(mapping(), &mut io)
                    .unwrap_err()
                    .error,
                NvmeControllerError::RegisterRead
            );
        }
        let mut io = registers();
        io.fail_write = true;
        assert_eq!(
            disable_nvme_controller(mapping(), &mut io)
                .unwrap_err()
                .error,
            NvmeControllerError::RegisterWrite
        );
    }
}
