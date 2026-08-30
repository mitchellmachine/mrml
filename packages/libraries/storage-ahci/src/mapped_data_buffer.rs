//! Directional access to one already-mapped AHCI data DMA extent.
//!
//! The byte mapping is safe Rust. A separate backend must perform the exact
//! platform cache/coherency operations; this module does not treat ordinary
//! memory copies as proof that a device or CPU can observe them.

use crate::{AhciDataBufferIo, AhciDataDmaRegion};

/// Platform cache/coherency boundary for one exact data DMA region.
///
/// Implementations must not change mappings or authority. Success confirms
/// only the named visibility transition; IOMMU installation and revocation
/// remain separate lifecycle operations owned outside this adapter.
pub trait AhciDataBufferSync {
    fn prepare_device_write(&mut self, region: AhciDataDmaRegion) -> Result<(), ()>;
    fn prepare_device_read(&mut self, region: AhciDataDmaRegion) -> Result<(), ()>;
    fn complete_device_write(&mut self, region: AhciDataDmaRegion) -> Result<(), ()>;
    fn complete_device_read(&mut self, region: AhciDataDmaRegion) -> Result<(), ()>;
    fn publish_sanitized(&mut self, region: AhciDataDmaRegion) -> Result<(), ()>;
}

pub struct AhciMappedDataBuffer<'a, S> {
    region: AhciDataDmaRegion,
    bytes: &'a mut [u8],
    sync: S,
    state: DataState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DataState {
    Idle,
    DeviceWrite(AhciDataDmaRegion),
    DeviceRead(AhciDataDmaRegion),
    AwaitingSanitize(AhciDataDmaRegion),
    Uncertain(AhciDataDmaRegion),
}

impl<'a, S> AhciMappedDataBuffer<'a, S> {
    pub fn new(region: AhciDataDmaRegion, bytes: &'a mut [u8], sync: S) -> Option<Self> {
        if region.memory_object.0 == 0
            || region.allocation_generation == 0
            || region.physical_base == 0
            || region.bytes == 0
            || region.bytes > 1024 * 1024
            || usize::try_from(region.bytes).ok() != Some(bytes.len())
            || region.physical_base.checked_add(region.bytes).is_none()
        {
            return None;
        }
        Some(Self {
            region,
            bytes,
            sync,
            state: DataState::Idle,
        })
    }

    pub const fn is_available(&self) -> bool {
        matches!(self.state, DataState::Idle)
    }

    pub fn into_clean_parts(self) -> Result<(&'a mut [u8], S), Self> {
        if self.state == DataState::Idle {
            Ok((self.bytes, self.sync))
        } else {
            Err(self)
        }
    }

    fn exact_bytes(&mut self, requested: AhciDataDmaRegion) -> Result<&mut [u8], ()> {
        if requested.memory_object != self.region.memory_object
            || requested.allocation_generation != self.region.allocation_generation
            || requested.physical_base != self.region.physical_base
            || requested.bytes == 0
            || requested.bytes > self.region.bytes
        {
            return Err(());
        }
        let bytes = usize::try_from(requested.bytes).map_err(|_| ())?;
        self.bytes.get_mut(..bytes).ok_or(())
    }

    fn expected_region(&self) -> Option<AhciDataDmaRegion> {
        match self.state {
            DataState::Idle => None,
            DataState::DeviceWrite(region)
            | DataState::DeviceRead(region)
            | DataState::AwaitingSanitize(region)
            | DataState::Uncertain(region) => Some(region),
        }
    }
}

impl<S: AhciDataBufferSync> AhciDataBufferIo for AhciMappedDataBuffer<'_, S> {
    fn prepare_read(&mut self, region: AhciDataDmaRegion) -> Result<(), ()> {
        if self.state != DataState::Idle {
            return Err(());
        }
        self.exact_bytes(region)?.fill(0);
        if self.sync.prepare_device_write(region).is_err() {
            self.state = DataState::Uncertain(region);
            return Err(());
        }
        self.state = DataState::DeviceWrite(region);
        Ok(())
    }

    fn prepare_write(&mut self, region: AhciDataDmaRegion, input: &[u8]) -> Result<(), ()> {
        if self.state != DataState::Idle || u64::try_from(input.len()).ok() != Some(region.bytes) {
            return Err(());
        }
        self.exact_bytes(region)?.copy_from_slice(input);
        if self.sync.prepare_device_read(region).is_err() {
            self.state = DataState::Uncertain(region);
            return Err(());
        }
        self.state = DataState::DeviceRead(region);
        Ok(())
    }

    fn complete_read(&mut self, region: AhciDataDmaRegion, output: &mut [u8]) -> Result<(), ()> {
        if self.state != DataState::DeviceWrite(region)
            || u64::try_from(output.len()).ok() != Some(region.bytes)
        {
            return Err(());
        }
        if self.sync.complete_device_write(region).is_err() {
            self.state = DataState::Uncertain(region);
            return Err(());
        }
        output.copy_from_slice(self.exact_bytes(region)?);
        self.state = DataState::AwaitingSanitize(region);
        Ok(())
    }

    fn complete_write(&mut self, region: AhciDataDmaRegion) -> Result<(), ()> {
        if self.state != DataState::DeviceRead(region) {
            return Err(());
        }
        if self.sync.complete_device_read(region).is_err() {
            self.state = DataState::Uncertain(region);
            return Err(());
        }
        self.state = DataState::AwaitingSanitize(region);
        Ok(())
    }

    fn sanitize(&mut self, region: AhciDataDmaRegion) -> Result<(), ()> {
        if self
            .expected_region()
            .is_some_and(|active| active != region)
        {
            return Err(());
        }
        self.exact_bytes(region)?.fill(0);
        if self.sync.publish_sanitized(region).is_err() {
            self.state = DataState::Uncertain(region);
            return Err(());
        }
        self.state = DataState::Idle;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_kernel::ObjectId;

    const PREPARE_WRITE: u8 = 1;
    const PREPARE_READ: u8 = 2;
    const COMPLETE_WRITE: u8 = 3;
    const COMPLETE_READ: u8 = 4;
    const SANITIZE: u8 = 5;

    #[derive(Default)]
    struct Sync {
        events: [u8; 8],
        count: usize,
        reject: Option<u8>,
    }

    impl Sync {
        fn event(&mut self, event: u8) -> Result<(), ()> {
            self.events[self.count] = event;
            self.count += 1;
            if self.reject == Some(event) {
                Err(())
            } else {
                Ok(())
            }
        }
    }

    impl AhciDataBufferSync for Sync {
        fn prepare_device_write(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> {
            self.event(PREPARE_WRITE)
        }
        fn prepare_device_read(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> {
            self.event(PREPARE_READ)
        }
        fn complete_device_write(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> {
            self.event(COMPLETE_WRITE)
        }
        fn complete_device_read(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> {
            self.event(COMPLETE_READ)
        }
        fn publish_sanitized(&mut self, _: AhciDataDmaRegion) -> Result<(), ()> {
            self.event(SANITIZE)
        }
    }

    fn region(bytes: u64) -> AhciDataDmaRegion {
        AhciDataDmaRegion {
            memory_object: ObjectId(9),
            allocation_generation: 7,
            physical_base: 0x4000,
            bytes,
        }
    }

    #[test]
    fn read_and_write_transitions_require_directional_sync_and_sanitization() {
        let full = region(1024);
        let transfer = region(512);
        let mut bytes = [0xa5; 1024];
        let mut buffer = AhciMappedDataBuffer::new(full, &mut bytes, Sync::default()).unwrap();
        buffer.prepare_read(transfer).unwrap();
        assert!(!buffer.is_available());
        buffer.bytes[..512].fill(0x5a);
        let mut output = [0; 512];
        buffer.complete_read(transfer, &mut output).unwrap();
        assert_eq!(output, [0x5a; 512]);
        buffer.sanitize(transfer).unwrap();
        assert!(buffer.is_available());
        buffer.prepare_write(transfer, &[0xcc; 512]).unwrap();
        buffer.complete_write(transfer).unwrap();
        buffer.sanitize(transfer).unwrap();
        let (bytes, sync) = buffer.into_clean_parts().ok().unwrap();
        assert!(bytes[..512].iter().all(|byte| *byte == 0));
        assert_eq!(
            &sync.events[..sync.count],
            &[
                PREPARE_WRITE,
                COMPLETE_WRITE,
                SANITIZE,
                PREPARE_READ,
                COMPLETE_READ,
                SANITIZE,
            ]
        );
    }

    #[test]
    fn substituted_regions_lengths_and_operation_order_fail_before_sync() {
        let full = region(1024);
        let transfer = region(512);
        let mut bytes = [0; 1024];
        let mut buffer = AhciMappedDataBuffer::new(full, &mut bytes, Sync::default()).unwrap();
        let substituted = AhciDataDmaRegion {
            allocation_generation: 8,
            ..transfer
        };
        assert_eq!(buffer.prepare_read(substituted), Err(()));
        assert_eq!(buffer.prepare_write(transfer, &[0; 511]), Err(()));
        assert_eq!(buffer.complete_write(transfer), Err(()));
        assert_eq!(buffer.sync.count, 0);
        buffer.prepare_read(transfer).unwrap();
        assert_eq!(buffer.complete_write(transfer), Err(()));
        assert_eq!(buffer.sanitize(region(256)), Err(()));
        assert_eq!(buffer.sync.count, 1);
    }

    #[test]
    fn synchronization_uncertainty_retains_unavailable_state_until_exact_cleanup() {
        let full = region(1024);
        let transfer = region(512);
        let mut bytes = [0xa5; 1024];
        let sync = Sync {
            reject: Some(COMPLETE_WRITE),
            ..Sync::default()
        };
        let mut buffer = AhciMappedDataBuffer::new(full, &mut bytes, sync).unwrap();
        buffer.prepare_read(transfer).unwrap();
        assert_eq!(buffer.complete_read(transfer, &mut [0; 512]), Err(()));
        assert!(!buffer.is_available());
        assert!(buffer.into_clean_parts().is_err());

        let mut bytes = [0xa5; 1024];
        let sync = Sync {
            reject: Some(COMPLETE_WRITE),
            ..Sync::default()
        };
        let mut buffer = AhciMappedDataBuffer::new(full, &mut bytes, sync).unwrap();
        buffer.prepare_read(transfer).unwrap();
        assert_eq!(buffer.complete_read(transfer, &mut [0; 512]), Err(()));
        buffer.sync.reject = None;
        buffer.sanitize(transfer).unwrap();
        assert!(buffer.is_available());
        assert!(buffer.bytes[..512].iter().all(|byte| *byte == 0));
    }
}
