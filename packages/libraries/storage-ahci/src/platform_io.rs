//! Composition of launch-bound AHCI register access and monotonic delay.

use crate::{AhciAbarMapping, AhciRegisterIo, AhciResetIo, NativeAhciRegisterIo};

/// Platform-owned monotonic delay used only for bounded AHCI timing.
pub trait AhciMonotonicDelay {
    /// Returns only after at least `microseconds` elapsed monotonically.
    fn delay_at_least_microseconds(&mut self, microseconds: u32) -> Result<(), ()>;
}

/// One owner for register and timing mechanism required by AHCI dispatch.
pub struct AhciPlatformIo<R, D> {
    registers: R,
    delay: D,
}

impl<R, D> AhciPlatformIo<R, D> {
    pub const fn new(registers: R, delay: D) -> Self {
        Self { registers, delay }
    }

    pub fn into_parts(self) -> (R, D) {
        (self.registers, self.delay)
    }
}

impl<D> AhciPlatformIo<NativeAhciRegisterIo, D> {
    /// Constructs the volatile register half from the authenticated mapping.
    ///
    /// # Safety
    ///
    /// The caller must satisfy [`NativeAhciRegisterIo::new`] for `mapping` and
    /// retain exclusive assignment until this owner is consumed.
    pub unsafe fn from_installed_mapping(mapping: AhciAbarMapping, delay: D) -> Option<Self> {
        let registers = unsafe { NativeAhciRegisterIo::new(mapping) }?;
        Some(Self::new(registers, delay))
    }
}

impl<R: AhciRegisterIo, D> AhciRegisterIo for AhciPlatformIo<R, D> {
    fn read_u32(&mut self, offset: u32) -> Result<u32, ()> {
        self.registers.read_u32(offset)
    }

    fn write_u32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
        self.registers.write_u32(offset, value)
    }
}

impl<R: AhciRegisterIo, D: AhciMonotonicDelay> AhciResetIo for AhciPlatformIo<R, D> {
    fn delay_microseconds(&mut self, microseconds: u32) -> Result<(), ()> {
        self.delay.delay_at_least_microseconds(microseconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_kernel::ObjectId;

    #[derive(Default)]
    struct Registers {
        value: u32,
        reads: usize,
        writes: usize,
    }

    impl AhciRegisterIo for Registers {
        fn read_u32(&mut self, offset: u32) -> Result<u32, ()> {
            assert_eq!(offset, 0x118);
            self.reads += 1;
            Ok(self.value)
        }

        fn write_u32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
            assert_eq!(offset, 0x118);
            self.writes += 1;
            self.value = value;
            Ok(())
        }
    }

    #[derive(Default)]
    struct Delay {
        requested: u32,
        reject: bool,
    }

    impl AhciMonotonicDelay for Delay {
        fn delay_at_least_microseconds(&mut self, microseconds: u32) -> Result<(), ()> {
            self.requested = microseconds;
            if self.reject { Err(()) } else { Ok(()) }
        }
    }

    #[test]
    fn platform_owner_delegates_registers_and_exact_monotonic_delay() {
        let mut io = AhciPlatformIo::new(Registers::default(), Delay::default());
        io.write_u32(0x118, 0x11).unwrap();
        assert_eq!(io.read_u32(0x118), Ok(0x11));
        assert_eq!(io.delay_microseconds(1_000), Ok(()));
        let (registers, delay) = io.into_parts();
        assert_eq!((registers.reads, registers.writes), (1, 1));
        assert_eq!(delay.requested, 1_000);

        let mut rejected = AhciPlatformIo::new(
            Registers::default(),
            Delay { requested: 0, reject: true },
        );
        assert_eq!(rejected.delay_microseconds(77), Err(()));
        assert_eq!(rejected.into_parts().1.requested, 77);
    }

    #[test]
    fn native_platform_owner_rejects_invalid_register_mapping() {
        let invalid = AhciAbarMapping {
            device_object: ObjectId(1),
            configuration_generation: 2,
            mapping_generation: 3,
            physical_base: 0x1000,
            virtual_base: 0,
            bytes: 0x2000,
        };
        assert!(unsafe {
            AhciPlatformIo::from_installed_mapping(invalid, Delay::default())
        }
        .is_none());
    }
}
