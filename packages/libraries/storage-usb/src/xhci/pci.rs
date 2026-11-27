//! Read-only PCI identity and BAR checks for the native xHCI admission path.
//! A matching descriptor is evidence, not permission to map or enable DMA.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciLocation {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

/// Captured under one exclusive PCI assignment. The enumerator supplies BAR0's
/// length from its resource record, not from an xHCI register or a driver guess.
/// BARs in the sample are the restored (assigned) values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciSnapshot {
    pub location: PciLocation,
    pub configuration_generation: u64,
    pub vendor_device: u32,
    pub class_revision: u32,
    pub header_type: u8,
    pub command: u16,
    pub bar0: u32,
    pub bar1: u32,
    pub bar0_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciController {
    location: PciLocation,
    generation: u64,
    vendor_device: u32,
    class_revision: u32,
    header_type: u8,
    bar0_attributes: u8,
    bar0_base: u64,
    bar0_bytes: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PciError {
    InvalidIdentity,
    NotXhci,
    BarGeometry,
    AssignmentChanged,
    BusMasterEnabled,
    CommandMismatch,
}

impl PciController {
    pub fn discover(snapshot: PciSnapshot) -> Result<Self, PciError> {
        if snapshot.location.device > 31
            || snapshot.location.function > 7
            || snapshot.configuration_generation == 0
            || matches!(snapshot.vendor_device as u16, 0 | u16::MAX)
        {
            return Err(PciError::InvalidIdentity);
        }
        if snapshot.header_type & 0x7f != 0 || snapshot.class_revision >> 8 != 0x0c0330 {
            return Err(PciError::NotXhci);
        }
        let (upper, address_limit) = match snapshot.bar0 & 0xf {
            0 => (0, Some(1u64 << 32)),
            4 => (u64::from(snapshot.bar1) << 32, None),
            _ => return Err(PciError::BarGeometry),
        };
        let bar0_base = upper | u64::from(snapshot.bar0 & !0xf);
        let bar0_bytes = u32::try_from(snapshot.bar0_bytes).map_err(|_| PciError::BarGeometry)?;
        let bar_end = bar0_base
            .checked_add(snapshot.bar0_bytes)
            .ok_or(PciError::BarGeometry)?;
        if bar0_base == 0
            || bar0_bytes < 4096
            || !bar0_bytes.is_power_of_two()
            || bar0_base % u64::from(bar0_bytes) != 0
            || address_limit.is_some_and(|limit| bar_end > limit)
        {
            return Err(PciError::BarGeometry);
        }
        Ok(Self {
            location: snapshot.location,
            generation: snapshot.configuration_generation,
            vendor_device: snapshot.vendor_device,
            class_revision: snapshot.class_revision,
            header_type: snapshot.header_type,
            bar0_attributes: (snapshot.bar0 & 0xf) as u8,
            bar0_base,
            bar0_bytes,
        })
    }

    pub(super) fn verify_identity(&self, observed: PciSnapshot) -> Result<(), PciError> {
        if Self::discover(observed)? == *self {
            Ok(())
        } else {
            Err(PciError::AssignmentChanged)
        }
    }

    pub const fn bar0(&self) -> (u64, u32) {
        (self.bar0_base, self.bar0_bytes)
    }

    /// Check again under the lock that will protect assignment and activation.
    /// A stale snapshot cannot establish ownership or supply that lock.
    pub fn verify_unarmed(&self, observed: PciSnapshot) -> Result<(), PciError> {
        self.verify_identity(observed)?;
        if observed.command & (1 << 2) != 0 {
            return Err(PciError::BusMasterEnabled);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> PciSnapshot {
        PciSnapshot {
            location: PciLocation {
                segment: 0,
                bus: 0,
                device: 3,
                function: 0,
            },
            configuration_generation: 1,
            vendor_device: 0x000d_1b36,
            class_revision: 0x0c03_3001,
            header_type: 0,
            command: 0,
            bar0: 0xfeb0_0004,
            bar1: 1,
            bar0_bytes: 0x4000,
        }
    }

    #[test]
    fn only_exact_unarmed_assignment_is_accepted() {
        let original = snapshot();
        let controller = PciController::discover(original).unwrap();
        assert_eq!(controller.bar0(), (0x1_feb0_0000, 0x4000));
        assert_eq!(controller.verify_unarmed(original), Ok(()));
        for changed in [
            PciSnapshot {
                configuration_generation: 2,
                ..original
            },
            PciSnapshot {
                location: PciLocation {
                    segment: 1,
                    ..original.location
                },
                ..original
            },
            PciSnapshot {
                location: PciLocation {
                    bus: 1,
                    ..original.location
                },
                ..original
            },
            PciSnapshot {
                location: PciLocation {
                    function: 1,
                    ..original.location
                },
                ..original
            },
            PciSnapshot {
                vendor_device: 0x000e_1b36,
                ..original
            },
            PciSnapshot {
                bar1: 2,
                ..original
            },
            PciSnapshot {
                bar0_bytes: 0x8000,
                ..original
            },
        ] {
            assert_eq!(
                controller.verify_unarmed(changed),
                Err(PciError::AssignmentChanged)
            );
        }
        assert_eq!(
            controller.verify_unarmed(PciSnapshot {
                command: 4,
                ..original
            }),
            Err(PciError::BusMasterEnabled)
        );
    }

    #[test]
    fn rejects_absent_functions_and_wrong_class_or_header() {
        let original = snapshot();
        for invalid in [
            PciSnapshot {
                vendor_device: u32::MAX,
                ..original
            },
            PciSnapshot {
                configuration_generation: 0,
                ..original
            },
            PciSnapshot {
                location: PciLocation {
                    device: 32,
                    ..original.location
                },
                ..original
            },
        ] {
            assert_eq!(
                PciController::discover(invalid),
                Err(PciError::InvalidIdentity)
            );
        }
        for invalid in [
            PciSnapshot {
                class_revision: 0x0c03_2000,
                ..original
            },
            PciSnapshot {
                header_type: 1,
                ..original
            },
        ] {
            assert_eq!(PciController::discover(invalid), Err(PciError::NotXhci));
        }
    }

    #[test]
    fn accepts_only_nonprefetchable_aligned_bounded_memory_bars() {
        let original = snapshot();
        let bits32 = PciSnapshot {
            bar0: 0xfeb0_0000,
            ..original
        };
        assert_eq!(
            PciController::discover(bits32).unwrap().bar0(),
            (0xfeb0_0000, 0x4000)
        );
        for invalid in [
            PciSnapshot {
                bar0: 1,
                ..original
            },
            PciSnapshot {
                bar0: original.bar0 | 8,
                ..original
            },
            PciSnapshot {
                bar0: original.bar0 | 0x1000,
                ..original
            },
            PciSnapshot {
                bar0: 0xffff_c004,
                bar1: u32::MAX,
                ..original
            },
            PciSnapshot {
                bar0_bytes: 0x3000,
                ..original
            },
            PciSnapshot {
                bar0_bytes: 1u64 << 32,
                ..original
            },
        ] {
            assert_eq!(PciController::discover(invalid), Err(PciError::BarGeometry));
        }
    }
}
