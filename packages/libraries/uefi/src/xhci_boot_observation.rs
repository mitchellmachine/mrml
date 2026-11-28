//! Correlates copied USB diagnostic observations across firmware exit.
//! This module does not read hardware, create mappings, or grant ownership.

use super::inspect_bar0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XhciFunction {
    /// PCI segment in bits 31:16, bus in 15:8, device/function in 7:0.
    pub requester: u32,
    pub vendor_device: u32,
    pub class_revision: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedBootXhci {
    function: XhciFunction,
    bar_base: u64,
    bar_bytes: u32,
}

/// A later sample copied by a caller, not proof the caller read safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostExitXhci {
    pub function: XhciFunction,
    pub firmware_exited: bool,
    pub pci_command: u16,
    /// Exact physical extent independently checked by the read-only observer.
    pub observed_bar: Option<(u64, u32)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorrelationError {
    FirmwareExitUnproven,
    ChangedFunction,
    MemoryDecodeDisabled,
    BarUnverifiedOrChanged,
}

/// Facts for a read-only report; there is deliberately no successful
/// ownership, boot-source retirement, or DMA-isolation verdict here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorrelatedBootXhci {
    pub bus_master_enabled: bool,
}

impl RetainedBootXhci {
    /// Retain only the positively identified USB boot requester and the
    /// firmware-validated BAR allocation. A different USB controller,
    /// an unresolved boot source, and a non-USB source are not equivalent.
    pub fn from_firmware(
        usb_boot_requester: Option<u32>,
        function: XhciFunction,
        command: u16,
        header: u8,
        bar_low: u32,
        bar_high: u32,
        resource: &[u8],
    ) -> Option<Self> {
        let vendor = function.vendor_device as u16;
        if usb_boot_requester != Some(function.requester)
            || matches!(vendor, 0 | u16::MAX)
            || function.class_revision >> 8 != 0x0c0330
        {
            return None;
        }
        let (bar_base, bar_bytes) = inspect_bar0(command, header, bar_low, bar_high, resource)?;
        Some(Self {
            function,
            bar_base,
            bar_bytes,
        })
    }

    /// Pointer-free fields for an observation report, not a mapping request.
    pub fn diagnostic_fields(self) -> (XhciFunction, u64, u32) {
        (self.function, self.bar_base, self.bar_bytes)
    }

    /// Compare copied facts only. A matching extent is not safe MMIO
    /// coverage by itself, and BME off alone never implies DMA denial.
    pub fn correlate(self, post: PostExitXhci) -> Result<CorrelatedBootXhci, CorrelationError> {
        if !post.firmware_exited {
            return Err(CorrelationError::FirmwareExitUnproven);
        }
        if post.function != self.function {
            return Err(CorrelationError::ChangedFunction);
        }
        if post.pci_command & 2 == 0 {
            return Err(CorrelationError::MemoryDecodeDisabled);
        }
        if post.observed_bar != Some((self.bar_base, self.bar_bytes)) {
            return Err(CorrelationError::BarUnverifiedOrChanged);
        }
        Ok(CorrelatedBootXhci {
            bus_master_enabled: post.pci_command & 4 != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xhci_inventory::{BAR_RESOURCE_BYTES, BAR_RESOURCE_HEADER};

    const FUNCTION: XhciFunction = XhciFunction {
        requester: 0x00a0,
        vendor_device: 0x02ed_8086,
        class_revision: 0x0c03_3000,
    };
    const BASE: u64 = 0xceef_0000;
    const LENGTH: u32 = 0x1_0000;

    fn resource() -> [u8; BAR_RESOURCE_BYTES] {
        let mut bytes = [0; BAR_RESOURCE_BYTES];
        bytes[..3].copy_from_slice(&BAR_RESOURCE_HEADER);
        bytes[6..14].copy_from_slice(&64u64.to_le_bytes());
        bytes[14..22].copy_from_slice(&BASE.to_le_bytes());
        bytes[38..46].copy_from_slice(&u64::from(LENGTH).to_le_bytes());
        bytes[46] = 0x79;
        bytes
    }

    fn retained() -> RetainedBootXhci {
        RetainedBootXhci::from_firmware(
            Some(FUNCTION.requester),
            FUNCTION,
            6,
            0,
            BASE as u32 | 4,
            0,
            &resource(),
        )
        .unwrap()
    }

    const POST: PostExitXhci = PostExitXhci {
        function: FUNCTION,
        firmware_exited: true,
        pci_command: 6,
        observed_bar: Some((BASE, LENGTH)),
    };

    #[test]
    fn retain_only_the_exact_usb_boot_function_and_firmware_bar() {
        for requester in [None, Some(0x00a1), Some(0x0001_00a0)] {
            assert_eq!(
                RetainedBootXhci::from_firmware(
                    requester,
                    FUNCTION,
                    6,
                    0,
                    BASE as u32 | 4,
                    0,
                    &resource(),
                ),
                None
            );
        }
        assert_eq!(
            RetainedBootXhci::from_firmware(
                Some(FUNCTION.requester),
                FUNCTION,
                6,
                0,
                (BASE + u64::from(LENGTH)) as u32 | 4,
                0,
                &resource(),
            ),
            None
        );
    }

    #[test]
    fn rejects_substituted_function_or_revision() {
        for function in [
            XhciFunction {
                requester: 0x0001_00a0,
                ..FUNCTION
            },
            XhciFunction {
                requester: 0x00a1,
                ..FUNCTION
            },
            XhciFunction {
                vendor_device: 0x000d_1b36,
                ..FUNCTION
            },
            XhciFunction {
                class_revision: 0x0c03_3001,
                ..FUNCTION
            },
        ] {
            assert_eq!(
                retained().correlate(PostExitXhci { function, ..POST }),
                Err(CorrelationError::ChangedFunction)
            );
        }
    }

    #[test]
    fn requires_firmware_exit_and_current_decode_with_an_exact_extent() {
        assert_eq!(
            retained().correlate(PostExitXhci {
                firmware_exited: false,
                ..POST
            }),
            Err(CorrelationError::FirmwareExitUnproven)
        );
        assert_eq!(
            retained().correlate(PostExitXhci {
                pci_command: 4,
                ..POST
            }),
            Err(CorrelationError::MemoryDecodeDisabled)
        );
        for observed_bar in [
            None,
            Some((BASE, LENGTH / 2)),
            Some((BASE, LENGTH * 2)),
            Some((BASE + u64::from(LENGTH), LENGTH)),
        ] {
            assert_eq!(
                retained().correlate(PostExitXhci {
                    observed_bar,
                    ..POST
                }),
                Err(CorrelationError::BarUnverifiedOrChanged)
            );
        }
    }

    #[test]
    fn reports_bus_master_state_without_authorizing_any_transition() {
        assert_eq!(
            retained().correlate(POST),
            Ok(CorrelatedBootXhci {
                bus_master_enabled: true
            })
        );
        assert_eq!(
            retained().correlate(PostExitXhci {
                pci_command: 2,
                ..POST
            }),
            Ok(CorrelatedBootXhci {
                bus_master_enabled: false
            })
        );
    }
}
