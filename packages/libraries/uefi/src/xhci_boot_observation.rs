//! Correlates copied USB diagnostic observations across firmware exit.
//! This module does not read hardware, create mappings, or grant ownership.

use super::inspect_bar0;

pub const BOOT_XHCI_RECORD_BYTES: usize = 40;
const RECORD_MAGIC: &[u8; 8] = b"MRMLXHCI";
const RECORD_VERSION: u16 = 1;

/// Untrusted diagnostic bytes decoded as an observation, never as a
/// firmware-validated snapshot or as permission to read/write registers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedBootXhci(RetainedBootXhci);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootXhciRecordError {
    BadLength,
    BadMagic,
    UnsupportedVersion,
    ReservedBits,
    InvalidFunction,
    InvalidRange,
    UnexpectedFunction,
}

fn valid_function(function: XhciFunction) -> bool {
    !matches!(function.vendor_device as u16, 0 | u16::MAX)
        && function.class_revision >> 8 == 0x0c0330
}

impl DecodedBootXhci {
    /// Decode only canonical V1 fields for the independently identified
    /// boot controller. A valid record proves no source or ownership.
    pub fn decode(
        bytes: &[u8],
        expected: XhciFunction,
    ) -> Result<Self, BootXhciRecordError> {
        let bytes: &[u8; BOOT_XHCI_RECORD_BYTES] = bytes
            .try_into()
            .map_err(|_| BootXhciRecordError::BadLength)?;
        let u16_at = |offset| u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
        let u32_at = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        if &bytes[..8] != RECORD_MAGIC {
            return Err(BootXhciRecordError::BadMagic);
        }
        if u16_at(8) != RECORD_VERSION {
            return Err(BootXhciRecordError::UnsupportedVersion);
        }
        if usize::from(u16_at(10)) != BOOT_XHCI_RECORD_BYTES {
            return Err(BootXhciRecordError::BadLength);
        }
        if bytes[36..] != [0; 4] {
            return Err(BootXhciRecordError::ReservedBits);
        }
        let function = XhciFunction {
            requester: u32_at(12),
            vendor_device: u32_at(16),
            class_revision: u32_at(20),
        };
        if !valid_function(function) {
            return Err(BootXhciRecordError::InvalidFunction);
        }
        if function != expected {
            return Err(BootXhciRecordError::UnexpectedFunction);
        }
        let bar_base = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        let bar_bytes = u32_at(32);
        if bar_base == 0
            || bar_bytes < 0x20
            || !bar_bytes.is_power_of_two()
            || !bar_base.is_multiple_of(u64::from(bar_bytes))
            || bar_base.checked_add(u64::from(bar_bytes)).is_none()
        {
            return Err(BootXhciRecordError::InvalidRange);
        }
        Ok(Self(RetainedBootXhci { function, bar_base, bar_bytes }))
    }

    /// Compare with separately gathered diagnostic evidence. In particular,
    /// the address in this record does not establish safe MMIO coverage.
    pub fn correlate(self, post: PostExitXhci) -> Result<CorrelatedBootXhci, CorrelationError> {
        self.0.correlate(post)
    }
}

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
        if usb_boot_requester != Some(function.requester) || !valid_function(function) {
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

    /// Serialize copied observation fields; the record is not authenticated.
    pub fn encode(self) -> [u8; BOOT_XHCI_RECORD_BYTES] {
        let mut bytes = [0; BOOT_XHCI_RECORD_BYTES];
        bytes[..8].copy_from_slice(RECORD_MAGIC);
        bytes[8..10].copy_from_slice(&RECORD_VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&(BOOT_XHCI_RECORD_BYTES as u16).to_le_bytes());
        bytes[12..16].copy_from_slice(&self.function.requester.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.function.vendor_device.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.function.class_revision.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.bar_base.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.bar_bytes.to_le_bytes());
        bytes
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

    #[test]
    fn record_is_canonical_and_still_requires_independent_post_exit_evidence() {
        let encoded = retained().encode();
        assert_eq!(
            encoded,
            *b"MRMLXHCI\x01\x00\x28\x00\xa0\x00\x00\x00\x86\x80\xed\x02\x00\x30\x03\x0c\x00\x00\xef\xce\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00"
        );
        let observed = DecodedBootXhci::decode(&encoded, FUNCTION).unwrap();
        assert_eq!(observed.correlate(POST), retained().correlate(POST));
        assert_eq!(
            observed.correlate(PostExitXhci { observed_bar: None, ..POST }),
            Err(CorrelationError::BarUnverifiedOrChanged),
        );
    }

    #[test]
    fn rejects_noncanonical_records_and_substitution() {
        let encoded = retained().encode();
        for length in 0..BOOT_XHCI_RECORD_BYTES {
            assert_eq!(
                DecodedBootXhci::decode(&encoded[..length], FUNCTION),
                Err(BootXhciRecordError::BadLength)
            );
        }
        let mut oversized = [0; BOOT_XHCI_RECORD_BYTES + 1];
        oversized[..BOOT_XHCI_RECORD_BYTES].copy_from_slice(&encoded);
        assert_eq!(DecodedBootXhci::decode(&oversized, FUNCTION), Err(BootXhciRecordError::BadLength));
        for (offset, value, error) in [
            (0, 0, BootXhciRecordError::BadMagic),
            (8, 2, BootXhciRecordError::UnsupportedVersion),
            (10, 39, BootXhciRecordError::BadLength),
            (13, 1, BootXhciRecordError::UnexpectedFunction),
            (16, 0x87, BootXhciRecordError::UnexpectedFunction),
            (20, 1, BootXhciRecordError::UnexpectedFunction),
            (21, 0, BootXhciRecordError::InvalidFunction),
            (24, 1, BootXhciRecordError::InvalidRange),
            (32, 1, BootXhciRecordError::InvalidRange),
            (39, 1, BootXhciRecordError::ReservedBits),
        ] {
            let mut bad = encoded;
            bad[offset] = value;
            assert_eq!(DecodedBootXhci::decode(&bad, FUNCTION), Err(error), "offset {offset}");
        }
        let mut bad = encoded;
        bad[24..32].copy_from_slice(&0xffff_ffff_ffff_0000u64.to_le_bytes());
        assert_eq!(DecodedBootXhci::decode(&bad, FUNCTION), Err(BootXhciRecordError::InvalidRange));
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
