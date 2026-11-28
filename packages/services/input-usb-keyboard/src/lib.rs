#![no_std]
#![forbid(unsafe_code)]

//! USB HID boot keyboard, Appendix B.1 of USB HID 1.11.
//! An external USB function service verifies the interface and selects boot
//! protocol before forwarding complete interrupt-IN reports. This decoder
//! exposes key usages, not characters, and grants no input routing authority.

mod function;
pub use function::{DescriptorError, KeyboardFunction, UsbKeyboardSpeed, find_keyboard_function};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyboardError {
    UnsupportedInterface,
    WrongReportLength,
    ErrorUsage(u8),
    DuplicateUsage(u8),
    ModifierInKeyArray(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyboardReport {
    pub modifiers: u8,
    pub usages: [u8; 6],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootKeyboard(());

impl BootKeyboard {
    /// The protocol selection result must come from the owning USB service,
    /// not from the peripheral's interface descriptor alone.
    pub fn bind(
        class: u8,
        subclass: u8,
        protocol: u8,
        boot_selected: bool,
    ) -> Result<Self, KeyboardError> {
        if (class, subclass, protocol) != (3, 1, 1) || !boot_selected {
            return Err(KeyboardError::UnsupportedInterface);
        }
        Ok(Self(()))
    }

    /// Canonicalize the unordered array. Zero means no usage; byte 1 is
    /// reserved for OEM use and is not interpreted as an input.
    pub fn decode(self, report: &[u8]) -> Result<KeyboardReport, KeyboardError> {
        let bytes: &[u8; 8] = report
            .try_into()
            .map_err(|_| KeyboardError::WrongReportLength)?;
        let mut usages = [0; 6];
        for (index, usage) in bytes[2..].iter().copied().enumerate() {
            if (1..=3).contains(&usage) {
                // Rollover, POST failure and undefined error must not trigger
                // presses or synthesize an all-keys-released report.
                return Err(KeyboardError::ErrorUsage(usage));
            }
            if (0xe0..=0xe7).contains(&usage) {
                return Err(KeyboardError::ModifierInKeyArray(usage));
            }
            if usage != 0 && usages[..index].contains(&usage) {
                return Err(KeyboardError::DuplicateUsage(usage));
            }
            usages[index] = usage;
        }
        usages.sort_unstable();
        Ok(KeyboardReport {
            modifiers: bytes[0],
            usages,
        })
    }
}

/// A single newly pressed keyboard usage on a validated boot-protocol stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyPress {
    pub usage: u8,
    pub modifiers: u8,
}

/// Bounded edge tracking for the first interactive keyboard route. The
/// transport owner must reset this on replacement, a gap or revocation.
pub struct BootKeyStream {
    keyboard: BootKeyboard,
    previous: KeyboardReport,
    armed: bool,
}

impl BootKeyStream {
    pub const fn new(keyboard: BootKeyboard) -> Self {
        Self {
            keyboard,
            previous: KeyboardReport {
                modifiers: 0,
                usages: [0; 6],
            },
            armed: false,
        }
    }

    pub fn reset(&mut self) {
        self.armed = false;
    }

    pub fn ingest(&mut self, bytes: &[u8]) -> Result<Option<KeyPress>, KeyboardError> {
        let report = match self.keyboard.decode(bytes) {
            Ok(report) => report,
            Err(error) => {
                self.reset();
                return Err(error);
            }
        };
        if !self.armed {
            self.armed = report.modifiers == 0 && report.usages == [0; 6];
            self.previous = report;
            return Ok(None);
        }
        let usage = report.usages[5];
        // One ordinary key at a time; unordered chords have no text order.
        // Holding a key or changing modifiers alone cannot manufacture input.
        let press = (usage != 0 && report.usages[4] == 0 && !self.previous.usages.contains(&usage))
            .then_some(KeyPress {
                usage,
                modifiers: report.modifiers,
            });
        self.previous = report;
        Ok(press)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edges_require_neutral_after_attach_reset_and_malformed_reports() {
        let mut stream = BootKeyStream::new(BootKeyboard::bind(3, 1, 1, true).unwrap());
        let a = [0, 0, 4, 0, 0, 0, 0, 0];
        let shifted_a = [2, 0, 4, 0, 0, 0, 0, 0];
        assert_eq!(stream.ingest(&a), Ok(None));
        assert_eq!(stream.ingest(&[0; 8]), Ok(None));
        assert_eq!(
            stream.ingest(&a),
            Ok(Some(KeyPress {
                usage: 4,
                modifiers: 0
            }))
        );
        assert_eq!(stream.ingest(&a), Ok(None));
        assert_eq!(stream.ingest(&shifted_a), Ok(None));
        assert!(stream.ingest(&[0, 0, 1, 0, 0, 0, 0, 0]).is_err());
        assert_eq!(stream.ingest(&a), Ok(None));
        assert_eq!(stream.ingest(&[0; 8]), Ok(None));
        assert_eq!(
            stream.ingest(&shifted_a),
            Ok(Some(KeyPress {
                usage: 4,
                modifiers: 2
            }))
        );
        stream.reset();
        assert_eq!(stream.ingest(&a), Ok(None));
    }

    #[test]
    fn chord_and_subsequent_partial_release_do_not_manufacture_text() {
        let mut stream = BootKeyStream::new(BootKeyboard::bind(3, 1, 1, true).unwrap());
        assert_eq!(stream.ingest(&[0; 8]), Ok(None));
        assert_eq!(stream.ingest(&[0, 0, 40, 4, 0, 0, 0, 0]), Ok(None));
        assert_eq!(stream.ingest(&[0, 0, 40, 0, 0, 0, 0, 0]), Ok(None));
        assert_eq!(stream.ingest(&[0; 8]), Ok(None));
        assert_eq!(
            stream.ingest(&[0, 0, 40, 0, 0, 0, 0, 0]),
            Ok(Some(KeyPress {
                usage: 40,
                modifiers: 0
            }))
        );
    }

    #[test]
    fn requires_keyboard_interface_and_successful_boot_selection() {
        for args in [
            (2, 1, 1, true),
            (3, 0, 1, true),
            (3, 1, 2, true),
            (3, 1, 1, false),
        ] {
            assert_eq!(
                BootKeyboard::bind(args.0, args.1, args.2, args.3),
                Err(KeyboardError::UnsupportedInterface)
            );
        }
    }

    #[test]
    fn decodes_unordered_usages_and_ignores_oem_byte() {
        let boot = BootKeyboard::bind(3, 1, 1, true).unwrap();
        assert_eq!(
            boot.decode(&[2, 255, 30, 0, 4, 0, 0, 0]),
            Ok(KeyboardReport {
                modifiers: 2,
                usages: [0, 0, 0, 0, 4, 30]
            })
        );
        assert_eq!(
            boot.decode(&[0; 8]),
            Ok(KeyboardReport {
                modifiers: 0,
                usages: [0; 6]
            })
        );
    }

    #[test]
    fn rejects_malformed_and_rollover_instead_of_releasing_everything() {
        let boot = BootKeyboard::bind(3, 1, 1, true).unwrap();
        assert_eq!(boot.decode(&[0; 7]), Err(KeyboardError::WrongReportLength));
        assert_eq!(boot.decode(&[0; 9]), Err(KeyboardError::WrongReportLength));
        for err in 1..=3 {
            assert_eq!(
                boot.decode(&[0, 0, 4, 0, err, 0, 0, 0]),
                Err(KeyboardError::ErrorUsage(err))
            );
        }
        assert_eq!(
            boot.decode(&[0, 0, 4, 0, 4, 0, 0, 0]),
            Err(KeyboardError::DuplicateUsage(4))
        );
        assert_eq!(
            boot.decode(&[0, 0, 0xe1, 0, 0, 0, 0, 0]),
            Err(KeyboardError::ModifierInKeyArray(0xe1))
        );
    }
}
