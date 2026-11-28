#![no_std]
#![forbid(unsafe_code)]

//! USB HID boot mouse, Appendix B.2 of USB HID 1.11. The owning USB service
//! selects boot protocol and sends complete interrupt-IN reports; this core
//! only decodes the relative pointer and three boot buttons.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MouseError {
    UnsupportedInterface,
    WrongReportLength,
    DeltaOutsideBootRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MouseReport {
    /// Bit 0 left, bit 1 right, bit 2 middle.
    pub buttons: u8,
    /// Signed device counts, positive to the right.
    pub dx: i8,
    /// Signed device counts, positive downward.
    pub dy: i8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootMouse(());

impl BootMouse {
    /// The boot protocol selection result is supplied by the owning USB
    /// function service, not asserted by the device report.
    pub fn bind(
        class: u8,
        subclass: u8,
        protocol: u8,
        boot_selected: bool,
    ) -> Result<Self, MouseError> {
        if (class, subclass, protocol) != (3, 1, 2) || !boot_selected {
            return Err(MouseError::UnsupportedInterface);
        }
        Ok(Self(()))
    }

    /// HID 1.11 permits trailing boot extensions through byte 8. Ignore
    /// them, and padding in the button byte: no wheel or fourth button is
    /// inferred without a validated report-protocol descriptor.
    pub fn decode(self, report: &[u8]) -> Result<MouseReport, MouseError> {
        if !(3..=8).contains(&report.len()) {
            return Err(MouseError::WrongReportLength);
        }
        let dx = report[1] as i8;
        let dy = report[2] as i8;
        if dx == i8::MIN || dy == i8::MIN {
            return Err(MouseError::DeltaOutsideBootRange);
        }
        Ok(MouseReport {
            buttons: report[0] & 7,
            dx,
            dy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_supported_relative_axes_and_buttons() {
        let boot = BootMouse::bind(3, 1, 2, true).unwrap();
        assert_eq!(
            boot.decode(&[0xfd, 0x81, 127]),
            Ok(MouseReport {
                buttons: 5,
                dx: -127,
                dy: 127
            })
        );
        assert_eq!(
            boot.decode(&[0xfc, 5, 0xfb, 0xff]),
            Ok(MouseReport {
                buttons: 4,
                dx: 5,
                dy: -5
            })
        );
    }

    #[test]
    fn rejects_missing_protocol_short_oversize_and_invalid_axis() {
        assert_eq!(
            BootMouse::bind(3, 1, 1, true),
            Err(MouseError::UnsupportedInterface)
        );
        assert_eq!(
            BootMouse::bind(3, 1, 2, false),
            Err(MouseError::UnsupportedInterface)
        );
        let boot = BootMouse::bind(3, 1, 2, true).unwrap();
        assert_eq!(boot.decode(&[0, 0]), Err(MouseError::WrongReportLength));
        assert_eq!(boot.decode(&[0; 9]), Err(MouseError::WrongReportLength));
        assert_eq!(
            boot.decode(&[0, 0x80, 0]),
            Err(MouseError::DeltaOutsideBootRange)
        );
        assert_eq!(
            boot.decode(&[0, 0, 0x80]),
            Err(MouseError::DeltaOutsideBootRange)
        );
    }
}
