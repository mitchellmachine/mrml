#![no_std]
#![forbid(unsafe_code)]

//! Bounded HID absolute-pointer decoder for the emulator tablet profile.
//! Report protocol only, without Report IDs, pen pressure or multitouch.
//! This is not a general HID descriptor interpreter or an input capability.

const DESKTOP: u16 = 1;
const BUTTON: u16 = 9;
const ABSOLUTE_MAX: u16 = 0x7fff;
const REPORT_BYTES: usize = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TabletError {
    UnsupportedInterface,
    UnsupportedDescriptor,
    WrongReportLength,
    OutOfRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TabletReport {
    /// Absolute device coordinates, 0 through 32767 inclusive on each axis.
    pub x: u16,
    pub y: u16,
    /// Low three or five bits according to the accepted descriptor.
    pub buttons: u8,
    /// Relative wheel counts, -127 through +127 inclusive.
    pub wheel: i8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbsoluteTablet {
    button_mask: u8,
}

// HID 1.11 §6.2.2 short-item encodings with at most two data bytes. The
// profile below checks each expected item and consumes the entire descriptor;
// no unknown or context-changing item is skipped.
struct Items<'a>(&'a [u8]);

impl Items<'_> {
    fn tag(&mut self, tag: u8) -> Option<u16> {
        let (&prefix, rest) = self.0.split_first()?;
        if prefix & !3 != tag || prefix & 3 > 2 {
            return None;
        }
        let count = usize::from(prefix & 3);
        let payload = rest.get(..count)?;
        self.0 = &rest[count..];
        Some(match payload {
            [] => 0,
            [lo] => u16::from(*lo),
            [lo, hi] => u16::from_le_bytes([*lo, *hi]),
            _ => return None,
        })
    }

    fn expect(&mut self, tag: u8, value: u16) -> Option<()> {
        // Every item except End Collection must have a nonempty payload.
        let prefix = *self.0.first()?;
        let count = prefix & 3;
        if (tag == END && count != 0) || (tag != END && count == 0) {
            return None;
        }
        (self.tag(tag)? == value).then_some(())
    }

    fn descriptor(&mut self) -> Option<u8> {
        let e = |items: &mut Self, pairs: &[(u8, u16)]| -> Option<()> {
            for &(tag, value) in pairs {
                items.expect(tag, value)?;
            }
            Some(())
        };
        e(
            self,
            &[
                (PAGE, DESKTOP),
                (USAGE, 2),
                (COLLECTION, 1),
                (USAGE, 1),
                (COLLECTION, 0),
                (PAGE, BUTTON),
                (USAGE_MIN, 1),
            ],
        )?;
        let buttons = self.tag(USAGE_MAX)?;
        if !matches!(buttons, 3 | 5) {
            return None;
        }
        e(
            self,
            &[
                (LOGICAL_MIN, 0),
                (LOGICAL_MAX, 1),
                (COUNT, buttons),
                (SIZE, 1),
                (INPUT, 2),
                (COUNT, 1),
                (SIZE, 8 - buttons),
                (INPUT, 1),
                (PAGE, DESKTOP),
                (USAGE, 0x30),
                (USAGE, 0x31),
                (LOGICAL_MIN, 0),
                (LOGICAL_MAX, ABSOLUTE_MAX),
                (PHYSICAL_MIN, 0),
                (PHYSICAL_MAX, ABSOLUTE_MAX),
                (SIZE, 16),
                (COUNT, 2),
                (INPUT, 2),
                (PAGE, DESKTOP),
                (USAGE, 0x38),
            ],
        )?;
        // HID interprets Logical Minimum as signed. Check the original
        // width so the positive two-byte value 0x0081 cannot match -127.
        match *self.0.first()? & 3 {
            1 => self.expect(LOGICAL_MIN, 0x81)?,
            2 => self.expect(LOGICAL_MIN, 0xff81)?,
            _ => return None,
        }
        e(
            self,
            &[
                (LOGICAL_MAX, 127),
                (PHYSICAL_MIN, 0),
                (PHYSICAL_MAX, 0),
                (SIZE, 8),
                (COUNT, 1),
                (INPUT, 6),
                (END, 0),
                (END, 0),
            ],
        )?;
        self.0.is_empty().then_some((1 << buttons) - 1)
    }
}

const PAGE: u8 = 0x04;
const USAGE: u8 = 0x08;
const LOGICAL_MIN: u8 = 0x14;
const USAGE_MIN: u8 = 0x18;
const LOGICAL_MAX: u8 = 0x24;
const USAGE_MAX: u8 = 0x28;
const PHYSICAL_MIN: u8 = 0x34;
const PHYSICAL_MAX: u8 = 0x44;
const SIZE: u8 = 0x74;
const INPUT: u8 = 0x80;
const COUNT: u8 = 0x94;
const COLLECTION: u8 = 0xa0;
const END: u8 = 0xc0;

impl AbsoluteTablet {
    /// The interface has the HID class, no boot subclass and no boot
    /// protocol. Only the checked descriptor determines the report layout.
    pub fn bind(
        class: u8,
        subclass: u8,
        protocol: u8,
        descriptor: &[u8],
    ) -> Result<Self, TabletError> {
        if (class, subclass, protocol) != (3, 0, 0) {
            return Err(TabletError::UnsupportedInterface);
        }
        let button_mask = Items(descriptor)
            .descriptor()
            .ok_or(TabletError::UnsupportedDescriptor)?;
        Ok(Self { button_mask })
    }

    pub fn decode(self, report: &[u8]) -> Result<TabletReport, TabletError> {
        let &[mask, x0, x1, y0, y1, wheel] =
            <&[u8; REPORT_BYTES]>::try_from(report).map_err(|_| TabletError::WrongReportLength)?;
        let x = u16::from_le_bytes([x0, x1]);
        let y = u16::from_le_bytes([y0, y1]);
        let wheel = wheel as i8;
        if x > ABSOLUTE_MAX || y > ABSOLUTE_MAX || wheel == i8::MIN {
            return Err(TabletError::OutOfRange);
        }
        Ok(TabletReport {
            x,
            y,
            buttons: mask & self.button_mask,
            wheel,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    // Assemble a standards-shaped descriptor from individual semantic items.
    fn fixture() -> Vec<u8> {
        let globals_and_fields = [
            (PAGE, 1),
            (USAGE, 2),
            (COLLECTION, 1),
            (USAGE, 1),
            (COLLECTION, 0),
            (PAGE, 9),
            (USAGE_MIN, 1),
            (USAGE_MAX, 5),
            (LOGICAL_MIN, 0),
            (LOGICAL_MAX, 1),
            (COUNT, 5),
            (SIZE, 1),
            (INPUT, 2),
            (COUNT, 1),
            (SIZE, 3),
            (INPUT, 1),
            (PAGE, 1),
            (USAGE, 0x30),
            (USAGE, 0x31),
            (LOGICAL_MIN, 0),
            (LOGICAL_MAX, 32767),
            (PHYSICAL_MIN, 0),
            (PHYSICAL_MAX, 32767),
            (SIZE, 16),
            (COUNT, 2),
            (INPUT, 2),
            (PAGE, 1),
            (USAGE, 0x38),
            (LOGICAL_MIN, 0x81),
            (LOGICAL_MAX, 127),
            (PHYSICAL_MIN, 0),
            (PHYSICAL_MAX, 0),
            (SIZE, 8),
            (COUNT, 1),
            (INPUT, 6),
        ];
        let mut descriptor = Vec::new();
        for (tag, value) in globals_and_fields {
            if value > 255 {
                descriptor.extend([tag | 2, value as u8, (value >> 8) as u8]);
            } else {
                descriptor.extend([tag | 1, value as u8]);
            }
        }
        descriptor.extend([END, END]);
        descriptor
    }

    #[test]
    fn accepts_absolute_coordinates_and_relative_wheel_only_for_bound_profile() {
        let d = fixture();
        let tablet = AbsoluteTablet::bind(3, 0, 0, &d).unwrap();
        assert_eq!(
            tablet.decode(&[0xff, 0xff, 0x7f, 1, 0, 0x81]),
            Ok(TabletReport {
                x: 32767,
                y: 1,
                buttons: 31,
                wheel: -127
            })
        );
        assert_eq!(
            AbsoluteTablet::bind(3, 1, 2, &d),
            Err(TabletError::UnsupportedInterface)
        );
        for report in [
            [0, 0, 0x80, 0, 0, 0],
            [0, 0, 0, 0, 0x80, 0],
            [0, 0, 0, 0, 0, 0x80],
        ] {
            assert_eq!(tablet.decode(&report), Err(TabletError::OutOfRange));
        }
        assert_eq!(tablet.decode(&[0; 5]), Err(TabletError::WrongReportLength));
        assert_eq!(tablet.decode(&[0; 7]), Err(TabletError::WrongReportLength));
    }

    #[test]
    fn rejects_incomplete_or_incompatible_descriptor_items() {
        let d = fixture();
        for len in 0..d.len() {
            assert_eq!(
                AbsoluteTablet::bind(3, 0, 0, &d[..len]),
                Err(TabletError::UnsupportedDescriptor)
            );
        }
        let mut extended = d.clone();
        extended.push(END);
        assert_eq!(
            AbsoluteTablet::bind(3, 0, 0, &extended),
            Err(TabletError::UnsupportedDescriptor)
        );

        let mut relative_axes = d.clone();
        let offset = relative_axes
            .windows(4)
            .rposition(|w| w == [COUNT | 1, 2, INPUT | 1, 2])
            .unwrap();
        relative_axes[offset + 3] = 6;
        assert_eq!(
            AbsoluteTablet::bind(3, 0, 0, &relative_axes),
            Err(TabletError::UnsupportedDescriptor)
        );

        let mut report_id = d.clone();
        report_id.splice(6..6, [0x85, 1]);
        assert_eq!(
            AbsoluteTablet::bind(3, 0, 0, &report_id),
            Err(TabletError::UnsupportedDescriptor)
        );

        let mut positive_wheel_min = d;
        let offset = positive_wheel_min
            .windows(2)
            .position(|w| w == [LOGICAL_MIN | 1, 0x81])
            .unwrap();
        positive_wheel_min.splice(offset..offset + 2, [LOGICAL_MIN | 2, 0x81, 0]);
        assert_eq!(
            AbsoluteTablet::bind(3, 0, 0, &positive_wheel_min),
            Err(TabletError::UnsupportedDescriptor)
        );
    }
}
