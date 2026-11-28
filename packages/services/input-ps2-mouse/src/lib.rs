#![no_std]

//! Standard three-byte PS/2 mouse packet decoder. The shared i8042
//! broker must route auxiliary data and remove command traffic.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MouseReport {
    pub left: bool,
    pub right: bool,
    pub middle: bool,
    pub dx: i16,
    /// Positive is down, as in the display coordinate system.
    pub dy: i16,
}

#[derive(Default)]
pub struct Ps2Mouse {
    packet: [u8; 3],
    count: usize,
}

impl Ps2Mouse {
    /// Discard partial input after a transport gap, restart or rebind.
    pub fn reset(&mut self) {
        self.count = 0;
    }

    pub fn push(&mut self, byte: u8) -> Option<MouseReport> {
        if self.count == 0 && byte & 0x08 == 0 {
            return None;
        }
        self.packet[self.count] = byte;
        self.count += 1;
        if self.count != 3 {
            return None;
        }
        self.reset();
        let [flags, x, y] = self.packet;
        // Do not turn overflowed motion into an arbitrary displacement.
        if flags & 0xc0 != 0 {
            return None;
        }
        let delta = |value, negative| i16::from(value) - if negative { 256 } else { 0 };
        Some(MouseReport {
            left: flags & 1 != 0,
            right: flags & 2 != 0,
            middle: flags & 4 != 0,
            dx: delta(x, flags & 0x10 != 0),
            dy: -delta(y, flags & 0x20 != 0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_nine_bit_signed_motion_and_button_state() {
        let mut mouse = Ps2Mouse::default();
        for byte in [0x00, 0x3d, 0x00] {
            assert_eq!(mouse.push(byte), None);
        }
        assert_eq!(
            mouse.push(0xff),
            Some(MouseReport {
                left: true,
                right: false,
                middle: true,
                dx: -256,
                dy: 1,
            })
        );
        assert_eq!(mouse.push(0x0a), None);
        assert_eq!(mouse.push(255), None);
        assert_eq!(
            mouse.push(255),
            Some(MouseReport {
                left: false,
                right: true,
                middle: false,
                dx: 255,
                dy: -255,
            })
        );
    }

    #[test]
    fn rejects_overflow_and_resets_after_transport_gap() {
        let mut mouse = Ps2Mouse::default();
        for byte in [0x48, 8, 8] {
            assert_eq!(mouse.push(byte), None);
        }
        assert_eq!(mouse.push(8), None);
        mouse.reset();
        for byte in [0, 8, 0] {
            assert_eq!(mouse.push(byte), None);
        }
        assert_eq!(
            mouse.push(0),
            Some(MouseReport {
                left: false,
                right: false,
                middle: false,
                dx: 0,
                dy: 0,
            })
        );
    }
}
