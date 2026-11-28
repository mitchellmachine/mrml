//! Seat adapters operate on decoded input, not raw keyboard or mouse ports.
use crate::{Desktop, Event, Key, RouteError, TerminalRoute};
use mrml_input_ps2_keyboard::KeyboardEvent;
use mrml_input_ps2_mouse::MouseReport;

/// Map a press from the validated USB keyboard service to desktop policy.
/// This does not bind a device, acquire USB authority, or bypass seat focus.
pub fn usb_keyboard(press: mrml_input_usb_keyboard::KeyPress) -> Option<Event> {
    // Only a Shift modifier belongs to this minimal US keymap.
    if press.modifiers & !0x22 != 0 {
        return None;
    }
    let shift = press.modifiers != 0;
    let ch = match press.usage {
        0x04..=0x1d => (if shift { b'A' } else { b'a' }) + press.usage - 0x04,
        0x1e..=0x27 => {
            (if shift { b"!@#$%^&*()" } else { b"1234567890" })[(press.usage - 0x1e) as usize]
        }
        0x28 if !shift => return Some(Event::Enter),
        0x2a if !shift => return Some(Event::TerminalKey(Key::Backspace)),
        0x2b if !shift => return Some(Event::Tab),
        0x2c => b' ',
        _ => return None,
    };
    Some(Event::TerminalKey(Key::Text(char::from(ch))))
}

#[derive(Default)]
pub struct Ps2Seat {
    modifiers: u8,
}

impl Ps2Seat {
    /// Clear modifier state after loss or replacement of the keyboard stream.
    pub fn reset_keyboard(&mut self) {
        self.modifiers = 0;
    }

    pub fn keyboard(&mut self, event: KeyboardEvent) -> Option<Event> {
        let KeyboardEvent::Key {
            scan,
            extended,
            pressed,
        } = event
        else {
            return None;
        };
        let bit = match (extended, scan) {
            (false, 0x12) => 1,
            (false, 0x59) => 2,
            (true, 0x1f) => 4,
            (true, 0x27) => 8,
            (false, 0x14) => 16,
            (true, 0x14) => 32,
            (false, 0x11) => 64,
            (true, 0x11) => 128,
            _ => 0,
        };
        if bit != 0 {
            if pressed {
                self.modifiers |= bit;
            } else {
                self.modifiers &= !bit;
            }
            return None;
        }
        if !pressed || self.modifiers & 0xf0 != 0 {
            return None;
        }
        if self.modifiers & 0x0c != 0 {
            return (scan == 0x5a && self.modifiers & 3 == 0).then_some(Event::SuperEnter);
        }
        match (extended, scan) {
            (_, 0x5a) => return Some(Event::Enter),
            (false, 0x0d) if self.modifiers & 3 == 0 => return Some(Event::Tab),
            (false, 0x66) => return Some(Event::TerminalKey(Key::Backspace)),
            (false, 0x29) => return Some(Event::TerminalKey(Key::Text(' '))),
            (true, _) => return None,
            _ => {}
        }
        const LETTERS: [u8; 26] = [
            0x1c, 0x32, 0x21, 0x23, 0x24, 0x2b, 0x34, 0x33, 0x43, 0x3b, 0x42, 0x4b, 0x3a, 0x31,
            0x44, 0x4d, 0x15, 0x2d, 0x1b, 0x2c, 0x3c, 0x2a, 0x1d, 0x22, 0x35, 0x1a,
        ];
        let shift = self.modifiers & 3 != 0;
        if let Some(i) = LETTERS.iter().position(|&code| code == scan) {
            return Some(Event::TerminalKey(Key::Text(char::from(
                (if shift { b'A' } else { b'a' }) + i as u8,
            ))));
        }
        const NUMBERS: [u8; 10] = [0x16, 0x1e, 0x26, 0x25, 0x2e, 0x36, 0x3d, 0x3e, 0x46, 0x45];
        let i = NUMBERS.iter().position(|&code| code == scan)?;
        let byte = (if shift { b"!@#$%^&*()" } else { b"1234567890" })[i];
        Some(Event::TerminalKey(Key::Text(char::from(byte))))
    }

    /// The seat owner separately declares attachment and detachment. Decoded
    /// motion by itself must never create a cursor or an attached device.
    pub fn mouse(
        desktop: &mut Desktop,
        route: &mut impl TerminalRoute,
        report: MouseReport,
    ) -> Result<(), RouteError> {
        desktop.event(
            Event::MouseMotion(i32::from(report.dx), i32::from(report.dy)),
            route,
        )?;
        desktop.event(Event::MousePrimary(report.left), route)
    }
}
