//! USB-IF HID 1.11 boot keyboard selection. This is a narrow profile,
//! not a general USB configuration parser or a grant of endpoint authority.

use crate::{BootKeyStream, BootKeyboard};

const MAX_CONFIGURATION: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsbKeyboardSpeed {
    Low,
    Full,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorError {
    Malformed,
    Unsupported,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyboardFunction {
    configuration: u8,
    interface: u8,
    interrupt_in: u8,
    packet_bytes: u8,
    interval_frames: u8,
}

impl KeyboardFunction {
    pub const fn configuration(self) -> u8 {
        self.configuration
    }
    pub const fn interface(self) -> u8 {
        self.interface
    }
    pub const fn interrupt_in(self) -> u8 {
        self.interrupt_in
    }
    pub const fn packet_bytes(self) -> u8 {
        self.packet_bytes
    }
    pub const fn interval_frames(self) -> u8 {
        self.interval_frames
    }

    /// Execute the one HID request through the owner's already configured,
    /// generation-bound control pipe. A failed or nonzero data-stage
    /// completion must return false. The request itself grants no authority.
    pub fn select_boot(
        self,
        complete_no_data: impl FnOnce([u8; 8]) -> bool,
    ) -> Option<BootKeyStream> {
        // Host-to-device, class, interface; SET_PROTOCOL(BOOT), zero bytes.
        let setup = [0x21, 0x0b, 0, 0, self.interface, 0, 0, 0];
        if !complete_no_data(setup) {
            return None;
        }
        Some(BootKeyStream::new(BootKeyboard(())))
    }
}

/// Select one default-alt HID Boot Keyboard with one interrupt-IN endpoint.
/// The address, speed, configuration and interface still need to be bound by
/// the USB owner before any transaction. Unrelated endpoints cannot supply
/// the keyboard input address and active endpoint aliases are refused.
pub fn find_keyboard_function(
    bytes: &[u8],
    speed: UsbKeyboardSpeed,
) -> Result<KeyboardFunction, DescriptorError> {
    use DescriptorError::*;
    if !(9..=MAX_CONFIGURATION).contains(&bytes.len())
        || bytes[0] != 9
        || bytes[1] != 2
        || usize::from(u16::from_le_bytes([bytes[2], bytes[3]])) != bytes.len()
        || bytes[4] == 0
        || bytes[5] == 0
    {
        return Err(Malformed);
    }

    let mut interfaces = [false; 256];
    let mut default_count = 0usize;
    let mut active_endpoints = 0u32;
    let mut current_alt = None;
    let mut candidate = None;
    let mut in_keyboard = false;
    let mut saw_hid = false;
    let mut endpoint = None;
    let mut rest = &bytes[9..];
    while !rest.is_empty() {
        let len = usize::from(rest[0]);
        if len < 2 || len > rest.len() {
            return Err(Malformed);
        }
        let (d, next) = rest.split_at(len);
        rest = next;
        match d[1] {
            2 => return Err(Malformed),
            4 => {
                if len != 9 {
                    return Err(Malformed);
                }
                current_alt = Some(d[3]);
                in_keyboard = d[3] == 0 && d[5..8] == [3, 1, 1];
                if d[3] == 0 {
                    let index = usize::from(d[2]);
                    if interfaces[index] {
                        return Err(Ambiguous);
                    }
                    interfaces[index] = true;
                    default_count += 1;
                }
                if in_keyboard {
                    if candidate.is_some() {
                        return Err(Ambiguous);
                    }
                    if d[4] != 1 {
                        return Err(Unsupported);
                    }
                    candidate = Some(d[2]);
                }
            }
            0x21 if in_keyboard => {
                if saw_hid || len != 9 || d[5] != 1 || d[6] != 0x22 || d[7..9] == [0, 0] {
                    return Err(Malformed);
                }
                saw_hid = true;
            }
            5 => {
                if len < 7 || current_alt.is_none() {
                    return Err(Malformed);
                }
                let address = d[2];
                let num = address & 0x0f;
                if num == 0 || address & 0x70 != 0 {
                    return Err(Malformed);
                }
                if current_alt == Some(0) {
                    let bit = 1u32 << (u32::from(num) + if address & 0x80 != 0 { 16 } else { 0 });
                    if active_endpoints & bit != 0 {
                        return Err(Ambiguous);
                    }
                    active_endpoints |= bit;
                }
                if in_keyboard {
                    if endpoint.is_some() || !saw_hid {
                        return Err(Malformed);
                    }
                    let size = u16::from_le_bytes([d[4], d[5]]);
                    let max = match speed {
                        UsbKeyboardSpeed::Low => 8,
                        UsbKeyboardSpeed::Full => 64,
                    };
                    if len != 7
                        || address & 0x80 == 0
                        || d[3] != 3
                        || !(8..=max).contains(&size)
                        || d[6] == 0
                    {
                        return Err(Unsupported);
                    }
                    endpoint = Some((address, size as u8, d[6]));
                }
            }
            _ => {}
        }
    }
    if default_count != usize::from(bytes[4]) {
        return Err(Malformed);
    }
    let interface = candidate.ok_or(Unsupported)?;
    let (interrupt_in, packet_bytes, interval_frames) = endpoint.ok_or(Malformed)?;
    Ok(KeyboardFunction {
        configuration: bytes[5],
        interface,
        interrupt_in,
        packet_bytes,
        interval_frames,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEYBOARD: [u8; 34] = [
        9, 2, 34, 0, 1, 4, 0, 0x80, 50, 9, 4, 0, 0, 1, 3, 1, 1, 0, 9, 0x21, 0x11, 1, 0, 1, 0x22,
        63, 0, 7, 5, 0x83, 3, 8, 0, 10,
    ];

    #[test]
    fn selects_the_exact_endpoint_and_requires_success_for_boot_mode() {
        let function = find_keyboard_function(&KEYBOARD, UsbKeyboardSpeed::Full).unwrap();
        assert_eq!(function.configuration(), 4);
        assert_eq!(function.interrupt_in(), 0x83);
        assert_eq!(function.packet_bytes(), 8);
        assert_eq!(function.interval_frames(), 10);
        assert!(
            function
                .select_boot(|packet| {
                    assert_eq!(packet, [0x21, 0x0b, 0, 0, 0, 0, 0, 0]);
                    false
                })
                .is_none()
        );
        let mut stream = function.select_boot(|_| true).unwrap();
        assert_eq!(stream.ingest(&[0; 8]), Ok(None));
        assert_eq!(
            stream
                .ingest(&[0, 0, 4, 0, 0, 0, 0, 0])
                .unwrap()
                .unwrap()
                .usage,
            4
        );
    }

    #[test]
    fn rejects_truncation_misbound_endpoint_and_unsupported_layouts() {
        for end in 0..KEYBOARD.len() {
            assert!(find_keyboard_function(&KEYBOARD[..end], UsbKeyboardSpeed::Full).is_err());
        }
        for (index, value) in [
            (12, 1),
            (13, 0),
            (16, 2),
            (24, 0x23),
            (29, 3),
            (30, 2),
            (31, 7),
            (32, 1),
            (33, 0),
        ] {
            let mut bytes = KEYBOARD;
            bytes[index] = value;
            assert!(find_keyboard_function(&bytes, UsbKeyboardSpeed::Full).is_err());
        }
        let mut bytes = KEYBOARD;
        bytes[31] = 16;
        assert!(find_keyboard_function(&bytes, UsbKeyboardSpeed::Full).is_ok());
        assert!(find_keyboard_function(&bytes, UsbKeyboardSpeed::Low).is_err());
    }

    #[test]
    fn refuses_aliases_and_two_keyboard_candidates() {
        let mut both = [0; 59];
        both[..34].copy_from_slice(&KEYBOARD);
        both[34..].copy_from_slice(&KEYBOARD[9..]);
        both[2] = 59;
        both[4] = 2;
        both[36] = 1;
        both[54] = 0x84;
        assert_eq!(
            find_keyboard_function(&both, UsbKeyboardSpeed::Full),
            Err(DescriptorError::Ambiguous)
        );
        both[41] = 2; // second interface is mouse; its endpoint remains separate.
        assert!(find_keyboard_function(&both, UsbKeyboardSpeed::Full).is_ok());
        both[54] = 0x83;
        assert_eq!(
            find_keyboard_function(&both, UsbKeyboardSpeed::Full),
            Err(DescriptorError::Ambiguous)
        );
    }
}
