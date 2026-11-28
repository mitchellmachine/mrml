#![no_std]

//! PS/2 keyboard scan set 2 decoder. The shared i8042 broker must route
//! keyboard data and separate command replies before delivery.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyboardEvent {
    Key {
        scan: u8,
        extended: bool,
        pressed: bool,
    },
    /// Pause has no separate release in normal scan set 2.
    Pause,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Prefix {
    #[default]
    None,
    Break,
    Extended,
    ExtendedBreak,
    Pause(usize),
}

#[derive(Default)]
pub struct Ps2Keyboard {
    prefix: Prefix,
}

const PAUSE_TAIL: [u8; 7] = [0x14, 0x77, 0xe1, 0xf0, 0x14, 0xf0, 0x77];

impl Ps2Keyboard {
    /// Discard partial input after a transport gap, restart or rebind.
    pub fn reset(&mut self) {
        self.prefix = Prefix::None;
    }

    pub fn push(&mut self, byte: u8) -> Option<KeyboardEvent> {
        use Prefix::*;
        let prefix = core::mem::take(&mut self.prefix);
        self.prefix = match (prefix, byte) {
            (Pause(index), byte) => {
                if PAUSE_TAIL[index] != byte {
                    return Option::None;
                }
                if index + 1 == PAUSE_TAIL.len() {
                    return Some(KeyboardEvent::Pause);
                }
                Pause(index + 1)
            }
            (None, 0xe0) => Extended,
            (None, 0xe1) => Pause(0),
            (None, 0xf0) => Break,
            (Extended, 0xf0) => ExtendedBreak,
            // Repeated or misplaced prefixes never become key data.
            (_, 0xe0 | 0xe1 | 0xf0) => None,
            (prefix, scan) => {
                let extended = matches!(prefix, Extended | ExtendedBreak);
                let valid = if extended {
                    // Includes Print Screen proper (0x7c), but excludes
                    // the fake Shift byte (0x12) in its scan-set-2 sequence.
                    matches!(
                        scan,
                        0x11 | 0x14
                            | 0x1f
                            | 0x27
                            | 0x2f
                            | 0x4a
                            | 0x5a
                            | 0x69
                            | 0x6b
                            | 0x6c
                            | 0x70
                            | 0x71
                            | 0x72
                            | 0x74
                            | 0x75
                            | 0x7a
                            | 0x7c
                            | 0x7d
                    )
                } else {
                    matches!(scan, 0x01 | 0x03..=0x07 | 0x09..=0x0e | 0x11..=0x12
                        | 0x14..=0x16 | 0x1a..=0x1e | 0x21..=0x26 | 0x29..=0x2e
                        | 0x31..=0x36 | 0x3a..=0x3e | 0x41..=0x46 | 0x49..=0x4e
                        | 0x52 | 0x54..=0x55 | 0x58..=0x5b | 0x5d | 0x61 | 0x66
                        | 0x69 | 0x6b..=0x6c | 0x70..=0x7e | 0x83)
                };
                return valid.then_some(KeyboardEvent::Key {
                    scan,
                    extended,
                    pressed: !matches!(prefix, Break | ExtendedBreak),
                });
            }
        };
        Option::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_make_break_and_extended_keys() {
        let mut keyboard = Ps2Keyboard::default();
        assert_eq!(
            keyboard.push(0x1c),
            Some(KeyboardEvent::Key {
                scan: 0x1c,
                extended: false,
                pressed: true
            })
        );
        assert_eq!(keyboard.push(0xf0), None);
        assert_eq!(
            keyboard.push(0x1c),
            Some(KeyboardEvent::Key {
                scan: 0x1c,
                extended: false,
                pressed: false
            })
        );
        for prefix in [0xe0, 0xf0] {
            assert_eq!(keyboard.push(prefix), None);
        }
        assert_eq!(
            keyboard.push(0x75),
            Some(KeyboardEvent::Key {
                scan: 0x75,
                extended: true,
                pressed: false
            })
        );
    }

    #[test]
    fn pause_print_screen_and_invalid_sequences_do_not_inject_other_keys() {
        let mut keyboard = Ps2Keyboard::default();
        for byte in [0xe0, 0x12, 0xe0] {
            assert_eq!(keyboard.push(byte), None);
        }
        assert_eq!(
            keyboard.push(0x7c),
            Some(KeyboardEvent::Key {
                scan: 0x7c,
                extended: true,
                pressed: true
            })
        );
        for byte in [0xe1, 0x14, 0x77, 0xe1, 0xf0, 0x14, 0xf0] {
            assert_eq!(keyboard.push(byte), None);
        }
        assert_eq!(keyboard.push(0x77), Some(KeyboardEvent::Pause));
        for byte in [0xe1, 0x1c, 0xff, 0xe0, 0xe0, 0xfe] {
            assert_eq!(keyboard.push(byte), None);
        }
        keyboard.push(0xf0);
        keyboard.reset();
        assert!(matches!(
            keyboard.push(0x1c),
            Some(KeyboardEvent::Key { pressed: true, .. })
        ));
    }
}
