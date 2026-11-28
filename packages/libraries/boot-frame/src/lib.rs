//! Bounded wire codec for the device-free desktop diagnostic mailbox.
#![no_std]
#![forbid(unsafe_code)]

mod panel;
pub use panel::{BootPanel, glyph};

pub const BOOT_REQUEST: [u8; 8] = *b"MRMLDB1\0";

/// The authenticated diagnostic has a closed, versioned set of inputs.
/// It carries no hardware reports, addresses, or app-launch authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootScene {
    Idle,
    Enter,
    Begin,
    TextA,
    LiveBegin,
    End,
    Space,
    Submit,
    Backspace,
    Letter(BootLetter),
}

pub const MAX_LIVE_KEYS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootLetter(u8);

impl BootLetter {
    pub const fn new(byte: u8) -> Option<Self> {
        if byte.is_ascii_uppercase() {
            Some(Self(byte))
        } else {
            None
        }
    }

    pub const fn character(self) -> char {
        self.0 as char
    }
}

impl BootScene {
    pub const fn request(self) -> [u8; BOOT_REQUEST.len()] {
        match self {
            Self::Idle => BOOT_REQUEST,
            Self::Enter => *b"MRMLDB1\x01",
            Self::Begin => *b"MRMLDB1\x02",
            Self::TextA => *b"MRMLDB1\x03",
            Self::LiveBegin => *b"MRMLDB1\x04",
            Self::End => *b"MRMLDB1\x05",
            Self::Space => *b"MRMLDB1\x06",
            Self::Submit => *b"MRMLDB1\x07",
            Self::Backspace => *b"MRMLDB1\x08",
            Self::Letter(letter) => [b'M', b'R', b'M', b'L', b'D', b'B', b'1', letter.0],
        }
    }

    pub fn parse(request: &[u8; BOOT_REQUEST.len()]) -> Result<Self, Error> {
        if request[..7] != BOOT_REQUEST[..7] {
            return Err(Error::InvalidRequest);
        }
        if let Some(letter) = BootLetter::new(request[7]) {
            return Ok(Self::Letter(letter));
        }
        [
            Self::Idle,
            Self::Enter,
            Self::Begin,
            Self::TextA,
            Self::LiveBegin,
            Self::End,
            Self::Space,
            Self::Submit,
            Self::Backspace,
        ]
        .into_iter()
        .find(|scene| scene.request() == *request)
        .ok_or(Error::InvalidRequest)
    }
}
#[cfg(test)]
#[test]
fn live_letter_codes_are_bounded_and_require_exact_magic() {
    for byte in 0..=255 {
        let mut framed = BOOT_REQUEST;
        framed[7] = byte;
        let decoded = BootScene::parse(&framed);
        assert_eq!(
            decoded.ok().and_then(|scene| match scene {
                BootScene::Letter(letter) => Some(letter.character()),
                _ => None,
            }),
            BootLetter::new(byte).map(BootLetter::character)
        );
        framed[0] ^= 1;
        assert_eq!(BootScene::parse(&framed), Err(Error::InvalidRequest));
    }
}

pub const BOOT_REPLY_BYTES: usize = 4096;

pub const HEADER_BYTES: usize = 8;
pub const MAX_BYTES: usize = 4096 - 32;
pub const WIDTH: usize = 120;
pub const HEIGHT: usize = 70;
pub const ROW_BYTES: usize = WIDTH * 4;
pub const FRAME_BYTES: usize = ROW_BYTES * HEIGHT;
const PIXELS: usize = WIDTH * HEIGHT;
pub const TAG: [u8; 4] = *b"MDF1";
pub const COLORS: [[u8; 4]; 10] = [
    [44, 32, 24, 0],
    [31, 21, 14, 0],
    [82, 60, 36, 0],
    [34, 23, 16, 0],
    [73, 52, 35, 0],
    [69, 50, 46, 0],
    [103, 72, 36, 0],
    [54, 39, 26, 0],
    [248, 234, 214, 0],
    [255, 251, 245, 0],
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidDesktop,
    UnknownColor,
    TooLarge,
    InvalidPacket,
    WrongOutputSize,
    InvalidRequest,
}

/// Validate the complete projected guest buffer, including unused padding.
pub fn decode_boot_reply(reply: &[u8; BOOT_REPLY_BYTES], output: &mut [u8]) -> Result<(), Error> {
    decode(boot_packet(reply)?, output)
}

/// Check the whole stopped guest mailbox without allocating a decoded frame.
pub fn validate_boot_reply(reply: &[u8; BOOT_REPLY_BYTES]) -> Result<(), Error> {
    validate_packet(boot_packet(reply)?)
}

fn boot_packet(reply: &[u8; BOOT_REPLY_BYTES]) -> Result<&[u8], Error> {
    let len = usize::from(u16::from_le_bytes([reply[4], reply[5]]));
    if !(HEADER_BYTES + 2..=MAX_BYTES).contains(&len) || reply[len..].iter().any(|&byte| byte != 0)
    {
        return Err(Error::InvalidPacket);
    }
    Ok(&reply[..len])
}

/// Refuse malformed or partial frames before modifying the caller's buffer.
pub fn decode(packet: &[u8], output: &mut [u8]) -> Result<(), Error> {
    if output.len() != FRAME_BYTES {
        return Err(Error::WrongOutputSize);
    }
    validate_packet(packet)?;
    let mut at = 0;
    for run in packet[HEADER_BYTES..].chunks_exact(2) {
        let end = at + usize::from(run[0]) * 4;
        for pixel in output[at..end].chunks_exact_mut(4) {
            pixel.copy_from_slice(&COLORS[usize::from(run[1])]);
        }
        at = end;
    }
    Ok(())
}

fn validate_packet(packet: &[u8]) -> Result<(), Error> {
    if !(HEADER_BYTES + 2..=MAX_BYTES).contains(&packet.len())
        || packet[..4] != TAG
        || usize::from(u16::from_le_bytes([packet[4], packet[5]])) != packet.len()
        || packet[6..8] != [0; 2]
        || packet.len() % 2 != 0
    {
        return Err(Error::InvalidPacket);
    }
    let runs = packet[HEADER_BYTES..].chunks_exact(2);
    let mut count = 0usize;
    let mut previous = None;
    for run in runs {
        if run[0] == 0
            || usize::from(run[1]) >= COLORS.len()
            || previous.is_some_and(|(length, color)| color == run[1] && length != u8::MAX)
        {
            return Err(Error::InvalidPacket);
        }
        count += usize::from(run[0]);
        if count > PIXELS {
            return Err(Error::InvalidPacket);
        }
        previous = Some((run[0], run[1]));
    }
    if count != PIXELS {
        return Err(Error::InvalidPacket);
    }
    Ok(())
}
