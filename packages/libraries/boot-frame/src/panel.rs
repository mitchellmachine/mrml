//! Fixed, address-free desktop state for native-resolution projection.
use crate::{BOOT_REPLY_BYTES, Error};

const TEXT: usize = 32;
const BYTES: usize = 8 + TEXT * 2;
const TAG: [u8; 4] = *b"MDP1";

#[derive(Debug, Eq, PartialEq)]
pub struct BootPanel<'a> {
    pub open: bool,
    pub keys: u8,
    pub input: &'a [u8],
    pub output: &'a [u8],
}

impl<'a> BootPanel<'a> {
    pub fn encode(&self, reply: &mut [u8; BOOT_REPLY_BYTES]) -> Result<(), Error> {
        reply.fill(0);
        Self::check(self.open, self.keys, self.input, self.output)?;
        reply[..4].copy_from_slice(&TAG);
        reply[4..8].copy_from_slice(&[
            u8::from(self.open),
            self.keys,
            self.input.len() as u8,
            self.output.len() as u8,
        ]);
        reply[8..8 + self.input.len()].copy_from_slice(self.input);
        reply[8 + TEXT..8 + TEXT + self.output.len()].copy_from_slice(self.output);
        Ok(())
    }

    pub fn decode(reply: &'a [u8; BOOT_REPLY_BYTES]) -> Result<Self, Error> {
        let input_end = 8 + usize::from(reply[6]);
        let output_end = 8 + TEXT + usize::from(reply[7]);
        if reply[..4] != TAG
            || reply[4] > 1
            || input_end > 8 + TEXT
            || output_end > BYTES
            || reply[input_end..8 + TEXT].iter().any(|&b| b != 0)
            || reply[output_end..].iter().any(|&b| b != 0)
        {
            return Err(Error::InvalidPacket);
        }
        let result = Self {
            open: reply[4] == 1,
            keys: reply[5],
            input: &reply[8..input_end],
            output: &reply[8 + TEXT..output_end],
        };
        Self::check(result.open, result.keys, result.input, result.output)?;
        Ok(result)
    }

    fn check(open: bool, keys: u8, input: &[u8], output: &[u8]) -> Result<(), Error> {
        if (!open && (keys != 0 || !input.is_empty() || !output.is_empty()))
            || input.len() > TEXT
            || output.len() > TEXT
            || !input
                .iter()
                .chain(output)
                .all(|b| (b' '..=b'~').contains(b))
        {
            return Err(Error::InvalidPacket);
        }
        Ok(())
    }
}

#[cfg(test)]
#[test]
fn panel_rejects_noncanonical_lengths_controls_and_hidden_data() {
    let mut reply = [0; BOOT_REPLY_BYTES];
    let good = BootPanel {
        open: true,
        keys: 8,
        input: b"",
        output: b"HI",
    };
    good.encode(&mut reply).unwrap();
    assert_eq!(BootPanel::decode(&reply), Ok(good));
    for (index, bad) in [
        (1, 0),
        (4, 0),
        (6, 33),
        (7, 255),
        (9, 1),
        (40, 27),
        (4095, 1),
    ] {
        let mut damaged = reply;
        damaged[index] = bad;
        assert!(BootPanel::decode(&damaged).is_err());
    }
}

pub fn glyph(ch: char) -> [u8; 7] {
    match ch.to_ascii_uppercase() {
        '0' => [14, 17, 19, 21, 25, 17, 14],
        '1' => [4, 12, 4, 4, 4, 4, 14],
        '2' => [14, 17, 1, 2, 4, 8, 31],
        '3' => [30, 1, 1, 14, 1, 1, 30],
        '4' => [2, 6, 10, 18, 31, 2, 2],
        '5' => [31, 16, 30, 1, 1, 17, 30],
        '6' => [6, 8, 16, 30, 17, 17, 14],
        '7' => [31, 1, 2, 4, 8, 8, 8],
        '8' => [14, 17, 17, 14, 17, 17, 14],
        '9' => [14, 17, 17, 15, 1, 2, 12],
        'B' => [30, 17, 17, 30, 17, 17, 30],
        'F' => [31, 16, 16, 30, 16, 16, 16],
        'H' => [17, 17, 17, 31, 17, 17, 17],
        'J' => [7, 2, 2, 2, 18, 18, 12],
        'L' => [16, 16, 16, 16, 16, 16, 31],
        'O' => [14, 17, 17, 17, 17, 17, 14],
        'P' => [30, 17, 17, 30, 16, 16, 16],
        'Q' => [14, 17, 17, 17, 21, 18, 13],
        'U' => [17, 17, 17, 17, 17, 17, 14],
        'W' => [17, 17, 17, 21, 21, 21, 10],
        'X' => [17, 17, 10, 4, 10, 17, 17],
        'Z' => [31, 1, 2, 4, 8, 16, 31],
        'A' => [14, 17, 17, 31, 17, 17, 17],
        'C' => [14, 17, 16, 16, 16, 17, 14],
        'D' => [30, 17, 17, 17, 17, 17, 30],
        'E' => [31, 16, 16, 30, 16, 16, 31],
        'G' => [14, 17, 16, 23, 17, 17, 14],
        'I' => [14, 4, 4, 4, 4, 4, 14],
        'K' => [17, 18, 20, 24, 20, 18, 17],
        'M' => [17, 27, 21, 21, 17, 17, 17],
        'N' => [17, 25, 21, 19, 17, 17, 17],
        'R' => [30, 17, 17, 30, 20, 18, 17],
        'S' => [15, 16, 16, 14, 1, 1, 30],
        'T' => [31, 4, 4, 4, 4, 4, 4],
        'V' => [17, 17, 17, 17, 17, 10, 4],
        'Y' => [17, 17, 10, 4, 4, 4, 4],
        '>' => [16, 8, 4, 2, 4, 8, 16],
        '$' => [4, 15, 20, 14, 5, 30, 4],
        ':' => [0, 4, 4, 0, 4, 4, 0],
        'λ' => [8, 4, 4, 6, 10, 17, 17],
        ' ' => [0, 0, 0, 0, 0, 0, 0],
        _ => [14, 17, 1, 2, 4, 0, 4],
    }
}
