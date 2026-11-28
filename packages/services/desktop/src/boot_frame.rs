//! A fixed-geometry, single-mailbox diagnostic frame. Contains pixels, not
//! guest-provided addresses, framebuffer authority, or display-mode requests.
use crate::{Desktop, raster};

pub const BOOT_REQUEST: [u8; 8] = *b"MRMLDB1\0";
pub const BOOT_REPLY_BYTES: usize = 4096;

pub const HEADER_BYTES: usize = 8;
pub const MAX_BYTES: usize = 4096 - 32;
const PIXELS: usize = raster::WIDTH * raster::HEIGHT;
const TAG: [u8; 4] = *b"MDF1";
const COLORS: [[u8; 4]; 10] = [
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

/// The size becomes valid only after the payload is complete.
pub fn encode(
    desktop: &Desktop,
    echo: &[char],
    packet: &mut [u8; MAX_BYTES],
) -> Result<usize, Error> {
    packet[..HEADER_BYTES].fill(0);
    let mut row = [0; raster::ROW_BYTES];
    let mut end = HEADER_BYTES;
    let mut color = 0u8;
    let mut count = 0u8;
    let mut flush = |count: u8, color: u8| -> Result<(), Error> {
        let slot = packet.get_mut(end..end + 2).ok_or(Error::TooLarge)?;
        slot.copy_from_slice(&[count, color]);
        end += 2;
        Ok(())
    };
    for y in 0..raster::HEIGHT {
        if !raster::row(desktop, echo, y, &mut row) {
            return Err(Error::InvalidDesktop);
        }
        for pixel in row.chunks_exact(4) {
            let next = COLORS
                .iter()
                .position(|value| value == pixel)
                .ok_or(Error::UnknownColor)? as u8;
            if count != 0 && (next != color || count == u8::MAX) {
                flush(count, color)?;
                count = 0;
            }
            color = next;
            count += 1;
        }
    }
    flush(count, color)?;
    packet[..4].copy_from_slice(&TAG);
    packet[4..6].copy_from_slice(&(end as u16).to_le_bytes());
    Ok(end)
}

/// One-shot Win64 diagnostic entry: fixed request, separate RAM reply.
/// The reply is zero on failure, and padding remains zero on success.
pub fn render_boot_reply(
    request: &[u8; BOOT_REQUEST.len()],
    reply: &mut [u8; BOOT_REPLY_BYTES],
) -> Result<(), Error> {
    reply.fill(0);
    if request != &BOOT_REQUEST {
        return Err(Error::InvalidRequest);
    }
    let desktop = Desktop::new(480, 280).ok_or(Error::InvalidDesktop)?;
    let packet = (&mut reply[..MAX_BYTES])
        .try_into()
        .map_err(|_| Error::WrongOutputSize)?;
    match encode(&desktop, &[], packet) {
        Ok(_) => Ok(()),
        Err(error) => {
            reply.fill(0);
            Err(error)
        }
    }
}

/// Validate the complete projected guest buffer, including unused padding.
pub fn decode_boot_reply(reply: &[u8; BOOT_REPLY_BYTES], output: &mut [u8]) -> Result<(), Error> {
    let len = usize::from(u16::from_le_bytes([reply[4], reply[5]]));
    if !(HEADER_BYTES + 2..=MAX_BYTES).contains(&len) || reply[len..].iter().any(|&byte| byte != 0)
    {
        return Err(Error::InvalidPacket);
    }
    decode(&reply[..len], output)
}

/// Refuse malformed or partial frames before modifying the caller's buffer.
pub fn decode(packet: &[u8], output: &mut [u8]) -> Result<(), Error> {
    if output.len() != raster::FRAME_BYTES {
        return Err(Error::WrongOutputSize);
    }
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
    for run in runs.clone() {
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
    let mut at = 0;
    for run in runs {
        let end = at + usize::from(run[0]) * 4;
        for pixel in output[at..end].chunks_exact_mut(4) {
            pixel.copy_from_slice(&COLORS[usize::from(run[1])]);
        }
        at = end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_request_seals_frame_and_rejects_nonzero_padding() {
        let mut reply = [0xa7; BOOT_REPLY_BYTES];
        assert_eq!(
            render_boot_reply(b"wrongabi", &mut reply),
            Err(Error::InvalidRequest)
        );
        assert!(reply.iter().all(|&byte| byte == 0));
        render_boot_reply(&BOOT_REQUEST, &mut reply).unwrap();
        let mut frame = [0; raster::FRAME_BYTES];
        decode_boot_reply(&reply, &mut frame).unwrap();
        assert_eq!(frame[..4], COLORS[0]);
        reply[BOOT_REPLY_BYTES - 1] = 1;
        frame.fill(0xa7);
        assert_eq!(
            decode_boot_reply(&reply, &mut frame),
            Err(Error::InvalidPacket)
        );
        assert!(frame.iter().all(|&byte| byte == 0xa7));
    }

    #[test]
    fn complete_frame_fits_and_invalid_packet_does_not_modify_output() {
        let desktop = Desktop::new(480, 280).unwrap();
        let mut packet = [0; MAX_BYTES];
        let len = encode(&desktop, &[], &mut packet).unwrap();
        let mut output = [0xa7; raster::FRAME_BYTES];
        for cut in [0, 7, len - 1, len - 2] {
            assert_eq!(
                decode(&packet[..cut], &mut output),
                Err(Error::InvalidPacket)
            );
        }
        let first_run = packet[HEADER_BYTES + 1];
        packet[HEADER_BYTES + 1] = u8::MAX;
        assert_eq!(
            decode(&packet[..len], &mut output),
            Err(Error::InvalidPacket)
        );
        assert!(output.iter().all(|&b| b == 0xa7));
        packet[HEADER_BYTES + 1] = first_run;
        decode(&packet[..len], &mut output).unwrap();
        assert_eq!(output[..4], COLORS[0]);
    }
}
