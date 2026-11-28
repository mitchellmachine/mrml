//! A fixed-geometry, single-mailbox diagnostic frame. Contains pixels, not
//! guest-provided addresses, framebuffer authority, or display-mode requests.
use crate::{Desktop, raster};

pub use mrml_boot_frame::{
    BOOT_REPLY_BYTES, BOOT_REQUEST, Error, HEADER_BYTES, MAX_BYTES, decode, decode_boot_reply,
    validate_boot_reply,
};
use mrml_boot_frame::{COLORS, TAG};

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
        validate_boot_reply(&reply).unwrap();
        let mut frame = [0; raster::FRAME_BYTES];
        decode_boot_reply(&reply, &mut frame).unwrap();
        assert_eq!(frame[..4], COLORS[0]);
        reply[BOOT_REPLY_BYTES - 1] = 1;
        assert_eq!(validate_boot_reply(&reply), Err(Error::InvalidPacket));
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
