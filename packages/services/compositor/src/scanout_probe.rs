//! Fixed one-shot compositor service probe; independent of the syscall adapter.
use mrml_kernel::{FramebufferLayout, PixelFormat};

use crate::{BootScanoutError, render_private_boot_frame};

pub const BOOT_SCANOUT_PROBE_WIDTH: u32 = 128;
pub const BOOT_SCANOUT_PROBE_HEIGHT: u32 = 32;
pub const BOOT_SCANOUT_PROBE_BYTES: usize =
    BOOT_SCANOUT_PROBE_WIDTH as usize * BOOT_SCANOUT_PROBE_HEIGHT as usize * 4;
pub const BOOT_SCANOUT_PROBE_READY: [u8; 16] = *b"MRMLSCN1\x00\x40\x00\x00\x00\x00\x00\x00";

pub trait BootScanoutProbeTransport {
    fn write_frame(&mut self, frame: &[u8; BOOT_SCANOUT_PROBE_BYTES]) -> bool;
    fn release_frame(&mut self) -> bool;
    fn send_ready(&mut self, ready: &[u8; 16]) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootScanoutProbeError {
    Raster(BootScanoutError),
    Write,
    Release,
    Reply,
}

pub fn run_boot_scanout_probe(
    transport: &mut impl BootScanoutProbeTransport,
    private: &mut [u8; BOOT_SCANOUT_PROBE_BYTES],
) -> Result<(), BootScanoutProbeError> {
    let layout = FramebufferLayout::new(
        BOOT_SCANOUT_PROBE_BYTES as u64,
        BOOT_SCANOUT_PROBE_WIDTH,
        BOOT_SCANOUT_PROBE_HEIGHT,
        BOOT_SCANOUT_PROBE_WIDTH,
        PixelFormat::BlueGreenRedReserved,
    )
    .expect("fixed probe geometry");
    let raster = render_private_boot_frame(layout, private);
    let copied = raster.is_ok() && transport.write_frame(private);
    let released = transport.release_frame();
    if !released {
        return Err(BootScanoutProbeError::Release);
    }
    raster.map_err(BootScanoutProbeError::Raster)?;
    if !copied {
        return Err(BootScanoutProbeError::Write);
    }
    if !transport.send_ready(&BOOT_SCANOUT_PROBE_READY) {
        return Err(BootScanoutProbeError::Reply);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Transport {
        writes: usize,
        releases: usize,
        replies: usize,
        fail_write: bool,
        fail_release: bool,
    }

    impl BootScanoutProbeTransport for Transport {
        fn write_frame(&mut self, frame: &[u8; BOOT_SCANOUT_PROBE_BYTES]) -> bool {
            assert_eq!((self.writes, self.releases, self.replies), (0, 0, 0));
            assert_eq!(&frame[..4], &[0x5a, 0x3b, 0x0b, 0]);
            let glyph = (24 * BOOT_SCANOUT_PROBE_WIDTH as usize + 16) * 4;
            assert_eq!(&frame[glyph..glyph + 4], &[255, 255, 255, 0]);
            self.writes += 1;
            !self.fail_write
        }

        fn release_frame(&mut self) -> bool {
            assert_eq!((self.writes, self.releases, self.replies), (1, 0, 0));
            self.releases += 1;
            !self.fail_release
        }

        fn send_ready(&mut self, ready: &[u8; 16]) -> bool {
            assert_eq!((self.writes, self.releases, self.replies), (1, 1, 0));
            assert_eq!(&ready[..8], b"MRMLSCN1");
            assert_eq!(
                u64::from_le_bytes(ready[8..].try_into().unwrap()),
                BOOT_SCANOUT_PROBE_BYTES as u64
            );
            self.replies += 1;
            true
        }
    }

    #[test]
    fn ready_requires_exact_render_copy_and_write_grant_release() {
        for (fail_write, fail_release, expected) in [
            (false, false, Ok(())),
            (true, false, Err(BootScanoutProbeError::Write)),
            (false, true, Err(BootScanoutProbeError::Release)),
        ] {
            let mut tx = Transport {
                fail_write,
                fail_release,
                ..Transport::default()
            };
            let mut frame = [0u8; BOOT_SCANOUT_PROBE_BYTES];
            assert_eq!(run_boot_scanout_probe(&mut tx, &mut frame), expected);
            assert_eq!(
                (tx.writes, tx.releases, tx.replies),
                (1, 1, usize::from(expected.is_ok()))
            );
        }
    }
}
