//! Evidence from QEMU's emulated VGA scanout, not the MRML guest trace.
use std::io::Read;
use std::path::Path;

const MAX_FRAME: usize = 4096 * 4096 * 3 + 64;
const BG: [u8; 3] = [11, 59, 90];
const WHITE: [u8; 3] = [255; 3];

pub(super) fn verify_fat32_screen(path: &Path) -> Result<(usize, usize), String> {
    verify(&read_screen(path)?).map_err(str::to_owned)
}

#[derive(Clone, Copy)]
pub(super) enum DesktopScene {
    Idle,
    Enter,
    Persistent,
    LiveKeyboard,
}

pub(super) fn verify_desktop_screen(
    path: &Path,
    scene: DesktopScene,
) -> Result<(usize, usize), String> {
    verify_desktop(&read_screen(path)?, scene).map_err(str::to_owned)
}

fn read_screen(path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take((MAX_FRAME + 1) as u64).read_to_end(&mut bytes))
        .map_err(|error| format!("read QEMU screen: {error}"))?;
    Ok(bytes)
}

fn parse(bytes: &[u8]) -> Result<(usize, usize, &[u8]), &'static str> {
    if bytes.len() > MAX_FRAME {
        return Err("QEMU screen exceeds fixture size limit");
    }
    let mut fields = bytes.splitn(4, |&byte| byte == b'\n');
    if fields.next() != Some(&b"P6"[..]) {
        return Err("invalid QEMU screen format");
    }
    let geometry = std::str::from_utf8(fields.next().ok_or("missing screen geometry")?)
        .map_err(|_| "invalid screen geometry")?;
    let (w, h) = geometry
        .split_once(' ')
        .ok_or("invalid screen dimensions")?;
    let parse = |v: &str| v.parse::<usize>().ok().filter(|&n| (1..=4096).contains(&n));
    let width = parse(w).ok_or("invalid screen width")?;
    let height = parse(h).ok_or("invalid screen height")?;
    if fields.next() != Some(&b"255"[..]) {
        return Err("invalid QEMU screen color depth");
    }
    let rgb = fields.next().ok_or("missing QEMU screen pixels")?;
    if rgb.len() != width * height * 3 {
        return Err("QEMU screen pixel length mismatch");
    }
    Ok((width, height, rgb))
}

fn verify_desktop(bytes: &[u8], scene: DesktopScene) -> Result<(usize, usize), &'static str> {
    use core::fmt::Write as _;
    const W: usize = 120;
    const H: usize = 70;
    // SHA3-512 of the raw hosted reference raster, row-major RGB, without
    // the signed guest's mailbox codec or the boot scanout path.
    let golden = match scene {
        DesktopScene::Idle => concat!(
            "b3406f001edef3b09a9e7a85ae53d6e71445daf1f9096660b1d17d826941bbde4",
            "45183f169d842ed2cee62f7786ab50cbf3ad0a7fdad7c35b85227ef042951cb",
        ),
        DesktopScene::Persistent | DesktopScene::LiveKeyboard => concat!(
            "ef859ad1827bfa4fbe53df1101f75dbdd9cc65ec2e7849d08e21b214cf5d92f1",
            "2348fddb23c45c728f0e690f160e94eb164f32e93ee759ff79591608831502dc",
        ),
        DesktopScene::Enter => concat!(
            "19760ffdadb80915cf9df340e823673bb3cedc8a6829c7d338ca6cf0254d4761",
            "84549b67d910abc10adb7dd22e7c9e006bba7e92ba87432af9abe562fc94c8ad",
        ),
    };
    let (width, height, rgb) = parse(bytes)?;
    let scale = (width / W).min(height / H);
    if scale == 0 {
        return Err("QEMU display is too small to recover every desktop reference pixel");
    }
    let left = (width - W * scale) / 2;
    let top = (height - H * scale) / 2;
    let stride = width * 3;
    let mut tile = [0; W * H * 3];
    for sy in 0..H {
        for sx in 0..W {
            let offset = (top + sy * scale) * stride + (left + sx * scale) * 3;
            let sample = (sy * W + sx) * 3;
            tile[sample..sample + 3].copy_from_slice(&rgb[offset..offset + 3]);
        }
    }
    for (y, row) in rgb.chunks_exact(stride).enumerate() {
        for (x, pixel) in row.chunks_exact(3).enumerate() {
            if (left..left + W * scale).contains(&x) && (top..top + H * scale).contains(&y) {
                let sample = (((y - top) / scale) * W + (x - left) / scale) * 3;
                if pixel != &tile[sample..sample + 3] {
                    return Err("QEMU desktop pixel group was not uniformly scaled");
                }
            } else if pixel != BG {
                return Err("QEMU desktop has unexpected pixels outside the centered preview");
            }
        }
    }
    let mut digest = String::with_capacity(128);
    for byte in crate::Sha3_512::digest(&tile) {
        write!(digest, "{byte:02x}").map_err(|_| "QEMU desktop digest formatting failed")?;
    }
    if digest != golden {
        return Err("QEMU desktop pixels do not match the hosted reference raster");
    }
    Ok((width, height))
}

fn verify(bytes: &[u8]) -> Result<(usize, usize), &'static str> {
    let (width, height, rgb) = parse(bytes)?;
    // The 30-character loader diagnostic starts at (16, 24). Check every
    // cell of PASS, including background, independently of the trace bytes.
    const LABEL_BYTES: usize = b"FAT32 RESTART: PASS - 28 BYTES".len();
    const PREFIX_BYTES: usize = b"FAT32 RESTART: ".len();
    const PASS: [[u8; 7]; 4] = [
        [30, 17, 17, 30, 16, 16, 16],
        [14, 17, 17, 31, 17, 17, 17],
        [15, 16, 16, 14, 1, 1, 30],
        [15, 16, 16, 14, 1, 1, 30],
    ];
    let zoom = (width.saturating_sub(16) / (LABEL_BYTES * 6 - 1)).min(3);
    if zoom == 0 || 24 + 7 * zoom > height || rgb[..3] != BG {
        return Err("missing MRML boot diagnostic background or bounds");
    }
    for (letter, glyph) in PASS.iter().enumerate() {
        let left = 16 + (PREFIX_BYTES + letter) * 6 * zoom;
        for (row, bits) in glyph.iter().copied().enumerate() {
            for col in 0..6 {
                let color = if col < 5 && bits & (16 >> col) != 0 {
                    WHITE
                } else {
                    BG
                };
                for dy in 0..zoom {
                    for dx in 0..zoom {
                        let offset = ((24 + row * zoom + dy) * width + left + col * zoom + dx) * 3;
                        if rgb[offset..offset + 3] != color {
                            return Err("QEMU output does not show the FAT32 PASS marker");
                        }
                    }
                }
            }
        }
    }
    Ok((width, height))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pixels_must_be_exactly_present_and_bounded() {
        assert!(verify(b"P3\n10 4\n255\n").is_err());
        assert!(verify(b"P6\n4097 4\n255\n").is_err());
        assert!(verify(b"P6\n640 480\n255\n\x0b\x3b\x5a").is_err());
        let mut empty = b"P6\n320 200\n255\n".to_vec();
        empty.extend(BG.into_iter().cycle().take(320 * 200 * 3));
        assert_eq!(
            verify(&empty),
            Err("QEMU output does not show the FAT32 PASS marker")
        );
    }
}
