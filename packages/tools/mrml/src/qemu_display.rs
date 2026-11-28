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
    Draft,
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
    let (w, h, rgb) = parse(bytes)?;
    // OVMF/QEMU's pinned 1024x768 reference fixture. These geometry and
    // glyph expectations are independent of the compositor implementation.
    if (w, h) != (1024, 768) {
        return Err("unexpected QEMU desktop reference resolution");
    }
    let pixel = |x: usize, y: usize| &rgb[(y * w + x) * 3..][..3];
    const WALL: [u8; 3] = [30, 34, 41];
    const PANE: [u8; 3] = [20, 24, 30];
    const GREEN: [u8; 3] = [146, 208, 153];
    const WHITE: [u8; 3] = [232, 237, 245];
    if pixel(0, 0) != [19, 22, 27]
        || pixel(1023, 0) != [19, 22, 27]
        || pixel(5, 3) != [40, 85, 119]
        || pixel(0, 767) != WALL
        || pixel(1023, 767) != WALL
    {
        return Err("desktop is missing its full-width bar, active workspace, or background");
    }

    let check_text = |x: usize, y: usize, letters: &[[u8; 7]], ink: [u8; 3]| {
        for (i, glyph) in letters.iter().enumerate() {
            for (dy, row) in glyph.iter().enumerate() {
                for dx in 0..6 {
                    let expected = if dx < 5 && row & (16 >> dx) != 0 {
                        ink
                    } else {
                        PANE
                    };
                    for by in 0..2 {
                        for bx in 0..2 {
                            if pixel(x + i * 12 + dx * 2 + bx, y + dy * 2 + by) != expected {
                                return Err("clishell command, output, or key count pixels differ");
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    };
    const EMPTY: [u8; 7] = [0; 7];
    const E: [u8; 7] = [31, 16, 16, 30, 16, 16, 31];
    const C: [u8; 7] = [14, 17, 16, 16, 16, 17, 14];
    const H: [u8; 7] = [17, 17, 17, 31, 17, 17, 17];
    const O: [u8; 7] = [14, 17, 17, 17, 17, 17, 14];
    const I: [u8; 7] = [14, 4, 4, 4, 4, 4, 14];
    const R: [u8; 7] = [30, 17, 17, 30, 20, 18, 17];
    const A: [u8; 7] = [14, 17, 17, 31, 17, 17, 17];
    const D: [u8; 7] = [30, 17, 17, 17, 17, 17, 30];
    const Y: [u8; 7] = [17, 17, 10, 4, 4, 4, 4];
    const ZERO: [u8; 7] = [14, 17, 19, 21, 25, 17, 14];
    const ONE: [u8; 7] = [4, 12, 4, 4, 4, 4, 14];
    const SEVEN: [u8; 7] = [31, 1, 2, 4, 8, 8, 8];
    const EIGHT: [u8; 7] = [14, 17, 17, 14, 17, 17, 14];
    if matches!(scene, DesktopScene::Idle) {
        if pixel(50, 700) != WALL || pixel(950, 700) != WALL {
            return Err("desktop idle unexpectedly has open panes");
        }
        return Ok((w, h));
    }
    if pixel(13, 45) != [40, 85, 119]
        || pixel(350, 43) != [49, 60, 74]
        || pixel(50, 700) != PANE
        || pixel(950, 700) != PANE
        || pixel(800, 700) != WALL
    {
        return Err("desktop panes do not fill the available workspace with normal gaps");
    }
    match scene {
        DesktopScene::Idle => unreachable!(),
        DesktopScene::Enter => {
            check_text(42, 126, &[EMPTY], WHITE)?;
            check_text(24, 102, &[EMPTY], GREEN)?;
            check_text(820, 102, &[ZERO], WHITE)?;
        }
        DesktopScene::Draft => {
            check_text(42, 126, &[E, C, H, O, EMPTY, H, I], WHITE)?;
            check_text(24, 102, &[EMPTY], GREEN)?;
            check_text(820, 102, &[SEVEN], WHITE)?;
        }
        DesktopScene::LiveKeyboard => {
            check_text(42, 126, &[EMPTY], WHITE)?;
            check_text(24, 102, &[H, I, EMPTY], GREEN)?;
            check_text(820, 102, &[EIGHT], WHITE)?;
        }
        DesktopScene::Persistent => {
            check_text(42, 126, &[EMPTY], WHITE)?;
            check_text(24, 102, &[R, E, A, D, Y, EMPTY], GREEN)?;
            check_text(820, 102, &[ONE, ONE], WHITE)?;
        }
    }
    Ok((w, h))
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
