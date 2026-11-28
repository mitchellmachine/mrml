//! Fixed-size diagnostic thumbnail. No framebuffer mapping or output rights.
use crate::{Control, Desktop, Point};

pub const WIDTH: usize = 120;
pub const HEIGHT: usize = 70;
pub const ROW_BYTES: usize = WIDTH * 4;
pub const FRAME_BYTES: usize = ROW_BYTES * HEIGHT;

pub fn row(desktop: &Desktop, echo: &[char], y: usize, pixels: &mut [u8; ROW_BYTES]) -> bool {
    if desktop.size() != (480, 280) || y >= HEIGHT {
        return false;
    }
    let mut count = [0; 10];
    let digits = decimal(desktop.diagnostics().keys_delivered, &mut count);
    for (x, pixel) in pixels.chunks_exact_mut(4).enumerate() {
        let p = Point((x * 4) as u16, (y * 4) as u16);
        let mut rgb = if p.1 < 44 { [24, 32, 44] } else { [14, 21, 31] };
        for n in desktop.nodes() {
            if n.bounds.contains(p) {
                rgb = match n.control {
                    Control::Terminal if p.1 < 96 => [36, 60, 82],
                    Control::Terminal => [16, 23, 34],
                    Control::Diagnostics => [35, 52, 73],
                    Control::TaskManager => [46, 50, 69],
                    _ if n.focused || n.selected => [36, 72, 103],
                    _ => [26, 39, 54],
                };
            }
        }
        let text = desktop.nodes().any(|n| match n.control {
            Control::Workspace(id) => lit(
                x,
                y,
                usize::from(n.bounds.0) / 4 + 2,
                2,
                [char::from(b'0' + id)],
            ),
            Control::OpenTerminal => lit(x, y, 36, 2, "TERM".chars()),
            Control::TaskManagerButton => lit(x, y, 65, 2, "TASKS".chars()),
            Control::Terminal => {
                lit(x, y, 5, 16, "TERM".chars())
                    || lit(
                        x,
                        y,
                        5,
                        27,
                        core::iter::once('>')
                            .chain(echo[echo.len().saturating_sub(10)..].iter().copied())
                            .take(11),
                    )
            }
            Control::Diagnostics => {
                lit(x, y, 83, 16, "DIAG".chars())
                    || lit(x, y, 83, 29, "KEYS".chars())
                    || lit(x, y, 83, 39, digits.iter().copied().map(char::from))
            }
            Control::TaskManager => lit(x, y, 5, 16, "TASKS".chars()),
            _ => false,
        });
        if text {
            rgb = [214, 234, 248];
        }
        if let Some(Point(cx, cy)) = desktop.cursor() {
            let (cx, cy) = (usize::from(cx) / 4, usize::from(cy) / 4);
            let arrow = match y.checked_sub(cy) {
                Some(0) => 1,
                Some(1) => 2,
                Some(2) => 3,
                Some(3) => 2,
                Some(4) => 1,
                _ => 0,
            };
            if x.checked_sub(cx).is_some_and(|dx| dx < arrow) {
                rgb = [245, 251, 255];
            }
        }
        pixel.copy_from_slice(&[rgb[2], rgb[1], rgb[0], 0]);
    }
    true
}

fn decimal(mut value: u32, data: &mut [u8; 10]) -> &[u8] {
    let mut at = data.len();
    loop {
        at -= 1;
        data[at] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            return &data[at..];
        }
    }
}

fn lit(x: usize, y: usize, sx: usize, sy: usize, chars: impl IntoIterator<Item = char>) -> bool {
    let Some(x) = x.checked_sub(sx) else {
        return false;
    };
    let Some(y) = y.checked_sub(sy).filter(|&row| row < 7) else {
        return false;
    };
    let column = x % 6;
    column < 5
        && chars
            .into_iter()
            .nth(x / 6)
            .is_some_and(|ch| glyph(ch)[y] & (1 << (4 - column)) != 0)
}

fn glyph(ch: char) -> [u8; 7] {
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
        ':' => [0, 4, 4, 0, 4, 4, 0],
        'λ' => [8, 4, 4, 6, 10, 17, 17],
        ' ' => [0, 0, 0, 0, 0, 0, 0],
        _ => [14, 17, 1, 2, 4, 0, 4],
    }
}
