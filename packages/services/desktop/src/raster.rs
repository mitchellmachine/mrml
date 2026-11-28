//! Fixed-size diagnostic thumbnail. No framebuffer mapping or output rights.
use crate::{Control, Desktop, Point};

pub const WIDTH: usize = 120;
pub const HEIGHT: usize = 70;
pub const ROW_BYTES: usize = WIDTH * 4;
pub const FRAME_BYTES: usize = ROW_BYTES * HEIGHT;

pub fn row(desktop: &Desktop, y: usize, pixels: &mut [u8; ROW_BYTES]) -> bool {
    if desktop.size() != (480, 280) || y >= HEIGHT {
        return false;
    }
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
