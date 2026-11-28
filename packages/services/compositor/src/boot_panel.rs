//! Render a compact Sway-inspired scene at the actual framebuffer geometry.
use mrml_boot_frame::{BootPanel, glyph};
use mrml_kernel::{Color, FramebufferError, FramebufferLayout, FramebufferSurface};

const BG: Color = color(30, 34, 41);
const BAR: Color = color(19, 22, 27);
const SELECTED: Color = color(40, 85, 119);
const TEXT: Color = color(232, 237, 245);
const MUTED: Color = color(158, 174, 194);
const PANE: Color = color(20, 24, 30);
const TITLE: Color = color(49, 60, 74);
const GREEN: Color = color(146, 208, 153);

const fn color(red: u8, green: u8, blue: u8) -> Color {
    Color { red, green, blue }
}

fn ui_scale(w: u32, h: u32) -> u32 {
    // Resolution-based fallback. This is not measured physical density.
    ((w.min(h) + 544) / 576).clamp(1, 6)
}

pub(crate) fn paint(
    model: BootPanel<'_>,
    layout: FramebufferLayout,
    pixels: &mut [u8],
) -> Result<(), FramebufferError> {
    let (w, h) = (layout.width(), layout.height());
    let s = ui_scale(w, h);
    let mut out = FramebufferSurface::from_layout(layout, pixels)?;
    out.fill_rectangle(0, 0, w, h, BG)?;
    let bar = (14 * s).min(h);
    out.fill_rectangle(0, 0, w, bar, BAR)?;
    for (i, label) in [b"1", b"2", b"3"].into_iter().enumerate() {
        let x = (2 + i as u32 * 11) * s;
        if x + 10 * s <= w && 12 * s <= h {
            out.fill_rectangle(x, s, 10 * s, 12 * s, if i == 0 { SELECTED } else { BAR })?;
        }
        text(&mut out, layout, x + 2 * s, 4 * s, s, w, label, TEXT)?;
    }
    text(&mut out, layout, 37 * s, 4 * s, s, w, b"MRML", MUTED)?;
    if w >= 180 * s {
        text(
            &mut out,
            layout,
            w - 64 * s,
            4 * s,
            s,
            w,
            b"WORKSPACE 1",
            MUTED,
        )?;
    }
    let gap = 6 * s;
    let top = bar + gap;
    if w < gap * 2 + 6 * s || h < top + 12 * s + gap {
        return Ok(());
    }
    if !model.open {
        text(
            &mut out,
            layout,
            gap,
            top + 2 * s,
            s,
            w - gap,
            b"ENTER: OPEN TERMINAL",
            MUTED,
        )?;
        return Ok(());
    }

    let side = if w >= 360 * s {
        (w / 5).clamp(72 * s, 124 * s)
    } else {
        0
    };
    let right = if side == 0 {
        w - gap
    } else {
        w - side - gap * 2
    };
    let height = h - top - gap;
    out.fill_rectangle(gap, top, right - gap, height, PANE)?;
    out.fill_rectangle(gap, top, right - gap, (13 * s).min(height), TITLE)?;
    out.fill_rectangle(gap, top, s, height, SELECTED)?;
    let x = gap * 2;
    let limit = right.saturating_sub(2 * s);
    text(
        &mut out,
        layout,
        x,
        top + 3 * s,
        s,
        limit,
        b"CLISHELL",
        TEXT,
    )?;
    text(
        &mut out,
        layout,
        x,
        top + 18 * s,
        s,
        limit,
        b"echo <text>",
        MUTED,
    )?;
    text(
        &mut out,
        layout,
        x,
        top + 31 * s,
        s,
        limit,
        model.output,
        GREEN,
    )?;
    text(&mut out, layout, x, top + 43 * s, s, limit, b"$", GREEN)?;
    text(
        &mut out,
        layout,
        x + 9 * s,
        top + 43 * s,
        s,
        limit,
        model.input,
        TEXT,
    )?;

    if side != 0 {
        let side_x = right + gap;
        out.fill_rectangle(side_x, top, side, height, PANE)?;
        out.fill_rectangle(side_x, top, side, (13 * s).min(height), TITLE)?;
        text(
            &mut out,
            layout,
            side_x + gap,
            top + 3 * s,
            s,
            w - gap,
            b"INPUT",
            TEXT,
        )?;
        let keys = u32::from(model.keys);
        let digits = [
            b'0' + (keys / 100) as u8,
            b'0' + ((keys / 10) % 10) as u8,
            b'0' + (keys % 10) as u8,
        ];
        let start = if keys >= 100 {
            0
        } else if keys >= 10 {
            1
        } else {
            2
        };
        text(
            &mut out,
            layout,
            side_x + gap,
            top + 19 * s,
            s,
            w - gap,
            b"KEYS",
            MUTED,
        )?;
        text(
            &mut out,
            layout,
            side_x + gap,
            top + 31 * s,
            s,
            w - gap,
            &digits[start..],
            TEXT,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn text(
    out: &mut FramebufferSurface<'_>,
    layout: FramebufferLayout,
    mut x: u32,
    y: u32,
    s: u32,
    limit: u32,
    bytes: &[u8],
    color: Color,
) -> Result<(), FramebufferError> {
    if y + 7 * s > layout.height() {
        return Ok(());
    }
    for &b in bytes {
        if x + 5 * s > limit.min(layout.width()) {
            break;
        }
        for (row, bits) in glyph(char::from(b)).into_iter().enumerate() {
            for col in 0..5 {
                if bits & (16 >> col) != 0 {
                    out.fill_rectangle(x + col * s, y + row as u32 * s, s, s, color)?;
                }
            }
        }
        x += 6 * s;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use mrml_kernel::PixelFormat;

    #[test]
    fn geometry_reflows_with_compact_text_across_modes() {
        assert_eq!(ui_scale(1024, 768), 2);
        assert_eq!(ui_scale(1920, 1080), 2);
        assert_eq!(ui_scale(3840, 2160), 4);
        assert_eq!(ui_scale(7680, 4320), 6);
        for (w, h) in [(1, 1), (320, 240), (640, 960), (1024, 768), (3840, 2160)] {
            let stride = w + 1;
            let len = (stride * h * 4) as usize;
            let layout =
                FramebufferLayout::new(len as u64, w, h, stride, PixelFormat::RedGreenBlueReserved)
                    .unwrap();
            let mut frame = std::vec![255; len];
            paint(
                BootPanel {
                    open: true,
                    keys: 8,
                    input: b"",
                    output: b"HI",
                },
                layout,
                &mut frame,
            )
            .unwrap();
            assert_eq!(&frame[..4], &[19, 22, 27, 0]);
            for row in frame.chunks_exact((stride * 4) as usize) {
                assert_eq!(&row[(w * 4) as usize..], &[255; 4]);
            }
            if w == 1024 {
                let px = |x: usize, y: usize| &frame[(y * stride as usize + x) * 4..][..4];
                assert_eq!(px(0, 760), &[30, 34, 41, 0]);
                assert_eq!(px(50, 750), &[20, 24, 30, 0]);
                assert_eq!(px(950, 750), &[20, 24, 30, 0]);
            }
        }
    }
}
