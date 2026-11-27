use crate::PhysAddr;

const BYTES_PER_PIXEL: u64 = 4;
const MAX_DIMENSION: u32 = 16_384;
const MAX_STRIDE: u32 = 32_768;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PixelFormat {
    RedGreenBlueReserved,
    BlueGreenRedReserved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramebufferError {
    Missing,
    Unaligned,
    InvalidDimensions,
    InvalidStride,
    InvalidLength,
    Overflow,
    UnsupportedPixelFormat,
    BufferTooSmall,
    OutOfBounds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FramebufferInfo {
    base: PhysAddr,
    layout: FramebufferLayout,
}

/// Validated scanout geometry, without a physical address or mapping authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FramebufferLayout {
    byte_length: u64,
    width: u32,
    height: u32,
    stride: u32,
    format: PixelFormat,
}

impl FramebufferInfo {
    pub fn new(
        base: u64,
        byte_length: u64,
        width: u32,
        height: u32,
        stride: u32,
        format: PixelFormat,
    ) -> Result<Self, FramebufferError> {
        if base == 0 || byte_length == 0 {
            return Err(FramebufferError::Missing);
        }
        let base = PhysAddr::new(base).map_err(|_| FramebufferError::Unaligned)?;
        if base.get().checked_add(byte_length).is_none() {
            return Err(FramebufferError::InvalidLength);
        }
        Ok(Self {
            base,
            layout: FramebufferLayout::new(byte_length, width, height, stride, format)?,
        })
    }

    pub const fn base(self) -> PhysAddr {
        self.base
    }
    pub const fn byte_length(self) -> u64 {
        self.layout.byte_length()
    }
    pub const fn width(self) -> u32 {
        self.layout.width()
    }
    pub const fn height(self) -> u32 {
        self.layout.height()
    }
    pub const fn stride(self) -> u32 {
        self.layout.stride()
    }
    pub const fn pixel_format(self) -> PixelFormat {
        self.layout.format()
    }
    pub const fn format(self) -> PixelFormat {
        self.layout.format()
    }
    pub const fn end(self) -> u64 {
        self.base.get() + self.layout.byte_length()
    }
    pub const fn layout(self) -> FramebufferLayout {
        self.layout
    }
}

impl FramebufferLayout {
    pub fn new(
        byte_length: u64,
        width: u32,
        height: u32,
        stride: u32,
        format: PixelFormat,
    ) -> Result<Self, FramebufferError> {
        if byte_length == 0 {
            return Err(FramebufferError::Missing);
        }
        if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
            return Err(FramebufferError::InvalidDimensions);
        }
        if stride < width || stride > MAX_STRIDE {
            return Err(FramebufferError::InvalidStride);
        }
        let required = u64::from(stride)
            .checked_mul(u64::from(height))
            .and_then(|pixels| pixels.checked_mul(BYTES_PER_PIXEL))
            .ok_or(FramebufferError::Overflow)?;
        if byte_length < required || byte_length > isize::MAX as u64 {
            return Err(FramebufferError::InvalidLength);
        }
        Ok(Self {
            byte_length,
            width,
            height,
            stride,
            format,
        })
    }

    pub const fn byte_length(self) -> u64 {
        self.byte_length
    }
    pub const fn width(self) -> u32 {
        self.width
    }
    pub const fn height(self) -> u32 {
        self.height
    }
    pub const fn stride(self) -> u32 {
        self.stride
    }
    pub const fn format(self) -> PixelFormat {
        self.format
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Color {
    pub red: u8,
    pub green: u8,
    pub blue: u8,
}

/// Safe renderer over a framebuffer mapping established by architecture code.
/// It cannot access row padding or bytes beyond the validated GOP allocation.
pub struct FramebufferSurface<'a> {
    info: FramebufferLayout,
    bytes: &'a mut [u8],
}

impl<'a> FramebufferSurface<'a> {
    pub fn new(info: FramebufferInfo, bytes: &'a mut [u8]) -> Result<Self, FramebufferError> {
        Self::from_layout(info.layout(), bytes)
    }

    pub fn from_layout(
        info: FramebufferLayout,
        bytes: &'a mut [u8],
    ) -> Result<Self, FramebufferError> {
        let declared =
            usize::try_from(info.byte_length).map_err(|_| FramebufferError::BufferTooSmall)?;
        if bytes.len() < declared {
            return Err(FramebufferError::BufferTooSmall);
        }
        Ok(Self {
            info,
            bytes: &mut bytes[..declared],
        })
    }

    pub fn set_pixel(&mut self, x: u32, y: u32, color: Color) -> Result<(), FramebufferError> {
        if x >= self.info.width || y >= self.info.height {
            return Err(FramebufferError::OutOfBounds);
        }
        let pixel = u64::from(y)
            .checked_mul(u64::from(self.info.stride))
            .and_then(|row| row.checked_add(u64::from(x)))
            .and_then(|index| index.checked_mul(BYTES_PER_PIXEL))
            .ok_or(FramebufferError::Overflow)?;
        let offset = usize::try_from(pixel).map_err(|_| FramebufferError::Overflow)?;
        let encoded = match self.info.format {
            PixelFormat::RedGreenBlueReserved => [color.red, color.green, color.blue, 0],
            PixelFormat::BlueGreenRedReserved => [color.blue, color.green, color.red, 0],
        };
        self.bytes[offset..offset + 4].copy_from_slice(&encoded);
        Ok(())
    }

    pub fn fill_rectangle(
        &mut self,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        color: Color,
    ) -> Result<(), FramebufferError> {
        let end_x = x.checked_add(width).ok_or(FramebufferError::Overflow)?;
        let end_y = y.checked_add(height).ok_or(FramebufferError::Overflow)?;
        if width == 0 || height == 0 || end_x > self.info.width || end_y > self.info.height {
            return Err(FramebufferError::OutOfBounds);
        }
        for row in y..end_y {
            for column in x..end_x {
                self.set_pixel(column, row, color)?;
            }
        }
        Ok(())
    }

    /// Paint the kernel's early-boot marker without a font or compositor dependency.
    pub fn mark_kernel_ready(&mut self, color: Color) -> Result<(), FramebufferError> {
        self.draw_boot_label(b"MRML KERNEL READY", color)
    }

    /// Draw a bounded early-boot label. Deliberately not a general text renderer.
    pub fn draw_boot_label(&mut self, label: &[u8], color: Color) -> Result<(), FramebufferError> {
        const X: u32 = 16;
        const Y: u32 = 24;
        if label.is_empty()
            || label.len() > 40
            || label.iter().any(|&byte| boot_glyph(byte).is_none())
        {
            return Err(FramebufferError::OutOfBounds);
        }
        let columns = label.len() as u32 * 6 - 1;
        let zoom = self
            .info
            .width
            .saturating_sub(X)
            .checked_div(columns)
            .unwrap_or(0)
            .min(3);
        if zoom == 0 || self.info.height < Y + 7 * zoom {
            return Ok(());
        }
        for (column, byte) in label.iter().copied().enumerate() {
            let glyph = boot_glyph(byte).ok_or(FramebufferError::OutOfBounds)?;
            for (row, bits) in glyph.into_iter().enumerate() {
                for bit in 0..5 {
                    if bits & (1 << (4 - bit)) != 0 {
                        self.fill_rectangle(
                            X + (column as u32 * 6 + bit) * zoom,
                            Y + row as u32 * zoom,
                            zoom,
                            zoom,
                            color,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn boot_glyph(byte: u8) -> Option<[u8; 7]> {
    Some(match byte {
        b'M' => [17, 27, 21, 21, 17, 17, 17],
        b'R' => [30, 17, 17, 30, 20, 18, 17],
        b'L' => [16, 16, 16, 16, 16, 16, 31],
        b' ' => [0; 7],
        b'K' => [17, 18, 20, 24, 20, 18, 17],
        b'E' => [31, 16, 16, 30, 16, 16, 31],
        b'N' => [17, 25, 21, 19, 17, 17, 17],
        b'A' => [14, 17, 17, 31, 17, 17, 17],
        b'D' => [30, 17, 17, 17, 17, 17, 30],
        b'Y' => [17, 17, 10, 4, 4, 4, 4],
        b'F' => [31, 16, 16, 30, 16, 16, 16],
        b'T' => [31, 4, 4, 4, 4, 4, 4],
        b'0' => [14, 17, 19, 21, 25, 17, 14],
        b'1' => [4, 12, 4, 4, 4, 4, 14],
        b'4' => [2, 6, 10, 18, 31, 2, 2],
        b'5' => [31, 16, 30, 1, 1, 17, 14],
        b'6' => [6, 8, 16, 30, 17, 17, 14],
        b'7' => [31, 1, 2, 4, 8, 8, 8],
        b'9' => [14, 17, 17, 15, 1, 2, 12],
        b'C' => [14, 17, 16, 16, 16, 17, 14],
        b'3' => [30, 1, 1, 14, 1, 1, 30],
        b'2' => [14, 17, 1, 2, 4, 8, 31],
        b'S' => [15, 16, 16, 14, 1, 1, 30],
        b'O' => [14, 17, 17, 17, 17, 17, 14],
        b'P' => [30, 17, 17, 30, 16, 16, 16],
        b'I' => [14, 4, 4, 4, 4, 4, 14],
        b'B' => [30, 17, 17, 30, 17, 17, 30],
        b'G' => [14, 17, 16, 23, 17, 17, 15],
        b'V' => [17, 17, 17, 17, 17, 10, 4],
        b'X' => [17, 17, 10, 4, 10, 17, 17],
        b'8' => [14, 17, 17, 14, 17, 17, 14],
        b':' => [0, 4, 4, 0, 4, 4, 0],
        b'-' => [0, 0, 0, 31, 0, 0, 0],
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fat32_terminal_label_draws_and_invalid_label_leaves_pixels_unchanged() {
        let info = FramebufferInfo::new(
            0x1000,
            38_400,
            200,
            48,
            200,
            PixelFormat::RedGreenBlueReserved,
        )
        .unwrap();
        let mut bytes = [0u8; 38_400];
        let white = Color {
            red: 255,
            green: 255,
            blue: 255,
        };
        let mut surface = FramebufferSurface::new(info, &mut bytes).unwrap();
        assert_eq!(
            surface.draw_boot_label(b"FAT32?", white),
            Err(FramebufferError::OutOfBounds)
        );
        assert!(surface.bytes.iter().all(|&byte| byte == 0));
        surface
            .draw_boot_label(b"FAT32 RESTART: PASS - 28 BYTES", white)
            .unwrap();
        let first = (24 * 200 + 16) * 4;
        let last = (24 * 200 + 16 + 29 * 6 + 1) * 4;
        assert_eq!(&surface.bytes[first..first + 4], &[255, 255, 255, 0]);
        assert_eq!(&surface.bytes[last..last + 4], &[255, 255, 255, 0]);
    }

    #[test]
    fn handoff_stage_labels_render_at_small_framebuffer_size() {
        let info = FramebufferInfo::new(
            0x1000,
            39_936,
            208,
            48,
            208,
            PixelFormat::BlueGreenRedReserved,
        )
        .unwrap();
        let labels: &[&[u8]] = &[
            b"MRML EFI END START",
            b"MRML EFI END PASS",
            b"MRML MAP PASS",
            b"MRML MADT PASS",
            b"MRML KERNEL START",
            b"MRML KERNEL ENTRY",
            b"MRML SMP START",
            b"MRML SMP READY",
            b"VMX PROBE START",
            b"VMX PROBE PASS",
            b"VMX PROBE NOT PASSED - 00",
            b"VMX PROBE NOT PASSED - 12",
            b"VMX PROBE NOT PASSED - 34",
            b"VMX PROBE NOT PASSED - 56",
            b"VMX PROBE NOT PASSED - 78",
            b"VMX PROBE NOT PASSED - 9A",
            b"VMX PROBE NOT PASSED - BC",
            b"VMX PROBE NOT PASSED - DE",
            b"VMX PROBE NOT PASSED - 0F",
            b"MRML MAP EMPTY - SEND MEMMAP",
            b"MRML MAP STRIDE - SEND MEMMAP",
            b"MRML MAP TAIL - SEND MEMMAP",
            b"MRML MAP ALIGN - SEND MEMMAP",
            b"MRML MAP NO PAGES - SEND MEMMAP",
            b"MRML MAP RANGE - SEND MEMMAP",
            b"MRML MAP OVERLAP - SEND MEMMAP",
            b"MRML MAP LIMIT - SEND MEMMAP",
            b"MRML MAP FRAME - SEND MEMMAP",
        ];
        let mut bytes = [0; 39_936];
        for label in labels {
            bytes.fill(0);
            FramebufferSurface::new(info, &mut bytes)
                .unwrap()
                .draw_boot_label(
                    label,
                    Color {
                        red: 255,
                        green: 255,
                        blue: 255,
                    },
                )
                .unwrap();
            assert_eq!(&bytes[(24 * 208 + 16) * 4..][..4], &[255, 255, 255, 0]);
        }
    }

    #[test]
    fn ready_text_requires_room_and_respects_padding() {
        let info = FramebufferInfo::new(
            0x1000,
            65_536,
            320,
            48,
            322,
            PixelFormat::BlueGreenRedReserved,
        )
        .unwrap();
        let mut bytes = [0x5a; 65_536];
        FramebufferSurface::new(info, &mut bytes)
            .unwrap()
            .mark_kernel_ready(Color {
                red: 1,
                green: 2,
                blue: 3,
            })
            .unwrap();
        let offset = (24 * 322 + 16) * 4;
        assert_eq!(&bytes[offset..offset + 4], &[3, 2, 1, 0]);
        assert_eq!(&bytes[offset + 12..offset + 16], &[0x5a; 4]);
        assert_eq!(&bytes[(24 * 322 + 320) * 4..(25 * 322) * 4], &[0x5a; 8]);
        let info =
            FramebufferInfo::new(0x1000, 16, 2, 2, 2, PixelFormat::RedGreenBlueReserved).unwrap();
        let mut tiny = [0x5a; 16];
        FramebufferSurface::new(info, &mut tiny)
            .unwrap()
            .mark_kernel_ready(Color {
                red: 1,
                green: 2,
                blue: 3,
            })
            .unwrap();
        assert_eq!(tiny, [0x5a; 16]);
    }

    #[test]
    fn validates_gop_geometry_and_renders_both_pixel_orders() {
        assert_eq!(
            FramebufferInfo::new(0x1000, 64, 4, 4, 3, PixelFormat::RedGreenBlueReserved),
            Err(FramebufferError::InvalidStride)
        );
        let rgb =
            FramebufferInfo::new(0x1000, 64, 4, 4, 4, PixelFormat::RedGreenBlueReserved).unwrap();
        let mut bytes = [0u8; 64];
        {
            let mut surface = FramebufferSurface::new(rgb, &mut bytes).unwrap();
            surface
                .set_pixel(
                    1,
                    1,
                    Color {
                        red: 1,
                        green: 2,
                        blue: 3,
                    },
                )
                .unwrap();
        }
        assert_eq!(&bytes[20..24], &[1, 2, 3, 0]);

        let bgr =
            FramebufferInfo::new(0x1000, 64, 4, 4, 4, PixelFormat::BlueGreenRedReserved).unwrap();
        let mut bytes = [0u8; 64];
        FramebufferSurface::new(bgr, &mut bytes)
            .unwrap()
            .fill_rectangle(
                0,
                0,
                2,
                1,
                Color {
                    red: 1,
                    green: 2,
                    blue: 3,
                },
            )
            .unwrap();
        assert_eq!(&bytes[..8], &[3, 2, 1, 0, 3, 2, 1, 0]);
    }

    #[test]
    fn rendering_is_strictly_bounded() {
        let info =
            FramebufferInfo::new(0x1000, 64, 4, 4, 4, PixelFormat::RedGreenBlueReserved).unwrap();
        let mut short = [0u8; 63];
        assert!(matches!(
            FramebufferSurface::new(info, &mut short),
            Err(FramebufferError::BufferTooSmall)
        ));
        let mut bytes = [0u8; 64];
        let mut surface = FramebufferSurface::new(info, &mut bytes).unwrap();
        assert_eq!(
            surface.fill_rectangle(
                3,
                3,
                2,
                1,
                Color {
                    red: 0,
                    green: 0,
                    blue: 0
                }
            ),
            Err(FramebufferError::OutOfBounds)
        );
        assert_eq!(
            FramebufferInfo::new(
                0x1000,
                (isize::MAX as u64) + 1,
                1,
                1,
                1,
                PixelFormat::RedGreenBlueReserved,
            ),
            Err(FramebufferError::InvalidLength)
        );
        assert_eq!(
            FramebufferInfo::new(!0xfff, 4096, 1, 1, 1, PixelFormat::RedGreenBlueReserved,),
            Err(FramebufferError::InvalidLength)
        );
    }
}
