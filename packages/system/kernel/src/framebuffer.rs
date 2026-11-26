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
        if byte_length < required
            || byte_length > isize::MAX as u64
            || base.get().checked_add(byte_length).is_none()
        {
            return Err(FramebufferError::InvalidLength);
        }
        Ok(Self {
            base,
            byte_length,
            width,
            height,
            stride,
            format,
        })
    }

    pub const fn base(self) -> PhysAddr {
        self.base
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
    pub const fn pixel_format(self) -> PixelFormat {
        self.format
    }
    pub const fn format(self) -> PixelFormat {
        self.format
    }
    pub const fn end(self) -> u64 {
        self.base.get() + self.byte_length
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
    info: FramebufferInfo,
    bytes: &'a mut [u8],
}

impl<'a> FramebufferSurface<'a> {
    pub fn new(info: FramebufferInfo, bytes: &'a mut [u8]) -> Result<Self, FramebufferError> {
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
    /// Small diagnostic surfaces retain the existing colored marker.
    pub fn mark_kernel_ready(&mut self, color: Color) -> Result<(), FramebufferError> {
        const GLYPHS: [[u8; 7]; 10] = [
            [17, 27, 21, 21, 17, 17, 17], // M
            [30, 17, 17, 30, 20, 18, 17], // R
            [16, 16, 16, 16, 16, 16, 31], // L
            [0; 7],                       // space
            [17, 18, 20, 24, 20, 18, 17], // K
            [31, 16, 16, 30, 16, 16, 31], // E
            [17, 25, 21, 19, 17, 17, 17], // N
            [14, 17, 17, 31, 17, 17, 17], // A
            [30, 17, 17, 17, 17, 17, 30], // D
            [17, 17, 10, 4, 4, 4, 4],     // Y
        ];
        const TEXT: [usize; 17] = [0, 1, 0, 2, 3, 4, 5, 1, 6, 5, 2, 3, 1, 5, 7, 8, 9];
        const X: u32 = 16;
        const Y: u32 = 24;
        const ZOOM: u32 = 3;
        if self.info.width < X + (TEXT.len() as u32 * 6 - 1) * ZOOM
            || self.info.height < Y + 7 * ZOOM
        {
            return Ok(());
        }
        for (column, glyph) in TEXT.iter().copied().enumerate() {
            for (row, bits) in GLYPHS[glyph].iter().copied().enumerate() {
                for bit in 0..5 {
                    if bits & (1 << (4 - bit)) != 0 {
                        self.fill_rectangle(
                            X + (column as u32 * 6 + bit) * ZOOM,
                            Y + row as u32 * ZOOM,
                            ZOOM,
                            ZOOM,
                            color,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
