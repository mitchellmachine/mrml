//! Boot scanout rendering performed by the compositor, not the kernel.
use mrml_kernel::{
    Capability, CapabilitySpace, Color, DisplayOutputIdentity, FramebufferError, FramebufferLayout,
    FramebufferSurface, Rights,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootScanoutError {
    StaleOutput,
    WrongAuthority,
    Framebuffer(FramebufferError),
}

/// Paint the marker into one scanout slice lent to the compositor.
///
/// The trusted caller must provide the current output identity and its exact
/// bounded slice. Neither the identity nor the geometry authorizes a mapping.
/// The output control capability must be checked again on every call.
pub fn paint_boot_ready<const N: usize>(
    capabilities: &CapabilitySpace<N>,
    control: Capability,
    binding: DisplayOutputIdentity,
    current: DisplayOutputIdentity,
    layout: FramebufferLayout,
    pixels: &mut [u8],
) -> Result<(), BootScanoutError> {
    if binding != current {
        return Err(BootScanoutError::StaleOutput);
    }
    if capabilities.authorize_exact(control, Rights::CONTROL) != Ok(current.object()) {
        return Err(BootScanoutError::WrongAuthority);
    }
    let mut surface =
        FramebufferSurface::from_layout(layout, pixels).map_err(BootScanoutError::Framebuffer)?;
    surface
        .fill_rectangle(
            0,
            0,
            layout.width(),
            layout.height(),
            Color {
                red: 0x0b,
                green: 0x3b,
                blue: 0x5a,
            },
        )
        .map_err(BootScanoutError::Framebuffer)?;
    surface
        .mark_kernel_ready(Color {
            red: 0xff,
            green: 0xff,
            blue: 0xff,
        })
        .map_err(BootScanoutError::Framebuffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_kernel::{ObjectId, PixelFormat};

    #[test]
    fn paint_preserves_padding_and_bytes_outside_scanout() {
        let mut caps = CapabilitySpace::<2>::new();
        let output = DisplayOutputIdentity::new(ObjectId(5), 1).unwrap();
        let control = caps.insert(output.object(), Rights::CONTROL).unwrap();
        let layout = FramebufferLayout::new(
            1440 * 48 + 8,
            352,
            48,
            360,
            PixelFormat::BlueGreenRedReserved,
        )
        .unwrap();
        let mut pixels = [0xa7; 1440 * 48 + 16];
        paint_boot_ready(&caps, control, output, output, layout, &mut pixels).unwrap();
        assert_eq!(&pixels[..4], &[0x5a, 0x3b, 0x0b, 0]);
        assert_eq!(&pixels[24 * 1440 + 16 * 4..][..4], &[255, 255, 255, 0]);
        for row in pixels[..1440 * 48].chunks_exact(1440) {
            assert_eq!(&row[352 * 4..], &[0xa7; 32]);
        }
        assert_eq!(&pixels[1440 * 48..], &[0xa7; 16]);
    }

    #[test]
    fn rejected_calls_cannot_write_pixels() {
        let mut caps = CapabilitySpace::<4>::new();
        let output = DisplayOutputIdentity::new(ObjectId(5), 1).unwrap();
        let replacement = DisplayOutputIdentity::new(ObjectId(5), 2).unwrap();
        let control = caps.insert(output.object(), Rights::CONTROL).unwrap();
        let inspect = caps.insert(output.object(), Rights::INSPECT).unwrap();
        let other = caps.insert(ObjectId(6), Rights::CONTROL).unwrap();
        let broad = caps
            .insert(output.object(), Rights::CONTROL.union(Rights::DELEGATE))
            .unwrap();
        let layout =
            FramebufferLayout::new(16, 2, 2, 2, PixelFormat::RedGreenBlueReserved).unwrap();
        let mut pixels = [0xa7; 16];
        assert_eq!(
            paint_boot_ready(&caps, control, output, replacement, layout, &mut pixels),
            Err(BootScanoutError::StaleOutput)
        );
        for cap in [inspect, other, broad] {
            assert_eq!(
                paint_boot_ready(&caps, cap, output, output, layout, &mut pixels),
                Err(BootScanoutError::WrongAuthority)
            );
        }
        assert_eq!(
            paint_boot_ready(&caps, control, output, output, layout, &mut pixels[..15]),
            Err(BootScanoutError::Framebuffer(
                FramebufferError::BufferTooSmall
            ))
        );
        caps.revoke(control).unwrap();
        assert_eq!(
            paint_boot_ready(&caps, control, output, output, layout, &mut pixels),
            Err(BootScanoutError::WrongAuthority)
        );
        assert_eq!(pixels, [0xa7; 16]);
    }
}
