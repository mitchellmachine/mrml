//! Boot scanout rendering performed by the compositor, not the kernel.
use mrml_kernel::{
    Capability, CapabilitySpace, Color, DisplayOutputIdentity, FramebufferError, FramebufferLayout,
    FramebufferSurface, IsolationAdmissionTable, IsolationMode, IsolationPlacement,
    IsolationServiceSpec, Rights, RoutedIsolationService, TotalMicrovmClass,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootScanoutError {
    InvalidRoute,
    CaptureUnavailable,
    StaleOutput,
    WrongAuthority,
    Framebuffer(FramebufferError),
}

/// Draw into compositor-private RAM. This grants no display authority.
pub fn render_private_boot_frame(
    layout: FramebufferLayout,
    pixels: &mut [u8],
) -> Result<(), BootScanoutError> {
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

/// Select projection without changing display authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootProjection {
    ExactTopLeft,
    FitCentered,
}

/// Publish only from the exact running compositor route under strict Total.
///
/// The trusted supervisor supplies the original admission table, the current
/// route specification, and a capture operation bound to the concrete endpoint.
/// The capture must return a stable frame snapshot, not mutable guest memory.
/// The trusted transport supplies the negotiated source layout and the output
/// owner supplies the current GOP-derived layout. This performs no firmware call
/// or mapping and never gives the guest access to the output aperture.
#[allow(clippy::too_many_arguments)]
pub fn publish_total_guest_scanout<'frame, E, const N: usize, const DOMAINS: usize>(
    admission: &IsolationAdmissionTable<DOMAINS>,
    route: &RoutedIsolationService<E>,
    expected: IsolationServiceSpec,
    capabilities: &CapabilitySpace<N>,
    control: Capability,
    binding: DisplayOutputIdentity,
    current: DisplayOutputIdentity,
    source_layout: FramebufferLayout,
    output_layout: FramebufferLayout,
    projection: BootProjection,
    capture: impl FnOnce(&E) -> Option<&'frame [u8]>,
    scanout: &mut [u8],
) -> Result<(), BootScanoutError> {
    if admission.mode() != IsolationMode::TotalMicrovm
        || route.class() != TotalMicrovmClass::MicrovmEligible
        || route.placement() != IsolationPlacement::Microvm
        || expected.class() != route.class()
        || expected.placement() != route.placement()
        || expected.domain() != route.domain()
        || expected.interface() != route.interface()
        || expected.interface_generation() != route.interface_generation()
        || expected.provider_generation() != route.provider_generation()
        || expected.system_generation() != route.system_generation()
        || expected.policy_generation() != route.policy_generation()
        || !route.is_live_in(admission)
    {
        return Err(BootScanoutError::InvalidRoute);
    }
    validate_output(capabilities, control, binding, current)?;
    let frame = capture(route.endpoint()).ok_or(BootScanoutError::CaptureUnavailable)?;
    match projection {
        BootProjection::ExactTopLeft => {
            copy_visible_pixels(source_layout, frame, output_layout, scanout)
        }
        BootProjection::FitCentered => {
            fit_visible_pixels(source_layout, frame, output_layout, scanout)
        }
    }
}

fn copy_visible_pixels(
    source: FramebufferLayout,
    guest_frame: &[u8],
    output: FramebufferLayout,
    scanout: &mut [u8],
) -> Result<(), BootScanoutError> {
    if guest_frame.len() != source.byte_length() as usize {
        return Err(BootScanoutError::Framebuffer(
            FramebufferError::InvalidLength,
        ));
    }
    if scanout.len() < output.byte_length() as usize {
        return Err(BootScanoutError::Framebuffer(
            FramebufferError::BufferTooSmall,
        ));
    }
    if source.width() > output.width() || source.height() > output.height() {
        return Err(BootScanoutError::Framebuffer(FramebufferError::OutOfBounds));
    }

    // Layout construction validates the stride and its full extent. All
    // validation precedes the first write. An exact, top-left rectangle is
    // enough for the boot marker; no scaling, clipping or mode switching.
    let source_stride = source.stride() as usize * 4;
    let output_stride = output.stride() as usize * 4;
    let visible = source.width() as usize * 4;
    let rows = source.height() as usize;
    let swap = source.format() != output.format();
    for (src, dst) in guest_frame
        .chunks_exact(source_stride)
        .zip(scanout.chunks_exact_mut(output_stride))
        .take(rows)
    {
        for (pixel, out) in src[..visible]
            .chunks_exact(4)
            .zip(dst[..visible].chunks_exact_mut(4))
        {
            let (first, third) = if swap {
                (pixel[2], pixel[0])
            } else {
                (pixel[0], pixel[2])
            };
            out.copy_from_slice(&[first, pixel[1], third, 0]);
        }
    }
    Ok(())
}

fn fit_viewport(sw: usize, sh: usize, w: usize, h: usize) -> (usize, usize, usize, usize) {
    let scale = (w / sw).min(h / sh);
    let (dw, dh) = if scale != 0 {
        (sw * scale, sh * scale)
    } else if w * sh <= h * sw {
        (w, (w * sh / sw).max(1))
    } else {
        ((h * sw / sh).max(1), h)
    };
    ((w - dw) / 2, (h - dh) / 2, dw, dh)
}

fn fit_visible_pixels(
    source: FramebufferLayout,
    guest_frame: &[u8],
    output: FramebufferLayout,
    scanout: &mut [u8],
) -> Result<(), BootScanoutError> {
    if guest_frame.len() != source.byte_length() as usize {
        return Err(BootScanoutError::Framebuffer(
            FramebufferError::InvalidLength,
        ));
    }
    if scanout.len() < output.byte_length() as usize {
        return Err(BootScanoutError::Framebuffer(
            FramebufferError::BufferTooSmall,
        ));
    }
    // Layouts limit dimensions to 16,384. Products of two dimensions fit
    // usize on the supported targets; row padding and spare bytes stay intact.
    let (sw, sh) = (source.width() as usize, source.height() as usize);
    let (w, h) = (output.width() as usize, output.height() as usize);
    let (x, y, dw, dh) = fit_viewport(sw, sh, w, h);
    let ss = source.stride() as usize * 4;
    let ds = output.stride() as usize * 4;
    let swap = source.format() != output.format();
    let bg = match output.format() {
        mrml_kernel::PixelFormat::RedGreenBlueReserved => [0x0b, 0x3b, 0x5a, 0],
        mrml_kernel::PixelFormat::BlueGreenRedReserved => [0x5a, 0x3b, 0x0b, 0],
    };
    for (dy, row) in scanout.chunks_exact_mut(ds).take(h).enumerate() {
        let inside_y = (y..y + dh).contains(&dy);
        let source_row = if inside_y { (dy - y) * sh / dh * ss } else { 0 };
        for (dx, pixel) in row[..w * 4].chunks_exact_mut(4).enumerate() {
            let value = if inside_y && (x..x + dw).contains(&dx) {
                let offset = source_row + (dx - x) * sw / dw * 4;
                let src = &guest_frame[offset..offset + 4];
                if swap {
                    [src[2], src[1], src[0], 0]
                } else {
                    [src[0], src[1], src[2], 0]
                }
            } else {
                bg
            };
            pixel.copy_from_slice(&value);
        }
    }
    Ok(())
}

fn validate_output<const N: usize>(
    capabilities: &CapabilitySpace<N>,
    control: Capability,
    binding: DisplayOutputIdentity,
    current: DisplayOutputIdentity,
) -> Result<(), BootScanoutError> {
    if binding != current {
        return Err(BootScanoutError::StaleOutput);
    }
    if capabilities.authorize_exact(control, Rights::CONTROL) != Ok(current.object()) {
        return Err(BootScanoutError::WrongAuthority);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_kernel::PixelFormat;

    #[test]
    fn private_raster_projects_to_both_gop_formats_without_touching_other_pixels() {
        let source = FramebufferLayout::new(
            132 * 32 * 4 + 4,
            128,
            32,
            132,
            PixelFormat::BlueGreenRedReserved,
        )
        .unwrap();
        let mut frame = [0xEE; 132 * 32 * 4 + 4];
        render_private_boot_frame(source, &mut frame).unwrap();
        assert_eq!(&frame[128 * 4..132 * 4], &[0xEE; 16]);
        frame[3] = 0xEE;
        for (format, pixel) in [
            (PixelFormat::RedGreenBlueReserved, [0x0b, 0x3b, 0x5a, 0]),
            (PixelFormat::BlueGreenRedReserved, [0x5a, 0x3b, 0x0b, 0]),
        ] {
            let output = FramebufferLayout::new(160 * 40 * 4 + 8, 144, 40, 160, format).unwrap();
            let mut screen = [0xa7; 160 * 40 * 4 + 16];
            copy_visible_pixels(source, &frame, output, &mut screen).unwrap();
            assert_eq!(&screen[..4], &pixel);
            assert_eq!(&screen[(24 * 160 + 16) * 4..][..4], &[255, 255, 255, 0]);
            for row in screen[..160 * 32 * 4].chunks_exact(160 * 4) {
                assert!(row[128 * 4..].iter().all(|&byte| byte == 0xa7));
            }
            assert!(screen[160 * 32 * 4..].iter().all(|&byte| byte == 0xa7));
        }
    }

    #[test]
    fn total_scanout_captures_only_from_current_admitted_microvm() {
        use mrml_kernel::{ObjectId, PixelFormat, prepare_isolation_service_route};

        let spec = |generation, placement| {
            IsolationServiceSpec::new(
                ObjectId(1),
                ObjectId(2),
                1,
                generation,
                3,
                4,
                TotalMicrovmClass::MicrovmEligible,
                placement,
            )
            .unwrap()
        };
        let microvm = spec(5, IsolationPlacement::Microvm);
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, 3, 4).unwrap();
        let route = prepare_isolation_service_route(&mut admission, microvm)
            .unwrap()
            .commit(&mut admission, 7u64)
            .unwrap();
        let output = DisplayOutputIdentity::new(ObjectId(6), 1).unwrap();
        let mut caps = CapabilitySpace::<5>::new();
        let grant = caps.insert(output.object(), Rights::CONTROL).unwrap();
        let revoked = caps.insert(output.object(), Rights::CONTROL).unwrap();
        caps.revoke(revoked).unwrap();
        let wrong_output = caps.insert(ObjectId(7), Rights::CONTROL).unwrap();
        let inspect = caps.insert(output.object(), Rights::INSPECT).unwrap();
        let broad = caps
            .insert(output.object(), Rights::CONTROL.union(Rights::DELEGATE))
            .unwrap();
        let replaced_output = DisplayOutputIdentity::new(output.object(), 2).unwrap();
        let layout = FramebufferLayout::new(4, 1, 1, 1, PixelFormat::BlueGreenRedReserved).unwrap();
        let frame = [5, 6, 7, 0];
        let mut screen = [0xa7; 4];

        for (capability, current, error) in [
            (grant, replaced_output, BootScanoutError::StaleOutput),
            (revoked, output, BootScanoutError::WrongAuthority),
            (wrong_output, output, BootScanoutError::WrongAuthority),
            (inspect, output, BootScanoutError::WrongAuthority),
            (broad, output, BootScanoutError::WrongAuthority),
        ] {
            assert_eq!(
                publish_total_guest_scanout(
                    &admission,
                    &route,
                    microvm,
                    &caps,
                    capability,
                    output,
                    current,
                    layout,
                    layout,
                    BootProjection::ExactTopLeft,
                    |_| panic!("invalid output authority captured"),
                    &mut screen
                ),
                Err(error)
            );
            assert_eq!(screen, [0xa7; 4]);
        }

        let wrong_provider = spec(6, IsolationPlacement::Microvm);
        assert_eq!(
            publish_total_guest_scanout(
                &admission,
                &route,
                wrong_provider,
                &caps,
                grant,
                output,
                output,
                layout,
                layout,
                BootProjection::ExactTopLeft,
                |_| panic!("wrong provider captured"),
                &mut screen,
            ),
            Err(BootScanoutError::InvalidRoute)
        );
        assert_eq!(screen, [0xa7; 4]);
        publish_total_guest_scanout(
            &admission,
            &route,
            microvm,
            &caps,
            grant,
            output,
            output,
            layout,
            layout,
            BootProjection::ExactTopLeft,
            |endpoint| {
                assert_eq!(*endpoint, 7);
                Some(&frame)
            },
            &mut screen,
        )
        .unwrap();
        assert_eq!(screen, frame);

        admission.retire(microvm.domain()).unwrap();
        let replacement = prepare_isolation_service_route(&mut admission, microvm)
            .unwrap()
            .commit(&mut admission, 8u64)
            .unwrap();
        assert_eq!(
            publish_total_guest_scanout(
                &admission,
                &route,
                microvm,
                &caps,
                grant,
                output,
                output,
                layout,
                layout,
                BootProjection::ExactTopLeft,
                |_| panic!("retired guest captured"),
                &mut screen,
            ),
            Err(BootScanoutError::InvalidRoute)
        );
        assert_eq!(
            publish_total_guest_scanout(
                &admission,
                &replacement,
                microvm,
                &caps,
                grant,
                output,
                output,
                layout,
                layout,
                BootProjection::ExactTopLeft,
                |endpoint| {
                    assert_eq!(*endpoint, 8);
                    None
                },
                &mut screen,
            ),
            Err(BootScanoutError::CaptureUnavailable)
        );

        let mut balanced =
            IsolationAdmissionTable::<1>::new(IsolationMode::HostedRegression, 3, 4).unwrap();
        let native = spec(5, IsolationPlacement::NativeService);
        let native_route = prepare_isolation_service_route(&mut balanced, native)
            .unwrap()
            .commit(&mut balanced, 9u64)
            .unwrap();
        assert_eq!(
            publish_total_guest_scanout(
                &balanced,
                &native_route,
                native,
                &caps,
                grant,
                output,
                output,
                layout,
                layout,
                BootProjection::ExactTopLeft,
                |_| panic!("native fallback captured"),
                &mut screen,
            ),
            Err(BootScanoutError::InvalidRoute)
        );
        assert_eq!(screen, frame);
    }

    #[test]
    fn viewport_fits_standard_hidpi_portrait_and_small_modes() {
        for (w, h, expected) in [
            (1024, 768, (32, 104, 960, 560)),
            (1920, 1080, (60, 15, 1800, 1050)),
            (3840, 2160, (120, 30, 3600, 2100)),
            (768, 1024, (24, 302, 720, 420)),
            (60, 40, (0, 2, 60, 35)),
            (1, 1, (0, 0, 1, 1)),
        ] {
            assert_eq!(fit_viewport(120, 70, w, h), expected);
        }
    }

    #[test]
    fn fit_centers_converts_and_preserves_padding() {
        let source =
            FramebufferLayout::new(12, 2, 1, 3, PixelFormat::BlueGreenRedReserved).unwrap();
        let output =
            FramebufferLayout::new(112, 5, 4, 7, PixelFormat::RedGreenBlueReserved).unwrap();
        let mut screen = [0xa7; 116];
        let frame = [5, 6, 7, 255, 8, 9, 10, 255, 0xde, 0xad, 0xbe, 0xef];
        fit_visible_pixels(source, &frame, output, &mut screen).unwrap();
        let bg = [0x0b, 0x3b, 0x5a, 0];
        for (y, row) in screen[..112].chunks_exact(28).enumerate() {
            for (x, pixel) in row[..20].chunks_exact(4).enumerate() {
                let expected = match (y, x) {
                    (1..=2, 0..=1) => [7, 6, 5, 0],
                    (1..=2, 2..=3) => [10, 9, 8, 0],
                    _ => bg,
                };
                assert_eq!(pixel, expected);
            }
            assert_eq!(&row[20..], &[0xa7; 8]);
        }
        assert_eq!(&screen[112..], &[0xa7; 4]);
        let before = screen;
        assert!(fit_visible_pixels(source, &frame[..11], output, &mut screen).is_err());
        assert!(fit_visible_pixels(source, &frame, output, &mut screen[..111]).is_err());
        assert_eq!(screen, before);
    }

    #[test]
    fn invalid_geometry_and_lengths_never_partially_publish() {
        let layout =
            FramebufferLayout::new(16, 2, 2, 2, PixelFormat::RedGreenBlueReserved).unwrap();
        let small = FramebufferLayout::new(8, 1, 2, 1, PixelFormat::RedGreenBlueReserved).unwrap();
        let guest = [1; 16];
        let mut sink = [0xa7; 16];
        assert_eq!(
            copy_visible_pixels(layout, &guest[..15], layout, &mut sink),
            Err(BootScanoutError::Framebuffer(
                FramebufferError::InvalidLength
            ))
        );
        assert_eq!(
            copy_visible_pixels(layout, &guest, layout, &mut sink[..15]),
            Err(BootScanoutError::Framebuffer(
                FramebufferError::BufferTooSmall
            ))
        );
        assert_eq!(
            copy_visible_pixels(layout, &guest, small, &mut sink),
            Err(BootScanoutError::Framebuffer(FramebufferError::OutOfBounds))
        );
        assert_eq!(sink, [0xa7; 16]);
    }
}
