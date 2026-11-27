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
    validate_output(capabilities, control, binding, current)?;
    render_private_boot_frame(layout, pixels)
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

/// Publish only from the exact running compositor route under strict Total.
///
/// The trusted supervisor supplies the original admission table, the current
/// route specification, and a capture operation bound to the concrete endpoint.
/// The capture must return a stable frame snapshot, not mutable guest memory.
#[allow(clippy::too_many_arguments)]
pub fn publish_total_guest_scanout<'frame, E, const N: usize, const DOMAINS: usize>(
    admission: &IsolationAdmissionTable<DOMAINS>,
    route: &RoutedIsolationService<E>,
    expected: IsolationServiceSpec,
    capabilities: &CapabilitySpace<N>,
    control: Capability,
    binding: DisplayOutputIdentity,
    current: DisplayOutputIdentity,
    layout: FramebufferLayout,
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
    copy_visible_pixels(layout, frame, scanout)
}

/// Publish a compositor-rendered microVM frame into a host-owned scanout.
///
/// The projection owner supplies the captured guest image and lends the
/// exact output slice and geometry. No physical address or scanout slice is
/// passed into the guest. Copy only visible pixels, leaving scanout padding
/// and allocation tail private. This is a copy primitive, not guest launch.
#[cfg(test)]
fn publish_guest_scanout<const N: usize>(
    capabilities: &CapabilitySpace<N>,
    control: Capability,
    binding: DisplayOutputIdentity,
    current: DisplayOutputIdentity,
    layout: FramebufferLayout,
    guest_frame: &[u8],
    scanout: &mut [u8],
) -> Result<(), BootScanoutError> {
    validate_output(capabilities, control, binding, current)?;
    copy_visible_pixels(layout, guest_frame, scanout)
}

fn copy_visible_pixels(
    layout: FramebufferLayout,
    guest_frame: &[u8],
    scanout: &mut [u8],
) -> Result<(), BootScanoutError> {
    let declared = layout.byte_length() as usize;
    if guest_frame.len() != declared || scanout.len() < declared {
        return Err(BootScanoutError::Framebuffer(
            FramebufferError::InvalidLength,
        ));
    }
    // FramebufferLayout validates these products and the full stride extent.
    let stride = layout.stride() as usize * 4;
    let row_pixels = layout.width() as usize * 4;
    let frame_bytes = stride * layout.height() as usize;
    for (guest, hardware) in guest_frame[..frame_bytes]
        .chunks_exact(stride)
        .zip(scanout[..frame_bytes].chunks_exact_mut(stride))
    {
        hardware[..row_pixels].copy_from_slice(&guest[..row_pixels]);
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
    fn microvm_frame_copy_never_exposes_scanout_padding_and_fails_closed() {
        let mut caps = CapabilitySpace::<2>::new();
        let output = DisplayOutputIdentity::new(ObjectId(5), 1).unwrap();
        let replacement = DisplayOutputIdentity::new(ObjectId(5), 2).unwrap();
        let control = caps.insert(output.object(), Rights::CONTROL).unwrap();
        let layout =
            FramebufferLayout::new(26, 2, 2, 3, PixelFormat::RedGreenBlueReserved).unwrap();
        let mut guest = [0x55; 26];
        let mut scanout = [0xa7; 28];
        paint_boot_ready(&caps, control, output, output, layout, &mut guest).unwrap();
        assert_eq!(
            publish_guest_scanout(
                &caps,
                control,
                output,
                replacement,
                layout,
                &guest,
                &mut scanout
            ),
            Err(BootScanoutError::StaleOutput)
        );
        assert_eq!(
            publish_guest_scanout(
                &caps,
                control,
                output,
                output,
                layout,
                &guest[..25],
                &mut scanout
            ),
            Err(BootScanoutError::Framebuffer(
                FramebufferError::InvalidLength
            ))
        );
        assert_eq!(scanout, [0xa7; 28]);
        publish_guest_scanout(&caps, control, output, output, layout, &guest, &mut scanout)
            .unwrap();
        assert_eq!(&scanout[0..8], &guest[0..8]);
        assert_eq!(&scanout[12..20], &guest[12..20]);
        assert_eq!(&scanout[8..12], &[0xa7; 4]);
        assert_eq!(&scanout[20..28], &[0xa7; 8]);
        caps.revoke(control).unwrap();
        assert_eq!(
            publish_guest_scanout(&caps, control, output, output, layout, &guest, &mut scanout),
            Err(BootScanoutError::WrongAuthority)
        );
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
        let mut caps = CapabilitySpace::<1>::new();
        let grant = caps.insert(output.object(), Rights::CONTROL).unwrap();
        let layout = FramebufferLayout::new(4, 1, 1, 1, PixelFormat::BlueGreenRedReserved).unwrap();
        let frame = [5, 6, 7, 0];
        let mut screen = [0xa7; 4];

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
                |endpoint| {
                    assert_eq!(*endpoint, 8);
                    None
                },
                &mut screen,
            ),
            Err(BootScanoutError::CaptureUnavailable)
        );

        let mut balanced =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, 3, 4).unwrap();
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
                |_| panic!("native fallback captured"),
                &mut screen,
            ),
            Err(BootScanoutError::InvalidRoute)
        );
        assert_eq!(screen, frame);
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
