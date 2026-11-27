//! Opt-in firmware boot of the signed embedded-media restart test.
use super::*;
use mrml_kernel::{Color, FramebufferInfo, FramebufferSurface, PAGE_SIZE, ServiceLaunch};

type EraseRange = (u64, u64, u64, bool);

struct Diagnostic {
    retired: UserContext,
    replacement: UserContext,
    ranges: [EraseRange; 2],
    display: FramebufferInfo,
}

static mut DIAGNOSTIC: Option<Diagnostic> = None;

pub(super) fn prepare(handoff: &BootHandoff) -> UserContext {
    let display = handoff.framebuffer();
    if !paint(display, b"FAT32 RESTART: NOT PASSED") {
        halt();
    }
    trace(0xd0);
    let diagnostic = prepare_pair(handoff, display).unwrap_or_else(|| halt());
    let first = diagnostic.retired;
    // SAFETY: the BSP publishes this once before starting either user task.
    unsafe { core::ptr::addr_of_mut!(DIAGNOSTIC).write(Some(diagnostic)) };
    trace(0xd1);
    first
}

fn prepare_pair(handoff: &BootHandoff, display: FramebufferInfo) -> Option<Diagnostic> {
    let launch = handoff.service()?;
    let artifact_length = usize::try_from(launch.artifact_length()).ok()?;
    // SAFETY: validated handoff guarantees a complete read-only artifact retained by the loader.
    let artifact = unsafe {
        core::slice::from_raw_parts(
            launch.artifact_physical().get() as *const u8,
            artifact_length,
        )
    };
    let signed = SignedArtifact::decode(artifact).ok()?;
    let verified = signed
        .verify_executable(
            &TrustRoot::new(
                ArtifactKind::ServiceImage,
                embedded_service_root()?,
                embedded_service_minimum_version()?,
            ),
            ArtifactKind::ServiceImage,
        )
        .ok()?;
    let image_pages = u64::from(verified.image().image_size()).div_ceil(PAGE_SIZE);
    const STACK_PAGES: u64 = 64;
    const TABLE_PAGES: u64 = 64;
    if launch.image_pages() != image_pages.checked_mul(2)?
        || launch.stack_pages() != STACK_PAGES * 2
        || launch.table_pages() != TABLE_PAGES * 2
    {
        return None;
    }
    let slot = |index: u64| -> Option<ServiceLaunch> {
        let offset = |base: PhysAddr, pages: u64| {
            PhysAddr::new(
                base.get()
                    .checked_add(pages.checked_mul(PAGE_SIZE)?.checked_mul(index)?)?,
            )
            .ok()
        };
        ServiceLaunch::new(
            launch.artifact_physical(),
            launch.artifact_length(),
            offset(launch.image_physical(), image_pages)?,
            image_pages,
            launch.image_virtual(),
            launch.entry(),
            offset(launch.stack_physical(), STACK_PAGES)?,
            STACK_PAGES,
            launch.stack_top(),
            offset(launch.table_physical(), TABLE_PAGES)?,
            TABLE_PAGES,
            launch.version(),
            launch.measurement(),
        )
        .ok()
    };
    let first = slot(0)?;
    let second = slot(1)?;
    let context = |slot: ServiceLaunch| {
        let plan = ServiceAddressSpace::<40>::from_handoff(slot, &verified, &[]).ok()?;
        // SAFETY: the two disjoint stores were reserved and zeroed by the
        // authenticated loader. Both retain the live supervisor mappings, not a user half.
        let tables = unsafe {
            let store =
                PreallocatedPageTableStore::new(slot.table_physical(), slot.table_pages()).ok()?;
            plan.build_page_tables_with_current_kernel(store).ok()?
        };
        UserContext::new(tables.root(), plan.entry(), plan.stack_top()).ok()
    };
    Some(Diagnostic {
        retired: context(first)?,
        replacement: context(second)?,
        ranges: [
            (
                first.image_virtual(),
                first.image_physical().get(),
                image_pages,
                false,
            ),
            (
                first.stack_top().checked_sub(STACK_PAGES * PAGE_SIZE)?,
                first.stack_physical().get(),
                STACK_PAGES,
                true,
            ),
        ],
        display,
    })
}

fn diagnostic() -> &'static Diagnostic {
    // SAFETY: only called on the BSP after the immutable diagnostic is published.
    unsafe { (*core::ptr::addr_of!(DIAGNOSTIC)).as_ref() }.unwrap_or_else(|| halt())
}

pub(super) fn restart_layout() -> (UserContext, u64, [EraseRange; 2]) {
    let state = diagnostic();
    trace(0xd2);
    (
        state.replacement,
        state.retired.page_table().get(),
        state.ranges,
    )
}

pub(super) fn finish(pass: bool) {
    if pass {
        if !paint(diagnostic().display, b"FAT32 RESTART: PASS - 28 BYTES") {
            halt();
        }
        trace(0xd3);
    } else {
        paint(diagnostic().display, b"FAT32 RESTART: FAIL");
        trace(0xdf);
    }
}

pub(super) fn paint(info: FramebufferInfo, label: &[u8]) -> bool {
    // A complete one-pixel-scale label must fit even in a firmware fallback mode.
    if label.is_empty()
        || label.len() > 40
        || info.width() < 16 + (label.len() as u32 * 6 - 1)
        || info.height() < 45
    {
        return false;
    }
    // SAFETY: the loader mapped the validated framebuffer supervisor-only;
    // both roots retain that mapping, and this probe draws only on the BSP.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(info.base().get() as *mut u8, info.byte_length() as usize)
    };
    FramebufferSurface::new(info, bytes)
        .and_then(|mut surface| {
            surface.fill_rectangle(
                0,
                0,
                info.width(),
                info.height(),
                Color {
                    red: 11,
                    green: 59,
                    blue: 90,
                },
            )?;
            surface.draw_boot_label(
                label,
                Color {
                    red: 255,
                    green: 255,
                    blue: 255,
                },
            )
        })
        .is_ok()
}

pub(super) fn dma_handoff_verified() {
    trace(0xd4);
}

pub(super) fn dma_cpu_policy(verified: bool) {
    trace(if verified { 0xd8 } else { 0xd9 });
}

pub(super) fn dma_topology_verified() {
    trace(0xd5);
}

pub(super) fn dma_mmio_coverage(covered: bool) {
    trace(if covered { 0xd6 } else { 0xd7 });
}

#[cfg(feature = "q35-mmio-probe")]
pub(super) fn dma_fixture_rendezvous() -> bool {
    let scratch = || {
        let byte: u8;
        // SAFETY: this signed QEMU-only BSP fixture reads only the dedicated
        // emulated ISA serial scratch register. No interrupt or UART setup.
        unsafe { asm!("in al, dx", in("dx") 0x2ffu16, out("al") byte, options(nomem, nostack)) };
        byte
    };
    if scratch() != 0 {
        trace(0xdf);
        return false;
    }
    trace(0xdc);
    for _ in 0..100_000_000 {
        match scratch() {
            0 => core::hint::spin_loop(),
            0xa6 => {
                trace(0xde);
                return true;
            }
            _ => {
                trace(0xdd);
                return false;
            }
        }
    }
    trace(0xdf);
    false
}

/// Samples only aligned fixed RO registers of the two verified fixture pages.
/// The caller must keep the verified root active throughout these reads.
#[cfg(feature = "q35-mmio-probe")]
pub(super) unsafe fn dma_fixture_register_snapshot(
    mappings: [Option<mrml_kernel::arch::x86_64::Mapping>; 3],
) {
    use mrml_kernel::arch::x86_64::VtdRegisterLayout;
    let [Some(drhd), Some(ecam), bridge] =
        mappings.map(|mapping| mapping.map(|page| page.virtual_start().get() as usize))
    else {
        trace(0xdb);
        return;
    };
    // SAFETY: the caller establishes the current, exact, alias-free UC leaves
    // and release. Only fixed aligned widths inside the proven apertures.
    let (version, cap, ecap, status, pci_id, pci_command, pci_class, header, bar0, bar1) = unsafe {
        (
            core::ptr::read_volatile((drhd) as *const u32),
            core::ptr::read_volatile((drhd + 0x08) as *const u64),
            core::ptr::read_volatile((drhd + 0x10) as *const u64),
            core::ptr::read_volatile((drhd + 0x1c) as *const u32),
            core::ptr::read_volatile(ecam as *const u32),
            core::ptr::read_volatile((ecam + 0x04) as *const u16),
            core::ptr::read_volatile((ecam + 0x08) as *const u32),
            core::ptr::read_volatile((ecam + 0x0e) as *const u8),
            core::ptr::read_volatile((ecam + 0x10) as *const u32),
            core::ptr::read_volatile((ecam + 0x14) as *const u32),
        )
    };
    if version != 0x10
        || VtdRegisterLayout::from_capabilities(cap, ecap)
            .and_then(|layout| layout.require_aperture(0x230))
            .is_err()
        || pci_id != 0x000d_1b36
        || pci_class >> 8 != 0x0c0330
        || header & 0x7f != 0
        || pci_command & 2 == 0
        || bar0 & 0xf != 4
    {
        trace(0xdb);
        return;
    }
    let (bridge_command, bridge_buses) = match bridge {
        None => (0, 0),
        Some(bridge) => {
            // SAFETY: the caller verified the signed isolated model's exact
            // RO/NX UC bridge leaf before the host proved and released it.
            let (identity, command, class, header, buses) = unsafe {
                (
                    core::ptr::read_volatile(bridge as *const u32),
                    core::ptr::read_volatile((bridge + 4) as *const u16),
                    core::ptr::read_volatile((bridge + 8) as *const u32),
                    core::ptr::read_volatile((bridge + 14) as *const u8),
                    core::ptr::read_volatile((bridge + 0x18) as *const u32),
                )
            };
            if identity != 0x000c_1b36
                || class >> 16 != 0x0604
                || header & 0x7f != 1
                || buses & 0x00ff_ffff != 0x0041_4140
                || status != 0
            {
                trace(0xdb);
                return;
            }
            (command, buses)
        }
    };
    for bytes in [
        &version.to_le_bytes()[..],
        &cap.to_le_bytes(),
        &ecap.to_le_bytes(),
        &status.to_le_bytes(),
        &pci_id.to_le_bytes(),
        &pci_command.to_le_bytes(),
        &pci_class.to_le_bytes(),
        &[header],
        &bar0.to_le_bytes(),
        &bar1.to_le_bytes(),
        &bridge_command.to_le_bytes(),
        &bridge_buses.to_le_bytes(),
    ] {
        for &byte in bytes {
            trace(byte);
        }
    }
    trace(0xda);
}

fn trace(stage: u8) {
    // SAFETY: this diagnostic runs at CPL0 on x86 and port 0xe9 is the opt-in trace.
    unsafe { asm!("out dx, al", in("dx") 0xe9u16, in("al") stage, options(nomem, nostack)) };
}
