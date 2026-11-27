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

pub(super) fn dma_topology_verified() {
    trace(0xd5);
}

pub(super) fn dma_mmio_coverage(covered: bool) {
    trace(if covered { 0xd6 } else { 0xd7 });
}

fn trace(stage: u8) {
    // SAFETY: this diagnostic runs at CPL0 on x86 and port 0xe9 is the opt-in trace.
    unsafe { asm!("out dx, al", in("dx") 0xe9u16, in("al") stage, options(nomem, nostack)) };
}
