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
pub(super) fn fixture_scratch() -> u8 {
    let byte: u8;
    // SAFETY: this signed QEMU-only BSP fixture reads only the dedicated
    // emulated ISA serial scratch register. No interrupt or UART setup.
    unsafe { asm!("in al, dx", in("dx") 0x2ffu16, out("al") byte, options(nomem, nostack)) };
    byte
}

#[cfg(feature = "q35-mmio-probe")]
pub(super) fn dma_fixture_rendezvous(expected: u8) -> bool {
    if fixture_scratch() != 0 {
        trace(0xdf);
        return false;
    }
    trace(0xdc);
    for _ in 0..100_000_000 {
        match fixture_scratch() {
            0 => core::hint::spin_loop(),
            byte if byte == expected => {
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

/// Samples fixed registers; the sealed shutdown case also clears two BME bits.
/// The caller must keep the verified root active throughout these reads.
#[cfg(feature = "q35-mmio-probe")]
pub(super) unsafe fn dma_fixture_register_snapshot(
    mappings: [Option<mrml_kernel::arch::x86_64::Mapping>; 4],
    shutdown: bool,
    bar_preflight: bool,
    cold: Option<(
        &ActivePageTables,
        &mrml_kernel::arch::x86_64::InitializedBootDma,
        &[u8],
    )>,
    release: u8,
) {
    use mrml_kernel::arch::x86_64::VtdRegisterLayout;
    let [Some(drhd), Some(ecam), bridge, xhci] =
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
    let (xhci_cap0, xhci_command, xhci_status) = match (bridge, xhci) {
        (None, None) => (0u32, 0u32, 0u32),
        (Some(_), Some(xhci)) => {
            if bar0 != 0x8120_0004 || bar1 != 0 {
                trace(0xdb);
                return;
            }
            // SAFETY: the signed isolated fixture checked the exact active
            // RO/NX UC BAR page and a matching live PCI assignment. The host
            // verified this entire page before releasing the sole boot CPU.
            let (cap0, command, status) = unsafe {
                let cap0 = core::ptr::read_volatile(xhci as *const u32);
                if cap0 != 0x0100_0040 {
                    trace(0xdb);
                    return;
                }
                (
                    cap0,
                    core::ptr::read_volatile((xhci + 0x40) as *const u32),
                    core::ptr::read_volatile((xhci + 0x44) as *const u32),
                )
            };
            (cap0, command, status)
        }
        _ => {
            trace(0xdb);
            return;
        }
    };
    if bar_preflight {
        let Some(xhci) = xhci else {
            trace(0xdb);
            return;
        };
        use mrml_storage_usb::xhci::{LegacyOwnership, inspect_legacy_ownership};
        // SAFETY: exact three-page BAR and host release. The four
        // fixed dwords are within the proved subregions; the capability
        // walker can read aligned dwords only inside the first 0x40 bytes.
        let (extended, ownership) = unsafe {
            let extended = [0x14, 0x18, 0x1020, 0x2000]
                .map(|offset| core::ptr::read_volatile((xhci + offset) as *const u32));
            let ownership = inspect_legacy_ownership(0x40, |offset| {
                Ok::<_, ()>(core::ptr::read_volatile(
                    (xhci + offset as usize) as *const u32,
                ))
            });
            (extended, ownership)
        };
        if !matches!(ownership, Ok(LegacyOwnership::Absent))
            || extended[0] != 0x2000
            || extended[1] != 0x1000
            || extended[2] & !3 != 0
            || extended[3] != 0
            || xhci_command != 0
            || xhci_status != 1
        {
            trace(0xdb);
            return;
        }
    }
    let (endpoint_after, bridge_after) = if shutdown {
        let Some(bridge) = bridge else {
            trace(0xdb);
            return;
        };
        // This first shutdown test refuses a running, resetting, not-ready or
        // faulted controller. No controller register writes are admitted.
        if xhci_command != 0 || xhci_status != 1 || pci_command != 7 || bridge_command != 7 {
            trace(0xdb);
            return;
        }
        // SAFETY: the shutdown-only mapping and release authorizes exactly
        // these two PCI COMMAND words in the owned QEMU subtree. BAR and
        // remapper mappings stay read-only. Guest executes alone at CPL0.
        let completed = unsafe {
            let endpoint = (ecam + 4) as *mut u16;
            let root_port = (bridge + 4) as *mut u16;
            if endpoint.read_volatile() != pci_command
                || root_port.read_volatile() != bridge_command
            {
                None
            } else {
                endpoint.write_volatile(pci_command & !4);
                let endpoint_after = endpoint.read_volatile();
                if endpoint_after != pci_command & !4 {
                    None
                } else {
                    root_port.write_volatile(bridge_command & !4);
                    let bridge_after = root_port.read_volatile();
                    (bridge_after == bridge_command & !4).then_some((endpoint_after, bridge_after))
                }
            }
        };
        let Some(commands) = completed else {
            // No retries, re-enable, or continuation after uncertain state.
            trace(0xdb);
            return;
        };
        commands
    } else {
        (0u16, 0u16)
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
        &xhci_cap0.to_le_bytes(),
        &xhci_command.to_le_bytes(),
        &xhci_status.to_le_bytes(),
        &endpoint_after.to_le_bytes(),
        &bridge_after.to_le_bytes(),
    ] {
        for &byte in bytes {
            trace(byte);
        }
    }
    trace(0xda);
    if let Some((active, dma, dmar)) = cold
        && !fixture_activate(
            active,
            dma,
            dmar,
            pci_id,
            bridge_buses,
            if matches!(release, 0xaa..=0xac) {
                mappings[3]
            } else {
                None
            },
            matches!(release, 0xab | 0xac),
        )
    {
        trace(0xdb);
    }
}

#[cfg(feature = "q35-mmio-probe")]
fn fixture_activate(
    active: &ActivePageTables,
    dma: &mrml_kernel::arch::x86_64::InitializedBootDma,
    dmar: &[u8],
    endpoint_id: u32,
    bridge_buses: u32,
    command_bar: Option<mrml_kernel::arch::x86_64::Mapping>,
    media: bool,
) -> bool {
    use mrml_kernel::arch::x86_64::{
        DmarTopology, PciConfigSpace, SINGLE_REQUESTER_VTD_TABLE_PAGES, VerifiedVtdUnit,
        VtdDmaAperture, prepare_cold_legacy_vtd_root, verify_q35_activation_mmio,
    };
    use mrml_kernel::{DeviceAddress, PhysAddr};

    // The signed snapshot verified the live endpoint and root-port identity,
    // header kind, bus numbers, controller halt and both BME readbacks.
    struct ObservedConfig {
        endpoint_id: u32,
        buses: u32,
    }
    impl PciConfigSpace for ObservedConfig {
        fn read_u32(&mut self, address: DeviceAddress, offset: u16) -> Option<u32> {
            match (
                address.segment(),
                address.bus(),
                address.device(),
                address.function(),
                offset,
            ) {
                (0, 0x41, 0, 0, 0) => Some(self.endpoint_id),
                (0, 0x40, 0, 0, 0) => Some(0x000c_1b36),
                (0, 0x40, 0, 0, 0x0c) => Some(1 << 16),
                (0, 0x40, 0, 0, 0x18) => Some(self.buses),
                _ => None,
            }
        }
    }

    let result = (|| {
        let topology = DmarTopology::<1, 64>::parse(dmar).ok()?;
        let requester = DeviceAddress::new(0, 0x41, 0, 0).ok()?;
        let route = topology
            .route_for_requester(
                requester,
                &mut ObservedConfig {
                    endpoint_id,
                    buses: bridge_buses,
                },
            )
            .ok()?;
        let root = dma.mapping().physical_start();
        let table_bytes = PAGE_SIZE * SINGLE_REQUESTER_VTD_TABLE_PAGES as u64;
        let payload = PhysAddr::new(root.get().checked_add(table_bytes)?).ok()?;
        if dma.reservation().bytes() != 16 * PAGE_SIZE || route.register_base().get() != 0xfed9_0000
        {
            return None;
        }
        let aperture = VtdDmaAperture {
            route,
            hardware_domain: 1,
            device_base: 0x20_0000,
            physical_base: payload,
            pages: if media { 4 } else { 1 },
        };
        // SAFETY: the sole BSP just checked the exact exclusive WB mapping
        // and owns the dedicated 16-page boot-lifetime allocation. Both
        // requesters are quiesced and the remapper is still off. No reference
        // to these six table pages survives preparation, nor are they freed.
        let prepared = unsafe {
            let tables = &mut *(dma.mapping().virtual_start().get()
                as *mut [[u64; 512]; SINGLE_REQUESTER_VTD_TABLE_PAGES]);
            prepare_cold_legacy_vtd_root(tables, root, aperture)
        }
        .ok()?;
        trace(0xc1);
        for byte in root.get().to_le_bytes() {
            trace(byte);
        }
        trace(0xc2);
        for _ in 0..100_000_000 {
            match fixture_scratch() {
                0xa8 | 0xaa..=0xac => core::hint::spin_loop(),
                0xb8 => {
                    // SAFETY: signed cold mode, checked exact live branch
                    // and cleared PCI BME bits, then independently verified
                    // paused host table/readback evidence. Device state and
                    // pinned RAM remain exclusively owned by this fixture.
                    unsafe {
                        let token = verify_q35_activation_mmio(active, dmar).ok()?;
                        let mut unit = VerifiedVtdUnit::from_native(token, 1024).ok()?;
                        unit.activate_cold_legacy_root(prepared).ok()?;
                        let backing = &mut *(dma.mapping().virtual_start().get()
                            as *mut [[u64; 512]; SINGLE_REQUESTER_VTD_TABLE_PAGES]);
                        let mut tables = unit.borrow_boot_tables(route, root, backing).ok()?;
                        if let Some(bar) = command_bar {
                            use mrml_kernel::arch::x86_64::{Mapping, PagePermissions, VirtAddr};
                            let cpu = VirtAddr::new(
                                dma.mapping()
                                    .virtual_start()
                                    .get()
                                    .checked_add(table_bytes)?,
                            )
                            .ok()?;
                            let payload = Mapping::new(
                                cpu,
                                aperture.physical_base,
                                u64::from(aperture.pages),
                                PagePermissions::KERNEL_READ_WRITE,
                            )
                            .ok()?;
                            return super::q35_xhci_command::run(
                                &mut tables,
                                &mut unit,
                                aperture,
                                payload,
                                bar,
                            )
                            .then_some(());
                        }
                        unit.install_routed_dma_aperture(&mut tables, aperture)
                            .ok()?;
                        unit.verify_routed_dma_aperture(
                            &tables,
                            route,
                            aperture.hardware_domain,
                            aperture.device_base,
                            aperture.physical_base,
                            aperture.pages,
                        )
                        .ok()?;
                        trace(0xc3);
                        // Keep the window pinned, with BME still off, until
                        // the host independently observes the present leaf.
                        for _ in 0..100_000_000 {
                            match fixture_scratch() {
                                0xb8 => core::hint::spin_loop(),
                                0xb9 => {
                                    unit.revoke_routed_dma_aperture(&mut tables, aperture)
                                        .ok()?;
                                    trace(0xc5);
                                    return Some(());
                                }
                                _ => return None,
                            }
                        }
                    }
                    return None;
                }
                _ => {
                    trace(0xc4);
                    return Some(());
                }
            }
        }
        None
    })();
    result.is_some()
}

pub(super) fn trace(stage: u8) {
    // SAFETY: this diagnostic runs at CPL0 on x86 and port 0xe9 is the opt-in trace.
    unsafe { asm!("out dx, al", in("dx") 0xe9u16, in("al") stage, options(nomem, nostack)) };
}
