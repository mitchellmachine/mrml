//! Host-only evidence for the exact q35 USB DMA regression fixture.
//! QEMU's flat monitor format is not a stable ABI; unfamiliar output fails
//! closed. This module never issues guest mapping authority.

use std::io::{BufRead as _, BufReader, Read as _};
use std::process::Child;
use std::sync::mpsc;
use std::time::Duration;

const MAX_LINE: usize = 128 * 1024;
const ECAM: (u64, u64) = (0xe000_0000, 0xefff_ffff);
const DRHD: (u64, u64) = (0xfed9_0000, 0xfed9_022f);
const DRHD_PAGE: (u64, u64) = (DRHD.0, DRHD.0 + 4095);

pub(super) fn fixture_acpi_table(profile: u8) -> [u8; 36] {
    let mut table = [0u8; 36];
    table[..4].copy_from_slice(b"MQ35");
    table[4..8].copy_from_slice(&36u32.to_le_bytes());
    table[8] = 1;
    table[10..].copy_from_slice(b"MRMLQ3MMIOTEST\x01\x00\x00\x00MRML\x01\x00\x00\x00");
    table[32] = profile;
    table[9] = 0u8.wrapping_sub(table.iter().copied().fold(0u8, u8::wrapping_add));
    table
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum PostCheck {
    ObserveAttached,
    DenyActivation,
    SeparateBoot,
    SharedBoot,
}

#[derive(Clone, Copy)]
enum PausedCheck {
    Resources,
    NoRemapper,
    SharedBoot,
    IsolatedSharedBoot,
}

pub(super) fn verify_paused_q35_resources(child: &mut Child) -> Result<(), String> {
    inspect_q35(child, None, false, None, None, PausedCheck::Resources).map(|_| ())
}

pub(super) fn verify_paused_no_remapper(child: &mut Child) -> Result<(), String> {
    inspect_q35(child, None, true, None, None, PausedCheck::NoRemapper).map(|_| ())
}

pub(super) fn verify_paused_shared_boot(child: &mut Child, isolated: bool) -> Result<(), String> {
    let check = if isolated {
        PausedCheck::IsolatedSharedBoot
    } else {
        PausedCheck::SharedBoot
    };
    inspect_q35(child, None, isolated, None, None, check).map(|_| ())
}

pub(super) fn release_q35_fixture(
    child: &mut Child,
    release: u8,
    isolated: bool,
    post: Option<(&std::path::Path, &[u8])>,
    cold: Option<PostCheck>,
) -> Result<Option<FixtureState>, String> {
    inspect_q35(child, Some(release), isolated, post, cold, PausedCheck::Resources)
}

fn inspect_q35(
    child: &mut Child,
    release: Option<u8>,
    isolated: bool,
    post: Option<(&std::path::Path, &[u8])>,
    cold: Option<PostCheck>,
    paused_check: PausedCheck,
) -> Result<Option<FixtureState>, String> {
    let mut stdin = child.stdin.take().ok_or("missing QMP input")?;
    let stdout = child.stdout.take().ok_or("missing QMP output")?;
    let post = post.map(|(path, prefix)| (path.to_owned(), prefix.to_vec()));
    let (send, receive) = mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .spawn(move || {
            let mut reader = BufReader::new(stdout);
            let result = inspect_qmp(
                &mut stdin,
                &mut reader,
                release,
                isolated,
                post.as_ref()
                    .map(|(path, prefix)| (path.as_path(), prefix.as_slice())),
                cold,
                paused_check,
            );
            let _ = send.send(result);
        })
        .map_err(|e| format!("QMP reader: {e}"))?;
    // The caller always kills/reaps QEMU, including on timeout, which closes
    // the pipe and releases the reader.
    let result = receive
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| "timed out reading QEMU resource map".to_owned());
    if result.is_ok() {
        worker.join().map_err(|_| "QMP reader panicked")?;
    }
    result?
}

fn inspect_qmp(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
    release: Option<u8>,
    isolated: bool,
    post: Option<(&std::path::Path, &[u8])>,
    cold: Option<PostCheck>,
    paused_check: PausedCheck,
) -> Result<Option<FixtureState>, String> {
    qmp_write(stdin, "{\"execute\":\"qmp_capabilities\",\"id\":71}\n")?;
    ack(reader, "{\"return\": {}, \"id\": 71}")?;
    qmp_write(stdin, "{\"execute\":\"stop\",\"id\":72}\n")?;
    ack(reader, "{\"return\": {}, \"id\": 72}")?;
    qmp_write(
        stdin,
        "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info mtree -f\"},\"id\":73}\n",
    )?;
    let map = read_monitor(&mut *reader, 73)?;
    match paused_check {
        PausedCheck::Resources => {}
        PausedCheck::SharedBoot | PausedCheck::IsolatedSharedBoot => {
            validate(&map)?;
            verify_shared_boot(stdin, reader)?;
            if matches!(paused_check, PausedCheck::IsolatedSharedBoot) {
                check_isolation_properties(stdin, reader)?;
                qmp_write(stdin, "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info pci\"},\"id\":76}\n")?;
                let pci = read_monitor(&mut *reader, 76)?;
                fixture_bar_for_topology(&pci, true, false)?;
                println!("q35-isolated-shared-boot|status=PASS|requester=0000:41:00.0|boot_backend_writes=0|activated=false");
            }
            println!(
                "q35-usb-shared-boot|status=PASS|firmware_disk_read=true|loader_rejected=true|native_release=false|boot_backend_writes=0"
            );
            return Ok(None);
        }
        PausedCheck::NoRemapper => {
            validate_resources(&map, false)?;
            println!(
                "q35-usb-no-remapper|status=PASS|loader_rejected=true|native_driver_entered=false"
            );
            return Ok(None);
        }
    }
    validate(&map)?;
    let mut guest_before = None;
    let mut usb_record_before = None;
    let record_check = match release {
        Some(0xbc) => Some(UsbRecordCheck::Present),
        Some(0xbd) => Some(UsbRecordCheck::WrongRelease),
        Some(0xbe) => Some(UsbRecordCheck::Missing),
        _ => None,
    };
    if matches!(release, Some(0xad..=0xaf | 0xb4 | 0xb5 | 0xb7 | 0xba | 0xbc..=0xbe)) {
        validate_scratch_uart(&map)?;
        if let Some(check) = record_check {
            verify_record_boot(stdin, reader, check)?;
        } else {
            verify_shared_boot(stdin, reader)?;
        }
        if let Some(check) = record_check {
            verify_shared_record_class(stdin, reader)?;
            usb_record_before = Some((sample_shared_controller(stdin, reader)?, check));
        } else if matches!(release, Some(0xad | 0xaf | 0xb4 | 0xb5 | 0xb7 | 0xba)) {
            let before = sample_shared_controller(stdin, reader)?;
            qmp_write(
                stdin,
                "{\"execute\":\"device_del\",\"arguments\":{\"id\":\"mrml_shared_boot\"},\"id\":152}\n",
            )?;
            ack(reader, "{\"return\": {}, \"id\": 152}")?;
            qmp_write(
                stdin,
                "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info qtree\"},\"id\":153}\n",
            )?;
            let tree = read_monitor(&mut *reader, 153)?;
            if !retired_shared_boot_topology(&tree) {
                return Err(
                    "shared boot disk did not detach while the controller stayed present".into(),
                );
            }
            let after = sample_shared_controller(stdin, reader)?;
            if !before.matches_control(after) {
                return Err(
                    "virtual USB removal changed PCI identity, controller control or VT-d state"
                        .into(),
                );
            }
            if matches!(release, Some(0xb5 | 0xb7 | 0xba)) {
                if after.disable_command() != Some(3) {
                    return Err("guest BME fixture does not have the exact halted baseline".into());
                }
                guest_before = Some(after);
            }
            if matches!(release, Some(0xaf | 0xb4)) {
                let command = after
                    .disable_command()
                    .ok_or("shared BME fixture is not quiescent")?;
                let allowed = release == Some(0xaf);
                if allowed {
                    write_shared_command_word(stdin, reader, after.pci_command, command)?;
                }
                let final_state = sample_shared_controller(stdin, reader)?;
                let expected = if allowed {
                    SharedController {
                        pci_command: (after.pci_command & 0xffff_0000) | u32::from(command),
                        ..after
                    }
                } else {
                    after
                };
                if !expected.matches_control(final_state)
                    || expected.pci_command != final_state.pci_command
                {
                    return Err(
                        "shared BME test changed more than the authorized command bit".into(),
                    );
                }
                println!(
                    "q35-shared-bme|status=PASS|actor=qemu-host|allowed={allowed}|command_before={:#06x}|command_after={:#06x}|halted=true|vtd_unchanged=true",
                    after.pci_command as u16, final_state.pci_command as u16,
                );
            }
            for (phase, state) in [("before-detach", before), ("after-detach", after)] {
                println!(
                    "q35-shared-controller|phase={phase}|bdf=0000:00:1b.0|bar0={:#x}|pci_cmd={:#06x}|bme={}|run={}|halted={}|usbsts={:#010x}|vtd_translation={}|vtd_gsts={:#010x}|vtd_root={:#018x}|vtd_faults={:#010x}",
                    state.xhci.bar.start,
                    state.pci_command as u16,
                    state.pci_command & 4 != 0,
                    state.xhci.command & 1 != 0,
                    state.xhci.status & 1 != 0,
                    state.xhci.status,
                    state.gsts & (1 << 31) != 0,
                    state.gsts,
                    state.root,
                    state.fsts,
                );
            }
            println!(
                "q35-usb-preload|status=PASS|efi_exited=true|virtual_boot_disk_detached=true|boot_backend_writes=0"
            );
        } else {
            println!(
                "q35-usb-preload|status=PASS|efi_exited=true|virtual_boot_disk_detached=false|denied=true"
            );
        }
    }
    let cold_shared = cold == Some(PostCheck::SharedBoot);
    let observe_attached = cold == Some(PostCheck::ObserveAttached);
    if observe_attached && (release != Some(0xa6) || !isolated) {
        return Err("retained boot source observation requires the read-only release".into());
    }
    let bar = if matches!(release, Some(0xa6..=0xa9 | 0xbb)) {
        if isolated {
            check_isolation_properties(stdin, reader)?;
        }
        qmp_write(
            stdin,
            "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info pci\"},\"id\":76}\n",
        )?;
        let bar = fixture_bar_for_topology(&read_monitor(&mut *reader, 76)?, isolated, !(cold_shared || observe_attached))?;
        qmp_write(
            stdin,
            "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info mtree -f -o\"},\"id\":77}\n",
        )?;
        let preflight = matches!(release, Some(0xa9..=0xac));
        validate_fixture_bar(&read_monitor(&mut *reader, 77)?, bar, isolated, preflight)?;
        if preflight {
            for (id, offset, mask, expected) in [
                (113, 0x14, u32::MAX, 0x2000),
                (114, 0x18, u32::MAX, 0x1000),
                (115, 0x1020, !3, 0),
                (116, 0x2000, u32::MAX, 0),
            ] {
                let actual = read_model_dword(stdin, reader, bar.start + offset, id)?;
                if actual & mask != expected {
                    return Err(format!(
                        "unexpected xHCI readback at +{offset:#x}: {actual:#x}, expected {expected:#x}"
                    ));
                }
            }
        }
        let state = sample_xhci_state(stdin, reader, bar)?;
        let state = if cold_shared {
            verify_shared_boot(stdin, reader)?;
            let before = sample_shutdown(stdin, reader, 90)?;
            detach_shared_disk(stdin, reader)?;
            qmp_write(stdin, "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info pci\"},\"id\":76}\n")?;
            let current_bar = fixture_bar_for_topology(&read_monitor(&mut *reader, 76)?, true, false)?;
            let after = sample_xhci_state(stdin, reader, current_bar)?;
            if !state.matches_halted_shared_boot(after)
                || before.boot != u32::MAX
                || before.gsts != 0
                || sample_shutdown(stdin, reader, 90)? != before
            {
                return Err("shared cold boot detachment changed guarded controller state".into());
            }
            after
        } else {
            state
        };
        if preflight && (state.command != 0 || state.status != 1) {
            return Err("controller is not halted with interrupts off".into());
        }
        Some(state)
    } else {
        None
    };
    let observation = if observe_attached {
        let state = bar.filter(|_| isolated).ok_or("missing isolated no-write sample")?;
        verify_shared_boot(stdin, reader)?;
        Some(observe_attached_boot(stdin, reader, state)?)
    } else {
        None
    };
    let shutdown = matches!(release, Some(0xa7 | 0xa8 | 0xbb));
    let before = if shutdown {
        let state = bar
            .filter(|_| isolated)
            .ok_or("missing isolated controller sample")?;
        let tolerated_events = if cold_shared { 1 << 3 } else { 0 };
        if state.command != 0 || state.status & !tolerated_events != 1 || post.is_none() {
            return Err(
                "isolated controller is not already halted or lacks readback channel".into(),
            );
        }
        Some(sample_shutdown(&mut *stdin, &mut *reader, 90)?)
    } else {
        None
    };
    if before.is_some_and(|snapshot| {
        snapshot.endpoint as u16 != 7 || snapshot.bridge as u16 != 7 || snapshot.gsts != 0
    }) {
        return Err("unexpected firmware PCI or remapping state before shutdown".into());
    }
    if let Some(mode) = release {
        let byte = match mode {
            0xaf => 0xad,
            0xb4 => 0xae,
            0xbd => 0xbe, // Wrong release on correct marked profile.
            0xbe => 0xbc, // Correct release, but booted on a different controller.
            byte => byte,
        };
        validate_scratch_uart(&map)?;
        if !matches!(byte, 0xa6..=0xa9 | 0xad | 0xae | 0x5a | 0xb5 | 0xb7 | 0xba | 0xbb | 0xbc | 0xbe) {
            return Err("unknown q35 fixture release value".into());
        }
        qmp_write(
            stdin,
            &format!(
                "{{\"execute\":\"human-monitor-command\",\"arguments\":{{\"command-line\":\"o /b 0x2ff {byte:#x}\"}},\"id\":74}}\n"
            ),
        )?;
        ack(reader, "{\"return\": \"\", \"id\": 74}")?;
        qmp_write(stdin, "{\"execute\":\"cont\",\"id\":75}\n")?;
        ack(reader, "{\"return\": {}, \"id\": 75}")?;
    }
    if let Some((before, check)) = usb_record_before {
        let (path, prefix) = post.ok_or("missing USB record trace")?;
        verify_copied_usb_record(stdin, reader, path, prefix, before, check)?;
        return Ok(None);
    }
    if let Some(before) = guest_before {
        let allow = matches!(release, Some(0xb5 | 0xba));
        let require_unproven = release == Some(0xba);
        let (path, expected) = post.ok_or("missing signed guest BME trace expectation")?;
        verify_guest_bme(stdin, reader, path, expected, before, allow, require_unproven)?;
    }
    if let Some(baseline) = observation {
        let (path, prefix) = post.ok_or("missing read-only signed guest trace")?;
        let state = bar.ok_or("missing isolated no-write sample")?;
        let report = await_fixed_report(path, prefix, state, false)?;
        qmp_write(stdin, "{\"execute\":\"stop\",\"id\":94}\n")?;
        ack(reader, "{\"return\": {}, \"id\": 94}")?;
        verify_shared_boot(stdin, reader)?;
        if sample_xhci_state(stdin, reader, state.bar)? != state
            || observe_attached_boot(stdin, reader, state)? != baseline
        {
            return Err("state changed during the read-only boot diagnostic".into());
        }
        println!("{report}");
        println!("q35-usb-post-firmware-observation|status=PASS|firmware_exited=true|boot_source=attached|bme=on|vtd_translation=off|ownership_transfer=unproven|hardware_writes=false");
        return Ok(bar);
    }
    if let (Some(before), Some((path, prefix)), Some(state)) = (before, post, bar) {
        if let Some(mode) = cold {
            inspect_cold_activation(
                stdin,
                reader,
                &map,
                (path, prefix),
                state,
                before,
                mode,
            )?;
            return Ok(bar);
        }
        await_fixed_report(path, prefix, state, true)?;
        qmp_write(stdin, "{\"execute\":\"stop\",\"id\":94}\n")?;
        ack(reader, "{\"return\": {}, \"id\": 94}")?;
        let after = sample_shutdown(stdin, reader, 95)?;
        if after
            != (ShutdownSample {
                endpoint: before.endpoint & !4,
                bridge: before.bridge & !4,
                ..before
            })
            || sample_xhci_state(stdin, reader, state.bar)? != state
        {
            return Err("paused QEMU did not confirm the exact PCI BME-only shutdown".into());
        }
    }
    Ok(bar)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ShutdownSample {
    endpoint: u32,
    bridge: u32,
    boot: u32,
    gsts: u32,
}

fn observe_attached_boot(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
    state: FixtureState,
) -> Result<ShutdownSample, String> {
    let baseline = sample_shutdown(stdin, reader, 90)?;
    if !state.matches_halted_shared_boot(state)
        || baseline.endpoint as u16 != 7
        || baseline.bridge as u16 != 7
        || baseline.boot != u32::MAX
        || baseline.gsts != 0
        || read_root_pointer(stdin, reader)? != 0
        || read_model_dword(stdin, reader, DRHD.0 + 0x34, 104)? != 0
    {
        return Err("unexpected retained boot source, PCI or remapper observation".into());
    }
    Ok(baseline)
}

fn sample_shutdown(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
    id: u8,
) -> Result<ShutdownSample, String> {
    // These offsets are within the live, independently checked ECAM and
    // DRHD apertures. The QMP monitor only reads the emulated device state.
    Ok(ShutdownSample {
        endpoint: read_model_dword(stdin, reader, 0xe410_0004, id)?,
        bridge: read_model_dword(stdin, reader, 0xe400_0004, id + 1)?,
        boot: read_model_dword(stdin, reader, 0xe002_8004, id + 2)?,
        gsts: read_model_dword(stdin, reader, 0xfed9_001c, id + 3)?,
    })
}

fn wait_cold_trace(
    path: &std::path::Path,
    prefix: &[u8],
    state: FixtureState,
    stages: &[u8],
) -> Result<(u64, String), String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let report_end = prefix.len() + 66;
    let ready = report_end + 10;
    let target = ready + stages.len();
    while std::time::Instant::now() < deadline {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(512).read_to_end(&mut bytes))
            .map_err(|e| format!("read cold trace: {e}"))?;
        if bytes.len() < target {
            if bytes.get(report_end) == Some(&0xdb) {
                return Err("signed guest refused the cold root".into());
            }
            std::thread::sleep(Duration::from_millis(5));
            continue;
        }
        if bytes.len() != target
            || bytes[report_end] != 0xc1
            || bytes[ready - 1] != 0xc2
            || &bytes[ready..] != stages
        {
            return Err(format!(
                "unexpected signed activation stages: {:02x?}, expected {stages:02x?}",
                &bytes[report_end..]
            ));
        }
        let sample = register_snapshot(prefix, &bytes[..report_end], state, true, true)?
            .ok_or("missing cold shutdown sample")?;
        let root = u64::from_le_bytes(bytes[report_end + 1..ready - 1].try_into().unwrap());
        return Ok((root, sample));
    }
    Err("missing signed cold activation trace".into())
}

fn verify_root_ram(map: &str, root: u64) -> Result<(), String> {
    let last = root
        .checked_add(16 * 4096 - 1)
        .filter(|&last| root >= 0x10_0000 && root % 4096 == 0 && last < 1 << 32)
        .ok_or("invalid signed fixture boot RAM extent")?;
    let mut matched = false;
    for line in cpu_ranges(map)? {
        let (start, end, kind, name) = flat_range(line)?;
        if start <= last && root <= end {
            if matched
                || start > root
                || end < last
                || kind != "0, ram"
                || (name != "pc.ram" && name != format!("pc.ram @{start:016x}"))
            {
                return Err(format!("unexpected overlapping root RAM resource: {line}"));
            }
            matched = true;
        }
    }
    if !matched {
        return Err("signed table frames are not backed by PC RAM".into());
    }
    Ok(())
}

fn verify_root_page(text: &str, root: u64, page: u64, leaf: u64, pages: u8) -> Result<(), String> {
    verify_root_page_with_context(text, root, page, leaf, pages, true)
}

fn verify_root_page_with_context(
    text: &str,
    root: u64,
    page: u64,
    leaf: u64,
    pages: u8,
    context_present: bool,
) -> Result<(), String> {
    let address = root + page * 4096;
    let mut index = 0u64;
    for line in text.lines() {
        let (start, words) = line.split_once(':').ok_or("bad cold table dump row")?;
        if start != format!("{:08x}", address + index * 8) || words.trim().is_empty() {
            return Err("noncontiguous cold root readout".into());
        }
        for value in words.split_whitespace() {
            if index >= 512 || value.len() != 18 {
                return Err("bad cold table word width or count".into());
            }
            let actual = u64::from_str_radix(value.strip_prefix("0x").ok_or("bad cold word")?, 16)
                .map_err(|_| "invalid cold table word")?;
            let expected = match (page, index) {
                (0, 130) => (address + 4096) | 1,
                (1, 0) if context_present => (address + 4096) | 1,
                (1, 1) if context_present => 0x102,
                (2 | 3, 0) | (4, 1) => (address + 4096) | 3,
                (5, slot) if slot < u64::from(pages) && leaf != 0 => leaf + 4096 * slot,
                _ => 0,
            };
            if actual != expected {
                return Err(format!(
                    "wrong cold table value at page {page} word {index}"
                ));
            }
            index += 1;
        }
    }
    (index == 512)
        .then_some(())
        .ok_or("short cold table dump".into())
}

fn check_live_leaf(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
    root: u64,
    leaf: u64,
    pages: u8,
) -> Result<(), String> {
    qmp_write(
        stdin,
        &format!(
            "{{\"execute\":\"human-monitor-command\",\"arguments\":{{\"command-line\":\"xp /512gx {:#x}\"}},\"id\":112}}\n",
            root + 5 * 4096,
        ),
    )?;
    verify_root_page(&read_monitor(reader, 112)?, root, 5, leaf, pages)
}

fn read_root_pointer(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
) -> Result<u64, String> {
    let low = read_model_dword(stdin, reader, 0xfed9_0020, 102)?;
    let high = read_model_dword(stdin, reader, 0xfed9_0024, 103)?;
    Ok(u64::from(high) << 32 | u64::from(low))
}

fn inspect_cold_activation(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
    map: &str,
    trace: (&std::path::Path, &[u8]),
    state: FixtureState,
    firmware: ShutdownSample,
    mode: PostCheck,
) -> Result<(), String> {
    let allow = mode != PostCheck::DenyActivation;
    let (path, prefix) = trace;
    let (root, _) = wait_cold_trace(path, prefix, state, &[])?;
    qmp_write(stdin, "{\"execute\":\"stop\",\"id\":94}\n")?;
    ack(reader, "{\"return\": {}, \"id\": 94}")?;
    let shutdown = ShutdownSample {
        endpoint: firmware.endpoint & !4,
        bridge: firmware.bridge & !4,
        ..firmware
    };
    if sample_shutdown(stdin, reader, 95)? != shutdown
        || sample_xhci_state(stdin, reader, state.bar)? != state
        || read_root_pointer(stdin, reader)? != 0
        || read_model_dword(stdin, reader, 0xfed9_0034, 104)? != 0
    {
        return Err("cold fixture was not quiesced with pristine remapper".into());
    }
    verify_root_ram(map, root)?;
    for page in 0..6 {
        qmp_write(
            stdin,
            &format!(
                "{{\"execute\":\"human-monitor-command\",\"arguments\":{{\"command-line\":\"xp /512gx {:#x}\"}},\"id\":105}}\n",
                root + page * 4096,
            ),
        )?;
        verify_root_page(&read_monitor(&mut *reader, 105)?, root, page, 0, 1)?;
    }
    let byte = if allow { 0xb8 } else { 0x5b };
    qmp_write(
        stdin,
        &format!(
            "{{\"execute\":\"human-monitor-command\",\"arguments\":{{\"command-line\":\"o /b 0x2ff {byte:#x}\"}},\"id\":106}}\n"
        ),
    )?;
    ack(reader, "{\"return\": \"\", \"id\": 106}")?;
    qmp_write(stdin, "{\"execute\":\"cont\",\"id\":107}\n")?;
    ack(reader, "{\"return\": {}, \"id\": 107}")?;
    let (after_root, _) = wait_cold_trace(
        path,
        prefix,
        state,
        if allow { &[0xc3] } else { &[0xc4] },
    )?;
    qmp_write(stdin, "{\"execute\":\"stop\",\"id\":108}\n")?;
    ack(reader, "{\"return\": {}, \"id\": 108}")?;
    let expected = ShutdownSample {
        gsts: if allow { 0xc000_0000 } else { 0 },
        ..shutdown
    };
    if after_root != root
        || sample_shutdown(stdin, reader, 95)? != expected
        || sample_xhci_state(stdin, reader, state.bar)? != state
        || read_root_pointer(stdin, reader)? != if allow { root } else { 0 }
        || read_model_dword(stdin, reader, 0xfed9_0034, 104)? != 0
    {
        return Err("paused QEMU did not confirm the exact cold remapper state".into());
    }
    if allow {
        let payload = root + 6 * 4096;
        check_live_leaf(stdin, reader, root, payload | 3, 1)?;
        qmp_write(
            stdin,
            "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"o /b 0x2ff 0xb9\"},\"id\":109}\n",
        )?;
        ack(reader, "{\"return\": \"\", \"id\": 109}")?;
        qmp_write(stdin, "{\"execute\":\"cont\",\"id\":110}\n")?;
        ack(reader, "{\"return\": {}, \"id\": 110}")?;
        let (revoked_root, _) = wait_cold_trace(path, prefix, state, &[0xc3, 0xc5])?;
        qmp_write(stdin, "{\"execute\":\"stop\",\"id\":111}\n")?;
        ack(reader, "{\"return\": {}, \"id\": 111}")?;
        if revoked_root != root
            || sample_shutdown(stdin, reader, 95)? != expected
            || sample_xhci_state(stdin, reader, state.bar)? != state
            || read_root_pointer(stdin, reader)? != root
            || read_model_dword(stdin, reader, 0xfed9_0034, 104)? != 0
        {
            return Err("unexpected remapper or PCI state after DMA leaf withdrawal".into());
        }
        check_live_leaf(stdin, reader, root, payload, 1)?;
        qmp_write(stdin, &format!("{{\"execute\":\"human-monitor-command\",\"arguments\":{{\"command-line\":\"xp /512gx {:#x}\"}},\"id\":172}}\n", root + 4096))?;
        verify_root_page_with_context(&read_monitor(&mut *reader, 172)?, root, 1, 0, 1, false)?;
    }
    if mode == PostCheck::SharedBoot {
        verify_shared_disk_retired(stdin, reader)?;
        println!("q35-vtd-shared-boot|status=PASS|requester=0000:41:00.0|boot_source_detached=true|exact_requester_denied=true");
    }
    println!(
        "q35-vtd-cold|status=PASS|activated={allow}|root={root:#x}|aperture_installed_and_revoked={allow}|no_present_dma_leaves=true|exact_requester_denied={allow}|bme=false"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct SharedController {
    xhci: FixtureState,
    pci_command: u32,
    gsts: u32,
    root: u64,
    fsts: u32,
}

impl SharedController {
    fn disable_command(self) -> Option<u16> {
        let command = self.pci_command as u16;
        (command & 6 == 6
            && self.xhci.command == 0
            && self.xhci.status & 1 != 0
            && self.gsts == 0
            && self.root == 0
            && self.fsts == 0)
            .then_some(command & !4)
    }

    fn matches_control(self, after: Self) -> bool {
        // Detach may set the port-change bit. It must not move the BAR,
        // alter the controller's Run/Halted state or alter remapping.
        self.xhci.bar == after.xhci.bar
            && self.xhci.cap0 == after.xhci.cap0
            && self.xhci.command == after.xhci.command
            && self.xhci.status & 1 == after.xhci.status & 1
            && self.pci_command as u16 == after.pci_command as u16
            && self.gsts == after.gsts
            && self.root == after.root
            && self.fsts == after.fsts
    }
}

fn sample_shared_controller(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
) -> Result<SharedController, String> {
    qmp_write(
        stdin,
        "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info pci\"},\"id\":154}\n",
    )?;
    let bar = fixture_bar(&read_monitor(&mut *reader, 154)?, false)?;
    qmp_write(
        stdin,
        "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info mtree -f -o\"},\"id\":155}\n",
    )?;
    validate_fixture_bar(&read_monitor(&mut *reader, 155)?, bar, false, false)?;
    // The outer QMP check proved the ECAM and DRHD apertures. Bind the
    // config dwords to the same exact 00:1b.0 candidate validated above.
    const ENDPOINT: u64 = ECAM.0 + (27 << 15);
    if read_model_dword(stdin, reader, ENDPOINT, 156)? != 0x000d_1b36 {
        return Err("wrong shared-controller ECAM identity".into());
    }
    let pci_command = read_model_dword(stdin, reader, ENDPOINT + 4, 157)?;
    if pci_command as u16 == u16::MAX || pci_command & 2 == 0 {
        return Err("shared controller lacks readable PCI memory decoding".into());
    }
    let gsts = read_model_dword(stdin, reader, DRHD.0 + 0x1c, 158)?;
    let fsts = read_model_dword(stdin, reader, DRHD.0 + 0x34, 159)?;
    let root = read_root_pointer(stdin, reader)?;
    if gsts == u32::MAX || fsts == u32::MAX || root == u64::MAX {
        return Err("invalid shared-controller VT-d sample".into());
    }
    Ok(SharedController {
        xhci: sample_xhci_state(stdin, reader, bar)?,
        pci_command,
        gsts,
        root,
        fsts,
    })
}

fn verify_shared_record_class(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
) -> Result<(), String> {
    const ENDPOINT_CLASS: u64 = ECAM.0 + (27 << 15) + 8;
    if read_model_dword(stdin, reader, ENDPOINT_CLASS, 173)? != 0x0c03_3001 {
        return Err("incorrect shared USB record class or revision".into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UsbRecordCheck {
    Present,
    WrongRelease,
    Missing,
}

fn verify_record_boot(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
    check: UsbRecordCheck,
) -> Result<(), String> {
    if check == UsbRecordCheck::Missing {
        verify_boot_on(stdin, reader, "bus: mrml_boot_xhci.0")
    } else {
        verify_shared_boot(stdin, reader)
    }
}

fn verify_copied_usb_record(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
    path: &std::path::Path,
    prefix: &[u8],
    before: SharedController,
    check: UsbRecordCheck,
) -> Result<(), String> {
    let mut expected = prefix.to_vec();
    if check != UsbRecordCheck::Present {
        expected.push(0xeb);
    } else {
        // The requester, PCI ID and class are independently checked by the host
        // from the sealed root-bus fixture and the exact read-only PCI sample.
        expected.extend_from_slice(b"\xbdMRMLXHCI\x01\x00\x28\x00\xd8\x00\x00\x00\x36\x1b\x0d\x00\x01\x30\x03\x0c");
        expected.extend_from_slice(&before.xhci.bar.start.to_le_bytes());
        expected.extend_from_slice(&0x4000u32.to_le_bytes());
        expected.extend_from_slice(&[0, 0, 0, 0, 0xbe]);
    }
    let read_trace = || {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(512).read_to_end(&mut bytes))
            .map_err(|e| format!("read copied USB record trace: {e}"))?;
        Ok::<Vec<u8>, String>(bytes)
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let bytes = read_trace()?;
        if bytes == expected {
            break;
        }
        if !expected.starts_with(&bytes) || std::time::Instant::now() >= deadline {
            return Err(format!("missing or altered post-exit USB record: {bytes:02x?}"));
        }
        std::thread::sleep(Duration::from_millis(3));
    }
    qmp_write(stdin, "{\"execute\":\"stop\",\"id\":168}\n")?;
    ack(reader, "{\"return\": {}, \"id\": 168}")?;
    if read_trace()? != expected {
        return Err("USB record trace continued beyond the terminal result".into());
    }
    verify_record_boot(stdin, reader, check)?;
    verify_shared_record_class(stdin, reader)?;
    let after = sample_shared_controller(stdin, reader)?;
    if before.pci_command != after.pci_command
        || before.xhci != after.xhci
        || !before.matches_control(after)
    {
        return Err("controller changed during the USB record-only diagnostic".into());
    }
    let count = if check == UsbRecordCheck::Present { 40 } else { 0 };
    println!("q35-usb-record|status=PASS|case={check:?}|firmware_exited=true|bytes={count}|boot_disk_attached=true|controller_writes=false|media_writes=0");
    Ok(())
}

fn verify_guest_bme(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
    path: &std::path::Path,
    expected: &[u8],
    before: SharedController,
    allow: bool,
    require_unproven: bool,
) -> Result<(), String> {
    let verdict = if allow { 0xef } else { 0xeb };
    let stop_at = expected
        .iter()
        .position(|&byte| byte == verdict)
        .ok_or("missing signed guest PCI verdict")?;
    let prefix = &expected[..=stop_at];
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(512).read_to_end(&mut bytes))
            .map_err(|e| format!("guest PCI trace read: {e}"))?;
        if bytes == prefix {
            break;
        }
        if !prefix.starts_with(&bytes) || std::time::Instant::now() >= deadline {
            return Err(format!(
                "unexpected or missing signed guest PCI verdict: {bytes:02x?}"
            ));
        }
        std::thread::sleep(Duration::from_millis(3));
    }
    qmp_write(stdin, "{\"execute\":\"stop\",\"id\":168}\n")?;
    ack(reader, "{\"return\": {}, \"id\": 168}")?;
    let after = sample_shared_controller(stdin, reader)?;
    let expected = SharedController {
        pci_command: if allow {
            before.pci_command & !4
        } else {
            before.pci_command
        },
        ..before
    };
    if expected.pci_command != after.pci_command || !expected.matches_control(after) {
        return Err("independent QEMU readback disagrees with guest PCI verdict".into());
    }
    println!(
        "q35-shared-bme|status=PASS|actor=mrml-guest|allowed={allow}|command_before={:#06x}|command_after={:#06x}|halted=true|vtd_unchanged=true",
        before.pci_command as u16, after.pci_command as u16
    );
    if allow {
        qmp_write(stdin, "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info qtree\"},\"id\":171}\n")?;
        if !retired_shared_boot_topology(&read_monitor(&mut *reader, 171)?) {
            return Err("virtual boot source is not retired at guest release".into());
        }
        if require_unproven {
            // Independently require translation to be off and no active
            // root in this exact negative fixture. A running remapper is
            // not a substitute for the requester proof either.
            if after.gsts != 0 || after.root != 0 {
                return Err("unexpected active VT-d state in missing-proof fixture".into());
            }
            println!("q35-shared-no-dma-proof|boot_source_retired=true|bme=false|xhci_halted=true|translation=false");
        } else {
            println!("q35-shared-release|status=PASS|boot_source_retired=true|bme=false|xhci_halted=true");
        }
        // Only the test UART release register is written by the host.
        qmp_write(
            stdin,
            "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"o /b 0x2ff 0xb6\"},\"id\":169}\n",
        )?;
        ack(reader, "{\"return\": \"\", \"id\": 169}")?;
    }
    qmp_write(stdin, "{\"execute\":\"cont\",\"id\":170}\n")?;
    ack(reader, "{\"return\": {}, \"id\": 170}")
}

// This is a host-only action on the paused disposable q35 machine. The CPU
// ECAM sample and the independent mechanism-1 read must agree before the sole
// command-word update. Restore the previous selection before guest release.
fn write_shared_command_word(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
    command_status: u32,
    new_command: u16,
) -> Result<(), String> {
    const SELECTOR: u32 = 0x8000_0004 | (27 << 11);
    let saved = read_config_port(stdin, reader, 0xcf8, 160)?;
    qmp_port_write(stdin, reader, "w", 0xcf8, SELECTOR, 161)?;
    let result = (|| {
        if read_config_port(stdin, reader, 0xcf8, 162)? != SELECTOR
            || read_config_port(stdin, reader, 0xcfc, 163)? != command_status
            || command_status as u16 & 4 == 0
            || new_command != (command_status as u16 & !4)
        {
            return Err(
                "shared xHCI PCI configuration changed before the scoped command write".into(),
            );
        }
        qmp_port_write(stdin, reader, "h", 0xcfc, u32::from(new_command), 164)
    })();
    qmp_port_write(stdin, reader, "w", 0xcf8, saved, 165)?;
    if read_config_port(stdin, reader, 0xcf8, 166)? != saved {
        return Err("shared xHCI PCI selector was not restored".into());
    }
    result
}

fn read_config_port(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
    port: u16,
    id: u8,
) -> Result<u32, String> {
    qmp_write(
        stdin,
        &format!(
            "{{\"execute\":\"human-monitor-command\",\"arguments\":{{\"command-line\":\"i /w {port:#x}\"}},\"id\":{id}}}\n"
        ),
    )?;
    let output = read_monitor(reader, id)?;
    let prefix = format!("portl[0x{port:04x}] = 0x");
    let word = output
        .trim_end()
        .strip_prefix(&prefix)
        .filter(|word| word.len() == 8)
        .ok_or("unexpected scoped QEMU PCI port read")?;
    u32::from_str_radix(word, 16).map_err(|_| "invalid scoped QEMU PCI port value".into())
}

fn qmp_port_write(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
    width: &str,
    port: u16,
    value: u32,
    id: u8,
) -> Result<(), String> {
    if !matches!((width, port), ("w", 0xcf8) | ("h", 0xcfc)) {
        return Err("unexpected QEMU PCI config port write scope".into());
    }
    qmp_write(
        stdin,
        &format!(
            "{{\"execute\":\"human-monitor-command\",\"arguments\":{{\"command-line\":\"o /{width} {port:#x} {value:#x}\"}},\"id\":{id}}}\n"
        ),
    )?;
    ack(reader, &format!("{{\"return\": \"\", \"id\": {id}}}"))
}

fn detach_shared_disk(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
) -> Result<(), String> {
    qmp_write(stdin, "{\"execute\":\"device_del\",\"arguments\":{\"id\":\"mrml_shared_boot\"},\"id\":152}\n")?;
    ack(reader, "{\"return\": {}, \"id\": 152}")?;
    verify_shared_disk_retired(stdin, reader)
}

fn verify_shared_disk_retired(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
) -> Result<(), String> {
    qmp_write(stdin, "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info qtree\"},\"id\":153}\n")?;
    if !retired_shared_boot_topology(&read_monitor(reader, 153)?) {
        return Err("virtual boot source is not detached from its retained controller".into());
    }
    Ok(())
}

#[cfg(test)]
fn shared_boot_topology(tree: &str) -> bool {
    boot_topology(tree, "bus: mrml_probe_xhci.0")
}

fn boot_topology(tree: &str, boot_bus: &str) -> bool {
    let mut bus = None;
    let mut buses = 0;
    let mut disks = 0;
    let mut matched = false;
    for line in tree.lines() {
        let content = line.trim_start();
        let indent = line.len() - content.len();
        if bus.is_some_and(|depth| indent <= depth) {
            bus = None;
        }
        if content == boot_bus {
            buses += 1;
            bus = Some(indent);
        }
        if content == "dev: usb-storage, id \"mrml_shared_boot\"" {
            disks += 1;
            matched = bus.is_some_and(|depth| indent == depth + 2);
        }
    }
    buses == 1 && disks == 1 && matched
}

fn retired_shared_boot_topology(tree: &str) -> bool {
    let mut bus = None;
    let mut buses = 0;
    for line in tree.lines() {
        let content = line.trim_start();
        let indent = line.len() - content.len();
        if content.contains("mrml_shared_boot") {
            return false;
        }
        if bus.is_some_and(|depth| indent <= depth) {
            bus = None;
        }
        if content == "bus: mrml_probe_xhci.0" {
            buses += 1;
            bus = Some(indent);
        } else if bus.is_some() && content.starts_with("dev: ") {
            return false;
        }
    }
    buses == 1
}

fn verify_shared_boot(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
) -> Result<(), String> {
    verify_boot_on(stdin, reader, "bus: mrml_probe_xhci.0")
}

fn verify_boot_on(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
    boot_bus: &str,
) -> Result<(), String> {
    qmp_write(
        stdin,
        "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info qtree\"},\"id\":150}\n",
    )?;
    if !boot_topology(&read_monitor(&mut *reader, 150)?, boot_bus) {
        return Err(
            "QEMU did not attach the firmware boot disk directly to the probe controller".into(),
        );
    }
    qmp_write(
        stdin,
        "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info blockstats\"},\"id\":151}\n",
    )?;
    let stats = read_monitor(reader, 151)?;
    let [read_bytes, reads, write_bytes, writes] =
        named_block_stats(&stats, "esp:").map_err(|e| format!("{e}: {stats}"))?;
    if read_bytes == 0 || reads == 0 || write_bytes != 0 || writes != 0 {
        return Err(format!(
            "unexpected shared boot disk counters: {read_bytes}/{reads} reads, {write_bytes}/{writes} writes"
        ));
    }
    Ok(())
}

fn named_block_stats(stats: &str, prefix: &str) -> Result<[u64; 4], String> {
    let stats = stats.replace("\r\n", "\n");
    let mut entries = stats
        .split("\n\n")
        .filter_map(|entry| entry.trim().strip_prefix(prefix));
    let (entry, structured) = match entries.next() {
        Some(entry) if entry.lines().any(|row| row.starts_with("Read:")) => {
            if entries.next().is_some() {
                return Err("duplicate scratch statistics".into());
            }
            (entry, true)
        }
        _ => {
            let mut lines = stats
                .lines()
                .filter_map(|line| line.trim().strip_prefix(prefix));
            let entry = lines.next().ok_or("missing named scratch statistics")?;
            if lines.next().is_some() {
                return Err("duplicate scratch statistics".into());
            }
            (entry, false)
        }
    };
    let mut counters = [0; 4];
    if structured {
        for (index, label) in [(0, "Read:"), (2, "Write:")] {
            let mut rows = entry.lines().filter_map(|line| line.strip_prefix(label));
            let row = rows.next().ok_or("missing scratch stats row")?;
            let mut fields = row.split_whitespace();
            if rows.next().is_some() {
                return Err("duplicate scratch stats row".into());
            }
            for out in &mut counters[index..index + 2] {
                *out = fields
                    .next()
                    .and_then(|value| value.parse().ok())
                    .ok_or("bad scratch stats row")?;
            }
        }
    } else {
        for (out, field) in
            counters
                .iter_mut()
                .zip(["rd_bytes", "rd_operations", "wr_bytes", "wr_operations"])
        {
            let mut values = entry.split_whitespace().filter_map(|word| {
                let (key, value) = word.split_once('=')?;
                (key == field).then_some(value)
            });
            *out = values
                .next()
                .and_then(|value| value.parse().ok())
                .ok_or("bad scratch stats field")?;
            if values.next().is_some() {
                return Err("duplicate scratch stats field".into());
            }
        }
    }
    Ok(counters)
}

fn await_fixed_report(
    path: &std::path::Path,
    prefix: &[u8],
    state: FixtureState,
    shutdown: bool,
) -> Result<String, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(512).read_to_end(&mut bytes))
            .map_err(|e| format!("read fixed register trace: {e}"))?;
        // The loop starts immediately after cont, so dc alone is legitimate.
        if let Some(report) = register_snapshot(prefix, &bytes, state, true, shutdown)? {
            return Ok(report);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Err("missing complete signed fixed register report".into())
}

fn check_isolation_properties(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
) -> Result<(), String> {
    for (request, reply) in [
        (
            "{\"execute\":\"qom-get\",\"arguments\":{\"path\":\"/machine\",\"property\":\"default-bus-bypass-iommu\"},\"id\":81}\n",
            "{\"return\": true, \"id\": 81}",
        ),
        (
            "{\"execute\":\"qom-get\",\"arguments\":{\"path\":\"/machine/peripheral/probe_domain\",\"property\":\"bypass_iommu\"},\"id\":82}\n",
            "{\"return\": false, \"id\": 82}",
        ),
        (
            "{\"execute\":\"qom-get\",\"arguments\":{\"path\":\"/machine/peripheral/mrml_probe_vtd\",\"property\":\"intremap\"},\"id\":83}\n",
            "{\"return\": \"off\", \"id\": 83}",
        ),
    ] {
        qmp_write(stdin, request)?;
        ack(reader, reply)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FixtureState {
    bar: FixtureBar,
    cap0: u32,
    command: u32,
    status: u32,
}

impl FixtureState {
    fn matches_halted_shared_boot(self, after: Self) -> bool {
        // Only the xHCI Port Change Detect event can differ when unplugging
        // the disposable boot device. No running, reset or fault is admitted.
        const PORT_CHANGE: u32 = 1 << 3;
        self.bar == after.bar
            && self.cap0 == after.cap0
            && self.command == 0
            && after.command == 0
            && self.status & !PORT_CHANGE == 1
            && after.status & !PORT_CHANGE == 1
    }
}

fn sample_xhci_state(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
    bar: FixtureBar,
) -> Result<FixtureState, String> {
    // validate_fixture_bar has proved these precise, aligned 32-bit windows in
    // the paused VM. Never derive an address from an unchecked register word.
    let cap0 = read_model_dword(stdin, reader, bar.start, 78)?;
    if cap0 & 0xffff != 0x40 || !matches!(cap0 >> 16, 0x100 | 0x110 | 0x120) {
        return Err("unexpected xHCI CAPLENGTH or HCIVERSION".into());
    }
    let command = read_model_dword(stdin, reader, bar.start + 0x40, 79)?;
    let status = read_model_dword(stdin, reader, bar.start + 0x44, 80)?;
    if command == u32::MAX || status == u32::MAX {
        return Err("invalid xHCI operational register sample".into());
    }
    Ok(FixtureState {
        bar,
        cap0,
        command,
        status,
    })
}

fn read_model_dword(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
    address: u64,
    id: u8,
) -> Result<u32, String> {
    qmp_write(
        stdin,
        &format!(
            "{{\"execute\":\"human-monitor-command\",\"arguments\":{{\"command-line\":\"xp /1wx {address:#x}\"}},\"id\":{id}}}\n"
        ),
    )?;
    let text = read_monitor(reader, id)?;
    let (at, word) = text
        .trim_end()
        .split_once(": 0x")
        .ok_or("malformed QEMU xHCI register readout")?;
    if at != format!("{address:08x}") || word.len() != 8 {
        return Err("unexpected address or width in QEMU xHCI register readout".into());
    }
    u32::from_str_radix(word, 16).map_err(|_| "bad QEMU xHCI register value".into())
}

fn qmp_write(out: &mut impl std::io::Write, message: &str) -> Result<(), String> {
    out.write_all(message.as_bytes())
        .map_err(|e| format!("QMP write: {e}"))
}

fn ack(reader: &mut impl std::io::BufRead, expected: &str) -> Result<(), String> {
    for _ in 0..12 {
        let line = qmp_line(reader)?;
        if line.trim_end() == expected {
            return Ok(());
        }
        if !line.starts_with("{\"event\"")
            && !line.starts_with("{\"QMP\"")
            && !line.contains(", \"event\":")
        {
            return Err(format!(
                "unexpected QMP acknowledgment: {}",
                line.trim_end()
            ));
        }
    }
    Err("missing QMP acknowledgment".into())
}

fn qmp_line(reader: &mut impl std::io::BufRead) -> Result<String, String> {
    let mut raw = String::new();
    let bytes = reader
        .by_ref()
        .take(MAX_LINE as u64 + 1)
        .read_line(&mut raw)
        .map_err(|e| format!("QMP read: {e}"))?;
    if bytes == 0 || bytes > MAX_LINE || !raw.ends_with('\n') {
        return Err("invalid QMP reply length".into());
    }
    Ok(raw)
}

fn read_monitor(mut reader: impl std::io::BufRead, id: u8) -> Result<String, String> {
    for _ in 0..12 {
        let raw = qmp_line(&mut reader)?;
        let line = raw.trim_end();
        if line.starts_with("{\"error\"") {
            return Err("QEMU rejected a resource query".into());
        }
        if let Some(body) = line.strip_suffix(format!(", \"id\": {id}}}").as_str()) {
            let data = body
                .strip_prefix("{\"return\": \"")
                .and_then(|body| body.strip_suffix('"'))
                .ok_or("invalid QMP resource payload")?;
            return decode_map(data);
        }
    }
    Err("missing QMP resource reply".into())
}

fn validate_scratch_uart(map: &str) -> Result<(), String> {
    let mut views = map.split("FlatView #").filter(|view| {
        view.lines()
            .any(|line| line.trim() == "AS \"I/O\", root: io")
    });
    let view = views.next().ok_or("missing QEMU I/O FlatView")?;
    if views.next().is_some() {
        return Err("ambiguous QEMU I/O FlatView".into());
    }
    let root = "Root memory region: io";
    let tail = view.split_once(root).ok_or("missing QEMU I/O root")?.1;
    let mut uart = false;
    for line in tail.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let (extent, meta) = line.split_once(" (prio ").ok_or("bad QEMU I/O range")?;
        let (start, end) = extent.split_once('-').ok_or("bad QEMU I/O extent")?;
        let start = u64::from_str_radix(start, 16).map_err(|_| "bad QEMU I/O start")?;
        let end = u64::from_str_radix(end, 16).map_err(|_| "bad QEMU I/O end")?;
        if start > end {
            return Err("reversed QEMU I/O extent".into());
        }
        if start <= 0x2ff && end >= 0x2f8 {
            if uart || start != 0x2f8 || end != 0x2ff || meta != "0, i/o): serial" {
                return Err("unexpected QEMU serial scratch range or overlap".into());
            }
            uart = true;
        }
    }
    if !uart {
        return Err("missing QEMU serial scratch range".into());
    }
    Ok(())
}

pub(super) fn register_snapshot(
    prefix: &[u8],
    bytes: &[u8],
    state: FixtureState,
    isolated: bool,
    shutdown: bool,
) -> Result<Option<String>, String> {
    if prefix.starts_with(bytes) {
        return Ok(None);
    }
    let data = bytes
        .strip_prefix(prefix)
        .ok_or("unexpected q35 fixed-register trace prefix")?;
    if data.first() == Some(&0xdb) {
        return Err("q35 guest rejected the VT-d extent or exact xHCI PCI identity".into());
    }
    if data.len() < 66 {
        return Ok(None);
    }
    if data.len() != 66 || data[65] != 0xda {
        return Err("wrong q35 fixed-register report length or trailer".into());
    }
    let long = |at| u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
    let quad = |at| u64::from_le_bytes(data[at..at + 8].try_into().unwrap());
    let (ver, cap, ecap, gsts, pci, class) =
        (long(0), quad(4), quad(12), long(20), long(24), long(30));
    let command = u16::from_le_bytes(data[28..30].try_into().unwrap());
    let bridge_command = u16::from_le_bytes(data[43..45].try_into().unwrap());
    let bridge_buses = long(45);
    if (isolated && (bridge_buses & 0x00ff_ffff != 0x0041_4140 || gsts != 0))
        || (!isolated && (bridge_command != 0 || bridge_buses != 0))
    {
        return Err("unexpected signed xHCI bridge or remapper state".into());
    }
    let guest_xhci = [long(49), long(53), long(57)];
    let expected_xhci = if isolated {
        [state.cap0, state.command, state.status]
    } else {
        [0; 3]
    };
    if guest_xhci != expected_xhci {
        return Err("signed guest xHCI operational state disagrees with the paused host".into());
    }
    let cleared = &data[61..65];
    let report = if shutdown {
        "q35-verified-pci-shutdown"
    } else {
        "q35-read-only-registers"
    };
    if cleared != if shutdown { &[3, 0, 3, 0] } else { &[0; 4] } {
        return Err(
            "signed guest shutdown word readbacks do not match the requested profile".into(),
        );
    }
    let bar = state.bar;
    let (bar0, bar1) = (long(35), long(39));
    let guest_base = u64::from(bar1) << 32 | u64::from(bar0 & !0xf);
    if ver != 0x10
        || cap == 0
        || ecap == 0
        || pci != 0x000d_1b36
        || class >> 8 != 0x0c0330
        || data[34] & 0x7f != 0
        || command & 2 == 0
        || bar0 & 0xf != 4
        || guest_base != bar.start
    {
        return Err("q35 fixed-register report disagrees with the exact fixture".into());
    }
    Ok(Some(format!(
        "{report}|status=PASS|ver={ver:#x}|cap={cap:#018x}|ecap={ecap:#018x}|gsts={gsts:#010x}|pci={pci:#010x}|command={command:#06x}|class_revision={class:#010x}|bme={}|bar0={:#x}..={:#x}|xhci_cap0={:#010x}|xhci_usbcmd={:#010x}|xhci_usbsts={:#010x}|xhci_run={}|xhci_halted={}|isolated={isolated}|bridge_command={bridge_command:#06x}|bridge_buses={bridge_buses:#010x}|guest_xhci_match={isolated}|shutdown={shutdown}",
        command & (1 << 2) != 0,
        bar.start,
        bar.end,
        state.cap0,
        state.command,
        state.status,
        state.command & 1 != 0,
        state.status & 1 != 0,
    )))
}

fn decode_map(data: &str) -> Result<String, String> {
    let mut out = String::with_capacity(data.len());
    let mut chars = data.chars();
    while let Some(ch) = chars.next() {
        out.push(match ch {
            '\\' => match chars.next() {
                Some('r') => '\r',
                Some('n') => '\n',
                Some('t') => '\t',
                Some('"') => '"',
                Some('\\') => '\\',
                _ => return Err("unsupported QMP resource escape".into()),
            },
            '"' => return Err("unescaped QMP resource quote".into()),
            c if c.is_ascii_graphic() || c == ' ' => c,
            _ => return Err("non-ASCII QMP resource payload".into()),
        });
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FixtureBar {
    start: u64,
    end: u64,
}

fn validate_isolated_pci_branch(pci: &str, separate_boot: bool) -> Result<(), String> {
    let mut current = 0u8;
    let mut roots = 0;
    let mut endpoints = 0;
    let mut expander = 0;
    let mut boot = 0;
    let mut bridge_fields = 0u8;
    for line in pci.lines().map(str::trim) {
        if let Some(stanza) = line.strip_prefix("Bus ") {
            let (bus, _) = stanza.split_once(',').ok_or("bad QEMU bus stanza")?;
            let bus: u8 = bus.trim().parse().map_err(|_| "bad QEMU PCI bus")?;
            current = match (bus, line) {
                (64, "Bus 64, device   0, function 0:") => {
                    roots += 1;
                    1
                }
                (65, "Bus 65, device   0, function 0:") => {
                    endpoints += 1;
                    2
                }
                (0, "Bus  0, device  27, function 0:") => {
                    expander += 1;
                    3
                }
                (0, "Bus  0, device   5, function 0:") => {
                    boot += 1;
                    4
                }
                (0, _) => 0,
                _ => return Err("unexpected PCI function/bus beside isolated xHCI".into()),
            };
        } else {
            let bit = match (current, line) {
                (1, "PCI bridge: PCI device 1b36:000c") => 1,
                (1, "secondary bus 65.") => 2,
                (1, "subordinate bus 65.") => 4,
                (1, "id \"probe_port\"") => 8,
                (3, "id \"probe_domain\"") => 16,
                (4, "id \"mrml_boot_xhci\"") => 32,
                (3, "Host bridge: PCI device 1b36:000b") => 64,
                (4, "USB controller: PCI device 1b36:000d") => 128,
                (_, "id \"probe_port\"" | "id \"probe_domain\"" | "id \"mrml_boot_xhci\"") => {
                    return Err("misplaced exact PCI topology identity".into());
                }
                (1, fields)
                    if fields.starts_with("secondary bus ")
                        || fields.starts_with("subordinate bus ") =>
                {
                    return Err("unexpected PCI root port routing".into());
                }
                _ => 0,
            };
            if bridge_fields & bit != 0 {
                return Err("duplicate QEMU PCI branch field".into());
            }
            bridge_fields |= bit;
        }
    }
    let required_fields = if separate_boot { u8::MAX } else { u8::MAX & !(32 | 128) };
    if (roots, endpoints, expander, boot, bridge_fields)
        != (1, 1, 1, u8::from(separate_boot), required_fields)
    {
        return Err("missing complete isolated QEMU PCI branch".into());
    }
    Ok(())
}

fn fixture_bar(pci: &str, isolated: bool) -> Result<FixtureBar, String> {
    fixture_bar_for_topology(pci, isolated, true)
}

fn fixture_bar_for_topology(
    pci: &str,
    isolated: bool,
    separate_boot: bool,
) -> Result<FixtureBar, String> {
    if isolated {
        validate_isolated_pci_branch(pci, separate_boot)?;
    }
    let endpoint = if isolated {
        "Bus 65, device   0, function 0:"
    } else {
        "Bus  0, device  27, function 0:"
    };
    let mut exact = false;
    let mut identity = false;
    let mut device_id = false;
    let mut bar = None;
    let mut slot_seen = false;
    for line in pci.lines() {
        let line = line.trim();
        if line.starts_with("Bus ") {
            exact = line == endpoint;
            if exact && std::mem::replace(&mut slot_seen, true) {
                return Err("duplicate QEMU fixture PCI function".into());
            }
        } else if line == "id \"mrml_probe_xhci\"" {
            if !exact || std::mem::replace(&mut device_id, true) {
                return Err("unexpected QEMU xHCI fixture device ID placement".into());
            }
        } else if exact && line == "USB controller: PCI device 1b36:000d" {
            if std::mem::replace(&mut identity, true) {
                return Err("duplicate QEMU fixture identity".into());
            }
        } else if exact && line.starts_with("BAR") {
            let assignment = line
                .strip_prefix("BAR0: 64 bit memory at 0x")
                .ok_or("unexpected BAR on QEMU fixture PCI function")?;
            let (start, end) = assignment
                .split_once(" [0x")
                .and_then(|(start, end)| Some((start, end.strip_suffix(']')?)))
                .ok_or("malformed QEMU fixture BAR0 assignment")?;
            let start = u64::from_str_radix(start, 16).map_err(|_| "bad fixture BAR0 base")?;
            let end = u64::from_str_radix(end, 16).map_err(|_| "bad fixture BAR0 end")?;
            if start == 0
                || start % 0x4000 != 0
                || start.checked_add(0x3fff) != Some(end)
                || bar.replace(FixtureBar { start, end }).is_some()
            {
                return Err("invalid or duplicate fixture BAR0 extent".into());
            }
        }
    }
    if !device_id || !identity {
        return Err("missing exact QEMU fixture PCI identity".into());
    }
    bar.ok_or("missing assigned fixture BAR0".into())
}

fn validate_fixture_bar(
    map: &str,
    bar: FixtureBar,
    isolated: bool,
    preflight: bool,
) -> Result<(), String> {
    const OWNER: &str = " owner:{dev path=/machine/peripheral/mrml_probe_xhci/xhci-core}";
    const REGIONS: &[(u64, u64, &str)] = &[
        (0, 0x3f, "capabilities"),
        (0x40, 0x43f, "operational"),
        (0x440, 0x44f, "usb3 port #1"),
        (0x450, 0x45f, "usb3 port #2"),
        (0x460, 0x46f, "usb3 port #3"),
        (0x470, 0x47f, "usb3 port #4"),
        (0x480, 0x48f, "usb2 port #1"),
        (0x490, 0x49f, "usb2 port #2"),
        (0x4a0, 0x4af, "usb2 port #3"),
        (0x4b0, 0x4bf, "usb2 port #4"),
        (0x1000, 0x121f, "runtime"),
        (0x2000, 0x281f, "doorbell"),
    ];
    if isolated && bar.start != 0x8120_0000 {
        return Err("changed isolated model BAR0 base".into());
    }
    let (expected, last_byte) = if preflight {
        if !isolated {
            return Err("extended xHCI BAR requires the isolated model".into());
        }
        (REGIONS, 0x2fff)
    } else if isolated {
        (&REGIONS[..10], 0xfff)
    } else {
        (&REGIONS[..2], 0x43f)
    };
    let mut observed = 0usize;
    for line in cpu_ranges(map)? {
        let (start, end, kind, description) = flat_range(line)?;
        if start > bar.start + last_byte || end < bar.start {
            continue;
        }
        let Some(index) = expected.iter().position(|&(lo, hi, name)| {
            (start, end) == (bar.start + lo, bar.start + hi)
                && kind == "0, i/o"
                && description.strip_prefix(name) == Some(OWNER)
        }) else {
            return Err(format!(
                "unexpected CPU-visible xHCI register range: {line}"
            ));
        };
        let bit = 1usize << index;
        if observed & bit != 0 {
            return Err("duplicate xHCI register range".into());
        }
        observed |= bit;
    }
    if observed != (1usize << expected.len()) - 1 {
        return Err("missing CPU-visible xHCI register range".into());
    }
    Ok(())
}

fn cpu_ranges(map: &str) -> Result<impl Iterator<Item = &str>, String> {
    let mut views = map.split("FlatView #").filter(|view| {
        view.lines()
            .any(|line| line.trim() == "AS \"memory\", root: system")
    });
    let view = views.next().ok_or("missing QEMU system FlatView")?;
    if views.next().is_some()
        || !view
            .lines()
            .any(|line| line.trim() == "AS \"cpu-memory-0\", root: system")
    {
        return Err("ambiguous or non-CPU QEMU system FlatView".into());
    }
    let mut tail = view
        .lines()
        .skip_while(|line| line.trim() != "Root memory region: system");
    tail.next().ok_or("missing QEMU system root")?;
    Ok(tail.map(str::trim).filter(|line| !line.is_empty()))
}

fn flat_range(line: &str) -> Result<(u64, u64, &str, &str), String> {
    let (extent, meta) = line.split_once(" (prio ").ok_or("bad QEMU range")?;
    let (start, inclusive_end) = extent.split_once('-').ok_or("bad QEMU extent")?;
    if start.len() != 16 || inclusive_end.len() != 16 {
        return Err("bad QEMU address width".into());
    }
    let start = u64::from_str_radix(start, 16).map_err(|_| "bad QEMU range start")?;
    let end = u64::from_str_radix(inclusive_end, 16).map_err(|_| "bad QEMU range end")?;
    if start > end {
        return Err("reversed QEMU range".into());
    }
    let (kind, name) = meta.split_once("): ").ok_or("bad QEMU region type")?;
    Ok((start, end, kind, name))
}

fn validate(map: &str) -> Result<(), String> {
    validate_resources(map, true)
}

fn validate_resources(map: &str, expect_drhd: bool) -> Result<(), String> {
    let mut ecam = false;
    let mut drhd = false;
    for line in cpu_ranges(map)? {
        let (start, end, kind, name) = flat_range(line)?;
        if start <= ECAM.1 && ECAM.0 <= end {
            if ecam || (start, end) != ECAM || kind != "0, i/o" || name != "pcie-mmcfg-mmio" {
                return Err("unexpected CPU-visible QEMU ECAM overlap".into());
            }
            ecam = true;
        }
        if start <= DRHD_PAGE.1 && DRHD_PAGE.0 <= end {
            if drhd || (start, end) != DRHD || kind != "0, i/o" || name != "intel_iommu" {
                return Err("unexpected CPU-visible QEMU DRHD or page-padding overlap".into());
            }
            drhd = true;
        }
    }
    if !ecam || drhd != expect_drhd {
        return Err("missing exact QEMU ECAM or DRHD register resource".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn cold_shared_detachment_accepts_only_halted_port_change() {
        use super::{FixtureBar, FixtureState};
        let before = FixtureState {
            bar: FixtureBar { start: 0x8120_0000, end: 0x8120_3fff },
            cap0: 0x0100_0040,
            command: 0,
            status: 1,
        };
        assert!(before.matches_halted_shared_boot(FixtureState { status: 9, ..before }));
        for status in [0, 2, 3, 5, 17, 1 << 11 | 1, u32::MAX] {
            assert!(!before.matches_halted_shared_boot(FixtureState { status, ..before }));
        }
        assert!(!before.matches_halted_shared_boot(FixtureState { command: 1, ..before }));
        assert!(!before.matches_halted_shared_boot(FixtureState { cap0: 0x0100_0020, ..before }));
    }

    #[test]
    fn retired_boot_topology_requires_one_empty_controller_bus() {
        let empty = "dev: qemu-xhci\n  bus: mrml_probe_xhci.0\n    type usb-bus\n    bus-prop: label\ndev: other\n";
        assert!(super::retired_shared_boot_topology(empty));
        for tree in [
            empty.replace("    bus-prop: label", "    dev: usb-storage, id \"other\""),
            empty.replace("mrml_probe_xhci.0", "other.0"),
            format!("{empty}{empty}"),
            format!("{empty}dev: usb-storage, id \"mrml_shared_boot\"\n"),
        ] {
            assert!(!super::retired_shared_boot_topology(&tree));
        }
    }
    use super::*;

    #[test]
    fn shared_controller_accepts_port_change_but_not_control_or_remapper_drift() {
        let initial = SharedController {
            xhci: FixtureState {
                bar: FixtureBar {
                    start: 0x10000,
                    end: 0x13fff,
                },
                cap0: 0x0100_0040,
                command: 0,
                status: 1,
            },
            pci_command: 7,
            gsts: 0,
            root: 0,
            fsts: 0,
        };
        assert_eq!(initial.disable_command(), Some(3));
        assert_eq!(
            SharedController {
                pci_command: 6,
                ..initial
            }
            .disable_command(),
            Some(2)
        );
        assert_eq!(
            SharedController {
                pci_command: 3,
                ..initial
            }
            .disable_command(),
            None
        );
        assert_eq!(
            SharedController {
                gsts: 1 << 31,
                ..initial
            }
            .disable_command(),
            None
        );
        assert_eq!(
            SharedController {
                xhci: FixtureState {
                    command: 1,
                    ..initial.xhci
                },
                ..initial
            }
            .disable_command(),
            None
        );
        let mut after = initial;
        after.xhci.status |= 1 << 4;
        after.pci_command |= 1 << 19; // Separate PCI status half.
        assert!(initial.matches_control(after));
        after.xhci.status &= !1;
        assert!(!initial.matches_control(after));
        for changed in [
            SharedController {
                pci_command: 3,
                ..initial
            },
            SharedController {
                gsts: 1 << 31,
                ..initial
            },
            SharedController {
                root: 0x1000,
                ..initial
            },
            SharedController { fsts: 1, ..initial },
            SharedController {
                xhci: FixtureState {
                    command: 1,
                    ..initial.xhci
                },
                ..initial
            },
            SharedController {
                xhci: FixtureState {
                    bar: FixtureBar {
                        start: 0x20000,
                        end: 0x23fff,
                    },
                    ..initial.xhci
                },
                ..initial
            },
        ] {
            assert!(!initial.matches_control(changed));
        }
    }

    #[test]
    fn shared_boot_requires_unique_direct_attachment_and_named_stats() {
        let tree = concat!(
            "  bus: mrml_probe_xhci.0\n",
            "    dev: usb-storage, id \"mrml_shared_boot\"\n",
            "      drive = \"esp\"\n",
            "  bus: usb-other.0\n",
        );
        assert!(shared_boot_topology(tree));
        assert!(!shared_boot_topology(
            &tree.replace("mrml_probe_xhci.0", "different.0")
        ));
        assert!(!shared_boot_topology(
            &tree.replace("    dev:", "      dev:")
        ));
        assert!(!shared_boot_topology(&format!("{tree}{tree}")));
        assert_eq!(
            named_block_stats(
                "esp: rd_bytes=512 rd_operations=1 wr_bytes=0 wr_operations=0\n",
                "esp:"
            )
            .unwrap(),
            [512, 1, 0, 0]
        );
    }

    const VIEW: &str = concat!(
        "FlatView #0\n AS \"memory\", root: system\n AS \"cpu-memory-0\", root: system\n",
        " Root memory region: system\n",
        "  00000000e0000000-00000000efffffff (prio 0, i/o): pcie-mmcfg-mmio\n",
        "  00000000fed90000-00000000fed9022f (prio 0, i/o): intel_iommu\n",
    );

    #[test]
    fn cold_fixture_rejects_non_ram_overlap_and_unexpected_dma_leaf() {
        use std::fmt::Write as _;
        let ram = "  0000000000100000-0000000007ffffff (prio 0, ram): pc.ram\n";
        let map = format!("{VIEW}{ram}");
        assert!(verify_root_ram(&map, 0x400000).is_ok());
        for root in [0xfffff, 0x400001, 0x07ff_f000, 0xffff_f000, u64::MAX] {
            assert!(verify_root_ram(&map, root).is_err());
        }
        assert!(verify_root_ram(VIEW, 0x400000).is_err());
        assert!(verify_root_ram(&format!("{map}{ram}"), 0x400000).is_err());

        let mut dump = String::new();
        for word in 0..512 {
            writeln!(dump, "{:08x}: 0x0000000000000000", 0x405000 + word * 8).unwrap();
        }
        assert!(verify_root_page(&dump, 0x400000, 5, 0, 1).is_ok());
        assert!(
            verify_root_page(
                &dump.replacen("0000000000000000", "0000000000406003", 1),
                0x400000,
                5,
                0,
                1
            )
            .is_err()
        );
        assert!(verify_root_page(&dump[1..], 0x400000, 5, 0, 1).is_err());
        assert!(verify_root_page(&dump[..dump.len() - 4], 0x400000, 5, 0, 1).is_err());
    }

    #[test]
    fn exact_system_view_excludes_padding_conflicts_and_ignores_dma_views() {
        let no_drhd = VIEW
            .lines()
            .filter(|line| !line.contains("intel_iommu"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(validate_resources(&no_drhd, false).is_ok());
        assert!(validate_resources(VIEW, false).is_err());
        assert!(validate_resources(&no_drhd, true).is_err());
        assert!(validate(VIEW).is_ok());
        assert!(
            validate(&format!(
                "{VIEW}FlatView #1\n AS \"vtd-root\", root: vtd-nodmar\n"
            ))
            .is_ok()
        );
        for old in ["cpu-memory-0", "efffffff", "intel_iommu", "(prio 0, i/o)"] {
            assert!(validate(&VIEW.replace(old, "wrong")).is_err());
        }
        assert!(validate(&format!("{VIEW}{VIEW}")).is_err());
        assert!(
            validate(&format!(
                "{VIEW}  00000000fed90230-00000000fed903ff (prio 1, ram): unexpected\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn qmp_framing_rejects_wrong_id_errors_and_missing_newline() {
        let line = concat!(r#"{"return": "AS \"memory\"\r\n", "id": 73}"#, "\n").as_bytes();
        assert_eq!(read_monitor(line, 73).unwrap(), "AS \"memory\"\r\n");
        assert!(read_monitor(&line[..line.len() - 1], 73).is_err());
        assert!(read_monitor(&b"{\"return\": \"x\", \"id\": 61}\n"[..], 73).is_err());
        assert!(read_monitor(&b"{\"error\": {}}\n"[..], 73).is_err());
    }

    #[test]
    fn qmp_release_requires_stop_and_both_exact_resource_views() {
        let uart = concat!(
            "FlatView #1\n AS \"I/O\", root: io\n Root memory region: io\n",
            "  00000000000002f8-00000000000002ff (prio 0, i/o): serial\n",
        );
        for (stop, map, allowed) in [
            (72, format!("{VIEW}{uart}"), true),
            (90, format!("{VIEW}{uart}"), false),
            (72, VIEW.into(), false),
            (72, format!("{VIEW}{uart}{uart}"), false),
            (
                72,
                format!("{}{uart}", VIEW.replace("intel_iommu", "unknown")),
                false,
            ),
        ] {
            let frame = map.replace('"', "\\\"").replace('\n', "\\n");
            let replies = format!(
                "{{\"return\": {{}}, \"id\": 71}}\n{{\"return\": {{}}, \"id\": {stop}}}\n{{\"return\": \"{frame}\", \"id\": 73}}\n{{\"return\": \"\", \"id\": 74}}\n{{\"return\": {{}}, \"id\": 75}}\n"
            );
            let mut sent = Vec::new();
            assert_eq!(
                inspect_qmp(
                    &mut sent,
                    &mut replies.as_bytes(),
                    Some(0x5a),
                    false,
                    None,
                    None,
                    PausedCheck::Resources,
                )
                .is_ok(),
                allowed
            );
            let sent = String::from_utf8(sent).unwrap();
            assert_eq!(sent.contains("o /b"), allowed);
            assert_eq!(sent.contains("\"cont\""), allowed);
        }
    }

    const PCI: &str = concat!(
        "  Bus  0, device  27, function 0:\n",
        "    USB controller: PCI device 1b36:000d\n",
        "      BAR0: 64 bit memory at 0xc000004000 [0xc000007fff]\n",
        "      id \"mrml_probe_xhci\"\n",
    );
    const XHCI_MAP: &str = concat!(
        "  000000c000004000-000000c00000403f (prio 0, i/o): capabilities owner:{dev path=/machine/peripheral/mrml_probe_xhci/xhci-core}\n",
        "  000000c000004040-000000c00000443f (prio 0, i/o): operational owner:{dev path=/machine/peripheral/mrml_probe_xhci/xhci-core}\n",
    );

    #[test]
    fn isolation_branch_requires_exact_bridge_and_no_other_downstream_functions() {
        let pci = PCI.replace("Bus  0, device  27,", "Bus 65, device   0,");
        let branch = concat!(
            "Bus 64, device   0, function 0:\n",
            " PCI bridge: PCI device 1b36:000c\n secondary bus 65.\n subordinate bus 65.\n id \"probe_port\"\n",
            "Bus  0, device  27, function 0:\n Host bridge: PCI device 1b36:000b\n id \"probe_domain\"\n",
            "Bus  0, device   5, function 0:\n USB controller: PCI device 1b36:000d\n id \"mrml_boot_xhci\"\n",
        );
        let topology = format!("{branch}{pci}");
        assert!(fixture_bar(&topology, true).is_ok());
        assert!(fixture_bar(&topology, false).is_err());
        let shared = topology.replace(
            "Bus  0, device   5, function 0:\n USB controller: PCI device 1b36:000d\n id \"mrml_boot_xhci\"\n",
            "",
        );
        assert!(fixture_bar_for_topology(&shared, true, false).is_ok());
        assert!(fixture_bar_for_topology(&topology, true, false).is_err());
        assert!(fixture_bar_for_topology(&shared, true, true).is_err());
        assert!(fixture_bar_for_topology(
            &format!("{shared}Bus 65, device   1, function 0:\n"),
            true,
            false,
        ).is_err());
        for bad in [
            topology.replace("subordinate bus 65.", "subordinate bus 66."),
            topology.replace("Bus 65,", "Bus  0,"),
            topology.replace("id \"probe_port\"", "id \"unknown\""),
            topology.replace("id \"mrml_boot_xhci\"", "id \"mrml_probe_xhci\""),
            format!("{topology}Bus 65, device   1, function 0:\n"),
            format!("{topology}Bus 66, device   0, function 0:\n"),
        ] {
            assert!(fixture_bar(&bad, true).is_err(), "{bad}");
        }
    }

    #[test]
    fn correct_release_requires_exact_live_bar_and_register_owners() {
        let encode = |body: &str| body.replace('"', "\\\"").replace('\n', "\\n");
        let base = encode(&format!(
            "{VIEW}FlatView #1\n AS \"I/O\", root: io\n Root memory region: io\n  00000000000002f8-00000000000002ff (prio 0, i/o): serial\n"
        ));
        for (pci, mapped, allowed) in [
            (PCI.to_owned(), XHCI_MAP.to_owned(), true),
            (PCI.replace("27,", "26,"), XHCI_MAP.to_owned(), false),
            (PCI.replace("000d", "000e"), XHCI_MAP.to_owned(), false),
            (
                PCI.replace("64 bit", "64 bit prefetchable"),
                XHCI_MAP.to_owned(),
                false,
            ),
            (PCI.replace("007fff", "008000"), XHCI_MAP.to_owned(), false),
            (format!("{PCI}{PCI}"), XHCI_MAP.to_owned(), false),
            (
                PCI.into(),
                XHCI_MAP.replace("probe_xhci", "boot_xhci"),
                false,
            ),
            (PCI.into(), XHCI_MAP.replace("00443f", "00443e"), false),
            (PCI.into(), "".into(), false),
            (PCI.into(), format!("{XHCI_MAP}{XHCI_MAP}"), false),
        ] {
            let pci = encode(&pci);
            let mapped = encode(&format!("{VIEW}{mapped}"));
            let replies = format!(
                "{{\"return\": {{}}, \"id\": 71}}\n{{\"return\": {{}}, \"id\": 72}}\n{{\"return\": \"{base}\", \"id\": 73}}\n{{\"return\": \"{pci}\", \"id\": 76}}\n{{\"return\": \"{mapped}\", \"id\": 77}}\n{{\"return\": \"c000004000: 0x01000040\\r\\n\", \"id\": 78}}\n{{\"return\": \"c000004040: 0x00000000\\r\\n\", \"id\": 79}}\n{{\"return\": \"c000004044: 0x00000001\\r\\n\", \"id\": 80}}\n{{\"return\": \"\", \"id\": 74}}\n{{\"return\": {{}}, \"id\": 75}}\n"
            );
            let mut sent = Vec::new();
            let result = inspect_qmp(
                &mut sent,
                &mut replies.as_bytes(),
                Some(0xa6),
                false,
                None,
                None,
                PausedCheck::Resources,
            );
            assert_eq!(
                result.as_ref().is_ok_and(Option::is_some),
                allowed,
                "{result:?}"
            );
            let sent = String::from_utf8(sent).unwrap();
            assert_eq!(sent.contains("o /b"), allowed);
            assert_eq!(sent.contains("\"cont\""), allowed);
        }
    }

    #[test]
    fn isolated_bar_proof_covers_all_port_extents_and_rejects_padding_overlap() {
        let bar = FixtureBar {
            start: 0x8120_0000,
            end: 0x8120_3fff,
        };
        let mut page = XHCI_MAP.replace("000000c000004", "0000000081200");
        for port in 0..8 {
            let start = bar.start + 0x440 + 16 * port;
            let protocol = if port < 4 { 3 } else { 2 };
            let number = port % 4 + 1;
            page.push_str(&format!(
                "  {start:016x}-{:016x} (prio 0, i/o): usb{protocol} port #{number} owner:{{dev path=/machine/peripheral/mrml_probe_xhci/xhci-core}}\n",
                start + 15,
            ));
        }
        let exact = format!("{VIEW}{page}");
        assert!(validate_fixture_bar(&exact, bar, true, false).is_ok());
        assert!(validate_fixture_bar(&exact, bar, true, true).is_err());
        let full = format!(
            concat!(
                "{} 0000000081201000-000000008120121f (prio 0, i/o): runtime owner:{{dev path=/machine/peripheral/mrml_probe_xhci/xhci-core}}\n",
                "  0000000081202000-000000008120281f (prio 0, i/o): doorbell owner:{{dev path=/machine/peripheral/mrml_probe_xhci/xhci-core}}\n",
            ),
            exact
        );
        assert!(validate_fixture_bar(&full, bar, true, true).is_ok());
        assert!(
            validate_fixture_bar(
                &full.replace("runtime owner", "unexpected owner"),
                bar,
                true,
                true
            )
            .is_err()
        );
        let padding = format!("{full} 0000000081202ff0-0000000081202fff (prio 0, ram): conflict\n");
        assert!(validate_fixture_bar(&padding, bar, true, true).is_err());
        assert!(
            validate_fixture_bar(
                &exact.replace("usb3 port #4", "usb2 port #4"),
                bar,
                true,
                false
            )
            .is_err()
        );
        assert!(
            validate_fixture_bar(&exact.replace("8120049f", "8120049e"), bar, true, false).is_err()
        );
        let unexpected =
            format!("{exact} 0000000081200ff0-0000000081200fff (prio 1, ram): conflict\n");
        assert!(validate_fixture_bar(&unexpected, bar, true, false).is_err());
        assert!(validate_fixture_bar(&format!("{exact}{page}"), bar, true, false).is_err());
    }

    #[test]
    fn fixed_xhci_reads_stop_on_an_unproven_geometry_or_bad_reply() {
        let bar = fixture_bar(PCI, false).unwrap();
        let cap = "{\"return\": \"c000004000: 0x01000040\\r\\n\", \"id\": 78}\n";
        let cmd = "{\"return\": \"c000004040: 0x00000001\\r\\n\", \"id\": 79}\n";
        let sts = "{\"return\": \"c000004044: 0x00000000\\r\\n\", \"id\": 80}\n";
        for (cap, reads) in [
            (cap.to_owned(), 3),
            (cap.replace("01000040", "01000044"), 1),
            (cap.replace("c000004000", "c000008000"), 1),
            (cap.replace("01000040", "4001000040"), 1),
            (cap.replace("01000040", "ffffffff"), 1),
        ] {
            let replies = format!("{cap}{cmd}{sts}");
            let mut sent = Vec::new();
            let state = sample_xhci_state(&mut sent, &mut replies.as_bytes(), bar);
            match reads {
                3 => {
                    let state = state.unwrap();
                    assert_eq!(state.command, 1);
                    assert_eq!(state.status, 0);
                }
                _ => assert!(state.is_err()),
            }
            let sent = String::from_utf8(sent).unwrap();
            assert_eq!(sent.matches("xp /1wx").count(), reads);
            assert!(!sent.contains("o /b"));
        }
    }

    #[test]
    fn snapshot_requires_the_release_prefix_and_a_complete_exact_report() {
        let prefix = [0xdc, 0xde];
        let bar = FixtureBar {
            start: 0xc000004000,
            end: 0xc000007fff,
        };
        let state = FixtureState {
            bar,
            cap0: 0x01000040,
            command: 0,
            status: 1,
        };
        let data = [
            &prefix[..],
            &0x10_u32.to_le_bytes(),
            &0x80d2_008c_222f_0606_u64.to_le_bytes(),
            &0xf42_u64.to_le_bytes(),
            &0_u32.to_le_bytes(),
            &0x000d_1b36_u32.to_le_bytes(),
            &6_u16.to_le_bytes(),
            &0x0c03_3001_u32.to_le_bytes(),
            &[0],
            &0x4004_u32.to_le_bytes(),
            &0xc0_u32.to_le_bytes(),
            &[0; 22],
            &[0xda],
        ]
        .concat();
        let mut shutdown = data.clone();
        shutdown[30] = 7;
        shutdown[45..47].copy_from_slice(&7u16.to_le_bytes());
        shutdown[47..51].copy_from_slice(&0x0041_4140u32.to_le_bytes());
        shutdown[51..55].copy_from_slice(&state.cap0.to_le_bytes());
        shutdown[59..63].copy_from_slice(&state.status.to_le_bytes());
        shutdown[63..67].copy_from_slice(&[3, 0, 3, 0]);
        assert!(
            register_snapshot(&prefix, &shutdown, state, true, true)
                .unwrap()
                .is_some()
        );
        assert!(register_snapshot(&prefix, &shutdown, state, true, false).is_err());
        for at in [63, 65] {
            let mut wrong = shutdown.clone();
            wrong[at] |= 4;
            assert!(register_snapshot(&prefix, &wrong, state, true, true).is_err());
        }
        for end in 0..data.len() {
            assert_eq!(
                register_snapshot(&prefix, &data[..end], state, false, false).unwrap(),
                None
            );
        }
        assert!(
            register_snapshot(&prefix, &data, state, false, false)
                .unwrap()
                .unwrap()
                .contains("|bme=true")
        );
        for at in [0, 1, 2, 26, 35, 36, 37, 41, 45, 48, 51, 55, 60, 63, 66, 67] {
            let mut wrong = data.clone();
            wrong[at] ^= 0xff;
            assert!(register_snapshot(&prefix, &wrong, state, false, false).is_err());
        }
        assert!(register_snapshot(&prefix, &[0xdc, 0xde, 0xdb], state, false, false).is_err());
        assert!(
            register_snapshot(
                &prefix,
                &[data.as_slice(), &[0]].concat(),
                state,
                false,
                false
            )
            .is_err()
        );
    }
}
