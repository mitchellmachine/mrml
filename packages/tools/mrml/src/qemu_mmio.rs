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

pub(super) fn verify_paused_q35_resources(child: &mut Child) -> Result<(), String> {
    inspect_q35(child, None, false, None, None).map(|_| ())
}

pub(super) fn release_q35_fixture(
    child: &mut Child,
    release: u8,
    isolated: bool,
    post: Option<(&std::path::Path, &[u8])>,
    cold: Option<bool>,
) -> Result<Option<FixtureState>, String> {
    inspect_q35(child, Some(release), isolated, post, cold)
}

fn inspect_q35(
    child: &mut Child,
    release: Option<u8>,
    isolated: bool,
    post: Option<(&std::path::Path, &[u8])>,
    cold: Option<bool>,
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
    cold: Option<bool>,
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
    validate(&map)?;
    let bar = if matches!(release, Some(0xa6..=0xaa)) {
        if isolated {
            check_isolation_properties(stdin, reader)?;
        }
        qmp_write(
            stdin,
            "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info pci\"},\"id\":76}\n",
        )?;
        let bar = fixture_bar(&read_monitor(&mut *reader, 76)?, isolated)?;
        qmp_write(
            stdin,
            "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info mtree -f -o\"},\"id\":77}\n",
        )?;
        let preflight = matches!(release, Some(0xa9 | 0xaa));
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
        if preflight && (state.command != 0 || state.status != 1) {
            return Err("controller is not halted with interrupts off".into());
        }
        Some(state)
    } else {
        None
    };
    let shutdown = matches!(release, Some(0xa7 | 0xa8 | 0xaa));
    let before = if shutdown {
        let state = bar
            .filter(|_| isolated)
            .ok_or("missing isolated controller sample")?;
        if state.command != 0 || state.status != 1 || post.is_none() {
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
    if let Some(byte) = release {
        validate_scratch_uart(&map)?;
        if !matches!(byte, 0xa6..=0xaa | 0x5a) {
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
    if let (Some(before), Some((path, prefix)), Some(state)) = (before, post, bar) {
        if let Some(allow) = cold {
            inspect_cold_activation(
                stdin,
                reader,
                &map,
                (path, prefix),
                state,
                before,
                (allow, release == Some(0xaa)),
            )?;
            return Ok(bar);
        }
        await_shutdown_report(path, prefix, state)?;
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
            return Err("unexpected signed cold activation trace".into());
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

fn verify_root_page(text: &str, root: u64, page: u64, leaf: u64) -> Result<(), String> {
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
                (0, 130) | (1, 0) => (address + 4096) | 1,
                (1, 1) => 0x102,
                (2 | 3, 0) | (4, 1) => (address + 4096) | 3,
                (5, 0) => leaf,
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
) -> Result<(), String> {
    qmp_write(
        stdin,
        &format!(
            "{{\"execute\":\"human-monitor-command\",\"arguments\":{{\"command-line\":\"xp /512gx {:#x}\"}},\"id\":112}}\n",
            root + 5 * 4096,
        ),
    )?;
    verify_root_page(&read_monitor(reader, 112)?, root, 5, leaf)
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
    mode: (bool, bool),
) -> Result<(), String> {
    let (allow, command) = mode;
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
        verify_root_page(&read_monitor(&mut *reader, 105)?, root, page, 0)?;
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
        if !allow {
            &[0xc4]
        } else if command {
            &[0xc6]
        } else {
            &[0xc3]
        },
    )?;
    qmp_write(stdin, "{\"execute\":\"stop\",\"id\":108}\n")?;
    ack(reader, "{\"return\": {}, \"id\": 108}")?;
    if command && allow {
        if after_root != root {
            return Err("xHCI root changed during the command".into());
        }
        return inspect_command_completion(stdin, reader, trace, root, state, firmware);
    }
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
        check_live_leaf(stdin, reader, root, payload | 3)?;
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
        check_live_leaf(stdin, reader, root, payload)?;
    }
    println!(
        "q35-vtd-cold|status=PASS|activated={allow}|root={root:#x}|aperture_installed_and_revoked={allow}|no_present_dma_leaves=true|bme=false"
    );
    Ok(())
}

fn inspect_command_completion(
    stdin: &mut impl std::io::Write,
    reader: &mut impl std::io::BufRead,
    trace: (&std::path::Path, &[u8]),
    root: u64,
    initial: FixtureState,
    firmware: ShutdownSample,
) -> Result<(), String> {
    let (path, prefix) = trace;
    let command = sample_xhci_state(stdin, reader, initial.bar)?;
    let active = ShutdownSample {
        gsts: 0xc000_0000,
        ..firmware
    };
    let payload = root + 6 * 4096;
    if command.command != 1
        || command.status & 0x1805 != 0
        || sample_shutdown(stdin, reader, 95)? != active
        || read_root_pointer(stdin, reader)? != root
        || read_model_dword(stdin, reader, 0xfed9_0034, 104)? != 0
    {
        return Err("command fixture lacks live authority or has an xHCI/VT-d fault".into());
    }
    check_live_leaf(stdin, reader, root, payload | 3)?;
    for (index, expected) in [0x20_0100, 0, 1 << 24, (33 << 10) | 1]
        .into_iter()
        .enumerate()
    {
        if read_model_dword(stdin, reader, payload + 0x300 + 4 * index as u64, 117)? != expected {
            return Err("no matching DMA-written xHCI command completion event".into());
        }
    }
    qmp_write(
        stdin,
        "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"o /b 0x2ff 0xba\"},\"id\":118}\n",
    )?;
    ack(reader, "{\"return\": \"\", \"id\": 118}")?;
    qmp_write(stdin, "{\"execute\":\"cont\",\"id\":119}\n")?;
    ack(reader, "{\"return\": {}, \"id\": 119}")?;
    let (after_root, _) = wait_cold_trace(path, prefix, initial, &[0xc6, 0xc7])?;
    qmp_write(stdin, "{\"execute\":\"stop\",\"id\":120}\n")?;
    ack(reader, "{\"return\": {}, \"id\": 120}")?;
    let stopped = sample_xhci_state(stdin, reader, initial.bar)?;
    if after_root != root
        || stopped.command != 0
        || stopped.status & 0x1805 != 1
        || sample_shutdown(stdin, reader, 95)?
            != (ShutdownSample {
                endpoint: active.endpoint & !4,
                bridge: active.bridge & !4,
                ..active
            })
        || read_root_pointer(stdin, reader)? != root
        || read_model_dword(stdin, reader, 0xfed9_0034, 104)? != 0
    {
        return Err("xHCI shutdown did not leave the exact halted BME-off state".into());
    }
    check_live_leaf(stdin, reader, root, payload)?;
    qmp_write(
        stdin,
        &format!(
            "{{\"execute\":\"human-monitor-command\",\"arguments\":{{\"command-line\":\"xp /512gx {payload:#x}\"}},\"id\":121}}\n",
        ),
    )?;
    verify_root_page(&read_monitor(reader, 121)?, root, 6, 0)?;
    println!(
        "q35-xhci-command|status=PASS|completion=success|payload={payload:#x}|halted=true|bme=false|aperture_revoked=true|payload_zero=true"
    );
    Ok(())
}
fn await_shutdown_report(
    path: &std::path::Path,
    prefix: &[u8],
    state: FixtureState,
) -> Result<(), String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(512).read_to_end(&mut bytes))
            .map_err(|e| format!("read shutdown trace: {e}"))?;
        // The loop starts immediately after cont, so dc alone is legitimate.
        if register_snapshot(prefix, &bytes, state, true, true)?.is_some() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Err("missing complete signed shutdown report".into())
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

fn validate_isolated_pci_branch(pci: &str) -> Result<(), String> {
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
    if (roots, endpoints, expander, boot, bridge_fields) != (1, 1, 1, 1, u8::MAX) {
        return Err("missing complete isolated QEMU PCI branch".into());
    }
    Ok(())
}

fn fixture_bar(pci: &str, isolated: bool) -> Result<FixtureBar, String> {
    if isolated {
        validate_isolated_pci_branch(pci)?;
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
    if !ecam || !drhd {
        return Err("missing exact QEMU ECAM or DRHD register resource".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(verify_root_page(&dump, 0x400000, 5, 0).is_ok());
        assert!(
            verify_root_page(
                &dump.replacen("0000000000000000", "0000000000406003", 1),
                0x400000,
                5,
                0
            )
            .is_err()
        );
        assert!(verify_root_page(&dump[1..], 0x400000, 5, 0).is_err());
        assert!(verify_root_page(&dump[..dump.len() - 4], 0x400000, 5, 0).is_err());
    }

    #[test]
    fn exact_system_view_excludes_padding_conflicts_and_ignores_dma_views() {
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
                    None
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
