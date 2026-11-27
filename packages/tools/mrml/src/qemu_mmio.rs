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

pub(super) fn fixture_acpi_table() -> [u8; 36] {
    let mut table = [0u8; 36];
    table[..4].copy_from_slice(b"MQ35");
    table[4..8].copy_from_slice(&36u32.to_le_bytes());
    table[8] = 1;
    table[10..].copy_from_slice(b"MRMLQ3MMIOTEST\x01\x00\x00\x00MRML\x01\x00\x00\x00");
    table[9] = 0u8.wrapping_sub(table.iter().copied().fold(0u8, u8::wrapping_add));
    table
}

pub(super) fn verify_paused_q35_resources(child: &mut Child) -> Result<(), String> {
    inspect_q35(child, None).map(|_| ())
}

pub(super) fn release_q35_fixture(
    child: &mut Child,
    valid: bool,
) -> Result<Option<FixtureBar>, String> {
    inspect_q35(child, Some(valid))
}

fn inspect_q35(child: &mut Child, release: Option<bool>) -> Result<Option<FixtureBar>, String> {
    let mut stdin = child.stdin.take().ok_or("missing QMP input")?;
    let stdout = child.stdout.take().ok_or("missing QMP output")?;
    let (send, receive) = mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .spawn(move || {
            let _ = send.send(inspect_qmp(
                &mut stdin,
                &mut BufReader::new(stdout),
                release,
            ));
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
    release: Option<bool>,
) -> Result<Option<FixtureBar>, String> {
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
    let bar = if release == Some(true) {
        qmp_write(
            stdin,
            "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info pci\"},\"id\":76}\n",
        )?;
        let bar = fixture_bar(&read_monitor(&mut *reader, 76)?)?;
        qmp_write(
            stdin,
            "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info mtree -f -o\"},\"id\":77}\n",
        )?;
        validate_fixture_bar(&read_monitor(&mut *reader, 77)?, bar)?;
        Some(bar)
    } else {
        None
    };
    if let Some(valid) = release {
        validate_scratch_uart(&map)?;
        let write = if valid {
            "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"o /b 0x2ff 0xa6\"},\"id\":74}\n"
        } else {
            "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"o /b 0x2ff 0x5a\"},\"id\":74}\n"
        };
        qmp_write(stdin, write)?;
        ack(reader, "{\"return\": \"\", \"id\": 74}")?;
        qmp_write(stdin, "{\"execute\":\"cont\",\"id\":75}\n")?;
        ack(reader, "{\"return\": {}, \"id\": 75}")?;
    }
    Ok(bar)
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
    bar: FixtureBar,
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
    if data.len() < 44 {
        return Ok(None);
    }
    if data.len() != 44 || data[43] != 0xda {
        return Err("wrong q35 fixed-register report length or trailer".into());
    }
    let long = |at| u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
    let quad = |at| u64::from_le_bytes(data[at..at + 8].try_into().unwrap());
    let (ver, cap, ecap, gsts, pci, class) =
        (long(0), quad(4), quad(12), long(20), long(24), long(30));
    let command = u16::from_le_bytes(data[28..30].try_into().unwrap());
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
        "q35-read-only-registers|status=PASS|ver={ver:#x}|cap={cap:#018x}|ecap={ecap:#018x}|gsts={gsts:#010x}|pci={pci:#010x}|command={command:#06x}|class_revision={class:#010x}|bme={}|bar0={:#x}..={:#x}",
        command & (1 << 2) != 0,
        bar.start,
        bar.end
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

fn fixture_bar(pci: &str) -> Result<FixtureBar, String> {
    let mut exact = false;
    let mut identity = false;
    let mut device_id = false;
    let mut bar = None;
    let mut slot_seen = false;
    for line in pci.lines() {
        let line = line.trim();
        if line.starts_with("Bus ") {
            exact = line == "Bus  0, device  27, function 0:";
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

fn validate_fixture_bar(map: &str, bar: FixtureBar) -> Result<(), String> {
    let mut observed = [false; 2];
    let expected = [(0, 0x3f, "capabilities"), (0x40, 0x43f, "operational")];
    for line in cpu_ranges(map)? {
        let (start, end, kind, description) = flat_range(line)?;
        if start > bar.start + 0x43f || end < bar.start {
            continue;
        }
        let Some(index) = expected.iter().position(|&(lo, hi, name)| {
            (start, end) == (bar.start + lo, bar.start + hi)
                && kind == "0, i/o"
                && description.strip_prefix(name)
                    == Some(" owner:{dev path=/machine/peripheral/mrml_probe_xhci/xhci-core}")
        }) else {
            return Err(format!(
                "unexpected CPU-visible xHCI register range: {line}"
            ));
        };
        if std::mem::replace(&mut observed[index], true) {
            return Err("duplicate xHCI capability or operational register range".into());
        }
    }
    if observed != [true; 2] {
        return Err("missing CPU-visible xHCI capability or operational register range".into());
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
        assert_eq!(read_monitor(&line[..], 73).unwrap(), "AS \"memory\"\r\n");
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
                inspect_qmp(&mut sent, &mut replies.as_bytes(), Some(false)).is_ok(),
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
                "{{\"return\": {{}}, \"id\": 71}}\n{{\"return\": {{}}, \"id\": 72}}\n{{\"return\": \"{base}\", \"id\": 73}}\n{{\"return\": \"{pci}\", \"id\": 76}}\n{{\"return\": \"{mapped}\", \"id\": 77}}\n{{\"return\": \"\", \"id\": 74}}\n{{\"return\": {{}}, \"id\": 75}}\n"
            );
            let mut sent = Vec::new();
            let result = inspect_qmp(&mut sent, &mut replies.as_bytes(), Some(true));
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
    fn snapshot_requires_the_release_prefix_and_a_complete_exact_report() {
        let prefix = [0xdc, 0xde];
        let bar = FixtureBar {
            start: 0xc000004000,
            end: 0xc000007fff,
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
            &[0xda],
        ]
        .concat();
        for end in 0..data.len() {
            assert_eq!(register_snapshot(&prefix, &data[..end], bar).unwrap(), None);
        }
        assert!(
            register_snapshot(&prefix, &data, bar)
                .unwrap()
                .unwrap()
                .contains("|bme=true")
        );
        for at in [0, 1, 2, 26, 35, 36, 37, 41, 45] {
            let mut wrong = data.clone();
            wrong[at] ^= 0xff;
            assert!(register_snapshot(&prefix, &wrong, bar).is_err());
        }
        assert!(register_snapshot(&prefix, &[0xdc, 0xde, 0xdb], bar).is_err());
        assert!(register_snapshot(&prefix, &[data.as_slice(), &[0]].concat(), bar).is_err());
    }
}
