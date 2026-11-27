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
    inspect_q35(child, None)
}

pub(super) fn release_q35_fixture(child: &mut Child, valid: bool) -> Result<(), String> {
    inspect_q35(child, Some(valid))
}

fn inspect_q35(child: &mut Child, release: Option<bool>) -> Result<(), String> {
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
) -> Result<(), String> {
    qmp_write(stdin, "{\"execute\":\"qmp_capabilities\",\"id\":71}\n")?;
    ack(reader, "{\"return\": {}, \"id\": 71}")?;
    qmp_write(stdin, "{\"execute\":\"stop\",\"id\":72}\n")?;
    ack(reader, "{\"return\": {}, \"id\": 72}")?;
    qmp_write(
        stdin,
        "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info mtree -f\"},\"id\":73}\n",
    )?;
    let map = read_map(&mut *reader)?;
    validate(&map)?;
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
    Ok(())
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

fn read_map(mut reader: impl std::io::BufRead) -> Result<String, String> {
    for _ in 0..12 {
        let raw = qmp_line(&mut reader)?;
        let line = raw.trim_end();
        if line.starts_with("{\"error\"") {
            return Err("QEMU rejected a resource query".into());
        }
        if let Some(body) = line.strip_suffix(", \"id\": 73}") {
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

fn validate(map: &str) -> Result<(), String> {
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
    let mut ecam = false;
    let mut drhd = false;
    for line in tail.map(str::trim).filter(|line| !line.is_empty()) {
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
        assert_eq!(read_map(&line[..]).unwrap(), "AS \"memory\"\r\n");
        assert!(read_map(&line[..line.len() - 1]).is_err());
        assert!(read_map(&b"{\"return\": \"x\", \"id\": 61}\n"[..]).is_err());
        assert!(read_map(&b"{\"error\": {}}\n"[..]).is_err());
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
                inspect_qmp(&mut sent, &mut replies.as_bytes(), Some(true)).is_ok(),
                allowed
            );
            let sent = String::from_utf8(sent).unwrap();
            assert_eq!(sent.contains("o /b"), allowed);
            assert_eq!(sent.contains("\"cont\""), allowed);
        }
    }
}
