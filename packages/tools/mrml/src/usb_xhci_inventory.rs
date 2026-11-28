//! QEMU-only regression for the standalone read-only EFI xHCI inventory.
use super::{Scratch, Workspace, build_or_test, string, words};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MAX_SERIAL: u64 = 128 * 1024;
const RETURN: &str = "xhci-inventory: returning to firmware; no controller handoff";
const MENU: &str = "BdsDxe: starting Boot0000 \"BootManagerMenuApp\"";
const GEOMETRY: &str = "xhci DMA: scratchpads=0 page-mask=0x0001";
const START: &str = "MRML xhci-inventory: read-only";
const BOOT_EVIDENCE: &str = "xhci boot evidence: ";
const BOOT_WIRE: &str = "xhci boot wire ";

fn exact_usb_boot_evidence(report: &str) -> bool {
    if report.lines().filter(|line| line.starts_with(BOOT_EVIDENCE)).count() != 1 {
        return false;
    }
    let Some((_, usb)) = report.split_once("xhci 0000:00:06.0 pci=1b36:000d rev=01 cmd=") else {
        return false;
    };
    let usb = usb.split("\nxhci 0000:").next().unwrap_or(usb);
    let Some(bar_line) = usb.lines().find_map(|line| line.strip_prefix("xhci BAR0=")) else {
        return false;
    };
    let Some((bar, _)) = bar_line.split_once(" ownership=Ok(Absent)") else {
        return false;
    };
    let Some((base, size)) = bar.split_once(" size=") else {
        return false;
    };
    let expected = format!(
        "{BOOT_EVIDENCE}requester=00000030 pci=000d1b36 class=0c033001 bar0={base} size={size}"
    );
    let Some(base) = base.strip_prefix("0x").and_then(|hex| u64::from_str_radix(hex, 16).ok()) else {
        return false;
    };
    if size != "0x4000" || base == 0 || !base.is_multiple_of(0x4000)
        || base.checked_add(0x4000).is_none()
        || report.lines().filter(|line| line.starts_with(BOOT_WIRE)).count() != 2
    {
        return false;
    }
    // Independently reconstruct the diagnostic V1 bytes from the fixed
    // emulator identity and text report, then compare the exact wire output.
    let mut tail = String::new();
    for byte in 0x0c03_3001u32.to_le_bytes().into_iter()
        .chain(base.to_le_bytes())
        .chain(0x4000u32.to_le_bytes())
        .chain([0u8; 4])
    {
        use std::fmt::Write as _;
        write!(tail, "{byte:02x}").unwrap();
    }
    let mut lines = usb.lines().skip_while(|line| *line != expected);
    lines.next() == Some(expected.as_str())
        && lines.next() == Some("xhci boot wire 0: 4d524d4c584843490100280030000000361b0d00")
        && lines.next() == Some(format!("xhci boot wire 1: {tail}").as_str())
}

#[derive(Clone, Copy, Debug)]
enum Case {
    NoController,
    NoRemapper,
    WithRemapper,
    UsbBoot,
}

impl Case {
    fn observed(self, log: &str) -> bool {
        let Some((_, log)) = log.split_once(START) else {
            return false;
        };
        let Some((report, firmware)) = log.split_once(RETURN) else {
            return false;
        };
        if !firmware.contains(MENU) || report.contains("incomplete (") {
            return false;
        }
        let reported = |expected: &str| report.lines().any(|line| line == expected);
        let mut reference = report.lines().filter(|line| line.starts_with("xhci Dragonair reference: "));
        if reference.next() != Some("xhci Dragonair reference: reference requester unavailable")
            || reference.next().is_some()
        {
            return false;
        }
        if !matches!(self, Self::UsbBoot)
            && report.lines().any(|line| line.starts_with(BOOT_EVIDENCE) || line.starts_with(BOOT_WIRE))
        {
            return false;
        }
        if matches!(self, Self::NoController) {
            return reported("xhci-inventory: controllers=0 incomplete=0")
                && !report.lines().any(|line| line.starts_with("xhci 0000:"));
        }
        if matches!(self, Self::UsbBoot) {
            return reported("xhci-inventory: controllers=2 incomplete=0")
                && exact_usb_boot_evidence(report)
                && report.lines().filter(|line| line.starts_with("xhci passive PCI plan: ")).count() == 1
                && reported("xhci passive PCI plan: explicit firmware MMIO coverage missing")
                && report.lines().any(|line| line.starts_with("xhci map ECAM seg=0000 0xe0000000..0xf0000000: "))
                && report.lines().any(|line| line.starts_with("xhci map DRHD routed 0xfed90000..0xfed91000: "))
                && report.lines().any(|line| line.starts_with("xhci map PCI page 0xe0030000..0xe0031000: "))
                && report.lines().filter(|line| line.starts_with("xhci DXE ECAM window=") && line.contains(" page=") && !line.contains("not-queried")).count() == 1
                && report.lines().filter(|line| line.starts_with("xhci DXE DRHD routed 0xfed90000: ") && !line.ends_with("not-queried")).count() == 1
                && report.lines().any(|line| {
                    (line.starts_with("xhci map ECAM ") || line.starts_with("xhci map DRHD "))
                        && matches!(line.rsplit_once(": ").map(|(_, state)| state), Some("absent" | "non-mmio" | "partial-mmio"))
                })
                && report.lines().filter(|line| *line == GEOMETRY).count() == 2
                && report
                    .split("xhci 0000:00:05.0")
                    .nth(1)
                    .and_then(|report| report.split("xhci 0000:00:06.0").next())
                    .is_some_and(|device| {
                        device
                            .lines()
                            .any(|line| line == "xhci boot source: separate-usb")
                    })
                && report
                    .split("xhci 0000:00:06.0")
                    .nth(1)
                    .is_some_and(|device| {
                        device
                            .lines()
                            .any(|line| line == "xhci boot source: shared-usb")
                    });
        }
        reported(GEOMETRY)
            && reported("xhci 0000:00:05.0 pci=1b36:000d rev=01 cmd=0007")
            && reported("xhci MCFG: valid, entries=1, covered=true")
            && reported("xhci-inventory: controllers=1 incomplete=0")
            && reported("xhci boot source: non-usb")
            && report.lines().any(|line| {
                line.starts_with("xhci BAR0=0x")
                    && line.ends_with(" size=0x4000 ownership=Ok(Absent)")
            })
            && match self {
                Self::NoController | Self::UsbBoot => false,
                Self::NoRemapper => reported("xhci DMAR: MissingDmar"),
                Self::WithRemapper => reported("xhci DMAR: valid, units=1, DRHD=0xfed90000"),
            }
    }
}

pub(super) fn test(
    workspace: &Workspace,
    code: &str,
    vars: &str,
    qemu: &str,
) -> Result<(), String> {
    let firmware = |file| {
        let path = fs::canonicalize(file).map_err(|e| format!("OVMF file {file}: {e}"))?;
        if !path.is_file() {
            return Err(format!("OVMF input is not a file: {file}"));
        }
        Ok(path)
    };
    let (code, vars) = (firmware(code)?, firmware(vars)?);
    build_or_test(
        workspace,
        &words(&[
            "build",
            "org.mrml.library.uefi",
            "--target",
            "uefi-x86_64",
            "--release",
            "--feature-profile",
            "xhci_inventory",
        ]),
    )?;
    let efi = workspace
        .root
        .join("target/mrml-native/uefi/release/mrml-xhci-inventory.efi");
    let bytes = fs::read(efi).map_err(|e| format!("read inventory EFI image: {e}"))?;
    if !bytes.starts_with(b"MZ") {
        return Err("inventory output is not an EFI PE image".into());
    }
    for case in [
        Case::NoController,
        Case::NoRemapper,
        Case::WithRemapper,
        Case::UsbBoot,
    ] {
        let scratch = Scratch::new().map_err(|e| e.to_string())?;
        let esp = scratch.path("esp");
        let boot = esp.join("EFI/BOOT");
        fs::create_dir_all(&boot).map_err(|e| e.to_string())?;
        let image = boot.join("BOOTX64.EFI");
        fs::write(&image, &bytes).map_err(|e| e.to_string())?;
        let vars_copy = scratch.path("vars.fd");
        fs::copy(&vars, &vars_copy).map_err(|e| e.to_string())?;
        let serial = scratch.path("serial.txt");
        let stderr = scratch.path("qemu-error.txt");
        let mut command = Command::new(qemu);
        command
            .args([
                "-machine",
                "q35,accel=tcg",
                "-m",
                "256M",
                "-nodefaults",
                "-display",
                "none",
                "-monitor",
                "none",
                "-no-reboot",
                "-serial",
            ])
            .arg(format!("file:{}", string(&serial)))
            .arg("-drive")
            .arg(drive(&code, "if=pflash,format=raw,readonly=on,file="))
            .arg("-drive")
            .arg(drive(&vars_copy, "if=pflash,format=raw,file="))
            // Only a private virtual FAT directory; no host storage devices.
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(File::create(&stderr).map_err(|e| e.to_string())?);
        if !matches!(case, Case::NoController) {
            command.args(["-device", "qemu-xhci,addr=0x05"]);
        }
        if matches!(case, Case::UsbBoot) {
            command
                .args(["-device", "qemu-xhci,id=boot_usb,addr=0x06"])
                .arg("-drive")
                .arg(drive(&esp, "if=none,id=inventory,format=raw,file=fat:rw:"))
                .args([
                    "-device",
                    "usb-storage,drive=inventory,bus=boot_usb.0,bootindex=1",
                ]);
        } else {
            command
                .arg("-drive")
                .arg(drive(&esp, "format=raw,file=fat:rw:"));
        }
        if matches!(case, Case::WithRemapper | Case::UsbBoot) {
            command.args(["-device", "intel-iommu"]);
        }
        let mut child = command.spawn().map_err(|e| format!("start QEMU: {e}"))?;
        let started = Instant::now();
        let result = loop {
            let log = bounded(&serial);
            if case.observed(&log) {
                break Ok(());
            }
            match child.try_wait() {
                Ok(None) if started.elapsed() < Duration::from_secs(40) => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                state => {
                    let lines = log
                        .lines()
                        .filter(|line| line.starts_with("xhci") || line.contains(START))
                        .take(16)
                        .collect::<Vec<_>>();
                    break Err(format!(
                        "QEMU inventory {case:?} failed ({state:?}): {lines:?}; {}",
                        bounded(&stderr)
                    ));
                }
            }
        };
        // Always reap the QEMU instance before disposing of its image files.
        let _ = child.kill();
        child
            .wait()
            .map_err(|e| format!("reap inventory QEMU: {e}"))?;
        result?;
        if fs::read(image).map_err(|e| e.to_string())? != bytes {
            return Err("QEMU altered the inventory image".into());
        }
        println!("q35-xhci-inventory|status=PASS|case={case:?}|returned_to_firmware=true");
    }
    Ok(())
}

fn drive(path: &Path, prefix: &str) -> String {
    format!("{prefix}{}", string(path).replace(',', ",,"))
}

fn bounded(path: &Path) -> String {
    let mut raw = Vec::new();
    if let Ok(file) = File::open(path) {
        let _ = file.take(MAX_SERIAL).read_to_end(&mut raw);
    }
    String::from_utf8_lossy(&raw).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_one_evidence_record_bound_to_the_actual_boot_controller() {
        let line = "xhci boot evidence: requester=00000030 pci=000d1b36 class=0c033001 bar0=0x00000000f1000000 size=0x4000";
        let report = format!(
            "xhci 0000:00:05.0 pci=1b36:000d rev=01 cmd=0007\nxhci 0000:00:06.0 pci=1b36:000d rev=01 cmd=0007\nxhci BAR0=0x00000000f1000000 size=0x4000 ownership=Ok(Absent)\n{line}\nxhci boot wire 0: 4d524d4c584843490100280030000000361b0d00\nxhci boot wire 1: 0130030c000000f1000000000040000000000000\n"
        );
        assert!(exact_usb_boot_evidence(&report));
        assert!(!exact_usb_boot_evidence(&format!("{line}\n{report}")));
        assert!(!exact_usb_boot_evidence(&report.replace("requester=00000030", "requester=00000028")));
        assert!(!exact_usb_boot_evidence(&report.replace("bar0=0x00000000f1000000", "bar0=0x00000000f2000000")));
        assert!(!exact_usb_boot_evidence(&report.replace(line, "")));
        assert!(!exact_usb_boot_evidence(&report.replace("wire 0:", "wire 1:")));
        assert!(!exact_usb_boot_evidence(&report.replace("0130030c", "0131030c")));
        assert!(!exact_usb_boot_evidence(&report.replace("wire 1: 0130030c000000f1", "wire 1: 0130030c000000f2")));
    }

    #[test]
    fn requires_exact_report_then_real_return_to_firmware() {
        let log = format!(
            "{START}\r\nxhci Dragonair reference: reference requester unavailable\r\nxhci-inventory: controllers=0 incomplete=0\r\n{RETURN}\r\n{MENU}\r\n"
        );
        assert!(Case::NoController.observed(&log));
        assert!(!Case::NoController.observed(&log.replace("reference requester unavailable", "matches recorded inventory; no handoff")));
        assert!(!Case::NoController.observed(&log.replace("reference requester unavailable", "reference requester unavailable\nxhci Dragonair reference: reference requester unavailable")));
        assert!(!Case::NoController.observed(&log.replace(MENU, "")));
        assert!(!Case::NoController.observed(&log.replace(RETURN, "")));
        assert!(!Case::NoController.observed(&log.replace("incomplete=0", "incomplete=1")));
        assert!(!Case::WithRemapper.observed(&log));
    }
}
