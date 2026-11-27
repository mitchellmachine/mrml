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
const START: &str = "MRML xhci-inventory: read-only";

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
        if matches!(self, Self::NoController) {
            return reported("xhci-inventory: controllers=0 incomplete=0")
                && !report.lines().any(|line| line.starts_with("xhci 0000:"));
        }
        if matches!(self, Self::UsbBoot) {
            return reported("xhci-inventory: controllers=2 incomplete=0")
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
        reported("xhci 0000:00:05.0 pci=1b36:000d rev=01 cmd=0007")
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
        if matches!(case, Case::WithRemapper) {
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
    fn requires_exact_report_then_real_return_to_firmware() {
        let log = format!(
            "{START}\r\nxhci-inventory: controllers=0 incomplete=0\r\n{RETURN}\r\n{MENU}\r\n"
        );
        assert!(Case::NoController.observed(&log));
        assert!(!Case::NoController.observed(&log.replace(MENU, "")));
        assert!(!Case::NoController.observed(&log.replace(RETURN, "")));
        assert!(!Case::NoController.observed(&log.replace("incomplete=0", "incomplete=1")));
        assert!(!Case::WithRemapper.observed(&log));
    }
}
