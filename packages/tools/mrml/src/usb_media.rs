//! Hosted front end for the signed MRML diagnostic media.
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead as _, IsTerminal as _, Read as _, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::usb_image::{self, BYTES};
#[cfg(any(test, all(any(windows, target_os = "linux"), target_arch = "x86_64")))]
use crate::usb_transfer::transfer;
#[cfg(all(any(windows, target_os = "linux"), target_arch = "x86_64"))]
use crate::usb_transfer::{WriteMode, require_only_usb};
use crate::{Sha3_512, Workspace, build_or_test, load_workspace, package_command, release_command};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "usb_linux.rs"]
mod host;
#[cfg(all(windows, target_arch = "x86_64"))]
#[path = "usb_windows.rs"]
mod host;

const USAGE: &str = "usage: mrml usb image OUTPUT.img | mrml usb image-vmx OUTPUT.img | mrml usb test-vmx IMAGE.img OVMF_CODE OVMF_VARS QEMU | mrml usb list [--erase|-e] | mrml usb burn IMAGE.img | mrml usb autoburn [--image IMAGE.img] [--erase|-e] | mrml usb test OVMF_CODE OVMF_VARS QEMU | mrml usb test-dma OVMF_CODE OVMF_VARS QEMU | mrml usb test-dma-acpi OVMF_CODE OVMF_VARS QEMU | mrml usb test-dma-map OVMF_CODE OVMF_VARS QEMU | mrml usb test-xhci-inventory OVMF_CODE OVMF_VARS QEMU | mrml usb test-shared-preload OVMF_CODE OVMF_VARS QEMU";

#[path = "usb_xhci_inventory.rs"]
mod xhci_inventory;

#[derive(Clone, Copy)]
enum DiagnosticImage {
    Fat32,
    Vmx,
    Dma,
    Q35Mmio,
    SharedPreload,
}

pub(super) fn command(args: &[String]) -> Result<(), String> {
    match args {
        [mode] if matches!(mode.as_str(), "help" | "--help" | "-h") => {
            println!("{USAGE}");
            Ok(())
        }
        [mode, file] if mode == "image" => {
            create(&load_workspace()?, Path::new(file), DiagnosticImage::Fat32)
        }
        [mode, file] if mode == "image-vmx" => {
            create(&load_workspace()?, Path::new(file), DiagnosticImage::Vmx)
        }
        [mode, image, code, vars, qemu] if mode == "test-vmx" => test_vmx(image, code, vars, qemu),
        [mode, code, vars, qemu] if mode == "test-dma-map" => test_dma_map(code, vars, qemu),
        [mode, code, vars, qemu] if mode == "test-shared-preload" => {
            let scratch = Scratch::new().map_err(|e| e.to_string())?;
            let image = scratch.path("shared-preload.img");
            create(&load_workspace()?, &image, DiagnosticImage::SharedPreload)?;
            let absolute = |input: &str| std::path::absolute(input).map(|path| string(&path)).map_err(|e| e.to_string());
            let executable = if Path::new(qemu).components().count() > 1 { absolute(qemu)? } else { qemu.to_owned() };
            for (case, trace, expected) in [
                (crate::qemu_boot::Q35FixtureCase::SharedPreloadUnmarked, "unmarked.trace", "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6a7a8b1eb"),
                (crate::qemu_boot::Q35FixtureCase::SharedPreloadDenied, "denied.trace", "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6a7a8b1e7eb"),
                (crate::qemu_boot::Q35FixtureCase::SharedPreload, "removed.trace", "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6a7a8b1e7eab2b3d0d1d2d3"),
                (crate::qemu_boot::Q35FixtureCase::SharedDenyBme, "bme-denied.trace", "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6a7a8b1e7eb"),
                (crate::qemu_boot::Q35FixtureCase::SharedDisableBme, "bme-cleared.trace", "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6a7a8b1e7eab2b3d0d1d2d3"),
                (crate::qemu_boot::Q35FixtureCase::SharedGuestBmeDenied, "guest-bme-denied.trace", "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6a7a8b1e7eb"),
                (crate::qemu_boot::Q35FixtureCase::SharedGuestBme, "guest-bme-cleared.trace", "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6a7a8b1e7efeab2b3d0d1d2d3"),
            ] {
                let fixture = Scratch::new().map_err(|e| e.to_string())?;
                let args = words(&[
                    &string(&image), &absolute(code)?, &absolute(vars)?, &executable,
                    &string(&fixture.path(trace)), "--expect-hex", expected,
                    "--timeout-seconds", "45", "--iommu", "intel",
                ]);
                crate::qemu_boot::run_q35_map_only_fixture(&args, case)?;
            }
            Ok(())
        }
        [mode, code, vars, qemu] if mode == "test-xhci-inventory" => {
            xhci_inventory::test(&load_workspace()?, code, vars, qemu)
        }
        [mode, code, vars, qemu]
            if matches!(mode.as_str(), "test" | "test-dma" | "test-dma-acpi") =>
        {
            let acpi_probe = mode == "test-dma-acpi";
            let dma_probe = acpi_probe || mode == "test-dma";
            let scratch = Scratch::new().map_err(|error| error.to_string())?;
            let image = scratch.path("bringup.img");
            let profile = if dma_probe {
                DiagnosticImage::Dma
            } else {
                DiagnosticImage::Fat32
            };
            create(&load_workspace()?, &image, profile)?;
            let expected_trace = if acpi_probe {
                "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6a7a8e1f1b1b2b3d4d8d5d7d0d1d2d3"
            } else if dma_probe {
                "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6a7a8b1b2b3d4d8d0d1d2d3"
            } else {
                "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6a7a8b1b2b3d0d1d2d3"
            };
            let mut options = words(&[
                &string(&image),
                code,
                vars,
                qemu,
                &string(&scratch.path("boot.trace")),
                "--expect-hex",
                expected_trace,
                "--timeout-seconds",
                "60",
            ]);
            if acpi_probe {
                options.extend(words(&["--iommu", "intel"]));
            }
            if acpi_probe {
                crate::qemu_boot::run_qemu_with_q35_evidence(&options)
            } else {
                crate::qemu_boot::run_qemu(&options)
            }
        }
        _ => device_command(args).map_err(|error| format!("mrml usb: {error}")),
    }
}

fn test_vmx(image: &str, code: &str, vars: &str, qemu: &str) -> Result<(), String> {
    let scratch = Scratch::new().map_err(|error| error.to_string())?;
    let source = Path::new(image);
    let meta = fs::metadata(source).map_err(|error| error.to_string())?;
    if !meta.is_file() || meta.len() != BYTES as u64 {
        return Err("VMX test requires an exact-size MRML USB image".into());
    }
    // The loader updates its reserved boot report. Give each run a private
    // image copy so the exact image supplied by the operator stays unchanged.
    let staged = scratch.path("vmx.img");
    let copy = || fs::copy(source, &staged).map(|_| ()).map_err(|error| error.to_string());
    let run = |accelerator, name, expected| {
        crate::qemu_boot::run_qemu(&words(&[
            &string(&staged), code, vars, qemu, &string(&scratch.path(name)),
            "--accelerator", accelerator, "--expect-hex", expected,
            "--timeout-seconds", "60",
        ]))
    };
    copy()?;
    run("tcg", "vmx-absent.trace", "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6a7a8b1b2b3d0e0e6")?;
    copy()?;
    run("kvm", "vmx-present.trace", "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6a7a8b1b2b3d0d1d2d3d4dfd6")
}

fn test_dma_map(code: &str, vars: &str, qemu: &str) -> Result<(), String> {
    use crate::qemu_boot::Q35FixtureCase;
    let scratch = Scratch::new().map_err(|error| error.to_string())?;
    let image = scratch.path("q35-map-only.img");
    create(&load_workspace()?, &image, DiagnosticImage::Q35Mmio)?;
    let absolute = |input| {
        std::path::absolute(input)
            .map(|path| string(&path))
            .map_err(|e| e.to_string())
    };
    let executable = if Path::new(qemu).components().count() > 1 {
        absolute(qemu)?
    } else {
        qemu.to_owned()
    };
    // First show that the exact same authenticated image refuses to map
    // anything when the dedicated hypervisor-supplied table is missing.
    for (case, trace, expected) in [
        (
            Q35FixtureCase::NoMarker,
            "q35-no-marker.trace",
            "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6e4ed",
        ),
        (
            Q35FixtureCase::SharedBootNoMarker,
            "q35-shared-boot-no-marker.trace",
            "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6e4ed",
        ),
        (
            Q35FixtureCase::WrongRelease,
            "q35-wrong-release.trace",
            "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6eaa7a8e1f1b1ecb2b3d4d8d5d7dcdd",
        ),
        (
            Q35FixtureCase::ValidRelease,
            "q35-map.trace",
            "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6eaa7a8e1f1b1ecb2b3d4d8d5d7dcde",
        ),
        (
            Q35FixtureCase::IsolatedWrongRelease,
            "q35-isolated-wrong-release.trace",
            "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6eaa7a8e1f1b1ecb2b3d4d8d5d7dcdd",
        ),
        (
            Q35FixtureCase::IsolatedValidRelease,
            "q35-isolated-map.trace",
            "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6eaa7a8e1f1b1ecb2b3d4d8d5d7dcde",
        ),
        (
            Q35FixtureCase::ShutdownWrongRelease,
            "q35-shutdown-wrong-release.trace",
            "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6eaa7a8e1f1b1ecb2b3d4d8d5d7dcdd",
        ),
        (
            Q35FixtureCase::ShutdownValidRelease,
            "q35-shutdown.trace",
            "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6eaa7a8e1f1b1ecb2b3d4d8d5d7dcde",
        ),
        (
            Q35FixtureCase::ColdWrongRelease,
            "q35-cold-wrong-release.trace",
            "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6eaa7a8e1f1b1ecb2b3d4d8d5d7dcdd",
        ),
        (
            Q35FixtureCase::ColdDenyActivation,
            "q35-cold-deny-activation.trace",
            "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6eaa7a8e1f1b1ecb2b3d4d8d5d7dcde",
        ),
        (
            Q35FixtureCase::ColdActivate,
            "q35-cold-activate.trace",
            "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6eaa7a8e1f1b1ecb2b3d4d8d5d7dcde",
        ),
        (
            Q35FixtureCase::BarWrongRelease,
            "q35-bar-wrong-release.trace",
            "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6eaa7a8e1f1b1ecb2b3d4d8d5d7dcdd",
        ),
        (
            Q35FixtureCase::BarValidRelease,
            "q35-bar-preflight.trace",
            "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6eaa7a8e1f1b1ecb2b3d4d8d5d7dcde",
        ),
        (
            Q35FixtureCase::RetiredPrivileged(5),
            "q35-retired-command.trace",
            "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6e5ed",
        ),
        (
            Q35FixtureCase::RetiredPrivileged(6),
            "q35-retired-storage-read.trace",
            "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6e5ed",
        ),
        (
            Q35FixtureCase::RetiredPrivileged(7),
            "q35-retired-storage-write.trace",
            "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6e5ed",
        ),
        (
            Q35FixtureCase::NoRemapper,
            "q35-no-remapper.trace",
            "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6e2ed",
        ),
    ] {
        let case_dir = Scratch::new().map_err(|error| error.to_string())?;
        let arguments = words(&[
            &string(&image),
            &absolute(code)?,
            &absolute(vars)?,
            &executable,
            &string(&case_dir.path(trace)),
            "--expect-hex",
            expected,
            "--timeout-seconds",
            "60",
            "--iommu",
            "intel",
        ]);
        crate::qemu_boot::run_q35_map_only_fixture(&arguments, case)?;
    }
    Ok(())
}

#[cfg(all(any(windows, target_os = "linux"), target_arch = "x86_64"))]
fn device_command(args: &[String]) -> io::Result<()> {
    match args {
        [mode] if mode == "list" => {
            preview(&host::disks(false)?);
            Ok(())
        }
        [mode, flag] if mode == "list" && erase_flag(flag) => {
            let disk = discover_autoburn(true)?;
            preview(std::slice::from_ref(&disk));
            Ok(())
        }
        [mode, file] if mode == "burn" => burn(Path::new(file), false),
        [mode, options @ ..] if mode == "autoburn" => {
            let (source, erase) = autoburn_options(options)?;
            autoburn(source, erase)
        }
        #[cfg(windows)]
        [mode, path, token, digest, flag] if mode == "--elevated-autoburn" => {
            elevated_autoburn(Path::new(path), token, digest, flag)
        }
        [mode, file, marker]
            if cfg!(windows) && mode == "burn" && marker == "--elevated-console" =>
        {
            let result = burn(Path::new(file), true);
            if let Err(error) = &result {
                eprintln!("mrml usb: {error}");
            }
            let _ = answer("Press Enter to close this window.");
            result
        }
        _ => Err(io::Error::other(USAGE)),
    }
}

#[cfg(all(any(windows, target_os = "linux"), target_arch = "x86_64"))]
fn erase_flag(flag: &str) -> bool {
    matches!(flag, "--erase" | "-e")
}

#[cfg(not(all(any(windows, target_os = "linux"), target_arch = "x86_64")))]
fn device_command(_args: &[String]) -> io::Result<()> {
    Err(io::Error::other(
        "USB writing is supported on x86-64 Windows and Linux; native MRML is planned",
    ))
}

type Disk = crate::usb_transfer::Disk<host_identity::Identity>;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use host as host_identity;
#[cfg(all(windows, target_arch = "x86_64"))]
use host as host_identity;
#[cfg(not(all(any(windows, target_os = "linux"), target_arch = "x86_64")))]
mod host_identity {
    pub(super) type Identity = ();
}

fn clean(label: &str) -> String {
    label
        .chars()
        .take(160)
        .map(|x| if x.is_control() { '?' } else { x })
        .collect()
}

fn preview(disks: &[Disk]) {
    if disks.is_empty() {
        println!("No eligible removable USB drive.");
    }
    for (index, disk) in disks.iter().enumerate() {
        println!(
            "{}. {}  {}  {:.2} GiB",
            index + 1,
            clean(&disk.path.to_string_lossy()),
            clean(&disk.label),
            disk.capacity as f64 / (1u64 << 30) as f64
        );
    }
}

fn answer(prompt: &str) -> io::Result<String> {
    print!("{prompt} ");
    io::stdout().flush()?;
    let mut response = String::new();
    if io::stdin().lock().take(258).read_line(&mut response)? == 0 || response.len() > 256 {
        return Err(io::Error::other("canceled; no bytes written"));
    }
    Ok(response.trim_end_matches(['\r', '\n']).into())
}

fn authorized_index(disks: &[Disk], ask: impl Fn(&str) -> io::Result<String>) -> io::Result<usize> {
    let paths: Vec<_> = disks.iter().map(|disk| disk.path.clone()).collect();
    authorize(&paths, ask)
}

fn authorize(paths: &[PathBuf], ask: impl Fn(&str) -> io::Result<String>) -> io::Result<usize> {
    let index = match paths.len() {
        0 => return Err(io::Error::other("no eligible removable USB drive")),
        1 => 1,
        count => ask("USB drive number (Enter to cancel):")?
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=count).contains(n))
            .ok_or_else(|| io::Error::other("invalid selection; no bytes written"))?,
    };
    let target = clean(&paths[index - 1].to_string_lossy());
    if ask(&format!(
        "All data on {target} will be lost. Type ERASE {index}:"
    ))? != format!("ERASE {index}")
    {
        return Err(io::Error::other("canceled; no bytes written"));
    }
    Ok(index - 1)
}

fn sha3(bytes: &[u8]) -> String {
    Sha3_512::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(all(any(windows, target_os = "linux"), target_arch = "x86_64"))]
fn burn(path: &Path, child: bool) -> io::Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(io::Error::other("burning requires an interactive terminal"));
    }
    let path = path.canonicalize()?;
    let image = usb_image::read_regular(&path, BYTES)?;
    usb_image::check_image(&image)?;
    if !host::privileged() {
        if child {
            return Err(io::Error::other("the new console is not elevated"));
        }
        return host::elevate(&path);
    }
    let digest = sha3(&image);
    println!("Image SHA3-512: {digest}");
    let available = host::disks(false)?;
    preview(&available);
    let disk = &available[authorized_index(&available, answer)?];
    if !host::disks(false)?.contains(disk) {
        return Err(io::Error::other(
            "target identity changed; no bytes written",
        ));
    }
    write_verified(disk, &image, WriteMode::Manual)
}

#[cfg(all(any(windows, target_os = "linux"), target_arch = "x86_64"))]
fn discover_autoburn(erase: bool) -> io::Result<Disk> {
    let connected = host::usb_storage()?;
    select_single(&connected, || host::disks(erase))
}

#[cfg(all(any(windows, target_os = "linux"), target_arch = "x86_64"))]
fn autoburn_options(args: &[String]) -> io::Result<(Option<&Path>, bool)> {
    let mut source = None;
    let mut erase = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if erase_flag(arg) && !erase {
            erase = true;
        } else if arg == "--image" && source.is_none() {
            let path = args
                .next()
                .filter(|path| !path.is_empty() && !path.starts_with('-'))
                .ok_or_else(|| io::Error::other(USAGE))?;
            source = Some(Path::new(path));
        } else {
            return Err(io::Error::other(USAGE));
        }
    }
    Ok((source, erase))
}

#[cfg(all(any(windows, target_os = "linux"), target_arch = "x86_64"))]
fn autoburn_image(source: Option<&Path>) -> io::Result<Vec<u8>> {
    let image = if let Some(path) = source {
        usb_image::read_regular(path, BYTES)?
    } else {
        let workspace = load_workspace().map_err(io::Error::other)?;
        build_image(&workspace, DiagnosticImage::Fat32).map_err(io::Error::other)?
    };
    usb_image::check_image(&image)?;
    Ok(image)
}

#[cfg(all(any(windows, target_os = "linux"), target_arch = "x86_64"))]
fn autoburn(source: Option<&Path>, erase: bool) -> io::Result<()> {
    #[cfg(windows)]
    if !host::privileged() {
        return request_autoburn(source, erase);
    }
    #[cfg(windows)]
    host::check_write_policy()?;
    #[cfg(target_os = "linux")]
    let elevated_writer = if host::privileged() {
        None
    } else {
        Some(crate::usb_polkit::Writer::locate()?)
    };
    run_autoburn(
        || discover_autoburn(erase),
        || {
            let image = autoburn_image(source)?;
            println!("Image SHA3-512: {}", sha3(&image));
            Ok(image)
        },
        |disk, image| {
            #[cfg(target_os = "linux")]
            if let Some(writer) = elevated_writer {
                return writer.write(host::fingerprint(disk), image);
            }
            write_verified(disk, image, WriteMode::Auto { erase })
        },
    )
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn request_autoburn(source: Option<&Path>, erase: bool) -> io::Result<()> {
    let (token, label) = host::autoburn_token()?;
    println!(
        "Autoburn will erase {} after Windows authorization.",
        clean(&label)
    );
    let scratch = Scratch::new()?;
    let file = scratch.path("autoburn.img");
    let image = autoburn_image(source)?;
    publish(&file, &image)?;
    if host::autoburn_token()?.0 != token {
        return Err(io::Error::other("USB identity changed; no bytes written"));
    }
    let digest = sha3(&image);
    println!("Image SHA3-512: {digest}");
    let status = host::elevate_autoburn(&file, &token, &digest, erase)?;
    let receipt = usb_image::read_regular(&file.with_extension("result"), 4096).map_err(|_| {
        io::Error::other(format!(
            "Windows writer exited with status {status} without a receipt"
        ))
    })?;
    let receipt = String::from_utf8(receipt).map_err(io::Error::other)?;
    if status == 0 && receipt == "verified" {
        println!(
            "Verified {BYTES} bytes on {}. Safely eject the drive.",
            clean(&label)
        );
        Ok(())
    } else {
        Err(io::Error::other(receipt))
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn elevated_autoburn(path: &Path, token: &str, digest: &str, flag: &str) -> io::Result<()> {
    if !host::privileged() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows writer is not elevated",
        ));
    }
    let sha = |s: &str| s.len() == 128 && s.bytes().all(|b| b.is_ascii_hexdigit());
    if !path.is_absolute()
        || path.file_name().and_then(|s| s.to_str()) != Some("autoburn.img")
        || !path
            .parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with("mrml-usb-"))
        || !sha(token)
        || !sha(digest)
        || !matches!(flag, "0" | "1")
    {
        return Err(io::Error::other("invalid elevated USB request"));
    }
    let erase = flag == "1";
    // Claim a fresh outcome file before any disk I/O; do not overwrite caller files.
    let mut receipt = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.with_extension("result"))?;
    let result = (|| {
        host::check_write_policy()?;
        let disk = discover_autoburn(erase)?;
        if !host::matches_autoburn_token(&disk, token) {
            return Err(io::Error::other("USB identity changed; no bytes written"));
        }
        let image = usb_image::read_regular(path, BYTES)?;
        usb_image::check_image(&image)?;
        if sha3(&image) != digest {
            return Err(io::Error::other(
                "USB image changed before elevation; no bytes written",
            ));
        }
        host::write_image(&disk, &image, WriteMode::Auto { erase })
    })();
    match &result {
        Ok(()) => receipt.write_all(b"verified")?,
        Err(error) => receipt.write_all(error.to_string().as_bytes())?,
    }
    receipt.sync_all()?;
    result
}

#[cfg(all(any(windows, target_os = "linux"), target_arch = "x86_64"))]
fn select_single(
    connected: &[PathBuf],
    eligible: impl FnOnce() -> io::Result<Vec<Disk>>,
) -> io::Result<Disk> {
    match connected {
        [] => Err(io::Error::other(
            "no USB storage drive connected; no bytes written",
        )),
        [path] => eligible()?
            .into_iter()
            .find(|disk| disk.path == *path)
            .ok_or_else(|| {
                io::Error::other("the only USB storage drive is not eligible; no bytes written")
            }),
        _ => Err(io::Error::other(
            "more than one USB storage drive connected; no bytes written",
        )),
    }
}

#[cfg(all(any(windows, target_os = "linux"), target_arch = "x86_64"))]
fn run_autoburn(
    discover: impl Fn() -> io::Result<Disk>,
    build: impl FnOnce() -> io::Result<Vec<u8>>,
    write: impl FnOnce(&Disk, &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let disk = discover()?;
    println!("Autoburn will erase this USB drive:");
    preview(std::slice::from_ref(&disk));
    let image = build()?;
    if discover()? != disk {
        return Err(io::Error::other(
            "target identity changed; no bytes written",
        ));
    }
    write(&disk, &image)
}

#[cfg(all(any(windows, target_os = "linux"), target_arch = "x86_64"))]
fn write_verified(disk: &Disk, image: &[u8], mode: WriteMode) -> io::Result<()> {
    host::write_image(disk, image, mode)?;
    println!(
        "Verified {} bytes on {}. Safely eject the drive.",
        image.len(),
        disk.path.display()
    );
    Ok(())
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> io::Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir()
            .canonicalize()?
            .join(format!("mrml-usb-{}-{now:x}", std::process::id()));
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt as _;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
        };
        #[cfg(not(unix))]
        let builder = fs::DirBuilder::new();
        builder.create(&path)?;
        Ok(Self(path))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // This exact, non-shared scratch directory was created by this invocation.
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn create(workspace: &Workspace, output: &Path, profile: DiagnosticImage) -> Result<(), String> {
    if !(cfg!(target_os = "linux") || cfg!(windows)) {
        return Err(
            "Image assembly currently requires the Windows or Linux MRML build toolchain".into(),
        );
    }
    if output.extension().and_then(|ext| ext.to_str()) != Some("img")
        || fs::symlink_metadata(output).is_ok()
    {
        return Err("Choose a new .img filename; images are never overwritten".into());
    }
    let bytes = build_image(workspace, profile)?;
    publish(output, &bytes).map_err(|e| format!("USB image output error: {e}"))?;
    println!(
        "usb-image|bytes={}|sha3-512={}|output={}",
        bytes.len(),
        sha3(&bytes),
        output.display()
    );
    Ok(())
}

fn build_image(workspace: &Workspace, profile: DiagnosticImage) -> Result<Vec<u8>, String> {
    let usb = Scratch::new().map_err(|e| e.to_string())?;
    let target = if cfg!(windows) { "windows" } else { "linux" };
    let native = workspace.root.join("target/mrml-native");
    let sign = native.join(target).join("release").join(if cfg!(windows) {
        "mrml-sign.exe"
    } else {
        "mrml-sign"
    });
    let loader = native.join("uefi/release/mrml-loader.efi");
    let kernel = native.join("uefi/release/mrml-kernel-pe.efi");
    let service = native.join("mrml_native-x86_64-unknown-uefi/release/mrml-fat32-service.efi");
    let build = |id: &str, target: &str, extra: Vec<String>| {
        let mut args = words(&["build", id, "--target", target, "--release"]);
        args.extend(extra);
        build_or_test(workspace, &args)
    };
    build("org.mrml.tool.sign", target, vec![])?;
    build("org.mrml.library.storage.fat32", "native", vec![])?;
    let key = |role: &str, kind: &str| string(&usb.path(&format!("{role}.{kind}")));
    for role in [
        "kernel",
        "service",
        "kernel-package",
        "loader-package",
        "config-package",
        "release",
    ] {
        signer(
            &sign,
            words(&["keygen", &key(role, "private"), &key(role, "public")]),
            false,
        )?;
    }
    let digest = |role| -> Result<String, String> {
        let text = signer(&sign, words(&["key-digest", &key(role, "public")]), true)?;
        let text = text.trim();
        if text.len() != 128 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Invalid diagnostic key digest".into());
        }
        Ok(text.to_owned())
    };
    let kr = digest("kernel")?;
    let sr = digest("service")?;
    let pr = digest("kernel-package")?;
    let rr = digest("release")?;
    build(
        "org.mrml.system.bootloader",
        "uefi-x86_64",
        words(&[
            "--feature-profile",
            match profile {
                DiagnosticImage::Q35Mmio => "uefi_q35_mmio_probe",
                DiagnosticImage::Vmx => "vmx_root_probe",
                _ => "uefi_fat32_restart_probe",
            },
            "--compile-env",
            &format!("MRML_SERVICE_ROOT_DIGEST_HEX={sr}"),
            "--compile-env",
            "MRML_SERVICE_MIN_VERSION=1",
        ]),
    )?;
    build(
        "org.mrml.library.uefi",
        "uefi-x86_64",
        words(&[
            "--feature-profile",
            match profile {
                DiagnosticImage::Fat32 | DiagnosticImage::Vmx => "fat32_restart_boot",
                DiagnosticImage::SharedPreload => "usb_preload_probe",
                DiagnosticImage::Dma => "boot_dma_probe",
                DiagnosticImage::Q35Mmio => "q35_mmio_probe",
            },
            "--compile-env",
            &format!("MRML_KERNEL_ROOT_DIGEST_HEX={kr}"),
            "--compile-env",
            "MRML_KERNEL_MIN_VERSION=1",
            "--compile-env",
            &format!("MRML_SERVICE_ROOT_DIGEST_HEX={sr}"),
            "--compile-env",
            "MRML_SERVICE_MIN_VERSION=1",
            "--compile-env",
            &format!("MRML_KERNEL_PACKAGE_ROOT_DIGEST_HEX={pr}"),
            "--compile-env",
            &format!("MRML_SYSTEM_RELEASE_ROOT_DIGEST_HEX={rr}"),
        ]),
    )?;
    let kernel_signed = usb.path("kernel.signed");
    let service_signed = usb.path("service.signed");
    for (role, input, output) in [
        ("kernel", &kernel, &kernel_signed),
        ("service", &service, &service_signed),
    ] {
        signer(
            &sign,
            words(&[
                "sign-bundle",
                role,
                "1",
                &string(input),
                &key(role, "private"),
                &string(output),
            ]),
            false,
        )?;
    }
    let config = usb.path("configuration.bin");
    fs::write(&config, b"MRML disposable UEFI USB diagnostic\n").map_err(|e| e.to_string())?;
    let loader_package = usb.path("loader.mrp");
    let kernel_package = usb.path("kernel.mrp");
    let config_package = usb.path("config.mrp");
    for (id, class, purpose, source, destination, private) in [
        (
            "org.mrml.library.uefi",
            "bootloader",
            "uefi-loader",
            &loader,
            &loader_package,
            "loader-package",
        ),
        (
            "org.mrml.system.kernel",
            "kernel",
            "kernel",
            &kernel_signed,
            &kernel_package,
            "kernel-package",
        ),
        (
            "org.mrml.service.config",
            "configuration",
            "configuration",
            &config,
            &config_package,
            "config-package",
        ),
    ] {
        package_command(
            workspace,
            &words(&[
                "create",
                id,
                class,
                "1",
                "x86_64",
                purpose,
                &string(source),
                &string(destination),
                "--private-key",
                &key(private, "private"),
            ]),
        )?;
    }
    let release = usb.path("system.mrs");
    release_command(
        workspace,
        &words(&[
            "create",
            "1",
            &string(&loader_package),
            &string(&kernel_package),
            &string(&config_package),
            &key("release", "private"),
            &string(&release),
        ]),
    )?;
    release_command(
        workspace,
        &words(&["verify", &string(&release), &key("release", "public")]),
    )?;
    usb_image::compose([
        &loader,
        &loader_package,
        &kernel_package,
        &config_package,
        &release,
        &service_signed,
    ])
    .map_err(|e| e.to_string())
}

fn publish(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn words(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

fn signer(executable: &Path, args: Vec<String>, capture: bool) -> Result<String, String> {
    let mut child = Command::new(executable);
    child.args(args);
    if capture {
        let result = child.output().map_err(|e| format!("MRML signer: {e}"))?;
        if result.status.success() {
            return String::from_utf8(result.stdout).map_err(|e| e.to_string());
        }
    } else if child
        .status()
        .map_err(|e| format!("MRML signer: {e}"))?
        .success()
    {
        return Ok(String::new());
    }
    Err("MRML signer failed; no boot image was published".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::Cursor;

    #[test]
    fn verified_transfer_detects_corruption() {
        let mut media = Cursor::new(vec![0; 8]);
        transfer(&mut media, b"abcdefgh", |_| Ok(())).unwrap();
        media.set_position(0);
        assert!(
            transfer(&mut media, b"abcdefgh", |file| {
                file.get_mut()[3] ^= 1;
                Ok(())
            })
            .is_err()
        );
    }

    #[test]
    fn publishing_never_overwrites() {
        let temp = Scratch::new().unwrap();
        let path = temp.path("test.img");
        publish(&path, b"original").unwrap();
        assert!(publish(&path, b"replacement").is_err());
        assert_eq!(fs::read(path).unwrap(), b"original");
    }

    #[test]
    fn asks_for_choice_only_when_ambiguous_and_requires_exact_erase() {
        let confirm = |count, entries: &[&str]| {
            let replies = RefCell::new(entries.iter());
            select_test(count, |_| {
                replies
                    .borrow_mut()
                    .next()
                    .map(|s| (*s).into())
                    .ok_or_else(|| io::Error::other("no input"))
            })
        };
        assert_eq!(confirm(1, &["ERASE 1"]).unwrap(), 0);
        assert_eq!(confirm(2, &["2", "ERASE 2"]).unwrap(), 1);
        for (count, entries) in [
            (0, &[][..]),
            (2, &["3"][..]),
            (2, &["2", "ERASE 1"][..]),
            (1, &["yes"][..]),
        ] {
            assert!(confirm(count, entries).is_err());
        }
    }

    fn select_test(count: usize, ask: impl Fn(&str) -> io::Result<String>) -> io::Result<usize> {
        let choices: Vec<PathBuf> = (1..=count)
            .map(|i| PathBuf::from(format!("USB {i}")))
            .collect();
        authorize(&choices, ask)
    }

    #[cfg(all(any(windows, target_os = "linux"), target_arch = "x86_64"))]
    mod unattended {
        use super::*;
        use std::cell::Cell;

        #[test]
        fn explicit_erase_accepts_only_documented_flags() {
            for option in ["--erase", "-e"] {
                assert!(erase_flag(option));
            }
            for option in ["erase", "e", "--force", "--erase=yes"] {
                assert!(!erase_flag(option));
            }
        }

        #[test]
        fn explicit_image_and_erase_are_independent_and_unambiguous() {
            for (args, expected) in [
                (&[][..], (None, false)),
                (&["-e"][..], (None, true)),
                (
                    &["--image", "test image.img"][..],
                    (Some(Path::new("test image.img")), false),
                ),
                (
                    &["--erase", "--image", "test.img"][..],
                    (Some(Path::new("test.img")), true),
                ),
                (
                    &["--image", "test.img", "-e"][..],
                    (Some(Path::new("test.img")), true),
                ),
            ] {
                assert_eq!(autoburn_options(&words(args)).unwrap(), expected);
            }
            for args in [
                &["--image"][..],
                &["--image", "--erase"][..],
                &["--image", "a.img", "--image", "b.img"][..],
                &["-e", "--erase"][..],
                &["a.img"][..],
            ] {
                assert!(autoburn_options(&words(args)).is_err());
            }
            let scratch = Scratch::new().unwrap();
            assert!(autoburn_image(Some(&scratch.path("missing.img"))).is_err());
        }

        fn disk(path: &str) -> Disk {
            Disk {
                path: path.into(),
                label: "test device".into(),
                capacity: BYTES as u64,
                identity: host::test_identity(),
            }
        }

        #[test]
        fn counts_ineligible_connected_drives_and_requires_the_exact_path() {
            let target = disk("target");
            for connected in [vec![], vec![target.path.clone(), "ineligible".into()]] {
                assert!(select_single(&connected, || panic!("must not select")).is_err());
            }
            assert!(select_single(std::slice::from_ref(&target.path), || Ok(vec![])).is_err());
            assert!(select_single(&["other".into()], || Ok(vec![target.clone()])).is_err());
            assert_eq!(
                select_single(std::slice::from_ref(&target.path), || Ok(vec![
                    target.clone()
                ]))
                .unwrap(),
                target
            );
        }

        #[test]
        fn builds_once_and_verifies_the_pinned_target_without_prompting() {
            let target = disk("target");
            let sightings = Cell::new(0);
            run_autoburn(
                || {
                    sightings.set(sightings.get() + 1);
                    Ok(target.clone())
                },
                || {
                    assert_eq!(sightings.get(), 1);
                    Ok(b"diagnostic".to_vec())
                },
                |selected, image| {
                    assert_eq!(sightings.get(), 2);
                    assert_eq!(selected, &target);
                    require_only_usb(selected, || Ok(vec![target.path.clone()]))?;
                    let mut file = Cursor::new(Vec::new());
                    transfer(&mut file, image, |_| Ok(()))?;
                    assert_eq!(file.into_inner(), b"diagnostic");
                    Ok(())
                },
            )
            .unwrap();
        }

        #[test]
        fn refuses_target_swaps_inventory_changes_and_build_failure() {
            let target = disk("target");
            let mut replacement = target.clone();
            replacement.capacity += 512;
            let before = Cell::new(true);
            let never_write = |_: &Disk, _: &[u8]| panic!("must not write");
            assert!(
                run_autoburn(
                    || Ok(if before.replace(false) {
                        target.clone()
                    } else {
                        replacement.clone()
                    }),
                    || Ok(vec![1]),
                    never_write,
                )
                .is_err()
            );
            assert!(
                run_autoburn(
                    || Ok(target.clone()),
                    || Err(io::Error::other("build failed")),
                    never_write,
                )
                .is_err()
            );
            for changed in [
                vec![],
                vec!["replacement".into()],
                vec![target.path.clone(), "additional drive".into()],
            ] {
                assert!(require_only_usb(&target, || Ok(changed)).is_err());
            }
            assert!(
                require_only_usb(&target, || Err(io::Error::other("inventory unavailable")))
                    .is_err()
            );
        }
    }
}
