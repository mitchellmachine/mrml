//! Hosted front end for the signed MRML diagnostic media.
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead as _, IsTerminal as _, Read, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::usb_image::{self, BYTES};
use crate::{Sha3_512, Workspace, build_or_test, load_workspace, package_command, release_command};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "usb_linux.rs"]
mod host;
#[cfg(all(windows, target_arch = "x86_64"))]
#[path = "usb_windows.rs"]
mod host;

const USAGE: &str = "usage: mrml usb image OUTPUT.img | mrml usb list | mrml usb burn IMAGE.img | mrml usb test OVMF_CODE OVMF_VARS QEMU";

pub(super) fn command(args: &[String]) -> Result<(), String> {
    match args {
        [mode] if matches!(mode.as_str(), "help" | "--help" | "-h") => {
            println!("{USAGE}");
            Ok(())
        }
        [mode, file] if mode == "image" => create(&load_workspace()?, Path::new(file)),
        [mode, code, vars, qemu] if mode == "test" => {
            let scratch = Scratch::new().map_err(|error| error.to_string())?;
            let image = scratch.path("bringup.img");
            create(&load_workspace()?, &image)?;
            crate::qemu_boot::run_qemu(&words(&[
                &string(&image),
                code,
                vars,
                qemu,
                &string(&scratch.path("boot.trace")),
                "--expect-hex",
                "c8b0b2b0b2c9b0b2b2a1a2a3a4a5a6a7a8b1b2b3d0d1d2d3",
                "--timeout-seconds",
                "60",
            ]))
        }
        _ => device_command(args).map_err(|error| format!("mrml usb: {error}")),
    }
}

#[cfg(all(any(windows, target_os = "linux"), target_arch = "x86_64"))]
fn device_command(args: &[String]) -> io::Result<()> {
    match args {
        [mode] if mode == "list" => {
            preview(&host::disks()?);
            Ok(())
        }
        [mode, file] if mode == "burn" => burn(Path::new(file), false),
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

#[cfg(not(all(any(windows, target_os = "linux"), target_arch = "x86_64")))]
fn device_command(_args: &[String]) -> io::Result<()> {
    Err(io::Error::other(
        "USB writing is supported on x86-64 Windows and Linux; native MRML is planned",
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Disk {
    path: PathBuf,
    label: String,
    capacity: u64,
    identity: host_identity::Identity,
}

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
    let available = host::disks()?;
    preview(&available);
    let disk = &available[authorized_index(&available, answer)?];
    if !host::disks()?.contains(disk) {
        return Err(io::Error::other(
            "target identity changed; no bytes written",
        ));
    }
    host::write_image(disk, &image)?;
    println!(
        "Verified {} bytes on {}. Safely eject the drive.",
        image.len(),
        disk.path.display()
    );
    Ok(())
}

fn transfer<T: Read + Write + std::io::Seek>(
    disk: &mut T,
    image: &[u8],
    flush_media: impl FnOnce(&mut T) -> io::Result<()>,
) -> io::Result<()> {
    const CHUNK: usize = 1024 * 1024;
    for block in image.chunks(CHUNK) {
        disk.write_all(block)?;
    }
    flush_media(disk)?;
    disk.seek(SeekFrom::Start(0))?;
    let mut readback = vec![0; CHUNK];
    for (index, block) in image.chunks(CHUNK).enumerate() {
        disk.read_exact(&mut readback[..block.len()])?;
        if readback[..block.len()] != *block {
            return Err(io::Error::other(format!(
                "USB verification failed at byte {}",
                index * CHUNK
            )));
        }
    }
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

fn create(workspace: &Workspace, output: &Path) -> Result<(), String> {
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
            "uefi_fat32_restart_probe",
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
            "fat32_restart_boot",
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
    let bytes = usb_image::compose([
        &loader,
        &loader_package,
        &kernel_package,
        &config_package,
        &release,
        &service_signed,
    ])
    .map_err(|e| e.to_string())?;
    publish(output, &bytes).map_err(|e| format!("USB image output error: {e}"))?;
    println!(
        "usb-image|bytes={}|sha3-512={}|output={}",
        bytes.len(),
        sha3(&bytes),
        output.display()
    );
    Ok(())
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
}
