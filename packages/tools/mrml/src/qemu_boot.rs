use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const IMAGE_BYTES: u64 = 80 * 1024 * 1024;
const ESP_OFFSET_BYTES: u64 = 1024 * 1024;
const SUCCESS_TRACE: [u8; 20] = [
    0xc8, 0xb0, 0xb2, 0xb0, 0xb2, 0xc9, 0xb0, 0xb2, 0xb2, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xb1, 0xb2, 0xb3,
];

pub fn create_media(args: &[String]) -> Result<(), String> {
    if args.len() != 11 {
        return Err("PackageBootMediaUsage { expected: LOADER BOOTLOADER_PACKAGE KERNEL_PACKAGE CONFIGURATION_PACKAGE SYSTEM_RELEASE SERVICE_SIGNED OUTPUT SFDISK MFORMAT MMD MCOPY }".into());
    }
    for input in &args[..6] {
        let metadata = fs::metadata(input).map_err(|error| {
            format!("PackageBootInputReadError {{ path: {input}, detail: {error} }}")
        })?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 64 * 1024 * 1024 {
            return Err(format!(
                "PackageBootInputSize {{ path: {input}, bytes: {} }}",
                metadata.len()
            ));
        }
    }
    let output = Path::new(&args[6]);
    let image = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|error| format!("PackageBootMediaCreateError {{ detail: {error} }}"))?;
    image
        .set_len(IMAGE_BYTES)
        .map_err(|error| format!("PackageBootMediaSizeError {{ detail: {error} }}"))?;
    drop(image);

    let result: Result<(), String> = (|| {
        run_with_input(
            &args[7],
            &[output.as_os_str()],
            b"label: gpt\nlabel-id: 4d524d4c-0000-4000-8000-000000000001\nsize=64M,type=U,uuid=4d524d4c-0000-4000-8000-000000000002\n",
            "sfdisk",
        )?;
        let image_spec = format!("{}@@{ESP_OFFSET_BYTES}", output.display());
        run(
            &args[8],
            &["-i", &image_spec, "-F", "-v", "MRMLBOOT", "::"],
            "mformat",
        )?;
        for directory in ["::/EFI", "::/EFI/BOOT", "::/EFI/MRML"] {
            run(&args[9], &["-i", &image_spec, directory], "mmd")?;
        }
        for (source, destination) in [
            (&args[0], "::/EFI/BOOT/BOOTX64.EFI"),
            (&args[1], "::/EFI/MRML/BOOTLOADER.PACKAGE"),
            (&args[2], "::/EFI/MRML/KERNEL.PACKAGE"),
            (&args[3], "::/EFI/MRML/CONFIGURATION.PACKAGE"),
            (&args[4], "::/EFI/MRML/SYSTEM.RELEASE"),
            (&args[5], "::/EFI/MRML/SERVICE.SIGNED"),
        ] {
            run(
                &args[10],
                &["-i", &image_spec, source, destination],
                "mcopy",
            )?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(output);
    }
    result?;
    println!(
        "package-boot-media|operation=create|status=PASS|format=gpt-fat32|esp_offset={ESP_OFFSET_BYTES}|bytes={IMAGE_BYTES}|packages=3|release=1|early_artifacts=1"
    );
    Ok(())
}

pub fn run_qemu(args: &[String]) -> Result<(), String> {
    run_qemu_config(args, false)
}

pub(super) fn run_qemu_with_q35_evidence(args: &[String]) -> Result<(), String> {
    run_qemu_config(args, true)
}

fn run_qemu_config(args: &[String], verify_q35: bool) -> Result<(), String> {
    if args.len() < 5 {
        return Err("PackageQemuBootUsage { expected: IMAGE OVMF_CODE OVMF_VARS QEMU TRACE [--accelerator tcg|whpx|kvm] [--iommu intel] [--timeout-seconds N] [--expect-hex HEX | --expect-rejection-hex HEX] }".into());
    }
    for input in &args[..3] {
        if !Path::new(input).is_file() {
            return Err(format!("PackageQemuBootInputMissing {{ path: {input} }}"));
        }
    }
    validate_options(&args[5..])?;
    let trace = Path::new(&args[4]);
    if trace.exists() {
        return Err(format!(
            "PackageQemuTraceExists {{ path: {} }}",
            trace.display()
        ));
    }
    let timeout = option(args, "--timeout-seconds")?
        .unwrap_or("30")
        .parse::<u64>()
        .ok()
        .filter(|seconds| (1..=300).contains(seconds))
        .ok_or_else(|| "PackageQemuTimeoutInvalid".to_owned())?;
    let accelerator = option(args, "--accelerator")?.unwrap_or("tcg");
    if !matches!(accelerator, "tcg" | "whpx" | "kvm") {
        return Err("PackageQemuAcceleratorInvalid".into());
    }
    let intel_iommu = match option(args, "--iommu")? {
        None => false,
        Some("intel") => true,
        Some(_) => return Err("PackageQemuIommuInvalid".into()),
    };
    if verify_q35 && (!intel_iommu || accelerator != "tcg") {
        return Err("QEMU resource evidence requires q35/TCG with Intel IOMMU".into());
    }
    let expected = option(args, "--expect-hex")?
        .map(parse_hex)
        .transpose()?
        .unwrap_or_else(|| SUCCESS_TRACE.to_vec());
    let rejection = option(args, "--expect-rejection-hex")?
        .map(parse_hex)
        .transpose()?;
    if rejection.is_some() && option(args, "--expect-hex")?.is_some() {
        return Err("PackageQemuExpectationConflict".into());
    }
    if rejection
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.len() > 128)
    {
        return Err("PackageQemuRejectionTraceSize".into());
    }
    if expected.is_empty() || expected.len() > 256 {
        return Err("PackageQemuExpectedTraceSize".into());
    }

    let vars = trace.with_extension("vars.fd");
    if vars.exists() {
        return Err(format!(
            "PackageQemuVarsExists {{ path: {} }}",
            vars.display()
        ));
    }
    fs::copy(&args[2], &vars)
        .map_err(|error| format!("PackageQemuVarsCopyError {{ detail: {error} }}"))?;
    let result = run_qemu_child(QemuChildOptions {
        qemu: &args[3],
        image: &args[0],
        code: &args[1],
        vars: &vars,
        trace,
        expected: &expected,
        rejection: rejection.as_deref(),
        timeout,
        accelerator,
        intel_iommu,
        verify_q35,
    });
    let _ = fs::remove_file(vars);
    result
}

struct QemuChildOptions<'a> {
    qemu: &'a str,
    image: &'a str,
    code: &'a str,
    vars: &'a Path,
    trace: &'a Path,
    expected: &'a [u8],
    rejection: Option<&'a [u8]>,
    timeout: u64,
    accelerator: &'a str,
    intel_iommu: bool,
    verify_q35: bool,
}

fn run_qemu_child(options: QemuChildOptions<'_>) -> Result<(), String> {
    let QemuChildOptions {
        qemu,
        image,
        code,
        vars,
        trace,
        expected,
        rejection,
        timeout,
        accelerator,
        intel_iommu,
        verify_q35,
    } = options;
    let machine = format!("q35,accel={accelerator}");
    let mut command = Command::new(qemu);
    if intel_iommu {
        command.args(["-device", "intel-iommu,aw-bits=48,intremap=off"]);
    }
    if verify_q35 {
        command.args(["-no-user-config", "-qmp", "stdio"]);
    }
    let mut child = command
        .args(["-machine", &machine, "-m", "512M", "-display", "none"])
        .args(["-serial", "none", "-monitor", "none", "-no-reboot"])
        .arg("-drive")
        .arg(format!("if=pflash,format=raw,readonly=on,file={code}"))
        .arg("-drive")
        .arg(format!("if=pflash,format=raw,file={}", vars.display()))
        .arg("-drive")
        .arg(format!("if=none,id=esp,format=raw,file={image}"))
        .args(["-device", "qemu-xhci"])
        .args(["-device", "usb-storage,drive=esp,removable=on,bootindex=1"])
        .args(["-device", "virtio-rng-pci"])
        .arg("-debugcon")
        .arg(format!("file:{}", trace.display()))
        .args(["-global", "isa-debugcon.iobase=0xe9"])
        .stdin(if verify_q35 {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(if verify_q35 {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("PackageQemuLaunchError {{ detail: {error} }}"))?;
    let start = Instant::now();
    loop {
        if let Ok(bytes) = fs::read(trace) {
            if rejection.is_some_and(|prefix| rejected_twice(&bytes, prefix)) {
                child
                    .kill()
                    .map_err(|error| format!("PackageQemuStopError {{ detail: {error} }}"))?;
                let _ = child.wait();
                println!(
                    "package-qemu-boot|status=QEMU_UEFI_BOOT_REJECT_PASS|accelerator={accelerator}|stage={}|trace={}|bytes={}",
                    boot_stage(&bytes),
                    encode_hex(&bytes),
                    bytes.len()
                );
                return Ok(());
            }
            if rejection.is_none() && bytes == expected {
                let evidence =
                    verify_q35.then(|| crate::qemu_mmio::verify_paused_q35_resources(&mut child));
                child
                    .kill()
                    .map_err(|error| format!("PackageQemuStopError {{ detail: {error} }}"))?;
                let _ = child.wait();
                if let Some(evidence) = evidence {
                    evidence?;
                    println!(
                        "qemu-mmio-model|status=PASS|ecam=0xe0000000..=0xefffffff|drhd=0xfed90000..=0xfed9022f|padding=unmapped"
                    );
                }
                println!(
                    "package-qemu-boot|status=QEMU_UEFI_BOOT_PASS|accelerator={accelerator}|stage={}|trace={}|bytes={}",
                    boot_stage(&bytes),
                    encode_hex(&bytes),
                    bytes.len()
                );
                return Ok(());
            }
            if rejection.is_none() && bytes.len() >= expected.len() {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "PackageQemuTraceMismatch {{ stage: {}, expected: {}, actual: {} }}",
                    boot_stage(&bytes),
                    encode_hex(expected),
                    encode_hex(&bytes)
                ));
            }
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("PackageQemuWaitError {{ detail: {error} }}"))?
        {
            let actual = fs::read(trace).unwrap_or_default();
            return Err(format!(
                "PackageQemuExited {{ stage: {}, status: {status} }}",
                boot_stage(&actual)
            ));
        }
        if start.elapsed() >= Duration::from_secs(timeout) {
            let _ = child.kill();
            let _ = child.wait();
            let actual = fs::read(trace).unwrap_or_default();
            return Err(format!(
                "PackageQemuTimeout {{ stage: {}, expected: {}, actual: {} }}",
                boot_stage(&actual),
                encode_hex(expected),
                encode_hex(&actual)
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn run(program: &str, args: &[&str], role: &str) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| {
            format!("PackageBootMediaToolError {{ role: {role}, detail: {error} }}")
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "PackageBootMediaToolFailed {{ role: {role}, status: {status} }}"
        ))
    }
}

fn run_with_input(
    program: &str,
    args: &[&std::ffi::OsStr],
    input: &[u8],
    role: &str,
) -> Result<(), String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| {
            format!("PackageBootMediaToolError {{ role: {role}, detail: {error} }}")
        })?;
    child
        .stdin
        .take()
        .ok_or_else(|| format!("PackageBootMediaToolPipe {{ role: {role} }}"))?
        .write_all(input)
        .map_err(|error| {
            format!("PackageBootMediaToolWrite {{ role: {role}, detail: {error} }}")
        })?;
    let status = child
        .wait()
        .map_err(|error| format!("PackageBootMediaToolWait {{ role: {role}, detail: {error} }}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "PackageBootMediaToolFailed {{ role: {role}, status: {status} }}"
        ))
    }
}

fn validate_options(args: &[String]) -> Result<(), String> {
    let mut index = 0;
    while index < args.len() {
        if !matches!(
            args[index].as_str(),
            "--accelerator"
                | "--iommu"
                | "--timeout-seconds"
                | "--expect-hex"
                | "--expect-rejection-hex"
        ) || index + 1 == args.len()
        {
            return Err("PackageQemuBootUsage { unknown_option }".into());
        }
        index += 2;
    }
    Ok(())
}

fn option<'a>(args: &'a [String], name: &str) -> Result<Option<&'a str>, String> {
    let mut found = args
        .windows(2)
        .filter(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str());
    let value = found.next();
    if found.next().is_some()
        || value.is_some_and(|value| value.starts_with('-'))
        || (value.is_none() && args.iter().any(|arg| arg == name))
    {
        return Err(format!("InvalidOption {{ option: {name} }}"));
    }
    Ok(value)
}

fn parse_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("PackageQemuExpectedTraceInvalid".into());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = core::str::from_utf8(pair)
                .map_err(|_| "PackageQemuExpectedTraceInvalid".to_owned())?;
            u8::from_str_radix(text, 16).map_err(|_| "PackageQemuExpectedTraceInvalid".to_owned())
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn rejected_twice(trace: &[u8], prefix: &[u8]) -> bool {
    !prefix.is_empty()
        && trace.len() >= prefix.len() * 2
        && trace[..prefix.len()] == *prefix
        && trace[prefix.len()..prefix.len() * 2] == *prefix
        && !trace
            .windows(SUCCESS_TRACE.len())
            .any(|window| window == SUCCESS_TRACE)
}

fn boot_stage(trace: &[u8]) -> &'static str {
    const RELEASE_LOADED: &[u8] = &[0xc8];
    const EARLY_PACKAGES_VERIFIED: &[u8] = &[0xc8, 0xb0, 0xb2, 0xb0, 0xb2, 0xc9];
    const KERNEL_PACKAGE_VERIFIED: &[u8] = &[0xc8, 0xb0, 0xb2, 0xb0, 0xb2, 0xc9, 0xb0, 0xb2, 0xb2];
    const KERNEL_IMAGE_VERIFIED: &[u8] =
        &[0xc8, 0xb0, 0xb2, 0xb0, 0xb2, 0xc9, 0xb0, 0xb2, 0xb2, 0xa1];
    if trace == SUCCESS_TRACE {
        "kernel-entry-reached"
    } else if trace.starts_with(KERNEL_IMAGE_VERIFIED) {
        "kernel-image-verified"
    } else if trace.starts_with(KERNEL_PACKAGE_VERIFIED) {
        "kernel-package-verified"
    } else if trace.starts_with(EARLY_PACKAGES_VERIFIED) {
        "early-packages-verified"
    } else if trace.starts_with(RELEASE_LOADED) {
        "generation-manifest-loaded"
    } else if trace.is_empty() {
        "firmware-launched"
    } else {
        "efi-loader-entered"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expected_trace_hex_round_trips() {
        let encoded = encode_hex(&SUCCESS_TRACE);
        assert_eq!(parse_hex(&encoded).unwrap(), SUCCESS_TRACE);
        assert!(parse_hex("abc").is_err());
        assert!(parse_hex("zz").is_err());
        let prefix = [0xc8, 0xb0, 0xb2];
        assert!(rejected_twice(
            &[0xc8, 0xb0, 0xb2, 0xc8, 0xb0, 0xb2],
            &prefix
        ));
        assert!(!rejected_twice(&SUCCESS_TRACE, &prefix));
    }

    #[test]
    fn accelerator_option_is_explicit_and_bounded() {
        let options = ["--accelerator".to_owned(), "whpx".to_owned()];
        validate_options(&options).unwrap();
        assert_eq!(option(&options, "--accelerator").unwrap(), Some("whpx"));
        assert!(validate_options(&["--accelerator".to_owned()]).is_err());
        assert!(validate_options(&["--unknown".to_owned(), "tcg".to_owned()]).is_err());
    }

    #[test]
    fn boot_stage_requires_ordered_canonical_prefixes() {
        assert_eq!(boot_stage(&[]), "firmware-launched");
        assert_eq!(boot_stage(&[0x01]), "efi-loader-entered");
        assert_eq!(boot_stage(&[0xc8]), "generation-manifest-loaded");
        assert_eq!(
            boot_stage(&[0xc8, 0xb0, 0xb2, 0xb0, 0xb2, 0xc9]),
            "early-packages-verified"
        );
        assert_eq!(
            boot_stage(&[0xc8, 0xb0, 0xb2, 0xb0, 0xb2, 0xc9, 0xb0, 0xb2, 0xb2]),
            "kernel-package-verified"
        );
        assert_eq!(boot_stage(&SUCCESS_TRACE), "kernel-entry-reached");
    }
}
