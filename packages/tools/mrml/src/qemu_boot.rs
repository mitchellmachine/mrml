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
    if args.len() < 5 {
        return Err("PackageQemuBootUsage { expected: IMAGE OVMF_CODE OVMF_VARS QEMU TRACE [--timeout-seconds N] [--expect-hex HEX | --expect-rejection-hex HEX] }".into());
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
    let result = run_qemu_child(
        &args[3],
        &args[0],
        &args[1],
        &vars,
        trace,
        &expected,
        rejection.as_deref(),
        timeout,
    );
    let _ = fs::remove_file(vars);
    result
}

fn run_qemu_child(
    qemu: &str,
    image: &str,
    code: &str,
    vars: &Path,
    trace: &Path,
    expected: &[u8],
    rejection: Option<&[u8]>,
    timeout: u64,
) -> Result<(), String> {
    let mut child = Command::new(qemu)
        .args([
            "-machine",
            "q35,accel=tcg",
            "-m",
            "512M",
            "-display",
            "none",
        ])
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
        .stdin(Stdio::null())
        .stdout(Stdio::null())
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
                    "package-qemu-boot|status=QEMU_UEFI_BOOT_REJECT_PASS|trace={}|bytes={}",
                    encode_hex(&bytes),
                    bytes.len()
                );
                return Ok(());
            }
            if rejection.is_none() && bytes == expected {
                child
                    .kill()
                    .map_err(|error| format!("PackageQemuStopError {{ detail: {error} }}"))?;
                let _ = child.wait();
                println!(
                    "package-qemu-boot|status=QEMU_UEFI_BOOT_PASS|trace={}|bytes={}",
                    encode_hex(&bytes),
                    bytes.len()
                );
                return Ok(());
            }
            if rejection.is_none() && bytes.len() >= expected.len() {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "PackageQemuTraceMismatch {{ expected: {}, actual: {} }}",
                    encode_hex(expected),
                    encode_hex(&bytes)
                ));
            }
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("PackageQemuWaitError {{ detail: {error} }}"))?
        {
            return Err(format!("PackageQemuExited {{ status: {status} }}"));
        }
        if start.elapsed() >= Duration::from_secs(timeout) {
            let _ = child.kill();
            let _ = child.wait();
            let actual = fs::read(trace).unwrap_or_default();
            return Err(format!(
                "PackageQemuTimeout {{ expected: {}, actual: {} }}",
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
            "--timeout-seconds" | "--expect-hex" | "--expect-rejection-hex"
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
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("PackageQemuExpectedTraceInvalid".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
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
}
