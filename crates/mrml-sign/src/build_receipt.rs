use mrml_crypto::Sha3_512;
use mrml_error::{Result, anyhow};
use mrml_kernel::{BUILD_RECEIPT_MAX_BYTES, BuildReceipt};
use mrml_runtime::{Text, Vector, mrml_println as println};

const MAX_INPUT: usize = 512 * 1024 * 1024;
const MAX_VALUE: usize = 256;
const HEADER: &str = "MRML-BUILD-RECEIPT-v1\n";

struct Input<'a> {
    name: &'static str,
    path: &'a str,
}

pub fn create(args: &[Text]) -> Result<()> {
    if args.len() != 11 {
        return Err(anyhow!("invalid build-receipt arguments"));
    }
    let output = &args[0];
    let source = &args[1];
    let rustc = canonical_value("rustc", &args[2])?;
    let cargo = canonical_value("cargo", &args[3])?;
    let target = canonical_value("target", &args[4])?;
    let profile = canonical_value("profile", &args[5])?;
    let inputs = [
        Input {
            name: "source-archive",
            path: source,
        },
        Input {
            name: "cargo-lock",
            path: &args[6],
        },
        Input {
            name: "kernel",
            path: &args[7],
        },
        Input {
            name: "service",
            path: &args[8],
        },
        Input {
            name: "loader",
            path: &args[9],
        },
        Input {
            name: "configuration",
            path: &args[10],
        },
    ];

    let mut receipt =
        Vector::with_capacity(BUILD_RECEIPT_MAX_BYTES).map_err(|_| anyhow!("allocation failed"))?;
    append(&mut receipt, HEADER.as_bytes())?;
    append_field(&mut receipt, "rustc", rustc.as_bytes())?;
    append_field(&mut receipt, "cargo", cargo.as_bytes())?;
    append_field(&mut receipt, "target", target.as_bytes())?;
    append_field(&mut receipt, "profile", profile.as_bytes())?;
    for input in inputs {
        let bytes = mrml_runtime::read_file_bounded(input.path, MAX_INPUT)?;
        append_number(&mut receipt, input.name, "length", bytes.len() as u64)?;
        append_digest(&mut receipt, input.name, Sha3_512::digest(&bytes))?;
    }
    if receipt.len() > BUILD_RECEIPT_MAX_BYTES || BuildReceipt::decode(&receipt).is_err() {
        return Err(anyhow!("build receipt exceeds canonical bound"));
    }
    mrml_runtime::write_new_file(output, &receipt)?;
    println!("wrote canonical build receipt");
    Ok(())
}

pub fn compare(first: &str, second: &str) -> Result<()> {
    let first = mrml_runtime::read_file_bounded(first, BUILD_RECEIPT_MAX_BYTES)?;
    let second = mrml_runtime::read_file_bounded(second, BUILD_RECEIPT_MAX_BYTES)?;
    if first != second || BuildReceipt::decode(&first).is_err() {
        return Err(anyhow!("build receipts differ or are noncanonical"));
    }
    println!("build receipts match byte-for-byte");
    Ok(())
}

fn canonical_value<'a>(_name: &str, value: &'a str) -> Result<&'a str> {
    if value.is_empty()
        || value.len() > MAX_VALUE
        || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(anyhow!("invalid canonical build field"));
    }
    Ok(value)
}

fn append(output: &mut Vector<u8>, bytes: &[u8]) -> Result<()> {
    output
        .try_extend_from_slice(bytes)
        .map_err(|_| anyhow!("allocation failed"))
}

fn append_field(output: &mut Vector<u8>, name: &str, value: &[u8]) -> Result<()> {
    append(output, name.as_bytes())?;
    append(output, b"=")?;
    append(output, value)?;
    append(output, b"\n")
}

fn append_number(output: &mut Vector<u8>, name: &str, suffix: &str, value: u64) -> Result<()> {
    let value = mrml_runtime::mrml_format!("{value}");
    append_field(
        output,
        &mrml_runtime::mrml_format!("{name}.{suffix}"),
        value.as_bytes(),
    )
}

fn append_digest(output: &mut Vector<u8>, name: &str, digest: [u8; 64]) -> Result<()> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0u8; 128];
    for (index, byte) in digest.iter().copied().enumerate() {
        encoded[index * 2] = HEX[(byte >> 4) as usize];
        encoded[index * 2 + 1] = HEX[(byte & 15) as usize];
    }
    append_field(
        output,
        &mrml_runtime::mrml_format!("{name}.sha3-512"),
        &encoded,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(root: &str, output: &str) -> Vector<Text> {
        let mut args = Vector::new();
        args.push(output.into());
        args.push(mrml_runtime::join_path(root, "source.tar"));
        args.push("rustc 1.91.0 (fixture)".into());
        args.push("cargo 1.91.0 (fixture)".into());
        args.push("x86_64-unknown-uefi".into());
        args.push("release".into());
        args.push(mrml_runtime::join_path(root, "Cargo.lock"));
        args.push(mrml_runtime::join_path(root, "kernel.efi"));
        args.push(mrml_runtime::join_path(root, "service.efi"));
        args.push(mrml_runtime::join_path(root, "loader.efi"));
        args.push(mrml_runtime::join_path(root, "configuration.bin"));
        args
    }

    #[test]
    fn receipts_are_path_independent_canonical_and_detect_changes() {
        let root = mrml_runtime::join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-build-receipt-{}", mrml_runtime::process_id()),
        );
        mrml_runtime::create_dir_all(&root).unwrap();
        for (name, bytes) in [
            ("source.tar", b"source".as_slice()),
            ("Cargo.lock", b"dependencies".as_slice()),
            ("kernel.efi", b"kernel".as_slice()),
            ("service.efi", b"service".as_slice()),
            ("loader.efi", b"loader".as_slice()),
            ("configuration.bin", b"configuration".as_slice()),
        ] {
            mrml_runtime::write_file(&mrml_runtime::join_path(&root, name), bytes).unwrap();
        }
        let first = mrml_runtime::join_path(&root, "first.receipt");
        let second = mrml_runtime::join_path(&root, "second.receipt");
        create(&arguments(&root, &first)).unwrap();
        create(&arguments(&root, &second)).unwrap();
        compare(&first, &second).unwrap();

        mrml_runtime::write_file(&mrml_runtime::join_path(&root, "kernel.efi"), b"changed")
            .unwrap();
        let changed = mrml_runtime::join_path(&root, "changed.receipt");
        create(&arguments(&root, &changed)).unwrap();
        assert!(compare(&first, &changed).is_err());

        let bytes = mrml_runtime::read_file(&first).unwrap();
        assert!(BuildReceipt::decode(&bytes).is_ok());
        assert!(
            !core::str::from_utf8(&bytes)
                .unwrap()
                .contains(root.as_str())
        );
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn canonical_parser_rejects_ambiguous_or_extended_receipts() {
        assert!(BuildReceipt::decode(b"MRML-BUILD-RECEIPT-v1\n").is_err());
        assert!(BuildReceipt::decode(b"MRML-BUILD-RECEIPT-v1\nrustc=x\n").is_err());
        assert!(canonical_value("target", "line\nbreak").is_err());
        assert!(canonical_value("target", "").is_err());
    }
}
