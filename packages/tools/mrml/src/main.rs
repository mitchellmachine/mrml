pub mod abi;
#[path = "../../../libraries/package-format/src/activation.rs"]
pub mod activation;
mod assurance;
pub mod binding;
#[path = "../../../services/certificate/src/caa.rs"]
mod certificate_caa;
#[path = "../../../libraries/package-format/src/component_launch.rs"]
pub mod component_launch;
#[path = "../../../libraries/package-format/src/component_resolution.rs"]
pub mod component_resolution;
pub mod generation;
mod input_audit;
#[path = "../../../libraries/package-format/src/interface_catalog.rs"]
pub mod interface_catalog;
pub mod isolation;
pub mod loader;
pub mod manifest;
pub mod manifest_catalog;
pub mod migration;
pub mod package;
pub mod resolver;
#[path = "../../../libraries/package-format/src/runtime_inventory.rs"]
pub mod runtime_inventory;
pub mod runtime_placement;
pub mod schema;
pub mod servicing;
#[path = "../../../libraries/package-format/src/system_generation.rs"]
pub mod system_generation;
#[path = "../../../libraries/package-format/src/system_release.rs"]
pub mod system_release;

pub use activation::*;
pub use component_launch::*;
pub use component_resolution::*;
pub use interface_catalog::*;
pub use runtime_inventory::*;
pub use system_generation::*;
pub use system_release::*;

extern crate self as mrml_crypto;

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::Write as _;
use std::path::{Component as PathComponent, Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Instant;

use certificate_caa::{CaaChallengeMethod, CaaPolicy, MAX_CAA_RECORD_BYTES, MAX_CAA_RECORDS};
use generation::mrml_package_identifier;
use isolation::IsolationPolicy;
use manifest::Document as ManifestDocument;
#[cfg(not(mrml_stage_zero))]
use mrml_certificate::{
    BackupExportReceipt, BackupTransferReceipt, BackupTransferReceiptState, ExpiryHealth,
    HostedLifecycleClient, MAX_BACKUP_BYTES, MAX_MANAGED_STATUS_BYTES, ManagedIdentityStatus,
    RenewalSource, TlsIdentityId, decode_managed_identity_status,
    untrusted_backup_container_digest,
};
#[path = "../../../libraries/crypto/src/sha3.rs"]
#[allow(dead_code)]
mod package_sha3;
pub use package_sha3::Sha3_512;
#[path = "../../../libraries/crypto/src/lamport.rs"]
mod package_lamport;
pub use package_lamport::{
    LAMPORT_PRIVATE_KEY_BYTES, LAMPORT_PUBLIC_KEY_BYTES, LAMPORT_SIGNATURE_BYTES,
    lamport_public_key, lamport_sign, lamport_verify,
};
#[path = "../../../libraries/package-format/src/core.rs"]
#[allow(dead_code)]
mod boot_package_core;
#[path = "../../../libraries/package-format/src/release.rs"]
#[allow(dead_code)]
mod boot_release_core;
use schema::InterfaceSchema;

const MAX_WORKSPACE_BYTES: u64 = 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_COMPONENTS: usize = 256;
const MAX_DISCOVERY_DIRECTORIES: usize = 4096;
const PINNED_NIGHTLY: &str = "nightly-2026-11-26";
const TARGET_FAMILIES: [&str; 5] = ["WINDOWS", "LINUX", "MRML_NATIVE", "UEFI", "CUDA"];

#[derive(Clone, Debug)]
struct Component {
    id: String,
    path: String,
    cargo_package: String,
    class: String,
    targets: Vec<String>,
    default: bool,
    dependencies: Vec<String>,
    features: Vec<String>,
    outputs: Vec<String>,
    input_policy: InputCounts,
    input_sites: Vec<input_audit::DeclaredInputSite>,
    isolation: IsolationPolicy,
    rust_action: Option<RustAction>,
}

#[derive(Clone, Debug)]
struct RustAction {
    crate_name: String,
    crate_type: String,
    source: String,
    externs: Vec<RustExtern>,
    tests: Vec<RustTest>,
    test_stack_bytes: Option<usize>,
    host_build_targets: Vec<String>,
    projected_build_targets: Vec<String>,
    host_test_targets: Vec<String>,
    examples: Vec<RustExample>,
    benchmarks: Vec<RustBenchmark>,
    binaries: Vec<RustBinary>,
    ptx: Option<RustPtx>,
    compile_env: Vec<RustCompileEnv>,
    absent_compile_env: Vec<String>,
    feature_sets: Vec<RustFeatureSet>,
    feature_profiles: Vec<RustFeatureProfile>,
    target_triples: Vec<RustTargetTriple>,
}

#[derive(Clone, Debug)]
struct RustFeatureSet {
    targets: Vec<String>,
    features: Vec<String>,
}

#[derive(Clone, Debug)]
struct RustFeatureProfile {
    name: String,
    targets: Vec<String>,
    features: Vec<String>,
}

#[derive(Clone, Debug)]
struct RustTargetTriple {
    target: String,
    triple: String,
}

#[derive(Clone, Debug)]
struct RustExtern {
    package: String,
    crate_name: String,
    targets: Vec<String>,
    feature: Option<String>,
    provider_profile: String,
    provider_profiles: BTreeMap<String, String>,
    test_only: bool,
}

#[derive(Clone, Debug)]
struct RustTest {
    name: String,
    source: String,
    self_extern: bool,
}

#[derive(Clone, Debug)]
struct RustExample {
    name: String,
    source: String,
    targets: Vec<String>,
    feature: Option<String>,
}

#[derive(Clone, Debug)]
struct RustBenchmark {
    name: String,
    source: String,
    self_extern: bool,
}

#[derive(Clone, Debug)]
struct RustPtx {
    output: String,
    source: String,
    feature: String,
    compile_env: String,
    default_gpu_arch: String,
}

#[derive(Clone, Debug)]
struct RustCompileEnv {
    name: String,
    value: String,
    uses: usize,
}

#[derive(Clone, Debug)]
struct RustBinary {
    output: String,
    crate_name: String,
    source: String,
    self_extern: bool,
    targets: Vec<String>,
    feature: Option<String>,
}

#[derive(Clone, Copy, Debug)]
struct RustCompileMode<'a> {
    target: &'a str,
    compile_target: &'a str,
    release: bool,
    test: bool,
    gpu_arch: Option<&'a str>,
    compile_env: &'a BTreeMap<String, String>,
    sanitizer: Option<&'a str>,
}

#[derive(Clone, Copy, Debug)]
struct RustActionRequest<'a> {
    operation: &'a str,
    target: &'a str,
    release: bool,
    gpu_arch: Option<&'a str>,
    feature_profile: &'a str,
    compile_env: &'a BTreeMap<String, String>,
    sanitizer: Option<&'a str>,
}

#[derive(Debug)]
struct Workspace {
    root: PathBuf,
    components: Vec<Component>,
    interface_bindings: Vec<InterfaceBindingLock>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InterfaceBindingLock {
    consumer: String,
    interface: String,
    generation: u64,
    fingerprint: String,
    provider: String,
    form: String,
    targets: Vec<String>,
}

struct ManifestDeclarations {
    records: Vec<Vec<String>>,
    interface_bindings: Vec<InterfaceBindingLock>,
    isolation_policies: BTreeMap<String, IsolationPolicy>,
    build_inputs: BTreeMap<String, Vec<input_audit::DeclaredInputSite>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputMode {
    Human,
    Structured,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "help" | "--help" | "-h") {
        print_help();
        return Ok(());
    }
    if args[0] == "usb" {
        return usb_media::command(&args[1..]);
    }
    let workspace = load_workspace()?;
    match args[0].as_str() {
        "list" => list(&workspace, &args[1..]),
        "build" | "test" => build_or_test(&workspace, &args),
        "compiler" => compiler_command(&workspace, &args[1..]),
        "cert" => cert_command(&args[1..]),
        "doctor" => doctor(&workspace, &args[1..]),
        "audit" => audit(&workspace, &args[1..]),
        "assurance" => assurance::command(&workspace, &args[1..]),
        "manifest" => manifest_command(&workspace, &args[1..]),
        "interface" => interface_command(&args[1..]),
        "package" => package_command(&workspace, &args[1..]),
        "release" => release_command(&workspace, &args[1..]),
        command @ ("image" | "publish") => Err(format!(
            "UnsupportedOperation {{ command: {command}, status: PLANNED }}"
        )),
        command => Err(format!("UnknownCommand {{ command: {command} }}")),
    }
}

fn print_help() {
    println!("mrml - canonical MRML repository build frontend (native migration stage)");
    println!(
        "usage: mrml <list|doctor|audit|assurance|build|test|compiler|manifest|interface|package|release|cert> [component] [options]"
    );
    println!("       mrml manifest <check|fmt|lock> [--check]");
    println!("       mrml assurance <check|generate|inspect>");
    println!(
        "       mrml usb image OUTPUT.img | mrml usb list [--erase|-e] | mrml usb burn IMAGE.img | mrml usb autoburn [--erase|-e]"
    );
    println!("       mrml usb test OVMF_CODE OVMF_VARS QEMU");
    println!("       mrml cert caa <recommend|verify> ...");
    println!(
        "       mrml cert status (--snapshot FILE | --endpoint 127.0.0.1:PORT --session-capability FILE --identity HEX) [--output human|structured]"
    );
    println!(
        "       mrml cert backup <create --output-file FILE|verify --input FILE> --policy-generation N --transfer-generation N --endpoint 127.0.0.1:PORT --session-capability FILE [--output human|structured]"
    );
    println!(
        "       mrml cert restore [--verify-only] --input FILE --policy-generation N --transfer-generation N --endpoint 127.0.0.1:PORT --session-capability FILE [--confirm-digest HEX] [--output human|structured]"
    );
    println!(
        "       mrml compiler mrml-rustc-experimental link-elf INPUT... --entry NAME -o OUTPUT [--release]"
    );
    println!(
        "       mrml compiler mrml-rustc-experimental compile-elf INPUT --function NAME -o OUTPUT [--release]"
    );
    println!(
        "       mrml compiler mrml-rustc-experimental <link-pe INPUT... --entry NAME|compile-pe INPUT --function NAME> -o OUTPUT [--release]"
    );
    println!("       mrml manifest migrate LEGACY_WORKSPACE NEW_ROOT");
    println!(
        "       mrml package create ID CLASS VERSION ARCH PURPOSE INPUT [OUTPUT] [--compress] [--private-key KEY]"
    );
    println!("       mrml package verify FILE [--require-signature] [--output structured]");
    println!(
        "       mrml release create VERSION BOOTLOADER.mrp KERNEL.mrp CONFIGURATION.mrp PRIVATE_KEY [OUTPUT.mrs]"
    );
    println!("       mrml release verify RELEASE.mrs PUBLIC_KEY");
    println!(
        "       mrml release system-create GENERATION.mrmlbin INTERFACES.mrmlbin PRIVATE_KEY OUTPUT.mrs"
    );
    println!(
        "       mrml release system-create GENERATION.mrmlbin INTERFACES.mrmlbin RUNTIME.mrmlbin PRIVATE_KEY OUTPUT.mrs"
    );
    println!("       mrml release runtime-inventory-create GENERATION.mrmlbin OUTPUT.mrmlbin");
    println!("       mrml release system-verify RELEASE.mrs PUBLIC_KEY");
    println!(
        "       mrml package adversarial-boot-fixture CASE BOOTLOADER_PACKAGE CONFIGURATION_PACKAGE KERNEL_SIGNED PACKAGE_PRIVATE RELEASE_PRIVATE KERNEL_OUTPUT RELEASE_OUTPUT"
    );
    println!(
        "       mrml package boot-media-create LOADER BOOTLOADER_PACKAGE KERNEL_PACKAGE CONFIGURATION_PACKAGE SYSTEM_RELEASE SERVICE_SIGNED OUTPUT SFDISK MFORMAT MMD MCOPY"
    );
    println!(
        "       mrml package qemu-boot IMAGE OVMF_CODE OVMF_VARS QEMU TRACE [--accelerator tcg|whpx|kvm] [--timeout-seconds N] [--expect-hex HEX | --expect-rejection-hex HEX]"
    );
    println!("       mrml interface generate-rust SCHEMA OUTPUT");
    println!("  --all                 select every target-compatible component");
    println!("  --keep-going          attempt all selected components; fail if any fail");
    println!("  --target <family>     native|windows|linux|uefi-x86_64|cuda-nvidia");
    println!("  --gpu-arch <name>     required metadata for CUDA target");
    println!("  --release             use release profile");
    println!("  --feature-profile P   select a declared Rust feature profile");
    println!("  --compile-env N=V     set an allowlisted manifest compile input");
    println!("  --sanitizer address   instrument Linux native tests with AddressSanitizer");
    println!("  --output structured   emit stable key=value records");
}

fn cert_command(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("caa") => cert_caa_command(&args[1..]),
        #[cfg(not(mrml_stage_zero))]
        Some("status") => cert_status_command(&args[1..]),
        #[cfg(not(mrml_stage_zero))]
        Some("backup") => cert_backup_command(&args[1..]),
        #[cfg(not(mrml_stage_zero))]
        Some("restore") => cert_restore_command(&args[1..]),
        Some(operation) => Err(format!(
            "CertificateOperationUnavailable {{ operation: {operation}, status: REMAINS_OPEN }}"
        )),
        None => Err("CertificateUsageError { expected: caa|status|backup|restore }".into()),
    }
}

#[cfg(not(mrml_stage_zero))]
fn cert_restore_command(args: &[String]) -> Result<(), String> {
    let (operation, options) = match args.first().map(String::as_str) {
        Some("--verify-only") => ("verify", &args[1..]),
        _ => ("restore", args),
    };
    let mut routed = Vec::with_capacity(options.len() + 1);
    routed.push(operation.to_owned());
    routed.extend_from_slice(options);
    cert_backup_command(&routed)
}

#[cfg(not(mrml_stage_zero))]
fn cert_status_command(args: &[String]) -> Result<(), String> {
    let mut snapshot = None;
    let mut endpoint = None;
    let mut session_capability = None;
    let mut identity = None;
    let mut output = OutputMode::Human;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--snapshot" => {
                index += 1;
                snapshot = Some(
                    args.get(index)
                        .map(String::as_str)
                        .ok_or("CertificateStatusSnapshotMissing")?,
                );
            }
            "--output" => {
                index += 1;
                output = match args.get(index).map(String::as_str) {
                    Some("human") => OutputMode::Human,
                    Some("structured") => OutputMode::Structured,
                    _ => return Err("CertificateStatusOutputInvalid".into()),
                };
            }
            "--endpoint" => {
                index += 1;
                endpoint = Some(
                    args.get(index)
                        .map(String::as_str)
                        .ok_or("CertificateStatusEndpointMissing")?,
                );
            }
            "--session-capability" => {
                index += 1;
                session_capability = Some(
                    args.get(index)
                        .map(String::as_str)
                        .ok_or("CertificateStatusSessionCapabilityMissing")?,
                );
            }
            "--identity" => {
                index += 1;
                identity = Some(
                    args.get(index)
                        .map(String::as_str)
                        .ok_or("CertificateStatusIdentityMissing")?,
                );
            }
            option => {
                return Err(format!(
                    "CertificateStatusUnknownOption {{ option: {option} }}"
                ));
            }
        }
        index += 1;
    }
    let status = match (snapshot, endpoint, session_capability, identity) {
        (Some(path), None, None, None) => read_certificate_status_snapshot(path)?,
        (None, Some(endpoint), Some(capability_path), Some(identity)) => {
            read_live_certificate_status(endpoint, capability_path, identity)?
        }
        (None, None, None, None) => {
            return Err("CertificateStatusRouteMissing { expected: --snapshot FILE or --endpoint ... --session-capability ... --identity ... }".into());
        }
        _ => return Err("CertificateStatusRouteAmbiguous".into()),
    };
    print!("{}", render_certificate_status(status, output));
    Ok(())
}

#[cfg(not(mrml_stage_zero))]
fn read_certificate_status_snapshot(path: &str) -> Result<ManagedIdentityStatus, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("CertificateStatusSnapshotUnreadable {{ detail: {error} }}"))?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_MANAGED_STATUS_BYTES as u64
    {
        return Err("CertificateStatusSnapshotSizeInvalid".into());
    }
    let bytes = fs::read(path)
        .map_err(|error| format!("CertificateStatusSnapshotUnreadable {{ detail: {error} }}"))?;
    decode_managed_identity_status(&bytes)
        .map_err(|error| format!("CertificateStatusSnapshotInvalid {{ detail: {error:?} }}"))
}

#[cfg(not(mrml_stage_zero))]
fn read_live_certificate_status(
    endpoint: &str,
    capability_path: &str,
    identity: &str,
) -> Result<ManagedIdentityStatus, String> {
    let identity = decode_fixed_hex::<16>(identity)
        .ok_or("CertificateStatusIdentityInvalid { required: 32 lowercase hex digits }")?;
    let mut client = connect_certificate_session(endpoint, capability_path)?;
    client
        .identity_status(TlsIdentityId(identity))
        .map_err(|error| format!("CertificateStatusSessionFailed {{ detail: {error:?} }}"))
}

#[cfg(not(mrml_stage_zero))]
fn connect_certificate_session(
    endpoint: &str,
    capability_path: &str,
) -> Result<HostedLifecycleClient, String> {
    let port = endpoint
        .strip_prefix("127.0.0.1:")
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or("CertificateSessionEndpointInvalid { required: 127.0.0.1:PORT }")?;
    let metadata = fs::metadata(capability_path).map_err(|error| {
        format!("CertificateStatusSessionCapabilityUnreadable {{ detail: {error} }}")
    })?;
    if !metadata.is_file() || metadata.len() != 32 {
        return Err("CertificateStatusSessionCapabilitySizeInvalid".into());
    }
    let mut bytes = fs::read(capability_path).map_err(|error| {
        format!("CertificateStatusSessionCapabilityUnreadable {{ detail: {error} }}")
    })?;
    if bytes.len() != 32 {
        bytes.fill(0);
        return Err("CertificateStatusSessionCapabilitySizeInvalid".into());
    }
    let mut capability = [0u8; 32];
    capability.copy_from_slice(&bytes);
    bytes.fill(0);
    let result = HostedLifecycleClient::connect_session([127, 0, 0, 1], port, capability);
    capability.fill(0);
    result.map_err(|error| format!("CertificateSessionFailed {{ detail: {error:?} }}"))
}

#[cfg(not(mrml_stage_zero))]
fn cert_backup_command(args: &[String]) -> Result<(), String> {
    let operation = args
        .first()
        .map(String::as_str)
        .ok_or("CertificateBackupUsageError { expected: create|verify|restore }")?;
    if !matches!(operation, "create" | "verify" | "restore") {
        return Err("CertificateBackupOperationInvalid".into());
    }
    let mut input = None;
    let mut output_file = None;
    let mut policy_generation = None;
    let mut transfer_generation = None;
    let mut endpoint = None;
    let mut session_capability = None;
    let mut confirmed_digest = None;
    let mut output = OutputMode::Human;
    let mut index = 1;
    while index < args.len() {
        let value = |index: usize| {
            args.get(index)
                .map(String::as_str)
                .ok_or("CertificateBackupOptionValueMissing")
        };
        match args[index].as_str() {
            "--input" => {
                index += 1;
                input = Some(value(index)?);
            }
            "--output-file" => {
                index += 1;
                output_file = Some(value(index)?);
            }
            "--policy-generation" => {
                index += 1;
                policy_generation = Some(parse_nonzero_generation(value(index)?)?);
            }
            "--transfer-generation" => {
                index += 1;
                transfer_generation = Some(parse_nonzero_generation(value(index)?)?);
            }
            "--endpoint" => {
                index += 1;
                endpoint = Some(value(index)?);
            }
            "--session-capability" => {
                index += 1;
                session_capability = Some(value(index)?);
            }
            "--confirm-digest" => {
                index += 1;
                confirmed_digest = Some(
                    decode_fixed_hex::<32>(value(index)?)
                        .ok_or("CertificateBackupConfirmationDigestInvalid")?,
                );
            }
            "--output" => {
                index += 1;
                output = match value(index)? {
                    "human" => OutputMode::Human,
                    "structured" => OutputMode::Structured,
                    _ => return Err("CertificateBackupOutputInvalid".into()),
                };
            }
            _ => return Err("CertificateBackupUnknownOption".into()),
        }
        index += 1;
    }
    let policy_generation = policy_generation.ok_or("CertificateBackupPolicyGenerationMissing")?;
    let transfer_generation =
        transfer_generation.ok_or("CertificateBackupTransferGenerationMissing")?;
    let endpoint = endpoint.ok_or("CertificateBackupEndpointMissing")?;
    let capability = session_capability.ok_or("CertificateBackupSessionCapabilityMissing")?;
    if operation == "create" {
        if input.is_some() || confirmed_digest.is_some() {
            return Err("CertificateBackupCreateUnexpectedInput".into());
        }
        let destination = output_file.ok_or("CertificateBackupOutputFileMissing")?;
        let mut client = connect_certificate_session(endpoint, capability)?;
        let mut bytes = vec![0u8; MAX_BACKUP_BYTES];
        let result =
            client.create_backup_container(policy_generation, transfer_generation, &mut bytes);
        let (written, receipt) = match result {
            Ok(value) => value,
            Err(error) => {
                bytes.fill(0);
                return Err(format!(
                    "CertificateBackupSessionFailed {{ detail: {error:?} }}"
                ));
            }
        };
        let write_result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)
                .map_err(|error| {
                    format!("CertificateBackupOutputUnavailable {{ detail: {error} }}")
                })?;
            file.write_all(&bytes[..written])
                .and_then(|()| file.sync_all())
                .map_err(|error| format!("CertificateBackupOutputFailed {{ detail: {error} }}"))
        })();
        bytes.fill(0);
        write_result?;
        print!(
            "{}",
            render_backup_export_receipt(receipt, destination, output)
        );
        return Ok(());
    }
    if output_file.is_some() {
        return Err("CertificateBackupUnexpectedOutputFile".into());
    }
    let input = input.ok_or("CertificateBackupInputMissing")?;
    let metadata = fs::metadata(input)
        .map_err(|error| format!("CertificateBackupUnreadable {{ detail: {error} }}"))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_BACKUP_BYTES as u64 {
        return Err("CertificateBackupSizeInvalid".into());
    }
    let mut bytes = fs::read(input)
        .map_err(|error| format!("CertificateBackupUnreadable {{ detail: {error} }}"))?;
    let digest =
        untrusted_backup_container_digest(&bytes).map_err(|_| "CertificateBackupSizeInvalid")?;
    let restore_confirmation = match (operation, confirmed_digest) {
        ("verify", None) => None,
        ("restore", Some(confirmed)) if confirmed == digest => Some(confirmed),
        ("restore", _) => {
            bytes.fill(0);
            return Err(format!(
                "CertificateBackupRestoreConfirmationRequired {{ exact_digest: {} }}",
                encode_hex(&digest)
            ));
        }
        _ => {
            bytes.fill(0);
            return Err("CertificateBackupVerifyRejectsConfirmation".into());
        }
    };
    let mut client = match connect_certificate_session(endpoint, capability) {
        Ok(client) => client,
        Err(error) => {
            bytes.fill(0);
            return Err(error);
        }
    };
    let result = match restore_confirmation {
        None => client.verify_backup_container(policy_generation, transfer_generation, &bytes),
        Some(confirmed) => client.restore_backup_container(
            policy_generation,
            transfer_generation,
            &bytes,
            confirmed,
        ),
    };
    bytes.fill(0);
    let receipt = result
        .map_err(|error| format!("CertificateBackupSessionFailed {{ detail: {error:?} }}"))?;
    print!("{}", render_backup_receipt(receipt, output));
    Ok(())
}

#[cfg(not(mrml_stage_zero))]
fn render_backup_export_receipt(
    receipt: BackupExportReceipt,
    destination: &str,
    output: OutputMode,
) -> String {
    match output {
        OutputMode::Human => format!(
            "Certificate backup created\n  file: {destination}\n  export generation: {}\n  policy generation: {}\n  records: {}\n  bytes: {}\n  digest: {}\n",
            receipt.export_generation,
            receipt.policy_generation,
            receipt.record_count,
            receipt.total_bytes,
            encode_hex(&receipt.backup_digest)
        ),
        OutputMode::Structured => format!(
            "cert-backup|operation=create|status=PASS|export_generation={}|policy_generation={}|records={}|bytes={}|digest={}|file_hex={}\n",
            receipt.export_generation,
            receipt.policy_generation,
            receipt.record_count,
            receipt.total_bytes,
            encode_hex(&receipt.backup_digest),
            encode_hex(destination.as_bytes())
        ),
    }
}

#[cfg(not(mrml_stage_zero))]
fn parse_nonzero_generation(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| "CertificateGenerationInvalid".into())
}

#[cfg(not(mrml_stage_zero))]
fn render_backup_receipt(receipt: BackupTransferReceipt, output: OutputMode) -> String {
    let state = match receipt.state {
        BackupTransferReceiptState::Accepted => "accepted",
        BackupTransferReceiptState::Verified => "verified",
        BackupTransferReceiptState::Restored => "restored",
        BackupTransferReceiptState::Cancelled => "cancelled",
    };
    match output {
        OutputMode::Human => format!(
            "Certificate backup {state}\n  transfer generation: {}\n  policy generation: {}\n  records: {}\n  digest: {}\n",
            receipt.transfer_generation,
            receipt.policy_generation,
            receipt.record_count,
            encode_hex(&receipt.backup_digest)
        ),
        OutputMode::Structured => format!(
            "cert-backup|status=PASS|state={state}|transfer_generation={}|policy_generation={}|accepted_bytes={}|total_bytes={}|records={}|digest={}\n",
            receipt.transfer_generation,
            receipt.policy_generation,
            receipt.accepted_bytes,
            receipt.total_bytes,
            receipt.record_count,
            encode_hex(&receipt.backup_digest)
        ),
    }
}

#[cfg(not(mrml_stage_zero))]
fn render_certificate_status(status: ManagedIdentityStatus, output: OutputMode) -> String {
    use core::fmt::Write as _;

    let mut output_text = String::new();
    let identity = encode_hex(&status.identity.0);
    let active = status.active;
    let generation = active.map_or(0, |descriptor| descriptor.generation);
    let health = status
        .renewal
        .map(|renewal| expiry_health_name(renewal.health))
        .unwrap_or("unconfigured");
    let mut names = String::new();
    if let Some(descriptor) = active {
        let mut scratch = [0u8; 253];
        for identifier in descriptor.identifiers[..usize::from(descriptor.identifier_count)]
            .iter()
            .flatten()
        {
            if !names.is_empty() {
                names.push(',');
            }
            names.push_str(identifier.write_value(&mut scratch).unwrap_or("invalid"));
        }
    }
    if names.is_empty() {
        names.push('-');
    }
    match output {
        OutputMode::Human => {
            let _ = writeln!(output_text, "TLS identity {identity}");
            let _ = writeln!(
                output_text,
                "  policy generation: {}",
                status.policy_generation
            );
            let _ = writeln!(output_text, "  active generation: {generation}");
            let _ = writeln!(output_text, "  identifiers: {names}");
            let _ = writeln!(output_text, "  renewal health: {health}");
            if let Some(descriptor) = active {
                let _ = writeln!(
                    output_text,
                    "  leaf SPKI SHA-256: {}",
                    encode_hex(&descriptor.leaf_spki_digest)
                );
                let _ = writeln!(
                    output_text,
                    "  chain SHA-256: {}",
                    encode_hex(&descriptor.chain_digest)
                );
                let _ = writeln!(output_text, "  expires: {}", descriptor.not_after);
                let _ = writeln!(output_text, "  profile: {}", descriptor.profile.name());
            }
        }
        OutputMode::Structured => {
            let (source, renew_at, requery_at, expires, failures) =
                status.renewal.map_or(("none", 0, 0, 0, 0), |renewal| {
                    (
                        match renewal.source {
                            RenewalSource::Ari => "ari",
                            RenewalSource::LifetimeFallback => "lifetime-fallback",
                        },
                        renewal.renew_at_unix,
                        renewal.requery_ari_at_unix,
                        renewal.not_after_unix,
                        renewal.failure_count,
                    )
                });
            let _ = writeln!(
                output_text,
                "cert-status|status=PASS|identity={identity}|policy_generation={}|generation={generation}|identifiers={names}|health={health}|renewal_source={source}|renew_at={renew_at}|ari_requery_at={requery_at}|expires={expires}|failures={failures}|renewal_in_progress={}",
                status.policy_generation,
                status.renewal_in_progress()
            );
        }
    }
    output_text
}

#[cfg(not(mrml_stage_zero))]
fn expiry_health_name(health: ExpiryHealth) -> &'static str {
    match health {
        ExpiryHealth::Healthy => "healthy",
        ExpiryHealth::Warning => "warning",
        ExpiryHealth::Critical => "critical",
        ExpiryHealth::Expired => "expired",
    }
}

#[cfg(not(mrml_stage_zero))]
fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(not(mrml_stage_zero))]
fn decode_fixed_hex<const N: usize>(input: &str) -> Option<[u8; N]> {
    if input.len() != N * 2
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut output = [0u8; N];
    for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(output)
}

#[cfg(not(mrml_stage_zero))]
fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn cert_caa_command(args: &[String]) -> Result<(), String> {
    let operation = args
        .first()
        .map(String::as_str)
        .ok_or("CertificateCaaUsageError { expected: recommend|verify ISSUER ... }")?;
    let issuer = args
        .get(1)
        .map(String::as_str)
        .ok_or("CertificateCaaIssuerMissing")?;
    let mut allow_http01 = false;
    let mut allow_tls_alpn01 = false;
    let mut allow_dns01 = false;
    let mut wildcard = false;
    let mut account_uri = None;
    let mut output = OutputMode::Human;
    let mut method = None;
    let mut records = Vec::new();
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--http-01" => allow_http01 = true,
            "--tls-alpn-01" => allow_tls_alpn01 = true,
            "--dns-01" => allow_dns01 = true,
            "--wildcard" => wildcard = true,
            "--account-uri" => {
                index += 1;
                account_uri = Some(
                    args.get(index)
                        .map(String::as_str)
                        .ok_or("CertificateCaaAccountUriMissing")?,
                );
            }
            "--method" => {
                index += 1;
                method = Some(match args.get(index).map(String::as_str) {
                    Some("http-01") => CaaChallengeMethod::Http01,
                    Some("tls-alpn-01") => CaaChallengeMethod::TlsAlpn01,
                    Some("dns-01") => CaaChallengeMethod::Dns01,
                    _ => return Err("CertificateCaaMethodInvalid".into()),
                });
            }
            "--record" => {
                index += 1;
                let record = args
                    .get(index)
                    .map(String::as_str)
                    .ok_or("CertificateCaaRecordMissing")?;
                if records.len() == MAX_CAA_RECORDS {
                    return Err("CertificateCaaRecordLimitExceeded".into());
                }
                records.push(record);
            }
            "--output" => {
                index += 1;
                output = match args.get(index).map(String::as_str) {
                    Some("structured") => OutputMode::Structured,
                    Some("human") => OutputMode::Human,
                    _ => return Err("CertificateCaaOutputInvalid".into()),
                };
            }
            option => {
                return Err(format!(
                    "CertificateCaaUnknownOption {{ option: {option} }}"
                ));
            }
        }
        index += 1;
    }
    let policy = CaaPolicy {
        issuer_domain: issuer,
        allow_http01,
        allow_tls_alpn01,
        allow_dns01,
        allow_wildcard: wildcard,
        account_uri,
    };
    match operation {
        "recommend" => {
            if method.is_some() || !records.is_empty() {
                return Err("CertificateCaaRecommendUnexpectedVerificationInput".into());
            }
            let mut rendered = [0; MAX_CAA_RECORD_BYTES];
            let written = policy
                .write_recommended_records(&mut rendered)
                .map_err(|error| format!("CertificateCaaPolicyInvalid {{ detail: {error:?} }}"))?;
            let records = std::str::from_utf8(&rendered[..written])
                .map_err(|_| "CertificateCaaEncodingInvalid")?;
            match output {
                OutputMode::Human => print!("{records}"),
                OutputMode::Structured => println!(
                    "cert-caa|operation=recommend|status=PASS|issuer={issuer}|wildcard={wildcard}|records={}",
                    records.trim_end().replace('\n', "\\n")
                ),
            }
            Ok(())
        }
        "verify" => {
            let method = method.ok_or("CertificateCaaMethodMissing")?;
            policy
                .authorize_observed(&records, wildcard, method)
                .map_err(|error| format!("CertificateCaaUnauthorized {{ detail: {error:?} }}"))?;
            match output {
                OutputMode::Human => println!("CAA policy authorizes the exact requested issuance"),
                OutputMode::Structured => println!(
                    "cert-caa|operation=verify|status=PASS|issuer={issuer}|wildcard={wildcard}|records={}",
                    records.len()
                ),
            }
            Ok(())
        }
        _ => Err("CertificateCaaUsageError { expected: recommend|verify ISSUER ... }".into()),
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ExperimentalLinkRequest<'a> {
    inputs: Vec<&'a str>,
    entry: &'a str,
    output: &'a str,
    release: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct ExperimentalCompileRequest<'a> {
    input: &'a str,
    function: &'a str,
    output: &'a str,
    release: bool,
}

fn validate_experimental_compiler_mode(args: &[String], operation: &str) -> Result<(), String> {
    let Some(mode) = args.first().map(String::as_str) else {
        return Err("CompilerModeMissing".into());
    };
    match mode {
        "mrml-rustc-experimental" => Ok(()),
        "mrml-rustc-production" => {
            Err("CompilerModeUnavailable { mode: MrmlRustcProduction }".into())
        }
        "upstream-rustc" => Err(format!(
            "CompilerOperationUnsupported {{ mode: UpstreamRustc, operation: {operation} }}"
        )),
        other => Err(format!("CompilerModeInvalid {{ mode: {other} }}")),
    }
}

fn parse_experimental_link_request<'a>(
    args: &'a [String],
    expected_operation: &str,
) -> Result<ExperimentalLinkRequest<'a>, String> {
    validate_experimental_compiler_mode(args, expected_operation)?;
    if args.get(1).map(String::as_str) != Some(expected_operation) {
        return Err(format!(
            "CompilerOperationInvalid {{ expected: {expected_operation} }}"
        ));
    }
    let release = args.iter().any(|argument| argument == "--release");
    if args
        .iter()
        .filter(|argument| *argument == "--release")
        .count()
        > 1
    {
        return Err("InvalidOption { option: --release }".into());
    }
    let filtered = args
        .iter()
        .skip(2)
        .filter(|argument| argument.as_str() != "--release")
        .map(String::as_str)
        .collect::<Vec<_>>();
    let Some(entry_marker) = filtered.iter().position(|argument| *argument == "--entry") else {
        return Err("MissingOptionValue { option: --entry }".into());
    };
    if entry_marker == 0
        || filtered.get(entry_marker + 1).is_none()
        || filtered.get(entry_marker + 2) != Some(&"-o")
        || filtered.get(entry_marker + 3).is_none()
        || filtered.len() != entry_marker + 4
    {
        return Err("CompilerLinkSyntaxError".into());
    }
    let inputs = filtered[..entry_marker].to_vec();
    if inputs.iter().any(|input| input.starts_with('-')) {
        return Err("CompilerLinkInputInvalid".into());
    }
    let entry = filtered[entry_marker + 1];
    let output = filtered[entry_marker + 3];
    if entry.is_empty() || entry.starts_with('-') || output.is_empty() || output.starts_with('-') {
        return Err("CompilerLinkSyntaxError".into());
    }
    Ok(ExperimentalLinkRequest {
        inputs,
        entry,
        output,
        release,
    })
}

fn parse_experimental_compile_request<'a>(
    args: &'a [String],
    expected_operation: &str,
) -> Result<ExperimentalCompileRequest<'a>, String> {
    validate_experimental_compiler_mode(args, expected_operation)?;
    if args.get(1).map(String::as_str) != Some(expected_operation) {
        return Err(format!(
            "CompilerOperationInvalid {{ expected: {expected_operation} }}"
        ));
    }
    let release = args.iter().any(|argument| argument == "--release");
    if args
        .iter()
        .filter(|argument| *argument == "--release")
        .count()
        > 1
    {
        return Err("InvalidOption { option: --release }".into());
    }
    let filtered = args
        .iter()
        .skip(2)
        .filter(|argument| argument.as_str() != "--release")
        .map(String::as_str)
        .collect::<Vec<_>>();
    if filtered.len() != 5 || filtered[1] != "--function" || filtered[3] != "-o" {
        return Err("CompilerCompileSyntaxError".into());
    }
    let input = filtered[0];
    let function = filtered[2];
    let output = filtered[4];
    if input.is_empty()
        || input.starts_with('-')
        || function.is_empty()
        || function.starts_with('-')
        || output.is_empty()
        || output.starts_with('-')
    {
        return Err("CompilerCompileSyntaxError".into());
    }
    Ok(ExperimentalCompileRequest {
        input,
        function,
        output,
        release,
    })
}

fn compiler_command(workspace: &Workspace, args: &[String]) -> Result<(), String> {
    let operation = args.get(1).map(String::as_str);
    let (release, driver_arguments, failure, format) = match operation {
        Some(operation @ ("link-elf" | "link-pe")) => {
            let request = parse_experimental_link_request(args, operation)?;
            let (driver_operation, format) = if operation == "link-elf" {
                ("--link-elf", "ELF64")
            } else {
                ("--link-coff", "PE32+")
            };
            let mut arguments = vec![driver_operation.to_owned()];
            arguments.extend(request.inputs.into_iter().map(str::to_owned));
            arguments.extend([
                "--entry".to_owned(),
                request.entry.to_owned(),
                "-o".to_owned(),
                request.output.to_owned(),
            ]);
            (request.release, arguments, "CompilerLinkFailed", format)
        }
        Some(operation @ ("compile-elf" | "compile-pe")) => {
            let request = parse_experimental_compile_request(args, operation)?;
            let (emit, format) = if operation == "compile-elf" {
                ("elf-executable", "ELF64")
            } else {
                ("pe", "PE32+")
            };
            (
                request.release,
                vec![
                    "--emit".to_owned(),
                    emit.to_owned(),
                    "--function".to_owned(),
                    request.function.to_owned(),
                    request.input.to_owned(),
                    "-o".to_owned(),
                    request.output.to_owned(),
                ],
                "CompilerCompileFailed",
                format,
            )
        }
        _ => {
            return Err(
                "CompilerOperationInvalid { expected: link-elf|compile-elf|link-pe|compile-pe }"
                    .into(),
            );
        }
    };
    let host = host_family()?;
    let compile_target = default_rust_target(host)?;
    let mut build_args = vec!["build".to_owned(), "mrml-rustc-driver".to_owned()];
    if release {
        build_args.push("--release".to_owned());
    }
    build_or_test(workspace, &build_args)?;
    let component = find_component(workspace, "mrml-rustc-driver")?;
    let action = component
        .rust_action
        .as_ref()
        .ok_or("NativeActionDisappeared")?;
    let binary = action
        .binaries
        .iter()
        .find(|binary| binary.output == "mrml-rustc")
        .ok_or("CompilerDriverBinaryMissing")?;
    let driver = native_output_dir(workspace, host, compile_target, release)?.join(format!(
        "{}{}",
        binary.output,
        rust_binary_extension(compile_target)
    ));
    let mut command = Command::new(&driver);
    command.current_dir(&workspace.root).args(driver_arguments);
    configure_process_stack(&mut command, Some(32 * 1024 * 1024))?;
    let status = command
        .status()
        .map_err(|error| {
            format!(
                "CompilerDriverUnavailable {{ mode: MrmlRustcExperimental, path: {}, detail: {error} }}",
                driver.display()
            )
        })?;
    if !status.success() {
        return Err(format!(
            "{failure} {{ mode: MrmlRustcExperimental, format: {format}, status: {:?} }}",
            status.code()
        ));
    }
    println!(
        "mrml compiler: mode=MrmlRustcExperimental operation={} linker=mrml-rustc format={format} status=PASS",
        operation.unwrap_or("invalid")
    );
    Ok(())
}

fn derive_runtime_inventory(
    workspace: &Workspace,
    generation_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let generation = SystemGenerationView::decode(generation_bytes)
        .map_err(|error| format!("RuntimeInventoryGenerationInvalid {{ detail: {error:?} }}"))?;
    let mut records = Vec::with_capacity(generation.package_count() as usize);
    for package in generation.packages() {
        let component = workspace
            .components
            .iter()
            .find(|component| component.id == package.package_id())
            .ok_or_else(|| {
                format!(
                    "RuntimeInventoryPackageUnknown {{ package: {} }}",
                    package.package_id()
                )
            })?;
        let runtime = component.isolation.runtime().ok_or_else(|| {
            format!(
                "RuntimeInventoryClassificationMissing {{ package: {} }}",
                package.package_id()
            )
        })?;
        let class = match runtime.class() {
            isolation::RuntimeClass::MicrovmEligible => RuntimeIsolationClass::MicrovmEligible,
            isolation::RuntimeClass::HostSubstrateRequired => {
                RuntimeIsolationClass::HostSubstrateRequired
            }
            isolation::RuntimeClass::BootOnly => RuntimeIsolationClass::BootOnly,
            isolation::RuntimeClass::RecoveryOnly => RuntimeIsolationClass::RecoveryOnly,
            isolation::RuntimeClass::UnsupportedBlocker => {
                RuntimeIsolationClass::UnsupportedBlocker
            }
        };
        let map_placement = |placement: isolation::IsolationPlacement| match placement {
            isolation::IsolationPlacement::InProcess => RuntimeIsolationPlacement::InProcess,
            isolation::IsolationPlacement::NativeProcess => {
                RuntimeIsolationPlacement::NativeProcess
            }
            isolation::IsolationPlacement::NativeService => {
                RuntimeIsolationPlacement::NativeService
            }
            isolation::IsolationPlacement::Microvm => RuntimeIsolationPlacement::Microvm,
            isolation::IsolationPlacement::Platform => RuntimeIsolationPlacement::Platform,
        };
        let supported = component
            .isolation
            .supported()
            .iter()
            .copied()
            .fold(0, |bits, placement| bits | map_placement(placement).bit());
        records.push(RuntimeInventoryRecord {
            package_id: package.package_id(),
            version: package.version(),
            artifact_digest: package.artifact_digest(),
            class,
            must_run: runtime.must_run(),
            preferred: map_placement(component.isolation.preferred()),
            minimum: map_placement(component.isolation.minimum()),
            maximum: map_placement(component.isolation.maximum()),
            supported,
            reason: runtime.reason(),
        });
    }
    let mut output = vec![0; MAX_RUNTIME_INVENTORY_BYTES];
    let length = encode_runtime_inventory(generation.generation(), &records, &mut output)
        .map_err(|error| format!("RuntimeInventoryEncode {{ detail: {error:?} }}"))?;
    output.truncate(length);
    let inventory = RuntimeInventoryView::decode(&output)
        .map_err(|error| format!("RuntimeInventoryDecode {{ detail: {error:?} }}"))?;
    inventory
        .validate_system_generation(generation)
        .map_err(|error| format!("RuntimeInventoryGenerationMismatch {{ detail: {error:?} }}"))?;
    Ok(output)
}

fn release_command(workspace: &Workspace, args: &[String]) -> Result<(), String> {
    let operation = match args.first().map(String::as_str) {
        Some("create") if matches!(args.len(), 6 | 7) => "release-create",
        Some("verify") if args.len() == 3 => "release-verify",
        Some("system-create") if matches!(args.len(), 5 | 6) => "system-release-create",
        Some("system-verify") if args.len() == 3 => "system-release-verify",
        Some("runtime-inventory-create") if args.len() == 3 => "runtime-inventory-create",
        _ => {
            return Err(
                "ReleaseUsageError { expected: create VERSION BOOTLOADER.mrp KERNEL.mrp CONFIGURATION.mrp PRIVATE_KEY [OUTPUT.mrs] | verify RELEASE.mrs PUBLIC_KEY | runtime-inventory-create GENERATION.mrmlbin OUTPUT.mrmlbin | system-create GENERATION.mrmlbin INTERFACES.mrmlbin [RUNTIME.mrmlbin] PRIVATE_KEY OUTPUT.mrs | system-verify RELEASE.mrs PUBLIC_KEY }"
                    .into(),
            );
        }
    };
    let mut package_args = args.to_vec();
    package_args[0] = operation.into();
    package_command(workspace, &package_args)
}

fn package_command(workspace: &Workspace, args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("runtime-inventory-create") if args.len() == 3 => {
            let generation = fs::read(&args[1])
                .map_err(|error| format!("RuntimeInventoryGenerationRead {{ detail: {error} }}"))?;
            let encoded = derive_runtime_inventory(workspace, &generation)?;
            write_new(&args[2], &encoded, "runtime-inventory")?;
            let view = RuntimeInventoryView::decode(&encoded)
                .map_err(|error| format!("RuntimeInventorySelfVerify {{ detail: {error:?} }}"))?;
            println!(
                "runtime-inventory|operation=create|status=PASS|generation={}|packages={}|bytes={}|output={}",
                view.generation(),
                view.package_count(),
                encoded.len(),
                args[2]
            );
            Ok(())
        }
        Some("adversarial-boot-fixture") if args.len() == 9 => {
            let bootloader = fs::read(&args[2]).map_err(|error| {
                format!("AdversarialBootFixtureRead {{ role: bootloader, detail: {error} }}")
            })?;
            let configuration = fs::read(&args[3]).map_err(|error| {
                format!("AdversarialBootFixtureRead {{ role: configuration, detail: {error} }}")
            })?;
            let kernel = fs::read(&args[4]).map_err(|error| {
                format!("AdversarialBootFixtureRead {{ role: kernel, detail: {error} }}")
            })?;
            let mut package_private = fs::read(&args[5]).map_err(|error| {
                format!("AdversarialBootFixtureKeyRead {{ role: package, detail: {error} }}")
            })?;
            let mut release_private = fs::read(&args[6]).map_err(|error| {
                format!("AdversarialBootFixtureKeyRead {{ role: release, detail: {error} }}")
            })?;
            let result = package::build_adversarial_boot_fixture(
                &args[1],
                &bootloader,
                &configuration,
                &kernel,
                &package_private,
                &release_private,
            );
            package_private.fill(0);
            release_private.fill(0);
            fs::remove_file(&args[5]).map_err(|error| {
                format!("AdversarialBootFixtureKeyConsume {{ role: package, detail: {error} }}")
            })?;
            fs::remove_file(&args[6]).map_err(|error| {
                format!("AdversarialBootFixtureKeyConsume {{ role: release, detail: {error} }}")
            })?;
            let (kernel, release) = result
                .map_err(|error| format!("AdversarialBootFixtureBuild {{ detail: {error:?} }}"))?;
            write_new(&args[7], &kernel, "adversarial-kernel-package")?;
            write_new(&args[8], &release, "adversarial-system-release")?;
            println!(
                "package-adversarial-fixture|status=PASS|case={}|kernel_bytes={}|release_bytes={}|one_time_keys=2",
                args[1],
                kernel.len(),
                release.len()
            );
            Ok(())
        }
        Some("release-create") if matches!(args.len(), 6 | 7) => {
            let version = args[1]
                .parse::<u64>()
                .map_err(|_| "ReleaseVersionInvalid".to_owned())?;
            let bootloader = fs::read(&args[2]).map_err(|error| {
                format!("ReleasePackageReadError {{ role: bootloader, detail: {error} }}")
            })?;
            let kernel = fs::read(&args[3]).map_err(|error| {
                format!("ReleasePackageReadError {{ role: kernel, detail: {error} }}")
            })?;
            let configuration = fs::read(&args[4]).map_err(|error| {
                format!("ReleasePackageReadError {{ role: configuration, detail: {error} }}")
            })?;
            let mut private = fs::read(&args[5])
                .map_err(|error| format!("ReleaseKeyReadError {{ detail: {error} }}"))?;
            let encoded =
                package::build_release(version, &bootloader, &kernel, &configuration, &private)
                    .map_err(|error| format!("ReleaseBuildError {{ detail: {error:?} }}"))?;
            private.fill(0);
            fs::remove_file(&args[5])
                .map_err(|error| format!("ReleaseKeyConsumeError {{ detail: {error} }}"))?;
            let output_path = args.get(6).cloned().unwrap_or(
                package::default_release_filename(version)
                    .map_err(|error| format!("ReleaseOutputNameError {{ detail: {error:?} }}"))?,
            );
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output_path)
                .map_err(|error| format!("ReleaseOutputCreateError {{ detail: {error} }}"))?;
            output
                .write_all(&encoded)
                .and_then(|_| output.sync_all())
                .map_err(|error| format!("ReleaseOutputWriteError {{ detail: {error} }}"))?;
            println!(
                "system-release|operation=create|status=PASS|version={version}|packages=3|bytes={}|output={output_path}",
                encoded.len()
            );
            Ok(())
        }
        Some("release-verify") if args.len() == 3 => {
            let bytes = fs::read(&args[1])
                .map_err(|error| format!("ReleaseReadError {{ detail: {error} }}"))?;
            let public = fs::read(&args[2])
                .map_err(|error| format!("ReleaseRootReadError {{ detail: {error} }}"))?;
            let release = boot_release_core::parse_release(&bytes, true)
                .map_err(|error| format!("ReleaseVerifyError {{ detail: {error:?} }}"))?;
            if public.len() != LAMPORT_PUBLIC_KEY_BYTES
                || Sha3_512::digest(&public) != release.key_id
            {
                return Err("ReleaseTrustRootMismatch".into());
            }
            println!(
                "system-release|operation=verify|status=PASS|version={}|packages=3|digest={}",
                release.version,
                release
                    .digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            Ok(())
        }
        Some("system-release-create") if matches!(args.len(), 5 | 6) => {
            let generation = fs::read(&args[1])
                .map_err(|error| format!("SystemReleaseGenerationRead {{ detail: {error} }}"))?;
            let catalog = fs::read(&args[2])
                .map_err(|error| format!("SystemReleaseCatalogRead {{ detail: {error} }}"))?;
            let (runtime, private_index, output_index) = if args.len() == 6 {
                (
                    Some(fs::read(&args[3]).map_err(|error| {
                        format!("SystemReleaseRuntimeInventoryRead {{ detail: {error} }}")
                    })?),
                    4,
                    5,
                )
            } else {
                (None, 3, 4)
            };
            let mut private = fs::read(&args[private_index])
                .map_err(|error| format!("SystemReleaseKeyRead {{ detail: {error} }}"))?;
            let encoded = if let Some(runtime) = runtime.as_deref() {
                package::build_system_release_with_runtime_inventory(
                    &generation,
                    &catalog,
                    runtime,
                    &private,
                )
            } else {
                package::build_system_release(&generation, &catalog, &private)
            }
            .map_err(|error| format!("SystemReleaseBuild {{ detail: {error:?} }}"))?;
            private.fill(0);
            fs::remove_file(&args[private_index])
                .map_err(|error| format!("SystemReleaseKeyConsume {{ detail: {error} }}"))?;
            write_new(&args[output_index], &encoded, "general-system-release")?;
            let release = parse_system_release(&encoded)
                .map_err(|error| format!("SystemReleaseSelfVerify {{ detail: {error:?} }}"))?;
            println!(
                "system-release|operation=create-general|status=PASS|generation={}|runtime_inventory={}|bytes={}|output={}",
                release.generation().generation(),
                u8::from(release.runtime_inventory().is_some()),
                encoded.len(),
                args[output_index]
            );
            Ok(())
        }
        Some("system-release-verify") if args.len() == 3 => {
            let bytes = fs::read(&args[1])
                .map_err(|error| format!("SystemReleaseRead {{ detail: {error} }}"))?;
            let public = fs::read(&args[2])
                .map_err(|error| format!("SystemReleaseRootRead {{ detail: {error} }}"))?;
            let release = parse_system_release(&bytes)
                .map_err(|error| format!("SystemReleaseVerify {{ detail: {error:?} }}"))?;
            if public.len() != LAMPORT_PUBLIC_KEY_BYTES
                || Sha3_512::digest(&public) != release.key_id()
            {
                return Err("SystemReleaseTrustRootMismatch".into());
            }
            println!(
                "system-release|operation=verify-general|status=PASS|generation={}|runtime_inventory={}|digest={}",
                release.generation().generation(),
                u8::from(release.runtime_inventory().is_some()),
                release
                    .content_digest()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            Ok(())
        }
        Some("boot-media-create") => qemu_boot::create_media(&args[1..]),
        Some("qemu-boot") => qemu_boot::run_qemu(&args[1..]),
        Some("create") if args.len() >= 7 => {
            let id = &args[1];
            if !workspace
                .components
                .iter()
                .any(|component| component.id == *id)
            {
                return Err(format!("PackageIdentityUnknown {{ package: {id} }}"));
            }
            let class = &args[2];
            let version = args[3]
                .parse::<u64>()
                .map_err(|_| "PackageVersionInvalid".to_owned())?;
            let architecture = &args[4];
            let purpose = &args[5];
            let input_path = Path::new(&args[6]);
            let explicit_output = args.get(7).filter(|value| !value.starts_with("--"));
            let option_start = if explicit_output.is_some() { 8 } else { 7 };
            let default_output = package::default_package_filename(id, version)
                .map_err(|error| format!("PackageOutputNameError {{ detail: {error:?} }}"))?;
            let output_path = Path::new(explicit_output.unwrap_or(&default_output));
            let options = &args[option_start..];
            let compress = options.iter().any(|arg| arg == "--compress");
            let private_path = options
                .windows(2)
                .find(|pair| pair[0] == "--private-key")
                .map(|pair| pair[1].as_str());
            if options
                .iter()
                .any(|arg| arg.starts_with("--") && arg != "--compress" && arg != "--private-key")
            {
                return Err("PackageUsageError { unknown_option }".into());
            }
            let input = fs::read(input_path)
                .map_err(|error| format!("PackageInputReadError {{ detail: {error} }}"))?;
            if input.is_empty() || input.len() > package::MAX_PAYLOAD_BYTES {
                return Err(format!("PackageInputSize {{ bytes: {} }}", input.len()));
            }
            let mut private = private_path
                .map(fs::read)
                .transpose()
                .map_err(|error| format!("PackageKeyReadError {{ detail: {error} }}"))?;
            let encoded = package::build(
                id,
                class,
                version,
                &[package::BuildPayload {
                    name: purpose,
                    purpose,
                    architecture,
                    compress,
                    bytes: &input,
                }],
                private.as_deref(),
            )
            .map_err(|error| format!("PackageBuildError {{ detail: {error:?} }}"))?;
            if let Some(private) = private.as_mut() {
                private.fill(0);
            }
            if let Some(path) = private_path {
                fs::remove_file(path)
                    .map_err(|error| format!("PackageKeyConsumeError {{ detail: {error} }}"))?;
            }
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output_path)
                .map_err(|error| format!("PackageOutputCreateError {{ detail: {error} }}"))?;
            output
                .write_all(&encoded)
                .and_then(|_| output.sync_all())
                .map_err(|error| format!("PackageOutputWriteError {{ detail: {error} }}"))?;
            println!(
                "package|operation=create|status=PASS|id={id}|class={class}|version={version}|architecture={architecture}|purpose={purpose}|compression={}|signed={}|bytes={}|output={}",
                if compress { "zstd" } else { "none" },
                private.is_some(),
                encoded.len(),
                output_path.display()
            );
            Ok(())
        }
        Some("verify") if args.len() >= 2 => {
            let require_signature = args.iter().any(|arg| arg == "--require-signature");
            let structured = args
                .windows(2)
                .any(|pair| pair == ["--output", "structured"]);
            let bytes = fs::read(&args[1])
                .map_err(|error| format!("PackageReadError {{ detail: {error} }}"))?;
            let verification_started = Instant::now();
            let parsed = package::parse(&bytes, require_signature)
                .map_err(|error| format!("PackageVerifyError {{ detail: {error:?} }}"))?;
            let parse_signature_us = verification_started.elapsed().as_micros();
            let decode_started = Instant::now();
            for payload in &parsed.payloads {
                let mut decoded = vec![0_u8; payload.raw_len];
                payload.decode(&mut decoded).map_err(|error| {
                    format!(
                        "PackagePayloadVerifyError {{ name: {}, detail: {error:?} }}",
                        payload.name
                    )
                })?;
            }
            let decode_us = decode_started.elapsed().as_micros();
            let total_us = verification_started.elapsed().as_micros();
            let sizes = package::size_breakdown(&parsed, bytes.len())
                .map_err(|error| format!("PackageSizeError {{ detail: {error:?} }}"))?;
            if structured {
                for payload in &parsed.payloads {
                    println!(
                        "package-payload|name={}|purpose={}|architecture={}|compression={}|stored_bytes={}|raw_bytes={}",
                        payload.name,
                        payload.purpose,
                        payload.architecture,
                        payload.compression,
                        payload.bytes.len(),
                        payload.raw_len
                    );
                }
                println!(
                    "package-measure|total_bytes={}|raw_payload_bytes={}|stored_payload_bytes={}|format_metadata_bytes={}|signature_bytes={}|parse_signature_us={parse_signature_us}|decode_us={decode_us}|total_us={total_us}|samples=1",
                    sizes.total_bytes,
                    sizes.raw_payload_bytes,
                    sizes.stored_payload_bytes,
                    sizes.format_metadata_bytes,
                    sizes.signature_bytes,
                );
            }
            let digest = parsed
                .content_digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            println!(
                "package-verify|status=PASS|format=1|id={}|class={}|version={}|signed={}|payloads={}|digest={digest}",
                parsed.id,
                parsed.class,
                parsed.version,
                parsed.signed,
                parsed.payloads.len()
            );
            Ok(())
        }
        _ => Err("PackageUsageError { expected: create | verify }".into()),
    }
}

fn write_new(path: &str, bytes: &[u8], role: &str) -> Result<(), String> {
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("OutputCreateError {{ role: {role}, detail: {error} }}"))?;
    output
        .write_all(bytes)
        .and_then(|_| output.sync_all())
        .map_err(|error| format!("OutputWriteError {{ role: {role}, detail: {error} }}"))
}

mod qemu_boot;
mod usb_image;
mod usb_media;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod usb_polkit;
mod usb_transfer;

fn manifest_command(workspace: &Workspace, args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("check") if args.len() == 1 => {
            let graph = verify_native_graph(workspace)?;
            println!(
                "manifest|status=PASS|format=mrml|version=2|components={}|dependencies={}",
                workspace.components.len(),
                graph.dependency_count
            );
            Ok(())
        }
        Some("fmt") => {
            let check = args.get(1).map(String::as_str) == Some("--check");
            if args.len() > usize::from(check) + 1 {
                return Err("ManifestUsageError { expected: fmt [--check] }".into());
            }
            let mut paths = vec![workspace.root.join("mrml.toml")];
            paths.extend(
                workspace
                    .components
                    .iter()
                    .map(|component| workspace.root.join(&component.path).join("mrml.toml")),
            );
            let mut changed = 0_usize;
            for path in paths {
                let label = path
                    .strip_prefix(&workspace.root)
                    .unwrap_or(&path)
                    .to_string_lossy();
                let text = read_bounded_manifest(&path, &label)?;
                let canonical = ManifestDocument::parse(text.as_bytes())
                    .map_err(|error| manifest_error(&label, error))?
                    .canonical();
                if text != canonical {
                    changed = changed.checked_add(1).ok_or("ManifestCountOverflow")?;
                    if !check {
                        let mut output = fs::OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .open(&path)
                            .map_err(|error| {
                                format!("ManifestWriteError {{ file: {label}, detail: {error} }}")
                            })?;
                        output.write_all(canonical.as_bytes()).map_err(|error| {
                            format!("ManifestWriteError {{ file: {label}, detail: {error} }}")
                        })?;
                        output.sync_all().map_err(|error| {
                            format!("ManifestSyncError {{ file: {label}, detail: {error} }}")
                        })?;
                    }
                }
            }
            if check && changed != 0 {
                return Err(format!("ManifestFormattingRequired {{ files: {changed} }}"));
            }
            println!("manifest-fmt|status=PASS|changed={changed}|check={check}");
            Ok(())
        }
        Some("lock") => {
            let check = args.get(1).map(String::as_str) == Some("--check");
            if args.len() > usize::from(check) + 1 {
                return Err("ManifestUsageError { expected: lock [--check] }".into());
            }
            write_workspace_lock(workspace, check)
        }
        Some("migrate") if args.len() == 3 => {
            let packages = migration::migrate(Path::new(&args[1]), Path::new(&args[2]))?;
            println!("manifest-migrate|status=PASS|source=v1|destination=v2|packages={packages}");
            Ok(())
        }
        _ => Err(
            "ManifestUsageError { expected: check | fmt [--check] | lock [--check] | migrate }"
                .into(),
        ),
    }
}

fn write_workspace_lock(workspace: &Workspace, check: bool) -> Result<(), String> {
    let mut components = workspace.components.iter().collect::<Vec<_>>();
    components.sort_by(|left, right| left.id.cmp(&right.id));
    let mut encoded = String::from(
        "[lock]\nformat = \"mrml-workspace-lock\"\nversion = 2\ntoolchain = \"nightly-2026-11-26\"\n\n",
    );
    let compile_edges = workspace
        .components
        .iter()
        .map(|component| component.dependencies.len())
        .sum::<usize>();
    const SYSTEM_RELEASE: [(&str, &str); 3] = [
        ("bootloader", "org.mrml.library.uefi"),
        ("kernel", "org.mrml.system.kernel"),
        ("configuration", "org.mrml.service.config"),
    ];
    for (_, package) in SYSTEM_RELEASE {
        if !workspace
            .components
            .iter()
            .any(|candidate| candidate.id == package)
        {
            return Err(format!(
                "SystemReleasePackageMissing {{ package: {package} }}"
            ));
        }
    }
    encoded.push_str("[graphs]\n");
    encoded.push_str(&format!("compile_edges = {compile_edges}\n"));
    encoded.push_str("build_tool_edges = 0\n");
    encoded.push_str(&format!(
        "runtime_interface_edges = {}\n",
        workspace.interface_bindings.len()
    ));
    let package_edges = workspace
        .components
        .iter()
        .map(|component| {
            classified_package_dependencies(workspace, component).map(|edges| edges.len())
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<usize>();
    encoded.push_str(&format!("package_edges = {package_edges}\n"));
    encoded.push_str(&format!(
        "system_release_edges = {}\n\n",
        SYSTEM_RELEASE.len()
    ));
    for component in components {
        let mut dependencies = component
            .dependencies
            .iter()
            .map(|name| {
                workspace
                    .components
                    .iter()
                    .find(|candidate| &candidate.cargo_package == name)
                    .map(|candidate| candidate.id.as_str())
                    .ok_or_else(|| {
                        format!(
                            "WorkspaceLockDependencyMissing {{ component: {}, dependency: {name} }}",
                            component.id
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        dependencies.sort_unstable();
        encoded.push_str("[[package]]\n");
        encoded.push_str(&format!("id = \"{}\"\n", component.id));
        encoded.push_str(&format!("path = \"{}\"\n", component.path));
        encoded.push_str(&format!(
            "isolation_default = \"{}\"\n",
            component.isolation.preferred().token()
        ));
        encoded.push_str(&format!(
            "isolation_minimum = \"{}\"\n",
            component.isolation.minimum().token()
        ));
        encoded.push_str(&format!(
            "isolation_maximum = \"{}\"\n",
            component.isolation.maximum().token()
        ));
        encoded.push_str("isolation_supported = [");
        for (index, placement) in component.isolation.supported().iter().enumerate() {
            if index != 0 {
                encoded.push_str(", ");
            }
            encoded.push('"');
            encoded.push_str(placement.token());
            encoded.push('"');
        }
        encoded.push_str("]\n");
        encoded.push_str("compile_dependencies = [");
        for (index, dependency) in dependencies.iter().enumerate() {
            if index != 0 {
                encoded.push_str(", ");
            }
            encoded.push('"');
            encoded.push_str(dependency);
            encoded.push('"');
        }
        encoded.push_str("]\n\n");
        let classified = classified_package_dependencies(workspace, component)?;
        for class in ["STATIC_RUNTIME", "BOOT_BOUND", "SYSTEM_RELEASE_BOUND"] {
            encoded.push_str(&format!("{} = [", class.to_ascii_lowercase()));
            let matches = classified
                .iter()
                .filter(|(_, edge_class)| edge_class == &class)
                .map(|(package, _)| package.as_str())
                .collect::<Vec<_>>();
            for (index, package) in matches.iter().enumerate() {
                if index != 0 {
                    encoded.push_str(", ");
                }
                encoded.push('"');
                encoded.push_str(package);
                encoded.push('"');
            }
            encoded.push_str("]\n");
        }
        encoded.push('\n');
    }
    for binding in &workspace.interface_bindings {
        encoded.push_str("[[interface_binding]]\n");
        encoded.push_str(&format!("consumer = \"{}\"\n", binding.consumer));
        encoded.push_str(&format!("interface = \"{}\"\n", binding.interface));
        encoded.push_str(&format!("generation = {}\n", binding.generation));
        encoded.push_str(&format!("fingerprint = \"{}\"\n", binding.fingerprint));
        encoded.push_str(&format!("provider = \"{}\"\n", binding.provider));
        encoded.push_str(&format!("form = \"{}\"\n", binding.form));
        encoded.push_str("targets = [");
        for (index, target) in binding.targets.iter().enumerate() {
            if index != 0 {
                encoded.push_str(", ");
            }
            encoded.push('"');
            encoded.push_str(target);
            encoded.push('"');
        }
        encoded.push_str("]\n\n");
    }
    for (role, package) in SYSTEM_RELEASE {
        encoded.push_str("[[system_release_package]]\n");
        encoded.push_str(&format!("role = \"{role}\"\n"));
        encoded.push_str(&format!("package = \"{package}\"\n\n"));
    }
    if encoded.ends_with("\n\n") {
        encoded.pop();
    }
    let canonical = encoded;
    let path = workspace.root.join("mrml.lock");
    let current = fs::read_to_string(&path).ok();
    if check && current.as_deref() != Some(canonical.as_str()) {
        return Err("WorkspaceLockOutOfDate".into());
    }
    if !check && current.as_deref() != Some(canonical.as_str()) {
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|error| format!("WorkspaceLockWriteError {{ detail: {error} }}"))?;
        output
            .write_all(canonical.as_bytes())
            .and_then(|_| output.sync_all())
            .map_err(|error| format!("WorkspaceLockWriteError {{ detail: {error} }}"))?;
    }
    println!(
        "manifest-lock|status=PASS|packages={}|interfaces={}|check={check}",
        workspace.components.len(),
        workspace.interface_bindings.len()
    );
    Ok(())
}

fn classified_package_dependencies(
    workspace: &Workspace,
    component: &Component,
) -> Result<Vec<(String, &'static str)>, String> {
    let action = component.rust_action.as_ref().ok_or_else(|| {
        format!(
            "DependencyClassificationActionMissing {{ package: {} }}",
            component.id
        )
    })?;
    let mut classified = Vec::new();
    for external in &action.externs {
        if external.test_only {
            continue;
        }
        let provider = workspace
            .components
            .iter()
            .find(|candidate| candidate.cargo_package == external.package)
            .ok_or_else(|| {
                format!(
                    "DependencyClassificationProviderMissing {{ package: {}, dependency: {} }}",
                    component.id, external.package
                )
            })?;
        if provider.class == "SHARED" && provider.id.starts_with("org.mrml.interface.") {
            continue;
        }
        let class = match component.id.as_str() {
            "org.mrml.system.bootloader" | "org.mrml.library.uefi" => "BOOT_BOUND",
            "org.mrml.system.service-image" => "SYSTEM_RELEASE_BOUND",
            _ => "STATIC_RUNTIME",
        };
        classified.push((provider.id.clone(), class));
    }
    classified.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(classified)
}

fn interface_command(args: &[String]) -> Result<(), String> {
    if args.len() != 3 || args[0] != "generate-rust" {
        return Err("InterfaceUsageError { expected: generate-rust SCHEMA OUTPUT }".into());
    }
    let input_path = Path::new(&args[1]);
    let metadata = fs::metadata(input_path)
        .map_err(|error| format!("InterfaceSchemaMetadataError {{ detail: {error} }}"))?;
    if metadata.len() == 0 || metadata.len() > schema::MAX_INTERFACE_SCHEMA_BYTES as u64 {
        return Err(format!(
            "InterfaceSchemaLengthError {{ bytes: {} }}",
            metadata.len()
        ));
    }
    let bytes = fs::read(input_path)
        .map_err(|error| format!("InterfaceSchemaReadError {{ detail: {error} }}"))?;
    let schema = InterfaceSchema::parse(&bytes)
        .map_err(|error| format!("InterfaceSchemaError {{ detail: {error:?} }}"))?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[2])
        .map_err(|error| format!("InterfaceOutputCreateError {{ detail: {error} }}"))?;
    output
        .write_all(schema.generate_rust().as_bytes())
        .map_err(|error| format!("InterfaceOutputWriteError {{ detail: {error} }}"))?;
    output
        .sync_all()
        .map_err(|error| format!("InterfaceOutputSyncError {{ detail: {error} }}"))?;
    let fingerprint = schema
        .fingerprint()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    println!(
        "interface={} generation={} fingerprint={fingerprint}",
        schema.identity().name(),
        schema.identity().generation()
    );
    Ok(())
}

fn find_root() -> Result<PathBuf, String> {
    let mut current =
        env::current_dir().map_err(|e| format!("CurrentDirectoryError {{ detail: {e} }}"))?;
    loop {
        if current.join("mrml.toml").is_file() {
            return Ok(current);
        }
        if !current.pop() {
            return Err("WorkspaceNotFound { file: mrml.toml }".into());
        }
    }
}

fn read_bounded_manifest(path: &Path, label: &str) -> Result<String, String> {
    let bytes = fs::metadata(path)
        .map_err(|error| format!("ManifestMetadataError {{ file: {label}, detail: {error} }}"))?
        .len();
    if bytes == 0 || bytes > MAX_MANIFEST_BYTES {
        return Err(format!(
            "ManifestSizeLimit {{ file: {label}, bytes: {bytes}, limit: {MAX_MANIFEST_BYTES} }}"
        ));
    }
    fs::read_to_string(path)
        .map_err(|error| format!("ManifestReadError {{ file: {label}, detail: {error} }}"))
}

fn audit_workspace_admission(root: &Path, admitted: &BTreeSet<String>) -> Result<(), String> {
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0_usize;
    while let Some(directory) = pending.pop() {
        visited = visited.checked_add(1).ok_or("WorkspaceDiscoveryOverflow")?;
        if visited > MAX_DISCOVERY_DIRECTORIES {
            return Err(format!(
                "WorkspaceDiscoveryLimit {{ limit: {MAX_DISCOVERY_DIRECTORIES} }}"
            ));
        }
        let entries = fs::read_dir(&directory).map_err(|error| {
            format!(
                "WorkspaceDiscoveryReadError {{ directory: {}, detail: {error} }}",
                directory.display()
            )
        })?;
        for entry in entries {
            let entry = entry
                .map_err(|error| format!("WorkspaceDiscoveryEntryError {{ detail: {error} }}"))?;
            let file_type = entry
                .file_type()
                .map_err(|error| format!("WorkspaceDiscoveryTypeError {{ detail: {error} }}"))?;
            let name = entry.file_name();
            if file_type.is_dir() {
                if name != ".git" && name != "target" {
                    pending.push(entry.path());
                }
                continue;
            }
            if file_type.is_symlink() || name != "mrml.toml" || directory == root {
                continue;
            }
            let relative = directory
                .strip_prefix(root)
                .map_err(|_| "WorkspaceDiscoveryEscape".to_owned())?
                .to_string_lossy()
                .replace('\\', "/");
            if !admitted.contains(&relative) {
                return Err(format!(
                    "WorkspaceManifestNotAdmitted {{ path: {relative}/mrml.toml }}"
                ));
            }
        }
    }
    Ok(())
}

fn load_manifest_declarations(root: &Path) -> Result<ManifestDeclarations, String> {
    let root_text = read_bounded_manifest(&root.join("mrml.toml"), "mrml.toml")?;
    let root_document = ManifestDocument::parse(root_text.as_bytes())
        .map_err(|error| manifest_error("mrml.toml", error))?;
    let workspace = root_document
        .section("workspace")
        .map_err(|error| manifest_error("mrml.toml", error))?;
    let members = workspace
        .strings("members")
        .map_err(|error| manifest_error("mrml.toml", error))?;
    if members.len() > MAX_COMPONENTS {
        return Err(format!("ComponentCountLimit {{ limit: {MAX_COMPONENTS} }}"));
    }
    let mut seen = BTreeSet::new();
    let mut declarations = Vec::new();
    let mut declaration_bytes = 0_usize;
    let mut interface_definitions = BTreeMap::new();
    let mut providers = Vec::new();
    let mut requirements = Vec::new();
    let mut isolation_policies = BTreeMap::new();
    let mut build_inputs = BTreeMap::new();
    for member in members {
        if !safe_relative_path(member) || !seen.insert(member.clone()) {
            return Err(format!("InvalidWorkspaceMember {{ path: {member} }}"));
        }
        let relative = format!("{member}/mrml.toml");
        let manifest_text = read_bounded_manifest(&root.join(&relative), &relative)?;
        let document = ManifestDocument::parse(manifest_text.as_bytes())
            .map_err(|error| manifest_error(&relative, error))?;
        let package = document
            .section("package")
            .map_err(|error| manifest_error(&relative, error))?;
        let package_id = package
            .string("id")
            .map_err(|error| manifest_error(&relative, error))?;
        let package_kind = package
            .string("kind")
            .map_err(|error| manifest_error(&relative, error))?;
        let isolation = IsolationPolicy::parse(&document, package_kind, package_id)?;
        if isolation_policies
            .insert(package_id.to_owned(), isolation)
            .is_some()
        {
            return Err(format!(
                "DuplicateIsolationPolicy {{ package: {package_id} }}"
            ));
        }
        let package_inputs = declared_build_inputs(&document, package_id, member, root, &relative)?;
        if build_inputs
            .insert(package_id.to_owned(), package_inputs)
            .is_some()
        {
            return Err(format!(
                "DuplicateBuildInputPolicy {{ package: {package_id} }}"
            ));
        }
        let target_families: Vec<_> = document
            .array_sections("target")
            .map(v2_target_family)
            .collect::<Result<_, _>>()?;
        if let Some(interface) = document
            .sections
            .iter()
            .find(|section| !section.array && section.name == "interface")
        {
            let generation = interface
                .integer("generation")
                .map_err(|error| manifest_error(&relative, error))?;
            let fingerprint = interface
                .string("fingerprint")
                .map_err(|error| manifest_error(&relative, error))?;
            if interface_definitions
                .insert(package_id.to_owned(), (generation, fingerprint.to_owned()))
                .is_some()
            {
                return Err(format!("DuplicateInterface {{ interface: {package_id} }}"));
            }
        }
        for provider in document.array_sections("provides") {
            let binding = interface_binding(provider, &relative)?;
            let form = interface_form(provider, &relative)?;
            providers.push((
                package_id.to_owned(),
                provider
                    .string("interface")
                    .map_err(|error| manifest_error(&relative, error))?
                    .to_owned(),
                provider
                    .integer("generation")
                    .map_err(|error| manifest_error(&relative, error))?,
                provider
                    .string("fingerprint")
                    .map_err(|error| manifest_error(&relative, error))?
                    .to_owned(),
                binding.to_owned(),
                form.to_owned(),
                target_families.clone(),
            ));
        }
        for requirement in document.array_sections("requires") {
            let binding = interface_binding(requirement, &relative)?;
            let form = interface_form(requirement, &relative)?;
            let multiplicity = interface_multiplicity(requirement, &relative)?;
            validate_dynamic_requirement(package_kind, package_id)?;
            requirements.push((
                package_id.to_owned(),
                requirement
                    .string("interface")
                    .map_err(|error| manifest_error(&relative, error))?
                    .to_owned(),
                requirement
                    .integer("generation")
                    .map_err(|error| manifest_error(&relative, error))?,
                requirement
                    .string("fingerprint")
                    .map_err(|error| manifest_error(&relative, error))?
                    .to_owned(),
                binding.to_owned(),
                form.to_owned(),
                multiplicity.to_owned(),
                target_families.clone(),
            ));
        }
        for declaration in v2_declarations(&document, member, &relative)? {
            let record_bytes = declaration.iter().map(String::len).sum::<usize>();
            let next = declaration_bytes
                .checked_add(record_bytes)
                .ok_or("WorkspaceSizeOverflow")?;
            if next as u64 > MAX_WORKSPACE_BYTES {
                return Err(format!(
                    "WorkspaceSizeLimit {{ bytes: {next}, limit: {MAX_WORKSPACE_BYTES} }}"
                ));
            }
            declaration_bytes = next;
            declarations.push(declaration);
        }
    }
    audit_workspace_admission(root, &seen)?;
    for (provider, interface, generation, fingerprint, _, _, _) in &providers {
        if interface_definitions.get(interface) != Some(&(*generation, fingerprint.clone())) {
            return Err(format!(
                "InterfaceProviderInvalid {{ provider: {provider}, interface: {interface}, generation: {generation} }}"
            ));
        }
    }
    for (consumer, interface, generation, fingerprint, binding, form, _, targets) in &requirements {
        if interface_definitions.get(interface) != Some(&(*generation, fingerprint.clone())) {
            return Err(format!(
                "InterfaceRequirementInvalid {{ consumer: {consumer}, interface: {interface}, generation: {generation} }}"
            ));
        }
        if !providers.iter().any(
            |(
                _,
                provided,
                provider_generation,
                provider_fingerprint,
                provider_binding,
                provider_form,
                provider_targets,
            )| {
                provided == interface
                    && provider_generation == generation
                    && provider_fingerprint == fingerprint
                    && provider_binding == binding
                    && provider_form == form
                    && targets
                        .iter()
                        .all(|target| provider_targets.contains(target))
            },
        ) {
            return Err(format!(
                "InterfaceUnavailable {{ consumer: {consumer}, interface: {interface}, generation: {generation} }}"
            ));
        }
    }
    let mut interface_bindings = Vec::new();
    for (consumer, interface, generation, fingerprint, binding, form, multiplicity, targets) in
        requirements
    {
        let matching = providers
            .iter()
            .filter(
                |(
                    _,
                    provided,
                    provider_generation,
                    provider_fingerprint,
                    provider_binding,
                    provider_form,
                    provider_targets,
                )| {
                    provided == &interface
                        && provider_generation == &generation
                        && provider_fingerprint == &fingerprint
                        && provider_binding == &binding
                        && provider_form == &form
                        && targets
                            .iter()
                            .all(|target| provider_targets.contains(target))
                },
            )
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return Err(format!(
                "InterfaceUnavailable {{ consumer: {consumer}, interface: {interface}, generation: {generation} }}"
            ));
        }
        if multiplicity == "one" && matching.len() != 1 {
            return Err(format!(
                "InterfaceProviderAmbiguous {{ consumer: {consumer}, interface: {interface}, providers: {} }}",
                matching.len()
            ));
        }
        for provider in matching {
            interface_bindings.push(InterfaceBindingLock {
                consumer: consumer.clone(),
                interface: interface.clone(),
                generation,
                fingerprint: fingerprint.clone(),
                provider: provider.0.clone(),
                form: form.clone(),
                targets: targets.iter().map(|target| (*target).to_owned()).collect(),
            });
        }
    }
    interface_bindings.sort_by(|left, right| {
        (&left.consumer, &left.interface, &left.provider).cmp(&(
            &right.consumer,
            &right.interface,
            &right.provider,
        ))
    });
    Ok(ManifestDeclarations {
        records: declarations,
        interface_bindings,
        isolation_policies,
        build_inputs,
    })
}

fn interface_binding<'a>(
    section: &'a manifest::Section,
    relative: &str,
) -> Result<&'a str, String> {
    let binding = section
        .string("binding")
        .map_err(|error| manifest_error(relative, error))?;
    if binding != "dynamic" {
        return Err(format!(
            "InterfaceBindingInvalid {{ file: {relative}, binding: {binding} }}"
        ));
    }
    Ok(binding)
}

fn interface_form<'a>(section: &'a manifest::Section, relative: &str) -> Result<&'a str, String> {
    let form = section
        .string("form")
        .map_err(|error| manifest_error(relative, error))?;
    if !matches!(form, "in-process" | "isolated-service") {
        return Err(format!(
            "InterfaceFormInvalid {{ file: {relative}, form: {form} }}"
        ));
    }
    Ok(form)
}

fn interface_multiplicity<'a>(
    section: &'a manifest::Section,
    relative: &str,
) -> Result<&'a str, String> {
    let multiplicity = section
        .optional_string("multiplicity")
        .map_err(|error| manifest_error(relative, error))?
        .unwrap_or("one");
    if !matches!(multiplicity, "one" | "many") {
        return Err(format!(
            "InterfaceMultiplicityInvalid {{ file: {relative}, multiplicity: {multiplicity} }}"
        ));
    }
    Ok(multiplicity)
}

fn validate_dynamic_requirement(package_kind: &str, package_id: &str) -> Result<(), String> {
    if package_kind == "bootloader" {
        return Err(format!("BootDependencyInvalid {{ package: {package_id} }}"));
    }
    if package_kind == "recovery" {
        return Err(format!(
            "RecoveryDependencyInvalid {{ package: {package_id} }}"
        ));
    }
    Ok(())
}

fn manifest_error(file: &str, error: manifest::Error) -> String {
    format!("ManifestV2Error {{ file: {file}, detail: {error:?} }}")
}

fn declared_build_inputs(
    document: &ManifestDocument,
    package: &str,
    member: &str,
    root: &Path,
    file: &str,
) -> Result<Vec<input_audit::DeclaredInputSite>, String> {
    let mut declarations = Vec::new();
    for section in document.array_sections("build_input") {
        let kind_text = section
            .string("kind")
            .map_err(|error| manifest_error(file, error))?;
        // Build-script and proc-macro authority is already identified by the
        // manifest artifact declaration. Exact source-site identity applies to
        // ambient inputs discovered in Rust source.
        if matches!(kind_text, "build-script" | "proc-macro") {
            continue;
        }
        let kind = input_audit::BuildInputKind::parse(kind_text).map_err(|_| {
            format!("ManifestBuildInputInvalid {{ package: {package}, kind: {kind_text} }}")
        })?;
        let raw_line = section
            .integer("line")
            .map_err(|error| manifest_error(file, error))?;
        let line = usize::try_from(raw_line).map_err(|_| {
            format!("ManifestBuildInputLineInvalid {{ package: {package}, line: {raw_line} }}")
        })?;
        declarations.push(input_audit::DeclaredInputSite {
            id: section
                .string("id")
                .map_err(|error| manifest_error(file, error))?
                .to_owned(),
            kind,
            path: section
                .string("path")
                .map_err(|error| manifest_error(file, error))?
                .to_owned(),
            line,
            fingerprint: section
                .string("fingerprint")
                .map_err(|error| manifest_error(file, error))?
                .to_owned(),
            reason: section
                .string("reason")
                .map_err(|error| manifest_error(file, error))?
                .to_owned(),
        });
    }
    input_audit::validate_declarations(package, member, root, &declarations)?;
    Ok(declarations)
}

fn v2_target_family(section: &manifest::Section) -> Result<&'static str, String> {
    let environment = section
        .string("environment")
        .map_err(|error| manifest_error("target", error))?;
    let arch = section
        .string("arch")
        .map_err(|error| manifest_error("target", error))?;
    if arch != "x86_64" && environment != "gpu" {
        return Err(format!(
            "ManifestTargetUnsupported {{ environment: {environment}, arch: {arch} }}"
        ));
    }
    match environment {
        "windows" => Ok("WINDOWS"),
        "linux" => Ok("LINUX"),
        "mrml" => Ok("MRML_NATIVE"),
        "uefi" => Ok("UEFI"),
        "gpu" if section.optional_string("toolchain").ok().flatten() == Some("cuda-nvidia") => {
            Ok("CUDA")
        }
        _ => Err(format!(
            "ManifestTargetUnsupported {{ environment: {environment}, arch: {arch} }}"
        )),
    }
}

fn v2_build_class(kind: &str, profile: &str) -> Result<&'static str, String> {
    match (kind, profile) {
        ("bootstrap-tool", "host-tool") => Ok("BOOTSTRAP_ONLY"),
        ("compiler", "compiler") => Ok("COMPILER"),
        ("application", "system-application")
        | ("kernel", "kernel")
        | ("service", "system-service") => Ok("MRML_NATIVE"),
        ("bootloader", "uefi") => Ok("UEFI"),
        ("library", "gpu-kernel") => Ok("GPU"),
        ("test", "test") => Ok("TEST"),
        ("library", "library") | ("interface", "interface") => Ok("SHARED"),
        ("application", "host-tool") | ("tool", "host-tool") | ("vmm", "vmm") => {
            Ok("HOST_WINDOWS_LINUX")
        }
        ("experiment", "host-tool") | ("experiment", "vmm") => Ok("EXPERIMENT"),
        _ => Err(format!(
            "ManifestPackageProfileInvalid {{ kind: {kind}, profile: {profile} }}"
        )),
    }
}

fn v2_declarations(
    document: &ManifestDocument,
    member: &str,
    file: &str,
) -> Result<Vec<Vec<String>>, String> {
    let package = document
        .section("package")
        .map_err(|error| manifest_error(file, error))?;
    let id = package
        .string("id")
        .map_err(|error| manifest_error(file, error))?;
    let name = package
        .string("name")
        .map_err(|error| manifest_error(file, error))?;
    let kind = package
        .string("kind")
        .map_err(|error| manifest_error(file, error))?;
    let profile = package
        .string("profile")
        .map_err(|error| manifest_error(file, error))?;
    let default = package
        .boolean("default")
        .map_err(|error| manifest_error(file, error))?;
    let class = v2_build_class(kind, profile)?;
    let targets: Vec<_> = document
        .array_sections("target")
        .map(v2_target_family)
        .collect::<Result<_, _>>()?;
    if targets.is_empty() {
        return Err(format!("ManifestTargetMissing {{ package: {id} }}"));
    }
    let features: Vec<_> = document
        .array_sections("feature")
        .map(|section| {
            section
                .string("name")
                .map(str::to_owned)
                .map_err(|error| manifest_error(file, error))
        })
        .collect::<Result<_, _>>()?;
    let outputs: Vec<_> = document
        .array_sections("artifact")
        .map(|section| {
            Ok(format!(
                "{}:{}",
                section
                    .string("name")
                    .map_err(|error| manifest_error(file, error))?,
                section
                    .string("kind")
                    .map_err(|error| manifest_error(file, error))?
            ))
        })
        .collect::<Result<_, String>>()?;
    let dependencies: Vec<_> = document
        .array_sections("dependency")
        .filter(|section| section.optional_string("scope").ok().flatten() == Some("compile"))
        .map(|section| {
            section
                .string("compile_name")
                .map(str::to_owned)
                .map_err(|error| manifest_error(file, error))
        })
        .collect::<Result<_, _>>()?;
    let mut input_counts = InputCounts::default();
    for input in document.array_sections("build_input") {
        match input
            .string("kind")
            .map_err(|error| manifest_error(file, error))?
        {
            "build-script" => input_counts.build_scripts += 1,
            "proc-macro" => input_counts.proc_macros += 1,
            "native-link" => input_counts.native_links += 1,
            "compile-env" => input_counts.compile_env += 1,
            "included-file" => input_counts.included_files += 1,
            "external-command" => input_counts.external_commands += 1,
            other => {
                return Err(format!(
                    "ManifestBuildInputInvalid {{ package: {id}, kind: {other} }}"
                ));
            }
        }
    }
    let mut declarations = vec![vec![
        "component".into(),
        id.into(),
        member.into(),
        name.into(),
        class.into(),
        targets.join(","),
        default.to_string(),
        dependencies.join(","),
        features.join(","),
        outputs.join(","),
        input_counts.structured(),
    ]];
    let rust = document
        .section("rust")
        .map_err(|error| manifest_error(file, error))?;
    let mut externs = Vec::new();
    for dependency in document
        .array_sections("dependency")
        .filter(|section| section.optional_string("scope").ok().flatten() == Some("compile"))
    {
        let compile_name = dependency
            .string("compile_name")
            .map_err(|error| manifest_error(file, error))?;
        let alias = dependency
            .string("alias")
            .map_err(|error| manifest_error(file, error))?;
        let targets = dependency
            .optional_strings("targets")
            .map_err(|error| manifest_error(file, error))?;
        let mut encoded = format!(
            "{compile_name}={alias}@{}",
            if targets.is_empty() {
                "*".into()
            } else {
                targets.join(",")
            }
        );
        if let Some(feature) = dependency
            .optional_string("feature")
            .map_err(|error| manifest_error(file, error))?
        {
            encoded.push('?');
            encoded.push_str(feature);
        }
        if let Some(provider_profile) = dependency
            .optional_string("provider_profile")
            .map_err(|error| manifest_error(file, error))?
        {
            encoded.push('#');
            encoded.push_str(provider_profile);
        }
        if dependency
            .optional_boolean("test_only")
            .map_err(|error| manifest_error(file, error))?
            == Some(true)
        {
            encoded.push_str("!test");
        }
        externs.push(encoded);
    }
    declarations.push(vec![
        "action".into(),
        id.into(),
        rust.string("crate_name")
            .map_err(|error| manifest_error(file, error))?
            .into(),
        rust.string("crate_type")
            .map_err(|error| manifest_error(file, error))?
            .into(),
        rust.string("source")
            .map_err(|error| manifest_error(file, error))?
            .into(),
        externs.join(";"),
    ]);
    for (section_name, record_name) in [("test", "test"), ("benchmark", "benchmark")] {
        for section in document.array_sections(section_name) {
            declarations.push(vec![
                record_name.into(),
                id.into(),
                section
                    .string("name")
                    .map_err(|error| manifest_error(file, error))?
                    .into(),
                section
                    .string("source")
                    .map_err(|error| manifest_error(file, error))?
                    .into(),
                section
                    .boolean("self_extern")
                    .map_err(|error| manifest_error(file, error))?
                    .to_string(),
            ]);
        }
    }
    for section in document.array_sections("example") {
        let targets = section
            .optional_strings("targets")
            .map_err(|error| manifest_error(file, error))?;
        let feature = section
            .optional_string("feature")
            .map_err(|error| manifest_error(file, error))?
            .unwrap_or("");
        let mut record = vec![
            "example".into(),
            id.into(),
            section
                .string("name")
                .map_err(|error| manifest_error(file, error))?
                .into(),
            section
                .string("source")
                .map_err(|error| manifest_error(file, error))?
                .into(),
        ];
        if !targets.is_empty() || !feature.is_empty() {
            record.push(if targets.is_empty() {
                "*".into()
            } else {
                targets.join(",")
            });
            record.push(feature.into());
        }
        declarations.push(record);
    }
    for section in document.array_sections("binary") {
        let targets = section
            .optional_strings("targets")
            .map_err(|error| manifest_error(file, error))?;
        let feature = section
            .optional_string("feature")
            .map_err(|error| manifest_error(file, error))?;
        let mut record = vec![
            "binary".into(),
            id.into(),
            section
                .string("output")
                .map_err(|error| manifest_error(file, error))?
                .into(),
            section
                .string("crate_name")
                .map_err(|error| manifest_error(file, error))?
                .into(),
            section
                .string("source")
                .map_err(|error| manifest_error(file, error))?
                .into(),
            section
                .boolean("self_extern")
                .map_err(|error| manifest_error(file, error))?
                .to_string(),
        ];
        if !targets.is_empty() || feature.is_some() {
            record.push(if targets.is_empty() {
                "*".into()
            } else {
                targets.join(",")
            });
            record.push(feature.unwrap_or("").into());
        }
        declarations.push(record);
    }
    for section in document.array_sections("feature_set") {
        declarations.push(vec![
            "feature-set".into(),
            id.into(),
            section
                .strings("targets")
                .map_err(|error| manifest_error(file, error))?
                .join(","),
            section
                .optional_strings("features")
                .map_err(|error| manifest_error(file, error))?
                .join(","),
        ]);
    }
    for section in document.array_sections("feature_profile") {
        declarations.push(vec![
            "feature-profile".into(),
            id.into(),
            section
                .string("name")
                .map_err(|error| manifest_error(file, error))?
                .into(),
            section
                .strings("targets")
                .map_err(|error| manifest_error(file, error))?
                .join(","),
            section
                .optional_strings("features")
                .map_err(|error| manifest_error(file, error))?
                .join(","),
        ]);
    }
    for section in document.array_sections("compile_env") {
        declarations.push(vec![
            "compile-env".into(),
            id.into(),
            section
                .string("name")
                .map_err(|error| manifest_error(file, error))?
                .into(),
            section
                .string("value")
                .map_err(|error| manifest_error(file, error))?
                .into(),
            input_counts.compile_env.to_string(),
        ]);
    }
    for section in document.array_sections("absent_compile_env") {
        declarations.push(vec![
            "compile-env-absent".into(),
            id.into(),
            section
                .string("name")
                .map_err(|error| manifest_error(file, error))?
                .into(),
        ]);
    }
    for (name, record) in [
        ("host_build", "host-builds"),
        ("projected_build", "projected-builds"),
        ("host_test", "host-tests"),
    ] {
        for section in document.array_sections(name) {
            declarations.push(vec![
                record.into(),
                id.into(),
                section
                    .strings("targets")
                    .map_err(|error| manifest_error(file, error))?
                    .join(","),
            ]);
        }
    }
    if let Ok(policy) = document.section("test_policy") {
        declarations.push(vec![
            "test-policy".into(),
            id.into(),
            policy
                .integer("stack_bytes")
                .map_err(|error| manifest_error(file, error))?
                .to_string(),
        ]);
    }
    for section in document.array_sections("target_triple") {
        declarations.push(vec![
            "target-triple".into(),
            id.into(),
            section
                .string("target")
                .map_err(|error| manifest_error(file, error))?
                .into(),
            section
                .string("triple")
                .map_err(|error| manifest_error(file, error))?
                .into(),
        ]);
    }
    for section in document.array_sections("extern_profile") {
        declarations.push(vec![
            "extern-profile".into(),
            id.into(),
            section
                .string("compile_name")
                .map_err(|error| manifest_error(file, error))?
                .into(),
            section
                .string("consumer")
                .map_err(|error| manifest_error(file, error))?
                .into(),
            section
                .string("provider")
                .map_err(|error| manifest_error(file, error))?
                .into(),
        ]);
    }
    for section in document.array_sections("generated") {
        declarations.push(vec![
            "ptx".into(),
            id.into(),
            section
                .string("output")
                .map_err(|error| manifest_error(file, error))?
                .into(),
            section
                .string("source")
                .map_err(|error| manifest_error(file, error))?
                .into(),
            section
                .string("feature")
                .map_err(|error| manifest_error(file, error))?
                .into(),
            section
                .string("compile_env")
                .map_err(|error| manifest_error(file, error))?
                .into(),
            section
                .string("default_arch")
                .map_err(|error| manifest_error(file, error))?
                .into(),
        ]);
    }
    Ok(declarations)
}

fn load_workspace() -> Result<Workspace, String> {
    let root = find_root()?;
    let declarations = load_manifest_declarations(&root)?;
    let mut components = Vec::new();
    let mut rust_actions = Vec::new();
    let mut rust_tests = Vec::new();
    let mut rust_test_policies = Vec::new();
    let mut rust_host_builds = Vec::new();
    let mut rust_projected_builds = Vec::new();
    let mut rust_host_tests = Vec::new();
    let mut rust_examples = Vec::new();
    let mut rust_benchmarks = Vec::new();
    let mut rust_binaries = Vec::new();
    let mut rust_ptx = Vec::new();
    let mut rust_compile_env = Vec::new();
    let mut rust_absent_compile_env = Vec::new();
    let mut rust_feature_sets = Vec::new();
    let mut rust_feature_profiles = Vec::new();
    let mut rust_extern_profiles = Vec::new();
    let mut rust_target_triples = Vec::new();
    for (index, record) in declarations.records.iter().enumerate() {
        let fields: Vec<&str> = record.iter().map(String::as_str).collect();
        match fields.as_slice() {
            [
                "component",
                id,
                path,
                cargo,
                class,
                targets,
                default,
                dependencies,
                features,
                outputs,
                input_policy,
            ] => {
                if components.len() >= MAX_COMPONENTS {
                    return Err(format!("ComponentCountLimit {{ limit: {MAX_COMPONENTS} }}"));
                }
                if !mrml_package_identifier(id) {
                    return Err(format!(
                        "InvalidPackageIdentity {{ line: {}, package: {id} }}",
                        index + 1
                    ));
                }
                if components.iter().any(|item: &Component| {
                    item.id == *id || item.path == *path || item.cargo_package == *cargo
                }) {
                    return Err(format!(
                        "DuplicateComponent {{ line: {}, id: {id} }}",
                        index + 1
                    ));
                }
                if !safe_relative_path(path) || !root.join(path).join("mrml.toml").is_file() {
                    return Err(format!(
                        "ComponentPathMissing {{ line: {}, path: {path} }}",
                        index + 1
                    ));
                }
                components.push(Component {
                    id: (*id).into(),
                    path: (*path).into(),
                    cargo_package: (*cargo).into(),
                    class: (*class).into(),
                    targets: targets.split(',').map(str::to_owned).collect(),
                    default: *default == "true",
                    dependencies: split_declaration(dependencies),
                    features: split_declaration(features),
                    outputs: split_declaration(outputs),
                    input_policy: parse_input_policy(input_policy, index + 1)?,
                    input_sites: declarations
                        .build_inputs
                        .get(*id)
                        .cloned()
                        .ok_or_else(|| format!("BuildInputPolicyMissing {{ package: {id} }}"))?,
                    isolation: declarations
                        .isolation_policies
                        .get(*id)
                        .cloned()
                        .ok_or_else(|| format!("IsolationPolicyMissing {{ package: {id} }}"))?,
                    rust_action: None,
                });
            }
            ["action", component, crate_name, crate_type, source, externs] => {
                if rust_actions.iter().any(
                    |(existing, _, _, _, _): &(String, String, String, String, String)| {
                        existing == component
                    },
                ) {
                    return Err(format!(
                        "DuplicateRustAction {{ line: {}, component: {component} }}",
                        index + 1
                    ));
                }
                rust_actions.push((
                    (*component).into(),
                    (*crate_name).into(),
                    (*crate_type).into(),
                    (*source).into(),
                    (*externs).into(),
                ));
            }
            ["test", component, name, source, self_extern] => {
                rust_tests.push((
                    (*component).to_owned(),
                    (*name).to_owned(),
                    (*source).to_owned(),
                    (*self_extern).to_owned(),
                ));
            }
            ["test-policy", component, stack_bytes] => {
                rust_test_policies.push(((*component).to_owned(), (*stack_bytes).to_owned()));
            }
            ["host-builds", component, targets] => {
                rust_host_builds.push(((*component).to_owned(), (*targets).to_owned()));
            }
            ["projected-builds", component, targets] => {
                rust_projected_builds.push(((*component).to_owned(), (*targets).to_owned()));
            }
            ["host-tests", component, targets] => {
                rust_host_tests.push(((*component).to_owned(), (*targets).to_owned()));
            }
            ["example", component, name, source] => {
                rust_examples.push((
                    (*component).to_owned(),
                    (*name).to_owned(),
                    (*source).to_owned(),
                    "*".to_owned(),
                    String::new(),
                ));
            }
            ["example", component, name, source, targets, feature] => {
                rust_examples.push((
                    (*component).to_owned(),
                    (*name).to_owned(),
                    (*source).to_owned(),
                    (*targets).to_owned(),
                    (*feature).to_owned(),
                ));
            }
            ["benchmark", component, name, source, self_extern] => {
                rust_benchmarks.push((
                    (*component).to_owned(),
                    (*name).to_owned(),
                    (*source).to_owned(),
                    (*self_extern).to_owned(),
                ));
            }
            [
                "ptx",
                component,
                output,
                source,
                feature,
                compile_env,
                default_gpu_arch,
            ] => {
                rust_ptx.push((
                    (*component).to_owned(),
                    (*output).to_owned(),
                    (*source).to_owned(),
                    (*feature).to_owned(),
                    (*compile_env).to_owned(),
                    (*default_gpu_arch).to_owned(),
                ));
            }
            ["binary", component, output, crate_name, source, self_extern] => {
                rust_binaries.push((
                    (*component).to_owned(),
                    (*output).to_owned(),
                    (*crate_name).to_owned(),
                    (*source).to_owned(),
                    (*self_extern).to_owned(),
                    "*".to_owned(),
                    String::new(),
                ));
            }
            [
                "binary",
                component,
                output,
                crate_name,
                source,
                self_extern,
                targets,
                feature,
            ] => {
                rust_binaries.push((
                    (*component).to_owned(),
                    (*output).to_owned(),
                    (*crate_name).to_owned(),
                    (*source).to_owned(),
                    (*self_extern).to_owned(),
                    (*targets).to_owned(),
                    (*feature).to_owned(),
                ));
            }
            ["compile-env", component, name, value] => {
                rust_compile_env.push((
                    (*component).to_owned(),
                    (*name).to_owned(),
                    (*value).to_owned(),
                    "1".to_owned(),
                ));
            }
            ["compile-env", component, name, value, uses] => {
                rust_compile_env.push((
                    (*component).to_owned(),
                    (*name).to_owned(),
                    (*value).to_owned(),
                    (*uses).to_owned(),
                ));
            }
            ["compile-env-absent", component, name] => {
                rust_absent_compile_env.push(((*component).to_owned(), (*name).to_owned()));
            }
            ["feature-set", component, features] => {
                rust_feature_sets.push((
                    (*component).to_owned(),
                    "*".to_owned(),
                    (*features).to_owned(),
                ));
            }
            ["feature-set", component, targets, features] => {
                rust_feature_sets.push((
                    (*component).to_owned(),
                    (*targets).to_owned(),
                    (*features).to_owned(),
                ));
            }
            ["feature-profile", component, name, targets, features] => {
                rust_feature_profiles.push((
                    (*component).to_owned(),
                    (*name).to_owned(),
                    (*targets).to_owned(),
                    (*features).to_owned(),
                ));
            }
            ["extern-profile", component, package, consumer, provider] => {
                rust_extern_profiles.push((
                    (*component).to_owned(),
                    (*package).to_owned(),
                    (*consumer).to_owned(),
                    (*provider).to_owned(),
                ));
            }
            ["target-triple", component, target, triple] => {
                rust_target_triples.push((
                    (*component).to_owned(),
                    (*target).to_owned(),
                    (*triple).to_owned(),
                ));
            }
            _ => return Err(format!("WorkspaceSyntaxError {{ line: {} }}", index + 1)),
        }
    }
    if components.is_empty() {
        return Err("EmptyWorkspace".into());
    }
    for (component_id, crate_name, crate_type, source, externs) in rust_actions {
        let component = components
            .iter_mut()
            .find(|component| component.id == component_id)
            .ok_or_else(|| format!("RustActionComponentMissing {{ component: {component_id} }}"))?;
        if !matches!(crate_type.as_str(), "lib" | "cdylib" | "none") {
            return Err(format!(
                "UnsupportedRustActionType {{ component: {component_id}, crate_type: {crate_type} }}"
            ));
        }
        if !rust_identifier(&crate_name) {
            return Err(format!(
                "RustActionCrateNameInvalid {{ component: {component_id}, crate_name: {crate_name} }}"
            ));
        }
        let externs = parse_rust_externs(&externs)?;
        if externs.iter().any(|external| {
            external
                .feature
                .as_ref()
                .is_some_and(|feature| !component.features.iter().any(|known| known == feature))
        }) {
            return Err(format!(
                "RustExternFeatureDrift {{ component: {component_id} }}"
            ));
        }
        let mut extern_packages: Vec<_> = externs
            .iter()
            .map(|external| external.package.clone())
            .collect();
        extern_packages.sort();
        if component.dependencies != extern_packages {
            return Err(format!(
                "RustActionExternDrift {{ component: {component_id}, dependencies: {}, externs: {} }}",
                component.dependencies.join(","),
                extern_packages.join(",")
            ));
        }
        let source_valid = if crate_type == "none" {
            source == "-"
        } else {
            let component_root = root.join(&component.path);
            let source_path = root.join(&source);
            safe_relative_path(&source)
                && source_path.is_file()
                && source_path.starts_with(&component_root)
        };
        if !source_valid {
            return Err(format!(
                "RustActionSourceInvalid {{ component: {component_id}, source: {source} }}"
            ));
        }
        component.rust_action = Some(RustAction {
            crate_name,
            crate_type,
            source,
            externs,
            tests: Vec::new(),
            test_stack_bytes: None,
            host_build_targets: Vec::new(),
            projected_build_targets: Vec::new(),
            host_test_targets: Vec::new(),
            examples: Vec::new(),
            benchmarks: Vec::new(),
            binaries: Vec::new(),
            ptx: None,
            compile_env: Vec::new(),
            absent_compile_env: Vec::new(),
            feature_sets: Vec::new(),
            feature_profiles: Vec::new(),
            target_triples: Vec::new(),
        });
    }
    for (component_id, targets, features) in rust_feature_sets {
        let component = components
            .iter_mut()
            .find(|component| component.id == component_id)
            .ok_or_else(|| {
                format!("RustFeatureComponentMissing {{ component: {component_id} }}")
            })?;
        let action = component
            .rust_action
            .as_mut()
            .ok_or_else(|| format!("RustFeatureActionMissing {{ component: {component_id} }}"))?;
        let features = split_declaration(&features);
        let targets = if targets == "*" {
            component.targets.clone()
        } else {
            split_declaration(&targets)
        };
        if features.iter().any(|feature| {
            feature == "default" || !component.features.iter().any(|known| known == feature)
        }) || targets.is_empty()
            || targets
                .iter()
                .any(|target| !component.targets.iter().any(|known| known == target))
            || action.feature_sets.iter().any(|set| {
                set.targets
                    .iter()
                    .any(|existing| targets.iter().any(|target| target == existing))
            })
        {
            return Err(format!(
                "RustFeatureSetInvalid {{ component: {component_id}, features: {} }}",
                features.join(",")
            ));
        }
        action
            .feature_sets
            .push(RustFeatureSet { targets, features });
    }
    for (component_id, name, targets, features) in rust_feature_profiles {
        let component = components
            .iter_mut()
            .find(|component| component.id == component_id)
            .ok_or_else(|| {
                format!("RustFeatureProfileComponentMissing {{ component: {component_id} }}")
            })?;
        let action = component.rust_action.as_mut().ok_or_else(|| {
            format!("RustFeatureProfileActionMissing {{ component: {component_id} }}")
        })?;
        let features = split_declaration(&features);
        let targets = if targets == "*" {
            component.targets.clone()
        } else {
            split_declaration(&targets)
        };
        if name == "default"
            || !rust_identifier(&name)
            || features.iter().any(|feature| {
                feature == "default" || !component.features.iter().any(|known| known == feature)
            })
            || targets.is_empty()
            || targets
                .iter()
                .any(|target| !TARGET_FAMILIES.contains(&target.as_str()))
            || action.feature_profiles.iter().any(|profile| {
                profile.name == name
                    && profile
                        .targets
                        .iter()
                        .any(|existing| targets.iter().any(|target| target == existing))
            })
        {
            return Err(format!(
                "RustFeatureProfileInvalid {{ component: {component_id}, profile: {name} }}"
            ));
        }
        action.feature_profiles.push(RustFeatureProfile {
            name,
            targets,
            features,
        });
    }
    for (component_id, package, consumer_profile, provider_profile) in rust_extern_profiles {
        let component_index = components
            .iter()
            .position(|component| component.id == component_id)
            .ok_or_else(|| {
                format!("RustExternProfileComponentMissing {{ component: {component_id} }}")
            })?;
        let dependency_profiles = components
            .iter()
            .find(|component| component.cargo_package == package)
            .and_then(|component| component.rust_action.as_ref())
            .map(|action| action.feature_profiles.clone())
            .ok_or_else(|| {
                format!(
                    "RustExternProfileDependencyMissing {{ component: {component_id}, dependency: {package} }}"
                )
            })?;
        let component_targets = components[component_index].targets.clone();
        let action = components[component_index]
            .rust_action
            .as_mut()
            .ok_or_else(|| {
                format!("RustExternProfileActionMissing {{ component: {component_id} }}")
            })?;
        let consumer = action
            .feature_profiles
            .iter()
            .find(|profile| profile.name == consumer_profile)
            .ok_or_else(|| {
                format!(
                    "RustExternConsumerProfileMissing {{ component: {component_id}, profile: {consumer_profile} }}"
                )
            })?;
        let external = action
            .externs
            .iter_mut()
            .find(|external| external.package == package)
            .ok_or_else(|| {
                format!(
                    "RustExternProfileBindingMissing {{ component: {component_id}, dependency: {package} }}"
                )
            })?;
        if !rust_identifier(&provider_profile)
            || external.provider_profiles.contains_key(&consumer_profile)
            || consumer.targets.iter().any(|target| {
                component_targets.contains(target)
                    && external.targets.contains(target)
                    && !dependency_profiles.iter().any(|profile| {
                        profile.name == provider_profile && profile.targets.contains(target)
                    })
            })
        {
            return Err(format!(
                "RustExternProfileInvalid {{ component: {component_id}, dependency: {package}, consumer: {consumer_profile}, provider: {provider_profile} }}"
            ));
        }
        external
            .provider_profiles
            .insert(consumer_profile, provider_profile);
    }
    for (component_id, target, triple) in rust_target_triples {
        let component = components
            .iter_mut()
            .find(|component| component.id == component_id)
            .ok_or_else(|| {
                format!("RustTargetTripleComponentMissing {{ component: {component_id} }}")
            })?;
        let action = component.rust_action.as_mut().ok_or_else(|| {
            format!("RustTargetTripleActionMissing {{ component: {component_id} }}")
        })?;
        let valid_pair = matches!(
            (target.as_str(), triple.as_str()),
            ("MRML_NATIVE", "x86_64-unknown-uefi")
        );
        if !valid_pair
            || !component.targets.contains(&target)
            || action
                .target_triples
                .iter()
                .any(|declaration| declaration.target == target)
        {
            return Err(format!(
                "RustTargetTripleInvalid {{ component: {component_id}, target: {target}, triple: {triple} }}"
            ));
        }
        action
            .target_triples
            .push(RustTargetTriple { target, triple });
    }
    for (component_id, stack_bytes) in rust_test_policies {
        let component = components
            .iter_mut()
            .find(|component| component.id == component_id)
            .ok_or_else(|| {
                format!("RustTestPolicyComponentMissing {{ component: {component_id} }}")
            })?;
        let action = component.rust_action.as_mut().ok_or_else(|| {
            format!("RustTestPolicyActionMissing {{ component: {component_id} }}")
        })?;
        let bytes = stack_bytes
            .parse::<usize>()
            .map_err(|_| format!("RustTestStackInvalid {{ component: {component_id} }}"))?;
        if !(1024 * 1024..=64 * 1024 * 1024).contains(&bytes)
            || action.test_stack_bytes.replace(bytes).is_some()
        {
            return Err(format!(
                "RustTestStackInvalid {{ component: {component_id}, bytes: {bytes} }}"
            ));
        }
    }
    for (component_id, targets) in rust_host_builds {
        let component = components
            .iter_mut()
            .find(|component| component.id == component_id)
            .ok_or_else(|| {
                format!("RustHostBuildComponentMissing {{ component: {component_id} }}")
            })?;
        let action = component
            .rust_action
            .as_mut()
            .ok_or_else(|| format!("RustHostBuildActionMissing {{ component: {component_id} }}"))?;
        let targets = split_declaration(&targets);
        if targets.is_empty()
            || targets
                .iter()
                .any(|target| !matches!(target.as_str(), "WINDOWS" | "LINUX"))
            || !action.host_build_targets.is_empty()
        {
            return Err(format!(
                "RustHostBuildTargetInvalid {{ component: {component_id}, targets: {} }}",
                targets.join(",")
            ));
        }
        action.host_build_targets = targets;
    }
    for (component_id, targets) in rust_projected_builds {
        let component = components
            .iter_mut()
            .find(|component| component.id == component_id)
            .ok_or_else(|| {
                format!("RustProjectedBuildComponentMissing {{ component: {component_id} }}")
            })?;
        let action = component.rust_action.as_mut().ok_or_else(|| {
            format!("RustProjectedBuildActionMissing {{ component: {component_id} }}")
        })?;
        let targets = split_declaration(&targets);
        if targets.is_empty()
            || targets
                .iter()
                .any(|target| !matches!(target.as_str(), "MRML_NATIVE" | "UEFI" | "CUDA"))
            || targets
                .iter()
                .any(|target| component.targets.contains(target))
            || targets
                .iter()
                .any(|target| action.host_build_targets.contains(target))
            || !action.projected_build_targets.is_empty()
        {
            return Err(format!(
                "RustProjectedBuildTargetInvalid {{ component: {component_id}, targets: {} }}",
                targets.join(",")
            ));
        }
        action.projected_build_targets = targets;
    }
    for (component_id, targets) in rust_host_tests {
        let component = components
            .iter_mut()
            .find(|component| component.id == component_id)
            .ok_or_else(|| {
                format!("RustHostTestComponentMissing {{ component: {component_id} }}")
            })?;
        let action = component
            .rust_action
            .as_mut()
            .ok_or_else(|| format!("RustHostTestActionMissing {{ component: {component_id} }}"))?;
        let targets = split_declaration(&targets);
        if targets.is_empty()
            || targets
                .iter()
                .any(|target| !matches!(target.as_str(), "WINDOWS" | "LINUX"))
            || !action.host_test_targets.is_empty()
        {
            return Err(format!(
                "RustHostTestTargetInvalid {{ component: {component_id}, targets: {} }}",
                targets.join(",")
            ));
        }
        action.host_test_targets = targets;
    }
    for (component_id, name, source, self_extern) in rust_tests {
        let component = components
            .iter_mut()
            .find(|component| component.id == component_id)
            .ok_or_else(|| format!("RustTestComponentMissing {{ component: {component_id} }}"))?;
        let action = component
            .rust_action
            .as_mut()
            .ok_or_else(|| format!("RustTestActionMissing {{ component: {component_id} }}"))?;
        if !rust_identifier(&name)
            || !safe_relative_path(&source)
            || !root.join(&source).is_file()
            || !root.join(&source).starts_with(root.join(&component.path))
            || !matches!(self_extern.as_str(), "true" | "false")
            || action.tests.iter().any(|test| test.name == name)
        {
            return Err(format!(
                "RustTestDeclarationInvalid {{ component: {component_id}, test: {name} }}"
            ));
        }
        action.tests.push(RustTest {
            name,
            source,
            self_extern: self_extern == "true",
        });
    }
    for (component_id, name, source, targets, feature) in rust_examples {
        let component = components
            .iter_mut()
            .find(|component| component.id == component_id)
            .ok_or_else(|| {
                format!("RustExampleComponentMissing {{ component: {component_id} }}")
            })?;
        let action = component
            .rust_action
            .as_mut()
            .ok_or_else(|| format!("RustExampleActionMissing {{ component: {component_id} }}"))?;
        let targets = if targets == "*" {
            component.targets.clone()
        } else {
            split_declaration(&targets)
        };
        let feature = (!feature.is_empty()).then_some(feature);
        if !rust_identifier(&name)
            || !safe_relative_path(&source)
            || !root.join(&source).is_file()
            || !root.join(&source).starts_with(root.join(&component.path))
            || targets.is_empty()
            || targets
                .iter()
                .any(|target| !component.targets.contains(target))
            || feature
                .as_ref()
                .is_some_and(|feature| !component.features.contains(feature))
            || action.examples.iter().any(|example| example.name == name)
        {
            return Err(format!(
                "RustExampleDeclarationInvalid {{ component: {component_id}, example: {name} }}"
            ));
        }
        action.examples.push(RustExample {
            name,
            source,
            targets,
            feature,
        });
    }
    for (component_id, name, source, self_extern) in rust_benchmarks {
        let component = components
            .iter_mut()
            .find(|component| component.id == component_id)
            .ok_or_else(|| {
                format!("RustBenchmarkComponentMissing {{ component: {component_id} }}")
            })?;
        let action = component
            .rust_action
            .as_mut()
            .ok_or_else(|| format!("RustBenchmarkActionMissing {{ component: {component_id} }}"))?;
        if !rust_identifier(&name)
            || !safe_relative_path(&source)
            || !root.join(&source).is_file()
            || !root.join(&source).starts_with(root.join(&component.path))
            || !matches!(self_extern.as_str(), "true" | "false")
            || action
                .benchmarks
                .iter()
                .any(|benchmark| benchmark.name == name)
        {
            return Err(format!(
                "RustBenchmarkDeclarationInvalid {{ component: {component_id}, benchmark: {name} }}"
            ));
        }
        action.benchmarks.push(RustBenchmark {
            name,
            source,
            self_extern: self_extern == "true",
        });
    }
    for (component_id, output, source, feature, compile_env, default_gpu_arch) in rust_ptx {
        let component = components
            .iter_mut()
            .find(|component| component.id == component_id)
            .ok_or_else(|| format!("RustPtxComponentMissing {{ component: {component_id} }}"))?;
        let action = component
            .rust_action
            .as_mut()
            .ok_or_else(|| format!("RustPtxActionMissing {{ component: {component_id} }}"))?;
        if !rust_output_name(&output)
            || !output.ends_with(".ptx")
            || !safe_relative_path(&source)
            || !root.join(&source).is_file()
            || !root.join(&source).starts_with(root.join(&component.path))
            || !component.features.contains(&feature)
            || compile_env != "OUT_DIR"
            || !valid_gpu_architecture(&default_gpu_arch)
            || action.ptx.is_some()
        {
            return Err(format!(
                "RustPtxDeclarationInvalid {{ component: {component_id}, output: {output} }}"
            ));
        }
        action.ptx = Some(RustPtx {
            output,
            source,
            feature,
            compile_env,
            default_gpu_arch,
        });
    }
    for (component_id, output, crate_name, source, self_extern, targets, feature) in rust_binaries {
        let component = components
            .iter_mut()
            .find(|component| component.id == component_id)
            .ok_or_else(|| format!("RustBinaryComponentMissing {{ component: {component_id} }}"))?;
        let action = component
            .rust_action
            .as_mut()
            .ok_or_else(|| format!("RustBinaryActionMissing {{ component: {component_id} }}"))?;
        let targets = if targets == "*" {
            component.targets.clone()
        } else {
            split_declaration(&targets)
        };
        let feature = (!feature.is_empty()).then_some(feature);
        if !rust_output_name(&output)
            || !rust_identifier(&crate_name)
            || !safe_relative_path(&source)
            || !root.join(&source).is_file()
            || !root.join(&source).starts_with(root.join(&component.path))
            || !matches!(self_extern.as_str(), "true" | "false")
            || targets.is_empty()
            || targets
                .iter()
                .any(|target| !component.targets.contains(target))
            || feature
                .as_ref()
                .is_some_and(|feature| !component.features.contains(feature))
            || action.binaries.iter().any(|binary| binary.output == output)
        {
            return Err(format!(
                "RustBinaryDeclarationInvalid {{ component: {component_id}, output: {output} }}"
            ));
        }
        action.binaries.push(RustBinary {
            output,
            crate_name,
            source,
            self_extern: self_extern == "true",
            targets,
            feature,
        });
    }
    for (component_id, name, value, uses) in rust_compile_env {
        let component = components
            .iter_mut()
            .find(|component| component.id == component_id)
            .ok_or_else(|| {
                format!("RustCompileEnvComponentMissing {{ component: {component_id} }}")
            })?;
        let action = component.rust_action.as_mut().ok_or_else(|| {
            format!("RustCompileEnvActionMissing {{ component: {component_id} }}")
        })?;
        let uses = uses.parse::<usize>().map_err(|_| {
            format!("RustCompileEnvUseCountInvalid {{ component: {component_id}, name: {name} }}")
        })?;
        if !rust_identifier(&name)
            || value.len() > 1024
            || value.contains(['\r', '\n', '\0'])
            || !(1..=64).contains(&uses)
            || action
                .compile_env
                .iter()
                .any(|existing| existing.name == name)
        {
            return Err(format!(
                "RustCompileEnvInvalid {{ component: {component_id}, name: {name} }}"
            ));
        }
        action
            .compile_env
            .push(RustCompileEnv { name, value, uses });
    }
    for (component_id, name) in rust_absent_compile_env {
        let component = components
            .iter_mut()
            .find(|component| component.id == component_id)
            .ok_or_else(|| {
                format!("RustCompileEnvComponentMissing {{ component: {component_id} }}")
            })?;
        let action = component.rust_action.as_mut().ok_or_else(|| {
            format!("RustCompileEnvActionMissing {{ component: {component_id} }}")
        })?;
        if !rust_identifier(&name)
            || action
                .compile_env
                .iter()
                .any(|existing| existing.name == name)
            || action.absent_compile_env.contains(&name)
        {
            return Err(format!(
                "RustCompileEnvInvalid {{ component: {component_id}, name: {name} }}"
            ));
        }
        action.absent_compile_env.push(name);
    }
    for component in &components {
        if let Some(action) = &component.rust_action {
            if action
                .compile_env
                .iter()
                .map(|input| input.uses)
                .sum::<usize>()
                + action.absent_compile_env.len()
                + usize::from(action.ptx.is_some())
                != component.input_policy.compile_env
            {
                return Err(format!(
                    "RustCompileEnvDrift {{ component: {}, declared: {}, inputs: {} }}",
                    component.id,
                    action
                        .compile_env
                        .iter()
                        .map(|input| input.uses)
                        .sum::<usize>()
                        + action.absent_compile_env.len()
                        + usize::from(action.ptx.is_some()),
                    component.input_policy.compile_env
                ));
            }
            if !component.features.is_empty() {
                let mut covered: Vec<_> = action
                    .feature_sets
                    .iter()
                    .flat_map(|set| set.targets.iter().cloned())
                    .collect();
                let mut required = component.targets.clone();
                covered.sort();
                required.sort();
                if covered != required {
                    return Err(format!(
                        "RustFeatureSetMissing {{ component: {}, targets: {} }}",
                        component.id,
                        required.join(",")
                    ));
                }
            }
            let mut declared_libraries: Vec<_> = component
                .outputs
                .iter()
                .filter_map(|output| output.strip_suffix(":lib"))
                .collect();
            let mut library_actions = if action.crate_type == "lib" {
                vec![action.crate_name.as_str()]
            } else {
                Vec::new()
            };
            declared_libraries.sort();
            library_actions.sort();
            if declared_libraries != library_actions {
                return Err(format!(
                    "RustLibraryOutputDrift {{ component: {}, outputs: {}, libraries: {} }}",
                    component.id,
                    declared_libraries.join(","),
                    library_actions.join(",")
                ));
            }
            let mut declared_cdylibs: Vec<_> = component
                .outputs
                .iter()
                .filter_map(|output| output.strip_suffix(":cdylib"))
                .collect();
            let mut cdylib_actions = if action.crate_type == "cdylib" {
                vec![action.crate_name.as_str()]
            } else {
                Vec::new()
            };
            declared_cdylibs.sort();
            cdylib_actions.sort();
            if declared_cdylibs != cdylib_actions {
                return Err(format!(
                    "RustCdylibOutputDrift {{ component: {}, outputs: {}, cdylibs: {} }}",
                    component.id,
                    declared_cdylibs.join(","),
                    cdylib_actions.join(",")
                ));
            }
            for external in &action.externs {
                let dependency = components
                    .iter()
                    .find(|candidate| candidate.cargo_package == external.package)
                    .and_then(|candidate| candidate.rust_action.as_ref())
                    .ok_or_else(|| {
                        format!(
                            "NativeDependencyActionMissing {{ component: {}, dependency: {} }}",
                            component.id, external.package
                        )
                    })?;
                if dependency.crate_type != "lib" {
                    return Err(format!(
                        "NativeDependencyNotLibrary {{ component: {}, dependency: {} }}",
                        component.id, external.package
                    ));
                }
                if external.provider_profile != "default" {
                    for target in component
                        .targets
                        .iter()
                        .chain(action.host_build_targets.iter())
                        .chain(action.projected_build_targets.iter())
                        .chain(action.host_test_targets.iter())
                        .filter(|target| external.targets.contains(target))
                    {
                        if !dependency.feature_profiles.iter().any(|profile| {
                            profile.name == external.provider_profile
                                && profile.targets.contains(target)
                        }) {
                            return Err(format!(
                                "RustExternProviderProfileMissing {{ component: {}, dependency: {}, profile: {}, target: {} }}",
                                component.id, external.package, external.provider_profile, target
                            ));
                        }
                    }
                }
            }
            let mut declared: Vec<_> = component
                .outputs
                .iter()
                .filter_map(|output| output.strip_suffix(":test"))
                .collect();
            let mut actions: Vec<_> = action.tests.iter().map(|test| test.name.as_str()).collect();
            declared.sort();
            actions.sort();
            if declared != actions {
                return Err(format!(
                    "RustTestOutputDrift {{ component: {}, outputs: {}, tests: {} }}",
                    component.id,
                    declared.join(","),
                    actions.join(",")
                ));
            }
            let mut declared_examples: Vec<_> = component
                .outputs
                .iter()
                .filter_map(|output| output.strip_suffix(":example"))
                .collect();
            let mut example_actions: Vec<_> = action
                .examples
                .iter()
                .map(|example| example.name.as_str())
                .collect();
            declared_examples.sort();
            example_actions.sort();
            if declared_examples != example_actions {
                return Err(format!(
                    "RustExampleOutputDrift {{ component: {}, outputs: {}, examples: {} }}",
                    component.id,
                    declared_examples.join(","),
                    example_actions.join(",")
                ));
            }
            let mut declared_benchmarks: Vec<_> = component
                .outputs
                .iter()
                .filter_map(|output| output.strip_suffix(":bench"))
                .collect();
            let mut benchmark_actions: Vec<_> = action
                .benchmarks
                .iter()
                .map(|benchmark| benchmark.name.as_str())
                .collect();
            declared_benchmarks.sort();
            benchmark_actions.sort();
            if declared_benchmarks != benchmark_actions {
                return Err(format!(
                    "RustBenchmarkOutputDrift {{ component: {}, outputs: {}, benchmarks: {} }}",
                    component.id,
                    declared_benchmarks.join(","),
                    benchmark_actions.join(",")
                ));
            }
            let mut declared_generated: Vec<_> = component
                .outputs
                .iter()
                .filter_map(|output| output.strip_suffix(":generated"))
                .collect();
            let mut ptx_actions = action
                .ptx
                .iter()
                .map(|ptx| ptx.output.as_str())
                .collect::<Vec<_>>();
            declared_generated.sort();
            ptx_actions.sort();
            if declared_generated != ptx_actions
                || action.ptx.is_some()
                    && (component.input_policy.build_scripts != 0
                        || component.input_policy.external_commands != 0
                        || component.input_policy.included_files != 1)
            {
                return Err(format!(
                    "RustGeneratedOutputDrift {{ component: {} }}",
                    component.id
                ));
            }
            let mut declared_binaries: Vec<_> = component
                .outputs
                .iter()
                .filter_map(|output| output.strip_suffix(":bin"))
                .collect();
            let mut binary_actions: Vec<_> = action
                .binaries
                .iter()
                .map(|binary| binary.output.as_str())
                .collect();
            declared_binaries.sort();
            binary_actions.sort();
            if declared_binaries != binary_actions {
                return Err(format!(
                    "RustBinaryOutputDrift {{ component: {}, outputs: {}, binaries: {} }}",
                    component.id,
                    declared_binaries.join(","),
                    binary_actions.join(",")
                ));
            }
        }
    }
    if let Some(component) = components
        .iter()
        .find(|component| component.rust_action.is_none())
    {
        return Err(format!(
            "NativeActionMissing {{ component: {} }}",
            component.id
        ));
    }
    Ok(Workspace {
        root,
        components,
        interface_bindings: declarations.interface_bindings,
    })
}

fn safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.contains([':', '\\'])
        && Path::new(value)
            .components()
            .all(|component| matches!(component, PathComponent::Normal(_)))
}

fn rust_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_'))
}

fn rust_output_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value.bytes().all(
            |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' | b'.'),
        )
}

fn parse_rust_externs(value: &str) -> Result<Vec<RustExtern>, String> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for declaration in value.split(';') {
        let (declaration_body, test_only) = declaration
            .strip_suffix("!test")
            .map(|body| (body, true))
            .unwrap_or((declaration, false));
        let (binding, target_and_feature) = declaration_body
            .split_once('@')
            .ok_or_else(|| format!("RustExternSyntaxError {{ declaration: {declaration} }}"))?;
        let (package, crate_name) = binding
            .split_once('=')
            .ok_or_else(|| format!("RustExternSyntaxError {{ declaration: {declaration} }}"))?;
        if package.is_empty() || !rust_identifier(crate_name) {
            return Err(format!(
                "RustExternIdentityInvalid {{ declaration: {declaration} }}"
            ));
        }
        let (target_and_feature, provider_profile) = target_and_feature
            .split_once('#')
            .map(|(declaration, profile)| (declaration, profile.to_owned()))
            .unwrap_or((target_and_feature, "default".to_owned()));
        if !rust_identifier(&provider_profile) {
            return Err(format!(
                "RustExternProviderProfileInvalid {{ declaration: {declaration} }}"
            ));
        }
        let (targets, feature) = target_and_feature
            .split_once('?')
            .map(|(targets, feature)| (targets, Some(feature.to_owned())))
            .unwrap_or((target_and_feature, None));
        if feature
            .as_deref()
            .is_some_and(|feature| !rust_identifier(feature))
        {
            return Err(format!(
                "RustExternFeatureInvalid {{ declaration: {declaration} }}"
            ));
        }
        let targets = if targets == "*" {
            TARGET_FAMILIES
                .iter()
                .map(|target| (*target).into())
                .collect()
        } else {
            split_declaration(targets)
        };
        if targets.is_empty()
            || targets
                .iter()
                .any(|target| !TARGET_FAMILIES.contains(&target.as_str()))
        {
            return Err(format!(
                "RustExternTargetInvalid {{ declaration: {declaration} }}"
            ));
        }
        if result.iter().any(|external: &RustExtern| {
            external.package == package || external.crate_name == crate_name
        }) {
            return Err(format!(
                "RustExternDuplicate {{ declaration: {declaration} }}"
            ));
        }
        result.push(RustExtern {
            package: package.into(),
            crate_name: crate_name.into(),
            targets,
            feature,
            provider_profile,
            provider_profiles: BTreeMap::new(),
            test_only,
        });
    }
    result.sort_by(|left, right| left.package.cmp(&right.package));
    Ok(result)
}

fn rust_extern_active(
    external: &RustExtern,
    action: &RustAction,
    target: &str,
    compile_target: &str,
    profile: &str,
    test: bool,
) -> bool {
    (!external.test_only || test)
        && external.targets.iter().any(|family| {
            family == target
                || compile_target_family(compile_target).is_ok_and(|host| family == host)
        })
        && external
            .feature
            .as_ref()
            .is_none_or(|feature| rust_features(action, target, profile).contains(feature))
}

fn rust_binary_active(binary: &RustBinary, action: &RustAction, target: &str) -> bool {
    binary.targets.iter().any(|candidate| candidate == target)
        && binary
            .feature
            .as_ref()
            .is_none_or(|feature| rust_features(action, target, "default").contains(feature))
}

fn rust_example_active(example: &RustExample, action: &RustAction, target: &str) -> bool {
    example.targets.iter().any(|candidate| candidate == target)
        && example
            .feature
            .as_ref()
            .is_none_or(|feature| rust_features(action, target, "default").contains(feature))
}

fn rust_features<'a>(action: &'a RustAction, target: &str, profile: &str) -> &'a [String] {
    if profile == "default" {
        action
            .feature_sets
            .iter()
            .find(|set| set.targets.iter().any(|candidate| candidate == target))
            .map(|set| set.features.as_slice())
            .unwrap_or(&[])
    } else {
        action
            .feature_profiles
            .iter()
            .find(|set| {
                set.name == profile && set.targets.iter().any(|candidate| candidate == target)
            })
            .map(|set| set.features.as_slice())
            .unwrap_or(&[])
    }
}

fn rust_extern_provider_profile<'a>(external: &'a RustExtern, profile: &str) -> &'a str {
    external
        .provider_profiles
        .get(profile)
        .map(String::as_str)
        .unwrap_or(&external.provider_profile)
}

fn apply_rust_features(
    command: &mut Command,
    component: &Component,
    action: &RustAction,
    target: &str,
    profile: &str,
) {
    for feature in rust_features(action, target, profile) {
        command.arg("--cfg").arg(format!("feature=\"{feature}\""));
    }
    let values = component
        .features
        .iter()
        .filter(|feature| feature.as_str() != "default")
        .map(|feature| format!("\"{feature}\""))
        .collect::<Vec<_>>()
        .join(",");
    command
        .arg("--check-cfg")
        .arg(format!("cfg(feature, values({values}))"))
        .arg("--check-cfg")
        .arg("cfg(test)")
        .arg("--check-cfg")
        .arg("cfg(mrml_stage_zero)");
}

fn apply_rust_compile_env(
    command: &mut Command,
    action: &RustAction,
    overrides: &BTreeMap<String, String>,
) {
    for input in &action.compile_env {
        command.env(&input.name, &input.value);
    }
    for name in &action.absent_compile_env {
        if let Some(value) = overrides.get(name) {
            command.env(name, value);
        } else {
            command.env_remove(name);
        }
    }
}

fn parse_input_policy(value: &str, line: usize) -> Result<InputCounts, String> {
    let mut counts = InputCounts::default();
    let mut seen = [false; 6];
    for field in value.split(',') {
        let (name, raw_count) = field
            .split_once(':')
            .ok_or_else(|| format!("InputPolicySyntaxError {{ line: {line} }}"))?;
        let count = raw_count
            .parse::<usize>()
            .map_err(|_| format!("InputPolicyCountError {{ line: {line}, kind: {name} }}"))?;
        let (slot, destination) = match name {
            "build-script" => (0, &mut counts.build_scripts),
            "proc-macro" => (1, &mut counts.proc_macros),
            "native-link" => (2, &mut counts.native_links),
            "compile-env" => (3, &mut counts.compile_env),
            "included-file" => (4, &mut counts.included_files),
            "external-command" => (5, &mut counts.external_commands),
            _ => {
                return Err(format!(
                    "InputPolicyUnknownKind {{ line: {line}, kind: {name} }}"
                ));
            }
        };
        if seen[slot] {
            return Err(format!(
                "InputPolicyDuplicateKind {{ line: {line}, kind: {name} }}"
            ));
        }
        seen[slot] = true;
        *destination = count;
    }
    if !seen.iter().all(|value| *value) {
        return Err(format!("InputPolicyMissingKind {{ line: {line} }}"));
    }
    Ok(counts)
}

fn split_declaration(value: &str) -> Vec<String> {
    let mut values: Vec<_> = value
        .split(',')
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect();
    values.sort();
    values.dedup();
    values
}

fn output_mode(args: &[String]) -> OutputMode {
    args.windows(2)
        .find(|pair| pair[0] == "--output")
        .map(|pair| pair[1].as_str())
        .filter(|value| *value == "structured")
        .map(|_| OutputMode::Structured)
        .unwrap_or(OutputMode::Human)
}

fn list(workspace: &Workspace, args: &[String]) -> Result<(), String> {
    let mode = output_mode(args);
    for component in &workspace.components {
        if mode == OutputMode::Structured {
            println!(
                "manifest-component|id={}|path={}|class={}|targets={}|dependencies={}|features={}|outputs={}|inputs={}|builder=native-rustc",
                component.id,
                component.path,
                component.class,
                component.targets.join(","),
                component.dependencies.join(","),
                component.features.join(","),
                component.outputs.join(","),
                component.input_policy.structured()
            );
        } else {
            println!(
                "{:<48} {:<18} {}",
                component.id, component.class, component.path
            );
        }
    }
    Ok(())
}

fn host_family() -> Result<&'static str, String> {
    match env::consts::OS {
        "windows" => Ok("WINDOWS"),
        "linux" => Ok("LINUX"),
        other => Err(format!(
            "UnsupportedHost {{ host: {other}, supported: [windows,linux] }}"
        )),
    }
}

fn requested_target(args: &[String]) -> Result<String, String> {
    let value = args
        .windows(2)
        .find(|pair| pair[0] == "--target")
        .map(|pair| pair[1].as_str());
    Ok(match value {
        None | Some("host") => host_family()?.into(),
        Some("native") => "MRML_NATIVE".into(),
        Some("windows") => "WINDOWS".into(),
        Some("linux") => "LINUX".into(),
        Some("uefi-x86_64") => "UEFI".into(),
        Some("cuda-nvidia") => "CUDA".into(),
        Some(other) => return Err(format!("UnsupportedTarget {{ target: {other} }}")),
    })
}

fn selector(args: &[String]) -> Option<&str> {
    args.get(1)
        .filter(|arg| !arg.starts_with('-'))
        .map(String::as_str)
}

fn requested_option<'a>(args: &'a [String], name: &str) -> Result<Option<&'a str>, String> {
    let mut values = args
        .windows(2)
        .filter(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str());
    let value = values.next();
    if value.is_some_and(|value| value.starts_with('-')) || values.next().is_some() {
        return Err(format!("InvalidOption {{ option: {name} }}"));
    }
    if value.is_none() && args.iter().any(|arg| arg == name) {
        return Err(format!("MissingOptionValue {{ option: {name} }}"));
    }
    Ok(value)
}

fn requested_compile_env(args: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut values = BTreeMap::new();
    for pair in args.windows(2).filter(|pair| pair[0] == "--compile-env") {
        let (name, value) = pair[1]
            .split_once('=')
            .ok_or_else(|| "InvalidOption { option: --compile-env }".to_owned())?;
        if name.is_empty()
            || value.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || values.insert(name.to_owned(), value.to_owned()).is_some()
        {
            return Err("InvalidOption { option: --compile-env }".to_owned());
        }
    }
    if args.last().is_some_and(|arg| arg == "--compile-env") {
        return Err("MissingOptionValue { option: --compile-env }".to_owned());
    }
    Ok(values)
}

fn build_or_test(workspace: &Workspace, args: &[String]) -> Result<(), String> {
    let operation = args[0].as_str();
    let mode = output_mode(args);
    let target = requested_target(args)?;
    let host = host_family()?;
    if matches!(target.as_str(), "WINDOWS" | "LINUX") && target != host {
        return Err(format!(
            "ToolchainUnavailable {{ target: {target}, required_component: cross_host_rust_target }}"
        ));
    }
    let all = args.iter().any(|arg| arg == "--all");
    let selected = selector(args);
    let release = args.iter().any(|arg| arg == "--release");
    let feature_profile = requested_option(args, "--feature-profile")?.unwrap_or("default");
    let compile_env = requested_compile_env(args)?;
    let sanitizer = requested_option(args, "--sanitizer")?;
    if let Some(value) = sanitizer
        && (value != "address" || operation != "test" || target != "LINUX")
    {
        return Err(format!(
            "UnsupportedSanitizer {{ sanitizer: {value}, operation: {operation}, target: {target}, supported: address-on-linux-test }}"
        ));
    }
    let mut components: Vec<&Component> = workspace
        .components
        .iter()
        .filter(|component| {
            let target_matches = component.targets.contains(&target)
                || component.rust_action.as_ref().is_some_and(|action| {
                    (operation == "build" && action.host_build_targets.contains(&target))
                        || (operation == "test" && action.host_test_targets.contains(&target))
                });
            if let Some(value) = selected {
                (component.id == value
                    || component.path == value
                    || component.cargo_package == value)
                    && target_matches
            } else if all {
                target_matches
            } else {
                component.default && target_matches
            }
        })
        .collect();

    if selected.is_none() && target == "WINDOWS" {
        add_component(workspace, &mut components, "mrml-whp-run");
    }
    if selected.is_none() && target == "LINUX" {
        add_component(workspace, &mut components, "mrml-kvm-run");
    }
    if target == "UEFI" && selected.is_none() && !all {
        components = vec![find_component(workspace, "mrml-kernel-image")?];
    }
    if target == "CUDA" {
        components = vec![find_component(workspace, "mrml-tensor")?];
        check_cuda(args)?;
    }
    if components.is_empty() {
        return Err(format!("NoMatchingComponents {{ target: {target} }}"));
    }

    let keep_going = args.iter().any(|arg| arg == "--keep-going");
    let mut failures = Vec::new();
    let mut attempted = 0_u32;
    for component in components {
        // These are host-model tests, not execution of freestanding binaries.
        if operation == "test"
            && target == "MRML_NATIVE"
            && all
            && selected.is_none()
            && !component
                .rust_action
                .as_ref()
                .is_some_and(|action| action.host_test_targets.iter().any(|item| item == host))
        {
            emit(
                mode,
                operation,
                component,
                &target,
                "host-model",
                "NO_HOST_HARNESS",
            );
            continue;
        }
        attempted += 1;
        if target == "CUDA" && mode == OutputMode::Structured {
            let gpu_arch = args
                .windows(2)
                .find(|pair| pair[0] == "--gpu-arch")
                .map(|pair| pair[1].as_str())
                .unwrap_or("missing");
            println!(
                "metadata|target=CUDA|gpu_arch={gpu_arch}|artifact=PTX|toolchain=upstream-rustc-nvptx|runtime_authority=none"
            );
        }
        let builder = if operation == "test" && target == "MRML_NATIVE" {
            "native-build-plus-host-model"
        } else {
            "native-rustc"
        };
        emit(mode, operation, component, &target, builder, "START");
        let gpu_arch = args
            .windows(2)
            .find(|pair| pair[0] == "--gpu-arch")
            .map(|pair| pair[1].as_str());
        let result = run_rust_action(
            workspace,
            component,
            RustActionRequest {
                operation,
                target: &target,
                release,
                gpu_arch,
                feature_profile,
                compile_env: &compile_env,
                sanitizer,
            },
        );
        match result {
            Ok(()) => emit(mode, operation, component, &target, builder, "PASS"),
            Err(error) if keep_going => {
                emit(mode, operation, component, &target, builder, "FAIL");
                failures.push(error);
            }
            Err(error) => return Err(error),
        }
    }
    if attempted == 0 {
        return Err(format!("NoTestHarnesses {{ target: {target} }}"));
    }
    if !failures.is_empty() {
        return Err(format!(
            "ComponentFailures ({}/{}):\n{}",
            failures.len(),
            attempted,
            failures.join("\n")
        ));
    }
    Ok(())
}

fn run_rust_action(
    workspace: &Workspace,
    component: &Component,
    request: RustActionRequest<'_>,
) -> Result<(), String> {
    let RustActionRequest {
        operation,
        target,
        release,
        gpu_arch,
        feature_profile,
        compile_env,
        sanitizer,
    } = request;
    let compile_target = rust_compile_target(
        component
            .rust_action
            .as_ref()
            .ok_or("NativeActionDisappeared")?,
        target,
    )?;
    let action = component
        .rust_action
        .as_ref()
        .ok_or("NativeActionDisappeared")?;
    if feature_profile != "default"
        && !action.feature_profiles.iter().any(|profile| {
            profile.name == feature_profile && profile.targets.iter().any(|item| item == target)
        })
    {
        return Err(format!(
            "RustFeatureProfileUnavailable {{ component: {}, target: {target}, profile: {feature_profile} }}",
            component.id
        ));
    }
    for name in compile_env.keys() {
        if !action.absent_compile_env.iter().any(|item| item == name)
            && !action.compile_env.iter().any(|item| &item.name == name)
        {
            return Err(format!(
                "CompileEnvNotAllowlisted {{ component: {}, name: {name} }}",
                component.id
            ));
        }
    }
    let mut built = BTreeSet::new();
    compile_rust_component(
        workspace,
        component,
        &RustCompileMode {
            target,
            compile_target: &compile_target,
            release,
            test: false,
            gpu_arch,
            compile_env,
            sanitizer,
        },
        feature_profile,
        &mut built,
    )?;
    for binary in action
        .binaries
        .iter()
        .filter(|binary| rust_binary_active(binary, action, target))
    {
        compile_declared_binary(
            workspace,
            component,
            action,
            binary,
            &RustCompileMode {
                target,
                compile_target: &compile_target,
                release,
                test: false,
                gpu_arch,
                compile_env,
                sanitizer,
            },
            feature_profile,
        )?;
    }
    if operation == "test" {
        let test_target = if matches!(target, "WINDOWS" | "LINUX" | "CUDA") {
            target
        } else {
            let host = host_family()?;
            if !action.host_test_targets.iter().any(|target| target == host) {
                return Err(format!(
                    "NativeTestTargetUnavailable {{ component: {}, build_target: {target}, host: {host} }}",
                    component.id
                ));
            }
            host
        };
        let test_compile_target = default_rust_target(test_target)?.to_owned();
        let test_mode = RustCompileMode {
            target: test_target,
            compile_target: &test_compile_target,
            release,
            test: true,
            gpu_arch,
            compile_env,
            sanitizer,
        };
        let mut test_built = BTreeSet::new();
        // Inline tests emit a test executable, not the library that separate
        // host harnesses and binary tests may link via self_extern.
        if target != test_target
            || compile_target != test_compile_target
            || feature_profile != "default"
        {
            compile_rust_component(
                workspace,
                component,
                &RustCompileMode {
                    test: false,
                    ..test_mode
                },
                "default",
                &mut test_built,
            )?;
        }
        compile_rust_component(workspace, component, &test_mode, "default", &mut test_built)?;
        for test in &action.tests {
            run_declared_test(
                workspace,
                component,
                action,
                test,
                test_target,
                release,
                sanitizer,
            )?;
        }
        for binary in action
            .binaries
            .iter()
            .filter(|binary| rust_binary_active(binary, action, test_target))
        {
            compile_declared_binary(
                workspace,
                component,
                action,
                binary,
                &RustCompileMode {
                    target: test_target,
                    compile_target: &test_compile_target,
                    release,
                    test: true,
                    gpu_arch,
                    compile_env,
                    sanitizer,
                },
                "default",
            )?;
        }
        for example in action
            .examples
            .iter()
            .filter(|example| rust_example_active(example, action, test_target))
        {
            compile_declared_example(
                workspace,
                component,
                action,
                example,
                test_target,
                release,
                sanitizer,
            )?;
        }
        for benchmark in &action.benchmarks {
            compile_declared_benchmark(
                workspace,
                component,
                action,
                benchmark,
                test_target,
                release,
                sanitizer,
            )?;
        }
    }
    Ok(())
}

fn compile_declared_ptx(
    workspace: &Workspace,
    component: &Component,
    ptx: &RustPtx,
    target: &str,
    compile_target: &str,
    release: bool,
    gpu_arch: &str,
) -> Result<(), String> {
    if !valid_gpu_architecture(gpu_arch) {
        return Err(format!("InvalidGpuArchitecture {{ value: {gpu_arch} }}"));
    }
    let output_dir = native_output_dir(workspace, target, compile_target, release)?;
    fs::create_dir_all(&output_dir)
        .map_err(|error| format!("ArtifactDirectoryError {{ detail: {error} }}"))?;
    let output = output_dir.join(&ptx.output);
    if output.is_file() {
        fs::remove_file(&output)
            .map_err(|error| format!("ArtifactCleanupError {{ detail: {error} }}"))?;
    }
    let rustc = pinned_tool("rustc")?;
    let status = Command::new(rustc)
        .current_dir(&workspace.root)
        .arg(&ptx.source)
        .args(["--crate-name", "mrml_cuda_ptx"])
        .args(["--crate-type", "cdylib"])
        .args(["--edition", "2024"])
        .args(["--target", "nvptx64-nvidia-cuda"])
        .arg("-O")
        .arg("-C")
        .arg(format!("target-cpu={gpu_arch}"))
        .args(["-C", "unsafe-allow-abi-mismatch=target-cpu"])
        .args(["--emit", "asm"])
        .arg("-o")
        .arg(&output)
        .status()
        .map_err(|error| {
            format!(
                "ToolchainUnavailable {{ target: CUDA, required_component: rustc, detail: {error} }}"
            )
        })?;
    if !status.success() || !output.is_file() {
        return Err(format!(
            "GeneratedPtxFailed {{ component: {}, gpu_arch: {gpu_arch}, status: {:?} }}",
            component.id,
            status.code()
        ));
    }
    Ok(())
}

fn apply_generated_compile_env(command: &mut Command, action: &RustAction, output_dir: &Path) {
    if let Some(ptx) = &action.ptx {
        command.env(&ptx.compile_env, output_dir);
    }
}

fn compile_rust_component(
    workspace: &Workspace,
    component: &Component,
    mode: &RustCompileMode<'_>,
    feature_profile: &str,
    built: &mut BTreeSet<String>,
) -> Result<(), String> {
    let RustCompileMode {
        target,
        compile_target,
        release,
        test,
        gpu_arch,
        compile_env,
        sanitizer,
    } = *mode;
    let build_key = format!(
        "{}#{target}#{compile_target}#{feature_profile}#{}",
        component.id,
        sanitizer.unwrap_or("none")
    );
    if !test && built.contains(&build_key) {
        return Ok(());
    }
    let action = component.rust_action.as_ref().ok_or_else(|| {
        format!(
            "NativeDependencyActionMissing {{ component: {} }}",
            component.id
        )
    })?;
    if let Some(ptx) = action
        .ptx
        .as_ref()
        .filter(|ptx| rust_features(action, target, feature_profile).contains(&ptx.feature))
    {
        compile_declared_ptx(
            workspace,
            component,
            ptx,
            target,
            compile_target,
            release,
            gpu_arch.unwrap_or(&ptx.default_gpu_arch),
        )?;
    }
    for external in action.externs.iter().filter(|external| {
        rust_extern_active(
            external,
            action,
            target,
            compile_target,
            feature_profile,
            test,
        )
    }) {
        let dependency = workspace
            .components
            .iter()
            .find(|candidate| candidate.cargo_package == external.package)
            .ok_or_else(|| {
                format!(
                    "NativeDependencyMissing {{ component: {}, dependency: {} }}",
                    component.id, external.package
                )
            })?;
        let dependency_action = dependency.rust_action.as_ref().ok_or_else(|| {
            format!(
                "NativeDependencyActionMissing {{ component: {}, dependency: {} }}",
                component.id, dependency.id
            )
        })?;
        let compile_family = compile_target_family(compile_target).ok();
        if !dependency
            .targets
            .iter()
            .any(|family| family == target || compile_family.is_some_and(|host| family == host))
            && !dependency_action
                .host_build_targets
                .iter()
                .any(|family| family == target || compile_family.is_some_and(|host| family == host))
            && !dependency_action
                .projected_build_targets
                .iter()
                .any(|family| family == target)
        {
            return Err(format!(
                "NativeDependencyTargetMismatch {{ component: {}, dependency: {}, target: {target} }}",
                component.id, dependency.id
            ));
        }
        compile_rust_component(
            workspace,
            dependency,
            &RustCompileMode {
                test: false,
                ..*mode
            },
            rust_extern_provider_profile(external, feature_profile),
            built,
        )?;
    }

    if action.crate_type == "none" {
        if !test {
            built.insert(build_key);
        }
        return Ok(());
    }

    let output_dir = native_output_dir(workspace, target, compile_target, release)?;
    fs::create_dir_all(&output_dir)
        .map_err(|error| format!("ArtifactDirectoryError {{ detail: {error} }}"))?;
    let extension = if test {
        rust_binary_extension(compile_target)
    } else {
        ""
    };
    let output = if test {
        output_dir.join(format!("{}_tests{extension}", action.crate_name))
    } else {
        native_artifact(
            workspace,
            action,
            target,
            compile_target,
            release,
            feature_profile,
        )?
    };
    let rustc = pinned_tool("rustc")?;
    let mut command = Command::new(rustc);
    command
        .current_dir(&workspace.root)
        .args(["--crate-name", &action.crate_name])
        .args(["--edition", "2024"])
        .arg(&action.source)
        .args(["--crate-type", &action.crate_type])
        .args(["-C", "panic=abort"])
        .arg("-C")
        .arg(format!(
            "metadata={}",
            rust_metadata_discriminator(component, target, compile_target, feature_profile)
        ))
        .arg("-L")
        .arg(format!("dependency={}", output_dir.display()))
        .arg("-o")
        .arg(&output);
    apply_rust_features(&mut command, component, action, target, feature_profile);
    apply_rust_compile_env(&mut command, action, compile_env);
    apply_generated_compile_env(&mut command, action, &output_dir);
    for external in action.externs.iter().filter(|external| {
        rust_extern_active(
            external,
            action,
            target,
            compile_target,
            feature_profile,
            test,
        )
    }) {
        let dependency = workspace
            .components
            .iter()
            .find(|candidate| candidate.cargo_package == external.package)
            .ok_or("NativeDependencyDisappeared")?;
        let dependency_action = dependency
            .rust_action
            .as_ref()
            .ok_or("NativeDependencyActionDisappeared")?;
        command.arg("--extern").arg(format!(
            "{}={}",
            external.crate_name,
            native_artifact(
                workspace,
                dependency_action,
                target,
                compile_target,
                release,
                rust_extern_provider_profile(external, feature_profile),
            )?
            .display()
        ));
    }
    if test {
        command.arg("--test").arg("-Zpanic-abort-tests");
        apply_test_stack(&mut command, action, compile_target);
    }
    apply_rust_compile_target(&mut command, compile_target)?;
    apply_rust_sanitizer(&mut command, sanitizer, compile_target)?;
    if release {
        command.args([
            "-C",
            "opt-level=3",
            "-C",
            "lto=thin",
            "-C",
            "codegen-units=1",
            "-C",
            "strip=symbols",
        ]);
    }
    let status = command.status().map_err(|error| {
        format!(
            "ToolchainUnavailable {{ target: {target}, required_component: rustc, detail: {error} }}"
        )
    })?;
    if !status.success() {
        return Err(format!(
            "BuildFailed {{ component: {}, target: {target}, builder: native-rustc, status: {:?} }}",
            component.id,
            status.code()
        ));
    }
    if test {
        execute_test(&output, component, action.test_stack_bytes)?;
    } else {
        built.insert(build_key);
    }
    Ok(())
}

fn run_declared_test(
    workspace: &Workspace,
    component: &Component,
    action: &RustAction,
    test: &RustTest,
    target: &str,
    release: bool,
    sanitizer: Option<&str>,
) -> Result<(), String> {
    let compile_target = default_rust_target(target)?;
    let output_dir = native_output_dir(workspace, target, compile_target, release)?;
    ensure_artifact_directory(&output_dir)?;
    let extension = rust_binary_extension(compile_target);
    let output = output_dir.join(format!("{}_tests{extension}", test.name));
    let rustc = pinned_tool("rustc")?;
    let mut command = Command::new(rustc);
    command
        .current_dir(&workspace.root)
        .args(["--crate-name", &test.name])
        .args(["--edition", "2024"])
        .arg(&test.source)
        .arg("--test")
        .arg("-Zpanic-abort-tests")
        .args(["-C", "panic=abort"])
        .arg("-L")
        .arg(format!("dependency={}", output_dir.display()))
        .arg("-o")
        .arg(&output);
    apply_rust_features(&mut command, component, action, target, "default");
    apply_rust_compile_env(&mut command, action, &BTreeMap::new());
    apply_generated_compile_env(&mut command, action, &output_dir);
    if test.self_extern {
        command.arg("--extern").arg(format!(
            "{}={}",
            action.crate_name,
            native_artifact(
                workspace,
                action,
                target,
                compile_target,
                release,
                "default",
            )?
            .display()
        ));
    }
    apply_test_stack(&mut command, action, compile_target);
    for external in action.externs.iter().filter(|external| {
        rust_extern_active(external, action, target, compile_target, "default", true)
    }) {
        let dependency = workspace
            .components
            .iter()
            .find(|candidate| candidate.cargo_package == external.package)
            .ok_or("NativeDependencyDisappeared")?;
        let dependency_action = dependency
            .rust_action
            .as_ref()
            .ok_or("NativeDependencyActionDisappeared")?;
        command.arg("--extern").arg(format!(
            "{}={}",
            external.crate_name,
            native_artifact(
                workspace,
                dependency_action,
                target,
                compile_target,
                release,
                &external.provider_profile,
            )?
            .display()
        ));
    }
    apply_rust_compile_target(&mut command, compile_target)?;
    apply_rust_sanitizer(&mut command, sanitizer, compile_target)?;
    let status = command
        .status()
        .map_err(|error| format!("TestCompileUnavailable {{ detail: {error} }}"))?;
    if !status.success() {
        return Err(format!(
            "TestCompileFailed {{ component: {}, test: {}, status: {:?} }}",
            component.id,
            test.name,
            status.code()
        ));
    }
    execute_test(&output, component, action.test_stack_bytes)
}

fn compile_declared_example(
    workspace: &Workspace,
    component: &Component,
    action: &RustAction,
    example: &RustExample,
    target: &str,
    release: bool,
    sanitizer: Option<&str>,
) -> Result<(), String> {
    let compile_target = default_rust_target(target)?;
    let output_dir = native_output_dir(workspace, target, compile_target, release)?;
    ensure_artifact_directory(&output_dir)?;
    let extension = rust_binary_extension(compile_target);
    let output = output_dir.join(format!("{}{extension}", example.name));
    let rustc = pinned_tool("rustc")?;
    let mut command = Command::new(rustc);
    command
        .current_dir(&workspace.root)
        .args(["--crate-name", &example.name])
        .args(["--edition", "2024"])
        .arg(&example.source)
        .args(["--crate-type", "bin"])
        .args(["-C", "panic=abort"])
        .arg("-L")
        .arg(format!("dependency={}", output_dir.display()))
        .arg("--extern")
        .arg(format!(
            "{}={}",
            action.crate_name,
            native_artifact(
                workspace,
                action,
                target,
                compile_target,
                release,
                "default",
            )?
            .display()
        ))
        .arg("-o")
        .arg(&output);
    apply_rust_features(&mut command, component, action, target, "default");
    apply_rust_compile_env(&mut command, action, &BTreeMap::new());
    apply_generated_compile_env(&mut command, action, &output_dir);
    for external in action.externs.iter().filter(|external| {
        rust_extern_active(external, action, target, compile_target, "default", false)
    }) {
        let dependency = workspace
            .components
            .iter()
            .find(|candidate| candidate.cargo_package == external.package)
            .ok_or("NativeDependencyDisappeared")?;
        let dependency_action = dependency
            .rust_action
            .as_ref()
            .ok_or("NativeDependencyActionDisappeared")?;
        command.arg("--extern").arg(format!(
            "{}={}",
            external.crate_name,
            native_artifact(
                workspace,
                dependency_action,
                target,
                compile_target,
                release,
                &external.provider_profile,
            )?
            .display()
        ));
    }
    apply_rust_compile_target(&mut command, compile_target)?;
    apply_rust_sanitizer(&mut command, sanitizer, compile_target)?;
    if release {
        command.args([
            "-C",
            "opt-level=3",
            "-C",
            "lto=thin",
            "-C",
            "codegen-units=1",
            "-C",
            "strip=symbols",
        ]);
    }
    let status = command
        .status()
        .map_err(|error| format!("ExampleCompileUnavailable {{ detail: {error} }}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "ExampleCompileFailed {{ component: {}, example: {}, status: {:?} }}",
            component.id,
            example.name,
            status.code()
        ))
    }
}

fn compile_declared_benchmark(
    workspace: &Workspace,
    component: &Component,
    action: &RustAction,
    benchmark: &RustBenchmark,
    target: &str,
    release: bool,
    sanitizer: Option<&str>,
) -> Result<(), String> {
    let compile_target = default_rust_target(target)?;
    let output_dir = native_output_dir(workspace, target, compile_target, release)?;
    ensure_artifact_directory(&output_dir)?;
    let extension = rust_binary_extension(compile_target);
    let output = output_dir.join(format!("{}{extension}", benchmark.name));
    let rustc = pinned_tool("rustc")?;
    let mut command = Command::new(rustc);
    command
        .current_dir(&workspace.root)
        .args(["--crate-name", &benchmark.name])
        .args(["--edition", "2024"])
        .arg(&benchmark.source)
        .args(["--crate-type", "bin"])
        .args(["-C", "panic=abort"])
        .arg("-L")
        .arg(format!("dependency={}", output_dir.display()))
        .arg("-o")
        .arg(&output);
    apply_rust_features(&mut command, component, action, target, "default");
    apply_rust_compile_env(&mut command, action, &BTreeMap::new());
    apply_generated_compile_env(&mut command, action, &output_dir);
    if benchmark.self_extern {
        command.arg("--extern").arg(format!(
            "{}={}",
            action.crate_name,
            native_artifact(
                workspace,
                action,
                target,
                compile_target,
                release,
                "default",
            )?
            .display()
        ));
    }
    for external in action.externs.iter().filter(|external| {
        rust_extern_active(external, action, target, compile_target, "default", false)
    }) {
        let dependency = workspace
            .components
            .iter()
            .find(|candidate| candidate.cargo_package == external.package)
            .ok_or("NativeDependencyDisappeared")?;
        let dependency_action = dependency
            .rust_action
            .as_ref()
            .ok_or("NativeDependencyActionDisappeared")?;
        command.arg("--extern").arg(format!(
            "{}={}",
            external.crate_name,
            native_artifact(
                workspace,
                dependency_action,
                target,
                compile_target,
                release,
                &external.provider_profile,
            )?
            .display()
        ));
    }
    apply_rust_compile_target(&mut command, compile_target)?;
    apply_rust_sanitizer(&mut command, sanitizer, compile_target)?;
    if release {
        command.args([
            "-C",
            "opt-level=3",
            "-C",
            "lto=thin",
            "-C",
            "codegen-units=1",
            "-C",
            "strip=symbols",
        ]);
    }
    let status = command
        .status()
        .map_err(|error| format!("BenchmarkCompileUnavailable {{ detail: {error} }}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "BenchmarkCompileFailed {{ component: {}, benchmark: {}, status: {:?} }}",
            component.id,
            benchmark.name,
            status.code()
        ))
    }
}

fn compile_declared_binary(
    workspace: &Workspace,
    component: &Component,
    action: &RustAction,
    binary: &RustBinary,
    mode: &RustCompileMode<'_>,
    feature_profile: &str,
) -> Result<(), String> {
    let RustCompileMode {
        target,
        compile_target,
        release,
        test,
        gpu_arch: _,
        compile_env,
        sanitizer,
    } = *mode;
    let output_dir = native_output_dir(workspace, target, compile_target, release)?;
    ensure_artifact_directory(&output_dir)?;
    let extension = rust_binary_extension(compile_target);
    let filename = if test {
        format!("{}_bin_tests{extension}", binary.output)
    } else {
        format!("{}{extension}", binary.output)
    };
    let output = output_dir.join(filename);
    let rustc = pinned_tool("rustc")?;
    let mut command = Command::new(rustc);
    command
        .current_dir(&workspace.root)
        .args(["--crate-name", &binary.crate_name])
        .args(["--edition", "2024"])
        .arg(&binary.source)
        .args(["-C", "panic=abort"])
        .arg("-L")
        .arg(format!("dependency={}", output_dir.display()))
        .arg("-o")
        .arg(&output);
    if test {
        command.arg("--test").arg("-Zpanic-abort-tests");
        apply_test_stack(&mut command, action, compile_target);
    } else {
        command.args(["--crate-type", "bin"]);
    }
    apply_rust_features(&mut command, component, action, target, feature_profile);
    apply_rust_compile_env(&mut command, action, compile_env);
    apply_generated_compile_env(&mut command, action, &output_dir);
    if binary.self_extern {
        command.arg("--extern").arg(format!(
            "{}={}",
            action.crate_name,
            native_artifact(
                workspace,
                action,
                target,
                compile_target,
                release,
                feature_profile,
            )?
            .display()
        ));
    }
    for external in action.externs.iter().filter(|external| {
        rust_extern_active(
            external,
            action,
            target,
            compile_target,
            feature_profile,
            test,
        )
    }) {
        let dependency = workspace
            .components
            .iter()
            .find(|candidate| candidate.cargo_package == external.package)
            .ok_or("NativeDependencyDisappeared")?;
        let dependency_action = dependency
            .rust_action
            .as_ref()
            .ok_or("NativeDependencyActionDisappeared")?;
        command.arg("--extern").arg(format!(
            "{}={}",
            external.crate_name,
            native_artifact(
                workspace,
                dependency_action,
                target,
                compile_target,
                release,
                rust_extern_provider_profile(external, feature_profile),
            )?
            .display()
        ));
    }
    apply_rust_compile_target(&mut command, compile_target)?;
    apply_rust_sanitizer(&mut command, sanitizer, compile_target)?;
    if release {
        command.args([
            "-C",
            "opt-level=3",
            "-C",
            "lto=thin",
            "-C",
            "codegen-units=1",
            "-C",
            "strip=symbols",
        ]);
    }
    let status = command
        .status()
        .map_err(|error| format!("BinaryCompileUnavailable {{ detail: {error} }}"))?;
    if !status.success() {
        return Err(format!(
            "BinaryCompileFailed {{ component: {}, binary: {}, test: {test}, status: {:?} }}",
            component.id,
            binary.output,
            status.code()
        ));
    }
    if test {
        execute_test(&output, component, action.test_stack_bytes)?;
    }
    Ok(())
}

fn execute_test(
    output: &Path,
    component: &Component,
    stack_bytes: Option<usize>,
) -> Result<(), String> {
    let mut command = Command::new(output);
    configure_process_stack(&mut command, stack_bytes)?;
    let status = command
        .status()
        .map_err(|error| format!("TestExecutionUnavailable {{ detail: {error} }}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "TestFailed {{ component: {}, status: {:?} }}",
            component.id,
            status.code()
        ))
    }
}

#[cfg(target_os = "linux")]
fn configure_process_stack(
    command: &mut Command,
    stack_bytes: Option<usize>,
) -> Result<(), String> {
    use std::io;
    use std::os::unix::process::CommandExt;

    #[repr(C)]
    struct RLimit {
        current: u64,
        maximum: u64,
    }
    unsafe extern "C" {
        fn setrlimit(resource: i32, limit: *const RLimit) -> i32;
    }
    const RLIMIT_STACK: i32 = 3;
    if let Some(bytes) = stack_bytes {
        let bytes = u64::try_from(bytes).map_err(|_| "RustTestStackConversionError")?;
        // SAFETY: pre_exec runs after fork and before exec. The closure captures
        // only a Copy integer, constructs the documented Linux rlimit layout,
        // and reports errno without allocation when setrlimit rejects it.
        unsafe {
            command.pre_exec(move || {
                let limit = RLimit {
                    current: bytes,
                    maximum: bytes,
                };
                if setrlimit(RLIMIT_STACK, &limit) == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn configure_process_stack(
    _command: &mut Command,
    _stack_bytes: Option<usize>,
) -> Result<(), String> {
    Ok(())
}

fn apply_test_stack(command: &mut Command, action: &RustAction, compile_target: &str) {
    if let Some(bytes) = action.test_stack_bytes {
        if compile_target == "x86_64-pc-windows-gnullvm" {
            command.arg("-C").arg(format!("link-arg=/STACK:{bytes}"));
        } else if compile_target == "x86_64-unknown-linux-gnu" {
            command
                .arg("-C")
                .arg(format!("link-arg=-Wl,-z,stack-size={bytes}"));
        }
    }
}

fn default_rust_target(target: &str) -> Result<&'static str, String> {
    match target {
        "WINDOWS" => Ok("x86_64-pc-windows-gnullvm"),
        "LINUX" => Ok("x86_64-unknown-linux-gnu"),
        "MRML_NATIVE" => Ok("x86_64-unknown-none"),
        "UEFI" => Ok("x86_64-unknown-uefi"),
        "CUDA" if cfg!(target_os = "windows") => Ok("x86_64-pc-windows-gnullvm"),
        "CUDA" if cfg!(target_os = "linux") => Ok("x86_64-unknown-linux-gnu"),
        _ => Err(format!(
            "RustActionTargetUnsupported {{ target: {target} }}"
        )),
    }
}

fn compile_target_family(compile_target: &str) -> Result<&'static str, String> {
    match compile_target {
        "x86_64-pc-windows-gnullvm" => Ok("WINDOWS"),
        "x86_64-unknown-linux-gnu" => Ok("LINUX"),
        other => Err(format!(
            "RustCompileHostFamilyUnavailable {{ target: {other} }}"
        )),
    }
}

fn rust_compile_target(action: &RustAction, target: &str) -> Result<String, String> {
    Ok(action
        .target_triples
        .iter()
        .find(|declaration| declaration.target == target)
        .map(|declaration| declaration.triple.clone())
        .unwrap_or(default_rust_target(target)?.to_owned()))
}

fn apply_rust_sanitizer(
    command: &mut Command,
    sanitizer: Option<&str>,
    compile_target: &str,
) -> Result<(), String> {
    match sanitizer {
        None => Ok(()),
        Some("address") if compile_target == "x86_64-unknown-linux-gnu" => {
            command
                .arg("-Zsanitizer=address")
                .args(["-C", "force-frame-pointers=yes"])
                .args([
                    "-C",
                    "link-arg=-lgcc_s",
                    "-C",
                    "link-arg=-lutil",
                    "-C",
                    "link-arg=-lrt",
                    "-C",
                    "link-arg=-lpthread",
                    "-C",
                    "link-arg=-lm",
                    "-C",
                    "link-arg=-ldl",
                ]);
            Ok(())
        }
        Some(value) => Err(format!(
            "UnsupportedSanitizerTarget {{ sanitizer: {value}, compile_target: {compile_target} }}"
        )),
    }
}

fn apply_rust_compile_target(command: &mut Command, compile_target: &str) -> Result<(), String> {
    match compile_target {
        "x86_64-pc-windows-gnullvm" => {
            command.args(["-C", "linker=rust-lld", "-C", "target-feature=+crt-static"]);
        }
        "x86_64-unknown-linux-gnu" | "x86_64-unknown-none" => {
            command.args(["--target", compile_target]);
        }
        "x86_64-unknown-uefi" => {
            command.args([
                "--target",
                compile_target,
                "-C",
                "link-arg=/debug:none",
                "-C",
                "link-arg=/timestamp:0",
            ]);
        }
        _ => {
            return Err(format!(
                "RustCompileTargetUnsupported {{ target: {compile_target} }}"
            ));
        }
    }
    Ok(())
}

fn rust_binary_extension(compile_target: &str) -> &'static str {
    match compile_target {
        "x86_64-pc-windows-gnullvm" => ".exe",
        "x86_64-unknown-uefi" => ".efi",
        _ => "",
    }
}

fn rust_metadata_discriminator(
    component: &Component,
    target: &str,
    compile_target: &str,
    feature_profile: &str,
) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for field in [
        component.id.as_str(),
        target,
        compile_target,
        feature_profile,
    ] {
        for byte in field.bytes().chain(core::iter::once(0xff)) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
    }
    format!("mrml_{hash:016x}")
}

fn native_output_dir(
    workspace: &Workspace,
    target: &str,
    compile_target: &str,
    release: bool,
) -> Result<PathBuf, String> {
    let target_directory = if target != "CUDA" && compile_target == default_rust_target(target)? {
        target.to_ascii_lowercase()
    } else {
        format!("{}-{compile_target}", target.to_ascii_lowercase())
    };
    Ok(workspace
        .root
        .join("target")
        .join("mrml-native")
        .join(target_directory)
        .join(if release { "release" } else { "debug" }))
}

fn ensure_artifact_directory(output_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(output_dir)
        .map_err(|error| format!("ArtifactDirectoryError {{ detail: {error} }}"))
}

fn native_artifact(
    workspace: &Workspace,
    action: &RustAction,
    target: &str,
    compile_target: &str,
    release: bool,
    feature_profile: &str,
) -> Result<PathBuf, String> {
    let profile_suffix = if feature_profile == "default" {
        String::new()
    } else {
        format!("__{feature_profile}")
    };
    let name = match (
        action.crate_type.as_str(),
        compile_target_family(compile_target).ok(),
    ) {
        ("cdylib", Some("WINDOWS")) => format!("{}{profile_suffix}.dll", action.crate_name),
        ("cdylib", Some("LINUX")) => format!("lib{}{profile_suffix}.so", action.crate_name),
        _ => format!("lib{}{profile_suffix}.rlib", action.crate_name),
    };
    Ok(native_output_dir(workspace, target, compile_target, release)?.join(name))
}

fn find_component<'a>(workspace: &'a Workspace, cargo: &str) -> Result<&'a Component, String> {
    workspace
        .components
        .iter()
        .find(|item| item.cargo_package == cargo)
        .ok_or_else(|| format!("ComponentNotFound {{ cargo_package: {cargo} }}"))
}

fn add_component<'a>(workspace: &'a Workspace, selected: &mut Vec<&'a Component>, cargo: &str) {
    if let Some(item) = workspace
        .components
        .iter()
        .find(|item| item.cargo_package == cargo)
        && !selected.iter().any(|existing| existing.id == item.id)
    {
        selected.push(item);
    }
}

fn check_cuda(args: &[String]) -> Result<(), String> {
    let gpu_arch = args
        .windows(2)
        .find(|pair| pair[0] == "--gpu-arch")
        .map(|pair| pair[1].as_str())
        .ok_or("MissingTargetMetadata { target: CUDA, required: gpu_arch }")?;
    let rustc = pinned_tool("rustc")?;
    let output = Command::new(rustc)
        .args(["--print", "target-list"])
        .output()
        .map_err(|e| {
            format!(
                "ToolchainUnavailable {{ target: CUDA, required_component: rustc, detail: {e} }}"
            )
        })?;
    let targets = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() || !targets.lines().any(|line| line == "nvptx64-nvidia-cuda") {
        return Err(
            "ToolchainUnavailable { target: CUDA, required_component: nvptx64-nvidia-cuda }".into(),
        );
    }
    if !valid_gpu_architecture(gpu_arch) {
        return Err(format!("InvalidGpuArchitecture {{ value: {gpu_arch} }}"));
    }
    Ok(())
}

fn valid_gpu_architecture(value: &str) -> bool {
    let digits = value
        .strip_prefix("sm_")
        .or_else(|| value.strip_prefix("compute_"));
    digits.is_some_and(|digits| {
        (2..=3).contains(&digits.len()) && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn emit(
    mode: OutputMode,
    operation: &str,
    component: &Component,
    target: &str,
    builder: &str,
    status: &str,
) {
    if mode == OutputMode::Structured {
        println!(
            "result|operation={operation}|component={}|target={target}|compiler=upstream-rustc|builder={builder}|status={status}",
            component.id
        );
    } else {
        println!("mrml {operation}: {} [{target}] {status}", component.id);
    }
}

fn doctor(workspace: &Workspace, args: &[String]) -> Result<(), String> {
    let mode = output_mode(args);
    let host = host_family()?;
    let rustc_path = pinned_tool("rustc")?;
    let rustc = tool_version(&rustc_path, "rustc")?;
    let graph = verify_native_graph(workspace)?;
    if mode == OutputMode::Structured {
        println!(
            "doctor|host={host}|workspace_version=3|components={}|dependencies={}|resolver=native|rustc={}",
            workspace.components.len(),
            graph.dependency_count,
            clean(&rustc)
        );
    } else {
        println!(
            "host: {host}\nworkspace: v3 ({} components; {} native dependency edges verified)\nresolver: native\nrustc: {}",
            workspace.components.len(),
            graph.dependency_count,
            rustc.trim()
        );
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct NativeGraph {
    dependency_count: usize,
    order: Vec<usize>,
}

fn verify_native_graph(workspace: &Workspace) -> Result<NativeGraph, String> {
    let mut packages = BTreeMap::new();
    for (index, component) in workspace.components.iter().enumerate() {
        if component.targets.is_empty()
            || component
                .targets
                .iter()
                .any(|target| !TARGET_FAMILIES.contains(&target.as_str()))
        {
            return Err(format!(
                "InvalidComponentTarget {{ component: {}, targets: {} }}",
                component.id,
                component.targets.join(",")
            ));
        }
        if component.outputs.is_empty() {
            return Err(format!(
                "MissingComponentOutput {{ component: {} }}",
                component.id
            ));
        }
        if packages
            .insert(component.cargo_package.as_str(), index)
            .is_some()
        {
            return Err(format!(
                "DuplicatePackageIdentity {{ package: {} }}",
                component.cargo_package
            ));
        }
    }

    let mut dependency_count = 0_usize;
    let mut edges = Vec::with_capacity(workspace.components.len());
    for component in &workspace.components {
        let mut component_edges = Vec::with_capacity(component.dependencies.len());
        for dependency in &component.dependencies {
            let index = *packages.get(dependency.as_str()).ok_or_else(|| {
                format!(
                    "MissingDependency {{ component: {}, dependency: {dependency} }}",
                    component.id
                )
            })?;
            if workspace.components[index].id == component.id {
                return Err(format!("SelfDependency {{ component: {} }}", component.id));
            }
            component_edges.push(index);
            dependency_count = dependency_count
                .checked_add(1)
                .ok_or("DependencyCountOverflow")?;
        }
        edges.push(component_edges);
    }

    let mut states = vec![0_u8; workspace.components.len()];
    let mut stack = Vec::new();
    let mut order = Vec::with_capacity(workspace.components.len());
    for index in 0..workspace.components.len() {
        visit_component(
            index,
            workspace,
            &edges,
            &mut states,
            &mut stack,
            &mut order,
        )?;
    }
    Ok(NativeGraph {
        dependency_count,
        order,
    })
}

fn visit_component(
    index: usize,
    workspace: &Workspace,
    edges: &[Vec<usize>],
    states: &mut [u8],
    stack: &mut Vec<usize>,
    order: &mut Vec<usize>,
) -> Result<(), String> {
    if stack.len() >= MAX_COMPONENTS {
        return Err(format!(
            "DependencyDepthLimit {{ limit: {MAX_COMPONENTS} }}"
        ));
    }
    match states[index] {
        2 => return Ok(()),
        1 => {
            let start = stack.iter().position(|item| *item == index).unwrap_or(0);
            let mut cycle: Vec<_> = stack[start..]
                .iter()
                .map(|item| workspace.components[*item].id.as_str())
                .collect();
            cycle.push(workspace.components[index].id.as_str());
            return Err(format!(
                "DependencyCycle {{ path: {} }}",
                cycle.join(" -> ")
            ));
        }
        _ => {}
    }
    states[index] = 1;
    stack.push(index);
    for dependency in &edges[index] {
        visit_component(*dependency, workspace, edges, states, stack, order)?;
    }
    stack.pop();
    states[index] = 2;
    order.push(index);
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct InputCounts {
    build_scripts: usize,
    proc_macros: usize,
    native_links: usize,
    compile_env: usize,
    included_files: usize,
    external_commands: usize,
}

impl InputCounts {
    fn structured(self) -> String {
        format!(
            "build-script:{},proc-macro:{},native-link:{},compile-env:{},included-file:{},external-command:{}",
            self.build_scripts,
            self.proc_macros,
            self.native_links,
            self.compile_env,
            self.included_files,
            self.external_commands
        )
    }

    fn add(&mut self, other: Self) -> Result<(), String> {
        self.build_scripts = self
            .build_scripts
            .checked_add(other.build_scripts)
            .ok_or("AuditCountOverflow")?;
        self.proc_macros = self
            .proc_macros
            .checked_add(other.proc_macros)
            .ok_or("AuditCountOverflow")?;
        self.native_links = self
            .native_links
            .checked_add(other.native_links)
            .ok_or("AuditCountOverflow")?;
        self.compile_env = self
            .compile_env
            .checked_add(other.compile_env)
            .ok_or("AuditCountOverflow")?;
        self.included_files = self
            .included_files
            .checked_add(other.included_files)
            .ok_or("AuditCountOverflow")?;
        self.external_commands = self
            .external_commands
            .checked_add(other.external_commands)
            .ok_or("AuditCountOverflow")?;
        Ok(())
    }
}

fn audit(workspace: &Workspace, args: &[String]) -> Result<(), String> {
    let mode = output_mode(args);
    let graph = verify_native_graph(workspace)?;
    let dependency_count = graph.dependency_count;
    let mut feature_count = 0_usize;
    let mut target_count = 0_usize;
    let mut counts = InputCounts::default();
    for index in &graph.order {
        let component = &workspace.components[*index];
        feature_count = feature_count
            .checked_add(component.features.len())
            .ok_or("AuditCountOverflow")?;
        target_count = target_count
            .checked_add(component.outputs.len())
            .ok_or("AuditCountOverflow")?;
        for output in &component.outputs {
            if mode == OutputMode::Structured {
                println!(
                    "native-output|component={}|declaration={}",
                    clean(&component.id),
                    clean(output)
                );
            }
        }
        if mode == OutputMode::Structured {
            println!(
                "native-component|id={}|dependencies={}|features={}",
                clean(&component.id),
                component.dependencies.join(","),
                component.features.join(",")
            );
        }
    }
    for component in &workspace.components {
        let mut component_counts = InputCounts {
            build_scripts: component
                .outputs
                .iter()
                .filter(|output| output.ends_with(":custom-build"))
                .count(),
            proc_macros: component
                .outputs
                .iter()
                .filter(|output| output.ends_with(":proc-macro"))
                .count(),
            ..InputCounts::default()
        };
        let observed = input_audit::scan_package(&workspace.root, &component.path)?;
        input_audit::verify_declarations(&component.id, &component.input_sites, &observed)?;
        for site in &observed {
            match site.kind {
                input_audit::BuildInputKind::NativeLink => {
                    component_counts.native_links = component_counts
                        .native_links
                        .checked_add(1)
                        .ok_or("AuditCountOverflow")?;
                }
                input_audit::BuildInputKind::CompileEnv => {
                    component_counts.compile_env = component_counts
                        .compile_env
                        .checked_add(1)
                        .ok_or("AuditCountOverflow")?;
                }
                input_audit::BuildInputKind::IncludedFile => {
                    component_counts.included_files = component_counts
                        .included_files
                        .checked_add(1)
                        .ok_or("AuditCountOverflow")?;
                }
                input_audit::BuildInputKind::ExternalCommand => {
                    component_counts.external_commands = component_counts
                        .external_commands
                        .checked_add(1)
                        .ok_or("AuditCountOverflow")?;
                }
            }
            if mode == OutputMode::Structured {
                let declaration = component
                    .input_sites
                    .iter()
                    .find(|declaration| {
                        declaration.kind == site.kind
                            && declaration.path == site.path
                            && declaration.fingerprint == site.fingerprint
                    })
                    .ok_or("InputSiteVerificationInvariant")?;
                println!(
                    "input|component={}|id={}|kind={}|path={}|line={}|declared_line={}|fingerprint={}",
                    clean(&component.id),
                    clean(&declaration.id),
                    site.kind.token(),
                    clean(&site.path),
                    site.line,
                    declaration.line,
                    site.fingerprint
                );
            }
        }
        if component.input_policy != component_counts {
            return Err(format!(
                "InputPolicyDrift {{ component: {}, declared: {}, actual: {} }}",
                component.id,
                component.input_policy.structured(),
                component_counts.structured()
            ));
        }
        counts.add(component_counts)?;
    }
    if mode == OutputMode::Structured {
        println!(
            "audit|status=PASS|resolver=native|components={}|dependencies={dependency_count}|features={feature_count}|outputs={target_count}|build_scripts={}|proc_macros={}|native_links={}|compile_env={}|included_files={}|external_commands={}|input_identity=fingerprint-v1",
            workspace.components.len(),
            counts.build_scripts,
            counts.proc_macros,
            counts.native_links,
            counts.compile_env,
            counts.included_files,
            counts.external_commands
        );
    } else {
        println!(
            "audit PASS (native resolver): {} components, {dependency_count} dependency records, {feature_count} features, {target_count} outputs\ninputs: {} build scripts, {} proc macros, {} native links, {} compile-time environment reads, {} included files, {} external command sites; source inputs matched by stable ID and token fingerprint",
            workspace.components.len(),
            counts.build_scripts,
            counts.proc_macros,
            counts.native_links,
            counts.compile_env,
            counts.included_files,
            counts.external_commands
        );
    }
    Ok(())
}

fn pinned_tool(tool: &str) -> Result<PathBuf, String> {
    let host = host_family()?;
    let toolchain = match host {
        "WINDOWS" => format!("{PINNED_NIGHTLY}-x86_64-pc-windows-gnullvm"),
        "LINUX" => format!("{PINNED_NIGHTLY}-x86_64-unknown-linux-gnu"),
        _ => unreachable!(),
    };
    let output = Command::new("rustup")
        .args(["which", "--toolchain", &toolchain, tool])
        .output()
        .map_err(|error| {
            format!(
                "ToolchainUnavailable {{ required_component: rustup, toolchain: {toolchain}, detail: {error} }}"
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "ToolchainUnavailable {{ required_component: {tool}, toolchain: {toolchain} }}"
        ));
    }
    let path =
        String::from_utf8(output.stdout).map_err(|_| "ToolchainPathInvalidUtf8".to_owned())?;
    let path = PathBuf::from(path.trim());
    if !path.is_file() {
        return Err(format!(
            "ToolchainPathMissing {{ required_component: {tool}, toolchain: {toolchain} }}"
        ));
    }
    Ok(path)
}

fn tool_version(tool: &Path, name: &str) -> Result<String, String> {
    let output = Command::new(tool).arg("--version").output().map_err(|e| {
        format!("ToolchainUnavailable {{ required_component: {name}, detail: {e} }}")
    })?;
    if !output.status.success() {
        return Err(format!("ToolchainFailed {{ tool: {name} }}"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn clean(value: &str) -> String {
    value.trim().replace(['|', '='], "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component(package: &str, dependencies: &[&str]) -> Component {
        Component {
            id: format!("org.mrml.{package}"),
            path: package.into(),
            cargo_package: package.into(),
            class: "TEST".into(),
            targets: vec!["WINDOWS".into(), "LINUX".into()],
            default: false,
            dependencies: dependencies.iter().map(|value| (*value).into()).collect(),
            features: Vec::new(),
            outputs: vec![format!("{package}:lib")],
            input_policy: InputCounts::default(),
            input_sites: Vec::new(),
            isolation: IsolationPolicy::default_for_kind("test"),
            rust_action: None,
        }
    }

    fn workspace(components: Vec<Component>) -> Workspace {
        Workspace {
            root: PathBuf::new(),
            components,
            interface_bindings: Vec::new(),
        }
    }

    #[test]
    fn output_mode_is_explicit() {
        assert_eq!(
            output_mode(&["--output".into(), "structured".into()]),
            OutputMode::Structured
        );
        assert_eq!(output_mode(&[]), OutputMode::Human);
    }

    #[test]
    #[cfg(not(mrml_stage_zero))]
    fn certificate_status_snapshot_rendering_is_exact_and_secret_free() {
        let status = ManagedIdentityStatus {
            identity: mrml_certificate::TlsIdentityId([0x2a; 16]),
            policy_generation: 7,
            active: None,
            renewal: None,
            renewal_lease: None,
            replacement: None,
        };
        assert_eq!(
            render_certificate_status(status, OutputMode::Structured),
            "cert-status|status=PASS|identity=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a|policy_generation=7|generation=0|identifiers=-|health=unconfigured|renewal_source=none|renew_at=0|ari_requery_at=0|expires=0|failures=0|renewal_in_progress=false\n"
        );
        assert_eq!(
            render_certificate_status(status, OutputMode::Human),
            "TLS identity 2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a\n  policy generation: 7\n  active generation: 0\n  identifiers: -\n  renewal health: unconfigured\n"
        );
        assert!(
            cert_status_command(&[])
                .unwrap_err()
                .starts_with("CertificateStatusRouteMissing")
        );
        assert_eq!(
            decode_fixed_hex::<4>("0123abcd"),
            Some([0x01, 0x23, 0xab, 0xcd])
        );
        assert_eq!(decode_fixed_hex::<4>("0123ABCD"), None);
    }

    #[test]
    #[cfg(not(mrml_stage_zero))]
    fn certificate_backup_receipt_rendering_is_exact() {
        let receipt = BackupTransferReceipt {
            state: BackupTransferReceiptState::Verified,
            purpose: mrml_certificate::BackupTransferPurpose::VerifyOnly,
            transfer_generation: 11,
            policy_generation: 7,
            accepted_bytes: 4097,
            total_bytes: 4097,
            record_count: 2,
            backup_digest: [0x5c; 32],
        };
        assert_eq!(
            render_backup_receipt(receipt, OutputMode::Structured),
            "cert-backup|status=PASS|state=verified|transfer_generation=11|policy_generation=7|accepted_bytes=4097|total_bytes=4097|records=2|digest=5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c\n"
        );
        assert_eq!(parse_nonzero_generation("1"), Ok(1));
        assert!(parse_nonzero_generation("0").is_err());
    }
    #[test]
    fn release_frontend_accepts_only_canonical_operations() {
        let workspace = workspace(Vec::new());
        assert!(
            release_command(&workspace, &[])
                .unwrap_err()
                .starts_with("ReleaseUsageError")
        );
        assert!(
            release_command(&workspace, &["create".into()])
                .unwrap_err()
                .starts_with("ReleaseUsageError")
        );
        assert!(
            release_command(&workspace, &["publish".into()])
                .unwrap_err()
                .starts_with("ReleaseUsageError")
        );
    }

    fn runtime_policy(kind: &str, package: &str, body: &str) -> IsolationPolicy {
        let manifest = format!("[manifest]\nformat = \"mrml\"\nversion = 2\n\n[isolation]\n{body}");
        let document = manifest::Document::parse(manifest.as_bytes()).unwrap();
        IsolationPolicy::parse(&document, kind, package).unwrap()
    }

    #[test]
    fn runtime_inventory_is_derived_from_exact_manifest_classification() {
        let mut application = component("app.runtime", &[]);
        application.isolation = runtime_policy(
            "application",
            &application.id,
            "default = \"native-process\"\nminimum = \"native-process\"\nmaximum = \"microvm\"\nsupported = [\"native-process\", \"microvm\"]\nruntime_class = \"microvm-eligible\"\nmust_run = true\n",
        );
        let digest = [0x52; 64];
        let records = [SystemGenerationDigestRecord {
            package_id: application.id.as_str(),
            version: 9,
            artifact_digest: &digest,
        }];
        let mut generation = [0; 256];
        let generation_length = encode_system_generation(41, &records, &mut generation).unwrap();

        let encoded = derive_runtime_inventory(
            &workspace(vec![application]),
            &generation[..generation_length],
        )
        .unwrap();
        let inventory = RuntimeInventoryView::decode(&encoded).unwrap();
        let record = inventory.records().next().unwrap();
        assert_eq!(inventory.generation(), 41);
        assert_eq!(record.package_id, "org.mrml.app.runtime");
        assert_eq!(record.version, 9);
        assert_eq!(*record.artifact_digest, digest);
        assert_eq!(record.class, RuntimeIsolationClass::MicrovmEligible);
        assert!(record.must_run);
        assert_eq!(record.preferred, RuntimeIsolationPlacement::NativeProcess);
        assert_eq!(record.minimum, RuntimeIsolationPlacement::NativeProcess);
        assert_eq!(record.maximum, RuntimeIsolationPlacement::Microvm);
        assert_ne!(
            record.supported & RuntimeIsolationPlacement::NativeProcess.bit(),
            0
        );
        assert_ne!(
            record.supported & RuntimeIsolationPlacement::Microvm.bit(),
            0
        );
        assert_eq!(record.reason, "");
    }

    #[test]
    fn runtime_inventory_rejects_unclassified_generation_members() {
        let application = component("app.unclassified", &[]);
        let digest = [0x63; 64];
        let records = [SystemGenerationDigestRecord {
            package_id: application.id.as_str(),
            version: 1,
            artifact_digest: &digest,
        }];
        let mut generation = [0; 256];
        let generation_length = encode_system_generation(7, &records, &mut generation).unwrap();
        assert_eq!(
            derive_runtime_inventory(
                &workspace(vec![application]),
                &generation[..generation_length],
            )
            .unwrap_err(),
            "RuntimeInventoryClassificationMissing { package: org.mrml.app.unclassified }"
        );
    }

    #[test]
    fn general_release_cli_consumes_one_use_key_and_verifies_explicit_root() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "mrml-system-release-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let generation_path = directory.join("generation.bin");
        let catalog_path = directory.join("catalog.bin");
        let runtime_path = directory.join("runtime.bin");
        let private_path = directory.join("release.private");
        let public_path = directory.join("release.public");
        let release_path = directory.join("system.mrs");
        let records = [SystemGenerationDigestRecord {
            package_id: "org.mrml.zstd",
            version: 3,
            artifact_digest: &[0x31; 64],
        }];
        let mut generation = [0; 128];
        let generation_length = encode_system_generation(4, &records, &mut generation).unwrap();
        let requirement = ComponentInterfaceRequirement::exact(
            "org.mrml.zim",
            "org.mrml.interface.compression.zstd",
            3,
            [0x6a; 32],
        )
        .unwrap();
        let provider = ComponentInterfaceProvider::exact(
            "org.mrml.zstd",
            "org.mrml.interface.compression.zstd",
            3,
            [0x6a; 32],
            ComponentProviderForms::MICROVM,
        )
        .unwrap();
        let mut catalog = [0; 256];
        let catalog_length =
            encode_interface_catalog(4, &[requirement], &[provider], &mut catalog).unwrap();
        let runtime_record = RuntimeInventoryRecord {
            package_id: "org.mrml.zstd",
            version: 3,
            artifact_digest: &[0x31; 64],
            class: RuntimeIsolationClass::MicrovmEligible,
            must_run: true,
            preferred: RuntimeIsolationPlacement::NativeService,
            minimum: RuntimeIsolationPlacement::NativeService,
            maximum: RuntimeIsolationPlacement::Microvm,
            supported: RuntimeIsolationPlacement::NativeService.bit()
                | RuntimeIsolationPlacement::Microvm.bit(),
            reason: "",
        };
        let mut runtime = [0; 256];
        let runtime_length = encode_runtime_inventory(4, &[runtime_record], &mut runtime).unwrap();
        fs::write(&generation_path, &generation[..generation_length]).unwrap();
        fs::write(&catalog_path, &catalog[..catalog_length]).unwrap();
        fs::write(&runtime_path, &runtime[..runtime_length]).unwrap();
        let private = vec![0x73; LAMPORT_PRIVATE_KEY_BYTES];
        let mut public = vec![0; LAMPORT_PUBLIC_KEY_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        fs::write(&private_path, &private).unwrap();
        fs::write(&public_path, &public).unwrap();
        let workspace = workspace(Vec::new());
        release_command(
            &workspace,
            &[
                "system-create".into(),
                generation_path.to_string_lossy().into_owned(),
                catalog_path.to_string_lossy().into_owned(),
                runtime_path.to_string_lossy().into_owned(),
                private_path.to_string_lossy().into_owned(),
                release_path.to_string_lossy().into_owned(),
            ],
        )
        .unwrap();
        assert!(!private_path.exists());
        assert!(
            parse_system_release(&fs::read(&release_path).unwrap())
                .unwrap()
                .runtime_inventory()
                .is_some()
        );
        release_command(
            &workspace,
            &[
                "system-verify".into(),
                release_path.to_string_lossy().into_owned(),
                public_path.to_string_lossy().into_owned(),
            ],
        )
        .unwrap();
        public[0] ^= 1;
        fs::write(&public_path, &public).unwrap();
        assert_eq!(
            release_command(
                &workspace,
                &[
                    "system-verify".into(),
                    release_path.to_string_lossy().into_owned(),
                    public_path.to_string_lossy().into_owned(),
                ],
            ),
            Err("SystemReleaseTrustRootMismatch".into())
        );
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn selector_ignores_option_values() {
        let args = vec![
            "build".into(),
            "org.mrml.compiler.core".into(),
            "--output".into(),
            "structured".into(),
        ];
        assert_eq!(selector(&args), Some("org.mrml.compiler.core"));
    }
    #[test]
    fn structured_cleaning_is_bounded_to_delimiters() {
        assert_eq!(clean("a|b=c\n"), "a_b_c");
    }
    #[test]
    fn native_declarations_are_canonicalized() {
        assert_eq!(split_declaration("z,a,z"), ["a", "z"]);
        assert!(split_declaration("").is_empty());
    }
    #[test]
    fn system_application_is_native_without_becoming_a_service() {
        assert_eq!(
            v2_build_class("application", "system-application"),
            Ok("MRML_NATIVE")
        );
        assert!(v2_build_class("service", "system-application").is_err());
        assert!(v2_build_class("application", "system-service").is_err());
    }
    #[test]
    fn rust_actions_reject_escaping_paths_and_invalid_crate_names() {
        assert!(safe_relative_path("packages/libraries/math/src/lib.rs"));
        assert!(!safe_relative_path(
            "packages/libraries/math/../crypto/src/lib.rs"
        ));
        assert!(!safe_relative_path("C:/outside.rs"));
        assert!(rust_identifier("mrml_math"));
        assert!(!rust_identifier("../mrml-math"));
        assert!(rust_output_name("mrml-git"));
        assert!(!rust_output_name("../mrml-git"));
    }
    #[test]
    fn package_identity_is_distinct_from_cargo_and_crate_identity() {
        assert!(mrml_package_identifier("org.mrml.zstd"));
        assert!(mrml_package_identifier("org.mrml.system.vmm-kvm"));
        assert!(!mrml_package_identifier("mrml-zstd"));
        assert!(!mrml_package_identifier("org.mrml.mrml_zstd"));
        assert!(!mrml_package_identifier("org.mrml.Zstd"));
        assert!(!mrml_package_identifier("org.mrml.zstd-"));
    }
    #[test]
    fn interface_binding_form_is_explicit_and_bounded() {
        let in_process = ManifestDocument::parse(
            b"[manifest]\nformat = \"mrml\"\nversion = 2\n\n[[requires]]\nbinding = \"dynamic\"\nform = \"in-process\"\n",
        )
        .unwrap();
        let section = in_process.array_sections("requires").next().unwrap();
        assert_eq!(interface_binding(section, "fixture"), Ok("dynamic"));
        assert_eq!(interface_form(section, "fixture"), Ok("in-process"));
        assert_eq!(interface_multiplicity(section, "fixture"), Ok("one"));

        let many = ManifestDocument::parse(
            b"[manifest]\nformat = \"mrml\"\nversion = 2\n\n[[requires]]\nbinding = \"dynamic\"\nform = \"isolated-service\"\nmultiplicity = \"many\"\n",
        )
        .unwrap();
        assert_eq!(
            interface_multiplicity(many.array_sections("requires").next().unwrap(), "fixture"),
            Ok("many")
        );
        let invalid = ManifestDocument::parse(
            b"[manifest]\nformat = \"mrml\"\nversion = 2\n\n[[requires]]\nbinding = \"dynamic\"\nform = \"isolated-service\"\nmultiplicity = \"ambient\"\n",
        )
        .unwrap();
        assert!(
            interface_multiplicity(
                invalid.array_sections("requires").next().unwrap(),
                "fixture"
            )
            .is_err()
        );

        let isolated = ManifestDocument::parse(
            b"[manifest]\nformat = \"mrml\"\nversion = 2\n\n[[provides]]\nbinding = \"dynamic\"\nform = \"isolated-service\"\n",
        )
        .unwrap();
        assert_eq!(
            interface_form(
                isolated.array_sections("provides").next().unwrap(),
                "fixture"
            ),
            Ok("isolated-service")
        );

        for invalid in ["static", "path", "dll", "service.exe"] {
            let text = format!(
                "[manifest]\nformat = \"mrml\"\nversion = 2\n\n[[requires]]\nbinding = \"dynamic\"\nform = \"{invalid}\"\n"
            );
            let document = ManifestDocument::parse(text.as_bytes()).unwrap();
            assert!(
                interface_form(
                    document.array_sections("requires").next().unwrap(),
                    "fixture"
                )
                .is_err()
            );
        }
        assert!(validate_dynamic_requirement("library", "org.mrml.zim").is_ok());
        assert_eq!(
            validate_dynamic_requirement("bootloader", "org.mrml.system.bootloader"),
            Err("BootDependencyInvalid { package: org.mrml.system.bootloader }".to_owned())
        );
        assert_eq!(
            validate_dynamic_requirement("recovery", "org.mrml.system.recovery"),
            Err("RecoveryDependencyInvalid { package: org.mrml.system.recovery }".to_owned())
        );
    }
    #[test]
    fn rust_target_variants_are_allowlisted_and_extension_exact() {
        assert_eq!(
            default_rust_target("MRML_NATIVE").unwrap(),
            "x86_64-unknown-none"
        );
        assert_eq!(rust_binary_extension("x86_64-unknown-uefi"), ".efi");
        assert_eq!(rust_binary_extension("x86_64-unknown-linux-gnu"), "");
        assert_eq!(default_rust_target("UEFI").unwrap(), "x86_64-unknown-uefi");
        let cuda_target = default_rust_target("CUDA").unwrap();
        let linux_output = native_output_dir(
            &workspace(Vec::new()),
            "LINUX",
            "x86_64-unknown-linux-gnu",
            false,
        )
        .unwrap();
        assert_eq!(
            linux_output,
            PathBuf::from("target/mrml-native/linux/debug")
        );
        assert_ne!(linux_output, PathBuf::from("target/mrml"));
        assert_eq!(
            native_output_dir(&workspace(Vec::new()), "CUDA", cuda_target, false).unwrap(),
            PathBuf::from("target")
                .join("mrml-native")
                .join(format!("cuda-{cuda_target}"))
                .join("debug")
        );
        let crypto = component("mrml-crypto", &[]);
        assert_ne!(
            rust_metadata_discriminator(&crypto, "WINDOWS", "x86_64-pc-windows-gnullvm", "default"),
            rust_metadata_discriminator(&crypto, "WINDOWS", "x86_64-pc-windows-gnullvm", "core")
        );
        assert!(valid_gpu_architecture("sm_120"));
        assert!(valid_gpu_architecture("compute_90"));
        assert!(!valid_gpu_architecture("sm_120;other"));
        assert!(!valid_gpu_architecture("sm_"));
    }

    #[test]
    fn experimental_linker_selection_is_explicit_and_fail_closed() {
        let arguments = [
            "mrml-rustc-experimental",
            "link-elf",
            "entry.o",
            "core.rlib",
            "--entry",
            "start",
            "-o",
            "image",
            "--release",
        ]
        .map(str::to_owned);
        assert_eq!(
            parse_experimental_link_request(&arguments, "link-elf").unwrap(),
            ExperimentalLinkRequest {
                inputs: vec!["entry.o", "core.rlib"],
                entry: "start",
                output: "image",
                release: true,
            }
        );
        assert_eq!(
            parse_experimental_link_request(
                &[
                    "mrml-rustc-production".into(),
                    "link-elf".into(),
                    "entry.o".into(),
                    "--entry".into(),
                    "start".into(),
                    "-o".into(),
                    "image".into(),
                ],
                "link-elf"
            ),
            Err("CompilerModeUnavailable { mode: MrmlRustcProduction }".into())
        );
        assert!(
            parse_experimental_link_request(
                &[
                    "mrml-rustc-experimental".into(),
                    "link-elf".into(),
                    "--entry".into(),
                    "start".into(),
                    "-o".into(),
                    "image".into(),
                ],
                "link-elf"
            )
            .is_err()
        );
        let compile_arguments = [
            "mrml-rustc-experimental",
            "compile-elf",
            "source.rs",
            "--function",
            "start",
            "-o",
            "image",
            "--release",
        ]
        .map(str::to_owned);
        assert_eq!(
            parse_experimental_compile_request(&compile_arguments, "compile-elf").unwrap(),
            ExperimentalCompileRequest {
                input: "source.rs",
                function: "start",
                output: "image",
                release: true,
            }
        );
        assert_eq!(
            parse_experimental_compile_request(
                &[
                    "upstream-rustc".into(),
                    "compile-elf".into(),
                    "source.rs".into(),
                    "--function".into(),
                    "start".into(),
                    "-o".into(),
                    "image".into(),
                ],
                "compile-elf"
            ),
            Err(
                "CompilerOperationUnsupported { mode: UpstreamRustc, operation: compile-elf }"
                    .into()
            )
        );
        assert!(
            parse_experimental_compile_request(
                &[
                    "mrml-rustc-experimental".into(),
                    "compile-elf".into(),
                    "source.rs".into(),
                    "--function".into(),
                    "start".into(),
                    "-o".into(),
                ],
                "compile-elf"
            )
            .is_err()
        );
        let pe_arguments = [
            "mrml-rustc-experimental",
            "compile-pe",
            "source.rs",
            "--function",
            "start",
            "-o",
            "image.exe",
        ]
        .map(str::to_owned);
        assert_eq!(
            parse_experimental_compile_request(&pe_arguments, "compile-pe").unwrap(),
            ExperimentalCompileRequest {
                input: "source.rs",
                function: "start",
                output: "image.exe",
                release: false,
            }
        );
        let pe_link_arguments = [
            "mrml-rustc-experimental",
            "link-pe",
            "entry.obj",
            "core.rlib",
            "--entry",
            "start",
            "-o",
            "image.exe",
        ]
        .map(str::to_owned);
        assert_eq!(
            parse_experimental_link_request(&pe_link_arguments, "link-pe").unwrap(),
            ExperimentalLinkRequest {
                inputs: vec!["entry.obj", "core.rlib"],
                entry: "start",
                output: "image.exe",
                release: false,
            }
        );
    }
    #[test]
    fn linux_address_sanitizer_links_the_unwind_runtime() {
        let mut command = Command::new("rustc");
        apply_rust_sanitizer(&mut command, Some("address"), "x86_64-unknown-linux-gnu").unwrap();
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for library in ["gcc_s", "util", "rt", "pthread", "m", "dl"] {
            let link_argument = format!("link-arg=-l{library}");
            assert!(
                arguments
                    .windows(2)
                    .any(|pair| pair == ["-C", link_argument.as_str()]),
                "missing Linux ASan runtime dependency {library}"
            );
        }
    }
    #[test]
    fn rust_externs_are_target_scoped_and_unique() {
        let externs = parse_rust_externs(
            "mrml-linux=mrml_linux@LINUX?nvidia;mrml-windows=mrml_windows@WINDOWS",
        )
        .unwrap();
        assert_eq!(externs.len(), 2);
        assert_eq!(externs[0].package, "mrml-linux");
        assert_eq!(externs[0].targets, ["LINUX"]);
        assert_eq!(externs[0].feature.as_deref(), Some("nvidia"));
        assert_eq!(externs[0].provider_profile, "default");
        assert_eq!(externs[1].feature, None);
        assert_eq!(externs[1].provider_profile, "default");
        let profiled = parse_rust_externs("mrml-crypto=mrml_crypto@*?core#kernel").unwrap();
        assert_eq!(profiled[0].feature.as_deref(), Some("core"));
        assert_eq!(profiled[0].provider_profile, "kernel");
        let test_only = parse_rust_externs("mrml-crypto=mrml_crypto@*#core!test").unwrap();
        assert!(test_only[0].test_only);
        assert_eq!(test_only[0].provider_profile, "core");
        let mut forwarded = parse_rust_externs("mrml-model=mrml_model@*").unwrap();
        forwarded[0]
            .provider_profiles
            .insert("auto".into(), "auto".into());
        assert_eq!(rust_extern_provider_profile(&forwarded[0], "auto"), "auto");
        assert_eq!(
            rust_extern_provider_profile(&forwarded[0], "runtime"),
            "default"
        );
        assert!(parse_rust_externs("mrml-runtime=bad-name@*").is_err());
        assert!(parse_rust_externs("mrml-runtime=mrml_runtime@*?").is_err());
        assert!(parse_rust_externs("mrml-runtime=mrml_runtime@*#bad-name").is_err());
        assert!(
            parse_rust_externs(
                "mrml-runtime=mrml_runtime@WINDOWS;mrml-runtime=runtime_again@LINUX"
            )
            .is_err()
        );
    }
    #[test]
    fn input_policy_requires_every_unique_kind() {
        let policy = parse_input_policy(
            "build-script:1,proc-macro:0,native-link:2,compile-env:3,included-file:4,external-command:5",
            7,
        )
        .unwrap();
        assert_eq!(policy.build_scripts, 1);
        assert_eq!(policy.external_commands, 5);
        assert!(parse_input_policy("build-script:0", 7).is_err());
        assert!(parse_input_policy(
            "build-script:0,build-script:0,proc-macro:0,native-link:0,compile-env:0,included-file:0,external-command:0",
            7
        )
        .is_err());
    }

    #[test]
    fn native_graph_orders_dependencies_before_consumers() {
        let workspace = workspace(vec![
            component("application", &["service", "library"]),
            component("service", &["library"]),
            component("library", &[]),
        ]);
        let graph = verify_native_graph(&workspace).unwrap();
        let order: Vec<_> = graph
            .order
            .iter()
            .map(|index| workspace.components[*index].cargo_package.as_str())
            .collect();
        assert_eq!(graph.dependency_count, 3);
        assert_eq!(order, ["library", "service", "application"]);
    }

    #[test]
    fn native_graph_rejects_missing_dependencies() {
        let error = verify_native_graph(&workspace(vec![component("application", &["missing"])]))
            .unwrap_err();
        assert!(error.contains("MissingDependency"));
        assert!(error.contains("missing"));
    }

    #[test]
    fn native_graph_reports_the_cycle_path() {
        let error = verify_native_graph(&workspace(vec![
            component("alpha", &["beta"]),
            component("beta", &["alpha"]),
        ]))
        .unwrap_err();
        assert_eq!(
            error,
            "DependencyCycle { path: org.mrml.alpha -> org.mrml.beta -> org.mrml.alpha }"
        );
    }

    #[test]
    fn native_graph_rejects_unknown_targets_and_empty_outputs() {
        let mut invalid_target = component("invalid-target", &[]);
        invalid_target.targets = vec!["PLAN9".into()];
        assert!(
            verify_native_graph(&workspace(vec![invalid_target]))
                .unwrap_err()
                .contains("InvalidComponentTarget")
        );

        let mut missing_output = component("missing-output", &[]);
        missing_output.outputs.clear();
        assert!(
            verify_native_graph(&workspace(vec![missing_output]))
                .unwrap_err()
                .contains("MissingComponentOutput")
        );
    }

    #[test]
    #[cfg(not(mrml_stage_zero))]
    fn certificate_restore_routes_verify_only_and_mutating_forms() {
        let verify = ["--verify-only"].map(str::to_owned);
        assert_eq!(
            cert_restore_command(&verify).unwrap_err(),
            "CertificateBackupPolicyGenerationMissing"
        );
        assert_eq!(
            cert_restore_command(&[]).unwrap_err(),
            "CertificateBackupPolicyGenerationMissing"
        );
    }

    #[test]
    #[cfg(not(mrml_stage_zero))]
    fn certificate_backup_create_requires_exact_export_inputs() {
        let create = ["create"].map(str::to_owned);
        assert_eq!(
            cert_backup_command(&create).unwrap_err(),
            "CertificateBackupPolicyGenerationMissing"
        );
    }

    #[test]
    #[cfg(not(mrml_stage_zero))]
    fn certificate_backup_create_receipt_is_secret_free_and_machine_stable() {
        let receipt = BackupExportReceipt {
            export_generation: 9,
            policy_generation: 4,
            offset: 120,
            total_bytes: 120,
            record_count: 3,
            backup_digest: [0xab; 32],
            finished: true,
        };
        let rendered =
            render_backup_export_receipt(receipt, "backup file.mrcb", OutputMode::Structured);
        assert!(rendered.contains("operation=create|status=PASS"));
        assert!(rendered.contains("file_hex=6261636b75702066696c652e6d726362"));
        assert!(!rendered.contains("backup file"));
    }
}
