//! Explicit local bootstrap oracles; disposable signing keys and a Rust Docker stand-in.
extern crate std;
use std::{format, string::String};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn checked(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn put(root: &Path, name: &str, bytes: &[u8], mode: u32) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
const SOURCE: &str = "1111111111111111111111111111111111111111";
const DOCKER_HELPER: &str = r#"
use std::{env,fs::OpenOptions,io::{Read,Write}};
fn main() {
 let args:Vec<String>=env::args().skip(1).collect();
 let mut trace=OpenOptions::new().create(true).append(true).open(env::var_os("MRML_RELEASE_DOCKER_TRACE").unwrap()).unwrap();
 writeln!(trace,"{}",args.join(" ")).unwrap();
 if args.first().map(String::as_str)==Some("load") {
  let mut input=Vec::new();std::io::stdin().take(1048576).read_to_end(&mut input).unwrap();
  println!("Loaded test archive");return;
 }
 if args.get(0).map(String::as_str)==Some("image") && args.get(1).map(String::as_str)==Some("ls") {
  if env::var_os("MRML_RELEASE_PREFLIGHT_FAIL").is_some(){std::process::exit(9)}
  if env::var_os("MRML_RELEASE_NO_EXISTING_TAG").is_some(){return}
  if env::var_os("MRML_RELEASE_PREFLIGHT_MALFORMED").is_some(){println!("not-an-image-id");return}
  let tag=args.iter().find_map(|arg|arg.strip_prefix("reference=")).unwrap();
  let roles=["git-authority","gitd","git-protected-signer","git-credential-agent","git-backup","certd","git"];
  let index=roles.iter().position(|role|tag.contains(&format!("/{role}:"))).unwrap();
  let id=if env::var_os("MRML_RELEASE_WRONG_ID").is_some(){"b".repeat(64)}else{format!("{}",index+1).repeat(64)};
  println!("sha256:{id}");
  if env::var_os("MRML_RELEASE_PREFLIGHT_MULTIPLE").is_some(){println!("sha256:{id}")}
  return;
 }
 if args.get(0).map(String::as_str)==Some("image") && args.get(1).map(String::as_str)==Some("inspect") {
  let image=args.last().unwrap();
  let roles=["git-authority","gitd","git-protected-signer","git-credential-agent","git-backup","certd","git"];
  let role_index=if image.starts_with("sha256:") {image.as_bytes()[7].wrapping_sub(b'1') as usize} else {roles.iter().position(|role|image.contains(&format!("/{role}:"))).unwrap()};
  let role=*roles.get(role_index).unwrap();
  let user=match role {"git-authority"=>"21002:21002","gitd"=>"21001:21001","git-protected-signer"=>"21006:21006","git-credential-agent"=>"21009:21009","git-backup"=>"0:0","certd"=>"21003:21003","git"=>"21005:21005",_=>std::process::exit(3)};
  let id=if env::var_os("MRML_RELEASE_WRONG_ID").is_some() && !image.starts_with("sha256:"){"b".repeat(64)}else{format!("{}", role_index + 1).repeat(64)};
  let template=args.iter().position(|a| a=="--format").and_then(|i|args.get(i+1)).map(String::as_str).unwrap_or("");
  if template=="{{.Id}}" {println!("sha256:{id}");}
  else if template.contains(".Id") {println!("sha256:{id} linux/amd64 {user} [\"/usr/bin/mrml-{role}\"]");}
  else {println!("linux/amd64 {user} [\"/usr/bin/mrml-{role}\"]");}
  return;
 }
 std::process::exit(4)
}
"#;
fn invoke(
    binary: &Path,
    action: &str,
    bundle: &Path,
    key: &Path,
    cosign: &Path,
    docker: &Path,
    trace: &Path,
) -> Output {
    let mut command = Command::new(binary);
    command.arg(action).arg(bundle).arg(key).arg(cosign);
    if action == "load" {
        command.arg(docker);
    }
    command
        .env("MRML_RELEASE_DOCKER_TRACE", trace)
        .env("COSIGN_PASSWORD", "")
        .output()
        .unwrap()
}
fn sign(binary: &Path, cosign: &Path, bundle: &Path, key: &Path, config: &Path) {
    checked(Command::new(binary).arg("manifest").arg(bundle).arg(SOURCE));
    checked(
        Command::new(cosign)
            .args(["sign-blob", "--yes", "--key"])
            .arg(key)
            .arg("--signing-config")
            .arg(config)
            .arg("--bundle")
            .arg(bundle.join("release.manifest.cosign.bundle"))
            .arg(bundle.join("release.manifest"))
            .env("COSIGN_PASSWORD", ""),
    );
}
fn fixture(bundle: &Path, public: &Path) {
    fixture_profile(bundle, public, false);
}
fn fixture_profile(bundle: &Path, public: &Path, extended: bool) {
    put(
        bundle,
        "source.commit",
        format!("{SOURCE}\n").as_bytes(),
        0o644,
    );
    for name in [
        "binaries.sha256",
        "test-evidence.txt",
        "evidence/streaming/source.commit",
        "evidence/streaming/metadata",
        "evidence/streaming/summary",
        "evidence/streaming/process.tsv",
        "evidence/streaming/SHA256SUMS",
        "deploy/compose.git.yaml",
        "deploy/compose.signer.yaml",
        "deploy/compose.credential-agent.yaml",
        "config/gitd.conf",
        "deploy/gitd.example.conf",
        "evidence/streaming/content.sha256",
    ] {
        put(
            bundle,
            name,
            b"local negative test fixture; not deployment evidence\n",
            0o644,
        );
    }
    put(
        bundle,
        "evidence/streaming/source.commit",
        format!("{SOURCE}\n").as_bytes(),
        0o644,
    );
    put(
        bundle,
        "deploy/start-git.sh",
        b"test-only unexecuted helper content\n",
        0o755,
    );
    put(
        bundle,
        "signatures/cosign.pub",
        &fs::read(public).unwrap(),
        0o644,
    );
    let version = if extended { 6 } else { 5 };
    let mut lock =
        format!("format=mrml-images-git-v{version}\nversion=test\nplatform=linux/amd64\n");
    let roles = [
        ("git-authority", "21002:21002"),
        ("gitd", "21001:21001"),
        ("git-protected-signer", "21006:21006"),
        ("git-credential-agent", "21009:21009"),
        ("git-backup", "0:0"),
        ("certd", "21003:21003"),
        ("git", "21005:21005"),
    ];
    for (index, &(role, user)) in roles[..if extended { 7 } else { 5 }].iter().enumerate() {
        let archive = format!("opaque fake-Docker test archive for {role}\n");
        let mut hash = mrml_crypto::Sha256::new();
        hash.update(archive.as_bytes());
        let digest: String = hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        put(
            bundle,
            &format!("images/{role}.tar"),
            archive.as_bytes(),
            0o644,
        );
        put(
            bundle,
            &format!("images/{role}.identity"),
            format!("sha256:{}\n", format!("{}", index + 1).repeat(64)).as_bytes(),
            0o644,
        );
        put(bundle, &format!("sbom/{role}.spdx.json"), b"{}\n", 0o644);
        lock.push_str(&format!("image=mrml/{role}:test archive_sha256={digest} producer_id=sha256:{} user={user} entrypoint=/usr/bin/mrml-{role}\n", format!("{}", index + 1).repeat(64)));
    }
    put(bundle, "images.git.lock", lock.as_bytes(), 0o644);
}
#[test]
#[ignore = "explicit disposable cosign3 key oracle and Rust Docker helper; requires release binary and test rustc paths"]
fn external_release_key_and_every_signed_file_gate_docker_load() {
    let binary = PathBuf::from(std::env::var_os("MRML_RELEASE_TEST_BINARY").unwrap());
    let rustc = PathBuf::from(std::env::var_os("MRML_RELEASE_TEST_RUSTC").unwrap());
    let cosign = PathBuf::from(
        std::env::var_os("MRML_RELEASE_TEST_COSIGN").unwrap_or_else(|| "/usr/bin/cosign".into()),
    );
    let root = std::env::temp_dir().join(format!("mrml-release-cli-oracle-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["owner", "attacker"] {
        checked(
            Command::new(&cosign)
                .args(["generate-key-pair", "--output-key-prefix"])
                .arg(root.join(name))
                .env("COSIGN_PASSWORD", ""),
        );
    }
    let config = root.join("offline-signing.json");
    checked(
        Command::new(&cosign)
            .args([
                "signing-config",
                "create",
                "--no-default-fulcio",
                "--no-default-oidc",
                "--no-default-rekor",
                "--no-default-tsa",
                "--out",
            ])
            .arg(&config),
    );
    fs::write(root.join("docker.rs"), DOCKER_HELPER).unwrap();
    let docker = root.join("docker");
    checked(
        Command::new(&rustc)
            .args(["--edition=2024"])
            .arg(root.join("docker.rs"))
            .arg("-o")
            .arg(&docker),
    );
    let trace = root.join("docker.trace");
    let bundle = root.join("bundle");
    fs::create_dir(&bundle).unwrap();
    let owner_public = root.join("owner.pub");
    fixture(&bundle, &owner_public);
    sign(&binary, &cosign, &bundle, &root.join("owner.key"), &config);
    assert!(
        invoke(
            &binary,
            "verify",
            &bundle,
            &owner_public,
            &cosign,
            &docker,
            &trace
        )
        .status
        .success()
    );
    assert!(!trace.exists());
    for name in [
        "deploy/compose.git.yaml",
        "deploy/start-git.sh",
        "images/gitd.tar",
        "test-evidence.txt",
        "sbom/gitd.spdx.json",
        "config/gitd.conf",
        "deploy/gitd.example.conf",
        "evidence/streaming/content.sha256",
    ] {
        let original = fs::read(bundle.join(name)).unwrap();
        fs::write(bundle.join(name), b"tampered\n").unwrap();
        assert!(
            !invoke(
                &binary,
                "load",
                &bundle,
                &owner_public,
                &cosign,
                &docker,
                &trace
            )
            .status
            .success(),
            "modified {name}"
        );
        assert!(!trace.exists());
        fs::write(bundle.join(name), original).unwrap();
    }
    let original = fs::read(bundle.join("deploy/compose.git.yaml")).unwrap();
    fs::remove_file(bundle.join("deploy/compose.git.yaml")).unwrap();
    assert!(
        !invoke(
            &binary,
            "load",
            &bundle,
            &owner_public,
            &cosign,
            &docker,
            &trace
        )
        .status
        .success()
    );
    assert!(!trace.exists());
    put(&bundle, "deploy/compose.git.yaml", &original, 0o644);
    put(&bundle, "extra-executable", b"unlisted\n", 0o755);
    assert!(
        !invoke(
            &binary,
            "load",
            &bundle,
            &owner_public,
            &cosign,
            &docker,
            &trace
        )
        .status
        .success()
    );
    assert!(!trace.exists());
    fs::remove_file(bundle.join("extra-executable")).unwrap();
    let manifest_path = bundle.join("release.manifest");
    let signature_path = bundle.join("release.manifest.cosign.bundle");
    let original_manifest = fs::read(&manifest_path).unwrap();
    let original_signature = fs::read(&signature_path).unwrap();
    let text = String::from_utf8(original_manifest.clone()).unwrap();
    let duplicate = text.lines().find(|line| line.starts_with("file ")).unwrap();
    fs::write(&manifest_path, format!("{text}{duplicate}\n")).unwrap();
    checked(
        Command::new(&cosign)
            .args(["sign-blob", "--yes", "--key"])
            .arg(root.join("owner.key"))
            .arg("--signing-config")
            .arg(&config)
            .arg("--bundle")
            .arg(&signature_path)
            .arg(&manifest_path)
            .env("COSIGN_PASSWORD", ""),
    );
    assert!(
        !invoke(
            &binary,
            "load",
            &bundle,
            &owner_public,
            &cosign,
            &docker,
            &trace
        )
        .status
        .success(),
        "valid signature must not admit duplicate manifest entries"
    );
    assert!(!trace.exists());
    fs::write(&manifest_path, original_manifest).unwrap();
    fs::write(&signature_path, original_signature).unwrap();
    let archive = root.join("release.tar");
    checked(Command::new(&binary).arg("pack").arg(&bundle).arg(&archive));
    let extracted = root.join("extracted");
    checked(
        Command::new(&binary)
            .arg("extract")
            .arg(&archive)
            .arg(&extracted)
            .arg(&owner_public)
            .arg(&cosign),
    );
    assert!(
        invoke(
            &binary,
            "verify",
            &extracted,
            &owner_public,
            &cosign,
            &docker,
            &trace
        )
        .status
        .success()
    );
    for path in [
        "release.manifest",
        "deploy/compose.git.yaml",
        "deploy/start-git.sh",
        "images/gitd.tar",
        "evidence/streaming/content.sha256",
    ] {
        assert_eq!(
            fs::read(extracted.join(path)).unwrap(),
            fs::read(bundle.join(path)).unwrap()
        );
    }
    let mut damaged_tar = fs::read(&archive).unwrap();
    let needle = b"opaque fake-Docker test archive for gitd\n";
    let offset = damaged_tar
        .windows(needle.len())
        .position(|bytes| bytes == needle)
        .unwrap();
    damaged_tar[offset] ^= 1;
    let damaged_path = root.join("tampered.tar");
    fs::write(&damaged_path, damaged_tar).unwrap();
    let rejected_destination = root.join("must-not-create");
    let rejected = Command::new(&binary)
        .arg("extract")
        .arg(&damaged_path)
        .arg(&rejected_destination)
        .arg(&owner_public)
        .arg(&cosign)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    if rejected_destination.exists() {
        assert_eq!(
            fs::metadata(&rejected_destination)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(!rejected_destination.join("release.manifest").exists());
        assert_private_partial_tree(&rejected_destination);
    }
    let mut invalid_signature_tar = fs::read(&archive).unwrap();
    let signature_bytes = fs::read(&signature_path).unwrap();
    let offset = invalid_signature_tar
        .windows(signature_bytes.len())
        .position(|bytes| bytes == signature_bytes)
        .unwrap();
    invalid_signature_tar[offset] ^= 1;
    let invalid_signature_archive = root.join("invalid-signature.tar");
    fs::write(&invalid_signature_archive, invalid_signature_tar).unwrap();
    let unauthenticated_destination = root.join("unauthenticated-must-not-create");
    let invalid = Command::new(&binary)
        .arg("extract")
        .arg(&invalid_signature_archive)
        .arg(&unauthenticated_destination)
        .arg(&owner_public)
        .arg(&cosign)
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(
        !unauthenticated_destination.exists(),
        "invalid signature must reject before destination creation"
    );
    assert!(
        !invoke(
            &binary,
            "verify",
            &bundle,
            &bundle.join("signatures/cosign.pub"),
            &cosign,
            &docker,
            &trace
        )
        .status
        .success(),
        "bundle-contained key is not external authority"
    );
    let original_manifest = fs::read(&manifest_path).unwrap();
    let original_signature = fs::read(&signature_path).unwrap();
    let mismatch = String::from_utf8(original_manifest.clone())
        .unwrap()
        .replacen(
            &format!("source {SOURCE}\n"),
            &format!("source {}\n", "2".repeat(40)),
            1,
        );
    fs::write(&manifest_path, mismatch).unwrap();
    checked(
        Command::new(&cosign)
            .args(["sign-blob", "--yes", "--key"])
            .arg(root.join("owner.key"))
            .arg("--signing-config")
            .arg(&config)
            .arg("--bundle")
            .arg(&signature_path)
            .arg(&manifest_path)
            .env("COSIGN_PASSWORD", ""),
    );
    assert!(
        !invoke(
            &binary,
            "load",
            &bundle,
            &owner_public,
            &cosign,
            &docker,
            &trace
        )
        .status
        .success(),
        "authenticated source identity must match source.commit"
    );
    assert!(!trace.exists());
    fs::write(&manifest_path, original_manifest).unwrap();
    fs::write(&signature_path, original_signature).unwrap();
    let lock_path = bundle.join("images.git.lock");
    let original_lock = fs::read_to_string(&lock_path).unwrap();
    let original_manifest = fs::read(&manifest_path).unwrap();
    let original_signature = fs::read(&signature_path).unwrap();
    let first_digest = original_lock
        .split_whitespace()
        .find_map(|field| field.strip_prefix("archive_sha256="))
        .unwrap();
    let malformed_locks = [
        original_lock.replacen("user=21002:21002", "user=0:0", 1),
        original_lock.replacen(
            "entrypoint=/usr/bin/mrml-git-authority",
            "entrypoint=/bin/unapproved",
            1,
        ),
        original_lock.replacen(first_digest, &"0".repeat(64), 1),
        format!(
            "{original_lock}image=mrml/unapproved:test archive_sha256={} producer_id=sha256:{} user=0:0 entrypoint=/bin/unapproved\n",
            "0".repeat(64),
            "9".repeat(64)
        ),
    ];
    for malformed in malformed_locks {
        fs::write(&lock_path, malformed).unwrap();
        fs::remove_file(&manifest_path).unwrap();
        fs::remove_file(&signature_path).unwrap();
        sign(&binary, &cosign, &bundle, &root.join("owner.key"), &config);
        // The malformed lock is deliberately covered by a valid owner signature;
        // rejection must come from exact release structure, before Docker.
        checked(
            Command::new(&cosign)
                .args(["verify-blob", "--key"])
                .arg(&owner_public)
                .arg("--bundle")
                .arg(&signature_path)
                .arg("--insecure-ignore-tlog")
                .arg(&manifest_path),
        );
        assert!(
            !invoke(
                &binary,
                "load",
                &bundle,
                &owner_public,
                &cosign,
                &docker,
                &trace
            )
            .status
            .success()
        );
        assert!(!trace.exists());
    }
    fs::write(&lock_path, original_lock).unwrap();
    fs::write(&manifest_path, original_manifest).unwrap();
    fs::write(&signature_path, original_signature).unwrap();
    let successful = invoke(
        &binary,
        "load",
        &bundle,
        &owner_public,
        &cosign,
        &docker,
        &trace,
    );
    assert!(
        successful.status.success(),
        "{}",
        String::from_utf8_lossy(&successful.stderr)
    );
    assert!(trace.exists());
    let positive_trace = fs::read_to_string(&trace).unwrap();
    let first_load = positive_trace.find("load ").unwrap();
    let post_load = &positive_trace[first_load..];
    let immutable = post_load
        .find(&format!("sha256:{}", "1".repeat(64)))
        .unwrap();
    let canonical = post_load.find("mrml/git-authority:test").unwrap();
    assert!(
        immutable < canonical,
        "successful load must recheck immutable ID then tag"
    );
    fs::remove_file(&trace).unwrap();
    let wrong = Command::new(&binary)
        .arg("load")
        .arg(&bundle)
        .arg(&owner_public)
        .arg(&cosign)
        .arg(&docker)
        .env("MRML_RELEASE_DOCKER_TRACE", &trace)
        .env("MRML_RELEASE_WRONG_ID", "1")
        .output()
        .unwrap();
    assert!(!wrong.status.success());
    let inspected = fs::read_to_string(&trace).unwrap();
    assert!(inspected.contains("reference=mrml/git-authority:test"));
    assert!(
        !inspected.lines().any(|line| line.starts_with("load ")),
        "wrong existing tag must reject before any image load"
    );
    fs::remove_file(&trace).unwrap();
    for flag in [
        "MRML_RELEASE_PREFLIGHT_FAIL",
        "MRML_RELEASE_PREFLIGHT_MALFORMED",
        "MRML_RELEASE_PREFLIGHT_MULTIPLE",
    ] {
        let denied = Command::new(&binary)
            .arg("load")
            .arg(&bundle)
            .arg(&owner_public)
            .arg(&cosign)
            .arg(&docker)
            .env("MRML_RELEASE_DOCKER_TRACE", &trace)
            .env(flag, "1")
            .output()
            .unwrap();
        assert!(!denied.status.success(), "{flag}");
        let calls = fs::read_to_string(&trace).unwrap();
        assert!(calls.contains("image ls "));
        assert!(!calls.lines().any(|line| line.starts_with("load ")));
        fs::remove_file(&trace).unwrap();
    }
    let absent = Command::new(&binary)
        .arg("load")
        .arg(&bundle)
        .arg(&owner_public)
        .arg(&cosign)
        .arg(&docker)
        .env("MRML_RELEASE_DOCKER_TRACE", &trace)
        .env("MRML_RELEASE_NO_EXISTING_TAG", "1")
        .output()
        .unwrap();
    assert!(
        absent.status.success(),
        "{}",
        String::from_utf8_lossy(&absent.stderr)
    );
    let calls = fs::read_to_string(&trace).unwrap();
    assert_eq!(
        calls
            .lines()
            .filter(|line| line.starts_with("load "))
            .count(),
        5
    );
    assert!(calls.contains("image inspect "));
    fs::remove_file(&trace).unwrap();
    let shared_link = std::env::temp_dir().join(format!(
        "mrml-release-untrusted-cosign-link-{}",
        std::process::id()
    ));
    std::os::unix::fs::symlink(&cosign, &shared_link).unwrap();
    assert!(
        !invoke(
            &binary,
            "verify",
            &bundle,
            &owner_public,
            &shared_link,
            &docker,
            &trace
        )
        .status
        .success(),
        "shared-parent executable symlink is not a trusted tool capability"
    );
    assert!(!trace.exists());
    fs::remove_file(&shared_link).unwrap();
    let shared_copy = std::env::temp_dir().join(format!(
        "mrml-release-untrusted-cosign-copy-{}",
        std::process::id()
    ));
    fs::copy(&cosign, &shared_copy).unwrap();
    assert!(
        !invoke(
            &binary,
            "verify",
            &bundle,
            &owner_public,
            &shared_copy,
            &docker,
            &trace
        )
        .status
        .success(),
        "shared writable executable parent is untrusted even when sticky"
    );
    assert!(!trace.exists());
    fs::remove_file(&shared_copy).unwrap();
    seven_role_profile(&binary, &cosign, &docker, &root, &config, &trace);
    let original_manifest = fs::read(&manifest_path).unwrap();
    let original_signature = fs::read(&signature_path).unwrap();
    fs::remove_file(&manifest_path).unwrap();
    fs::remove_file(&signature_path).unwrap();
    let untrusted_tool = bundle.join("deploy/cosign");
    fs::copy(&docker, &untrusted_tool).unwrap();
    sign(&binary, &cosign, &bundle, &root.join("owner.key"), &config);
    assert!(
        invoke(
            &binary,
            "verify",
            &bundle,
            &owner_public,
            &cosign,
            &docker,
            &trace
        )
        .status
        .success()
    );
    assert!(
        !invoke(
            &binary,
            "verify",
            &bundle,
            &owner_public,
            &untrusted_tool,
            &docker,
            &trace
        )
        .status
        .success(),
        "bundle-contained verifier tool must not execute"
    );
    assert!(!trace.exists());
    fs::remove_file(&untrusted_tool).unwrap();
    fs::write(&manifest_path, original_manifest).unwrap();
    fs::write(&signature_path, original_signature).unwrap();
    fs::remove_file(bundle.join("release.manifest")).unwrap();
    fs::remove_file(bundle.join("release.manifest.cosign.bundle")).unwrap();
    put(
        &bundle,
        "signatures/cosign.pub",
        &fs::read(root.join("attacker.pub")).unwrap(),
        0o644,
    );
    sign(
        &binary,
        &cosign,
        &bundle,
        &root.join("attacker.key"),
        &config,
    );
    assert!(
        invoke(
            &binary,
            "verify",
            &bundle,
            &root.join("attacker.pub"),
            &cosign,
            &docker,
            &trace
        )
        .status
        .success(),
        "replacement signature must be internally valid"
    );
    assert!(
        !invoke(
            &binary,
            "load",
            &bundle,
            &owner_public,
            &cosign,
            &docker,
            &trace
        )
        .status
        .success()
    );
    assert!(!trace.exists());
    std::eprintln!(
        "local cosign release oracle: external owner key enforced, signed file substitutions denied before Docker, wrong image ID denied"
    );
    fs::remove_dir_all(root).unwrap();
}

// Uses actual owner signatures and the same independent mock engine boundary;
// payloads are test data and do not claim Compose or real image execution.
fn seven_role_profile(
    binary: &Path,
    cosign: &Path,
    docker: &Path,
    root: &Path,
    config: &Path,
    trace: &Path,
) {
    let bundle = root.join("bundle-v6");
    fs::create_dir(&bundle).unwrap();
    let public = root.join("owner.pub");
    let private = root.join("owner.key");
    fixture_profile(&bundle, &public, true);
    sign(binary, cosign, &bundle, &private, config);
    let loaded = invoke(binary, "load", &bundle, &public, cosign, docker, trace);
    assert!(
        loaded.status.success(),
        "{}",
        String::from_utf8_lossy(&loaded.stderr)
    );
    let calls = fs::read_to_string(trace).unwrap();
    assert_eq!(
        calls
            .lines()
            .filter(|line| line.starts_with("load "))
            .count(),
        7
    );
    for (role, number) in [("certd", 6), ("git", 7)] {
        assert!(calls.contains(&format!("reference=mrml/{role}:test")));
        assert!(calls.contains(&format!("sha256:{}", format!("{number}").repeat(64))));
    }
    fs::remove_file(trace).unwrap();
    let original = fs::read_to_string(bundle.join("images.git.lock")).unwrap();
    let identity = fs::read(bundle.join("images/git.identity")).unwrap();
    for attack in 0..4 {
        let lock = match attack {
            0 => format!(
                "{original}{}\n",
                original
                    .lines()
                    .last()
                    .unwrap()
                    .replace("mrml/git:test", "mrml/unapproved:test")
            ),
            1 => original.replace("mrml-images-git-v6", "mrml-images-git-v5"),
            2 => original.replace("user=21003:21003", "user=0:0"),
            _ => original.replace(&"7".repeat(64), &"8".repeat(64)),
        };
        fs::write(bundle.join("images.git.lock"), lock).unwrap();
        if attack == 3 {
            fs::write(
                bundle.join("images/git.identity"),
                format!("sha256:{}\n", "8".repeat(64)),
            )
            .unwrap();
        }
        fs::remove_file(bundle.join("release.manifest")).unwrap();
        fs::remove_file(bundle.join("release.manifest.cosign.bundle")).unwrap();
        sign(binary, cosign, &bundle, &private, config);
        let rejected = invoke(binary, "load", &bundle, &public, cosign, docker, trace);
        assert!(!rejected.status.success(), "signed v6 attack {attack}");
        if trace.exists() {
            let calls = fs::read_to_string(trace).unwrap();
            assert!(
                !calls.lines().any(|line| line.starts_with("load ")),
                "attack {attack}"
            );
            fs::remove_file(trace).unwrap();
        }
        fs::write(bundle.join("images/git.identity"), &identity).unwrap();
    }
}

fn assert_private_partial_tree(root: &Path) {
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        let metadata = fs::symlink_metadata(&path).unwrap();
        if metadata.is_dir() {
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
            assert_private_partial_tree(&path);
        } else {
            assert!(metadata.is_file());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
    }
}

mod legacy_wrapper {
    extern crate std;
    use std::eprintln;
    use std::{format, string::String, vec::Vec};
    use std::{
        fs,
        path::{Path, PathBuf},
        process::Command,
    };
    fn run(c: &mut Command) -> Vec<u8> {
        let o = c.output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        o.stdout
    }
    fn put(root: &Path, name: &str, b: &[u8]) {
        let p = root.join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b).unwrap();
    }
    fn sha(p: &Path) -> String {
        String::from_utf8(run(Command::new("sha256sum").arg(p))).unwrap()[..64].into()
    }
    fn walk(root: &Path, at: &Path, files: &mut Vec<PathBuf>) {
        for e in fs::read_dir(at).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(root, &p, files)
            } else {
                files.push(p.strip_prefix(root).unwrap().into())
            }
        }
    }
    #[test]
    #[ignore = "explicit wrapper regression with disposable cosign keys and compiled Rust policy stand-ins"]
    fn legacy_wrapper_rejects_substituted_bundle_key() {
        let root =
            std::env::temp_dir().join(format!("mrml-legacy-release-red-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let bundle = root.join("bundle");
        fs::create_dir(&bundle).unwrap();
        for name in ["owner", "attacker"] {
            run(Command::new("cosign")
                .args(["generate-key-pair", "--output-key-prefix"])
                .arg(root.join(name))
                .env("COSIGN_PASSWORD", ""));
        }
        let cfg = bundle.join("signatures/offline-signing-config.json");
        fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        run(Command::new("cosign")
            .args([
                "signing-config",
                "create",
                "--no-default-fulcio",
                "--no-default-oidc",
                "--no-default-rekor",
                "--no-default-tsa",
                "--out",
            ])
            .arg(&cfg));
        put(
            &bundle,
            "signatures/cosign.pub",
            &fs::read(root.join("attacker.pub")).unwrap(),
        );
        let source = b"1111111111111111111111111111111111111111\n";
        for p in ["source.commit", "evidence/streaming/source.commit"] {
            put(&bundle, p, source);
        }
        for p in [
            "binaries.sha256",
            "test-evidence.txt",
            "evidence/streaming/summary",
            "evidence/streaming/process.tsv",
        ] {
            put(&bundle, p, b"local negative fixture only\n");
        }
        put(
            &bundle,
            "evidence/streaming/metadata",
            b"source_bytes=268435456\n",
        );
        put(
            &bundle,
            "evidence/streaming/SHA256SUMS",
            format!(
                "{}  source.commit\n",
                sha(&bundle.join("evidence/streaming/source.commit"))
            )
            .as_bytes(),
        );
        let mut lock =
            String::from("format=mrml-images-git-v5\nversion=test\nplatform=linux/amd64\n");
        for role in [
            "git-authority",
            "gitd",
            "git-protected-signer",
            "git-credential-agent",
            "git-backup",
        ] {
            put(
                &bundle,
                &format!("images/{role}.tar"),
                b"test image archive\n",
            );
            put(&bundle, &format!("images/{role}.identity"), b"fixture\n");
            put(&bundle, &format!("sbom/{role}.spdx.json"), b"{}\n");
            lock.push_str(&format!(
                "image=mrml/{role}:test archive_sha256={} user=0:0 entrypoint=/test\n",
                sha(&bundle.join(format!("images/{role}.tar")))
            ));
            run(Command::new("cosign")
                .args(["sign-blob", "--yes", "--key"])
                .arg(root.join("attacker.key"))
                .arg("--signing-config")
                .arg(&cfg)
                .arg("--bundle")
                .arg(bundle.join(format!("signatures/{role}.cosign.bundle")))
                .arg(bundle.join(format!("images/{role}.tar")))
                .env("COSIGN_PASSWORD", ""));
        }
        put(&bundle, "images.git.lock", lock.as_bytes());
        fs::create_dir_all(bundle.join("policy-source/deploy/compose")).unwrap();
        put(
            &bundle,
            "policy-source/tools/containers/measure-git-streaming.sh",
            b"fixture\n",
        );
        fs::write(root.join("policy.rs"),r#"use std::io::Write;fn main(){let mut f=std::fs::OpenOptions::new().create(true).append(true).open(std::env::var_os("MRML_LEGACY_SCRIPT_TRACE").unwrap()).unwrap();writeln!(f,"bundle policy executed").unwrap();}"#).unwrap();
        run(Command::new("rustc")
            .args(["--edition=2024"])
            .arg(root.join("policy.rs"))
            .arg("-o")
            .arg(root.join("policy")));
        for name in [
            "test-compose-git.sh",
            "test-compose-signer.sh",
            "test-compose-credential-agent.sh",
        ] {
            let p = bundle.join("deploy").join(name);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::copy(root.join("policy"), p).unwrap();
        }
        let mut files = Vec::new();
        walk(&bundle, &bundle, &mut files);
        files.sort();
        let mut sums = String::new();
        for p in files {
            sums.push_str(&format!("{}  {}\n", sha(&bundle.join(&p)), p.display()));
        }
        put(&bundle, "SHA256SUMS", sums.as_bytes());
        let verifier = std::env::var_os("MRML_LEGACY_BUNDLE_VERIFIER").unwrap();
        let trace = root.join("executed");
        let result = Command::new(verifier)
            .arg(&bundle)
            .arg(root.join("owner.pub"))
            .arg("/usr/bin/cosign")
            .env("MRML_LEGACY_SCRIPT_TRACE", &trace)
            .output()
            .unwrap();
        eprintln!(
            "fixture={} verifier_status={} policy_executions={}\n{}\n{}",
            root.display(),
            result.status,
            fs::read_to_string(&trace)
                .unwrap_or_default()
                .lines()
                .count(),
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            !result.status.success(),
            "legacy verifier accepted attacker key despite independent owner key and executed bundle policies"
        );
    }
}
