//! Standalone hosted operator regression; the executable doubles as bounded
//! Docker/Podman/id test doubles. No real container engine is invoked.
use std::{env, fs, io::Write, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};
fn main() {
    let executable = env::args().next().unwrap();
    let name = std::path::Path::new(&executable)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    if name == "id" {
        println!("0");
        return;
    }
    if name == "docker" || name == "podman" {
        let args: Vec<_> = env::args().skip(1).collect();
        let root = PathBuf::from(env::var_os("COLD_TEST_ROOT").unwrap());
        if args.first().map(String::as_str) == Some("ps") {
            if env::var("COLD_QUERY_FAIL").unwrap() == "1" {
                std::process::exit(42);
            }
            let expected = format!(
                "volume=guard-test-{}",
                env::var("COLD_RUNNING_SUFFIX").unwrap()
            );
            if args.iter().any(|a| a == &expected) {
                println!("separate-project-running-container");
            }
            return;
        }
        if args.first().map(String::as_str) == Some("volume") {
            println!("{}", root.join("_data").display());
            return;
        }
        if args.iter().any(|a| a == "ps") {
            return;
        } // Different Compose project is empty.
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("mutation"))
            .unwrap()
            .write_all(b"attempted\n")
            .unwrap();
        std::process::exit(43);
    }
    let repository = env::current_dir().unwrap();
    let root = env::temp_dir().join(format!("mrml-trust-cold-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("_data")).unwrap();
    let binary = env::current_exe().unwrap();
    for tool in ["id", "docker", "podman"] {
        fs::hard_link(&binary, root.join(tool)).unwrap();
    }
    let environment = root.join("environment");
    fs::write(&environment, "MRML_VOLUME_PREFIX=guard-test\nMRML_PROTECTED_REPOSITORY=owner/project\nMRML_GIT_SIGNER_KEYS_VOLUME=guard-test-git-signer-keys\nMRML_GIT_SIGNER_CANDIDATE_KEYS_VOLUME=guard-test-git-signer-next-keys\nMRML_OPENPGP_CREATED_AT=1700000000\nMRML_TRUST_GENERATION=1\nMRML_REVOCATION_GENERATION=1\n").unwrap();
    fs::set_permissions(&environment, fs::Permissions::from_mode(0o600)).unwrap();
    let digest = "a".repeat(128);
    let cases: [(&str, Vec<&str>); 4] = [
        (
            "construct-git-trust-policy.sh",
            vec!["overlap", "owner/project", "1700000000", "1900000000"],
        ),
        (
            "sign-git-trust-policy.sh",
            vec![
                "overlap",
                "owner/project",
                "1",
                "2",
                "1700000000",
                "1700000001",
            ],
        ),
        (
            "select-git-signer-key-slot.sh",
            vec!["next", "1700000001", "2", "1"],
        ),
        (
            "transition-git-trust.sh",
            vec!["owner/project", "1700000001", "1", &digest],
        ),
    ];
    let mut failures = 0;
    for runtime in ["docker", "podman"] {
        for (script, arguments) in &cases {
            for suffix in ["gitd-policies", "authority-state", "git-signer-state"] {
                for query_fail in ["0", "1"] {
                    let _ = fs::remove_file(root.join("mutation"));
                    let output = Command::new("/bin/sh")
                        .arg(repository.join("deploy/compose").join(script))
                        .args(arguments)
                        .env("PATH", format!("{}:/usr/bin:/bin", root.display()))
                        .env("COLD_TEST_ROOT", &root)
                        .env("COLD_RUNNING_SUFFIX", suffix)
                        .env("COLD_QUERY_FAIL", query_fail)
                        .env("MRML_CONTAINER_RUNTIME", runtime)
                        .env("MRML_ENV_FILE", &environment)
                        .env_remove("MRML_VOLUME_PREFIX")
                        .output()
                        .unwrap();
                    let denied = !output.status.success() && !root.join("mutation").exists();
                    let reason = query_fail == "1"
                        || String::from_utf8_lossy(&output.stderr)
                            .contains("requires stopped Gitd, authority, and signer");
                    if !denied || !reason {
                        failures += 1;
                        eprintln!(
                            "FAIL {runtime} {script} {suffix} query_fail={query_fail}: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                }
            }
        }
    }
    fs::remove_dir_all(&root).unwrap();
    assert_eq!(
        failures, 0,
        "operator must reject cross-project volume consumers and failed queries before any mutation"
    );
    println!("PASS: 48 separate-project consumer/query-failure cases");
}
