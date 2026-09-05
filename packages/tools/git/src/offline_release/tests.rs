extern crate std;
use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::atomic::{AtomicUsize, Ordering};
static NEXT: AtomicUsize = AtomicUsize::new(0);
const SOURCE: &str = "1111111111111111111111111111111111111111";
struct Fixture {
    base: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(std::format!(
            "mrml-offline-release-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(base.join("root")).unwrap();
        Self { base }
    }
    fn path(&self, name: &str) -> std::string::String {
        self.base.join(name).to_str().unwrap().into()
    }
    fn payload(&self, name: &str, contents: &[u8], mode: u32) {
        let path = self.base.join("root").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        if path.exists() {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    fn seal(&self) -> Vector<u8> {
        let manifest = generate_manifest(&self.path("root"), SOURCE).unwrap();
        std::fs::write(self.base.join("root").join(MANIFEST_NAME), &manifest[..]).unwrap();
        std::fs::write(
            self.base.join("root").join(SIGNATURE_NAME),
            b"test-only signature oracle placeholder",
        )
        .unwrap();
        manifest
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

#[test]
fn canonical_inventory_binds_every_payload_and_rejects_mutation() {
    let fixture = Fixture::new();
    fixture.payload("bin/helper", b"helper bytes", 0o555);
    fixture.payload("images/a.tar", b"opaque image", 0o644);
    fixture.payload("compose.yaml", b"services: {}\n", 0o444);
    let manifest = fixture.seal();
    assert_eq!(
        verify_directory(&fixture.path("root"), &manifest)
            .unwrap()
            .files
            .len(),
        3
    );
    assert_eq!(
        generate_manifest(&fixture.path("root"), SOURCE).unwrap(),
        manifest
    );
    fixture.payload("compose.yaml", b"services: changed\n", 0o444);
    assert_eq!(
        verify_directory(&fixture.path("root"), &manifest),
        Err(ReleaseError::Mismatch)
    );
}
#[test]
fn inventory_rejects_extra_files_empty_directories_links_and_special_modes() {
    for attack in 0..5 {
        let fixture = Fixture::new();
        fixture.payload("payload", b"original", 0o644);
        let manifest = fixture.seal();
        match attack {
            0 => fixture.payload("extra", b"extra", 0o644),
            1 => std::fs::create_dir(fixture.base.join("root/extra")).unwrap(),
            2 => symlink("payload", fixture.base.join("root/link")).unwrap(),
            3 => std::fs::hard_link(
                fixture.base.join("root/payload"),
                fixture.base.join("root/link"),
            )
            .unwrap(),
            _ => std::fs::set_permissions(
                fixture.base.join("root/payload"),
                std::fs::Permissions::from_mode(0o4755),
            )
            .unwrap(),
        }
        assert!(verify_directory(&fixture.path("root"), &manifest).is_err());
    }
}
#[test]
fn manifest_rejects_duplicates_traversal_platform_and_noncanonical_sizes() {
    let fixture = Fixture::new();
    fixture.payload("payload", b"x", 0o644);
    let manifest = fixture.seal();
    let text = core::str::from_utf8(&manifest).unwrap();
    let line = text.lines().last().unwrap();
    let duplicate = std::format!("{text}{line}\n");
    assert!(parse_manifest(duplicate.as_bytes()).is_err());
    for changed in [
        text.replace(" payload\n", " ../payload\n"),
        text.replace(" payload\n", " /payload\n"),
        text.replace(" payload\n", " a//payload\n"),
        text.replace("linux/amd64", "linux/arm64"),
        text.replace(" 1 0644 ", " 01 0644 "),
        text.replace(" 0644 ", " 0666 "),
    ] {
        assert!(parse_manifest(changed.as_bytes()).is_err());
    }
}
#[test]
fn archive_round_trip_and_private_directory_copy_preserve_exact_bytes_and_modes() {
    let fixture = Fixture::new();
    fixture.payload("bin/helper", b"not executed", 0o755);
    fixture.payload("images/a.tar", &[0x5a; 70_001], 0o644);
    let manifest = fixture.seal();
    create_archive(&fixture.path("root"), &fixture.path("bundle.tar")).unwrap();
    let inspected = inspect_archive(&fixture.path("bundle.tar")).unwrap();
    assert_eq!(inspected.manifest, manifest);
    extract_archive(inspected, &fixture.path("extracted"), &manifest).unwrap();
    verify_directory(&fixture.path("extracted"), &manifest).unwrap();
    assert_eq!(
        std::fs::metadata(fixture.base.join("extracted"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(fixture.base.join("extracted/bin/helper"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    copy_authenticated_directory(&fixture.path("root"), &fixture.path("copied"), &manifest)
        .unwrap();
    verify_directory(&fixture.path("copied"), &manifest).unwrap();
    assert!(
        copy_authenticated_directory(&fixture.path("root"), &fixture.path("copied"), &manifest)
            .is_err()
    );
}
#[test]
fn archive_tampering_after_inspection_never_enables_payload_execution() {
    use std::io::{Seek, SeekFrom, Write};
    let fixture = Fixture::new();
    fixture.payload("a-helper", b"executable candidate", 0o755);
    let manifest = fixture.seal();
    create_archive(&fixture.path("root"), &fixture.path("bundle.tar")).unwrap();
    let inspected = inspect_archive(&fixture.path("bundle.tar")).unwrap();
    let mut corrupt = std::fs::OpenOptions::new()
        .write(true)
        .open(fixture.path("bundle.tar"))
        .unwrap();
    corrupt.seek(SeekFrom::Start(512)).unwrap();
    corrupt.write_all(b"X").unwrap();
    assert!(extract_archive(inspected, &fixture.path("rejected"), &manifest).is_err());
    let metadata = std::fs::metadata(fixture.base.join("rejected/a-helper")).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert!(!fixture.base.join("rejected/release.manifest").exists());
}
#[test]
fn archive_rejects_bad_checksum_footer_duplicates_and_link_types_before_writing() {
    let fixture = Fixture::new();
    fixture.payload("a", b"payload", 0o644);
    let _manifest = fixture.seal();
    create_archive(&fixture.path("root"), &fixture.path("bundle.tar")).unwrap();
    let original = std::fs::read(fixture.path("bundle.tar")).unwrap();
    for attack in 0..7 {
        let mut bytes = original.clone();
        match attack {
            0 => bytes[0] ^= 1,
            1 => {
                let last = bytes.len() - 1;
                bytes[last] = 1;
            }
            2 => {
                let duplicate = bytes[..1024].to_vec();
                bytes.splice(1024..1024, duplicate);
            }
            3..=5 => {
                bytes[156] = match attack {
                    3 => b'1',
                    4 => b'2',
                    _ => b'x',
                };
                fix_checksum(&mut bytes[..512]);
            }
            _ => {
                bytes[..100].fill(0);
                bytes[..4].copy_from_slice(b"../a");
                fix_checksum(&mut bytes[..512]);
            }
        }
        std::fs::write(fixture.path("bad.tar"), bytes).unwrap();
        assert!(
            inspect_archive(&fixture.path("bad.tar")).is_err(),
            "attack {attack}"
        );
    }
}
fn fix_checksum(header: &mut [u8]) {
    header[148..156].fill(b' ');
    let checksum: u64 = header.iter().map(|b| u64::from(*b)).sum();
    let text = std::format!("{checksum:07o}\0");
    header[148..156].copy_from_slice(text.as_bytes());
}

#[test]
fn destination_parent_is_checked_before_creation() {
    let fixture = Fixture::new();
    fixture.payload("payload", b"x", 0o644);
    let manifest = fixture.seal();
    for name in ["writable", "safe"] {
        std::fs::create_dir(fixture.base.join(name)).unwrap();
    }
    std::fs::set_permissions(
        fixture.base.join("writable"),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    std::fs::set_permissions(
        fixture.base.join("safe"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    symlink("safe", fixture.base.join("alias")).unwrap();
    for target in ["writable/new", "safe/../safe/new", "alias/new"] {
        assert!(
            copy_authenticated_directory(&fixture.path("root"), &fixture.path(target), &manifest)
                .is_err()
        );
        assert!(!fixture.base.join("writable/new").exists());
        assert!(!fixture.base.join("safe/new").exists());
    }
}
#[test]
fn retained_archive_ignores_path_replacement_but_rechecks_signed_metadata() {
    let fixture = Fixture::new();
    fixture.payload("a", b"payload", 0o644);
    let manifest = fixture.seal();
    create_archive(&fixture.path("root"), &fixture.path("bundle.tar")).unwrap();
    let inspected = inspect_archive(&fixture.path("bundle.tar")).unwrap();
    std::fs::rename(fixture.path("bundle.tar"), fixture.path("saved.tar")).unwrap();
    std::fs::write(fixture.path("bundle.tar"), b"different inode").unwrap();
    extract_archive(inspected, &fixture.path("retained"), &manifest).unwrap();
    verify_directory(&fixture.path("retained"), &manifest).unwrap();
    let original = std::fs::read(fixture.path("saved.tar")).unwrap();
    for (index, needle) in [
        b"MRML-OFFLINE-RELEASE".as_slice(),
        b"test-only signature oracle placeholder".as_slice(),
    ]
    .iter()
    .enumerate()
    {
        std::fs::write(fixture.path("changing.tar"), &original).unwrap();
        let inspected = inspect_archive(&fixture.path("changing.tar")).unwrap();
        let mut changed = original.clone();
        let at = changed
            .windows(needle.len())
            .position(|s| s == *needle)
            .unwrap();
        changed[at] ^= 1;
        std::fs::write(fixture.path("changing.tar"), changed).unwrap();
        let output = std::format!("metadata-rejected-{index}");
        assert!(extract_archive(inspected, &fixture.path(&output), &manifest).is_err());
        assert!(!fixture.base.join(output).exists());
    }
}
