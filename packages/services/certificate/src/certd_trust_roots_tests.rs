use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::atomic::{AtomicUsize, Ordering};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    root: std::path::PathBuf,
    path: std::path::PathBuf,
    uid: u32,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "mrml-certd-public-roots-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("roots.pem");
        std::fs::write(&path, b"initial").unwrap();
        let uid = std::fs::metadata(&path).unwrap().uid();
        Self { root, path, uid }
    }
    fn write(&self, bytes: &[u8]) {
        std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&self.path, bytes).unwrap();
        std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o444)).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
const PEM: &[u8] = include_bytes!("../tests/fixtures/local-acme-root.pem");
#[test]
fn actual_trust_loader_accepts_small_public_ca_file() {
    let fixture = Fixture::new();
    fixture.write(PEM);
    let chain = load_trust_roots_at(&fixture.path, fixture.uid, Sha256::digest(PEM)).unwrap();
    assert_eq!(chain.count(), 1);
    assert_eq!(
        chain.certificate(0),
        PemCertificateChain::parse(PEM).unwrap().certificate(0)
    );
}
#[test]
fn actual_trust_loader_uses_public_chain_bound_without_raising_secret_bound() {
    let fixture = Fixture::new();
    let mut pem = PEM.to_vec();
    pem.resize(MAX_CERTIFICATE_CHAIN_BYTES, b'\n');
    fixture.write(&pem);
    assert_eq!(
        load_trust_roots_at(&fixture.path, fixture.uid, Sha256::digest(&pem))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(mrml_certificate::MAX_HOSTED_SECRET_BYTES, 16 * 1024);
    assert!(matches!(
        HostedSecret::open(
            &fixture.path,
            fixture.uid,
            0o444,
            MAX_CERTIFICATE_CHAIN_BYTES
        ),
        Err(mrml_certificate::HostedSecretError::Oversized)
    ));
}
#[test]
fn actual_trust_loader_preserves_digest_owner_mode_link_and_size_denials() {
    let fixture = Fixture::new();
    fixture.write(PEM);
    let digest = Sha256::digest(PEM);
    assert!(load_trust_roots_at(&fixture.path, fixture.uid, [0; 32]).is_err());
    assert!(load_trust_roots_at(&fixture.path, fixture.uid.wrapping_add(1), digest).is_err());
    for mode in [0o400, 0o644, 0o4444] {
        std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(load_trust_roots_at(&fixture.path, fixture.uid, digest).is_err());
    }
    fixture.write(PEM);
    let link = fixture.root.join("link.pem");
    symlink(&fixture.path, &link).unwrap();
    assert!(load_trust_roots_at(&link, fixture.uid, digest).is_err());
    std::fs::remove_file(&link).unwrap();
    std::fs::hard_link(&fixture.path, &link).unwrap();
    assert!(load_trust_roots_at(&fixture.path, fixture.uid, digest).is_err());
    std::fs::remove_file(&link).unwrap();
    fixture.write(&[]);
    assert!(load_trust_roots_at(&fixture.path, fixture.uid, Sha256::digest(&[])).is_err());
    let large = vec![b'\n'; MAX_CERTIFICATE_CHAIN_BYTES + 1];
    fixture.write(&large);
    assert!(load_trust_roots_at(&fixture.path, fixture.uid, Sha256::digest(&large)).is_err());
    fixture.write(PEM);
    let parent_link = fixture.root.join("parent-link");
    symlink(&fixture.root, &parent_link).unwrap();
    assert!(load_trust_roots_at(&parent_link.join("roots.pem"), fixture.uid, digest).is_err());
}
