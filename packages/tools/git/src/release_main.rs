#![no_std]
#![cfg_attr(not(test), no_main)]
#![cfg_attr(test, allow(dead_code))]

use mrml_error::{Result, anyhow};
use mrml_git::offline_release::{self as release, MANIFEST_NAME, Manifest, SIGNATURE_NAME};
use mrml_runtime::{
    Command, DirectoryCapability, File, Text, Vector, mrml_format as format,
    mrml_println as println,
};

const ROLES: [(&str, &str); 5] = [
    ("git-authority", "21002:21002"),
    ("gitd", "21001:21001"),
    ("git-protected-signer", "21006:21006"),
    ("git-credential-agent", "21009:21009"),
    ("git-backup", "0:0"),
];
// V6 explicitly extends the retained five-role Git profile with certificate
// service and native Git client images; no role is inferred from bundle data.
const ROLES_V6: [(&str, &str); 7] = [
    ROLES[0],
    ROLES[1],
    ROLES[2],
    ROLES[3],
    ROLES[4],
    ("certd", "21003:21003"),
    ("git", "21005:21005"),
];
const REQUIRED: &[&str] = &[
    "source.commit",
    "binaries.sha256",
    "test-evidence.txt",
    "images.git.lock",
    "evidence/streaming/source.commit",
    "evidence/streaming/metadata",
    "evidence/streaming/summary",
    "evidence/streaming/process.tsv",
    "evidence/streaming/SHA256SUMS",
    "evidence/streaming/content.sha256",
    "deploy/compose.git.yaml",
    "deploy/compose.signer.yaml",
    "deploy/compose.credential-agent.yaml",
    "deploy/start-git.sh",
    "deploy/gitd.example.conf",
];
struct Workspace {
    parent: DirectoryCapability,
    root: DirectoryCapability,
    name: Text,
    path: Text,
    inode: u64,
    device: u64,
    uid: u32,
}
fn clean(root: &DirectoryCapability, budget: &mut usize) -> Result<()> {
    let children = root.read_directory_bounded(*budget)?;
    *budget = budget
        .checked_sub(children.len())
        .ok_or_else(|| anyhow!("cleanup entry bound"))?;
    for child in children {
        if child.is_directory && !child.is_symlink {
            let directory = root.open_directory(&child.name)?;
            clean(&directory, budget)?;
            root.remove_directory(&child.name)?;
        } else {
            root.remove_file(&child.name)?;
        }
    }
    Ok(())
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let Ok(current) = self.parent.open_directory(&self.name) else {
            return;
        };
        let Ok(metadata) = current.metadata() else {
            return;
        };
        if metadata.inode != self.inode || metadata.device != self.device {
            return;
        }
        if clean(&self.root, &mut (release::MAX_FILES * 2 + 64)).is_ok() {
            let _ = self.parent.remove_directory(&self.name);
        }
    }
}
fn trusted_ancestors(path: &str, uid: u32) -> Result<()> {
    release::validate_private_parent(path, uid)
        .map_err(|e| anyhow!("unsafe trusted parent: {:?}", e))
}

impl Workspace {
    fn new(parent_path: &str) -> Result<Self> {
        let uid = release::invoking_uid().map_err(|e| anyhow!("invoking owner: {:?}", e))?;
        let parent = release::trusted_parent_capability(parent_path, uid)
            .map_err(|e| anyhow!("private workspace parent: {:?}", e))?;
        let mut random = [0; 16];
        mrml_runtime::fill_random(&mut random)
            .map_err(|_| anyhow!("private workspace randomness failed"))?;
        let mut suffix = Text::new();
        for byte in random {
            suffix.push_str(&format!("{byte:02x}"));
        }
        let name = format!(".mrml-release-{suffix}");
        let root = parent.create_directory(&name, 0o700)?;
        let metadata = root.metadata()?;
        let workspace = Self {
            parent,
            root,
            name: name.clone(),
            path: format!("{}/{name}", parent_path.trim_end_matches('/')),
            inode: metadata.inode,
            device: metadata.device,
            uid: metadata.uid,
        };
        if metadata.uid != uid || metadata.mode & 0o777 != 0o700 {
            return Err(anyhow!("private workspace mode required"));
        }
        trusted_ancestors(parent_path, metadata.uid)?;
        Ok(workspace)
    }
    fn write(&self, name: &str, bytes: &[u8]) -> Result<Text> {
        let mut file = self.root.create_new_file(name, 0o600)?;
        file.write_all(bytes)?;
        file.sync()?;
        self.root.sync()?;
        Ok(format!("{}/{name}", self.path))
    }
}
fn canonical_directory(path: &str) -> Result<Text> {
    if !path.starts_with('/') {
        return Err(anyhow!("absolute release directory required"));
    }
    // Verify original path without symlink traversal before canonicalizing names.
    DirectoryCapability::open_root(path)?;
    Ok(mrml_runtime::canonical_path(path)?)
}
fn within(path: &str, root: &str) -> bool {
    (root == "/" && path.starts_with('/'))
        || path == root
        || path
            .strip_prefix(root)
            .is_some_and(|tail| tail.starts_with('/'))
}
fn parent(path: &str) -> Result<&str> {
    let offset = path
        .rfind('/')
        .ok_or_else(|| anyhow!("absolute path required"))?;
    Ok(if offset == 0 { "/" } else { &path[..offset] })
}
fn external_path(path: &str, excluded: &str, uid: u32, executable: bool) -> Result<Text> {
    if !path.starts_with('/')
        || path.len() > 4096
        || within(path, excluded)
        || path[1..]
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(anyhow!("external absolute trust input required"));
    }
    // The original spelling is executed, so its parent must be stable too.
    // Only the final symlink may differ (notably /snap/bin/docker -> snap).
    trusted_ancestors(parent(path)?, uid)?;
    let canonical = mrml_runtime::canonical_path(path)?;
    if within(&canonical, excluded) {
        return Err(anyhow!("trust input resolves inside release"));
    }
    trusted_ancestors(parent(&canonical)?, uid)?;
    if executable {
        for parent_path in [parent(path)?, parent(&canonical)?] {
            if DirectoryCapability::open_root(parent_path)?
                .metadata()?
                .mode
                & 0o022
                != 0
            {
                return Err(anyhow!(
                    "external executable parent must not be group or other writable"
                ));
            }
        }
    }
    let file = File::open_regular(&canonical)?;
    let metadata = file.metadata()?;
    if metadata.links != 1
        || (metadata.uid != 0 && metadata.uid != uid)
        || metadata.mode & 0o7022 != 0
        || (executable && metadata.mode & 0o111 == 0)
    {
        return Err(anyhow!("unsafe external trust input"));
    }
    Ok(canonical)
}
fn read_file(root: &DirectoryCapability, name: &str, limit: usize) -> Result<Vector<u8>> {
    let mut file = root.open_regular(name)?;
    let metadata = file.metadata()?;
    if metadata.links != 1 || metadata.mode & 0o7000 != 0 {
        return Err(anyhow!("unsafe release metadata"));
    }
    let size = usize::try_from(file.len()?).map_err(|_| anyhow!("metadata size"))?;
    if size == 0 || size > limit {
        return Err(anyhow!("metadata bound"));
    }
    let mut bytes = Vector::new();
    bytes
        .try_resize(size, 0)
        .map_err(|_| anyhow!("allocation"))?;
    file.read_exact(&mut bytes)?;
    if file.read(&mut [0; 1])? != 0 {
        return Err(anyhow!("metadata changed during read"));
    }
    Ok(bytes)
}
fn authenticate(
    workspace: &Workspace,
    excluded: &str,
    manifest: &[u8],
    bundle: &[u8],
    key: &str,
    cosign: &str,
) -> Result<Manifest> {
    if manifest.len() > release::MAX_MANIFEST_BYTES || bundle.len() > release::MAX_MANIFEST_BYTES {
        return Err(anyhow!("signature input bound"));
    }
    let key = external_path(key, excluded, workspace.uid, false)?;
    external_path(cosign, excluded, workspace.uid, true)?;
    let key_parent = DirectoryCapability::open_root(parent(&key)?)?;
    let key_bytes = read_file(&key_parent, key.rsplit('/').next().unwrap_or(""), 64 * 1024)?;
    let manifest_path = workspace.write(MANIFEST_NAME, manifest)?;
    let bundle_path = workspace.write(SIGNATURE_NAME, bundle)?;
    let key_path = workspace.write("owner.pub", &key_bytes)?;
    // Invoke the original absolute spelling: Snap dispatch depends on argv[0].
    let output = Command::new(cosign)
        .args([
            "verify-blob",
            "--offline",
            "--insecure-ignore-tlog",
            "--key",
        ])
        .arg(&key_path)
        .arg("--bundle")
        .arg(&bundle_path)
        .arg(&manifest_path)
        .output_with_limits(1024 * 1024, 60_000)?;
    if !output.status.success() {
        return Err(anyhow!("external owner signature verification failed"));
    }
    release::parse_manifest(manifest)
        .map_err(|e| anyhow!("authenticated manifest rejected: {:?}", e))
}
fn metadata(root: &str) -> Result<(Vector<u8>, Vector<u8>)> {
    let root = DirectoryCapability::open_root(root)?;
    Ok((
        read_file(&root, MANIFEST_NAME, release::MAX_MANIFEST_BYTES)?,
        read_file(&root, SIGNATURE_NAME, release::MAX_MANIFEST_BYTES)?,
    ))
}
fn text(bytes: &[u8]) -> Result<&str> {
    core::str::from_utf8(bytes).map_err(|_| anyhow!("non-UTF8 release metadata"))
}
fn digest_text(bytes: &[u8; 32]) -> Text {
    let mut result = Text::new();
    for b in bytes {
        result.push_str(&format!("{b:02x}"));
    }
    result
}
struct Image {
    tag: Text,
    id: Text,
    archive: Text,
    user: Text,
    entrypoint: Text,
}
fn authenticated_metadata(
    root: &DirectoryCapability,
    manifest: &Manifest,
    name: &str,
    limit: usize,
) -> Result<Vector<u8>> {
    let index = manifest
        .files
        .binary_search_by(|entry| entry.path.as_str().cmp(name))
        .map_err(|_| anyhow!("missing authenticated metadata"))?;
    let entry = &manifest.files[index];
    let bytes = read_file(root, name, limit)?;
    if bytes.len() as u64 != entry.size || mrml_crypto::Sha256::digest(&bytes) != entry.digest {
        return Err(anyhow!("release metadata changed after authentication"));
    }
    Ok(bytes)
}
fn valid_image_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && version
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn semantics(root: &str, manifest: &Manifest) -> Result<Vector<Image>> {
    let root = DirectoryCapability::open_root(root)?;
    for name in REQUIRED {
        if manifest
            .files
            .binary_search_by(|entry| entry.path.as_str().cmp(name))
            .is_err()
        {
            return Err(anyhow!("required release payload missing"));
        }
    }
    let source = format!("{}\n", manifest.source);
    for name in ["source.commit", "evidence/streaming/source.commit"] {
        if authenticated_metadata(&root, manifest, name, 128)? != source.as_bytes() {
            return Err(anyhow!("release source identity mismatch"));
        }
    }
    let bytes = authenticated_metadata(&root, manifest, "images.git.lock", 16 * 1024)?;
    let lock = text(&bytes)?;
    if !lock.ends_with('\n') {
        return Err(anyhow!("noncanonical image lock"));
    }
    let mut lines = lock[..lock.len() - 1].split('\n');
    let roles: &[(&str, &str)] = match lines.next() {
        Some("format=mrml-images-git-v5") => &ROLES,
        Some("format=mrml-images-git-v6") => &ROLES_V6,
        _ => return Err(anyhow!("image lock version")),
    };
    let version = lines
        .next()
        .and_then(|line| line.strip_prefix("version="))
        .filter(|v| valid_image_version(v))
        .ok_or_else(|| anyhow!("image version"))?;
    if lines.next() != Some("platform=linux/amd64") {
        return Err(anyhow!("image platform"));
    }
    let mut images = Vector::new();
    for &(role, user) in roles {
        let line = lines.next().ok_or_else(|| anyhow!("missing image role"))?;
        let mut fields = line.split(' ');
        let tag = fields
            .next()
            .and_then(|f| f.strip_prefix("image="))
            .ok_or_else(|| anyhow!("image tag"))?;
        if tag != format!("mrml/{role}:{version}").as_str() {
            return Err(anyhow!("image role/tag mismatch"));
        }
        let digest = fields
            .next()
            .and_then(|f| f.strip_prefix("archive_sha256="))
            .ok_or_else(|| anyhow!("archive digest"))?;
        let id = fields
            .next()
            .and_then(|f| f.strip_prefix("producer_id=sha256:"))
            .filter(|id| {
                id.len() == 64
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    && id.bytes().any(|b| b != b'0')
            })
            .ok_or_else(|| anyhow!("producer image identity"))?;
        if fields.next() != Some(format!("user={user}").as_str()) {
            return Err(anyhow!("image user mismatch"));
        }
        let entrypoint = format!("/usr/bin/mrml-{role}");
        if fields.next() != Some(format!("entrypoint={entrypoint}").as_str())
            || fields.next().is_some()
        {
            return Err(anyhow!("image entrypoint mismatch"));
        }
        let archive = format!("images/{role}.tar");
        let entry = &manifest.files[manifest
            .files
            .binary_search_by(|f| f.path.cmp(&archive))
            .map_err(|_| anyhow!("missing image archive"))?];
        if digest != digest_text(&entry.digest).as_str() {
            return Err(anyhow!("image archive digest mismatch"));
        }
        let identity = format!("images/{role}.identity");
        let sbom = format!("sbom/{role}.spdx.json");
        for name in [&identity, &sbom] {
            if manifest
                .files
                .binary_search_by(|f| f.path.cmp(name))
                .is_err()
            {
                return Err(anyhow!("missing image metadata"));
            }
        }
        let id = format!("sha256:{id}");
        if authenticated_metadata(&root, manifest, &identity, 128)? != format!("{id}\n").as_bytes()
        {
            return Err(anyhow!("image identity file mismatch"));
        }
        images
            .try_push(Image {
                tag: tag.into(),
                id,
                archive,
                user: user.into(),
                entrypoint,
            })
            .map_err(|_| anyhow!("allocation"))?;
    }
    if lines.next().is_some() {
        return Err(anyhow!("unexpected image role"));
    }
    Ok(images)
}
fn inspect_image(docker: &str, target: &str, image: &Image) -> Result<()> {
    let output = Command::new(docker)
        .args([
            "image",
            "inspect",
            "--format",
            "{{.Id}} {{.Os}}/{{.Architecture}} {{.Config.User}} {{json .Config.Entrypoint}}",
            target,
        ])
        .output_with_limits(64 * 1024, 30_000)?;
    let expected = format!(
        "{} linux/amd64 {} [\"{}\"]\n",
        image.id, image.user, image.entrypoint
    );
    if !output.status.success() || output.stdout != expected.as_bytes() {
        return Err(anyhow!(
            "loaded Docker image ID/runtime/tag mismatch; previously loaded images are retained"
        ));
    }
    Ok(())
}
fn preflight_image(docker: &str, image: &Image) -> Result<()> {
    let reference = format!("reference={}", image.tag);
    let output = Command::new(docker)
        .args(["image", "ls", "--no-trunc", "--filter"])
        .arg(&reference)
        .args(["--format", "{{.ID}}"])
        .output_with_limits(64 * 1024, 30_000)?;
    if !output.status.success() {
        return Err(anyhow!("Docker tag preflight failed; no images loaded"));
    }
    if output.stdout.is_empty() {
        return Ok(());
    }
    if output.stdout != format!("{}\n", image.id).as_bytes() {
        return Err(anyhow!(
            "Docker tag preflight returned conflicting or malformed identities; no images loaded"
        ));
    }
    inspect_image(docker, &image.tag, image)
}

fn application_main() -> Result<()> {
    let args = mrml_runtime::command_arguments();
    let action = args.get(1).map(|a| a.as_str()).unwrap_or("");
    match action {
        "manifest" if args.len() == 4 => {
            let root = canonical_directory(&args[2])?;
            let bytes = release::generate_manifest(&root, &args[3])
                .map_err(|e| anyhow!("manifest generation: {:?}", e))?;
            let directory = DirectoryCapability::open_root(&root)?;
            let mut file = directory.create_new_file(MANIFEST_NAME, 0o644)?;
            file.write_all(&bytes)?;
            file.sync()?;
            directory.sync()?;
            println!("wrote bounded release manifest");
            Ok(())
        }
        "pack" if args.len() == 4 => {
            let root = canonical_directory(&args[2])?;
            release::create_archive(&root, &args[3])
                .map_err(|e| anyhow!("archive creation: {:?}", e))?;
            println!("created release archive; authentication remains required before consumption");
            Ok(())
        }
        "verify" | "load" if args.len() == if action == "load" { 6 } else { 5 } => {
            let root = canonical_directory(&args[2])?;
            let workspace = Workspace::new(if action == "load" {
                parent(&root)?
            } else {
                "/tmp"
            })?;
            let (manifest, bundle) = metadata(&root)?;
            let parsed = authenticate(&workspace, &root, &manifest, &bundle, &args[3], &args[4])?;
            release::verify_directory(&root, &manifest)
                .map_err(|e| anyhow!("release inventory: {:?}", e))?;
            if action == "verify" {
                semantics(&root, &parsed)?;
                println!("verified external owner signature and complete release inventory");
                return Ok(());
            }
            let docker = &args[5];
            external_path(docker, &root, workspace.uid, true)?;
            let staged = format!("{}/payload", workspace.path);
            release::copy_authenticated_directory(&root, &staged, &manifest)
                .map_err(|e| anyhow!("authenticated staging: {:?}", e))?;
            let staged_root = DirectoryCapability::open_root(&staged)?;
            if read_file(&staged_root, SIGNATURE_NAME, release::MAX_MANIFEST_BYTES)? != bundle {
                return Err(anyhow!("signature bundle changed before staging"));
            }
            let images = semantics(&staged, &parsed)?;
            for image in &images {
                preflight_image(docker, image)?;
            }
            let image_count = images.len();
            for image in images {
                let archive = format!("{}/{}", staged, image.archive);
                let output = Command::new(docker)
                    .args(["load", "--input"])
                    .arg(&archive)
                    .output_with_limits(1024 * 1024, 300_000)?;
                if !output.status.success() {
                    return Err(anyhow!(
                        "Docker load failed; any previously loaded images remain"
                    ));
                }
                inspect_image(docker, &image.id, &image)?;
                inspect_image(docker, &image.tag, &image)?;
            }
            println!(
                "loaded authenticated archives; {} expected image IDs, tags, platform, users and entrypoints verified",
                image_count
            );
            Ok(())
        }
        "extract" if args.len() == 6 => {
            let archive = release::inspect_archive(&args[2])
                .map_err(|e| anyhow!("archive inspection: {:?}", e))?;
            let workspace = Workspace::new("/tmp")?;
            let excluded = mrml_runtime::canonical_path(&args[2])?;
            authenticate(
                &workspace,
                &excluded,
                &archive.manifest,
                &archive.signature_bundle,
                &args[4],
                &args[5],
            )?;
            let manifest = archive.manifest.clone();
            let staged = format!("{}/payload", workspace.path);
            let parsed = release::extract_archive(archive, &staged, &manifest)
                .map_err(|e| anyhow!("archive extraction: {:?}", e))?;
            semantics(&staged, &parsed)?;
            release::copy_authenticated_directory(&staged, &args[3], &manifest)
                .map_err(|e| anyhow!("verified release publication: {:?}", e))?;
            println!("extracted externally authenticated release into new private destination");
            Ok(())
        }
        _ => Err(anyhow!(
            "usage: mrml-git-release manifest ROOT SOURCE | pack ROOT OUT.tar | verify ROOT OWNER_KEY COSIGN_ABS | extract TAR NEW_DEST OWNER_KEY COSIGN_ABS | load ROOT OWNER_KEY COSIGN_ABS DOCKER_ABS"
        )),
    }
}
#[cfg(test)]
mod ordinary_tests {
    use super::{valid_image_version, within};
    #[test]
    fn release_root_containment_has_exact_component_boundaries() {
        assert!(within("/usr/bin/tool", "/"));
        assert!(within("/bundle", "/bundle"));
        assert!(within("/bundle/tool", "/bundle"));
        assert!(!within("/bundle-extra/tool", "/bundle"));
        assert!(!within("relative", "/"));
    }
    #[test]
    fn image_version_uses_bounded_docker_tag_grammar() {
        for value in ["test", "v1.2.3", "_staged", "release-2026"] {
            assert!(valid_image_version(value));
        }
        for value in ["", ".hidden", "-option", "tag/alias", "two words", "é"] {
            assert!(!valid_image_version(value));
        }
        assert!(valid_image_version(
            core::str::from_utf8(&[b'a'; 128]).unwrap()
        ));
        assert!(!valid_image_version(
            core::str::from_utf8(&[b'a'; 129]).unwrap()
        ));
    }
}

#[cfg(test)]
mod release_cli_tests;
mrml_runtime::mrml_entrypoint!(application_main);
