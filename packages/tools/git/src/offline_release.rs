//! Bounded Linux offline-release inventory and USTAR transport.
//!
//! This module does not authenticate signatures or execute release content.
//! The caller must authenticate the exact manifest using an external trust root
//! before calling `extract_archive`. Names and archive metadata grant no authority.
use mrml_crypto::Sha256;
use mrml_runtime::{DirectoryCapability, File, FileError, Text, Vector};

mod archive;
pub use archive::{
    InspectedArchive, copy_authenticated_directory, create_archive, extract_archive,
    inspect_archive, invoking_uid, trusted_parent_capability, validate_private_parent,
};

pub const MANIFEST_NAME: &str = "release.manifest";
pub const SIGNATURE_NAME: &str = "release.manifest.cosign.bundle";
pub const MAX_FILES: usize = 20_000;
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = (1 << 33) - 1; // USTAR's eleven octal size digits.
const COPY_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseError {
    Io,
    Allocation,
    InvalidManifest,
    UnsafePath,
    UnsafeFile,
    Limit,
    Mismatch,
    InvalidArchive,
}
impl From<FileError> for ReleaseError {
    fn from(_: FileError) -> Self {
        Self::Io
    }
}
type Result<T> = core::result::Result<T, ReleaseError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseFile {
    pub path: Text,
    pub size: u64,
    pub mode: u32,
    pub digest: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    pub source: Text,
    pub files: Vector<ReleaseFile>,
}

fn reserved(path: &str) -> bool {
    matches!(path, MANIFEST_NAME | SIGNATURE_NAME)
}
fn safe_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 255
        || path.split('/').count() > 16
        || !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
        || path
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == ".." || p.starts_with('-'))
    {
        return Err(ReleaseError::UnsafePath);
    }
    Ok(())
}
fn valid_source(source: &str) -> bool {
    matches!(source.len(), 40 | 64)
        && source
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && source.bytes().any(|b| b != b'0')
}
fn append(out: &mut Vector<u8>, bytes: &[u8]) -> Result<()> {
    if out
        .len()
        .checked_add(bytes.len())
        .is_none_or(|n| n > MAX_MANIFEST_BYTES)
    {
        return Err(ReleaseError::Limit);
    }
    out.try_extend_from_slice(bytes)
        .map_err(|_| ReleaseError::Allocation)
}
fn hex(digest: &[u8; 32]) -> [u8; 64] {
    let mut out = [0; 64];
    for (i, byte) in digest.iter().enumerate() {
        out[2 * i] = b"0123456789abcdef"[(byte >> 4) as usize];
        out[2 * i + 1] = b"0123456789abcdef"[(byte & 15) as usize];
    }
    out
}
fn parse_digest(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 {
        return Err(ReleaseError::InvalidManifest);
    }
    let mut out = [0; 32];
    for (i, b) in text.bytes().enumerate() {
        let value = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => return Err(ReleaseError::InvalidManifest),
        };
        out[i / 2] |= value << if i % 2 == 0 { 4 } else { 0 };
    }
    Ok(out)
}
fn canonical_size(text: &str) -> Result<u64> {
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(ReleaseError::InvalidManifest);
    }
    let size = text
        .parse::<u64>()
        .map_err(|_| ReleaseError::InvalidManifest)?;
    if size > MAX_FILE_BYTES {
        return Err(ReleaseError::Limit);
    }
    Ok(size)
}
fn add_entry(files: &mut Vector<ReleaseFile>, entry: ReleaseFile, total: &mut u64) -> Result<()> {
    if files.len() >= MAX_FILES {
        return Err(ReleaseError::Limit);
    }
    safe_path(&entry.path)?;
    if reserved(&entry.path) || files.last().is_some_and(|old| old.path >= entry.path) {
        return Err(ReleaseError::InvalidManifest);
    }
    for (offset, byte) in entry.path.bytes().enumerate() {
        if byte == b'/'
            && files
                .binary_search_by(|f| f.path.as_str().cmp(&entry.path[..offset]))
                .is_ok()
        {
            return Err(ReleaseError::UnsafePath);
        }
    }
    *total = total
        .checked_add(entry.size)
        .filter(|n| *n <= MAX_TOTAL_BYTES)
        .ok_or(ReleaseError::Limit)?;
    files.try_push(entry).map_err(|_| ReleaseError::Allocation)
}

pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ReleaseError::Limit);
    }
    let text = core::str::from_utf8(bytes).map_err(|_| ReleaseError::InvalidManifest)?;
    if !text.ends_with('\n') {
        return Err(ReleaseError::InvalidManifest);
    }
    let mut lines = text[..text.len() - 1].split('\n');
    if lines.next() != Some("MRML-OFFLINE-RELEASE 1") {
        return Err(ReleaseError::InvalidManifest);
    }
    let source = lines
        .next()
        .and_then(|s| s.strip_prefix("source "))
        .filter(|s| valid_source(s))
        .ok_or(ReleaseError::InvalidManifest)?;
    if lines.next() != Some("platform linux/amd64") {
        return Err(ReleaseError::InvalidManifest);
    }
    let mut files = Vector::new();
    let mut total = 0;
    for line in lines {
        let mut fields = line.split(' ');
        if fields.next() != Some("file") {
            return Err(ReleaseError::InvalidManifest);
        }
        let digest = parse_digest(fields.next().ok_or(ReleaseError::InvalidManifest)?)?;
        let size = canonical_size(fields.next().ok_or(ReleaseError::InvalidManifest)?)?;
        let mode = match fields.next() {
            Some("0444") => 0o444,
            Some("0555") => 0o555,
            Some("0644") => 0o644,
            Some("0755") => 0o755,
            _ => return Err(ReleaseError::InvalidManifest),
        };
        let path = fields.next().ok_or(ReleaseError::InvalidManifest)?;
        if fields.next().is_some() {
            return Err(ReleaseError::InvalidManifest);
        }
        add_entry(
            &mut files,
            ReleaseFile {
                path: path.into(),
                size,
                mode,
                digest,
            },
            &mut total,
        )?;
    }
    if files.is_empty() {
        return Err(ReleaseError::InvalidManifest);
    }
    Ok(Manifest {
        source: source.into(),
        files,
    })
}

fn checked_file(root: &DirectoryCapability, path: &str) -> Result<File> {
    let file = root.open_regular(path)?;
    let metadata = file.metadata()?;
    if metadata.links != 1 || metadata.mode & 0o170000 != 0o100000 || metadata.mode & 0o7000 != 0 {
        return Err(ReleaseError::UnsafeFile);
    }
    Ok(file)
}
fn hash_file(file: &mut File, size: u64) -> Result<[u8; 32]> {
    let mut digest = Sha256::new();
    let mut buffer = [0; COPY_BYTES];
    let mut remaining = size;
    while remaining != 0 {
        let count = remaining.min(COPY_BYTES as u64) as usize;
        file.read_exact(&mut buffer[..count])?;
        digest.update(&buffer[..count]);
        remaining -= count as u64;
    }
    if file.read(&mut buffer[..1])? != 0 {
        return Err(ReleaseError::Mismatch);
    }
    Ok(digest.finalize())
}
fn inventory(root: &DirectoryCapability) -> Result<Vector<ReleaseFile>> {
    fn walk(
        root: &DirectoryCapability,
        dir: &DirectoryCapability,
        prefix: &str,
        files: &mut Vector<ReleaseFile>,
        nodes: &mut usize,
        total: &mut u64,
    ) -> Result<()> {
        let remaining = (MAX_FILES * 2 + 2)
            .checked_sub(*nodes)
            .ok_or(ReleaseError::Limit)?;
        let children = dir.read_directory_bounded(remaining.min(MAX_FILES + 2))?;
        // Charge the complete retained listing before descending: ancestors'
        // unvisited names remain allocated while a child is enumerated.
        *nodes = nodes
            .checked_add(children.len())
            .filter(|n| *n <= MAX_FILES * 2 + 2)
            .ok_or(ReleaseError::Limit)?;
        for child in children {
            let path = if prefix.is_empty() {
                child.name
            } else {
                mrml_runtime::mrml_format!("{prefix}/{}", child.name)
            };
            safe_path(&path)?;
            if child.is_symlink {
                return Err(ReleaseError::UnsafeFile);
            }
            if child.is_directory {
                let before = files.len();
                let descendant = root.open_directory(&path)?;
                walk(root, &descendant, &path, files, nodes, total)?;
                if files.len() == before {
                    return Err(ReleaseError::UnsafeFile);
                }
            } else {
                let mut file = checked_file(root, &path)?;
                if reserved(&path) {
                    continue;
                }
                if files.len() >= MAX_FILES {
                    return Err(ReleaseError::Limit);
                }
                let mode = file.metadata()?.mode & 0o777;
                if !matches!(mode, 0o444 | 0o555 | 0o644 | 0o755) {
                    return Err(ReleaseError::UnsafeFile);
                }
                let size = file.len()?;
                if size > MAX_FILE_BYTES {
                    return Err(ReleaseError::Limit);
                }
                *total = total
                    .checked_add(size)
                    .filter(|n| *n <= MAX_TOTAL_BYTES)
                    .ok_or(ReleaseError::Limit)?;
                let digest = hash_file(&mut file, size)?;
                files
                    .try_push(ReleaseFile {
                        path,
                        size,
                        mode,
                        digest,
                    })
                    .map_err(|_| ReleaseError::Allocation)?;
            }
        }
        Ok(())
    }
    let mut files = Vector::new();
    walk(root, root, "", &mut files, &mut 0, &mut 0)?;
    files.sort_unstable_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}
fn encode_manifest(source: &str, files: &[ReleaseFile]) -> Result<Vector<u8>> {
    if !valid_source(source) || files.is_empty() {
        return Err(ReleaseError::InvalidManifest);
    }
    let mut out = Vector::new();
    append(
        &mut out,
        mrml_runtime::mrml_format!(
            "MRML-OFFLINE-RELEASE 1\nsource {source}\nplatform linux/amd64\n"
        )
        .as_bytes(),
    )?;
    for file in files {
        append(&mut out, b"file ")?;
        append(&mut out, &hex(&file.digest))?;
        append(
            &mut out,
            mrml_runtime::mrml_format!(" {} {:04o} {}\n", file.size, file.mode, file.path)
                .as_bytes(),
        )?;
    }
    parse_manifest(&out)?;
    Ok(out)
}
pub fn generate_manifest(root: &str, source: &str) -> Result<Vector<u8>> {
    let directory = DirectoryCapability::open_root(root)?;
    encode_manifest(source, &inventory(&directory)?)
}
pub fn verify_directory(root: &str, manifest: &[u8]) -> Result<Manifest> {
    let expected = parse_manifest(manifest)?;
    let root = DirectoryCapability::open_root(root)?;
    if inventory(&root)? != expected.files {
        return Err(ReleaseError::Mismatch);
    }
    Ok(expected)
}

#[cfg(test)]
mod tests;
