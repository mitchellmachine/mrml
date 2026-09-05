use super::*;

const MAX_ARCHIVE_BYTES: u64 = MAX_TOTAL_BYTES + 32 * 1024 * 1024;
const MAX_FOOTER_BYTES: u64 = 10_240;

pub struct InspectedArchive {
    file: File,
    pub manifest: Vector<u8>,
    pub signature_bundle: Vector<u8>,
}
struct TarEntry {
    path: Text,
    size: u64,
    mode: u32,
    offset: u64,
}
fn octal(field: &[u8]) -> Result<u64> {
    let mut value = 0u64;
    let mut ended = false;
    for &b in field {
        match b {
            b'0'..=b'7' if !ended => {
                value = value
                    .checked_mul(8)
                    .and_then(|n| n.checked_add(u64::from(b - b'0')))
                    .ok_or(ReleaseError::InvalidArchive)?
            }
            0 | b' ' => ended = true,
            _ => return Err(ReleaseError::InvalidArchive),
        }
    }
    Ok(value)
}
fn name(field: &[u8]) -> Result<&str> {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    if field[end..].iter().any(|b| *b != 0) {
        return Err(ReleaseError::InvalidArchive);
    }
    core::str::from_utf8(&field[..end]).map_err(|_| ReleaseError::InvalidArchive)
}
fn parse_header(header: &[u8; 512], offset: u64) -> Result<TarEntry> {
    if &header[257..263] != b"ustar\0"
        || &header[263..265] != b"00"
        || !matches!(header[156], 0 | b'0')
        || header[157..257].iter().any(|b| *b != 0)
        || header[500..].iter().any(|b| *b != 0)
    {
        return Err(ReleaseError::InvalidArchive);
    }
    let checksum = header
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                32
            } else {
                u64::from(*b)
            }
        })
        .sum::<u64>();
    if octal(&header[148..156])? != checksum {
        return Err(ReleaseError::InvalidArchive);
    }
    let prefix = name(&header[345..500])?;
    let leaf = name(&header[..100])?;
    let path = if prefix.is_empty() {
        leaf.into()
    } else {
        mrml_runtime::mrml_format!("{prefix}/{leaf}")
    };
    safe_path(&path)?;
    let mode = octal(&header[100..108])?;
    if !matches!(mode, 0o444 | 0o555 | 0o644 | 0o755) {
        return Err(ReleaseError::UnsafeFile);
    }
    // Metadata is syntax-checked, never restored as ownership or timestamps.
    for field in [&header[108..116], &header[116..124], &header[136..148]] {
        octal(field)?;
    }
    if octal(&header[329..337])? != 0 || octal(&header[337..345])? != 0 {
        return Err(ReleaseError::InvalidArchive);
    }
    let size = octal(&header[124..136])?;
    if size > MAX_FILE_BYTES {
        return Err(ReleaseError::Limit);
    }
    Ok(TarEntry {
        path,
        size,
        mode: mode as u32,
        offset,
    })
}
fn rounded(size: u64) -> Result<u64> {
    size.checked_add(511)
        .map(|n| n / 512 * 512)
        .ok_or(ReleaseError::Limit)
}
fn scan(file: &mut File) -> Result<Vector<TarEntry>> {
    let length = file.len()?;
    if length > MAX_ARCHIVE_BYTES || length < 1024 || length % 512 != 0 {
        return Err(ReleaseError::InvalidArchive);
    }
    let mut entries: Vector<TarEntry> = Vector::new();
    let mut offset = 0;
    let mut total = 0u64;
    loop {
        let mut header = [0; 512];
        file.seek(offset)?;
        file.read_exact(&mut header)?;
        if header.iter().all(|b| *b == 0) {
            let footer = length - offset;
            if !(1024..=MAX_FOOTER_BYTES).contains(&footer) {
                return Err(ReleaseError::InvalidArchive);
            }
            for _ in 1..footer / 512 {
                file.read_exact(&mut header)?;
                if header.iter().any(|b| *b != 0) {
                    return Err(ReleaseError::InvalidArchive);
                }
            }
            break;
        }
        if entries.len() >= MAX_FILES + 2 {
            return Err(ReleaseError::Limit);
        }
        let entry = parse_header(&header, offset + 512)?;
        if entries.last().is_some_and(|old| old.path >= entry.path) {
            return Err(ReleaseError::InvalidArchive);
        }
        for (i, b) in entry.path.bytes().enumerate() {
            if b == b'/'
                && entries
                    .binary_search_by(|old| old.path.as_str().cmp(&entry.path[..i]))
                    .is_ok()
            {
                return Err(ReleaseError::UnsafePath);
            }
        }
        total = total
            .checked_add(entry.size)
            .filter(|n| *n <= MAX_TOTAL_BYTES + 2 * MAX_MANIFEST_BYTES as u64)
            .ok_or(ReleaseError::Limit)?;
        offset = entry
            .offset
            .checked_add(rounded(entry.size)?)
            .filter(|n| *n <= length - 1024)
            .ok_or(ReleaseError::InvalidArchive)?;
        let padding = rounded(entry.size)? - entry.size;
        if padding != 0 {
            file.seek(entry.offset + entry.size)?;
            file.read_exact(&mut header[..padding as usize])?;
            if header[..padding as usize].iter().any(|b| *b != 0) {
                return Err(ReleaseError::InvalidArchive);
            }
        }
        entries
            .try_push(entry)
            .map_err(|_| ReleaseError::Allocation)?;
    }
    Ok(entries)
}
fn read_entry(file: &mut File, entry: &TarEntry) -> Result<Vector<u8>> {
    if entry.size > MAX_MANIFEST_BYTES as u64 {
        return Err(ReleaseError::Limit);
    }
    file.seek(entry.offset)?;
    let mut bytes = Vector::new();
    bytes
        .try_resize(entry.size as usize, 0)
        .map_err(|_| ReleaseError::Allocation)?;
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn validate_entries(entries: &[TarEntry], manifest: &Manifest) -> Result<()> {
    if entries.len() != manifest.files.len() + 2 {
        return Err(ReleaseError::Mismatch);
    }
    let mut payload = 0;
    let mut metadata = 0;
    for entry in entries {
        if reserved(&entry.path) {
            if entry.size == 0 || entry.size > MAX_MANIFEST_BYTES as u64 {
                return Err(ReleaseError::Limit);
            }
            metadata += 1;
        } else {
            let expected = manifest.files.get(payload).ok_or(ReleaseError::Mismatch)?;
            if entry.path != expected.path
                || entry.size != expected.size
                || entry.mode != expected.mode
            {
                return Err(ReleaseError::Mismatch);
            }
            payload += 1;
        }
    }
    if payload != manifest.files.len() || metadata != 2 {
        return Err(ReleaseError::Mismatch);
    }
    Ok(())
}
pub fn inspect_archive(path: &str) -> Result<InspectedArchive> {
    let mut file = File::open_regular(path)?;
    if file.metadata()?.links != 1 {
        return Err(ReleaseError::UnsafeFile);
    }
    let entries = scan(&mut file)?;
    let manifest_entry = entries
        .iter()
        .find(|e| e.path == MANIFEST_NAME)
        .ok_or(ReleaseError::InvalidArchive)?;
    let signature_entry = entries
        .iter()
        .find(|e| e.path == SIGNATURE_NAME)
        .ok_or(ReleaseError::InvalidArchive)?;
    let manifest = read_entry(&mut file, manifest_entry)?;
    let signature_bundle = read_entry(&mut file, signature_entry)?;
    validate_entries(&entries, &parse_manifest(&manifest)?)?;
    Ok(InspectedArchive {
        file,
        manifest,
        signature_bundle,
    })
}
fn set_octal(field: &mut [u8], value: u64) -> Result<()> {
    field.fill(b'0');
    let last = field.len() - 1;
    field[last] = 0;
    let mut remaining = value;
    for i in (0..last).rev() {
        field[i] = b'0' + (remaining & 7) as u8;
        remaining >>= 3;
    }
    if remaining != 0 {
        return Err(ReleaseError::Limit);
    }
    Ok(())
}
fn header(path: &str, size: u64, mode: u32) -> Result<[u8; 512]> {
    safe_path(path)?;
    let mut out = [0; 512];
    if path.len() <= 100 {
        out[..path.len()].copy_from_slice(path.as_bytes());
    } else {
        let split = path
            .rmatch_indices('/')
            .find(|(i, _)| *i <= 155 && path.len() - i - 1 <= 100)
            .map(|(i, _)| i)
            .ok_or(ReleaseError::UnsafePath)?;
        out[..path.len() - split - 1].copy_from_slice(&path.as_bytes()[split + 1..]);
        out[345..345 + split].copy_from_slice(&path.as_bytes()[..split]);
    }
    set_octal(&mut out[100..108], u64::from(mode))?;
    set_octal(&mut out[108..116], 0)?;
    set_octal(&mut out[116..124], 0)?;
    set_octal(&mut out[124..136], size)?;
    set_octal(&mut out[136..148], 0)?;
    out[148..156].fill(b' ');
    out[156] = b'0';
    out[257..263].copy_from_slice(b"ustar\0");
    out[263..265].copy_from_slice(b"00");
    let checksum = out.iter().map(|b| u64::from(*b)).sum();
    set_octal(&mut out[148..156], checksum)?;
    Ok(out)
}
fn read_metadata(root: &DirectoryCapability, path: &str) -> Result<Vector<u8>> {
    let mut file = checked_file(root, path)?;
    let size = file.len()?;
    if size == 0 || size > MAX_MANIFEST_BYTES as u64 {
        return Err(ReleaseError::Limit);
    }
    let mut bytes = Vector::new();
    bytes
        .try_resize(size as usize, 0)
        .map_err(|_| ReleaseError::Allocation)?;
    file.read_exact(&mut bytes)?;
    if file.read(&mut [0; 1])? != 0 {
        return Err(ReleaseError::Mismatch);
    }
    Ok(bytes)
}
fn parent_child(path: &str) -> Result<(DirectoryCapability, &str)> {
    let split = path.rfind('/').ok_or(ReleaseError::UnsafePath)?;
    let child = &path[split + 1..];
    safe_path(child)?;
    if child.contains('/') {
        return Err(ReleaseError::UnsafePath);
    }
    let parent = if split == 0 { "/" } else { &path[..split] };
    Ok((DirectoryCapability::open_root(parent)?, child))
}
/// Require each ancestor to be owned by the invoking owner or the system root.
/// Shared writable directories additionally require sticky-bit protection.
/// This validates pathname stability for later consumers of the private snapshot.
pub fn trusted_parent_capability(path: &str, uid: u32) -> Result<DirectoryCapability> {
    if !path.starts_with('/')
        || path.len() > 4096
        || (path != "/"
            && path[1..]
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".."))
    {
        return Err(ReleaseError::UnsafePath);
    }
    let mut directory = DirectoryCapability::open_root("/")?;
    let mut prefix = Text::new();
    for component in core::iter::once("").chain(path.split('/').filter(|p| !p.is_empty())) {
        if !component.is_empty() {
            prefix.push_str("/");
            prefix.push_str(component);
            // Explicit owner-selected ancestors may cross filesystem mounts.
            // Each absolute prefix still rejects every symlink and is checked
            // before descending. Payload traversal remains NO_XDEV beneath its root.
            directory = DirectoryCapability::open_root(&prefix)?;
        }
        let metadata = directory.metadata()?;
        if (metadata.uid != 0 && metadata.uid != uid)
            || (metadata.mode & 0o022 != 0 && metadata.mode & 0o1000 == 0)
        {
            return Err(ReleaseError::UnsafeFile);
        }
    }
    Ok(directory)
}

pub fn validate_private_parent(path: &str, uid: u32) -> Result<()> {
    trusted_parent_capability(path, uid).map(|_| ())
}
/// Establish the invoking UID from a retained newly-created descriptor, before
/// opening any caller-selected destination. The bootstrap parent is root-owned.
pub fn invoking_uid() -> Result<u32> {
    let parent = DirectoryCapability::open_root("/tmp")?;
    let parent_metadata = parent.metadata()?;
    if parent_metadata.uid != 0
        || (parent_metadata.mode & 0o022 != 0 && parent_metadata.mode & 0o1000 == 0)
    {
        return Err(ReleaseError::UnsafeFile);
    }
    let mut random = [0; 16];
    mrml_runtime::fill_random(&mut random).map_err(|_| ReleaseError::Io)?;
    let mut suffix = Text::new();
    for byte in random {
        suffix.push_str(&mrml_runtime::mrml_format!("{byte:02x}"));
    }
    let name = mrml_runtime::mrml_format!(".mrml-release-uid-{suffix}");
    let file = parent.create_new_file(&name, 0o600)?;
    let metadata = file.metadata()?;
    let named = parent.open_regular(&name)?.metadata()?;
    if metadata.inode != named.inode || metadata.device != named.device {
        return Err(ReleaseError::UnsafeFile);
    }
    parent.remove_file(&name)?;
    Ok(metadata.uid)
}

fn private_destination(path: &str) -> Result<DirectoryCapability> {
    let uid = invoking_uid()?;
    let parent_path = mrml_runtime::parent_path(path).ok_or(ReleaseError::UnsafePath)?;
    let child = path.rsplit('/').next().ok_or(ReleaseError::UnsafePath)?;
    safe_path(child)?;
    let parent = trusted_parent_capability(parent_path, uid)?;
    let destination = parent.create_directory(child, 0o700)?;
    let metadata = destination.metadata()?;
    if metadata.uid != uid || metadata.mode & 0o777 != 0o700 {
        return Err(ReleaseError::UnsafeFile);
    }
    parent.sync()?;
    Ok(destination)
}

fn create_payload(root: &DirectoryCapability, path: &str) -> Result<File> {
    let mut directory = root.try_clone()?;
    let mut components = path.split('/').peekable();
    while let Some(name) = components.next() {
        if components.peek().is_none() {
            let file = directory.create_new_file(name, 0o600)?;
            directory.sync()?;
            return Ok(file);
        }
        directory = match directory.open_directory(name) {
            Ok(existing) => existing,
            Err(_) => {
                let child = directory.create_directory(name, 0o700)?;
                directory.sync()?;
                child
            }
        };
    }
    Err(ReleaseError::UnsafePath)
}
fn copy_bytes(source: &mut File, target: &mut File, size: u64) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut buffer = [0; COPY_BYTES];
    let mut remaining = size;
    while remaining != 0 {
        let count = remaining.min(COPY_BYTES as u64) as usize;
        source.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        target.write_all(&buffer[..count])?;
        remaining -= count as u64;
    }
    target.sync()?;
    Ok(hash.finalize())
}
fn finalize(
    root: &DirectoryCapability,
    manifest: &Manifest,
    bytes: &[u8],
    bundle: &[u8],
) -> Result<()> {
    // All payload hashes have passed before any executable mode is installed.
    for (name, data) in [(MANIFEST_NAME, bytes), (SIGNATURE_NAME, bundle)] {
        let mut file = root.create_new_file(name, 0o600)?;
        file.write_all(data)?;
        file.sync()?;
    }
    for entry in &manifest.files {
        let file = checked_file(root, &entry.path)?;
        let metadata = file.metadata()?;
        file.set_owner_mode(metadata.uid, metadata.gid, entry.mode)?;
        file.sync()?;
    }
    root.sync()?;
    Ok(())
}
pub fn create_archive(root: &str, output: &str) -> Result<()> {
    if output
        .strip_prefix(root)
        .is_some_and(|tail| tail.starts_with('/'))
    {
        return Err(ReleaseError::UnsafePath);
    }
    let directory = DirectoryCapability::open_root(root)?;
    let bytes = read_metadata(&directory, MANIFEST_NAME)?;
    let bundle = read_metadata(&directory, SIGNATURE_NAME)?;
    let manifest = parse_manifest(&bytes)?;
    if inventory(&directory)? != manifest.files {
        return Err(ReleaseError::Mismatch);
    }
    let mut files = manifest.files.clone();
    for (path, data) in [(MANIFEST_NAME, &bytes[..]), (SIGNATURE_NAME, &bundle[..])] {
        files
            .try_push(ReleaseFile {
                path: path.into(),
                size: data.len() as u64,
                mode: 0o644,
                digest: Sha256::digest(data),
            })
            .map_err(|_| ReleaseError::Allocation)?;
    }
    files.sort_unstable_by(|a, b| a.path.cmp(&b.path));
    let (parent, child) = parent_child(output)?;
    let mut archive = parent.create_new_file(child, 0o600)?;
    for entry in files {
        archive.write_all(&header(&entry.path, entry.size, entry.mode)?)?;
        let actual = if entry.path == MANIFEST_NAME {
            archive.write_all(&bytes)?;
            Sha256::digest(&bytes)
        } else if entry.path == SIGNATURE_NAME {
            archive.write_all(&bundle)?;
            Sha256::digest(&bundle)
        } else {
            let mut source = checked_file(&directory, &entry.path)?;
            let digest = copy_bytes(&mut source, &mut archive, entry.size)?;
            if source.read(&mut [0; 1])? != 0 {
                return Err(ReleaseError::Mismatch);
            }
            digest
        };
        if actual != entry.digest {
            return Err(ReleaseError::Mismatch);
        }
        archive.write_all(&[0; 512][..(rounded(entry.size)? - entry.size) as usize])?;
    }
    archive.write_all(&[0; 1024])?;
    archive.sync()?;
    parent.sync()?;
    Ok(())
}
/// The caller authenticates these exact manifest bytes with its external key first.
pub fn extract_archive(
    mut archive: InspectedArchive,
    destination: &str,
    authenticated_manifest: &[u8],
) -> Result<Manifest> {
    if archive.manifest != authenticated_manifest {
        return Err(ReleaseError::Mismatch);
    }
    let manifest = parse_manifest(authenticated_manifest)?;
    let entries = scan(&mut archive.file)?;
    validate_entries(&entries, &manifest)?;
    // Recheck held archive metadata after signature verification; the underlying
    // inode may have been modified even though pathname replacement is harmless.
    for entry in entries.iter().filter(|e| reserved(&e.path)) {
        let bytes = read_entry(&mut archive.file, entry)?;
        let expected = if entry.path == MANIFEST_NAME {
            &archive.manifest[..]
        } else {
            &archive.signature_bundle[..]
        };
        if bytes != expected {
            return Err(ReleaseError::Mismatch);
        }
    }
    let root = private_destination(destination)?;
    for entry in entries.iter().filter(|e| !reserved(&e.path)) {
        let expected = &manifest.files[manifest
            .files
            .binary_search_by(|f| f.path.cmp(&entry.path))
            .map_err(|_| ReleaseError::Mismatch)?];
        let mut target = create_payload(&root, &entry.path)?;
        archive.file.seek(entry.offset)?;
        if copy_bytes(&mut archive.file, &mut target, entry.size)? != expected.digest {
            return Err(ReleaseError::Mismatch);
        }
    }
    finalize(
        &root,
        &manifest,
        authenticated_manifest,
        &archive.signature_bundle,
    )?;
    Ok(manifest)
}
/// Copies and hashes the bytes Docker will consume, rather than verifying one
/// pathname and subsequently loading a potentially different file generation.
pub fn copy_authenticated_directory(
    source: &str,
    destination: &str,
    authenticated_manifest: &[u8],
) -> Result<Manifest> {
    let manifest = parse_manifest(authenticated_manifest)?;
    let source_root = DirectoryCapability::open_root(source)?;
    if read_metadata(&source_root, MANIFEST_NAME)? != authenticated_manifest {
        return Err(ReleaseError::Mismatch);
    }
    let bundle = read_metadata(&source_root, SIGNATURE_NAME)?;
    if inventory(&source_root)? != manifest.files {
        return Err(ReleaseError::Mismatch);
    }
    let root = private_destination(destination)?;
    for entry in &manifest.files {
        let mut input = checked_file(&source_root, &entry.path)?;
        if input.len()? != entry.size || input.metadata()?.mode & 0o777 != entry.mode {
            return Err(ReleaseError::Mismatch);
        }
        let mut target = create_payload(&root, &entry.path)?;
        if copy_bytes(&mut input, &mut target, entry.size)? != entry.digest
            || input.read(&mut [0; 1])? != 0
        {
            return Err(ReleaseError::Mismatch);
        }
    }
    finalize(&root, &manifest, authenticated_manifest, &bundle)?;
    Ok(manifest)
}
