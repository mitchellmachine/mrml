extern crate std;

use mrml_crypto::{Sha256, aes128_gcm_open, aes128_gcm_seal, erase_secret_bytes, hmac_sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

const MAGIC: &[u8; 8] = b"MRMLHCB1";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 72;
const TAG_BYTES: usize = 16;
const ENTRY_HEADER_BYTES: usize = 40;
const LINUX_O_NOFOLLOW: i32 = 0x20_000;
pub const MAX_HOSTED_BACKUP_FILES: usize = 512;
pub const MAX_HOSTED_BACKUP_FILE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_HOSTED_BACKUP_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HostedBackupRole {
    Certd = 1,
    Acmed = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedBackupDescriptor {
    pub role: HostedBackupRole,
    pub generation: u64,
    pub file_count: u16,
    pub plaintext_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedBackupError {
    InvalidGeneration,
    InvalidSource,
    UnsafeEntry,
    TooManyFiles,
    TooLarge,
    OutputExists,
    Io,
    AuthenticationFailed,
    Malformed,
    RoleMismatch,
}

#[derive(Clone, Copy)]
pub struct HostedBackupSource<'a> {
    pub source: &'a Path,
    pub archive_name: &'a str,
}

struct Entry {
    name: String,
    mode: u16,
    bytes: Vec<u8>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

pub fn create_hosted_component_backup(
    role: HostedBackupRole,
    generation: u64,
    owner_uid: u32,
    sources: &[HostedBackupSource<'_>],
    backup_key: &[u8; 32],
    output: &Path,
) -> Result<HostedBackupDescriptor, HostedBackupError> {
    if generation == 0 || sources.is_empty() || backup_key == &[0; 32] || !output.is_absolute() {
        return Err(HostedBackupError::InvalidGeneration);
    }
    let mut entries = Vec::new();
    for source in sources {
        validate_archive_name(source.archive_name)?;
        collect_source(source.source, source.archive_name, owner_uid, &mut entries)?;
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    if entries.is_empty() || entries.len() > MAX_HOSTED_BACKUP_FILES {
        clear_entries(&mut entries);
        return Err(HostedBackupError::TooManyFiles);
    }
    if entries.windows(2).any(|pair| pair[0].name == pair[1].name) {
        clear_entries(&mut entries);
        return Err(HostedBackupError::UnsafeEntry);
    }
    let file_count = u16::try_from(entries.len()).map_err(|_| HostedBackupError::TooManyFiles)?;
    let mut plaintext = Vec::new();
    for entry in &entries {
        let name = entry.name.as_bytes();
        let Some(required) = ENTRY_HEADER_BYTES
            .checked_add(name.len())
            .and_then(|length| length.checked_add(entry.bytes.len()))
            .and_then(|length| plaintext.len().checked_add(length))
        else {
            plaintext.fill(0);
            return Err(HostedBackupError::TooLarge);
        };
        if required > MAX_HOSTED_BACKUP_BYTES || name.len() > u16::MAX as usize {
            plaintext.fill(0);
            clear_entries(&mut entries);
            return Err(HostedBackupError::TooLarge);
        }
        plaintext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        plaintext.extend_from_slice(&entry.mode.to_be_bytes());
        plaintext.extend_from_slice(&(entry.bytes.len() as u32).to_be_bytes());
        plaintext.extend_from_slice(&Sha256::digest(&entry.bytes));
        plaintext.extend_from_slice(name);
        plaintext.extend_from_slice(&entry.bytes);
    }
    clear_entries(&mut entries);
    let descriptor = HostedBackupDescriptor {
        role,
        generation,
        file_count,
        plaintext_digest: Sha256::digest(&plaintext),
    };
    let mut nonce = [0u8; 12];
    mrml_runtime::fill_random(&mut nonce).map_err(|_| HostedBackupError::Io)?;
    let mut header = [0u8; HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&VERSION.to_be_bytes());
    header[10] = role as u8;
    header[12..20].copy_from_slice(&generation.to_be_bytes());
    header[20..22].copy_from_slice(&file_count.to_be_bytes());
    header[24..28].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());
    header[28..40].copy_from_slice(&nonce);
    header[40..72].copy_from_slice(&descriptor.plaintext_digest);
    let mut derived = hmac_sha256(
        backup_key,
        &[b"mrml-hosted-component-backup-aes-v1", &[role as u8]],
    );
    let mut key = [0u8; 16];
    key.copy_from_slice(&derived[..16]);
    erase_secret_bytes(&mut derived);
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; TAG_BYTES];
    let sealed = aes128_gcm_seal(&key, &nonce, &header, &plaintext, &mut ciphertext, &mut tag);
    erase_secret_bytes(&mut key);
    plaintext.fill(0);
    if !sealed {
        ciphertext.fill(0);
        return Err(HostedBackupError::AuthenticationFailed);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(LINUX_O_NOFOLLOW)
        .open(output)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                HostedBackupError::OutputExists
            } else {
                HostedBackupError::Io
            }
        })?;
    let result = file
        .write_all(&header)
        .and_then(|_| file.write_all(&ciphertext))
        .and_then(|_| file.write_all(&tag))
        .and_then(|_| file.sync_all())
        .map_err(|_| HostedBackupError::Io);
    ciphertext.fill(0);
    if result.is_err() {
        let _ = fs::remove_file(output);
        return Err(HostedBackupError::Io);
    }
    sync_parent(output)?;
    Ok(descriptor)
}

pub fn verify_hosted_component_backup(
    expected_role: HostedBackupRole,
    backup_key: &[u8; 32],
    input: &Path,
) -> Result<HostedBackupDescriptor, HostedBackupError> {
    if backup_key == &[0; 32] || !input.is_absolute() {
        return Err(HostedBackupError::Malformed);
    }
    let metadata = fs::symlink_metadata(input).map_err(|_| HostedBackupError::Io)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1 {
        return Err(HostedBackupError::UnsafeEntry);
    }
    let length = usize::try_from(metadata.len()).map_err(|_| HostedBackupError::TooLarge)?;
    if length <= HEADER_BYTES + TAG_BYTES
        || length > HEADER_BYTES + MAX_HOSTED_BACKUP_BYTES + TAG_BYTES
    {
        return Err(HostedBackupError::TooLarge);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(LINUX_O_NOFOLLOW)
        .open(input)
        .map_err(|_| HostedBackupError::Io)?;
    let mut encoded = vec![0u8; length];
    file.read_exact(&mut encoded)
        .map_err(|_| HostedBackupError::Io)?;
    let header: [u8; HEADER_BYTES] = encoded[..HEADER_BYTES]
        .try_into()
        .map_err(|_| HostedBackupError::Malformed)?;
    if &header[..8] != MAGIC
        || header[8..10] != VERSION.to_be_bytes()
        || header[11] != 0
        || header[22..24] != [0; 2]
    {
        encoded.fill(0);
        return Err(HostedBackupError::Malformed);
    }
    let role = match header[10] {
        1 => HostedBackupRole::Certd,
        2 => HostedBackupRole::Acmed,
        _ => return Err(HostedBackupError::Malformed),
    };
    if role != expected_role {
        encoded.fill(0);
        return Err(HostedBackupError::RoleMismatch);
    }
    let generation = u64::from_be_bytes(
        header[12..20]
            .try_into()
            .map_err(|_| HostedBackupError::Malformed)?,
    );
    let file_count = u16::from_be_bytes(
        header[20..22]
            .try_into()
            .map_err(|_| HostedBackupError::Malformed)?,
    );
    let payload_length = u32::from_be_bytes(
        header[24..28]
            .try_into()
            .map_err(|_| HostedBackupError::Malformed)?,
    ) as usize;
    if generation == 0
        || file_count == 0
        || usize::from(file_count) > MAX_HOSTED_BACKUP_FILES
        || length != HEADER_BYTES + payload_length + TAG_BYTES
    {
        encoded.fill(0);
        return Err(HostedBackupError::Malformed);
    }
    let nonce: [u8; 12] = header[28..40]
        .try_into()
        .map_err(|_| HostedBackupError::Malformed)?;
    let expected_digest: [u8; 32] = header[40..72]
        .try_into()
        .map_err(|_| HostedBackupError::Malformed)?;
    let mut derived = hmac_sha256(
        backup_key,
        &[b"mrml-hosted-component-backup-aes-v1", &[role as u8]],
    );
    let mut key = [0u8; 16];
    key.copy_from_slice(&derived[..16]);
    erase_secret_bytes(&mut derived);
    let mut plaintext = vec![0u8; payload_length];
    let tag: [u8; TAG_BYTES] = encoded[length - TAG_BYTES..]
        .try_into()
        .map_err(|_| HostedBackupError::Malformed)?;
    let opened = aes128_gcm_open(
        &key,
        &nonce,
        &header,
        &encoded[HEADER_BYTES..length - TAG_BYTES],
        &tag,
        &mut plaintext,
    );
    erase_secret_bytes(&mut key);
    encoded.fill(0);
    let validation = if !opened || Sha256::digest(&plaintext) != expected_digest {
        Err(HostedBackupError::AuthenticationFailed)
    } else {
        count_entries(&plaintext).and_then(|count| {
            if count != file_count {
                Err(HostedBackupError::AuthenticationFailed)
            } else {
                validate_plaintext_entries(&plaintext)
            }
        })
    };
    plaintext.fill(0);
    validation?;
    Ok(HostedBackupDescriptor {
        role,
        generation,
        file_count,
        plaintext_digest: expected_digest,
    })
}

fn collect_source(
    path: &Path,
    name: &str,
    owner_uid: u32,
    entries: &mut Vec<Entry>,
) -> Result<(), HostedBackupError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| HostedBackupError::InvalidSource)?;
    if metadata.file_type().is_symlink() || metadata.uid() != owner_uid {
        return Err(HostedBackupError::UnsafeEntry);
    }
    if metadata.is_file() {
        collect_file(path, name, &metadata, entries)?;
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(HostedBackupError::UnsafeEntry);
    }
    let mut children = Vec::new();
    for child in fs::read_dir(path).map_err(|_| HostedBackupError::Io)? {
        if entries.len() + children.len() >= MAX_HOSTED_BACKUP_FILES {
            return Err(HostedBackupError::TooManyFiles);
        }
        children.push(child.map_err(|_| HostedBackupError::Io)?.path());
    }
    children.sort();
    for child in children {
        let component = child
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(HostedBackupError::UnsafeEntry)?;
        validate_archive_name(component)?;
        collect_source(
            &child,
            &std::format!("{}/{}", name, component),
            owner_uid,
            entries,
        )?;
    }
    Ok(())
}

fn collect_file(
    path: &Path,
    name: &str,
    metadata: &fs::Metadata,
    entries: &mut Vec<Entry>,
) -> Result<(), HostedBackupError> {
    if metadata.nlink() != 1
        || metadata.len() > MAX_HOSTED_BACKUP_FILE_BYTES as u64
        || entries.len() >= MAX_HOSTED_BACKUP_FILES
    {
        return Err(HostedBackupError::UnsafeEntry);
    }
    let mode = (metadata.permissions().mode() & 0o777) as u16;
    if mode & 0o022 != 0 || mode & 0o111 != 0 {
        return Err(HostedBackupError::UnsafeEntry);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(LINUX_O_NOFOLLOW)
        .open(path)
        .map_err(|_| HostedBackupError::Io)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(metadata.len() as usize)
        .map_err(|_| HostedBackupError::TooLarge)?;
    file.read_to_end(&mut bytes)
        .map_err(|_| HostedBackupError::Io)?;
    if bytes.len() != metadata.len() as usize {
        bytes.fill(0);
        return Err(HostedBackupError::Io);
    }
    entries.push(Entry {
        name: name.to_string(),
        mode,
        bytes,
    });
    Ok(())
}

fn validate_plaintext_entries(input: &[u8]) -> Result<(), HostedBackupError> {
    let mut offset = 0usize;
    let mut prior: Option<&str> = None;
    while offset < input.len() {
        if input.len() - offset < ENTRY_HEADER_BYTES {
            return Err(HostedBackupError::Malformed);
        }
        let name_length =
            u16::from_be_bytes(input[offset..offset + 2].try_into().unwrap()) as usize;
        let mode = u16::from_be_bytes(input[offset + 2..offset + 4].try_into().unwrap());
        let length = u32::from_be_bytes(input[offset + 4..offset + 8].try_into().unwrap()) as usize;
        let digest: [u8; 32] = input[offset + 8..offset + 40].try_into().unwrap();
        offset += ENTRY_HEADER_BYTES;
        let end = offset
            .checked_add(name_length)
            .and_then(|value| value.checked_add(length))
            .ok_or(HostedBackupError::Malformed)?;
        if name_length == 0
            || length > MAX_HOSTED_BACKUP_FILE_BYTES
            || end > input.len()
            || mode & 0o022 != 0
            || mode & 0o111 != 0
        {
            return Err(HostedBackupError::UnsafeEntry);
        }
        let name = core::str::from_utf8(&input[offset..offset + name_length])
            .map_err(|_| HostedBackupError::Malformed)?;
        validate_archive_name(name)?;
        if prior.is_some_and(|value| value >= name) {
            return Err(HostedBackupError::UnsafeEntry);
        }
        offset += name_length;
        if Sha256::digest(&input[offset..offset + length]) != digest {
            return Err(HostedBackupError::AuthenticationFailed);
        }
        offset += length;
        prior = Some(name);
    }
    Ok(())
}

fn count_entries(input: &[u8]) -> Result<u16, HostedBackupError> {
    let mut count = 0u16;
    let mut offset = 0usize;
    while offset < input.len() {
        if input.len() - offset < ENTRY_HEADER_BYTES {
            return Err(HostedBackupError::Malformed);
        }
        let name = u16::from_be_bytes(input[offset..offset + 2].try_into().unwrap()) as usize;
        let bytes = u32::from_be_bytes(input[offset + 4..offset + 8].try_into().unwrap()) as usize;
        offset = offset
            .checked_add(ENTRY_HEADER_BYTES + name + bytes)
            .ok_or(HostedBackupError::TooLarge)?;
        if offset > input.len() {
            return Err(HostedBackupError::Malformed);
        }
        count = count
            .checked_add(1)
            .ok_or(HostedBackupError::TooManyFiles)?;
    }
    Ok(count)
}

fn validate_archive_name(name: &str) -> Result<(), HostedBackupError> {
    if name.is_empty() || name.len() > 1024 || name.starts_with('/') || name.contains('\\') {
        return Err(HostedBackupError::UnsafeEntry);
    }
    if Path::new(name)
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(HostedBackupError::UnsafeEntry);
    }
    Ok(())
}

fn clear_entries(entries: &mut Vec<Entry>) {
    for entry in entries {
        entry.bytes.fill(0);
    }
}

fn sync_parent(path: &Path) -> Result<(), HostedBackupError> {
    let parent = path.parent().ok_or(HostedBackupError::InvalidSource)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(LINUX_O_NOFOLLOW)
        .open(parent)
        .map_err(|_| HostedBackupError::Io)?;
    directory.sync_all().map_err(|_| HostedBackupError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    use std::path::PathBuf;

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(std::format!(
                "mrml-component-backup-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn encrypted_component_round_trips_and_rejects_role_key_and_ciphertext_substitution() {
        let root = TestRoot::new();
        let state = root.0.join("state");
        fs::create_dir(&state).unwrap();
        fs::write(state.join("one.record"), b"authenticated public record").unwrap();
        fs::write(state.join("key.bin"), b"encrypted private key bytes").unwrap();
        fs::set_permissions(state.join("key.bin"), fs::Permissions::from_mode(0o600)).unwrap();
        let output = root.0.join("component.mrb");
        let descriptor = create_hosted_component_backup(
            HostedBackupRole::Certd,
            7,
            metadata_uid(&state),
            &[HostedBackupSource {
                source: &state,
                archive_name: "certd",
            }],
            &[0x41; 32],
            &output,
        )
        .unwrap();
        assert_eq!(descriptor.file_count, 2);
        assert_eq!(
            verify_hosted_component_backup(HostedBackupRole::Certd, &[0x41; 32], &output).unwrap(),
            descriptor
        );
        assert!(matches!(
            verify_hosted_component_backup(HostedBackupRole::Acmed, &[0x41; 32], &output),
            Err(HostedBackupError::RoleMismatch)
        ));
        assert!(matches!(
            verify_hosted_component_backup(HostedBackupRole::Certd, &[0x42; 32], &output),
            Err(HostedBackupError::AuthenticationFailed)
        ));
        let encoded = fs::read(&output).unwrap();
        assert!(
            !encoded
                .windows(b"encrypted private key bytes".len())
                .any(|window| window == b"encrypted private key bytes")
        );
        let changed = root.0.join("changed.mrb");
        let mut mutated = encoded;
        mutated[HEADER_BYTES + 1] ^= 1;
        fs::write(&changed, mutated).unwrap();
        assert!(matches!(
            verify_hosted_component_backup(HostedBackupRole::Certd, &[0x41; 32], &changed),
            Err(HostedBackupError::AuthenticationFailed)
        ));
    }

    #[test]
    fn source_scan_rejects_symlinks_hardlinks_traversal_and_existing_output() {
        let root = TestRoot::new();
        let state = root.0.join("state");
        fs::create_dir(&state).unwrap();
        let original = state.join("one.record");
        fs::write(&original, b"record").unwrap();
        let hardlink = state.join("two.record");
        fs::hard_link(&original, &hardlink).unwrap();
        let output = root.0.join("component.mrb");
        assert!(matches!(
            create_hosted_component_backup(
                HostedBackupRole::Acmed,
                1,
                metadata_uid(&state),
                &[HostedBackupSource {
                    source: &state,
                    archive_name: "acmed",
                }],
                &[0x11; 32],
                &output,
            ),
            Err(HostedBackupError::UnsafeEntry)
        ));
        fs::remove_file(&hardlink).unwrap();
        assert!(matches!(
            create_hosted_component_backup(
                HostedBackupRole::Acmed,
                1,
                metadata_uid(&state),
                &[HostedBackupSource {
                    source: &state,
                    archive_name: "../acmed",
                }],
                &[0x11; 32],
                &output,
            ),
            Err(HostedBackupError::UnsafeEntry)
        ));
        create_hosted_component_backup(
            HostedBackupRole::Acmed,
            1,
            metadata_uid(&state),
            &[HostedBackupSource {
                source: &state,
                archive_name: "acmed",
            }],
            &[0x11; 32],
            &output,
        )
        .unwrap();
        assert!(matches!(
            create_hosted_component_backup(
                HostedBackupRole::Acmed,
                2,
                metadata_uid(&state),
                &[HostedBackupSource {
                    source: &state,
                    archive_name: "acmed",
                }],
                &[0x11; 32],
                &output,
            ),
            Err(HostedBackupError::OutputExists)
        ));
        let link = root.0.join("link.mrb");
        std::os::unix::fs::symlink(&output, &link).unwrap();
        assert!(matches!(
            verify_hosted_component_backup(HostedBackupRole::Acmed, &[0x11; 32], &link),
            Err(HostedBackupError::UnsafeEntry)
        ));
    }

    fn metadata_uid(path: &Path) -> u32 {
        fs::metadata(path).unwrap().uid()
    }
}
