//! Descriptor-relative collection of canonical Git backup volume entries.

use mrml_crypto::Sha256;
use mrml_git::{
    BackupInventoryEntry, BackupInventoryFileKind, BackupVolume, MAX_BACKUP_INVENTORY_ENTRIES,
};
use mrml_runtime::{DirectoryCapability, Text, Vector};

const MAX_BACKUP_PATH_BYTES: usize = 1024;
const MAX_BACKUP_DEPTH: usize = 64;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupVolumeError {
    Open,
    Enumerate,
    UnsafeEntry,
    Resource,
    Read,
    Changed,
}

/// Enumerates one retained volume without converting descendants back to
/// ambient paths. The caller supplies the logical volume identity; paths are
/// returned in canonical byte order and never include the volume root itself.
pub fn collect_backup_volume(
    root_path: &str,
    volume: BackupVolume,
) -> Result<Vector<BackupInventoryEntry>, BackupVolumeError> {
    let root = DirectoryCapability::open_root(root_path).map_err(|_| BackupVolumeError::Open)?;
    validate_directory(&root)?;
    let mut output = Vector::new();
    collect_directory(&root, "", volume, 0, &mut output)?;
    Ok(output)
}

fn collect_directory(
    directory: &DirectoryCapability,
    parent: &str,
    volume: BackupVolume,
    depth: usize,
    output: &mut Vector<BackupInventoryEntry>,
) -> Result<(), BackupVolumeError> {
    if depth >= MAX_BACKUP_DEPTH {
        return Err(BackupVolumeError::Resource);
    }
    let remaining = MAX_BACKUP_INVENTORY_ENTRIES
        .checked_sub(output.len())
        .ok_or(BackupVolumeError::Resource)?;
    let mut children = directory
        .read_directory_bounded(remaining)
        .map_err(|_| BackupVolumeError::Enumerate)?;
    children.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    for child in children {
        if child.is_symlink {
            return Err(BackupVolumeError::UnsafeEntry);
        }
        let path = if parent.is_empty() {
            child.name.to_string()
        } else {
            format!("{parent}/{}", child.name)
        };
        if path.len() > MAX_BACKUP_PATH_BYTES {
            return Err(BackupVolumeError::Resource);
        }
        if child.is_directory {
            let retained = directory
                .open_directory(child.name.as_str())
                .map_err(|_| BackupVolumeError::Changed)?;
            let metadata = retained
                .metadata()
                .map_err(|_| BackupVolumeError::Changed)?;
            if metadata.mode & 0o170000 != 0o040000 || metadata.links < 2 {
                return Err(BackupVolumeError::UnsafeEntry);
            }
            push_entry(
                output,
                BackupInventoryEntry {
                    volume,
                    path: Text::from(path.as_str()),
                    kind: BackupInventoryFileKind::Directory,
                    mode: (metadata.mode & 0o7777) as u16,
                    uid: metadata.uid,
                    gid: metadata.gid,
                    size: 0,
                    digest: [0; 32],
                },
            )?;
            collect_directory(&retained, &path, volume, depth + 1, output)?;
        } else {
            let mut file = directory
                .open_regular(child.name.as_str())
                .map_err(|_| BackupVolumeError::UnsafeEntry)?;
            let metadata = file.metadata().map_err(|_| BackupVolumeError::Changed)?;
            if metadata.mode & 0o170000 != 0o100000 || metadata.links != 1 {
                return Err(BackupVolumeError::UnsafeEntry);
            }
            let size = file.len().map_err(|_| BackupVolumeError::Changed)?;
            let mut digest = Sha256::new();
            let mut consumed = 0u64;
            let mut buffer = [0u8; COPY_BUFFER_BYTES];
            while consumed < size {
                let wanted = usize::try_from((size - consumed).min(buffer.len() as u64))
                    .map_err(|_| BackupVolumeError::Resource)?;
                let count = file
                    .read(&mut buffer[..wanted])
                    .map_err(|_| BackupVolumeError::Read)?;
                if count == 0 {
                    return Err(BackupVolumeError::Changed);
                }
                digest.update(&buffer[..count]);
                consumed = consumed
                    .checked_add(count as u64)
                    .ok_or(BackupVolumeError::Resource)?;
            }
            if file
                .read(&mut buffer[..1])
                .map_err(|_| BackupVolumeError::Read)?
                != 0
            {
                return Err(BackupVolumeError::Changed);
            }
            push_entry(
                output,
                BackupInventoryEntry {
                    volume,
                    path: Text::from(path.as_str()),
                    kind: BackupInventoryFileKind::Regular,
                    mode: (metadata.mode & 0o7777) as u16,
                    uid: metadata.uid,
                    gid: metadata.gid,
                    size,
                    digest: digest.finalize(),
                },
            )?;
        }
    }
    Ok(())
}

fn validate_directory(directory: &DirectoryCapability) -> Result<(), BackupVolumeError> {
    let metadata = directory.metadata().map_err(|_| BackupVolumeError::Open)?;
    if metadata.mode & 0o170000 != 0o040000 || metadata.links < 2 {
        return Err(BackupVolumeError::UnsafeEntry);
    }
    Ok(())
}

fn push_entry(
    output: &mut Vector<BackupInventoryEntry>,
    entry: BackupInventoryEntry,
) -> Result<(), BackupVolumeError> {
    if output.len() == MAX_BACKUP_INVENTORY_ENTRIES {
        return Err(BackupVolumeError::Resource);
    }
    output.push(entry);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    fn root(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("mrml-backup-volume-{label}-{}", std::process::id()))
    }

    #[test]
    fn collects_sorted_descriptor_relative_metadata_and_content() {
        let root = root("canonical");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("z"), b"last").unwrap();
        fs::create_dir(root.join("a")).unwrap();
        fs::write(root.join("a/first"), b"content").unwrap();
        let entries =
            collect_backup_volume(root.to_str().unwrap(), BackupVolume::GitdRepositories).unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            ["a", "a/first", "z"]
        );
        assert_eq!(entries[1].size, 7);
        assert_eq!(entries[1].digest, Sha256::digest(b"content"));
        assert_eq!(
            entries[1].uid,
            fs::metadata(root.join("a/first")).unwrap().uid()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_symlinks_and_hard_linked_regular_files() {
        let root = root("unsafe");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::write(root.join("file"), b"content").unwrap();
        symlink("file", root.join("link")).unwrap();
        assert_eq!(
            collect_backup_volume(root.to_str().unwrap(), BackupVolume::GitdState),
            Err(BackupVolumeError::UnsafeEntry)
        );
        fs::remove_file(root.join("link")).unwrap();
        fs::hard_link(root.join("file"), root.join("second")).unwrap();
        assert_eq!(
            collect_backup_volume(root.to_str().unwrap(), BackupVolume::GitdState),
            Err(BackupVolumeError::UnsafeEntry)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
