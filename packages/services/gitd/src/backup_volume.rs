//! Descriptor-relative collection of canonical Git backup volume entries.

use mrml_crypto::Sha256;
use mrml_git::{
    AUTHORITY_GENERATION_RECORD_MAX_BYTES, ActiveRefFile, BackupInventory, BackupInventoryEntry,
    BackupInventoryFileKind, BackupRepositoryGeneration, BackupVolume,
    MAX_BACKUP_INVENTORY_ENTRIES, authority_generation_record_name,
    parse_authority_generation_record,
};
use mrml_runtime::{DirectoryCapability, Text, Vector};

use crate::{
    DeploymentRepositoryProfile, GitdConfig, load_deployment_catalog, verify_repository_admission,
};

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
    Catalog,
    Generation,
}

pub const BACKUP_VOLUME_ORDER: [BackupVolume; 10] = BackupVolume::ALL;

/// Constructs the complete canonical inventory from all ten mounted source
/// volumes and exact live repository generations. The roots are positional in
/// `BACKUP_VOLUME_ORDER`; cache is intentionally not accepted.
pub fn collect_backup_inventory(
    config: &GitdConfig,
    backup_generation: u64,
    volume_roots: [&str; 10],
    authority_generation_root: &str,
) -> Result<BackupInventory, BackupVolumeError> {
    if backup_generation == 0 {
        return Err(BackupVolumeError::Generation);
    }
    let catalog = load_deployment_catalog(config).map_err(|_| BackupVolumeError::Catalog)?;
    let state_root =
        DirectoryCapability::open_root(config.state_root.to_str().ok_or(BackupVolumeError::Open)?)
            .map_err(|_| BackupVolumeError::Open)?;
    let repository_root = DirectoryCapability::open_root(
        config
            .repository_root
            .to_str()
            .ok_or(BackupVolumeError::Open)?,
    )
    .map_err(|_| BackupVolumeError::Open)?;
    let authority_root = DirectoryCapability::open_root(authority_generation_root)
        .map_err(|_| BackupVolumeError::Open)?;
    let mut repositories = Vector::new();
    repositories
        .try_reserve_exact(catalog.repositories.len())
        .map_err(|_| BackupVolumeError::Resource)?;
    for entry in &catalog.repositories {
        let state_directory = state_root
            .open_directory(entry.repository.as_str())
            .map_err(|_| BackupVolumeError::Generation)?;
        let state = ActiveRefFile::open_capability(state_directory)
            .and_then(|active| active.load())
            .map_err(|_| BackupVolumeError::Generation)?;
        let view = mrml_git::FilesystemRepositoryView::open_capabilities(
            entry.repository.clone(),
            repository_root
                .open_directory(entry.repository.as_str())
                .map_err(|_| BackupVolumeError::Generation)?,
            state_root
                .open_directory(entry.repository.as_str())
                .map_err(|_| BackupVolumeError::Generation)?,
        )
        .map_err(|_| BackupVolumeError::Generation)?;
        verify_repository_admission(entry, &view).map_err(|_| BackupVolumeError::Generation)?;
        if state.repository != entry.repository
            || state.repository_generation != entry.repository_generation
            || state.trust_generation != entry.trust_generation
            || state.revocation_generation != entry.revocation_generation
        {
            return Err(BackupVolumeError::Generation);
        }
        let authority_generation = if entry.profile.class == DeploymentRepositoryProfile::Protected
        {
            read_authority_generation(&authority_root, config.authority_uid, &entry.repository)?
        } else {
            0
        };
        repositories.push(BackupRepositoryGeneration {
            repository: entry.repository.clone(),
            repository_generation: state.repository_generation,
            pack_generation: state.pack_generation,
            trust_generation: state.trust_generation,
            revocation_generation: state.revocation_generation,
            authority_generation,
        });
    }

    let mut entries = Vector::new();
    for (volume, root) in BACKUP_VOLUME_ORDER.into_iter().zip(volume_roots) {
        let collected = collect_backup_volume(root, volume)?;
        if entries
            .len()
            .checked_add(collected.len())
            .is_none_or(|count| count > MAX_BACKUP_INVENTORY_ENTRIES)
        {
            return Err(BackupVolumeError::Resource);
        }
        entries
            .try_reserve(collected.len())
            .map_err(|_| BackupVolumeError::Resource)?;
        entries.extend(collected);
    }
    Ok(BackupInventory {
        backup_generation,
        repositories,
        entries,
    })
}

fn read_authority_generation(
    root: &DirectoryCapability,
    authority_uid: u32,
    repository: &mrml_git::RepositoryIdentity,
) -> Result<u64, BackupVolumeError> {
    let name = authority_generation_record_name(repository);
    let mut file = root
        .open_regular(name.as_str())
        .map_err(|_| BackupVolumeError::Generation)?;
    let metadata = file.metadata().map_err(|_| BackupVolumeError::Generation)?;
    let length = usize::try_from(file.len().map_err(|_| BackupVolumeError::Generation)?)
        .map_err(|_| BackupVolumeError::Resource)?;
    if metadata.mode & 0o170000 != 0o100000
        || metadata.mode & 0o777 != 0o600
        || metadata.uid != authority_uid
        || metadata.links != 1
        || length > AUTHORITY_GENERATION_RECORD_MAX_BYTES
    {
        return Err(BackupVolumeError::Generation);
    }
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)
        .map_err(|_| BackupVolumeError::Generation)?;
    parse_authority_generation_record(&bytes, repository)
        .map(|generation| generation.0)
        .map_err(|_| BackupVolumeError::Generation)
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
    let metadata = root.metadata().map_err(|_| BackupVolumeError::Open)?;
    push_entry(
        &mut output,
        BackupInventoryEntry {
            volume,
            path: Text::from("."),
            kind: BackupInventoryFileKind::Directory,
            mode: (metadata.mode & 0o7777) as u16,
            uid: metadata.uid,
            gid: metadata.gid,
            size: 0,
            digest: [0; 32],
        },
    )?;
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
            if metadata.mode & 0o170000 != 0o040000 {
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
    if metadata.mode & 0o170000 != 0o040000 {
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
    use mrml_git::{RepositoryGeneration, RepositoryIdentity, encode_authority_generation_record};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

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
            [".", "a", "a/first", "z"]
        );
        assert_eq!(entries[2].size, 7);
        assert_eq!(entries[2].digest, Sha256::digest(b"content"));
        assert_eq!(
            entries[2].uid,
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

    #[test]
    fn authority_generation_is_exact_repository_bound_state() {
        let root = root("authority-generation");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let repository = RepositoryIdentity::parse("owner/protected").unwrap();
        let name = authority_generation_record_name(&repository);
        fs::write(
            root.join(name.as_str()),
            encode_authority_generation_record(&repository, RepositoryGeneration(23)).unwrap(),
        )
        .unwrap();
        fs::set_permissions(root.join(name.as_str()), fs::Permissions::from_mode(0o600)).unwrap();
        let owner = fs::metadata(root.join(name.as_str())).unwrap().uid();
        let retained = DirectoryCapability::open_root(root.to_str().unwrap()).unwrap();
        assert_eq!(
            read_authority_generation(&retained, owner, &repository),
            Ok(23)
        );
        let other = RepositoryIdentity::parse("owner/other").unwrap();
        assert_eq!(
            read_authority_generation(&retained, owner, &other),
            Err(BackupVolumeError::Generation)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
