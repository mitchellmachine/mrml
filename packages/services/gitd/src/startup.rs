use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use crate::GitdConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupValidationError {
    Missing,
    Symlink,
    Type,
    Owner,
    Permissions,
}

pub fn validate_storage_layout(config: &GitdConfig) -> Result<(), StartupValidationError> {
    for path in [
        &config.repository_root,
        &config.state_root,
        &config.quarantine_root,
        &config.cache_root,
        &config.receipt_root,
    ] {
        validate_directory(path, config.gitd_uid, config.gitd_gid, true)?;
    }
    validate_directory(&config.policy_root, config.gitd_uid, config.gitd_gid, false)
}

fn validate_directory(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    require_owner_write: bool,
) -> Result<(), StartupValidationError> {
    validate_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| StartupValidationError::Missing)?;
    if metadata.file_type().is_symlink() {
        return Err(StartupValidationError::Symlink);
    }
    if !metadata.file_type().is_dir() {
        return Err(StartupValidationError::Type);
    }
    if metadata.uid() != expected_uid || metadata.gid() != expected_gid {
        return Err(StartupValidationError::Owner);
    }
    let mode = metadata.mode() & 0o777;
    if mode & 0o007 != 0
        || mode & 0o020 != 0
        || mode & 0o500 != 0o500
        || (require_owner_write && mode & 0o200 == 0)
    {
        return Err(StartupValidationError::Permissions);
    }
    Ok(())
}

fn validate_components(path: &Path) -> Result<(), StartupValidationError> {
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(Path::new("/")),
            Component::Normal(value) => current.push(value),
            _ => return Err(StartupValidationError::Type),
        }
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| StartupValidationError::Missing)?;
        if metadata.file_type().is_symlink() {
            return Err(StartupValidationError::Symlink);
        }
        if !metadata.file_type().is_dir() {
            return Err(StartupValidationError::Type);
        }
        if current != Path::new("/")
            && metadata.mode() & 0o022 != 0
            && metadata.mode() & 0o1000 == 0
        {
            return Err(StartupValidationError::Permissions);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    #[test]
    fn exact_owned_layout_passes_and_symlink_or_writable_parent_fails() {
        let root = std::env::temp_dir().join(format!("mrml-gitd-layout-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(&root).unwrap();
        let paths = [
            "repos",
            "state",
            "quarantine",
            "cache",
            "receipts",
            "policies",
        ];
        for name in paths {
            let path = root.join(name);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut config = crate::parse_gitd_config(
            b"version=1\nserver_name=git.example.invalid\nlisten_port=8443\nrepository_root=/a\nstate_root=/b\nquarantine_root=/c\ncache_root=/d\nreceipt_root=/e\npolicy_root=/f\nrepository_catalog=/f/repositories.v1\nprofile_catalog=/f/profiles.v1\ntoken_records=/b/tokens.v1\ntoken_pepper=/run/secrets/gitd-token-pepper\nauthority_socket=/g\ncertd_socket=/h\nauthority_capability=/i\ncertd_capability=/j\ngitd_uid=1\ngitd_gid=1\nauthority_uid=2\nauthority_gid=2\ncertd_uid=3\ncertd_gid=3\nnext_authority_request_id=1\nnext_certd_request_id=1\nmax_connections=1\nmax_uploads=1\nmax_receives=1\nmax_body_bytes=1024\ndrain_seconds=1\n",
        )
        .unwrap();
        config.gitd_uid = metadata.uid();
        config.gitd_gid = metadata.gid();
        config.repository_root = root.join("repos");
        config.state_root = root.join("state");
        config.quarantine_root = root.join("quarantine");
        config.cache_root = root.join("cache");
        config.receipt_root = root.join("receipts");
        config.policy_root = root.join("policies");
        assert_eq!(validate_storage_layout(&config), Ok(()));

        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            validate_storage_layout(&config),
            Err(StartupValidationError::Permissions)
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir(config.cache_root.clone()).unwrap();
        symlink(root.join("state"), &config.cache_root).unwrap();
        assert_eq!(
            validate_storage_layout(&config),
            Err(StartupValidationError::Symlink)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
