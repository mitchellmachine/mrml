extern crate std;

use crate::{HmacSha256DurableAuthenticator, DURABLE_AUTHENTICATION_KEY_BYTES};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

const LINUX_O_NOFOLLOW: i32 = 0x20_000;
pub const PRODUCTION_SECRET_MODE: u32 = 0o400;
pub const MAX_HOSTED_SECRET_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedSecretError {
    InvalidPath,
    Symlink,
    NotRegular,
    WrongOwner,
    WrongMode,
    MultipleLinks,
    Empty,
    Oversized,
    ChangedDuringOpen,
    ReadFailed,
    WrongLength,
}

pub struct HostedSecret {
    bytes: [u8; MAX_HOSTED_SECRET_BYTES],
    length: usize,
}

impl HostedSecret {
    pub fn open(
        path: &Path,
        expected_uid: u32,
        expected_mode: u32,
        maximum_length: usize,
    ) -> Result<Self, HostedSecretError> {
        if maximum_length == 0 || maximum_length > MAX_HOSTED_SECRET_BYTES {
            return Err(HostedSecretError::Oversized);
        }
        reject_unsafe_path(path)?;
        let path_metadata = std::fs::symlink_metadata(path).map_err(map_open_error)?;
        if path_metadata.file_type().is_symlink() {
            return Err(HostedSecretError::Symlink);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(LINUX_O_NOFOLLOW)
            .open(path)
            .map_err(map_open_error)?;
        let metadata = file.metadata().map_err(|_| HostedSecretError::ReadFailed)?;
        validate_metadata(&metadata, expected_uid, expected_mode, maximum_length)?;
        if metadata.dev() != path_metadata.dev() || metadata.ino() != path_metadata.ino() {
            return Err(HostedSecretError::ChangedDuringOpen);
        }

        let length = usize::try_from(metadata.len()).map_err(|_| HostedSecretError::Oversized)?;
        let mut bytes = [0u8; MAX_HOSTED_SECRET_BYTES];
        file.read_exact(&mut bytes[..length])
            .map_err(|_| HostedSecretError::ReadFailed)?;
        let mut trailing = [0u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|_| HostedSecretError::ReadFailed)?
            != 0
        {
            return Err(HostedSecretError::ChangedDuringOpen);
        }
        Ok(Self { bytes, length })
    }

    pub fn expose(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

impl Drop for HostedSecret {
    fn drop(&mut self) {
        self.bytes.fill(0);
        self.length = 0;
    }
}

pub fn load_durable_authenticator(
    path: &Path,
    expected_uid: u32,
) -> Result<HmacSha256DurableAuthenticator, HostedSecretError> {
    let secret = HostedSecret::open(
        path,
        expected_uid,
        PRODUCTION_SECRET_MODE,
        DURABLE_AUTHENTICATION_KEY_BYTES,
    )?;
    let key: [u8; DURABLE_AUTHENTICATION_KEY_BYTES] = secret
        .expose()
        .try_into()
        .map_err(|_| HostedSecretError::WrongLength)?;
    Ok(HmacSha256DurableAuthenticator::new(key))
}

fn validate_metadata(
    metadata: &std::fs::Metadata,
    expected_uid: u32,
    expected_mode: u32,
    maximum_length: usize,
) -> Result<(), HostedSecretError> {
    if !metadata.is_file() {
        return Err(HostedSecretError::NotRegular);
    }
    if metadata.uid() != expected_uid {
        return Err(HostedSecretError::WrongOwner);
    }
    if metadata.mode() & 0o7777 != expected_mode {
        return Err(HostedSecretError::WrongMode);
    }
    if metadata.nlink() != 1 {
        return Err(HostedSecretError::MultipleLinks);
    }
    if metadata.len() == 0 {
        return Err(HostedSecretError::Empty);
    }
    if metadata.len() > maximum_length as u64 {
        return Err(HostedSecretError::Oversized);
    }
    Ok(())
}

fn reject_unsafe_path(path: &Path) -> Result<(), HostedSecretError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(HostedSecretError::InvalidPath);
    }
    let mut parent = PathBuf::new();
    for component in path
        .parent()
        .ok_or(HostedSecretError::InvalidPath)?
        .components()
    {
        parent.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&parent).map_err(map_open_error)?;
        if metadata.file_type().is_symlink() {
            return Err(HostedSecretError::Symlink);
        }
        if !metadata.is_dir() {
            return Err(HostedSecretError::InvalidPath);
        }
    }
    Ok(())
}

fn map_open_error(error: std::io::Error) -> HostedSecretError {
    if error.raw_os_error() == Some(40) {
        HostedSecretError::Symlink
    } else {
        HostedSecretError::ReadFailed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn root(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(std::format!(
            "mrml-certd-secret-{}-{}",
            label,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        path
    }

    fn write_secret(path: &Path, bytes: &[u8]) -> u32 {
        let mut file = File::create(path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).unwrap();
        file.metadata().unwrap().uid()
    }

    #[test]
    fn exact_secret_loads_and_wrong_mode_or_length_fails() {
        let root = root("exact");
        let path = root.join("unlock.key");
        let uid = write_secret(&path, &[0x51; 32]);
        assert!(load_durable_authenticator(&path, uid).is_ok());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o440)).unwrap();
        assert!(matches!(
            HostedSecret::open(&path, uid, 0o400, 32),
            Err(HostedSecretError::WrongMode)
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.write_all(&[7; 31]).unwrap();
        drop(file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(
            load_durable_authenticator(&path, uid),
            Err(HostedSecretError::WrongLength)
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn symlink_and_hardlink_are_rejected() {
        let root = root("links");
        let actual = root.join("actual.key");
        let uid = write_secret(&actual, &[0x62; 32]);
        let link = root.join("link.key");
        symlink(&actual, &link).unwrap();
        assert!(matches!(
            HostedSecret::open(&link, uid, 0o400, 32),
            Err(HostedSecretError::Symlink)
        ));
        let hardlink = root.join("hard.key");
        std::fs::hard_link(&actual, &hardlink).unwrap();
        assert!(matches!(
            HostedSecret::open(&actual, uid, 0o400, 32),
            Err(HostedSecretError::MultipleLinks)
        ));
        std::fs::remove_dir_all(root).unwrap();
    }
}
