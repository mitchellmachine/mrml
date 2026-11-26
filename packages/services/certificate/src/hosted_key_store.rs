extern crate std;

use crate::{AccountP256SigningKey, CertificateP256SigningKey, TlsSigningRoute};
use mrml_crypto::{
    aes128_gcm_open, aes128_gcm_seal, erase_secret_bytes, hmac_sha256, P256Error, P256SecretKey,
    Sha256,
};
use std::format;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

const MAGIC: &[u8; 8] = b"MRMLP256";
const VERSION: u8 = 1;
const HEADER_BYTES: usize = 120;
const RECORD_BYTES: usize = HEADER_BYTES + 32 + 16;
const LINUX_O_NOFOLLOW: i32 = 0x20_000;
const KEY_FILE_MODE: u32 = 0o600;
const KEY_DIRECTORY_MODE: u32 = 0o700;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HostedP256KeyRole {
    AcmeAccount = 1,
    TlsIdentity = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedP256KeyDescriptor {
    pub role: HostedP256KeyRole,
    pub object_id: [u8; 16],
    pub key_generation: u64,
    pub binding_generation: u64,
    pub binding_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedP256KeyError {
    InvalidDescriptor,
    InvalidRoot,
    StoreUnavailable,
    AlreadyExists,
    NotFound,
    Malformed,
    AuthenticationFailed,
    EntropyUnavailable,
    InvalidKey,
}

pub struct HostedP256KeyStore {
    root: PathBuf,
    owner_uid: u32,
    wrapping_key: [u8; 16],
}

impl Drop for HostedP256KeyStore {
    fn drop(&mut self) {
        erase_secret_bytes(&mut self.wrapping_key);
    }
}

impl HostedP256KeyStore {
    pub fn open(
        root: &Path,
        owner_uid: u32,
        unlock_key: &[u8; 32],
    ) -> Result<Self, HostedP256KeyError> {
        validate_absolute_path(root)?;
        let existed = root.exists();
        fs::create_dir_all(root).map_err(|_| HostedP256KeyError::StoreUnavailable)?;
        if !existed {
            fs::set_permissions(root, fs::Permissions::from_mode(KEY_DIRECTORY_MODE))
                .map_err(|_| HostedP256KeyError::StoreUnavailable)?;
        }
        let metadata = fs::symlink_metadata(root).map_err(|_| HostedP256KeyError::InvalidRoot)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != owner_uid
            || metadata.mode() & 0o7777 != KEY_DIRECTORY_MODE
        {
            return Err(HostedP256KeyError::InvalidRoot);
        }
        let mut derived = hmac_sha256(unlock_key, &[b"mrml-certd-hosted-p256-aes-128-gcm-v1"]);
        let mut wrapping_key = [0u8; 16];
        wrapping_key.copy_from_slice(&derived[..16]);
        erase_secret_bytes(&mut derived);
        Ok(Self {
            root: root.to_path_buf(),
            owner_uid,
            wrapping_key,
        })
    }

    pub fn create_account(
        &self,
        descriptor: HostedP256KeyDescriptor,
        entropy: impl FnMut(&mut [u8]) -> Result<(), P256Error>,
    ) -> Result<AccountP256SigningKey, HostedP256KeyError> {
        if descriptor.role != HostedP256KeyRole::AcmeAccount {
            return Err(HostedP256KeyError::InvalidDescriptor);
        }
        let key = self.create_key(descriptor, entropy)?;
        Ok(AccountP256SigningKey::from_secret_key(
            key,
            descriptor.binding_generation,
            descriptor.key_generation,
        ))
    }

    pub fn load_account(
        &self,
        descriptor: HostedP256KeyDescriptor,
    ) -> Result<AccountP256SigningKey, HostedP256KeyError> {
        if descriptor.role != HostedP256KeyRole::AcmeAccount {
            return Err(HostedP256KeyError::InvalidDescriptor);
        }
        let key = self.load_key(descriptor)?;
        Ok(AccountP256SigningKey::from_secret_key(
            key,
            descriptor.binding_generation,
            descriptor.key_generation,
        ))
    }

    pub fn create_certificate(
        &self,
        descriptor: HostedP256KeyDescriptor,
        route: TlsSigningRoute,
        entropy: impl FnMut(&mut [u8]) -> Result<(), P256Error>,
    ) -> Result<CertificateP256SigningKey, HostedP256KeyError> {
        if descriptor.role != HostedP256KeyRole::TlsIdentity
            || route.identity.0 != descriptor.object_id
        {
            return Err(HostedP256KeyError::InvalidDescriptor);
        }
        let key = self.create_key(descriptor, entropy)?;
        CertificateP256SigningKey::from_secret_key(
            key,
            descriptor.key_generation,
            descriptor.binding_generation,
            descriptor.binding_digest,
            route,
        )
        .map_err(|_| HostedP256KeyError::InvalidKey)
    }

    pub fn load_certificate(
        &self,
        descriptor: HostedP256KeyDescriptor,
        route: TlsSigningRoute,
    ) -> Result<CertificateP256SigningKey, HostedP256KeyError> {
        if descriptor.role != HostedP256KeyRole::TlsIdentity
            || route.identity.0 != descriptor.object_id
        {
            return Err(HostedP256KeyError::InvalidDescriptor);
        }
        let key = self.load_key(descriptor)?;
        CertificateP256SigningKey::from_secret_key(
            key,
            descriptor.key_generation,
            descriptor.binding_generation,
            descriptor.binding_digest,
            route,
        )
        .map_err(|_| HostedP256KeyError::InvalidKey)
    }

    fn create_key(
        &self,
        descriptor: HostedP256KeyDescriptor,
        mut entropy: impl FnMut(&mut [u8]) -> Result<(), P256Error>,
    ) -> Result<P256SecretKey, HostedP256KeyError> {
        validate_descriptor(descriptor)?;
        let mut scalar = [0u8; 32];
        let mut selected = None;
        for _ in 0..128 {
            entropy(&mut scalar).map_err(|_| HostedP256KeyError::EntropyUnavailable)?;
            if let Ok(key) = P256SecretKey::from_bytes(scalar) {
                selected = Some(key);
                break;
            }
            erase_secret_bytes(&mut scalar);
        }
        let key = selected.ok_or(HostedP256KeyError::EntropyUnavailable)?;
        let public_identity = key_public_identity(&key)?;
        let result = self.write_record(descriptor, public_identity, &scalar);
        erase_secret_bytes(&mut scalar);
        result?;
        Ok(key)
    }

    fn write_record(
        &self,
        descriptor: HostedP256KeyDescriptor,
        public_identity: [u8; 32],
        scalar: &[u8; 32],
    ) -> Result<(), HostedP256KeyError> {
        let path = self.path(descriptor);
        if path.exists() {
            return Err(HostedP256KeyError::AlreadyExists);
        }
        let mut nonce = [0u8; 12];
        mrml_runtime::fill_random(&mut nonce)
            .map_err(|_| HostedP256KeyError::EntropyUnavailable)?;
        let header = encode_header(descriptor, public_identity, nonce);
        let mut ciphertext = [0u8; 32];
        let mut tag = [0u8; 16];
        if !aes128_gcm_seal(
            &self.wrapping_key,
            &nonce,
            &header,
            scalar,
            &mut ciphertext,
            &mut tag,
        ) {
            return Err(HostedP256KeyError::StoreUnavailable);
        }
        let pending = path.with_extension("pending");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(KEY_FILE_MODE)
            .custom_flags(LINUX_O_NOFOLLOW)
            .open(&pending)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists || path.exists() {
                    HostedP256KeyError::AlreadyExists
                } else {
                    HostedP256KeyError::StoreUnavailable
                }
            })?;
        file.write_all(&header)
            .and_then(|_| file.write_all(&ciphertext))
            .and_then(|_| file.write_all(&tag))
            .and_then(|_| file.sync_all())
            .map_err(|_| HostedP256KeyError::StoreUnavailable)?;
        drop(file);
        match fs::hard_link(&pending, &path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&pending);
                return Err(HostedP256KeyError::AlreadyExists);
            }
            Err(_) => return Err(HostedP256KeyError::StoreUnavailable),
        }
        fs::remove_file(&pending).map_err(|_| HostedP256KeyError::StoreUnavailable)?;
        sync_directory(&self.root)?;
        erase_secret_bytes(&mut ciphertext);
        erase_secret_bytes(&mut tag);
        Ok(())
    }

    fn load_key(
        &self,
        descriptor: HostedP256KeyDescriptor,
    ) -> Result<P256SecretKey, HostedP256KeyError> {
        validate_descriptor(descriptor)?;
        let path = self.path(descriptor);
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(LINUX_O_NOFOLLOW)
            .open(&path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    HostedP256KeyError::NotFound
                } else {
                    HostedP256KeyError::StoreUnavailable
                }
            })?;
        let metadata = file
            .metadata()
            .map_err(|_| HostedP256KeyError::StoreUnavailable)?;
        if !metadata.is_file()
            || metadata.uid() != self.owner_uid
            || metadata.mode() & 0o7777 != KEY_FILE_MODE
            || metadata.nlink() != 1
            || metadata.len() != RECORD_BYTES as u64
        {
            return Err(HostedP256KeyError::Malformed);
        }
        let mut record = [0u8; RECORD_BYTES];
        file.read_exact(&mut record)
            .map_err(|_| HostedP256KeyError::StoreUnavailable)?;
        if !header_matches_descriptor(&record[..HEADER_BYTES], descriptor) {
            return Err(HostedP256KeyError::Malformed);
        }
        let nonce: [u8; 12] = record[108..120]
            .try_into()
            .map_err(|_| HostedP256KeyError::Malformed)?;
        let tag: [u8; 16] = record[HEADER_BYTES + 32..]
            .try_into()
            .map_err(|_| HostedP256KeyError::Malformed)?;
        let mut scalar = [0u8; 32];
        let opened = aes128_gcm_open(
            &self.wrapping_key,
            &nonce,
            &record[..HEADER_BYTES],
            &record[HEADER_BYTES..HEADER_BYTES + 32],
            &tag,
            &mut scalar,
        );
        if !opened {
            erase_secret_bytes(&mut scalar);
            erase_secret_bytes(&mut record);
            return Err(HostedP256KeyError::AuthenticationFailed);
        }
        let expected_public_identity = record_public_identity(&record);
        erase_secret_bytes(&mut record);
        let result = P256SecretKey::from_bytes(scalar)
            .map_err(|_| HostedP256KeyError::InvalidKey)
            .and_then(|key| {
                if key_public_identity(&key)? != expected_public_identity {
                    Err(HostedP256KeyError::AuthenticationFailed)
                } else {
                    Ok(key)
                }
            });
        erase_secret_bytes(&mut scalar);
        result
    }

    fn path(&self, descriptor: HostedP256KeyDescriptor) -> PathBuf {
        self.root.join(format!(
            "k{:02x}-{}-g{:016x}.sealed",
            descriptor.role as u8,
            hex(&descriptor.object_id),
            descriptor.key_generation
        ))
    }
}

fn validate_descriptor(value: HostedP256KeyDescriptor) -> Result<(), HostedP256KeyError> {
    if value.object_id == [0; 16]
        || value.key_generation == 0
        || value.binding_generation == 0
        || value.binding_digest == [0; 32]
    {
        Err(HostedP256KeyError::InvalidDescriptor)
    } else {
        Ok(())
    }
}

fn encode_header(
    value: HostedP256KeyDescriptor,
    public_identity: [u8; 32],
    nonce: [u8; 12],
) -> [u8; HEADER_BYTES] {
    let mut out = [0u8; HEADER_BYTES];
    out[..8].copy_from_slice(MAGIC);
    out[8] = VERSION;
    out[9] = value.role as u8;
    out[12..28].copy_from_slice(&value.object_id);
    out[28..36].copy_from_slice(&value.key_generation.to_be_bytes());
    out[36..44].copy_from_slice(&value.binding_generation.to_be_bytes());
    out[44..76].copy_from_slice(&value.binding_digest);
    out[76..108].copy_from_slice(&public_identity);
    out[108..120].copy_from_slice(&nonce);
    out
}
fn header_matches_descriptor(header: &[u8], value: HostedP256KeyDescriptor) -> bool {
    header.len() == HEADER_BYTES
        && header[..8] == *MAGIC
        && header[8] == VERSION
        && header[9] == value.role as u8
        && header[10..12] == [0; 2]
        && header[12..28] == value.object_id
        && header[28..36] == value.key_generation.to_be_bytes()
        && header[36..44] == value.binding_generation.to_be_bytes()
        && header[44..76] == value.binding_digest
}
fn record_public_identity(record: &[u8; RECORD_BYTES]) -> [u8; 32] {
    record[76..108].try_into().unwrap_or([0; 32])
}
fn key_public_identity(key: &P256SecretKey) -> Result<[u8; 32], HostedP256KeyError> {
    let public = key
        .public_key()
        .map_err(|_| HostedP256KeyError::InvalidKey)?;
    let mut hash = Sha256::new();
    hash.update(b"mrml-hosted-p256-public-identity-v1\0");
    hash.update(&public);
    Ok(hash.finalize())
}
fn validate_absolute_path(path: &Path) -> Result<(), HostedP256KeyError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(HostedP256KeyError::InvalidRoot);
    }
    let mut current = PathBuf::new();
    for component in path
        .parent()
        .ok_or(HostedP256KeyError::InvalidRoot)?
        .components()
    {
        current.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| HostedP256KeyError::InvalidRoot)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(HostedP256KeyError::InvalidRoot);
        }
    }
    Ok(())
}
fn sync_directory(path: &Path) -> Result<(), HostedP256KeyError> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| HostedP256KeyError::StoreUnavailable)
}
fn hex(bytes: &[u8]) -> std::string::String {
    use std::fmt::Write as _;
    let mut s = std::string::String::new();
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    fn root(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "mrml-p256-store-{label}-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(KEY_DIRECTORY_MODE)).unwrap();
        path
    }

    fn account_descriptor() -> HostedP256KeyDescriptor {
        HostedP256KeyDescriptor {
            role: HostedP256KeyRole::AcmeAccount,
            object_id: [3; 16],
            key_generation: 4,
            binding_generation: 5,
            binding_digest: [6; 32],
        }
    }

    #[test]
    fn encrypted_account_key_reopens_as_same_use_only_signer() {
        let root = root("reopen");
        let owner = fs::metadata(&root).unwrap().uid();
        let store = HostedP256KeyStore::open(&root, owner, &[0x41; 32]).unwrap();
        let mut scalar = [0u8; 32];
        scalar[31] = 7;
        let created = store
            .create_account(account_descriptor(), |output| {
                output.copy_from_slice(&scalar);
                Ok(())
            })
            .unwrap();
        let expected = created.public_jwk().unwrap().sec1_uncompressed();
        drop(store);

        let reopened = HostedP256KeyStore::open(&root, owner, &[0x41; 32]).unwrap();
        let loaded = reopened.load_account(account_descriptor()).unwrap();
        assert!(loaded.public_jwk().unwrap().sec1_uncompressed() == expected);
        assert!(matches!(
            reopened.create_account(account_descriptor(), |output| {
                output.copy_from_slice(&scalar);
                Ok(())
            }),
            Err(HostedP256KeyError::AlreadyExists)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrong_unlock_key_tampering_and_metadata_substitution_fail_closed() {
        let root = root("tamper");
        let owner = fs::metadata(&root).unwrap().uid();
        let descriptor = account_descriptor();
        let store = HostedP256KeyStore::open(&root, owner, &[0x51; 32]).unwrap();
        let mut scalar = [0u8; 32];
        scalar[31] = 11;
        store
            .create_account(descriptor, |output| {
                output.copy_from_slice(&scalar);
                Ok(())
            })
            .unwrap();
        let wrong = HostedP256KeyStore::open(&root, owner, &[0x52; 32]).unwrap();
        assert_eq!(
            wrong.load_account(descriptor).err(),
            Some(HostedP256KeyError::AuthenticationFailed)
        );

        let path = store.path(descriptor);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let tamper_offset = SeekFrom::Start(HEADER_BYTES as u64 + 3);
        file.seek(tamper_offset).unwrap();
        let mut ciphertext = [0u8; 1];
        file.read_exact(&mut ciphertext).unwrap();
        // A fixed replacement can match this randomized ciphertext by chance.
        ciphertext[0] ^= 1;
        file.seek(tamper_offset).unwrap();
        file.write_all(&ciphertext).unwrap();
        file.sync_all().unwrap();
        assert_eq!(
            store.load_account(descriptor).err(),
            Some(HostedP256KeyError::AuthenticationFailed)
        );

        let mut substituted = descriptor;
        substituted.binding_generation += 1;
        assert_eq!(
            store.load_account(substituted).err(),
            Some(HostedP256KeyError::Malformed)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn descriptor_and_file_permissions_are_strict() {
        let root = root("mode");
        let owner = fs::metadata(&root).unwrap().uid();
        let store = HostedP256KeyStore::open(&root, owner, &[0x61; 32]).unwrap();
        let mut invalid = account_descriptor();
        invalid.binding_digest = [0; 32];
        assert_eq!(
            store.load_account(invalid).err(),
            Some(HostedP256KeyError::InvalidDescriptor)
        );
        let descriptor = account_descriptor();
        let mut scalar = [0u8; 32];
        scalar[31] = 13;
        store
            .create_account(descriptor, |out| {
                out.copy_from_slice(&scalar);
                Ok(())
            })
            .unwrap();
        fs::set_permissions(store.path(descriptor), fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            store.load_account(descriptor).err(),
            Some(HostedP256KeyError::Malformed)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
