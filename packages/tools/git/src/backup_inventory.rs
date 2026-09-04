//! Canonical bounded inventory authenticated inside a Git backup stream.

use mrml_crypto::Sha256;
use mrml_runtime::{Text, Vector};

use crate::{
    PackGeneration, RepositoryGeneration, RepositoryIdentity, RevocationGeneration, TrustGeneration,
};

const MAGIC: &[u8; 8] = b"MRGBIV01";
const VERSION: u16 = 1;
const DIGEST_BYTES: usize = 32;
const ENTRY_FIXED_BYTES: usize = 56;
const REPOSITORY_FIXED_BYTES: usize = 42;
const MAX_PATH_BYTES: usize = 1024;
const MAX_REPOSITORIES: usize = 65_536;
pub const MAX_BACKUP_INVENTORY_ENTRIES: usize = 1_000_000;
pub const MAX_BACKUP_INVENTORY_BYTES: usize = 64 * 1024 * 1024;
pub const BACKUP_VOLUME_MASK: u16 = (1 << 10) - 1;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum BackupVolume {
    GitdRepositories = 1,
    GitdState = 2,
    GitdQuarantine = 3,
    GitdReceipts = 4,
    GitdPolicies = 5,
    GitdSecrets = 6,
    GitdConfiguration = 7,
    AuthorityState = 8,
    AuthoritySecrets = 9,
    AuthorityConfiguration = 10,
}

impl BackupVolume {
    const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::GitdRepositories,
            2 => Self::GitdState,
            3 => Self::GitdQuarantine,
            4 => Self::GitdReceipts,
            5 => Self::GitdPolicies,
            6 => Self::GitdSecrets,
            7 => Self::GitdConfiguration,
            8 => Self::AuthorityState,
            9 => Self::AuthoritySecrets,
            10 => Self::AuthorityConfiguration,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BackupInventoryFileKind {
    Directory = 1,
    Regular = 2,
}

impl BackupInventoryFileKind {
    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Directory),
            2 => Some(Self::Regular),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupRepositoryGeneration {
    pub repository: RepositoryIdentity,
    pub repository_generation: RepositoryGeneration,
    pub pack_generation: PackGeneration,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    /// Zero for a conventional repository; nonzero for a protected repository.
    pub authority_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupInventoryEntry {
    pub volume: BackupVolume,
    pub path: Text,
    pub kind: BackupInventoryFileKind,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupInventory {
    pub backup_generation: u64,
    pub repositories: Vector<BackupRepositoryGeneration>,
    pub entries: Vector<BackupInventoryEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupInventoryError {
    Malformed,
    NonCanonical,
    Resource,
    Integrity,
}

pub fn encode_backup_inventory(
    inventory: &BackupInventory,
) -> Result<Vector<u8>, BackupInventoryError> {
    validate_inventory(inventory)?;
    let mut output = Vector::new();
    append(&mut output, MAGIC)?;
    append_u16(&mut output, usize::from(VERSION))?;
    append_u16(&mut output, usize::from(BACKUP_VOLUME_MASK))?;
    append_u64(&mut output, inventory.backup_generation)?;
    append_u32(&mut output, inventory.repositories.len())?;
    append_u32(&mut output, inventory.entries.len())?;
    for repository in &inventory.repositories {
        let identity = repository.repository.as_str().as_bytes();
        append_u16(&mut output, identity.len())?;
        append(&mut output, identity)?;
        append_u64(&mut output, repository.repository_generation.0)?;
        append_u64(&mut output, repository.pack_generation.0)?;
        append_u64(&mut output, repository.trust_generation.0)?;
        append_u64(&mut output, repository.revocation_generation.0)?;
        append_u64(&mut output, repository.authority_generation)?;
    }
    for entry in &inventory.entries {
        append(&mut output, &[entry.volume as u8, entry.kind as u8])?;
        append_u16(&mut output, usize::from(entry.mode))?;
        append(&mut output, &entry.uid.to_be_bytes())?;
        append(&mut output, &entry.gid.to_be_bytes())?;
        append_u64(&mut output, entry.size)?;
        append_u16(&mut output, entry.path.len())?;
        append_u16(&mut output, 0)?;
        append(&mut output, &entry.digest)?;
        append(&mut output, entry.path.as_bytes())?;
    }
    if output
        .len()
        .checked_add(DIGEST_BYTES)
        .is_none_or(|length| length > MAX_BACKUP_INVENTORY_BYTES)
    {
        return Err(BackupInventoryError::Resource);
    }
    let digest = Sha256::digest(&output);
    append(&mut output, &digest)?;
    Ok(output)
}

pub fn parse_backup_inventory(input: &[u8]) -> Result<BackupInventory, BackupInventoryError> {
    if input.len() < 28 + DIGEST_BYTES || input.len() > MAX_BACKUP_INVENTORY_BYTES {
        return Err(BackupInventoryError::Malformed);
    }
    let content_end = input.len() - DIGEST_BYTES;
    if Sha256::digest(&input[..content_end]) != input[content_end..] {
        return Err(BackupInventoryError::Integrity);
    }
    let mut cursor = Cursor::new(&input[..content_end]);
    if cursor.take(8)? != MAGIC || cursor.u16()? != VERSION || cursor.u16()? != BACKUP_VOLUME_MASK {
        return Err(BackupInventoryError::Malformed);
    }
    let backup_generation = cursor.u64()?;
    let repository_count =
        usize::try_from(cursor.u32()?).map_err(|_| BackupInventoryError::Resource)?;
    let entry_count = usize::try_from(cursor.u32()?).map_err(|_| BackupInventoryError::Resource)?;
    if repository_count == 0
        || repository_count > MAX_REPOSITORIES
        || entry_count > MAX_BACKUP_INVENTORY_ENTRIES
    {
        return Err(BackupInventoryError::Resource);
    }
    let minimum = repository_count
        .checked_mul(REPOSITORY_FIXED_BYTES)
        .and_then(|value| value.checked_add(entry_count.checked_mul(ENTRY_FIXED_BYTES)?))
        .ok_or(BackupInventoryError::Resource)?;
    if minimum > cursor.remaining() {
        return Err(BackupInventoryError::Malformed);
    }
    let mut repositories = Vector::new();
    repositories
        .try_reserve_exact(repository_count)
        .map_err(|_| BackupInventoryError::Resource)?;
    for _ in 0..repository_count {
        let identity = core::str::from_utf8(cursor.length_prefixed()?)
            .map_err(|_| BackupInventoryError::Malformed)?;
        repositories.push(BackupRepositoryGeneration {
            repository: RepositoryIdentity::parse(identity)
                .map_err(|_| BackupInventoryError::Malformed)?,
            repository_generation: RepositoryGeneration(cursor.nonzero_u64()?),
            pack_generation: PackGeneration(cursor.nonzero_u64()?),
            trust_generation: TrustGeneration(cursor.nonzero_u64()?),
            revocation_generation: RevocationGeneration(cursor.nonzero_u64()?),
            authority_generation: cursor.u64()?,
        });
    }
    let mut entries = Vector::new();
    entries
        .try_reserve_exact(entry_count)
        .map_err(|_| BackupInventoryError::Resource)?;
    for _ in 0..entry_count {
        let volume =
            BackupVolume::from_code(cursor.u8()?).ok_or(BackupInventoryError::Malformed)?;
        let kind = BackupInventoryFileKind::from_code(cursor.u8()?)
            .ok_or(BackupInventoryError::Malformed)?;
        let mode = cursor.u16()?;
        let uid = cursor.u32()?;
        let gid = cursor.u32()?;
        let size = cursor.u64()?;
        let path_length = usize::from(cursor.u16()?);
        if cursor.u16()? != 0 || path_length == 0 || path_length > MAX_PATH_BYTES {
            return Err(BackupInventoryError::Malformed);
        }
        let digest: [u8; 32] = cursor.take(32)?.try_into().unwrap();
        let path = core::str::from_utf8(cursor.take(path_length)?)
            .map_err(|_| BackupInventoryError::Malformed)?;
        entries.push(BackupInventoryEntry {
            volume,
            path: path.into(),
            kind,
            mode,
            uid,
            gid,
            size,
            digest,
        });
    }
    if cursor.remaining() != 0 {
        return Err(BackupInventoryError::Malformed);
    }
    let inventory = BackupInventory {
        backup_generation,
        repositories,
        entries,
    };
    validate_inventory(&inventory)?;
    Ok(inventory)
}

fn validate_inventory(inventory: &BackupInventory) -> Result<(), BackupInventoryError> {
    if inventory.backup_generation == 0
        || inventory.repositories.is_empty()
        || inventory.repositories.len() > MAX_REPOSITORIES
        || inventory.entries.len() > MAX_BACKUP_INVENTORY_ENTRIES
    {
        return Err(BackupInventoryError::Resource);
    }
    let mut previous_repository: Option<&str> = None;
    for repository in &inventory.repositories {
        if previous_repository.is_some_and(|previous| previous >= repository.repository.as_str())
            || repository.repository_generation.0 == 0
            || repository.pack_generation.0 == 0
            || repository.trust_generation.0 == 0
            || repository.revocation_generation.0 == 0
        {
            return Err(BackupInventoryError::NonCanonical);
        }
        previous_repository = Some(repository.repository.as_str());
    }
    let mut previous_entry: Option<(BackupVolume, &str)> = None;
    for entry in &inventory.entries {
        validate_path(entry.path.as_str())?;
        if entry.mode & !0o7777 != 0
            || matches!(entry.kind, BackupInventoryFileKind::Directory)
                && (entry.size != 0 || entry.digest != [0; 32])
            || matches!(entry.kind, BackupInventoryFileKind::Regular) && entry.digest == [0; 32]
            || previous_entry
                .is_some_and(|previous| previous >= (entry.volume, entry.path.as_str()))
        {
            return Err(BackupInventoryError::NonCanonical);
        }
        previous_entry = Some((entry.volume, entry.path.as_str()));
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), BackupInventoryError> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\0')
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(BackupInventoryError::NonCanonical);
    }
    Ok(())
}

fn append(output: &mut Vector<u8>, bytes: &[u8]) -> Result<(), BackupInventoryError> {
    if output
        .len()
        .checked_add(bytes.len())
        .is_none_or(|length| length > MAX_BACKUP_INVENTORY_BYTES)
    {
        return Err(BackupInventoryError::Resource);
    }
    output
        .try_extend_from_slice(bytes)
        .map_err(|_| BackupInventoryError::Resource)
}

fn append_u16(output: &mut Vector<u8>, value: usize) -> Result<(), BackupInventoryError> {
    append(
        output,
        &u16::try_from(value)
            .map_err(|_| BackupInventoryError::Resource)?
            .to_be_bytes(),
    )
}

fn append_u32(output: &mut Vector<u8>, value: usize) -> Result<(), BackupInventoryError> {
    append(
        output,
        &u32::try_from(value)
            .map_err(|_| BackupInventoryError::Resource)?
            .to_be_bytes(),
    )
}

fn append_u64(output: &mut Vector<u8>, value: u64) -> Result<(), BackupInventoryError> {
    append(output, &value.to_be_bytes())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], BackupInventoryError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(BackupInventoryError::Resource)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(BackupInventoryError::Malformed)?;
        self.position = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, BackupInventoryError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, BackupInventoryError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, BackupInventoryError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, BackupInventoryError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn nonzero_u64(&mut self) -> Result<u64, BackupInventoryError> {
        let value = self.u64()?;
        if value == 0 {
            Err(BackupInventoryError::Malformed)
        } else {
            Ok(value)
        }
    }
    fn length_prefixed(&mut self) -> Result<&'a [u8], BackupInventoryError> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > MAX_PATH_BYTES {
            return Err(BackupInventoryError::Malformed);
        }
        self.take(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inventory() -> BackupInventory {
        BackupInventory {
            backup_generation: 9,
            repositories: [BackupRepositoryGeneration {
                repository: RepositoryIdentity::parse("owner/repository").unwrap(),
                repository_generation: RepositoryGeneration(7),
                pack_generation: PackGeneration(8),
                trust_generation: TrustGeneration(4),
                revocation_generation: RevocationGeneration(3),
                authority_generation: 7,
            }]
            .into(),
            entries: [
                BackupInventoryEntry {
                    volume: BackupVolume::GitdRepositories,
                    path: "owner".into(),
                    kind: BackupInventoryFileKind::Directory,
                    mode: 0o700,
                    uid: 21001,
                    gid: 21001,
                    size: 0,
                    digest: [0; 32],
                },
                BackupInventoryEntry {
                    volume: BackupVolume::GitdRepositories,
                    path: "owner/repository/.git/HEAD".into(),
                    kind: BackupInventoryFileKind::Regular,
                    mode: 0o600,
                    uid: 21001,
                    gid: 21001,
                    size: 21,
                    digest: Sha256::digest(b"ref: refs/heads/main\n"),
                },
                BackupInventoryEntry {
                    volume: BackupVolume::AuthorityState,
                    path: "generations/owner".into(),
                    kind: BackupInventoryFileKind::Directory,
                    mode: 0o700,
                    uid: 21002,
                    gid: 21002,
                    size: 0,
                    digest: [0; 32],
                },
            ]
            .into(),
        }
    }

    #[test]
    fn canonical_inventory_round_trips() {
        let inventory = inventory();
        let encoded = encode_backup_inventory(&inventory).unwrap();
        assert_eq!(parse_backup_inventory(&encoded).unwrap(), inventory);
    }

    #[test]
    fn tamper_truncation_reordering_and_unsafe_paths_fail_closed() {
        let mut encoded = encode_backup_inventory(&inventory()).unwrap();
        encoded[30] ^= 1;
        assert_eq!(
            parse_backup_inventory(&encoded),
            Err(BackupInventoryError::Integrity)
        );
        encoded.pop();
        assert!(parse_backup_inventory(&encoded).is_err());

        let mut reordered = inventory();
        reordered.entries.swap(0, 1);
        assert_eq!(
            encode_backup_inventory(&reordered),
            Err(BackupInventoryError::NonCanonical)
        );
        let mut unsafe_entry = inventory();
        unsafe_entry.entries[0].path = "../escape".into();
        assert_eq!(
            encode_backup_inventory(&unsafe_entry),
            Err(BackupInventoryError::NonCanonical)
        );
    }

    #[test]
    fn generation_and_file_metadata_are_bounded_and_exact() {
        let mut candidate = inventory();
        candidate.repositories[0].repository_generation = RepositoryGeneration(0);
        assert!(encode_backup_inventory(&candidate).is_err());
        let mut candidate = inventory();
        candidate.entries[0].size = 1;
        assert!(encode_backup_inventory(&candidate).is_err());
        let mut candidate = inventory();
        candidate.entries[1].digest = [0; 32];
        assert!(encode_backup_inventory(&candidate).is_err());
    }
}
