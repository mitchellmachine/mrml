use mrml_crypto::Sha256;
use mrml_git::{
    AuthorityCandidateContext, AuthorityCandidateRecord, AuthorityCandidateStatus,
    QuarantineTransactionId, RepositoryGeneration, RepositoryIdentity, RevocationGeneration,
    TrustGeneration,
};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"MRACAN01";
const DOMAIN: &[u8] = b"MRML git authority candidate journal v1\0";
const O_NOFOLLOW: i32 = 0x20_000;
const MAX_REPOSITORY_BYTES: usize = 255;
const FIXED_BYTES: usize = 8 + 16 + 2 + 8 * 4 + 64 * 6 + 1 + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateStoreError {
    AlreadyExists,
    Invalid,
    Missing,
    Stale,
    Unavailable,
}

pub struct LinuxAuthorityCandidateStore {
    root: PathBuf,
    owner_uid: u32,
}

impl LinuxAuthorityCandidateStore {
    pub fn open(root: &str, owner_uid: u32) -> Result<Self, CandidateStoreError> {
        if owner_uid == 0 {
            return Err(CandidateStoreError::Invalid);
        }
        let root = fs::canonicalize(root).map_err(|_| CandidateStoreError::Unavailable)?;
        validate_directory(&root, owner_uid)?;
        Ok(Self { root, owner_uid })
    }

    pub fn begin(
        &self,
        context: AuthorityCandidateContext,
    ) -> Result<AuthorityCandidateRecord, CandidateStoreError> {
        validate_context(&context)?;
        let record = AuthorityCandidateRecord {
            context,
            status: AuthorityCandidateStatus::Receiving,
        };
        let path = self.path(record.context.id);
        if path.exists() {
            return match self.query(record.context.id) {
                Ok(existing) if existing == record => Ok(existing),
                Ok(_) => Err(CandidateStoreError::AlreadyExists),
                Err(error) => Err(error),
            };
        }
        self.write_new(&path, &record)?;
        sync_directory(&self.root)?;
        self.query(record.context.id)
    }

    pub fn query(
        &self,
        id: QuarantineTransactionId,
    ) -> Result<AuthorityCandidateRecord, CandidateStoreError> {
        if id.0 == [0; 16] {
            return Err(CandidateStoreError::Invalid);
        }
        let path = self.path(id);
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    CandidateStoreError::Missing
                } else {
                    CandidateStoreError::Unavailable
                }
            })?;
        validate_file(&file, self.owner_uid)?;
        let length = usize::try_from(
            file.metadata()
                .map_err(|_| CandidateStoreError::Unavailable)?
                .len(),
        )
        .map_err(|_| CandidateStoreError::Invalid)?;
        if length < FIXED_BYTES || length > FIXED_BYTES + MAX_REPOSITORY_BYTES {
            return Err(CandidateStoreError::Invalid);
        }
        let mut encoded = vec![0; length];
        file.read_exact(&mut encoded)
            .map_err(|_| CandidateStoreError::Unavailable)?;
        decode(&encoded, id)
    }

    pub fn transition(
        &self,
        context: &AuthorityCandidateContext,
        expected: AuthorityCandidateStatus,
        next: AuthorityCandidateStatus,
    ) -> Result<AuthorityCandidateRecord, CandidateStoreError> {
        validate_context(context)?;
        let current = self.query(context.id)?;
        if &current.context != context {
            return Err(CandidateStoreError::Stale);
        }
        if current.status == next {
            return Ok(current);
        }
        if current.status != expected || !expected.permits(next) {
            return Err(CandidateStoreError::Stale);
        }
        let replacement = AuthorityCandidateRecord {
            context: context.clone(),
            status: next,
        };
        let temporary = self.temporary_path(context.id);
        if temporary.exists() {
            return Err(CandidateStoreError::Unavailable);
        }
        self.write_new(&temporary, &replacement)?;
        fs::rename(&temporary, self.path(context.id))
            .map_err(|_| CandidateStoreError::Unavailable)?;
        sync_directory(&self.root)?;
        let reread = self.query(context.id)?;
        (reread == replacement)
            .then_some(reread)
            .ok_or(CandidateStoreError::Unavailable)
    }

    fn path(&self, id: QuarantineTransactionId) -> PathBuf {
        self.root.join(format!("{}.candidate", id_hex(id)))
    }

    fn temporary_path(&self, id: QuarantineTransactionId) -> PathBuf {
        self.root.join(format!("{}.candidate.next", id_hex(id)))
    }

    fn write_new(
        &self,
        path: &Path,
        record: &AuthorityCandidateRecord,
    ) -> Result<(), CandidateStoreError> {
        let encoded = encode(record)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(path)
            .map_err(|_| CandidateStoreError::Unavailable)?;
        file.write_all(&encoded)
            .and_then(|_| file.sync_all())
            .map_err(|_| CandidateStoreError::Unavailable)?;
        validate_file(&file, self.owner_uid)
    }
}

fn encode(record: &AuthorityCandidateRecord) -> Result<Vec<u8>, CandidateStoreError> {
    validate_context(&record.context)?;
    let repository = record.context.repository.as_str().as_bytes();
    let mut output = Vec::with_capacity(FIXED_BYTES + repository.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&record.context.id.0);
    output.extend_from_slice(&(repository.len() as u16).to_be_bytes());
    output.extend_from_slice(repository);
    output.extend_from_slice(&record.context.current_generation.0.to_be_bytes());
    output.extend_from_slice(&record.context.next_generation.0.to_be_bytes());
    output.extend_from_slice(&record.context.trust_generation.0.to_be_bytes());
    output.extend_from_slice(&record.context.revocation_generation.0.to_be_bytes());
    output.extend_from_slice(&record.context.policy_digest);
    output.extend_from_slice(&record.context.ref_update_digest);
    output.extend_from_slice(&record.context.introduced_commit_set_digest);
    output.extend_from_slice(&record.context.arrival_pack_digest);
    output.extend_from_slice(&record.context.proof_set_digest);
    output.extend_from_slice(&record.context.activation_digest);
    output.push(record.status as u8);
    let checksum = Sha256::digest(&[DOMAIN, output.as_slice()].concat());
    output.extend_from_slice(&checksum);
    Ok(output)
}

fn decode(
    input: &[u8],
    expected_id: QuarantineTransactionId,
) -> Result<AuthorityCandidateRecord, CandidateStoreError> {
    if input.len() < FIXED_BYTES || &input[..8] != MAGIC {
        return Err(CandidateStoreError::Invalid);
    }
    let checksum_at = input.len().checked_sub(32).ok_or(CandidateStoreError::Invalid)?;
    if Sha256::digest(&[DOMAIN, &input[..checksum_at]].concat()).as_slice()
        != &input[checksum_at..]
    {
        return Err(CandidateStoreError::Invalid);
    }
    let mut cursor = 8;
    let mut id = [0; 16];
    id.copy_from_slice(take(input, &mut cursor, 16)?);
    if id != expected_id.0 {
        return Err(CandidateStoreError::Invalid);
    }
    let repository_length = u16::from_be_bytes(
        take(input, &mut cursor, 2)?
            .try_into()
            .map_err(|_| CandidateStoreError::Invalid)?,
    ) as usize;
    if repository_length == 0 || repository_length > MAX_REPOSITORY_BYTES {
        return Err(CandidateStoreError::Invalid);
    }
    let repository = std::str::from_utf8(take(input, &mut cursor, repository_length)?)
        .map_err(|_| CandidateStoreError::Invalid)?;
    let repository =
        RepositoryIdentity::parse(repository).map_err(|_| CandidateStoreError::Invalid)?;
    let read_u64 = |input: &[u8], cursor: &mut usize| {
        Ok::<u64, CandidateStoreError>(u64::from_be_bytes(
            take(input, cursor, 8)?
                .try_into()
                .map_err(|_| CandidateStoreError::Invalid)?,
        ))
    };
    let current_generation = RepositoryGeneration(read_u64(input, &mut cursor)?);
    let next_generation = RepositoryGeneration(read_u64(input, &mut cursor)?);
    let trust_generation = TrustGeneration(read_u64(input, &mut cursor)?);
    let revocation_generation = RevocationGeneration(read_u64(input, &mut cursor)?);
    let mut digest = || -> Result<[u8; 64], CandidateStoreError> {
        take(input, &mut cursor, 64)?
            .try_into()
            .map_err(|_| CandidateStoreError::Invalid)
    };
    let context = AuthorityCandidateContext {
        id: expected_id,
        repository,
        current_generation,
        next_generation,
        trust_generation,
        revocation_generation,
        policy_digest: digest()?,
        ref_update_digest: digest()?,
        introduced_commit_set_digest: digest()?,
        arrival_pack_digest: digest()?,
        proof_set_digest: digest()?,
        activation_digest: digest()?,
    };
    let status = AuthorityCandidateStatus::from_code(
        *take(input, &mut cursor, 1)?
            .first()
            .ok_or(CandidateStoreError::Invalid)?,
    )
    .ok_or(CandidateStoreError::Invalid)?;
    if cursor != checksum_at {
        return Err(CandidateStoreError::Invalid);
    }
    validate_context(&context)?;
    Ok(AuthorityCandidateRecord { context, status })
}

fn validate_context(context: &AuthorityCandidateContext) -> Result<(), CandidateStoreError> {
    if context.id.0 == [0; 16]
        || context.current_generation.0 == 0
        || context.current_generation.0.checked_add(1) != Some(context.next_generation.0)
        || context.trust_generation.0 == 0
        || context.repository.as_str().is_empty()
        || context.repository.as_str().len() > MAX_REPOSITORY_BYTES
        || context.policy_digest == [0; 64]
        || context.ref_update_digest == [0; 64]
        || context.introduced_commit_set_digest == [0; 64]
        || context.arrival_pack_digest == [0; 64]
        || context.proof_set_digest == [0; 64]
        || context.activation_digest == [0; 64]
    {
        return Err(CandidateStoreError::Invalid);
    }
    Ok(())
}

fn take<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], CandidateStoreError> {
    let end = cursor.checked_add(length).ok_or(CandidateStoreError::Invalid)?;
    let bytes = input.get(*cursor..end).ok_or(CandidateStoreError::Invalid)?;
    *cursor = end;
    Ok(bytes)
}

fn id_hex(id: QuarantineTransactionId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in id.0 {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 15) as usize] as char);
    }
    output
}

fn validate_directory(path: &Path, owner_uid: u32) -> Result<(), CandidateStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| CandidateStoreError::Unavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(CandidateStoreError::Invalid);
    }
    Ok(())
}

fn validate_file(file: &File, owner_uid: u32) -> Result<(), CandidateStoreError> {
    let metadata = file.metadata().map_err(|_| CandidateStoreError::Unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(CandidateStoreError::Invalid);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), CandidateStoreError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| CandidateStoreError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn context(id: u8, repository: &str) -> AuthorityCandidateContext {
        AuthorityCandidateContext {
            id: QuarantineTransactionId([id; 16]),
            repository: RepositoryIdentity::parse(repository).unwrap(),
            current_generation: RepositoryGeneration(7),
            next_generation: RepositoryGeneration(8),
            trust_generation: TrustGeneration(3),
            revocation_generation: RevocationGeneration(4),
            policy_digest: [1; 64],
            ref_update_digest: [2; 64],
            introduced_commit_set_digest: [3; 64],
            arrival_pack_digest: [4; 64],
            proof_set_digest: [5; 64],
            activation_digest: [6; 64],
        }
    }

    fn store(name: &str) -> (PathBuf, LinuxAuthorityCandidateStore) {
        let root = std::env::temp_dir().join(format!(
            "mrml-authority-candidate-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let owner = fs::metadata(&root).unwrap().uid();
        let store = LinuxAuthorityCandidateStore::open(root.to_str().unwrap(), owner).unwrap();
        (root, store)
    }

    #[test]
    fn exact_candidate_survives_reopen_and_advances_in_order() {
        let (root, store) = store("advance");
        let context = context(11, "owner/repository");
        assert_eq!(store.begin(context.clone()).unwrap().status, AuthorityCandidateStatus::Receiving);
        assert_eq!(store.begin(context.clone()).unwrap().status, AuthorityCandidateStatus::Receiving);
        let statuses = [
            AuthorityCandidateStatus::ProofsSealed,
            AuthorityCandidateStatus::Authorized,
            AuthorityCandidateStatus::ActivationStarted,
            AuthorityCandidateStatus::Activated,
            AuthorityCandidateStatus::ReceiptPersisted,
            AuthorityCandidateStatus::Completed,
        ];
        let mut expected = AuthorityCandidateStatus::Receiving;
        for status in statuses {
            assert_eq!(store.transition(&context, expected, status).unwrap().status, status);
            expected = status;
        }
        let owner = fs::metadata(&root).unwrap().uid();
        let reopened = LinuxAuthorityCandidateStore::open(root.to_str().unwrap(), owner).unwrap();
        assert_eq!(reopened.query(context.id).unwrap().status, AuthorityCandidateStatus::Completed);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn conflicting_identity_context_and_state_transitions_fail_closed() {
        let (root, store) = store("conflict");
        let original = context(12, "owner/first");
        store.begin(original.clone()).unwrap();
        let conflicting = context(12, "owner/second");
        assert_eq!(store.begin(conflicting.clone()), Err(CandidateStoreError::AlreadyExists));
        assert_eq!(
            store.transition(
                &conflicting,
                AuthorityCandidateStatus::Receiving,
                AuthorityCandidateStatus::ProofsSealed,
            ),
            Err(CandidateStoreError::Stale)
        );
        assert_eq!(
            store.transition(
                &original,
                AuthorityCandidateStatus::Receiving,
                AuthorityCandidateStatus::Authorized,
            ),
            Err(CandidateStoreError::Stale)
        );
        assert_eq!(
            store.transition(
                &original,
                AuthorityCandidateStatus::Receiving,
                AuthorityCandidateStatus::Aborted,
            )
            .unwrap()
            .status,
            AuthorityCandidateStatus::Aborted
        );
        assert_eq!(
            store.transition(
                &original,
                AuthorityCandidateStatus::Aborted,
                AuthorityCandidateStatus::Completed,
            ),
            Err(CandidateStoreError::Stale)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn corruption_and_rollback_inputs_are_rejected() {
        let (root, store) = store("corruption");
        let mut invalid = context(13, "owner/repository");
        invalid.next_generation = RepositoryGeneration(9);
        assert_eq!(store.begin(invalid), Err(CandidateStoreError::Invalid));
        let valid = context(14, "owner/repository");
        store.begin(valid.clone()).unwrap();
        let path = store.path(valid.id);
        let mut bytes = fs::read(&path).unwrap();
        bytes[40] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert_eq!(store.query(valid.id), Err(CandidateStoreError::Invalid));
        let _ = fs::remove_dir_all(root);
    }
}
