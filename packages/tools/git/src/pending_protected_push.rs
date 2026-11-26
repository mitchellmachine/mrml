//! Durable client-side identity for a protected push whose outcome may be uncertain.

use mrml_crypto::Sha256;
use mrml_runtime::{File, Text, Vector, join_path, path_exists, remove_file, sync_directory};

use crate::{
    GitdCoreError, ObjectId, QuarantineTransactionId, RepositoryGeneration, RepositoryIdentity,
    RevocationGeneration, TrustGeneration,
};

const MAGIC: &[u8; 8] = b"MRGPPJ01";
const FILE_NAME: &str = "mrml-pending-protected-push-v1";
const MAX_RECORD_BYTES: usize = 4096;
const MAX_TEXT_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PendingProtectedPush {
    pub repository: RepositoryIdentity,
    pub reference: Text,
    pub candidate: QuarantineTransactionId,
    pub old: ObjectId,
    pub new: ObjectId,
    pub repository_generation: RepositoryGeneration,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
}

impl PendingProtectedPush {
    pub fn create(git_dir: &str, record: &Self) -> Result<(), GitdCoreError> {
        let encoded = encode(record)?;
        let path = path(git_dir);
        if path_exists(&path) {
            return Err(GitdCoreError::Authorization);
        }
        let mut file = File::create_new(&path).map_err(|_| GitdCoreError::Authorization)?;
        file.write_all(&encoded)
            .map_err(|_| GitdCoreError::Authorization)?;
        file.sync().map_err(|_| GitdCoreError::Authorization)?;
        drop(file);
        sync_directory(git_dir).map_err(|_| GitdCoreError::Authorization)
    }

    pub fn load(git_dir: &str) -> Result<Option<Self>, GitdCoreError> {
        let path = path(git_dir);
        if !path_exists(&path) {
            return Ok(None);
        }
        let mut file = File::open_regular(&path).map_err(|_| GitdCoreError::Authorization)?;
        let length = usize::try_from(file.len().map_err(|_| GitdCoreError::Authorization)?)
            .map_err(|_| GitdCoreError::Resource)?;
        if length == 0 || length > MAX_RECORD_BYTES {
            return Err(GitdCoreError::Authorization);
        }
        let mut encoded = Vector::new();
        encoded
            .try_reserve_exact(length)
            .map_err(|_| GitdCoreError::Resource)?;
        encoded.resize(length, 0);
        file.read_exact(&mut encoded)
            .map_err(|_| GitdCoreError::Authorization)?;
        decode(&encoded).map(Some)
    }

    pub fn remove(git_dir: &str) -> Result<(), GitdCoreError> {
        let path = path(git_dir);
        if !path_exists(&path) {
            return Ok(());
        }
        remove_file(&path).map_err(|_| GitdCoreError::Authorization)?;
        sync_directory(git_dir).map_err(|_| GitdCoreError::Authorization)
    }
}

fn path(git_dir: &str) -> Text {
    join_path(git_dir, FILE_NAME)
}

fn encode(record: &PendingProtectedPush) -> Result<Vector<u8>, GitdCoreError> {
    if record.candidate.0 == [0; 16]
        || record.old == record.new
        || record.repository_generation.0 == 0
        || record.trust_generation.0 == 0
        || record.revocation_generation.0 == 0
        || !record.reference.starts_with("refs/heads/")
    {
        return Err(GitdCoreError::Authorization);
    }
    let mut output = Vector::new();
    append(&mut output, MAGIC)?;
    append_text(&mut output, record.repository.as_str())?;
    append_text(&mut output, &record.reference)?;
    append(&mut output, &record.candidate.0)?;
    append(&mut output, record.old.as_bytes())?;
    append(&mut output, record.new.as_bytes())?;
    append(&mut output, &record.repository_generation.0.to_be_bytes())?;
    append(&mut output, &record.trust_generation.0.to_be_bytes())?;
    append(&mut output, &record.revocation_generation.0.to_be_bytes())?;
    let checksum = Sha256::digest(&output);
    append(&mut output, &checksum)?;
    if output.len() > MAX_RECORD_BYTES {
        return Err(GitdCoreError::Resource);
    }
    Ok(output)
}

fn decode(input: &[u8]) -> Result<PendingProtectedPush, GitdCoreError> {
    if input.len() < 32 || input.len() > MAX_RECORD_BYTES {
        return Err(GitdCoreError::Authorization);
    }
    let body_length = input.len() - 32;
    if Sha256::digest(&input[..body_length]) != input[body_length..] {
        return Err(GitdCoreError::Authorization);
    }
    let mut cursor = Cursor {
        input: &input[..body_length],
        offset: 0,
    };
    if cursor.take(8)? != MAGIC {
        return Err(GitdCoreError::Authorization);
    }
    let repository = RepositoryIdentity::parse(cursor.text()?)?;
    let reference: Text = cursor.text()?.into();
    let mut candidate = [0; 16];
    candidate.copy_from_slice(cursor.take(16)?);
    let mut old = [0; 32];
    old.copy_from_slice(cursor.take(32)?);
    let mut new = [0; 32];
    new.copy_from_slice(cursor.take(32)?);
    let repository_generation = cursor.u64()?;
    let trust_generation = cursor.u64()?;
    let revocation_generation = cursor.u64()?;
    if cursor.offset != cursor.input.len() {
        return Err(GitdCoreError::Authorization);
    }
    let record = PendingProtectedPush {
        repository,
        reference,
        candidate: QuarantineTransactionId(candidate),
        old: ObjectId::from_bytes(crate::ObjectFormat::Sha256, &old)
            .ok_or(GitdCoreError::Authorization)?,
        new: ObjectId::from_bytes(crate::ObjectFormat::Sha256, &new)
            .ok_or(GitdCoreError::Authorization)?,
        repository_generation: RepositoryGeneration(repository_generation),
        trust_generation: TrustGeneration(trust_generation),
        revocation_generation: RevocationGeneration(revocation_generation),
    };
    encode(&record)?;
    Ok(record)
}

fn append(output: &mut Vector<u8>, input: &[u8]) -> Result<(), GitdCoreError> {
    output
        .try_extend_from_slice(input)
        .map_err(|_| GitdCoreError::Resource)
}

fn append_text(output: &mut Vector<u8>, input: &str) -> Result<(), GitdCoreError> {
    if input.is_empty() || input.len() > MAX_TEXT_BYTES {
        return Err(GitdCoreError::Resource);
    }
    append(output, &(input.len() as u16).to_be_bytes())?;
    append(output, input.as_bytes())
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], GitdCoreError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(GitdCoreError::Resource)?;
        let output = self
            .input
            .get(self.offset..end)
            .ok_or(GitdCoreError::Authorization)?;
        self.offset = end;
        Ok(output)
    }
    fn text(&mut self) -> Result<&'a str, GitdCoreError> {
        let length = u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| GitdCoreError::Authorization)?,
        ) as usize;
        if length == 0 || length > MAX_TEXT_BYTES {
            return Err(GitdCoreError::Resource);
        }
        core::str::from_utf8(self.take(length)?).map_err(|_| GitdCoreError::Authorization)
    }
    fn u64(&mut self) -> Result<u64, GitdCoreError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| GitdCoreError::Authorization)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> PendingProtectedPush {
        PendingProtectedPush {
            repository: RepositoryIdentity::parse("owner/repo").unwrap(),
            reference: "refs/heads/main".into(),
            candidate: QuarantineTransactionId([7; 16]),
            old: ObjectId::from_bytes(crate::ObjectFormat::Sha256, &[8; 32]).unwrap(),
            new: ObjectId::from_bytes(crate::ObjectFormat::Sha256, &[9; 32]).unwrap(),
            repository_generation: RepositoryGeneration(3),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(5),
        }
    }

    #[test]
    fn record_round_trips_and_tamper_truncation_fail_closed() {
        let expected = record();
        let encoded = encode(&expected).unwrap();
        assert_eq!(decode(&encoded).unwrap(), expected);
        for end in 0..encoded.len() {
            assert!(decode(&encoded[..end]).is_err());
        }
        let mut tampered = encoded;
        tampered[20] ^= 1;
        assert!(decode(&tampered).is_err());
    }

    #[test]
    fn durable_record_blocks_overwrite_reopens_and_removes() {
        let root = mrml_runtime::join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!(
                "mrml-pending-protected-push-{}",
                mrml_runtime::process_id()
            ),
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        mrml_runtime::create_dir_all(&root).unwrap();
        let expected = record();
        PendingProtectedPush::create(&root, &expected).unwrap();
        let mut replacement = expected.clone();
        replacement.candidate = QuarantineTransactionId([99; 16]);
        assert!(PendingProtectedPush::create(&root, &replacement).is_err());
        assert_eq!(PendingProtectedPush::load(&root).unwrap(), Some(expected));
        PendingProtectedPush::remove(&root).unwrap();
        assert_eq!(PendingProtectedPush::load(&root).unwrap(), None);
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
