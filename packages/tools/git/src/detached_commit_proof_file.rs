//! Crash-durable immutable storage for untrusted detached commit proofs.

use crate::git_file_root::GitFileRoot;
use mrml_crypto::{ML_DSA_65_SIGNATURE_BYTES, Sha256};
use mrml_openpgp::MAX_OPENPGP_SIGNATURE_BYTES;
use mrml_runtime::{
    File, Text, Vector, canonical_path, create_dir_all, join_path, path_exists, path_is_directory,
};

use crate::{
    DetachedCommitProofRecord, HistoryVerificationError, ObjectFormat, ObjectId,
    ProtectedHistoryContext, SignaturePurpose,
};

const MAGIC: &[u8; 8] = b"MRDPROF1";
const DIGEST_BYTES: usize = 32;
const FIXED_BYTES: usize = 8 + 1 + 1 + 8 + 8 + 8 + 2 + 32 + 4 + 4 + DIGEST_BYTES;
const MAX_PROOF_FILE_BYTES: usize = FIXED_BYTES
    + crate::gitd_core::MAX_REPOSITORY_IDENTITY_BYTES
    + MAX_OPENPGP_SIGNATURE_BYTES
    + ML_DSA_65_SIGNATURE_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetachedCommitProofFileError {
    Resource,
    Io,
    AlreadyExists,
    Integrity,
    Context,
    Durability,
}

/// An immutable directory of proof records. File names are only lookup
/// accelerators; every lookup rechecks the complete stored context and record.
pub struct DurableDetachedCommitProofDirectory {
    root: Text,
    retained: GitFileRoot,
}

impl DurableDetachedCommitProofDirectory {
    pub fn open(path: &str) -> Result<Self, DetachedCommitProofFileError> {
        create_dir_all(path).map_err(|_| DetachedCommitProofFileError::Io)?;
        let root = canonical_path(path).map_err(|_| DetachedCommitProofFileError::Io)?;
        if !path_is_directory(&root) {
            return Err(DetachedCommitProofFileError::Io);
        }
        Ok(Self {
            root,
            retained: GitFileRoot::Ambient,
        })
    }

    #[cfg(target_os = "linux")]
    pub fn open_capability(
        root: mrml_runtime::DirectoryCapability,
    ) -> Result<Self, DetachedCommitProofFileError> {
        let metadata = root
            .metadata()
            .map_err(|_| DetachedCommitProofFileError::Io)?;
        if metadata.mode & 0o777 != 0o700 {
            return Err(DetachedCommitProofFileError::Io);
        }
        Ok(Self {
            root: Text::new(),
            retained: GitFileRoot::Retained(root),
        })
    }

    pub fn insert(
        &self,
        context: ProtectedHistoryContext<'_>,
        record: &DetachedCommitProofRecord,
    ) -> Result<(), DetachedCommitProofFileError> {
        validate_context(context, record.commit())?;
        let bytes = encode_record(context, record)?;
        let name = self.name(context, record.commit())?;
        if self.exists(&name)? {
            return self.exact_existing(context, record, &name);
        }
        let mut file = match self.create_file(&name) {
            Ok(file) => file,
            Err(_) if self.exists(&name)? => return self.exact_existing(context, record, &name),
            Err(_) => return Err(DetachedCommitProofFileError::Io),
        };
        file.write_all(&bytes)
            .map_err(|_| DetachedCommitProofFileError::Io)?;
        file.sync()
            .map_err(|_| DetachedCommitProofFileError::Durability)?;
        drop(file);
        self.sync()?;
        match self.lookup(context, record.commit())? {
            Some(reopened) if reopened == *record => Ok(()),
            _ => Err(DetachedCommitProofFileError::Integrity),
        }
    }

    fn exact_existing(
        &self,
        context: ProtectedHistoryContext<'_>,
        record: &DetachedCommitProofRecord,
        name: &str,
    ) -> Result<(), DetachedCommitProofFileError> {
        let file = self.open_file(name)?;
        file.sync()
            .map_err(|_| DetachedCommitProofFileError::Durability)?;
        drop(file);
        self.sync()?;
        match self.lookup(context, record.commit())? {
            Some(existing) if existing == *record => Ok(()),
            Some(_) => Err(DetachedCommitProofFileError::AlreadyExists),
            None => Err(DetachedCommitProofFileError::Integrity),
        }
    }

    pub fn lookup(
        &self,
        context: ProtectedHistoryContext<'_>,
        commit: ObjectId,
    ) -> Result<Option<DetachedCommitProofRecord>, DetachedCommitProofFileError> {
        validate_context(context, commit)?;
        let name = self.name(context, commit)?;
        if !self.exists(&name)? {
            return Ok(None);
        }
        let mut file = self.open_file(&name)?;
        let length = usize::try_from(
            file.len()
                .map_err(|_| DetachedCommitProofFileError::Integrity)?,
        )
        .map_err(|_| DetachedCommitProofFileError::Resource)?;
        if length > MAX_PROOF_FILE_BYTES {
            return Err(DetachedCommitProofFileError::Resource);
        }
        let mut bytes = Vector::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| DetachedCommitProofFileError::Resource)?;
        bytes.resize(length, 0);
        file.read_exact(&mut bytes)
            .map_err(|_| DetachedCommitProofFileError::Integrity)?;
        parse_record(context, commit, &bytes).map(Some)
    }

    fn name(
        &self,
        context: ProtectedHistoryContext<'_>,
        commit: ObjectId,
    ) -> Result<Text, DetachedCommitProofFileError> {
        let key = encode_key(context, commit)?;
        let digest = Sha256::digest(&key);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = Text::new();
        for byte in digest {
            name.push(HEX[(byte >> 4) as usize] as char);
            name.push(HEX[(byte & 15) as usize] as char);
        }
        name.push_str(".commit-proof");
        Ok(name)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn path(
        &self,
        context: ProtectedHistoryContext<'_>,
        commit: ObjectId,
    ) -> Result<Text, DetachedCommitProofFileError> {
        Ok(join_path(&self.root, &self.name(context, commit)?))
    }

    fn exists(&self, name: &str) -> Result<bool, DetachedCommitProofFileError> {
        #[cfg(target_os = "linux")]
        if let Some(root) = self.retained.as_ref() {
            if root.open_regular(name).is_ok() {
                return Ok(true);
            }
            if root
                .read_directory()
                .map_err(|_| DetachedCommitProofFileError::Io)?
                .iter()
                .any(|entry| entry.name.as_str() == name)
            {
                return Err(DetachedCommitProofFileError::Integrity);
            }
            return Ok(false);
        }
        Ok(path_exists(&join_path(&self.root, name)))
    }

    fn create_file(&self, name: &str) -> Result<File, DetachedCommitProofFileError> {
        match &self.retained {
            #[cfg(target_os = "linux")]
            GitFileRoot::Retained(root) => root
                .create_new_file(name, 0o600)
                .map_err(|_| DetachedCommitProofFileError::Io),
            GitFileRoot::Ambient => File::create_new(&join_path(&self.root, name))
                .map_err(|_| DetachedCommitProofFileError::Io),
        }
    }

    fn open_file(&self, name: &str) -> Result<File, DetachedCommitProofFileError> {
        let file = match &self.retained {
            #[cfg(target_os = "linux")]
            GitFileRoot::Retained(root) => root.open_regular(name),
            GitFileRoot::Ambient => File::open_regular(&join_path(&self.root, name)),
        }
        .map_err(|_| DetachedCommitProofFileError::Integrity)?;
        #[cfg(target_os = "linux")]
        if self.retained.as_ref().is_some() {
            let metadata = file
                .metadata()
                .map_err(|_| DetachedCommitProofFileError::Integrity)?;
            if metadata.mode & 0o777 != 0o600 || metadata.links != 1 {
                return Err(DetachedCommitProofFileError::Integrity);
            }
        }
        Ok(file)
    }

    fn sync(&self) -> Result<(), DetachedCommitProofFileError> {
        match &self.retained {
            #[cfg(target_os = "linux")]
            GitFileRoot::Retained(root) => root
                .sync()
                .map_err(|_| DetachedCommitProofFileError::Durability),
            GitFileRoot::Ambient => sync_proof_directory(&self.root),
        }
    }
}

fn validate_context(
    context: ProtectedHistoryContext<'_>,
    commit: ObjectId,
) -> Result<(), DetachedCommitProofFileError> {
    if context.repository_generation.0 == 0
        || context.trust_generation.0 == 0
        || context.revocation_generation.0 == 0
        || context.purpose != SignaturePurpose::GitCommit
        || context.object_format != commit.format()
        || commit.is_zero()
    {
        return Err(DetachedCommitProofFileError::Context);
    }
    Ok(())
}

fn encode_key(
    context: ProtectedHistoryContext<'_>,
    commit: ObjectId,
) -> Result<Vector<u8>, DetachedCommitProofFileError> {
    validate_context(context, commit)?;
    let repository = context.repository.as_str().as_bytes();
    let mut out = Vector::new();
    out.try_reserve_exact(1 + 1 + 8 * 3 + 2 + repository.len() + commit.as_bytes().len())
        .map_err(|_| DetachedCommitProofFileError::Resource)?;
    out.push(format_byte(context.object_format));
    out.push(purpose_byte(context.purpose));
    out.extend(context.repository_generation.0.to_be_bytes());
    out.extend(context.trust_generation.0.to_be_bytes());
    out.extend(context.revocation_generation.0.to_be_bytes());
    out.extend(
        u16::try_from(repository.len())
            .map_err(|_| DetachedCommitProofFileError::Resource)?
            .to_be_bytes(),
    );
    out.extend(repository.iter().copied());
    out.extend(commit.as_bytes().iter().copied());
    Ok(out)
}

fn encode_record(
    context: ProtectedHistoryContext<'_>,
    record: &DetachedCommitProofRecord,
) -> Result<Vector<u8>, DetachedCommitProofFileError> {
    let key = encode_key(context, record.commit())?;
    let openpgp = record.openpgp_signature();
    let ml_dsa = record.ml_dsa_signature();
    let capacity = MAGIC
        .len()
        .checked_add(key.len())
        .and_then(|value| value.checked_add(4 + openpgp.len()))
        .and_then(|value| value.checked_add(4 + ml_dsa.len()))
        .and_then(|value| value.checked_add(DIGEST_BYTES))
        .ok_or(DetachedCommitProofFileError::Resource)?;
    if capacity > MAX_PROOF_FILE_BYTES {
        return Err(DetachedCommitProofFileError::Resource);
    }
    let mut out = Vector::new();
    out.try_reserve_exact(capacity)
        .map_err(|_| DetachedCommitProofFileError::Resource)?;
    out.extend(MAGIC.iter().copied());
    out.extend(key);
    out.extend(
        u32::try_from(openpgp.len())
            .map_err(|_| DetachedCommitProofFileError::Resource)?
            .to_be_bytes(),
    );
    out.extend(openpgp.iter().copied());
    out.extend(
        u32::try_from(ml_dsa.len())
            .map_err(|_| DetachedCommitProofFileError::Resource)?
            .to_be_bytes(),
    );
    out.extend(ml_dsa.iter().copied());
    out.extend(Sha256::digest(&out));
    Ok(out)
}

fn parse_record(
    expected: ProtectedHistoryContext<'_>,
    commit: ObjectId,
    input: &[u8],
) -> Result<DetachedCommitProofRecord, DetachedCommitProofFileError> {
    if input.len() < FIXED_BYTES || input.len() > MAX_PROOF_FILE_BYTES || &input[..8] != MAGIC {
        return Err(DetachedCommitProofFileError::Integrity);
    }
    let body_end = input.len() - DIGEST_BYTES;
    if Sha256::digest(&input[..body_end]).as_slice() != &input[body_end..] {
        return Err(DetachedCommitProofFileError::Integrity);
    }
    let expected_key = encode_key(expected, commit)?;
    let key_end = MAGIC
        .len()
        .checked_add(expected_key.len())
        .ok_or(DetachedCommitProofFileError::Resource)?;
    if input.get(MAGIC.len()..key_end) != Some(&expected_key[..]) {
        return Err(DetachedCommitProofFileError::Context);
    }
    let mut cursor = key_end;
    let openpgp_len = take_u32(input, &mut cursor)? as usize;
    if openpgp_len == 0 || openpgp_len > MAX_OPENPGP_SIGNATURE_BYTES {
        return Err(DetachedCommitProofFileError::Integrity);
    }
    let openpgp_end = cursor
        .checked_add(openpgp_len)
        .ok_or(DetachedCommitProofFileError::Resource)?;
    let openpgp = input
        .get(cursor..openpgp_end)
        .ok_or(DetachedCommitProofFileError::Integrity)?;
    cursor = openpgp_end;
    let ml_dsa_len = take_u32(input, &mut cursor)? as usize;
    if ml_dsa_len != ML_DSA_65_SIGNATURE_BYTES {
        return Err(DetachedCommitProofFileError::Integrity);
    }
    let ml_dsa_end = cursor
        .checked_add(ml_dsa_len)
        .ok_or(DetachedCommitProofFileError::Resource)?;
    if ml_dsa_end != body_end {
        return Err(DetachedCommitProofFileError::Integrity);
    }
    let ml_dsa = input
        .get(cursor..ml_dsa_end)
        .ok_or(DetachedCommitProofFileError::Integrity)?;
    DetachedCommitProofRecord::new(commit, openpgp, ml_dsa).map_err(map_record_error)
}

fn take_u32(input: &[u8], cursor: &mut usize) -> Result<u32, DetachedCommitProofFileError> {
    let end = cursor
        .checked_add(4)
        .ok_or(DetachedCommitProofFileError::Resource)?;
    let bytes: [u8; 4] = input
        .get(*cursor..end)
        .ok_or(DetachedCommitProofFileError::Integrity)?
        .try_into()
        .map_err(|_| DetachedCommitProofFileError::Integrity)?;
    *cursor = end;
    Ok(u32::from_be_bytes(bytes))
}

fn map_record_error(error: HistoryVerificationError) -> DetachedCommitProofFileError {
    match error {
        HistoryVerificationError::Resource => DetachedCommitProofFileError::Resource,
        _ => DetachedCommitProofFileError::Integrity,
    }
}

const fn format_byte(format: ObjectFormat) -> u8 {
    match format {
        ObjectFormat::Sha1 => 1,
        ObjectFormat::Sha256 => 2,
    }
}

const fn purpose_byte(purpose: SignaturePurpose) -> u8 {
    match purpose {
        SignaturePurpose::GitCommit => 1,
        SignaturePurpose::GitAnnotatedTag => 2,
        SignaturePurpose::SourceManifest => 3,
        SignaturePurpose::SourceLock => 4,
        SignaturePurpose::BuildReceipt => 5,
        SignaturePurpose::KeyRotation => 6,
        SignaturePurpose::KeyRevocation => 7,
        SignaturePurpose::EmergencyRecovery => 8,
    }
}

#[cfg(unix)]
fn sync_proof_directory(path: &str) -> Result<(), DetachedCommitProofFileError> {
    mrml_runtime::sync_directory(path).map_err(|_| DetachedCommitProofFileError::Durability)
}

#[cfg(not(unix))]
fn sync_proof_directory(_: &str) -> Result<(), DetachedCommitProofFileError> {
    Err(DetachedCommitProofFileError::Durability)
}

#[cfg(all(test, unix))]
mod tests {
    extern crate std;

    use super::*;
    use crate::{RepositoryGeneration, RevocationGeneration, TrustGeneration};

    fn temporary_root(label: &str) -> Text {
        join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-proof-store-{label}-{}", mrml_runtime::process_id()),
        )
    }

    fn repository() -> crate::RepositoryIdentity {
        crate::RepositoryIdentity::parse("owner/protected").unwrap()
    }

    fn context(
        repository: &crate::RepositoryIdentity,
        generation: u64,
    ) -> ProtectedHistoryContext<'_> {
        ProtectedHistoryContext {
            repository,
            repository_generation: RepositoryGeneration(generation),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(8),
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha256,
        }
    }

    fn record(byte: u8) -> DetachedCommitProofRecord {
        DetachedCommitProofRecord::new(
            ObjectId::Sha256([byte; 32]),
            &[byte; 17],
            &[byte; ML_DSA_65_SIGNATURE_BYTES],
        )
        .unwrap()
    }

    #[test]
    fn persists_reopens_and_exact_matches_context() {
        let root = temporary_root("persist");
        let _ = mrml_runtime::remove_dir_all(&root);
        let repository = repository();
        let exact = context(&repository, 3);
        let proof = record(1);
        DurableDetachedCommitProofDirectory::open(&root)
            .unwrap()
            .insert(exact, &proof)
            .unwrap();
        let reopened = DurableDetachedCommitProofDirectory::open(&root).unwrap();
        assert_eq!(
            reopened.lookup(exact, proof.commit()).unwrap(),
            Some(proof.clone())
        );
        assert_eq!(
            reopened
                .lookup(context(&repository, 4), proof.commit())
                .unwrap(),
            None
        );
        let wrong = context(&repository, 4);
        let exact_path = reopened.path(exact, proof.commit()).unwrap();
        let wrong_path = reopened.path(wrong, proof.commit()).unwrap();
        let bytes = mrml_runtime::read_file_bounded(&exact_path, MAX_PROOF_FILE_BYTES).unwrap();
        mrml_runtime::write_file(&wrong_path, &bytes).unwrap();
        assert_eq!(
            reopened.lookup(wrong, proof.commit()),
            Err(DetachedCommitProofFileError::Context)
        );
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn exact_duplicate_is_idempotent_and_conflict_does_not_replace() {
        let root = temporary_root("duplicate");
        let _ = mrml_runtime::remove_dir_all(&root);
        let repository = repository();
        let exact = context(&repository, 3);
        let proof = record(2);
        let directory = DurableDetachedCommitProofDirectory::open(&root).unwrap();
        directory.insert(exact, &proof).unwrap();
        directory.insert(exact, &proof).unwrap();
        let conflicting = DetachedCommitProofRecord::new(
            proof.commit(),
            &[9; 17],
            &[9; ML_DSA_65_SIGNATURE_BYTES],
        )
        .unwrap();
        assert_eq!(
            directory.insert(exact, &conflicting),
            Err(DetachedCommitProofFileError::AlreadyExists)
        );
        assert_eq!(
            directory.lookup(exact, proof.commit()).unwrap(),
            Some(proof)
        );
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn tamper_and_torn_record_fail_closed() {
        let root = temporary_root("integrity");
        let _ = mrml_runtime::remove_dir_all(&root);
        let repository = repository();
        let exact = context(&repository, 3);
        let proof = record(3);
        let directory = DurableDetachedCommitProofDirectory::open(&root).unwrap();
        directory.insert(exact, &proof).unwrap();
        let path = directory.path(exact, proof.commit()).unwrap();
        let mut bytes = mrml_runtime::read_file_bounded(&path, MAX_PROOF_FILE_BYTES).unwrap();
        let tampered = bytes.len() - DIGEST_BYTES - 1;
        bytes[tampered] ^= 1;
        mrml_runtime::write_file(&path, &bytes).unwrap();
        assert_eq!(
            directory.lookup(exact, proof.commit()),
            Err(DetachedCommitProofFileError::Integrity)
        );
        bytes.truncate(bytes.len() / 2);
        mrml_runtime::write_file(&path, &bytes).unwrap();
        assert_eq!(
            directory.lookup(exact, proof.commit()),
            Err(DetachedCommitProofFileError::Integrity)
        );
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn invalid_and_wrong_format_contexts_fail_closed() {
        let root = temporary_root("context");
        let _ = mrml_runtime::remove_dir_all(&root);
        let repository = repository();
        let mut wrong = context(&repository, 3);
        wrong.object_format = ObjectFormat::Sha1;
        let proof = record(4);
        let directory = DurableDetachedCommitProofDirectory::open(&root).unwrap();
        assert_eq!(
            directory.insert(wrong, &proof),
            Err(DetachedCommitProofFileError::Context)
        );
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn retained_proof_root_survives_ambient_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let root = temporary_root("retained");
        let displaced = mrml_runtime::mrml_format!("{root}-displaced");
        let _ = mrml_runtime::remove_dir_all(&root);
        let _ = mrml_runtime::remove_dir_all(&displaced);
        mrml_runtime::create_dir_all(&root).unwrap();
        std::fs::set_permissions(root.as_str(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let capability = mrml_runtime::DirectoryCapability::open_root(&root).unwrap();
        let directory = DurableDetachedCommitProofDirectory::open_capability(capability).unwrap();
        mrml_runtime::rename_file(&root, &displaced).unwrap();
        mrml_runtime::create_dir_all(&root).unwrap();

        let repository = repository();
        let exact = context(&repository, 3);
        let proof = record(5);
        directory.insert(exact, &proof).unwrap();
        assert_eq!(
            directory.lookup(exact, proof.commit()).unwrap(),
            Some(proof.clone())
        );
        let name = directory.name(exact, proof.commit()).unwrap();
        assert!(mrml_runtime::path_exists(&join_path(&displaced, &name)));
        assert!(!mrml_runtime::path_exists(&join_path(&root, &name)));
        mrml_runtime::remove_dir_all(&root).unwrap();
        mrml_runtime::remove_dir_all(&displaced).unwrap();
    }
}
