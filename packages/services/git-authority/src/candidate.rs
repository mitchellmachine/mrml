use mrml_crypto::{ML_DSA_65_SIGNATURE_BYTES, Sha256};
use mrml_git::{
    AuthorityCandidateContext, AuthorityCandidateRecord, AuthorityCandidateStatus,
    DetachedCommitProofRecord, DurableDetachedCommitProofDirectory, ObjectFormat, ObjectId,
    ProtectedHistoryContext, QuarantineTransactionId, RepositoryGeneration, RepositoryIdentity,
    RevocationGeneration, SignaturePurpose, TrustGeneration, candidate_proof_set_digest,
};
use mrml_openpgp::MAX_OPENPGP_SIGNATURE_BYTES;
use mrml_runtime::{DirectoryCapability, File};
#[cfg(test)]
use std::fs;
use std::path::PathBuf;

const MAGIC: &[u8; 8] = b"MRACAN01";
const DOMAIN: &[u8] = b"MRML git authority candidate journal v1\0";
const MAX_REPOSITORY_BYTES: usize = 255;
const FIXED_BYTES: usize = 8 + 16 + 2 + 8 * 4 + 64 * 6 + 1 + 32;
const PROOF_SET_MAGIC: &[u8; 8] = b"MRACPF01";
const MAX_PROOFS: usize = mrml_git::MAX_DETACHED_COMMIT_PROOFS;
const MAX_PROOF_SET_BYTES: usize = 8
    + 4
    + MAX_PROOFS * (32 + 4 + MAX_OPENPGP_SIGNATURE_BYTES + 4 + ML_DSA_65_SIGNATURE_BYTES)
    + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateStoreError {
    AlreadyExists,
    Invalid,
    Missing,
    Stale,
    Unavailable,
}

pub struct LinuxAuthorityCandidateStore {
    root: DirectoryCapability,
    root_path: PathBuf,
    owner_uid: u32,
    repository: Option<RepositoryIdentity>,
    prefix: String,
}

impl LinuxAuthorityCandidateStore {
    pub fn open(root: &str, owner_uid: u32) -> Result<Self, CandidateStoreError> {
        if owner_uid == 0 {
            return Err(CandidateStoreError::Invalid);
        }
        let root_path =
            std::fs::canonicalize(root).map_err(|_| CandidateStoreError::Unavailable)?;
        let root =
            DirectoryCapability::open_root(root_path.to_str().ok_or(CandidateStoreError::Invalid)?)
                .map_err(|_| CandidateStoreError::Unavailable)?;
        Self::from_capability(root, root_path, owner_uid)
    }

    pub fn open_capability(
        root: DirectoryCapability,
        owner_uid: u32,
    ) -> Result<Self, CandidateStoreError> {
        Self::from_capability(root, PathBuf::new(), owner_uid)
    }

    /// Bind production storage to one repository. Legacy records remain in
    /// place; a checked record selects one namespace for the entire operation.
    pub fn open_repository_capability(
        root: DirectoryCapability,
        owner_uid: u32,
        repository: RepositoryIdentity,
    ) -> Result<Self, CandidateStoreError> {
        let mut store = Self::from_capability(root, PathBuf::new(), owner_uid)?;
        store.repository = Some(repository);
        Ok(store)
    }

    fn from_capability(
        root: DirectoryCapability,
        root_path: PathBuf,
        owner_uid: u32,
    ) -> Result<Self, CandidateStoreError> {
        if owner_uid == 0 {
            return Err(CandidateStoreError::Invalid);
        }
        validate_directory(&root, owner_uid)?;
        Ok(Self {
            root,
            root_path,
            owner_uid,
            repository: None,
            prefix: String::new(),
        })
    }

    fn check_repository(&self, repository: &RepositoryIdentity) -> Result<(), CandidateStoreError> {
        if self
            .repository
            .as_ref()
            .is_some_and(|bound| bound != repository)
        {
            return Err(CandidateStoreError::Invalid);
        }
        Ok(())
    }

    fn select_candidate(&self, id: QuarantineTransactionId) -> Result<Self, CandidateStoreError> {
        let repository = self
            .repository
            .as_ref()
            .ok_or(CandidateStoreError::Invalid)?;
        if id.0 == [0; 16] {
            return Err(CandidateStoreError::Invalid);
        }
        let mut selected = Self::from_capability(
            self.root
                .try_clone()
                .map_err(|_| CandidateStoreError::Unavailable)?,
            self.root_path.clone(),
            self.owner_uid,
        )?;
        // The existing full repository digest supplies a stable bounded name;
        // only the decoded exact repository binding authorizes record use.
        selected.prefix = format!(
            "{}-",
            mrml_git::authority_generation_record_name(repository)
        );
        let current = selected.read_record(id)?;
        if current
            .as_ref()
            .is_some_and(|record| &record.context.repository != repository)
        {
            return Err(CandidateStoreError::Invalid);
        }
        let legacy = self.read_record(id)?;
        if legacy
            .as_ref()
            .is_some_and(|record| &record.context.repository == repository)
        {
            if current.is_some() {
                return Err(CandidateStoreError::Invalid);
            }
            selected.prefix.clear();
        }
        // Never mix legacy proof or temporary files with namespaced journals.
        // Selection is performed once before the internal operation below.
        Ok(selected)
    }

    pub fn begin(
        &self,
        context: AuthorityCandidateContext,
    ) -> Result<AuthorityCandidateRecord, CandidateStoreError> {
        self.check_repository(&context.repository)?;
        if self.repository.is_some() {
            return self.select_candidate(context.id)?.begin(context);
        }
        validate_context(&context)?;
        let record = AuthorityCandidateRecord {
            context,
            status: AuthorityCandidateStatus::Receiving,
        };
        let name = self.name(record.context.id);
        if self.open_optional_file(&name)?.is_some() {
            return match self.query(record.context.id) {
                Ok(existing) if existing == record => Ok(existing),
                Ok(_) => Err(CandidateStoreError::AlreadyExists),
                Err(error) => Err(error),
            };
        }
        self.write_new(&name, &record)?;
        self.sync()?;
        self.query(record.context.id)
    }

    pub fn query(
        &self,
        id: QuarantineTransactionId,
    ) -> Result<AuthorityCandidateRecord, CandidateStoreError> {
        if self.repository.is_some() {
            let record = self.select_candidate(id)?.query(id)?;
            self.check_repository(&record.context.repository)?;
            return Ok(record);
        }
        self.read_record(id)?.ok_or(CandidateStoreError::Missing)
    }

    fn read_record(
        &self,
        id: QuarantineTransactionId,
    ) -> Result<Option<AuthorityCandidateRecord>, CandidateStoreError> {
        if id.0 == [0; 16] {
            return Err(CandidateStoreError::Invalid);
        }
        let Some(mut file) = self.open_optional_file(&self.name(id))? else {
            return Ok(None);
        };
        let length = usize::try_from(file.len().map_err(|_| CandidateStoreError::Unavailable)?)
            .map_err(|_| CandidateStoreError::Invalid)?;
        if length < FIXED_BYTES || length > FIXED_BYTES + MAX_REPOSITORY_BYTES {
            return Err(CandidateStoreError::Invalid);
        }
        let mut encoded = vec![0; length];
        file.read_exact(&mut encoded)
            .map_err(|_| CandidateStoreError::Unavailable)?;
        decode(&encoded, id).map(Some)
    }

    pub fn transition(
        &self,
        context: &AuthorityCandidateContext,
        expected: AuthorityCandidateStatus,
        next: AuthorityCandidateStatus,
    ) -> Result<AuthorityCandidateRecord, CandidateStoreError> {
        self.check_repository(&context.repository)?;
        if self.repository.is_some() {
            return self
                .select_candidate(context.id)?
                .transition(context, expected, next);
        }
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
        let temporary = self.temporary_name(context.id);
        if self.open_optional_file(&temporary)?.is_some() {
            return Err(CandidateStoreError::Unavailable);
        }
        self.write_new(&temporary, &replacement)?;
        self.root
            .rename_child(&temporary, &self.name(context.id))
            .map_err(|_| CandidateStoreError::Unavailable)?;
        self.sync()?;
        let reread = self.query(context.id)?;
        (reread == replacement)
            .then_some(reread)
            .ok_or(CandidateStoreError::Unavailable)
    }

    pub fn install_proof(
        &self,
        context: &AuthorityCandidateContext,
        proof_context: ProtectedHistoryContext<'_>,
        proof: &DetachedCommitProofRecord,
    ) -> Result<(), CandidateStoreError> {
        self.check_repository(&context.repository)?;
        if self.repository.is_some() {
            return self
                .select_candidate(context.id)?
                .install_proof(context, proof_context, proof);
        }
        let record = self.query(context.id)?;
        if record.context != *context || record.status != AuthorityCandidateStatus::Receiving {
            return Err(CandidateStoreError::Stale);
        }
        if proof_context.repository != &context.repository
            || proof_context.repository_generation != context.current_generation
            || proof_context.trust_generation != context.trust_generation
            || proof_context.revocation_generation != context.revocation_generation
            || proof_context.purpose != SignaturePurpose::GitCommit
            || proof_context.object_format != ObjectFormat::Sha256
        {
            return Err(CandidateStoreError::Invalid);
        }
        let proof_directory = self.proof_directory(context.id, true)?;
        let mut proofs = self.load_proof_set(context.id)?;
        match proofs.binary_search_by_key(&proof.commit(), DetachedCommitProofRecord::commit) {
            Ok(index) if proofs[index] == *proof => {
                let directory = DurableDetachedCommitProofDirectory::open_capability(
                    proof_directory
                        .try_clone()
                        .map_err(|_| CandidateStoreError::Unavailable)?,
                )
                .map_err(|_| CandidateStoreError::Unavailable)?;
                return match directory.lookup(proof_context, proof.commit()) {
                    Ok(Some(existing)) if existing == *proof => Ok(()),
                    _ => Err(CandidateStoreError::Invalid),
                };
            }
            Ok(_) => return Err(CandidateStoreError::AlreadyExists),
            Err(index) if index != proofs.len() => return Err(CandidateStoreError::Invalid),
            Err(_) => {}
        }
        if proofs.len() >= MAX_PROOFS {
            return Err(CandidateStoreError::Invalid);
        }
        let directory = DurableDetachedCommitProofDirectory::open_capability(proof_directory)
            .map_err(|_| CandidateStoreError::Unavailable)?;
        directory
            .insert(proof_context, proof)
            .map_err(|error| match error {
                mrml_git::DetachedCommitProofFileError::AlreadyExists => {
                    CandidateStoreError::AlreadyExists
                }
                _ => CandidateStoreError::Unavailable,
            })?;
        proofs.push(proof.clone());
        self.replace_proof_set(context.id, &proofs)
    }

    pub fn seal_proofs(
        &self,
        context: &AuthorityCandidateContext,
    ) -> Result<(), CandidateStoreError> {
        self.check_repository(&context.repository)?;
        if self.repository.is_some() {
            return self.select_candidate(context.id)?.seal_proofs(context);
        }
        let record = self.query(context.id)?;
        if record.context != *context || record.status != AuthorityCandidateStatus::Receiving {
            return Err(CandidateStoreError::Stale);
        }
        let proofs = self.load_proof_set(context.id)?;
        if candidate_proof_set_digest(&proofs).map_err(|_| CandidateStoreError::Invalid)?
            != context.proof_set_digest
        {
            return Err(CandidateStoreError::Invalid);
        }
        let proof_directory = self.proof_directory(context.id, false)?;
        let entries = proof_directory
            .read_directory()
            .map_err(|_| CandidateStoreError::Unavailable)?;
        if entries.len() != proofs.len()
            || entries.iter().any(|entry| {
                entry.is_directory || entry.is_symlink || !entry.name.ends_with(".commit-proof")
            })
        {
            return Err(CandidateStoreError::Invalid);
        }
        let directory = DurableDetachedCommitProofDirectory::open_capability(proof_directory)
            .map_err(|_| CandidateStoreError::Unavailable)?;
        let proof_context = ProtectedHistoryContext {
            repository: &context.repository,
            repository_generation: context.current_generation,
            trust_generation: context.trust_generation,
            revocation_generation: context.revocation_generation,
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha256,
        };
        for proof in &proofs {
            match directory.lookup(proof_context, proof.commit()) {
                Ok(Some(existing)) if existing == *proof => {}
                _ => return Err(CandidateStoreError::Invalid),
            }
        }
        Ok(())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn proof_set_path(&self, id: QuarantineTransactionId) -> PathBuf {
        self.root_path.join(self.proof_set_name(id))
    }

    fn proof_directory_name(&self, id: QuarantineTransactionId) -> String {
        format!("{}{}.proofs", self.prefix, id_hex(id))
    }

    fn proof_set_name(&self, id: QuarantineTransactionId) -> String {
        format!("{}{}.proof-set", self.prefix, id_hex(id))
    }

    fn proof_set_temporary_name(&self, id: QuarantineTransactionId) -> String {
        format!("{}{}.proof-set.next", self.prefix, id_hex(id))
    }

    fn proof_directory(
        &self,
        id: QuarantineTransactionId,
        create: bool,
    ) -> Result<DirectoryCapability, CandidateStoreError> {
        let name = self.proof_directory_name(id);
        let directory = match self.root.open_directory(&name) {
            Ok(directory) => directory,
            Err(_) if create => self
                .root
                .create_directory(&name, 0o700)
                .map_err(|_| CandidateStoreError::Unavailable)?,
            Err(_) => return Err(CandidateStoreError::Missing),
        };
        validate_directory(&directory, self.owner_uid)?;
        if create {
            self.sync()?;
        }
        Ok(directory)
    }

    fn load_proof_set(
        &self,
        id: QuarantineTransactionId,
    ) -> Result<Vec<DetachedCommitProofRecord>, CandidateStoreError> {
        let name = self.proof_set_name(id);
        let mut file = match self.open_optional_file(&name)? {
            Some(file) => file,
            None => return Ok(Vec::new()),
        };
        let length = usize::try_from(file.len().map_err(|_| CandidateStoreError::Unavailable)?)
            .map_err(|_| CandidateStoreError::Invalid)?;
        if length < PROOF_SET_MAGIC.len() + 4 + 32 || length > MAX_PROOF_SET_BYTES {
            return Err(CandidateStoreError::Invalid);
        }
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes)
            .map_err(|_| CandidateStoreError::Unavailable)?;
        decode_proof_set(&bytes)
    }

    fn replace_proof_set(
        &self,
        id: QuarantineTransactionId,
        proofs: &[DetachedCommitProofRecord],
    ) -> Result<(), CandidateStoreError> {
        let encoded = encode_proof_set(proofs)?;
        let temporary = self.proof_set_temporary_name(id);
        if self.open_optional_file(&temporary)?.is_some() {
            return Err(CandidateStoreError::Unavailable);
        }
        let mut file = self
            .root
            .create_new_file(&temporary, 0o600)
            .map_err(|_| CandidateStoreError::Unavailable)?;
        file.write_all(&encoded)
            .and_then(|_| file.sync())
            .map_err(|_| CandidateStoreError::Unavailable)?;
        validate_file(&file, self.owner_uid)?;
        drop(file);
        self.root
            .rename_child(&temporary, &self.proof_set_name(id))
            .map_err(|_| CandidateStoreError::Unavailable)?;
        self.sync()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn path(&self, id: QuarantineTransactionId) -> PathBuf {
        self.root_path.join(self.name(id))
    }

    fn name(&self, id: QuarantineTransactionId) -> String {
        format!("{}{}.candidate", self.prefix, id_hex(id))
    }

    fn temporary_name(&self, id: QuarantineTransactionId) -> String {
        format!("{}{}.candidate.next", self.prefix, id_hex(id))
    }

    fn write_new(
        &self,
        name: &str,
        record: &AuthorityCandidateRecord,
    ) -> Result<(), CandidateStoreError> {
        let encoded = encode(record)?;
        let mut file = self
            .root
            .create_new_file(name, 0o600)
            .map_err(|_| CandidateStoreError::Unavailable)?;
        file.write_all(&encoded)
            .and_then(|_| file.sync())
            .map_err(|_| CandidateStoreError::Unavailable)?;
        validate_file(&file, self.owner_uid)
    }

    fn sync(&self) -> Result<(), CandidateStoreError> {
        self.root
            .sync()
            .map_err(|_| CandidateStoreError::Unavailable)
    }

    fn open_optional_file(&self, name: &str) -> Result<Option<File>, CandidateStoreError> {
        if let Ok(file) = self.root.open_regular(name) {
            validate_file(&file, self.owner_uid)?;
            return Ok(Some(file));
        }
        if self
            .root
            .read_directory()
            .map_err(|_| CandidateStoreError::Unavailable)?
            .iter()
            .any(|entry| entry.name.as_str() == name)
        {
            return Err(CandidateStoreError::Invalid);
        }
        Ok(None)
    }
}

fn encode_proof_set(proofs: &[DetachedCommitProofRecord]) -> Result<Vec<u8>, CandidateStoreError> {
    if proofs.len() > MAX_PROOFS
        || !proofs
            .windows(2)
            .all(|pair| pair[0].commit() < pair[1].commit())
    {
        return Err(CandidateStoreError::Invalid);
    }
    let mut output = Vec::new();
    output.extend_from_slice(PROOF_SET_MAGIC);
    output.extend_from_slice(&(proofs.len() as u32).to_be_bytes());
    for proof in proofs {
        if proof.commit().format() != ObjectFormat::Sha256 {
            return Err(CandidateStoreError::Invalid);
        }
        output.extend_from_slice(proof.commit().as_bytes());
        output.extend_from_slice(&(proof.openpgp_signature().len() as u32).to_be_bytes());
        output.extend_from_slice(proof.openpgp_signature());
        output.extend_from_slice(&(proof.ml_dsa_signature().len() as u32).to_be_bytes());
        output.extend_from_slice(proof.ml_dsa_signature());
    }
    if output
        .len()
        .checked_add(32)
        .is_none_or(|length| length > MAX_PROOF_SET_BYTES)
    {
        return Err(CandidateStoreError::Invalid);
    }
    output.extend_from_slice(&Sha256::digest(&output));
    Ok(output)
}

fn decode_proof_set(input: &[u8]) -> Result<Vec<DetachedCommitProofRecord>, CandidateStoreError> {
    if input.len() < PROOF_SET_MAGIC.len() + 4 + 32 || input.len() > MAX_PROOF_SET_BYTES {
        return Err(CandidateStoreError::Invalid);
    }
    let checksum_at = input.len() - 32;
    if Sha256::digest(&input[..checksum_at]) != input[checksum_at..] {
        return Err(CandidateStoreError::Invalid);
    }
    let mut cursor = PROOF_SET_MAGIC.len();
    if &input[..cursor] != PROOF_SET_MAGIC {
        return Err(CandidateStoreError::Invalid);
    }
    let count = u32::from_be_bytes(
        take(input, &mut cursor, 4)?
            .try_into()
            .map_err(|_| CandidateStoreError::Invalid)?,
    ) as usize;
    if count > MAX_PROOFS {
        return Err(CandidateStoreError::Invalid);
    }
    let mut proofs = Vec::with_capacity(count);
    for _ in 0..count {
        let commit = ObjectId::from_bytes(ObjectFormat::Sha256, take(input, &mut cursor, 32)?)
            .ok_or(CandidateStoreError::Invalid)?;
        let openpgp_len = u32::from_be_bytes(
            take(input, &mut cursor, 4)?
                .try_into()
                .map_err(|_| CandidateStoreError::Invalid)?,
        ) as usize;
        if openpgp_len == 0 || openpgp_len > MAX_OPENPGP_SIGNATURE_BYTES {
            return Err(CandidateStoreError::Invalid);
        }
        let openpgp = take(input, &mut cursor, openpgp_len)?;
        let ml_dsa_len = u32::from_be_bytes(
            take(input, &mut cursor, 4)?
                .try_into()
                .map_err(|_| CandidateStoreError::Invalid)?,
        ) as usize;
        if ml_dsa_len != ML_DSA_65_SIGNATURE_BYTES {
            return Err(CandidateStoreError::Invalid);
        }
        let ml_dsa = take(input, &mut cursor, ml_dsa_len)?;
        let proof = DetachedCommitProofRecord::new(commit, openpgp, ml_dsa)
            .map_err(|_| CandidateStoreError::Invalid)?;
        if proofs
            .last()
            .is_some_and(|previous: &DetachedCommitProofRecord| previous.commit() >= commit)
        {
            return Err(CandidateStoreError::Invalid);
        }
        proofs.push(proof);
    }
    if cursor != checksum_at {
        return Err(CandidateStoreError::Invalid);
    }
    Ok(proofs)
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
    let checksum_at = input
        .len()
        .checked_sub(32)
        .ok_or(CandidateStoreError::Invalid)?;
    if Sha256::digest(&[DOMAIN, &input[..checksum_at]].concat()).as_slice() != &input[checksum_at..]
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
    let end = cursor
        .checked_add(length)
        .ok_or(CandidateStoreError::Invalid)?;
    let bytes = input
        .get(*cursor..end)
        .ok_or(CandidateStoreError::Invalid)?;
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

fn validate_directory(
    directory: &DirectoryCapability,
    owner_uid: u32,
) -> Result<(), CandidateStoreError> {
    let metadata = directory
        .metadata()
        .map_err(|_| CandidateStoreError::Unavailable)?;
    if metadata.uid != owner_uid || metadata.mode & 0o022 != 0 {
        return Err(CandidateStoreError::Invalid);
    }
    Ok(())
}

fn validate_file(file: &File, owner_uid: u32) -> Result<(), CandidateStoreError> {
    let metadata = file
        .metadata()
        .map_err(|_| CandidateStoreError::Unavailable)?;
    if metadata.links != 1 || metadata.uid != owner_uid || metadata.mode & 0o777 != 0o600 {
        return Err(CandidateStoreError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

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
        assert_eq!(
            store.begin(context.clone()).unwrap().status,
            AuthorityCandidateStatus::Receiving
        );
        assert_eq!(
            store.begin(context.clone()).unwrap().status,
            AuthorityCandidateStatus::Receiving
        );
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
            assert_eq!(
                store.transition(&context, expected, status).unwrap().status,
                status
            );
            expected = status;
        }
        let owner = fs::metadata(&root).unwrap().uid();
        let reopened = LinuxAuthorityCandidateStore::open(root.to_str().unwrap(), owner).unwrap();
        assert_eq!(
            reopened.query(context.id).unwrap().status,
            AuthorityCandidateStatus::Completed
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn retained_candidate_root_survives_ambient_replacement() {
        let (root, store) = store("retained");
        let displaced = root.with_extension("displaced");
        let _ = fs::remove_dir_all(&displaced);
        fs::rename(&root, &displaced).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        let commit = ObjectId::from_bytes(ObjectFormat::Sha256, &[7; 32]).unwrap();
        let proof =
            DetachedCommitProofRecord::new(commit, &[8; 64], &[9; ML_DSA_65_SIGNATURE_BYTES])
                .unwrap();
        let mut context = context(15, "owner/retained");
        context.proof_set_digest =
            candidate_proof_set_digest(core::slice::from_ref(&proof)).unwrap();
        store.begin(context.clone()).unwrap();
        let proof_context = ProtectedHistoryContext {
            repository: &context.repository,
            repository_generation: context.current_generation,
            trust_generation: context.trust_generation,
            revocation_generation: context.revocation_generation,
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha256,
        };
        store
            .install_proof(&context, proof_context, &proof)
            .unwrap();
        store.seal_proofs(&context).unwrap();
        store
            .transition(
                &context,
                AuthorityCandidateStatus::Receiving,
                AuthorityCandidateStatus::ProofsSealed,
            )
            .unwrap();
        assert_eq!(
            store.query(context.id).unwrap().status,
            AuthorityCandidateStatus::ProofsSealed
        );
        assert!(displaced.join(store.name(context.id)).is_file());
        assert!(displaced.join(store.proof_set_name(context.id)).is_file());
        assert!(
            displaced
                .join(store.proof_directory_name(context.id))
                .is_dir()
        );
        assert!(!root.join(store.name(context.id)).exists());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(displaced).unwrap();
    }

    #[test]
    fn conflicting_identity_context_and_state_transitions_fail_closed() {
        let (root, store) = store("conflict");
        let original = context(12, "owner/first");
        store.begin(original.clone()).unwrap();
        let conflicting = context(12, "owner/second");
        assert_eq!(
            store.begin(conflicting.clone()),
            Err(CandidateStoreError::AlreadyExists)
        );
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
            store
                .transition(
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
    fn candidate_proof_set_is_durable_exact_and_sealed() {
        let (root, store) = store("proofs");
        let commit = ObjectId::from_bytes(ObjectFormat::Sha256, &[9; 32]).unwrap();
        let proof =
            DetachedCommitProofRecord::new(commit, &[3; 64], &[4; ML_DSA_65_SIGNATURE_BYTES])
                .unwrap();
        let mut candidate = context(14, "owner/repository");
        candidate.proof_set_digest =
            candidate_proof_set_digest(core::slice::from_ref(&proof)).unwrap();
        store.begin(candidate.clone()).unwrap();
        let proof_context = ProtectedHistoryContext {
            repository: &candidate.repository,
            repository_generation: candidate.current_generation,
            trust_generation: candidate.trust_generation,
            revocation_generation: candidate.revocation_generation,
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha256,
        };
        store
            .install_proof(&candidate, proof_context, &proof)
            .unwrap();
        store
            .install_proof(&candidate, proof_context, &proof)
            .unwrap();
        let owner = fs::metadata(&root).unwrap().uid();
        let reopened = LinuxAuthorityCandidateStore::open(root.to_str().unwrap(), owner).unwrap();
        reopened.seal_proofs(&candidate).unwrap();
        let manifest = reopened.proof_set_path(candidate.id);
        let mut bytes = fs::read(&manifest).unwrap();
        bytes[12] ^= 1;
        fs::write(&manifest, bytes).unwrap();
        assert_eq!(
            reopened.seal_proofs(&candidate),
            Err(CandidateStoreError::Invalid)
        );
        let _ = fs::remove_dir_all(root);
    }

    fn scoped_store(root: &std::path::Path, repository: &str) -> LinuxAuthorityCandidateStore {
        LinuxAuthorityCandidateStore::open_repository_capability(
            DirectoryCapability::open_root(root.to_str().unwrap()).unwrap(),
            fs::metadata(root).unwrap().uid(),
            RepositoryIdentity::parse(repository).unwrap(),
        )
        .unwrap()
    }

    fn proof_candidate(
        repository: &str,
        signature: u8,
    ) -> (AuthorityCandidateContext, DetachedCommitProofRecord) {
        let proof = DetachedCommitProofRecord::new(
            ObjectId::from_bytes(ObjectFormat::Sha256, &[21; 32]).unwrap(),
            &[signature; 64],
            &[signature; ML_DSA_65_SIGNATURE_BYTES],
        )
        .unwrap();
        let mut candidate = context(22, repository);
        candidate.proof_set_digest =
            candidate_proof_set_digest(core::slice::from_ref(&proof)).unwrap();
        (candidate, proof)
    }

    fn install_candidate_proof(
        store: &LinuxAuthorityCandidateStore,
        candidate: &AuthorityCandidateContext,
        proof: &DetachedCommitProofRecord,
    ) {
        store
            .install_proof(
                candidate,
                ProtectedHistoryContext {
                    repository: &candidate.repository,
                    repository_generation: candidate.current_generation,
                    trust_generation: candidate.trust_generation,
                    revocation_generation: candidate.revocation_generation,
                    purpose: SignaturePurpose::GitCommit,
                    object_format: ObjectFormat::Sha256,
                },
                proof,
            )
            .unwrap();
    }

    #[test]
    fn scoped_same_id_candidates_recover_independent_proofs_and_lifecycles() {
        let (root, legacy) = store("scoped-independent");
        drop(legacy);
        let a = scoped_store(&root, "owner/alpha");
        let b = scoped_store(&root, "owner/beta");
        let (ca, pa) = proof_candidate("owner/alpha", 31);
        let (cb, pb) = proof_candidate("owner/beta", 32);
        a.begin(ca.clone()).unwrap();
        b.begin(cb.clone()).unwrap();
        install_candidate_proof(&a, &ca, &pa);
        install_candidate_proof(&b, &cb, &pb);
        a.seal_proofs(&ca).unwrap();
        b.seal_proofs(&cb).unwrap();
        assert_eq!(a.begin(cb.clone()), Err(CandidateStoreError::Invalid));
        assert_eq!(a.seal_proofs(&cb), Err(CandidateStoreError::Invalid));
        assert_eq!(
            a.install_proof(
                &cb,
                ProtectedHistoryContext {
                    repository: &cb.repository,
                    repository_generation: cb.current_generation,
                    trust_generation: cb.trust_generation,
                    revocation_generation: cb.revocation_generation,
                    purpose: SignaturePurpose::GitCommit,
                    object_format: ObjectFormat::Sha256,
                },
                &pb,
            ),
            Err(CandidateStoreError::Invalid)
        );
        assert_eq!(
            a.transition(
                &cb,
                AuthorityCandidateStatus::Receiving,
                AuthorityCandidateStatus::Aborted
            ),
            Err(CandidateStoreError::Invalid)
        );
        a.transition(
            &ca,
            AuthorityCandidateStatus::Receiving,
            AuthorityCandidateStatus::ProofsSealed,
        )
        .unwrap();
        drop(a);
        drop(b);
        let a = scoped_store(&root, "owner/alpha");
        let b = scoped_store(&root, "owner/beta");
        assert_eq!(
            a.query(ca.id).unwrap().status,
            AuthorityCandidateStatus::ProofsSealed
        );
        assert_eq!(
            b.query(cb.id).unwrap().status,
            AuthorityCandidateStatus::Receiving
        );
        b.seal_proofs(&cb).unwrap();
        b.transition(
            &cb,
            AuthorityCandidateStatus::Receiving,
            AuthorityCandidateStatus::Aborted,
        )
        .unwrap();
        let statuses = [
            AuthorityCandidateStatus::Authorized,
            AuthorityCandidateStatus::ActivationStarted,
            AuthorityCandidateStatus::Activated,
            AuthorityCandidateStatus::ReceiptPersisted,
            AuthorityCandidateStatus::Completed,
        ];
        let mut previous = AuthorityCandidateStatus::ProofsSealed;
        for next in statuses {
            a.transition(&ca, previous, next).unwrap();
            previous = next;
        }
        assert_eq!(
            a.query(ca.id).unwrap().status,
            AuthorityCandidateStatus::Completed
        );
        assert_eq!(
            b.query(cb.id).unwrap().status,
            AuthorityCandidateStatus::Aborted
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scoped_recovery_preserves_legacy_artifacts_with_same_id_sibling() {
        let (root, legacy) = store("scoped-legacy");
        let (ca, pa) = proof_candidate("owner/alpha", 41);
        let (cb, pb) = proof_candidate("owner/beta", 42);
        legacy.begin(ca.clone()).unwrap();
        install_candidate_proof(&legacy, &ca, &pa);
        let original_proofs = fs::read(legacy.proof_set_path(ca.id)).unwrap();
        let a = scoped_store(&root, "owner/alpha");
        let b = scoped_store(&root, "owner/beta");
        assert_eq!(b.query(ca.id), Err(CandidateStoreError::Missing));
        b.begin(cb.clone()).unwrap();
        install_candidate_proof(&b, &cb, &pb);
        a.seal_proofs(&ca).unwrap();
        b.seal_proofs(&cb).unwrap();
        a.transition(
            &ca,
            AuthorityCandidateStatus::Receiving,
            AuthorityCandidateStatus::ProofsSealed,
        )
        .unwrap();
        assert_eq!(
            legacy.query(ca.id).unwrap().status,
            AuthorityCandidateStatus::ProofsSealed
        );
        assert_eq!(
            fs::read(legacy.proof_set_path(ca.id)).unwrap(),
            original_proofs
        );
        assert!(root.join(legacy.proof_directory_name(ca.id)).is_dir());
        drop(a);
        drop(b);
        let a = scoped_store(&root, "owner/alpha");
        let b = scoped_store(&root, "owner/beta");
        a.transition(
            &ca,
            AuthorityCandidateStatus::ProofsSealed,
            AuthorityCandidateStatus::Authorized,
        )
        .unwrap();
        b.seal_proofs(&cb).unwrap();
        assert_eq!(
            legacy.query(ca.id).unwrap().status,
            AuthorityCandidateStatus::Authorized
        );
        assert_eq!(b.query(cb.id).unwrap().context, cb);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scoped_recovery_rejects_ambiguous_and_substituted_journals() {
        let (root, legacy) = store("scoped-ambiguous");
        let a = scoped_store(&root, "owner/alpha");
        let (ca, _) = proof_candidate("owner/alpha", 51);
        let (cb, _) = proof_candidate("owner/beta", 52);
        a.begin(ca.clone()).unwrap();
        let selected_name = a.select_candidate(ca.id).unwrap().name(ca.id);
        legacy.begin(ca.clone()).unwrap();
        assert_eq!(a.query(ca.id), Err(CandidateStoreError::Invalid));
        assert_eq!(
            a.transition(
                &ca,
                AuthorityCandidateStatus::Receiving,
                AuthorityCandidateStatus::Aborted
            ),
            Err(CandidateStoreError::Invalid)
        );
        fs::remove_file(legacy.path(ca.id)).unwrap();
        fs::write(
            root.join(&selected_name),
            encode(&AuthorityCandidateRecord {
                context: cb,
                status: AuthorityCandidateStatus::Receiving,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(a.query(ca.id), Err(CandidateStoreError::Invalid));
        assert_eq!(a.begin(ca), Err(CandidateStoreError::Invalid));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scoped_journal_corruption_and_symlinks_fail_closed() {
        let (root, legacy) = store("scoped-hostile-journal");
        let a = scoped_store(&root, "owner/alpha");
        let (ca, _) = proof_candidate("owner/alpha", 61);
        a.begin(ca.clone()).unwrap();
        let journal = root.join(a.select_candidate(ca.id).unwrap().name(ca.id));
        let good = fs::read(&journal).unwrap();
        fs::write(&journal, b"malformed").unwrap();
        assert_eq!(a.query(ca.id), Err(CandidateStoreError::Invalid));
        fs::write(&journal, &good).unwrap();
        fs::write(legacy.path(ca.id), b"malformed legacy").unwrap();
        fs::set_permissions(legacy.path(ca.id), fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(a.query(ca.id), Err(CandidateStoreError::Invalid));
        fs::remove_file(legacy.path(ca.id)).unwrap();
        std::os::unix::fs::symlink(&journal, legacy.path(ca.id)).unwrap();
        assert_eq!(a.query(ca.id), Err(CandidateStoreError::Invalid));
        fs::remove_file(legacy.path(ca.id)).unwrap();
        let displaced = root.join("displaced-journal");
        fs::rename(&journal, &displaced).unwrap();
        std::os::unix::fs::symlink(&displaced, &journal).unwrap();
        assert_eq!(a.query(ca.id), Err(CandidateStoreError::Invalid));
        assert_eq!(fs::read(displaced).unwrap(), good);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scoped_incomplete_transition_and_corrupt_proofs_do_not_poison_sibling() {
        let (root, legacy) = store("scoped-failure-isolation");
        drop(legacy);
        let a = scoped_store(&root, "owner/alpha");
        let b = scoped_store(&root, "owner/beta");
        let (ca, pa) = proof_candidate("owner/alpha", 71);
        let (cb, pb) = proof_candidate("owner/beta", 72);
        a.begin(ca.clone()).unwrap();
        b.begin(cb.clone()).unwrap();
        install_candidate_proof(&a, &ca, &pa);
        install_candidate_proof(&b, &cb, &pb);
        let selected = a.select_candidate(ca.id).unwrap();
        selected
            .write_new(
                &selected.temporary_name(ca.id),
                &AuthorityCandidateRecord {
                    context: ca.clone(),
                    status: AuthorityCandidateStatus::ProofsSealed,
                },
            )
            .unwrap();
        assert_eq!(
            a.transition(
                &ca,
                AuthorityCandidateStatus::Receiving,
                AuthorityCandidateStatus::ProofsSealed
            ),
            Err(CandidateStoreError::Unavailable)
        );
        fs::write(
            root.join(selected.proof_set_name(ca.id)),
            b"corrupt proof set",
        )
        .unwrap();
        assert_eq!(a.seal_proofs(&ca), Err(CandidateStoreError::Invalid));
        drop(b);
        let b = scoped_store(&root, "owner/beta");
        b.seal_proofs(&cb).unwrap();
        b.transition(
            &cb,
            AuthorityCandidateStatus::Receiving,
            AuthorityCandidateStatus::ProofsSealed,
        )
        .unwrap();
        assert_eq!(
            a.query(ca.id).unwrap().status,
            AuthorityCandidateStatus::Receiving
        );
        assert_eq!(
            b.query(cb.id).unwrap().status,
            AuthorityCandidateStatus::ProofsSealed
        );
        fs::remove_dir_all(root).unwrap();
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
