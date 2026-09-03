//! Transport-neutral boundary between an untrusted Git/web edge and gitd.
//!
//! Names identify objects but never carry authority. Implementations of
//! [`GitdCoreBackend`] must independently authorize each operation and bind
//! reads and mutations to the exact generations supplied by the caller.

use core::fmt;
use mrml_crypto::Sha3_512;
use mrml_runtime::{Text, Vector};

use crate::verification::{ProtectedHistoryContext, VerifiedCommitRange};
use crate::{ObjectFormat, ObjectId};

pub const MAX_REPOSITORY_IDENTITY_BYTES: usize = 257;
pub const MAX_REF_NAME_BYTES: usize = 1_024;
pub const MAX_REPOSITORY_PATH_BYTES: usize = 4_096;
pub const MAX_REFS_PER_TRANSACTION: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepositoryGeneration(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TrustGeneration(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RevocationGeneration(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackGeneration(pub u64);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RepositoryIdentity(Text);

impl RepositoryIdentity {
    pub fn parse(value: &str) -> Result<Self, GitdCoreError> {
        if value.is_empty()
            || value.len() > MAX_REPOSITORY_IDENTITY_BYTES
            || value.bytes().any(|byte| !byte.is_ascii())
        {
            return Err(GitdCoreError::MalformedIdentifier);
        }
        let mut pieces = value.split('/');
        let owner = pieces.next().ok_or(GitdCoreError::MalformedIdentifier)?;
        let repository = pieces.next().ok_or(GitdCoreError::MalformedIdentifier)?;
        if pieces.next().is_some()
            || !valid_identity_part(owner)
            || !valid_identity_part(repository)
        {
            return Err(GitdCoreError::MalformedIdentifier);
        }
        Ok(Self(value.into()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

fn valid_identity_part(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FullRefName(Text);

impl FullRefName {
    pub fn parse(value: &str) -> Result<Self, GitdCoreError> {
        if value.len() > MAX_REF_NAME_BYTES
            || !value.starts_with("refs/")
            || value.ends_with('/')
            || value.ends_with('.')
            || value.ends_with(".lock")
            || value.contains("..")
            || value.contains("@{")
            || value.contains("//")
            || value
                .split('/')
                .any(|part| part.is_empty() || part.starts_with('.'))
            || value.bytes().any(|byte| {
                !byte.is_ascii()
                    || byte <= b' '
                    || byte == 0x7f
                    || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
            })
        {
            return Err(GitdCoreError::MalformedRef);
        }
        Ok(Self(value.into()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RepositoryPath(Text);

impl RepositoryPath {
    pub fn parse(value: &str) -> Result<Self, GitdCoreError> {
        if value.len() > MAX_REPOSITORY_PATH_BYTES
            || value.starts_with('/')
            || value.ends_with('/')
            || value.contains('\\')
            || value.bytes().any(|byte| byte == 0 || !byte.is_ascii())
            || (!value.is_empty()
                && value
                    .split('/')
                    .any(|part| part.is_empty() || matches!(part, "." | "..")))
        {
            return Err(GitdCoreError::MalformedPath);
        }
        Ok(Self(value.into()))
    }

    pub fn root() -> Self {
        Self(Text::new())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryLimits {
    pub max_entries: u32,
    pub max_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkBudget {
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_memory_bytes: u64,
    pub max_work_units: u64,
}

pub trait BoundedRead {
    fn remaining(&self) -> u64;
    fn read(&mut self, output: &mut [u8]) -> Result<usize, GitdCoreError>;
}

pub trait BoundedWrite {
    fn remaining(&self) -> u64;
    fn write(&mut self, input: &[u8]) -> Result<(), GitdCoreError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignaturePurpose {
    GitCommit,
    GitAnnotatedTag,
    SourceManifest,
    SourceLock,
    BuildReceipt,
    KeyRotation,
    KeyRevocation,
    EmergencyRecovery,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitPage {
    pub repository_generation: RepositoryGeneration,
    pub commits: Vector<ObjectId>,
    pub next: Option<ObjectId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitDetails {
    pub repository_generation: RepositoryGeneration,
    pub commit: ObjectId,
    pub tree: ObjectId,
    pub parents: Vector<ObjectId>,
    pub author: Text,
    pub message: Text,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnotatedTagDetails {
    pub repository_generation: RepositoryGeneration,
    pub reference: FullRefName,
    pub tag: ObjectId,
    pub target: ObjectId,
    pub target_type: crate::ObjectKind,
    pub tagger: Text,
    pub message: Text,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnotatedTagPage {
    pub repository_generation: RepositoryGeneration,
    pub tags: Vector<AnnotatedTagDetails>,
    pub next_offset: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreePage {
    pub repository_generation: RepositoryGeneration,
    pub tree: ObjectId,
    pub entries: Vector<RepositoryPath>,
    pub next_offset: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPage {
    pub repository_generation: RepositoryGeneration,
    pub blob: ObjectId,
    pub offset: u64,
    pub bytes: Vector<u8>,
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadmeCandidate {
    pub repository_generation: RepositoryGeneration,
    pub tree: ObjectId,
    pub path: RepositoryPath,
    pub blob: ObjectId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedMetadataDescriptor {
    pub repository_generation: RepositoryGeneration,
    pub tree: ObjectId,
    pub path: RepositoryPath,
    pub blob: ObjectId,
    pub size: u64,
    pub purpose: SignaturePurpose,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImmutablePackDescriptor {
    pub repository_generation: RepositoryGeneration,
    pub commit: ObjectId,
    pub object_format: ObjectFormat,
    pub pack_profile_version: u32,
    pub encoder_version: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryEventCursor {
    pub repository_generation: RepositoryGeneration,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    pub pack_generation: PackGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryEvent {
    pub previous: RepositoryEventCursor,
    pub current: RepositoryEventCursor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryEventPage {
    pub events: Vector<RepositoryEvent>,
    pub next: RepositoryEventCursor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositorySummary {
    pub repository_generation: RepositoryGeneration,
    pub default_branch: FullRefName,
    pub object_format: ObjectFormat,
    pub refs: Vector<(FullRefName, ObjectId)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationSummary {
    pub object: ObjectId,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    pub purpose: SignaturePurpose,
    pub openpgp_authorized: bool,
    pub ml_dsa_65_authorized: bool,
    pub exact_pair_authorized: bool,
    pub hybrid_required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmartGitOperation {
    UploadPack,
    ReceivePack,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmartGitRequest {
    pub repository: RepositoryIdentity,
    pub repository_generation: RepositoryGeneration,
    pub operation: SmartGitOperation,
    pub object_format: ObjectFormat,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmartGitResponse {
    pub repository_generation: RepositoryGeneration,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub refs_activated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateRefUpdate {
    pub name: FullRefName,
    pub expected_old: Option<ObjectId>,
    pub proposed_new: Option<ObjectId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateRefTransaction {
    pub repository: RepositoryIdentity,
    pub repository_generation: RepositoryGeneration,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    pub updates: Vector<CandidateRefUpdate>,
}

/// A ref update whose object closure, ancestry, signatures, and exact policy
/// generation have been verified. Fields are deliberately private.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRefUpdate {
    name: FullRefName,
    expected_old: Option<ObjectId>,
    proposed_new: Option<ObjectId>,
}

impl VerifiedRefUpdate {
    pub fn name(&self) -> &FullRefName {
        &self.name
    }

    pub fn expected_old(&self) -> Option<ObjectId> {
        self.expected_old
    }

    pub fn proposed_new(&self) -> Option<ObjectId> {
        self.proposed_new
    }
}

/// An atomic transaction produced only by the gitd verifier. Fields are
/// private so transport code cannot manufacture authorization from object IDs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRefTransaction {
    repository: RepositoryIdentity,
    repository_generation: RepositoryGeneration,
    trust_generation: TrustGeneration,
    revocation_generation: RevocationGeneration,
    introduced_commit_set_digest: [u8; 64],
    introduced_commits: Vector<ObjectId>,
    updates: Vector<VerifiedRefUpdate>,
}

impl VerifiedRefTransaction {
    pub fn repository(&self) -> &RepositoryIdentity {
        &self.repository
    }

    pub fn repository_generation(&self) -> RepositoryGeneration {
        self.repository_generation
    }

    pub fn trust_generation(&self) -> TrustGeneration {
        self.trust_generation
    }

    pub fn revocation_generation(&self) -> RevocationGeneration {
        self.revocation_generation
    }

    pub fn updates(&self) -> &[VerifiedRefUpdate] {
        &self.updates
    }

    pub const fn introduced_commit_set_digest(&self) -> [u8; 64] {
        self.introduced_commit_set_digest
    }

    /// Canonical sorted unique introduced set retained for bounded second-stage
    /// authority work. The digest above authenticates these exact identifiers.
    pub fn introduced_commits(&self) -> &[ObjectId] {
        &self.introduced_commits
    }
}

/// Convert exact verified commit ranges into an atomic fast-forward ref
/// transaction. Creation, deletion, and history replacement require separate
/// policy-specific builders and therefore fail closed here.
pub fn build_verified_fast_forward_transaction(
    candidate: CandidateRefTransaction,
    ranges: &[VerifiedCommitRange],
) -> Result<VerifiedRefTransaction, GitdCoreError> {
    if candidate.repository_generation.0 == 0
        || candidate.trust_generation.0 == 0
        || candidate.revocation_generation.0 == 0
        || candidate.updates.is_empty()
        || candidate.updates.len() > MAX_REFS_PER_TRANSACTION
        || candidate.updates.len() != ranges.len()
    {
        return Err(GitdCoreError::Policy);
    }
    if candidate.updates.iter().enumerate().any(|(index, update)| {
        candidate.updates[..index]
            .iter()
            .any(|previous| previous.name == update.name)
    }) {
        return Err(GitdCoreError::MalformedRef);
    }
    let mut updates = Vector::new();
    let mut introduced = Vector::new();
    let context = ProtectedHistoryContext {
        repository: &candidate.repository,
        repository_generation: candidate.repository_generation,
        trust_generation: candidate.trust_generation,
        revocation_generation: candidate.revocation_generation,
        purpose: SignaturePurpose::GitCommit,
        object_format: candidate
            .updates
            .first()
            .and_then(|update| update.proposed_new)
            .ok_or(GitdCoreError::Unsupported)?
            .format(),
    };
    for (update, range) in candidate.updates.into_iter().zip(ranges.iter()) {
        let old = update.expected_old.ok_or(GitdCoreError::Unsupported)?;
        let new = update.proposed_new.ok_or(GitdCoreError::Unsupported)?;
        if old.is_zero()
            || new.is_zero()
            || old.format() != new.format()
            || range.old() != old
            || range.new() != new
            || !range.matches_context(&context)
        {
            return Err(GitdCoreError::Ancestry);
        }
        introduced
            .try_extend_from_slice(range.introduced())
            .map_err(|_| GitdCoreError::Resource)?;
        updates.push(VerifiedRefUpdate {
            name: update.name,
            expected_old: Some(old),
            proposed_new: Some(new),
        });
    }
    introduced.sort_unstable();
    let mut unique_introduced = Vector::new();
    unique_introduced
        .try_reserve_exact(introduced.len())
        .map_err(|_| GitdCoreError::Resource)?;
    for commit in introduced {
        if unique_introduced.last() != Some(&commit) {
            unique_introduced.push(commit);
        }
    }
    if unique_introduced.is_empty() {
        return Err(GitdCoreError::Ancestry);
    }
    let mut introduced_hash = Sha3_512::new();
    introduced_hash.update(b"MRML git introduced commit set v1\0");
    introduced_hash.update(
        &u32::try_from(unique_introduced.len())
            .map_err(|_| GitdCoreError::Resource)?
            .to_be_bytes(),
    );
    for commit in &unique_introduced {
        introduced_hash.update(&[match commit.format() {
            ObjectFormat::Sha1 => 1,
            ObjectFormat::Sha256 => 2,
        }]);
        introduced_hash.update(commit.as_bytes());
    }
    Ok(VerifiedRefTransaction {
        repository: candidate.repository,
        repository_generation: candidate.repository_generation,
        trust_generation: candidate.trust_generation,
        revocation_generation: candidate.revocation_generation,
        introduced_commit_set_digest: introduced_hash.finalize(),
        introduced_commits: unique_introduced,
        updates,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitdCoreError {
    MalformedInput,
    MalformedIdentifier,
    MalformedRef,
    MalformedPath,
    Authorization,
    ObjectValidation,
    Ancestry,
    Signature,
    Policy,
    Resource,
    Storage,
    StaleGeneration,
    UncertainCommit,
    Unsupported,
}

impl fmt::Display for GitdCoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MalformedInput => "malformed Git protocol input",
            Self::MalformedIdentifier => "malformed repository identity",
            Self::MalformedRef => "malformed full ref name",
            Self::MalformedPath => "malformed repository path",
            Self::Authorization => "operation is not authorized",
            Self::ObjectValidation => "Git object validation failed",
            Self::Ancestry => "required ancestry proof failed",
            Self::Signature => "required signature verification failed",
            Self::Policy => "trust policy rejected the operation",
            Self::Resource => "bounded resource budget exhausted",
            Self::Storage => "repository storage operation failed",
            Self::StaleGeneration => "repository generation is stale",
            Self::UncertainCommit => "durable transaction outcome is uncertain",
            Self::Unsupported => "Git protocol operation is unsupported",
        })
    }
}

impl core::error::Error for GitdCoreError {}

pub trait GitdCoreBackend {
    fn repository_generation(
        &self,
        repository: &RepositoryIdentity,
    ) -> Result<RepositoryGeneration, GitdCoreError>;

    fn authority_generations(
        &self,
        _repository: &RepositoryIdentity,
    ) -> Result<(RepositoryGeneration, TrustGeneration, RevocationGeneration), GitdCoreError> {
        Err(GitdCoreError::Unsupported)
    }

    fn repository_summary(
        &self,
        repository: &RepositoryIdentity,
        limits: QueryLimits,
    ) -> Result<RepositorySummary, GitdCoreError>;

    fn resolve_ref(
        &self,
        repository: &RepositoryIdentity,
        revision: &str,
    ) -> Result<ObjectId, GitdCoreError>;

    fn read_commit_page(
        &self,
        repository: &RepositoryIdentity,
        commit: ObjectId,
        limits: QueryLimits,
    ) -> Result<CommitPage, GitdCoreError>;

    fn read_commit_details(
        &self,
        _repository: &RepositoryIdentity,
        _commit: ObjectId,
        _limits: QueryLimits,
    ) -> Result<CommitDetails, GitdCoreError> {
        Err(GitdCoreError::Unsupported)
    }

    fn read_annotated_tag_page(
        &self,
        _repository: &RepositoryIdentity,
        _offset: u64,
        _limits: QueryLimits,
    ) -> Result<AnnotatedTagPage, GitdCoreError> {
        Err(GitdCoreError::Unsupported)
    }

    fn read_annotated_tag_details(
        &self,
        _repository: &RepositoryIdentity,
        _reference: &FullRefName,
        _limits: QueryLimits,
    ) -> Result<AnnotatedTagDetails, GitdCoreError> {
        Err(GitdCoreError::Unsupported)
    }

    fn read_tree_page(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        limits: QueryLimits,
    ) -> Result<TreePage, GitdCoreError>;

    fn read_tree_page_at(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        offset: u64,
        limits: QueryLimits,
    ) -> Result<TreePage, GitdCoreError> {
        if offset != 0 {
            return Err(GitdCoreError::Unsupported);
        }
        self.read_tree_page(repository, treeish, path, limits)
    }

    fn read_blob_page(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        limits: QueryLimits,
    ) -> Result<BlobPage, GitdCoreError>;

    fn read_blob_page_at(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        offset: u64,
        limits: QueryLimits,
    ) -> Result<BlobPage, GitdCoreError> {
        if offset != 0 {
            return Err(GitdCoreError::Unsupported);
        }
        self.read_blob_page(repository, treeish, path, limits)
    }

    fn resolve_readme_candidate(
        &self,
        _repository: &RepositoryIdentity,
        _treeish: ObjectId,
    ) -> Result<Option<ReadmeCandidate>, GitdCoreError> {
        Err(GitdCoreError::Unsupported)
    }

    fn read_verified_metadata(
        &self,
        _repository: &RepositoryIdentity,
        _treeish: ObjectId,
        _path: &RepositoryPath,
        _purpose: SignaturePurpose,
        _policy: TrustGeneration,
        _revocations: RevocationGeneration,
        _limits: QueryLimits,
    ) -> Result<VerifiedMetadataDescriptor, GitdCoreError> {
        Err(GitdCoreError::Unsupported)
    }

    fn immutable_pack_descriptor(
        &self,
        _repository: &RepositoryIdentity,
        _commit: ObjectId,
    ) -> Result<ImmutablePackDescriptor, GitdCoreError> {
        Err(GitdCoreError::Unsupported)
    }

    fn repository_events_after(
        &self,
        _repository: &RepositoryIdentity,
        _cursor: RepositoryEventCursor,
        _limits: QueryLimits,
    ) -> Result<RepositoryEventPage, GitdCoreError> {
        Err(GitdCoreError::Unsupported)
    }

    fn verification_summary(
        &self,
        repository: &RepositoryIdentity,
        object: ObjectId,
        policy: TrustGeneration,
        revocations: RevocationGeneration,
    ) -> Result<VerificationSummary, GitdCoreError>;

    fn smart_git(
        &mut self,
        request: SmartGitRequest,
        input: &mut dyn BoundedRead,
        output: &mut dyn BoundedWrite,
        budget: WorkBudget,
    ) -> Result<SmartGitResponse, GitdCoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::{HistoryVerificationLimits, verify_introduced_history};

    #[test]
    fn repository_identity_is_exactly_owner_and_name() {
        assert_eq!(
            RepositoryIdentity::parse("mitchellrenouf/mrml")
                .unwrap()
                .as_str(),
            "mitchellrenouf/mrml"
        );
        for invalid in [
            "",
            "owner",
            "/repo",
            "owner/",
            "a/b/c",
            "../repo",
            "owner/.git",
        ] {
            assert_eq!(
                RepositoryIdentity::parse(invalid),
                Err(GitdCoreError::MalformedIdentifier)
            );
        }
    }

    #[test]
    fn full_refs_reject_revision_and_filesystem_escapes() {
        assert_eq!(
            FullRefName::parse("refs/heads/main").unwrap().as_str(),
            "refs/heads/main"
        );
        for invalid in [
            "main",
            "refs/heads/../main",
            "refs//main",
            "refs/heads/main.lock",
            "refs/heads/@{1}",
            "refs/heads/a\\b",
        ] {
            assert_eq!(
                FullRefName::parse(invalid),
                Err(GitdCoreError::MalformedRef)
            );
        }
    }

    #[test]
    fn repository_paths_never_escape_the_object_graph() {
        assert!(RepositoryPath::parse("src/lib.rs").is_ok());
        assert_eq!(RepositoryPath::root().as_str(), "");
        for invalid in ["/etc/passwd", "../secret", "src/../secret", "a//b", "a\\b"] {
            assert_eq!(
                RepositoryPath::parse(invalid),
                Err(GitdCoreError::MalformedPath)
            );
        }
    }

    #[test]
    fn only_exact_verified_ranges_construct_fast_forward_transactions() {
        let old = ObjectId::Sha1([1u8; 20]);
        let new = ObjectId::Sha1([2u8; 20]);
        let range = verify_introduced_history(
            old,
            new,
            HistoryVerificationLimits::default(),
            |id| {
                Ok(if id == new {
                    [old].into()
                } else {
                    Vector::new()
                })
            },
            |_| Ok(()),
        )
        .unwrap();
        let candidate = CandidateRefTransaction {
            repository: RepositoryIdentity::parse("owner/repository").unwrap(),
            repository_generation: RepositoryGeneration(3),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(5),
            updates: [CandidateRefUpdate {
                name: FullRefName::parse("refs/heads/main").unwrap(),
                expected_old: Some(old),
                proposed_new: Some(new),
            }]
            .into(),
        };
        let verified = build_verified_fast_forward_transaction(candidate, &[range]).unwrap();
        assert_eq!(verified.repository_generation(), RepositoryGeneration(3));
        assert_eq!(verified.updates()[0].proposed_new(), Some(new));
        assert_eq!(verified.introduced_commits(), &[new]);
    }
}
