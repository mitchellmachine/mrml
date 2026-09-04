use mrml_crypto::Sha256;
use mrml_runtime::{Shared, Text, Vector};
use mrml_zstd::{HttpEncodingProfile, encode_http};
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use crate::{GitdAuthentication, Header, RepositoryAction, RequestHead};

const MAX_IDENTITY: usize = 257;
const MAX_PATH: usize = 4096;
const MAX_REVISION: usize = 128;
const MAX_MARKDOWN: usize = 2 * 1024 * 1024;
const MAX_RENDERED: usize = 8 * 1024 * 1024;
const MAX_MARKDOWN_LINES: usize = 100_000;
const MAX_HEADING_DEPTH: usize = 6;
const MARKDOWN_PROFILE_VERSION: &str = "markdown-bounded-v3";
const RENDERER_VERSION: &str = "gitd-html-v3";
const TEMPLATE_VERSION: &str = "mrml-template-v2";
const THEME_VERSION: &str = "charcoal-amber-v1";
const SANITIZER_VERSION: &str = "structural-sanitizer-v2";

const HEALTH_STARTING: u8 = 0;
const HEALTH_READY: u8 = 1;
const HEALTH_DRAINING: u8 = 2;
const HEALTH_FAILED: u8 = 3;
const HEALTH_DEGRADED: u8 = 4;

pub struct GitdOperationalHealth {
    state: AtomicU8,
}

impl GitdOperationalHealth {
    pub const fn starting() -> Self {
        Self {
            state: AtomicU8::new(HEALTH_STARTING),
        }
    }

    pub fn mark_ready(&self) {
        let _ = self.state.compare_exchange(
            HEALTH_STARTING,
            HEALTH_READY,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub fn begin_drain(&self) {
        if self.state.load(Ordering::Acquire) != HEALTH_FAILED {
            self.state.store(HEALTH_DRAINING, Ordering::Release);
        }
    }

    pub fn fail(&self) {
        self.state.store(HEALTH_FAILED, Ordering::Release);
    }

    pub fn degrade(&self) {
        let _ = self.state.compare_exchange(
            HEALTH_READY,
            HEALTH_DEGRADED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub fn recover_readiness(&self) {
        let _ = self.state.compare_exchange(
            HEALTH_DEGRADED,
            HEALTH_READY,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub fn is_ready(&self) -> bool {
        self.state.load(Ordering::Acquire) == HEALTH_READY
    }
}
const HIGHLIGHTER_VERSION: &str = "language-labels-v1";
const ENCODING_PROFILE_VERSION: &str = "zstd-bounded-raw-rle-v1";
const VERIFIER_VERSION: &str = "gitd-verifier-view-v1";
const HYBRID_PROFILE_VERSION: &str = "mrml-hybrid-v1";
const SMART_GIT_INPUT_LIMIT: u64 = 1024 * 1024 * 1024;
const SMART_GIT_OUTPUT_LIMIT: u64 = 1024 * 1024 * 1024;
const SMART_GIT_MEMORY_LIMIT: u64 = 64 * 1024 * 1024;
const SMART_GIT_WORK_LIMIT: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RepositoryIdentity(Text);

impl RepositoryIdentity {
    pub fn parse(value: &str) -> Result<Self, BackendError> {
        let mut parts = value.split('/');
        let owner = parts.next().ok_or(BackendError::MalformedIdentifier)?;
        let repo = parts.next().ok_or(BackendError::MalformedIdentifier)?;
        if value.len() > MAX_IDENTITY
            || parts.next().is_some()
            || !valid_identity(owner)
            || !valid_identity(repo)
        {
            return Err(BackendError::MalformedIdentifier);
        }
        Ok(Self(value.into()))
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryPath(Text);

impl RepositoryPath {
    pub fn parse(value: &str) -> Result<Self, BackendError> {
        if value.len() > MAX_PATH
            || value.starts_with('/')
            || value.ends_with('/')
            || value.contains('\\')
            || value.bytes().any(|byte| byte == 0 || !byte.is_ascii())
            || (!value.is_empty()
                && value
                    .split('/')
                    .any(|part| part.is_empty() || matches!(part, "." | "..")))
        {
            return Err(BackendError::MalformedPath);
        }
        Ok(Self(value.into()))
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepositoryGeneration(pub u64);
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TrustGeneration(pub u64);
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RevocationGeneration(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectId(pub [u8; 32]);

impl ObjectId {
    pub fn hex(&self) -> Text {
        let mut output = Text::new();
        for byte in self.0 {
            output.push_str(&mrml_runtime::mrml_format!("{byte:02x}"));
        }
        output
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
    fn read(&mut self, output: &mut [u8]) -> Result<usize, BackendError>;
}
pub trait BoundedWrite {
    fn remaining(&self) -> u64;
    fn write(&mut self, input: &[u8]) -> Result<(), BackendError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositorySummary {
    pub generation: RepositoryGeneration,
    pub default_branch: Text,
    pub description: Text,
    pub refs: Vector<(Text, ObjectId)>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitPage {
    pub generation: RepositoryGeneration,
    pub commits: Vector<ObjectId>,
    pub next: Option<ObjectId>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreePage {
    pub generation: RepositoryGeneration,
    pub entries: Vector<RepositoryPath>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPage {
    pub generation: RepositoryGeneration,
    pub object: ObjectId,
    pub bytes: Vector<u8>,
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationState {
    MrmlHybridVerified,
    LegacySignatureAccepted,
    OpenPgpOnly,
    PostQuantumOnly,
    UnauthorizedSigner,
    RevokedKey,
    PolicyMismatch,
    MalformedSignature,
    InvalidSignature,
    Unverified,
}

impl VerificationState {
    fn label(self) -> &'static str {
        match self {
            Self::MrmlHybridVerified => "MRML Hybrid Verified",
            Self::LegacySignatureAccepted => "Legacy Signature Accepted",
            Self::OpenPgpOnly => "OpenPGP Only",
            Self::PostQuantumOnly => "Post-Quantum Only",
            Self::UnauthorizedSigner => "Unauthorized Signer",
            Self::RevokedKey => "Revoked Key",
            Self::PolicyMismatch => "Policy Mismatch",
            Self::MalformedSignature => "Malformed Signature",
            Self::InvalidSignature => "Invalid Signature",
            Self::Unverified => "Unverified",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationSummary {
    pub state: VerificationState,
    pub openpgp_fingerprint: Text,
    pub ml_dsa_public_key_digest: Text,
    pub algorithms: Text,
    pub signature_hash: Text,
    pub repository: RepositoryIdentity,
    pub purpose: Text,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    pub history_since_cutover_verified: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmartGitOperation {
    Discovery,
    ReceiveDiscovery,
    UploadPack,
    ReceivePack,
}
pub struct SmartGitRequest {
    pub repository: RepositoryIdentity,
    pub generation: RepositoryGeneration,
    pub operation: SmartGitOperation,
}
/// A Smart Git request whose route, authorization, and repository generation
/// have been validated without consuming or producing body bytes.
///
/// The private fields and consuming execution API make this a one-shot
/// transport prelude rather than a reusable authority token.
pub struct PreparedSmartGitRequest {
    request: SmartGitRequest,
    budget: WorkBudget,
    _operation_permit: Option<GitdOperationPermit>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GitdOperationLimitMetrics {
    pub configured_maximum: u32,
    pub current_usage: u32,
    pub rejections: u64,
    pub wait_nanoseconds: u64,
    pub permit_leak_assertion_failures: u64,
}

struct GitdOperationClass {
    configured_maximum: u32,
    current_usage: AtomicU32,
    rejections: AtomicU64,
    permit_leak_assertion_failures: AtomicU64,
}

impl GitdOperationClass {
    const fn new(configured_maximum: u32) -> Self {
        Self {
            configured_maximum,
            current_usage: AtomicU32::new(0),
            rejections: AtomicU64::new(0),
            permit_leak_assertion_failures: AtomicU64::new(0),
        }
    }

    fn try_acquire(&self) -> bool {
        let acquired =
            self.current_usage
                .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    (current < self.configured_maximum).then_some(current + 1)
                });
        if acquired.is_err() {
            self.rejections.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    fn release(&self) {
        if self
            .current_usage
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(1)
            })
            .is_err()
        {
            self.permit_leak_assertion_failures
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn metrics(&self) -> GitdOperationLimitMetrics {
        GitdOperationLimitMetrics {
            configured_maximum: self.configured_maximum,
            current_usage: self.current_usage.load(Ordering::Acquire),
            rejections: self.rejections.load(Ordering::Relaxed),
            // Admission is deliberately nonblocking, so there is no waiting
            // interval to accumulate and overload fails immediately.
            wait_nanoseconds: 0,
            permit_leak_assertion_failures: self
                .permit_leak_assertion_failures
                .load(Ordering::Relaxed),
        }
    }
}

pub struct GitdOperationLimits {
    uploads: GitdOperationClass,
    receives: GitdOperationClass,
}

impl GitdOperationLimits {
    pub fn new(max_uploads: u32, max_receives: u32) -> Result<Self, BackendError> {
        if max_uploads == 0 || max_receives == 0 {
            return Err(BackendError::ResourceLimit);
        }
        Ok(Self {
            uploads: GitdOperationClass::new(max_uploads),
            receives: GitdOperationClass::new(max_receives),
        })
    }

    pub fn upload_metrics(&self) -> GitdOperationLimitMetrics {
        self.uploads.metrics()
    }

    pub fn receive_metrics(&self) -> GitdOperationLimitMetrics {
        self.receives.metrics()
    }

    fn try_acquire(
        limits: &Shared<Self>,
        operation: SmartGitOperation,
    ) -> Result<Option<GitdOperationPermit>, BackendError> {
        let class = match operation {
            SmartGitOperation::UploadPack => GitdOperationClassKind::Upload,
            SmartGitOperation::ReceivePack => GitdOperationClassKind::Receive,
            SmartGitOperation::Discovery | SmartGitOperation::ReceiveDiscovery => return Ok(None),
        };
        let acquired = match class {
            GitdOperationClassKind::Upload => limits.uploads.try_acquire(),
            GitdOperationClassKind::Receive => limits.receives.try_acquire(),
        };
        if !acquired {
            return Err(BackendError::ResourceLimit);
        }
        Ok(Some(GitdOperationPermit {
            limits: limits.clone(),
            class,
        }))
    }
}

#[derive(Clone, Copy)]
enum GitdOperationClassKind {
    Upload,
    Receive,
}

struct GitdOperationPermit {
    limits: Shared<GitdOperationLimits>,
    class: GitdOperationClassKind,
}

impl Drop for GitdOperationPermit {
    fn drop(&mut self) {
        match self.class {
            GitdOperationClassKind::Upload => self.limits.uploads.release(),
            GitdOperationClassKind::Receive => self.limits.receives.release(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmartGitResponse {
    pub generation: RepositoryGeneration,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub refs_activated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendError {
    MalformedIdentifier,
    MalformedPath,
    MalformedRevision,
    NotFound,
    Private,
    StaleGeneration,
    ResourceLimit,
    Unsupported,
    Storage,
}

pub trait GitdBackend {
    fn candidate_status(
        &self,
        repository: &RepositoryIdentity,
        candidate_id: [u8; 16],
    ) -> Result<Vector<u8>, BackendError>;
    fn repository_generation(
        &self,
        repository: &RepositoryIdentity,
    ) -> Result<RepositoryGeneration, BackendError>;
    fn repository_summary(
        &self,
        repository: &RepositoryIdentity,
        limits: QueryLimits,
    ) -> Result<RepositorySummary, BackendError>;
    fn resolve_ref(
        &self,
        repository: &RepositoryIdentity,
        revision: &str,
    ) -> Result<ObjectId, BackendError>;
    fn read_commit_page(
        &self,
        repository: &RepositoryIdentity,
        commit: ObjectId,
        limits: QueryLimits,
    ) -> Result<CommitPage, BackendError>;
    fn read_tree_page(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        limits: QueryLimits,
    ) -> Result<TreePage, BackendError>;
    fn read_blob_page(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        limits: QueryLimits,
    ) -> Result<BlobPage, BackendError>;
    fn verification_summary(
        &self,
        repository: &RepositoryIdentity,
        object: ObjectId,
        policy: TrustGeneration,
        revocations: RevocationGeneration,
    ) -> Result<VerificationSummary, BackendError>;
    fn smart_git(
        &mut self,
        request: SmartGitRequest,
        input: &mut dyn BoundedRead,
        output: &mut dyn BoundedWrite,
        budget: WorkBudget,
    ) -> Result<SmartGitResponse, BackendError>;
}

pub trait CacheStore {
    fn read(&mut self, key: &[u8], output: &mut Vector<u8>) -> Result<bool, BackendError>;
    fn write_atomic(&mut self, key: &[u8], value: &[u8]) -> Result<(), BackendError>;
    fn remove_corrupt(&mut self, key: &[u8]) -> Result<(), BackendError>;
}

#[cfg(unix)]
pub struct LinuxFilesystemCacheStore {
    root: Text,
    maximum_entries: usize,
    maximum_bytes: u64,
    next_temporary: u64,
}

#[cfg(unix)]
impl LinuxFilesystemCacheStore {
    pub fn new(
        root: &str,
        maximum_entries: usize,
        maximum_bytes: u64,
    ) -> Result<Self, BackendError> {
        if root.is_empty()
            || root.len() > 2048
            || root.as_bytes().contains(&0)
            || maximum_entries == 0
            || maximum_entries > 4096
            || maximum_bytes == 0
        {
            return Err(BackendError::ResourceLimit);
        }
        mrml_runtime::create_dir_all(root).map_err(|_| BackendError::Storage)?;
        mrml_runtime::sync_directory(root).map_err(|_| BackendError::Storage)?;
        let mut store = Self {
            root: root.into(),
            maximum_entries,
            maximum_bytes,
            next_temporary: 1,
        };
        store.cleanup_interrupted_writes()?;
        Ok(store)
    }

    fn filename(key: &[u8]) -> Result<Text, BackendError> {
        if key.len() != 32 {
            return Err(BackendError::Storage);
        }
        let mut name = Text::new();
        for byte in key {
            name.push_str(&mrml_runtime::mrml_format!("{byte:02x}"));
        }
        name.push_str(".cache");
        Ok(name)
    }

    fn path(&self, key: &[u8]) -> Result<Text, BackendError> {
        Ok(mrml_runtime::join_path(
            self.root.as_str(),
            Self::filename(key)?.as_str(),
        ))
    }

    fn enforce_quota(&mut self, protected: &str) -> Result<(), BackendError> {
        let entries =
            mrml_runtime::read_directory(self.root.as_str()).map_err(|_| BackendError::Storage)?;
        let mut files: Vector<(Text, u64)> = Vector::new();
        let mut bytes = 0u64;
        for entry in entries {
            if entry.is_directory || entry.is_symlink || !entry.name.ends_with(".cache") {
                continue;
            }
            let path = mrml_runtime::join_path(self.root.as_str(), entry.name.as_str());
            let length = mrml_runtime::File::open_regular(path.as_str())
                .and_then(|file| file.len())
                .map_err(|_| BackendError::Storage)?;
            bytes = bytes
                .checked_add(length)
                .ok_or(BackendError::ResourceLimit)?;
            files
                .try_push((path, length))
                .map_err(|_| BackendError::ResourceLimit)?;
        }
        let mut index = 0;
        while (files.len() > self.maximum_entries || bytes > self.maximum_bytes)
            && index < files.len()
        {
            if files[index].0 != protected {
                let (path, length) = files.remove(index);
                mrml_runtime::remove_file(path.as_str()).map_err(|_| BackendError::Storage)?;
                bytes -= length;
            } else {
                index += 1;
            }
        }
        if files.len() > self.maximum_entries || bytes > self.maximum_bytes {
            return Err(BackendError::ResourceLimit);
        }
        mrml_runtime::sync_directory(self.root.as_str()).map_err(|_| BackendError::Storage)
    }

    fn ensure_root(&self) -> Result<(), BackendError> {
        mrml_runtime::create_dir_all(self.root.as_str()).map_err(|_| BackendError::Storage)
    }

    fn cleanup_interrupted_writes(&mut self) -> Result<(), BackendError> {
        let entries =
            mrml_runtime::read_directory(self.root.as_str()).map_err(|_| BackendError::Storage)?;
        let mut changed = false;
        for entry in entries {
            if entry.is_directory || entry.is_symlink || !entry.name.starts_with(".tmp-") {
                continue;
            }
            let path = mrml_runtime::join_path(self.root.as_str(), entry.name.as_str());
            mrml_runtime::remove_file(path.as_str()).map_err(|_| BackendError::Storage)?;
            changed = true;
        }
        if changed {
            mrml_runtime::sync_directory(self.root.as_str()).map_err(|_| BackendError::Storage)?;
        }
        Ok(())
    }
}

#[cfg(unix)]
impl CacheStore for LinuxFilesystemCacheStore {
    fn read(&mut self, key: &[u8], output: &mut Vector<u8>) -> Result<bool, BackendError> {
        let path = self.path(key)?;
        if !mrml_runtime::path_exists(path.as_str()) {
            return Ok(false);
        }
        let mut file =
            mrml_runtime::File::open_regular(path.as_str()).map_err(|_| BackendError::Storage)?;
        let length = usize::try_from(file.len().map_err(|_| BackendError::Storage)?)
            .map_err(|_| BackendError::ResourceLimit)?;
        if length > MAX_CACHE_RECORD {
            return Err(BackendError::ResourceLimit);
        }
        let mut bytes = Vector::with_capacity(length).map_err(|_| BackendError::ResourceLimit)?;
        bytes
            .try_resize(length, 0)
            .map_err(|_| BackendError::ResourceLimit)?;
        file.read_exact(&mut bytes)
            .map_err(|_| BackendError::Storage)?;
        output
            .try_extend_from_slice(&bytes)
            .map_err(|_| BackendError::ResourceLimit)?;
        Ok(true)
    }

    fn write_atomic(&mut self, key: &[u8], value: &[u8]) -> Result<(), BackendError> {
        if value.len() > MAX_CACHE_RECORD || value.len() as u64 > self.maximum_bytes {
            return Err(BackendError::ResourceLimit);
        }
        self.ensure_root()?;
        let target = self.path(key)?;
        let temporary_name = mrml_runtime::mrml_format!(
            ".tmp-{}-{}",
            mrml_runtime::process_id(),
            self.next_temporary
        );
        self.next_temporary = self
            .next_temporary
            .checked_add(1)
            .ok_or(BackendError::ResourceLimit)?;
        let temporary = mrml_runtime::join_path(self.root.as_str(), temporary_name.as_str());
        let result = (|| {
            let mut file = mrml_runtime::File::create_new(temporary.as_str())
                .map_err(|_| BackendError::Storage)?;
            file.write_all(value).map_err(|_| BackendError::Storage)?;
            file.sync().map_err(|_| BackendError::Storage)?;
            drop(file);
            mrml_runtime::rename_file(temporary.as_str(), target.as_str())
                .map_err(|_| BackendError::Storage)?;
            mrml_runtime::sync_directory(self.root.as_str()).map_err(|_| BackendError::Storage)?;
            self.enforce_quota(target.as_str())
        })();
        if result.is_err() {
            let _ = mrml_runtime::remove_file(temporary.as_str());
        }
        result
    }

    fn remove_corrupt(&mut self, key: &[u8]) -> Result<(), BackendError> {
        self.ensure_root()?;
        let path = self.path(key)?;
        let _ = mrml_runtime::remove_file(path.as_str());
        mrml_runtime::sync_directory(self.root.as_str()).map_err(|_| BackendError::Storage)
    }
}

const CACHE_RECORD_MAGIC: &[u8; 8] = b"MRMLC2\0\0";
const MAX_CACHE_RECORD: usize = 2 * MAX_RENDERED + 128;

pub struct PersistentRepresentationCache<S: CacheStore> {
    store: S,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepresentationGenerationPermit {
    slot: u64,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SingleFlightDecision {
    Generate(RepresentationGenerationPermit),
    InProgress,
}

struct InFlightRepresentation {
    key: [u8; 32],
    slot: u64,
    generation: u64,
}

/// Bounded single-owner coordinator for cache misses. The HTTP reactor calls
/// `begin` before dispatching generation and `complete` after atomically
/// publishing the record. Concurrent misses observe `InProgress` and cannot
/// start duplicate compression work.
pub struct RepresentationSingleFlight {
    entries: Vector<InFlightRepresentation>,
    maximum_entries: usize,
    next_slot: u64,
    next_generation: u64,
}

impl RepresentationSingleFlight {
    pub fn new(maximum_entries: usize) -> Result<Self, BackendError> {
        if maximum_entries == 0 || maximum_entries > 4096 {
            return Err(BackendError::ResourceLimit);
        }
        Ok(Self {
            entries: Vector::new(),
            maximum_entries,
            next_slot: 1,
            next_generation: 1,
        })
    }

    pub fn begin(&mut self, logical_key: &str) -> Result<SingleFlightDecision, BackendError> {
        let key = cache_storage_key(logical_key)?;
        if self.entries.iter().any(|entry| entry.key == key) {
            return Ok(SingleFlightDecision::InProgress);
        }
        if self.entries.len() >= self.maximum_entries {
            return Err(BackendError::ResourceLimit);
        }
        let permit = RepresentationGenerationPermit {
            slot: self.next_slot,
            generation: self.next_generation,
        };
        self.next_slot = self
            .next_slot
            .checked_add(1)
            .ok_or(BackendError::ResourceLimit)?;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(BackendError::ResourceLimit)?;
        self.entries
            .try_push(InFlightRepresentation {
                key,
                slot: permit.slot,
                generation: permit.generation,
            })
            .map_err(|_| BackendError::ResourceLimit)?;
        Ok(SingleFlightDecision::Generate(permit))
    }

    pub fn complete(&mut self, permit: RepresentationGenerationPermit) -> Result<(), BackendError> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.slot == permit.slot && entry.generation == permit.generation)
            .ok_or(BackendError::StaleGeneration)?;
        self.entries.remove(index);
        Ok(())
    }

    pub fn active(&self) -> usize {
        self.entries.len()
    }
}

impl<S: CacheStore> PersistentRepresentationCache<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn load(
        &mut self,
        logical_key: &str,
    ) -> Result<Option<CachedRepresentation>, BackendError> {
        let key = cache_storage_key(logical_key)?;
        let mut record = Vector::new();
        if !self.store.read(&key, &mut record)? {
            return Ok(None);
        }
        match decode_cache_record(&record) {
            Ok(value) => Ok(Some(value)),
            Err(_) => {
                self.store.remove_corrupt(&key)?;
                Ok(None)
            }
        }
    }

    pub fn store(
        &mut self,
        logical_key: &str,
        value: &CachedRepresentation,
    ) -> Result<(), BackendError> {
        let key = cache_storage_key(logical_key)?;
        let record = encode_cache_record(value)?;
        self.store.write_atomic(&key, &record)
    }

    pub fn into_store(self) -> S {
        self.store
    }
}

fn cache_storage_key(logical_key: &str) -> Result<[u8; 32], BackendError> {
    if logical_key.is_empty() || logical_key.len() > 4096 {
        return Err(BackendError::ResourceLimit);
    }
    let mut hash = Sha256::new();
    hash.update(b"mrml-gitd-cache-key-v1\0");
    hash.update(logical_key.as_bytes());
    Ok(hash.finalize())
}

fn encode_cache_record(value: &CachedRepresentation) -> Result<Vector<u8>, BackendError> {
    if value.identity.len() > MAX_RENDERED || value.zstd.len() > MAX_RENDERED {
        return Err(BackendError::ResourceLimit);
    }
    let total = 8usize
        .checked_add(8)
        .and_then(|size| size.checked_add(64))
        .and_then(|size| size.checked_add(value.identity.len()))
        .and_then(|size| size.checked_add(value.zstd.len()))
        .ok_or(BackendError::ResourceLimit)?;
    if total > MAX_CACHE_RECORD {
        return Err(BackendError::ResourceLimit);
    }
    let mut record = Vector::new();
    record
        .try_extend_from_slice(CACHE_RECORD_MAGIC)
        .map_err(|_| BackendError::ResourceLimit)?;
    record
        .try_extend_from_slice(&(value.identity.len() as u32).to_be_bytes())
        .map_err(|_| BackendError::ResourceLimit)?;
    record
        .try_extend_from_slice(&(value.zstd.len() as u32).to_be_bytes())
        .map_err(|_| BackendError::ResourceLimit)?;
    record
        .try_extend_from_slice(&Sha256::digest(&value.identity))
        .map_err(|_| BackendError::ResourceLimit)?;
    record
        .try_extend_from_slice(&Sha256::digest(&value.zstd))
        .map_err(|_| BackendError::ResourceLimit)?;
    record
        .try_extend_from_slice(&value.identity)
        .map_err(|_| BackendError::ResourceLimit)?;
    record
        .try_extend_from_slice(&value.zstd)
        .map_err(|_| BackendError::ResourceLimit)?;
    Ok(record)
}

fn decode_cache_record(record: &[u8]) -> Result<CachedRepresentation, BackendError> {
    if record.len() < 80 || record.len() > MAX_CACHE_RECORD || &record[..8] != CACHE_RECORD_MAGIC {
        return Err(BackendError::Storage);
    }
    let identity_length = u32::from_be_bytes(
        record[8..12]
            .try_into()
            .map_err(|_| BackendError::Storage)?,
    ) as usize;
    let zstd_length = u32::from_be_bytes(
        record[12..16]
            .try_into()
            .map_err(|_| BackendError::Storage)?,
    ) as usize;
    if identity_length > MAX_RENDERED || zstd_length > MAX_RENDERED {
        return Err(BackendError::Storage);
    }
    let identity_end = 80usize
        .checked_add(identity_length)
        .ok_or(BackendError::Storage)?;
    let record_end = identity_end
        .checked_add(zstd_length)
        .ok_or(BackendError::Storage)?;
    if record_end != record.len() {
        return Err(BackendError::Storage);
    }
    let identity = &record[80..identity_end];
    let zstd = &record[identity_end..record_end];
    if record[16..48] != Sha256::digest(identity) || record[48..80] != Sha256::digest(zstd) {
        return Err(BackendError::Storage);
    }
    let decoded = mrml_zstd::decode(zstd).map_err(|_| BackendError::Storage)?;
    if &decoded[..] != identity {
        return Err(BackendError::Storage);
    }
    let mut owned_identity = Vector::new();
    owned_identity
        .try_extend_from_slice(identity)
        .map_err(|_| BackendError::ResourceLimit)?;
    let mut owned_zstd = Vector::new();
    owned_zstd
        .try_extend_from_slice(zstd)
        .map_err(|_| BackendError::ResourceLimit)?;
    Ok(CachedRepresentation {
        identity: owned_identity,
        zstd: owned_zstd,
        etag_identity: etag(b"identity-v1", identity),
        etag_zstd: etag(b"zstd-rfc8878-v2", zstd),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedRepresentation {
    pub identity: Vector<u8>,
    pub zstd: Vector<u8>,
    pub etag_identity: Text,
    pub etag_zstd: Text,
}

impl CachedRepresentation {
    pub fn prepare(identity: &[u8]) -> Result<Self, BackendError> {
        if identity.len() > MAX_RENDERED {
            return Err(BackendError::ResourceLimit);
        }
        let mut plain = Vector::new();
        plain
            .try_extend_from_slice(identity)
            .map_err(|_| BackendError::ResourceLimit)?;
        let zstd = encode_http(identity, HttpEncodingProfile::BoundedRfc8878V2)
            .map_err(|_| BackendError::ResourceLimit)?;
        Ok(Self {
            etag_identity: etag(b"identity-v1", identity),
            etag_zstd: etag(b"zstd-rfc8878-v2", &zstd),
            identity: plain,
            zstd,
        })
    }
}

fn etag(domain: &[u8], bytes: &[u8]) -> Text {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    let digest = hash.finalize();
    let mut output: Text = "\"".into();
    for byte in digest {
        output.push_str(&mrml_runtime::mrml_format!("{byte:02x}"));
    }
    output.push('"');
    output
}

struct CacheEntry {
    key: Text,
    value: CachedRepresentation,
    bytes: usize,
}

pub struct MemoryRepresentationCache {
    entries: Vector<CacheEntry>,
    maximum_entries: usize,
    maximum_bytes: usize,
    used: usize,
    pub generation_count: u64,
}

impl MemoryRepresentationCache {
    pub fn new(maximum_entries: usize, maximum_bytes: usize) -> Result<Self, BackendError> {
        if maximum_entries == 0 || maximum_entries > 4096 || maximum_bytes == 0 {
            return Err(BackendError::ResourceLimit);
        }
        Ok(Self {
            entries: Vector::new(),
            maximum_entries,
            maximum_bytes,
            used: 0,
            generation_count: 0,
        })
    }
    pub fn get(&mut self, key: &str) -> Option<&CachedRepresentation> {
        let index = self.entries.iter().position(|entry| entry.key == key)?;
        let entry = self.entries.remove(index);
        self.entries.push(entry);
        self.entries.last().map(|entry| &entry.value)
    }
    pub fn insert(&mut self, key: &str, value: CachedRepresentation) -> Result<(), BackendError> {
        let bytes = value
            .identity
            .len()
            .checked_add(value.zstd.len())
            .ok_or(BackendError::ResourceLimit)?;
        if bytes > self.maximum_bytes || key.len() > 4096 {
            return Err(BackendError::ResourceLimit);
        }
        if let Some(index) = self.entries.iter().position(|entry| entry.key == key) {
            self.used -= self.entries.remove(index).bytes;
        }
        while self.entries.len() >= self.maximum_entries || self.used + bytes > self.maximum_bytes {
            self.used -= self.entries.remove(0).bytes;
        }
        self.entries
            .try_push(CacheEntry {
                key: key.into(),
                value,
                bytes,
            })
            .map_err(|_| BackendError::ResourceLimit)?;
        self.used += bytes;
        self.generation_count = self.generation_count.saturating_add(1);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitdHttpResponse {
    pub status: u16,
    pub headers: Vector<Header>,
    pub body: Vector<u8>,
}

struct EmptySmartGitInput;
impl BoundedRead for EmptySmartGitInput {
    fn remaining(&self) -> u64 {
        0
    }
    fn read(&mut self, _output: &mut [u8]) -> Result<usize, BackendError> {
        Ok(0)
    }
}

struct BufferedSmartGitOutput {
    bytes: Vector<u8>,
    limit: usize,
}
impl BufferedSmartGitOutput {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vector::new(),
            limit,
        }
    }
}
impl BoundedWrite for BufferedSmartGitOutput {
    fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.bytes.len()) as u64
    }
    fn write(&mut self, input: &[u8]) -> Result<(), BackendError> {
        if input.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(BackendError::ResourceLimit);
        }
        self.bytes
            .try_extend_from_slice(input)
            .map_err(|_| BackendError::ResourceLimit)
    }
}

pub struct GitdHttp3Server<B: GitdBackend> {
    backend: B,
    cache: MemoryRepresentationCache,
    flights: RepresentationSingleFlight,
    trust: TrustGeneration,
    revocations: RevocationGeneration,
    authentication: Option<Shared<GitdAuthentication>>,
    operational_health: Option<Shared<GitdOperationalHealth>>,
    operation_limits: Option<Shared<GitdOperationLimits>>,
}

impl<B: GitdBackend> GitdHttp3Server<B> {
    pub fn new(backend: B, cache_bytes: usize) -> Result<Self, BackendError> {
        Ok(Self {
            backend,
            cache: MemoryRepresentationCache::new(256, cache_bytes)?,
            flights: RepresentationSingleFlight::new(256)?,
            trust: TrustGeneration(0),
            revocations: RevocationGeneration(0),
            authentication: None,
            operational_health: None,
            operation_limits: None,
        })
    }
    pub fn configure_authentication(&mut self, authentication: GitdAuthentication) {
        self.authentication = Some(Shared::new(authentication));
    }
    pub fn configure_shared_authentication(&mut self, authentication: Shared<GitdAuthentication>) {
        self.authentication = Some(authentication);
    }
    pub fn configure_operational_health(&mut self, health: Shared<GitdOperationalHealth>) {
        self.operational_health = Some(health);
    }
    pub fn configure_operation_limits(&mut self, limits: Shared<GitdOperationLimits>) {
        self.operation_limits = Some(limits);
    }
    pub fn set_verification_generations(
        &mut self,
        trust: TrustGeneration,
        revocations: RevocationGeneration,
    ) {
        self.trust = trust;
        self.revocations = revocations;
    }
    pub fn handle(&mut self, request: &RequestHead) -> GitdHttpResponse {
        match self.handle_inner(request) {
            Ok(response) => response,
            Err(
                BackendError::NotFound
                | BackendError::MalformedIdentifier
                | BackendError::MalformedPath
                | BackendError::MalformedRevision,
            ) => self.error(404, "Not found"),
            Err(BackendError::Private) => self.error(404, "Not found"),
            Err(BackendError::ResourceLimit) => self.error(429, "Request limit reached"),
            Err(BackendError::StaleGeneration) => self.error(503, "Repository changed; retry"),
            Err(_) => self.error(503, "Service unavailable"),
        }
    }

    /// Execute one Smart Git request against caller-owned bounded streams.
    /// HTTP/2 and HTTP/3 listeners use this same entry point so DATA frames are
    /// backpressured by the transport rather than collected into a whole pack.
    pub fn handle_smart_git(
        &mut self,
        request: &RequestHead,
        input: &mut dyn BoundedRead,
        output: &mut dyn BoundedWrite,
    ) -> GitdHttpResponse {
        match self
            .prepare_smart_git(request, input.remaining(), output.remaining())
            .and_then(|(prepared, response)| {
                self.execute_prepared_smart_git(prepared, input, output)?;
                Ok(response)
            }) {
            Ok(response) => response,
            Err(
                BackendError::NotFound
                | BackendError::MalformedIdentifier
                | BackendError::MalformedPath
                | BackendError::MalformedRevision
                | BackendError::Private,
            ) => self.error(404, "Not found"),
            Err(BackendError::ResourceLimit) => self.error(429, "Request limit reached"),
            Err(BackendError::StaleGeneration) => self.error(503, "Repository changed"),
            Err(_) => self.error(503, "Service unavailable"),
        }
    }

    /// Validate a Smart Git request and construct the response headers before
    /// any request or response body byte crosses the backend boundary.
    pub fn prepare_smart_git(
        &self,
        request: &RequestHead,
        input_remaining: u64,
        output_remaining: u64,
    ) -> Result<(PreparedSmartGitRequest, GitdHttpResponse), BackendError> {
        if request.scheme != "https" || single_header(request, "git-protocol")? != Some("version=2")
        {
            return Err(BackendError::Unsupported);
        }
        let (path, query) = match request.target.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (request.target.as_str(), None),
        };
        let relative = path.strip_prefix('/').ok_or(BackendError::NotFound)?;
        let pieces: Vector<&str> = relative.split('/').collect();
        if pieces.len() < 3 || pieces.len() > 4 || !pieces[1].ends_with(".git") {
            return Err(BackendError::NotFound);
        }
        let name = pieces[1]
            .strip_suffix(".git")
            .ok_or(BackendError::NotFound)?;
        let repository =
            RepositoryIdentity::parse(&mrml_runtime::mrml_format!("{}/{}", pieces[0], name))?;
        let (operation, response_type) = match (request.method.as_str(), &pieces[2..], query) {
            ("GET", ["info", "refs"], Some("service=git-upload-pack")) => (
                SmartGitOperation::Discovery,
                "application/x-git-upload-pack-advertisement",
            ),
            ("GET", ["info", "refs"], Some("service=git-receive-pack")) => (
                SmartGitOperation::ReceiveDiscovery,
                "application/x-git-receive-pack-advertisement",
            ),
            ("POST", ["git-upload-pack"], None) => {
                require_content_type(request, "application/x-git-upload-pack-request")?;
                (
                    SmartGitOperation::UploadPack,
                    "application/x-git-upload-pack-result",
                )
            }
            ("POST", ["git-receive-pack"], None) => {
                require_content_type(request, "application/x-git-receive-pack-request")?;
                (
                    SmartGitOperation::ReceivePack,
                    "application/x-git-receive-pack-result",
                )
            }
            _ => return Err(BackendError::NotFound),
        };
        let action = if matches!(
            operation,
            SmartGitOperation::ReceiveDiscovery | SmartGitOperation::ReceivePack
        ) {
            RepositoryAction::Write
        } else {
            RepositoryAction::Read
        };
        let now = mrml_runtime::unix_time_seconds().ok_or(BackendError::Storage)?;
        self.authentication
            .as_ref()
            .ok_or(BackendError::Private)?
            .authorize(&request.headers, &repository, action, now)
            .map_err(|_| BackendError::Private)?;
        let generation = self.backend.repository_generation(&repository)?;
        let operation_permit = match self.operation_limits.as_ref() {
            Some(limits) => GitdOperationLimits::try_acquire(limits, operation)?,
            None => None,
        };
        let prepared = PreparedSmartGitRequest {
            request: SmartGitRequest {
                repository,
                generation,
                operation,
            },
            budget: WorkBudget {
                max_input_bytes: SMART_GIT_INPUT_LIMIT.min(input_remaining),
                max_output_bytes: SMART_GIT_OUTPUT_LIMIT.min(output_remaining),
                max_memory_bytes: SMART_GIT_MEMORY_LIMIT,
                max_work_units: SMART_GIT_WORK_LIMIT,
            },
            _operation_permit: operation_permit,
        };
        let mut response = self.text(200, response_type, b"", true)?;
        if let Some(index) = response
            .headers
            .iter()
            .position(|header| header.name.eq_ignore_ascii_case("content-length"))
        {
            response.headers.remove(index);
        }
        set_header(&mut response.headers, "cache-control", "no-store")?;
        set_header(&mut response.headers, "pragma", "no-cache")?;
        Ok((prepared, response))
    }

    /// Execute a previously prepared request exactly once against bounded
    /// transport streams.
    pub fn execute_prepared_smart_git(
        &mut self,
        prepared: PreparedSmartGitRequest,
        input: &mut dyn BoundedRead,
        output: &mut dyn BoundedWrite,
    ) -> Result<SmartGitResponse, BackendError> {
        let generation = prepared.request.generation;
        let operation = prepared.request.operation;
        let result = self
            .backend
            .smart_git(prepared.request, input, output, prepared.budget)?;
        let expected_generation = if operation == SmartGitOperation::ReceivePack
            && result.refs_activated
        {
            RepositoryGeneration(
                generation
                    .0
                    .checked_add(1)
                    .ok_or(BackendError::StaleGeneration)?,
            )
        } else {
            generation
        };
        if result.generation != expected_generation
            || (operation != SmartGitOperation::ReceivePack && result.refs_activated)
        {
            return Err(BackendError::StaleGeneration);
        }
        Ok(result)
    }
    fn handle_inner(&mut self, request: &RequestHead) -> Result<GitdHttpResponse, BackendError> {
        if request.method != "GET" && request.method != "POST" {
            return Ok(self.error(405, "Method not allowed"));
        }
        let target = request.target.split('?').next().unwrap_or("");
        if target == "/health/live" {
            let mut response = self.text(200, "text/plain; charset=utf-8", b"live\n", false)?;
            set_header(&mut response.headers, "cache-control", "no-store")?;
            return Ok(response);
        }
        if target == "/health/ready" {
            let ready = self
                .operational_health
                .as_ref()
                .is_some_and(|health| health.is_ready());
            let mut response = self.text(
                if ready { 200 } else { 503 },
                "text/plain; charset=utf-8",
                if ready { b"ready\n" } else { b"not-ready\n" },
                false,
            )?;
            set_header(&mut response.headers, "cache-control", "no-store")?;
            return Ok(response);
        }
        if target == "/" {
            return self.html_page(request, "MRML", "Independent systems research", "<h1>MRML</h1><p>Experimental operating-system, compiler, and application-platform research.</p>", true, "/", "home-v1");
        }
        if target == "/projects" {
            return self.html_page(request, "Public projects", "Public MRML source repositories", "<h1>Public projects</h1><p><a href=\"/mitchellrenouf/mrml\">mitchellrenouf/mrml</a></p>", true, "/projects", "projects-v1");
        }
        if target == "/robots.txt" {
            return self.text(200, "text/plain; charset=utf-8", b"User-agent: *\nDisallow: /api/\nDisallow: /*.git/\nSitemap: https://mrml.ca/sitemap.xml\n", false);
        }
        if target == "/.well-known/security.txt" {
            return self.text(200, "text/plain; charset=utf-8", b"Contact: mailto:mitchellrenouf@mrml.ca\nCanonical: https://mrml.ca/.well-known/security.txt\n", false);
        }
        if target == "/sitemap.xml" {
            return self.text(200, "application/xml; charset=utf-8", b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>https://mrml.ca/</loc></url><url><loc>https://mrml.ca/projects</loc></url><url><loc>https://mrml.ca/mitchellrenouf/mrml</loc></url></urlset>", false);
        }
        if target.starts_with("/api/v1/") {
            let mut response = self.text(
                200,
                "application/json; charset=utf-8",
                b"{\"api\":\"mrml-gitd\",\"version\":1}",
                true,
            )?;
            set_header(&mut response.headers, "cache-control", "no-store")?;
            return Ok(response);
        }
        self.repository_route(request, target)
    }
    fn repository_route(
        &mut self,
        request: &RequestHead,
        target: &str,
    ) -> Result<GitdHttpResponse, BackendError> {
        let path = target.strip_prefix('/').ok_or(BackendError::NotFound)?;
        let pieces: Vector<&str> = path.split('/').collect();
        if pieces.len() < 2 {
            return Err(BackendError::NotFound);
        }
        let repo_name = pieces[1].strip_suffix(".git").unwrap_or(pieces[1]);
        let repository =
            RepositoryIdentity::parse(&mrml_runtime::mrml_format!("{}/{}", pieces[0], repo_name))?;
        if pieces[1].ends_with(".git")
            && pieces.len() == 4
            && pieces[2] == "mrml-candidate-v1"
        {
            if request.method != "GET"
                || request.scheme != "https"
                || request.target.as_str() != target
            {
                return Err(BackendError::NotFound);
            }
            let now = mrml_runtime::unix_time_seconds().ok_or(BackendError::Storage)?;
            self.authentication
                .as_ref()
                .ok_or(BackendError::Private)?
                .authorize(&request.headers, &repository, RepositoryAction::Write, now)
                .map_err(|_| BackendError::Private)?;
            let candidate_id = parse_candidate_id(pieces[3])?;
            let body = self.backend.candidate_status(&repository, candidate_id)?;
            if body.is_empty() || body.len() > 256 * 1024 {
                return Err(BackendError::Storage);
            }
            let mut response = self.text(
                200,
                "application/vnd.mrml.git-candidate-status-v1",
                &body,
                true,
            )?;
            set_header(&mut response.headers, "cache-control", "no-store")?;
            set_header(&mut response.headers, "pragma", "no-cache")?;
            return Ok(response);
        }
        let generation = self.backend.repository_generation(&repository)?;
        if pieces[1].ends_with(".git") {
            return self.git_route(request, repository, generation, &pieces[2..]);
        }
        let summary = self.backend.repository_summary(
            &repository,
            QueryLimits {
                max_entries: 256,
                max_bytes: 1024 * 1024,
            },
        )?;
        if summary.generation != generation {
            return Err(BackendError::StaleGeneration);
        }
        let kind = pieces.get(2).copied().unwrap_or("overview");
        let revision = pieces
            .get(3)
            .copied()
            .unwrap_or(summary.default_branch.as_str());
        validate_revision(revision)?;
        let object = self.backend.resolve_ref(&repository, revision)?;
        let context = representation_cache_key(
            &repository,
            generation,
            kind,
            target,
            revision,
            &object,
            self.trust,
            self.revocations,
        )?;
        if let Some(cached) = self.cache.get(&context) {
            return Ok(representation_response(request, cached, true));
        }
        let permit = match self.flights.begin(&context)? {
            SingleFlightDecision::Generate(permit) => permit,
            SingleFlightDecision::InProgress => return Err(BackendError::StaleGeneration),
        };
        let result = (|| {
            let content = match kind {
                "overview" => mrml_runtime::mrml_format!(
                    "<h1>{}</h1><p>{}</p><nav aria-label=\"Repository\"><a href=\"/{}/tree/{}/\">Files</a> <a href=\"/{}/commits/{}\">Commits</a> <a href=\"/{}/signatures\">Signatures</a></nav>",
                    repository.as_str(),
                    escape(summary.description.as_str()),
                    repository.as_str(),
                    object.hex(),
                    repository.as_str(),
                    object.hex(),
                    repository.as_str()
                ),
                "tree" => {
                    let relative = join_path(pieces.get(4..).unwrap_or(&[]));
                    let tree = self.backend.read_tree_page(
                        &repository,
                        object.clone(),
                        &RepositoryPath::parse(relative.as_str())?,
                        QueryLimits {
                            max_entries: 256,
                            max_bytes: 1024 * 1024,
                        },
                    )?;
                    let mut html: Text = "<h1>Files</h1><ul>".into();
                    for entry in tree.entries {
                        html.push_str("<li>");
                        html.push_str(&escape(entry.as_str()));
                        html.push_str("</li>");
                    }
                    html.push_str("</ul>");
                    html
                }
                "blob" => {
                    let relative = join_path(pieces.get(4..).unwrap_or(&[]));
                    let blob = self.backend.read_blob_page(
                        &repository,
                        object.clone(),
                        &RepositoryPath::parse(relative.as_str())?,
                        QueryLimits {
                            max_entries: 1,
                            max_bytes: MAX_MARKDOWN as u64,
                        },
                    )?;
                    if !blob.complete {
                        return Err(BackendError::ResourceLimit);
                    }
                    render_markdown(&blob.bytes, &repository, &object)?
                }
                "commits" | "commit" => {
                    let commits = self.backend.read_commit_page(
                        &repository,
                        object.clone(),
                        QueryLimits {
                            max_entries: 100,
                            max_bytes: 1024 * 1024,
                        },
                    )?;
                    let mut html: Text = "<h1>Commits</h1><ol>".into();
                    for commit in commits.commits {
                        html.push_str("<li><code>");
                        html.push_str(&commit.hex());
                        html.push_str("</code></li>");
                    }
                    html.push_str("</ol>");
                    html
                }
                "branches" | "tags" | "releases" => {
                    let mut html = mrml_runtime::mrml_format!("<h1>{}</h1><ul>", escape(kind));
                    for (name, oid) in summary.refs {
                        html.push_str("<li><code>");
                        html.push_str(&escape(name.as_str()));
                        html.push_str("</code> ");
                        html.push_str(&oid.hex());
                        html.push_str("</li>");
                    }
                    html.push_str("</ul>");
                    html
                }
                "signatures" => verification_html(&self.backend.verification_summary(
                    &repository,
                    object.clone(),
                    self.trust,
                    self.revocations,
                )?),
                _ if kind == "api" || pieces[0] == "api" => return Err(BackendError::NotFound),
                _ => return Err(BackendError::NotFound),
            };
            let page = document(&repository.as_str(), &content, target, true);
            let prepared = CachedRepresentation::prepare(page.as_bytes())?;
            self.cache.insert(&context, prepared)?;
            Ok(representation_response(
                request,
                self.cache.get(&context).ok_or(BackendError::Storage)?,
                true,
            ))
        })();
        self.flights.complete(permit)?;
        result
    }
    fn git_route(
        &mut self,
        request: &RequestHead,
        _repository: RepositoryIdentity,
        _generation: RepositoryGeneration,
        _pieces: &[&str],
    ) -> Result<GitdHttpResponse, BackendError> {
        let mut input = EmptySmartGitInput;
        let mut output = BufferedSmartGitOutput::new(SMART_GIT_MEMORY_LIMIT as usize);
        let (prepared, mut response) =
            self.prepare_smart_git(request, input.remaining(), output.remaining())?;
        self.execute_prepared_smart_git(prepared, &mut input, &mut output)?;
        response.body = output.bytes;
        set_header(
            &mut response.headers,
            "content-length",
            &mrml_runtime::mrml_format!("{}", response.body.len()),
        )?;
        Ok(response)
    }
    fn html_page(
        &mut self,
        request: &RequestHead,
        title: &str,
        description: &str,
        content: &str,
        index: bool,
        canonical_path: &str,
        key: &str,
    ) -> Result<GitdHttpResponse, BackendError> {
        let key = static_cache_key(key)?;
        if self.cache.get(&key).is_none() {
            let page = document(
                title,
                &mrml_runtime::mrml_format!("<h1>{}</h1>{}", escape(description), content),
                canonical_path,
                index,
            );
            self.cache
                .insert(&key, CachedRepresentation::prepare(page.as_bytes())?)?;
        }
        Ok(representation_response(
            request,
            self.cache.get(&key).ok_or(BackendError::Storage)?,
            index,
        ))
    }
    fn text(
        &self,
        status: u16,
        content_type: &str,
        body: &[u8],
        noindex: bool,
    ) -> Result<GitdHttpResponse, BackendError> {
        let mut headers = security_headers(noindex)?;
        set_header(&mut headers, "content-type", content_type)?;
        set_header(
            &mut headers,
            "content-length",
            &mrml_runtime::mrml_format!("{}", body.len()),
        )?;
        let mut owned = Vector::new();
        owned
            .try_extend_from_slice(body)
            .map_err(|_| BackendError::ResourceLimit)?;
        Ok(GitdHttpResponse {
            status,
            headers,
            body: owned,
        })
    }
    fn error(&self, status: u16, message: &str) -> GitdHttpResponse {
        self.text(
            status,
            "text/plain; charset=utf-8",
            message.as_bytes(),
            true,
        )
        .unwrap_or(GitdHttpResponse {
            status: 503,
            headers: Vector::new(),
            body: Vector::new(),
        })
    }
}

fn parse_candidate_id(input: &str) -> Result<[u8; 16], BackendError> {
    if input.len() != 32 {
        return Err(BackendError::NotFound);
    }
    let mut output = [0u8; 16];
    for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
        let high = lowercase_hex(pair[0]).ok_or(BackendError::NotFound)?;
        let low = lowercase_hex(pair[1]).ok_or(BackendError::NotFound)?;
        output[index] = (high << 4) | low;
    }
    if output == [0; 16] {
        return Err(BackendError::NotFound);
    }
    Ok(output)
}

const fn lowercase_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn key_field(output: &mut Text, name: &str, value: &str) -> Result<(), BackendError> {
    if name.len() > 64 || value.len() > MAX_PATH {
        return Err(BackendError::ResourceLimit);
    }
    output.push_str(name);
    output.push('=');
    output.push_str(&mrml_runtime::mrml_format!("{}:", value.len()));
    output.push_str(value);
    output.push('|');
    Ok(())
}

fn static_cache_key(name: &str) -> Result<Text, BackendError> {
    let mut output: Text = "gitd-representation-v3|".into();
    for (field, value) in [
        ("static", name),
        ("renderer", RENDERER_VERSION),
        ("template", TEMPLATE_VERSION),
        ("theme", THEME_VERSION),
        ("encoding", ENCODING_PROFILE_VERSION),
    ] {
        key_field(&mut output, field, value)?;
    }
    Ok(cache_key_digest(&output))
}

#[allow(clippy::too_many_arguments)]
fn representation_cache_key(
    repository: &RepositoryIdentity,
    generation: RepositoryGeneration,
    kind: &str,
    target: &str,
    revision: &str,
    object: &ObjectId,
    trust: TrustGeneration,
    revocations: RevocationGeneration,
) -> Result<Text, BackendError> {
    let mut output: Text = "gitd-representation-v3|".into();
    let generation = mrml_runtime::mrml_format!("{}", generation.0);
    let trust = mrml_runtime::mrml_format!("{}", trust.0);
    let revocations = mrml_runtime::mrml_format!("{}", revocations.0);
    let object = object.hex();
    for (field, value) in [
        ("repository", repository.as_str()),
        ("object-format", "sha256"),
        ("generation", generation.as_str()),
        ("kind", kind),
        ("target", target),
        ("revision", revision),
        ("object", object.as_str()),
        ("markdown", MARKDOWN_PROFILE_VERSION),
        ("renderer", RENDERER_VERSION),
        ("template", TEMPLATE_VERSION),
        ("theme", THEME_VERSION),
        ("sanitizer", SANITIZER_VERSION),
        ("highlighter", HIGHLIGHTER_VERSION),
        ("encoding", ENCODING_PROFILE_VERSION),
        ("trust", trust.as_str()),
        ("revocations", revocations.as_str()),
        ("verifier", VERIFIER_VERSION),
        ("hybrid", HYBRID_PROFILE_VERSION),
    ] {
        key_field(&mut output, field, value)?;
    }
    Ok(cache_key_digest(&output))
}

fn cache_key_digest(material: &str) -> Text {
    let digest = Sha256::digest(material.as_bytes());
    let mut output: Text = "gitd-v3-".into();
    for byte in digest {
        output.push_str(&mrml_runtime::mrml_format!("{byte:02x}"));
    }
    output
}

fn accepts_zstd(request: &RequestHead) -> bool {
    request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("accept-encoding")
            && header.value.split(',').any(|encoding| {
                let mut parameters = encoding.split(';');
                if parameters.next().map(str::trim) != Some("zstd") {
                    return false;
                }
                !parameters.any(|parameter| {
                    let mut pair = parameter.trim().splitn(2, '=');
                    pair.next().map(str::trim) == Some("q")
                        && pair.next().map(str::trim) == Some("0")
                })
            })
    })
}

fn header_contains_etag(request: &RequestHead, etag: &str) -> bool {
    request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("if-none-match")
            && header
                .value
                .split(',')
                .any(|candidate| candidate.trim() == etag)
    })
}

fn representation_response(
    request: &RequestHead,
    representation: &CachedRepresentation,
    index: bool,
) -> GitdHttpResponse {
    let zstd = accepts_zstd(request);
    let selected_etag = if zstd {
        representation.etag_zstd.as_str()
    } else {
        representation.etag_identity.as_str()
    };
    let not_modified = header_contains_etag(request, selected_etag);
    let body = if not_modified {
        Vector::new()
    } else if zstd {
        representation.zstd.clone()
    } else {
        representation.identity.clone()
    };
    let mut headers = security_headers(!index).unwrap_or_default();
    let _ = set_header(&mut headers, "content-type", "text/html; charset=utf-8");
    let _ = set_header(
        &mut headers,
        "content-length",
        &mrml_runtime::mrml_format!("{}", body.len()),
    );
    let _ = set_header(&mut headers, "vary", "accept-encoding");
    let _ = set_header(&mut headers, "etag", selected_etag);
    if zstd {
        let _ = set_header(&mut headers, "content-encoding", "zstd");
    }
    GitdHttpResponse {
        status: if not_modified { 304 } else { 200 },
        headers,
        body,
    }
}

fn security_headers(noindex: bool) -> Result<Vector<Header>, BackendError> {
    let mut headers = Vector::new();
    for (name, value) in [
        (
            "content-security-policy",
            "default-src 'none'; style-src 'self'; img-src 'self' https://raw.mrml.ca; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        ),
    ] {
        set_header(&mut headers, name, value)?;
    }
    if noindex {
        set_header(&mut headers, "x-robots-tag", "noindex, nofollow")?;
    }
    Ok(headers)
}

fn set_header(headers: &mut Vector<Header>, name: &str, value: &str) -> Result<(), BackendError> {
    headers
        .try_push(Header {
            name: name.into(),
            value: value.into(),
        })
        .map_err(|_| BackendError::ResourceLimit)
}

fn single_header<'a>(
    request: &'a RequestHead,
    name: &str,
) -> Result<Option<&'a str>, BackendError> {
    let mut values = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name));
    let value = values.next().map(|header| header.value.as_str());
    if values.next().is_some() {
        return Err(BackendError::MalformedIdentifier);
    }
    Ok(value)
}

fn require_content_type(request: &RequestHead, expected: &str) -> Result<(), BackendError> {
    match single_header(request, "content-type")? {
        Some(value) if value == expected => Ok(()),
        _ => Err(BackendError::Unsupported),
    }
}

fn validate_revision(revision: &str) -> Result<(), BackendError> {
    if revision.is_empty()
        || revision.len() > MAX_REVISION
        || revision
            .bytes()
            .any(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'-' | b'_' | b'.' | b'/'))
        || revision.contains("..")
        || revision.contains("@{")
    {
        Err(BackendError::MalformedRevision)
    } else {
        Ok(())
    }
}

fn escape(input: &str) -> Text {
    let mut output = Text::new();
    for character in input.chars() {
        output.push_str(match character {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            '\'' => "&#39;",
            _ => {
                output.push(character);
                continue;
            }
        });
    }
    output
}

fn document(title: &str, content: &str, canonical_path: &str, index: bool) -> Text {
    let escaped_title = escape(title);
    let mut html = mrml_runtime::mrml_format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{} — MRML</title><meta name=\"description\" content=\"{}\"><link rel=\"canonical\" href=\"https://mrml.ca{}\"><meta property=\"og:title\" content=\"{}\"><meta property=\"og:type\" content=\"website\"><link rel=\"stylesheet\" href=\"/styles.css\">",
        escaped_title,
        escaped_title,
        escape(canonical_path),
        escaped_title
    );
    if !index {
        html.push_str("<meta name=\"robots\" content=\"noindex,nofollow\">");
    }
    html.push_str("</head><body><a class=\"skip-link\" href=\"#content\">Skip to content</a><header><nav aria-label=\"Primary\"><a href=\"/\">MRML</a> <a href=\"/projects\">Projects</a></nav></header><main id=\"content\">");
    html.push_str(content);
    html.push_str("</main><footer><a href=\"/.well-known/security.txt\">Security</a> <a href=\"/privacy.html\">Privacy</a></footer></body></html>");
    html
}

pub fn render_markdown(
    input: &[u8],
    repository: &RepositoryIdentity,
    object: &ObjectId,
) -> Result<Text, BackendError> {
    if input.len() > MAX_MARKDOWN {
        return Err(BackendError::ResourceLimit);
    }
    let source = core::str::from_utf8(input).map_err(|_| BackendError::MalformedPath)?;
    if source.lines().count() > MAX_MARKDOWN_LINES {
        return Err(BackendError::ResourceLimit);
    }
    let mut output = Text::new();
    let mut in_code = false;
    let mut list: Option<&str> = None;
    let mut heading_ids: Vector<Text> = Vector::new();
    let mut lines = source.lines().peekable();
    while let Some(line) = lines.next() {
        if line.starts_with("```") {
            if in_code {
                output.push_str("</code></pre>");
            } else {
                let language = line[3..].trim();
                output.push_str("<pre tabindex=\"0\"><code");
                if let Some(language) = markdown_language(language) {
                    output.push_str(" class=\"language-");
                    output.push_str(language);
                    output.push('"');
                }
                output.push('>');
            }
            in_code = !in_code;
            continue;
        }
        if in_code {
            output.push_str(&escape(line));
            output.push('\n');
            continue;
        }
        if line.contains('|')
            && let Some(separator) = lines.peek()
            && table_separator(separator)?
        {
            if let Some(tag) = list.take() {
                output.push_str("</");
                output.push_str(tag);
                output.push('>');
            }
            lines.next();
            output.push_str("<div class=\"table-scroll\" tabindex=\"0\"><table><thead>");
            render_table_row(&mut output, line, "th", repository, object)?;
            output.push_str("</thead><tbody>");
            while let Some(row) = lines.peek().copied() {
                if row.trim().is_empty() || !row.contains('|') {
                    break;
                }
                lines.next();
                render_table_row(&mut output, row, "td", repository, object)?;
            }
            output.push_str("</tbody></table></div>");
            if output.len() > MAX_RENDERED {
                return Err(BackendError::ResourceLimit);
            }
            continue;
        }
        let hashes = line.bytes().take_while(|byte| *byte == b'#').count();
        if hashes > 0 && hashes <= MAX_HEADING_DEPTH && line.as_bytes().get(hashes) == Some(&b' ') {
            if let Some(tag) = list.take() {
                output.push_str("</");
                output.push_str(tag);
                output.push('>');
            }
            let raw_text = &line[hashes + 1..];
            let text = inline_markdown(raw_text, repository, object)?;
            let heading_id = unique_heading_id(slug(raw_text), &mut heading_ids)?;
            output.push_str(&mrml_runtime::mrml_format!(
                "<h{hashes} id=\"{}\">{}</h{hashes}>",
                heading_id,
                text
            ));
        } else if matches!(line.trim(), "---" | "***" | "___") {
            if let Some(tag) = list.take() {
                output.push_str("</");
                output.push_str(tag);
                output.push('>');
            }
            output.push_str("<hr>");
        } else if let Some(quote) = line.strip_prefix("> ") {
            if let Some(tag) = list.take() {
                output.push_str("</");
                output.push_str(tag);
                output.push('>');
            }
            output.push_str("<blockquote><p>");
            output.push_str(&inline_markdown(quote, repository, object)?);
            output.push_str("</p></blockquote>");
        } else if let Some(item) = line.strip_prefix("- ") {
            if list != Some("ul") {
                if let Some(tag) = list.take() {
                    output.push_str("</");
                    output.push_str(tag);
                    output.push('>');
                }
                output.push_str("<ul>");
                list = Some("ul");
            }
            output.push_str("<li>");
            if let Some(task) = item.strip_prefix("[ ] ") {
                output
                    .push_str("<input type=\"checkbox\" disabled aria-label=\"Incomplete task\"> ");
                output.push_str(&inline_markdown(task, repository, object)?);
            } else if let Some(task) = item
                .strip_prefix("[x] ")
                .or_else(|| item.strip_prefix("[X] "))
            {
                output.push_str(
                    "<input type=\"checkbox\" checked disabled aria-label=\"Completed task\"> ",
                );
                output.push_str(&inline_markdown(task, repository, object)?);
            } else {
                output.push_str(&inline_markdown(item, repository, object)?);
            }
            output.push_str("</li>");
        } else if let Some(item) = ordered_list_item(line) {
            if list != Some("ol") {
                if let Some(tag) = list.take() {
                    output.push_str("</");
                    output.push_str(tag);
                    output.push('>');
                }
                output.push_str("<ol>");
                list = Some("ol");
            }
            output.push_str("<li>");
            output.push_str(&inline_markdown(item, repository, object)?);
            output.push_str("</li>");
        } else if line.trim().is_empty() {
            if let Some(tag) = list.take() {
                output.push_str("</");
                output.push_str(tag);
                output.push('>');
            }
        } else {
            if let Some(tag) = list.take() {
                output.push_str("</");
                output.push_str(tag);
                output.push('>');
            }
            output.push_str("<p>");
            output.push_str(&inline_markdown(line, repository, object)?);
            output.push_str("</p>");
        }
        if output.len() > MAX_RENDERED {
            return Err(BackendError::ResourceLimit);
        }
    }
    if in_code {
        output.push_str("</code></pre>");
    }
    if let Some(tag) = list {
        output.push_str("</");
        output.push_str(tag);
        output.push('>');
    }
    Ok(output)
}

fn table_separator(line: &str) -> Result<bool, BackendError> {
    let trimmed = line.trim().trim_matches('|');
    let mut columns = 0usize;
    for cell in trimmed.split('|') {
        columns += 1;
        if columns > 64 {
            return Err(BackendError::ResourceLimit);
        }
        let cell = cell.trim().trim_matches(':');
        if cell.len() < 3 || !cell.bytes().all(|byte| byte == b'-') {
            return Ok(false);
        }
    }
    Ok(columns > 0)
}

fn render_table_row(
    output: &mut Text,
    line: &str,
    cell_tag: &str,
    repository: &RepositoryIdentity,
    object: &ObjectId,
) -> Result<(), BackendError> {
    output.push_str("<tr>");
    let mut columns = 0usize;
    for cell in line.trim().trim_matches('|').split('|') {
        columns += 1;
        if columns > 64 {
            return Err(BackendError::ResourceLimit);
        }
        output.push('<');
        output.push_str(cell_tag);
        output.push('>');
        output.push_str(&inline_markdown(cell.trim(), repository, object)?);
        output.push_str("</");
        output.push_str(cell_tag);
        output.push('>');
    }
    output.push_str("</tr>");
    Ok(())
}

fn ordered_list_item(line: &str) -> Option<&str> {
    let dot = line.find(". ")?;
    (dot > 0 && dot <= 9 && line[..dot].bytes().all(|byte| byte.is_ascii_digit()))
        .then_some(&line[dot + 2..])
}

fn inline_markdown(
    input: &str,
    repository: &RepositoryIdentity,
    object: &ObjectId,
) -> Result<Text, BackendError> {
    let mut output = Text::new();
    let mut at = 0;
    'inline: while at < input.len() {
        for (marker, open, close) in [
            ("**", "<strong>", "</strong>"),
            ("__", "<strong>", "</strong>"),
            ("~~", "<del>", "</del>"),
            ("*", "<em>", "</em>"),
            ("_", "<em>", "</em>"),
        ] {
            if input[at..].starts_with(marker)
                && let Some(end) = input[at + marker.len()..].find(marker)
                && end > 0
            {
                let end = at + marker.len() + end;
                output.push_str(open);
                output.push_str(&escape(&input[at + marker.len()..end]));
                output.push_str(close);
                at = end + marker.len();
                continue 'inline;
            }
        }
        if input[at..].starts_with("<http")
            && let Some(end) = input[at + 1..].find('>')
        {
            let end = at + 1 + end;
            let url = &input[at + 1..end];
            let resolved = safe_link(url, repository, object)?;
            output.push_str("<a rel=\"nofollow noopener noreferrer\" href=\"");
            output.push_str(&escape(resolved.as_str()));
            output.push_str("\">");
            output.push_str(&escape(url));
            output.push_str("</a>");
            at = end + 1;
            continue;
        }
        if input[at..].starts_with("![")
            && let Some(close) = input[at + 2..].find(']')
            && input.as_bytes().get(at + close + 3) == Some(&b'(')
            && let Some(end) = input[at + close + 4..].find(')')
        {
            let label_end = at + close + 2;
            let url_start = label_end + 2;
            let url_end = url_start + end;
            let label = escape(&input[at + 2..label_end]);
            let url = &input[url_start..url_end];
            if ascii_prefix(url, "https://") || ascii_prefix(url, "http://") {
                let resolved = safe_link(url, repository, object)?;
                output.push_str(
                    "<a class=\"external-image\" rel=\"nofollow noopener noreferrer\" href=\"",
                );
                output.push_str(&escape(resolved.as_str()));
                output.push_str("\">");
                output.push_str(&label);
                output.push_str(" (external image)</a>");
            } else {
                let path = safe_repository_path(url)?;
                output.push_str("<img loading=\"lazy\" referrerpolicy=\"no-referrer\" src=\"https://raw.mrml.ca/");
                output.push_str(&escape(repository.as_str()));
                output.push_str("/raw/");
                output.push_str(&object.hex());
                output.push('/');
                output.push_str(&escape(path.as_str()));
                output.push_str("\" alt=\"");
                output.push_str(&label);
                output.push_str("\">");
            }
            at = url_end + 1;
            continue;
        }
        if input.as_bytes()[at] == b'`'
            && let Some(end) = input[at + 1..].find('`')
        {
            let end = at + 1 + end;
            output.push_str("<code>");
            output.push_str(&escape(&input[at + 1..end]));
            output.push_str("</code>");
            at = end + 1;
            continue;
        }
        if input.as_bytes()[at] == b'['
            && let Some(close) = input[at + 1..].find(']')
            && input.as_bytes().get(at + close + 2) == Some(&b'(')
            && let Some(end) = input[at + close + 3..].find(')')
        {
            let label_end = at + close + 1;
            let url_start = label_end + 2;
            let url_end = url_start + end;
            let url = &input[url_start..url_end];
            let resolved = safe_link(url, repository, object)?;
            output.push_str("<a rel=\"nofollow noopener\" href=\"");
            output.push_str(&escape(resolved.as_str()));
            output.push_str("\">");
            output.push_str(&escape(&input[at + 1..label_end]));
            output.push_str("</a>");
            at = url_end + 1;
            continue;
        }
        let next_link = input[at..].find('[').map(|v| at + v);
        let next_image = input[at..].find("![").map(|v| at + v);
        let next_code = input[at..].find('`').map(|v| at + v);
        let next = match (next_link, next_code) {
            (Some(link), Some(code)) => core::cmp::min(link, code),
            (Some(link), None) => link,
            (None, Some(code)) => code,
            (None, None) => input.len(),
        };
        let next = next_image.map_or(next, |image| core::cmp::min(image, next));
        let mut next = next;
        for marker in ["**", "__", "~~", "*", "_", "<http"] {
            if let Some(found) = input[at..].find(marker) {
                next = core::cmp::min(next, at + found);
            }
        }
        let end = if next == at { at + 1 } else { next };
        output.push_str(&escape(&input[at..end]));
        at = end;
    }
    Ok(output)
}

fn markdown_language(language: &str) -> Option<&'static str> {
    match language {
        "rust" | "rs" => Some("rust"),
        "toml" => Some("toml"),
        "sh" | "bash" => Some("sh"),
        "text" | "console" => Some("text"),
        "json" => Some("json"),
        "html" => Some("html"),
        "css" => Some("css"),
        "javascript" | "js" => Some("javascript"),
        "typescript" | "ts" => Some("typescript"),
        "c" => Some("c"),
        "cpp" | "c++" => Some("cpp"),
        "asm" | "assembly" | "s" => Some("assembly"),
        "yaml" | "yml" => Some("yaml"),
        "powershell" | "ps1" => Some("powershell"),
        "python" | "py" => Some("python"),
        "diff" | "patch" => Some("diff"),
        _ => None,
    }
}

fn unique_heading_id(base: Text, headings: &mut Vector<Text>) -> Result<Text, BackendError> {
    if headings.len() >= MAX_MARKDOWN_LINES {
        return Err(BackendError::ResourceLimit);
    }
    let mut candidate = base.clone();
    let mut suffix = 0usize;
    while headings.iter().any(|heading| heading == &candidate) {
        suffix = suffix.checked_add(1).ok_or(BackendError::ResourceLimit)?;
        candidate = mrml_runtime::mrml_format!("{base}-{suffix}");
    }
    headings
        .try_push(candidate.clone())
        .map_err(|_| BackendError::ResourceLimit)?;
    Ok(candidate)
}

fn safe_link(
    url: &str,
    repository: &RepositoryIdentity,
    object: &ObjectId,
) -> Result<Text, BackendError> {
    if ascii_prefix(url, "javascript:")
        || ascii_prefix(url, "data:")
        || ascii_prefix(url, "file:")
        || url.contains('\0')
        || url.contains('\\')
        || url.starts_with('/')
        || url.split('/').any(|part| part == "..")
        || url.contains('%')
    {
        return Err(BackendError::MalformedPath);
    }
    if ascii_prefix(url, "https://") || ascii_prefix(url, "http://") || ascii_prefix(url, "mailto:")
    {
        return Ok(url.into());
    }
    Ok(mrml_runtime::mrml_format!(
        "/{}/blob/{}/{}",
        repository.as_str(),
        object.hex(),
        url
    ))
}

fn safe_repository_path(path: &str) -> Result<Text, BackendError> {
    if path.is_empty()
        || path.contains(['\0', '\\'])
        || path.starts_with('/')
        || path.contains('%')
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || path.contains(':')
    {
        return Err(BackendError::MalformedPath);
    }
    Ok(path.into())
}

fn ascii_prefix(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}

fn join_path(parts: &[&str]) -> Text {
    let mut output = Text::new();
    for (index, part) in parts.iter().enumerate() {
        if index != 0 {
            output.push('/');
        }
        output.push_str(part);
    }
    output
}

fn slug(value: &str) -> Text {
    let mut slug = Text::new();
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
        } else if (character.is_whitespace() || character == '-') && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        "section".into()
    } else {
        slug
    }
}

fn verification_html(summary: &VerificationSummary) -> Text {
    mrml_runtime::mrml_format!(
        "<h1>Signature verification</h1><section class=\"verification-state\" aria-label=\"Verification status: {}\"><h2>{}</h2><dl><dt>OpenPGP fingerprint</dt><dd><code>{}</code></dd><dt>ML-DSA public-key digest</dt><dd><code>{}</code></dd><dt>Algorithms</dt><dd>{}</dd><dt>Signature hash</dt><dd><code>{}</code></dd><dt>Repository</dt><dd>{}</dd><dt>Purpose</dt><dd>{}</dd><dt>Policy generation</dt><dd>{}</dd><dt>Revocation generation</dt><dd>{}</dd><dt>History since cutover</dt><dd>{}</dd></dl></section>",
        summary.state.label(),
        summary.state.label(),
        escape(summary.openpgp_fingerprint.as_str()),
        escape(summary.ml_dsa_public_key_digest.as_str()),
        escape(summary.algorithms.as_str()),
        escape(summary.signature_hash.as_str()),
        escape(summary.repository.as_str()),
        escape(summary.purpose.as_str()),
        summary.trust_generation.0,
        summary.revocation_generation.0,
        if summary.history_since_cutover_verified {
            "Verified"
        } else {
            "Not verified"
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccessScopes, RepositoryAccessPolicy, RepositoryProfile, TokenAuthority};

    #[derive(Default)]
    struct MockCacheStore {
        key: Vector<u8>,
        value: Vector<u8>,
        removals: usize,
    }

    impl CacheStore for MockCacheStore {
        fn read(&mut self, key: &[u8], output: &mut Vector<u8>) -> Result<bool, BackendError> {
            if self.key != key || self.value.is_empty() {
                return Ok(false);
            }
            output
                .try_extend_from_slice(&self.value)
                .map_err(|_| BackendError::ResourceLimit)?;
            Ok(true)
        }

        fn write_atomic(&mut self, key: &[u8], value: &[u8]) -> Result<(), BackendError> {
            self.key.clear();
            self.value.clear();
            self.key
                .try_extend_from_slice(key)
                .map_err(|_| BackendError::ResourceLimit)?;
            self.value
                .try_extend_from_slice(value)
                .map_err(|_| BackendError::ResourceLimit)
        }

        fn remove_corrupt(&mut self, key: &[u8]) -> Result<(), BackendError> {
            if self.key == key {
                self.value.clear();
            }
            self.removals += 1;
            Ok(())
        }
    }

    struct MockBackend {
        generation: RepositoryGeneration,
    }

    fn oid(byte: u8) -> ObjectId {
        ObjectId([byte; 32])
    }

    impl GitdBackend for MockBackend {
        fn candidate_status(
            &self,
            _repository: &RepositoryIdentity,
            candidate_id: [u8; 16],
        ) -> Result<Vector<u8>, BackendError> {
            if candidate_id == [0x11; 16] {
                let mut response = Vector::new();
                response
                    .try_extend_from_slice(b"candidate-status")
                    .map_err(|_| BackendError::ResourceLimit)?;
                Ok(response)
            } else {
                Err(BackendError::NotFound)
            }
        }

        fn repository_generation(
            &self,
            _repository: &RepositoryIdentity,
        ) -> Result<RepositoryGeneration, BackendError> {
            Ok(self.generation)
        }
        fn repository_summary(
            &self,
            _repository: &RepositoryIdentity,
            _limits: QueryLimits,
        ) -> Result<RepositorySummary, BackendError> {
            Ok(RepositorySummary {
                generation: self.generation,
                default_branch: "main".into(),
                description: "MRML source".into(),
                refs: [
                    ("refs/heads/main".into(), oid(1)),
                    ("refs/tags/v1".into(), oid(2)),
                ]
                .into(),
            })
        }
        fn resolve_ref(
            &self,
            _repository: &RepositoryIdentity,
            revision: &str,
        ) -> Result<ObjectId, BackendError> {
            validate_revision(revision)?;
            Ok(oid(1))
        }
        fn read_commit_page(
            &self,
            _repository: &RepositoryIdentity,
            _commit: ObjectId,
            _limits: QueryLimits,
        ) -> Result<CommitPage, BackendError> {
            Ok(CommitPage {
                generation: self.generation,
                commits: [oid(1), oid(2)].into(),
                next: None,
            })
        }
        fn read_tree_page(
            &self,
            _repository: &RepositoryIdentity,
            _treeish: ObjectId,
            _path: &RepositoryPath,
            _limits: QueryLimits,
        ) -> Result<TreePage, BackendError> {
            Ok(TreePage {
                generation: self.generation,
                entries: [RepositoryPath::parse("README.md").unwrap()].into(),
            })
        }
        fn read_blob_page(
            &self,
            _repository: &RepositoryIdentity,
            _treeish: ObjectId,
            _path: &RepositoryPath,
            _limits: QueryLimits,
        ) -> Result<BlobPage, BackendError> {
            Ok(BlobPage {
                generation: self.generation,
                object: oid(3),
                bytes: (*b"# MRML\n\nSafe **source**.\n").into(),
                complete: true,
            })
        }
        fn verification_summary(
            &self,
            repository: &RepositoryIdentity,
            object: ObjectId,
            policy: TrustGeneration,
            revocations: RevocationGeneration,
        ) -> Result<VerificationSummary, BackendError> {
            Ok(VerificationSummary {
                state: VerificationState::MrmlHybridVerified,
                openpgp_fingerprint: "0123456789ABCDEF".into(),
                ml_dsa_public_key_digest: "abcdef".into(),
                algorithms: "OpenPGP Ed25519 + ML-DSA-65".into(),
                signature_hash: object.hex(),
                repository: repository.clone(),
                purpose: "Git commit".into(),
                trust_generation: policy,
                revocation_generation: revocations,
                history_since_cutover_verified: true,
            })
        }
        fn smart_git(
            &mut self,
            request: SmartGitRequest,
            _input: &mut dyn BoundedRead,
            output: &mut dyn BoundedWrite,
            _budget: WorkBudget,
        ) -> Result<SmartGitResponse, BackendError> {
            let bytes = match request.operation {
                SmartGitOperation::Discovery => b"000eversion 2\n0000".as_slice(),
                SmartGitOperation::ReceiveDiscovery => b"000eversion 2\n0000".as_slice(),
                SmartGitOperation::UploadPack => b"000dpackfile\n0000".as_slice(),
                SmartGitOperation::ReceivePack => b"000eunpack ok\n0000".as_slice(),
            };
            output.write(bytes)?;
            Ok(SmartGitResponse {
                generation: if request.operation == SmartGitOperation::ReceivePack {
                    RepositoryGeneration(request.generation.0 + 1)
                } else {
                    request.generation
                },
                bytes_read: 0,
                bytes_written: bytes.len() as u64,
                refs_activated: request.operation == SmartGitOperation::ReceivePack,
            })
        }
    }

    fn request(method: &str, target: &str, zstd: bool) -> RequestHead {
        let mut headers = Vector::new();
        if zstd {
            headers.push(Header {
                name: "accept-encoding".into(),
                value: "gzip, zstd".into(),
            });
        }
        RequestHead {
            method: method.into(),
            scheme: "https".into(),
            authority: "mrml.ca".into(),
            target: target.into(),
            headers,
        }
    }

    fn smart_request(method: &str, target: &str, content_type: Option<&str>) -> RequestHead {
        let mut request = request(method, target, false);
        request.headers.push(Header {
            name: "git-protocol".into(),
            value: "version=2".into(),
        });
        if let Some(content_type) = content_type {
            request.headers.push(Header {
                name: "content-type".into(),
                value: content_type.into(),
            });
        }
        request
    }

    #[test]
    fn smart_git_routes_share_one_bounded_backend_and_validate_exact_http_metadata() {
        let mut server = GitdHttp3Server::new(
            MockBackend {
                generation: RepositoryGeneration(7),
            },
            4 * 1024 * 1024,
        )
        .unwrap();
        let token_authority = TokenAuthority::new([7; 32]).unwrap();
        let repository = RepositoryIdentity::parse("mitchellrenouf/mrml").unwrap();
        let (mut token, record) = token_authority
            .issue(
                repository.clone(),
                AccessScopes::WRITE,
                1,
                u64::MAX,
                1,
                "route test",
            )
            .unwrap();
        let token = token.reveal_once().unwrap();
        server.configure_authentication(
            GitdAuthentication::new(
                token_authority,
                [RepositoryAccessPolicy {
                    repository,
                    profile: RepositoryProfile::PublicRead,
                    revocation_generation: 1,
                }]
                .into(),
                [record].into(),
            )
            .unwrap(),
        );
        let candidate_target =
            "/mitchellrenouf/mrml.git/mrml-candidate-v1/11111111111111111111111111111111";
        let mut candidate_request = request("GET", candidate_target, false);
        candidate_request.headers.push(Header {
            name: "authorization".into(),
            value: mrml_runtime::mrml_format!("Bearer {token}"),
        });
        let candidate_response = server.handle(&candidate_request);
        assert_eq!(candidate_response.status, 200);
        assert_eq!(&candidate_response.body[..], b"candidate-status");
        assert!(candidate_response.headers.iter().any(|header| {
            header.name == "content-type"
                && header.value == "application/vnd.mrml.git-candidate-status-v1"
        }));
        assert_eq!(server.handle(&request("GET", candidate_target, false)).status, 404);
        for malformed in [
            "/mitchellrenouf/mrml.git/mrml-candidate-v1/00000000000000000000000000000000",
            "/mitchellrenouf/mrml.git/mrml-candidate-v1/1111111111111111111111111111111",
            "/mitchellrenouf/mrml.git/mrml-candidate-v1/1111111111111111111111111111111A",
        ] {
            let mut malformed_request = request("GET", malformed, false);
            malformed_request.headers.push(Header {
                name: "authorization".into(),
                value: mrml_runtime::mrml_format!("Bearer {token}"),
            });
            assert_eq!(server.handle(&malformed_request).status, 404);
        }
        for (method, target, request_type, response_type) in [
            (
                "GET",
                "/mitchellrenouf/mrml.git/info/refs?service=git-upload-pack",
                None,
                "application/x-git-upload-pack-advertisement",
            ),
            (
                "GET",
                "/mitchellrenouf/mrml.git/info/refs?service=git-receive-pack",
                None,
                "application/x-git-receive-pack-advertisement",
            ),
            (
                "POST",
                "/mitchellrenouf/mrml.git/git-upload-pack",
                Some("application/x-git-upload-pack-request"),
                "application/x-git-upload-pack-result",
            ),
            (
                "POST",
                "/mitchellrenouf/mrml.git/git-receive-pack",
                Some("application/x-git-receive-pack-request"),
                "application/x-git-receive-pack-result",
            ),
        ] {
            let mut request = smart_request(method, target, request_type);
            if target.contains("git-receive-pack") {
                request.headers.push(Header {
                    name: "authorization".into(),
                    value: mrml_runtime::mrml_format!("Bearer {token}"),
                });
            }
            let mut input = EmptySmartGitInput;
            let mut output = BufferedSmartGitOutput::new(1024);
            let (prepared, response) = server
                .prepare_smart_git(&request, input.remaining(), output.remaining())
                .unwrap();
            assert!(output.bytes.is_empty(), "preparation wrote route {target}");
            server
                .execute_prepared_smart_git(prepared, &mut input, &mut output)
                .unwrap();
            assert_eq!(response.status, 200, "route {target}");
            assert!(!output.bytes.is_empty());
            assert!(
                response.headers.iter().any(|header| {
                    header.name == "content-type" && header.value == response_type
                })
            );
            assert!(
                response
                    .headers
                    .iter()
                    .any(|header| { header.name == "cache-control" && header.value == "no-store" })
            );
            assert!(
                !response
                    .headers
                    .iter()
                    .any(|header| header.name == "content-length")
            );
        }

        for mut invalid in [
            smart_request(
                "GET",
                "/mitchellrenouf/mrml.git/info/refs?service=git-upload-pack&x=1",
                None,
            ),
            smart_request(
                "POST",
                "/mitchellrenouf/mrml.git/git-upload-pack",
                Some("application/octet-stream"),
            ),
        ] {
            let mut input = EmptySmartGitInput;
            let mut output = BufferedSmartGitOutput::new(1024);
            assert_ne!(
                server
                    .handle_smart_git(&invalid, &mut input, &mut output)
                    .status,
                200
            );
            invalid.headers.push(Header {
                name: "Git-Protocol".into(),
                value: "version=2".into(),
            });
            assert_ne!(
                server
                    .handle_smart_git(&invalid, &mut input, &mut output)
                    .status,
                200
            );
        }
    }

    #[test]
    fn receive_authentication_precedes_body_consumption() {
        struct CountingInput {
            reads: usize,
        }
        impl BoundedRead for CountingInput {
            fn remaining(&self) -> u64 {
                1024
            }
            fn read(&mut self, _output: &mut [u8]) -> Result<usize, BackendError> {
                self.reads += 1;
                Ok(0)
            }
        }
        let mut server = GitdHttp3Server::new(
            MockBackend {
                generation: RepositoryGeneration(7),
            },
            4096,
        )
        .unwrap();
        let request = smart_request(
            "POST",
            "/mitchellrenouf/mrml.git/git-receive-pack",
            Some("application/x-git-receive-pack-request"),
        );
        let mut input = CountingInput { reads: 0 };
        let mut output = BufferedSmartGitOutput::new(1024);
        assert_eq!(
            server
                .handle_smart_git(&request, &mut input, &mut output)
                .status,
            404
        );
        assert_eq!(input.reads, 0);
        assert!(output.bytes.is_empty());
    }

    #[test]
    fn operational_health_distinguishes_liveness_readiness_and_drain() {
        let mut server = GitdHttp3Server::new(
            MockBackend {
                generation: RepositoryGeneration(7),
            },
            4096,
        )
        .unwrap();
        let health = Shared::new(GitdOperationalHealth::starting());
        server.configure_operational_health(health.clone());
        assert_eq!(server.handle(&request("GET", "/health/live", false)).status, 200);
        assert_eq!(
            server.handle(&request("GET", "/health/ready", false)).status,
            503
        );
        health.mark_ready();
        let ready = server.handle(&request("GET", "/health/ready", false));
        assert_eq!(ready.status, 200);
        assert!(ready
            .headers
            .iter()
            .any(|header| header.name == "cache-control" && header.value == "no-store"));
        health.degrade();
        assert_eq!(
            server.handle(&request("GET", "/health/ready", false)).status,
            503
        );
        health.recover_readiness();
        assert_eq!(
            server.handle(&request("GET", "/health/ready", false)).status,
            200
        );
        health.begin_drain();
        assert_eq!(
            server.handle(&request("GET", "/health/ready", false)).status,
            503
        );
        health.fail();
        health.mark_ready();
        assert_eq!(
            server.handle(&request("GET", "/health/ready", false)).status,
            503
        );
    }

    #[test]
    fn every_required_web_route_runs_against_mock_backend() {
        let mut server = GitdHttp3Server::new(
            MockBackend {
                generation: RepositoryGeneration(7),
            },
            4 * 1024 * 1024,
        )
        .unwrap();
        server.set_verification_generations(TrustGeneration(11), RevocationGeneration(13));
        for target in [
            "/",
            "/projects",
            "/mitchellrenouf/mrml",
            "/mitchellrenouf/mrml/tree/main/src",
            "/mitchellrenouf/mrml/blob/main/README.md",
            "/mitchellrenouf/mrml/commits/main",
            "/mitchellrenouf/mrml/commit/aaaaaaaa",
            "/mitchellrenouf/mrml/branches",
            "/mitchellrenouf/mrml/tags",
            "/mitchellrenouf/mrml/releases",
            "/mitchellrenouf/mrml/signatures",
            "/api/v1/projects",
            "/sitemap.xml",
            "/robots.txt",
            "/.well-known/security.txt",
        ] {
            let response = server.handle(&request("GET", target, false));
            assert_eq!(response.status, 200, "route {target}");
            assert!(!response.body.is_empty(), "route {target}");
        }
        let projects = server.handle(&request("GET", "/projects", false));
        assert!(
            core::str::from_utf8(&projects.body)
                .unwrap()
                .contains("<link rel=\"canonical\" href=\"https://mrml.ca/projects\">")
        );
        for target in [
            "/mitchellrenouf/mrml.git/info/refs?service=git-upload-pack",
            "/mitchellrenouf/mrml.git/git-upload-pack",
            "/mitchellrenouf/mrml.git/git-receive-pack",
        ] {
            let method = if target.contains("info/refs") {
                "GET"
            } else {
                "POST"
            };
            let response = server.handle(&request(method, target, false));
            assert_eq!(response.status, 503, "route {target}");
            assert!(
                response
                    .headers
                    .iter()
                    .any(|header| header.name == "x-robots-tag")
            );
        }
    }

    #[test]
    fn cache_hit_serves_precomputed_zstd_without_regeneration() {
        let mut server = GitdHttp3Server::new(
            MockBackend {
                generation: RepositoryGeneration(7),
            },
            4 * 1024 * 1024,
        )
        .unwrap();
        let plain = server.handle(&request("GET", "/mitchellrenouf/mrml", false));
        let generated = server.cache.generation_count;
        let compressed = server.handle(&request("GET", "/mitchellrenouf/mrml", true));
        assert_eq!(server.cache.generation_count, generated);
        assert!(
            compressed
                .headers
                .iter()
                .any(|header| header.name == "content-encoding" && header.value == "zstd")
        );
        assert_ne!(plain.body, compressed.body);
        assert_eq!(
            &mrml_zstd::decode(&compressed.body).unwrap()[..],
            &plain.body[..]
        );

        let home = server.handle(&request("GET", "/", true));
        assert!(
            home.headers
                .iter()
                .any(|header| { header.name == "content-encoding" && header.value == "zstd" })
        );

        let mut no_zstd = request("GET", "/", false);
        no_zstd.headers.push(Header {
            name: "accept-encoding".into(),
            value: "zstd;q=0, gzip".into(),
        });
        let identity = server.handle(&no_zstd);
        assert!(
            !identity
                .headers
                .iter()
                .any(|header| header.name == "content-encoding")
        );

        let etag = home
            .headers
            .iter()
            .find(|header| header.name == "etag")
            .unwrap()
            .value
            .clone();
        let mut conditional = request("GET", "/", true);
        conditional.headers.push(Header {
            name: "if-none-match".into(),
            value: etag,
        });
        let not_modified = server.handle(&conditional);
        assert_eq!(not_modified.status, 304);
        assert!(not_modified.body.is_empty());
    }

    #[test]
    fn persistent_cache_round_trips_and_evicts_corruption() {
        let representation = CachedRepresentation::prepare(b"bounded persistent page").unwrap();
        let mut cache = PersistentRepresentationCache::new(MockCacheStore::default());
        cache
            .store("repository:generation:object", &representation)
            .unwrap();
        assert_eq!(
            cache.load("repository:generation:object").unwrap(),
            Some(representation.clone())
        );
        let mut store = cache.into_store();
        let last = store.value.len() - 1;
        store.value[last] ^= 1;
        let mut cache = PersistentRepresentationCache::new(store);
        assert_eq!(cache.load("repository:generation:object").unwrap(), None);
        let store = cache.into_store();
        assert_eq!(store.removals, 1);
        assert!(store.value.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn linux_cache_store_syncs_atomic_records_and_enforces_quota() {
        let root = mrml_runtime::join_path(
            mrml_runtime::temporary_directory().as_str(),
            mrml_runtime::mrml_format!("mrml-gitd-cache-{}", mrml_runtime::process_id()).as_str(),
        );
        let _ = mrml_runtime::remove_dir_all(root.as_str());
        let store = LinuxFilesystemCacheStore::new(root.as_str(), 1, 1024 * 1024).unwrap();
        let mut cache = PersistentRepresentationCache::new(store);
        let first = CachedRepresentation::prepare(b"first durable page").unwrap();
        let second = CachedRepresentation::prepare(b"second durable page").unwrap();
        cache.store("first", &first).unwrap();
        cache.store("second", &second).unwrap();
        assert_eq!(cache.load("first").unwrap(), None);
        assert_eq!(cache.load("second").unwrap(), Some(second));
        assert!(
            mrml_runtime::read_directory(root.as_str())
                .unwrap()
                .iter()
                .all(|entry| !entry.name.starts_with(".tmp-"))
        );
        mrml_runtime::remove_dir_all(root.as_str()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn linux_cache_store_recovers_interrupted_writes_and_deleted_root() {
        let root = mrml_runtime::join_path(
            mrml_runtime::temporary_directory().as_str(),
            mrml_runtime::mrml_format!("mrml-gitd-cache-recovery-{}", mrml_runtime::process_id())
                .as_str(),
        );
        let _ = mrml_runtime::remove_dir_all(root.as_str());
        mrml_runtime::create_dir_all(root.as_str()).unwrap();
        let stale = mrml_runtime::join_path(root.as_str(), ".tmp-7-9");
        let mut file = mrml_runtime::File::create_new(stale.as_str()).unwrap();
        file.write_all(b"partial").unwrap();
        file.sync().unwrap();
        drop(file);
        let store = LinuxFilesystemCacheStore::new(root.as_str(), 4, 1024 * 1024).unwrap();
        assert!(!mrml_runtime::path_exists(stale.as_str()));
        mrml_runtime::remove_dir_all(root.as_str()).unwrap();
        let mut cache = PersistentRepresentationCache::new(store);
        let value = CachedRepresentation::prepare(b"recreated root").unwrap();
        cache.store("after-delete", &value).unwrap();
        assert_eq!(cache.load("after-delete").unwrap(), Some(value));
        mrml_runtime::remove_dir_all(root.as_str()).unwrap();
    }

    #[test]
    fn single_flight_elects_one_generator_and_rejects_stale_completion() {
        let mut flights = RepresentationSingleFlight::new(1).unwrap();
        let SingleFlightDecision::Generate(first) = flights.begin("key-a").unwrap() else {
            panic!("first miss was not elected")
        };
        assert_eq!(flights.begin("key-a"), Ok(SingleFlightDecision::InProgress));
        assert_eq!(flights.begin("key-b"), Err(BackendError::ResourceLimit));
        flights.complete(first).unwrap();
        assert_eq!(flights.active(), 0);
        assert_eq!(flights.complete(first), Err(BackendError::StaleGeneration));
        assert!(matches!(
            flights.begin("key-a"),
            Ok(SingleFlightDecision::Generate(_))
        ));
    }

    #[test]
    fn markdown_escapes_active_content_and_rejects_unsafe_links() {
        let repository = RepositoryIdentity::parse("mitchellrenouf/mrml").unwrap();
        let rendered = render_markdown(
            b"# Heading\n\n<script>alert(1)</script>\n\n[safe](docs/README.md)",
            &repository,
            &oid(1),
        )
        .unwrap();
        assert!(rendered.contains("&lt;script&gt;"));
        assert!(!rendered.contains("<script>"));
        assert!(rendered.contains("/mitchellrenouf/mrml/blob/"));
        let structured = render_markdown(
            b"# Repeat\n# Repeat\n\nUse `<tag>`.\n\n```rust\nfn main() { <unsafe> }\n```\n```unknown\n<script>\n```",
            &repository,
            &oid(1),
        )
        .unwrap();
        assert!(structured.contains("id=\"repeat\""));
        assert!(structured.contains("id=\"repeat-1\""));
        assert!(structured.contains("<code>&lt;tag&gt;</code>"));
        assert!(structured.contains("<code class=\"language-rust\">"));
        assert!(!structured.contains("language-unknown"));
        assert!(!structured.contains("<script>"));
        let images = render_markdown(
            b"![local](docs/diagram.png) ![remote](https://example.test/pixel.png)",
            &repository,
            &oid(1),
        )
        .unwrap();
        assert!(images.contains("https://raw.mrml.ca/mitchellrenouf/mrml/raw/"));
        assert!(images.contains("referrerpolicy=\"no-referrer\""));
        assert!(!images.contains(
            "<img loading=\"lazy\" referrerpolicy=\"no-referrer\" src=\"https://example.test"
        ));
        assert!(images.contains("class=\"external-image\""));
        assert!(images.contains("href=\"https://example.test/pixel.png\""));
        assert!(images.contains("(external image)</a>"));
        let profile = render_markdown(
            b"**strong** *emphasis* ~~removed~~ <https://example.test/doc>\n\n> quoted\n\n---\n\n1. first\n2. second\n\n- [ ] pending\n- [x] complete",
            &repository,
            &oid(1),
        )
        .unwrap();
        for expected in [
            "<strong>strong</strong>",
            "<em>emphasis</em>",
            "<del>removed</del>",
            "href=\"https://example.test/doc\"",
            "<blockquote><p>quoted</p></blockquote>",
            "<hr>",
            "<ol><li>first</li><li>second</li></ol>",
            "aria-label=\"Incomplete task\"",
            "aria-label=\"Completed task\"",
        ] {
            assert!(profile.contains(expected), "missing {expected}: {profile}");
        }
        let table = render_markdown(
            b"| Name | State |\n| --- | --- |\n| edge | **ready** |",
            &repository,
            &oid(1),
        )
        .unwrap();
        assert!(table.contains("<div class=\"table-scroll\" tabindex=\"0\"><table>"));
        assert!(table.contains("<th>Name</th><th>State</th>"));
        assert!(table.contains("<td>edge</td><td><strong>ready</strong></td>"));
        let mut wide_header = Text::new();
        let mut wide_separator = Text::new();
        for _ in 0..65 {
            wide_header.push_str("|x");
            wide_separator.push_str("|---");
        }
        wide_header.push_str("|\n");
        wide_header.push_str(&wide_separator);
        wide_header.push('|');
        assert_eq!(
            render_markdown(wide_header.as_bytes(), &repository, &oid(1)),
            Err(BackendError::ResourceLimit)
        );
        for unsafe_url in [
            "javascript:alert(1)",
            "data:text/html,x",
            "file:/etc/passwd",
            "../secret",
            "%2e%2e/secret",
        ] {
            let markdown = mrml_runtime::mrml_format!("[x]({unsafe_url})");
            assert_eq!(
                render_markdown(markdown.as_bytes(), &repository, &oid(1)),
                Err(BackendError::MalformedPath)
            );
        }
        for unsafe_image in ["../secret.png", "data:image/svg+xml,x", "/host/path.png"] {
            let markdown = mrml_runtime::mrml_format!("![x]({unsafe_image})");
            assert_eq!(
                render_markdown(markdown.as_bytes(), &repository, &oid(1)),
                Err(BackendError::MalformedPath)
            );
        }
    }

    #[test]
    fn verification_cache_key_binds_policy_and_revocation_generations() {
        let mut server = GitdHttp3Server::new(
            MockBackend {
                generation: RepositoryGeneration(7),
            },
            4 * 1024 * 1024,
        )
        .unwrap();
        server.set_verification_generations(TrustGeneration(1), RevocationGeneration(2));
        let first = server.handle(&request("GET", "/mitchellrenouf/mrml/signatures", false));
        let count = server.cache.generation_count;
        server.set_verification_generations(TrustGeneration(2), RevocationGeneration(1));
        let second = server.handle(&request("GET", "/mitchellrenouf/mrml/signatures", false));
        assert_eq!(first.status, 200);
        assert_eq!(second.status, 200);
        assert!(server.cache.generation_count > count);

        let repository = RepositoryIdentity::parse("mitchellrenouf/mrml").unwrap();
        let first_key = representation_cache_key(
            &repository,
            RepositoryGeneration(7),
            "blob",
            "/mitchellrenouf/mrml/blob/main/README.md",
            "main",
            &oid(9),
            TrustGeneration(1),
            RevocationGeneration(2),
        )
        .unwrap();
        let second_key = representation_cache_key(
            &repository,
            RepositoryGeneration(7),
            "blob",
            "/mitchellrenouf/mrml/blob/main/docs/README.md",
            "main",
            &oid(9),
            TrustGeneration(2),
            RevocationGeneration(1),
        )
        .unwrap();
        assert_ne!(first_key, second_key);
        assert!(first_key.starts_with("gitd-v3-"));
        assert_eq!(first_key.len(), 72);
    }

    #[test]
    fn configured_operation_limits_are_shared_independent_and_release_on_drop() {
        let limits = Shared::new(GitdOperationLimits::new(2, 1).unwrap());
        assert!(
            GitdOperationLimits::try_acquire(&limits, SmartGitOperation::Discovery)
                .unwrap()
                .is_none()
        );

        let upload_one = GitdOperationLimits::try_acquire(&limits, SmartGitOperation::UploadPack)
            .unwrap()
            .unwrap();
        let upload_two = GitdOperationLimits::try_acquire(&limits, SmartGitOperation::UploadPack)
            .unwrap()
            .unwrap();
        assert!(matches!(
            GitdOperationLimits::try_acquire(&limits, SmartGitOperation::UploadPack),
            Err(BackendError::ResourceLimit)
        ));

        let receive = GitdOperationLimits::try_acquire(&limits, SmartGitOperation::ReceivePack)
            .unwrap()
            .unwrap();
        assert!(matches!(
            GitdOperationLimits::try_acquire(&limits, SmartGitOperation::ReceivePack),
            Err(BackendError::ResourceLimit)
        ));
        assert_eq!(limits.upload_metrics().current_usage, 2);
        assert_eq!(limits.receive_metrics().current_usage, 1);

        drop(upload_one);
        let replacement = GitdOperationLimits::try_acquire(&limits, SmartGitOperation::UploadPack)
            .unwrap()
            .unwrap();
        drop(upload_two);
        drop(replacement);
        drop(receive);

        assert_eq!(
            limits.upload_metrics(),
            GitdOperationLimitMetrics {
                configured_maximum: 2,
                current_usage: 0,
                rejections: 1,
                wait_nanoseconds: 0,
                permit_leak_assertion_failures: 0,
            }
        );
        assert_eq!(
            limits.receive_metrics(),
            GitdOperationLimitMetrics {
                configured_maximum: 1,
                current_usage: 0,
                rejections: 1,
                wait_nanoseconds: 0,
                permit_leak_assertion_failures: 0,
            }
        );

        let cancellation_permit =
            GitdOperationLimits::try_acquire(&limits, SmartGitOperation::UploadPack).unwrap();
        let cancelled = PreparedSmartGitRequest {
            request: SmartGitRequest {
                repository: RepositoryIdentity::parse("mitchellrenouf/mrml").unwrap(),
                generation: RepositoryGeneration(7),
                operation: SmartGitOperation::UploadPack,
            },
            budget: WorkBudget {
                max_input_bytes: 0,
                max_output_bytes: 0,
                max_memory_bytes: 1,
                max_work_units: 1,
            },
            _operation_permit: cancellation_permit,
        };
        assert_eq!(limits.upload_metrics().current_usage, 1);
        drop(cancelled);
        assert_eq!(limits.upload_metrics().current_usage, 0);

        let failure_permit =
            GitdOperationLimits::try_acquire(&limits, SmartGitOperation::UploadPack).unwrap();
        let failed = PreparedSmartGitRequest {
            request: SmartGitRequest {
                repository: RepositoryIdentity::parse("mitchellrenouf/mrml").unwrap(),
                generation: RepositoryGeneration(7),
                operation: SmartGitOperation::UploadPack,
            },
            budget: WorkBudget {
                max_input_bytes: 0,
                max_output_bytes: 0,
                max_memory_bytes: 1,
                max_work_units: 1,
            },
            _operation_permit: failure_permit,
        };
        let mut server = GitdHttp3Server::new(
            MockBackend {
                generation: RepositoryGeneration(7),
            },
            1024,
        )
        .unwrap();
        let mut input = EmptySmartGitInput;
        let mut output = BufferedSmartGitOutput::new(0);
        assert_eq!(
            server.execute_prepared_smart_git(failed, &mut input, &mut output),
            Err(BackendError::ResourceLimit)
        );
        assert_eq!(limits.upload_metrics().current_usage, 0);

        limits.uploads.release();
        assert_eq!(limits.upload_metrics().permit_leak_assertion_failures, 1);
        assert_eq!(limits.upload_metrics().current_usage, 0);
    }
}
