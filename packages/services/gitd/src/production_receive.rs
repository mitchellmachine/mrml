use std::ffi::CString;
use std::path::{Path, PathBuf};

use mrml_git::{
    HistoryVerificationLimits, LinuxDurableReceiveStore, LinuxDurableTrustPolicyStore,
    ObjectFormat, ProtectedReceiveAuthority, QuarantineLimits, QuarantineTransactionId,
    DEFAULT_MAX_INCOMING_PACK_BYTES,
};
use mrml_http::{
    BackendError, BoundedRead, BoundedWrite, SmartGitOperation, SmartGitRequest, SmartGitResponse,
    WorkBudget,
};

use crate::{AdmittedRepository, DeploymentRepository, DeploymentRepositoryProfile, GitdConfig};

pub struct ProductionReceiveRepository {
    profile: DeploymentRepositoryProfile,
    policy: Option<PathBuf>,
    journals: PathBuf,
    quarantine: PathBuf,
    state: PathBuf,
    plain_receipts: PathBuf,
    authenticated_receipts: PathBuf,
    max_body_bytes: u64,
    max_object_bytes: u64,
    minimum_free_space_bytes: u64,
}

impl ProductionReceiveRepository {
    pub const fn requires_authority(&self) -> bool {
        matches!(self.profile, DeploymentRepositoryProfile::Protected)
    }

    pub fn candidate_status(
        &self,
        repository: &mrml_git::RepositoryIdentity,
        id: QuarantineTransactionId,
        authority: &mut dyn ProtectedReceiveAuthority,
    ) -> Result<mrml_runtime::Vector<u8>, BackendError> {
        if !self.requires_authority() {
            return Err(BackendError::NotFound);
        }
        let record = authority
            .query_candidate_by_id(repository, id)
            .map_err(|_| BackendError::NotFound)?;
        let authenticated_receipt = if matches!(
            record.status,
            mrml_git::AuthorityCandidateStatus::ReceiptPersisted
                | mrml_git::AuthorityCandidateStatus::Completed
        ) {
            let directory = mrml_git::AuthenticatedAuditReceiptDirectory::open(path(
                &self.authenticated_receipts,
            )?)
            .map_err(|_| BackendError::NotFound)?;
            let receipt = directory
                .load(id, authority)
                .map_err(|_| BackendError::NotFound)?;
            Some(
                mrml_git::encode_authenticated_audit_receipt(&receipt)
                    .map_err(|_| BackendError::Storage)?,
            )
        } else {
            None
        };
        mrml_git::encode_authority_candidate_status_result(
            &mrml_git::AuthorityCandidateStatusResult {
                record,
                authenticated_receipt,
            },
        )
        .map_err(|_| BackendError::Storage)
    }

    pub fn new(
        config: &GitdConfig,
        entry: &DeploymentRepository,
        admitted: &AdmittedRepository,
    ) -> Result<Self, BackendError> {
        let (owner, repository) = entry
            .repository
            .as_str()
            .split_once('/')
            .ok_or(BackendError::MalformedIdentifier)?;
        let policy = if entry.profile.class == DeploymentRepositoryProfile::Protected {
            let policy = config.policy_root.join(owner).join(repository);
            if !policy.is_dir()
                || policy
                    .symlink_metadata()
                    .map_err(|_| BackendError::Storage)?
                    .file_type()
                    .is_symlink()
            {
                return Err(BackendError::Storage);
            }
            Some(policy)
        } else {
            None
        };
        Ok(Self {
            profile: entry.profile.class,
            policy,
            journals: admitted.paths.state.join("receive-journals"),
            quarantine: admitted.paths.quarantine.clone(),
            state: admitted.paths.state.clone(),
            plain_receipts: admitted.paths.receipts.join("plain"),
            authenticated_receipts: admitted.paths.receipts.join("authenticated"),
            max_body_bytes: receive_pack_limit(config.max_body_bytes),
            max_object_bytes: entry.profile.max_object_bytes,
            minimum_free_space_bytes: config.minimum_free_space_bytes,
        })
    }

    pub fn execute(
        &self,
        view: &mut mrml_git::FilesystemRepositoryView,
        authority: Option<&mut (dyn ProtectedReceiveAuthority + Send)>,
        request: SmartGitRequest,
        input: &mut dyn BoundedRead,
        output: &mut dyn BoundedWrite,
        budget: WorkBudget,
    ) -> Result<SmartGitResponse, BackendError> {
        if request.operation != SmartGitOperation::ReceivePack {
            return Err(BackendError::Unsupported);
        }
        let mut store = LinuxDurableReceiveStore::open(
            path(&self.journals)?,
            path(&self.quarantine)?,
            path(&self.state)?,
            path(&self.plain_receipts)?,
            ObjectFormat::Sha256,
            self.max_body_bytes,
        )
        .map_err(|_| BackendError::Storage)?;
        let mut transaction = [0u8; 16];
        mrml_runtime::fill_random(&mut transaction).map_err(|_| BackendError::Storage)?;
        let mut quarantine_limits = QuarantineLimits::default();
        quarantine_limits.max_incoming_pack_bytes = self.max_body_bytes;
        quarantine_limits.max_individual_object_bytes = self.max_object_bytes;
        quarantine_limits.minimum_free_space_bytes = self.minimum_free_space_bytes;
        quarantine_limits.max_expanded_object_bytes = self
            .max_body_bytes
            .checked_mul(4)
            .ok_or(BackendError::ResourceLimit)?;
        let core_request = mrml_git::SmartGitRequest {
            repository: mrml_git::RepositoryIdentity::parse(request.repository.as_str())
                .map_err(map_core_error)?,
            repository_generation: mrml_git::RepositoryGeneration(request.generation.0),
            operation: mrml_git::SmartGitOperation::ReceivePack,
            object_format: ObjectFormat::Sha256,
        };
        let core_budget = mrml_git::WorkBudget {
            max_input_bytes: budget.max_input_bytes,
            max_output_bytes: budget.max_output_bytes,
            max_memory_bytes: budget.max_memory_bytes,
            max_work_units: budget.max_work_units,
        };
        let response = if self.profile == DeploymentRepositoryProfile::Protected {
            let authority = authority.ok_or(BackendError::Unsupported)?;
            let policy_path = self.policy.as_ref().ok_or(BackendError::Private)?;
            let policy = LinuxDurableTrustPolicyStore::open(path(policy_path)?)
                .and_then(|store| store.load())
                .map_err(|_| BackendError::Private)?;
            view.execute_protected_receive(
                core_request,
                &mut store,
                &policy,
                path(&self.authenticated_receipts)?,
                authority,
                QuarantineTransactionId(transaction),
                quarantine_limits,
                HistoryVerificationLimits::default(),
                available_bytes(&self.quarantine)?,
                &mut ReadBridge(input),
                &mut WriteBridge(output),
                core_budget,
            )
        } else {
            view.execute_conventional_receive(
                core_request,
                &mut store,
                QuarantineTransactionId(transaction),
                quarantine_limits,
                HistoryVerificationLimits::default(),
                available_bytes(&self.quarantine)?,
                &mut ReadBridge(input),
                &mut WriteBridge(output),
                core_budget,
            )
        }
        .map_err(map_core_error)?;
        Ok(SmartGitResponse {
            generation: mrml_http::RepositoryGeneration(response.repository_generation.0),
            bytes_read: response.bytes_read,
            bytes_written: response.bytes_written,
            refs_activated: response.refs_activated,
        })
    }
}

pub(crate) const fn receive_pack_limit(max_body_bytes: u64) -> u64 {
    if max_body_bytes < DEFAULT_MAX_INCOMING_PACK_BYTES {
        max_body_bytes
    } else {
        DEFAULT_MAX_INCOMING_PACK_BYTES
    }
}

struct ReadBridge<'a>(&'a mut dyn BoundedRead);
impl mrml_git::BoundedRead for ReadBridge<'_> {
    fn remaining(&self) -> u64 {
        self.0.remaining()
    }
    fn read(&mut self, output: &mut [u8]) -> Result<usize, mrml_git::GitdCoreError> {
        self.0
            .read(output)
            .map_err(|_| mrml_git::GitdCoreError::Resource)
    }
}

struct WriteBridge<'a>(&'a mut dyn BoundedWrite);
impl mrml_git::BoundedWrite for WriteBridge<'_> {
    fn remaining(&self) -> u64 {
        self.0.remaining()
    }
    fn write(&mut self, input: &[u8]) -> Result<(), mrml_git::GitdCoreError> {
        self.0
            .write(input)
            .map_err(|_| mrml_git::GitdCoreError::Resource)
    }
}

fn path(path: &Path) -> Result<&str, BackendError> {
    path.to_str().ok_or(BackendError::Storage)
}

fn map_core_error(error: mrml_git::GitdCoreError) -> BackendError {
    eprintln!(
        "component=mrml-gitd event={}",
        core_receive_error_event(error)
    );
    match error {
        mrml_git::GitdCoreError::MalformedIdentifier => BackendError::MalformedIdentifier,
        mrml_git::GitdCoreError::MalformedPath => BackendError::MalformedPath,
        mrml_git::GitdCoreError::MalformedInput | mrml_git::GitdCoreError::MalformedRef => {
            BackendError::MalformedRevision
        }
        mrml_git::GitdCoreError::StaleGeneration => BackendError::StaleGeneration,
        mrml_git::GitdCoreError::Resource => BackendError::ResourceLimit,
        mrml_git::GitdCoreError::Unsupported => BackendError::Unsupported,
        mrml_git::GitdCoreError::Authorization
        | mrml_git::GitdCoreError::Ancestry
        | mrml_git::GitdCoreError::Signature
        | mrml_git::GitdCoreError::Policy => BackendError::Private,
        mrml_git::GitdCoreError::ObjectValidation => BackendError::NotFound,
        mrml_git::GitdCoreError::Storage | mrml_git::GitdCoreError::UncertainCommit => {
            BackendError::Storage
        }
    }
}

const fn core_receive_error_event(error: mrml_git::GitdCoreError) -> &'static str {
    match error {
        mrml_git::GitdCoreError::MalformedIdentifier => "receive_core_malformed_identifier",
        mrml_git::GitdCoreError::MalformedPath => "receive_core_malformed_path",
        mrml_git::GitdCoreError::MalformedInput => "receive_core_malformed_input",
        mrml_git::GitdCoreError::MalformedRef => "receive_core_malformed_ref",
        mrml_git::GitdCoreError::StaleGeneration => "receive_core_stale_generation",
        mrml_git::GitdCoreError::Resource => "receive_core_resource_limit",
        mrml_git::GitdCoreError::Unsupported => "receive_core_unsupported",
        mrml_git::GitdCoreError::Authorization => "receive_core_authorization",
        mrml_git::GitdCoreError::Ancestry => "receive_core_ancestry",
        mrml_git::GitdCoreError::Signature => "receive_core_signature",
        mrml_git::GitdCoreError::Policy => "receive_core_policy",
        mrml_git::GitdCoreError::ObjectValidation => "receive_core_object_validation",
        mrml_git::GitdCoreError::Storage => "receive_core_storage",
        mrml_git::GitdCoreError::UncertainCommit => "receive_core_uncertain_commit",
    }
}

#[repr(C)]
struct StatVfs {
    block_size: u64,
    fragment_size: u64,
    blocks: u64,
    blocks_free: u64,
    blocks_available: u64,
    files: u64,
    files_free: u64,
    files_available: u64,
    filesystem_id: u64,
    mount_flags: u64,
    maximum_name: u64,
    spare: [i32; 6],
}

unsafe extern "C" {
    fn statvfs(path: *const core::ffi::c_char, output: *mut StatVfs) -> i32;
}

fn available_bytes(path: &Path) -> Result<u64, BackendError> {
    let encoded =
        CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| BackendError::Storage)?;
    let mut status = core::mem::MaybeUninit::<StatVfs>::uninit();
    if unsafe { statvfs(encoded.as_ptr(), status.as_mut_ptr()) } != 0 {
        return Err(BackendError::Storage);
    }
    let status = unsafe { status.assume_init() };
    status
        .blocks_available
        .checked_mul(status.fragment_size)
        .ok_or(BackendError::ResourceLimit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_pack_limit_is_independent_from_larger_http_body_limit() {
        assert_eq!(receive_pack_limit(1024), 1024);
        assert_eq!(
            receive_pack_limit(8 * 1024 * 1024 * 1024),
            DEFAULT_MAX_INCOMING_PACK_BYTES
        );
    }

    #[test]
    fn live_filesystem_capacity_is_nonzero_and_path_bound() {
        assert!(available_bytes(Path::new("/tmp")).unwrap() > 0);
        assert_eq!(
            available_bytes(Path::new("/definitely/absent/mrml")),
            Err(BackendError::Storage)
        );
    }
}
