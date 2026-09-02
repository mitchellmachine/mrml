use std::ffi::CString;
use std::path::{Path, PathBuf};

use mrml_git::{
    HistoryVerificationLimits, LinuxDurableReceiveStore, LinuxDurableTrustPolicyStore,
    ObjectFormat, ProtectedReceiveAuthority, QuarantineLimits, QuarantineTransactionId,
};
use mrml_http::{
    BackendError, BoundedRead, BoundedWrite, SmartGitOperation, SmartGitRequest, SmartGitResponse,
    WorkBudget,
};

use crate::{AdmittedRepository, DeploymentRepository, GitdConfig};

pub struct ProductionReceiveRepository {
    policy: PathBuf,
    journals: PathBuf,
    quarantine: PathBuf,
    state: PathBuf,
    plain_receipts: PathBuf,
    authenticated_receipts: PathBuf,
    max_body_bytes: u64,
    max_object_bytes: u64,
}

impl ProductionReceiveRepository {
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
        Ok(Self {
            policy,
            journals: admitted.paths.state.join("receive-journals"),
            quarantine: admitted.paths.quarantine.clone(),
            state: admitted.paths.state.clone(),
            plain_receipts: admitted.paths.receipts.join("plain"),
            authenticated_receipts: admitted.paths.receipts.join("authenticated"),
            max_body_bytes: config.max_body_bytes,
            max_object_bytes: entry.profile.max_object_bytes,
        })
    }

    pub fn execute(
        &self,
        view: &mut mrml_git::FilesystemRepositoryView,
        authority: &mut (dyn ProtectedReceiveAuthority + Send),
        request: SmartGitRequest,
        input: &mut dyn BoundedRead,
        output: &mut dyn BoundedWrite,
        budget: WorkBudget,
    ) -> Result<SmartGitResponse, BackendError> {
        if request.operation != SmartGitOperation::ReceivePack {
            return Err(BackendError::Unsupported);
        }
        let policy = LinuxDurableTrustPolicyStore::open(path(&self.policy)?)
            .and_then(|store| store.load())
            .map_err(|_| BackendError::Private)?;
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
        quarantine_limits.max_expanded_object_bytes = self
            .max_body_bytes
            .checked_mul(4)
            .ok_or(BackendError::ResourceLimit)?;
        let response = view
            .execute_protected_receive(
                mrml_git::SmartGitRequest {
                    repository: mrml_git::RepositoryIdentity::parse(request.repository.as_str())
                        .map_err(map_core_error)?,
                    repository_generation: mrml_git::RepositoryGeneration(request.generation.0),
                    operation: mrml_git::SmartGitOperation::ReceivePack,
                    object_format: ObjectFormat::Sha256,
                },
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
                mrml_git::WorkBudget {
                    max_input_bytes: budget.max_input_bytes,
                    max_output_bytes: budget.max_output_bytes,
                    max_memory_bytes: budget.max_memory_bytes,
                    max_work_units: budget.max_work_units,
                },
            )
            .map_err(map_core_error)?;
        Ok(SmartGitResponse {
            generation: mrml_http::RepositoryGeneration(response.repository_generation.0),
            bytes_read: response.bytes_read,
            bytes_written: response.bytes_written,
            refs_activated: response.refs_activated,
        })
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
    fn live_filesystem_capacity_is_nonzero_and_path_bound() {
        assert!(available_bytes(Path::new("/tmp")).unwrap() > 0);
        assert_eq!(
            available_bytes(Path::new("/definitely/absent/mrml")),
            Err(BackendError::Storage)
        );
    }
}
