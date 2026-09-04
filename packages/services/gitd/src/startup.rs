use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use mrml_git::{
    AuditReceiptAuthority, AuthenticatedAuditReceiptDirectory, AuthenticatedReceiveStore,
    AuthorizedHybridPair, FilesystemRepositoryView, FullRefName, GitdCoreError,
    LinuxDurableReceiveStore,
    LinuxDurableTrustPolicyStore, ObjectFormat, PolicyPairStatus, RecoveryAction,
    TrustPolicyCandidate, TrustPolicyState,
};
use mrml_openpgp::PublicKeyV6;
use mrml_runtime::{DirectoryCapability, DirectoryMetadata, Vector};

use crate::{
    DeploymentRepository, DeploymentRepositoryProfile, GitdConfig,
    production_receive::receive_pack_limit, verify_repository_admission,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupValidationError {
    Missing,
    Symlink,
    Type,
    Owner,
    Permissions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryStoragePaths {
    pub objects: PathBuf,
    pub state: PathBuf,
    pub quarantine: PathBuf,
    pub cache: PathBuf,
    pub receipts: PathBuf,
}

pub struct RepositoryStorageCapabilities {
    pub objects: DirectoryCapability,
    pub state: DirectoryCapability,
    pub quarantine: DirectoryCapability,
    pub cache: DirectoryCapability,
    pub receipts: DirectoryCapability,
    pub policy: Option<DirectoryCapability>,
}

pub struct AdmittedRepository {
    pub paths: RepositoryStoragePaths,
    pub capabilities: RepositoryStorageCapabilities,
    pub view: FilesystemRepositoryView,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryAdmissionError {
    Identity,
    Layout(StartupValidationError),
    Open,
    Objects,
    State,
    Quarantine,
    Cache,
    Receipts,
    Policy,
    View,
    Arrival(GitdCoreError),
    Generation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryInitializationError {
    Identity,
    Layout,
    Exists,
    Create,
    Initialize,
    Verify,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedPolicyInitializationError {
    Profile,
    Validity,
    Admission,
    Path,
    Layout,
    Create,
    Policy,
    Exists,
    Verify,
}

pub fn initialize_catalog_protected_policy(
    config: &GitdConfig,
    entry: &DeploymentRepository,
    openpgp: &PublicKeyV6,
    ml_dsa: &[u8; mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES],
    valid_from: u64,
    valid_until: u64,
) -> Result<mrml_git::ObjectId, ProtectedPolicyInitializationError> {
    if entry.profile.class != DeploymentRepositoryProfile::Protected {
        return Err(ProtectedPolicyInitializationError::Profile);
    }
    if valid_from == 0 || valid_from >= valid_until {
        return Err(ProtectedPolicyInitializationError::Validity);
    }
    let admitted = admit_catalog_repository(config, entry).map_err(|error| {
        eprintln!(
            "component=mrml-gitd event=policy_initialization_admission_failed category={error:?}"
        );
        ProtectedPolicyInitializationError::Admission
    })?;
    let tip = admitted
        .view
        .resolve_ref(&entry.repository, "refs/heads/main")
        .map_err(|_| ProtectedPolicyInitializationError::Admission)?;
    let pair = AuthorizedHybridPair::bind(openpgp, ml_dsa);
    let policy = TrustPolicyState::establish(TrustPolicyCandidate {
        repository: entry.repository.clone(),
        generation: entry.trust_generation,
        previous_policy_digest: [0; 64],
        revocation_generation: entry.revocation_generation,
        protected_refs: [FullRefName::parse("refs/heads/main")
            .map_err(|_| ProtectedPolicyInitializationError::Policy)?]
        .into(),
        allow_sha1: false,
        allow_sha256: true,
        hybrid_required: true,
        legacy_checkpoint: None,
        hybrid_cutover: Some(tip),
        emergency_policy_digest: None,
        active_pairs: [pair].into(),
        pair_statuses: [PolicyPairStatus::new(pair, valid_from, valid_until, None)
            .map_err(|_| ProtectedPolicyInitializationError::Policy)?]
        .into(),
        legacy_v4_statuses: Vector::new(),
        revoked_legacy_v4: Vector::new(),
        revoked_openpgp: Vector::new(),
        revoked_ml_dsa: Vector::new(),
    })
    .map_err(|_| ProtectedPolicyInitializationError::Policy)?;
    let (owner, repository) = entry
        .repository
        .as_str()
        .split_once('/')
        .ok_or(ProtectedPolicyInitializationError::Path)?;
    let (owner_directory, policy_directory) = create_policy_directory(
        &config.policy_root,
        owner,
        repository,
        config.gitd_uid,
        config.gitd_gid,
    )?;
    match LinuxDurableTrustPolicyStore::create_capability(policy_directory, &policy) {
        Ok(store) => {
            if store
                .load()
                .map_err(|_| ProtectedPolicyInitializationError::Verify)?
                != policy
            {
                return Err(ProtectedPolicyInitializationError::Verify);
            }
            Ok(tip)
        }
        Err(mrml_git::TrustPolicyFileError::AlreadyExists) => {
            let _ = owner_directory.remove_directory(repository);
            Err(ProtectedPolicyInitializationError::Exists)
        }
        Err(_) => {
            let _ = owner_directory.remove_directory(repository);
            Err(ProtectedPolicyInitializationError::Policy)
        }
    }
}

fn create_policy_directory(
    root_path: &Path,
    owner: &str,
    repository: &str,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(DirectoryCapability, DirectoryCapability), ProtectedPolicyInitializationError> {
    let root = DirectoryCapability::open_root(
        root_path
            .to_str()
            .ok_or(ProtectedPolicyInitializationError::Path)?,
    )
    .map_err(|_| ProtectedPolicyInitializationError::Layout)?;
    validate_policy_capability(&root, expected_uid, expected_gid)?;
    let owner_directory = match root.open_directory(owner) {
        Ok(directory) => directory,
        Err(_) => root
            .create_directory(owner, 0o755)
            .map_err(|_| ProtectedPolicyInitializationError::Create)?,
    };
    validate_policy_capability(&owner_directory, expected_uid, expected_gid)?;
    if owner_directory
        .read_directory()
        .map_err(|_| ProtectedPolicyInitializationError::Layout)?
        .iter()
        .any(|entry| entry.name.as_str() == repository)
    {
        return Err(ProtectedPolicyInitializationError::Exists);
    }
    let policy_directory = owner_directory
        .create_directory(repository, 0o755)
        .map_err(|_| ProtectedPolicyInitializationError::Create)?;
    validate_policy_capability(&policy_directory, expected_uid, expected_gid)?;
    owner_directory
        .sync()
        .and_then(|()| root.sync())
        .map_err(|_| ProtectedPolicyInitializationError::Create)?;
    Ok((owner_directory, policy_directory))
}

fn validate_policy_capability(
    directory: &DirectoryCapability,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), ProtectedPolicyInitializationError> {
    let metadata = directory
        .metadata()
        .map_err(|_| ProtectedPolicyInitializationError::Layout)?;
    if metadata.uid != expected_uid
        || metadata.gid != expected_gid
        || metadata.mode & 0o777 != 0o755
    {
        return Err(ProtectedPolicyInitializationError::Layout);
    }
    Ok(())
}

/// Initializes one exact catalog entry and no other repository. All derived
/// paths are validated through retained roots before each creation. Any failure
/// leaves an incomplete, non-admissible generation for explicit inspection;
/// cleanup never follows a replaceable ambient path.
pub fn initialize_catalog_repository(
    config: &GitdConfig,
    entry: &DeploymentRepository,
) -> Result<mrml_git::ObjectId, RepositoryInitializationError> {
    validate_storage_layout(config).map_err(|_| RepositoryInitializationError::Layout)?;
    let (owner, repository) = entry
        .repository
        .as_str()
        .split_once('/')
        .ok_or(RepositoryInitializationError::Identity)?;
    if owner.is_empty() || repository.is_empty() || repository.contains('/') {
        return Err(RepositoryInitializationError::Identity);
    }
    let roots = [
        &config.repository_root,
        &config.state_root,
        &config.quarantine_root,
        &config.cache_root,
        &config.receipt_root,
    ];
    let mut capabilities = Vec::new();
    for root in roots {
        let root_capability = DirectoryCapability::open_root(
            root.to_str()
                .ok_or(RepositoryInitializationError::Identity)?,
        )
        .map_err(|_| RepositoryInitializationError::Layout)?;
        validate_directory_metadata(
            root_capability
                .metadata()
                .map_err(|_| RepositoryInitializationError::Layout)?,
            config.gitd_uid,
            config.gitd_gid,
        )
        .map_err(|_| RepositoryInitializationError::Layout)?;
        let owner_directory = match root_capability.open_directory(owner) {
            Ok(directory) => directory,
            Err(_) => root_capability
                .create_directory(owner, 0o700)
                .map_err(|_| RepositoryInitializationError::Create)?,
        };
        validate_directory_metadata(
            owner_directory
                .metadata()
                .map_err(|_| RepositoryInitializationError::Layout)?,
            config.gitd_uid,
            config.gitd_gid,
        )
        .map_err(|_| RepositoryInitializationError::Layout)?;
        if owner_directory
            .read_directory()
            .map_err(|_| RepositoryInitializationError::Layout)?
            .iter()
            .any(|entry| entry.name.as_str() == repository)
        {
            return Err(RepositoryInitializationError::Exists);
        }
        let leaf_directory = owner_directory
            .create_directory(repository, 0o700)
            .map_err(|_| RepositoryInitializationError::Create)?;
        owner_directory
            .sync()
            .and_then(|()| root_capability.sync())
            .map_err(|_| RepositoryInitializationError::Create)?;
        capabilities.push((owner_directory, leaf_directory));
    }
    for name in ["quarantine", "arrivals"] {
        capabilities[2]
            .1
            .create_directory(name, 0o700)
            .and_then(|directory| directory.sync())
            .map_err(|_| RepositoryInitializationError::Create)?;
    }
    capabilities[2]
        .1
        .sync()
        .map_err(|_| RepositoryInitializationError::Create)?;
    let initialized = mrml_git::FilesystemRepositoryView::initialize_sha256_capabilities(
        entry.repository.clone(),
        capabilities[0]
            .1
            .try_clone()
            .map_err(|_| RepositoryInitializationError::Initialize)?,
        capabilities[1]
            .1
            .try_clone()
            .map_err(|_| RepositoryInitializationError::Initialize)?,
        entry.repository_generation,
        entry.trust_generation,
        entry.revocation_generation,
    );
    if initialized.is_err() {
        return Err(RepositoryInitializationError::Initialize);
    }
    drop(initialized);
    let admitted = admit_catalog_repository(config, entry)
        .map_err(|_| RepositoryInitializationError::Verify)?;
    let tip = admitted
        .view
        .resolve_ref(&entry.repository, "refs/heads/main")
        .map_err(|_| RepositoryInitializationError::Verify);
    if tip.is_err() {
        drop(admitted);
    }
    tip
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RepositoryRecoverySummary {
    pub authenticated_receipts_recovered: u32,
    pub plain_receipts_recovered: u32,
    pub completed_journals: u32,
    pub discarded_journals: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RepositoryRecoveryStatus {
    pub recover_receipt: u32,
    pub mark_complete: u32,
    pub discard_before_activation: u32,
    pub reverify_before_activation: u32,
    pub manual_uncertain: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryRecoveryError {
    Path,
    Open,
    Journal,
    Receipt,
    PreActivationReverificationRequired,
    ManualUncertain,
    AuthorityCandidate,
    Count,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProtectedRecoveryProgress {
    CommitThenReceiptAndComplete,
    ReceiptAndComplete,
    ReceiptAlreadyComplete,
    Complete,
    CompleteAlreadyDone,
}

fn protected_recovery_progress(
    action: RecoveryAction,
    status: mrml_git::AuthorityCandidateStatus,
) -> Result<ProtectedRecoveryProgress, RepositoryRecoveryError> {
    match (action, status) {
        (
            RecoveryAction::RecoverAuditReceipt,
            mrml_git::AuthorityCandidateStatus::ActivationStarted,
        ) => Ok(ProtectedRecoveryProgress::CommitThenReceiptAndComplete),
        (RecoveryAction::RecoverAuditReceipt, mrml_git::AuthorityCandidateStatus::Activated)
        | (
            RecoveryAction::RecoverAuditReceipt,
            mrml_git::AuthorityCandidateStatus::ReceiptPersisted,
        ) => Ok(ProtectedRecoveryProgress::ReceiptAndComplete),
        (RecoveryAction::RecoverAuditReceipt, mrml_git::AuthorityCandidateStatus::Completed) => {
            Ok(ProtectedRecoveryProgress::ReceiptAlreadyComplete)
        }
        (RecoveryAction::MarkComplete, mrml_git::AuthorityCandidateStatus::ReceiptPersisted) => {
            Ok(ProtectedRecoveryProgress::Complete)
        }
        (RecoveryAction::MarkComplete, mrml_git::AuthorityCandidateStatus::Completed) => {
            Ok(ProtectedRecoveryProgress::CompleteAlreadyDone)
        }
        _ => Err(RepositoryRecoveryError::AuthorityCandidate),
    }
}

fn protected_discard_requires_abort(
    status: mrml_git::AuthorityCandidateStatus,
) -> Result<bool, RepositoryRecoveryError> {
    match status {
        mrml_git::AuthorityCandidateStatus::Receiving
        | mrml_git::AuthorityCandidateStatus::ProofsSealed
        | mrml_git::AuthorityCandidateStatus::Authorized
        | mrml_git::AuthorityCandidateStatus::ActivationStarted => Ok(true),
        mrml_git::AuthorityCandidateStatus::Aborted => Ok(false),
        _ => Err(RepositoryRecoveryError::AuthorityCandidate),
    }
}

pub fn inspect_admitted_repository_recovery(
    config: &GitdConfig,
    admitted: &AdmittedRepository,
) -> Result<RepositoryRecoveryStatus, RepositoryRecoveryError> {
    let store = open_recovery_store(admitted, receive_pack_limit(config.max_body_bytes))?;
    let actions = store
        .recovery_actions()
        .map_err(|_| RepositoryRecoveryError::Journal)?;
    let mut status = RepositoryRecoveryStatus::default();
    for (_, action) in actions {
        let counter = match action {
            RecoveryAction::RecoverAuditReceipt => &mut status.recover_receipt,
            RecoveryAction::MarkComplete => &mut status.mark_complete,
            RecoveryAction::DiscardBeforeActivation => &mut status.discard_before_activation,
            RecoveryAction::ReverifyBeforeActivation => &mut status.reverify_before_activation,
            RecoveryAction::ManualUncertain => &mut status.manual_uncertain,
        };
        *counter = counter
            .checked_add(1)
            .ok_or(RepositoryRecoveryError::Count)?;
    }
    Ok(status)
}

pub fn validate_storage_layout(config: &GitdConfig) -> Result<(), StartupValidationError> {
    for path in [
        &config.repository_root,
        &config.state_root,
        &config.quarantine_root,
        &config.cache_root,
        &config.receipt_root,
    ] {
        validate_directory(path, config.gitd_uid, config.gitd_gid, true)?;
    }
    validate_policy_directory(&config.policy_root, config.gitd_uid, config.gitd_gid, true)
}

pub fn admit_catalog_repository(
    config: &GitdConfig,
    entry: &DeploymentRepository,
) -> Result<AdmittedRepository, RepositoryAdmissionError> {
    let (owner, repository) = entry
        .repository
        .as_str()
        .split_once('/')
        .ok_or(RepositoryAdmissionError::Identity)?;
    if owner.is_empty() || repository.is_empty() || repository.contains('/') {
        return Err(RepositoryAdmissionError::Identity);
    }
    let derive = |root: &Path| root.join(owner).join(repository);
    let relative = format!("{owner}/{repository}");
    let paths = RepositoryStoragePaths {
        objects: derive(&config.repository_root),
        state: derive(&config.state_root),
        quarantine: derive(&config.quarantine_root),
        cache: derive(&config.cache_root),
        receipts: derive(&config.receipt_root),
    };
    let capabilities = RepositoryStorageCapabilities {
        objects: open_repository_capability(
            &config.repository_root,
            &relative,
            config.gitd_uid,
            config.gitd_gid,
        )
        .map_err(|_| RepositoryAdmissionError::Objects)?,
        state: open_repository_capability(
            &config.state_root,
            &relative,
            config.gitd_uid,
            config.gitd_gid,
        )
        .map_err(|_| RepositoryAdmissionError::State)?,
        quarantine: open_repository_capability(
            &config.quarantine_root,
            &relative,
            config.gitd_uid,
            config.gitd_gid,
        )
        .map_err(|_| RepositoryAdmissionError::Quarantine)?,
        cache: open_repository_capability(
            &config.cache_root,
            &relative,
            config.gitd_uid,
            config.gitd_gid,
        )
        .map_err(|_| RepositoryAdmissionError::Cache)?,
        receipts: open_repository_capability(
            &config.receipt_root,
            &relative,
            config.gitd_uid,
            config.gitd_gid,
        )
        .map_err(|_| RepositoryAdmissionError::Receipts)?,
        policy: config
            .policy_root
            .join(owner)
            .join(repository)
            .exists()
            .then(|| {
                open_policy_repository_capability(
                    &config.policy_root,
                    &relative,
                    config.gitd_uid,
                    config.gitd_gid,
                )
            })
            .transpose()
            .map_err(|_| RepositoryAdmissionError::Policy)?,
    };
    validate_private_child_directory(&capabilities.quarantine, "quarantine")?;
    validate_private_child_directory(&capabilities.quarantine, "arrivals")?;
    let mut view = FilesystemRepositoryView::open_capabilities(
        entry.repository.clone(),
        capabilities
            .objects
            .try_clone()
            .map_err(|_| RepositoryAdmissionError::View)?,
        capabilities
            .state
            .try_clone()
            .map_err(|_| RepositoryAdmissionError::View)?,
    )
    .map_err(|_| RepositoryAdmissionError::View)?;
    view.retain_arrival_directory(
        capabilities
            .quarantine
            .open_directory("arrivals")
            .map_err(|_| RepositoryAdmissionError::Arrival(GitdCoreError::Storage))?,
        receive_pack_limit(config.max_body_bytes),
    )
    .map_err(RepositoryAdmissionError::Arrival)?;
    verify_repository_admission(entry, &view).map_err(|_| RepositoryAdmissionError::Generation)?;
    Ok(AdmittedRepository {
        paths,
        capabilities,
        view,
    })
}

fn open_policy_repository_capability(
    root: &Path,
    relative: &str,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<DirectoryCapability, RepositoryAdmissionError> {
    let root = root.to_str().ok_or(RepositoryAdmissionError::Identity)?;
    let root = DirectoryCapability::open_root(root).map_err(|_| RepositoryAdmissionError::Open)?;
    let capability = root
        .open_directory(relative)
        .map_err(|_| RepositoryAdmissionError::Open)?;
    let metadata = capability
        .metadata()
        .map_err(|_| RepositoryAdmissionError::Open)?;
    let mode = metadata.mode & 0o777;
    if metadata.mode & 0o170000 != 0o040000
        || metadata.uid != expected_uid
        || metadata.gid != expected_gid
        || mode & 0o022 != 0
        || mode & 0o500 != 0o500
        || mode & 0o200 == 0
    {
        return Err(RepositoryAdmissionError::Layout(
            StartupValidationError::Permissions,
        ));
    }
    Ok(capability)
}

fn open_repository_capability(
    root: &Path,
    relative: &str,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<DirectoryCapability, RepositoryAdmissionError> {
    let root = root.to_str().ok_or(RepositoryAdmissionError::Identity)?;
    let root = DirectoryCapability::open_root(root).map_err(|_| RepositoryAdmissionError::Open)?;
    let capability = root
        .open_directory(relative)
        .map_err(|_| RepositoryAdmissionError::Open)?;
    validate_directory_metadata(
        capability
            .metadata()
            .map_err(|_| RepositoryAdmissionError::Open)?,
        expected_uid,
        expected_gid,
    )
    .map_err(RepositoryAdmissionError::Layout)?;
    Ok(capability)
}

fn validate_directory_metadata(
    metadata: DirectoryMetadata,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), StartupValidationError> {
    if metadata.mode & 0o170000 != 0o040000 {
        return Err(StartupValidationError::Type);
    }
    if metadata.uid != expected_uid || metadata.gid != expected_gid {
        return Err(StartupValidationError::Owner);
    }
    let mode = metadata.mode & 0o777;
    if mode & 0o027 != 0 || mode & 0o700 != 0o700 {
        return Err(StartupValidationError::Permissions);
    }
    Ok(())
}

pub fn recover_admitted_repository(
    config: &GitdConfig,
    entry: &DeploymentRepository,
    admitted: &AdmittedRepository,
    receipt_authority: &mut dyn AuditReceiptAuthority,
) -> Result<RepositoryRecoverySummary, RepositoryRecoveryError> {
    let mut store = open_recovery_store(admitted, receive_pack_limit(config.max_body_bytes))?;
    let actions = store
        .recovery_actions()
        .map_err(|_| RepositoryRecoveryError::Journal)?;
    let mut summary = RepositoryRecoverySummary::default();
    for (journal, action) in actions {
        match action {
            RecoveryAction::RecoverAuditReceipt
                if entry.profile.class == DeploymentRepositoryProfile::Protected =>
            {
                let receipts = AuthenticatedAuditReceiptDirectory::open_capability(
                    admitted
                        .capabilities
                        .receipts
                        .open_directory("authenticated")
                        .map_err(|_| RepositoryRecoveryError::Receipt)?,
                )
                .map_err(|_| RepositoryRecoveryError::Receipt)?;
                let mut authenticated = AuthenticatedReceiveStore::new_with_receipts(
                    &mut store,
                    receipts,
                    receipt_authority,
                );
                authenticated
                    .recover_audit_receipt(&journal)
                    .map_err(|_| RepositoryRecoveryError::Receipt)?;
                drop(authenticated);
                store
                    .complete_recovered_journal(&journal)
                    .map_err(|_| RepositoryRecoveryError::Journal)?;
                summary.authenticated_receipts_recovered = summary
                    .authenticated_receipts_recovered
                    .checked_add(1)
                    .ok_or(RepositoryRecoveryError::Count)?;
            }
            RecoveryAction::RecoverAuditReceipt => {
                store
                    .recover_audit_receipt(&journal)
                    .map_err(|_| RepositoryRecoveryError::Receipt)?;
                store
                    .complete_recovered_journal(&journal)
                    .map_err(|_| RepositoryRecoveryError::Journal)?;
                summary.plain_receipts_recovered = summary
                    .plain_receipts_recovered
                    .checked_add(1)
                    .ok_or(RepositoryRecoveryError::Count)?;
            }
            RecoveryAction::MarkComplete => {
                store
                    .complete_recovered_journal(&journal)
                    .map_err(|_| RepositoryRecoveryError::Journal)?;
                summary.completed_journals = summary
                    .completed_journals
                    .checked_add(1)
                    .ok_or(RepositoryRecoveryError::Count)?;
            }
            RecoveryAction::DiscardBeforeActivation => {
                store
                    .discard_recovered_unactivated(&journal)
                    .map_err(|_| RepositoryRecoveryError::Journal)?;
                summary.discarded_journals = summary
                    .discarded_journals
                    .checked_add(1)
                    .ok_or(RepositoryRecoveryError::Count)?;
            }
            RecoveryAction::ReverifyBeforeActivation => {
                store
                    .discard_recovered_unactivated(&journal)
                    .map_err(|_| RepositoryRecoveryError::Journal)?;
                summary.discarded_journals = summary
                    .discarded_journals
                    .checked_add(1)
                    .ok_or(RepositoryRecoveryError::Count)?;
            }
            RecoveryAction::ManualUncertain => {
                return Err(RepositoryRecoveryError::ManualUncertain);
            }
        }
    }
    Ok(summary)
}

pub fn recover_admitted_protected_repository(
    config: &GitdConfig,
    entry: &DeploymentRepository,
    admitted: &AdmittedRepository,
    authority: &mut dyn mrml_git::ProtectedReceiveAuthority,
) -> Result<RepositoryRecoverySummary, RepositoryRecoveryError> {
    if entry.profile.class != DeploymentRepositoryProfile::Protected {
        return Err(RepositoryRecoveryError::AuthorityCandidate);
    }
    let mut store = open_recovery_store(admitted, receive_pack_limit(config.max_body_bytes))?;
    let actions = store
        .recovery_actions()
        .map_err(|_| RepositoryRecoveryError::Journal)?;
    let mut summary = RepositoryRecoverySummary::default();
    for (journal, action) in actions {
        match action {
            RecoveryAction::RecoverAuditReceipt => {
                let receipt = store
                    .recovery_audit_receipt(&journal)
                    .map_err(|_| RepositoryRecoveryError::Journal)?;
                let record = authority
                    .query_candidate_by_id(&journal.repository, journal.transaction)
                    .map_err(|_| RepositoryRecoveryError::AuthorityCandidate)?;
                validate_recovery_candidate(&journal, &receipt, &record)?;
                let progress = protected_recovery_progress(action, record.status)?;
                if progress == ProtectedRecoveryProgress::CommitThenReceiptAndComplete {
                    authority
                        .commit_candidate(&record.context)
                        .map_err(|_| RepositoryRecoveryError::AuthorityCandidate)?;
                }
                let mut authenticated = AuthenticatedReceiveStore::new_with_receipts(
                    &mut store,
                    open_authenticated_receipts(admitted)?,
                    authority,
                );
                authenticated
                    .recover_audit_receipt(&journal)
                    .map_err(|_| RepositoryRecoveryError::Receipt)?;
                drop(authenticated);
                if progress != ProtectedRecoveryProgress::ReceiptAlreadyComplete {
                    authority
                        .complete_candidate(&record.context)
                        .map_err(|_| RepositoryRecoveryError::AuthorityCandidate)?;
                }
                store
                    .complete_recovered_journal(&journal)
                    .map_err(|_| RepositoryRecoveryError::Journal)?;
                summary.authenticated_receipts_recovered = summary
                    .authenticated_receipts_recovered
                    .checked_add(1)
                    .ok_or(RepositoryRecoveryError::Count)?;
            }
            RecoveryAction::MarkComplete => {
                let record = authority
                    .query_candidate_by_id(&journal.repository, journal.transaction)
                    .map_err(|_| RepositoryRecoveryError::AuthorityCandidate)?;
                let receipt = open_authenticated_receipts(admitted)?
                    .load(journal.transaction, authority)
                    .map_err(|_| RepositoryRecoveryError::Receipt)?;
                validate_recovery_candidate(&journal, &receipt.receipt, &record)?;
                let progress = protected_recovery_progress(action, record.status)?;
                if progress == ProtectedRecoveryProgress::Complete {
                    authority
                        .complete_candidate(&record.context)
                        .map_err(|_| RepositoryRecoveryError::AuthorityCandidate)?;
                }
                store
                    .complete_recovered_journal(&journal)
                    .map_err(|_| RepositoryRecoveryError::Journal)?;
                summary.completed_journals = summary
                    .completed_journals
                    .checked_add(1)
                    .ok_or(RepositoryRecoveryError::Count)?;
            }
            RecoveryAction::DiscardBeforeActivation => {
                let record = authority
                    .query_candidate_by_id(&journal.repository, journal.transaction)
                    .map_err(|_| RepositoryRecoveryError::AuthorityCandidate)?;
                validate_pre_activation_candidate(&journal, &record)?;
                if protected_discard_requires_abort(record.status)? {
                    authority
                        .abort_candidate(&record.context)
                        .map_err(|_| RepositoryRecoveryError::AuthorityCandidate)?;
                }
                store
                    .discard_recovered_unactivated(&journal)
                    .map_err(|_| RepositoryRecoveryError::Journal)?;
                summary.discarded_journals = summary
                    .discarded_journals
                    .checked_add(1)
                    .ok_or(RepositoryRecoveryError::Count)?;
            }
            RecoveryAction::ReverifyBeforeActivation => {
                let record = authority
                    .query_candidate_by_id(&journal.repository, journal.transaction)
                    .map_err(|_| RepositoryRecoveryError::AuthorityCandidate)?;
                validate_pre_activation_candidate(&journal, &record)?;
                if protected_discard_requires_abort(record.status)? {
                    authority
                        .abort_candidate(&record.context)
                        .map_err(|_| RepositoryRecoveryError::AuthorityCandidate)?;
                }
                store
                    .discard_recovered_unactivated(&journal)
                    .map_err(|_| RepositoryRecoveryError::Journal)?;
                summary.discarded_journals = summary
                    .discarded_journals
                    .checked_add(1)
                    .ok_or(RepositoryRecoveryError::Count)?;
            }
            RecoveryAction::ManualUncertain => {
                return Err(RepositoryRecoveryError::ManualUncertain);
            }
        }
    }
    Ok(summary)
}

fn open_authenticated_receipts(
    admitted: &AdmittedRepository,
) -> Result<AuthenticatedAuditReceiptDirectory, RepositoryRecoveryError> {
    AuthenticatedAuditReceiptDirectory::open_capability(
        admitted
            .capabilities
            .receipts
            .open_directory("authenticated")
            .map_err(|_| RepositoryRecoveryError::Receipt)?,
    )
    .map_err(|_| RepositoryRecoveryError::Receipt)
}

fn validate_recovery_candidate(
    journal: &mrml_git::ReceiveJournalRecord,
    receipt: &mrml_git::AuditReceipt,
    record: &mrml_git::AuthorityCandidateRecord,
) -> Result<(), RepositoryRecoveryError> {
    let canonical = mrml_git::encode_audit_receipt(receipt)
        .map_err(|_| RepositoryRecoveryError::AuthorityCandidate)?;
    let transcript = mrml_git::authenticated_audit_receipt_transcript(&canonical)
        .map_err(|_| RepositoryRecoveryError::AuthorityCandidate)?;
    let context = &record.context;
    if context.id != journal.transaction
        || context.repository != journal.repository
        || context.current_generation != journal.repository_generation
        || context.next_generation != receipt.activated_repository_generation
        || context.trust_generation != journal.trust_generation
        || context.revocation_generation != journal.revocation_generation
        || context.activation_digest != mrml_git::candidate_activation_digest(&transcript)
    {
        return Err(RepositoryRecoveryError::AuthorityCandidate);
    }
    Ok(())
}

fn validate_pre_activation_candidate(
    journal: &mrml_git::ReceiveJournalRecord,
    record: &mrml_git::AuthorityCandidateRecord,
) -> Result<(), RepositoryRecoveryError> {
    let next_generation = journal
        .repository_generation
        .0
        .checked_add(1)
        .map(mrml_git::RepositoryGeneration)
        .ok_or(RepositoryRecoveryError::AuthorityCandidate)?;
    let context = &record.context;
    if context.id != journal.transaction
        || context.repository != journal.repository
        || context.current_generation != journal.repository_generation
        || context.next_generation != next_generation
        || context.trust_generation != journal.trust_generation
        || context.revocation_generation != journal.revocation_generation
    {
        return Err(RepositoryRecoveryError::AuthorityCandidate);
    }
    Ok(())
}

fn open_recovery_store(
    admitted: &AdmittedRepository,
    max_pack_bytes: u64,
) -> Result<LinuxDurableReceiveStore, RepositoryRecoveryError> {
    let journals =
        open_or_create_private_directory(&admitted.capabilities.state, "receive-journals")?;
    let plain_receipts =
        open_or_create_private_directory(&admitted.capabilities.receipts, "plain")?;
    let _authenticated_receipts =
        open_or_create_private_directory(&admitted.capabilities.receipts, "authenticated")?;
    LinuxDurableReceiveStore::open_with_capabilities(
        journals,
        admitted
            .capabilities
            .quarantine
            .try_clone()
            .map_err(|_| RepositoryRecoveryError::Open)?,
        admitted
            .capabilities
            .state
            .try_clone()
            .map_err(|_| RepositoryRecoveryError::Open)?,
        plain_receipts,
        ObjectFormat::Sha256,
        max_pack_bytes,
    )
    .map_err(|_| RepositoryRecoveryError::Open)
}

fn validate_private_child_directory(
    parent: &DirectoryCapability,
    name: &str,
) -> Result<(), RepositoryAdmissionError> {
    let parent_metadata = parent
        .metadata()
        .map_err(|_| RepositoryAdmissionError::Open)?;
    let child = parent
        .open_directory(name)
        .map_err(|_| RepositoryAdmissionError::Open)?;
    let metadata = child
        .metadata()
        .map_err(|_| RepositoryAdmissionError::Open)?;
    if metadata.uid != parent_metadata.uid
        || metadata.gid != parent_metadata.gid
        || metadata.mode & 0o777 != 0o700
    {
        return Err(RepositoryAdmissionError::Open);
    }
    Ok(())
}

fn open_or_create_private_directory(
    parent: &DirectoryCapability,
    name: &str,
) -> Result<DirectoryCapability, RepositoryRecoveryError> {
    let directory = match parent.open_directory(name) {
        Ok(directory) => directory,
        Err(_) => parent
            .create_directory(name, 0o700)
            .map_err(|_| RepositoryRecoveryError::Open)?,
    };
    let parent_metadata = parent
        .metadata()
        .map_err(|_| RepositoryRecoveryError::Open)?;
    let metadata = directory
        .metadata()
        .map_err(|_| RepositoryRecoveryError::Open)?;
    if metadata.uid != parent_metadata.uid
        || metadata.gid != parent_metadata.gid
        || metadata.mode & 0o777 != 0o700
    {
        return Err(RepositoryRecoveryError::Open);
    }
    parent.sync().map_err(|_| RepositoryRecoveryError::Open)?;
    Ok(directory)
}

fn validate_directory(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    require_owner_write: bool,
) -> Result<(), StartupValidationError> {
    validate_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| StartupValidationError::Missing)?;
    if metadata.file_type().is_symlink() {
        return Err(StartupValidationError::Symlink);
    }
    if !metadata.file_type().is_dir() {
        return Err(StartupValidationError::Type);
    }
    if metadata.uid() != expected_uid || metadata.gid() != expected_gid {
        return Err(StartupValidationError::Owner);
    }
    let mode = metadata.mode() & 0o777;
    if mode & 0o007 != 0
        || mode & 0o020 != 0
        || mode & 0o500 != 0o500
        || (require_owner_write && mode & 0o200 == 0)
    {
        return Err(StartupValidationError::Permissions);
    }
    Ok(())
}

fn validate_policy_directory(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    require_owner_write: bool,
) -> Result<(), StartupValidationError> {
    validate_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| StartupValidationError::Missing)?;
    if metadata.file_type().is_symlink() {
        return Err(StartupValidationError::Symlink);
    }
    if !metadata.file_type().is_dir() {
        return Err(StartupValidationError::Type);
    }
    if metadata.uid() != expected_uid || metadata.gid() != expected_gid {
        return Err(StartupValidationError::Owner);
    }
    let mode = metadata.mode() & 0o777;
    if mode & 0o022 != 0 || mode & 0o555 != 0o555 || (require_owner_write && mode & 0o200 == 0) {
        return Err(StartupValidationError::Permissions);
    }
    Ok(())
}

fn validate_components(path: &Path) -> Result<(), StartupValidationError> {
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(Path::new("/")),
            Component::Normal(value) => current.push(value),
            _ => return Err(StartupValidationError::Type),
        }
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| StartupValidationError::Missing)?;
        if metadata.file_type().is_symlink() {
            return Err(StartupValidationError::Symlink);
        }
        if !metadata.file_type().is_dir() {
            return Err(StartupValidationError::Type);
        }
        if current != Path::new("/")
            && metadata.mode() & 0o022 != 0
            && metadata.mode() & 0o1000 == 0
        {
            return Err(StartupValidationError::Permissions);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_recovery_accepts_only_authority_states_proven_by_local_phase() {
        use mrml_git::AuthorityCandidateStatus as Status;

        assert_eq!(
            protected_recovery_progress(
                RecoveryAction::RecoverAuditReceipt,
                Status::ActivationStarted
            ),
            Ok(ProtectedRecoveryProgress::CommitThenReceiptAndComplete)
        );
        assert_eq!(
            protected_recovery_progress(RecoveryAction::RecoverAuditReceipt, Status::Activated),
            Ok(ProtectedRecoveryProgress::ReceiptAndComplete)
        );
        assert_eq!(
            protected_recovery_progress(RecoveryAction::RecoverAuditReceipt, Status::Completed),
            Ok(ProtectedRecoveryProgress::ReceiptAlreadyComplete)
        );
        assert_eq!(
            protected_recovery_progress(RecoveryAction::MarkComplete, Status::ReceiptPersisted),
            Ok(ProtectedRecoveryProgress::Complete)
        );
        assert_eq!(
            protected_recovery_progress(RecoveryAction::MarkComplete, Status::Completed),
            Ok(ProtectedRecoveryProgress::CompleteAlreadyDone)
        );
        for status in [
            Status::Receiving,
            Status::ProofsSealed,
            Status::Authorized,
            Status::Aborted,
        ] {
            assert_eq!(
                protected_recovery_progress(RecoveryAction::RecoverAuditReceipt, status),
                Err(RepositoryRecoveryError::AuthorityCandidate)
            );
            assert_eq!(
                protected_recovery_progress(RecoveryAction::MarkComplete, status),
                Err(RepositoryRecoveryError::AuthorityCandidate)
            );
        }
        for status in [
            Status::Receiving,
            Status::ProofsSealed,
            Status::Authorized,
            Status::ActivationStarted,
        ] {
            assert_eq!(protected_discard_requires_abort(status), Ok(true));
        }
        assert_eq!(protected_discard_requires_abort(Status::Aborted), Ok(false));
        for status in [
            Status::Activated,
            Status::ReceiptPersisted,
            Status::Completed,
        ] {
            assert_eq!(
                protected_discard_requires_abort(status),
                Err(RepositoryRecoveryError::AuthorityCandidate)
            );
        }
    }
    use mrml_crypto::ml_dsa_65_keygen;
    use mrml_git::{
        RepositoryGeneration, RepositoryIdentity, RevocationGeneration, TrustGeneration,
    };
    use mrml_http::GitdBackend;
    use mrml_openpgp::SigningKeyV6;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    struct TestReceiptAuthority;

    impl AuditReceiptAuthority for TestReceiptAuthority {
        fn signer_identity(&self) -> [u8; 64] {
            [9u8; 64]
        }

        fn sign(&mut self, _: &[u8], output: &mut [u8]) -> Result<usize, ()> {
            output.get_mut(..32).ok_or(())?.copy_from_slice(&[7u8; 32]);
            Ok(32)
        }

        fn verify(&mut self, _: &[u8], signature: &[u8]) -> Result<(), ()> {
            (signature == [7u8; 32]).then_some(()).ok_or(())
        }
    }

    #[test]
    fn exact_owned_layout_passes_and_symlink_or_writable_parent_fails() {
        let root = std::env::temp_dir().join(format!("mrml-gitd-layout-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(&root).unwrap();
        let paths = [
            "repos",
            "state",
            "quarantine",
            "cache",
            "receipts",
            "policies",
        ];
        for name in paths {
            let path = root.join(name);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::set_permissions(root.join("policies"), fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = crate::parse_gitd_config(
            b"version=1\nserver_name=git.example.invalid\nlisten_port=8443\nrepository_root=/a\nstate_root=/b\nquarantine_root=/c\ncache_root=/d\nreceipt_root=/e\npolicy_root=/f\nrepository_catalog=/f/repositories.v1\nrepository_catalog_sha256=1111111111111111111111111111111111111111111111111111111111111111\nprofile_catalog=/f/profiles.v1\nprofile_catalog_sha256=2222222222222222222222222222222222222222222222222222222222222222\ntoken_records=/b/tokens.v1\ntoken_pepper=/run/secrets/gitd-token-pepper\nquic_retry_key=/run/secrets/gitd-quic-retry-key\nquic_retry_generation=1\nauthority_socket=/g\ncertd_socket=/h\nauthority_capability=/i\ncertd_capability=/j\ngitd_uid=1\ngitd_gid=1\nauthority_uid=2\nauthority_gid=2\ncertd_uid=3\ncertd_gid=3\nnext_authority_request_id=1\nnext_certd_request_id=1\nmax_connections=1\nmax_uploads=1\nmax_receives=1\nmax_body_bytes=1024\nminimum_free_space_bytes=1073741824\ndrain_seconds=1\n",
        )
        .unwrap();
        config.gitd_uid = metadata.uid();
        config.gitd_gid = metadata.gid();
        config.repository_root = root.join("repos");
        config.state_root = root.join("state");
        config.quarantine_root = root.join("quarantine");
        config.cache_root = root.join("cache");
        config.receipt_root = root.join("receipts");
        config.policy_root = root.join("policies");
        assert_eq!(validate_storage_layout(&config), Ok(()));

        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            validate_storage_layout(&config),
            Err(StartupValidationError::Permissions)
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir(config.cache_root.clone()).unwrap();
        symlink(root.join("state"), &config.cache_root).unwrap();
        assert_eq!(
            validate_storage_layout(&config),
            Err(StartupValidationError::Symlink)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn catalog_repository_derives_all_paths_and_exact_matches_live_generations() {
        let root = std::env::temp_dir().join(format!(
            "mrml-gitd-repository-admission-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(&root).unwrap();
        let mut config = crate::parse_gitd_config(
            b"version=1\nserver_name=git.example.invalid\nlisten_port=8443\nrepository_root=/a\nstate_root=/b\nquarantine_root=/c\ncache_root=/d\nreceipt_root=/e\npolicy_root=/f\nrepository_catalog=/f/repositories.v1\nrepository_catalog_sha256=1111111111111111111111111111111111111111111111111111111111111111\nprofile_catalog=/f/profiles.v1\nprofile_catalog_sha256=2222222222222222222222222222222222222222222222222222222222222222\ntoken_records=/b/tokens.v1\ntoken_pepper=/run/secrets/gitd-token-pepper\nquic_retry_key=/run/secrets/gitd-quic-retry-key\nquic_retry_generation=1\nauthority_socket=/g\ncertd_socket=/h\nauthority_capability=/i\ncertd_capability=/j\ngitd_uid=1\ngitd_gid=1\nauthority_uid=2\nauthority_gid=2\ncertd_uid=3\ncertd_gid=3\nnext_authority_request_id=1\nnext_certd_request_id=1\nmax_connections=1\nmax_uploads=1\nmax_receives=1\nmax_body_bytes=1024\nminimum_free_space_bytes=1073741824\ndrain_seconds=1\n",
        )
        .unwrap();
        config.gitd_uid = metadata.uid();
        config.gitd_gid = metadata.gid();
        config.repository_root = root.join("repos");
        config.state_root = root.join("state");
        config.quarantine_root = root.join("quarantine");
        config.cache_root = root.join("cache");
        config.receipt_root = root.join("receipts");
        config.policy_root = root.join("policies");
        for storage_root in [
            &config.repository_root,
            &config.state_root,
            &config.quarantine_root,
            &config.cache_root,
            &config.receipt_root,
            &config.policy_root,
        ] {
            fs::create_dir(storage_root).unwrap();
            fs::set_permissions(storage_root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::set_permissions(&config.policy_root, fs::Permissions::from_mode(0o755)).unwrap();
        let identity = RepositoryIdentity::parse("owner/project").unwrap();
        let entry = crate::DeploymentRepository {
            repository: identity,
            profile: crate::DeploymentProfile {
                name: "protected".into(),
                class: crate::DeploymentRepositoryProfile::Protected,
                max_object_bytes: 1024,
            },
            repository_generation: RepositoryGeneration(4),
            trust_generation: TrustGeneration(6),
            revocation_generation: RevocationGeneration(8),
        };
        let tip = initialize_catalog_repository(&config, &entry).unwrap();
        assert_ne!(
            tip,
            mrml_git::ObjectId::zero(mrml_git::ObjectFormat::Sha256)
        );
        assert_eq!(
            initialize_catalog_repository(&config, &entry),
            Err(RepositoryInitializationError::Exists)
        );
        let openpgp = SigningKeyV6::from_seed([7; 32], 1_700_000_000).unwrap();
        let mut ml_public = [0; mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES];
        let mut ml_secret = [0; mrml_crypto::ML_DSA_65_SECRET_KEY_BYTES];
        ml_dsa_65_keygen(&[9; 32], &mut ml_public, &mut ml_secret).unwrap();
        assert_eq!(
            initialize_catalog_protected_policy(
                &config,
                &entry,
                &openpgp.public_key(),
                &ml_public,
                1_700_000_000,
                1_800_000_000,
            ),
            Ok(tip)
        );
        assert_eq!(
            initialize_catalog_protected_policy(
                &config,
                &entry,
                &openpgp.public_key(),
                &ml_public,
                1_700_000_000,
                1_800_000_000,
            ),
            Err(ProtectedPolicyInitializationError::Exists)
        );
        let objects = config.repository_root.join("owner/project");
        let admitted = admit_catalog_repository(&config, &entry).unwrap();
        assert_eq!(admitted.paths.objects, objects);
        assert_eq!(
            admitted.paths.receipts,
            config.receipt_root.join("owner/project")
        );
        let mut stale = entry.clone();
        stale.revocation_generation = RevocationGeneration(9);
        assert!(matches!(
            admit_catalog_repository(&config, &stale),
            Err(RepositoryAdmissionError::Generation)
        ));
        let displaced_objects = config.repository_root.join("owner/project-displaced");
        let displaced_state = config.state_root.join("owner/project-displaced");
        fs::rename(&admitted.paths.objects, &displaced_objects).unwrap();
        fs::rename(&admitted.paths.state, &displaced_state).unwrap();
        fs::create_dir(&admitted.paths.objects).unwrap();
        fs::create_dir(&admitted.paths.state).unwrap();
        assert_eq!(
            admitted
                .view
                .resolve_ref(&entry.repository, "refs/heads/main"),
            Ok(tip)
        );
        assert!(!admitted.paths.objects.join(".git").exists());
        assert!(!admitted.paths.state.join("active.refs").exists());
        assert_eq!(
            recover_admitted_repository(&config, &entry, &admitted, &mut TestReceiptAuthority),
            Ok(RepositoryRecoverySummary::default())
        );
        assert_eq!(
            inspect_admitted_repository_recovery(&config, &admitted),
            Ok(RepositoryRecoveryStatus::default())
        );
        let mut repositories = crate::GitdRepositorySet::new();
        repositories.add(&entry, admitted).unwrap();
        assert_eq!(repositories.len(), 1);
        assert_eq!(
            repositories
                .repository_generation(
                    &mrml_http::RepositoryIdentity::parse("owner/project").unwrap()
                )
                .unwrap(),
            mrml_http::RepositoryGeneration(4)
        );
        assert_eq!(
            repositories.repository_generation(
                &mrml_http::RepositoryIdentity::parse("owner/absent").unwrap()
            ),
            Err(mrml_http::BackendError::NotFound)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
