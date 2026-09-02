use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use mrml_git::{
    AuditReceiptAuthority, AuthenticatedReceiveStore, FilesystemRepositoryView,
    LinuxDurableReceiveStore, ObjectFormat, RecoveryAction,
};

use crate::{
    DeploymentRepository, DeploymentRepositoryProfile, GitdConfig, verify_repository_admission,
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

pub struct AdmittedRepository {
    pub paths: RepositoryStoragePaths,
    pub view: FilesystemRepositoryView,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryAdmissionError {
    Identity,
    Layout(StartupValidationError),
    Open,
    Generation,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RepositoryRecoverySummary {
    pub authenticated_receipts_recovered: u32,
    pub plain_receipts_recovered: u32,
    pub completed_journals: u32,
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
    Count,
}

pub fn inspect_admitted_repository_recovery(
    config: &GitdConfig,
    admitted: &AdmittedRepository,
) -> Result<RepositoryRecoveryStatus, RepositoryRecoveryError> {
    let journals = admitted.paths.state.join("receive-journals");
    let plain_receipts = admitted.paths.receipts.join("plain");
    let store = LinuxDurableReceiveStore::open(
        recovery_path(&journals)?,
        recovery_path(&admitted.paths.quarantine)?,
        recovery_path(&admitted.paths.state)?,
        recovery_path(&plain_receipts)?,
        ObjectFormat::Sha256,
        config.max_body_bytes,
    )
    .map_err(|_| RepositoryRecoveryError::Open)?;
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
    validate_directory(&config.policy_root, config.gitd_uid, config.gitd_gid, false)
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
    let paths = RepositoryStoragePaths {
        objects: derive(&config.repository_root),
        state: derive(&config.state_root),
        quarantine: derive(&config.quarantine_root),
        cache: derive(&config.cache_root),
        receipts: derive(&config.receipt_root),
    };
    for path in [
        &paths.objects,
        &paths.state,
        &paths.quarantine,
        &paths.cache,
        &paths.receipts,
    ] {
        validate_directory(path, config.gitd_uid, config.gitd_gid, true)
            .map_err(RepositoryAdmissionError::Layout)?;
    }
    let view = FilesystemRepositoryView::open(
        entry.repository.clone(),
        paths
            .objects
            .to_str()
            .ok_or(RepositoryAdmissionError::Identity)?,
        paths
            .state
            .to_str()
            .ok_or(RepositoryAdmissionError::Identity)?,
    )
    .map_err(|_| RepositoryAdmissionError::Open)?;
    verify_repository_admission(entry, &view).map_err(|_| RepositoryAdmissionError::Generation)?;
    Ok(AdmittedRepository { paths, view })
}

pub fn recover_admitted_repository(
    config: &GitdConfig,
    entry: &DeploymentRepository,
    admitted: &AdmittedRepository,
    receipt_authority: &mut dyn AuditReceiptAuthority,
) -> Result<RepositoryRecoverySummary, RepositoryRecoveryError> {
    let journals = admitted.paths.state.join("receive-journals");
    let plain_receipts = admitted.paths.receipts.join("plain");
    let authenticated_receipts = admitted.paths.receipts.join("authenticated");
    let mut store = LinuxDurableReceiveStore::open(
        recovery_path(&journals)?,
        recovery_path(&admitted.paths.quarantine)?,
        recovery_path(&admitted.paths.state)?,
        recovery_path(&plain_receipts)?,
        ObjectFormat::Sha256,
        config.max_body_bytes,
    )
    .map_err(|_| RepositoryRecoveryError::Open)?;
    let actions = store
        .recovery_actions()
        .map_err(|_| RepositoryRecoveryError::Journal)?;
    let mut summary = RepositoryRecoverySummary::default();
    for (journal, action) in actions {
        match action {
            RecoveryAction::RecoverAuditReceipt
                if entry.profile.class == DeploymentRepositoryProfile::Protected =>
            {
                let mut authenticated = AuthenticatedReceiveStore::new(
                    &mut store,
                    recovery_path(&authenticated_receipts)?,
                    receipt_authority,
                )
                .map_err(|_| RepositoryRecoveryError::Receipt)?;
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
            RecoveryAction::DiscardBeforeActivation | RecoveryAction::ReverifyBeforeActivation => {
                return Err(RepositoryRecoveryError::PreActivationReverificationRequired);
            }
            RecoveryAction::ManualUncertain => {
                return Err(RepositoryRecoveryError::ManualUncertain);
            }
        }
    }
    Ok(summary)
}

fn recovery_path(path: &Path) -> Result<&str, RepositoryRecoveryError> {
    path.to_str().ok_or(RepositoryRecoveryError::Path)
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
    use mrml_git::{
        ActiveRefFile, ActiveRefState, FullRefName, ObjectFormat, ObjectKind, PackGeneration,
        Repository, RepositoryGeneration, RepositoryIdentity, RevocationGeneration,
        TrustGeneration,
    };
    use mrml_http::GitdBackend;
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
        let mut config = crate::parse_gitd_config(
            b"version=1\nserver_name=git.example.invalid\nlisten_port=8443\nrepository_root=/a\nstate_root=/b\nquarantine_root=/c\ncache_root=/d\nreceipt_root=/e\npolicy_root=/f\nrepository_catalog=/f/repositories.v1\nrepository_catalog_sha256=1111111111111111111111111111111111111111111111111111111111111111\nprofile_catalog=/f/profiles.v1\nprofile_catalog_sha256=2222222222222222222222222222222222222222222222222222222222222222\ntoken_records=/b/tokens.v1\ntoken_pepper=/run/secrets/gitd-token-pepper\nquic_retry_key=/run/secrets/gitd-quic-retry-key\nquic_retry_generation=1\nauthority_socket=/g\ncertd_socket=/h\nauthority_capability=/i\ncertd_capability=/j\ngitd_uid=1\ngitd_gid=1\nauthority_uid=2\nauthority_gid=2\ncertd_uid=3\ncertd_gid=3\nnext_authority_request_id=1\nnext_certd_request_id=1\nmax_connections=1\nmax_uploads=1\nmax_receives=1\nmax_body_bytes=1024\ndrain_seconds=1\n",
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
            b"version=1\nserver_name=git.example.invalid\nlisten_port=8443\nrepository_root=/a\nstate_root=/b\nquarantine_root=/c\ncache_root=/d\nreceipt_root=/e\npolicy_root=/f\nrepository_catalog=/f/repositories.v1\nrepository_catalog_sha256=1111111111111111111111111111111111111111111111111111111111111111\nprofile_catalog=/f/profiles.v1\nprofile_catalog_sha256=2222222222222222222222222222222222222222222222222222222222222222\ntoken_records=/b/tokens.v1\ntoken_pepper=/run/secrets/gitd-token-pepper\nquic_retry_key=/run/secrets/gitd-quic-retry-key\nquic_retry_generation=1\nauthority_socket=/g\ncertd_socket=/h\nauthority_capability=/i\ncertd_capability=/j\ngitd_uid=1\ngitd_gid=1\nauthority_uid=2\nauthority_gid=2\ncertd_uid=3\ncertd_gid=3\nnext_authority_request_id=1\nnext_certd_request_id=1\nmax_connections=1\nmax_uploads=1\nmax_receives=1\nmax_body_bytes=1024\ndrain_seconds=1\n",
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
        for storage_root in [
            &config.repository_root,
            &config.state_root,
            &config.quarantine_root,
            &config.cache_root,
            &config.receipt_root,
        ] {
            let owner = storage_root.join("owner");
            fs::create_dir(&owner).unwrap();
            fs::set_permissions(&owner, fs::Permissions::from_mode(0o700)).unwrap();
            if storage_root != &config.repository_root {
                let leaf = owner.join("project");
                fs::create_dir(&leaf).unwrap();
                fs::set_permissions(&leaf, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        let objects = config.repository_root.join("owner/project");
        let repository =
            Repository::init_with_format(objects.to_str().unwrap(), ObjectFormat::Sha256).unwrap();
        fs::set_permissions(&objects, fs::Permissions::from_mode(0o700)).unwrap();
        let tip = repository.write_object(ObjectKind::Blob, b"tip").unwrap();
        let identity = RepositoryIdentity::parse("owner/project").unwrap();
        ActiveRefFile::initialize(
            config.state_root.join("owner/project").to_str().unwrap(),
            &ActiveRefState {
                repository: identity.clone(),
                repository_generation: RepositoryGeneration(4),
                trust_generation: TrustGeneration(6),
                revocation_generation: RevocationGeneration(8),
                pack_generation: PackGeneration(1),
                pack_set_digest: [1u8; 32],
                object_format: ObjectFormat::Sha256,
                default_branch: FullRefName::parse("refs/heads/main").unwrap(),
                refs: [(FullRefName::parse("refs/heads/main").unwrap(), tip)].into(),
            },
        )
        .unwrap();
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
        let admitted = admit_catalog_repository(&config, &entry).unwrap();
        assert_eq!(admitted.paths.objects, objects);
        assert_eq!(
            admitted.paths.receipts,
            config.receipt_root.join("owner/project")
        );
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
        let mut stale = entry.clone();
        stale.revocation_generation = RevocationGeneration(9);
        assert!(matches!(
            admit_catalog_repository(&config, &stale),
            Err(RepositoryAdmissionError::Generation)
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
