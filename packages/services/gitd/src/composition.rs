use mrml_git::{ProtectedReceiveAuthority, RepositoryIdentity};
use mrml_http::{
    BackendError, GitdAuthentication, GitdHttp3Server, GitdOperationLimits, GitdOperationalHealth,
};
use mrml_runtime::Shared;

use crate::{
    AuthenticationStoreError, DeploymentCatalog, GitdConfig, GitdRepositorySet,
    RepositoryAdmissionError, RepositoryRecoveryError, RepositoryRecoverySummary,
    SharedGitdRepositorySet, admit_catalog_repository, load_gitd_authentication,
    recover_admitted_protected_repository, recover_admitted_repository,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitdCompositionError {
    Authentication(AuthenticationStoreError),
    Admission(RepositoryAdmissionError),
    Recovery(RepositoryRecoveryError),
    Backend,
    Cache,
}

pub struct GitdComposedService {
    pub edge: GitdHttp3Server<SharedGitdRepositorySet>,
    pub recovery: Vec<(RepositoryIdentity, RepositoryRecoverySummary)>,
    backend: SharedGitdRepositorySet,
    authentication: Shared<GitdAuthentication>,
    health: Shared<GitdOperationalHealth>,
    operation_limits: Shared<GitdOperationLimits>,
}

impl GitdComposedService {
    pub fn worker_edge(
        &self,
        cache_bytes: usize,
    ) -> Result<GitdHttp3Server<SharedGitdRepositorySet>, BackendError> {
        let mut edge = GitdHttp3Server::new(self.backend.clone(), cache_bytes)?;
        edge.configure_shared_authentication(self.authentication.clone());
        edge.configure_operational_health(self.health.clone());
        edge.configure_operation_limits(self.operation_limits.clone());
        Ok(edge)
    }

    pub fn operational_health(&self) -> Shared<GitdOperationalHealth> {
        self.health.clone()
    }

    pub fn authentication(&self) -> Shared<GitdAuthentication> {
        self.authentication.clone()
    }

    pub fn operation_limits(&self) -> Shared<GitdOperationLimits> {
        self.operation_limits.clone()
    }
}

/// Construct the routable Git service only after every catalog repository is
/// admitted against live generations and every durable receive journal has a
/// non-ambiguous recovery result.
pub fn compose_gitd_service<A: ProtectedReceiveAuthority + Send + Clone + 'static>(
    config: &GitdConfig,
    catalog: &DeploymentCatalog,
    mut authority: A,
    cache_bytes: usize,
) -> Result<GitdComposedService, GitdCompositionError> {
    if catalog.repositories.is_empty() {
        return Err(GitdCompositionError::Backend);
    }
    let authentication =
        load_gitd_authentication(config, catalog).map_err(GitdCompositionError::Authentication)?;
    let mut repositories = GitdRepositorySet::new();
    let mut recovery = Vec::new();
    let mut admitted_repositories = Vec::new();
    recovery
        .try_reserve_exact(catalog.repositories.len())
        .map_err(|_| GitdCompositionError::Backend)?;
    for entry in &catalog.repositories {
        let admitted =
            admit_catalog_repository(config, entry).map_err(GitdCompositionError::Admission)?;
        let summary = if entry.profile.class == crate::DeploymentRepositoryProfile::Protected {
            verify_protected_live_generations(entry, &admitted, &mut authority)?;
            let summary =
                recover_admitted_protected_repository(config, entry, &admitted, &mut authority)
                    .map_err(GitdCompositionError::Recovery)?;
            verify_protected_live_generations(entry, &admitted, &mut authority)?;
            Ok(summary)
        } else {
            recover_admitted_repository(config, entry, &admitted, &mut authority)
        }
        .map_err(GitdCompositionError::Recovery)?;
        recovery.push((entry.repository.clone(), summary));
        admitted_repositories.push(admitted);
    }
    repositories
        .configure_receive_authority(authority)
        .map_err(|_| GitdCompositionError::Backend)?;
    for (entry, admitted) in catalog.repositories.iter().zip(admitted_repositories) {
        repositories
            .add_production(config, entry, admitted)
            .map_err(|_| GitdCompositionError::Backend)?;
    }
    if repositories.len() != catalog.repositories.len() {
        return Err(GitdCompositionError::Backend);
    }
    let shared = repositories
        .into_shared()
        .map_err(|_| GitdCompositionError::Backend)?;
    let authentication = Shared::new(authentication);
    let health = Shared::new(GitdOperationalHealth::starting());
    let operation_limits = Shared::new(
        GitdOperationLimits::new(config.max_uploads, config.max_receives)
            .map_err(|_| GitdCompositionError::Backend)?,
    );
    let mut edge = GitdHttp3Server::new(shared.clone(), cache_bytes)
        .map_err(|_| GitdCompositionError::Cache)?;
    edge.configure_shared_authentication(authentication.clone());
    edge.configure_operational_health(health.clone());
    edge.configure_operation_limits(operation_limits.clone());
    Ok(GitdComposedService {
        edge,
        recovery,
        backend: shared,
        authentication,
        health,
        operation_limits,
    })
}

fn verify_protected_live_generations<A: ProtectedReceiveAuthority>(
    entry: &crate::DeploymentRepository,
    admitted: &crate::AdmittedRepository,
    authority: &mut A,
) -> Result<(), GitdCompositionError> {
    let live = admitted
        .view
        .authority_generations()
        .map_err(|_| GitdCompositionError::Admission(RepositoryAdmissionError::Generation))?;
    let authoritative = authority
        .current_generations(&entry.repository)
        .map_err(|_| GitdCompositionError::Admission(RepositoryAdmissionError::Generation))?;
    if authoritative.0 != live.0
        || authoritative.0.0 < entry.repository_generation.0
        || authoritative.1 != entry.trust_generation
        || authoritative.2 != entry.revocation_generation
    {
        return Err(GitdCompositionError::Admission(
            RepositoryAdmissionError::Generation,
        ));
    }
    admitted
        .view
        .advance_authority_generations(authoritative.0, authoritative.1, authoritative.2)
        .map_err(|_| GitdCompositionError::Admission(RepositoryAdmissionError::Generation))?;
    if admitted
        .view
        .authority_generations()
        .map_err(|_| GitdCompositionError::Admission(RepositoryAdmissionError::Generation))?
        != authoritative
    {
        return Err(GitdCompositionError::Admission(
            RepositoryAdmissionError::Generation,
        ));
    }
    Ok(())
}
