use mrml_git::{AuditReceiptAuthority, RepositoryIdentity};
use mrml_http::GitdHttp3Server;

use crate::{
    AuthenticationStoreError, DeploymentCatalog, GitdConfig, GitdRepositorySet,
    RepositoryAdmissionError, RepositoryRecoveryError, RepositoryRecoverySummary,
    admit_catalog_repository, load_gitd_authentication, recover_admitted_repository,
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
    pub edge: GitdHttp3Server<GitdRepositorySet>,
    pub recovery: Vec<(RepositoryIdentity, RepositoryRecoverySummary)>,
}

/// Construct the routable Git service only after every catalog repository is
/// admitted against live generations and every durable receive journal has a
/// non-ambiguous recovery result.
pub fn compose_gitd_service(
    config: &GitdConfig,
    catalog: &DeploymentCatalog,
    receipt_authority: &mut dyn AuditReceiptAuthority,
    cache_bytes: usize,
) -> Result<GitdComposedService, GitdCompositionError> {
    if catalog.repositories.is_empty() {
        return Err(GitdCompositionError::Backend);
    }
    let authentication =
        load_gitd_authentication(config, catalog).map_err(GitdCompositionError::Authentication)?;
    let mut repositories = GitdRepositorySet::new();
    let mut recovery = Vec::new();
    recovery
        .try_reserve_exact(catalog.repositories.len())
        .map_err(|_| GitdCompositionError::Backend)?;
    for entry in &catalog.repositories {
        let admitted =
            admit_catalog_repository(config, entry).map_err(GitdCompositionError::Admission)?;
        let summary = recover_admitted_repository(config, entry, &admitted, receipt_authority)
            .map_err(GitdCompositionError::Recovery)?;
        recovery.push((entry.repository.clone(), summary));
        repositories
            .add(entry, admitted)
            .map_err(|_| GitdCompositionError::Backend)?;
    }
    if repositories.len() != catalog.repositories.len() {
        return Err(GitdCompositionError::Backend);
    }
    let mut edge =
        GitdHttp3Server::new(repositories, cache_bytes).map_err(|_| GitdCompositionError::Cache)?;
    edge.configure_authentication(authentication);
    Ok(GitdComposedService { edge, recovery })
}
