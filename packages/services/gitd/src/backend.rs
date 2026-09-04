use std::sync::{Arc, Mutex};

use mrml_http::{
    BackendError, BlobPage, BoundedRead, BoundedWrite, CommitPage, GitdBackend, ObjectId,
    QueryLimits, RepositoryGeneration, RepositoryIdentity, RepositoryPath, RepositorySummary,
    RevocationGeneration, SmartGitRequest, SmartGitResponse, TreePage, TrustGeneration,
    VerificationSummary, WorkBudget,
};
use mrml_runtime::Vector;

use crate::{
    AdmittedRepository, DeploymentRepository, GitdConfig, GitdCoreAdapter,
    ProductionReceiveRepository, RepositoryStorageCapabilities,
};

trait CloneReceiveAuthority: mrml_git::ProtectedReceiveAuthority + Send {
    fn clone_box(&self) -> Box<dyn CloneReceiveAuthority>;
}

impl<T> CloneReceiveAuthority for T
where
    T: mrml_git::ProtectedReceiveAuthority + Send + Clone + 'static,
{
    fn clone_box(&self) -> Box<dyn CloneReceiveAuthority> {
        Box::new(self.clone())
    }
}

type ReceiveAuthority = Mutex<Box<dyn CloneReceiveAuthority>>;

pub struct GitdRepositorySet {
    repositories: Vec<(
        RepositoryIdentity,
        GitdCoreAdapter<mrml_git::FilesystemRepositoryView>,
        Option<ProductionReceiveRepository>,
        Option<ReceiveAuthority>,
        RepositoryStorageCapabilities,
    )>,
    authority_prototype: Option<Box<dyn CloneReceiveAuthority>>,
}

impl GitdRepositorySet {
    pub fn new() -> Self {
        Self {
            repositories: Vec::new(),
            authority_prototype: None,
        }
    }

    pub fn configure_receive_authority<A>(
        &mut self,
        authority: A,
    ) -> Result<(), BackendError>
    where
        A: mrml_git::ProtectedReceiveAuthority + Send + Clone + 'static,
    {
        if self.authority_prototype.is_some() || !self.repositories.is_empty() {
            return Err(BackendError::Unsupported);
        }
        self.authority_prototype = Some(Box::new(authority));
        Ok(())
    }

    pub fn add(
        &mut self,
        entry: &DeploymentRepository,
        admitted: AdmittedRepository,
    ) -> Result<(), BackendError> {
        let identity = RepositoryIdentity::parse(entry.repository.as_str())?;
        if self
            .repositories
            .last()
            .is_some_and(|(previous, _, _, _, _)| previous >= &identity)
        {
            return Err(BackendError::MalformedIdentifier);
        }
        self.repositories.push((
            identity,
            GitdCoreAdapter::new(admitted.view),
            None,
            None,
            admitted.capabilities,
        ));
        Ok(())
    }

    pub fn add_production(
        &mut self,
        config: &GitdConfig,
        entry: &DeploymentRepository,
        admitted: AdmittedRepository,
    ) -> Result<(), BackendError> {
        if self.authority_prototype.is_none() {
            return Err(BackendError::Unsupported);
        }
        let identity = RepositoryIdentity::parse(entry.repository.as_str())?;
        if self
            .repositories
            .last()
            .is_some_and(|(previous, _, _, _, _)| previous >= &identity)
        {
            return Err(BackendError::MalformedIdentifier);
        }
        let receive = ProductionReceiveRepository::new(config, entry, &admitted)?;
        let authority = self
            .authority_prototype
            .as_ref()
            .map(|authority| Mutex::new(authority.clone_box()));
        self.repositories.push((
            identity,
            GitdCoreAdapter::new(admitted.view),
            Some(receive),
            authority,
            admitted.capabilities,
        ));
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.repositories.len()
    }

    pub fn is_empty(&self) -> bool {
        self.repositories.is_empty()
    }

    pub fn into_shared(self) -> Result<SharedGitdRepositorySet, BackendError> {
        let mut repositories = Vec::new();
        repositories
            .try_reserve_exact(self.repositories.len())
            .map_err(|_| BackendError::ResourceLimit)?;
        for (identity, adapter, receive, authority, capabilities) in self.repositories {
            repositories.push((
                identity,
                Mutex::new(adapter),
                receive,
                authority,
                capabilities,
            ));
        }
        Ok(SharedGitdRepositorySet {
            repositories: Arc::new(repositories),
        })
    }

    fn get(
        &self,
        repository: &RepositoryIdentity,
    ) -> Result<&GitdCoreAdapter<mrml_git::FilesystemRepositoryView>, BackendError> {
        self.repositories
            .binary_search_by(|(identity, _, _, _, _)| identity.cmp(repository))
            .map(|index| &self.repositories[index].1)
            .map_err(|_| BackendError::NotFound)
    }
}

#[derive(Clone)]
pub struct SharedGitdRepositorySet {
    repositories: Arc<
        Vec<(
            RepositoryIdentity,
            Mutex<GitdCoreAdapter<mrml_git::FilesystemRepositoryView>>,
            Option<ProductionReceiveRepository>,
            Option<ReceiveAuthority>,
            RepositoryStorageCapabilities,
        )>,
    >,
}

impl SharedGitdRepositorySet {
    pub fn len(&self) -> usize {
        self.repositories.len()
    }
    pub fn is_empty(&self) -> bool {
        self.repositories.is_empty()
    }
    fn index(&self, repository: &RepositoryIdentity) -> Result<usize, BackendError> {
        self.repositories
            .binary_search_by(|(identity, _, _, _, _)| identity.cmp(repository))
            .map_err(|_| BackendError::NotFound)
    }
}

impl GitdBackend for SharedGitdRepositorySet {
    fn candidate_status(
        &self,
        repository: &RepositoryIdentity,
        candidate_id: [u8; 16],
    ) -> Result<Vector<u8>, BackendError> {
        let index = self.index(repository)?;
        let receive = self.repositories[index]
            .2
            .as_ref()
            .ok_or(BackendError::NotFound)?;
        if !receive.requires_authority() {
            return Err(BackendError::NotFound);
        }
        let mut authority = self.repositories[index]
            .3
            .as_ref()
            .ok_or(BackendError::NotFound)?
            .lock()
            .map_err(|_| BackendError::Storage)?;
        let repository = mrml_git::RepositoryIdentity::parse(repository.as_str())
            .map_err(|_| BackendError::NotFound)?;
        receive.candidate_status(
            &repository,
            mrml_git::QuarantineTransactionId(candidate_id),
            authority.as_mut(),
        )
    }

    fn repository_generation(
        &self,
        repository: &RepositoryIdentity,
    ) -> Result<RepositoryGeneration, BackendError> {
        self.repositories[self.index(repository)?]
            .1
            .lock()
            .map_err(|_| BackendError::Storage)?
            .repository_generation(repository)
    }

    fn repository_summary(
        &self,
        repository: &RepositoryIdentity,
        limits: QueryLimits,
    ) -> Result<RepositorySummary, BackendError> {
        self.repositories[self.index(repository)?]
            .1
            .lock()
            .map_err(|_| BackendError::Storage)?
            .repository_summary(repository, limits)
    }

    fn resolve_ref(
        &self,
        repository: &RepositoryIdentity,
        revision: &str,
    ) -> Result<ObjectId, BackendError> {
        self.repositories[self.index(repository)?]
            .1
            .lock()
            .map_err(|_| BackendError::Storage)?
            .resolve_ref(repository, revision)
    }

    fn read_commit_page(
        &self,
        repository: &RepositoryIdentity,
        commit: ObjectId,
        limits: QueryLimits,
    ) -> Result<CommitPage, BackendError> {
        self.repositories[self.index(repository)?]
            .1
            .lock()
            .map_err(|_| BackendError::Storage)?
            .read_commit_page(repository, commit, limits)
    }

    fn read_tree_page(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        limits: QueryLimits,
    ) -> Result<TreePage, BackendError> {
        self.repositories[self.index(repository)?]
            .1
            .lock()
            .map_err(|_| BackendError::Storage)?
            .read_tree_page(repository, treeish, path, limits)
    }

    fn read_blob_page(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        limits: QueryLimits,
    ) -> Result<BlobPage, BackendError> {
        self.repositories[self.index(repository)?]
            .1
            .lock()
            .map_err(|_| BackendError::Storage)?
            .read_blob_page(repository, treeish, path, limits)
    }

    fn verification_summary(
        &self,
        repository: &RepositoryIdentity,
        object: ObjectId,
        policy: TrustGeneration,
        revocations: RevocationGeneration,
    ) -> Result<VerificationSummary, BackendError> {
        self.repositories[self.index(repository)?]
            .1
            .lock()
            .map_err(|_| BackendError::Storage)?
            .verification_summary(repository, object, policy, revocations)
    }

    fn smart_git(
        &mut self,
        request: SmartGitRequest,
        input: &mut dyn BoundedRead,
        output: &mut dyn BoundedWrite,
        budget: WorkBudget,
    ) -> Result<SmartGitResponse, BackendError> {
        let index = self.index(&request.repository)?;
        let mut adapter = self.repositories[index]
            .1
            .lock()
            .map_err(|_| BackendError::Storage)?;
        if request.operation == mrml_http::SmartGitOperation::ReceivePack {
            let receive = self.repositories[index]
                .2
                .as_ref()
                .ok_or(BackendError::Unsupported)?;
            if receive.requires_authority() {
                let mut authority = self.repositories[index]
                    .3
                    .as_ref()
                    .ok_or(BackendError::Unsupported)?
                    .lock()
                    .map_err(|_| BackendError::Storage)?;
                return receive.execute(
                    adapter.core_mut(),
                    Some(authority.as_mut()),
                    request,
                    input,
                    output,
                    budget,
                );
            }
            return receive.execute(adapter.core_mut(), None, request, input, output, budget);
        }
        adapter.smart_git(request, input, output, budget)
    }
}

impl Default for GitdRepositorySet {
    fn default() -> Self {
        Self::new()
    }
}

impl GitdBackend for GitdRepositorySet {
    fn candidate_status(
        &self,
        repository: &RepositoryIdentity,
        candidate_id: [u8; 16],
    ) -> Result<Vector<u8>, BackendError> {
        let index = self
            .repositories
            .binary_search_by(|(identity, _, _, _, _)| identity.cmp(repository))
            .map_err(|_| BackendError::NotFound)?;
        let receive = self.repositories[index]
            .2
            .as_ref()
            .ok_or(BackendError::NotFound)?;
        if !receive.requires_authority() {
            return Err(BackendError::NotFound);
        }
        let mut authority = self.repositories[index]
            .3
            .as_ref()
            .ok_or(BackendError::NotFound)?
            .lock()
            .map_err(|_| BackendError::Storage)?;
        let repository = mrml_git::RepositoryIdentity::parse(repository.as_str())
            .map_err(|_| BackendError::NotFound)?;
        receive.candidate_status(
            &repository,
            mrml_git::QuarantineTransactionId(candidate_id),
            authority.as_mut(),
        )
    }

    fn repository_generation(
        &self,
        repository: &RepositoryIdentity,
    ) -> Result<RepositoryGeneration, BackendError> {
        self.get(repository)?.repository_generation(repository)
    }

    fn repository_summary(
        &self,
        repository: &RepositoryIdentity,
        limits: QueryLimits,
    ) -> Result<RepositorySummary, BackendError> {
        self.get(repository)?.repository_summary(repository, limits)
    }

    fn resolve_ref(
        &self,
        repository: &RepositoryIdentity,
        revision: &str,
    ) -> Result<ObjectId, BackendError> {
        self.get(repository)?.resolve_ref(repository, revision)
    }

    fn read_commit_page(
        &self,
        repository: &RepositoryIdentity,
        commit: ObjectId,
        limits: QueryLimits,
    ) -> Result<CommitPage, BackendError> {
        self.get(repository)?
            .read_commit_page(repository, commit, limits)
    }

    fn read_tree_page(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        limits: QueryLimits,
    ) -> Result<TreePage, BackendError> {
        self.get(repository)?
            .read_tree_page(repository, treeish, path, limits)
    }

    fn read_blob_page(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        limits: QueryLimits,
    ) -> Result<BlobPage, BackendError> {
        self.get(repository)?
            .read_blob_page(repository, treeish, path, limits)
    }

    fn verification_summary(
        &self,
        repository: &RepositoryIdentity,
        object: ObjectId,
        policy: TrustGeneration,
        revocations: RevocationGeneration,
    ) -> Result<VerificationSummary, BackendError> {
        self.get(repository)?
            .verification_summary(repository, object, policy, revocations)
    }

    fn smart_git(
        &mut self,
        request: SmartGitRequest,
        input: &mut dyn BoundedRead,
        output: &mut dyn BoundedWrite,
        budget: WorkBudget,
    ) -> Result<SmartGitResponse, BackendError> {
        let repository = request.repository.clone();
        let index = self
            .repositories
            .binary_search_by(|(identity, _, _, _, _)| identity.cmp(&repository))
            .map_err(|_| BackendError::NotFound)?;
        if request.operation == mrml_http::SmartGitOperation::ReceivePack {
            let (_, adapter, receive, authority, _) = &mut self.repositories[index];
            let receive = receive.as_ref().ok_or(BackendError::Unsupported)?;
            if receive.requires_authority() {
                let mut authority = authority
                    .as_ref()
                    .ok_or(BackendError::Unsupported)?
                    .lock()
                    .map_err(|_| BackendError::Storage)?;
                return receive.execute(
                    adapter.core_mut(),
                    Some(authority.as_mut()),
                    request,
                    input,
                    output,
                    budget,
                );
            }
            return receive.execute(adapter.core_mut(), None, request, input, output, budget);
        }
        self.repositories[index]
            .1
            .smart_git(request, input, output, budget)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_backend_clones_one_exact_repository_index() {
        let shared = GitdRepositorySet::new().into_shared().unwrap();
        let clone = shared.clone();
        assert!(shared.is_empty());
        assert_eq!(clone.len(), 0);
        let missing = RepositoryIdentity::parse("owner/missing").unwrap();
        assert_eq!(
            clone.repository_generation(&missing),
            Err(BackendError::NotFound)
        );
    }
}
