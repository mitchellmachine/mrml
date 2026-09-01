use mrml_http::{
    BackendError, BlobPage, BoundedRead, BoundedWrite, CommitPage, GitdBackend, GitdCoreAdapter,
    ObjectId, QueryLimits, RepositoryGeneration, RepositoryIdentity, RepositoryPath,
    RepositorySummary, RevocationGeneration, SmartGitRequest, SmartGitResponse, TreePage,
    TrustGeneration, VerificationSummary, WorkBudget,
};

use crate::{AdmittedRepository, DeploymentRepository};

pub struct GitdRepositorySet {
    repositories: Vec<(
        RepositoryIdentity,
        GitdCoreAdapter<mrml_git::FilesystemRepositoryView>,
    )>,
}

impl GitdRepositorySet {
    pub fn new() -> Self {
        Self {
            repositories: Vec::new(),
        }
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
            .is_some_and(|(previous, _)| previous >= &identity)
        {
            return Err(BackendError::MalformedIdentifier);
        }
        self.repositories
            .push((identity, GitdCoreAdapter::new(admitted.view)));
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.repositories.len()
    }

    pub fn is_empty(&self) -> bool {
        self.repositories.is_empty()
    }

    fn get(
        &self,
        repository: &RepositoryIdentity,
    ) -> Result<&GitdCoreAdapter<mrml_git::FilesystemRepositoryView>, BackendError> {
        self.repositories
            .binary_search_by(|(identity, _)| identity.cmp(repository))
            .map(|index| &self.repositories[index].1)
            .map_err(|_| BackendError::NotFound)
    }

    fn get_mut(
        &mut self,
        repository: &RepositoryIdentity,
    ) -> Result<&mut GitdCoreAdapter<mrml_git::FilesystemRepositoryView>, BackendError> {
        self.repositories
            .binary_search_by(|(identity, _)| identity.cmp(repository))
            .map(|index| &mut self.repositories[index].1)
            .map_err(|_| BackendError::NotFound)
    }
}

impl Default for GitdRepositorySet {
    fn default() -> Self {
        Self::new()
    }
}

impl GitdBackend for GitdRepositorySet {
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
        self.get_mut(&repository)?
            .smart_git(request, input, output, budget)
    }
}
