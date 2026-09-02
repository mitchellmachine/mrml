use std::sync::{Arc, Mutex};

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

    pub fn into_shared(self) -> Result<SharedGitdRepositorySet, BackendError> {
        let mut repositories = Vec::new();
        repositories
            .try_reserve_exact(self.repositories.len())
            .map_err(|_| BackendError::ResourceLimit)?;
        for (identity, adapter) in self.repositories {
            repositories.push((identity, Mutex::new(adapter)));
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

#[derive(Clone)]
pub struct SharedGitdRepositorySet {
    repositories: Arc<
        Vec<(
            RepositoryIdentity,
            Mutex<GitdCoreAdapter<mrml_git::FilesystemRepositoryView>>,
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
            .binary_search_by(|(identity, _)| identity.cmp(repository))
            .map_err(|_| BackendError::NotFound)
    }
}

impl GitdBackend for SharedGitdRepositorySet {
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
        self.repositories[index]
            .1
            .lock()
            .map_err(|_| BackendError::Storage)?
            .smart_git(request, input, output, budget)
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
