//! Generation-stable, bounded repository queries for the untrusted edge.

use mrml_runtime::Vector;

use crate::{
    ActiveRefFile, BlobPage, CommitPage, GitdCoreError, ObjectId, ObjectKind, QueryLimits,
    Repository, RepositoryGeneration, RepositoryIdentity, RepositoryPath, RepositorySummary,
    TreePage,
};

pub struct FilesystemRepositoryView {
    identity: RepositoryIdentity,
    objects: Repository,
    refs: ActiveRefFile,
}

impl FilesystemRepositoryView {
    pub fn open(
        identity: RepositoryIdentity,
        repository_path: &str,
        active_refs_path: &str,
    ) -> Result<Self, GitdCoreError> {
        let objects = Repository::discover(repository_path).map_err(|_| GitdCoreError::Storage)?;
        let refs = ActiveRefFile::open(active_refs_path).map_err(|_| GitdCoreError::Storage)?;
        let state = refs.load().map_err(|_| GitdCoreError::Storage)?;
        if state.repository != identity || state.object_format != objects.object_format() {
            return Err(GitdCoreError::Authorization);
        }
        Ok(Self {
            identity,
            objects,
            refs,
        })
    }

    pub fn repository_generation(&self) -> Result<RepositoryGeneration, GitdCoreError> {
        Ok(self.load_state()?.repository_generation)
    }

    pub fn repository_summary(
        &self,
        repository: &RepositoryIdentity,
        limits: QueryLimits,
    ) -> Result<RepositorySummary, GitdCoreError> {
        validate_limits(limits)?;
        let state = self.load_for(repository)?;
        if state.refs.len() > limits.max_entries as usize
            || state
                .refs
                .iter()
                .try_fold(0u64, |total, (name, id)| {
                    total
                        .checked_add(name.as_str().len() as u64)
                        .and_then(|value| value.checked_add(id.as_bytes().len() as u64))
                })
                .is_none_or(|bytes| bytes > limits.max_bytes)
        {
            return Err(GitdCoreError::Resource);
        }
        Ok(RepositorySummary {
            repository_generation: state.repository_generation,
            default_branch: state.default_branch,
            object_format: state.object_format,
            refs: state.refs,
        })
    }

    pub fn resolve_ref(
        &self,
        repository: &RepositoryIdentity,
        revision: &str,
    ) -> Result<ObjectId, GitdCoreError> {
        let reference = crate::FullRefName::parse(revision)?;
        let state = self.load_for(repository)?;
        state
            .refs
            .iter()
            .find(|(name, _)| name == &reference)
            .map(|(_, id)| *id)
            .ok_or(GitdCoreError::ObjectValidation)
    }

    pub fn read_commit_page(
        &self,
        repository: &RepositoryIdentity,
        commit: ObjectId,
        limits: QueryLimits,
    ) -> Result<CommitPage, GitdCoreError> {
        validate_limits(limits)?;
        let before = self.load_for(repository)?;
        if commit.format() != before.object_format {
            return Err(GitdCoreError::ObjectValidation);
        }
        let mut commits = Vector::new();
        let mut next = Some(commit);
        let mut bytes = 0u64;
        while let Some(id) = next {
            if commits.len() >= limits.max_entries as usize {
                break;
            }
            let parsed = self
                .objects
                .read_commit(id)
                .map_err(|_| GitdCoreError::ObjectValidation)?;
            bytes = bytes
                .checked_add(id.as_bytes().len() as u64)
                .and_then(|value| value.checked_add(parsed.author.len() as u64))
                .and_then(|value| value.checked_add(parsed.message.len() as u64))
                .ok_or(GitdCoreError::Resource)?;
            if bytes > limits.max_bytes {
                return Err(GitdCoreError::Resource);
            }
            next = parsed.parents.first().copied();
            commits.push(id);
        }
        self.ensure_generation(before.repository_generation)?;
        Ok(CommitPage {
            repository_generation: before.repository_generation,
            commits,
            next,
        })
    }

    pub fn read_tree_page(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        limits: QueryLimits,
    ) -> Result<TreePage, GitdCoreError> {
        validate_limits(limits)?;
        let before = self.load_for(repository)?;
        let tree = self.tree_id(treeish, before.object_format)?;
        let index = self
            .objects
            .tree_index(tree)
            .map_err(|_| GitdCoreError::ObjectValidation)?;
        let prefix = path.as_str();
        let prefix_slash = mrml_runtime::mrml_format!("{prefix}/");
        let mut entries = Vector::new();
        let mut bytes = 0u64;
        for entry in &index.entries {
            if !prefix.is_empty()
                && entry.path != prefix
                && !entry.path.starts_with(prefix_slash.as_str())
            {
                continue;
            }
            if entries.len() >= limits.max_entries as usize {
                break;
            }
            bytes = bytes
                .checked_add(entry.path.len() as u64)
                .ok_or(GitdCoreError::Resource)?;
            if bytes > limits.max_bytes {
                return Err(GitdCoreError::Resource);
            }
            entries.push(RepositoryPath::parse(&entry.path)?);
        }
        let truncated = entries.len()
            < index
                .entries
                .iter()
                .filter(|entry| {
                    prefix.is_empty()
                        || entry.path == prefix
                        || entry.path.starts_with(prefix_slash.as_str())
                })
                .count();
        let next_offset = truncated.then_some(entries.len() as u64);
        self.ensure_generation(before.repository_generation)?;
        Ok(TreePage {
            repository_generation: before.repository_generation,
            tree,
            entries,
            next_offset,
        })
    }

    pub fn read_blob_page(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        limits: QueryLimits,
    ) -> Result<BlobPage, GitdCoreError> {
        validate_limits(limits)?;
        let before = self.load_for(repository)?;
        let tree = self.tree_id(treeish, before.object_format)?;
        let index = self
            .objects
            .tree_index(tree)
            .map_err(|_| GitdCoreError::ObjectValidation)?;
        let entry = index
            .entry(path.as_str())
            .ok_or(GitdCoreError::ObjectValidation)?;
        let object = self
            .objects
            .read_object(entry.id)
            .map_err(|_| GitdCoreError::ObjectValidation)?;
        if object.kind != ObjectKind::Blob {
            return Err(GitdCoreError::ObjectValidation);
        }
        let take = object
            .contents
            .len()
            .min(usize::try_from(limits.max_bytes).map_err(|_| GitdCoreError::Resource)?);
        let mut bytes = Vector::new();
        bytes
            .try_extend_from_slice(&object.contents[..take])
            .map_err(|_| GitdCoreError::Resource)?;
        self.ensure_generation(before.repository_generation)?;
        Ok(BlobPage {
            repository_generation: before.repository_generation,
            blob: entry.id,
            offset: 0,
            bytes,
            complete: take == object.contents.len(),
        })
    }

    fn tree_id(
        &self,
        treeish: ObjectId,
        format: crate::ObjectFormat,
    ) -> Result<ObjectId, GitdCoreError> {
        if treeish.format() != format {
            return Err(GitdCoreError::ObjectValidation);
        }
        let object = self
            .objects
            .read_object(treeish)
            .map_err(|_| GitdCoreError::ObjectValidation)?;
        match object.kind {
            ObjectKind::Tree => Ok(treeish),
            ObjectKind::Commit => self
                .objects
                .read_commit(treeish)
                .map(|commit| commit.tree)
                .map_err(|_| GitdCoreError::ObjectValidation),
            _ => Err(GitdCoreError::ObjectValidation),
        }
    }

    fn load_state(&self) -> Result<crate::ActiveRefState, GitdCoreError> {
        self.refs.load().map_err(|_| GitdCoreError::Storage)
    }

    fn load_for(
        &self,
        repository: &RepositoryIdentity,
    ) -> Result<crate::ActiveRefState, GitdCoreError> {
        if repository != &self.identity {
            return Err(GitdCoreError::Authorization);
        }
        let state = self.load_state()?;
        if state.repository != self.identity || state.object_format != self.objects.object_format()
        {
            return Err(GitdCoreError::Authorization);
        }
        Ok(state)
    }

    fn ensure_generation(&self, expected: RepositoryGeneration) -> Result<(), GitdCoreError> {
        if self.load_state()?.repository_generation == expected {
            Ok(())
        } else {
            Err(GitdCoreError::StaleGeneration)
        }
    }
}

fn validate_limits(limits: QueryLimits) -> Result<(), GitdCoreError> {
    if limits.max_entries == 0 || limits.max_bytes == 0 {
        Err(GitdCoreError::Resource)
    } else {
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use mrml_runtime::join_path;

    use super::*;
    use crate::{
        ActiveRefState, FullRefName, ObjectFormat, PackGeneration, RevocationGeneration,
        TrustGeneration,
    };

    #[test]
    fn queries_are_bounded_identity_scoped_and_generation_tagged() {
        let root = join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-repository-view-{}", mrml_runtime::process_id()),
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        let repository_path = join_path(&root, "objects");
        let refs_path = join_path(&root, "refs");
        let objects = Repository::init_with_format(&repository_path, ObjectFormat::Sha256).unwrap();
        let blob = objects
            .write_object(ObjectKind::Blob, b"bounded view")
            .unwrap();
        let mut tree_bytes = Vector::from(*b"100644 README.md\0");
        tree_bytes.extend(blob.as_bytes().iter().copied());
        let tree = objects.write_object(ObjectKind::Tree, &tree_bytes).unwrap();
        let commit_bytes = mrml_runtime::mrml_format!(
            "tree {}\nauthor Owner <owner@example.invalid> 1 +0000\n\ninitial\n",
            tree.to_hex()
        );
        let commit = objects
            .write_object(ObjectKind::Commit, commit_bytes.as_bytes())
            .unwrap();
        let identity = RepositoryIdentity::parse("owner/repository").unwrap();
        ActiveRefFile::initialize(
            &refs_path,
            &ActiveRefState {
                repository: identity.clone(),
                repository_generation: RepositoryGeneration(4),
                trust_generation: TrustGeneration(5),
                revocation_generation: RevocationGeneration(6),
                pack_generation: PackGeneration(1),
                object_format: ObjectFormat::Sha256,
                default_branch: FullRefName::parse("refs/heads/main").unwrap(),
                refs: [(FullRefName::parse("refs/heads/main").unwrap(), commit)].into(),
            },
        )
        .unwrap();
        let view =
            FilesystemRepositoryView::open(identity.clone(), &repository_path, &refs_path).unwrap();
        let limits = QueryLimits {
            max_entries: 8,
            max_bytes: 1024,
        };
        assert_eq!(view.repository_generation(), Ok(RepositoryGeneration(4)));
        assert_eq!(view.resolve_ref(&identity, "refs/heads/main"), Ok(commit));
        assert_eq!(
            view.repository_summary(&identity, limits)
                .unwrap()
                .repository_generation,
            RepositoryGeneration(4)
        );
        assert_eq!(
            &*view
                .read_commit_page(&identity, commit, limits)
                .unwrap()
                .commits,
            &[commit]
        );
        assert_eq!(
            &*view
                .read_tree_page(&identity, commit, &RepositoryPath::root(), limits)
                .unwrap()
                .entries,
            &[RepositoryPath::parse("README.md").unwrap()]
        );
        let blob_page = view
            .read_blob_page(
                &identity,
                commit,
                &RepositoryPath::parse("README.md").unwrap(),
                QueryLimits {
                    max_entries: 1,
                    max_bytes: 7,
                },
            )
            .unwrap();
        assert_eq!(&*blob_page.bytes, b"bounded");
        assert!(!blob_page.complete);
        assert_eq!(
            view.repository_summary(
                &RepositoryIdentity::parse("other/repository").unwrap(),
                limits,
            ),
            Err(GitdCoreError::Authorization)
        );
        assert_eq!(
            view.repository_summary(
                &identity,
                QueryLimits {
                    max_entries: 0,
                    max_bytes: 1,
                },
            ),
            Err(GitdCoreError::Resource)
        );
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
