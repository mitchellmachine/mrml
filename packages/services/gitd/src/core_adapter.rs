use mrml_http::{
    BackendError, BlobPage, BoundedRead, BoundedWrite, CommitPage, GitdBackend, ObjectId,
    QueryLimits, RepositoryGeneration, RepositoryIdentity, RepositoryPath, RepositorySummary,
    RevocationGeneration, SmartGitOperation, SmartGitRequest, SmartGitResponse, TreePage,
    TrustGeneration, VerificationState, VerificationSummary, WorkBudget,
};
use mrml_git::{GitdCoreBackend, GitdCoreError, ObjectFormat};
use mrml_runtime::{Text, Vector};

/// Explicit, fail-closed conversion boundary between the public edge model and
/// the authority-bearing Git core contract. The adapter adds no repository
/// authority and supports only SHA-256 repositories, matching the edge's exact
/// 32-byte object identity ABI.
pub struct GitdCoreAdapter<B> {
    core: B,
}

impl<B> GitdCoreAdapter<B> {
    pub const fn new(core: B) -> Self {
        Self { core }
    }

    pub fn into_inner(self) -> B {
        self.core
    }

    pub(crate) fn core_mut(&mut self) -> &mut B {
        &mut self.core
    }
}

fn core_repository(
    value: &RepositoryIdentity,
) -> Result<mrml_git::RepositoryIdentity, BackendError> {
    mrml_git::RepositoryIdentity::parse(value.as_str()).map_err(map_error)
}

fn core_path(value: &RepositoryPath) -> Result<mrml_git::RepositoryPath, BackendError> {
    mrml_git::RepositoryPath::parse(value.as_str()).map_err(map_error)
}

fn core_object(value: &ObjectId) -> Result<mrml_git::ObjectId, BackendError> {
    mrml_git::ObjectId::from_bytes(ObjectFormat::Sha256, &value.0)
        .ok_or(BackendError::MalformedIdentifier)
}

fn edge_object(value: mrml_git::ObjectId) -> Result<ObjectId, BackendError> {
    match value {
        mrml_git::ObjectId::Sha256(bytes) => Ok(ObjectId(bytes)),
        mrml_git::ObjectId::Sha1(_) => Err(BackendError::Unsupported),
    }
}

fn map_error(error: GitdCoreError) -> BackendError {
    match error {
        GitdCoreError::MalformedIdentifier => BackendError::MalformedIdentifier,
        GitdCoreError::MalformedPath => BackendError::MalformedPath,
        GitdCoreError::MalformedInput | GitdCoreError::MalformedRef => {
            BackendError::MalformedRevision
        }
        GitdCoreError::StaleGeneration => BackendError::StaleGeneration,
        GitdCoreError::Resource => BackendError::ResourceLimit,
        GitdCoreError::Unsupported => BackendError::Unsupported,
        GitdCoreError::Authorization
        | GitdCoreError::Ancestry
        | GitdCoreError::Signature
        | GitdCoreError::Policy => BackendError::Private,
        GitdCoreError::ObjectValidation => BackendError::NotFound,
        GitdCoreError::Storage | GitdCoreError::UncertainCommit => BackendError::Storage,
    }
}

struct ReadBridge<'a>(&'a mut dyn BoundedRead);
impl mrml_git::BoundedRead for ReadBridge<'_> {
    fn remaining(&self) -> u64 {
        self.0.remaining()
    }
    fn read(&mut self, output: &mut [u8]) -> Result<usize, GitdCoreError> {
        self.0.read(output).map_err(|_| GitdCoreError::Resource)
    }
}

struct WriteBridge<'a>(&'a mut dyn BoundedWrite);
impl mrml_git::BoundedWrite for WriteBridge<'_> {
    fn remaining(&self) -> u64 {
        self.0.remaining()
    }
    fn write(&mut self, input: &[u8]) -> Result<(), GitdCoreError> {
        self.0.write(input).map_err(|_| GitdCoreError::Resource)
    }
}

impl<B: GitdCoreBackend> GitdBackend for GitdCoreAdapter<B> {
    fn repository_generation(
        &self,
        repository: &RepositoryIdentity,
    ) -> Result<RepositoryGeneration, BackendError> {
        Ok(RepositoryGeneration(
            self.core
                .repository_generation(&core_repository(repository)?)
                .map_err(map_error)?
                .0,
        ))
    }

    fn repository_summary(
        &self,
        repository: &RepositoryIdentity,
        limits: QueryLimits,
    ) -> Result<RepositorySummary, BackendError> {
        let summary = self
            .core
            .repository_summary(
                &core_repository(repository)?,
                mrml_git::QueryLimits {
                    max_entries: limits.max_entries,
                    max_bytes: limits.max_bytes,
                },
            )
            .map_err(map_error)?;
        if summary.object_format != ObjectFormat::Sha256 {
            return Err(BackendError::Unsupported);
        }
        let mut refs = Vector::new();
        for (name, id) in summary.refs {
            refs.try_push((Text::from(name.as_str()), edge_object(id)?))
                .map_err(|_| BackendError::ResourceLimit)?;
        }
        Ok(RepositorySummary {
            generation: RepositoryGeneration(summary.repository_generation.0),
            default_branch: Text::from(summary.default_branch.as_str()),
            description: Text::new(),
            refs,
        })
    }

    fn resolve_ref(
        &self,
        repository: &RepositoryIdentity,
        revision: &str,
    ) -> Result<ObjectId, BackendError> {
        edge_object(
            self.core
                .resolve_ref(&core_repository(repository)?, revision)
                .map_err(map_error)?,
        )
    }

    fn read_commit_page(
        &self,
        repository: &RepositoryIdentity,
        commit: ObjectId,
        limits: QueryLimits,
    ) -> Result<CommitPage, BackendError> {
        let page = self
            .core
            .read_commit_page(
                &core_repository(repository)?,
                core_object(&commit)?,
                mrml_git::QueryLimits {
                    max_entries: limits.max_entries,
                    max_bytes: limits.max_bytes,
                },
            )
            .map_err(map_error)?;
        let mut commits = Vector::new();
        for id in page.commits {
            commits
                .try_push(edge_object(id)?)
                .map_err(|_| BackendError::ResourceLimit)?;
        }
        Ok(CommitPage {
            generation: RepositoryGeneration(page.repository_generation.0),
            commits,
            next: page.next.map(edge_object).transpose()?,
        })
    }

    fn read_tree_page(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        limits: QueryLimits,
    ) -> Result<TreePage, BackendError> {
        let page = self
            .core
            .read_tree_page(
                &core_repository(repository)?,
                core_object(&treeish)?,
                &core_path(path)?,
                mrml_git::QueryLimits {
                    max_entries: limits.max_entries,
                    max_bytes: limits.max_bytes,
                },
            )
            .map_err(map_error)?;
        let mut entries = Vector::new();
        for path in page.entries {
            entries
                .try_push(RepositoryPath::parse(path.as_str())?)
                .map_err(|_| BackendError::ResourceLimit)?;
        }
        Ok(TreePage {
            generation: RepositoryGeneration(page.repository_generation.0),
            entries,
        })
    }

    fn read_blob_page(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        limits: QueryLimits,
    ) -> Result<BlobPage, BackendError> {
        let page = self
            .core
            .read_blob_page(
                &core_repository(repository)?,
                core_object(&treeish)?,
                &core_path(path)?,
                mrml_git::QueryLimits {
                    max_entries: limits.max_entries,
                    max_bytes: limits.max_bytes,
                },
            )
            .map_err(map_error)?;
        Ok(BlobPage {
            generation: RepositoryGeneration(page.repository_generation.0),
            object: edge_object(page.blob)?,
            bytes: page.bytes,
            complete: page.complete,
        })
    }

    fn verification_summary(
        &self,
        repository: &RepositoryIdentity,
        object: ObjectId,
        policy: TrustGeneration,
        revocations: RevocationGeneration,
    ) -> Result<VerificationSummary, BackendError> {
        let summary = self
            .core
            .verification_summary(
                &core_repository(repository)?,
                core_object(&object)?,
                mrml_git::TrustGeneration(policy.0),
                mrml_git::RevocationGeneration(revocations.0),
            )
            .map_err(map_error)?;
        let state = if summary.openpgp_authorized
            && summary.ml_dsa_65_authorized
            && summary.exact_pair_authorized
        {
            VerificationState::MrmlHybridVerified
        } else if summary.openpgp_authorized && summary.ml_dsa_65_authorized {
            VerificationState::PolicyMismatch
        } else if summary.openpgp_authorized {
            VerificationState::OpenPgpOnly
        } else if summary.ml_dsa_65_authorized {
            VerificationState::PostQuantumOnly
        } else {
            VerificationState::Unverified
        };
        let purpose = Text::from(match summary.purpose {
            mrml_git::SignaturePurpose::GitCommit => "git-commit",
            mrml_git::SignaturePurpose::GitAnnotatedTag => "git-annotated-tag",
            mrml_git::SignaturePurpose::SourceManifest => "source-manifest",
            mrml_git::SignaturePurpose::SourceLock => "source-lock",
            mrml_git::SignaturePurpose::BuildReceipt => "build-receipt",
            mrml_git::SignaturePurpose::KeyRotation => "key-rotation",
            mrml_git::SignaturePurpose::KeyRevocation => "key-revocation",
            mrml_git::SignaturePurpose::EmergencyRecovery => "emergency-recovery",
        });
        Ok(VerificationSummary {
            state,
            openpgp_fingerprint: Text::new(),
            ml_dsa_public_key_digest: Text::new(),
            algorithms: Text::from("OpenPGP+ML-DSA-65"),
            signature_hash: Text::new(),
            repository: repository.clone(),
            purpose,
            trust_generation: TrustGeneration(summary.trust_generation.0),
            revocation_generation: RevocationGeneration(summary.revocation_generation.0),
            history_since_cutover_verified: summary.exact_pair_authorized,
        })
    }

    fn smart_git(
        &mut self,
        request: SmartGitRequest,
        input: &mut dyn BoundedRead,
        output: &mut dyn BoundedWrite,
        budget: WorkBudget,
    ) -> Result<SmartGitResponse, BackendError> {
        let operation = match request.operation {
            SmartGitOperation::Discovery => {
                let repository = core_repository(&request.repository)?;
                let summary = self
                    .core
                    .repository_summary(
                        &repository,
                        mrml_git::QueryLimits {
                            max_entries: 1,
                            max_bytes: 4096,
                        },
                    )
                    .map_err(map_error)?;
                if summary.repository_generation.0 != request.generation.0 {
                    return Err(BackendError::StaleGeneration);
                }
                if summary.object_format != ObjectFormat::Sha256 {
                    return Err(BackendError::Unsupported);
                }
                let output_limit = budget.max_output_bytes;
                let mut protocol = mrml_git::ProtocolBudget::new(mrml_git::WorkBudget {
                    max_input_bytes: budget.max_input_bytes,
                    max_output_bytes: budget.max_output_bytes,
                    max_memory_bytes: budget.max_memory_bytes,
                    max_work_units: budget.max_work_units,
                });
                mrml_git::write_v2_capability_advertisement(
                    &mut WriteBridge(output),
                    ObjectFormat::Sha256,
                    &mut protocol,
                )
                .map_err(map_error)?;
                return Ok(SmartGitResponse {
                    generation: request.generation,
                    bytes_read: 0,
                    bytes_written: output_limit - protocol.output_remaining(),
                    refs_activated: false,
                });
            }
            SmartGitOperation::UploadPack => mrml_git::SmartGitOperation::UploadPack,
            SmartGitOperation::ReceivePack => mrml_git::SmartGitOperation::ReceivePack,
        };
        let response = self
            .core
            .smart_git(
                mrml_git::SmartGitRequest {
                    repository: core_repository(&request.repository)?,
                    repository_generation: mrml_git::RepositoryGeneration(request.generation.0),
                    operation,
                    object_format: ObjectFormat::Sha256,
                },
                &mut ReadBridge(input),
                &mut WriteBridge(output),
                mrml_git::WorkBudget {
                    max_input_bytes: budget.max_input_bytes,
                    max_output_bytes: budget.max_output_bytes,
                    max_memory_bytes: budget.max_memory_bytes,
                    max_work_units: budget.max_work_units,
                },
            )
            .map_err(map_error)?;
        Ok(SmartGitResponse {
            generation: RepositoryGeneration(response.repository_generation.0),
            bytes_read: response.bytes_read,
            bytes_written: response.bytes_written,
            refs_activated: response.refs_activated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CoreMock {
        format: ObjectFormat,
    }

    impl GitdCoreBackend for CoreMock {
        fn repository_generation(
            &self,
            _: &mrml_git::RepositoryIdentity,
        ) -> Result<mrml_git::RepositoryGeneration, GitdCoreError> {
            Ok(mrml_git::RepositoryGeneration(7))
        }
        fn repository_summary(
            &self,
            _: &mrml_git::RepositoryIdentity,
            _: mrml_git::QueryLimits,
        ) -> Result<mrml_git::RepositorySummary, GitdCoreError> {
            let id = self.format.hash_bytes(b"commit 0\0");
            let mut refs = Vector::new();
            refs.push((mrml_git::FullRefName::parse("refs/heads/main")?, id));
            Ok(mrml_git::RepositorySummary {
                repository_generation: mrml_git::RepositoryGeneration(7),
                default_branch: mrml_git::FullRefName::parse("refs/heads/main")?,
                object_format: self.format,
                refs,
            })
        }
        fn resolve_ref(
            &self,
            _: &mrml_git::RepositoryIdentity,
            _: &str,
        ) -> Result<mrml_git::ObjectId, GitdCoreError> {
            Ok(self.format.hash_bytes(b"commit 0\0"))
        }
        fn read_commit_page(
            &self,
            _: &mrml_git::RepositoryIdentity,
            _: mrml_git::ObjectId,
            _: mrml_git::QueryLimits,
        ) -> Result<mrml_git::CommitPage, GitdCoreError> {
            Err(GitdCoreError::Unsupported)
        }
        fn read_tree_page(
            &self,
            _: &mrml_git::RepositoryIdentity,
            _: mrml_git::ObjectId,
            _: &mrml_git::RepositoryPath,
            _: mrml_git::QueryLimits,
        ) -> Result<mrml_git::TreePage, GitdCoreError> {
            Err(GitdCoreError::Unsupported)
        }
        fn read_blob_page(
            &self,
            _: &mrml_git::RepositoryIdentity,
            _: mrml_git::ObjectId,
            _: &mrml_git::RepositoryPath,
            _: mrml_git::QueryLimits,
        ) -> Result<mrml_git::BlobPage, GitdCoreError> {
            Err(GitdCoreError::Unsupported)
        }
        fn verification_summary(
            &self,
            _: &mrml_git::RepositoryIdentity,
            _: mrml_git::ObjectId,
            _: mrml_git::TrustGeneration,
            _: mrml_git::RevocationGeneration,
        ) -> Result<mrml_git::VerificationSummary, GitdCoreError> {
            Err(GitdCoreError::Signature)
        }
        fn smart_git(
            &mut self,
            _: mrml_git::SmartGitRequest,
            _: &mut dyn mrml_git::BoundedRead,
            _: &mut dyn mrml_git::BoundedWrite,
            _: mrml_git::WorkBudget,
        ) -> Result<mrml_git::SmartGitResponse, GitdCoreError> {
            Err(GitdCoreError::Authorization)
        }
    }

    #[test]
    fn adapter_preserves_generation_and_rejects_sha1_without_truncation() {
        let repository = RepositoryIdentity::parse("mitchellrenouf/mrml").unwrap();
        let sha256 = GitdCoreAdapter::new(CoreMock {
            format: ObjectFormat::Sha256,
        });
        assert_eq!(
            sha256.repository_generation(&repository),
            Ok(RepositoryGeneration(7))
        );
        let summary = sha256
            .repository_summary(
                &repository,
                QueryLimits {
                    max_entries: 8,
                    max_bytes: 4096,
                },
            )
            .unwrap();
        assert_eq!(summary.default_branch, "refs/heads/main");
        assert_eq!(summary.refs.len(), 1);

        let sha1 = GitdCoreAdapter::new(CoreMock {
            format: ObjectFormat::Sha1,
        });
        assert_eq!(
            sha1.repository_summary(
                &repository,
                QueryLimits {
                    max_entries: 8,
                    max_bytes: 4096
                }
            ),
            Err(BackendError::Unsupported)
        );
    }
}
