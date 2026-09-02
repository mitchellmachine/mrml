//! Generation-stable, bounded repository queries for the untrusted edge.

use mrml_runtime::Vector;

use crate::{
    encode_pack_with_format, parse_tree_with_format, read_v2_request, write_pkt_line,
    ActiveRefFile, AnnotatedTagDetails, AnnotatedTagPage, ArrivalPackStore, BlobPage, BoundedRead,
    BoundedWrite, Commit, CommitDetails, CommitPage, FullRefName, GitdCoreBackend, GitdCoreError,
    ImmutablePackCacheDirectory, ImmutablePackDescriptor, Index, IndexEntry, ObjectFormat,
    ObjectId, ObjectKind, PackCacheFileError, PackCacheKey, PackError, PackGeneration, PackObject,
    PackSetLimits, PackSetManifest, PackStreamEncoder, PackStreamOutput, PktLine, ProtocolBudget,
    ProtocolV2Request, QueryLimits, ReadmeCandidate, Repository, RepositoryEvent,
    RepositoryEventCursor, RepositoryEventPage, RepositoryGeneration, RepositoryIdentity,
    RepositoryPath, RepositorySummary, RevocationGeneration, SmartGitOperation, SmartGitRequest,
    SmartGitResponse, TreePage, TrustGeneration, VerificationSummary, VerifiedCommitProof,
    VerifiedGitObjectProof, VerifiedMetadataDescriptor, WorkBudget,
};

pub const MAX_VERIFICATION_SUMMARY_EVIDENCE: usize = 5_000;
const SELECTED_PACK_SET_LIMITS: PackSetLimits = PackSetLimits {
    max_packs: 65_536,
    max_objects: 10_000_000,
    max_pack_bytes: 8 * 1024 * 1024 * 1024 * 1024,
    max_index_bytes: 16 * 1024 * 1024 * 1024,
    max_work_units: 16 * 1024 * 1024 * 1024 * 1024,
};
const FETCH_PACK_PROFILE_VERSION: u32 = 1;
const FETCH_PACK_ENCODER_VERSION: u32 = 1;
const MAX_FETCH_PRECOMPUTE_REFS: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationSummaryEvidence {
    repository: RepositoryIdentity,
    repository_generation: RepositoryGeneration,
    summary: VerificationSummary,
}

impl VerificationSummaryEvidence {
    pub fn from_verified_hybrid_commit(proof: &VerifiedCommitProof) -> Self {
        Self {
            repository: proof.repository.clone(),
            repository_generation: proof.repository_generation,
            summary: VerificationSummary {
                object: proof.commit,
                trust_generation: proof.trust_generation,
                revocation_generation: proof.revocation_generation,
                purpose: proof.purpose,
                openpgp_authorized: true,
                ml_dsa_65_authorized: true,
                exact_pair_authorized: true,
                hybrid_required: true,
            },
        }
    }

    pub fn from_verified_git_object(proof: &VerifiedGitObjectProof) -> Self {
        Self {
            repository: proof.repository.clone(),
            repository_generation: proof.repository_generation,
            summary: VerificationSummary {
                object: proof.object,
                trust_generation: proof.trust_generation,
                revocation_generation: proof.revocation_generation,
                purpose: proof.purpose,
                openpgp_authorized: true,
                ml_dsa_65_authorized: true,
                exact_pair_authorized: true,
                hybrid_required: true,
            },
        }
    }
}

/// Read-only exact evidence installed by the verification authority. Merely
/// possessing object IDs or repository files cannot add an entry.
pub struct VerificationSummaryStore {
    evidence: Vector<VerificationSummaryEvidence>,
}

impl VerificationSummaryStore {
    pub fn new(evidence: Vector<VerificationSummaryEvidence>) -> Result<Self, GitdCoreError> {
        if evidence.len() > MAX_VERIFICATION_SUMMARY_EVIDENCE
            || !evidence
                .windows(2)
                .all(|pair| evidence_less(&pair[0], &pair[1]))
        {
            return Err(GitdCoreError::ObjectValidation);
        }
        Ok(Self { evidence })
    }

    fn exact(
        &self,
        repository: &RepositoryIdentity,
        repository_generation: RepositoryGeneration,
        object: ObjectId,
        trust: TrustGeneration,
        revocations: RevocationGeneration,
    ) -> Option<VerificationSummary> {
        self.evidence
            .iter()
            .find(|evidence| {
                &evidence.repository == repository
                    && evidence.repository_generation == repository_generation
                    && evidence.summary.object == object
                    && evidence.summary.trust_generation == trust
                    && evidence.summary.revocation_generation == revocations
            })
            .map(|evidence| evidence.summary.clone())
    }
}

fn evidence_less(left: &VerificationSummaryEvidence, right: &VerificationSummaryEvidence) -> bool {
    (
        &left.repository,
        left.repository_generation,
        left.summary.object,
        left.summary.trust_generation,
        left.summary.revocation_generation,
    ) < (
        &right.repository,
        right.repository_generation,
        right.summary.object,
        right.summary.trust_generation,
        right.summary.revocation_generation,
    )
}

fn append_reachable_children(
    object: &crate::Object,
    format: crate::ObjectFormat,
    pending: &mut Vector<ObjectId>,
) -> Result<(), GitdCoreError> {
    match object.kind {
        ObjectKind::Commit => {
            let commit = Commit::parse_with_format(&object.contents, format)
                .map_err(|_| GitdCoreError::ObjectValidation)?;
            pending.push(commit.tree);
            pending.extend(commit.parents.iter().copied());
        }
        ObjectKind::Tree => pending.extend(
            parse_tree_with_format(&object.contents, format)
                .map_err(|_| GitdCoreError::ObjectValidation)?
                .iter()
                .map(|entry| entry.id),
        ),
        ObjectKind::Tag => {
            let target = core::str::from_utf8(&object.contents)
                .ok()
                .and_then(|text| text.lines().find_map(|line| line.strip_prefix("object ")))
                .and_then(|text| ObjectId::parse_for(format, text))
                .ok_or(GitdCoreError::ObjectValidation)?;
            pending.push(target);
        }
        ObjectKind::Blob => {}
    }
    Ok(())
}

pub struct FilesystemRepositoryView {
    identity: RepositoryIdentity,
    objects: Repository,
    refs: ActiveRefFile,
    arrivals: Option<ArrivalPackStore>,
    pack_cache: Option<ImmutablePackCacheDirectory>,
    verification: VerificationSummaryStore,
}

impl GitdCoreBackend for FilesystemRepositoryView {
    fn repository_generation(
        &self,
        repository: &RepositoryIdentity,
    ) -> Result<RepositoryGeneration, GitdCoreError> {
        Ok(self.load_for(repository)?.repository_generation)
    }

    fn repository_summary(
        &self,
        repository: &RepositoryIdentity,
        limits: QueryLimits,
    ) -> Result<RepositorySummary, GitdCoreError> {
        Self::repository_summary(self, repository, limits)
    }

    fn resolve_ref(
        &self,
        repository: &RepositoryIdentity,
        revision: &str,
    ) -> Result<ObjectId, GitdCoreError> {
        Self::resolve_ref(self, repository, revision)
    }

    fn read_commit_page(
        &self,
        repository: &RepositoryIdentity,
        commit: ObjectId,
        limits: QueryLimits,
    ) -> Result<CommitPage, GitdCoreError> {
        Self::read_commit_page(self, repository, commit, limits)
    }

    fn read_commit_details(
        &self,
        repository: &RepositoryIdentity,
        commit: ObjectId,
        limits: QueryLimits,
    ) -> Result<CommitDetails, GitdCoreError> {
        Self::read_commit_details(self, repository, commit, limits)
    }

    fn read_annotated_tag_page(
        &self,
        repository: &RepositoryIdentity,
        offset: u64,
        limits: QueryLimits,
    ) -> Result<AnnotatedTagPage, GitdCoreError> {
        Self::read_annotated_tag_page(self, repository, offset, limits)
    }

    fn read_annotated_tag_details(
        &self,
        repository: &RepositoryIdentity,
        reference: &crate::FullRefName,
        limits: QueryLimits,
    ) -> Result<AnnotatedTagDetails, GitdCoreError> {
        Self::read_annotated_tag_details(self, repository, reference, limits)
    }

    fn read_tree_page(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        limits: QueryLimits,
    ) -> Result<TreePage, GitdCoreError> {
        Self::read_tree_page(self, repository, treeish, path, limits)
    }

    fn read_tree_page_at(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        offset: u64,
        limits: QueryLimits,
    ) -> Result<TreePage, GitdCoreError> {
        Self::read_tree_page_at(self, repository, treeish, path, offset, limits)
    }

    fn read_blob_page(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        limits: QueryLimits,
    ) -> Result<BlobPage, GitdCoreError> {
        Self::read_blob_page(self, repository, treeish, path, limits)
    }

    fn read_blob_page_at(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        offset: u64,
        limits: QueryLimits,
    ) -> Result<BlobPage, GitdCoreError> {
        Self::read_blob_page_at(self, repository, treeish, path, offset, limits)
    }

    fn read_verified_metadata(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        purpose: crate::SignaturePurpose,
        policy: TrustGeneration,
        revocations: RevocationGeneration,
        limits: QueryLimits,
    ) -> Result<VerifiedMetadataDescriptor, GitdCoreError> {
        Self::read_verified_metadata(
            self,
            repository,
            treeish,
            path,
            purpose,
            policy,
            revocations,
            limits,
        )
    }

    fn resolve_readme_candidate(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
    ) -> Result<Option<ReadmeCandidate>, GitdCoreError> {
        Self::resolve_readme_candidate(self, repository, treeish)
    }

    fn immutable_pack_descriptor(
        &self,
        repository: &RepositoryIdentity,
        commit: ObjectId,
    ) -> Result<ImmutablePackDescriptor, GitdCoreError> {
        Self::immutable_pack_descriptor(self, repository, commit)
    }

    fn repository_events_after(
        &self,
        repository: &RepositoryIdentity,
        cursor: RepositoryEventCursor,
        limits: QueryLimits,
    ) -> Result<RepositoryEventPage, GitdCoreError> {
        Self::repository_events_after(self, repository, cursor, limits)
    }

    fn verification_summary(
        &self,
        repository: &RepositoryIdentity,
        object: ObjectId,
        policy: TrustGeneration,
        revocations: RevocationGeneration,
    ) -> Result<VerificationSummary, GitdCoreError> {
        let state = self.load_for(repository)?;
        if policy != state.trust_generation || revocations != state.revocation_generation {
            return Err(GitdCoreError::StaleGeneration);
        }
        if object.is_zero() || object.format() != state.object_format {
            return Err(GitdCoreError::ObjectValidation);
        }
        self.read_object(&state, object)?;
        let summary = self
            .verification
            .exact(
                repository,
                state.repository_generation,
                object,
                policy,
                revocations,
            )
            .ok_or(GitdCoreError::Signature)?;
        self.ensure_exact_generation(&state)?;
        Ok(summary)
    }

    fn smart_git(
        &mut self,
        request: SmartGitRequest,
        input: &mut dyn BoundedRead,
        output: &mut dyn BoundedWrite,
        budget: WorkBudget,
    ) -> Result<SmartGitResponse, GitdCoreError> {
        if request.operation != SmartGitOperation::UploadPack {
            return Err(GitdCoreError::Unsupported);
        }
        let state = self.load_for(&request.repository)?;
        if state.repository_generation != request.repository_generation
            || state.object_format != request.object_format
        {
            return Err(GitdCoreError::StaleGeneration);
        }
        if budget.max_input_bytes == 0
            || budget.max_output_bytes == 0
            || budget.max_memory_bytes == 0
            || budget.max_work_units == 0
        {
            return Err(GitdCoreError::Resource);
        }
        let mut protocol = ProtocolBudget::new(budget);
        match read_v2_request(input, request.object_format, &mut protocol)? {
            ProtocolV2Request::LsRefs {
                peel,
                symrefs,
                unborn,
                prefixes,
            } => {
                self.write_ls_refs(
                    &state,
                    peel,
                    symrefs,
                    unborn,
                    &prefixes,
                    output,
                    &mut protocol,
                )?;
            }
            ProtocolV2Request::Fetch {
                wants,
                haves,
                done,
                thin_pack,
                ofs_delta: _,
                sideband_all,
            } => {
                if !done || thin_pack || sideband_all || wants.is_empty() {
                    return Err(GitdCoreError::Unsupported);
                }
                if wants
                    .iter()
                    .any(|want| !state.refs.iter().any(|(_, id)| id == want))
                {
                    return Err(GitdCoreError::Authorization);
                }
                if self.pack_cache.is_none() {
                    self.stream_pack_response(
                        &state,
                        &wants,
                        &haves,
                        output,
                        &mut protocol,
                        budget.max_memory_bytes,
                    )?;
                } else {
                    let pack = self.fetch_pack(&state, &wants, &haves)?;
                    if pack.len() as u64 > budget.max_memory_bytes {
                        return Err(GitdCoreError::Resource);
                    }
                    self.ensure_exact_generation(&state)?;
                    preflight_pack_response(pack.len(), output, protocol)?;
                    write_data_line(output, b"packfile\n", &mut protocol)?;
                    for chunk in pack.chunks(crate::MAX_PKT_LINE_BYTES - 5) {
                        let mut payload = Vector::new();
                        payload
                            .try_reserve_exact(chunk.len() + 1)
                            .map_err(|_| GitdCoreError::Resource)?;
                        payload.push(1);
                        payload
                            .try_extend_from_slice(chunk)
                            .map_err(|_| GitdCoreError::Resource)?;
                        write_pkt_line(output, &PktLine::Data(payload), &mut protocol)?;
                    }
                }
                write_pkt_line(output, &PktLine::Flush, &mut protocol)?;
            }
        }
        Ok(SmartGitResponse {
            repository_generation: state.repository_generation,
            bytes_read: budget.max_input_bytes - protocol.input_remaining(),
            bytes_written: budget.max_output_bytes - protocol.output_remaining(),
            refs_activated: false,
        })
    }
}

impl FilesystemRepositoryView {
    /// Creates the canonical empty SHA-256 state used by a deployment-owned
    /// repository catalog. The initial root commit is deterministic and carries
    /// no authorization; protected policy activation remains a separate gate.
    pub fn initialize_sha256(
        identity: RepositoryIdentity,
        objects_path: &str,
        state_path: &str,
        repository_generation: RepositoryGeneration,
        trust_generation: TrustGeneration,
        revocation_generation: RevocationGeneration,
    ) -> Result<Self, GitdCoreError> {
        if repository_generation.0 == 0 || trust_generation.0 == 0 || revocation_generation.0 == 0 {
            return Err(GitdCoreError::Policy);
        }
        let repository = Repository::init_with_format(objects_path, ObjectFormat::Sha256)
            .map_err(|_| GitdCoreError::Storage)?;
        let tree = repository
            .write_object(ObjectKind::Tree, &[])
            .map_err(|_| GitdCoreError::Storage)?;
        let contents = mrml_runtime::mrml_format!(
            "tree {}\nauthor MRML Deployment <deployment@mrml.invalid> 1 +0000\ncommitter MRML Deployment <deployment@mrml.invalid> 1 +0000\n\nMRML repository initialization\n",
            tree.to_hex()
        );
        let tip = repository
            .write_object(ObjectKind::Commit, contents.as_bytes())
            .map_err(|_| GitdCoreError::Storage)?;
        let manifest = crate::pack_set::build_pack_set_manifest(
            identity.clone(),
            repository_generation,
            PackGeneration(1),
            ObjectFormat::Sha256,
            Vector::new(),
            SELECTED_PACK_SET_LIMITS,
        )
        .map_err(|_| GitdCoreError::Storage)?;
        let pack_set_digest = manifest.digest().map_err(|_| GitdCoreError::Storage)?;
        ActiveRefFile::initialize_with_pack_set(
            state_path,
            &crate::ActiveRefState {
                repository: identity.clone(),
                repository_generation,
                trust_generation,
                revocation_generation,
                pack_generation: PackGeneration(1),
                pack_set_digest,
                object_format: ObjectFormat::Sha256,
                default_branch: FullRefName::parse("refs/heads/main")?,
                refs: [(FullRefName::parse("refs/heads/main")?, tip)].into(),
            },
            &manifest,
        )
        .map_err(|_| GitdCoreError::Storage)?;
        Self::open(identity, objects_path, state_path)
    }

    /// Executes one conventional fast-forward receive against the same
    /// authenticated object and ref stores used by reads. Edge authentication
    /// and profile authorization must already have succeeded.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_conventional_receive(
        &mut self,
        request: SmartGitRequest,
        store: &mut crate::LinuxDurableReceiveStore,
        transaction: crate::QuarantineTransactionId,
        quarantine_limits: crate::QuarantineLimits,
        history_limits: crate::HistoryVerificationLimits,
        ordinary_free_bytes: u64,
        input: &mut dyn BoundedRead,
        output: &mut dyn BoundedWrite,
        work_budget: WorkBudget,
    ) -> Result<SmartGitResponse, GitdCoreError> {
        let active = self.refs.load().map_err(|_| GitdCoreError::Storage)?;
        if active.repository != self.identity
            || request.repository != self.identity
            || request.repository_generation != active.repository_generation
            || request.object_format != active.object_format
        {
            return Err(GitdCoreError::StaleGeneration);
        }
        let prepared = crate::prepare_conventional_receive(
            request,
            &active,
            &self.objects,
            store,
            transaction,
            quarantine_limits,
            history_limits,
            ordinary_free_bytes,
            input,
            work_budget,
        )?;
        crate::finish_prepared_conventional_receive(prepared, store, output, work_budget)
    }

    /// Executes one protected receive against the same authenticated object
    /// and ref stores used by reads. Callers retain authority, policy, storage,
    /// resource, and transaction-ID ownership.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_protected_receive(
        &mut self,
        request: SmartGitRequest,
        store: &mut crate::LinuxDurableReceiveStore,
        policy: &crate::TrustPolicyState,
        signed_receipts_path: &str,
        authority: &mut dyn crate::ProtectedReceiveAuthority,
        transaction: crate::QuarantineTransactionId,
        quarantine_limits: crate::QuarantineLimits,
        history_limits: crate::HistoryVerificationLimits,
        ordinary_free_bytes: u64,
        input: &mut dyn BoundedRead,
        output: &mut dyn BoundedWrite,
        work_budget: WorkBudget,
    ) -> Result<SmartGitResponse, GitdCoreError> {
        let active = self.refs.load().map_err(|_| GitdCoreError::Storage)?;
        if active.repository != self.identity
            || request.repository != self.identity
            || request.repository_generation != active.repository_generation
            || request.object_format != active.object_format
        {
            return Err(GitdCoreError::StaleGeneration);
        }
        crate::ReceivePackCore {
            request,
            transaction,
            quarantine_limits,
            history_limits,
            ordinary_free_bytes,
            work_budget,
        }
        .execute_with_authority(
            &active,
            &self.objects,
            store,
            policy,
            signed_receipts_path,
            authority,
            input,
            output,
        )
    }

    fn stream_pack_response(
        &self,
        state: &crate::ActiveRefState,
        wants: &[ObjectId],
        haves: &[ObjectId],
        output: &mut dyn BoundedWrite,
        protocol: &mut ProtocolBudget,
        max_object_memory: u64,
    ) -> Result<(), GitdCoreError> {
        let ids = self.negotiated_object_ids(state, wants, haves)?;
        self.ensure_exact_generation(state)?;
        write_data_line(output, b"packfile\n", protocol)?;
        let mut sideband = SidebandPackWriter::new(output, protocol);
        let result = (|| {
            let mut encoder = PackStreamEncoder::new(ids.len(), state.object_format, &mut sideband)
                .map_err(|_| GitdCoreError::ObjectValidation)?;
            for id in ids {
                let object = self.read_object(state, id)?;
                if object.contents.len() as u64 > max_object_memory {
                    return Err(GitdCoreError::Resource);
                }
                encoder
                    .write_object(&PackObject {
                        id,
                        kind: object.kind,
                        contents: object.contents,
                    })
                    .map_err(|_| GitdCoreError::ObjectValidation)?;
            }
            encoder
                .finish()
                .map_err(|_| GitdCoreError::ObjectValidation)
        })();
        if let Some(error) = sideband.failure {
            return Err(error);
        }
        result?;
        self.ensure_exact_generation(state)
    }

    fn write_ls_refs(
        &self,
        state: &crate::ActiveRefState,
        peel: bool,
        symrefs: bool,
        unborn: bool,
        prefixes: &[Vector<u8>],
        output: &mut dyn BoundedWrite,
        budget: &mut ProtocolBudget,
    ) -> Result<(), GitdCoreError> {
        let default = state
            .refs
            .iter()
            .find(|(name, _)| name == &state.default_branch)
            .map(|(_, id)| *id);
        if prefix_matches(b"HEAD", prefixes) {
            if let Some(id) = default {
                let mut line = mrml_runtime::mrml_format!("{} HEAD", id.to_hex());
                if symrefs {
                    line.push_str(" symref-target:");
                    line.push_str(state.default_branch.as_str());
                }
                line.push('\n');
                write_data_line(output, line.as_bytes(), budget)?;
            } else if unborn {
                let mut line = mrml_runtime::Text::from("unborn HEAD symref-target:");
                line.push_str(state.default_branch.as_str());
                line.push('\n');
                write_data_line(output, line.as_bytes(), budget)?;
            }
        }
        for (name, id) in &state.refs {
            if !prefix_matches(name.as_str().as_bytes(), prefixes) {
                continue;
            }
            let mut line = mrml_runtime::mrml_format!("{} {}", id.to_hex(), name.as_str());
            if peel {
                if let Some(peeled) = self.peel_annotated_tag(state, *id)? {
                    line.push_str(" peeled:");
                    line.push_str(&peeled.to_hex());
                }
            }
            line.push('\n');
            write_data_line(output, line.as_bytes(), budget)?;
        }
        self.ensure_exact_generation(state)?;
        write_pkt_line(output, &PktLine::Flush, budget)
    }

    fn peel_annotated_tag(
        &self,
        state: &crate::ActiveRefState,
        mut id: ObjectId,
    ) -> Result<Option<ObjectId>, GitdCoreError> {
        let original = id;
        for _ in 0..16 {
            let object = self.read_object(state, id)?;
            if object.kind != ObjectKind::Tag {
                return Ok((id != original).then_some(id));
            }
            let headers = object
                .contents
                .split(|byte| *byte == b'\n')
                .take_while(|line| !line.is_empty());
            let mut target = None;
            for header in headers {
                if let Some(value) = header.strip_prefix(b"object ") {
                    if target.is_some() {
                        return Err(GitdCoreError::ObjectValidation);
                    }
                    let value =
                        core::str::from_utf8(value).map_err(|_| GitdCoreError::ObjectValidation)?;
                    target = ObjectId::parse_for(state.object_format, value);
                }
            }
            let next = target.ok_or(GitdCoreError::ObjectValidation)?;
            if next == id {
                return Err(GitdCoreError::ObjectValidation);
            }
            id = next;
        }
        Err(GitdCoreError::Resource)
    }

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
            arrivals: None,
            pack_cache: None,
            verification: VerificationSummaryStore::new(Vector::new())?,
        })
    }

    pub fn open_with_arrivals(
        identity: RepositoryIdentity,
        repository_path: &str,
        active_refs_path: &str,
        arrivals_path: &str,
        max_pack_bytes: u64,
    ) -> Result<Self, GitdCoreError> {
        let mut view = Self::open(identity, repository_path, active_refs_path)?;
        view.arrivals = Some(
            ArrivalPackStore::open(arrivals_path, view.objects.object_format(), max_pack_bytes)
                .map_err(|_| GitdCoreError::Storage)?,
        );
        // Refuse to open an arrival-backed view unless the exact active
        // generation's manifest is present and authentic.
        let state = view.load_state()?;
        view.selected_pack_set(&state)?;
        Ok(view)
    }

    pub fn with_verification_evidence(mut self, evidence: VerificationSummaryStore) -> Self {
        self.verification = evidence;
        self
    }

    /// Adds a durable immutable representation cache. Cache authority remains
    /// subordinate to the exact active repository generation encoded in every
    /// key; the directory name and a digest-name match never authorize a hit.
    pub fn with_pack_cache(mut self, path: &str) -> Result<Self, GitdCoreError> {
        self.pack_cache =
            Some(ImmutablePackCacheDirectory::open(path).map_err(map_pack_cache_error)?);
        Ok(self)
    }

    /// Precomputes the canonical pack for one exact ordered negotiation. Wants
    /// remain restricted to advertised refs, exactly like protocol-v2 fetch.
    pub fn precompute_fetch_pack(
        &self,
        repository: &RepositoryIdentity,
        wants: &[ObjectId],
        haves: &[ObjectId],
    ) -> Result<(), GitdCoreError> {
        if self.pack_cache.is_none() {
            return Err(GitdCoreError::Unsupported);
        }
        if wants.is_empty() {
            return Err(GitdCoreError::MalformedInput);
        }
        let state = self.load_for(repository)?;
        if wants
            .iter()
            .any(|want| !state.refs.iter().any(|(_, id)| id == want))
        {
            return Err(GitdCoreError::Authorization);
        }
        self.fetch_pack(&state, wants, haves)?;
        self.ensure_exact_generation(&state)
    }

    /// Precomputes one canonical single-want pack for the default branch, all
    /// exact tag refs, and caller-selected popular refs. Names identify
    /// candidates but grant no authority: every name resolves through the
    /// exact active state, and duplicate object tips produce one cache entry.
    pub fn precompute_selected_fetch_packs(
        &self,
        repository: &RepositoryIdentity,
        popular: &[FullRefName],
    ) -> Result<usize, GitdCoreError> {
        if self.pack_cache.is_none() {
            return Err(GitdCoreError::Unsupported);
        }
        if popular.len() > MAX_FETCH_PRECOMPUTE_REFS {
            return Err(GitdCoreError::Resource);
        }
        let state = self.load_for(repository)?;
        let tag_count = state
            .refs
            .iter()
            .filter(|(name, _)| name.as_str().starts_with("refs/tags/"))
            .count();
        let default_count = usize::from(
            state
                .refs
                .iter()
                .any(|(name, _)| name == &state.default_branch),
        );
        let intrinsic_count = tag_count
            .checked_add(default_count)
            .ok_or(GitdCoreError::Resource)?;
        if intrinsic_count > MAX_FETCH_PRECOMPUTE_REFS {
            return Err(GitdCoreError::Resource);
        }
        let selection_bound = intrinsic_count
            .checked_add(popular.len())
            .ok_or(GitdCoreError::Resource)?;
        let mut names = Vector::new();
        names
            .try_reserve_exact(selection_bound)
            .map_err(|_| GitdCoreError::Resource)?;
        if default_count == 1 {
            names.push(state.default_branch.clone());
        }
        for (name, _) in &state.refs {
            if name.as_str().starts_with("refs/tags/") {
                names.push(name.clone());
            }
        }
        for name in popular {
            if !state.refs.iter().any(|(active, _)| active == name) {
                return Err(GitdCoreError::ObjectValidation);
            }
            names.push(name.clone());
        }
        names.sort_unstable();
        let mut unique_names = Vector::new();
        unique_names
            .try_reserve_exact(names.len())
            .map_err(|_| GitdCoreError::Resource)?;
        for name in names {
            if unique_names.last() != Some(&name) {
                unique_names.push(name);
            }
        }
        if unique_names.len() > MAX_FETCH_PRECOMPUTE_REFS {
            return Err(GitdCoreError::Resource);
        }

        let mut tips = Vector::new();
        tips.try_reserve_exact(unique_names.len())
            .map_err(|_| GitdCoreError::Resource)?;
        for name in unique_names {
            let tip = state
                .refs
                .iter()
                .find(|(active, _)| active == &name)
                .map(|(_, id)| *id)
                .ok_or(GitdCoreError::ObjectValidation)?;
            tips.push(tip);
        }
        tips.sort_unstable();
        let mut unique_tips = Vector::new();
        unique_tips
            .try_reserve_exact(tips.len())
            .map_err(|_| GitdCoreError::Resource)?;
        for tip in tips {
            if unique_tips.last() != Some(&tip) {
                unique_tips.push(tip);
            }
        }
        for tip in &unique_tips {
            self.fetch_pack(&state, core::slice::from_ref(tip), &[])?;
        }
        self.ensure_exact_generation(&state)?;
        Ok(unique_tips.len())
    }

    pub fn repository_generation(&self) -> Result<RepositoryGeneration, GitdCoreError> {
        Ok(self.load_state()?.repository_generation)
    }

    pub fn authority_generations(
        &self,
    ) -> Result<(RepositoryGeneration, TrustGeneration, RevocationGeneration), GitdCoreError> {
        let state = self.load_state()?;
        if state.object_format != crate::ObjectFormat::Sha256 {
            return Err(GitdCoreError::ObjectValidation);
        }
        Ok((
            state.repository_generation,
            state.trust_generation,
            state.revocation_generation,
        ))
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
            let parsed = self.read_commit(&before, id)?;
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
        self.ensure_exact_generation(&before)?;
        Ok(CommitPage {
            repository_generation: before.repository_generation,
            commits,
            next,
        })
    }

    pub fn read_commit_details(
        &self,
        repository: &RepositoryIdentity,
        commit: ObjectId,
        limits: QueryLimits,
    ) -> Result<CommitDetails, GitdCoreError> {
        validate_limits(limits)?;
        let before = self.load_for(repository)?;
        if commit.format() != before.object_format {
            return Err(GitdCoreError::ObjectValidation);
        }
        let parsed = self.read_commit(&before, commit)?;
        if parsed.parents.len() > limits.max_entries as usize {
            return Err(GitdCoreError::Resource);
        }
        let bytes = parsed
            .author
            .len()
            .checked_add(parsed.message.len())
            .and_then(|value| {
                value.checked_add(parsed.parents.len().checked_mul(commit.as_bytes().len())?)
            })
            .ok_or(GitdCoreError::Resource)? as u64;
        if bytes > limits.max_bytes {
            return Err(GitdCoreError::Resource);
        }
        self.ensure_exact_generation(&before)?;
        Ok(CommitDetails {
            repository_generation: before.repository_generation,
            commit,
            tree: parsed.tree,
            parents: parsed.parents,
            author: parsed.author,
            message: parsed.message,
        })
    }

    pub fn read_annotated_tag_page(
        &self,
        repository: &RepositoryIdentity,
        offset: u64,
        limits: QueryLimits,
    ) -> Result<AnnotatedTagPage, GitdCoreError> {
        validate_limits(limits)?;
        let before = self.load_for(repository)?;
        let offset = usize::try_from(offset).map_err(|_| GitdCoreError::Resource)?;
        let mut annotated_seen = 0usize;
        let mut tags = Vector::new();
        let mut bytes = 0u64;
        let mut more = false;
        for (reference, id) in before
            .refs
            .iter()
            .filter(|(name, _)| name.as_str().starts_with("refs/tags/"))
        {
            let object = self.read_object(&before, *id)?;
            if object.kind != ObjectKind::Tag {
                continue;
            }
            if annotated_seen < offset {
                parse_annotated_tag(
                    self,
                    &before,
                    before.repository_generation,
                    reference,
                    *id,
                    &object.contents,
                )?;
                annotated_seen += 1;
                continue;
            }
            if tags.len() >= limits.max_entries as usize {
                more = true;
                break;
            }
            let details = parse_annotated_tag(
                self,
                &before,
                before.repository_generation,
                reference,
                *id,
                &object.contents,
            )?;
            bytes = bytes
                .checked_add(annotated_tag_bytes(&details)?)
                .ok_or(GitdCoreError::Resource)?;
            if bytes > limits.max_bytes {
                return Err(GitdCoreError::Resource);
            }
            annotated_seen += 1;
            tags.push(details);
        }
        if offset > annotated_seen {
            return Err(GitdCoreError::MalformedInput);
        }
        self.ensure_exact_generation(&before)?;
        Ok(AnnotatedTagPage {
            repository_generation: before.repository_generation,
            next_offset: more.then_some(annotated_seen as u64),
            tags,
        })
    }

    pub fn read_annotated_tag_details(
        &self,
        repository: &RepositoryIdentity,
        reference: &crate::FullRefName,
        limits: QueryLimits,
    ) -> Result<AnnotatedTagDetails, GitdCoreError> {
        validate_limits(limits)?;
        if !reference.as_str().starts_with("refs/tags/") {
            return Err(GitdCoreError::MalformedRef);
        }
        let before = self.load_for(repository)?;
        let tag = before
            .refs
            .iter()
            .find(|(name, _)| name == reference)
            .map(|(_, id)| *id)
            .ok_or(GitdCoreError::ObjectValidation)?;
        let object = self.read_object(&before, tag)?;
        if object.kind != ObjectKind::Tag {
            return Err(GitdCoreError::ObjectValidation);
        }
        let details = parse_annotated_tag(
            self,
            &before,
            before.repository_generation,
            reference,
            tag,
            &object.contents,
        )?;
        if limits.max_entries < 1 || annotated_tag_bytes(&details)? > limits.max_bytes {
            return Err(GitdCoreError::Resource);
        }
        self.ensure_exact_generation(&before)?;
        Ok(details)
    }

    pub fn resolve_readme_candidate(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
    ) -> Result<Option<ReadmeCandidate>, GitdCoreError> {
        let before = self.load_for(repository)?;
        let tree = self.tree_id(&before, treeish, before.object_format)?;
        let index = self.tree_index(&before, tree)?;
        let mut selected = None;
        for candidate in ["README.md", "README.txt", "README.rst", "README"] {
            if let Some(entry) = index.entry(candidate) {
                let object = self.read_object(&before, entry.id)?;
                if object.kind != ObjectKind::Blob {
                    return Err(GitdCoreError::ObjectValidation);
                }
                selected = Some(ReadmeCandidate {
                    repository_generation: before.repository_generation,
                    tree,
                    path: RepositoryPath::parse(candidate)?,
                    blob: entry.id,
                });
                break;
            }
        }
        self.ensure_exact_generation(&before)?;
        Ok(selected)
    }

    pub fn immutable_pack_descriptor(
        &self,
        repository: &RepositoryIdentity,
        commit: ObjectId,
    ) -> Result<ImmutablePackDescriptor, GitdCoreError> {
        let before = self.load_for(repository)?;
        if commit.format() != before.object_format {
            return Err(GitdCoreError::ObjectValidation);
        }
        let object = self.read_object(&before, commit)?;
        if object.kind != ObjectKind::Commit {
            return Err(GitdCoreError::ObjectValidation);
        }
        self.validate_commit_tip(&before, commit)?;
        self.ensure_exact_generation(&before)?;
        Ok(ImmutablePackDescriptor {
            repository_generation: before.repository_generation,
            commit,
            object_format: before.object_format,
            pack_profile_version: 1,
            encoder_version: 1,
        })
    }

    pub fn repository_events_after(
        &self,
        repository: &RepositoryIdentity,
        cursor: RepositoryEventCursor,
        limits: QueryLimits,
    ) -> Result<RepositoryEventPage, GitdCoreError> {
        validate_limits(limits)?;
        let state = self.load_for(repository)?;
        let current = RepositoryEventCursor {
            repository_generation: state.repository_generation,
            trust_generation: state.trust_generation,
            revocation_generation: state.revocation_generation,
            pack_generation: state.pack_generation,
        };
        for (previous, next) in [
            (
                cursor.repository_generation.0,
                current.repository_generation.0,
            ),
            (cursor.trust_generation.0, current.trust_generation.0),
            (
                cursor.revocation_generation.0,
                current.revocation_generation.0,
            ),
            (cursor.pack_generation.0, current.pack_generation.0),
        ] {
            if previous > next {
                return Err(GitdCoreError::StaleGeneration);
            }
        }
        let mut events = Vector::new();
        if cursor != current {
            if limits.max_entries < 1 || limits.max_bytes < 64 {
                return Err(GitdCoreError::Resource);
            }
            events.push(RepositoryEvent {
                previous: cursor,
                current,
            });
        }
        self.ensure_exact_generation(&state)?;
        Ok(RepositoryEventPage {
            events,
            next: current,
        })
    }

    pub fn read_tree_page(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        limits: QueryLimits,
    ) -> Result<TreePage, GitdCoreError> {
        self.read_tree_page_at(repository, treeish, path, 0, limits)
    }

    pub fn read_tree_page_at(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        offset: u64,
        limits: QueryLimits,
    ) -> Result<TreePage, GitdCoreError> {
        validate_limits(limits)?;
        let before = self.load_for(repository)?;
        let tree = self.tree_id(&before, treeish, before.object_format)?;
        let index = self.tree_index(&before, tree)?;
        let prefix = path.as_str();
        let prefix_slash = mrml_runtime::mrml_format!("{prefix}/");
        let offset = usize::try_from(offset).map_err(|_| GitdCoreError::Resource)?;
        let matching = index
            .entries
            .iter()
            .filter(|entry| {
                prefix.is_empty()
                    || entry.path == prefix
                    || entry.path.starts_with(prefix_slash.as_str())
            })
            .count();
        if offset > matching {
            return Err(GitdCoreError::MalformedInput);
        }
        let mut entries = Vector::new();
        let mut bytes = 0u64;
        for entry in index
            .entries
            .iter()
            .filter(|entry| {
                prefix.is_empty()
                    || entry.path == prefix
                    || entry.path.starts_with(prefix_slash.as_str())
            })
            .skip(offset)
        {
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
        let consumed = offset
            .checked_add(entries.len())
            .ok_or(GitdCoreError::Resource)?;
        let next_offset = (consumed < matching).then_some(consumed as u64);
        self.ensure_exact_generation(&before)?;
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
        self.read_blob_page_at(repository, treeish, path, 0, limits)
    }

    pub fn read_blob_page_at(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        offset: u64,
        limits: QueryLimits,
    ) -> Result<BlobPage, GitdCoreError> {
        validate_limits(limits)?;
        let before = self.load_for(repository)?;
        let tree = self.tree_id(&before, treeish, before.object_format)?;
        let index = self.tree_index(&before, tree)?;
        let entry = index
            .entry(path.as_str())
            .ok_or(GitdCoreError::ObjectValidation)?;
        let object = self.read_object(&before, entry.id)?;
        if object.kind != ObjectKind::Blob {
            return Err(GitdCoreError::ObjectValidation);
        }
        let offset = usize::try_from(offset).map_err(|_| GitdCoreError::Resource)?;
        if offset > object.contents.len() {
            return Err(GitdCoreError::MalformedInput);
        }
        let take = object
            .contents
            .len()
            .saturating_sub(offset)
            .min(usize::try_from(limits.max_bytes).map_err(|_| GitdCoreError::Resource)?);
        let mut bytes = Vector::new();
        bytes
            .try_extend_from_slice(&object.contents[offset..offset + take])
            .map_err(|_| GitdCoreError::Resource)?;
        self.ensure_exact_generation(&before)?;
        Ok(BlobPage {
            repository_generation: before.repository_generation,
            blob: entry.id,
            offset: offset as u64,
            bytes,
            complete: offset + take == object.contents.len(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn read_verified_metadata(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
        path: &RepositoryPath,
        purpose: crate::SignaturePurpose,
        policy: TrustGeneration,
        revocations: RevocationGeneration,
        limits: QueryLimits,
    ) -> Result<VerifiedMetadataDescriptor, GitdCoreError> {
        if !matches!(
            purpose,
            crate::SignaturePurpose::SourceManifest
                | crate::SignaturePurpose::SourceLock
                | crate::SignaturePurpose::BuildReceipt
        ) {
            return Err(GitdCoreError::Policy);
        }
        validate_limits(limits)?;
        let before = self.load_for(repository)?;
        let tree = self.tree_id(&before, treeish, before.object_format)?;
        let index = self.tree_index(&before, tree)?;
        let entry = index
            .entry(path.as_str())
            .ok_or(GitdCoreError::ObjectValidation)?;
        let object = self.read_object(&before, entry.id)?;
        if object.kind != ObjectKind::Blob {
            return Err(GitdCoreError::ObjectValidation);
        }
        if object.contents.len() as u64 > limits.max_bytes || limits.max_entries < 1 {
            return Err(GitdCoreError::Resource);
        }
        let summary =
            GitdCoreBackend::verification_summary(self, repository, entry.id, policy, revocations)?;
        if summary.purpose != purpose
            || !summary.openpgp_authorized
            || !summary.ml_dsa_65_authorized
            || !summary.exact_pair_authorized
        {
            return Err(GitdCoreError::Signature);
        }
        self.ensure_exact_generation(&before)?;
        Ok(VerifiedMetadataDescriptor {
            repository_generation: before.repository_generation,
            tree,
            path: path.clone(),
            blob: entry.id,
            size: object.contents.len() as u64,
            purpose,
            trust_generation: policy,
            revocation_generation: revocations,
        })
    }

    fn tree_id(
        &self,
        state: &crate::ActiveRefState,
        treeish: ObjectId,
        format: crate::ObjectFormat,
    ) -> Result<ObjectId, GitdCoreError> {
        if treeish.format() != format {
            return Err(GitdCoreError::ObjectValidation);
        }
        let object = self.read_object(state, treeish)?;
        match object.kind {
            ObjectKind::Tree => Ok(treeish),
            ObjectKind::Commit => self.read_commit(state, treeish).map(|commit| commit.tree),
            _ => Err(GitdCoreError::ObjectValidation),
        }
    }

    fn selected_pack_set(
        &self,
        state: &crate::ActiveRefState,
    ) -> Result<Option<PackSetManifest>, GitdCoreError> {
        let Some(_) = self.arrivals else {
            return Ok(None);
        };
        let manifest = self
            .refs
            .load_selected_pack_set(SELECTED_PACK_SET_LIMITS)
            .map_err(|_| GitdCoreError::Storage)?;
        if manifest.repository_generation() != state.repository_generation
            || manifest.pack_generation() != state.pack_generation
            || manifest
                .digest()
                .map_err(|_| GitdCoreError::ObjectValidation)?
                != state.pack_set_digest
        {
            return Err(GitdCoreError::StaleGeneration);
        }
        Ok(Some(manifest))
    }

    fn read_object(
        &self,
        state: &crate::ActiveRefState,
        id: ObjectId,
    ) -> Result<crate::Object, GitdCoreError> {
        if id.format() != state.object_format {
            return Err(GitdCoreError::ObjectValidation);
        }
        if let (Some(arrivals), Some(manifest)) = (&self.arrivals, self.selected_pack_set(state)?) {
            let selected = manifest
                .entries()
                .iter()
                .any(|entry| entry.object_ids().binary_search(&id).is_ok());
            if selected {
                return arrivals.read_selected_object(
                    &manifest,
                    id,
                    crate::DEFAULT_MAX_INDIVIDUAL_OBJECT_BYTES,
                );
            }
        }
        self.objects
            .read_object(id)
            .map_err(|_| GitdCoreError::ObjectValidation)
    }

    fn read_commit(
        &self,
        state: &crate::ActiveRefState,
        id: ObjectId,
    ) -> Result<Commit, GitdCoreError> {
        let object = self.read_object(state, id)?;
        if object.kind != ObjectKind::Commit {
            return Err(GitdCoreError::ObjectValidation);
        }
        Commit::parse_with_format(&object.contents, state.object_format)
            .map_err(|_| GitdCoreError::ObjectValidation)
    }

    fn tree_index(
        &self,
        state: &crate::ActiveRefState,
        tree: ObjectId,
    ) -> Result<Index, GitdCoreError> {
        let mut index = Index::empty_with_format(state.object_format);
        self.flatten_tree(state, tree, "", 0, &mut index)?;
        Ok(index)
    }

    fn flatten_tree(
        &self,
        state: &crate::ActiveRefState,
        id: ObjectId,
        prefix: &str,
        depth: usize,
        index: &mut Index,
    ) -> Result<(), GitdCoreError> {
        if depth > 128 {
            return Err(GitdCoreError::Resource);
        }
        let object = self.read_object(state, id)?;
        if object.kind != ObjectKind::Tree {
            return Err(GitdCoreError::ObjectValidation);
        }
        for entry in parse_tree_with_format(&object.contents, state.object_format)
            .map_err(|_| GitdCoreError::ObjectValidation)?
        {
            let path = if prefix.is_empty() {
                entry.name.clone()
            } else {
                mrml_runtime::mrml_format!("{prefix}/{}", entry.name)
            };
            if entry.mode == 0o40000 {
                self.flatten_tree(state, entry.id, &path, depth + 1, index)?;
            } else if matches!(entry.mode, 0o100644 | 0o100755) {
                if index.entries.len() >= 1_000_000 {
                    return Err(GitdCoreError::Resource);
                }
                let blob = self.read_object(state, entry.id)?;
                if blob.kind != ObjectKind::Blob {
                    return Err(GitdCoreError::ObjectValidation);
                }
                index.upsert(IndexEntry {
                    path,
                    id: entry.id,
                    mode: entry.mode,
                    size: blob
                        .contents
                        .len()
                        .try_into()
                        .map_err(|_| GitdCoreError::Resource)?,
                    stage: 0,
                });
            } else {
                return Err(GitdCoreError::ObjectValidation);
            }
        }
        Ok(())
    }

    fn validate_commit_tip(
        &self,
        state: &crate::ActiveRefState,
        tip: ObjectId,
    ) -> Result<(), GitdCoreError> {
        let mut pending = Vector::from([(tip, ObjectKind::Commit)]);
        let mut seen = Vector::new();
        while let Some((id, expected)) = pending.pop() {
            if seen.contains(&id) {
                continue;
            }
            if seen.len() >= 1_000_000 || pending.len() > 1_000_000 {
                return Err(GitdCoreError::Resource);
            }
            let object = self.read_object(state, id)?;
            if object.kind != expected {
                return Err(GitdCoreError::ObjectValidation);
            }
            match object.kind {
                ObjectKind::Commit => {
                    let commit = Commit::parse_with_format(&object.contents, state.object_format)
                        .map_err(|_| GitdCoreError::ObjectValidation)?;
                    pending.push((commit.tree, ObjectKind::Tree));
                    pending.extend(commit.parents.iter().map(|id| (*id, ObjectKind::Commit)));
                }
                ObjectKind::Tree => {
                    for entry in parse_tree_with_format(&object.contents, state.object_format)
                        .map_err(|_| GitdCoreError::ObjectValidation)?
                    {
                        let kind = match entry.mode {
                            0o40000 => ObjectKind::Tree,
                            0o100644 | 0o100755 | 0o120000 => ObjectKind::Blob,
                            _ => return Err(GitdCoreError::ObjectValidation),
                        };
                        pending.push((entry.id, kind));
                    }
                }
                ObjectKind::Blob => {}
                ObjectKind::Tag => return Err(GitdCoreError::ObjectValidation),
            }
            seen.push(id);
        }
        Ok(())
    }

    fn pack_negotiated(
        &self,
        state: &crate::ActiveRefState,
        wants: &[ObjectId],
        haves: &[ObjectId],
    ) -> Result<Vector<u8>, GitdCoreError> {
        let ids = self.negotiated_object_ids(state, wants, haves)?;
        let mut objects = Vector::new();
        for id in ids {
            let object = self.read_object(state, id)?;
            objects.push(PackObject {
                id,
                kind: object.kind,
                contents: object.contents,
            });
        }
        encode_pack_with_format(&objects, state.object_format)
            .map_err(|_| GitdCoreError::ObjectValidation)
    }

    fn negotiated_object_ids(
        &self,
        state: &crate::ActiveRefState,
        wants: &[ObjectId],
        haves: &[ObjectId],
    ) -> Result<Vector<ObjectId>, GitdCoreError> {
        let mut excluded = Vector::new();
        let mut pending: Vector<ObjectId> = haves.iter().copied().collect();
        while let Some(id) = pending.pop() {
            if excluded.contains(&id) {
                continue;
            }
            if excluded.len() >= 1_000_000 {
                return Err(GitdCoreError::Resource);
            }
            let object = self.read_object(state, id)?;
            append_reachable_children(&object, state.object_format, &mut pending)?;
            excluded.push(id);
        }
        let mut pending: Vector<ObjectId> = wants.iter().copied().collect();
        let mut seen = Vector::new();
        while let Some(id) = pending.pop() {
            if excluded.contains(&id) || seen.contains(&id) {
                continue;
            }
            if seen.len() >= 1_000_000 {
                return Err(GitdCoreError::Resource);
            }
            let object = self.read_object(state, id)?;
            append_reachable_children(&object, state.object_format, &mut pending)?;
            seen.push(id);
        }
        Ok(seen)
    }

    fn fetch_pack(
        &self,
        state: &crate::ActiveRefState,
        wants: &[ObjectId],
        haves: &[ObjectId],
    ) -> Result<Vector<u8>, GitdCoreError> {
        let Some(cache) = &self.pack_cache else {
            return self.pack_negotiated(state, wants, haves);
        };
        let key = PackCacheKey::new(
            state.object_format,
            wants.iter().copied().collect(),
            haves.iter().copied().collect(),
            state.repository_generation,
            FETCH_PACK_PROFILE_VERSION,
            FETCH_PACK_ENCODER_VERSION,
        )
        .map_err(|_| GitdCoreError::Resource)?;
        if let Some(pack) = cache.lookup(&key).map_err(map_pack_cache_error)? {
            return Ok(pack);
        }
        let pack = self.pack_negotiated(state, wants, haves)?;
        // Never populate a key after its full active state has become stale.
        self.ensure_exact_generation(state)?;
        match cache.insert(&key, &pack) {
            Ok(()) => {}
            // A concurrent producer may win. The independently generated
            // bytes are canonical, so this request can safely use its local
            // representation without waiting for or trusting a partial file.
            Err(PackCacheFileError::AlreadyExists) => {}
            Err(error) => return Err(map_pack_cache_error(error)),
        }
        Ok(pack)
    }

    fn ensure_exact_generation(
        &self,
        expected: &crate::ActiveRefState,
    ) -> Result<(), GitdCoreError> {
        let current = self.load_state()?;
        if current == *expected {
            Ok(())
        } else {
            Err(GitdCoreError::StaleGeneration)
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
}

fn map_pack_cache_error(error: PackCacheFileError) -> GitdCoreError {
    match error {
        PackCacheFileError::Resource => GitdCoreError::Resource,
        PackCacheFileError::Integrity | PackCacheFileError::Key => GitdCoreError::ObjectValidation,
        PackCacheFileError::Io
        | PackCacheFileError::AlreadyExists
        | PackCacheFileError::Durability => GitdCoreError::Storage,
    }
}

fn parse_annotated_tag(
    repository: &FilesystemRepositoryView,
    state: &crate::ActiveRefState,
    generation: RepositoryGeneration,
    reference: &crate::FullRefName,
    tag: ObjectId,
    contents: &[u8],
) -> Result<AnnotatedTagDetails, GitdCoreError> {
    let (headers, message) = contents
        .windows(2)
        .position(|pair| pair == b"\n\n")
        .map(|split| (&contents[..split], &contents[split + 2..]))
        .ok_or(GitdCoreError::ObjectValidation)?;
    let mut lines = headers.split(|byte| *byte == b'\n');
    let object_line = lines.next().ok_or(GitdCoreError::ObjectValidation)?;
    let type_line = lines.next().ok_or(GitdCoreError::ObjectValidation)?;
    let tag_line = lines.next().ok_or(GitdCoreError::ObjectValidation)?;
    let tagger_line = lines.next().ok_or(GitdCoreError::ObjectValidation)?;
    if lines.next().is_some() {
        return Err(GitdCoreError::ObjectValidation);
    }
    let target_text = object_line
        .strip_prefix(b"object ")
        .and_then(|bytes| core::str::from_utf8(bytes).ok())
        .ok_or(GitdCoreError::ObjectValidation)?;
    let target = ObjectId::parse_for(state.object_format, target_text)
        .ok_or(GitdCoreError::ObjectValidation)?;
    if target.is_zero() || target.format() != tag.format() {
        return Err(GitdCoreError::ObjectValidation);
    }
    let declared_type = type_line
        .strip_prefix(b"type ")
        .ok_or(GitdCoreError::ObjectValidation)?;
    let target_type = match declared_type {
        b"commit" => ObjectKind::Commit,
        b"tree" => ObjectKind::Tree,
        b"blob" => ObjectKind::Blob,
        b"tag" => ObjectKind::Tag,
        _ => return Err(GitdCoreError::ObjectValidation),
    };
    let tag_name = tag_line
        .strip_prefix(b"tag ")
        .ok_or(GitdCoreError::ObjectValidation)?;
    if tag_name.is_empty() || tag_name.iter().any(|byte| *byte <= b' ' || *byte == 0x7f) {
        return Err(GitdCoreError::ObjectValidation);
    }
    let tagger = tagger_line
        .strip_prefix(b"tagger ")
        .and_then(|bytes| core::str::from_utf8(bytes).ok())
        .filter(|value| !value.is_empty() && !value.bytes().any(|byte| byte == 0 || byte == b'\r'))
        .ok_or(GitdCoreError::ObjectValidation)?;
    let message = core::str::from_utf8(message).map_err(|_| GitdCoreError::ObjectValidation)?;
    let target_object = repository.read_object(state, target)?;
    if target_object.kind != target_type {
        return Err(GitdCoreError::ObjectValidation);
    }
    Ok(AnnotatedTagDetails {
        repository_generation: generation,
        reference: reference.clone(),
        tag,
        target,
        target_type,
        tagger: tagger.into(),
        message: message.into(),
    })
}

fn annotated_tag_bytes(details: &AnnotatedTagDetails) -> Result<u64, GitdCoreError> {
    details
        .reference
        .as_str()
        .len()
        .checked_add(details.tag.as_bytes().len())
        .and_then(|bytes| bytes.checked_add(details.target.as_bytes().len()))
        .and_then(|bytes| bytes.checked_add(details.tagger.len()))
        .and_then(|bytes| bytes.checked_add(details.message.len()))
        .map(|bytes| bytes as u64)
        .ok_or(GitdCoreError::Resource)
}

fn prefix_matches(name: &[u8], prefixes: &[Vector<u8>]) -> bool {
    prefixes.is_empty() || prefixes.iter().any(|prefix| name.starts_with(prefix))
}

fn write_data_line(
    output: &mut dyn BoundedWrite,
    bytes: &[u8],
    budget: &mut ProtocolBudget,
) -> Result<(), GitdCoreError> {
    let mut payload = Vector::new();
    payload
        .try_extend_from_slice(bytes)
        .map_err(|_| GitdCoreError::Resource)?;
    write_pkt_line(output, &PktLine::Data(payload), budget)
}

struct SidebandPackWriter<'a, 'b> {
    output: &'a mut dyn BoundedWrite,
    protocol: &'b mut ProtocolBudget,
    failure: Option<GitdCoreError>,
}

impl<'a, 'b> SidebandPackWriter<'a, 'b> {
    fn new(output: &'a mut dyn BoundedWrite, protocol: &'b mut ProtocolBudget) -> Self {
        Self {
            output,
            protocol,
            failure: None,
        }
    }
}

impl PackStreamOutput for SidebandPackWriter<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), PackError> {
        if self.failure.is_some() {
            return Err(PackError::TooLarge);
        }
        for chunk in bytes.chunks(crate::MAX_PKT_LINE_BYTES - 5) {
            let mut payload = Vector::new();
            let result = payload
                .try_reserve_exact(chunk.len() + 1)
                .map_err(|_| GitdCoreError::Resource)
                .and_then(|()| {
                    payload.push(1);
                    payload
                        .try_extend_from_slice(chunk)
                        .map_err(|_| GitdCoreError::Resource)
                })
                .and_then(|()| write_pkt_line(self.output, &PktLine::Data(payload), self.protocol));
            if let Err(error) = result {
                self.failure = Some(error);
                return Err(PackError::TooLarge);
            }
        }
        Ok(())
    }
}

fn preflight_pack_response(
    pack_bytes: usize,
    output: &dyn BoundedWrite,
    budget: ProtocolBudget,
) -> Result<(), GitdCoreError> {
    let chunk_bytes = crate::MAX_PKT_LINE_BYTES - 5;
    let chunks = pack_bytes
        .checked_add(chunk_bytes - 1)
        .ok_or(GitdCoreError::Resource)?
        / chunk_bytes;
    let framed = 13usize
        .checked_add(pack_bytes)
        .and_then(|value| value.checked_add(chunks.checked_mul(5)?))
        .and_then(|value| value.checked_add(4))
        .ok_or(GitdCoreError::Resource)?;
    let framed = framed as u64;
    if framed > output.remaining()
        || framed > budget.output_remaining()
        || framed > budget.work_remaining()
    {
        return Err(GitdCoreError::Resource);
    }
    Ok(())
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

    struct Reader {
        bytes: Vector<u8>,
        offset: usize,
    }

    impl BoundedRead for Reader {
        fn remaining(&self) -> u64 {
            (self.bytes.len() - self.offset) as u64
        }

        fn read(&mut self, output: &mut [u8]) -> Result<usize, GitdCoreError> {
            let count = output.len().min(5).min(self.bytes.len() - self.offset);
            output[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Ok(count)
        }
    }

    struct Writer(Vector<u8>);

    impl BoundedWrite for Writer {
        fn remaining(&self) -> u64 {
            (1024 * 1024 - self.0.len()) as u64
        }

        fn write(&mut self, input: &[u8]) -> Result<(), GitdCoreError> {
            self.0
                .try_extend_from_slice(input)
                .map_err(|_| GitdCoreError::Resource)
        }
    }

    fn work_budget() -> WorkBudget {
        WorkBudget {
            max_input_bytes: 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            max_memory_bytes: 1024 * 1024,
            max_work_units: 4 * 1024 * 1024,
        }
    }

    fn protocol_request(lines: &[Option<&[u8]>]) -> Reader {
        let mut writer = Writer(Vector::new());
        let mut budget = ProtocolBudget::new(work_budget());
        for line in lines {
            match line {
                Some(bytes) => write_data_line(&mut writer, bytes, &mut budget).unwrap(),
                None => write_pkt_line(&mut writer, &PktLine::Delimiter, &mut budget).unwrap(),
            }
        }
        write_pkt_line(&mut writer, &PktLine::Flush, &mut budget).unwrap();
        Reader {
            bytes: writer.0,
            offset: 0,
        }
    }

    #[test]
    fn queries_are_bounded_identity_scoped_and_generation_tagged() {
        let root = join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-repository-view-{}", mrml_runtime::process_id()),
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        let repository_path = join_path(&root, "objects");
        let refs_path = join_path(&root, "refs");
        let cache_path = join_path(&root, "fetch-cache");
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
        let tag_bytes = mrml_runtime::mrml_format!(
            "object {}\ntype commit\ntag v1\ntagger Owner <owner@example.invalid> 2 +0000\n\nrelease\n",
            commit.to_hex()
        );
        let tag = objects
            .write_object(ObjectKind::Tag, tag_bytes.as_bytes())
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
                pack_set_digest: [1; 32],
                object_format: ObjectFormat::Sha256,
                default_branch: FullRefName::parse("refs/heads/main").unwrap(),
                refs: [
                    (FullRefName::parse("refs/heads/main").unwrap(), commit),
                    (FullRefName::parse("refs/tags/latest").unwrap(), commit),
                    (FullRefName::parse("refs/tags/v1").unwrap(), tag),
                    (FullRefName::parse("refs/tags/v2").unwrap(), tag),
                ]
                .into(),
            },
        )
        .unwrap();
        let mut view =
            FilesystemRepositoryView::open(identity.clone(), &repository_path, &refs_path)
                .unwrap()
                .with_pack_cache(&cache_path)
                .unwrap();
        assert_eq!(
            view.authority_generations(),
            Ok((
                RepositoryGeneration(4),
                TrustGeneration(5),
                RevocationGeneration(6)
            ))
        );
        let evidence =
            VerificationSummaryEvidence::from_verified_hybrid_commit(&VerifiedCommitProof {
                commit,
                repository: identity.clone(),
                repository_generation: RepositoryGeneration(4),
                trust_generation: TrustGeneration(5),
                revocation_generation: RevocationGeneration(6),
                purpose: crate::SignaturePurpose::GitCommit,
                object_format: ObjectFormat::Sha256,
            });
        let tag_evidence =
            VerificationSummaryEvidence::from_verified_git_object(&VerifiedGitObjectProof {
                object: tag,
                repository: identity.clone(),
                repository_generation: RepositoryGeneration(4),
                trust_generation: TrustGeneration(5),
                revocation_generation: RevocationGeneration(6),
                purpose: crate::SignaturePurpose::GitAnnotatedTag,
                object_format: ObjectFormat::Sha256,
                object_kind: ObjectKind::Tag,
            });
        assert_eq!(tag_evidence.summary.object, tag);
        assert_eq!(
            tag_evidence.summary.purpose,
            crate::SignaturePurpose::GitAnnotatedTag
        );
        let metadata_evidence =
            VerificationSummaryEvidence::from_verified_git_object(&VerifiedGitObjectProof {
                object: blob,
                repository: identity.clone(),
                repository_generation: RepositoryGeneration(4),
                trust_generation: TrustGeneration(5),
                revocation_generation: RevocationGeneration(6),
                purpose: crate::SignaturePurpose::SourceManifest,
                object_format: ObjectFormat::Sha256,
                object_kind: ObjectKind::Blob,
            });
        let mut evidence_records = Vector::from([evidence, metadata_evidence]);
        evidence_records.sort_unstable_by(|left, right| {
            if evidence_less(left, right) {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Greater
            }
        });
        let evidence_store = VerificationSummaryStore::new(evidence_records).unwrap();
        assert!(evidence_store
            .exact(
                &identity,
                RepositoryGeneration(3),
                commit,
                TrustGeneration(5),
                RevocationGeneration(6),
            )
            .is_none());
        view = view.with_verification_evidence(evidence_store);
        let limits = QueryLimits {
            max_entries: 8,
            max_bytes: 1024,
        };
        assert_eq!(view.repository_generation(), Ok(RepositoryGeneration(4)));
        assert_eq!(
            GitdCoreBackend::repository_generation(&view, &identity),
            Ok(RepositoryGeneration(4))
        );
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
        let details =
            GitdCoreBackend::read_commit_details(&view, &identity, commit, limits).unwrap();
        assert_eq!(details.commit, commit);
        assert_eq!(details.tree, tree);
        assert!(details.parents.is_empty());
        assert_eq!(details.message, "initial\n");
        let tag_page =
            GitdCoreBackend::read_annotated_tag_page(&view, &identity, 0, limits).unwrap();
        assert_eq!(tag_page.repository_generation, RepositoryGeneration(4));
        assert_eq!(tag_page.tags.len(), 2);
        assert_eq!(tag_page.tags[0].reference.as_str(), "refs/tags/v1");
        assert_eq!(tag_page.tags[0].tag, tag);
        assert_eq!(tag_page.tags[0].target, commit);
        assert_eq!(tag_page.tags[0].target_type, ObjectKind::Commit);
        assert_eq!(
            tag_page.tags[0].tagger,
            "Owner <owner@example.invalid> 2 +0000"
        );
        assert_eq!(tag_page.tags[0].message, "release\n");
        assert_eq!(tag_page.next_offset, None);
        let first_tag = GitdCoreBackend::read_annotated_tag_page(
            &view,
            &identity,
            0,
            QueryLimits {
                max_entries: 1,
                max_bytes: 1024,
            },
        )
        .unwrap();
        assert_eq!(first_tag.tags.len(), 1);
        assert_eq!(first_tag.next_offset, Some(1));
        let second_tag = GitdCoreBackend::read_annotated_tag_page(
            &view,
            &identity,
            1,
            QueryLimits {
                max_entries: 1,
                max_bytes: 1024,
            },
        )
        .unwrap();
        assert_eq!(second_tag.tags[0].reference.as_str(), "refs/tags/v2");
        assert_eq!(second_tag.next_offset, None);
        assert_eq!(
            GitdCoreBackend::read_annotated_tag_details(
                &view,
                &identity,
                &FullRefName::parse("refs/tags/v1").unwrap(),
                limits,
            ),
            Ok(tag_page.tags[0].clone())
        );
        assert_eq!(
            GitdCoreBackend::read_annotated_tag_details(
                &view,
                &identity,
                &FullRefName::parse("refs/tags/latest").unwrap(),
                limits,
            ),
            Err(GitdCoreError::ObjectValidation)
        );
        assert_eq!(
            GitdCoreBackend::read_annotated_tag_page(&view, &identity, 3, limits),
            Err(GitdCoreError::MalformedInput)
        );
        assert_eq!(
            GitdCoreBackend::read_annotated_tag_page(
                &view,
                &identity,
                0,
                QueryLimits {
                    max_entries: 1,
                    max_bytes: 8
                },
            ),
            Err(GitdCoreError::Resource)
        );
        let duplicate = mrml_runtime::mrml_format!(
            "object {}\nobject {}\ntype commit\ntag bad\ntagger Owner <owner@example.invalid> 2 +0000\n\nmessage\n",
            commit.to_hex(),
            commit.to_hex()
        );
        assert_eq!(
            parse_annotated_tag(
                &view,
                &view.load_state().unwrap(),
                RepositoryGeneration(4),
                &FullRefName::parse("refs/tags/bad").unwrap(),
                tag,
                duplicate.as_bytes(),
            ),
            Err(GitdCoreError::ObjectValidation)
        );
        let wrong_type = mrml_runtime::mrml_format!(
            "object {}\ntype blob\ntag bad\ntagger Owner <owner@example.invalid> 2 +0000\n\nmessage\n",
            commit.to_hex()
        );
        assert_eq!(
            parse_annotated_tag(
                &view,
                &view.load_state().unwrap(),
                RepositoryGeneration(4),
                &FullRefName::parse("refs/tags/bad").unwrap(),
                tag,
                wrong_type.as_bytes(),
            ),
            Err(GitdCoreError::ObjectValidation)
        );
        let readme = GitdCoreBackend::resolve_readme_candidate(&view, &identity, commit)
            .unwrap()
            .unwrap();
        assert_eq!(readme.repository_generation, RepositoryGeneration(4));
        assert_eq!(readme.path, RepositoryPath::parse("README.md").unwrap());
        assert_eq!(readme.blob, blob);
        let metadata = GitdCoreBackend::read_verified_metadata(
            &view,
            &identity,
            commit,
            &RepositoryPath::parse("README.md").unwrap(),
            crate::SignaturePurpose::SourceManifest,
            TrustGeneration(5),
            RevocationGeneration(6),
            limits,
        )
        .unwrap();
        assert_eq!(metadata.blob, blob);
        assert_eq!(metadata.size, 12);
        assert_eq!(metadata.repository_generation, RepositoryGeneration(4));
        assert_eq!(
            GitdCoreBackend::read_verified_metadata(
                &view,
                &identity,
                commit,
                &RepositoryPath::parse("README.md").unwrap(),
                crate::SignaturePurpose::SourceLock,
                TrustGeneration(5),
                RevocationGeneration(6),
                limits,
            ),
            Err(GitdCoreError::Signature)
        );
        let descriptor =
            GitdCoreBackend::immutable_pack_descriptor(&view, &identity, commit).unwrap();
        assert_eq!(descriptor.repository_generation, RepositoryGeneration(4));
        assert_eq!(descriptor.commit, commit);
        assert_eq!(descriptor.object_format, ObjectFormat::Sha256);
        assert_eq!(descriptor.pack_profile_version, 1);
        assert_eq!(descriptor.encoder_version, 1);
        assert_eq!(
            GitdCoreBackend::immutable_pack_descriptor(&view, &identity, blob),
            Err(GitdCoreError::ObjectValidation)
        );
        let previous = RepositoryEventCursor {
            repository_generation: RepositoryGeneration(3),
            trust_generation: TrustGeneration(4),
            revocation_generation: RevocationGeneration(5),
            pack_generation: crate::PackGeneration(1),
        };
        let events =
            GitdCoreBackend::repository_events_after(&view, &identity, previous, limits).unwrap();
        assert_eq!(events.events.len(), 1);
        assert_eq!(events.events[0].previous, previous);
        assert_eq!(events.next.repository_generation, RepositoryGeneration(4));
        assert_eq!(events.next.trust_generation, TrustGeneration(5));
        assert_eq!(events.next.revocation_generation, RevocationGeneration(6));
        assert!(
            GitdCoreBackend::repository_events_after(&view, &identity, events.next, limits,)
                .unwrap()
                .events
                .is_empty()
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
        let blob_tail = GitdCoreBackend::read_blob_page_at(
            &view,
            &identity,
            commit,
            &RepositoryPath::parse("README.md").unwrap(),
            7,
            QueryLimits {
                max_entries: 1,
                max_bytes: 16,
            },
        )
        .unwrap();
        assert_eq!(blob_tail.offset, 7);
        assert_eq!(&*blob_tail.bytes, b" view");
        assert!(blob_tail.complete);
        let tree_tail = GitdCoreBackend::read_tree_page_at(
            &view,
            &identity,
            commit,
            &RepositoryPath::root(),
            1,
            limits,
        )
        .unwrap();
        assert!(tree_tail.entries.is_empty());
        assert_eq!(tree_tail.next_offset, None);
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
        assert_eq!(
            GitdCoreBackend::verification_summary(
                &view,
                &identity,
                commit,
                TrustGeneration(5),
                RevocationGeneration(6),
            ),
            Ok(VerificationSummary {
                object: commit,
                trust_generation: TrustGeneration(5),
                revocation_generation: RevocationGeneration(6),
                purpose: crate::SignaturePurpose::GitCommit,
                openpgp_authorized: true,
                ml_dsa_65_authorized: true,
                exact_pair_authorized: true,
                hybrid_required: true,
            })
        );
        assert_eq!(
            GitdCoreBackend::verification_summary(
                &view,
                &identity,
                commit,
                TrustGeneration(4),
                RevocationGeneration(6),
            ),
            Err(GitdCoreError::StaleGeneration)
        );
        assert_eq!(
            GitdCoreBackend::verification_summary(
                &view,
                &identity,
                tree,
                TrustGeneration(5),
                RevocationGeneration(6),
            ),
            Err(GitdCoreError::Signature)
        );
        assert_eq!(
            GitdCoreBackend::verification_summary(
                &view,
                &RepositoryIdentity::parse("other/repository").unwrap(),
                commit,
                TrustGeneration(5),
                RevocationGeneration(6),
            ),
            Err(GitdCoreError::Authorization)
        );

        let request = SmartGitRequest {
            repository: identity.clone(),
            repository_generation: RepositoryGeneration(4),
            operation: SmartGitOperation::UploadPack,
            object_format: ObjectFormat::Sha256,
        };
        let mut ls_input = protocol_request(&[
            Some(b"command=ls-refs\n"),
            Some(b"object-format=sha256\n"),
            None,
            Some(b"symrefs\n"),
            Some(b"ref-prefix refs/heads/\n"),
        ]);
        let mut ls_output = Writer(Vector::new());
        let response = view
            .smart_git(
                request.clone(),
                &mut ls_input,
                &mut ls_output,
                work_budget(),
            )
            .unwrap();
        assert!(!response.refs_activated);
        let ls_text = core::str::from_utf8(&ls_output.0).unwrap();
        assert!(ls_text.contains("refs/heads/main"));
        assert!(!ls_text.contains(" HEAD"));

        let mut tag_input = protocol_request(&[
            Some(b"command=ls-refs\n"),
            Some(b"object-format=sha256\n"),
            None,
            Some(b"peel\n"),
            Some(b"ref-prefix refs/tags/\n"),
        ]);
        let mut tag_output = Writer(Vector::new());
        view.smart_git(
            request.clone(),
            &mut tag_input,
            &mut tag_output,
            work_budget(),
        )
        .unwrap();
        let tag_text = core::str::from_utf8(&tag_output.0).unwrap();
        let expected_tag =
            mrml_runtime::mrml_format!("{} refs/tags/v1 peeled:{}", tag.to_hex(), commit.to_hex());
        assert!(tag_text.contains(expected_tag.as_str()));

        let want = mrml_runtime::mrml_format!("want {}\n", commit.to_hex());
        let mut fetch_input = protocol_request(&[
            Some(b"command=fetch\n"),
            Some(b"object-format=sha256\n"),
            None,
            Some(want.as_bytes()),
            Some(b"done\n"),
            Some(b"ofs-delta\n"),
        ]);
        let mut fetch_output = Writer(Vector::new());
        view.smart_git(request, &mut fetch_input, &mut fetch_output, work_budget())
            .unwrap();
        let mut response_reader = Reader {
            bytes: fetch_output.0,
            offset: 0,
        };
        let mut response_budget = ProtocolBudget::new(work_budget());
        assert_eq!(
            crate::read_pkt_line(&mut response_reader, &mut response_budget),
            Ok(PktLine::Data(Vector::from(*b"packfile\n")))
        );
        let mut pack = Vector::new();
        loop {
            match crate::read_pkt_line(&mut response_reader, &mut response_budget).unwrap() {
                PktLine::Data(payload) => {
                    assert_eq!(payload[0], 1);
                    pack.extend(payload[1..].iter().copied());
                }
                PktLine::Flush => break,
                _ => panic!("unexpected fetch response packet"),
            }
        }
        let objects = crate::parse_pack_with_format(&pack, ObjectFormat::Sha256).unwrap();
        assert!(objects.iter().any(|object| object.id == commit));
        view.precompute_fetch_pack(&identity, &[commit], &[])
            .unwrap();
        let cache = ImmutablePackCacheDirectory::open(&cache_path).unwrap();
        let exact_key = PackCacheKey::new(
            ObjectFormat::Sha256,
            Vector::from([commit]),
            Vector::new(),
            RepositoryGeneration(4),
            FETCH_PACK_PROFILE_VERSION,
            FETCH_PACK_ENCODER_VERSION,
        )
        .unwrap();
        assert_eq!(&cache.lookup(&exact_key).unwrap().unwrap()[..], &pack[..]);
        let stale_key = PackCacheKey::new(
            ObjectFormat::Sha256,
            Vector::from([commit]),
            Vector::new(),
            RepositoryGeneration(5),
            FETCH_PACK_PROFILE_VERSION,
            FETCH_PACK_ENCODER_VERSION,
        )
        .unwrap();
        assert_eq!(cache.lookup(&stale_key).unwrap(), None);
        assert_eq!(
            view.precompute_selected_fetch_packs(
                &identity,
                &[
                    FullRefName::parse("refs/heads/main").unwrap(),
                    FullRefName::parse("refs/tags/latest").unwrap(),
                ],
            ),
            Ok(2)
        );
        let tag_key = PackCacheKey::new(
            ObjectFormat::Sha256,
            Vector::from([tag]),
            Vector::new(),
            RepositoryGeneration(4),
            FETCH_PACK_PROFILE_VERSION,
            FETCH_PACK_ENCODER_VERSION,
        )
        .unwrap();
        assert!(cache.lookup(&tag_key).unwrap().is_some());
        assert_eq!(
            view.precompute_selected_fetch_packs(
                &identity,
                &[FullRefName::parse("refs/heads/missing").unwrap()],
            ),
            Err(GitdCoreError::ObjectValidation)
        );
        let too_many = core::iter::repeat(FullRefName::parse("refs/heads/main").unwrap())
            .take(MAX_FETCH_PRECOMPUTE_REFS + 1)
            .collect::<Vector<_>>();
        assert_eq!(
            view.precompute_selected_fetch_packs(&identity, &too_many),
            Err(GitdCoreError::Resource)
        );

        let mut streaming_view =
            FilesystemRepositoryView::open(identity.clone(), &repository_path, &refs_path).unwrap();
        let mut streaming_input = protocol_request(&[
            Some(b"command=fetch\n"),
            Some(b"object-format=sha256\n"),
            None,
            Some(want.as_bytes()),
            Some(b"done\n"),
            Some(b"ofs-delta\n"),
        ]);
        let mut streaming_output = Writer(Vector::new());
        streaming_view
            .smart_git(
                SmartGitRequest {
                    repository: identity.clone(),
                    repository_generation: RepositoryGeneration(4),
                    operation: SmartGitOperation::UploadPack,
                    object_format: ObjectFormat::Sha256,
                },
                &mut streaming_input,
                &mut streaming_output,
                work_budget(),
            )
            .unwrap();
        let mut streaming_reader = Reader {
            bytes: streaming_output.0,
            offset: 0,
        };
        let mut streaming_budget = ProtocolBudget::new(work_budget());
        assert_eq!(
            crate::read_pkt_line(&mut streaming_reader, &mut streaming_budget),
            Ok(PktLine::Data(Vector::from(*b"packfile\n")))
        );
        let mut streamed_pack = Vector::new();
        loop {
            match crate::read_pkt_line(&mut streaming_reader, &mut streaming_budget).unwrap() {
                PktLine::Data(payload) => {
                    assert_eq!(payload[0], 1);
                    streamed_pack.extend(payload[1..].iter().copied());
                }
                PktLine::Flush => break,
                _ => panic!("unexpected streaming fetch response packet"),
            }
        }
        let streamed_objects =
            crate::parse_pack_with_format(&streamed_pack, ObjectFormat::Sha256).unwrap();
        assert!(streamed_objects.iter().any(|object| object.id == commit));
        assert!(streamed_objects.iter().any(|object| object.id == blob));
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn selected_arrivals_are_the_only_arrivals_visible_to_queries_and_upload_pack() {
        let root = join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-selected-view-{}", mrml_runtime::process_id()),
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        let repository_path = join_path(&root, "repository");
        let refs_path = join_path(&root, "refs");
        let arrivals_path = join_path(&root, "arrivals");
        Repository::init_with_format(&repository_path, ObjectFormat::Sha256).unwrap();

        let blob = PackObject {
            id: ObjectId::blob_with_format(ObjectFormat::Sha256, b"arrival readme"),
            kind: ObjectKind::Blob,
            contents: Vector::from(*b"arrival readme"),
        };
        let mut tree_contents = Vector::from(*b"100644 README.md\0");
        tree_contents.extend(blob.id.as_bytes().iter().copied());
        let (tree_id, _) = crate::encode_loose_object_with_format(
            ObjectFormat::Sha256,
            ObjectKind::Tree,
            &tree_contents,
        );
        let tree = PackObject {
            id: tree_id,
            kind: ObjectKind::Tree,
            contents: tree_contents,
        };
        let commit_contents = mrml_runtime::mrml_format!(
            "tree {}\nauthor Owner <owner@example.invalid> 1 +0000\n\narrival\n",
            tree.id.to_hex()
        );
        let (commit_id, _) = crate::encode_loose_object_with_format(
            ObjectFormat::Sha256,
            ObjectKind::Commit,
            commit_contents.as_bytes(),
        );
        let commit = PackObject {
            id: commit_id,
            kind: ObjectKind::Commit,
            contents: commit_contents.as_bytes().iter().copied().collect(),
        };
        let selected = [blob.clone(), tree.clone(), commit.clone()];
        let selected_pack = encode_pack_with_format(&selected, ObjectFormat::Sha256).unwrap();
        let store =
            ArrivalPackStore::open(&arrivals_path, ObjectFormat::Sha256, 1024 * 1024).unwrap();
        let selected_tx = crate::QuarantineTransactionId([31; 16]);
        let selected_summary = store
            .stage_compacted_pack(selected_tx, &selected_pack, &[blob.id, tree.id, commit.id])
            .unwrap();
        store.install(selected_tx, 3).unwrap();

        let hidden = PackObject {
            id: ObjectId::blob_with_format(ObjectFormat::Sha256, b"installed but unselected"),
            kind: ObjectKind::Blob,
            contents: Vector::from(*b"installed but unselected"),
        };
        let hidden_pack =
            encode_pack_with_format(core::slice::from_ref(&hidden), ObjectFormat::Sha256).unwrap();
        let hidden_tx = crate::QuarantineTransactionId([32; 16]);
        store
            .stage_compacted_pack(hidden_tx, &hidden_pack, &[hidden.id])
            .unwrap();
        store.install(hidden_tx, 1).unwrap();

        let identity = RepositoryIdentity::parse("owner/selected").unwrap();
        let limits = PackSetLimits {
            max_packs: 8,
            max_objects: 16,
            max_pack_bytes: 1024 * 1024,
            max_index_bytes: 1024 * 1024,
            max_work_units: 8 * 1024 * 1024,
        };
        let manifest = crate::pack_set::build_pack_set_manifest(
            identity.clone(),
            RepositoryGeneration(9),
            PackGeneration(2),
            ObjectFormat::Sha256,
            Vector::from([selected_summary]),
            limits,
        )
        .unwrap();
        ActiveRefFile::initialize_with_pack_set(
            &refs_path,
            &ActiveRefState {
                repository: identity.clone(),
                repository_generation: RepositoryGeneration(9),
                trust_generation: TrustGeneration(3),
                revocation_generation: RevocationGeneration(4),
                pack_generation: PackGeneration(2),
                pack_set_digest: manifest.digest().unwrap(),
                object_format: ObjectFormat::Sha256,
                default_branch: FullRefName::parse("refs/heads/main").unwrap(),
                refs: [(FullRefName::parse("refs/heads/main").unwrap(), commit.id)].into(),
            },
            &manifest,
        )
        .unwrap();
        let mut view = FilesystemRepositoryView::open_with_arrivals(
            identity.clone(),
            &repository_path,
            &refs_path,
            &arrivals_path,
            1024 * 1024,
        )
        .unwrap();
        let query_limits = QueryLimits {
            max_entries: 8,
            max_bytes: 1024,
        };
        assert_eq!(
            view.read_commit_details(&identity, commit.id, query_limits)
                .unwrap()
                .tree,
            tree.id
        );
        assert_eq!(
            &*view
                .read_tree_page(&identity, commit.id, &RepositoryPath::root(), query_limits)
                .unwrap()
                .entries,
            &[RepositoryPath::parse("README.md").unwrap()]
        );
        assert_eq!(
            &*view
                .read_blob_page(
                    &identity,
                    commit.id,
                    &RepositoryPath::parse("README.md").unwrap(),
                    query_limits
                )
                .unwrap()
                .bytes,
            b"arrival readme"
        );
        let state = view.load_state().unwrap();
        assert_eq!(
            view.read_object(&state, hidden.id),
            Err(GitdCoreError::ObjectValidation)
        );

        let want = mrml_runtime::mrml_format!("want {}\n", commit.id.to_hex());
        let mut input = protocol_request(&[
            Some(b"command=fetch\n"),
            Some(b"object-format=sha256\n"),
            None,
            Some(want.as_bytes()),
            Some(b"done\n"),
            Some(b"ofs-delta\n"),
        ]);
        let mut output = Writer(Vector::new());
        view.smart_git(
            SmartGitRequest {
                repository: identity,
                repository_generation: RepositoryGeneration(9),
                operation: SmartGitOperation::UploadPack,
                object_format: ObjectFormat::Sha256,
            },
            &mut input,
            &mut output,
            work_budget(),
        )
        .unwrap();
        let mut reader = Reader {
            bytes: output.0,
            offset: 0,
        };
        let mut budget = ProtocolBudget::new(work_budget());
        assert_eq!(
            crate::read_pkt_line(&mut reader, &mut budget).unwrap(),
            PktLine::Data(Vector::from(*b"packfile\n"))
        );
        let mut pack = Vector::new();
        loop {
            match crate::read_pkt_line(&mut reader, &mut budget).unwrap() {
                PktLine::Data(payload) => pack.extend(payload[1..].iter().copied()),
                PktLine::Flush => break,
                _ => panic!("unexpected packet"),
            }
        }
        let packed = crate::parse_pack_with_format(&pack, ObjectFormat::Sha256).unwrap();
        assert!(packed.iter().any(|object| object.id == commit.id));
        assert!(packed.iter().any(|object| object.id == tree.id));
        assert!(packed.iter().any(|object| object.id == blob.id));
        assert!(!packed.iter().any(|object| object.id == hidden.id));
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
