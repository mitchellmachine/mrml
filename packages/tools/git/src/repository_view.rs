//! Generation-stable, bounded repository queries for the untrusted edge.

use mrml_runtime::Vector;

use crate::{
    ActiveRefFile, BlobPage, BoundedRead, BoundedWrite, CommitDetails, CommitPage, GitdCoreBackend,
    GitdCoreError, ObjectId, ObjectKind, PktLine, ProtocolBudget, ProtocolV2Request, QueryLimits,
    ReadmeCandidate, Repository, RepositoryGeneration, RepositoryIdentity, RepositoryPath,
    RepositorySummary, RevocationGeneration, SmartGitOperation, SmartGitRequest, SmartGitResponse,
    TreePage, TrustGeneration, VerificationSummary, WorkBudget, read_v2_request, write_pkt_line,
};

pub struct FilesystemRepositoryView {
    identity: RepositoryIdentity,
    objects: Repository,
    refs: ActiveRefFile,
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

    fn resolve_readme_candidate(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
    ) -> Result<Option<ReadmeCandidate>, GitdCoreError> {
        Self::resolve_readme_candidate(self, repository, treeish)
    }

    fn verification_summary(
        &self,
        repository: &RepositoryIdentity,
        _object: ObjectId,
        _policy: TrustGeneration,
        _revocations: RevocationGeneration,
    ) -> Result<VerificationSummary, GitdCoreError> {
        self.load_for(repository)?;
        Err(GitdCoreError::Unsupported)
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
                if !done || thin_pack || sideband_all || !haves.is_empty() || wants.len() != 1 {
                    return Err(GitdCoreError::Unsupported);
                }
                let want = wants[0];
                if !state.refs.iter().any(|(_, id)| *id == want) {
                    return Err(GitdCoreError::Authorization);
                }
                let pack = self
                    .objects
                    .pack_reachable(want)
                    .map_err(|_| GitdCoreError::ObjectValidation)?;
                if pack.len() as u64 > budget.max_memory_bytes {
                    return Err(GitdCoreError::Resource);
                }
                self.ensure_generation(state.repository_generation)?;
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
                if let Some(peeled) = self.peel_annotated_tag(*id)? {
                    line.push_str(" peeled:");
                    line.push_str(&peeled.to_hex());
                }
            }
            line.push('\n');
            write_data_line(output, line.as_bytes(), budget)?;
        }
        self.ensure_generation(state.repository_generation)?;
        write_pkt_line(output, &PktLine::Flush, budget)
    }

    fn peel_annotated_tag(&self, mut id: ObjectId) -> Result<Option<ObjectId>, GitdCoreError> {
        let original = id;
        for _ in 0..16 {
            let object = self
                .objects
                .read_object(id)
                .map_err(|_| GitdCoreError::ObjectValidation)?;
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
                    target = ObjectId::parse_for(self.objects.object_format(), value);
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
        let parsed = self
            .objects
            .read_commit(commit)
            .map_err(|_| GitdCoreError::ObjectValidation)?;
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
        self.ensure_generation(before.repository_generation)?;
        Ok(CommitDetails {
            repository_generation: before.repository_generation,
            commit,
            tree: parsed.tree,
            parents: parsed.parents,
            author: parsed.author,
            message: parsed.message,
        })
    }

    pub fn resolve_readme_candidate(
        &self,
        repository: &RepositoryIdentity,
        treeish: ObjectId,
    ) -> Result<Option<ReadmeCandidate>, GitdCoreError> {
        let before = self.load_for(repository)?;
        let tree = self.tree_id(treeish, before.object_format)?;
        let index = self
            .objects
            .tree_index(tree)
            .map_err(|_| GitdCoreError::ObjectValidation)?;
        let mut selected = None;
        for candidate in ["README.md", "README.txt", "README.rst", "README"] {
            if let Some(entry) = index.entry(candidate) {
                let object = self
                    .objects
                    .read_object(entry.id)
                    .map_err(|_| GitdCoreError::ObjectValidation)?;
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
        self.ensure_generation(before.repository_generation)?;
        Ok(selected)
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
        let tree = self.tree_id(treeish, before.object_format)?;
        let index = self
            .objects
            .tree_index(tree)
            .map_err(|_| GitdCoreError::ObjectValidation)?;
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
        self.ensure_generation(before.repository_generation)?;
        Ok(BlobPage {
            repository_generation: before.repository_generation,
            blob: entry.id,
            offset: offset as u64,
            bytes,
            complete: offset + take == object.contents.len(),
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
                object_format: ObjectFormat::Sha256,
                default_branch: FullRefName::parse("refs/heads/main").unwrap(),
                refs: [
                    (FullRefName::parse("refs/heads/main").unwrap(), commit),
                    (FullRefName::parse("refs/tags/v1").unwrap(), tag),
                ]
                .into(),
            },
        )
        .unwrap();
        let mut view =
            FilesystemRepositoryView::open(identity.clone(), &repository_path, &refs_path).unwrap();
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
        let details = GitdCoreBackend::read_commit_details(&view, &identity, commit, limits).unwrap();
        assert_eq!(details.commit, commit);
        assert_eq!(details.tree, tree);
        assert!(details.parents.is_empty());
        assert_eq!(details.message, "initial\n");
        let readme = GitdCoreBackend::resolve_readme_candidate(&view, &identity, commit)
            .unwrap()
            .unwrap();
        assert_eq!(readme.repository_generation, RepositoryGeneration(4));
        assert_eq!(readme.path, RepositoryPath::parse("README.md").unwrap());
        assert_eq!(readme.blob, blob);
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
            Err(GitdCoreError::Unsupported)
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
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
