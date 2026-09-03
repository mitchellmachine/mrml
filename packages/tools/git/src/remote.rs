use crate::{
    FetchPackLimits, HttpsRemote, MAX_FETCH_WANTS_PER_REQUEST, ObjectId, Repository,
    extract_pack_response, fetch_request, parse_advertisement, parse_push_response_mode,
    push_request_mode_negotiated,
};
use core::fmt;
use mrml_runtime::{Text, Vector};
use mrml_ssh::{AuthenticatedSsh, ChannelEvent, GitChannel, GitService, RsaPrivateKey, SshRemote};

const MAX_WIRE: usize = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchResult {
    pub objects: Vector<ObjectId>,
    pub branches: Vector<(Text, ObjectId)>,
    pub default_branch: Option<Text>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteInfo {
    pub references: usize,
    pub object_format: crate::ObjectFormat,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FetchError {
    Ssh,
    Https(crate::HttpsRemoteError),
    Protocol,
    Remote,
    Pack,
    Repository,
    TooLarge,
    NoReferences,
}

pub fn fetch_https(
    repository: &Repository,
    remote_name: &str,
    remote: &HttpsRemote,
    maximum_pack_bytes: u64,
) -> Result<FetchResult, FetchError> {
    fetch_https_with_provider(repository, remote_name, remote, maximum_pack_bytes, None)
}

pub fn fetch_https_authenticated(
    repository: &Repository,
    remote_name: &str,
    remote: &HttpsRemote,
    maximum_pack_bytes: u64,
    provider: &mut dyn crate::HttpsCredentialProvider,
) -> Result<FetchResult, FetchError> {
    fetch_https_with_provider(
        repository,
        remote_name,
        remote,
        maximum_pack_bytes,
        Some(provider),
    )
}

fn fetch_https_with_provider(
    repository: &Repository,
    remote_name: &str,
    remote: &HttpsRemote,
    maximum_pack_bytes: u64,
    mut provider: Option<&mut dyn crate::HttpsCredentialProvider>,
) -> Result<FetchResult, FetchError> {
    if repository.object_format() != crate::ObjectFormat::Sha256 {
        return Err(FetchError::Protocol);
    }
    let advertisement = match provider.as_deref_mut() {
        Some(provider) => remote.list_refs_authenticated(provider),
        None => remote.list_refs(),
    }
    .map_err(FetchError::Https)?;
    let mut branches: Vector<(Text, ObjectId)> = advertisement
        .refs
        .into_iter()
        .filter_map(|reference| {
            reference
                .name
                .strip_prefix("refs/heads/")
                .map(|branch| (branch.into(), reference.id))
        })
        .collect();
    branches.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    if branches.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(FetchError::Protocol);
    }
    if branches.is_empty() {
        repository
            .activate_remote_refs_atomically(remote_name, &[])
            .map_err(|_| FetchError::Repository)?;
        return Ok(FetchResult {
            objects: Vector::new(),
            branches,
            default_branch: advertisement.default_branch,
        });
    }
    let limits =
        FetchPackLimits::production(maximum_pack_bytes).map_err(|_| FetchError::TooLarge)?;
    let candidate = mrml_runtime::join_path(
        &repository.git_dir,
        &mrml_runtime::mrml_format!("mrml-fetch-{}", mrml_runtime::process_id()),
    );
    if mrml_runtime::path_exists(&candidate) {
        return Err(FetchError::Repository);
    }
    mrml_runtime::create_dir_all(&candidate).map_err(|_| FetchError::Repository)?;
    let result = (|| {
        let mut objects = Vector::new();
        let mut tips = Vector::new();
        for (_, id) in &branches {
            if !tips.contains(id) {
                tips.push(*id);
            }
        }
        let mut offset = 0usize;
        while offset < tips.len() {
            let end = core::cmp::min(offset + MAX_FETCH_WANTS_PER_REQUEST, tips.len());
            let wants = &tips[offset..end];
            let pack = mrml_runtime::join_path(
                &candidate,
                &mrml_runtime::mrml_format!("batch-{offset}.pack"),
            );
            let scratch = mrml_runtime::join_path(
                &candidate,
                &mrml_runtime::mrml_format!("batch-{offset}.objects"),
            );
            match provider.as_deref_mut() {
                Some(provider) => remote.fetch_pack_to_file_authenticated(
                    wants,
                    &[],
                    &pack,
                    maximum_pack_bytes,
                    provider,
                ),
                None => remote.fetch_pack_to_file(wants, &[], &pack, maximum_pack_bytes),
            }
            .map_err(FetchError::Https)?;
            let installed = repository
                .import_pack_file_validated_commit_tips(&pack, &scratch, wants, limits)
                .map_err(|_| FetchError::Pack)?;
            objects.extend(installed);
            offset = end;
        }
        mrml_runtime::remove_dir_all(&candidate).map_err(|_| FetchError::Repository)?;
        repository
            .activate_remote_refs_atomically(remote_name, &branches)
            .map_err(|_| FetchError::Repository)?;
        Ok(FetchResult {
            objects,
            branches: branches.clone(),
            default_branch: advertisement.default_branch,
        })
    })();
    if result.is_err() && mrml_runtime::path_exists(&candidate) {
        let _ = mrml_runtime::remove_dir_all(&candidate);
    }
    result
}

pub fn fetch_ssh(
    repository: &Repository,
    remote_name: &str,
    remote: &SshRemote,
    key: &RsaPrivateKey,
    host_key: &[u8],
) -> Result<FetchResult, FetchError> {
    let user = remote.user.as_deref().unwrap_or("git");
    let authenticated =
        AuthenticatedSsh::connect(&remote.host, remote.port.unwrap_or(22), user, key, host_key)
            .map_err(|_| FetchError::Ssh)?;
    let mut channel = GitChannel::open(authenticated, GitService::UploadPack, &remote.path)
        .map_err(|_| FetchError::Ssh)?;
    let advertisement_bytes = collect_until_flush(&mut channel)?;
    let advertisement =
        parse_advertisement(&advertisement_bytes).map_err(|_| FetchError::Protocol)?;
    if advertisement.object_format != repository.object_format() {
        return Err(FetchError::Protocol);
    }
    let mut wants = Vector::new();
    for reference in &advertisement.refs {
        if reference.name.starts_with("refs/heads/") && !wants.contains(&reference.id) {
            wants.push(reference.id);
        }
    }
    if wants.is_empty() {
        channel.send_all(b"0000").map_err(|_| FetchError::Ssh)?;
        channel.send_eof().map_err(|_| FetchError::Ssh)?;
        collect_to_close(&mut channel)?;
        repository
            .prune_remote_refs(remote_name, &[])
            .map_err(|_| FetchError::Repository)?;
        return Ok(FetchResult {
            objects: Vector::new(),
            branches: Vector::new(),
            default_branch: None,
        });
    }
    let side_band = advertisement
        .capabilities
        .iter()
        .any(|capability| capability == "side-band-64k");
    let mut capabilities = Vector::new();
    if side_band {
        capabilities.push("side-band-64k");
    }
    if advertisement
        .capabilities
        .iter()
        .any(|capability| capability == "ofs-delta")
    {
        capabilities.push("ofs-delta");
    }
    if let Some(capability) = advertisement
        .capabilities
        .iter()
        .find(|capability| capability.starts_with("object-format="))
    {
        capabilities.push(capability.as_str());
    }
    let request = fetch_request(&wants, &[], &capabilities).map_err(|_| FetchError::Protocol)?;
    channel.send_all(&request).map_err(|_| FetchError::Ssh)?;
    channel.send_eof().map_err(|_| FetchError::Ssh)?;
    let response = collect_to_close(&mut channel)?;
    let pack = extract_pack_response(&response, side_band).map_err(|_| FetchError::Protocol)?;
    let objects = repository
        .import_pack_validated_commit_tips(&pack, &wants)
        .map_err(|_| FetchError::Pack)?;
    let default_branch = advertisement.capabilities.iter().find_map(|capability| {
        capability
            .strip_prefix("symref=HEAD:refs/heads/")
            .map(Into::into)
    });
    let mut branches: Vector<(Text, ObjectId)> = Vector::new();
    for reference in advertisement.refs {
        if let Some(branch) = reference.name.strip_prefix("refs/heads/") {
            repository
                .update_remote_ref(remote_name, &reference.name, reference.id)
                .map_err(|_| FetchError::Repository)?;
            branches.push((branch.into(), reference.id));
        }
    }
    let live: Vector<Text> = branches.iter().map(|(branch, _)| branch.clone()).collect();
    repository
        .prune_remote_refs(remote_name, &live)
        .map_err(|_| FetchError::Repository)?;
    Ok(FetchResult {
        objects,
        branches,
        default_branch,
    })
}

fn append(output: &mut Vector<u8>, bytes: &[u8]) -> Result<(), FetchError> {
    if output
        .len()
        .checked_add(bytes.len())
        .is_none_or(|n| n > MAX_WIRE)
    {
        return Err(FetchError::TooLarge);
    }
    output.extend(bytes.iter().copied());
    Ok(())
}
fn collect_until_flush(channel: &mut GitChannel) -> Result<Vector<u8>, FetchError> {
    let mut output = Vector::new();
    loop {
        match channel.receive_event().map_err(|_| FetchError::Ssh)? {
            ChannelEvent::Data { bytes, .. } => {
                append(&mut output, &bytes)?;
                if advertisement_has_flush(&output)? {
                    return Ok(output);
                }
            }
            ChannelEvent::ExtendedData { .. } => return Err(FetchError::Remote),
            ChannelEvent::Close(_) | ChannelEvent::Eof(_) => return Err(FetchError::Protocol),
            _ => {}
        }
    }
}
fn advertisement_has_flush(source: &[u8]) -> Result<bool, FetchError> {
    let mut cursor = 0usize;
    while cursor < source.len() {
        if source.len() - cursor < 4 {
            return Ok(false);
        }
        let mut length = 0usize;
        for byte in &source[cursor..cursor + 4] {
            length = length.checked_mul(16).ok_or(FetchError::Protocol)?
                + match byte {
                    b'0'..=b'9' => (*byte - b'0') as usize,
                    b'a'..=b'f' => (*byte - b'a' + 10) as usize,
                    b'A'..=b'F' => (*byte - b'A' + 10) as usize,
                    _ => return Err(FetchError::Protocol),
                };
        }
        if length == 0 {
            return Ok(true);
        }
        if length < 4 || length > 65_520 {
            return Err(FetchError::Protocol);
        }
        if source.len() - cursor < length {
            return Ok(false);
        }
        cursor = cursor.checked_add(length).ok_or(FetchError::TooLarge)?;
    }
    Ok(false)
}
fn collect_to_close(channel: &mut GitChannel) -> Result<Vector<u8>, FetchError> {
    let mut output = Vector::new();
    let mut status = None;
    loop {
        match channel.receive_event().map_err(|_| FetchError::Ssh)? {
            ChannelEvent::Data { bytes, .. } => append(&mut output, &bytes)?,
            ChannelEvent::ExtendedData { .. } => return Err(FetchError::Remote),
            ChannelEvent::ExitStatus { status: value, .. } => status = Some(value),
            ChannelEvent::Close(_) => {
                return if status.is_none_or(|value| value == 0) {
                    Ok(output)
                } else {
                    Err(FetchError::Remote)
                };
            }
            _ => {}
        }
    }
}
impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ssh => "native SSH transport failed",
            Self::Https(error) => return write!(f, "native HTTPS transport failed: {error}"),
            Self::Protocol => "remote Git protocol response is invalid",
            Self::Remote => "remote Git service failed",
            Self::Pack => "received Git pack failed authentication",
            Self::Repository => "failed to update remote-tracking references",
            Self::TooLarge => "remote response exceeds limit",
            Self::NoReferences => "remote advertises no branch references",
        })
    }
}
impl core::error::Error for FetchError {}

pub fn check_ssh(
    remote: &SshRemote,
    key: &RsaPrivateKey,
    host_key: &[u8],
) -> Result<usize, FetchError> {
    Ok(inspect_ssh(remote, key, host_key)?.references)
}

pub fn inspect_ssh(
    remote: &SshRemote,
    key: &RsaPrivateKey,
    host_key: &[u8],
) -> Result<RemoteInfo, FetchError> {
    let user = remote.user.as_deref().unwrap_or("git");
    let authenticated =
        AuthenticatedSsh::connect(&remote.host, remote.port.unwrap_or(22), user, key, host_key)
            .map_err(|_| FetchError::Ssh)?;
    let mut channel = GitChannel::open(authenticated, GitService::UploadPack, &remote.path)
        .map_err(|_| FetchError::Ssh)?;
    let bytes = collect_until_flush(&mut channel)?;
    let advertisement = parse_advertisement(&bytes).map_err(|_| FetchError::Protocol)?;
    Ok(RemoteInfo {
        references: advertisement.refs.len(),
        object_format: advertisement.object_format,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PushResult {
    pub old: ObjectId,
    pub new: ObjectId,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushError {
    Ssh,
    Https,
    Protocol,
    Remote,
    Repository,
    TooLarge,
    NonFastForward,
    NeedsFetch,
}

struct PushPackFile {
    file: mrml_runtime::File,
    bytes: u64,
    failed: bool,
}

impl PushPackFile {
    fn create_new(path: &str) -> Result<Self, PushError> {
        Ok(Self {
            file: mrml_runtime::File::create_new(path).map_err(|_| PushError::Repository)?,
            bytes: 0,
            failed: false,
        })
    }

    fn finish(&self) -> Result<(), PushError> {
        self.file.sync().map_err(|_| PushError::Repository)
    }
}

impl crate::PackStreamOutput for PushPackFile {
    fn write(&mut self, bytes: &[u8]) -> Result<(), crate::PackError> {
        let Some(next) = self.bytes.checked_add(bytes.len() as u64) else {
            return Err(crate::PackError::TooLarge);
        };
        if next > MAX_WIRE as u64 || self.file.write_all(bytes).is_err() {
            self.failed = true;
            return Err(crate::PackError::TooLarge);
        }
        self.bytes = next;
        Ok(())
    }
}

pub fn push_https_authenticated(
    repository: &Repository,
    remote_name: &str,
    branch: &str,
    remote: &HttpsRemote,
    provider: &mut dyn crate::HttpsCredentialProvider,
) -> Result<PushResult, PushError> {
    if repository.object_format() != crate::ObjectFormat::Sha256 {
        return Err(PushError::Protocol);
    }
    let reference = mrml_runtime::mrml_format!("refs/heads/{branch}");
    let advertisement = remote
        .list_refs_authenticated(provider)
        .map_err(|_| PushError::Https)?;
    let old = advertisement
        .refs
        .iter()
        .find(|entry| entry.name == reference)
        .map(|entry| entry.id)
        .unwrap_or(ObjectId::zero(crate::ObjectFormat::Sha256));
    let new = repository
        .resolve_revision(branch)
        .map_err(|_| PushError::Repository)?;
    if old == new {
        return Ok(PushResult { old, new });
    }
    if !old.is_zero() {
        match repository.is_ancestor(old, new) {
            Ok(true) => {}
            Ok(false) => return Err(PushError::NonFastForward),
            Err(_) => return Err(PushError::NeedsFetch),
        }
    }
    let pack_path = mrml_runtime::join_path(
        &repository.git_dir,
        &mrml_runtime::mrml_format!("mrml-push-{}.pack", mrml_runtime::process_id()),
    );
    if mrml_runtime::path_exists(&pack_path) {
        return Err(PushError::Repository);
    }
    let result = (|| {
        let mut output = PushPackFile::create_new(&pack_path)?;
        let haves = if old.is_zero() { &[][..] } else { &[old][..] };
        if repository
            .write_negotiated_pack(&[new], haves, &mut output)
            .is_err()
        {
            return Err(if output.failed {
                PushError::Repository
            } else {
                PushError::Protocol
            });
        }
        output.finish()?;
        remote
            .push_pack_file_authenticated(old, new, &reference, &pack_path, provider)
            .map_err(|_| PushError::Https)?;
        repository
            .update_remote_ref(remote_name, &reference, new)
            .map_err(|_| PushError::Repository)?;
        Ok(PushResult { old, new })
    })();
    if mrml_runtime::path_exists(&pack_path) && mrml_runtime::remove_file(&pack_path).is_err() {
        return Err(PushError::Repository);
    }
    result
}

pub fn push_https_protected_authenticated(
    repository: &Repository,
    remote_name: &str,
    branch: &str,
    remote: &HttpsRemote,
    credential_provider: &mut dyn crate::HttpsCredentialProvider,
    proof_signer: &mut dyn crate::ProtectedCommitProofSigner,
    history_limits: crate::HistoryVerificationLimits,
) -> Result<PushResult, PushError> {
    if repository.object_format() != crate::ObjectFormat::Sha256 {
        return Err(PushError::Protocol);
    }
    let reference = mrml_runtime::mrml_format!("refs/heads/{branch}");
    let identity = remote
        .repository_identity()
        .map_err(|_| PushError::Protocol)?;
    if let Some(pending) = crate::pending_protected_push::PendingProtectedPush::load(
        &repository.git_dir,
    )
    .map_err(|_| PushError::Repository)?
    {
        if pending.repository != identity || pending.reference != reference {
            return Err(PushError::Https);
        }
        let status = remote
            .candidate_status_authenticated(pending.candidate, credential_provider)
            .map_err(|_| PushError::Https)?;
        if status.record.context.repository != pending.repository
            || status.record.context.id != pending.candidate
            || status.record.context.current_generation != pending.repository_generation
            || status.record.context.next_generation.0
                != pending
                    .repository_generation
                    .0
                    .checked_add(1)
                    .ok_or(PushError::Protocol)?
            || status.record.context.trust_generation != pending.trust_generation
            || status.record.context.revocation_generation != pending.revocation_generation
        {
            return Err(PushError::Protocol);
        }
        match status.record.status {
            crate::AuthorityCandidateStatus::ReceiptPersisted
            | crate::AuthorityCandidateStatus::Completed => {
                let receipt = status.authenticated_receipt.ok_or(PushError::Protocol)?;
                validate_protected_push_receipt(&receipt, &pending)?;
                proof_signer
                    .advance_repository_generation(&receipt)
                    .map_err(|_| PushError::Protocol)?;
                repository
                    .update_remote_ref(remote_name, &reference, pending.new)
                    .map_err(|_| PushError::Repository)?;
                crate::pending_protected_push::PendingProtectedPush::remove(&repository.git_dir)
                    .map_err(|_| PushError::Repository)?;
                return Ok(PushResult {
                    old: pending.old,
                    new: pending.new,
                });
            }
            crate::AuthorityCandidateStatus::Aborted => {
                crate::pending_protected_push::PendingProtectedPush::remove(&repository.git_dir)
                    .map_err(|_| PushError::Repository)?;
            }
            _ => return Err(PushError::Https),
        }
    }
    let advertisement = remote
        .list_refs_authenticated(credential_provider)
        .map_err(|_| PushError::Https)?;
    let old = advertisement
        .refs
        .iter()
        .find(|entry| entry.name == reference)
        .map(|entry| entry.id)
        .ok_or(PushError::NeedsFetch)?;
    let new = repository
        .resolve_revision(branch)
        .map_err(|_| PushError::Repository)?;
    if old == new {
        return Ok(PushResult { old, new });
    }
    match repository.is_ancestor(old, new) {
        Ok(true) => {}
        Ok(false) => return Err(PushError::NonFastForward),
        Err(_) => return Err(PushError::NeedsFetch),
    }
    let discovery = remote
        .discover_receive_pack_authenticated(credential_provider)
        .map_err(|_| PushError::Https)?;
    let context = crate::ProtectedHistoryContext {
        repository: &identity,
        repository_generation: discovery.repository_generation,
        trust_generation: discovery.trust_generation,
        revocation_generation: discovery.revocation_generation,
        purpose: crate::SignaturePurpose::GitCommit,
        object_format: crate::ObjectFormat::Sha256,
    };
    let proofs = crate::sign_protected_introduced_history(
        repository,
        context,
        old,
        new,
        history_limits,
        proof_signer,
    )
    .map_err(|_| PushError::Protocol)?;
    let mut candidate_id = [0u8; 16];
    mrml_runtime::fill_random(&mut candidate_id).map_err(|_| PushError::Repository)?;
    if candidate_id == [0; 16] {
        return Err(PushError::Repository);
    }
    let candidate_id = crate::QuarantineTransactionId(candidate_id);
    let pack_path = mrml_runtime::join_path(
        &repository.git_dir,
        &mrml_runtime::mrml_format!("mrml-push-{}.pack", mrml_runtime::process_id()),
    );
    if mrml_runtime::path_exists(&pack_path) {
        return Err(PushError::Repository);
    }
    let result = (|| {
        let mut output = PushPackFile::create_new(&pack_path)?;
        if repository
            .write_negotiated_pack(&[new], &[old], &mut output)
            .is_err()
        {
            return Err(if output.failed {
                PushError::Repository
            } else {
                PushError::Protocol
            });
        }
        output.finish()?;
        let pending = crate::pending_protected_push::PendingProtectedPush {
            repository: identity.clone(),
            reference: reference.clone(),
            candidate: candidate_id,
            old,
            new,
            repository_generation: discovery.repository_generation,
            trust_generation: discovery.trust_generation,
            revocation_generation: discovery.revocation_generation,
        };
        crate::pending_protected_push::PendingProtectedPush::create(
            &repository.git_dir,
            &pending,
        )
        .map_err(|_| PushError::Repository)?;
        let authenticated_receipt = match remote.push_protected_pack_file_authenticated(
                old,
                new,
                &reference,
                &pack_path,
                discovery,
                candidate_id,
                &proofs,
                credential_provider,
            )
        {
            Ok(receipt) => receipt,
            Err(_) => {
                let status = remote
                    .candidate_status_authenticated(candidate_id, credential_provider)
                    .map_err(|_| PushError::Https)?;
                if status.record.context.current_generation
                    != discovery.repository_generation
                    || status.record.context.next_generation.0
                        != discovery
                            .repository_generation
                            .0
                            .checked_add(1)
                            .ok_or(PushError::Protocol)?
                    || status.record.context.trust_generation != discovery.trust_generation
                    || status.record.context.revocation_generation
                        != discovery.revocation_generation
                {
                    return Err(PushError::Protocol);
                }
                match status.record.status {
                    crate::AuthorityCandidateStatus::ReceiptPersisted
                    | crate::AuthorityCandidateStatus::Completed => status
                        .authenticated_receipt
                        .ok_or(PushError::Protocol)?,
                    crate::AuthorityCandidateStatus::Aborted => {
                        crate::pending_protected_push::PendingProtectedPush::remove(
                            &repository.git_dir,
                        )
                        .map_err(|_| PushError::Repository)?;
                        return Err(PushError::Remote);
                    }
                    _ => return Err(PushError::Https),
                }
            }
        };
        validate_protected_push_receipt(&authenticated_receipt, &pending)?;
        proof_signer
            .advance_repository_generation(&authenticated_receipt)
            .map_err(|_| PushError::Protocol)?;
        repository
            .update_remote_ref(remote_name, &reference, new)
            .map_err(|_| PushError::Repository)?;
        crate::pending_protected_push::PendingProtectedPush::remove(&repository.git_dir)
            .map_err(|_| PushError::Repository)?;
        Ok(PushResult { old, new })
    })();
    if mrml_runtime::path_exists(&pack_path) && mrml_runtime::remove_file(&pack_path).is_err() {
        return Err(PushError::Repository);
    }
    result
}

fn validate_protected_push_receipt(
    authenticated_receipt: &[u8],
    pending: &crate::pending_protected_push::PendingProtectedPush,
) -> Result<(), PushError> {
    let receipt = crate::parse_authenticated_audit_receipt(authenticated_receipt)
        .map_err(|_| PushError::Protocol)?;
    if receipt.receipt.transaction != pending.candidate
        || receipt.receipt.repository != pending.repository
        || receipt.receipt.repository_generation != pending.repository_generation
        || receipt.receipt.trust_generation != pending.trust_generation
        || receipt.receipt.revocation_generation != pending.revocation_generation
        || receipt.receipt.activated_repository_generation.0
            != pending
                .repository_generation
                .0
                .checked_add(1)
                .ok_or(PushError::Protocol)?
        || receipt.receipt.updates.len() != 1
        || pending.reference != receipt.receipt.updates[0].0.as_str()
        || receipt.receipt.updates[0].1 != pending.old
        || receipt.receipt.updates[0].2 != pending.new
    {
        return Err(PushError::Protocol);
    }
    Ok(())
}

pub fn push_ssh(
    repository: &Repository,
    remote_name: &str,
    branch: &str,
    remote: &SshRemote,
    key: &RsaPrivateKey,
    host_key: &[u8],
) -> Result<PushResult, PushError> {
    let user = remote.user.as_deref().unwrap_or("git");
    let authenticated =
        AuthenticatedSsh::connect(&remote.host, remote.port.unwrap_or(22), user, key, host_key)
            .map_err(|_| PushError::Ssh)?;
    let mut channel = GitChannel::open(authenticated, GitService::ReceivePack, &remote.path)
        .map_err(|_| PushError::Ssh)?;
    let advertisement_bytes = collect_until_flush(&mut channel).map_err(map_fetch_push)?;
    let advertisement =
        parse_advertisement(&advertisement_bytes).map_err(|_| PushError::Protocol)?;
    if advertisement.object_format != repository.object_format() {
        return Err(PushError::Protocol);
    }
    if !advertisement
        .capabilities
        .iter()
        .any(|cap| cap == "report-status")
    {
        return Err(PushError::Protocol);
    }
    let side_band = advertisement
        .capabilities
        .iter()
        .any(|cap| cap == "side-band-64k");
    let reference = mrml_runtime::mrml_format!("refs/heads/{branch}");
    let old = advertisement
        .refs
        .iter()
        .find(|entry| entry.name == reference)
        .map(|entry| entry.id)
        .unwrap_or(ObjectId::zero(repository.object_format()));
    let new = repository
        .resolve_revision(branch)
        .map_err(|_| PushError::Repository)?;
    if old == new {
        return Ok(PushResult { old, new });
    }
    if !old.is_zero() {
        match repository.is_ancestor(old, new) {
            Ok(true) => {}
            Ok(false) => return Err(PushError::NonFastForward),
            Err(_) => return Err(PushError::NeedsFetch),
        }
    }
    let pack = repository
        .pack_reachable(new)
        .map_err(|_| PushError::Repository)?;
    let request = push_request_mode_negotiated(
        old,
        new,
        &reference,
        &pack,
        side_band,
        advertisement.object_format_explicit,
    )
    .map_err(|_| PushError::Protocol)?;
    channel.send_all(&request).map_err(|_| PushError::Ssh)?;
    channel.send_eof().map_err(|_| PushError::Ssh)?;
    let response = collect_to_close(&mut channel).map_err(map_fetch_push)?;
    parse_push_response_mode(&response, &reference, side_band).map_err(|_| PushError::Remote)?;
    repository
        .update_remote_ref(remote_name, &reference, new)
        .map_err(|_| PushError::Repository)?;
    Ok(PushResult { old, new })
}
fn map_fetch_push(error: FetchError) -> PushError {
    match error {
        FetchError::Ssh => PushError::Ssh,
        FetchError::TooLarge => PushError::TooLarge,
        FetchError::Remote => PushError::Remote,
        _ => PushError::Protocol,
    }
}
impl fmt::Display for PushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ssh => "native SSH transport failed",
            Self::Https => "native HTTPS transport failed or push result is uncertain",
            Self::Protocol => "remote receive-pack protocol is unsupported or invalid",
            Self::Remote => "remote rejected the pushed reference",
            Self::Repository => "failed to read or update repository state",
            Self::TooLarge => "push response exceeds limit",
            Self::NonFastForward => "push is not a fast-forward",
            Self::NeedsFetch => "remote tip is not available locally; fetch before pushing",
        })
    }
}
impl core::error::Error for PushError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertisement_flush_is_recognized_only_at_packet_boundaries() {
        let mut wire = Vector::new();
        crate::encode_packet(
            b"0000000000000000000000000000000000000000000000000000000000000000 capabilities^{}\0object-format=sha256\n",
            &mut wire,
        )
        .unwrap();
        assert!(!advertisement_has_flush(&wire).unwrap());
        crate::encode_flush(&mut wire);
        assert!(advertisement_has_flush(&wire).unwrap());
        for end in 0..wire.len() - 4 {
            assert!(!advertisement_has_flush(&wire[..end]).unwrap());
        }
    }
}
