#![no_std]

use mrml_runtime::{Text, Vector};

mod diff;
mod gitd_core;
mod hybrid_signing;
mod index;
mod inflate;
mod object;
mod openpgp_provider;
mod pack;
mod remote;
mod repository;
mod sha1;
mod smart_protocol;
mod transport;
mod trust_policy;
mod verification;

pub use diff::FileDiff;
pub use gitd_core::{
    BlobPage, BoundedRead, BoundedWrite, CandidateRefTransaction, CandidateRefUpdate, CommitPage,
    FullRefName, GitdCoreBackend, GitdCoreError, MAX_REFS_PER_TRANSACTION, QueryLimits,
    RepositoryGeneration, RepositoryIdentity, RepositoryPath, RepositorySummary,
    RevocationGeneration, SignaturePurpose, SmartGitOperation, SmartGitRequest, SmartGitResponse,
    TreePage, TrustGeneration, VerificationSummary, VerifiedRefTransaction, VerifiedRefUpdate,
    WorkBudget, build_verified_fast_forward_transaction,
};
pub use hybrid_signing::{sign_ml_dsa_65_git_payload, verify_ml_dsa_65_git_payload};
pub use index::{Index, IndexEntry, IndexError};
pub use mrml_openpgp::{
    DigestAlgorithm as OpenPgpDigestAlgorithm, Error as OpenPgpError,
    Fingerprint as OpenPgpFingerprint, PublicKey as OpenPgpPublicKey,
    SigningKey as OpenPgpSigningKey, VerificationPolicy as OpenPgpVerificationPolicy,
    VerifiedSignature as VerifiedOpenPgpSignature, parse_public_key_ascii, sign_detached_ascii,
    verify_detached_ascii, verify_detached_ascii_with_public_key,
};
pub use object::{
    Commit, Object, ObjectError, ObjectKind, TreeEntry, decode_loose_object, encode_loose_object,
    encode_loose_object_with_format, parse_tree, parse_tree_with_format,
};
pub use openpgp_provider::{
    OpenPgpServiceError, describe_public_key_via_interface, sign_git_payload_via_interface,
};
pub use pack::{
    PackError, PackObject, encode_pack, encode_pack_with_format, parse_pack, parse_pack_with_format,
};
pub use remote::{
    FetchError, FetchResult, PushError, PushResult, RemoteInfo, check_ssh, fetch_ssh, inspect_ssh,
    push_ssh,
};
pub use repository::{
    BlameLine, GitSignatureFormat, MergeOutcome, NativeChange, NativeChangeKind, RebaseOutcome,
    Repository, RepositoryError,
};
pub use sha1::{ObjectFormat, ObjectId, Sha1};
pub use smart_protocol::{
    MAX_PKT_LINE_BYTES, PktLine, ProtocolBudget, read_pkt_line, write_pkt_line,
};
pub use transport::{
    Advertisement, RemoteRef, TransportError, decode_packets, encode_flush, encode_packet,
    extract_pack_response, fetch_request, parse_advertisement, parse_push_response,
    parse_push_response_mode, push_request, push_request_mode, push_request_mode_negotiated,
};
pub use trust_policy::{
    AuthorizedHybridPair, GitObjectType, HYBRID_PROFILE_NAME, HybridPolicyError, HybridTrustPolicy,
    HybridVerificationRequest, MAX_ENCODED_TRUST_POLICY_BYTES, MAX_HYBRID_PAYLOAD_BYTES,
    MAX_POLICY_PAIRS, MAX_POLICY_PROTECTED_REFS, MAX_POLICY_REVOKED_KEYS, TrustPolicyCandidate,
    TrustPolicyState, VerifiedHybridSignature, canonical_hybrid_transcript, encode_trust_policy,
    parse_trust_policy, verify_hybrid_signature,
};
pub use verification::{
    DEFAULT_MAX_INTRODUCED_COMMITS, HistoryVerificationError, HistoryVerificationLimits,
    VerifiedCommitRange, verify_introduced_history,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cli {
    pub repository: Option<Text>,
    pub command: Text,
    pub arguments: Vector<Text>,
}

impl Cli {
    pub fn parse<I, S>(arguments: I) -> core::result::Result<Self, Text>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let all = arguments
            .into_iter()
            .map(|value| Text::from(value.as_ref()))
            .collect::<Vector<_>>();
        let mut repository = None;
        let mut index = 1;
        while index < all.len() {
            match all[index].as_str() {
                "-C" | "--repo" => {
                    index += 1;
                    repository = Some(
                        all.get(index)
                            .ok_or_else(|| Text::from("-C/--repo requires a path"))?
                            .clone(),
                    );
                    index += 1;
                }
                value if value.starts_with("--repo=") => {
                    repository = Some(value[7..].into());
                    index += 1;
                }
                _ => break,
            }
        }
        let command = all.get(index).cloned().unwrap_or_else(|| "status".into());
        let arguments = all
            .get(index + 1..)
            .unwrap_or(&[])
            .iter()
            .cloned()
            .collect();
        Ok(Self {
            repository,
            command,
            arguments,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileState {
    Added,
    Modified,
    Deleted,
    Renamed,
    Copied,
    Unmerged,
    Untracked,
    Ignored,
    Other,
}

impl FileState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Modified => "modified",
            Self::Deleted => "deleted",
            Self::Renamed => "renamed",
            Self::Copied => "copied",
            Self::Unmerged => "conflict",
            Self::Untracked => "untracked",
            Self::Ignored => "ignored",
            Self::Other => "changed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Change {
    pub index: char,
    pub worktree: char,
    pub path: Text,
    pub original_path: Option<Text>,
}

impl Change {
    pub fn conflicted(&self) -> bool {
        matches!(
            (self.index, self.worktree),
            ('D', 'D')
                | ('A', 'U')
                | ('U', 'D')
                | ('U', 'A')
                | ('D', 'U')
                | ('A', 'A')
                | ('U', 'U')
        )
    }

    pub fn staged(&self) -> bool {
        !matches!(self.index, ' ' | '?' | '!')
    }

    pub fn unstaged(&self) -> bool {
        !matches!(self.worktree, ' ' | '!')
    }

    pub fn state(&self) -> FileState {
        if self.conflicted() {
            return FileState::Unmerged;
        }
        let code = if self.worktree != ' ' {
            self.worktree
        } else {
            self.index
        };
        match code {
            'A' => FileState::Added,
            'M' => FileState::Modified,
            'D' => FileState::Deleted,
            'R' => FileState::Renamed,
            'C' => FileState::Copied,
            'U' => FileState::Unmerged,
            '?' => FileState::Untracked,
            '!' => FileState::Ignored,
            _ => FileState::Other,
        }
    }
}

/// Parse `git status --porcelain=v1 -z`. Rename/copy records consume two NUL fields.
pub fn parse_porcelain(source: &[u8]) -> Vector<Change> {
    let fields = source.split(|byte| *byte == 0).collect::<Vector<_>>();
    let mut changes = Vector::new();
    let mut index = 0;
    while index < fields.len() {
        let field = fields[index];
        if field.len() < 4 {
            index += 1;
            continue;
        }
        let x = field[0] as char;
        let y = field[1] as char;
        let path = Text::from_utf8_lossy(&field[3..]);
        let rename = matches!(x, 'R' | 'C') || matches!(y, 'R' | 'C');
        let original_path = if rename && index + 1 < fields.len() && !fields[index + 1].is_empty() {
            index += 1;
            Some(Text::from_utf8_lossy(fields[index]))
        } else {
            None
        };
        changes.push(Change {
            index: x,
            worktree: y,
            path,
            original_path,
        });
        index += 1;
    }
    changes
}

pub fn validate_positional(values: &[Text]) -> core::result::Result<(), Text> {
    if let Some(value) = values.iter().find(|value| {
        value.starts_with('-') || value.chars().any(|character| character.is_control())
    }) {
        Err(mrml_runtime::mrml_format!(
            "option-like value '{}' is not allowed here",
            value
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_staged_unstaged_untracked_and_spaces() {
        let parsed = parse_porcelain(b"M  src/lib.rs\0 M notes with spaces.md\0?? new.txt\0");
        assert_eq!(parsed.len(), 3);
        assert!(parsed[0].staged());
        assert!(!parsed[0].unstaged());
        assert!(!parsed[1].staged());
        assert!(parsed[1].unstaged());
        assert_eq!(parsed[1].path, "notes with spaces.md");
        assert_eq!(parsed[2].state(), FileState::Untracked);
    }

    #[test]
    fn consumes_rename_pair_without_phantom_change() {
        let parsed = parse_porcelain(b"R  new name.rs\0old name.rs\0 M next.rs\0");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].path, "new name.rs");
        assert_eq!(parsed[0].original_path.as_deref(), Some("old name.rs"));
        assert_eq!(parsed[1].path, "next.rs");
    }

    #[test]
    fn recognizes_every_porcelain_v1_conflict_pair() {
        for pair in ["DD", "AU", "UD", "UA", "DU", "AA", "UU"] {
            let record = mrml_runtime::mrml_format!("{} conflict.rs\0", pair);
            let parsed = parse_porcelain(record.as_bytes());
            assert_eq!(parsed[0].state(), FileState::Unmerged, "pair {pair}");
            assert!(parsed[0].conflicted());
        }
    }

    #[test]
    fn cli_parses_repository_before_command() {
        let cli = Cli::parse(["mrml-git", "-C", "other repo", "diff", "--staged"]).unwrap();
        assert_eq!(cli.repository.as_deref(), Some("other repo"));
        assert_eq!(cli.command, "diff");
        assert_eq!(cli.arguments[0], "--staged");
    }

    #[test]
    fn cli_rejects_missing_repository_path() {
        assert_eq!(
            Cli::parse(["mrml-git", "--repo"]).unwrap_err(),
            "-C/--repo requires a path"
        );
    }

    #[test]
    fn positional_validation_blocks_option_injection() {
        assert!(validate_positional(&Vector::from([Text::from("origin")])).is_ok());
        assert!(validate_positional(&Vector::from([Text::from("--force")])).is_err());
        assert!(validate_positional(&Vector::from([Text::from("key\ncommand")])).is_err());
    }
}
