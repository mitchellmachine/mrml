#![no_std]

use mrml_runtime::{Text, Vector};

#[cfg(test)]
mod adversarial;
mod arrival_pack;
mod audit_receipt;
mod authority_client;
mod authority_wire;
mod cache_pack;
mod cache_pack_file;
mod compaction;
mod compaction_file;
mod deflate;
mod detached_commit_proof;
mod detached_commit_proof_file;
mod diff;
mod gitd_core;
mod https_remote;
mod hybrid_signing;
mod index;
mod inflate;
mod local_repack;
mod object;
mod openpgp_provider;
mod pack;
mod pack_delta;
mod pack_file;
mod pack_index;
mod pack_set;
mod quarantine;
mod receive_backend;
mod receive_journal;
mod receive_journal_file;
mod receive_pack_core;
mod receive_store;
mod ref_state;
mod ref_state_file;
mod remote;
mod repository;
mod repository_view;
mod sha1;
mod signed_audit_receipt;
mod smart_protocol;
mod transport;
mod trust_policy;
mod trust_policy_file;
mod verification;

pub use arrival_pack::ArrivalPackStore;
pub use audit_receipt::{
    AuditReceiptDirectory, AuditReceiptError, MAX_AUDIT_RECEIPT_BYTES, encode_audit_receipt,
    parse_audit_receipt,
};
pub use authority_client::{
    AUTHORITY_OP_AUTHORIZE_RECEIVE, AUTHORITY_OP_AUTHORIZE_REF_TRANSACTION,
    AUTHORITY_OP_SIGN_RECEIPT, AUTHORITY_OP_VERIFY_COMMIT, AUTHORITY_OP_VERIFY_RECEIPT,
    ProtectedAuthorityRpc, RemoteProtectedReceiveAuthority,
};
pub use authority_wire::{
    AuthorityCommitRequest, AuthorityReceiptRequest, AuthorityRefTransactionRequest,
    MAX_AUTHORITY_COMMIT_BYTES, MAX_AUTHORITY_RECEIPT_TRANSCRIPT_BYTES, encode_authority_commit,
    encode_authority_receipt, encode_authority_receive, encode_authority_ref_transaction,
    parse_authority_commit, parse_authority_receipt, parse_authority_receive,
    parse_authority_ref_transaction,
};
pub use cache_pack::{
    ImmutablePackCache, MAX_CACHED_PACK_BYTES, MAX_PACK_CACHE_ENTRIES, MAX_PACK_CACHE_KEY_BYTES,
    MAX_PACK_CACHE_OBJECTS_PER_SIDE, PackCacheError, PackCacheKey,
};
pub use cache_pack_file::{ImmutablePackCacheDirectory, PackCacheFileError};
pub use compaction::{
    COMPACTION_DEFLATE_LEVEL, COMPACTION_DELTA_WINDOW, COMPACTION_FREE_RESERVE_BYTES,
    COMPACTION_MAX_DELTA_DEPTH, COMPACTION_MEMORY_LIMIT_BYTES, COMPACTION_WORKERS, CompactionError,
    CompactionJournal, CompactionPhase, CompactionProfile, CompactionResources, CompactionResult,
    CompactionSnapshot, CrashOutcome, compact_reachable,
};
pub use detached_commit_proof::{
    DetachedCommitProofRecord, DetachedCommitProofStore, DetachedHybridCommitVerifier,
    DurableDetachedHybridCommitVerifier, MAX_DETACHED_COMMIT_PROOFS,
};
pub use detached_commit_proof_file::{
    DetachedCommitProofFileError, DurableDetachedCommitProofDirectory,
};
pub use diff::FileDiff;
pub use gitd_core::{
    AnnotatedTagDetails, AnnotatedTagPage, BlobPage, BoundedRead, BoundedWrite,
    CandidateRefTransaction, CandidateRefUpdate, CommitDetails, CommitPage, FullRefName,
    GitdCoreBackend, GitdCoreError, ImmutablePackDescriptor, MAX_REFS_PER_TRANSACTION,
    PackGeneration, QueryLimits, ReadmeCandidate, RepositoryEvent, RepositoryEventCursor,
    RepositoryEventPage, RepositoryGeneration, RepositoryIdentity, RepositoryPath,
    RepositorySummary, RevocationGeneration, SignaturePurpose, SmartGitOperation, SmartGitRequest,
    SmartGitResponse, TreePage, TrustGeneration, VerificationSummary, VerifiedMetadataDescriptor,
    VerifiedRefTransaction, VerifiedRefUpdate, WorkBudget, build_verified_fast_forward_transaction,
};
pub use https_remote::{
    HttpsDiscovery, HttpsRefAdvertisement, HttpsRemote, HttpsRemoteError, HttpsTransport,
    SmartGitService,
};
pub use hybrid_signing::{sign_ml_dsa_65_git_payload, verify_ml_dsa_65_git_payload};
pub use index::{Index, IndexEntry, IndexError};
pub use local_repack::LocalRepackResult;
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
    PackError, PackObject, PackStreamEncoder, PackStreamOutput, encode_pack,
    encode_pack_with_format, parse_pack, parse_pack_with_format, parse_pack_with_index,
    write_pack_without_deltas,
};
pub use pack_index::{
    DEFAULT_MAX_PACK_INDEX_OBJECTS, PackIndex, PackIndexEntry, PackIndexError, build_pack_index_v2,
    parse_pack_index_v2,
};
pub use pack_set::{
    MAX_PACK_SET_MANIFEST_BYTES, PackSetEntry, PackSetError, PackSetLimits, PackSetManifest,
    encode_pack_set_manifest, parse_pack_set_manifest,
};
pub use quarantine::{
    ActivationSnapshot, AuditReceipt, DEFAULT_MAX_EXPANDED_OBJECT_BYTES,
    DEFAULT_MAX_INCOMING_PACK_BYTES, DEFAULT_MAX_INDIVIDUAL_OBJECT_BYTES,
    DEFAULT_MAX_OBJECTS_PER_PUSH, DEFAULT_MINIMUM_FREE_SPACE_BYTES, DurableFailure,
    DurableReceiveError, DurableReceiveStore, PushDiskReservation, PushStorageForecast,
    QuarantineError, QuarantineLimits, QuarantinePhase, QuarantineTransaction,
    QuarantineTransactionId, durably_activate_verified_receive, reserve_push_disk,
    reserve_push_disk_before_body,
};
pub use receive_backend::{
    PreparedProtectedReceive, ProtectedCommitVerifier, activate_prepared_protected_receive,
    finish_prepared_protected_receive, prepare_policy_classified_receive,
    prepare_protected_receive,
};
pub use receive_journal::{
    JournalRefUpdate, MAX_RECEIVE_JOURNAL_BYTES, ReceiveJournalError, ReceiveJournalRecord,
    RecoveryAction, classify_receive_recovery, encode_receive_journal, parse_receive_journal,
};
pub use receive_journal_file::ReceiveJournalDirectory;
pub use receive_pack_core::{
    ProtectedReceiveAuthority, ProtectedReceiveAuthorization, ReceivePackCore,
};
pub use receive_store::LinuxDurableReceiveStore;
pub use ref_state::{
    ActiveRefState, ActiveRefStateError, MAX_ACTIVE_REF_STATE_BYTES, MAX_ACTIVE_REFS,
    apply_verified_ref_transaction, apply_verified_ref_transaction_with_pack_set,
    encode_active_ref_state, parse_active_ref_state,
};
pub use ref_state_file::ActiveRefFile;
pub use remote::{
    FetchError, FetchResult, PushError, PushResult, RemoteInfo, check_ssh, fetch_ssh, inspect_ssh,
    push_ssh,
};
pub use repository::{
    BlameLine, GitSignatureFormat, MergeOutcome, NativeChange, NativeChangeKind, RebaseOutcome,
    Repository, RepositoryError,
};
pub use repository_view::{
    FilesystemRepositoryView, MAX_VERIFICATION_SUMMARY_EVIDENCE, VerificationSummaryEvidence,
    VerificationSummaryStore,
};
pub use sha1::{ObjectFormat, ObjectId, Sha1};
pub use signed_audit_receipt::{
    AuditReceiptAuthority, AuthenticatedAuditReceipt, AuthenticatedAuditReceiptDirectory,
    AuthenticatedReceiveStore, MAX_AUTHENTICATED_AUDIT_RECEIPT_BYTES,
};
pub use smart_protocol::{
    MAX_PKT_LINE_BYTES, MAX_V2_ARGUMENTS, MAX_V2_REF_PREFIXES, PktLine, ProtocolBudget,
    ProtocolV2Request, ReceivePackRequest, ReceiveRefStatus, read_pkt_line,
    read_receive_pack_commands, read_v2_request, write_pkt_line, write_receive_pack_report,
    write_v2_capability_advertisement,
};
pub use transport::{
    Advertisement, RemoteRef, TransportError, decode_packets, encode_flush, encode_packet,
    extract_pack_response, fetch_request, parse_advertisement, parse_push_response,
    parse_push_response_mode, push_request, push_request_mode, push_request_mode_negotiated,
};
pub use trust_policy::{
    AuthorizedHybridPair, EmergencyRecoveryAuthority, EmergencyRecoveryAuthorization,
    EmergencyRecoveryTransition, GitObjectType, HYBRID_PROFILE_NAME, HybridPolicyError,
    HybridTrustPolicy, HybridVerificationRequest, KeyRevocationStatement, LegacyV4KeyStatus,
    MAX_EMERGENCY_AUTHORITY_BYTES, MAX_EMERGENCY_TRANSITION_BYTES, MAX_ENCODED_TRUST_POLICY_BYTES,
    MAX_HYBRID_PAYLOAD_BYTES, MAX_KEY_REVOCATION_REASON_BYTES, MAX_KEY_REVOCATION_STATEMENT_BYTES,
    MAX_POLICY_LEGACY_V4_KEYS, MAX_POLICY_PAIRS, MAX_POLICY_PROTECTED_REFS,
    MAX_POLICY_REVOKED_KEYS, PolicyPairStatus, TrustPolicyCandidate, TrustPolicyState,
    VerifiedHybridSignature, authorize_emergency_recovery, bind_verified_commit_proof,
    bind_verified_git_object_proof, bind_verified_legacy_commit_proof, canonical_hybrid_transcript,
    encode_emergency_recovery_authority, encode_emergency_recovery_transition,
    encode_key_revocation_statement, encode_trust_policy, key_revocation_statement_digest,
    parse_emergency_recovery_authority, parse_emergency_recovery_transition,
    parse_key_revocation_statement, parse_trust_policy, verify_hybrid_signature,
};
pub use trust_policy_file::{LinuxDurableTrustPolicyStore, TrustPolicyFileError};
#[cfg(test)]
pub(crate) use verification::verify_introduced_history;
pub use verification::{
    DEFAULT_MAX_INTRODUCED_COMMITS, HistoryVerificationError, HistoryVerificationLimits,
    ProtectedHistoryContext, VerifiedCommitProof, VerifiedCommitRange, VerifiedGitObjectProof,
    VerifiedLegacyCommitProof, verify_policy_classified_history,
    verify_protected_introduced_history,
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
