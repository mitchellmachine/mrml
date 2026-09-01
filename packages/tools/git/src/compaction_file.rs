//! Durable composition of verified compaction with existing pack/ref stores.

use mrml_crypto::Sha256;

use crate::pack_set::build_pack_set_manifest;
use crate::{
    ActiveRefFile, ActiveRefState, ArrivalPackStore, CompactionResult, DurableFailure,
    ObjectFormat, PackSetLimits, QuarantineTransactionId, RepositoryGeneration,
};

#[allow(dead_code)] // internal compositor; not a public filesystem authority
pub(crate) struct LinuxCompactionStore {
    arrivals: ArrivalPackStore,
    refs: ActiveRefFile,
    format: ObjectFormat,
}

#[allow(dead_code)] // service scheduling is a later integration boundary
impl LinuxCompactionStore {
    pub(crate) fn open(
        arrivals_root: &str,
        refs_root: &str,
        format: ObjectFormat,
        max_pack_bytes: u64,
    ) -> Result<Self, DurableFailure> {
        Ok(Self {
            arrivals: ArrivalPackStore::open(arrivals_root, format, max_pack_bytes)?,
            refs: ActiveRefFile::open(refs_root).map_err(|_| DurableFailure::VerifierCrash)?,
            format,
        })
    }

    /// Installs an immutable replacement arrival before selecting its manifest.
    /// Existing arrivals are deliberately retained; retirement is a later,
    /// separately recoverable operation and never occurs on the push path.
    pub(crate) fn compact(
        &self,
        result: &CompactionResult,
        limits: PackSetLimits,
    ) -> Result<ActiveRefState, DurableFailure> {
        let current = self
            .refs
            .load()
            .map_err(|_| DurableFailure::VerifierCrash)?;
        if current.object_format != self.format
            || current.repository_generation != result.selected.repository_generation
            || current.pack_generation != result.selected.pack_generation
            || result.replacement_pack_generation.0
                != current
                    .pack_generation
                    .0
                    .checked_add(1)
                    .ok_or(DurableFailure::DiskFull)?
        {
            return Err(DurableFailure::StaleLock);
        }
        let transaction = compaction_transaction_id(
            current.repository.as_str(),
            result,
            Sha256::digest(&result.pack),
        );
        let staged = self.arrivals.stage_compacted_pack(
            transaction,
            &result.pack,
            &result.retained_object_ids,
        )?;
        self.arrivals.install(transaction, staged.object_count)?;
        let installed = self
            .arrivals
            .authenticated_installed_summary(transaction, staged.object_count)?;
        if installed != staged {
            return Err(DurableFailure::VerifierCrash);
        }
        let next_repository_generation = RepositoryGeneration(
            current
                .repository_generation
                .0
                .checked_add(1)
                .ok_or(DurableFailure::DiskFull)?,
        );
        let manifest = build_pack_set_manifest(
            current.repository.clone(),
            next_repository_generation,
            result.replacement_pack_generation,
            self.format,
            [installed].into(),
            limits,
        )
        .map_err(|_| DurableFailure::VerifierCrash)?;
        self.refs.activate_compaction(&manifest)
    }
}

fn compaction_transaction_id(
    repository: &str,
    result: &CompactionResult,
    pack_digest: [u8; 32],
) -> QuarantineTransactionId {
    let mut hash = Sha256::new();
    hash.update(b"mrml.gitd.compaction.arrival.v1\0");
    hash.update(&(repository.len() as u64).to_be_bytes());
    hash.update(repository.as_bytes());
    hash.update(&result.selected.repository_generation.0.to_be_bytes());
    hash.update(&result.selected.pack_generation.0.to_be_bytes());
    hash.update(&result.replacement_pack_generation.0.to_be_bytes());
    hash.update(&pack_digest);
    let digest = hash.finalize();
    let mut transaction = [0; 16];
    transaction.copy_from_slice(&digest[..16]);
    QuarantineTransactionId(transaction)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{
        ActiveRefState, CompactionSnapshot, FullRefName, ObjectKind, PackGeneration, PackObject,
        RepositoryIdentity, RevocationGeneration, TrustGeneration, encode_loose_object_with_format,
        encode_pack_with_format,
    };
    use mrml_runtime::{Text, Vector, join_path, path_exists};

    fn root(label: &str) -> Text {
        join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-compaction-{}-{}", label, mrml_runtime::process_id()),
        )
    }

    fn object(contents: &[u8]) -> PackObject {
        let (id, _) =
            encode_loose_object_with_format(ObjectFormat::Sha256, ObjectKind::Blob, contents);
        PackObject {
            id,
            kind: ObjectKind::Blob,
            contents: contents.iter().copied().collect(),
        }
    }

    fn manifest_name(digest: [u8; 32]) -> Text {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = Text::from("pack-set-");
        for byte in digest {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 15)]));
        }
        name.push_str(".manifest");
        name
    }

    fn fixture(
        label: &str,
    ) -> (
        Text,
        Text,
        LinuxCompactionStore,
        ActiveRefState,
        QuarantineTransactionId,
    ) {
        let root = root(label);
        let _ = mrml_runtime::remove_dir_all(&root);
        mrml_runtime::create_dir_all(&root).unwrap();
        let arrivals_root = join_path(&root, "packs");
        let refs_root = join_path(&root, "refs");
        let arrivals =
            ArrivalPackStore::open(&arrivals_root, ObjectFormat::Sha256, 1024 * 1024).unwrap();
        let old = object(b"old reachable");
        let old_pack = encode_pack_with_format(&[old.clone()], ObjectFormat::Sha256).unwrap();
        let old_transaction = QuarantineTransactionId([7; 16]);
        let summary = arrivals
            .stage_compacted_pack(old_transaction, &old_pack, &[old.id])
            .unwrap();
        arrivals
            .install(old_transaction, summary.object_count)
            .unwrap();
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let manifest = build_pack_set_manifest(
            repository.clone(),
            RepositoryGeneration(1),
            PackGeneration(1),
            ObjectFormat::Sha256,
            [summary].into(),
            PackSetLimits {
                max_packs: 1,
                max_objects: 1,
                max_pack_bytes: 1024 * 1024,
                max_index_bytes: 1024 * 1024,
                max_work_units: 1024 * 1024,
            },
        )
        .unwrap();
        let state = ActiveRefState {
            repository,
            repository_generation: RepositoryGeneration(1),
            trust_generation: TrustGeneration(2),
            revocation_generation: RevocationGeneration(3),
            pack_generation: PackGeneration(1),
            pack_set_digest: manifest.digest().unwrap(),
            object_format: ObjectFormat::Sha256,
            default_branch: FullRefName::parse("refs/heads/main").unwrap(),
            refs: [(FullRefName::parse("refs/heads/main").unwrap(), old.id)].into(),
        };
        ActiveRefFile::initialize_with_pack_set(&refs_root, &state, &manifest).unwrap();
        let store = LinuxCompactionStore::open(
            &arrivals_root,
            &refs_root,
            ObjectFormat::Sha256,
            1024 * 1024,
        )
        .unwrap();
        (root, refs_root, store, state, old_transaction)
    }

    fn limits() -> PackSetLimits {
        PackSetLimits {
            max_packs: 1,
            max_objects: 4,
            max_pack_bytes: 1024 * 1024,
            max_index_bytes: 1024 * 1024,
            max_work_units: 1024 * 1024,
        }
    }

    #[test]
    fn transaction_identity_binds_repository_generations_and_pack() {
        let (id, _) = encode_loose_object_with_format(ObjectFormat::Sha256, ObjectKind::Blob, b"a");
        let object = PackObject {
            id,
            kind: ObjectKind::Blob,
            contents: Vector::from(*b"a"),
        };
        let result = CompactionResult {
            selected: CompactionSnapshot {
                repository_generation: RepositoryGeneration(7),
                pack_generation: PackGeneration(3),
            },
            replacement_pack_generation: PackGeneration(4),
            retained_object_ids: [id].into(),
            pack: encode_pack_with_format(&[object], ObjectFormat::Sha256).unwrap(),
        };
        let digest = Sha256::digest(&result.pack);
        let first = compaction_transaction_id("owner/repo", &result, digest);
        assert_eq!(
            first,
            compaction_transaction_id("owner/repo", &result, digest)
        );
        assert_ne!(
            first,
            compaction_transaction_id("owner/other", &result, digest)
        );
        let mut later = result.clone();
        later.selected.pack_generation = PackGeneration(4);
        assert_ne!(
            first,
            compaction_transaction_id("owner/repo", &later, digest)
        );
    }

    #[test]
    fn preactivation_failure_preserves_active_state() {
        let (root, _, store, original, _) = fixture("failure");
        let replacement = object(b"replacement");
        let result = CompactionResult {
            selected: CompactionSnapshot {
                repository_generation: original.repository_generation,
                pack_generation: original.pack_generation,
            },
            replacement_pack_generation: PackGeneration(2),
            retained_object_ids: [replacement.id].into(),
            pack: encode_pack_with_format(&[replacement], ObjectFormat::Sha256).unwrap(),
        };
        let mut stale = result.clone();
        stale.selected.repository_generation = RepositoryGeneration(99);
        assert_eq!(
            store.compact(&stale, limits()),
            Err(DurableFailure::StaleLock)
        );
        assert_eq!(store.refs.load().unwrap(), original);
        let mut rejecting = limits();
        rejecting.max_packs = 0;
        assert_eq!(
            store.compact(&result, rejecting),
            Err(DurableFailure::VerifierCrash)
        );
        assert_eq!(store.refs.load().unwrap(), original);
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn activation_reopens_exact_state_and_retains_old_pack_and_manifest() {
        let (root, refs_root, store, original, old_transaction) = fixture("success");
        let old_manifest_path = join_path(&refs_root, &manifest_name(original.pack_set_digest));
        let replacement = object(b"replacement");
        let replacement_id = replacement.id;
        let result = CompactionResult {
            selected: CompactionSnapshot {
                repository_generation: original.repository_generation,
                pack_generation: original.pack_generation,
            },
            replacement_pack_generation: PackGeneration(2),
            retained_object_ids: [replacement_id].into(),
            pack: encode_pack_with_format(&[replacement], ObjectFormat::Sha256).unwrap(),
        };
        let next = store.compact(&result, limits()).unwrap();
        assert_eq!(next.repository_generation, RepositoryGeneration(2));
        assert_eq!(next.pack_generation, PackGeneration(2));
        assert_eq!(next.refs, original.refs);
        assert_eq!(next.trust_generation, original.trust_generation);
        assert_eq!(next.revocation_generation, original.revocation_generation);
        assert_eq!(store.refs.load().unwrap(), next);
        let selected = store.refs.load_selected_pack_set(limits()).unwrap();
        assert_eq!(selected.entries().len(), 1);
        assert_eq!(selected.entries()[0].object_ids(), &[replacement_id]);
        assert_eq!(
            store
                .arrivals
                .read_selected_object(&selected, replacement_id, 1024)
                .unwrap()
                .contents,
            b"replacement"[..]
        );
        store.arrivals.verify_installed(old_transaction, 1).unwrap();
        assert!(path_exists(&old_manifest_path));
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
