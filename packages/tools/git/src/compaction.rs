//! Generation-bound, deterministic reachability compaction planning.
//!
//! This module does not perform filesystem I/O.  It makes the state transitions
//! and recovery decisions required of a durable integration explicit; callers
//! remain responsible for writing, syncing, atomically activating, and later
//! removing the represented files.

use mrml_runtime::Vector;

use crate::{
    ObjectFormat, ObjectId, PackError, PackGeneration, PackObject, RepositoryGeneration,
    encode_pack_with_format, parse_pack_with_format,
};

pub const COMPACTION_WORKERS: u8 = 2;
pub const COMPACTION_MEMORY_LIMIT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const COMPACTION_FREE_RESERVE_BYTES: u64 = 40 * 1024 * 1024 * 1024;
pub const COMPACTION_DEFLATE_LEVEL: u8 = 9;
pub const COMPACTION_DELTA_WINDOW: u16 = 250;
pub const COMPACTION_MAX_DELTA_DEPTH: u8 = 50;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionProfile {
    pub workers: u8,
    pub memory_limit_bytes: u64,
    pub free_reserve_bytes: u64,
    pub deflate_level: u8,
    pub delta_window: u16,
    pub max_delta_depth: u8,
}

impl CompactionProfile {
    pub const FIXED: Self = Self {
        workers: COMPACTION_WORKERS,
        memory_limit_bytes: COMPACTION_MEMORY_LIMIT_BYTES,
        free_reserve_bytes: COMPACTION_FREE_RESERVE_BYTES,
        deflate_level: COMPACTION_DEFLATE_LEVEL,
        delta_window: COMPACTION_DELTA_WINDOW,
        max_delta_depth: COMPACTION_MAX_DELTA_DEPTH,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionSnapshot {
    pub repository_generation: RepositoryGeneration,
    pub pack_generation: PackGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionResources {
    pub free_bytes: u64,
    pub estimated_output_bytes: u64,
    pub estimated_memory_bytes: u64,
    pub push_active: bool,
    pub core_pressure: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactionError {
    GenerationChanged,
    PushActive,
    CorePressure,
    FreeReserve,
    MemoryBudget,
    OutputEstimate,
    GenerationOverflow,
    DuplicateObject,
    MissingReachableObject,
    Pack(PackError),
    Verification,
    InvalidTransition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactionResult {
    pub selected: CompactionSnapshot,
    pub replacement_pack_generation: PackGeneration,
    pub retained_object_ids: Vector<ObjectId>,
    pub pack: Vector<u8>,
}

/// Creates one replacement pack from an exact repository/pack snapshot.
///
/// Reachable IDs and objects are sorted solely by complete object ID.  There is
/// no adaptive codec choice, similarity search, storage-location ranking, or
/// distributed mapping.  A caller must re-read `live` immediately before
/// activation and pass that exact value to [`CompactionJournal::activate`].
pub fn compact_reachable(
    selected: CompactionSnapshot,
    live: CompactionSnapshot,
    resources: CompactionResources,
    format: ObjectFormat,
    reachable: &[ObjectId],
    objects: &[PackObject],
) -> Result<CompactionResult, CompactionError> {
    if selected != live {
        return Err(CompactionError::GenerationChanged);
    }
    if resources.push_active {
        return Err(CompactionError::PushActive);
    }
    if resources.core_pressure {
        return Err(CompactionError::CorePressure);
    }
    if resources.estimated_memory_bytes > COMPACTION_MEMORY_LIMIT_BYTES {
        return Err(CompactionError::MemoryBudget);
    }
    if resources
        .free_bytes
        .checked_sub(resources.estimated_output_bytes)
        .is_none_or(|remaining| remaining < COMPACTION_FREE_RESERVE_BYTES)
    {
        return Err(CompactionError::FreeReserve);
    }

    let mut reachable: Vector<ObjectId> = reachable.iter().copied().collect();
    reachable.sort_unstable();
    if reachable.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CompactionError::DuplicateObject);
    }
    let mut ordered = Vector::new();
    ordered
        .try_reserve_exact(reachable.len())
        .map_err(|_| CompactionError::Pack(PackError::TooLarge))?;
    for id in &reachable {
        if id.format() != format {
            return Err(CompactionError::MissingReachableObject);
        }
        let object = objects
            .iter()
            .find(|object| object.id == *id)
            .ok_or(CompactionError::MissingReachableObject)?;
        ordered.push(object.clone());
    }
    let pack = encode_pack_with_format(&ordered, format).map_err(CompactionError::Pack)?;
    if pack.len() as u64 > resources.estimated_output_bytes {
        return Err(CompactionError::OutputEstimate);
    }
    let decoded = parse_pack_with_format(&pack, format).map_err(CompactionError::Pack)?;
    if decoded != ordered {
        return Err(CompactionError::Verification);
    }
    let replacement_pack_generation = PackGeneration(
        selected
            .pack_generation
            .0
            .checked_add(1)
            .ok_or(CompactionError::GenerationOverflow)?,
    );
    Ok(CompactionResult {
        selected,
        replacement_pack_generation,
        retained_object_ids: reachable,
        pack,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactionPhase {
    Planned,
    Staged,
    StageSynced,
    Activated,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrashOutcome {
    KeepSelectedGenerationDiscardStage,
    KeepSelectedGenerationRecoverSyncedStage,
    UseReplacementKeepOldFiles,
    UseReplacementRetireOldFiles,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionJournal {
    pub selected: CompactionSnapshot,
    pub replacement_pack_generation: PackGeneration,
    pub phase: CompactionPhase,
}

impl CompactionJournal {
    pub const fn new(result: &CompactionResult) -> Self {
        Self {
            selected: result.selected,
            replacement_pack_generation: result.replacement_pack_generation,
            phase: CompactionPhase::Planned,
        }
    }

    pub fn stage(&mut self) -> Result<(), CompactionError> {
        self.advance(CompactionPhase::Planned, CompactionPhase::Staged)
    }

    pub fn sync_stage(&mut self) -> Result<(), CompactionError> {
        self.advance(CompactionPhase::Staged, CompactionPhase::StageSynced)
    }

    pub fn activate(&mut self, live: CompactionSnapshot) -> Result<(), CompactionError> {
        if self.phase != CompactionPhase::StageSynced {
            return Err(CompactionError::InvalidTransition);
        }
        if live != self.selected {
            return Err(CompactionError::GenerationChanged);
        }
        self.phase = CompactionPhase::Activated;
        Ok(())
    }

    pub fn retire(&mut self) -> Result<(), CompactionError> {
        self.advance(CompactionPhase::Activated, CompactionPhase::Retired)
    }

    pub const fn crash_outcome(self) -> CrashOutcome {
        match self.phase {
            CompactionPhase::Planned | CompactionPhase::Staged => {
                CrashOutcome::KeepSelectedGenerationDiscardStage
            }
            CompactionPhase::StageSynced => CrashOutcome::KeepSelectedGenerationRecoverSyncedStage,
            CompactionPhase::Activated => CrashOutcome::UseReplacementKeepOldFiles,
            CompactionPhase::Retired => CrashOutcome::UseReplacementRetireOldFiles,
        }
    }

    fn advance(
        &mut self,
        expected: CompactionPhase,
        next: CompactionPhase,
    ) -> Result<(), CompactionError> {
        if self.phase != expected {
            return Err(CompactionError::InvalidTransition);
        }
        self.phase = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObjectKind, encode_loose_object_with_format};

    fn object(contents: &[u8]) -> PackObject {
        let (id, _) =
            encode_loose_object_with_format(ObjectFormat::Sha256, ObjectKind::Blob, contents);
        PackObject {
            id,
            kind: ObjectKind::Blob,
            contents: contents.iter().copied().collect(),
        }
    }

    fn resources() -> CompactionResources {
        CompactionResources {
            free_bytes: COMPACTION_FREE_RESERVE_BYTES + 4096,
            estimated_output_bytes: 4096,
            estimated_memory_bytes: 4096,
            push_active: false,
            core_pressure: false,
        }
    }

    #[test]
    fn compaction_is_reachable_generation_bound_and_deterministic() {
        assert_eq!(CompactionProfile::FIXED.workers, 2);
        assert_eq!(CompactionProfile::FIXED.deflate_level, 9);
        assert_eq!(CompactionProfile::FIXED.delta_window, 250);
        assert_eq!(CompactionProfile::FIXED.max_delta_depth, 50);
        let snapshot = CompactionSnapshot {
            repository_generation: RepositoryGeneration(7),
            pack_generation: PackGeneration(11),
        };
        let a = object(b"reachable a");
        let b = object(b"unreachable");
        let c = object(b"reachable c");
        let first = compact_reachable(
            snapshot,
            snapshot,
            resources(),
            ObjectFormat::Sha256,
            &[c.id, a.id],
            &[b.clone(), a.clone(), c.clone()],
        )
        .unwrap();
        let second = compact_reachable(
            snapshot,
            snapshot,
            resources(),
            ObjectFormat::Sha256,
            &[a.id, c.id],
            &[c, b, a],
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.replacement_pack_generation, PackGeneration(12));
        assert_eq!(
            parse_pack_with_format(&first.pack, ObjectFormat::Sha256)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn compaction_pauses_and_rejects_stale_activation() {
        let snapshot = CompactionSnapshot {
            repository_generation: RepositoryGeneration(7),
            pack_generation: PackGeneration(11),
        };
        let mut busy = resources();
        busy.push_active = true;
        assert_eq!(
            compact_reachable(snapshot, snapshot, busy, ObjectFormat::Sha256, &[], &[]),
            Err(CompactionError::PushActive)
        );
        let result = compact_reachable(
            snapshot,
            snapshot,
            resources(),
            ObjectFormat::Sha256,
            &[],
            &[],
        )
        .unwrap();
        let mut journal = CompactionJournal::new(&result);
        journal.stage().unwrap();
        assert_eq!(
            journal.crash_outcome(),
            CrashOutcome::KeepSelectedGenerationDiscardStage
        );
        journal.sync_stage().unwrap();
        assert_eq!(
            journal.crash_outcome(),
            CrashOutcome::KeepSelectedGenerationRecoverSyncedStage
        );
        let changed = CompactionSnapshot {
            repository_generation: RepositoryGeneration(8),
            pack_generation: PackGeneration(12),
        };
        assert_eq!(
            journal.activate(changed),
            Err(CompactionError::GenerationChanged)
        );
        journal.activate(snapshot).unwrap();
        assert_eq!(
            journal.crash_outcome(),
            CrashOutcome::UseReplacementKeepOldFiles
        );
        journal.retire().unwrap();
        assert_eq!(
            journal.crash_outcome(),
            CrashOutcome::UseReplacementRetireOldFiles
        );
    }

    #[test]
    fn compaction_enforces_reserve_and_exact_reachability() {
        let snapshot = CompactionSnapshot {
            repository_generation: RepositoryGeneration(1),
            pack_generation: PackGeneration(1),
        };
        let a = object(b"a");
        let mut low = resources();
        low.free_bytes -= 1;
        assert_eq!(
            compact_reachable(
                snapshot,
                snapshot,
                low,
                ObjectFormat::Sha256,
                &[a.id],
                &[a.clone()]
            ),
            Err(CompactionError::FreeReserve)
        );
        assert_eq!(
            compact_reachable(
                snapshot,
                snapshot,
                resources(),
                ObjectFormat::Sha256,
                &[a.id],
                &[]
            ),
            Err(CompactionError::MissingReachableObject)
        );
        assert_eq!(
            compact_reachable(
                snapshot,
                snapshot,
                resources(),
                ObjectFormat::Sha256,
                &[a.id, a.id],
                &[a]
            ),
            Err(CompactionError::DuplicateObject)
        );
        let mut excessive_memory = resources();
        excessive_memory.estimated_memory_bytes = COMPACTION_MEMORY_LIMIT_BYTES + 1;
        assert_eq!(
            compact_reachable(
                snapshot,
                snapshot,
                excessive_memory,
                ObjectFormat::Sha256,
                &[],
                &[]
            ),
            Err(CompactionError::MemoryBudget)
        );
        let mut underestimated = resources();
        underestimated.estimated_output_bytes = 0;
        underestimated.free_bytes = COMPACTION_FREE_RESERVE_BYTES;
        assert_eq!(
            compact_reachable(
                snapshot,
                snapshot,
                underestimated,
                ObjectFormat::Sha256,
                &[],
                &[]
            ),
            Err(CompactionError::OutputEstimate)
        );
    }
}
