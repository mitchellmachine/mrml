//! Canonical single-record active ref state for atomic multi-ref activation.

use mrml_crypto::Sha256;
use mrml_runtime::Vector;

use crate::{
    FullRefName, GitdCoreError, ObjectFormat, ObjectId, PackGeneration, RepositoryGeneration,
    PackSetManifest, RepositoryIdentity, RevocationGeneration, TrustGeneration,
    VerifiedRefTransaction,
};

const MAGIC: &[u8; 8] = b"MRREFS02";
const DIGEST_BYTES: usize = 32;
pub const MAX_ACTIVE_REF_STATE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ACTIVE_REFS: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveRefState {
    pub repository: RepositoryIdentity,
    pub repository_generation: RepositoryGeneration,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    pub pack_generation: PackGeneration,
    pub pack_set_digest: [u8; 32],
    pub object_format: ObjectFormat,
    pub default_branch: FullRefName,
    pub refs: Vector<(FullRefName, ObjectId)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveRefStateError {
    Resource,
    Malformed,
    Integrity,
    Stale,
    Policy,
}

pub fn encode_active_ref_state(state: &ActiveRefState) -> Result<Vector<u8>, ActiveRefStateError> {
    validate_state(state)?;
    let mut output = Vector::new();
    append(&mut output, MAGIC)?;
    append_text(&mut output, state.repository.as_str())?;
    append_u64(&mut output, state.repository_generation.0)?;
    append_u64(&mut output, state.trust_generation.0)?;
    append_u64(&mut output, state.revocation_generation.0)?;
    append_u64(&mut output, state.pack_generation.0)?;
    append(&mut output, &state.pack_set_digest)?;
    append(
        &mut output,
        &[match state.object_format {
            ObjectFormat::Sha1 => 1,
            ObjectFormat::Sha256 => 2,
        }],
    )?;
    append_text(&mut output, state.default_branch.as_str())?;
    append_u32(&mut output, state.refs.len())?;
    for (name, id) in &state.refs {
        append_text(&mut output, name.as_str())?;
        append(&mut output, id.as_bytes())?;
    }
    if output
        .len()
        .checked_add(DIGEST_BYTES)
        .ok_or(ActiveRefStateError::Resource)?
        > MAX_ACTIVE_REF_STATE_BYTES
    {
        return Err(ActiveRefStateError::Resource);
    }
    let digest = Sha256::digest(&output);
    append(&mut output, &digest)?;
    Ok(output)
}

pub fn parse_active_ref_state(input: &[u8]) -> Result<ActiveRefState, ActiveRefStateError> {
    if input.len() < MAGIC.len() + DIGEST_BYTES || input.len() > MAX_ACTIVE_REF_STATE_BYTES {
        return Err(ActiveRefStateError::Malformed);
    }
    let body_len = input.len() - DIGEST_BYTES;
    if Sha256::digest(&input[..body_len]) != input[body_len..] {
        return Err(ActiveRefStateError::Integrity);
    }
    let mut cursor = Cursor::new(&input[..body_len]);
    if cursor.take(MAGIC.len())? != MAGIC {
        return Err(ActiveRefStateError::Malformed);
    }
    let repository = RepositoryIdentity::parse(cursor.text()?).map_err(map_identifier)?;
    let repository_generation = RepositoryGeneration(cursor.nonzero_u64()?);
    let trust_generation = TrustGeneration(cursor.nonzero_u64()?);
    let revocation_generation = RevocationGeneration(cursor.nonzero_u64()?);
    let pack_generation = PackGeneration(cursor.nonzero_u64()?);
    let mut pack_set_digest = [0; 32];
    pack_set_digest.copy_from_slice(cursor.take(32)?);
    let object_format = match cursor.u8()? {
        1 => ObjectFormat::Sha1,
        2 => ObjectFormat::Sha256,
        _ => return Err(ActiveRefStateError::Malformed),
    };
    let default_branch = FullRefName::parse(cursor.text()?).map_err(map_identifier)?;
    let count = usize::try_from(cursor.u32()?).map_err(|_| ActiveRefStateError::Resource)?;
    if count == 0 || count > MAX_ACTIVE_REFS {
        return Err(ActiveRefStateError::Malformed);
    }
    let mut refs = Vector::new();
    refs.try_reserve_exact(count)
        .map_err(|_| ActiveRefStateError::Resource)?;
    for _ in 0..count {
        let name = FullRefName::parse(cursor.text()?).map_err(map_identifier)?;
        let id = ObjectId::from_bytes(object_format, cursor.take(object_format.hash_len())?)
            .ok_or(ActiveRefStateError::Malformed)?;
        if id == ObjectId::zero(object_format) {
            return Err(ActiveRefStateError::Malformed);
        }
        refs.push((name, id));
    }
    if !cursor.is_empty() {
        return Err(ActiveRefStateError::Malformed);
    }
    let state = ActiveRefState {
        repository,
        repository_generation,
        trust_generation,
        revocation_generation,
        pack_generation,
        pack_set_digest,
        object_format,
        default_branch,
        refs,
    };
    validate_state(&state)?;
    Ok(state)
}

pub fn apply_verified_ref_transaction(
    current: &ActiveRefState,
    verified: &VerifiedRefTransaction,
) -> Result<ActiveRefState, ActiveRefStateError> {
    validate_state(current)?;
    if &current.repository != verified.repository()
        || current.repository_generation != verified.repository_generation()
        || current.trust_generation != verified.trust_generation()
        || current.revocation_generation != verified.revocation_generation()
    {
        return Err(ActiveRefStateError::Stale);
    }
    let mut refs = current.refs.clone();
    for update in verified.updates() {
        let old = update.expected_old().ok_or(ActiveRefStateError::Policy)?;
        let new = update.proposed_new().ok_or(ActiveRefStateError::Policy)?;
        if old.format() != current.object_format || new.format() != current.object_format {
            return Err(ActiveRefStateError::Policy);
        }
        let entry = refs
            .iter_mut()
            .find(|(name, _)| name == update.name())
            .ok_or(ActiveRefStateError::Stale)?;
        if entry.1 != old {
            return Err(ActiveRefStateError::Stale);
        }
        entry.1 = new;
    }
    refs.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let repository_generation = RepositoryGeneration(
        current
            .repository_generation
            .0
            .checked_add(1)
            .ok_or(ActiveRefStateError::Resource)?,
    );
    let next = ActiveRefState {
        repository: current.repository.clone(),
        repository_generation,
        trust_generation: current.trust_generation,
        revocation_generation: current.revocation_generation,
        pack_generation: current.pack_generation,
        pack_set_digest: current.pack_set_digest,
        object_format: current.object_format,
        default_branch: current.default_branch.clone(),
        refs,
    };
    validate_state(&next)?;
    Ok(next)
}

/// Applies one verified ref transaction while atomically selecting the exact
/// canonical pack set that contains the newly introduced objects. Possession
/// of a manifest is insufficient: every authority dimension and both next
/// generations must match exactly.
pub fn apply_verified_ref_transaction_with_pack_set(
    current: &ActiveRefState,
    verified: &VerifiedRefTransaction,
    manifest: &PackSetManifest,
) -> Result<ActiveRefState, ActiveRefStateError> {
    let mut next = apply_verified_ref_transaction(current, verified)?;
    if manifest.repository() != &current.repository
        || manifest.object_format() != current.object_format
        || manifest.repository_generation() != next.repository_generation
        || manifest.pack_generation().0
            != current
                .pack_generation
                .0
                .checked_add(1)
                .ok_or(ActiveRefStateError::Resource)?
    {
        return Err(ActiveRefStateError::Stale);
    }
    next.pack_generation = manifest.pack_generation();
    next.pack_set_digest = manifest
        .digest()
        .map_err(|_| ActiveRefStateError::Policy)?;
    validate_state(&next)?;
    Ok(next)
}

/// Selects a replacement pack set without changing ref, trust, or revocation
/// authority. Both generations advance exactly once so stale readers and
/// concurrent pushes fail closed.
#[allow(dead_code)] // invoked by ActiveRefFile's internal compaction path
pub(crate) fn apply_compaction_pack_set(
    current: &ActiveRefState,
    manifest: &PackSetManifest,
) -> Result<ActiveRefState, ActiveRefStateError> {
    let next_repository_generation = RepositoryGeneration(
        current
            .repository_generation
            .0
            .checked_add(1)
            .ok_or(ActiveRefStateError::Resource)?,
    );
    let next_pack_generation = PackGeneration(
        current
            .pack_generation
            .0
            .checked_add(1)
            .ok_or(ActiveRefStateError::Resource)?,
    );
    if manifest.repository() != &current.repository
        || manifest.object_format() != current.object_format
        || manifest.repository_generation() != next_repository_generation
        || manifest.pack_generation() != next_pack_generation
    {
        return Err(ActiveRefStateError::Stale);
    }
    let mut next = current.clone();
    next.repository_generation = next_repository_generation;
    next.pack_generation = next_pack_generation;
    next.pack_set_digest = manifest
        .digest()
        .map_err(|_| ActiveRefStateError::Policy)?;
    validate_state(&next)?;
    Ok(next)
}

fn validate_state(state: &ActiveRefState) -> Result<(), ActiveRefStateError> {
    if state.repository_generation.0 == 0
        || state.trust_generation.0 == 0
        || state.revocation_generation.0 == 0
        || state.pack_generation.0 == 0
        || state.pack_set_digest == [0; 32]
        || state.refs.is_empty()
        || state.refs.len() > MAX_ACTIVE_REFS
        || !state
            .refs
            .iter()
            .any(|(name, _)| name == &state.default_branch)
    {
        return Err(ActiveRefStateError::Policy);
    }
    for (index, (name, id)) in state.refs.iter().enumerate() {
        if id.format() != state.object_format
            || *id == ObjectId::zero(state.object_format)
            || index > 0 && state.refs[index - 1].0.as_str() >= name.as_str()
        {
            return Err(ActiveRefStateError::Policy);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack_set::{AuthenticatedPackIndexSummary, build_pack_set_manifest};
    use crate::{
        CandidateRefTransaction, CandidateRefUpdate, HistoryVerificationLimits, PackSetLimits,
        QuarantineTransactionId, build_verified_fast_forward_transaction,
        verify_introduced_history,
    };

    fn fixture() -> (ActiveRefState, VerifiedRefTransaction, ObjectId) {
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        let old = ObjectId::Sha256([1u8; 32]);
        let new = ObjectId::Sha256([2u8; 32]);
        let range = verify_introduced_history(
            old,
            new,
            HistoryVerificationLimits::default(),
            |id| {
                Ok(if id == new {
                    [old].into()
                } else {
                    Vector::new()
                })
            },
            |_| Ok(()),
        )
        .unwrap();
        let verified = build_verified_fast_forward_transaction(
            CandidateRefTransaction {
                repository: repository.clone(),
                repository_generation: RepositoryGeneration(7),
                trust_generation: TrustGeneration(8),
                revocation_generation: RevocationGeneration(9),
                updates: [CandidateRefUpdate {
                    name: FullRefName::parse("refs/heads/main").unwrap(),
                    expected_old: Some(old),
                    proposed_new: Some(new),
                }]
                .into(),
            },
            &[range],
        )
        .unwrap();
        let state = ActiveRefState {
            repository,
            repository_generation: RepositoryGeneration(7),
            trust_generation: TrustGeneration(8),
            revocation_generation: RevocationGeneration(9),
            pack_generation: PackGeneration(3),
            pack_set_digest: [5; 32],
            object_format: ObjectFormat::Sha256,
            default_branch: FullRefName::parse("refs/heads/main").unwrap(),
            refs: [
                (FullRefName::parse("refs/heads/main").unwrap(), old),
                (
                    FullRefName::parse("refs/tags/v1").unwrap(),
                    ObjectId::Sha256([4u8; 32]),
                ),
            ]
            .into(),
        };
        (state, verified, new)
    }

    #[test]
    fn canonical_ref_state_round_trips_and_rejects_integrity_or_order_changes() {
        let (state, _, _) = fixture();
        let encoded = encode_active_ref_state(&state).unwrap();
        assert_eq!(parse_active_ref_state(&encoded), Ok(state.clone()));
        assert_eq!(encode_active_ref_state(&state).unwrap(), encoded);
        let mut tampered = encoded.clone();
        tampered[12] ^= 1;
        assert_eq!(
            parse_active_ref_state(&tampered),
            Err(ActiveRefStateError::Integrity)
        );
        let mut unordered = state;
        unordered.refs.swap(0, 1);
        assert_eq!(
            encode_active_ref_state(&unordered),
            Err(ActiveRefStateError::Policy)
        );
    }

    #[test]
    fn verified_activation_is_exact_and_advances_one_repository_generation() {
        let (state, verified, new) = fixture();
        let next = apply_verified_ref_transaction(&state, &verified).unwrap();
        assert_eq!(next.repository_generation, RepositoryGeneration(8));
        assert_eq!(next.refs[0].1, new);
        assert_eq!(next.pack_generation, state.pack_generation);

        let mut stale = state.clone();
        stale.refs[0].1 = ObjectId::Sha256([6u8; 32]);
        assert_eq!(
            apply_verified_ref_transaction(&stale, &verified),
            Err(ActiveRefStateError::Stale)
        );
        let mut stale = state;
        stale.trust_generation = TrustGeneration(99);
        assert_eq!(
            apply_verified_ref_transaction(&stale, &verified),
            Err(ActiveRefStateError::Stale)
        );
    }

    #[test]
    fn pack_set_activation_advances_both_generations_and_binds_digest() {
        let (state, verified, new) = fixture();
        let manifest = build_pack_set_manifest(
            state.repository.clone(),
            RepositoryGeneration(8),
            PackGeneration(4),
            state.object_format,
            [AuthenticatedPackIndexSummary {
                transaction: QuarantineTransactionId([1; 16]),
                object_count: 1,
                pack_checksum: ObjectId::Sha256([2; 32]),
                index_checksum: ObjectId::Sha256([3; 32]),
                pack_bytes: 64,
                index_bytes: 64,
                work_units: 1,
                object_ids: [new].into(),
            }]
            .into(),
            PackSetLimits {
                max_packs: 1,
                max_objects: 1,
                max_pack_bytes: 64,
                max_index_bytes: 64,
                max_work_units: 1,
            },
        )
        .unwrap();
        let next = apply_verified_ref_transaction_with_pack_set(&state, &verified, &manifest)
            .unwrap();
        assert_eq!(next.repository_generation, RepositoryGeneration(8));
        assert_eq!(next.pack_generation, PackGeneration(4));
        assert_eq!(next.pack_set_digest, manifest.digest().unwrap());

        let stale_manifest = build_pack_set_manifest(
            state.repository.clone(),
            RepositoryGeneration(8),
            PackGeneration(5),
            state.object_format,
            [AuthenticatedPackIndexSummary {
                transaction: QuarantineTransactionId([1; 16]),
                object_count: 1,
                pack_checksum: ObjectId::Sha256([2; 32]),
                index_checksum: ObjectId::Sha256([3; 32]),
                pack_bytes: 64,
                index_bytes: 64,
                work_units: 1,
                object_ids: [new].into(),
            }]
            .into(),
            PackSetLimits {
                max_packs: 1,
                max_objects: 1,
                max_pack_bytes: 64,
                max_index_bytes: 64,
                max_work_units: 1,
            },
        )
        .unwrap();
        assert_eq!(
            apply_verified_ref_transaction_with_pack_set(&state, &verified, &stale_manifest),
            Err(ActiveRefStateError::Stale)
        );
    }
}

fn append(output: &mut Vector<u8>, bytes: &[u8]) -> Result<(), ActiveRefStateError> {
    if output
        .len()
        .checked_add(bytes.len())
        .ok_or(ActiveRefStateError::Resource)?
        > MAX_ACTIVE_REF_STATE_BYTES
    {
        return Err(ActiveRefStateError::Resource);
    }
    output
        .try_extend_from_slice(bytes)
        .map_err(|_| ActiveRefStateError::Resource)
}
fn append_text(output: &mut Vector<u8>, value: &str) -> Result<(), ActiveRefStateError> {
    let length = u16::try_from(value.len()).map_err(|_| ActiveRefStateError::Resource)?;
    append(output, &length.to_be_bytes())?;
    append(output, value.as_bytes())
}
fn append_u64(output: &mut Vector<u8>, value: u64) -> Result<(), ActiveRefStateError> {
    append(output, &value.to_be_bytes())
}
fn append_u32(output: &mut Vector<u8>, value: usize) -> Result<(), ActiveRefStateError> {
    append(
        output,
        &u32::try_from(value)
            .map_err(|_| ActiveRefStateError::Resource)?
            .to_be_bytes(),
    )
}
fn map_identifier(_: GitdCoreError) -> ActiveRefStateError {
    ActiveRefStateError::Malformed
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], ActiveRefStateError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(ActiveRefStateError::Malformed)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ActiveRefStateError::Malformed)?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, ActiveRefStateError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ActiveRefStateError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| ActiveRefStateError::Malformed)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, ActiveRefStateError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ActiveRefStateError::Malformed)?,
        ))
    }
    fn nonzero_u64(&mut self) -> Result<u64, ActiveRefStateError> {
        let value = u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ActiveRefStateError::Malformed)?,
        );
        if value == 0 {
            Err(ActiveRefStateError::Malformed)
        } else {
            Ok(value)
        }
    }
    fn text(&mut self) -> Result<&'a str, ActiveRefStateError> {
        let length = usize::from(self.u16()?);
        core::str::from_utf8(self.take(length)?).map_err(|_| ActiveRefStateError::Malformed)
    }
    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
