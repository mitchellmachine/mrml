//! Bounded verification of every commit introduced by a ref update.
//!
//! A verifier must never validate only the proposed tip.  This walker excludes
//! commits already reachable from the authenticated old tip, then visits every
//! newly introduced parent (including merge-side ancestry) before its child.

use mrml_runtime::Vector;

use crate::{
    ObjectFormat, ObjectId, RepositoryGeneration, RepositoryIdentity, RevocationGeneration,
    SignaturePurpose, TrustGeneration,
};

pub const DEFAULT_MAX_INTRODUCED_COMMITS: u32 = 5_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryVerificationLimits {
    pub max_existing_commits: u32,
    pub max_introduced_commits: u32,
    pub max_parents_per_commit: u16,
}

impl Default for HistoryVerificationLimits {
    fn default() -> Self {
        Self {
            max_existing_commits: 1_000_000,
            max_introduced_commits: DEFAULT_MAX_INTRODUCED_COMMITS,
            max_parents_per_commit: 64,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryVerificationError {
    MissingCommit,
    ObjectFormatMismatch,
    Cycle,
    NotFastForward,
    Signature,
    Resource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedHistoryContext<'a> {
    pub repository: &'a RepositoryIdentity,
    pub repository_generation: RepositoryGeneration,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
    pub purpose: SignaturePurpose,
    pub object_format: ObjectFormat,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCommitProof {
    pub(crate) commit: ObjectId,
    pub(crate) repository: RepositoryIdentity,
    pub(crate) repository_generation: RepositoryGeneration,
    pub(crate) trust_generation: TrustGeneration,
    pub(crate) revocation_generation: RevocationGeneration,
    pub(crate) purpose: SignaturePurpose,
    pub(crate) object_format: ObjectFormat,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCommitRange {
    old: ObjectId,
    new: ObjectId,
    introduced: Vector<ObjectId>,
    repository: Option<RepositoryIdentity>,
    repository_generation: RepositoryGeneration,
    trust_generation: TrustGeneration,
    revocation_generation: RevocationGeneration,
    purpose: SignaturePurpose,
    object_format: ObjectFormat,
}

impl VerifiedCommitRange {
    pub const fn old(&self) -> ObjectId {
        self.old
    }

    pub const fn new(&self) -> ObjectId {
        self.new
    }

    /// Deterministic parent-before-child verification order.
    pub fn introduced(&self) -> &[ObjectId] {
        &self.introduced
    }

    pub(crate) fn matches_context(&self, context: &ProtectedHistoryContext<'_>) -> bool {
        #[cfg(test)]
        if self.repository.is_none() {
            return true;
        }
        self.repository.as_ref() == Some(context.repository)
            && self.repository_generation == context.repository_generation
            && self.trust_generation == context.trust_generation
            && self.revocation_generation == context.revocation_generation
            && self.purpose == context.purpose
            && self.object_format == context.object_format
    }
}

#[derive(Clone, Debug)]
struct Frame {
    id: ObjectId,
    parents: Vector<ObjectId>,
    next_parent: usize,
}

pub fn verify_protected_introduced_history<R, V>(
    context: ProtectedHistoryContext<'_>,
    old: ObjectId,
    new: ObjectId,
    limits: HistoryVerificationLimits,
    read_parents: R,
    mut verify_commit: V,
) -> Result<VerifiedCommitRange, HistoryVerificationError>
where
    R: FnMut(ObjectId) -> Result<Vector<ObjectId>, HistoryVerificationError>,
    V: FnMut(ObjectId) -> Result<VerifiedCommitProof, HistoryVerificationError>,
{
    if context.repository_generation.0 == 0
        || context.trust_generation.0 == 0
        || context.revocation_generation.0 == 0
        || context.purpose != SignaturePurpose::GitCommit
        || old.format() != context.object_format
        || new.format() != context.object_format
    {
        return Err(HistoryVerificationError::Signature);
    }
    let mut range = verify_introduced_history(old, new, limits, read_parents, |id| {
        let proof = verify_commit(id)?;
        if proof.commit != id
            || proof.repository != *context.repository
            || proof.repository_generation != context.repository_generation
            || proof.trust_generation != context.trust_generation
            || proof.revocation_generation != context.revocation_generation
            || proof.purpose != context.purpose
            || proof.object_format != context.object_format
        {
            return Err(HistoryVerificationError::Signature);
        }
        Ok(())
    })?;
    range.repository = Some(context.repository.clone());
    range.repository_generation = context.repository_generation;
    range.trust_generation = context.trust_generation;
    range.revocation_generation = context.revocation_generation;
    range.purpose = context.purpose;
    range.object_format = context.object_format;
    Ok(range)
}

pub(crate) fn verify_introduced_history<R, V>(
    old: ObjectId,
    new: ObjectId,
    limits: HistoryVerificationLimits,
    mut read_parents: R,
    mut verify_commit: V,
) -> Result<VerifiedCommitRange, HistoryVerificationError>
where
    R: FnMut(ObjectId) -> Result<Vector<ObjectId>, HistoryVerificationError>,
    V: FnMut(ObjectId) -> Result<(), HistoryVerificationError>,
{
    if old.format() != new.format() {
        return Err(HistoryVerificationError::ObjectFormatMismatch);
    }
    if limits.max_existing_commits == 0
        || limits.max_introduced_commits == 0
        || limits.max_parents_per_commit == 0
    {
        return Err(HistoryVerificationError::Resource);
    }

    let mut old_reachable = Vector::new();
    collect_reachable(
        old,
        limits.max_existing_commits,
        limits.max_parents_per_commit,
        &mut read_parents,
        &mut old_reachable,
    )?;

    let mut verified = Vector::new();
    let mut visiting = Vector::new();
    let mut stack = Vector::new();
    push_frame(
        new,
        limits.max_parents_per_commit,
        &mut read_parents,
        &mut visiting,
        &mut stack,
    )?;
    let mut reached_old_history = old == new;
    while let Some(frame) = stack.last_mut() {
        if old_reachable.contains(&frame.id) {
            reached_old_history |= frame.id == old;
            let id = frame.id;
            stack.pop();
            remove_id(&mut visiting, id);
            continue;
        }
        if frame.next_parent < frame.parents.len() {
            let parent = frame.parents[frame.next_parent];
            frame.next_parent += 1;
            if parent.format() != new.format() {
                return Err(HistoryVerificationError::ObjectFormatMismatch);
            }
            if old_reachable.contains(&parent) {
                reached_old_history |= parent == old;
            } else if visiting.contains(&parent) {
                return Err(HistoryVerificationError::Cycle);
            } else if !verified.contains(&parent) {
                push_frame(
                    parent,
                    limits.max_parents_per_commit,
                    &mut read_parents,
                    &mut visiting,
                    &mut stack,
                )?;
            }
            continue;
        }

        let id = frame.id;
        verify_commit(id).map_err(|_| HistoryVerificationError::Signature)?;
        if verified.len() >= limits.max_introduced_commits as usize {
            return Err(HistoryVerificationError::Resource);
        }
        verified.push(id);
        stack.pop();
        remove_id(&mut visiting, id);
    }
    if !reached_old_history {
        return Err(HistoryVerificationError::NotFastForward);
    }
    Ok(VerifiedCommitRange {
        old,
        new,
        introduced: verified,
        repository: None,
        repository_generation: RepositoryGeneration(0),
        trust_generation: TrustGeneration(0),
        revocation_generation: RevocationGeneration(0),
        purpose: SignaturePurpose::GitCommit,
        object_format: new.format(),
    })
}

fn collect_reachable<R>(
    root: ObjectId,
    maximum: u32,
    max_parents: u16,
    read_parents: &mut R,
    output: &mut Vector<ObjectId>,
) -> Result<(), HistoryVerificationError>
where
    R: FnMut(ObjectId) -> Result<Vector<ObjectId>, HistoryVerificationError>,
{
    let mut pending = Vector::from([root]);
    while let Some(id) = pending.pop() {
        if output.contains(&id) {
            continue;
        }
        if output.len() >= maximum as usize {
            return Err(HistoryVerificationError::Resource);
        }
        let parents = read_parents(id)?;
        if parents.len() > max_parents as usize {
            return Err(HistoryVerificationError::Resource);
        }
        if parents
            .iter()
            .any(|parent| parent.format() != root.format())
        {
            return Err(HistoryVerificationError::ObjectFormatMismatch);
        }
        output.push(id);
        pending.extend(parents);
    }
    Ok(())
}

fn push_frame<R>(
    id: ObjectId,
    max_parents: u16,
    read_parents: &mut R,
    visiting: &mut Vector<ObjectId>,
    stack: &mut Vector<Frame>,
) -> Result<(), HistoryVerificationError>
where
    R: FnMut(ObjectId) -> Result<Vector<ObjectId>, HistoryVerificationError>,
{
    let parents = read_parents(id)?;
    if parents.len() > max_parents as usize {
        return Err(HistoryVerificationError::Resource);
    }
    visiting.push(id);
    stack.push(Frame {
        id,
        parents,
        next_parent: 0,
    });
    Ok(())
}

fn remove_id(values: &mut Vector<ObjectId>, id: ObjectId) {
    if let Some(index) = values.iter().position(|value| *value == id) {
        values.remove(index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u8) -> ObjectId {
        ObjectId::Sha1([value; 20])
    }

    fn graph(node: ObjectId) -> Result<Vector<ObjectId>, HistoryVerificationError> {
        Ok(match node.as_bytes()[0] {
            1 => Vector::new(),
            2 => [id(1)].into(),
            3 => [id(2)].into(),
            4 => [id(2)].into(),
            5 => [id(3), id(4)].into(),
            _ => return Err(HistoryVerificationError::MissingCommit),
        })
    }

    fn repository() -> RepositoryIdentity {
        RepositoryIdentity::parse("owner/protected").unwrap()
    }

    fn proof(
        commit: ObjectId,
        repository: &RepositoryIdentity,
        repository_generation: u64,
        trust_generation: u64,
        revocation_generation: u64,
        purpose: SignaturePurpose,
        object_format: ObjectFormat,
    ) -> VerifiedCommitProof {
        VerifiedCommitProof {
            commit,
            repository: repository.clone(),
            repository_generation: RepositoryGeneration(repository_generation),
            trust_generation: TrustGeneration(trust_generation),
            revocation_generation: RevocationGeneration(revocation_generation),
            purpose,
            object_format,
        }
    }

    fn context(repository: &RepositoryIdentity) -> ProtectedHistoryContext<'_> {
        ProtectedHistoryContext {
            repository,
            repository_generation: RepositoryGeneration(7),
            trust_generation: TrustGeneration(8),
            revocation_generation: RevocationGeneration(9),
            purpose: SignaturePurpose::GitCommit,
            object_format: ObjectFormat::Sha1,
        }
    }

    #[test]
    fn unsigned_intermediate_and_merge_side_invalid_proof_fail_closed() {
        let repository = repository();
        for rejected in [id(3), id(4)] {
            assert_eq!(
                verify_protected_introduced_history(
                    context(&repository),
                    id(2),
                    id(5),
                    HistoryVerificationLimits::default(),
                    graph,
                    |commit| if commit == rejected {
                        Err(HistoryVerificationError::Signature)
                    } else {
                        Ok(proof(
                            commit,
                            &repository,
                            7,
                            8,
                            9,
                            SignaturePurpose::GitCommit,
                            ObjectFormat::Sha1,
                        ))
                    },
                ),
                Err(HistoryVerificationError::Signature)
            );
        }
    }

    #[test]
    fn proof_must_match_id_and_every_authority_dimension() {
        let repository = repository();
        let other = RepositoryIdentity::parse("owner/other").unwrap();
        let variants = [
            proof(
                id(99),
                &repository,
                7,
                8,
                9,
                SignaturePurpose::GitCommit,
                ObjectFormat::Sha1,
            ),
            proof(
                id(3),
                &other,
                7,
                8,
                9,
                SignaturePurpose::GitCommit,
                ObjectFormat::Sha1,
            ),
            proof(
                id(3),
                &repository,
                6,
                8,
                9,
                SignaturePurpose::GitCommit,
                ObjectFormat::Sha1,
            ),
            proof(
                id(3),
                &repository,
                7,
                6,
                9,
                SignaturePurpose::GitCommit,
                ObjectFormat::Sha1,
            ),
            proof(
                id(3),
                &repository,
                7,
                8,
                6,
                SignaturePurpose::GitCommit,
                ObjectFormat::Sha1,
            ),
            proof(
                id(3),
                &repository,
                7,
                8,
                9,
                SignaturePurpose::BuildReceipt,
                ObjectFormat::Sha1,
            ),
            proof(
                id(3),
                &repository,
                7,
                8,
                9,
                SignaturePurpose::GitCommit,
                ObjectFormat::Sha256,
            ),
        ];
        for invalid in variants {
            assert_eq!(
                verify_protected_introduced_history(
                    context(&repository),
                    id(2),
                    id(3),
                    HistoryVerificationLimits::default(),
                    graph,
                    |commit| Ok(if commit == id(3) {
                        invalid.clone()
                    } else {
                        proof(
                            commit,
                            &repository,
                            7,
                            8,
                            9,
                            SignaturePurpose::GitCommit,
                            ObjectFormat::Sha1,
                        )
                    }),
                ),
                Err(HistoryVerificationError::Signature)
            );
        }
    }

    #[test]
    fn verifies_merge_side_ancestry_parent_before_child() {
        let mut order = Vector::new();
        let range = verify_introduced_history(
            id(2),
            id(5),
            HistoryVerificationLimits::default(),
            graph,
            |commit| {
                order.push(commit);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(&*range.introduced, &[id(3), id(4), id(5)]);
        assert_eq!(order, range.introduced);
    }

    #[test]
    fn invalid_intermediate_and_non_fast_forward_fail_closed() {
        assert_eq!(
            verify_introduced_history(
                id(2),
                id(5),
                HistoryVerificationLimits::default(),
                graph,
                |commit| if commit == id(4) {
                    Err(HistoryVerificationError::Signature)
                } else {
                    Ok(())
                },
            ),
            Err(HistoryVerificationError::Signature)
        );
        assert_eq!(
            verify_introduced_history(
                id(3),
                id(4),
                HistoryVerificationLimits::default(),
                graph,
                |_| Ok(()),
            ),
            Err(HistoryVerificationError::NotFastForward)
        );
    }

    #[test]
    fn cycles_and_limits_are_rejected() {
        let cycle = |node: ObjectId| {
            Ok(match node.as_bytes()[0] {
                1 => Vector::new(),
                6 => [id(7)].into(),
                7 => [id(6)].into(),
                _ => return Err(HistoryVerificationError::MissingCommit),
            })
        };
        assert_eq!(
            verify_introduced_history(
                id(1),
                id(6),
                HistoryVerificationLimits::default(),
                cycle,
                |_| Ok(()),
            ),
            Err(HistoryVerificationError::Cycle)
        );
        assert_eq!(
            verify_introduced_history(
                id(2),
                id(5),
                HistoryVerificationLimits {
                    max_introduced_commits: 2,
                    ..HistoryVerificationLimits::default()
                },
                graph,
                |_| Ok(()),
            ),
            Err(HistoryVerificationError::Resource)
        );
    }

    #[test]
    fn required_linear_range_scales_execute_at_exact_limits() {
        fn linear_id(value: u32) -> ObjectId {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&value.to_be_bytes());
            ObjectId::Sha256(bytes)
        }
        for count in [1u32, 100, 1_000, 5_000] {
            let range = verify_introduced_history(
                linear_id(0),
                linear_id(count),
                HistoryVerificationLimits::default(),
                |node| {
                    let value = u32::from_be_bytes(node.as_bytes()[..4].try_into().unwrap());
                    Ok(if value == 0 {
                        Vector::new()
                    } else {
                        [linear_id(value - 1)].into()
                    })
                },
                |_| Ok(()),
            )
            .unwrap();
            assert_eq!(range.introduced().len(), count as usize);
            assert_eq!(range.introduced().first(), Some(&linear_id(1)));
            assert_eq!(range.introduced().last(), Some(&linear_id(count)));
        }
        assert_eq!(
            verify_introduced_history(
                linear_id(0),
                linear_id(5_001),
                HistoryVerificationLimits::default(),
                |node| {
                    let value = u32::from_be_bytes(node.as_bytes()[..4].try_into().unwrap());
                    Ok(if value == 0 {
                        Vector::new()
                    } else {
                        [linear_id(value - 1)].into()
                    })
                },
                |_| Ok(()),
            ),
            Err(HistoryVerificationError::Resource)
        );
    }
}
