use crate::{Superblock, VolumeHeader};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveredSuperblock {
    block: u64,
    superblock: Superblock,
    fallback: bool,
}

impl RecoveredSuperblock {
    pub const fn block(self) -> u64 {
        self.block
    }

    pub const fn superblock(self) -> Superblock {
        self.superblock
    }

    pub const fn used_fallback(self) -> bool {
        self.fallback
    }
}

/// Validates the complete metadata graph selected by a superblock candidate.
///
/// # Safety
///
/// An implementation must read only from the immutable device generation being
/// recovered and validate the candidate's complete reachable root and allocation
/// metadata, including all covered digests, identities, generations, bounds,
/// ownership, and cross-references. `Invalid` must mean the candidate was fully
/// examined and cannot be selected. Transient or indeterminate failures must be
/// returned as `Backend`, never downgraded to `Invalid` to permit silent rollback.
pub unsafe trait CowRecoveryValidator {
    type Error;

    fn validate_candidate(
        &mut self,
        block: u64,
        candidate: Superblock,
    ) -> Result<(), CandidateValidationError<Self::Error>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateValidationError<E> {
    Invalid,
    Backend(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError<E> {
    NoValidSuperblock,
    InconsistentSuperblocks,
    Backend(E),
}

pub fn recover_superblock<V: CowRecoveryValidator>(
    header: VolumeHeader,
    primary: &[u8],
    secondary: &[u8],
    validator: &mut V,
) -> Result<RecoveredSuperblock, RecoveryError<V::Error>> {
    let primary = decode_and_validate(header, header.primary_superblock(), primary, validator)?;
    let secondary =
        decode_and_validate(header, header.secondary_superblock(), secondary, validator)?;

    match (primary, secondary) {
        (None, None) => Err(RecoveryError::NoValidSuperblock),
        (Some(candidate), None) | (None, Some(candidate)) => Ok(RecoveredSuperblock {
            block: candidate.0,
            superblock: candidate.1,
            fallback: true,
        }),
        (Some(primary), Some(secondary)) => select_pair(primary, secondary),
    }
}

fn decode_and_validate<V: CowRecoveryValidator>(
    header: VolumeHeader,
    block: u64,
    encoded: &[u8],
    validator: &mut V,
) -> Result<Option<(u64, Superblock)>, RecoveryError<V::Error>> {
    let candidate = match Superblock::decode(encoded, header) {
        Ok(candidate) => candidate,
        Err(_error) => return Ok(None),
    };
    match validator.validate_candidate(block, candidate) {
        Ok(()) => Ok(Some((block, candidate))),
        Err(CandidateValidationError::Invalid) => Ok(None),
        Err(CandidateValidationError::Backend(error)) => Err(RecoveryError::Backend(error)),
    }
}

fn select_pair<E>(
    primary: (u64, Superblock),
    secondary: (u64, Superblock),
) -> Result<RecoveredSuperblock, RecoveryError<E>> {
    let primary_generation = primary.1.generation();
    let secondary_generation = secondary.1.generation();
    if primary_generation == secondary_generation {
        if primary.1 != secondary.1 {
            return Err(RecoveryError::InconsistentSuperblocks);
        }
        return Ok(RecoveredSuperblock {
            block: primary.0,
            superblock: primary.1,
            fallback: false,
        });
    }
    let (newer, older) = if primary_generation > secondary_generation {
        (primary, secondary)
    } else {
        (secondary, primary)
    };
    if older.1.generation().checked_add(1) != Some(newer.1.generation()) {
        return Err(RecoveryError::InconsistentSuperblocks);
    }
    Ok(RecoveredSuperblock {
        block: newer.0,
        superblock: newer.1,
        fallback: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MetadataPointer, SUPERBLOCK_BYTES, StorageObjectId, VolumeId};

    fn volume() -> VolumeId {
        VolumeId::new([7; 16]).unwrap()
    }

    fn header() -> VolumeHeader {
        VolumeHeader::new(volume(), 4096, 100, 1, 2).unwrap()
    }

    fn superblock(generation: u64, root_block: u64) -> Superblock {
        Superblock::new(
            header(),
            generation,
            generation - 1,
            StorageObjectId::new(volume(), 1).unwrap(),
            MetadataPointer::new(root_block, 1).unwrap(),
            MetadataPointer::new(root_block + 1, 1).unwrap(),
        )
        .unwrap()
    }

    fn encoded(candidate: Superblock) -> [u8; SUPERBLOCK_BYTES] {
        let mut encoded = [0; SUPERBLOCK_BYTES];
        candidate.encode(&mut encoded);
        encoded
    }

    struct Validator {
        invalid_generation: Option<u64>,
        calls: usize,
    }

    unsafe impl CowRecoveryValidator for Validator {
        type Error = ();

        fn validate_candidate(
            &mut self,
            _block: u64,
            candidate: Superblock,
        ) -> Result<(), CandidateValidationError<Self::Error>> {
            self.calls += 1;
            if self.invalid_generation == Some(candidate.generation()) {
                Err(CandidateValidationError::Invalid)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn selects_newest_adjacent_fully_valid_candidate() {
        let older = encoded(superblock(4, 10));
        let newer = encoded(superblock(5, 20));
        let mut validator = Validator {
            invalid_generation: None,
            calls: 0,
        };
        let recovered = recover_superblock(header(), &older, &newer, &mut validator).unwrap();
        assert_eq!(recovered.block(), 2);
        assert_eq!(recovered.superblock().generation(), 5);
        assert!(!recovered.used_fallback());
        assert_eq!(validator.calls, 2);
    }

    #[test]
    fn falls_back_only_after_candidate_is_proven_invalid() {
        let older = encoded(superblock(4, 10));
        let newer = encoded(superblock(5, 20));
        let mut validator = Validator {
            invalid_generation: Some(5),
            calls: 0,
        };
        let recovered = recover_superblock(header(), &older, &newer, &mut validator).unwrap();
        assert_eq!(recovered.superblock().generation(), 4);
        assert!(recovered.used_fallback());
    }

    #[test]
    fn rejects_corruption_and_inconsistent_valid_lineage() {
        let older = encoded(superblock(4, 10));
        let mut corrupt = encoded(superblock(5, 20));
        corrupt[48] ^= 1;
        let mut validator = Validator {
            invalid_generation: Some(4),
            calls: 0,
        };
        assert_eq!(
            recover_superblock(header(), &older, &corrupt, &mut validator),
            Err(RecoveryError::NoValidSuperblock)
        );

        let newer_with_gap = encoded(superblock(7, 20));
        let mut validator = Validator {
            invalid_generation: None,
            calls: 0,
        };
        assert_eq!(
            recover_superblock(header(), &older, &newer_with_gap, &mut validator),
            Err(RecoveryError::InconsistentSuperblocks)
        );

        let same_generation_different_root = encoded(superblock(4, 30));
        assert_eq!(
            recover_superblock(
                header(),
                &older,
                &same_generation_different_root,
                &mut validator,
            ),
            Err(RecoveryError::InconsistentSuperblocks)
        );
    }

    #[test]
    fn identical_same_generation_initial_roots_are_accepted_deterministically() {
        let candidate = encoded(superblock(1, 10));
        let mut validator = Validator {
            invalid_generation: None,
            calls: 0,
        };
        let recovered =
            recover_superblock(header(), &candidate, &candidate, &mut validator).unwrap();
        assert_eq!(recovered.block(), header().primary_superblock());
        assert_eq!(recovered.superblock().generation(), 1);
        assert!(!recovered.used_fallback());
    }

    #[test]
    fn backend_uncertainty_never_becomes_rollback() {
        struct Uncertain;
        unsafe impl CowRecoveryValidator for Uncertain {
            type Error = u8;

            fn validate_candidate(
                &mut self,
                _block: u64,
                _candidate: Superblock,
            ) -> Result<(), CandidateValidationError<Self::Error>> {
                Err(CandidateValidationError::Backend(9))
            }
        }

        assert_eq!(
            recover_superblock(
                header(),
                &encoded(superblock(4, 10)),
                &encoded(superblock(5, 20)),
                &mut Uncertain,
            ),
            Err(RecoveryError::Backend(9))
        );
    }
}
