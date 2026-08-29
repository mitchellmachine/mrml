use core::array;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rights(u16);

impl Rights {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);
    pub const MAP: Self = Self(1 << 3);
    pub const SIGNAL: Self = Self(1 << 4);
    pub const DELEGATE: Self = Self(1 << 5);
    pub const CONTROL: Self = Self(1 << 6);
    pub const FLUSH: Self = Self(1 << 7);
    pub const ALLOCATE: Self = Self(1 << 8);
    pub const SHARE: Self = Self(1 << 9);
    pub const PIN: Self = Self(1 << 10);
    pub const INSPECT: Self = Self(1 << 11);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, requested: Self) -> bool {
        self.0 & requested.0 == requested.0
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn from_bits(bits: u16) -> Result<Self, CapabilityError> {
        let known = Self::READ.0
            | Self::WRITE.0
            | Self::EXECUTE.0
            | Self::MAP.0
            | Self::SIGNAL.0
            | Self::DELEGATE.0
            | Self::CONTROL.0
            | Self::FLUSH.0
            | Self::ALLOCATE.0
            | Self::SHARE.0
            | Self::PIN.0
            | Self::INSPECT.0;
        if bits == 0 || bits & !known != 0 {
            return Err(CapabilityError::Invalid);
        }
        Ok(Self(bits))
    }

    const fn intersect(self, limit: Self) -> Self {
        Self(self.0 & limit.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capability {
    slot: u32,
    generation: u32,
}

impl Capability {
    pub const fn token(self) -> u64 {
        ((self.generation as u64) << 32) | self.slot as u64
    }

    /// Reconstructs an untrusted opaque handle received over a syscall or
    /// service boundary. This grants no authority; every use must still pass
    /// exact-generation lookup and rights checks in a [`CapabilitySpace`].
    pub const fn from_token(token: u64) -> Self {
        Self {
            slot: token as u32,
            generation: (token >> 32) as u32,
        }
    }
}

#[derive(Clone, Copy)]
struct Entry {
    generation: u32,
    object: ObjectId,
    rights: Rights,
    occupied: bool,
    retired: bool,
}

impl Entry {
    const EMPTY: Self = Self {
        generation: 1,
        object: ObjectId(0),
        rights: Rights::NONE,
        occupied: false,
        retired: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityError {
    SpaceFull,
    GenerationExhausted,
    Invalid,
    PermissionDenied,
    DelegationDenied,
}

/// A fixed-capacity capability space. Handles carry generations so a revoked
/// slot cannot be reused through a stale handle (the ABA problem).
pub struct CapabilitySpace<const N: usize> {
    entries: [Entry; N],
}

impl<const N: usize> CapabilitySpace<N> {
    pub fn new() -> Self {
        Self {
            entries: array::from_fn(|_| Entry::EMPTY),
        }
    }

    pub fn insert(
        &mut self,
        object: ObjectId,
        rights: Rights,
    ) -> Result<Capability, CapabilityError> {
        let slot = self
            .entries
            .iter()
            .position(|entry| !entry.occupied && !entry.retired)
            .ok_or_else(|| {
                if self.entries.iter().any(|entry| entry.retired) {
                    CapabilityError::GenerationExhausted
                } else {
                    CapabilityError::SpaceFull
                }
            })?;
        let entry = &mut self.entries[slot];
        entry.object = object;
        entry.rights = rights;
        entry.occupied = true;
        Ok(Capability {
            slot: slot as u32,
            generation: entry.generation,
        })
    }

    pub fn authorize(
        &self,
        capability: Capability,
        requested: Rights,
    ) -> Result<ObjectId, CapabilityError> {
        let entry = self.entry(capability)?;
        entry
            .rights
            .contains(requested)
            .then_some(entry.object)
            .ok_or(CapabilityError::PermissionDenied)
    }

    pub fn authorize_exact(
        &self,
        capability: Capability,
        required: Rights,
    ) -> Result<ObjectId, CapabilityError> {
        Rights::from_bits(required.bits())?;
        let entry = self.entry(capability)?;
        if entry.rights != required {
            return Err(CapabilityError::PermissionDenied);
        }
        Ok(entry.object)
    }

    pub(crate) fn describe(
        &self,
        capability: Capability,
    ) -> Result<(ObjectId, Rights), CapabilityError> {
        let entry = self.entry(capability)?;
        Ok((entry.object, entry.rights))
    }

    /// Low-level attenuation primitive for kernel-owned delegation machinery.
    ///
    /// This is deliberately crate-private: cross-domain callers must use the
    /// tracked `TaskRuntime` IPC path so parent/child ancestry is recorded and
    /// transitive revocation cannot be bypassed.
    #[cfg(test)]
    pub(crate) fn derive<const M: usize>(
        &self,
        capability: Capability,
        requested: Rights,
        destination: &mut CapabilitySpace<M>,
    ) -> Result<Capability, CapabilityError> {
        let source = self.entry(capability)?;
        if !source.rights.contains(Rights::DELEGATE) {
            return Err(CapabilityError::DelegationDenied);
        }
        if !source.rights.contains(requested) {
            return Err(CapabilityError::PermissionDenied);
        }
        destination.insert(source.object, source.rights.intersect(requested))
    }

    /// Validates a complete bounded derivation set before publishing any
    /// destination authority.
    pub(crate) fn derive_batch<const M: usize>(
        &self,
        requested: &[(Capability, Rights)],
        destination: &mut CapabilitySpace<M>,
        output: &mut [Option<Capability>],
    ) -> Result<(), CapabilityError> {
        if requested.len() > output.len() || output.iter().any(Option::is_some) {
            return Err(CapabilityError::Invalid);
        }
        for (capability, rights) in requested.iter().copied() {
            let source = self.entry(capability)?;
            if !source.rights.contains(Rights::DELEGATE) {
                return Err(CapabilityError::DelegationDenied);
            }
            if !source.rights.contains(rights) {
                return Err(CapabilityError::PermissionDenied);
            }
        }
        let available = destination
            .entries
            .iter()
            .filter(|entry| !entry.occupied && !entry.retired)
            .count();
        if available < requested.len() {
            return Err(if destination.entries.iter().any(|entry| entry.retired) {
                CapabilityError::GenerationExhausted
            } else {
                CapabilityError::SpaceFull
            });
        }
        for (output, (capability, rights)) in output.iter_mut().zip(requested.iter().copied()) {
            let source = self
                .entry(capability)
                .expect("batch sources remain immutably borrowed");
            let slot = destination
                .entries
                .iter()
                .position(|entry| !entry.occupied && !entry.retired)
                .expect("batch destination capacity was preflighted");
            let entry = &mut destination.entries[slot];
            entry.object = source.object;
            entry.rights = source.rights.intersect(rights);
            entry.occupied = true;
            *output = Some(Capability {
                slot: slot as u32,
                generation: entry.generation,
            });
        }
        Ok(())
    }

    pub fn revoke(&mut self, capability: Capability) -> Result<(), CapabilityError> {
        let entry = self
            .entries
            .get_mut(capability.slot as usize)
            .filter(|entry| entry.occupied && entry.generation == capability.generation)
            .ok_or(CapabilityError::Invalid)?;
        // Clear every authority-bearing field before advancing or retiring the
        // generation. Revocation remains an atomic success; a later allocation
        // reports typed exhaustion because the slot can never be reused.
        entry.occupied = false;
        entry.object = ObjectId(0);
        entry.rights = Rights::NONE;
        match entry.generation.checked_add(1) {
            Some(next) => {
                entry.generation = next;
                Ok(())
            }
            None => {
                entry.retired = true;
                Ok(())
            }
        }
    }

    fn entry(&self, capability: Capability) -> Result<&Entry, CapabilityError> {
        self.entries
            .get(capability.slot as usize)
            .filter(|entry| entry.occupied && entry.generation == capability.generation)
            .ok_or(CapabilityError::Invalid)
    }
}

impl<const N: usize> Default for CapabilitySpace<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_attenuate_and_revoked_handles_never_revalidate() {
        let mut source = CapabilitySpace::<2>::new();
        let rights = Rights::READ
            .union(Rights::WRITE)
            .union(Rights::FLUSH)
            .union(Rights::DELEGATE);
        let root = source.insert(ObjectId(7), rights).unwrap();
        let mut child = CapabilitySpace::<2>::new();
        let read = source.derive(root, Rights::READ, &mut child).unwrap();
        assert_eq!(child.authorize(read, Rights::READ), Ok(ObjectId(7)));
        assert_eq!(child.authorize_exact(read, Rights::READ), Ok(ObjectId(7)));
        assert_eq!(
            child.authorize(read, Rights::WRITE),
            Err(CapabilityError::PermissionDenied)
        );
        assert_eq!(
            child.authorize(read, Rights::FLUSH),
            Err(CapabilityError::PermissionDenied)
        );
        assert_eq!(
            source.authorize_exact(root, Rights::READ),
            Err(CapabilityError::PermissionDenied)
        );
        assert_eq!(
            child.authorize_exact(read, Rights::NONE),
            Err(CapabilityError::Invalid)
        );
        child.revoke(read).unwrap();
        let replacement = child.insert(ObjectId(8), Rights::READ).unwrap();
        assert_ne!(read, replacement);
        assert_eq!(
            child.authorize(read, Rights::READ),
            Err(CapabilityError::Invalid)
        );
    }

    #[test]
    fn zero_and_stale_generations_are_rejected_across_ordinary_reuse() {
        let mut space = CapabilitySpace::<1>::new();
        let first = space.insert(ObjectId(1), Rights::READ).unwrap();
        assert_eq!(first.generation, 1);
        assert_eq!(
            space.authorize(Capability::from_token(0), Rights::READ),
            Err(CapabilityError::Invalid)
        );
        space.revoke(first).unwrap();
        let second = space.insert(ObjectId(2), Rights::READ).unwrap();
        assert_eq!(second.generation, 2);
        assert_eq!(
            space.authorize(first, Rights::READ),
            Err(CapabilityError::Invalid)
        );
        assert_eq!(space.authorize(second, Rights::READ), Ok(ObjectId(2)));
    }

    #[test]
    fn terminal_generation_is_revoked_and_permanently_retired() {
        let mut space = CapabilitySpace::<1>::new();
        space.entries[0].generation = u32::MAX - 1;

        let penultimate = space.insert(ObjectId(7), Rights::CONTROL).unwrap();
        assert_eq!(penultimate.generation, u32::MAX - 1);
        space.revoke(penultimate).unwrap();
        let terminal = space.insert(ObjectId(8), Rights::CONTROL).unwrap();
        assert_eq!(terminal.generation, u32::MAX);
        space.revoke(terminal).unwrap();
        assert_eq!(space.entries[0].object, ObjectId(0));
        assert_eq!(space.entries[0].rights, Rights::NONE);
        assert!(!space.entries[0].occupied);
        assert!(space.entries[0].retired);
        assert_eq!(
            space.authorize(terminal, Rights::CONTROL),
            Err(CapabilityError::Invalid)
        );
        assert_eq!(
            space.insert(ObjectId(9), Rights::CONTROL),
            Err(CapabilityError::GenerationExhausted)
        );
    }

    #[test]
    fn retired_slots_are_skipped_until_no_allocatable_slot_remains() {
        let mut space = CapabilitySpace::<2>::new();
        space.entries[0].generation = u32::MAX;
        let terminal = space.insert(ObjectId(10), Rights::READ).unwrap();
        space.revoke(terminal).unwrap();

        let live = space.insert(ObjectId(11), Rights::READ).unwrap();
        assert_eq!(live.slot, 1);
        assert_eq!(
            space.insert(ObjectId(12), Rights::READ),
            Err(CapabilityError::GenerationExhausted)
        );
        space.revoke(live).unwrap();
        let replacement = space.insert(ObjectId(13), Rights::READ).unwrap();
        assert_eq!(replacement.slot, 1);
        assert_eq!(replacement.generation, 2);
    }

    #[test]
    fn generation_one_capability_never_revives_after_terminal_reuse() {
        let mut space = CapabilitySpace::<1>::new();
        let generation_one = space.insert(ObjectId(21), Rights::READ).unwrap();
        space.revoke(generation_one).unwrap();

        // Focused exhaustion injection avoids billions of otherwise identical
        // revoke/reinsert cycles while exercising the real terminal path.
        space.entries[0].generation = u32::MAX;
        let terminal = space.insert(ObjectId(22), Rights::READ).unwrap();
        space.revoke(terminal).unwrap();
        assert_eq!(
            space.authorize(generation_one, Rights::READ),
            Err(CapabilityError::Invalid)
        );
        assert_eq!(
            space.insert(ObjectId(23), Rights::READ),
            Err(CapabilityError::GenerationExhausted)
        );
    }

    #[test]
    fn stateful_adversarial_sequences_preserve_attenuation_and_stale_handle_rejection() {
        const OPERATIONS: usize = 20_000;
        let rights = [
            Rights::READ,
            Rights::WRITE,
            Rights::READ.union(Rights::DELEGATE),
            Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE),
        ];
        let mut source = CapabilitySpace::<8>::new();
        let mut child = CapabilitySpace::<8>::new();
        let mut live = [None; 16];
        let mut stale = [None; 16];
        let mut next_stale = 0_usize;
        let mut state = 0x4d52_4d4c_cafe_babe_u64;

        for operation in 0..OPERATIONS {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let index = state as usize % live.len();
            match (state >> 8) & 3 {
                0 => {
                    let object = ObjectId((operation as u64).wrapping_add(1));
                    let granted = rights[(state >> 16) as usize % rights.len()];
                    if let Ok(handle) = source.insert(object, granted) {
                        assert_eq!(source.authorize_exact(handle, granted), Ok(object));
                        let slot = live
                            .iter()
                            .position(Option::is_none)
                            .expect("every live capability must have a model slot");
                        live[slot] = Some((handle, object, granted));
                    }
                }
                1 => {
                    if let Some((handle, object, granted)) = live[index] {
                        assert_eq!(source.authorize_exact(handle, granted), Ok(object));
                        for requested in rights {
                            let result = source.authorize(handle, requested);
                            assert_eq!(result.is_ok(), granted.contains(requested));
                        }
                    }
                }
                2 => {
                    if let Some((handle, object, granted)) = live[index] {
                        let requested = Rights::READ;
                        match source.derive(handle, requested, &mut child) {
                            Ok(derived) => {
                                assert!(granted.contains(Rights::DELEGATE));
                                assert!(granted.contains(requested));
                                assert_eq!(child.authorize_exact(derived, requested), Ok(object));
                                child.revoke(derived).unwrap();
                                assert_eq!(
                                    child.authorize(derived, requested),
                                    Err(CapabilityError::Invalid)
                                );
                            }
                            Err(CapabilityError::DelegationDenied) => {
                                assert!(!granted.contains(Rights::DELEGATE));
                            }
                            Err(CapabilityError::SpaceFull) => {}
                            Err(other) => panic!("unexpected derive result: {other:?}"),
                        }
                    }
                }
                _ => {
                    if let Some((handle, _, granted)) = live[index].take() {
                        source.revoke(handle).unwrap();
                        assert_eq!(
                            source.authorize(handle, granted),
                            Err(CapabilityError::Invalid)
                        );
                        let stale_slot = next_stale % stale.len();
                        stale[stale_slot] = Some((handle, granted));
                        next_stale += 1;
                    }
                }
            }
            for (handle, granted) in stale.iter().flatten().copied() {
                assert_eq!(
                    source.authorize(handle, granted),
                    Err(CapabilityError::Invalid)
                );
            }
        }
    }
}
