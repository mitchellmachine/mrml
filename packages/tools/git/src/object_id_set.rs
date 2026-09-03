//! Bounded exact object-ID membership with amortized constant-time operations.

use mrml_runtime::Vector;

use crate::ObjectId;

#[derive(Debug)]
pub(crate) struct ObjectIdSet {
    slots: Vector<Option<ObjectId>>,
    len: usize,
    maximum: usize,
}

impl ObjectIdSet {
    pub(crate) fn new(maximum: usize) -> Result<Self, ()> {
        if maximum == 0 {
            return Err(());
        }
        let initial = maximum.min(16).next_power_of_two();
        let mut slots = Vector::new();
        slots.try_reserve_exact(initial).map_err(|_| ())?;
        slots.resize(initial, None);
        Ok(Self {
            slots,
            len: 0,
            maximum,
        })
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn contains(&self, id: &ObjectId) -> bool {
        self.find(id).is_some()
    }

    /// Returns true only when a new exact ID was inserted.
    pub(crate) fn try_insert(&mut self, id: ObjectId) -> Result<bool, ()> {
        if self.contains(&id) {
            return Ok(false);
        }
        if self.len >= self.maximum {
            return Err(());
        }
        if (self.len + 1).saturating_mul(4) > self.slots.len().saturating_mul(3) {
            self.grow()?;
        }
        self.insert_unchecked(id);
        Ok(true)
    }

    pub(crate) fn remove(&mut self, id: &ObjectId) -> bool {
        let Some(mut index) = self.find(id) else {
            return false;
        };
        self.slots[index] = None;
        self.len -= 1;
        // Close the probe cluster so removal never creates a false miss.
        index = (index + 1) & (self.slots.len() - 1);
        while let Some(displaced) = self.slots[index].take() {
            self.len -= 1;
            self.insert_unchecked(displaced);
            index = (index + 1) & (self.slots.len() - 1);
        }
        true
    }

    fn grow(&mut self) -> Result<(), ()> {
        let largest = self.maximum.saturating_mul(2).next_power_of_two();
        let next = self.slots.len().saturating_mul(2).min(largest);
        if next <= self.slots.len() {
            return Err(());
        }
        let mut replacement = Vector::new();
        replacement.try_reserve_exact(next).map_err(|_| ())?;
        replacement.resize(next, None);
        let old = core::mem::replace(&mut self.slots, replacement);
        self.len = 0;
        for id in old.into_iter().flatten() {
            self.insert_unchecked(id);
        }
        Ok(())
    }

    fn find(&self, id: &ObjectId) -> Option<usize> {
        let mask = self.slots.len() - 1;
        let mut index = object_hash(id) & mask;
        for _ in 0..self.slots.len() {
            match self.slots[index] {
                Some(existing) if existing == *id => return Some(index),
                None => return None,
                Some(_) => index = (index + 1) & mask,
            }
        }
        None
    }

    fn insert_unchecked(&mut self, id: ObjectId) {
        let mask = self.slots.len() - 1;
        let mut index = object_hash(&id) & mask;
        while self.slots[index].is_some() {
            index = (index + 1) & mask;
        }
        self.slots[index] = Some(id);
        self.len += 1;
    }
}

fn object_hash(id: &ObjectId) -> usize {
    // Object IDs are already cryptographic digests. Mix the entire fixed-width
    // identifier so bucket selection is not controlled by one prefix/suffix.
    let mut hash = 0x9e37_79b9_7f4a_7c15u64;
    for chunk in id.as_bytes().chunks(8) {
        let mut word = [0u8; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        hash ^= u64::from_le_bytes(word)
            .wrapping_add(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(hash << 6)
            .wrapping_add(hash >> 2);
    }
    hash as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_deduplicates_and_closes_removed_probe_clusters() {
        let mut set = ObjectIdSet::new(1_000).unwrap();
        let ids: Vector<_> = (0..500u32)
            .map(|value| ObjectId::Sha256(mrml_crypto::Sha256::digest(&value.to_le_bytes())))
            .collect();
        for id in &ids {
            assert!(set.try_insert(*id).unwrap());
            assert!(!set.try_insert(*id).unwrap());
        }
        assert_eq!(set.len(), ids.len());
        for id in ids.iter().step_by(2) {
            assert!(set.remove(id));
        }
        for (index, id) in ids.iter().enumerate() {
            assert_eq!(set.contains(id), index % 2 == 1);
        }
    }
}
