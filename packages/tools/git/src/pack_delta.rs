//! Deterministic, bounded Git pack delta selection.

use crate::{ObjectId, PackError, PackObject};
use mrml_runtime::Vector;

pub(crate) const DELTA_WINDOW: usize = 250;
pub(crate) const MAX_DELTA_DEPTH: u8 = 50;
const HASH_BUCKETS: usize = 4096;
const MAX_HASH_CHAIN: usize = 64;
const MIN_MATCH: usize = 4;
const MAX_COPY: usize = 0x00ff_ffff;
const MAX_MATCH_COMPARE: usize = 65_536;
const MAX_DELTA_SEARCH_WORK: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeltaSelection {
    pub(crate) base_index: usize,
    pub(crate) bytes: Vector<u8>,
    pub(crate) depth: u8,
}

/// Selects only from the fixed direct-predecessor window. Candidate quality is
/// ordered solely by raw delta length and then the complete object ID.
pub(crate) fn select_deltas(
    objects: &[PackObject],
) -> Result<Vector<Option<DeltaSelection>>, PackError> {
    select_deltas_with_work(objects, MAX_DELTA_SEARCH_WORK)
}

fn select_deltas_with_work(
    objects: &[PackObject],
    max_work: usize,
) -> Result<Vector<Option<DeltaSelection>>, PackError> {
    let mut selected: Vector<Option<DeltaSelection>> = Vector::new();
    let mut work_remaining = max_work;
    selected
        .try_reserve_exact(objects.len())
        .map_err(|_| PackError::TooLarge)?;
    for (index, object) in objects.iter().enumerate() {
        let mut best: Option<(usize, ObjectId, Vector<u8>, u8)> = None;
        let start = index.saturating_sub(DELTA_WINDOW);
        for base_index in (start..index).rev() {
            let base = &objects[base_index];
            if base.kind != object.kind {
                continue;
            }
            let base_depth = selected[base_index].as_ref().map_or(0, |delta| delta.depth);
            if base_depth >= MAX_DELTA_DEPTH {
                continue;
            }
            let Some(delta) = make_delta(&base.contents, &object.contents, &mut work_remaining)?
            else {
                break;
            };
            if delta.len() >= object.contents.len() {
                continue;
            }
            let replace = best.as_ref().is_none_or(|(_, best_id, best_delta, _)| {
                (delta.len(), base.id) < (best_delta.len(), *best_id)
            });
            if replace {
                best = Some((base_index, base.id, delta, base_depth + 1));
            }
        }
        selected.push(best.map(|(base_index, _, bytes, depth)| DeltaSelection {
            base_index,
            bytes,
            depth,
        }));
    }
    Ok(selected)
}

fn make_delta(
    base: &[u8],
    target: &[u8],
    work_remaining: &mut usize,
) -> Result<Option<Vector<u8>>, PackError> {
    if base.len() > *work_remaining {
        return Ok(None);
    }
    *work_remaining -= base.len();
    let mut output = Vector::new();
    put_varint(base.len(), &mut output);
    put_varint(target.len(), &mut output);

    let mut heads = [usize::MAX; HASH_BUCKETS];
    let mut previous = Vector::new();
    previous
        .try_reserve_exact(base.len())
        .map_err(|_| PackError::TooLarge)?;
    previous.resize(base.len(), usize::MAX);
    if base.len() >= MIN_MATCH {
        for offset in 0..=base.len() - MIN_MATCH {
            let bucket = hash4(&base[offset..offset + MIN_MATCH]);
            previous[offset] = heads[bucket];
            heads[bucket] = offset;
        }
    }

    let mut literal_start = 0usize;
    let mut cursor = 0usize;
    while cursor < target.len() {
        let mut best_offset = 0usize;
        let mut best_length = 0usize;
        if cursor + MIN_MATCH <= target.len() && base.len() >= MIN_MATCH {
            let mut candidate = heads[hash4(&target[cursor..cursor + MIN_MATCH])];
            let mut probes = 0usize;
            while candidate != usize::MAX && probes < MAX_HASH_CHAIN {
                if *work_remaining == 0 {
                    return Ok(None);
                }
                *work_remaining -= 1;
                let maximum = (base.len() - candidate)
                    .min(target.len() - cursor)
                    .min(MAX_COPY)
                    .min(MAX_MATCH_COMPARE);
                let mut length = MIN_MATCH;
                while length < maximum && base[candidate + length] == target[cursor + length] {
                    if *work_remaining == 0 {
                        return Ok(None);
                    }
                    *work_remaining -= 1;
                    length += 1;
                }
                if length > best_length || (length == best_length && candidate < best_offset) {
                    best_offset = candidate;
                    best_length = length;
                }
                candidate = previous[candidate];
                probes += 1;
            }
        }
        if best_length >= MIN_MATCH {
            emit_literals(&target[literal_start..cursor], &mut output);
            emit_copy(best_offset, best_length, &mut output);
            cursor += best_length;
            literal_start = cursor;
        } else {
            cursor += 1;
        }
    }
    emit_literals(&target[literal_start..], &mut output);
    Ok(Some(output))
}

fn hash4(bytes: &[u8]) -> usize {
    let value = u32::from_le_bytes(bytes[..4].try_into().expect("four-byte match key"));
    (value.wrapping_mul(0x9e37_79b1) as usize) & (HASH_BUCKETS - 1)
}

fn put_varint(mut value: usize, output: &mut Vector<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn emit_literals(mut bytes: &[u8], output: &mut Vector<u8>) {
    while !bytes.is_empty() {
        let take = bytes.len().min(127);
        output.push(take as u8);
        output.extend(bytes[..take].iter().copied());
        bytes = &bytes[take..];
    }
}

fn emit_copy(offset: usize, length: usize, output: &mut Vector<u8>) {
    let mut opcode = 0x80u8;
    let mut parameters = [0u8; 7];
    let mut used = 0usize;
    for byte_index in 0..4 {
        let byte = ((offset >> (byte_index * 8)) & 0xff) as u8;
        if byte != 0 {
            opcode |= 1 << byte_index;
            parameters[used] = byte;
            used += 1;
        }
    }
    if length != 65_536 {
        for byte_index in 0..3 {
            let byte = ((length >> (byte_index * 8)) & 0xff) as u8;
            if byte != 0 {
                opcode |= 0x10 << byte_index;
                parameters[used] = byte;
                used += 1;
            }
        }
    }
    output.push(opcode);
    output.extend(parameters[..used].iter().copied());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObjectFormat, ObjectKind, encode_loose_object_with_format};

    fn blob(bytes: &[u8]) -> PackObject {
        let (id, _) = encode_loose_object_with_format(ObjectFormat::Sha1, ObjectKind::Blob, bytes);
        PackObject {
            id,
            kind: ObjectKind::Blob,
            contents: bytes.iter().copied().collect(),
        }
    }

    #[test]
    fn selection_is_deterministic_and_same_kind_only() {
        let mut tree = blob(b"abcdefgh-2222");
        tree.kind = ObjectKind::Tree;
        let objects = [blob(b"abcdefgh-0000"), blob(b"abcdefgh-1111"), tree];
        assert_eq!(
            select_deltas(&objects).unwrap(),
            select_deltas(&objects).unwrap()
        );
        assert_eq!(
            select_deltas(&objects).unwrap()[1]
                .as_ref()
                .unwrap()
                .base_index,
            0
        );
        assert!(select_deltas(&objects).unwrap()[2].is_none());
    }

    #[test]
    fn fixed_window_and_depth_are_enforced() {
        let mut objects = Vector::new();
        objects.push(blob(&[b'x'; 256]));
        for value in 0..=DELTA_WINDOW {
            objects.push(blob(&[value as u8; 256]));
        }
        assert_ne!(
            select_deltas(&objects)
                .unwrap()
                .last()
                .unwrap()
                .as_ref()
                .map(|d| d.base_index),
            Some(0)
        );

        let mut chain = Vector::new();
        for index in 0..=MAX_DELTA_DEPTH as usize {
            let mut bytes = Vector::from([b'a'; 512]);
            bytes[index] = b'b';
            chain.push(blob(&bytes));
        }
        assert!(
            select_deltas(&chain)
                .unwrap()
                .iter()
                .flatten()
                .all(|d| d.depth <= MAX_DELTA_DEPTH)
        );
    }

    #[test]
    fn incompressible_change_is_left_whole() {
        let objects = [blob(&[0; 32]), blob(&[1; 32])];
        assert!(select_deltas(&objects).unwrap()[1].is_none());
    }

    #[test]
    fn exhausted_search_budget_falls_back_deterministically() {
        let objects = [blob(&[b'a'; 512]), blob(&[b'a'; 512])];
        assert!(select_deltas_with_work(&objects, 0).unwrap()[1].is_none());
        assert_eq!(
            select_deltas_with_work(&objects, 8).unwrap(),
            select_deltas_with_work(&objects, 8).unwrap()
        );
    }
}
