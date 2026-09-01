//! Constant-memory authentication pass for quarantined pack files.

use mrml_runtime::File;

use crate::inflate::{InflateByteReader, inflate_zlib_reader};
use crate::sha1::GitObjectHasher;
use crate::{ObjectFormat, ObjectId, ObjectKind, PackError, PackIndexEntry};

const MAX_DELTA_DEPTH: u8 = 50;
const MAX_DELTA_INSTRUCTIONS: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackFileScan {
    pub(crate) bytes: u64,
    pub(crate) object_count: u32,
    pub(crate) checksum: ObjectId,
}

pub(crate) struct ValidatedDirectPack {
    pub(crate) objects: mrml_runtime::Vector<(ObjectId, ObjectKind)>,
    pub(crate) entries: mrml_runtime::Vector<PackIndexEntry>,
    pub(crate) expanded_bytes: u64,
    pub(crate) largest_object: u64,
    pub(crate) checksum: ObjectId,
}

#[derive(Clone)]
enum DeltaBase {
    Offset(u64),
    Id(ObjectId),
}

#[derive(Clone)]
struct PendingDelta {
    offset: u64,
    payload_offset: u64,
    declared_size: u64,
    base: DeltaBase,
    crc32: u32,
}

#[derive(Clone, Copy)]
struct ResolvedObject {
    offset: Option<u64>,
    id: ObjectId,
    kind: ObjectKind,
    depth: u8,
    crc32: u32,
}

struct FileCursor {
    file: File,
    position: u64,
    data_end: u64,
    work_remaining: u64,
    crc: Option<u32>,
}

impl FileCursor {
    fn read_protocol_byte(&mut self) -> Result<u8, PackError> {
        self.read_byte().map_err(|_| PackError::Truncated)
    }

    fn start_crc(&mut self) {
        self.crc = Some(0xffff_ffff);
    }

    fn finish_crc(&mut self) -> Result<u32, PackError> {
        self.crc.take().map(|crc| !crc).ok_or(PackError::TooLarge)
    }
}

impl InflateByteReader for FileCursor {
    fn read_byte(&mut self) -> Result<u8, crate::inflate::InflateError> {
        if self.position >= self.data_end || self.work_remaining == 0 {
            return Err(crate::inflate::InflateError::Truncated);
        }
        let mut byte = [0u8; 1];
        self.file
            .read_exact(&mut byte)
            .map_err(|_| crate::inflate::InflateError::Truncated)?;
        self.position += 1;
        self.work_remaining -= 1;
        if let Some(crc) = &mut self.crc {
            *crc = crc32_update(*crc, byte[0]);
        }
        Ok(byte[0])
    }

    fn consumed(&self) -> usize {
        usize::try_from(self.position).unwrap_or(usize::MAX)
    }
}

fn crc32_update(mut crc: u32, byte: u8) -> u32 {
    crc ^= u32::from(byte);
    for _ in 0..8 {
        crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
    }
    crc
}

pub(crate) fn scan_pack_file(
    path: &str,
    format: ObjectFormat,
    max_pack_bytes: u64,
    max_objects: u32,
    max_work_units: u64,
) -> Result<PackFileScan, PackError> {
    let mut file = File::open_regular(path).map_err(|_| PackError::Truncated)?;
    let bytes = file.len().map_err(|_| PackError::Truncated)?;
    let hash_len = format.hash_len() as u64;
    let data_bytes = bytes.checked_sub(hash_len).ok_or(PackError::Truncated)?;
    if bytes > max_pack_bytes || data_bytes < 12 || bytes > max_work_units {
        return Err(PackError::TooLarge);
    }

    let mut hash = GitObjectHasher::new(format);
    let mut header = [0u8; 12];
    let mut header_used = 0usize;
    let mut remaining = data_bytes;
    let mut buffer = [0u8; 64 * 1024];
    while remaining != 0 {
        let wanted =
            usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| PackError::TooLarge)?;
        let read = file
            .read(&mut buffer[..wanted])
            .map_err(|_| PackError::Truncated)?;
        if read == 0 || read > wanted {
            return Err(PackError::Truncated);
        }
        let copy = read.min(header.len() - header_used);
        header[header_used..header_used + copy].copy_from_slice(&buffer[..copy]);
        header_used += copy;
        hash.update(&buffer[..read]);
        remaining = remaining
            .checked_sub(read as u64)
            .ok_or(PackError::TooLarge)?;
    }
    if header_used != header.len() || &header[..4] != b"PACK" {
        return Err(PackError::Signature);
    }
    let version = u32::from_be_bytes(header[4..8].try_into().map_err(|_| PackError::Truncated)?);
    if !matches!(version, 2 | 3) {
        return Err(PackError::Version);
    }
    let object_count =
        u32::from_be_bytes(header[8..12].try_into().map_err(|_| PackError::Truncated)?);
    if object_count == 0 || object_count > max_objects {
        return Err(PackError::TooManyObjects);
    }
    let mut trailer = [0u8; 32];
    file.read_exact(&mut trailer[..format.hash_len()])
        .map_err(|_| PackError::Truncated)?;
    let expected =
        ObjectId::from_bytes(format, &trailer[..format.hash_len()]).ok_or(PackError::ObjectId)?;
    let checksum = hash.finalize();
    if checksum != expected {
        return Err(PackError::Checksum);
    }
    Ok(PackFileScan {
        bytes,
        object_count,
        checksum,
    })
}

/// Validates direct (non-delta) objects from an already authenticated regular
/// file while retaining at most one configured object in memory. Delta types
/// fail closed until the scratch-object resolver is connected.
#[allow(dead_code)] // compatibility entry point for direct-only callers
pub(crate) fn validate_direct_pack_file(
    path: &str,
    format: ObjectFormat,
    max_pack_bytes: u64,
    max_objects: u32,
    max_expanded_bytes: u64,
    max_individual_bytes: u64,
    max_work_units: u64,
) -> Result<ValidatedDirectPack, PackError> {
    validate_direct_pack_file_with_sink(
        path,
        format,
        max_pack_bytes,
        max_objects,
        max_expanded_bytes,
        max_individual_bytes,
        max_work_units,
        |_, _, _| Ok(()),
    )
}

#[allow(dead_code)] // compatibility entry point for direct-only callers
pub(crate) fn validate_direct_pack_file_with_sink<F>(
    path: &str,
    format: ObjectFormat,
    max_pack_bytes: u64,
    max_objects: u32,
    max_expanded_bytes: u64,
    max_individual_bytes: u64,
    max_work_units: u64,
    mut sink: F,
) -> Result<ValidatedDirectPack, PackError>
where
    F: FnMut(ObjectId, ObjectKind, &[u8]) -> Result<(), PackError>,
{
    validate_pack_file_with_bases(
        path,
        format,
        max_pack_bytes,
        max_objects,
        max_expanded_bytes,
        max_individual_bytes,
        max_work_units,
        &mut sink,
        |_, _| Ok(None),
    )
}

/// Validates direct and delta objects without retaining the whole pack. The
/// sink must make accepted objects available to `load_base`; an external base
/// is accepted only after its exact Git object ID is recomputed.
pub(crate) fn validate_pack_file_with_bases<F, B>(
    path: &str,
    format: ObjectFormat,
    max_pack_bytes: u64,
    max_objects: u32,
    max_expanded_bytes: u64,
    max_individual_bytes: u64,
    max_work_units: u64,
    sink: &mut F,
    mut load_base: B,
) -> Result<ValidatedDirectPack, PackError>
where
    F: FnMut(ObjectId, ObjectKind, &[u8]) -> Result<(), PackError>,
    B: FnMut(ObjectId, u64) -> Result<Option<(ObjectKind, mrml_runtime::Vector<u8>)>, PackError>,
{
    let scan = scan_pack_file(path, format, max_pack_bytes, max_objects, max_work_units)?;
    let second_pass = scan
        .bytes
        .checked_sub(format.hash_len() as u64)
        .ok_or(PackError::Truncated)?;
    let minimum_work = scan
        .bytes
        .checked_add(second_pass)
        .ok_or(PackError::TooLarge)?;
    if minimum_work > max_work_units {
        return Err(PackError::TooLarge);
    }
    let mut file = File::open_regular(path).map_err(|_| PackError::Truncated)?;
    file.seek(12).map_err(|_| PackError::Truncated)?;
    let mut cursor = FileCursor {
        file,
        position: 12,
        data_end: scan.bytes - format.hash_len() as u64,
        work_remaining: max_work_units - scan.bytes - 12,
        crc: None,
    };
    let mut resolved = mrml_runtime::Vector::new();
    let mut pending = mrml_runtime::Vector::new();
    resolved
        .try_reserve_exact(scan.object_count as usize)
        .map_err(|_| PackError::TooLarge)?;
    pending
        .try_reserve_exact(scan.object_count as usize)
        .map_err(|_| PackError::TooLarge)?;
    let mut expanded_bytes = 0u64;
    let mut largest_object = 0u64;
    for _ in 0..scan.object_count {
        let offset = cursor.position;
        cursor.start_crc();
        let first = cursor.read_protocol_byte()?;
        let object_type = (first >> 4) & 7;
        let mut size = u64::from(first & 15);
        let mut shift = 4u32;
        let mut header = first;
        while header & 0x80 != 0 {
            header = cursor.read_protocol_byte()?;
            if shift >= 64 {
                return Err(PackError::TooLarge);
            }
            size |= u64::from(header & 0x7f)
                .checked_shl(shift)
                .ok_or(PackError::TooLarge)?;
            shift += 7;
        }
        let base = match object_type {
            1..=4 => None,
            6 => {
                let mut byte = cursor.read_protocol_byte()?;
                let mut distance = u64::from(byte & 0x7f);
                while byte & 0x80 != 0 {
                    byte = cursor.read_protocol_byte()?;
                    distance = distance
                        .checked_add(1)
                        .and_then(|value| value.checked_shl(7))
                        .and_then(|value| value.checked_add(u64::from(byte & 0x7f)))
                        .ok_or(PackError::Delta)?;
                }
                Some(DeltaBase::Offset(
                    offset.checked_sub(distance).ok_or(PackError::Delta)?,
                ))
            }
            7 => {
                let mut bytes = [0u8; 32];
                for byte in &mut bytes[..format.hash_len()] {
                    *byte = cursor.read_protocol_byte()?;
                }
                Some(DeltaBase::Id(
                    ObjectId::from_bytes(format, &bytes[..format.hash_len()])
                        .ok_or(PackError::ObjectId)?,
                ))
            }
            _ => return Err(PackError::ObjectType),
        };
        if size > max_individual_bytes {
            return Err(PackError::TooLarge);
        }
        let payload_offset = cursor.position;
        let contents = inflate_zlib_reader(
            &mut cursor,
            usize::try_from(max_individual_bytes).map_err(|_| PackError::TooLarge)?,
        )
        .map_err(|_| PackError::Compression)?;
        if contents.len() as u64 != size {
            return Err(PackError::TooLarge);
        }
        if contents.len() as u64 > cursor.work_remaining {
            return Err(PackError::TooLarge);
        }
        cursor.work_remaining -= contents.len() as u64;
        let crc32 = cursor.finish_crc()?;
        if let Some(base) = base {
            pending.push(PendingDelta {
                offset,
                payload_offset,
                declared_size: size,
                base,
                crc32,
            });
        } else {
            let kind = match object_type {
                1 => ObjectKind::Commit,
                2 => ObjectKind::Tree,
                3 => ObjectKind::Blob,
                4 => ObjectKind::Tag,
                _ => return Err(PackError::ObjectType),
            };
            expanded_bytes = charge_expanded(expanded_bytes, size, max_expanded_bytes)?;
            largest_object = largest_object.max(size);
            let id = hash_object(format, kind, &contents);
            sink(id, kind, &contents)?;
            resolved.push(ResolvedObject {
                offset: Some(offset),
                id,
                kind,
                depth: 0,
                crc32,
            });
        }
    }
    if cursor.position != cursor.data_end {
        return Err(PackError::TrailingData);
    }
    let mut work_remaining = cursor.work_remaining;
    while !pending.is_empty() {
        let before = pending.len();
        let mut deferred = mrml_runtime::Vector::new();
        for delta in pending {
            let known = match delta.base {
                DeltaBase::Offset(base_offset) => resolved
                    .iter()
                    .find(|object| object.offset == Some(base_offset))
                    .copied()
                    .map(|object| (object, false)),
                DeltaBase::Id(id) => resolved
                    .iter()
                    .find(|object| object.id == id)
                    .copied()
                    .map(|object| (object, false)),
            };
            let (base_meta, base_contents) = if let Some((object, _)) = known {
                let contents =
                    load_base(object.id, max_individual_bytes)?.ok_or(PackError::MissingBase)?;
                if contents.0 != object.kind {
                    return Err(PackError::ObjectId);
                }
                (object, contents.1)
            } else if let DeltaBase::Id(id) = delta.base {
                let Some((kind, contents)) = load_base(id, max_individual_bytes)? else {
                    deferred.push(delta);
                    continue;
                };
                if hash_object(format, kind, &contents) != id {
                    return Err(PackError::ObjectId);
                }
                (
                    ResolvedObject {
                        offset: None,
                        id,
                        kind,
                        depth: 0,
                        crc32: 0,
                    },
                    contents,
                )
            } else {
                deferred.push(delta);
                continue;
            };
            let depth = base_meta.depth.checked_add(1).ok_or(PackError::Delta)?;
            if depth > MAX_DELTA_DEPTH {
                return Err(PackError::Delta);
            }
            let program = inflate_at(
                path,
                delta.payload_offset,
                cursor.data_end,
                max_individual_bytes,
                &mut work_remaining,
            )?;
            if program.len() as u64 != delta.declared_size {
                return Err(PackError::TooLarge);
            }
            let contents = apply_delta_bounded(
                &base_contents,
                &program,
                max_individual_bytes,
                &mut work_remaining,
            )?;
            let size = contents.len() as u64;
            expanded_bytes = charge_expanded(expanded_bytes, size, max_expanded_bytes)?;
            largest_object = largest_object.max(size);
            let id = hash_object(format, base_meta.kind, &contents);
            sink(id, base_meta.kind, &contents)?;
            resolved.push(ResolvedObject {
                offset: Some(delta.offset),
                id,
                kind: base_meta.kind,
                depth,
                crc32: delta.crc32,
            });
        }
        if deferred.len() == before {
            return Err(PackError::MissingBase);
        }
        pending = deferred;
    }
    resolved.sort_unstable_by_key(|object| object.offset.unwrap_or(u64::MAX));
    let mut objects = mrml_runtime::Vector::new();
    let mut entries = mrml_runtime::Vector::new();
    for object in resolved.iter().filter(|object| object.offset.is_some()) {
        let offset = object.offset.ok_or(PackError::Delta)?;
        objects.push((object.id, object.kind));
        entries.push(PackIndexEntry {
            id: object.id,
            crc32: object.crc32,
            offset,
        });
    }
    Ok(ValidatedDirectPack {
        objects,
        entries,
        expanded_bytes,
        largest_object,
        checksum: scan.checksum,
    })
}

fn charge_expanded(current: u64, amount: u64, limit: u64) -> Result<u64, PackError> {
    current
        .checked_add(amount)
        .filter(|total| *total <= limit)
        .ok_or(PackError::TooLarge)
}

fn hash_object(format: ObjectFormat, kind: ObjectKind, contents: &[u8]) -> ObjectId {
    let header = mrml_runtime::mrml_format!("{} {}\0", kind.name(), contents.len());
    let mut hash = GitObjectHasher::new(format);
    hash.update(header.as_bytes());
    hash.update(contents);
    hash.finalize()
}

fn inflate_at(
    path: &str,
    offset: u64,
    data_end: u64,
    max_output: u64,
    work_remaining: &mut u64,
) -> Result<mrml_runtime::Vector<u8>, PackError> {
    let file = File::open_regular(path).map_err(|_| PackError::Truncated)?;
    let mut cursor = FileCursor {
        file,
        position: offset,
        data_end,
        work_remaining: *work_remaining,
        crc: None,
    };
    cursor.file.seek(offset).map_err(|_| PackError::Truncated)?;
    let output = inflate_zlib_reader(
        &mut cursor,
        usize::try_from(max_output).map_err(|_| PackError::TooLarge)?,
    )
    .map_err(|_| PackError::Compression)?;
    *work_remaining = cursor.work_remaining;
    Ok(output)
}

fn delta_varint(source: &[u8], cursor: &mut usize) -> Result<u64, PackError> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *source.get(*cursor).ok_or(PackError::Truncated)?;
        *cursor = cursor.checked_add(1).ok_or(PackError::Delta)?;
        value |= u64::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(PackError::Delta)?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift = shift.checked_add(7).ok_or(PackError::Delta)?;
        if shift >= 64 {
            return Err(PackError::Delta);
        }
    }
}

fn apply_delta_bounded(
    base: &[u8],
    delta: &[u8],
    max_output: u64,
    work_remaining: &mut u64,
) -> Result<mrml_runtime::Vector<u8>, PackError> {
    let mut cursor = 0usize;
    if delta_varint(delta, &mut cursor)? != base.len() as u64 {
        return Err(PackError::Delta);
    }
    let result_size = delta_varint(delta, &mut cursor)?;
    if result_size > max_output {
        return Err(PackError::TooLarge);
    }
    let mut output = mrml_runtime::Vector::new();
    output
        .try_reserve_exact(usize::try_from(result_size).map_err(|_| PackError::TooLarge)?)
        .map_err(|_| PackError::TooLarge)?;
    let mut instructions = 0u64;
    while cursor < delta.len() {
        instructions = instructions.checked_add(1).ok_or(PackError::TooLarge)?;
        if instructions > MAX_DELTA_INSTRUCTIONS || *work_remaining == 0 {
            return Err(PackError::TooLarge);
        }
        *work_remaining -= 1;
        let opcode = delta[cursor];
        cursor += 1;
        if opcode & 0x80 != 0 {
            let mut offset = 0usize;
            let mut size = 0usize;
            for bit in 0..4 {
                if opcode & (1 << bit) != 0 {
                    offset |=
                        usize::from(*delta.get(cursor).ok_or(PackError::Truncated)?) << (bit * 8);
                    cursor += 1;
                }
            }
            for bit in 0..3 {
                if opcode & (0x10 << bit) != 0 {
                    size |=
                        usize::from(*delta.get(cursor).ok_or(PackError::Truncated)?) << (bit * 8);
                    cursor += 1;
                }
            }
            if size == 0 {
                size = 65_536;
            }
            let end = offset.checked_add(size).ok_or(PackError::Delta)?;
            let slice = base.get(offset..end).ok_or(PackError::Delta)?;
            append_delta_output(&mut output, slice, result_size, work_remaining)?;
        } else if opcode != 0 {
            let size = usize::from(opcode);
            let end = cursor.checked_add(size).ok_or(PackError::Delta)?;
            let slice = delta.get(cursor..end).ok_or(PackError::Truncated)?;
            append_delta_output(&mut output, slice, result_size, work_remaining)?;
            cursor = end;
        } else {
            return Err(PackError::Delta);
        }
    }
    if output.len() as u64 != result_size {
        return Err(PackError::Delta);
    }
    Ok(output)
}

fn append_delta_output(
    output: &mut mrml_runtime::Vector<u8>,
    bytes: &[u8],
    result_size: u64,
    work_remaining: &mut u64,
) -> Result<(), PackError> {
    let next = output
        .len()
        .checked_add(bytes.len())
        .ok_or(PackError::Delta)?;
    if next as u64 > result_size || bytes.len() as u64 > *work_remaining {
        return Err(PackError::TooLarge);
    }
    output
        .try_extend_from_slice(bytes)
        .map_err(|_| PackError::TooLarge)?;
    *work_remaining -= bytes.len() as u64;
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;
    use mrml_runtime::{Vector, join_path};

    use super::*;
    use crate::{ObjectKind, PackObject, encode_pack_with_format};

    fn stored(source: &[u8]) -> Vector<u8> {
        let mut output = Vector::from([0x78, 0x01]);
        output.push(1);
        output.extend((source.len() as u16).to_le_bytes());
        output.extend((!(source.len() as u16)).to_le_bytes());
        output.extend(source.iter().copied());
        let mut a = 1u32;
        let mut b = 0u32;
        for byte in source {
            a = (a + u32::from(*byte)) % 65_521;
            b = (b + a) % 65_521;
        }
        output.extend((b << 16 | a).to_be_bytes());
        output
    }

    fn header(kind: u8, mut size: usize, output: &mut Vector<u8>) {
        let mut first = kind << 4 | (size as u8 & 15);
        size >>= 4;
        if size != 0 {
            first |= 0x80;
        }
        output.push(first);
        while size != 0 {
            let mut byte = (size & 0x7f) as u8;
            size >>= 7;
            if size != 0 {
                byte |= 0x80;
            }
            output.push(byte);
        }
    }

    fn finish(mut pack: Vector<u8>, format: ObjectFormat) -> Vector<u8> {
        let checksum = format.hash_bytes(&pack);
        pack.extend(checksum.as_bytes().iter().copied());
        pack
    }

    #[test]
    fn constant_memory_scan_authenticates_both_git_formats() {
        let root = join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-pack-scan-{}", mrml_runtime::process_id()),
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        mrml_runtime::create_dir_all(&root).unwrap();
        for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
            let object = PackObject {
                id: ObjectId::blob_with_format(format, b"streamed scan"),
                kind: ObjectKind::Blob,
                contents: Vector::from(*b"streamed scan"),
            };
            let mut pack = encode_pack_with_format(&[object], format).unwrap();
            let path = join_path(&root, format.name());
            mrml_runtime::write_file(&path, &pack).unwrap();
            let scan =
                scan_pack_file(&path, format, pack.len() as u64, 1, pack.len() as u64).unwrap();
            assert_eq!(scan.bytes, pack.len() as u64);
            assert_eq!(scan.object_count, 1);
            let validated = validate_direct_pack_file(
                &path,
                format,
                pack.len() as u64,
                1,
                1024,
                1024,
                pack.len() as u64 * 2 + 1024,
            )
            .unwrap();
            assert_eq!(
                &*validated.objects,
                &[(
                    ObjectId::blob_with_format(format, b"streamed scan"),
                    ObjectKind::Blob
                )]
            );
            assert_eq!(validated.entries.len(), 1);
            assert_eq!(validated.expanded_bytes, 13);
            assert_eq!(validated.largest_object, 13);
            assert_eq!(validated.checksum, scan.checksum);

            let last = pack.len() - 1;
            pack[last] ^= 1;
            mrml_runtime::write_file(&path, &pack).unwrap();
            assert_eq!(
                scan_pack_file(&path, format, pack.len() as u64, 1, pack.len() as u64),
                Err(PackError::Checksum)
            );
        }
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn file_validator_resolves_ofs_and_forward_ref_deltas() {
        let root = join_path(
            &mrml_runtime::temporary_directory(),
            "mrml-pack-file-deltas",
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        mrml_runtime::create_dir_all(&root).unwrap();
        let format = ObjectFormat::Sha256;
        let base = b"native";
        let result = b"natXYZ!";
        let base_id = ObjectId::blob_with_format(format, base);
        let delta = [6, 7, 0x90, 3, 4, b'X', b'Y', b'Z', b'!'];

        // Forward REF delta first, followed by its direct base.
        let mut pack = Vector::from(*b"PACK");
        pack.extend(2u32.to_be_bytes());
        pack.extend(2u32.to_be_bytes());
        header(7, delta.len(), &mut pack);
        pack.extend(base_id.as_bytes().iter().copied());
        pack.extend(stored(&delta));
        header(3, base.len(), &mut pack);
        pack.extend(stored(base));
        let pack = finish(pack, format);
        let path = join_path(&root, "ref.pack");
        mrml_runtime::write_file(&path, &pack).unwrap();
        let stored_objects = RefCell::new(Vector::<(ObjectId, ObjectKind, Vector<u8>)>::new());
        let validated = validate_pack_file_with_bases(
            &path,
            format,
            pack.len() as u64,
            2,
            64,
            64,
            4096,
            &mut |id, kind, bytes| {
                let mut copied = Vector::new();
                copied
                    .try_extend_from_slice(bytes)
                    .map_err(|_| PackError::TooLarge)?;
                stored_objects.borrow_mut().push((id, kind, copied));
                Ok(())
            },
            |id, _| {
                Ok(stored_objects
                    .borrow()
                    .iter()
                    .find(|entry| entry.0 == id)
                    .map(|entry| (entry.1, entry.2.clone())))
            },
        )
        .unwrap();
        assert_eq!(validated.objects.len(), 2);
        assert!(validated.objects.iter().any(|(id, _)| *id == base_id));
        assert!(
            validated
                .objects
                .iter()
                .any(|(id, _)| *id == ObjectId::blob_with_format(format, result))
        );

        // OFS delta follows its base and resolves through the same scratch view.
        let mut pack = Vector::from(*b"PACK");
        pack.extend(2u32.to_be_bytes());
        pack.extend(2u32.to_be_bytes());
        let base_offset = pack.len();
        header(3, base.len(), &mut pack);
        pack.extend(stored(base));
        let delta_offset = pack.len();
        header(6, delta.len(), &mut pack);
        let distance = delta_offset - base_offset;
        assert!(distance < 128);
        pack.push(distance as u8);
        pack.extend(stored(&delta));
        let pack = finish(pack, format);
        let path = join_path(&root, "ofs.pack");
        mrml_runtime::write_file(&path, &pack).unwrap();
        let stored_objects = RefCell::new(Vector::<(ObjectId, ObjectKind, Vector<u8>)>::new());
        assert!(
            validate_pack_file_with_bases(
                &path,
                format,
                pack.len() as u64,
                2,
                64,
                64,
                4096,
                &mut |id, kind, bytes| {
                    let mut copied = Vector::new();
                    copied
                        .try_extend_from_slice(bytes)
                        .map_err(|_| PackError::TooLarge)?;
                    stored_objects.borrow_mut().push((id, kind, copied));
                    Ok(())
                },
                |id, _| Ok(stored_objects
                    .borrow()
                    .iter()
                    .find(|e| e.0 == id)
                    .map(|e| (e.1, e.2.clone()))),
            )
            .is_ok()
        );
        mrml_runtime::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn thin_ref_base_is_rehashed_and_missing_base_fails_closed() {
        let root = join_path(&mrml_runtime::temporary_directory(), "mrml-pack-file-thin");
        let _ = mrml_runtime::remove_dir_all(&root);
        mrml_runtime::create_dir_all(&root).unwrap();
        let format = ObjectFormat::Sha256;
        let base = b"native";
        let base_id = ObjectId::blob_with_format(format, base);
        let delta = [6, 7, 0x90, 3, 4, b'X', b'Y', b'Z', b'!'];
        let mut pack = Vector::from(*b"PACK");
        pack.extend(2u32.to_be_bytes());
        pack.extend(1u32.to_be_bytes());
        header(7, delta.len(), &mut pack);
        pack.extend(base_id.as_bytes().iter().copied());
        pack.extend(stored(&delta));
        let pack = finish(pack, format);
        let path = join_path(&root, "thin.pack");
        mrml_runtime::write_file(&path, &pack).unwrap();
        let mut sink = |_: ObjectId, _: ObjectKind, _: &[u8]| Ok(());
        assert!(matches!(
            validate_pack_file_with_bases(
                &path,
                format,
                pack.len() as u64,
                1,
                64,
                64,
                4096,
                &mut sink,
                |_, _| Ok(None)
            ),
            Err(PackError::MissingBase)
        ));
        assert!(
            validate_pack_file_with_bases(
                &path,
                format,
                pack.len() as u64,
                1,
                64,
                64,
                4096,
                &mut sink,
                |id, _| Ok((id == base_id).then(|| (ObjectKind::Blob, Vector::from(*base))))
            )
            .is_ok()
        );
        assert!(matches!(
            validate_pack_file_with_bases(
                &path,
                format,
                pack.len() as u64,
                1,
                64,
                64,
                4096,
                &mut sink,
                |id, _| Ok((id == base_id).then(|| (ObjectKind::Blob, Vector::from(*b"forged"))))
            ),
            Err(PackError::ObjectId)
        ));
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
