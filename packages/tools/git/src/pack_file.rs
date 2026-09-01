//! Constant-memory authentication pass for quarantined pack files.

use mrml_runtime::File;

use crate::inflate::{InflateByteReader, inflate_zlib_reader};
use crate::sha1::GitObjectHasher;
use crate::{ObjectFormat, ObjectId, ObjectKind, PackError, PackIndexEntry};

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
pub(crate) fn validate_direct_pack_file(
    path: &str,
    format: ObjectFormat,
    max_pack_bytes: u64,
    max_objects: u32,
    max_expanded_bytes: u64,
    max_individual_bytes: u64,
    max_work_units: u64,
) -> Result<ValidatedDirectPack, PackError> {
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
    let mut objects = mrml_runtime::Vector::new();
    let mut entries = mrml_runtime::Vector::new();
    objects
        .try_reserve_exact(scan.object_count as usize)
        .map_err(|_| PackError::TooLarge)?;
    entries
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
        let kind = match object_type {
            1 => ObjectKind::Commit,
            2 => ObjectKind::Tree,
            3 => ObjectKind::Blob,
            4 => ObjectKind::Tag,
            6 | 7 => return Err(PackError::MissingBase),
            _ => return Err(PackError::ObjectType),
        };
        if size > max_individual_bytes {
            return Err(PackError::TooLarge);
        }
        let contents = inflate_zlib_reader(
            &mut cursor,
            usize::try_from(max_individual_bytes).map_err(|_| PackError::TooLarge)?,
        )
        .map_err(|_| PackError::Compression)?;
        if contents.len() as u64 != size {
            return Err(PackError::TooLarge);
        }
        expanded_bytes = expanded_bytes
            .checked_add(size)
            .ok_or(PackError::TooLarge)?;
        if expanded_bytes > max_expanded_bytes {
            return Err(PackError::TooLarge);
        }
        if size > cursor.work_remaining {
            return Err(PackError::TooLarge);
        }
        cursor.work_remaining -= size;
        largest_object = largest_object.max(size);
        let header = mrml_runtime::mrml_format!("{} {}\0", kind.name(), contents.len());
        let mut object_hash = GitObjectHasher::new(format);
        object_hash.update(header.as_bytes());
        object_hash.update(&contents);
        let id = object_hash.finalize();
        entries.push(PackIndexEntry {
            id,
            crc32: cursor.finish_crc()?,
            offset,
        });
        objects.push((id, kind));
    }
    if cursor.position != cursor.data_end {
        return Err(PackError::TrailingData);
    }
    Ok(ValidatedDirectPack {
        objects,
        entries,
        expanded_bytes,
        largest_object,
        checksum: scan.checksum,
    })
}

#[cfg(test)]
mod tests {
    use mrml_runtime::{Vector, join_path};

    use super::*;
    use crate::{ObjectKind, PackObject, encode_pack_with_format};

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
}
