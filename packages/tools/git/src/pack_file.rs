//! Constant-memory authentication pass for quarantined pack files.

use mrml_runtime::File;

use crate::sha1::GitObjectHasher;
use crate::{ObjectFormat, ObjectId, PackError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackFileScan {
    pub(crate) bytes: u64,
    pub(crate) object_count: u32,
    pub(crate) checksum: ObjectId,
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
