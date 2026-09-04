//! Streaming emission of authenticated Git backup archives.

use std::io::{Read, Seek, SeekFrom, Write};

use mrml_crypto::Sha256;
use mrml_git::{
    BACKUP_FRAME_OVERHEAD, BACKUP_STREAM_HEADER_BYTES, BackupInventory, BackupInventoryFileKind,
    BackupStreamHeader, MAX_BACKUP_INVENTORY_BYTES, encode_backup_inventory,
    encode_backup_stream_header, open_backup_frame, parse_backup_inventory,
    parse_backup_stream_header, seal_backup_frame,
};
use mrml_runtime::DirectoryCapability;

const PAYLOAD_MAGIC: &[u8; 8] = b"MRGBPL01";
const PAYLOAD_PREFIX_BYTES: usize = 16;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupArchiveError {
    Inventory,
    Header,
    Open,
    Changed,
    Read,
    Encrypt,
    Write,
    Resource,
    Authentication,
    Truncated,
    Trailing,
    TargetNotEmpty,
    Metadata,
}

/// Authenticates and structurally verifies a complete archive without writing
/// any restored state. Success proves every inventory byte, file segment, and
/// the canonical terminal frame was consumed exactly once.
pub fn verify_backup_archive(
    reader: &mut dyn Read,
    backup_key: &[u8; 32],
) -> Result<BackupInventory, BackupArchiveError> {
    let mut encoded_header = [0u8; BACKUP_STREAM_HEADER_BYTES];
    read_exact_archive(reader, &mut encoded_header)?;
    let header =
        parse_backup_stream_header(&encoded_header).map_err(|_| BackupArchiveError::Header)?;
    let mut frames = FrameReader::new(reader, backup_key, encoded_header, header.chunk_bytes)?;
    let mut prefix = [0u8; PAYLOAD_PREFIX_BYTES];
    frames.read_exact_plaintext(&mut prefix)?;
    let inventory_length = backup_payload_inventory_length(&prefix)?;
    let mut encoded_inventory = vec![0; inventory_length];
    frames.read_exact_plaintext(&mut encoded_inventory)?;
    let inventory =
        parse_backup_inventory(&encoded_inventory).map_err(|_| BackupArchiveError::Inventory)?;
    if inventory.backup_generation != header.generation {
        return Err(BackupArchiveError::Inventory);
    }
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    for entry in &inventory.entries {
        if entry.kind == BackupInventoryFileKind::Regular {
            let mut digest = Sha256::new();
            let mut remaining = entry.size;
            while remaining != 0 {
                let count = usize::try_from(remaining.min(buffer.len() as u64))
                    .map_err(|_| BackupArchiveError::Resource)?;
                frames.read_exact_plaintext(&mut buffer[..count])?;
                digest.update(&buffer[..count]);
                remaining -= count as u64;
            }
            if digest.finalize() != entry.digest {
                return Err(BackupArchiveError::Authentication);
            }
        }
    }
    frames.finish()?;
    Ok(inventory)
}

/// Restores into ten distinct, empty target volumes. The complete archive is
/// authenticated before any target is opened, then authenticated again while
/// bytes are written. Any error leaves a disposable, invalid target set.
pub fn restore_backup_archive<R: Read + Seek>(
    reader: &mut R,
    backup_key: &[u8; 32],
    target_roots: [&str; 10],
) -> Result<BackupInventory, BackupArchiveError> {
    let verified = verify_backup_archive(reader, backup_key)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| BackupArchiveError::Read)?;
    let mut encoded_header = [0u8; BACKUP_STREAM_HEADER_BYTES];
    read_exact_archive(reader, &mut encoded_header)?;
    let header =
        parse_backup_stream_header(&encoded_header).map_err(|_| BackupArchiveError::Header)?;
    let mut frames = FrameReader::new(reader, backup_key, encoded_header, header.chunk_bytes)?;
    let mut prefix = [0u8; PAYLOAD_PREFIX_BYTES];
    frames.read_exact_plaintext(&mut prefix)?;
    let inventory_length = backup_payload_inventory_length(&prefix)?;
    let mut encoded_inventory = vec![0; inventory_length];
    frames.read_exact_plaintext(&mut encoded_inventory)?;
    let inventory =
        parse_backup_inventory(&encoded_inventory).map_err(|_| BackupArchiveError::Inventory)?;
    if inventory != verified {
        return Err(BackupArchiveError::Authentication);
    }

    let roots = open_empty_target_roots(target_roots)?;
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    for entry in &inventory.entries {
        if entry.path.as_str() == "." || entry.kind == BackupInventoryFileKind::Directory {
            if entry.path.as_str() != "." {
                let (parent, name) = retained_parent(&roots, entry.volume, entry.path.as_str())?;
                parent
                    .create_directory(name, 0o700)
                    .map_err(|_| BackupArchiveError::Changed)?;
                parent.sync().map_err(|_| BackupArchiveError::Write)?;
            }
            continue;
        }
        let (parent, name) = retained_parent(&roots, entry.volume, entry.path.as_str())?;
        let mut file = parent
            .create_new_file(name, 0o600)
            .map_err(|_| BackupArchiveError::Changed)?;
        let mut digest = Sha256::new();
        let mut remaining = entry.size;
        while remaining != 0 {
            let count = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| BackupArchiveError::Resource)?;
            frames.read_exact_plaintext(&mut buffer[..count])?;
            digest.update(&buffer[..count]);
            file.write_all(&buffer[..count])
                .map_err(|_| BackupArchiveError::Write)?;
            remaining -= count as u64;
        }
        if digest.finalize() != entry.digest {
            return Err(BackupArchiveError::Authentication);
        }
        file.sync().map_err(|_| BackupArchiveError::Write)?;
        file.set_owner_mode(entry.uid, entry.gid, u32::from(entry.mode))
            .map_err(|_| BackupArchiveError::Metadata)?;
        file.sync().map_err(|_| BackupArchiveError::Write)?;
        drop(file);
        parent.sync().map_err(|_| BackupArchiveError::Write)?;
    }
    frames.finish()?;

    for entry in inventory.entries.iter().rev() {
        if entry.kind != BackupInventoryFileKind::Directory {
            continue;
        }
        let directory = if entry.path.as_str() == "." {
            roots[entry.volume as usize - 1]
                .try_clone()
                .map_err(|_| BackupArchiveError::Open)?
        } else {
            roots[entry.volume as usize - 1]
                .open_directory(entry.path.as_str())
                .map_err(|_| BackupArchiveError::Changed)?
        };
        directory
            .set_owner_mode(entry.uid, entry.gid, u32::from(entry.mode))
            .map_err(|_| BackupArchiveError::Metadata)?;
        directory.sync().map_err(|_| BackupArchiveError::Write)?;
        if entry.path.as_str() != "." {
            let (parent, _) = retained_parent(&roots, entry.volume, entry.path.as_str())?;
            parent.sync().map_err(|_| BackupArchiveError::Write)?;
        }
    }

    let mut restored = mrml_runtime::Vector::new();
    for (volume, path) in mrml_git::BackupVolume::ALL.into_iter().zip(target_roots) {
        let entries =
            crate::collect_backup_volume(path, volume).map_err(|_| BackupArchiveError::Changed)?;
        restored
            .try_reserve(entries.len())
            .map_err(|_| BackupArchiveError::Resource)?;
        restored.extend(entries);
    }
    if restored != inventory.entries {
        return Err(BackupArchiveError::Changed);
    }
    Ok(inventory)
}

fn open_empty_target_roots(
    paths: [&str; 10],
) -> Result<Vec<DirectoryCapability>, BackupArchiveError> {
    let roots = open_roots(paths)?;
    for root in &roots {
        if !root
            .read_directory_bounded(1)
            .map_err(|_| BackupArchiveError::Open)?
            .is_empty()
        {
            return Err(BackupArchiveError::TargetNotEmpty);
        }
    }
    Ok(roots)
}

fn retained_parent<'a>(
    roots: &[DirectoryCapability],
    volume: mrml_git::BackupVolume,
    path: &'a str,
) -> Result<(DirectoryCapability, &'a str), BackupArchiveError> {
    let root = roots
        .get(volume as usize - 1)
        .ok_or(BackupArchiveError::Inventory)?;
    match path.rsplit_once('/') {
        Some((parent, name)) => root
            .open_directory(parent)
            .map(|directory| (directory, name))
            .map_err(|_| BackupArchiveError::Changed),
        None => root
            .try_clone()
            .map(|directory| (directory, path))
            .map_err(|_| BackupArchiveError::Changed),
    }
}

/// Writes one archive as fixed authenticated frames. Plaintext is a canonical
/// payload prefix, the canonical inventory, then each regular file's exact
/// bytes in inventory order. Directories carry no payload bytes.
pub fn write_backup_archive(
    writer: &mut dyn Write,
    backup_key: &[u8; 32],
    header: BackupStreamHeader,
    inventory: &BackupInventory,
    volume_roots: [&str; 10],
) -> Result<(), BackupArchiveError> {
    if inventory.backup_generation != header.generation {
        return Err(BackupArchiveError::Header);
    }
    let encoded_inventory =
        encode_backup_inventory(inventory).map_err(|_| BackupArchiveError::Inventory)?;
    let inventory_length =
        u32::try_from(encoded_inventory.len()).map_err(|_| BackupArchiveError::Resource)?;
    let encoded_header =
        encode_backup_stream_header(header).map_err(|_| BackupArchiveError::Header)?;
    writer
        .write_all(&encoded_header)
        .map_err(|_| BackupArchiveError::Write)?;
    let roots = open_roots(volume_roots)?;
    let mut frames = FrameWriter::new(writer, backup_key, encoded_header, header.chunk_bytes)?;
    let mut prefix = [0u8; PAYLOAD_PREFIX_BYTES];
    prefix[..8].copy_from_slice(PAYLOAD_MAGIC);
    prefix[8..12].copy_from_slice(&inventory_length.to_be_bytes());
    frames.write_plaintext(&prefix)?;
    frames.write_plaintext(&encoded_inventory)?;
    for entry in &inventory.entries {
        let root = roots
            .get(entry.volume as usize - 1)
            .ok_or(BackupArchiveError::Inventory)?;
        match entry.kind {
            BackupInventoryFileKind::Directory => {
                let metadata = if entry.path.as_str() == "." {
                    root.metadata().map_err(|_| BackupArchiveError::Changed)?
                } else {
                    root.open_directory(entry.path.as_str())
                        .and_then(|directory| directory.metadata())
                        .map_err(|_| BackupArchiveError::Changed)?
                };
                if metadata.mode & 0o170000 != 0o040000
                    || metadata.mode & 0o7777 != u32::from(entry.mode)
                    || metadata.uid != entry.uid
                    || metadata.gid != entry.gid
                    || metadata.links < 2
                    || entry.size != 0
                    || entry.digest != [0; 32]
                {
                    return Err(BackupArchiveError::Changed);
                }
            }
            BackupInventoryFileKind::Regular => {
                stream_regular(root, entry, &mut frames)?;
            }
        }
    }
    frames.finish()
}

fn open_roots(paths: [&str; 10]) -> Result<Vec<DirectoryCapability>, BackupArchiveError> {
    let mut roots = Vec::with_capacity(paths.len());
    let mut identities = Vec::with_capacity(paths.len());
    for path in paths {
        let root = DirectoryCapability::open_root(path).map_err(|_| BackupArchiveError::Open)?;
        let metadata = root.metadata().map_err(|_| BackupArchiveError::Open)?;
        if metadata.mode & 0o170000 != 0o040000 || metadata.links < 2 {
            return Err(BackupArchiveError::Open);
        }
        if identities.contains(&(metadata.device, metadata.inode)) {
            return Err(BackupArchiveError::Open);
        }
        identities.push((metadata.device, metadata.inode));
        roots.push(root);
    }
    Ok(roots)
}

fn stream_regular(
    root: &DirectoryCapability,
    entry: &mrml_git::BackupInventoryEntry,
    frames: &mut FrameWriter<'_>,
) -> Result<(), BackupArchiveError> {
    let mut file = root
        .open_regular(entry.path.as_str())
        .map_err(|_| BackupArchiveError::Changed)?;
    let metadata = file.metadata().map_err(|_| BackupArchiveError::Changed)?;
    let size = file.len().map_err(|_| BackupArchiveError::Changed)?;
    if metadata.mode & 0o170000 != 0o100000
        || metadata.mode & 0o7777 != u32::from(entry.mode)
        || metadata.uid != entry.uid
        || metadata.gid != entry.gid
        || metadata.links != 1
        || size != entry.size
    {
        return Err(BackupArchiveError::Changed);
    }
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    let mut digest = Sha256::new();
    let mut consumed = 0u64;
    while consumed < size {
        let wanted = usize::try_from((size - consumed).min(buffer.len() as u64))
            .map_err(|_| BackupArchiveError::Resource)?;
        let count = file
            .read(&mut buffer[..wanted])
            .map_err(|_| BackupArchiveError::Read)?;
        if count == 0 {
            return Err(BackupArchiveError::Changed);
        }
        digest.update(&buffer[..count]);
        frames.write_plaintext(&buffer[..count])?;
        consumed = consumed
            .checked_add(count as u64)
            .ok_or(BackupArchiveError::Resource)?;
    }
    if file
        .read(&mut buffer[..1])
        .map_err(|_| BackupArchiveError::Read)?
        != 0
        || digest.finalize() != entry.digest
    {
        return Err(BackupArchiveError::Changed);
    }
    Ok(())
}

struct FrameWriter<'a> {
    writer: &'a mut dyn Write,
    backup_key: &'a [u8; 32],
    header: [u8; BACKUP_STREAM_HEADER_BYTES],
    buffer: Vec<u8>,
    used: usize,
    sequence: u64,
}

struct FrameReader<'a> {
    reader: &'a mut dyn Read,
    backup_key: &'a [u8; 32],
    header: [u8; BACKUP_STREAM_HEADER_BYTES],
    plaintext: Vec<u8>,
    position: usize,
    length: usize,
    sequence: u64,
    final_seen: bool,
}

impl<'a> FrameReader<'a> {
    fn new(
        reader: &'a mut dyn Read,
        backup_key: &'a [u8; 32],
        header: [u8; BACKUP_STREAM_HEADER_BYTES],
        chunk_bytes: u32,
    ) -> Result<Self, BackupArchiveError> {
        let length = usize::try_from(chunk_bytes).map_err(|_| BackupArchiveError::Resource)?;
        Ok(Self {
            reader,
            backup_key,
            header,
            plaintext: vec![0; length],
            position: 0,
            length: 0,
            sequence: 0,
            final_seen: false,
        })
    }

    fn read_exact_plaintext(&mut self, mut output: &mut [u8]) -> Result<(), BackupArchiveError> {
        while !output.is_empty() {
            if self.position == self.length && !self.fill()? {
                return Err(BackupArchiveError::Truncated);
            }
            let count = output.len().min(self.length - self.position);
            output[..count].copy_from_slice(&self.plaintext[self.position..self.position + count]);
            self.position += count;
            output = &mut output[count..];
        }
        Ok(())
    }

    fn fill(&mut self) -> Result<bool, BackupArchiveError> {
        if self.final_seen {
            return Ok(false);
        }
        let mut frame_header = [0u8; 16];
        read_exact_archive(self.reader, &mut frame_header)?;
        let length = usize::try_from(u32::from_be_bytes(frame_header[8..12].try_into().unwrap()))
            .map_err(|_| BackupArchiveError::Resource)?;
        if length > self.plaintext.len() {
            return Err(BackupArchiveError::Authentication);
        }
        let mut frame = vec![0; BACKUP_FRAME_OVERHEAD + length];
        frame[..16].copy_from_slice(&frame_header);
        read_exact_archive(self.reader, &mut frame[16..])?;
        let (opened, final_frame) = open_backup_frame(
            self.backup_key,
            &self.header,
            self.sequence,
            &frame,
            &mut self.plaintext,
        )
        .map_err(|_| BackupArchiveError::Authentication)?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(BackupArchiveError::Resource)?;
        self.position = 0;
        self.length = opened;
        self.final_seen = final_frame;
        Ok(!final_frame)
    }

    fn finish(&mut self) -> Result<(), BackupArchiveError> {
        if self.position != self.length {
            return Err(BackupArchiveError::Trailing);
        }
        if !self.final_seen && self.fill()? {
            return Err(BackupArchiveError::Trailing);
        }
        let mut byte = [0u8; 1];
        match self.reader.read(&mut byte) {
            Ok(0) => Ok(()),
            Ok(_) => Err(BackupArchiveError::Trailing),
            Err(_) => Err(BackupArchiveError::Read),
        }
    }
}

fn read_exact_archive(
    reader: &mut dyn Read,
    mut output: &mut [u8],
) -> Result<(), BackupArchiveError> {
    while !output.is_empty() {
        match reader.read(output) {
            Ok(0) => return Err(BackupArchiveError::Truncated),
            Ok(count) => output = &mut output[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(BackupArchiveError::Read),
        }
    }
    Ok(())
}

impl<'a> FrameWriter<'a> {
    fn new(
        writer: &'a mut dyn Write,
        backup_key: &'a [u8; 32],
        header: [u8; BACKUP_STREAM_HEADER_BYTES],
        chunk_bytes: u32,
    ) -> Result<Self, BackupArchiveError> {
        let length = usize::try_from(chunk_bytes).map_err(|_| BackupArchiveError::Resource)?;
        Ok(Self {
            writer,
            backup_key,
            header,
            buffer: vec![0; length],
            used: 0,
            sequence: 0,
        })
    }

    fn write_plaintext(&mut self, mut input: &[u8]) -> Result<(), BackupArchiveError> {
        while !input.is_empty() {
            let count = input.len().min(self.buffer.len() - self.used);
            self.buffer[self.used..self.used + count].copy_from_slice(&input[..count]);
            self.used += count;
            input = &input[count..];
            if self.used == self.buffer.len() {
                self.emit(false)?;
            }
        }
        Ok(())
    }

    fn emit(&mut self, final_frame: bool) -> Result<(), BackupArchiveError> {
        let plaintext = if final_frame {
            &[][..]
        } else {
            &self.buffer[..self.used]
        };
        let mut sealed = vec![0; plaintext.len() + BACKUP_FRAME_OVERHEAD];
        let length = seal_backup_frame(
            self.backup_key,
            &self.header,
            self.sequence,
            final_frame,
            plaintext,
            &mut sealed,
        )
        .map_err(|_| BackupArchiveError::Encrypt)?;
        self.writer
            .write_all(&sealed[..length])
            .map_err(|_| BackupArchiveError::Write)?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(BackupArchiveError::Resource)?;
        self.used = 0;
        Ok(())
    }

    fn finish(mut self) -> Result<(), BackupArchiveError> {
        if self.used != 0 {
            self.emit(false)?;
        }
        self.emit(true)
    }
}

pub fn backup_payload_inventory_length(prefix: &[u8]) -> Result<usize, BackupArchiveError> {
    if prefix.len() != PAYLOAD_PREFIX_BYTES
        || &prefix[..8] != PAYLOAD_MAGIC
        || prefix[12..] != [0; 4]
    {
        return Err(BackupArchiveError::Inventory);
    }
    let length = usize::try_from(u32::from_be_bytes(prefix[8..12].try_into().unwrap()))
        .map_err(|_| BackupArchiveError::Resource)?;
    if length == 0 || length > MAX_BACKUP_INVENTORY_BYTES {
        return Err(BackupArchiveError::Resource);
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_git::{
        BackupInventoryEntry, BackupRepositoryGeneration, BackupVolume, PackGeneration,
        RepositoryGeneration, RepositoryIdentity, RevocationGeneration, TrustGeneration,
        open_backup_frame,
    };
    use mrml_runtime::{Text, Vector};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn archive_streams_canonical_inventory_and_file_bytes() {
        let root = std::env::temp_dir().join(format!("mrml-backup-archive-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut paths = Vec::new();
        for index in 0..10 {
            let path = root.join(index.to_string());
            fs::create_dir_all(&path).unwrap();
            paths.push(path);
        }
        let file_path = paths[0].join("objects.pack");
        fs::write(&file_path, b"hello").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();
        let metadata = fs::metadata(&file_path).unwrap();
        let mut entries = Vector::new();
        for (index, volume) in BackupVolume::ALL.into_iter().enumerate() {
            let root_metadata = fs::metadata(&paths[index]).unwrap();
            entries.push(BackupInventoryEntry {
                volume,
                path: Text::from("."),
                kind: BackupInventoryFileKind::Directory,
                mode: (root_metadata.mode() & 0o7777) as u16,
                uid: root_metadata.uid(),
                gid: root_metadata.gid(),
                size: 0,
                digest: [0; 32],
            });
            if index == 0 {
                entries.push(BackupInventoryEntry {
                    volume,
                    path: Text::from("objects.pack"),
                    kind: BackupInventoryFileKind::Regular,
                    mode: 0o600,
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                    size: 5,
                    digest: Sha256::digest(b"hello"),
                });
            }
        }
        let inventory = BackupInventory {
            backup_generation: 9,
            repositories: Vector::from([BackupRepositoryGeneration {
                repository: RepositoryIdentity::parse("owner/repository").unwrap(),
                repository_generation: RepositoryGeneration(1),
                pack_generation: PackGeneration(1),
                trust_generation: TrustGeneration(1),
                revocation_generation: RevocationGeneration(1),
                authority_generation: 0,
            }]),
            entries,
        };
        let path_refs: [&str; 10] = core::array::from_fn(|index| paths[index].to_str().unwrap());
        let header = BackupStreamHeader {
            generation: 9,
            chunk_bytes: 7,
            salt: [0x31; 16],
            nonce_prefix: [0x42; 4],
        };
        let key = [0x73; 32];
        let mut archive = Vec::new();
        write_backup_archive(&mut archive, &key, header, &inventory, path_refs).unwrap();

        let encoded_header: [u8; BACKUP_STREAM_HEADER_BYTES] =
            archive[..BACKUP_STREAM_HEADER_BYTES].try_into().unwrap();
        let mut cursor = BACKUP_STREAM_HEADER_BYTES;
        let mut sequence = 0;
        let mut plaintext = Vec::new();
        loop {
            let length =
                u32::from_be_bytes(archive[cursor + 8..cursor + 12].try_into().unwrap()) as usize;
            let end = cursor + BACKUP_FRAME_OVERHEAD + length;
            let mut opened = vec![0; header.chunk_bytes as usize];
            let (count, final_frame) = open_backup_frame(
                &key,
                &encoded_header,
                sequence,
                &archive[cursor..end],
                &mut opened,
            )
            .unwrap();
            plaintext.extend_from_slice(&opened[..count]);
            cursor = end;
            sequence += 1;
            if final_frame {
                break;
            }
        }
        assert_eq!(cursor, archive.len());
        let encoded_inventory = encode_backup_inventory(&inventory).unwrap();
        assert_eq!(
            backup_payload_inventory_length(&plaintext[..PAYLOAD_PREFIX_BYTES]),
            Ok(encoded_inventory.len())
        );
        assert_eq!(
            &plaintext[PAYLOAD_PREFIX_BYTES..PAYLOAD_PREFIX_BYTES + encoded_inventory.len()],
            &encoded_inventory[..]
        );
        assert_eq!(
            &plaintext[PAYLOAD_PREFIX_BYTES + encoded_inventory.len()..],
            b"hello"
        );
        assert_eq!(
            verify_backup_archive(&mut std::io::Cursor::new(&archive), &key),
            Ok(inventory.clone())
        );
        assert_eq!(
            verify_backup_archive(&mut std::io::Cursor::new(&archive), &[0x72; 32]),
            Err(BackupArchiveError::Authentication)
        );
        let mut tampered = archive.clone();
        tampered[BACKUP_STREAM_HEADER_BYTES + 16] ^= 1;
        assert_eq!(
            verify_backup_archive(&mut std::io::Cursor::new(&tampered), &key),
            Err(BackupArchiveError::Authentication)
        );
        assert!(
            verify_backup_archive(
                &mut std::io::Cursor::new(&archive[..archive.len() - 1]),
                &key
            )
            .is_err()
        );
        let mut trailing = archive.clone();
        trailing.push(0);
        assert_eq!(
            verify_backup_archive(&mut std::io::Cursor::new(&trailing), &key),
            Err(BackupArchiveError::Trailing)
        );

        let target_parent = root.join("targets");
        let mut targets = Vec::new();
        for index in 0..10 {
            let path = target_parent.join(index.to_string());
            fs::create_dir_all(&path).unwrap();
            targets.push(path);
        }
        let target_refs: [&str; 10] =
            core::array::from_fn(|index| targets[index].to_str().unwrap());
        assert_eq!(
            restore_backup_archive(&mut std::io::Cursor::new(&archive), &key, target_refs),
            Ok(inventory.clone())
        );
        assert_eq!(fs::read(targets[0].join("objects.pack")).unwrap(), b"hello");
        assert_eq!(
            fs::metadata(targets[0].join("objects.pack"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            restore_backup_archive(&mut std::io::Cursor::new(&archive), &key, target_refs),
            Err(BackupArchiveError::TargetNotEmpty)
        );

        let rejected_parent = root.join("rejected-targets");
        let mut rejected = Vec::new();
        for index in 0..10 {
            let path = rejected_parent.join(index.to_string());
            fs::create_dir_all(&path).unwrap();
            rejected.push(path);
        }
        let rejected_refs: [&str; 10] =
            core::array::from_fn(|index| rejected[index].to_str().unwrap());
        assert!(
            restore_backup_archive(&mut std::io::Cursor::new(&tampered), &key, rejected_refs)
                .is_err()
        );
        assert!(
            rejected
                .iter()
                .all(|path| fs::read_dir(path).unwrap().next().is_none())
        );
        fs::remove_dir_all(root).unwrap();
    }
}
