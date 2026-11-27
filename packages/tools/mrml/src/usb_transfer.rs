use std::io::{self, Read, SeekFrom, Write};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Disk<I> {
    pub(crate) path: PathBuf,
    pub(crate) label: String,
    pub(crate) capacity: u64,
    pub(crate) identity: I,
}

#[derive(Clone, Copy)]
pub(crate) enum WriteMode {
    Manual,
    Auto { erase: bool },
}

pub(crate) fn require_only_usb<I>(
    selected: &Disk<I>,
    connected: impl FnOnce() -> io::Result<Vec<PathBuf>>,
) -> io::Result<()> {
    if connected()?.as_slice() != std::slice::from_ref(&selected.path) {
        return Err(io::Error::other("USB inventory changed; no bytes written"));
    }
    Ok(())
}

pub(crate) fn transfer<T: Read + Write + std::io::Seek>(
    disk: &mut T,
    image: &[u8],
    flush_media: impl FnOnce(&mut T) -> io::Result<()>,
) -> io::Result<()> {
    const CHUNK: usize = 1024 * 1024;
    for block in image.chunks(CHUNK) {
        disk.write_all(block)?;
    }
    flush_media(disk)?;
    disk.seek(SeekFrom::Start(0))?;
    let mut readback = vec![0; CHUNK];
    for (index, block) in image.chunks(CHUNK).enumerate() {
        disk.read_exact(&mut readback[..block.len()])?;
        if readback[..block.len()] != *block {
            return Err(io::Error::other(format!(
                "USB verification failed at byte {}",
                index * CHUNK
            )));
        }
    }
    Ok(())
}
