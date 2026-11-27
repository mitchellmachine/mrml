//! Linux USB lease. Discovery is read-only; mutation needs an exclusive live block handle.
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{BYTES, Disk, WriteMode, require_only_usb, transfer};
use crate::usb_image::SECTOR;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Identity {
    node: PathBuf,
    dev: u64,
    generation: u64,
    geometry: Vec<(String, String, String)>,
}

#[cfg(test)]
pub(super) fn test_identity() -> Identity {
    Identity {
        node: PathBuf::new(),
        dev: 0,
        generation: 1,
        geometry: Vec::new(),
    }
}

unsafe extern "C" {
    fn geteuid() -> u32;
    fn ioctl(fd: i32, request: usize, ...) -> i32;
}

pub(super) fn privileged() -> bool {
    // SAFETY: geteuid has no parameters or memory side effects.
    (unsafe { geteuid() }) == 0
}

pub(super) fn elevate(image: &Path) -> io::Result<()> {
    let sudo = ["/usr/bin/sudo", "/bin/sudo"]
        .into_iter()
        .map(Path::new)
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            io::Error::other("sudo is unavailable; run mrml usb burn from a root terminal")
        })?;
    let mrml = std::env::current_exe()?.canonicalize()?;
    let status = Command::new(sudo)
        .arg("--")
        .arg(mrml)
        .args(["usb", "burn"])
        .arg(image)
        .status()?;
    if !status.success() {
        return Err(io::Error::other("elevated USB writer did not complete"));
    }
    Ok(())
}

fn read(path: &Path, field: &str) -> io::Result<String> {
    Ok(fs::read_to_string(path.join(field))?.trim().to_owned())
}

fn linux_dev(value: &str) -> Option<u64> {
    let (major, minor) = value.split_once(':')?;
    let major = major.parse::<u32>().ok()? as u64;
    let minor = minor.parse::<u32>().ok()? as u64;
    Some(
        ((major & 0xfff) << 8)
            | (minor & 0xff)
            | ((minor & !0xff) << 12)
            | ((major & !0xfff) << 32),
    )
}

fn occupied() -> io::Result<BTreeSet<u64>> {
    let info = fs::read_to_string("/proc/self/mountinfo")?;
    let mut known = BTreeSet::new();
    for line in info.lines() {
        let number = line
            .split_ascii_whitespace()
            .nth(2)
            .and_then(linux_dev)
            .ok_or_else(|| io::Error::other("cannot decode the current Linux mount table"))?;
        known.insert(number);
    }
    for line in fs::read_to_string("/proc/swaps")?.lines().skip(1) {
        let path = line
            .split_ascii_whitespace()
            .next()
            .ok_or_else(|| io::Error::other("cannot decode the current swap table"))?;
        let metadata = fs::metadata(path)?;
        known.insert(if metadata.file_type().is_block_device() {
            metadata.rdev()
        } else {
            metadata.dev()
        });
    }
    Ok(known)
}

fn has_holders(node: &Path) -> io::Result<bool> {
    Ok(fs::read_dir(node.join("holders"))?.next().is_some())
}

fn candidate(link: &Path, occupied: &BTreeSet<u64>) -> io::Result<Option<Disk>> {
    let Some(name) = link.file_name().and_then(|name| name.to_str()) else {
        return Ok(None);
    };
    if !name
        .strip_prefix("sd")
        .is_some_and(|tail| !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_lowercase()))
    {
        return Ok(None);
    }
    let node = link.canonicalize()?;
    let usb = node.ancestors().any(|parent| {
        fs::read_link(parent.join("subsystem"))
            .ok()
            .is_some_and(|kind| kind.file_name().is_some_and(|part| part == "usb"))
    });
    if !usb
        || read(&node, "removable")? != "1"
        || read(&node, "ro")? != "0"
        || read(&node, "queue/logical_block_size")? != SECTOR.to_string()
    {
        return Ok(None);
    }
    let capacity = read(&node, "size")?
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(512))
        .unwrap_or(0);
    let generation = read(&node, "diskseq")?.parse::<u64>().unwrap_or(0);
    let dev = linux_dev(&read(&node, "dev")?)
        .ok_or_else(|| io::Error::other("invalid Linux device number"))?;
    if capacity < BYTES as u64 || generation == 0 || occupied.contains(&dev) || has_holders(&node)?
    {
        return Ok(None);
    }
    let mut geometry = Vec::new();
    for child in fs::read_dir(&node)? {
        let child = child?.path();
        if !child.join("partition").is_file() {
            continue;
        }
        let device = read(&child, "dev")?;
        let id = linux_dev(&device)
            .ok_or_else(|| io::Error::other("invalid partition device number"))?;
        if occupied.contains(&id) || has_holders(&child)? {
            return Ok(None);
        }
        geometry.push((device, read(&child, "start")?, read(&child, "size")?));
    }
    geometry.sort();
    let path = PathBuf::from("/dev").join(name);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_block_device() || metadata.rdev() != dev {
        return Ok(None);
    }
    let label = read(&node, "device/model").unwrap_or_else(|_| "USB storage".into());
    let label = match node
        .ancestors()
        .find_map(|p| read(p, "serial").ok().filter(|s| !s.is_empty()))
    {
        Some(serial) => format!("{label} (serial {serial})"),
        None => label,
    };
    Ok(Some(Disk {
        path,
        label,
        capacity,
        identity: Identity {
            node,
            dev,
            generation,
            geometry,
        },
    }))
}

pub(super) fn disks(_erase: bool) -> io::Result<Vec<Disk>> {
    let occupied = occupied()?;
    let mut result = Vec::new();
    for entry in fs::read_dir("/sys/class/block")? {
        if let Ok(Some(disk)) = candidate(&entry?.path(), &occupied) {
            result.push(disk);
        }
    }
    result.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}

fn ioctl_number<const N: usize>(file: &File, request: usize) -> io::Result<[u8; N]> {
    let mut buffer = [0; N];
    // SAFETY: caller only uses fixed-width read ioctls with an output buffer of
    // the exact x86-64 Linux ABI size. The live File owns the block descriptor.
    if unsafe { ioctl(file.as_raw_fd(), request, buffer.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buffer)
}

pub(super) fn usb_storage() -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir("/sys/class/block")? {
        let entry = entry?;
        let node = entry.path().canonicalize()?;
        if node.join("partition").try_exists()? {
            continue;
        }
        for parent in node.ancestors() {
            match fs::read_link(parent.join("subsystem")) {
                Ok(kind) if kind.file_name().is_some_and(|part| part == "usb") => {
                    paths.push(PathBuf::from("/dev").join(entry.file_name()));
                    break;
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(paths)
}

pub(super) fn write_image(disk: &Disk, image: &[u8], mode: WriteMode) -> io::Result<()> {
    if !privileged() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "root needed",
        ));
    }
    const O_EXCL: i32 = 0x80;
    const O_NOFOLLOW: i32 = 0x20000;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(O_EXCL | O_NOFOLLOW)
        .open(&disk.path)?;
    let info = file.metadata()?;
    if !info.file_type().is_block_device()
        || info.rdev() != disk.identity.dev
        || u64::from_ne_bytes(ioctl_number(&file, 0x8008_1280)?) != disk.identity.generation
        || u64::from_ne_bytes(ioctl_number(&file, 0x8008_1272)?) != disk.capacity
        || u32::from_ne_bytes(ioctl_number(&file, 0x1268)?) as usize != SECTOR
        || !disks(false)?.contains(disk)
    {
        return Err(io::Error::other(
            "Linux drive identity or geometry changed; no bytes written",
        ));
    }
    // Linux already admits unmounted boot media; --erase never relaxes its checks.
    if let WriteMode::Auto { erase } = mode {
        let _ = erase;
        require_only_usb(disk, usb_storage)?;
    }
    transfer(&mut file, image, |file| {
        file.sync_all()?;
        // SAFETY: BLKFLSBUF takes no pointer and only flushes the pinned block device.
        if unsafe { ioctl(file.as_raw_fd(), 0x1261) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    })
    .map_err(|error| io::Error::other(format!("USB write or read-back incomplete: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_number_preserves_large_minor() {
        assert_eq!(linux_dev("8:19"), Some(8 * 256 + 19));
        assert_eq!(linux_dev("8:256"), Some(8 * 256 + (256 << 12)));
        assert_eq!(linux_dev("8:x"), None);
    }
}
