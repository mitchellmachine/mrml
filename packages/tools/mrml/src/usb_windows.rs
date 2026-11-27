//! Native Win32 USB discovery and exclusive volume claims.
use super::{BYTES, Disk, require_only_usb, transfer};
use std::ffi::{OsStr, c_void};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Identity {
    number: u32,
    serial: String,
    partitions: Vec<(u64, u64)>,
    volumes: Vec<PathBuf>,
    raw_guid: Option<[u8; 16]>,
}

#[cfg(test)]
pub(super) fn test_identity() -> Identity {
    Identity {
        number: 0,
        serial: "fixture".into(),
        partitions: Vec::new(),
        volumes: Vec::new(),
        raw_guid: None,
    }
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemWindowsDirectoryW(path: *mut u16, capacity: u32) -> u32;
    fn QueryDosDeviceW(name: *const u16, output: *mut u16, capacity: u32) -> u32;
    fn FindFirstVolumeW(name: *mut u16, capacity: u32) -> *mut c_void;
    fn FindNextVolumeW(handle: *mut c_void, name: *mut u16, capacity: u32) -> i32;
    fn FindVolumeClose(handle: *mut c_void) -> i32;
    fn GetDriveTypeW(root: *const u16) -> u32;
    fn DeviceIoControl(
        handle: *mut c_void,
        code: u32,
        input: *const c_void,
        input_len: u32,
        output: *mut c_void,
        output_len: u32,
        actual: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
}
#[link(name = "shell32", kind = "raw-dylib")]
unsafe extern "system" {
    fn IsUserAnAdmin() -> i32;
    fn ShellExecuteW(
        window: *mut c_void,
        verb: *const u16,
        file: *const u16,
        args: *const u16,
        cwd: *const u16,
        show: i32,
    ) -> isize;
}
pub(super) fn privileged() -> bool {
    // SAFETY: no pointers; queries the caller's token.
    (unsafe { IsUserAnAdmin() }) != 0
}
fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain([0]).collect()
}

pub(super) fn elevate(image: &Path) -> io::Result<()> {
    let exe = wide(std::env::current_exe()?.as_os_str());
    let cwd = wide(std::env::current_dir()?.as_os_str());
    let verb = wide("runas".as_ref());
    let path = image
        .to_str()
        .filter(|s| !s.contains('"') && !s.ends_with('\\'))
        .ok_or_else(|| io::Error::other("invalid image path"))?;
    let args = wide(format!("usb burn \"{path}\" --elevated-console").as_ref());
    // SAFETY: all inputs are live, NUL-terminated UTF-16. UAC prompts before launch.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            exe.as_ptr(),
            args.as_ptr(),
            cwd.as_ptr(),
            1,
        )
    };
    if result <= 32 {
        return Err(io::Error::other("Windows elevation failed or was canceled"));
    }
    println!("Continue in the Administrator USB writer window.");
    Ok(())
}

fn system_disk_numbers() -> io::Result<Vec<u32>> {
    let mut directory = [0u16; 1024];
    let capacity = directory.len() as u32;
    let output = directory.as_mut_ptr();
    // SAFETY: size matches the writable caller-owned UTF-16 array.
    let returned = unsafe { GetSystemWindowsDirectoryW(output, capacity) };
    let length = returned as usize;
    if length < 3 || length >= directory.len() || directory[1..3] != [58, 92] {
        return Err(io::Error::other("cannot identify the Windows system disk"));
    }
    let letter = char::from_u32(u32::from(directory[0]))
        .filter(char::is_ascii_alphabetic)
        .ok_or_else(|| io::Error::other("Windows directory does not have a local drive"))?;
    let volume = format!(r"\\.\{}:", letter.to_ascii_uppercase());
    let file = OpenOptions::new()
        .access_mode(0)
        .share_mode(3)
        .open(volume)?;
    Ok(extents(&file)?.into_iter().map(|extent| extent.0).collect())
}

fn disk_numbers() -> io::Result<Vec<u32>> {
    let mut names = vec![0u16; 32768];
    let capacity = names.len() as u32;
    let output = names.as_mut_ptr();
    // SAFETY: null device name requests enumeration; buffer capacity is exact.
    let returned = unsafe { QueryDosDeviceW(std::ptr::null(), output, capacity) };
    let length = returned as usize;
    if length == 0 || length > names.len() {
        return Err(io::Error::last_os_error());
    }
    let prefix: Vec<u16> = "PhysicalDrive".encode_utf16().collect();
    let mut numbers = Vec::new();
    for name in names[..length].split(|&c| c == 0) {
        if let Some(suffix) = name.strip_prefix(prefix.as_slice())
            && let Ok(number) = String::from_utf16_lossy(suffix).parse::<u32>()
            && number < 65536
        {
            numbers.push(number);
        }
    }
    numbers.sort_unstable();
    numbers.dedup();
    Ok(numbers)
}

fn volume_names() -> io::Result<Vec<PathBuf>> {
    let mut buf = [0u16; 64];
    // SAFETY: Windows owns the enumeration handle; writes only within buf.
    let handle = unsafe { FindFirstVolumeW(buf.as_mut_ptr(), buf.len() as u32) };
    if handle == usize::MAX as *mut c_void {
        return Err(io::Error::last_os_error());
    }
    struct Enum(*mut c_void);
    impl Drop for Enum {
        fn drop(&mut self) {
            // SAFETY: close the one successful enumeration handle.
            unsafe { FindVolumeClose(self.0) };
        }
    }
    let guard = Enum(handle);
    let mut names = Vec::new();
    loop {
        let end = buf
            .iter()
            .position(|&c| c == 0)
            .filter(|&end| end > 1 && buf[end - 1] == 92)
            .ok_or_else(|| io::Error::other("malformed Windows volume name"))?;
        let name = String::from_utf16_lossy(&buf[..end - 1]);
        volume_name(&name).ok_or_else(|| io::Error::other("unexpected Windows volume path"))?;
        names.push(PathBuf::from(name));
        if names.len() > 2048 {
            return Err(io::Error::other("too many Windows volumes to validate"));
        }
        buf.fill(0);
        // SAFETY: handle is still owned by guard and buf is writable.
        if unsafe { FindNextVolumeW(guard.0, buf.as_mut_ptr(), buf.len() as u32) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(18) {
                break;
            } // ERROR_NO_MORE_FILES
            return Err(error);
        }
    }
    names.sort();
    Ok(names)
}

fn volume_name(path: &str) -> Option<()> {
    let guid = path.strip_prefix(r"\\?\Volume{")?.strip_suffix('}')?;
    (guid.len() == 36
        && guid.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        }))
    .then_some(())
}

type Extent = (u32, u64, u64);

fn extents(file: &File) -> io::Result<Vec<Extent>> {
    let mut data = [0; 8 + 24 * 128];
    let length = control(file, 0x560000, &[], &mut data)?;
    if length < 8 {
        return Err(io::Error::other("truncated volume extent data"));
    }
    let count = u32_at(&data, 0) as usize;
    if count == 0 || count > 128 || length < 8 + count * 24 {
        return Err(io::Error::other("unrecognized volume extent data"));
    }
    Ok(data[8..8 + count * 24]
        .as_chunks::<24>()
        .0
        .iter()
        .map(|row| (u32_at(row, 0), u64_at(row, 8), u64_at(row, 16)))
        .collect())
}

fn volume_inventory() -> io::Result<Vec<(PathBuf, Vec<Extent>)>> {
    let mut result = Vec::new();
    for name in volume_names()? {
        let mut root = wide(name.as_os_str());
        let end = root.len() - 1;
        root[end] = 92;
        root.push(0);
        // SAFETY: exact NUL-terminated volume root from the system enumerator.
        if matches!(unsafe { GetDriveTypeW(root.as_ptr()) }, 4..=6) {
            continue;
        }
        let volume = OpenOptions::new()
            .access_mode(0)
            .share_mode(3)
            .open(&name)?;
        result.push((name, extents(&volume)?));
    }
    Ok(result)
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("checked ABI length"))
}

fn partitions(data: &[u8], capacity: u64, owned: bool) -> io::Result<Vec<(u64, u64)>> {
    const EFI: [u8; 16] = [
        0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9,
        0x3b,
    ];
    if data.len() < 48 {
        return Err(io::Error::other("truncated partition table"));
    }
    let style = u32_at(data, 0);
    let count = u32_at(data, 4) as usize;
    if style > 2 || count > 128 || data.len() < 48 + count * 144 {
        return Err(io::Error::other("unrecognized Windows partition table"));
    }
    let mut occupied = Vec::new();
    for row in data[48..48 + count * 144].as_chunks::<144>().0 {
        let start = u64_at(row, 8);
        let span = u64_at(row, 16);
        if span == 0 || u32_at(row, 24) == 0 {
            continue;
        }
        if start.checked_add(span).is_none_or(|end| end > capacity)
            || u32_at(row, 0) != style
            || (row[29] != 0 && !owned)
            || (style == 0 && (row[33] != 0 || (row[32] == 0xef && !owned)))
            || (style == 1 && row[32..48] == EFI)
        {
            return Err(io::Error::other(
                "disk has an EFI, active, service, or invalid partition",
            ));
        }
        occupied.push((start, span));
    }
    occupied.sort_unstable();
    Ok(occupied)
}

fn open(path: &Path, write: bool, flags: u32) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(write)
        .share_mode(3)
        .custom_flags(flags)
        .open(path)
}
fn control(file: &File, code: u32, input: &[u8], output: &mut [u8]) -> io::Result<usize> {
    let mut actual = 0;
    // SAFETY: synchronous ABI; File owns the open handle and slices match lengths.
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            if input.is_empty() {
                std::ptr::null()
            } else {
                input.as_ptr().cast()
            },
            input.len() as u32,
            if output.is_empty() {
                std::ptr::null_mut()
            } else {
                output.as_mut_ptr().cast()
            },
            output.len() as u32,
            &mut actual,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if actual as usize > output.len() {
        return Err(io::Error::other("invalid IOCTL reply length"));
    }
    Ok(actual as usize)
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("checked ABI length"),
    )
}

fn inspect(file: &File, number: u32) -> io::Result<Disk> {
    let mut device = [0; 12];
    let mut length = [0; 8];
    let mut geometry = [0; 24];
    if control(file, 0x2d1080, &[], &mut device)? != 12
        || u32_at(&device, 0) != 7
        || u32_at(&device, 4) != number
        || !matches!(u32_at(&device, 8), 0 | u32::MAX)
        || control(file, 0x7405c, &[], &mut length)? != 8
        || control(file, 0x70000, &[], &mut geometry)? != 24
        || u32_at(&geometry, 20) != 512
    {
        return Err(io::Error::other(
            "not a whole disk with 512-byte logical sectors",
        ));
    }
    let capacity = u64::from_le_bytes(length);
    if capacity < BYTES as u64 {
        return Err(io::Error::other("USB device too small"));
    }
    let mut props = [0; 4096];
    let n = control(file, 0x2d1400, &[0; 12], &mut props)?;
    if n < 36 || props[10] != 1 || u32_at(&props, 28) != 7 {
        return Err(io::Error::other("not removable USB storage"));
    }
    let text = |at| {
        let start = u32_at(&props, at) as usize;
        let text = props.get(start..n).filter(|_| start >= 36)?;
        let end = text.iter().position(|&b| b == 0)?;
        let value = std::str::from_utf8(&text[..end]).ok()?.trim();
        (!value.is_empty()).then_some(value)
    };
    let serial = text(24)
        .ok_or_else(|| io::Error::other("USB does not have a stable serial"))?
        .to_owned();
    let label = format!("{} (serial {serial})", text(16).unwrap_or("USB drive"));
    control(file, 0x70024, &[], &mut [])?; // IOCTL_DISK_IS_WRITABLE
    let mut info = [0; 48 + 144 * 128];
    let count = control(file, 0x70050, &[], &mut info)?;
    let layout = &info[..count];
    let partitions = match partitions(layout, capacity, false) {
        Ok(partitions) => partitions,
        Err(err) => {
            // The only exception to unknown EFI/service partitions is the
            // exact MRML MBR; never admit an active or GPT EFI partition.
            let mut block = Box::new(Aligned([0; 65536]));
            let mut view = file;
            view.seek(SeekFrom::Start(0))?;
            view.read_exact(&mut block.0[..512])?;
            view.seek(SeekFrom::Start(0))?;
            if block.0[..512] != crate::usb_image::partition_table() {
                return Err(err);
            }
            partitions(layout, capacity, true)?
        }
    };
    let mut extended = [0; 40];
    let raw_guid = match control(file, 0x2d1084, &[], &mut extended) {
        Ok(40) if u32_at(&extended, 12) == 7 && u32_at(&extended, 16) == number => {
            let guid: [u8; 16] = extended[20..36].try_into().expect("fixed GUID field");
            (guid != [0; 16]).then_some(guid)
        }
        Err(err) if matches!(err.raw_os_error(), Some(1 | 50)) => None,
        _ => return Err(io::Error::other("cannot verify Windows USB instance")),
    };
    Ok(Disk {
        path: physical_path(number),
        label,
        capacity,
        identity: Identity {
            number,
            serial,
            partitions,
            volumes: Vec::new(),
            raw_guid,
        },
    })
}

fn physical_path(number: u32) -> PathBuf {
    PathBuf::from(format!(r"\\.\PhysicalDrive{number}"))
}

pub(super) fn usb_storage() -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for number in disk_numbers()? {
        let path = physical_path(number);
        // Query transport without read/write access to the medium. Count USB
        // storage even if its layout, writability or identity makes it ineligible.
        let file = OpenOptions::new()
            .access_mode(0)
            .share_mode(3)
            .open(&path)?;
        let mut props = [0; 4096];
        let count = control(&file, 0x2d1400, &[0; 12], &mut props)?;
        if count < 36 || u32_at(&props, 28) == 0 {
            return Err(io::Error::other(
                "cannot classify Windows disk transport; no bytes written",
            ));
        }
        if u32_at(&props, 28) == 7 {
            paths.push(path);
        }
    }
    Ok(paths)
}

pub(super) fn disks() -> io::Result<Vec<Disk>> {
    let mut disks = Vec::new();
    for number in disk_numbers()? {
        if let Ok(disk) = open(&physical_path(number), false, 0).and_then(|f| inspect(&f, number)) {
            disks.push(disk);
        }
    }
    if disks.is_empty() {
        return Ok(disks);
    }
    let protected = system_disk_numbers()?;
    let volumes = volume_inventory()?;
    disks.retain_mut(|disk| {
        let id = &mut disk.identity;
        if protected.contains(&id.number) {
            return false;
        }
        for (path, extents) in &volumes {
            if !extents.iter().any(|e| e.0 == id.number) {
                continue;
            }
            let [(_, base, length)] = extents.as_slice() else {
                return false;
            };
            // A filesystem directly on a removable disk ("superfloppy") can
            // legitimately occupy the entire disk without a partition table.
            if !id.partitions.contains(&(*base, *length))
                && !(id.partitions.is_empty() && *base == 0 && *length == disk.capacity)
            {
                return false;
            }
            id.volumes.push(path.clone());
        }
        id.volumes.sort();
        true
    });
    let duplicates: Vec<u32> = disks
        .iter()
        .filter(|disk| {
            disks
                .iter()
                .filter(|other| {
                    other.identity.serial == disk.identity.serial
                        || disk.identity.raw_guid.is_some()
                            && other.identity.raw_guid == disk.identity.raw_guid
                })
                .count()
                > 1
        })
        .map(|disk| disk.identity.number)
        .collect();
    disks.retain(|disk| !duplicates.contains(&disk.identity.number));
    Ok(disks)
}

fn same_handle(file: &File, selected: &Disk) -> io::Result<bool> {
    let mut observed = inspect(file, selected.identity.number)?;
    observed
        .identity
        .volumes
        .clone_from(&selected.identity.volumes);
    Ok(observed == *selected)
}

const DIRECT: u32 = 0xa000_0000; // NO_BUFFERING | WRITE_THROUGH

pub(super) fn write_image(disk: &Disk, image: &[u8], only_usb: bool) -> io::Result<()> {
    if !privileged() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Administrator needed",
        ));
    }
    let file = open(&disk.path, true, DIRECT)?;
    let before = volume_names()?;
    if !disks()?.contains(disk) || !same_handle(&file, disk)? {
        return Err(io::Error::other("USB instance changed; no bytes written"));
    }
    let mut locks = Vec::new();
    for volume in &disk.identity.volumes {
        let handle = open(volume, true, 0)?;
        let spans = extents(&handle)?;
        if !matches!(spans.as_slice(), [(number, base, length)] if *number == disk.identity.number
            && (disk.identity.partitions.contains(&(*base, *length))
                || (disk.identity.partitions.is_empty() && *base == 0 && *length == disk.capacity)))
        {
            return Err(io::Error::other(
                "volume is not exclusive to the selected USB drive",
            ));
        }
        control(&handle, 0x90018, &[], &mut [])?; // FSCTL_LOCK_VOLUME
        locks.push(handle);
    }
    // Do not reopen a locked volume. Confirm its exact handle above, and
    // ensure the volume set and physical layout did not change in the interim.
    if volume_names()? != before || !same_handle(&file, disk)? {
        return Err(io::Error::other("USB layout changed; no bytes written"));
    }
    if only_usb {
        require_only_usb(disk, usb_storage)?;
    }
    for lock in &locks {
        control(lock, 0x90020, &[], &mut [])?;
    } // dismount only held volumes
    let mut raw = Raw::new(file);
    let result = transfer(&mut raw, image, |d| d.file.sync_all())
        .map_err(|err| io::Error::other(format!("USB write or read-back incomplete: {err}")));
    drop(locks);
    result
}

#[repr(align(4096))]
struct Aligned([u8; 65536]);
struct Raw {
    file: File,
    buffer: Box<Aligned>,
}
impl Raw {
    fn new(file: File) -> Self {
        Self {
            file,
            buffer: Box::new(Aligned([0; 65536])),
        }
    }
}
impl Read for Raw {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let length = out.len().min(self.buffer.0.len());
        let count = self.file.read(&mut self.buffer.0[..length])?;
        out[..count].copy_from_slice(&self.buffer.0[..count]);
        Ok(count)
    }
}
impl Write for Raw {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let length = input.len().min(self.buffer.0.len());
        self.buffer.0[..length].copy_from_slice(&input[..length]);
        self.file.write(&self.buffer.0[..length])
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
impl Seek for Raw {
    fn seek(&mut self, where_: SeekFrom) -> io::Result<u64> {
        self.file.seek(where_)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protects_system_partition_and_accepts_only_volume_guid_paths() {
        assert!(volume_name(r"\\?\Volume{11111111-1111-1111-1111-111111111111}").is_some());
        assert!(volume_name(r"C:\").is_none());
        let mut layout = [0u8; 48 + 144];
        layout[4] = 1;
        layout[56..64].copy_from_slice(&1024u64.to_le_bytes());
        layout[64..72].copy_from_slice(&4096u64.to_le_bytes());
        layout[72] = 1;
        layout[80] = 0x0c;
        assert_eq!(partitions(&layout, 8192, false).unwrap(), [(1024, 4096)]);
        layout[80] = 0xef;
        assert!(partitions(&layout, 8192, false).is_err());
        assert!(partitions(&layout, 8192, true).is_ok());
        layout[81] = 1;
        assert!(partitions(&layout, 8192, true).is_err());
    }
    #[test]
    fn unbuffered_transfer_uses_an_aligned_buffer() {
        let stage = super::super::Scratch::new().unwrap();
        let path = stage.path("test.bin");
        File::create_new(&path)
            .unwrap()
            .set_len(2 * 1024 * 1024)
            .unwrap();
        let image = vec![0xa7; 2 * 1024 * 1024];
        let mut raw = Raw::new(open(&path, true, DIRECT).unwrap());
        transfer(&mut raw, &image, |d| d.file.sync_all()).unwrap();
        drop(raw);
        assert_eq!(std::fs::read(path).unwrap(), image);
    }
}
