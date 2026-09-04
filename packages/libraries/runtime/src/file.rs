use crate::{Text, Vector};
use core::fmt;
use core::ptr::NonNull;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileError {
    InvalidPath,
    OpenFailed,
    ReadFailed,
    UnexpectedEnd,
    SeekFailed,
    MetadataFailed,
    InvalidUtf8,
    WriteFailed,
    DirectoryFailed,
    RemoveFailed,
    RenameFailed,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryMetadata {
    pub inode: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub links: u64,
    pub device: u64,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileMetadata {
    pub inode: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub links: u64,
    pub device: u64,
}

/// A retained Linux directory authority. Descendants are resolved by the
/// kernel beneath this descriptor and never converted back into ambient paths.
#[cfg(target_os = "linux")]
pub struct DirectoryCapability {
    inner: mrml_linux::NativeDirectory,
}

#[cfg(target_os = "linux")]
impl DirectoryCapability {
    pub fn try_clone(&self) -> Result<Self, FileError> {
        let inner = self.inner.try_clone().ok_or(FileError::OpenFailed)?;
        Ok(Self { inner })
    }

    pub fn open_root(path: &str) -> Result<Self, FileError> {
        if !path_is_absolute(path) {
            return Err(FileError::InvalidPath);
        }
        let encoded = encode_unix_path(path).ok_or(FileError::InvalidPath)?;
        let path =
            core::ffi::CStr::from_bytes_with_nul(&encoded).map_err(|_| FileError::InvalidPath)?;
        let inner = mrml_linux::NativeDirectory::open_root(path).ok_or(FileError::OpenFailed)?;
        Ok(Self { inner })
    }

    pub fn open_directory(&self, relative: &str) -> Result<Self, FileError> {
        validate_relative_capability_path(relative)?;
        let encoded = encode_unix_path(relative).ok_or(FileError::InvalidPath)?;
        let relative =
            core::ffi::CStr::from_bytes_with_nul(&encoded).map_err(|_| FileError::InvalidPath)?;
        let inner = self
            .inner
            .open_beneath(relative)
            .ok_or(FileError::OpenFailed)?;
        Ok(Self { inner })
    }

    pub fn open_regular(&self, relative: &str) -> Result<File, FileError> {
        validate_relative_capability_path(relative)?;
        let encoded = encode_unix_path(relative).ok_or(FileError::InvalidPath)?;
        let relative =
            core::ffi::CStr::from_bytes_with_nul(&encoded).map_err(|_| FileError::InvalidPath)?;
        let inner = self
            .inner
            .open_regular_beneath(relative)
            .ok_or(FileError::OpenFailed)?;
        Ok(File { inner, position: 0 })
    }

    pub fn create_new_file(&self, name: &str, mode: u32) -> Result<File, FileError> {
        validate_capability_child_name(name)?;
        let encoded = encode_unix_path(name).ok_or(FileError::InvalidPath)?;
        let name =
            core::ffi::CStr::from_bytes_with_nul(&encoded).map_err(|_| FileError::InvalidPath)?;
        let inner = self
            .inner
            .create_file(name, mode)
            .ok_or(FileError::OpenFailed)?;
        Ok(File { inner, position: 0 })
    }

    pub fn rename_child(&self, existing: &str, replacement: &str) -> Result<(), FileError> {
        validate_capability_child_name(existing)?;
        validate_capability_child_name(replacement)?;
        let existing = encode_unix_path(existing).ok_or(FileError::InvalidPath)?;
        let replacement = encode_unix_path(replacement).ok_or(FileError::InvalidPath)?;
        let existing =
            core::ffi::CStr::from_bytes_with_nul(&existing).map_err(|_| FileError::InvalidPath)?;
        let replacement = core::ffi::CStr::from_bytes_with_nul(&replacement)
            .map_err(|_| FileError::InvalidPath)?;
        self.inner
            .rename_child(existing, replacement)
            .then_some(())
            .ok_or(FileError::RenameFailed)
    }

    pub fn remove_file(&self, name: &str) -> Result<(), FileError> {
        validate_capability_child_name(name)?;
        let encoded = encode_unix_path(name).ok_or(FileError::InvalidPath)?;
        let name =
            core::ffi::CStr::from_bytes_with_nul(&encoded).map_err(|_| FileError::InvalidPath)?;
        self.inner
            .remove_file(name)
            .then_some(())
            .ok_or(FileError::RemoveFailed)
    }

    pub fn sync(&self) -> Result<(), FileError> {
        self.inner
            .sync()
            .then_some(())
            .ok_or(FileError::WriteFailed)
    }

    pub fn metadata(&self) -> Result<DirectoryMetadata, FileError> {
        let metadata = self.inner.metadata().ok_or(FileError::MetadataFailed)?;
        Ok(DirectoryMetadata {
            inode: metadata.inode,
            mode: metadata.mode,
            uid: metadata.uid,
            gid: metadata.gid,
            links: metadata.links,
            device: metadata.device,
        })
    }
}

#[cfg(target_os = "linux")]
fn validate_relative_capability_path(path: &str) -> Result<(), FileError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\0')
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(FileError::InvalidPath);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_capability_child_name(name: &str) -> Result<(), FileError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(FileError::InvalidPath);
    }
    Ok(())
}

pub struct DirectoryEntry {
    pub name: Text,
    pub is_directory: bool,
    pub is_symlink: bool,
}

pub struct MappedFile {
    _file: File,
    address: NonNull<u8>,
    length: usize,
    mapped: bool,
}

impl MappedFile {
    pub fn open_bounded(path: &str, limit: usize) -> Result<Self, FileError> {
        let file = File::open(path)?;
        let length = usize::try_from(file.len()?).map_err(|_| FileError::ReadFailed)?;
        if length > limit {
            return Err(FileError::ReadFailed);
        }
        if length == 0 {
            return Ok(Self {
                _file: file,
                address: NonNull::dangling(),
                length,
                mapped: false,
            });
        }
        #[cfg(windows)]
        let address = unsafe { mrml_windows::map_file_read_only(file.raw_handle(), length) };
        #[cfg(unix)]
        let address = unsafe { mrml_linux::map_file_read_only(file.raw_fd(), length) };
        Ok(Self {
            _file: file,
            address: address.ok_or(FileError::ReadFailed)?,
            length,
            mapped: true,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.address.as_ptr(), self.length) }
    }
}

impl AsRef<[u8]> for MappedFile {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}

impl core::ops::Deref for MappedFile {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes()
    }
}

impl Drop for MappedFile {
    fn drop(&mut self) {
        if self.mapped {
            #[cfg(windows)]
            let unmapped = unsafe { mrml_windows::unmap_file(self.address, self.length) };
            #[cfg(unix)]
            let unmapped = unsafe { mrml_linux::unmap_file(self.address, self.length) };
            debug_assert!(unmapped);
        }
    }
}

pub fn read_file(path: &str) -> Result<Vector<u8>, FileError> {
    read_file_bounded(path, usize::MAX)
}

pub fn read_file_bounded(path: &str, limit: usize) -> Result<Vector<u8>, FileError> {
    let mut file = File::open(path)?;
    let (mut bytes, expected_length) = match file.len() {
        Ok(length) => {
            let length = usize::try_from(length).map_err(|_| FileError::ReadFailed)?;
            if length > limit {
                return Err(FileError::ReadFailed);
            }
            (
                Vector::with_capacity(length).map_err(|_| FileError::ReadFailed)?,
                Some(length),
            )
        }
        Err(_) => (Vector::new(), None),
    };
    if let Some(length) = expected_length {
        bytes.resize(length, 0);
        file.read_exact(&mut bytes)?;
    }
    let mut chunk = [0u8; 8192];
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        if bytes
            .len()
            .checked_add(read)
            .is_none_or(|length| length > limit)
        {
            return Err(FileError::ReadFailed);
        }
        bytes
            .try_extend_from_slice(&chunk[..read])
            .map_err(|_| FileError::ReadFailed)?;
    }
    Ok(bytes)
}

pub fn read_file_text(path: &str) -> Result<Text, FileError> {
    Text::try_from_utf8(read_file(path)?).map_err(|_| FileError::InvalidUtf8)
}

pub fn read_file_text_bounded(path: &str, limit: usize) -> Result<Text, FileError> {
    Text::try_from_utf8(read_file_bounded(path, limit)?).map_err(|_| FileError::InvalidUtf8)
}

pub fn write_file(path: &str, contents: &[u8]) -> Result<(), FileError> {
    let mut file = File::create(path)?;
    file.write_all(contents)
}

/// Creates and writes a file only if no filesystem entry already has `path`.
pub fn write_new_file(path: &str, contents: &[u8]) -> Result<(), FileError> {
    let mut file = File::create_new(path)?;
    let result = file.write_all(contents);
    drop(file);
    if result.is_err() {
        let _ = remove_file(path);
    }
    result
}

/// Creates a new private file with platform owner-only policy, writes it
/// durably, and erases the caller's secret buffer on every return path.
pub fn write_secret_file(path: &str, contents: &mut [u8]) -> Result<(), FileError> {
    let mut created = false;
    let result = (|| {
        #[cfg(windows)]
        let inner = {
            let encoded = encode_windows_path(path).ok_or(FileError::InvalidPath)?;
            mrml_windows::NativeFile::create_secret(&encoded).ok_or(FileError::OpenFailed)?
        };
        #[cfg(unix)]
        let inner = {
            let encoded = encode_unix_path(path).ok_or(FileError::InvalidPath)?;
            let path = core::ffi::CStr::from_bytes_with_nul(&encoded)
                .map_err(|_| FileError::InvalidPath)?;
            mrml_linux::NativeFile::create_secret(path).ok_or(FileError::OpenFailed)?
        };
        created = true;
        let mut file = File { inner, position: 0 };
        file.write_all(contents)?;
        file.inner
            .sync()
            .then_some(())
            .ok_or(FileError::WriteFailed)
    })();
    contents.fill(0);
    if created && result.is_err() {
        let _ = remove_file(path);
    }
    result
}

impl fmt::Display for FileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPath => "invalid file path",
            Self::OpenFailed => "failed to open file",
            Self::ReadFailed => "failed to read file",
            Self::UnexpectedEnd => "unexpected end of file",
            Self::SeekFailed => "failed to seek file",
            Self::MetadataFailed => "failed to read file metadata",
            Self::InvalidUtf8 => "file is not valid UTF-8 text",
            Self::WriteFailed => "failed to write file",
            Self::DirectoryFailed => "failed to create directory",
            Self::RemoveFailed => "failed to remove file",
            Self::RenameFailed => "failed to rename file",
        })
    }
}

#[cfg(windows)]
fn encode_windows_path(path: &str) -> Option<Vector<u16>> {
    let mut encoded = Vector::with_capacity(path.len() + 1).ok()?;
    encoded.extend(path.encode_utf16());
    encoded.push(0);
    Some(encoded)
}

#[cfg(unix)]
fn encode_unix_path(path: &str) -> Option<Vector<u8>> {
    if path.as_bytes().contains(&0) {
        return None;
    }
    let mut encoded = Vector::with_capacity(path.len() + 1).ok()?;
    encoded.try_extend_from_slice(path.as_bytes()).ok()?;
    encoded.push(0);
    Some(encoded)
}

pub fn path_is_directory(path: &str) -> bool {
    #[cfg(windows)]
    {
        encode_windows_path(path).is_some_and(|path| mrml_windows::wide_path_is_directory(&path))
    }
    #[cfg(unix)]
    {
        encode_unix_path(path).is_some_and(|path| {
            core::ffi::CStr::from_bytes_with_nul(&path).is_ok_and(mrml_linux::path_is_directory)
        })
    }
}

pub fn path_is_file(path: &str) -> bool {
    #[cfg(windows)]
    {
        encode_windows_path(path).is_some_and(|path| mrml_windows::wide_path_is_file(&path))
    }
    #[cfg(unix)]
    {
        encode_unix_path(path).is_some_and(|path| {
            core::ffi::CStr::from_bytes_with_nul(&path).is_ok_and(mrml_linux::path_is_file)
        })
    }
}

pub fn path_exists(path: &str) -> bool {
    path_is_directory(path) || path_is_file(path)
}

pub fn path_is_absolute(path: &str) -> bool {
    if cfg!(windows) {
        path.starts_with(['/', '\\'])
            || (path.as_bytes().get(1) == Some(&b':')
                && path
                    .as_bytes()
                    .get(2)
                    .is_some_and(|byte| matches!(byte, b'/' | b'\\')))
    } else {
        path.starts_with('/')
    }
}

pub fn join_path(base: &str, child: &str) -> Text {
    if path_is_absolute(child) || base.is_empty() {
        return child.into();
    }
    let mut joined = Text::from(base.trim_end_matches(['/', '\\']));
    if !joined.is_empty() {
        joined.push(if cfg!(windows) { '\\' } else { '/' });
    }
    joined.push_str(child.trim_start_matches(['/', '\\']));
    joined
}

pub fn parent_path(path: &str) -> Option<&str> {
    let trimmed = path.trim_end_matches(['/', '\\']);
    let split = trimmed.rfind(['/', '\\'])?;
    if split == 0 {
        Some(&trimmed[..1])
    } else {
        Some(&trimmed[..split])
    }
}

pub fn canonical_path(path: &str) -> Result<Text, FileError> {
    #[cfg(windows)]
    {
        let encoded = encode_windows_path(path).ok_or(FileError::InvalidPath)?;
        const MAX_WINDOWS_PATH_UNITS: usize = 32_768;
        let mut output =
            Vector::with_capacity(MAX_WINDOWS_PATH_UNITS).map_err(|_| FileError::MetadataFailed)?;
        output.resize(MAX_WINDOWS_PATH_UNITS, 0);
        let length =
            mrml_windows::full_path_wide(&encoded, &mut output).ok_or(FileError::MetadataFailed)?;
        let mut result = Text::new();
        for character in core::char::decode_utf16(output[..length].iter().copied()) {
            result.push(character.map_err(|_| FileError::InvalidUtf8)?);
        }
        Ok(result)
    }
    #[cfg(unix)]
    {
        let encoded = encode_unix_path(path).ok_or(FileError::InvalidPath)?;
        let encoded =
            core::ffi::CStr::from_bytes_with_nul(&encoded).map_err(|_| FileError::InvalidPath)?;
        let mut output = [0u8; 4096];
        let path =
            mrml_linux::canonical_path(encoded, &mut output).ok_or(FileError::MetadataFailed)?;
        Text::try_from_str(core::str::from_utf8(path).map_err(|_| FileError::InvalidUtf8)?)
            .map_err(|_| FileError::MetadataFailed)
    }
}

pub fn create_dir_all(path: &str) -> Result<(), FileError> {
    let path = path.trim_end_matches(['/', '\\']);
    if path.is_empty() || path == "/" || path.ends_with(':') || path_is_directory(path) {
        return Ok(());
    }
    if let Some(split) = path.rfind(['/', '\\']) {
        let parent = &path[..split];
        if !parent.is_empty() && parent != path {
            create_dir_all(parent)?;
        }
    }
    #[cfg(windows)]
    let created =
        encode_windows_path(path).is_some_and(|path| mrml_windows::create_directory_wide(&path));
    #[cfg(unix)]
    let created = encode_unix_path(path).is_some_and(|path| {
        core::ffi::CStr::from_bytes_with_nul(&path).is_ok_and(mrml_linux::create_directory)
    });
    created.then_some(()).ok_or(FileError::DirectoryFailed)
}

pub fn remove_file(path: &str) -> Result<(), FileError> {
    #[cfg(windows)]
    let removed =
        encode_windows_path(path).is_some_and(|path| mrml_windows::delete_file_wide(&path));
    #[cfg(unix)]
    let removed = encode_unix_path(path).is_some_and(|path| {
        core::ffi::CStr::from_bytes_with_nul(&path).is_ok_and(mrml_linux::delete_file)
    });
    removed.then_some(()).ok_or(FileError::RemoveFailed)
}

fn remove_directory(path: &str) -> Result<(), FileError> {
    #[cfg(windows)]
    let removed =
        encode_windows_path(path).is_some_and(|path| mrml_windows::remove_directory_wide(&path));
    #[cfg(unix)]
    let removed = encode_unix_path(path).is_some_and(|path| {
        core::ffi::CStr::from_bytes_with_nul(&path).is_ok_and(mrml_linux::remove_directory)
    });
    removed.then_some(()).ok_or(FileError::RemoveFailed)
}

pub fn remove_dir_all(path: &str) -> Result<(), FileError> {
    for entry in read_directory(path)? {
        let mut child = Text::from(path.trim_end_matches(['/', '\\']));
        if !child.is_empty() && !child.ends_with(['/', '\\']) {
            child.push(if cfg!(windows) { '\\' } else { '/' });
        }
        child.push_str(&entry.name);
        if entry.is_directory && !entry.is_symlink {
            remove_dir_all(&child)?;
        } else if entry.is_directory {
            remove_directory(&child)?;
        } else {
            remove_file(&child)?;
        }
    }
    remove_directory(path)
}

pub fn rename_file(existing: &str, replacement: &str) -> Result<(), FileError> {
    #[cfg(windows)]
    let renamed = encode_windows_path(existing)
        .zip(encode_windows_path(replacement))
        .is_some_and(|(existing, replacement)| {
            mrml_windows::rename_file_wide(&existing, &replacement)
        });
    #[cfg(unix)]
    let renamed = encode_unix_path(existing)
        .zip(encode_unix_path(replacement))
        .is_some_and(|(existing, replacement)| {
            core::ffi::CStr::from_bytes_with_nul(&existing).is_ok_and(|existing| {
                core::ffi::CStr::from_bytes_with_nul(&replacement)
                    .is_ok_and(|replacement| mrml_linux::rename_file(existing, replacement))
            })
        });
    renamed.then_some(()).ok_or(FileError::RenameFailed)
}

pub fn read_directory(path: &str) -> Result<Vector<DirectoryEntry>, FileError> {
    let mut entries = Vector::new();
    #[cfg(windows)]
    {
        let mut pattern = encode_windows_path(path).ok_or(FileError::InvalidPath)?;
        pattern.pop();
        if !path.ends_with(['/', '\\']) {
            pattern.push('\\' as u16);
        }
        pattern.push('*' as u16);
        pattern.push(0);
        let mut directory =
            mrml_windows::NativeDirectory::open(&pattern).ok_or(FileError::DirectoryFailed)?;
        let mut wide_name = [0u16; 260];
        while let Some((length, is_directory, is_symlink)) = directory.next(&mut wide_name) {
            let mut name = Text::new();
            for character in core::char::decode_utf16(wide_name[..length].iter().copied()) {
                name.push(character.map_err(|_| FileError::InvalidUtf8)?);
            }
            if name != "." && name != ".." {
                entries.push(DirectoryEntry {
                    name,
                    is_directory,
                    is_symlink,
                });
            }
        }
    }
    #[cfg(unix)]
    {
        let encoded = encode_unix_path(path).ok_or(FileError::InvalidPath)?;
        let path =
            core::ffi::CStr::from_bytes_with_nul(&encoded).map_err(|_| FileError::InvalidPath)?;
        let mut directory =
            mrml_linux::NativeDirectory::open(path).ok_or(FileError::DirectoryFailed)?;
        let mut name_buffer = [0u8; 256];
        while let Some((name, is_directory, is_symlink)) = directory.next(&mut name_buffer) {
            let name = core::str::from_utf8(name).map_err(|_| FileError::InvalidUtf8)?;
            if name != "." && name != ".." {
                entries.push(DirectoryEntry {
                    name: name.into(),
                    is_directory,
                    is_symlink,
                });
            }
        }
    }
    Ok(entries)
}

#[cfg(unix)]
pub fn sync_directory(path: &str) -> Result<(), FileError> {
    let encoded = encode_unix_path(path).ok_or(FileError::InvalidPath)?;
    let path =
        core::ffi::CStr::from_bytes_with_nul(&encoded).map_err(|_| FileError::InvalidPath)?;
    let directory = mrml_linux::NativeDirectory::open(path).ok_or(FileError::DirectoryFailed)?;
    directory.sync().then_some(()).ok_or(FileError::WriteFailed)
}
impl core::error::Error for FileError {}

pub struct File {
    #[cfg(windows)]
    inner: mrml_windows::NativeFile,
    #[cfg(unix)]
    inner: mrml_linux::NativeFile,
    position: u64,
}

impl File {
    pub fn open(path: &str) -> Result<Self, FileError> {
        #[cfg(windows)]
        {
            let mut encoded =
                Vector::with_capacity(path.len() + 1).map_err(|_| FileError::OpenFailed)?;
            for unit in path.encode_utf16() {
                encoded.push(unit);
            }
            encoded.push(0);
            let inner =
                mrml_windows::NativeFile::open_read(&encoded).ok_or(FileError::OpenFailed)?;
            Ok(Self { inner, position: 0 })
        }
        #[cfg(unix)]
        {
            if path.as_bytes().contains(&0) {
                return Err(FileError::InvalidPath);
            }
            let mut encoded =
                Vector::with_capacity(path.len() + 1).map_err(|_| FileError::OpenFailed)?;
            encoded
                .try_extend_from_slice(path.as_bytes())
                .map_err(|_| FileError::OpenFailed)?;
            encoded.push(0);
            let path = core::ffi::CStr::from_bytes_with_nul(&encoded)
                .map_err(|_| FileError::InvalidPath)?;
            let inner = mrml_linux::NativeFile::open_read(path).ok_or(FileError::OpenFailed)?;
            Ok(Self { inner, position: 0 })
        }
    }

    /// Opens an existing regular file without following a final path link.
    pub fn open_regular(path: &str) -> Result<Self, FileError> {
        #[cfg(windows)]
        let inner = {
            let encoded = encode_windows_path(path).ok_or(FileError::InvalidPath)?;
            mrml_windows::NativeFile::open_regular_read(&encoded).ok_or(FileError::OpenFailed)?
        };
        #[cfg(unix)]
        let inner = {
            let encoded = encode_unix_path(path).ok_or(FileError::InvalidPath)?;
            let path = core::ffi::CStr::from_bytes_with_nul(&encoded)
                .map_err(|_| FileError::InvalidPath)?;
            mrml_linux::NativeFile::open_regular_read(path).ok_or(FileError::OpenFailed)?
        };
        Ok(Self { inner, position: 0 })
    }

    /// Checks the already-open descriptor, avoiding a path metadata race.
    pub fn is_owner_only_secret(&self) -> bool {
        #[cfg(unix)]
        {
            self.inner.has_private_read_permissions() && self.inner.is_owned_by_effective_user()
        }
        #[cfg(windows)]
        {
            false
        }
    }

    pub fn create(path: &str) -> Result<Self, FileError> {
        #[cfg(windows)]
        {
            let mut encoded =
                Vector::with_capacity(path.len() + 1).map_err(|_| FileError::OpenFailed)?;
            encoded.extend(path.encode_utf16());
            encoded.push(0);
            let inner =
                mrml_windows::NativeFile::create_write(&encoded).ok_or(FileError::OpenFailed)?;
            Ok(Self { inner, position: 0 })
        }
        #[cfg(unix)]
        {
            if path.as_bytes().contains(&0) {
                return Err(FileError::InvalidPath);
            }
            let mut encoded =
                Vector::with_capacity(path.len() + 1).map_err(|_| FileError::OpenFailed)?;
            encoded
                .try_extend_from_slice(path.as_bytes())
                .map_err(|_| FileError::OpenFailed)?;
            encoded.push(0);
            let path = core::ffi::CStr::from_bytes_with_nul(&encoded)
                .map_err(|_| FileError::InvalidPath)?;
            let inner = mrml_linux::NativeFile::create_write(path).ok_or(FileError::OpenFailed)?;
            Ok(Self { inner, position: 0 })
        }
    }

    pub fn create_new(path: &str) -> Result<Self, FileError> {
        #[cfg(windows)]
        {
            let encoded = encode_windows_path(path).ok_or(FileError::InvalidPath)?;
            let inner = mrml_windows::NativeFile::create_new_write(&encoded)
                .ok_or(FileError::OpenFailed)?;
            Ok(Self { inner, position: 0 })
        }
        #[cfg(unix)]
        {
            let encoded = encode_unix_path(path).ok_or(FileError::InvalidPath)?;
            let path = core::ffi::CStr::from_bytes_with_nul(&encoded)
                .map_err(|_| FileError::InvalidPath)?;
            let inner =
                mrml_linux::NativeFile::create_new_write(path).ok_or(FileError::OpenFailed)?;
            Ok(Self { inner, position: 0 })
        }
    }

    pub fn open_write(path: &str) -> Result<Self, FileError> {
        #[cfg(windows)]
        {
            let mut encoded =
                Vector::with_capacity(path.len() + 1).map_err(|_| FileError::OpenFailed)?;
            encoded.extend(path.encode_utf16());
            encoded.push(0);
            let inner =
                mrml_windows::NativeFile::open_write(&encoded).ok_or(FileError::OpenFailed)?;
            Ok(Self { inner, position: 0 })
        }
        #[cfg(unix)]
        {
            if path.as_bytes().contains(&0) {
                return Err(FileError::InvalidPath);
            }
            let mut encoded =
                Vector::with_capacity(path.len() + 1).map_err(|_| FileError::OpenFailed)?;
            encoded
                .try_extend_from_slice(path.as_bytes())
                .map_err(|_| FileError::OpenFailed)?;
            encoded.push(0);
            let path = core::ffi::CStr::from_bytes_with_nul(&encoded)
                .map_err(|_| FileError::InvalidPath)?;
            let inner = mrml_linux::NativeFile::open_write(path).ok_or(FileError::OpenFailed)?;
            Ok(Self { inner, position: 0 })
        }
    }

    pub fn read_exact(&mut self, mut buffer: &mut [u8]) -> Result<(), FileError> {
        while !buffer.is_empty() {
            let read = self.inner.read(buffer).ok_or(FileError::ReadFailed)?;
            if read == 0 {
                return Err(FileError::UnexpectedEnd);
            }
            self.position = self.position.saturating_add(read as u64);
            buffer = &mut buffer[read..];
        }
        Ok(())
    }

    pub fn read(&mut self, buffer: &mut [u8]) -> Result<usize, FileError> {
        let read = self.inner.read(buffer).ok_or(FileError::ReadFailed)?;
        self.position = self.position.saturating_add(read as u64);
        Ok(read)
    }

    pub fn write_all(&mut self, mut buffer: &[u8]) -> Result<(), FileError> {
        while !buffer.is_empty() {
            let written = self.inner.write(buffer).ok_or(FileError::WriteFailed)?;
            if written == 0 {
                return Err(FileError::WriteFailed);
            }
            self.position = self.position.saturating_add(written as u64);
            buffer = &buffer[written..];
        }
        Ok(())
    }

    pub fn seek(&mut self, position: u64) -> Result<(), FileError> {
        self.inner
            .seek_absolute(position)
            .then_some(())
            .ok_or(FileError::SeekFailed)?;
        self.position = position;
        Ok(())
    }

    pub fn len(&self) -> Result<u64, FileError> {
        self.inner.len().ok_or(FileError::MetadataFailed)
    }

    pub fn sync(&self) -> Result<(), FileError> {
        self.inner
            .sync()
            .then_some(())
            .ok_or(FileError::WriteFailed)
    }

    #[cfg(target_os = "linux")]
    pub fn metadata(&self) -> Result<FileMetadata, FileError> {
        let metadata = self.inner.metadata().ok_or(FileError::MetadataFailed)?;
        Ok(FileMetadata {
            inode: metadata.inode,
            mode: metadata.mode,
            uid: metadata.uid,
            gid: metadata.gid,
            links: metadata.links,
            device: metadata.device,
        })
    }

    pub const fn position(&self) -> u64 {
        self.position
    }

    #[cfg(windows)]
    pub fn raw_handle(&self) -> *mut core::ffi::c_void {
        self.inner.raw_handle()
    }
    #[cfg(unix)]
    pub fn raw_fd(&self) -> core::ffi::c_int {
        self.inner.raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    fn test_path(name: &str) -> Text {
        crate::join_path(
            &crate::temporary_directory(),
            &crate::mrml_format!("{name}-{}", crate::process_id()),
        )
    }

    #[test]
    fn native_file_reads_seeks_and_reports_length() {
        let path = test_path("mrml-file.bin");
        write_file(&path, b"native file").unwrap();

        let mut file = File::open(&path).unwrap();
        assert_eq!(file.len().unwrap(), 11);
        file.seek(7).unwrap();
        let mut suffix = [0; 4];
        file.read_exact(&mut suffix).unwrap();
        assert_eq!(&suffix, b"file");
        drop(file);
        remove_file(&path).unwrap();
    }

    #[test]
    fn regular_file_open_rejects_non_files() {
        let path = test_path("mrml-regular-open.bin");
        let link = test_path("mrml-regular-open-link.bin");
        write_file(&path, b"regular").unwrap();
        assert!(File::open_regular(&path).is_ok());
        assert!(File::open_regular(&crate::temporary_directory()).is_err());
        #[cfg(unix)]
        {
            assert!(File::open_regular("/dev/null").is_err());
            std::os::unix::fs::symlink(path.as_str(), link.as_str()).unwrap();
            assert!(File::open_regular(&link).is_err());
            remove_file(&link).unwrap();
        }
        #[cfg(windows)]
        if std::os::windows::fs::symlink_file(path.as_str(), link.as_str()).is_ok() {
            assert!(File::open_regular(&link).is_err());
            remove_file(&link).unwrap();
        }
        remove_file(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_classification_requires_a_regular_file() {
        let root = test_path("mrml-file-kind");
        create_dir_all(&root).unwrap();
        let file = join_path(&root, "regular.bin");
        write_file(&file, b"regular").unwrap();

        assert!(path_is_file(&file));
        assert!(!path_is_file(&root));
        assert!(!path_is_file("/dev/null"));

        remove_dir_all(&root).unwrap();
    }
    #[test]
    fn writes_truncates_and_reads_utf8_text_through_native_file() {
        let path = test_path("mrml-text.txt");
        write_file(&path, b"a longer discarded value").unwrap();
        write_file(&path, "observatory λ".as_bytes()).unwrap();
        assert_eq!(read_file_text(&path).unwrap(), "observatory λ");
        remove_file(&path).unwrap();
    }

    #[test]
    fn exclusive_writes_never_replace_an_existing_file() {
        let path = test_path("mrml-exclusive.bin");
        write_new_file(&path, b"first").unwrap();
        assert_eq!(write_new_file(&path, b"second"), Err(FileError::OpenFailed));
        assert_eq!(&*read_file(&path).unwrap(), b"first");
        remove_file(&path).unwrap();
    }

    #[test]
    fn secret_writes_are_exclusive_durable_and_erase_the_source() {
        let path = test_path("mrml-secret.bin");
        if path_exists(&path) {
            remove_file(&path).unwrap();
        }
        let mut secret = [0x5au8; 64];
        write_secret_file(&path, &mut secret).unwrap();
        assert!(secret.iter().all(|byte| *byte == 0));
        assert_eq!(&*read_file(&path).unwrap(), &[0x5a; 64]);
        let mut replacement = [0x33u8; 64];
        assert_eq!(
            write_secret_file(&path, &mut replacement),
            Err(FileError::OpenFailed)
        );
        assert!(replacement.iter().all(|byte| *byte == 0));
        assert_eq!(&*read_file(&path).unwrap(), &[0x5a; 64]);
        remove_file(&path).unwrap();
    }

    #[test]
    fn bounded_reads_reject_oversized_files() {
        let path = test_path("mrml-bounded.bin");
        write_file(&path, b"12345").unwrap();
        assert_eq!(&read_file_bounded(&path, 5).unwrap()[..], b"12345");
        assert_eq!(read_file_bounded(&path, 4), Err(FileError::ReadFailed));
        remove_file(&path).unwrap();
    }

    #[test]
    fn bounded_mappings_preserve_exact_bytes_and_reject_oversized_files() {
        let path = test_path("mrml-mapped.bin");
        write_file(&path, b"mapped bytes").unwrap();
        let mapped = MappedFile::open_bounded(&path, 12).unwrap();
        assert_eq!(mapped.bytes(), b"mapped bytes");
        drop(mapped);
        assert!(matches!(
            MappedFile::open_bounded(&path, 11),
            Err(FileError::ReadFailed)
        ));
        write_file(&path, b"").unwrap();
        assert!(MappedFile::open_bounded(&path, 0).unwrap().is_empty());
        remove_file(&path).unwrap();
    }

    #[test]
    fn renames_replaces_and_removes_files_natively() {
        let root = test_path("mrml-rename");
        create_dir_all(&root).unwrap();
        let source = join_path(&root, "source-λ.txt");
        let target = join_path(&root, "target-λ.txt");
        write_file(&source, b"new").unwrap();
        write_file(&target, b"old").unwrap();
        rename_file(&source, &target).unwrap();
        assert_eq!(&*read_file(&target).unwrap(), b"new");
        assert!(!path_exists(&source));
        remove_file(&target).unwrap();
        assert!(!path_exists(&target));
        remove_dir_all(&root).unwrap();
    }

    #[test]
    fn enumerates_unicode_files_and_directories_natively() {
        let root = test_path("mrml-enumerate");
        let child = join_path(&root, "folder-星");
        create_dir_all(&child).unwrap();
        let file = join_path(&root, "file-λ.txt");
        write_file(&file, b"entry").unwrap();
        let entries = read_directory(&root).unwrap();
        assert!(
            entries
                .iter()
                .any(|entry| entry.name == "folder-星" && entry.is_directory)
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.name == "file-λ.txt" && !entry.is_directory)
        );
        remove_dir_all(&root).unwrap();
        assert!(!path_exists(&root));
    }

    #[test]
    fn resolves_existing_paths_natively() {
        let root = test_path("mrml-canonical");
        create_dir_all(&root).unwrap();
        let resolved = canonical_path(&root).unwrap();
        assert!(path_is_directory(&resolved));
        assert!(resolved.contains("mrml-canonical-"));
        remove_dir_all(&root).unwrap();
    }

    #[test]
    fn recursively_creates_unicode_directories_and_rejects_file_conflicts() {
        let root = test_path("mrml-dir");
        let nested = join_path(&join_path(&root, "observatory-λ"), "deep");
        create_dir_all(&nested).unwrap();
        assert!(path_is_directory(&nested));
        let file = join_path(&nested, "conflict");
        write_file(&file, b"not a directory").unwrap();
        assert!(create_dir_all(&file).is_err());
        remove_dir_all(&root).unwrap();
        assert!(!path_exists(&root));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_directory_capability_rejects_escape_links_and_replacement() {
        use std::os::unix::fs::symlink;

        let root = test_path("mrml-directory-capability");
        let owner = join_path(&root, "owner");
        let repository = join_path(&owner, "repository");
        let replacement = join_path(&owner, "replacement");
        create_dir_all(&repository).unwrap();
        create_dir_all(&replacement).unwrap();
        symlink(
            repository.as_str(),
            join_path(&root, "repository-link").as_str(),
        )
        .unwrap();
        symlink("/proc/self/fd", join_path(&root, "magic-link").as_str()).unwrap();
        let regular = join_path(&root, "regular");
        write_file(&regular, b"retained").unwrap();
        symlink("regular", join_path(&root, "regular-link").as_str()).unwrap();

        let root_capability = DirectoryCapability::open_root(&root).unwrap();
        let retained_file = root_capability.open_regular("regular").unwrap();
        assert_eq!(retained_file.metadata().unwrap().links, 1);
        assert!(root_capability.open_regular("regular-link").is_err());
        std::fs::hard_link(
            regular.as_str(),
            join_path(&root, "regular-hard-link").as_str(),
        )
        .unwrap();
        assert_eq!(
            root_capability
                .open_regular("regular")
                .unwrap()
                .metadata()
                .unwrap()
                .links,
            2
        );
        let mut temporary = root_capability.create_new_file("state.new", 0o600).unwrap();
        temporary.write_all(b"generation").unwrap();
        temporary.sync().unwrap();
        assert_eq!(temporary.metadata().unwrap().mode & 0o777, 0o600);
        drop(temporary);
        root_capability
            .rename_child("state.new", "state.active")
            .unwrap();
        root_capability.sync().unwrap();
        let mut active = root_capability.open_regular("state.active").unwrap();
        let mut active_bytes = [0; 10];
        active.read_exact(&mut active_bytes).unwrap();
        assert_eq!(&active_bytes, b"generation");
        drop(active);
        root_capability.remove_file("state.active").unwrap();
        assert!(root_capability.open_regular("state.active").is_err());
        for invalid in ["", ".", "..", "nested/state", "nested\\state"] {
            assert!(root_capability.create_new_file(invalid, 0o600).is_err());
            assert!(root_capability.remove_file(invalid).is_err());
        }
        let retained = root_capability.open_directory("owner/repository").unwrap();
        let retained_metadata = retained.metadata().unwrap();
        assert_eq!(retained_metadata.mode & 0o170000, 0o040000);
        assert!(retained_metadata.links >= 2);
        for invalid in [
            "",
            "/owner/repository",
            "../repository",
            "owner/../repository",
            "owner//repository",
            "owner/repository/",
            "owner\\repository",
            "repository-link",
            "magic-link/0",
        ] {
            assert!(
                root_capability.open_directory(invalid).is_err(),
                "{invalid}"
            );
        }

        let displaced = join_path(&owner, "displaced");
        rename_file(&repository, &displaced).unwrap();
        rename_file(&replacement, &repository).unwrap();
        assert_eq!(retained.metadata().unwrap().inode, retained_metadata.inode);
        assert_ne!(
            root_capability
                .open_directory("owner/repository")
                .unwrap()
                .metadata()
                .unwrap()
                .inode,
            retained_metadata.inode
        );
        remove_dir_all(&root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn directory_resolution_under_rename_race_never_escapes_retained_root() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let root = test_path("mrml-directory-capability-race");
        let owner = join_path(&root, "owner");
        let repository = join_path(&owner, "repository");
        let alternate = join_path(&owner, "alternate");
        create_dir_all(&repository).unwrap();
        create_dir_all(&alternate).unwrap();
        let expected = DirectoryCapability::open_root(&root)
            .unwrap()
            .open_directory("owner/repository")
            .unwrap()
            .metadata()
            .unwrap();
        let alternate_expected = DirectoryCapability::open_root(&root)
            .unwrap()
            .open_directory("owner/alternate")
            .unwrap()
            .metadata()
            .unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = running.clone();
        let worker_owner = std::string::String::from(owner.as_str());
        let worker = std::thread::spawn(move || {
            let repository = std::format!("{worker_owner}/repository");
            let alternate = std::format!("{worker_owner}/alternate");
            while worker_running.load(Ordering::Acquire) {
                let _ = std::fs::rename(&repository, std::format!("{worker_owner}/moving"));
                let _ = std::fs::rename(&alternate, &repository);
                let _ = std::fs::rename(std::format!("{worker_owner}/moving"), &alternate);
            }
        });
        let root_capability = DirectoryCapability::open_root(&root).unwrap();
        let mut observed = 0usize;
        for _ in 0..10_000 {
            if let Ok(capability) = root_capability.open_directory("owner/repository") {
                let metadata = capability.metadata().unwrap();
                assert!(
                    metadata.inode == expected.inode || metadata.inode == alternate_expected.inode
                );
                assert_eq!(metadata.mode & 0o170000, 0o040000);
                observed += 1;
            }
        }
        running.store(false, Ordering::Release);
        worker.join().unwrap();
        assert!(observed > 0);
        remove_dir_all(&root).unwrap();
    }
}
