use core::{cell::RefCell, fmt};
#[cfg(target_os = "linux")]
use mrml_runtime::{DirectoryCapability, Shared};
use mrml_runtime::{
    File, FileError, Text, Vector, canonical_path, create_dir_all, join_path, parent_path,
    path_exists, path_is_directory, path_is_file, read_directory, read_file_bounded,
    read_file_text_bounded, remove_file, rename_file, sync_directory, write_file,
};
use mrml_ssh::{RsaPrivateKey, RsaPublicKey, sign_sshsig, verify_sshsig};

use crate::{
    Commit, FileDiff, Index, IndexEntry, IndexError, Object, ObjectError, ObjectFormat, ObjectId,
    ObjectKind, PackError, PackObject, decode_loose_object, encode_loose_object_with_format,
    encode_pack_with_format, parse_pack_with_format, parse_tree_with_format,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FetchPackLimits {
    pub max_pack_bytes: u64,
    pub max_objects: u32,
    pub max_expanded_bytes: u64,
    pub max_individual_bytes: u64,
    pub max_work_units: u64,
}

impl FetchPackLimits {
    pub fn production(max_pack_bytes: u64) -> Result<Self, RepositoryError> {
        if max_pack_bytes == 0 || max_pack_bytes > MAX_PACK_BYTES as u64 {
            return Err(RepositoryError::FileTooLarge);
        }
        Ok(Self {
            max_pack_bytes,
            max_objects: 1_000_000,
            max_expanded_bytes: max_pack_bytes
                .checked_mul(4)
                .ok_or(RepositoryError::FileTooLarge)?,
            max_individual_bytes: MAX_WORKTREE_FILE as u64,
            max_work_units: max_pack_bytes
                .checked_mul(6)
                .ok_or(RepositoryError::FileTooLarge)?,
        })
    }
}

const MAX_INDEX_BYTES: usize = 64 * 1024 * 1024;
const MAX_PACK_BYTES: usize = 1024 * 1024 * 1024;
const MAX_PACKED_REFS_BYTES: usize = 64 * 1024 * 1024;
const MAX_WORKTREE_FILE: usize = 256 * 1024 * 1024;
const MAX_WORKTREE_ENTRIES: usize = 1_000_000;
const MAX_DEPTH: usize = 128;
const MAX_REMOTE_REFS_BYTES: usize = 64 * 1024 * 1024;

fn append_reachable_children(
    object: &Object,
    format: ObjectFormat,
    pending: &mut Vector<ObjectId>,
) -> Result<(), RepositoryError> {
    match object.kind {
        ObjectKind::Commit => {
            let commit = Commit::parse_with_format(&object.contents, format)?;
            pending.push(commit.tree);
            pending.extend(commit.parents.iter().copied());
        }
        ObjectKind::Tree => pending.extend(
            parse_tree_with_format(&object.contents, format)?
                .iter()
                .map(|entry| entry.id),
        ),
        ObjectKind::Tag => {
            let text = core::str::from_utf8(&object.contents)
                .map_err(|_| RepositoryError::InvalidReference)?;
            let target = text
                .lines()
                .find_map(|line| line.strip_prefix("object "))
                .and_then(|value| ObjectId::parse_for(format, value))
                .ok_or(RepositoryError::InvalidReference)?;
            pending.push(target);
        }
        ObjectKind::Blob => {}
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct RetainedGitDirectory {
    capability: Shared<DirectoryCapability>,
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for RetainedGitDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedGitDirectory")
            .field("device", &self.device)
            .field("inode", &self.inode)
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl PartialEq for RetainedGitDirectory {
    fn eq(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

#[cfg(target_os = "linux")]
impl Eq for RetainedGitDirectory {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Repository {
    pub worktree: Text,
    pub git_dir: Text,
    object_format: ObjectFormat,
    pack_cache: RefCell<Vector<PackObject>>,
    #[cfg(target_os = "linux")]
    retained_git: Option<RetainedGitDirectory>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeChangeKind {
    Modified,
    Deleted,
    Untracked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeChange {
    pub path: Text,
    pub kind: NativeChangeKind,
    pub staged: bool,
    pub unstaged: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlameLine {
    pub commit: ObjectId,
    pub author: Text,
    pub line_number: usize,
    pub text: Text,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergeOutcome {
    UpToDate,
    FastForward(ObjectId),
    Merged(ObjectId),
    Conflicts(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebaseOutcome {
    UpToDate,
    Rebased { count: usize, head: ObjectId },
    Conflicts(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitSignatureFormat {
    OpenPgp,
    Ssh,
}

enum CommitSigning<'a> {
    Single(
        GitSignatureFormat,
        &'a mut dyn FnMut(&[u8]) -> Result<Text, RepositoryError>,
        &'a mut dyn FnMut(&[u8], &str) -> Result<(), RepositoryError>,
    ),
    Hybrid(
        &'a mut dyn FnMut(&[u8]) -> Result<Text, RepositoryError>,
        &'a mut dyn FnMut(&[u8]) -> Result<Text, RepositoryError>,
        &'a mut dyn FnMut(&[u8], &str) -> Result<(), RepositoryError>,
        &'a mut dyn FnMut(&[u8], &str) -> Result<(), RepositoryError>,
    ),
}

impl GitSignatureFormat {
    const fn begin_marker(self) -> &'static str {
        match self {
            Self::OpenPgp => "-----BEGIN PGP SIGNATURE-----",
            Self::Ssh => "-----BEGIN SSH SIGNATURE-----",
        }
    }

    const fn end_marker(self) -> &'static str {
        match self {
            Self::OpenPgp => "-----END PGP SIGNATURE-----",
            Self::Ssh => "-----END SSH SIGNATURE-----",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    File(FileError),
    Index(IndexError),
    NotRepository,
    AlreadyExists,
    UnsupportedLayout,
    InvalidHead,
    InvalidReference,
    TooManyFiles,
    TooDeep,
    UnsupportedFileType,
    FileTooLarge,
    InvalidWorktreePath,
    ConflictedIndex,
    DetachedHead,
    InvalidIdentity,
    ReferenceExists,
    ReferenceMissing,
    CurrentBranch,
    Object(ObjectError),
    Pack(PackError),
    WorktreeDirty,
    NoChanges,
    MergeRequired,
    Signing,
    UnsupportedObjectFormat,
}

impl Repository {
    /// Writes a deterministic pack containing every object reachable from
    /// local branches, tags, and HEAD. Existing objects and packs are retained.
    pub fn repack_local(&self) -> Result<crate::LocalRepackResult, RepositoryError> {
        crate::local_repack::repack(self)
    }

    pub fn discover(start: &str) -> Result<Self, RepositoryError> {
        let resolved = canonical_path(start)?;
        let mut current = if path_is_directory(&resolved) {
            resolved
        } else {
            parent_path(&resolved)
                .ok_or(RepositoryError::NotRepository)?
                .into()
        };
        loop {
            let marker = join_path(&current, ".git");
            if path_is_directory(&marker) {
                let object_format = repository_object_format(&marker)?;
                return Ok(Self {
                    worktree: current,
                    git_dir: marker,
                    object_format,
                    pack_cache: RefCell::new(Vector::new()),
                    #[cfg(target_os = "linux")]
                    retained_git: None,
                });
            }
            if path_exists(&marker) {
                return Err(RepositoryError::UnsupportedLayout);
            }
            let Some(parent) = parent_path(&current) else {
                break;
            };
            if current == parent {
                break;
            }
            current = parent.into();
        }
        Err(RepositoryError::NotRepository)
    }

    pub fn init(path: &str) -> Result<Self, RepositoryError> {
        Self::init_with_format(path, ObjectFormat::Sha1)
    }

    pub fn init_with_format(
        path: &str,
        object_format: ObjectFormat,
    ) -> Result<Self, RepositoryError> {
        create_dir_all(path)?;
        let worktree = canonical_path(path)?;
        let git_dir = join_path(&worktree, ".git");
        if path_exists(&git_dir) {
            return Err(RepositoryError::AlreadyExists);
        }
        create_dir_all(&join_path(&git_dir, "objects/info"))?;
        create_dir_all(&join_path(&git_dir, "objects/pack"))?;
        create_dir_all(&join_path(&git_dir, "refs/heads"))?;
        create_dir_all(&join_path(&git_dir, "refs/tags"))?;
        write_file(&join_path(&git_dir, "HEAD"), b"ref: refs/heads/main\n")?;
        let config = match object_format {
            ObjectFormat::Sha1 => "[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
            ObjectFormat::Sha256 => {
                "[extensions]\n\tobjectformat = sha256\n[core]\n\trepositoryformatversion = 1\n\tbare = false\n"
            }
        };
        write_file(&join_path(&git_dir, "config"), config.as_bytes())?;
        write_file(
            &join_path(&git_dir, "description"),
            b"Unnamed MRML repository\n",
        )?;
        Ok(Self {
            worktree,
            git_dir,
            object_format,
            pack_cache: RefCell::new(Vector::new()),
            #[cfg(target_os = "linux")]
            retained_git: None,
        })
    }

    #[cfg(target_os = "linux")]
    pub fn initialize_sha256_capability(
        worktree: DirectoryCapability,
    ) -> Result<Self, RepositoryError> {
        if !worktree
            .read_directory()?
            .iter()
            .all(|entry| entry.name.as_str() != ".git")
        {
            return Err(RepositoryError::AlreadyExists);
        }
        let git = worktree.create_directory(".git", 0o700)?;
        let objects = git.create_directory("objects", 0o700)?;
        objects.create_directory("info", 0o700)?;
        objects.create_directory("pack", 0o700)?;
        let refs = git.create_directory("refs", 0o700)?;
        refs.create_directory("heads", 0o700)?;
        refs.create_directory("tags", 0o700)?;
        write_capability_file(&git, "HEAD", b"ref: refs/heads/main\n")?;
        write_capability_file(
            &git,
            "config",
            b"[extensions]\n\tobjectformat = sha256\n[core]\n\trepositoryformatversion = 1\n\tbare = false\n",
        )?;
        write_capability_file(&git, "description", b"Unnamed MRML repository\n")?;
        objects.sync()?;
        refs.sync()?;
        git.sync()?;
        worktree.sync()?;
        Self::from_git_capability(git, ObjectFormat::Sha256)
    }

    #[cfg(target_os = "linux")]
    pub fn open_sha256_capability(worktree: DirectoryCapability) -> Result<Self, RepositoryError> {
        let git = worktree.open_directory(".git")?;
        let config = read_capability_file(&git, "config", 1024 * 1024)?;
        let config =
            core::str::from_utf8(&config).map_err(|_| RepositoryError::UnsupportedObjectFormat)?;
        let format = parse_repository_object_format(config)?;
        if format != ObjectFormat::Sha256 {
            return Err(RepositoryError::UnsupportedObjectFormat);
        }
        git.open_directory("objects")?.open_directory("pack")?;
        Self::from_git_capability(git, format)
    }

    #[cfg(target_os = "linux")]
    fn from_git_capability(
        git: DirectoryCapability,
        object_format: ObjectFormat,
    ) -> Result<Self, RepositoryError> {
        let metadata = git.metadata()?;
        if metadata.mode & 0o170000 != 0o040000
            || metadata.mode & 0o022 != 0
            || metadata.mode & 0o700 != 0o700
        {
            return Err(RepositoryError::UnsupportedLayout);
        }
        Ok(Self {
            worktree: Text::new(),
            git_dir: Text::new(),
            object_format,
            pack_cache: RefCell::new(Vector::new()),
            retained_git: Some(RetainedGitDirectory {
                capability: Shared::new(git),
                device: metadata.device,
                inode: metadata.inode,
            }),
        })
    }

    pub const fn object_format(&self) -> ObjectFormat {
        self.object_format
    }

    pub fn current_branch(&self) -> Result<Option<Text>, RepositoryError> {
        let head = read_file_text_bounded(&join_path(&self.git_dir, "HEAD"), 4096)?;
        let head = head.trim();
        if let Some(reference) = head.strip_prefix("ref: ") {
            validate_reference(reference)?;
            return Ok(reference.strip_prefix("refs/heads/").map(Into::into));
        }
        ObjectId::parse_for(self.object_format, head)
            .map(|_| None)
            .ok_or(RepositoryError::InvalidHead)
    }

    pub fn head(&self) -> Result<Option<ObjectId>, RepositoryError> {
        let head = read_file_text_bounded(&join_path(&self.git_dir, "HEAD"), 4096)?;
        let head = head.trim();
        if let Some(reference) = head.strip_prefix("ref: ") {
            validate_reference(reference)?;
            return self.read_reference(reference);
        }
        ObjectId::parse_for(self.object_format, head)
            .map(Some)
            .ok_or(RepositoryError::InvalidHead)
    }

    pub fn index(&self) -> Result<Index, RepositoryError> {
        let path = join_path(&self.git_dir, "index");
        if !path_is_file(&path) {
            return Ok(Index::empty_with_format(self.object_format));
        }
        Ok(Index::parse_with_format(
            &read_file_bounded(&path, MAX_INDEX_BYTES)?,
            self.object_format,
        )?)
    }

    pub fn write_object(
        &self,
        kind: ObjectKind,
        contents: &[u8],
    ) -> Result<ObjectId, RepositoryError> {
        let (id, encoded) = encode_loose_object_with_format(self.object_format, kind, contents);
        let hex = id.to_hex();
        #[cfg(target_os = "linux")]
        if let Some(retained) = &self.retained_git {
            let objects = retained.capability.open_directory("objects")?;
            let prefix = match objects.open_directory(&hex[..2]) {
                Ok(prefix) => prefix,
                Err(_) => objects.create_directory(&hex[..2], 0o700)?,
            };
            let name = &hex[2..];
            if prefix.open_regular(name).is_err() {
                let mut file = prefix.create_new_file(name, 0o600)?;
                file.write_all(&encoded)?;
                file.sync()?;
                prefix.sync()?;
                objects.sync()?;
            }
            let stored = self.read_object(id)?;
            if stored.kind != kind || &stored.contents[..] != contents {
                return Err(RepositoryError::InvalidHead);
            }
            return Ok(id);
        }
        let directory = join_path(&join_path(&self.git_dir, "objects"), &hex[..2]);
        let path = join_path(&directory, &hex[2..]);
        if !path_is_file(&path) {
            create_dir_all(&directory)?;
            write_file(&path, &encoded)?;
        }
        let stored = self.read_object(id)?;
        if stored.kind != kind || &stored.contents[..] != contents {
            return Err(RepositoryError::InvalidHead);
        }
        Ok(id)
    }

    pub fn read_object(&self, id: ObjectId) -> Result<Object, RepositoryError> {
        if id.format() != self.object_format {
            return Err(RepositoryError::InvalidReference);
        }
        let hex = id.to_hex();
        #[cfg(target_os = "linux")]
        if let Some(retained) = &self.retained_git {
            let objects = retained.capability.open_directory("objects")?;
            let prefix_name = &hex[..2];
            match objects.open_directory(prefix_name) {
                Ok(prefix) => {
                    let object_name = &hex[2..];
                    if let Some(entry) = prefix
                        .read_directory()?
                        .iter()
                        .find(|entry| entry.name.as_str() == object_name)
                    {
                        if entry.is_directory || entry.is_symlink {
                            return Err(RepositoryError::UnsupportedFileType);
                        }
                        return decode_retained_object(
                            prefix.open_regular(object_name)?,
                            id,
                            self.object_format,
                        );
                    }
                }
                Err(_) => {
                    if objects
                        .read_directory()?
                        .iter()
                        .any(|entry| entry.name.as_str() == prefix_name)
                    {
                        return Err(RepositoryError::UnsupportedFileType);
                    }
                }
            }
            if let Some(object) = self.cached_object(id) {
                return Ok(object);
            }
            let pack_root = objects.open_directory("pack")?;
            return self.read_packed_capability(&pack_root, id);
        }
        let path = join_path(
            &join_path(&self.git_dir, "objects"),
            &mrml_runtime::mrml_format!("{}/{}", &hex[..2], &hex[2..]),
        );
        if path_is_file(&path) {
            let encoded = read_file_bounded(&path, MAX_WORKTREE_FILE)?;
            let object = decode_loose_object(&encoded)?;
            let (computed, _) =
                encode_loose_object_with_format(self.object_format, object.kind, &object.contents);
            if computed != id {
                return Err(RepositoryError::InvalidHead);
            }
            return Ok(object);
        }
        if let Some(object) = self.cached_object(id) {
            return Ok(object);
        }
        let pack_root = join_path(&self.git_dir, "objects/pack");
        if path_is_directory(&pack_root) {
            let mut inspected = 0usize;
            for entry in read_directory(&pack_root)? {
                if entry.is_symlink {
                    return Err(RepositoryError::UnsupportedFileType);
                }
                if !entry.is_directory && entry.name.ends_with(".pack") {
                    inspected = inspected
                        .checked_add(1)
                        .ok_or(RepositoryError::TooManyFiles)?;
                    if inspected > 4096 {
                        return Err(RepositoryError::TooManyFiles);
                    }
                    let bytes =
                        read_file_bounded(&join_path(&pack_root, &entry.name), MAX_PACK_BYTES)?;
                    let objects = parse_pack_with_format(&bytes, self.object_format)?;
                    let found = objects.iter().find(|object| object.id == id).cloned();
                    let mut cache = self.pack_cache.borrow_mut();
                    cache.extend(objects);
                    cache.sort_unstable_by_key(|object| object.id);
                    if let Some(packed) = found {
                        return Ok(Object {
                            kind: packed.kind,
                            contents: packed.contents,
                        });
                    }
                }
            }
        }
        Err(RepositoryError::ReferenceMissing)
    }

    fn cached_object(&self, id: ObjectId) -> Option<Object> {
        let cache = self.pack_cache.borrow();
        cache
            .binary_search_by_key(&id, |object| object.id)
            .ok()
            .map(|index| Object {
                kind: cache[index].kind,
                contents: cache[index].contents.clone(),
            })
    }

    #[cfg(target_os = "linux")]
    fn read_packed_capability(
        &self,
        pack_root: &DirectoryCapability,
        id: ObjectId,
    ) -> Result<Object, RepositoryError> {
        let mut inspected = 0usize;
        for entry in pack_root.read_directory()? {
            if entry.is_symlink {
                return Err(RepositoryError::UnsupportedFileType);
            }
            if !entry.is_directory && entry.name.ends_with(".pack") {
                inspected = inspected
                    .checked_add(1)
                    .ok_or(RepositoryError::TooManyFiles)?;
                if inspected > 4096 {
                    return Err(RepositoryError::TooManyFiles);
                }
                let bytes =
                    read_open_file_bounded(pack_root.open_regular(&entry.name)?, MAX_PACK_BYTES)?;
                let parsed = parse_pack_with_format(&bytes, self.object_format)?;
                let found = parsed.iter().find(|object| object.id == id).cloned();
                let mut cache = self.pack_cache.borrow_mut();
                cache.extend(parsed);
                cache.sort_unstable_by_key(|object| object.id);
                if let Some(packed) = found {
                    return Ok(Object {
                        kind: packed.kind,
                        contents: packed.contents,
                    });
                }
            }
        }
        Err(RepositoryError::ReferenceMissing)
    }

    pub fn import_pack(&self, source: &[u8]) -> Result<Vector<ObjectId>, RepositoryError> {
        let objects = parse_pack_with_format(source, self.object_format)?;
        self.install_parsed_pack(objects)
    }

    /// Authenticates and traverses all advertised commit tips against an
    /// isolated parsed candidate before any loose object becomes visible.
    pub fn import_pack_validated_commit_tips(
        &self,
        source: &[u8],
        tips: &[ObjectId],
    ) -> Result<Vector<ObjectId>, RepositoryError> {
        let objects = parse_pack_with_format(source, self.object_format)?;
        self.validate_commit_tips_with_candidates(tips, &objects)?;
        self.install_parsed_pack(objects)
    }

    /// Validate a streamed pack from an isolated regular file without loading
    /// the whole pack, traverse every required commit tip before installation,
    /// and leave reference activation to the caller as a separate final step.
    pub fn import_pack_file_validated_commit_tips(
        &self,
        pack_path: &str,
        scratch_directory: &str,
        tips: &[ObjectId],
        limits: FetchPackLimits,
    ) -> Result<Vector<ObjectId>, RepositoryError> {
        if tips.is_empty()
            || limits.max_pack_bytes == 0
            || limits.max_pack_bytes > MAX_PACK_BYTES as u64
            || limits.max_objects == 0
            || limits.max_objects > 1_000_000
            || limits.max_expanded_bytes == 0
            || limits.max_individual_bytes == 0
            || limits.max_individual_bytes > MAX_WORKTREE_FILE as u64
            || limits.max_work_units < limits.max_pack_bytes
            || path_exists(scratch_directory)
        {
            return Err(RepositoryError::FileTooLarge);
        }
        create_dir_all(scratch_directory)?;
        let validated = crate::pack_file::validate_pack_file_with_bases(
            pack_path,
            self.object_format,
            limits.max_pack_bytes,
            limits.max_objects,
            limits.max_expanded_bytes,
            limits.max_individual_bytes,
            limits.max_work_units,
            &mut |id, kind, contents| {
                crate::arrival_pack::write_scratch_object(scratch_directory, id, kind, contents)
                    .map_err(|_| PackError::TooLarge)
            },
            |id, limit| {
                if let Some(object) =
                    crate::arrival_pack::read_scratch_object(scratch_directory, id, limit)?
                {
                    return Ok(Some(object));
                }
                match self.read_object(id) {
                    Ok(object) if object.contents.len() as u64 <= limit => {
                        Ok(Some((object.kind, object.contents)))
                    }
                    Ok(_) => Err(PackError::TooLarge),
                    Err(RepositoryError::ReferenceMissing) => Ok(None),
                    Err(_) => Err(PackError::MissingBase),
                }
            },
        )?;
        if validated.objects.is_empty()
            || tips.iter().any(|tip| {
                tip.format() != self.object_format
                    || (!validated.objects.iter().any(|(id, _)| id == tip)
                        && self.read_object(*tip).is_err())
            })
        {
            return Err(RepositoryError::InvalidReference);
        }
        self.validate_commit_tips_with_loader(tips, |id| {
            if let Some((kind, contents)) = crate::arrival_pack::read_scratch_object(
                scratch_directory,
                id,
                limits.max_individual_bytes,
            )? {
                return Ok(Some(Object { kind, contents }));
            }
            Ok(None)
        })?;
        let mut installed = Vector::new();
        for (id, expected_kind) in validated.objects {
            let (kind, contents) = crate::arrival_pack::read_scratch_object(
                scratch_directory,
                id,
                limits.max_individual_bytes,
            )?
            .ok_or(RepositoryError::InvalidReference)?;
            if kind != expected_kind || self.write_object(kind, &contents)? != id {
                return Err(RepositoryError::InvalidReference);
            }
            installed.push(id);
        }
        Ok(installed)
    }

    fn install_parsed_pack(
        &self,
        objects: Vector<PackObject>,
    ) -> Result<Vector<ObjectId>, RepositoryError> {
        let mut ids = Vector::new();
        for object in objects {
            let id = self.write_object(object.kind, &object.contents)?;
            if id != object.id {
                return Err(RepositoryError::InvalidHead);
            }
            ids.push(id);
        }
        Ok(ids)
    }

    pub fn pack_reachable(&self, tip: ObjectId) -> Result<Vector<u8>, RepositoryError> {
        self.pack_negotiated(&[tip], &[])
    }

    pub fn pack_negotiated(
        &self,
        wants: &[ObjectId],
        haves: &[ObjectId],
    ) -> Result<Vector<u8>, RepositoryError> {
        let ids = self.negotiated_object_ids(wants, haves)?;
        let mut objects = Vector::new();
        for id in ids {
            let object = self.read_object(id)?;
            objects.push(PackObject {
                id,
                kind: object.kind,
                contents: object.contents,
            });
        }
        encode_pack_with_format(&objects, self.object_format).map_err(Into::into)
    }

    pub fn write_negotiated_pack(
        &self,
        wants: &[ObjectId],
        haves: &[ObjectId],
        output: &mut dyn crate::PackStreamOutput,
    ) -> Result<usize, RepositoryError> {
        let ids = self.negotiated_object_ids(wants, haves)?;
        let count = ids.len();
        let mut encoder = crate::PackStreamEncoder::new(count, self.object_format, output)?;
        for id in ids {
            let object = self.read_object(id)?;
            encoder.write_object(&PackObject {
                id,
                kind: object.kind,
                contents: object.contents,
            })?;
        }
        encoder.finish()?;
        Ok(count)
    }

    fn negotiated_object_ids(
        &self,
        wants: &[ObjectId],
        haves: &[ObjectId],
    ) -> Result<Vector<ObjectId>, RepositoryError> {
        if wants.is_empty()
            || wants
                .iter()
                .chain(haves.iter())
                .any(|id| id.format() != self.object_format)
        {
            return Err(RepositoryError::InvalidReference);
        }
        let mut excluded = Vector::new();
        let mut pending: Vector<ObjectId> = haves.iter().copied().collect();
        while let Some(id) = pending.pop() {
            if excluded.contains(&id) {
                continue;
            }
            if excluded.len() >= 1_000_000 {
                return Err(RepositoryError::TooManyFiles);
            }
            let object = self.read_object(id)?;
            append_reachable_children(&object, self.object_format, &mut pending)?;
            excluded.push(id);
        }

        let mut pending: Vector<ObjectId> = wants.iter().copied().collect();
        let mut seen = Vector::new();
        while let Some(id) = pending.pop() {
            if excluded.contains(&id) || seen.contains(&id) {
                continue;
            }
            if seen.len() >= 1_000_000 {
                return Err(RepositoryError::TooManyFiles);
            }
            let object = self.read_object(id)?;
            append_reachable_children(&object, self.object_format, &mut pending)?;
            seen.push(id);
        }
        Ok(seen)
    }

    pub fn validate_commit_tips(&self, tips: &[ObjectId]) -> Result<(), RepositoryError> {
        self.validate_commit_tips_with_candidates(tips, &[])
    }

    fn validate_commit_tips_with_candidates(
        &self,
        tips: &[ObjectId],
        candidates: &[PackObject],
    ) -> Result<(), RepositoryError> {
        self.validate_commit_tips_with_loader(tips, |id| {
            Ok(candidates
                .iter()
                .find(|object| object.id == id)
                .map(|candidate| Object {
                    kind: candidate.kind,
                    contents: candidate.contents.clone(),
                }))
        })
    }

    fn validate_commit_tips_with_loader<F>(
        &self,
        tips: &[ObjectId],
        mut candidate: F,
    ) -> Result<(), RepositoryError>
    where
        F: FnMut(ObjectId) -> Result<Option<Object>, RepositoryError>,
    {
        let mut pending = Vector::new();
        for tip in tips {
            if tip.format() != self.object_format {
                return Err(RepositoryError::InvalidReference);
            }
            pending.push((*tip, ObjectKind::Commit));
        }
        let mut seen = Vector::new();
        while let Some((id, expected_kind)) = pending.pop() {
            let object = candidate(id)?.map_or_else(|| self.read_object(id), Ok)?;
            if object.kind != expected_kind {
                return Err(RepositoryError::InvalidReference);
            }
            if seen.contains(&id) {
                continue;
            }
            if seen.len() >= MAX_WORKTREE_ENTRIES || pending.len() > MAX_WORKTREE_ENTRIES {
                return Err(RepositoryError::TooManyFiles);
            }
            match object.kind {
                ObjectKind::Commit => {
                    let commit = Commit::parse_with_format(&object.contents, self.object_format)?;
                    if commit.parents.len() > MAX_WORKTREE_ENTRIES - seen.len() {
                        return Err(RepositoryError::TooManyFiles);
                    }
                    pending.push((commit.tree, ObjectKind::Tree));
                    pending.extend(
                        commit
                            .parents
                            .iter()
                            .map(|parent| (*parent, ObjectKind::Commit)),
                    );
                }
                ObjectKind::Tree => {
                    let entries = parse_tree_with_format(&object.contents, self.object_format)?;
                    if entries.len() > MAX_WORKTREE_ENTRIES - seen.len() {
                        return Err(RepositoryError::TooManyFiles);
                    }
                    for entry in entries {
                        let kind = match entry.mode {
                            0o40000 => ObjectKind::Tree,
                            0o100644 | 0o100755 | 0o120000 => ObjectKind::Blob,
                            0o160000 => return Err(RepositoryError::UnsupportedFileType),
                            _ => return Err(RepositoryError::InvalidReference),
                        };
                        pending.push((entry.id, kind));
                    }
                }
                ObjectKind::Tag => return Err(RepositoryError::InvalidReference),
                ObjectKind::Blob => {}
            }
            seen.push(id);
        }
        Ok(())
    }

    pub fn validate_reachable_refs(&self) -> Result<usize, RepositoryError> {
        let mut tips = Vector::new();
        for (_, id) in self.branches()? {
            if !tips.contains(&id) {
                tips.push(id);
            }
        }
        for (_, id) in self.tags()? {
            let commit = self.peel_commit(id)?;
            if !tips.contains(&commit) {
                tips.push(commit);
            }
        }
        if let Some(head) = self.head()? {
            let commit = self.peel_commit(head)?;
            if !tips.contains(&commit) {
                tips.push(commit);
            }
        }
        self.validate_commit_tips(&tips)?;
        Ok(tips.len())
    }

    pub fn resolve_revision(&self, revision: &str) -> Result<ObjectId, RepositoryError> {
        if let Some(split) = revision.find(['~', '^']) {
            if split == 0 {
                return Err(RepositoryError::InvalidReference);
            }
            let mut id = self.resolve_revision(&revision[..split])?;
            let bytes = revision.as_bytes();
            let mut cursor = split;
            while cursor < bytes.len() {
                let operator = bytes[cursor];
                cursor += 1;
                let start = cursor;
                while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
                    cursor += 1;
                }
                let count = if start == cursor {
                    1
                } else {
                    revision[start..cursor]
                        .parse::<usize>()
                        .map_err(|_| RepositoryError::InvalidReference)?
                };
                if count > 1_000_000 {
                    return Err(RepositoryError::TooManyFiles);
                }
                id = self.peel_commit(id)?;
                if operator == b'~' {
                    for _ in 0..count {
                        id = self
                            .read_commit(id)?
                            .parents
                            .first()
                            .copied()
                            .ok_or(RepositoryError::ReferenceMissing)?;
                    }
                } else if count != 0 {
                    id = self
                        .read_commit(id)?
                        .parents
                        .get(count - 1)
                        .copied()
                        .ok_or(RepositoryError::ReferenceMissing)?;
                }
            }
            return Ok(id);
        }
        if revision == "HEAD" {
            return self.head()?.ok_or(RepositoryError::ReferenceMissing);
        }
        if let Some(id) = ObjectId::parse_for(self.object_format, revision) {
            return Ok(id);
        }
        if revision.starts_with("refs/") {
            validate_reference(revision)?;
            return self
                .read_reference(revision)?
                .ok_or(RepositoryError::ReferenceMissing);
        }
        for prefix in ["refs/heads", "refs/tags"] {
            let reference = mrml_runtime::mrml_format!("{prefix}/{revision}");
            validate_reference(&reference)?;
            if let Some(id) = self.read_reference(&reference)? {
                return Ok(id);
            }
        }
        Err(RepositoryError::ReferenceMissing)
    }

    fn peel_commit(&self, mut id: ObjectId) -> Result<ObjectId, RepositoryError> {
        for _ in 0..128 {
            let object = self.read_object(id)?;
            match object.kind {
                ObjectKind::Commit => return Ok(id),
                ObjectKind::Tag => {
                    id = core::str::from_utf8(&object.contents)
                        .map_err(|_| RepositoryError::InvalidReference)?
                        .lines()
                        .find_map(|line| line.strip_prefix("object "))
                        .and_then(|value| ObjectId::parse_for(self.object_format, value))
                        .ok_or(RepositoryError::InvalidReference)?;
                }
                _ => return Err(RepositoryError::InvalidReference),
            }
        }
        Err(RepositoryError::TooDeep)
    }

    fn read_reference(&self, reference: &str) -> Result<Option<ObjectId>, RepositoryError> {
        validate_reference(reference)?;
        if let Some(remote_reference) = reference.strip_prefix("refs/remotes/")
            && let Some((remote, branch)) = remote_reference.split_once('/')
            && let Some(refs) = self.active_remote_refs(remote)?
        {
            return Ok(refs
                .into_iter()
                .find(|(name, _)| name == branch)
                .map(|(_, id)| id));
        }
        let path = join_path(&self.git_dir, reference);
        if path_is_file(&path) {
            let value = read_file_text_bounded(&path, 4096)?;
            return ObjectId::parse_for(self.object_format, value.trim())
                .map(Some)
                .ok_or(RepositoryError::InvalidReference);
        }
        Ok(self
            .packed_references()?
            .into_iter()
            .find(|(name, _)| name == reference)
            .map(|(_, id)| id))
    }

    fn packed_references(&self) -> Result<Vector<(Text, ObjectId)>, RepositoryError> {
        let path = join_path(&self.git_dir, "packed-refs");
        if !path_is_file(&path) {
            return Ok(Vector::new());
        }
        let text = read_file_text_bounded(&path, MAX_PACKED_REFS_BYTES)?;
        let mut output = Vector::new();
        let mut can_peel = false;
        for line in text.lines() {
            if line.is_empty() || line.starts_with('#') {
                can_peel = false;
                continue;
            }
            if let Some(hex) = line.strip_prefix('^') {
                if !can_peel || ObjectId::parse_for(self.object_format, hex).is_none() {
                    return Err(RepositoryError::InvalidReference);
                }
                can_peel = false;
                continue;
            }
            let (hex, reference) = line
                .split_once(' ')
                .ok_or(RepositoryError::InvalidReference)?;
            validate_reference(reference)?;
            let id = ObjectId::parse_for(self.object_format, hex)
                .ok_or(RepositoryError::InvalidReference)?;
            if output.len() >= MAX_WORKTREE_ENTRIES
                || output.iter().any(|(existing, _)| existing == reference)
            {
                return Err(RepositoryError::InvalidReference);
            }
            output.push((reference.into(), id));
            can_peel = reference.starts_with("refs/tags/");
        }
        Ok(output)
    }

    pub fn read_commit(&self, id: ObjectId) -> Result<Commit, RepositoryError> {
        let object = self.read_object(id)?;
        if object.kind != ObjectKind::Commit {
            return Err(RepositoryError::InvalidReference);
        }
        Ok(Commit::parse_with_format(
            &object.contents,
            self.object_format,
        )?)
    }

    pub fn history(
        &self,
        start: ObjectId,
        limit: usize,
    ) -> Result<Vector<(ObjectId, Commit)>, RepositoryError> {
        let mut history = Vector::new();
        let mut next = Some(start);
        while let Some(id) = next {
            if history.len() >= limit {
                break;
            }
            let commit = self.read_commit(id)?;
            next = commit.parents.first().copied();
            history.push((id, commit));
        }
        Ok(history)
    }

    pub fn tree_index(&self, tree: ObjectId) -> Result<Index, RepositoryError> {
        let mut index = Index::empty_with_format(self.object_format);
        self.flatten_tree(tree, "", 0, &mut index)?;
        Ok(index)
    }

    fn flatten_tree(
        &self,
        id: ObjectId,
        prefix: &str,
        depth: usize,
        index: &mut Index,
    ) -> Result<(), RepositoryError> {
        if depth > MAX_DEPTH {
            return Err(RepositoryError::TooDeep);
        }
        let object = self.read_object(id)?;
        if object.kind != ObjectKind::Tree {
            return Err(RepositoryError::InvalidReference);
        }
        for entry in parse_tree_with_format(&object.contents, self.object_format)? {
            let path = if prefix.is_empty() {
                entry.name.clone()
            } else {
                mrml_runtime::mrml_format!("{prefix}/{}", entry.name)
            };
            if entry.mode == 0o40000 {
                self.flatten_tree(entry.id, &path, depth + 1, index)?;
            } else if matches!(entry.mode, 0o100644 | 0o100755) {
                if index.entries.len() >= MAX_WORKTREE_ENTRIES {
                    return Err(RepositoryError::TooManyFiles);
                }
                let object = self.read_object(entry.id)?;
                if object.kind != ObjectKind::Blob {
                    return Err(RepositoryError::InvalidReference);
                }
                index.upsert(IndexEntry {
                    path,
                    id: entry.id,
                    mode: entry.mode,
                    size: object
                        .contents
                        .len()
                        .try_into()
                        .map_err(|_| RepositoryError::FileTooLarge)?,
                    stage: 0,
                });
            } else {
                return Err(RepositoryError::UnsupportedFileType);
            }
        }
        Ok(())
    }

    pub fn switch_branch(&self, branch: &str) -> Result<ObjectId, RepositoryError> {
        validate_reference(&mrml_runtime::mrml_format!("refs/heads/{branch}"))?;
        if !self.changes()?.is_empty() {
            return Err(RepositoryError::WorktreeDirty);
        }
        let id = self.resolve_revision(branch)?;
        let commit = self.read_commit(id)?;
        let target = self.tree_index(commit.tree)?;
        let current = self.index()?;
        let smudge_crlf = self.autocrlf_mode()?.1;
        let mut files: Vector<(Text, Vector<u8>)> = Vector::new();
        for entry in &target.entries {
            let object = self.read_object(entry.id)?;
            if object.kind != ObjectKind::Blob {
                return Err(RepositoryError::InvalidReference);
            }
            files.push((entry.path.clone(), object.contents));
        }
        for entry in &current.entries {
            if target.entry(&entry.path).is_none() {
                let path = join_path(&self.worktree, &entry.path);
                if path_is_file(&path) {
                    mrml_runtime::remove_file(&path)?;
                }
            }
        }
        for (relative, contents) in files {
            let path = join_path(&self.worktree, &relative);
            if let Some(parent) = parent_path(&path) {
                create_dir_all(parent)?;
            }
            write_file(&path, &smudge_worktree_bytes(&contents, smudge_crlf))?;
        }
        self.write_index(&target)?;
        write_file(
            &join_path(&self.git_dir, "HEAD"),
            mrml_runtime::mrml_format!("ref: refs/heads/{branch}\n").as_bytes(),
        )?;
        Ok(id)
    }

    pub fn checkout_branch_at(
        &self,
        branch: &str,
        id: ObjectId,
    ) -> Result<ObjectId, RepositoryError> {
        let reference = mrml_runtime::mrml_format!("refs/heads/{branch}");
        validate_reference(&reference)?;
        let commit = self.read_commit(id)?;
        if !self.changes()?.is_empty() {
            return Err(RepositoryError::WorktreeDirty);
        }
        let target = self.tree_index(commit.tree)?;
        self.materialize_index(&target)?;
        let path = join_path(&self.git_dir, &reference);
        if let Some(parent) = parent_path(&path) {
            create_dir_all(parent)?;
        }
        write_file(&path, mrml_runtime::mrml_format!("{id}\n").as_bytes())?;
        write_file(
            &join_path(&self.git_dir, "HEAD"),
            mrml_runtime::mrml_format!("ref: {reference}\n").as_bytes(),
        )?;
        Ok(id)
    }

    pub fn fast_forward(&self, revision: &str) -> Result<MergeOutcome, RepositoryError> {
        if !self.changes()?.is_empty() {
            return Err(RepositoryError::WorktreeDirty);
        }
        let current = self.head()?.ok_or(RepositoryError::ReferenceMissing)?;
        let target = self.resolve_revision(revision)?;
        if self.is_ancestor(target, current)? {
            return Ok(MergeOutcome::UpToDate);
        }
        if !self.is_ancestor(current, target)? {
            return Err(RepositoryError::MergeRequired);
        }
        let commit = self.read_commit(target)?;
        let index = self.tree_index(commit.tree)?;
        self.materialize_index(&index)?;
        let branch = self
            .current_branch()?
            .ok_or(RepositoryError::DetachedHead)?;
        let path = join_path(
            &self.git_dir,
            &mrml_runtime::mrml_format!("refs/heads/{branch}"),
        );
        let lock = mrml_runtime::mrml_format!("{path}.lock");
        if path_exists(&lock) {
            return Err(RepositoryError::AlreadyExists);
        }
        write_file(&lock, mrml_runtime::mrml_format!("{target}\n").as_bytes())?;
        mrml_runtime::rename_file(&lock, &path)?;
        Ok(MergeOutcome::FastForward(target))
    }

    pub fn is_ancestor(
        &self,
        ancestor: ObjectId,
        descendant: ObjectId,
    ) -> Result<bool, RepositoryError> {
        const MAX_COMMITS: usize = 1_000_000;
        let mut pending = Vector::from([descendant]);
        let mut seen: Vector<ObjectId> = Vector::new();
        while let Some(id) = pending.pop() {
            if id == ancestor {
                return Ok(true);
            }
            if seen.iter().any(|value| *value == id) {
                continue;
            }
            if seen.len() >= MAX_COMMITS {
                return Err(RepositoryError::TooManyFiles);
            }
            seen.push(id);
            pending.extend(self.read_commit(id)?.parents.iter().copied());
        }
        Ok(false)
    }

    pub fn merge(
        &self,
        revision: &str,
        name: &str,
        email: &str,
        timestamp: u64,
    ) -> Result<MergeOutcome, RepositoryError> {
        validate_identity(name, email)?;
        if !self.changes()?.is_empty() {
            return Err(RepositoryError::WorktreeDirty);
        }
        let current = self.head()?.ok_or(RepositoryError::ReferenceMissing)?;
        let target = self.resolve_revision(revision)?;
        if self.is_ancestor(target, current)? {
            return Ok(MergeOutcome::UpToDate);
        }
        if !self.is_ancestor(current, target)? {
            write_file(
                &join_path(&self.git_dir, "ORIG_HEAD"),
                mrml_runtime::mrml_format!("{current}\n").as_bytes(),
            )?;
            return self.three_way_merge(current, target, revision, name, email, timestamp);
        }
        let commit = self.read_commit(target)?;
        let target_index = self.tree_index(commit.tree)?;
        self.materialize_index(&target_index)?;
        let branch = self
            .current_branch()?
            .ok_or(RepositoryError::DetachedHead)?;
        let reference = mrml_runtime::mrml_format!("refs/heads/{branch}");
        let path = join_path(&self.git_dir, &reference);
        let lock = mrml_runtime::mrml_format!("{path}.lock");
        if path_exists(&lock) {
            return Err(RepositoryError::AlreadyExists);
        }
        write_file(&lock, mrml_runtime::mrml_format!("{target}\n").as_bytes())?;
        mrml_runtime::rename_file(&lock, &path)?;
        Ok(MergeOutcome::FastForward(target))
    }

    fn merge_base(&self, ours: ObjectId, theirs: ObjectId) -> Result<ObjectId, RepositoryError> {
        const LIMIT: usize = 1_000_000;
        let mut ours_seen = Vector::new();
        let mut pending = Vector::from([ours]);
        while let Some(id) = pending.pop() {
            if ours_seen.iter().any(|value| *value == id) {
                continue;
            }
            if ours_seen.len() >= LIMIT {
                return Err(RepositoryError::TooManyFiles);
            }
            ours_seen.push(id);
            pending.extend(self.read_commit(id)?.parents.iter().copied());
        }
        let mut theirs_seen = Vector::new();
        let mut queue = Vector::from([theirs]);
        let mut cursor = 0;
        while cursor < queue.len() {
            let id = queue[cursor];
            cursor += 1;
            if ours_seen.iter().any(|value| *value == id) {
                return Ok(id);
            }
            if theirs_seen.iter().any(|value| *value == id) {
                continue;
            }
            if theirs_seen.len() >= LIMIT {
                return Err(RepositoryError::TooManyFiles);
            }
            theirs_seen.push(id);
            queue.extend(self.read_commit(id)?.parents.iter().copied());
        }
        Err(RepositoryError::MergeRequired)
    }

    fn three_way_merge(
        &self,
        ours: ObjectId,
        theirs: ObjectId,
        label: &str,
        name: &str,
        email: &str,
        timestamp: u64,
    ) -> Result<MergeOutcome, RepositoryError> {
        let base = self.merge_base(ours, theirs)?;
        let base_index = self.tree_index(self.read_commit(base)?.tree)?;
        let ours_index = self.tree_index(self.read_commit(ours)?.tree)?;
        let theirs_index = self.tree_index(self.read_commit(theirs)?.tree)?;
        let mut names: Vector<Text> = base_index
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect();
        for source in [&ours_index, &theirs_index] {
            for entry in &source.entries {
                if !names.iter().any(|path| path == &entry.path) {
                    names.push(entry.path.clone());
                }
            }
        }
        names.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let mut merged = Index::empty_with_format(self.object_format);
        let mut conflicts: Vector<(Text, Option<Vector<u8>>, Option<Vector<u8>>)> = Vector::new();
        for path in names {
            let b = base_index.entry(&path);
            let o = ours_index.entry(&path);
            let t = theirs_index.entry(&path);
            let chosen = if same_entry(o, t) {
                o
            } else if same_entry(o, b) {
                t
            } else if same_entry(t, b) {
                o
            } else {
                None
            };
            if same_entry(o, t) || same_entry(o, b) || same_entry(t, b) {
                if let Some(entry) = chosen {
                    merged.upsert(entry.clone());
                }
            } else {
                if let Some(entry) = b {
                    let mut value = entry.clone();
                    value.stage = 1;
                    merged.upsert(value);
                }
                if let Some(entry) = o {
                    let mut value = entry.clone();
                    value.stage = 2;
                    merged.upsert(value);
                }
                if let Some(entry) = t {
                    let mut value = entry.clone();
                    value.stage = 3;
                    merged.upsert(value);
                }
                conflicts.push((
                    path,
                    match o {
                        Some(e) => Some(self.read_blob(e.id)?),
                        None => None,
                    },
                    match t {
                        Some(e) => Some(self.read_blob(e.id)?),
                        None => None,
                    },
                ));
            }
        }
        if !conflicts.is_empty() {
            let clean = Index {
                version: 2,
                format: self.object_format,
                entries: merged
                    .entries
                    .iter()
                    .filter(|entry| entry.stage == 0)
                    .cloned()
                    .collect(),
            };
            self.materialize_index(&clean)?;
            for (path, ours_bytes, theirs_bytes) in &conflicts {
                let disk = join_path(&self.worktree, path);
                if let Some(parent) = parent_path(&disk) {
                    create_dir_all(parent)?;
                }
                let ours_text = ours_bytes
                    .as_deref()
                    .and_then(|bytes| core::str::from_utf8(bytes).ok());
                let theirs_text = theirs_bytes
                    .as_deref()
                    .and_then(|bytes| core::str::from_utf8(bytes).ok());
                if let (Some(ours_text), Some(theirs_text)) = (ours_text, theirs_text) {
                    let marked = mrml_runtime::mrml_format!(
                        "<<<<<<< HEAD\n{}=======\n{}>>>>>>> {}\n",
                        ours_text,
                        theirs_text,
                        label
                    );
                    write_file(&disk, marked.as_bytes())?;
                } else if let Some(bytes) = ours_bytes {
                    write_file(&disk, bytes)?;
                }
            }
            self.write_index(&merged)?;
            write_file(
                &join_path(&self.git_dir, "MERGE_HEAD"),
                mrml_runtime::mrml_format!("{theirs}\n").as_bytes(),
            )?;
            return Ok(MergeOutcome::Conflicts(conflicts.len()));
        }
        self.materialize_index(&merged)?;
        let tree = self.write_tree_from_index(&merged)?;
        let message = mrml_runtime::mrml_format!("Merge {label}");
        let id =
            self.create_commit_object(tree, &[ours, theirs], &message, name, email, timestamp)?;
        self.update_current_branch(id)?;
        let original = join_path(&self.git_dir, "ORIG_HEAD");
        if path_is_file(&original) {
            mrml_runtime::remove_file(&original)?;
        }
        Ok(MergeOutcome::Merged(id))
    }

    pub fn abort_merge(&self) -> Result<ObjectId, RepositoryError> {
        let original_path = join_path(&self.git_dir, "ORIG_HEAD");
        let merge_path = join_path(&self.git_dir, "MERGE_HEAD");
        if !path_is_file(&original_path) || !path_is_file(&merge_path) {
            return Err(RepositoryError::ReferenceMissing);
        }
        let value = read_file_text_bounded(&original_path, 4096)?;
        let original = ObjectId::parse_for(self.object_format, value.trim())
            .ok_or(RepositoryError::InvalidReference)?;
        let index = self.tree_index(self.read_commit(original)?.tree)?;
        self.materialize_index(&index)?;
        self.update_current_branch(original)?;
        mrml_runtime::remove_file(&merge_path)?;
        mrml_runtime::remove_file(&original_path)?;
        Ok(original)
    }

    pub fn cherry_pick(
        &self,
        revision: &str,
        committer_name: &str,
        committer_email: &str,
        timestamp: u64,
    ) -> Result<MergeOutcome, RepositoryError> {
        validate_identity(committer_name, committer_email)?;
        if !self.changes()?.is_empty() {
            return Err(RepositoryError::WorktreeDirty);
        }
        let ours = self.head()?.ok_or(RepositoryError::ReferenceMissing)?;
        let theirs = self.resolve_revision(revision)?;
        let picked = self.read_commit(theirs)?;
        if picked.parents.len() > 1 {
            return Err(RepositoryError::MergeRequired);
        }
        let base_index = match picked.parents.first() {
            Some(id) => self.tree_index(self.read_commit(*id)?.tree)?,
            None => Index::empty_with_format(self.object_format),
        };
        let ours_index = self.tree_index(self.read_commit(ours)?.tree)?;
        let theirs_index = self.tree_index(picked.tree)?;
        let mut names: Vector<Text> = base_index
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect();
        for source in [&ours_index, &theirs_index] {
            for entry in &source.entries {
                if !names.iter().any(|path| path == &entry.path) {
                    names.push(entry.path.clone());
                }
            }
        }
        names.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let mut merged = Index::empty_with_format(self.object_format);
        let mut conflicts: Vector<(Text, Option<Vector<u8>>, Option<Vector<u8>>)> = Vector::new();
        for path in names {
            let b = base_index.entry(&path);
            let o = ours_index.entry(&path);
            let t = theirs_index.entry(&path);
            let chosen = if same_entry(o, t) {
                o
            } else if same_entry(o, b) {
                t
            } else if same_entry(t, b) {
                o
            } else {
                None
            };
            if same_entry(o, t) || same_entry(o, b) || same_entry(t, b) {
                if let Some(entry) = chosen {
                    merged.upsert(entry.clone());
                }
            } else {
                if let Some(entry) = b {
                    let mut value = entry.clone();
                    value.stage = 1;
                    merged.upsert(value);
                }
                if let Some(entry) = o {
                    let mut value = entry.clone();
                    value.stage = 2;
                    merged.upsert(value);
                }
                if let Some(entry) = t {
                    let mut value = entry.clone();
                    value.stage = 3;
                    merged.upsert(value);
                }
                conflicts.push((
                    path,
                    match o {
                        Some(e) => Some(self.read_blob(e.id)?),
                        None => None,
                    },
                    match t {
                        Some(e) => Some(self.read_blob(e.id)?),
                        None => None,
                    },
                ));
            }
        }
        write_file(
            &join_path(&self.git_dir, "ORIG_HEAD"),
            mrml_runtime::mrml_format!("{ours}\n").as_bytes(),
        )?;
        if !conflicts.is_empty() {
            let clean = Index {
                version: 2,
                format: self.object_format,
                entries: merged
                    .entries
                    .iter()
                    .filter(|entry| entry.stage == 0)
                    .cloned()
                    .collect(),
            };
            self.materialize_index(&clean)?;
            for (path, ours_bytes, theirs_bytes) in &conflicts {
                let disk = join_path(&self.worktree, path);
                if let Some(parent) = parent_path(&disk) {
                    create_dir_all(parent)?;
                }
                if let (Some(a), Some(b)) = (
                    ours_bytes
                        .as_deref()
                        .and_then(|v| core::str::from_utf8(v).ok()),
                    theirs_bytes
                        .as_deref()
                        .and_then(|v| core::str::from_utf8(v).ok()),
                ) {
                    write_file(
                        &disk,
                        mrml_runtime::mrml_format!(
                            "<<<<<<< HEAD\n{a}=======\n{b}>>>>>>> {revision}\n"
                        )
                        .as_bytes(),
                    )?;
                } else if let Some(bytes) = ours_bytes {
                    write_file(&disk, bytes)?;
                }
            }
            self.write_index(&merged)?;
            write_file(
                &join_path(&self.git_dir, "CHERRY_PICK_HEAD"),
                mrml_runtime::mrml_format!("{theirs}\n").as_bytes(),
            )?;
            return Ok(MergeOutcome::Conflicts(conflicts.len()));
        }
        self.materialize_index(&merged)?;
        let tree = self.write_tree_from_index(&merged)?;
        let mut contents = mrml_runtime::mrml_format!(
            "tree {tree}\nparent {ours}\nauthor {}\ncommitter {committer_name} <{committer_email}> {timestamp} +0000\n\n{}",
            picked.author,
            picked.message
        );
        if !contents.ends_with('\n') {
            contents.push('\n');
        }
        let id = self.write_object(ObjectKind::Commit, contents.as_bytes())?;
        self.update_current_branch(id)?;
        let original = join_path(&self.git_dir, "ORIG_HEAD");
        if path_is_file(&original) {
            mrml_runtime::remove_file(&original)?;
        }
        Ok(MergeOutcome::Merged(id))
    }

    pub fn abort_cherry_pick(&self) -> Result<ObjectId, RepositoryError> {
        self.abort_operation("CHERRY_PICK_HEAD")
    }

    pub fn rebase(
        &self,
        revision: &str,
        committer_name: &str,
        committer_email: &str,
        timestamp: u64,
    ) -> Result<RebaseOutcome, RepositoryError> {
        validate_identity(committer_name, committer_email)?;
        if !self.changes()?.is_empty() {
            return Err(RepositoryError::WorktreeDirty);
        }
        let original = self.head()?.ok_or(RepositoryError::ReferenceMissing)?;
        let target = self.resolve_revision(revision)?;
        if self.is_ancestor(target, original)? {
            return Ok(RebaseOutcome::UpToDate);
        }
        let base = self.merge_base(original, target)?;
        let mut commits = Vector::new();
        let mut cursor = original;
        while cursor != base {
            let commit = self.read_commit(cursor)?;
            if commit.parents.len() != 1 {
                return Err(RepositoryError::MergeRequired);
            }
            commits.push(cursor);
            cursor = commit.parents[0];
            if commits.len() > 1_000_000 {
                return Err(RepositoryError::TooManyFiles);
            }
        }
        commits.reverse();
        write_file(
            &join_path(&self.git_dir, "REBASE_ORIG_HEAD"),
            mrml_runtime::mrml_format!("{original}\n").as_bytes(),
        )?;
        let target_index = self.tree_index(self.read_commit(target)?.tree)?;
        self.materialize_index(&target_index)?;
        self.update_current_branch(target)?;
        let mut head = target;
        for (offset, commit) in commits.iter().enumerate() {
            write_file(
                &join_path(&self.git_dir, "REBASE_HEAD"),
                mrml_runtime::mrml_format!("{commit}\n").as_bytes(),
            )?;
            match self.cherry_pick(
                &commit.to_hex(),
                committer_name,
                committer_email,
                timestamp.saturating_add(offset as u64),
            )? {
                MergeOutcome::Merged(id) => head = id,
                MergeOutcome::Conflicts(count) => return Ok(RebaseOutcome::Conflicts(count)),
                _ => return Err(RepositoryError::MergeRequired),
            }
        }
        for name in ["REBASE_HEAD", "REBASE_ORIG_HEAD"] {
            let path = join_path(&self.git_dir, name);
            if path_is_file(&path) {
                mrml_runtime::remove_file(&path)?;
            }
        }
        Ok(RebaseOutcome::Rebased {
            count: commits.len(),
            head,
        })
    }

    pub fn abort_rebase(&self) -> Result<ObjectId, RepositoryError> {
        let original_path = join_path(&self.git_dir, "REBASE_ORIG_HEAD");
        if !path_is_file(&original_path) {
            return Err(RepositoryError::ReferenceMissing);
        }
        let value = read_file_text_bounded(&original_path, 4096)?;
        let original = ObjectId::parse_for(self.object_format, value.trim())
            .ok_or(RepositoryError::InvalidReference)?;
        let index = self.tree_index(self.read_commit(original)?.tree)?;
        self.materialize_index(&index)?;
        self.update_current_branch(original)?;
        for name in [
            "REBASE_HEAD",
            "REBASE_ORIG_HEAD",
            "CHERRY_PICK_HEAD",
            "ORIG_HEAD",
        ] {
            let path = join_path(&self.git_dir, name);
            if path_is_file(&path) {
                mrml_runtime::remove_file(&path)?;
            }
        }
        Ok(original)
    }

    fn abort_operation(&self, state: &str) -> Result<ObjectId, RepositoryError> {
        let original_path = join_path(&self.git_dir, "ORIG_HEAD");
        let state_path = join_path(&self.git_dir, state);
        if !path_is_file(&original_path) || !path_is_file(&state_path) {
            return Err(RepositoryError::ReferenceMissing);
        }
        let value = read_file_text_bounded(&original_path, 4096)?;
        let original = ObjectId::parse_for(self.object_format, value.trim())
            .ok_or(RepositoryError::InvalidReference)?;
        let index = self.tree_index(self.read_commit(original)?.tree)?;
        self.materialize_index(&index)?;
        self.update_current_branch(original)?;
        mrml_runtime::remove_file(&state_path)?;
        mrml_runtime::remove_file(&original_path)?;
        Ok(original)
    }

    fn materialize_index(&self, target: &Index) -> Result<(), RepositoryError> {
        let current = self.index()?;
        let smudge_crlf = self.autocrlf_mode()?.1;
        let mut files: Vector<(Text, Vector<u8>)> = Vector::new();
        for entry in &target.entries {
            files.push((entry.path.clone(), self.read_blob(entry.id)?));
        }
        for entry in &current.entries {
            if target.entry(&entry.path).is_none() {
                let path = join_path(&self.worktree, &entry.path);
                if path_is_file(&path) {
                    mrml_runtime::remove_file(&path)?;
                }
            }
        }
        for (relative, contents) in files {
            let path = join_path(&self.worktree, &relative);
            if let Some(parent) = parent_path(&path) {
                create_dir_all(parent)?;
            }
            write_file(&path, &smudge_worktree_bytes(&contents, smudge_crlf))?;
        }
        self.write_index(target)
    }

    fn write_index(&self, index: &Index) -> Result<(), RepositoryError> {
        let encoded = index.encode()?;
        let lock = join_path(&self.git_dir, "index.lock");
        if path_exists(&lock) {
            return Err(RepositoryError::AlreadyExists);
        }
        write_file(&lock, &encoded)?;
        mrml_runtime::rename_file(&lock, &join_path(&self.git_dir, "index"))?;
        Ok(())
    }

    pub fn restore(&self, paths: &[Text]) -> Result<(), RepositoryError> {
        let index = self.index()?;
        let smudge_crlf = self.autocrlf_mode()?.1;
        let mut files: Vector<(Text, Vector<u8>)> = Vector::new();
        for path in paths {
            validate_worktree_path(path)?;
            let entry = index.entry(path).ok_or(RepositoryError::ReferenceMissing)?;
            let object = self.read_object(entry.id)?;
            if object.kind != ObjectKind::Blob {
                return Err(RepositoryError::InvalidReference);
            }
            files.push((path.clone(), object.contents));
        }
        for (relative, contents) in files {
            let path = join_path(&self.worktree, &relative);
            if let Some(parent) = parent_path(&path) {
                create_dir_all(parent)?;
            }
            write_file(&path, &smudge_worktree_bytes(&contents, smudge_crlf))?;
        }
        Ok(())
    }

    pub fn unstage(&self, paths: &[Text]) -> Result<(), RepositoryError> {
        let mut index = self.index()?;
        let head = match self.head()? {
            Some(id) => Some(self.tree_index(self.read_commit(id)?.tree)?),
            None => None,
        };
        for path in paths {
            validate_worktree_path(path)?;
            if let Some(entry) = head.as_ref().and_then(|value| value.entry(path)).cloned() {
                index.upsert(entry);
            } else {
                index.remove(path);
            }
        }
        self.write_index(&index)
    }

    pub fn unstage_all(&self) -> Result<(), RepositoryError> {
        let index = match self.head()? {
            Some(id) => self.tree_index(self.read_commit(id)?.tree)?,
            None => Index::empty_with_format(self.object_format),
        };
        self.write_index(&index)
    }

    pub fn diff(&self, staged: bool, paths: &[Text]) -> Result<Vector<FileDiff>, RepositoryError> {
        for path in paths {
            validate_worktree_path(path)?;
        }
        let index = self.index()?;
        let clean_crlf = self.autocrlf_mode()?.0;
        let base = if staged {
            match self.head()? {
                Some(id) => self.tree_index(self.read_commit(id)?.tree)?,
                None => Index::empty_with_format(self.object_format),
            }
        } else {
            index.clone()
        };
        let mut names: Vector<Text> = base
            .entries
            .iter()
            .filter(|entry| entry.stage == 0)
            .map(|entry| entry.path.clone())
            .collect();
        if staged {
            for entry in &index.entries {
                if entry.stage == 0 && !names.iter().any(|name| name == &entry.path) {
                    names.push(entry.path.clone());
                }
            }
        }
        names.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let mut output = Vector::new();
        for name in names {
            if !paths.is_empty()
                && !paths.iter().any(|path| {
                    name.as_str() == path.as_str()
                        || name
                            .strip_prefix(path.as_str())
                            .is_some_and(|rest| rest.starts_with('/'))
                })
            {
                continue;
            }
            let old_entry = base.entry(&name);
            let new_entry = if staged {
                index.entry(&name)
            } else {
                old_entry
            };
            let old = match old_entry {
                Some(entry) => Some(self.read_blob(entry.id)?),
                None => None,
            };
            let new = if staged {
                match new_entry {
                    Some(entry) => Some(self.read_blob(entry.id)?),
                    None => None,
                }
            } else {
                let path = join_path(&self.worktree, &name);
                if path_is_file(&path) {
                    Some(clean_worktree_bytes(
                        &read_file_bounded(&path, MAX_WORKTREE_FILE)?,
                        clean_crlf,
                    ))
                } else {
                    None
                }
            };
            if old != new {
                output.push(FileDiff {
                    path: name,
                    old,
                    new,
                });
            }
        }
        Ok(output)
    }

    pub fn diff_revision(
        &self,
        revision: &str,
        paths: &[Text],
    ) -> Result<Vector<FileDiff>, RepositoryError> {
        for path in paths {
            validate_worktree_path(path)?;
        }
        let clean_crlf = self.autocrlf_mode()?.0;
        let id = self.resolve_revision(revision)?;
        let base = self.tree_index(self.read_commit(id)?.tree)?;
        let mut names: Vector<Text> = base
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect();
        let index = self.index()?;
        for entry in &index.entries {
            if entry.stage == 0 && !names.iter().any(|name| name == &entry.path) {
                names.push(entry.path.clone());
            }
        }
        names.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let mut output = Vector::new();
        for name in names {
            if !paths.is_empty()
                && !paths.iter().any(|path| {
                    name.as_str() == path.as_str()
                        || name
                            .strip_prefix(path.as_str())
                            .is_some_and(|rest| rest.starts_with('/'))
                })
            {
                continue;
            }
            let old = match base.entry(&name) {
                Some(entry) => Some(self.read_blob(entry.id)?),
                None => None,
            };
            let disk = join_path(&self.worktree, &name);
            let new = if path_is_file(&disk) {
                Some(clean_worktree_bytes(
                    &read_file_bounded(&disk, MAX_WORKTREE_FILE)?,
                    clean_crlf,
                ))
            } else {
                None
            };
            if old != new {
                output.push(FileDiff {
                    path: name,
                    old,
                    new,
                });
            }
        }
        Ok(output)
    }

    pub fn conflicted_paths(&self) -> Result<Vector<Text>, RepositoryError> {
        let index = self.index()?;
        let mut paths = Vector::new();
        for entry in &index.entries {
            if entry.stage != 0 && !paths.iter().any(|path| path == &entry.path) {
                paths.push(entry.path.clone());
            }
        }
        Ok(paths)
    }

    pub fn file_history(
        &self,
        path: &str,
        limit: usize,
    ) -> Result<Vector<(ObjectId, Commit)>, RepositoryError> {
        validate_worktree_path(path)?;
        let mut result = Vector::new();
        let mut next = self.head()?;
        let mut previous_blob = None;
        while let Some(id) = next {
            let commit = self.read_commit(id)?;
            let tree = self.tree_index(commit.tree)?;
            let blob = tree.entry(path).map(|entry| entry.id);
            if blob != previous_blob {
                result.push((id, commit.clone()));
                previous_blob = blob;
            }
            next = commit.parents.first().copied();
            if result.len() >= limit {
                break;
            }
        }
        Ok(result)
    }

    pub fn blame(&self, path: &str) -> Result<Vector<BlameLine>, RepositoryError> {
        validate_worktree_path(path)?;
        let head = self.head()?.ok_or(RepositoryError::ReferenceMissing)?;
        let mut child_commit = self.read_commit(head)?;
        let child_index = self.tree_index(child_commit.tree)?;
        let child_blob = child_index
            .entry(path)
            .ok_or(RepositoryError::ReferenceMissing)?
            .id;
        let mut child_text = Text::try_from_utf8(self.read_blob(child_blob)?)
            .map_err(|_| RepositoryError::UnsupportedFileType)?;
        let final_lines: Vector<Text> = split_lines(&child_text)
            .iter()
            .map(|line| Text::from(*line))
            .collect();
        let mut origins: Vector<(Option<usize>, ObjectId, Text)> = final_lines
            .iter()
            .enumerate()
            .map(|(index, _)| (Some(index), head, child_commit.author.clone()))
            .collect();
        loop {
            let Some(parent_id) = child_commit.parents.first().copied() else {
                break;
            };
            let parent_commit = self.read_commit(parent_id)?;
            let parent_index = self.tree_index(parent_commit.tree)?;
            let Some(parent_entry) = parent_index.entry(path) else {
                break;
            };
            let parent_text = Text::try_from_utf8(self.read_blob(parent_entry.id)?)
                .map_err(|_| RepositoryError::UnsupportedFileType)?;
            let mapping = line_mapping(&split_lines(&child_text), &split_lines(&parent_text));
            for (position, commit, author) in &mut origins {
                if let Some(child_position) = *position {
                    if let Some(parent_position) = mapping.get(child_position).copied().flatten() {
                        *position = Some(parent_position);
                        *commit = parent_id;
                        *author = parent_commit.author.clone();
                    } else {
                        *position = None;
                    }
                }
            }
            child_commit = parent_commit;
            child_text = parent_text;
        }
        let mut output = Vector::new();
        for (index, line) in final_lines.into_iter().enumerate() {
            let (_, commit, author) = origins[index].clone();
            output.push(BlameLine {
                commit,
                author,
                line_number: index + 1,
                text: line,
            });
        }
        Ok(output)
    }

    fn read_blob(&self, id: ObjectId) -> Result<Vector<u8>, RepositoryError> {
        let object = self.read_object(id)?;
        if object.kind != ObjectKind::Blob {
            return Err(RepositoryError::InvalidReference);
        }
        Ok(object.contents)
    }

    pub fn branches(&self) -> Result<Vector<(Text, ObjectId)>, RepositoryError> {
        let mut branches = Vector::new();
        let root = join_path(&self.git_dir, "refs/heads");
        if path_is_directory(&root) {
            self.collect_references(&root, "", &mut branches)?;
        }
        for (reference, id) in self.packed_references()? {
            if let Some(name) = reference.strip_prefix("refs/heads/")
                && !branches.iter().any(|(existing, _)| existing == name)
            {
                branches.push((name.into(), id));
            }
        }
        branches.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        Ok(branches)
    }

    fn collect_references(
        &self,
        directory: &str,
        prefix: &str,
        output: &mut Vector<(Text, ObjectId)>,
    ) -> Result<(), RepositoryError> {
        for entry in read_directory(directory)? {
            if entry.is_symlink {
                return Err(RepositoryError::UnsupportedFileType);
            }
            let path = join_path(directory, &entry.name);
            let name = if prefix.is_empty() {
                entry.name.clone()
            } else {
                mrml_runtime::mrml_format!("{}/{}", prefix, entry.name)
            };
            if entry.is_directory {
                self.collect_references(&path, &name, output)?;
            } else {
                let value = read_file_text_bounded(&path, 4096)?;
                let id = ObjectId::parse_for(self.object_format, value.trim())
                    .ok_or(RepositoryError::InvalidReference)?;
                output.push((name, id));
            }
        }
        Ok(())
    }

    pub fn create_branch(&self, name: &str, switch: bool) -> Result<ObjectId, RepositoryError> {
        let reference = mrml_runtime::mrml_format!("refs/heads/{name}");
        validate_reference(&reference)?;
        let id = self.head()?.ok_or(RepositoryError::ReferenceMissing)?;
        let path = join_path(&self.git_dir, &reference);
        if self.read_reference(&reference)?.is_some() {
            return Err(RepositoryError::ReferenceExists);
        }
        if let Some(parent) = parent_path(&path) {
            create_dir_all(parent)?;
        }
        write_file(&path, mrml_runtime::mrml_format!("{id}\n").as_bytes())?;
        if switch {
            write_file(
                &join_path(&self.git_dir, "HEAD"),
                mrml_runtime::mrml_format!("ref: {reference}\n").as_bytes(),
            )?;
        }
        Ok(id)
    }

    pub fn delete_branch(&self, name: &str) -> Result<(), RepositoryError> {
        let reference = mrml_runtime::mrml_format!("refs/heads/{name}");
        validate_reference(&reference)?;
        if self.current_branch()?.as_deref() == Some(name) {
            return Err(RepositoryError::CurrentBranch);
        }
        let path = join_path(&self.git_dir, &reference);
        if self.read_reference(&reference)?.is_none() {
            return Err(RepositoryError::ReferenceMissing);
        }
        if path_is_file(&path) {
            mrml_runtime::remove_file(&path)?;
        }
        self.remove_packed_reference(&reference)?;
        Ok(())
    }

    pub fn tags(&self) -> Result<Vector<(Text, ObjectId)>, RepositoryError> {
        let mut tags = Vector::new();
        let root = join_path(&self.git_dir, "refs/tags");
        if path_is_directory(&root) {
            self.collect_references(&root, "", &mut tags)?;
        }
        for (reference, id) in self.packed_references()? {
            if let Some(name) = reference.strip_prefix("refs/tags/")
                && !tags.iter().any(|(existing, _)| existing == name)
            {
                tags.push((name.into(), id));
            }
        }
        tags.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        Ok(tags)
    }

    pub fn create_tag(&self, name: &str) -> Result<ObjectId, RepositoryError> {
        let reference = mrml_runtime::mrml_format!("refs/tags/{name}");
        validate_reference(&reference)?;
        let id = self.head()?.ok_or(RepositoryError::ReferenceMissing)?;
        let path = join_path(&self.git_dir, &reference);
        if self.read_reference(&reference)?.is_some() {
            return Err(RepositoryError::ReferenceExists);
        }
        if let Some(parent) = parent_path(&path) {
            create_dir_all(parent)?;
        }
        write_file(&path, mrml_runtime::mrml_format!("{id}\n").as_bytes())?;
        Ok(id)
    }

    fn remove_packed_reference(&self, reference: &str) -> Result<(), RepositoryError> {
        let path = join_path(&self.git_dir, "packed-refs");
        if !path_is_file(&path) {
            return Ok(());
        }
        let text = read_file_text_bounded(&path, MAX_PACKED_REFS_BYTES)?;
        let mut output = Text::new();
        let mut removed = false;
        let mut skip_peeled = false;
        for line in text.lines() {
            if skip_peeled && line.starts_with('^') {
                skip_peeled = false;
                continue;
            }
            skip_peeled = false;
            let matches = !line.starts_with(['#', '^'])
                && line
                    .split_once(' ')
                    .is_some_and(|(_, name)| name == reference);
            if matches {
                removed = true;
                skip_peeled = true;
            } else {
                output.push_str(line);
                output.push('\n');
            }
        }
        if removed {
            write_file(&path, output.as_bytes())?;
        }
        Ok(())
    }

    pub fn create_signed_tag(
        &self,
        name: &str,
        message: &str,
        tagger: &str,
        email: &str,
        timestamp: u64,
        key: &RsaPrivateKey,
    ) -> Result<ObjectId, RepositoryError> {
        self.create_signed_tag_with(
            name,
            message,
            tagger,
            email,
            timestamp,
            GitSignatureFormat::Ssh,
            |payload| sign_sshsig(key, "git", payload).map_err(|_| RepositoryError::Signing),
            |payload, armor| {
                verify_sshsig(key.public_key(), "git", payload, armor)
                    .map_err(|_| RepositoryError::Signing)
            },
        )
    }

    pub fn create_signed_tag_with<F, V>(
        &self,
        name: &str,
        message: &str,
        tagger: &str,
        email: &str,
        timestamp: u64,
        signature_format: GitSignatureFormat,
        signer: F,
        verifier: V,
    ) -> Result<ObjectId, RepositoryError>
    where
        F: FnOnce(&[u8]) -> Result<Text, RepositoryError>,
        V: FnOnce(&[u8], &str) -> Result<(), RepositoryError>,
    {
        let reference = mrml_runtime::mrml_format!("refs/tags/{name}");
        validate_reference(&reference)?;
        let path = join_path(&self.git_dir, &reference);
        if self.read_reference(&reference)?.is_some() {
            return Err(RepositoryError::ReferenceExists);
        }
        validate_identity(tagger, email)?;
        if message.trim().is_empty() || message.contains('\0') {
            return Err(RepositoryError::InvalidIdentity);
        }
        let target = self.head()?.ok_or(RepositoryError::ReferenceMissing)?;
        let mut unsigned = mrml_runtime::mrml_format!(
            "object {target}\ntype commit\ntag {name}\ntagger {tagger} <{email}> {timestamp} +0000\n\n"
        );
        unsigned.push_str(message.trim());
        unsigned.push('\n');
        let signature = signer(unsigned.as_bytes())?;
        validate_signature_armor(&signature, signature_format)?;
        verifier(unsigned.as_bytes(), &signature)?;
        let mut contents = unsigned;
        contents.push_str(&signature);
        let id = self.write_object(ObjectKind::Tag, contents.as_bytes())?;
        if let Some(parent) = parent_path(&path) {
            create_dir_all(parent)?;
        }
        write_file(&path, mrml_runtime::mrml_format!("{id}\n").as_bytes())?;
        Ok(id)
    }

    pub fn verify_tag_signature(
        &self,
        id: ObjectId,
        key: &RsaPublicKey,
    ) -> Result<(), RepositoryError> {
        self.verify_tag_signature_with(id, GitSignatureFormat::Ssh, |payload, armor| {
            verify_sshsig(key, "git", payload, armor).map_err(|_| RepositoryError::Signing)
        })
    }

    pub fn verify_tag_signature_with<F>(
        &self,
        id: ObjectId,
        signature_format: GitSignatureFormat,
        verifier: F,
    ) -> Result<(), RepositoryError>
    where
        F: FnOnce(&[u8], &str) -> Result<(), RepositoryError>,
    {
        let object = self.read_object(id)?;
        if object.kind != ObjectKind::Tag {
            return Err(RepositoryError::InvalidReference);
        }
        let (unsigned, armor) = split_tag_signature(&object.contents, signature_format)?;
        verifier(unsigned, armor)
    }

    pub fn remotes(&self) -> Result<Vector<(Text, Text)>, RepositoryError> {
        let config = read_file_text_bounded(&join_path(&self.git_dir, "config"), 1024 * 1024)?;
        let mut output = Vector::new();
        let mut current: Option<Text> = None;
        for raw in config.lines() {
            let line = raw.trim();
            if line.starts_with('[') {
                current = remote_section(line).map(Into::into);
            } else if let Some(name) = &current {
                if let Some((key, value)) = line.split_once('=') {
                    if key.trim() == "url" {
                        output.push((name.clone(), value.trim().into()));
                    }
                }
            }
        }
        Ok(output)
    }

    pub fn set_remote(
        &self,
        name: &str,
        url: &str,
        require_existing: bool,
    ) -> Result<(), RepositoryError> {
        validate_config_name(name)?;
        if url.is_empty() || url.chars().any(char::is_control) {
            return Err(RepositoryError::InvalidReference);
        }
        let path = join_path(&self.git_dir, "config");
        let config = read_file_text_bounded(&path, 1024 * 1024)?;
        let target = mrml_runtime::mrml_format!("[remote \"{name}\"]");
        let mut output = Text::new();
        let mut in_target = false;
        let mut found = false;
        let mut wrote_url = false;
        for raw in config.lines() {
            let line = raw.trim();
            if line.starts_with('[') {
                if in_target && !wrote_url {
                    output.push_str(&mrml_runtime::mrml_format!("\turl = {url}\n"));
                }
                in_target = target == line;
                found |= in_target;
                wrote_url = false;
            }
            if in_target
                && line
                    .split_once('=')
                    .is_some_and(|(key, _)| key.trim() == "url")
            {
                output.push_str(&mrml_runtime::mrml_format!("\turl = {url}\n"));
                wrote_url = true;
            } else {
                output.push_str(raw);
                output.push('\n');
            }
        }
        if in_target && !wrote_url {
            output.push_str(&mrml_runtime::mrml_format!("\turl = {url}\n"));
        }
        if !found {
            if require_existing {
                return Err(RepositoryError::ReferenceMissing);
            }
            output.push_str(&mrml_runtime::mrml_format!(
                "\n{target}\n\turl = {url}\n\tfetch = +refs/heads/*:refs/remotes/{name}/*\n"
            ));
        }
        write_file(&path, output.as_bytes())?;
        Ok(())
    }

    pub fn update_remote_ref(
        &self,
        remote: &str,
        source: &str,
        id: ObjectId,
    ) -> Result<(), RepositoryError> {
        if id.format() != self.object_format {
            return Err(RepositoryError::InvalidReference);
        }
        validate_config_name(remote)?;
        let branch = source
            .strip_prefix("refs/heads/")
            .ok_or(RepositoryError::InvalidReference)?;
        validate_reference(source)?;
        let reference = mrml_runtime::mrml_format!("refs/remotes/{remote}/{branch}");
        validate_reference(&reference)?;
        let path = join_path(&self.git_dir, &reference);
        if let Some(parent) = parent_path(&path) {
            create_dir_all(parent)?;
        }
        write_file(&path, mrml_runtime::mrml_format!("{id}\n").as_bytes())?;
        Ok(())
    }

    /// Durably selects one complete remote-tracking branch set with a single
    /// rename. Once present, this manifest is authoritative over legacy loose
    /// and packed remote refs, including for branches omitted by the new set.
    pub fn activate_remote_refs_atomically(
        &self,
        remote: &str,
        branches: &[(Text, ObjectId)],
    ) -> Result<(), RepositoryError> {
        validate_config_name(remote)?;
        if branches.len() > MAX_WORKTREE_ENTRIES {
            return Err(RepositoryError::TooManyFiles);
        }
        let mut sorted: Vector<(Text, ObjectId)> = branches.iter().cloned().collect();
        sorted.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        for (index, (branch, id)) in sorted.iter().enumerate() {
            validate_reference(&mrml_runtime::mrml_format!("refs/heads/{branch}"))?;
            if id.format() != self.object_format || index > 0 && sorted[index - 1].0 == *branch {
                return Err(RepositoryError::InvalidReference);
            }
        }
        let root = join_path(&self.git_dir, "mrml-remote-refs");
        create_dir_all(&root)?;
        let active = join_path(&root, &mrml_runtime::mrml_format!("{remote}.refs"));
        let temporary = mrml_runtime::mrml_format!("{active}.new");
        let lock = mrml_runtime::mrml_format!("{active}.lock");
        let lock_file = File::create_new(&lock).map_err(|_| RepositoryError::AlreadyExists)?;
        let result = (|| {
            if path_exists(&temporary) {
                return Err(RepositoryError::AlreadyExists);
            }
            let bytes = encode_remote_refs(self.object_format, &sorted)?;
            let mut file = File::create_new(&temporary)?;
            file.write_all(&bytes)?;
            file.sync()?;
            drop(file);
            rename_file(&temporary, &active)?;
            sync_directory(&root)?;
            if self.active_remote_refs(remote)? != Some(sorted.clone()) {
                return Err(RepositoryError::InvalidReference);
            }
            Ok(())
        })();
        drop(lock_file);
        let _ = remove_file(&lock);
        if result.is_err() && path_exists(&temporary) {
            let _ = remove_file(&temporary);
        }
        result
    }

    pub(crate) fn active_remote_refs(
        &self,
        remote: &str,
    ) -> Result<Option<Vector<(Text, ObjectId)>>, RepositoryError> {
        validate_config_name(remote)?;
        let path = join_path(
            &join_path(&self.git_dir, "mrml-remote-refs"),
            &mrml_runtime::mrml_format!("{remote}.refs"),
        );
        if !path_is_file(&path) {
            return Ok(None);
        }
        parse_remote_refs(
            self.object_format,
            &read_file_bounded(&path, MAX_REMOTE_REFS_BYTES)?,
        )
        .map(Some)
    }

    pub fn prune_remote_refs(
        &self,
        remote: &str,
        live_branches: &[Text],
    ) -> Result<usize, RepositoryError> {
        validate_config_name(remote)?;
        for branch in live_branches {
            validate_reference(&mrml_runtime::mrml_format!("refs/heads/{branch}"))?;
        }
        let root = join_path(
            &self.git_dir,
            &mrml_runtime::mrml_format!("refs/remotes/{remote}"),
        );
        if !path_exists(&root) {
            return Ok(0);
        }
        let mut removed = 0;
        self.prune_remote_directory(&root, "", live_branches, 0, &mut removed)?;
        Ok(removed)
    }

    fn prune_remote_directory(
        &self,
        directory: &str,
        prefix: &str,
        live_branches: &[Text],
        depth: usize,
        removed: &mut usize,
    ) -> Result<(), RepositoryError> {
        if depth > MAX_DEPTH {
            return Err(RepositoryError::TooDeep);
        }
        for entry in read_directory(directory)? {
            if entry.is_symlink {
                return Err(RepositoryError::UnsupportedFileType);
            }
            let path = join_path(directory, &entry.name);
            let branch = if prefix.is_empty() {
                entry.name.clone()
            } else {
                mrml_runtime::mrml_format!("{prefix}/{}", entry.name)
            };
            if entry.is_directory {
                self.prune_remote_directory(&path, &branch, live_branches, depth + 1, removed)?;
            } else if !live_branches.iter().any(|live| live == &branch) {
                mrml_runtime::remove_file(&path)?;
                *removed = removed
                    .checked_add(1)
                    .ok_or(RepositoryError::TooManyFiles)?;
            }
        }
        Ok(())
    }

    pub fn config_value(&self, section: &str, key: &str) -> Result<Option<Text>, RepositoryError> {
        validate_config_name(section)?;
        validate_config_name(key)?;
        let config = read_file_text_bounded(&join_path(&self.git_dir, "config"), 1024 * 1024)?;
        if let Some(value) = config_text_value(&config, section, key) {
            return Ok(Some(value));
        }
        if let Some(path) = global_git_config_path()
            && path_is_file(&path)
        {
            let global = read_file_text_bounded(&path, 1024 * 1024)?;
            return Ok(config_text_value(&global, section, key));
        }
        Ok(None)
    }

    fn autocrlf_mode(&self) -> Result<(bool, bool), RepositoryError> {
        let mut value = self.config_value("core", "autocrlf")?;
        if value.is_none() {
            let global = global_git_config_path();
            if let Some(path) = global
                && path_is_file(&path)
            {
                let text = read_file_text_bounded(&path, 1024 * 1024)?;
                value = config_text_value(&text, "core", "autocrlf");
            }
        }
        Ok(match value.as_deref() {
            Some(value) if value.eq_ignore_ascii_case("true") => (true, true),
            Some(value) if value.eq_ignore_ascii_case("input") => (true, false),
            _ if cfg!(windows) => (true, false),
            _ => (false, false),
        })
    }

    pub fn set_config_value(
        &self,
        section: &str,
        key: &str,
        value: &str,
    ) -> Result<(), RepositoryError> {
        validate_config_name(section)?;
        validate_config_name(key)?;
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(RepositoryError::InvalidReference);
        }
        let path = join_path(&self.git_dir, "config");
        let config = read_file_text_bounded(&path, 1024 * 1024)?;
        let target = mrml_runtime::mrml_format!("[{section}]");
        let mut output = Text::new();
        let mut active = false;
        let mut found_section = false;
        let mut wrote = false;
        for raw in config.lines() {
            let line = raw.trim();
            if line.starts_with('[') {
                if active && !wrote {
                    output.push_str(&mrml_runtime::mrml_format!("\t{key} = {value}\n"));
                    wrote = true;
                }
                active = config_section_matches(line, section);
                found_section |= active;
            }
            if active
                && line
                    .split_once('=')
                    .is_some_and(|(found, _)| found.trim().eq_ignore_ascii_case(key))
            {
                output.push_str(&mrml_runtime::mrml_format!("\t{key} = {value}\n"));
                wrote = true;
            } else {
                output.push_str(raw);
                output.push('\n');
            }
        }
        if active && !wrote {
            output.push_str(&mrml_runtime::mrml_format!("\t{key} = {value}\n"));
        }
        if !found_section {
            output.push_str(&mrml_runtime::mrml_format!(
                "\n{target}\n\t{key} = {value}\n"
            ));
        }
        write_file(&path, output.as_bytes())?;
        Ok(())
    }

    pub fn set_upstream(&self, spec: &str) -> Result<(), RepositoryError> {
        let (remote, branch) = spec
            .split_once('/')
            .ok_or(RepositoryError::InvalidReference)?;
        validate_config_name(remote)?;
        validate_reference(&mrml_runtime::mrml_format!("refs/heads/{branch}"))?;
        self.resolve_revision(&mrml_runtime::mrml_format!(
            "refs/remotes/{remote}/{branch}"
        ))?;
        let current = self
            .current_branch()?
            .ok_or(RepositoryError::DetachedHead)?;
        let path = join_path(&self.git_dir, "config");
        let config = read_file_text_bounded(&path, 1024 * 1024)?;
        let target = mrml_runtime::mrml_format!("[branch \"{current}\"]");
        let mut output = Text::new();
        let mut active = false;
        let mut found = false;
        let mut remote_written = false;
        let mut merge_written = false;
        for raw in config.lines() {
            let line = raw.trim();
            if line.starts_with('[') {
                if active {
                    if !remote_written {
                        output.push_str(&mrml_runtime::mrml_format!("\tremote = {remote}\n"));
                    }
                    if !merge_written {
                        output.push_str(&mrml_runtime::mrml_format!(
                            "\tmerge = refs/heads/{branch}\n"
                        ));
                    }
                }
                active = target == line;
                found |= active;
                remote_written = false;
                merge_written = false;
            }
            if active
                && line
                    .split_once('=')
                    .is_some_and(|(key, _)| key.trim() == "remote")
            {
                output.push_str(&mrml_runtime::mrml_format!("\tremote = {remote}\n"));
                remote_written = true;
            } else if active
                && line
                    .split_once('=')
                    .is_some_and(|(key, _)| key.trim() == "merge")
            {
                output.push_str(&mrml_runtime::mrml_format!(
                    "\tmerge = refs/heads/{branch}\n"
                ));
                merge_written = true;
            } else {
                output.push_str(raw);
                output.push('\n');
            }
        }
        if active {
            if !remote_written {
                output.push_str(&mrml_runtime::mrml_format!("\tremote = {remote}\n"));
            }
            if !merge_written {
                output.push_str(&mrml_runtime::mrml_format!(
                    "\tmerge = refs/heads/{branch}\n"
                ));
            }
        }
        if !found {
            output.push_str(&mrml_runtime::mrml_format!(
                "\n{target}\n\tremote = {remote}\n\tmerge = refs/heads/{branch}\n"
            ));
        }
        write_file(&path, output.as_bytes())?;
        Ok(())
    }

    pub fn upstream_status(&self) -> Result<Option<(Text, usize, usize)>, RepositoryError> {
        let branch = self
            .current_branch()?
            .ok_or(RepositoryError::DetachedHead)?;
        let config = read_file_text_bounded(&join_path(&self.git_dir, "config"), 1024 * 1024)?;
        let target = mrml_runtime::mrml_format!("[branch \"{branch}\"]");
        let mut active = false;
        let mut remote = None;
        let mut merge: Option<Text> = None;
        for raw in config.lines() {
            let line = raw.trim();
            if line.starts_with('[') {
                active = target == line;
            } else if active {
                if let Some((key, value)) = line.split_once('=') {
                    match key.trim() {
                        "remote" => remote = Some(Text::from(value.trim())),
                        "merge" => merge = value.trim().strip_prefix("refs/heads/").map(Into::into),
                        _ => {}
                    }
                }
            }
        }
        let (Some(remote), Some(upstream_branch)) = (remote, merge) else {
            return Ok(None);
        };
        let local = self.head()?.ok_or(RepositoryError::ReferenceMissing)?;
        let remote_id = self.resolve_revision(&mrml_runtime::mrml_format!(
            "refs/remotes/{remote}/{upstream_branch}"
        ))?;
        let left = self.reachable_commits(local)?;
        let right = self.reachable_commits(remote_id)?;
        let ahead = left.iter().filter(|id| !right.contains(id)).count();
        let behind = right.iter().filter(|id| !left.contains(id)).count();
        Ok(Some((
            mrml_runtime::mrml_format!("{remote}/{upstream_branch}"),
            ahead,
            behind,
        )))
    }

    fn reachable_commits(&self, start: ObjectId) -> Result<Vector<ObjectId>, RepositoryError> {
        let mut pending = Vector::from([start]);
        let mut seen = Vector::new();
        while let Some(id) = pending.pop() {
            if seen.contains(&id) {
                continue;
            }
            if seen.len() >= 1_000_000 {
                return Err(RepositoryError::TooManyFiles);
            }
            let commit = self.read_commit(id)?;
            seen.push(id);
            pending.extend(commit.parents.iter().copied());
        }
        Ok(seen)
    }

    pub fn stage(&self, paths: &[Text]) -> Result<(), RepositoryError> {
        let mut index = self.index()?;
        let clean_crlf = self.autocrlf_mode()?.0;
        for relative in paths {
            validate_worktree_path(relative)?;
            index.remove(relative);
            let disk_path = join_path(&self.worktree, relative);
            if !path_exists(&disk_path) {
                continue;
            }
            if !path_is_file(&disk_path) {
                return Err(RepositoryError::UnsupportedFileType);
            }
            let contents = read_file_bounded(&disk_path, MAX_WORKTREE_FILE).map_err(|error| {
                if error == FileError::ReadFailed {
                    RepositoryError::FileTooLarge
                } else {
                    error.into()
                }
            })?;
            let contents = clean_worktree_bytes(&contents, clean_crlf);
            let id = self.write_object(ObjectKind::Blob, &contents)?;
            index.upsert(crate::IndexEntry {
                path: relative.clone(),
                id,
                mode: 0o100644,
                size: contents.len() as u32,
                stage: 0,
            });
        }
        let encoded = index.encode()?;
        let temporary = join_path(&self.git_dir, "index.lock");
        if path_exists(&temporary) {
            return Err(RepositoryError::AlreadyExists);
        }
        write_file(&temporary, &encoded)?;
        mrml_runtime::rename_file(&temporary, &join_path(&self.git_dir, "index"))?;
        Ok(())
    }

    pub fn remove_paths(&self, paths: &[Text]) -> Result<(), RepositoryError> {
        if paths.is_empty() {
            return Err(RepositoryError::InvalidWorktreePath);
        }
        let mut checked = Vector::new();
        checked
            .try_reserve_exact(paths.len())
            .map_err(|_| RepositoryError::TooManyFiles)?;
        let index = self.index()?;
        for relative in paths {
            validate_worktree_path(relative)?;
            let disk = join_path(&self.worktree, relative);
            if !path_is_file(&disk) || index.entry(relative).is_none() {
                return Err(RepositoryError::ReferenceMissing);
            }
            checked.push(disk);
        }
        for disk in checked {
            mrml_runtime::remove_file(&disk)?;
        }
        self.stage(paths)
    }

    pub fn move_path(&self, source: &str, destination: &str) -> Result<(), RepositoryError> {
        validate_worktree_path(source)?;
        validate_worktree_path(destination)?;
        if source == destination || self.index()?.entry(source).is_none() {
            return Err(RepositoryError::InvalidWorktreePath);
        }
        let source_disk = join_path(&self.worktree, source);
        let destination_disk = join_path(&self.worktree, destination);
        if !path_is_file(&source_disk) || path_exists(&destination_disk) {
            return Err(RepositoryError::AlreadyExists);
        }
        if let Some(parent) = parent_path(&destination_disk) {
            create_dir_all(parent)?;
        }
        mrml_runtime::rename_file(&source_disk, &destination_disk)?;
        self.stage(&[Text::from(source), Text::from(destination)])
    }

    pub fn write_tree(&self) -> Result<ObjectId, RepositoryError> {
        let index = self.index()?;
        self.write_tree_from_index(&index)
    }

    fn write_tree_from_index(&self, index: &Index) -> Result<ObjectId, RepositoryError> {
        if index.entries.iter().any(|entry| entry.stage != 0) {
            return Err(RepositoryError::ConflictedIndex);
        }
        self.write_tree_prefix(index, "")
    }

    fn write_tree_prefix(&self, index: &Index, prefix: &str) -> Result<ObjectId, RepositoryError> {
        let mut items: Vector<TreeItem> = Vector::new();
        for entry in &index.entries {
            let Some(remainder) = entry.path.strip_prefix(prefix) else {
                continue;
            };
            if let Some(split) = remainder.find('/') {
                let name = &remainder[..split];
                if items.iter().any(|item| item.directory && item.name == name) {
                    continue;
                }
                let mut child_prefix = Text::from(prefix);
                child_prefix.push_str(name);
                child_prefix.push('/');
                let id = self.write_tree_prefix(index, &child_prefix)?;
                items.push(TreeItem {
                    name: name.into(),
                    mode: 0o40000,
                    id,
                    directory: true,
                });
            } else if !remainder.is_empty() {
                items.push(TreeItem {
                    name: remainder.into(),
                    mode: entry.mode,
                    id: entry.id,
                    directory: false,
                });
            }
        }
        items.sort_unstable_by(|left, right| tree_name_cmp(left, right));
        let mut contents = Vector::new();
        for item in items {
            let mode = mrml_runtime::mrml_format!("{:o}", item.mode);
            contents.extend(mode.as_bytes().iter().copied());
            contents.push(b' ');
            contents.extend(item.name.as_bytes().iter().copied());
            contents.push(0);
            contents.extend(item.id.as_bytes().iter().copied());
        }
        self.write_object(ObjectKind::Tree, &contents)
    }

    pub fn commit(
        &self,
        message: &str,
        name: &str,
        email: &str,
        timestamp: u64,
    ) -> Result<ObjectId, RepositoryError> {
        self.commit_internal(message, name, email, timestamp, None)
    }

    pub fn commit_signed(
        &self,
        message: &str,
        name: &str,
        email: &str,
        timestamp: u64,
        key: &RsaPrivateKey,
    ) -> Result<ObjectId, RepositoryError> {
        self.commit_signed_with(
            message,
            name,
            email,
            timestamp,
            GitSignatureFormat::Ssh,
            |payload| sign_sshsig(key, "git", payload).map_err(|_| RepositoryError::Signing),
            |payload, armor| {
                verify_sshsig(key.public_key(), "git", payload, armor)
                    .map_err(|_| RepositoryError::Signing)
            },
        )
    }

    pub fn commit_signed_with<F, V>(
        &self,
        message: &str,
        name: &str,
        email: &str,
        timestamp: u64,
        signature_format: GitSignatureFormat,
        mut signer: F,
        mut verifier: V,
    ) -> Result<ObjectId, RepositoryError>
    where
        F: FnMut(&[u8]) -> Result<Text, RepositoryError>,
        V: FnMut(&[u8], &str) -> Result<(), RepositoryError>,
    {
        self.commit_internal(
            message,
            name,
            email,
            timestamp,
            Some(CommitSigning::Single(
                signature_format,
                &mut signer,
                &mut verifier,
            )),
        )
    }

    /// Create a commit whose canonical payload is signed first with ML-DSA-65,
    /// then covered (including that first signature) by an OpenPGP signature.
    /// Stock Git can verify the outer OpenPGP signature; MRML requires both.
    pub fn commit_hybrid_signed_with<M, P, PV, MV>(
        &self,
        message: &str,
        name: &str,
        email: &str,
        timestamp: u64,
        mut ml_dsa_signer: M,
        mut openpgp_signer: P,
        mut openpgp_verifier: PV,
        mut ml_dsa_verifier: MV,
    ) -> Result<ObjectId, RepositoryError>
    where
        M: FnMut(&[u8]) -> Result<Text, RepositoryError>,
        P: FnMut(&[u8]) -> Result<Text, RepositoryError>,
        PV: FnMut(&[u8], &str) -> Result<(), RepositoryError>,
        MV: FnMut(&[u8], &str) -> Result<(), RepositoryError>,
    {
        self.commit_internal(
            message,
            name,
            email,
            timestamp,
            Some(CommitSigning::Hybrid(
                &mut ml_dsa_signer,
                &mut openpgp_signer,
                &mut openpgp_verifier,
                &mut ml_dsa_verifier,
            )),
        )
    }

    fn commit_internal(
        &self,
        message: &str,
        name: &str,
        email: &str,
        timestamp: u64,
        signer: Option<CommitSigning<'_>>,
    ) -> Result<ObjectId, RepositoryError> {
        validate_identity(name, email)?;
        if message.trim().is_empty() || message.chars().any(|character| character == '\0') {
            return Err(RepositoryError::InvalidIdentity);
        }
        let branch = self
            .current_branch()?
            .ok_or(RepositoryError::DetachedHead)?;
        let tree = self.write_tree()?;
        let parent = self.head()?;
        let merge_head_path = join_path(&self.git_dir, "MERGE_HEAD");
        if !path_is_file(&merge_head_path)
            && parent
                .map(|id| self.read_commit(id).map(|commit| commit.tree == tree))
                .transpose()?
                .unwrap_or(false)
        {
            return Err(RepositoryError::NoChanges);
        }
        let mut contents = mrml_runtime::mrml_format!("tree {}\n", tree);
        if let Some(parent) = parent {
            contents.push_str(&mrml_runtime::mrml_format!("parent {}\n", parent));
        }
        if path_is_file(&merge_head_path) {
            let value = read_file_text_bounded(&merge_head_path, 4096)?;
            let merge_parent = ObjectId::parse_for(self.object_format, value.trim())
                .ok_or(RepositoryError::InvalidReference)?;
            contents.push_str(&mrml_runtime::mrml_format!("parent {merge_parent}\n"));
        }
        contents.push_str(&mrml_runtime::mrml_format!(
            "author {} <{}> {} +0000\ncommitter {} <{}> {} +0000\n",
            name,
            email,
            timestamp,
            name,
            email,
            timestamp
        ));
        let mut unsigned = contents.clone();
        unsigned.push('\n');
        unsigned.push_str(message.trim());
        unsigned.push('\n');
        if let Some(signer) = signer {
            let (signature_format, armor) = match signer {
                CommitSigning::Single(signature_format, signer, verifier) => {
                    let signature = signer(unsigned.as_bytes())?;
                    validate_signature_armor(&signature, signature_format)?;
                    verifier(unsigned.as_bytes(), &signature)?;
                    (signature_format, signature)
                }
                CommitSigning::Hybrid(
                    ml_dsa_signer,
                    openpgp_signer,
                    openpgp_verifier,
                    ml_dsa_verifier,
                ) => {
                    let ml_dsa = ml_dsa_signer(unsigned.as_bytes())?;
                    validate_ml_dsa_armor(&ml_dsa)?;
                    append_multiline_header(&mut contents, "mrml-mldsa65", &ml_dsa);
                    let mut outer_payload = contents.clone();
                    outer_payload.push('\n');
                    outer_payload.push_str(message.trim());
                    outer_payload.push('\n');
                    let openpgp = openpgp_signer(outer_payload.as_bytes())?;
                    validate_signature_armor(&openpgp, GitSignatureFormat::OpenPgp)?;
                    openpgp_verifier(outer_payload.as_bytes(), &openpgp)?;
                    ml_dsa_verifier(unsigned.as_bytes(), &ml_dsa)?;
                    (GitSignatureFormat::OpenPgp, openpgp)
                }
            };
            validate_signature_armor(&armor, signature_format)?;
            let header = match self.object_format {
                ObjectFormat::Sha1 => "gpgsig",
                ObjectFormat::Sha256 => "gpgsig-sha256",
            };
            append_multiline_header(&mut contents, header, &armor);
            contents.push('\n');
            contents.push_str(message.trim());
            contents.push('\n');
        } else {
            contents = unsigned;
        }
        let id = self.write_object(ObjectKind::Commit, contents.as_bytes())?;
        let reference = mrml_runtime::mrml_format!("refs/heads/{}", branch);
        validate_reference(&reference)?;
        let path = join_path(&self.git_dir, &reference);
        if let Some(parent) = parent_path(&path) {
            create_dir_all(parent)?;
        }
        let lock = mrml_runtime::mrml_format!("{}.lock", path);
        if path_exists(&lock) {
            return Err(RepositoryError::AlreadyExists);
        }
        write_file(&lock, mrml_runtime::mrml_format!("{}\n", id).as_bytes())?;
        mrml_runtime::rename_file(&lock, &path)?;
        if path_is_file(&merge_head_path) {
            mrml_runtime::remove_file(&merge_head_path)?;
        }
        let cherry_pick = join_path(&self.git_dir, "CHERRY_PICK_HEAD");
        if path_is_file(&cherry_pick) {
            mrml_runtime::remove_file(&cherry_pick)?;
        }
        let original = join_path(&self.git_dir, "ORIG_HEAD");
        if path_is_file(&original) {
            mrml_runtime::remove_file(&original)?;
        }
        Ok(id)
    }

    pub fn verify_commit_signature(
        &self,
        id: ObjectId,
        key: &RsaPublicKey,
    ) -> Result<(), RepositoryError> {
        self.verify_commit_signature_with(id, GitSignatureFormat::Ssh, |payload, armor| {
            verify_sshsig(key, "git", payload, armor).map_err(|_| RepositoryError::Signing)
        })
    }

    pub fn verify_commit_signature_with<F>(
        &self,
        id: ObjectId,
        signature_format: GitSignatureFormat,
        verifier: F,
    ) -> Result<(), RepositoryError>
    where
        F: FnOnce(&[u8], &str) -> Result<(), RepositoryError>,
    {
        let object = self.read_object(id)?;
        if object.kind != ObjectKind::Commit {
            return Err(RepositoryError::InvalidReference);
        }
        let (unsigned, armor) =
            split_commit_signature(&object.contents, self.object_format, signature_format)?;
        verifier(&unsigned, &armor)
    }

    pub fn verify_hybrid_commit_signature_with<P, M>(
        &self,
        id: ObjectId,
        openpgp_verifier: P,
        ml_dsa_verifier: M,
    ) -> Result<(), RepositoryError>
    where
        P: FnOnce(&[u8], &str) -> Result<(), RepositoryError>,
        M: FnOnce(&[u8], &str) -> Result<(), RepositoryError>,
    {
        let object = self.read_object(id)?;
        if object.kind != ObjectKind::Commit {
            return Err(RepositoryError::InvalidReference);
        }
        let (outer_payload, openpgp) = split_commit_signature(
            &object.contents,
            self.object_format,
            GitSignatureFormat::OpenPgp,
        )?;
        openpgp_verifier(&outer_payload, &openpgp)?;
        let (base_payload, ml_dsa) = split_ml_dsa_commit_signature(&outer_payload)?;
        ml_dsa_verifier(&base_payload, &ml_dsa)
    }

    fn create_commit_object(
        &self,
        tree: ObjectId,
        parents: &[ObjectId],
        message: &str,
        name: &str,
        email: &str,
        timestamp: u64,
    ) -> Result<ObjectId, RepositoryError> {
        validate_identity(name, email)?;
        let mut contents = mrml_runtime::mrml_format!("tree {tree}\n");
        for parent in parents {
            contents.push_str(&mrml_runtime::mrml_format!("parent {parent}\n"));
        }
        contents.push_str(&mrml_runtime::mrml_format!("author {name} <{email}> {timestamp} +0000\ncommitter {name} <{email}> {timestamp} +0000\n\n{}\n", message.trim()));
        self.write_object(ObjectKind::Commit, contents.as_bytes())
    }

    fn update_current_branch(&self, id: ObjectId) -> Result<(), RepositoryError> {
        let branch = self
            .current_branch()?
            .ok_or(RepositoryError::DetachedHead)?;
        let path = join_path(
            &self.git_dir,
            &mrml_runtime::mrml_format!("refs/heads/{branch}"),
        );
        let lock = mrml_runtime::mrml_format!("{path}.lock");
        if path_exists(&lock) {
            return Err(RepositoryError::AlreadyExists);
        }
        write_file(&lock, mrml_runtime::mrml_format!("{id}\n").as_bytes())?;
        mrml_runtime::rename_file(&lock, &path)?;
        Ok(())
    }

    pub fn stash_push(
        &self,
        message: &str,
        name: &str,
        email: &str,
        timestamp: u64,
    ) -> Result<ObjectId, RepositoryError> {
        validate_identity(name, email)?;
        let head = self.head()?.ok_or(RepositoryError::ReferenceMissing)?;
        let baseline = self.tree_index(self.read_commit(head)?.tree)?;
        let mut snapshot = self.index()?;
        let clean_crlf = self.autocrlf_mode()?.0;
        for entry in snapshot.clone().entries {
            let path = join_path(&self.worktree, &entry.path);
            if path_is_file(&path) {
                let contents =
                    clean_worktree_bytes(&read_file_bounded(&path, MAX_WORKTREE_FILE)?, clean_crlf);
                let id = self.write_object(ObjectKind::Blob, &contents)?;
                snapshot.upsert(IndexEntry {
                    path: entry.path.clone(),
                    id,
                    mode: entry.mode,
                    size: contents
                        .len()
                        .try_into()
                        .map_err(|_| RepositoryError::FileTooLarge)?,
                    stage: 0,
                });
            } else {
                snapshot.remove(&entry.path);
            }
        }
        if snapshot == baseline {
            return Err(RepositoryError::WorktreeDirty);
        }
        let tree = self.write_tree_from_index(&snapshot)?;
        let stash_path = join_path(&self.git_dir, "refs/stash");
        let previous = if path_is_file(&stash_path) {
            let value = read_file_text_bounded(&stash_path, 4096)?;
            Some(
                ObjectId::parse_for(self.object_format, value.trim())
                    .ok_or(RepositoryError::InvalidReference)?,
            )
        } else {
            None
        };
        let mut contents = mrml_runtime::mrml_format!("tree {tree}\n");
        if let Some(previous) = previous {
            contents.push_str(&mrml_runtime::mrml_format!("parent {previous}\n"));
        }
        contents.push_str(&mrml_runtime::mrml_format!("author {name} <{email}> {timestamp} +0000\ncommitter {name} <{email}> {timestamp} +0000\nmrml-stash-base {head}\n\n{}\n", if message.trim().is_empty() { "WIP" } else { message.trim() }));
        let id = self.write_object(ObjectKind::Commit, contents.as_bytes())?;
        if let Some(parent) = parent_path(&stash_path) {
            create_dir_all(parent)?;
        }
        write_file(&stash_path, mrml_runtime::mrml_format!("{id}\n").as_bytes())?;
        self.materialize_index(&baseline)?;
        Ok(id)
    }

    pub fn stash_list(&self, limit: usize) -> Result<Vector<(ObjectId, Commit)>, RepositoryError> {
        let path = join_path(&self.git_dir, "refs/stash");
        if !path_is_file(&path) {
            return Ok(Vector::new());
        }
        let value = read_file_text_bounded(&path, 4096)?;
        let id = ObjectId::parse_for(self.object_format, value.trim())
            .ok_or(RepositoryError::InvalidReference)?;
        self.history(id, limit)
    }

    pub fn stash_pop(&self) -> Result<ObjectId, RepositoryError> {
        if !self.changes()?.is_empty() {
            return Err(RepositoryError::WorktreeDirty);
        }
        let path = join_path(&self.git_dir, "refs/stash");
        if !path_is_file(&path) {
            return Err(RepositoryError::ReferenceMissing);
        }
        let value = read_file_text_bounded(&path, 4096)?;
        let id = ObjectId::parse_for(self.object_format, value.trim())
            .ok_or(RepositoryError::InvalidReference)?;
        let commit = self.read_commit(id)?;
        let snapshot = self.tree_index(commit.tree)?;
        self.materialize_index(&snapshot)?;
        if let Some(previous) = commit.parents.first() {
            write_file(&path, mrml_runtime::mrml_format!("{previous}\n").as_bytes())?;
        } else {
            mrml_runtime::remove_file(&path)?;
        }
        Ok(id)
    }

    pub fn changes(&self) -> Result<Vector<NativeChange>, RepositoryError> {
        let index = self.index()?;
        let clean_crlf = self.autocrlf_mode()?.0;
        let base = match self.head()? {
            Some(head) => self.tree_index(self.read_commit(head)?.tree)?,
            None => Index::empty_with_format(self.object_format),
        };
        let mut names: Vector<Text> = base
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect();
        for entry in index.entries.iter().filter(|entry| entry.stage == 0) {
            if !names.contains(&entry.path) {
                names.push(entry.path.clone());
            }
        }
        names.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let mut changes = Vector::new();
        for name in names {
            let base_id = base.entry(&name).map(|entry| entry.id);
            let index_id = index.entry(&name).map(|entry| entry.id);
            let staged = base_id != index_id;
            let path = join_path(&self.worktree, &name);
            let disk_id = if !path_exists(&path) {
                None
            } else if !path_is_file(&path) {
                return Err(RepositoryError::UnsupportedFileType);
            } else {
                let bytes = read_file_bounded(&path, MAX_WORKTREE_FILE).map_err(|error| {
                    if error == FileError::ReadFailed {
                        RepositoryError::FileTooLarge
                    } else {
                        error.into()
                    }
                })?;
                Some(ObjectId::blob_with_format(
                    self.object_format,
                    &clean_worktree_bytes(&bytes, clean_crlf),
                ))
            };
            let unstaged = index_id != disk_id;
            if staged || unstaged {
                changes.push(NativeChange {
                    path: name,
                    kind: if disk_id.is_none() || index_id.is_none() {
                        NativeChangeKind::Deleted
                    } else {
                        NativeChangeKind::Modified
                    },
                    staged,
                    unstaged,
                });
            }
        }
        let ignores = self.root_ignore_patterns()?;
        self.collect_untracked(&index, &self.worktree, "", 0, &ignores, &mut changes)?;
        Ok(changes)
    }

    fn root_ignore_patterns(&self) -> Result<Vector<Text>, RepositoryError> {
        let path = join_path(&self.worktree, ".gitignore");
        if !path_is_file(&path) {
            return Ok(Vector::new());
        }
        let text = read_file_text_bounded(&path, 1024 * 1024)?;
        let mut patterns = Vector::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.len() > 4096 || patterns.len() >= 65_536 {
                return Err(RepositoryError::TooManyFiles);
            }
            patterns.push(line.into());
        }
        Ok(patterns)
    }

    fn collect_untracked(
        &self,
        index: &Index,
        directory: &str,
        prefix: &str,
        depth: usize,
        ignores: &[Text],
        changes: &mut Vector<NativeChange>,
    ) -> Result<(), RepositoryError> {
        if depth > MAX_DEPTH {
            return Err(RepositoryError::TooDeep);
        }
        for entry in read_directory(directory)? {
            if depth == 0 && entry.name == ".git" {
                continue;
            }
            if entry.is_symlink {
                return Err(RepositoryError::UnsupportedFileType);
            }
            let disk_path = join_path(directory, &entry.name);
            let relative = if prefix.is_empty() {
                entry.name.clone()
            } else {
                let mut value = Text::from(prefix);
                value.push('/');
                value.push_str(&entry.name);
                value
            };
            if is_ignored(&relative, entry.is_directory, ignores) {
                continue;
            }
            if entry.is_directory {
                self.collect_untracked(index, &disk_path, &relative, depth + 1, ignores, changes)?;
            } else if index.entry(&relative).is_none() {
                if changes.len() >= MAX_WORKTREE_ENTRIES {
                    return Err(RepositoryError::TooManyFiles);
                }
                changes.push(NativeChange {
                    path: relative,
                    kind: NativeChangeKind::Untracked,
                    staged: false,
                    unstaged: true,
                });
            }
        }
        Ok(())
    }
}

fn config_text_value(text: &str, section: &str, key: &str) -> Option<Text> {
    let mut active = false;
    let mut selected = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            active = config_section_matches(line, section);
        } else if active
            && let Some((found, value)) = line.split_once('=')
            && found.trim().eq_ignore_ascii_case(key)
        {
            selected = Some(value.trim().into());
        }
    }
    selected
}

fn config_section_matches(header: &str, section: &str) -> bool {
    let Some(inner) = header
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .map(str::trim)
    else {
        return false;
    };
    if inner.eq_ignore_ascii_case(section) {
        return true;
    }
    let Some((base, subsection)) = section.split_once('.') else {
        return false;
    };
    let Some(split) = inner.find(char::is_whitespace) else {
        return false;
    };
    let found_base = inner[..split].trim();
    let quoted = inner[split..].trim();
    found_base.eq_ignore_ascii_case(base)
        && quoted
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .is_some_and(|value| value.eq_ignore_ascii_case(subsection))
}

fn global_git_config_path() -> Option<Text> {
    mrml_runtime::environment_variable("GIT_CONFIG_GLOBAL").or_else(|| {
        mrml_runtime::environment_variable(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .map(|home| join_path(&home, ".gitconfig"))
    })
}

fn repository_object_format(git_dir: &str) -> Result<ObjectFormat, RepositoryError> {
    let config = read_file_text_bounded(&join_path(git_dir, "config"), 1024 * 1024)?;
    parse_repository_object_format(&config)
}

#[cfg(target_os = "linux")]
fn write_capability_file(
    directory: &DirectoryCapability,
    name: &str,
    contents: &[u8],
) -> Result<(), RepositoryError> {
    let mut file = directory.create_new_file(name, 0o600)?;
    file.write_all(contents)?;
    file.sync()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_open_file_bounded(mut file: File, maximum: usize) -> Result<Vector<u8>, RepositoryError> {
    let length = usize::try_from(file.len()?).map_err(|_| RepositoryError::FileTooLarge)?;
    if length > maximum {
        return Err(RepositoryError::FileTooLarge);
    }
    let mut bytes = Vector::new();
    bytes
        .try_resize(length, 0)
        .map_err(|_| RepositoryError::FileTooLarge)?;
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn read_capability_file(
    directory: &DirectoryCapability,
    name: &str,
    maximum: usize,
) -> Result<Vector<u8>, RepositoryError> {
    read_open_file_bounded(directory.open_regular(name)?, maximum)
}

#[cfg(target_os = "linux")]
fn decode_retained_object(
    file: File,
    id: ObjectId,
    format: ObjectFormat,
) -> Result<Object, RepositoryError> {
    let encoded = read_open_file_bounded(file, MAX_WORKTREE_FILE)?;
    let object = decode_loose_object(&encoded)?;
    let (computed, _) = encode_loose_object_with_format(format, object.kind, &object.contents);
    if computed != id {
        return Err(RepositoryError::InvalidHead);
    }
    Ok(object)
}

fn parse_repository_object_format(config: &str) -> Result<ObjectFormat, RepositoryError> {
    let mut section = Text::new();
    let mut repository_version = None;
    let mut object_format = None;
    for raw in config.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.starts_with('[') {
            let name = line
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .ok_or(RepositoryError::UnsupportedObjectFormat)?;
            section = name.trim().into();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            if section.eq_ignore_ascii_case("extensions")
                || (section.eq_ignore_ascii_case("core")
                    && line.eq_ignore_ascii_case("repositoryformatversion"))
            {
                return Err(RepositoryError::UnsupportedObjectFormat);
            }
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if section.eq_ignore_ascii_case("core")
            && key.eq_ignore_ascii_case("repositoryformatversion")
        {
            if repository_version.is_some() {
                return Err(RepositoryError::UnsupportedObjectFormat);
            }
            repository_version = Some(
                value
                    .parse::<u32>()
                    .map_err(|_| RepositoryError::UnsupportedObjectFormat)?,
            );
        } else if section.eq_ignore_ascii_case("extensions") {
            if !key.eq_ignore_ascii_case("objectformat") || object_format.is_some() {
                return Err(RepositoryError::UnsupportedObjectFormat);
            }
            object_format = Some(value);
        }
    }
    match (repository_version.unwrap_or(0), object_format) {
        (0, None) => Ok(ObjectFormat::Sha1),
        (1, None) => Ok(ObjectFormat::Sha1),
        (1, Some(value)) if value.eq_ignore_ascii_case("sha1") => Ok(ObjectFormat::Sha1),
        (1, Some(value)) if value.eq_ignore_ascii_case("sha256") => Ok(ObjectFormat::Sha256),
        _ => Err(RepositoryError::UnsupportedObjectFormat),
    }
}

fn clean_worktree_bytes(source: &[u8], enabled: bool) -> Vector<u8> {
    if !enabled || source.contains(&0) || !source.windows(2).any(|pair| pair == b"\r\n") {
        return source.iter().copied().collect();
    }
    let mut output = Vector::new();
    let mut cursor = 0usize;
    while cursor < source.len() {
        if source.get(cursor..cursor + 2) == Some(&b"\r\n"[..]) {
            output.push(b'\n');
            cursor += 2;
        } else {
            output.push(source[cursor]);
            cursor += 1;
        }
    }
    output
}

fn smudge_worktree_bytes(source: &[u8], enabled: bool) -> Vector<u8> {
    if !enabled || source.contains(&0) || !source.contains(&b'\n') {
        return source.iter().copied().collect();
    }
    let mut output = Vector::new();
    let mut previous = None;
    for byte in source {
        if *byte == b'\n' && previous != Some(b'\r') {
            output.push(b'\r');
        }
        output.push(*byte);
        previous = Some(*byte);
    }
    output
}

fn is_ignored(path: &str, is_directory: bool, patterns: &[Text]) -> bool {
    let mut ignored = false;
    for configured in patterns {
        let (negated, mut pattern) = configured
            .strip_prefix('!')
            .map_or((false, configured.as_str()), |pattern| (true, pattern));
        if pattern.is_empty() {
            continue;
        }
        let directory_only = pattern.ends_with('/');
        pattern = pattern.trim_end_matches('/').trim_start_matches('/');
        let matches = if directory_only {
            (is_directory && ignore_pattern_matches(pattern, path))
                || path
                    .strip_prefix(pattern)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        } else {
            ignore_pattern_matches(pattern, path)
        };
        if matches {
            ignored = !negated;
        }
    }
    ignored
}

fn ignore_pattern_matches(pattern: &str, path: &str) -> bool {
    if pattern.contains('/') {
        wildcard_match(pattern.as_bytes(), path.as_bytes())
            || pattern
                .strip_prefix("**/")
                .is_some_and(|pattern| wildcard_match(pattern.as_bytes(), path.as_bytes()))
    } else {
        path.split('/')
            .any(|component| wildcard_match(pattern.as_bytes(), component.as_bytes()))
    }
}

fn wildcard_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize, bool)> = None;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            let double = pattern.get(p + 1) == Some(&b'*');
            p += if double { 2 } else { 1 };
            star = Some((p, t, double));
        } else if let Some((after, matched, crosses_slash)) = star {
            if matched >= text.len() || (!crosses_slash && text[matched] == b'/') {
                return false;
            }
            let next = matched + 1;
            star = Some((after, next, crosses_slash));
            p = after;
            t = next;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn validate_reference(reference: &str) -> Result<(), RepositoryError> {
    if !reference.starts_with("refs/")
        || reference.ends_with('/')
        || reference.contains("..")
        || reference.contains("@{")
        || reference.contains(['\\', ' ', '~', '^', ':', '?', '*', '['])
        || reference.split('/').any(|part| {
            part.is_empty()
                || part.starts_with('.')
                || part.ends_with('.')
                || part.ends_with(".lock")
        })
        || reference.chars().any(char::is_control)
    {
        Err(RepositoryError::InvalidReference)
    } else {
        Ok(())
    }
}

fn validate_worktree_path(path: &str) -> Result<(), RepositoryError> {
    if path.is_empty()
        || mrml_runtime::path_is_absolute(path)
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || path.chars().any(char::is_control)
    {
        Err(RepositoryError::InvalidWorktreePath)
    } else {
        Ok(())
    }
}

struct TreeItem {
    name: Text,
    mode: u32,
    id: ObjectId,
    directory: bool,
}

fn tree_name_cmp(left: &TreeItem, right: &TreeItem) -> core::cmp::Ordering {
    let mut index = 0;
    loop {
        let left_byte = left
            .name
            .as_bytes()
            .get(index)
            .copied()
            .or_else(|| left.directory.then_some(b'/'));
        let right_byte = right
            .name
            .as_bytes()
            .get(index)
            .copied()
            .or_else(|| right.directory.then_some(b'/'));
        match (left_byte, right_byte) {
            (Some(a), Some(b)) if a == b => index += 1,
            (Some(a), Some(b)) => return a.cmp(&b),
            (None, None) => return core::cmp::Ordering::Equal,
            (None, Some(_)) => return core::cmp::Ordering::Less,
            (Some(_), None) => return core::cmp::Ordering::Greater,
        }
    }
}

fn validate_identity(name: &str, email: &str) -> Result<(), RepositoryError> {
    if name.trim().is_empty()
        || email.trim().is_empty()
        || name.contains(['\n', '\r', '<', '>'])
        || email.contains(['\n', '\r', '<', '>'])
    {
        Err(RepositoryError::InvalidIdentity)
    } else {
        Ok(())
    }
}

fn same_entry(left: Option<&IndexEntry>, right: Option<&IndexEntry>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => left.id == right.id && left.mode == right.mode,
        _ => false,
    }
}

fn validate_config_name(value: &str) -> Result<(), RepositoryError> {
    if value.is_empty()
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        Err(RepositoryError::InvalidReference)
    } else {
        Ok(())
    }
}

fn split_commit_signature(
    contents: &[u8],
    object_format: ObjectFormat,
    signature_format: GitSignatureFormat,
) -> Result<(Vector<u8>, Text), RepositoryError> {
    let text = core::str::from_utf8(contents).map_err(|_| RepositoryError::Signing)?;
    let (headers, message) = text.split_once("\n\n").ok_or(RepositoryError::Signing)?;
    let expected = match object_format {
        ObjectFormat::Sha1 => "gpgsig ",
        ObjectFormat::Sha256 => "gpgsig-sha256 ",
    };
    let mut unsigned = Text::new();
    let mut armor = Text::new();
    let mut signing = false;
    let mut found = false;
    for line in headers.split('\n') {
        if let Some(first) = line.strip_prefix(expected) {
            if found {
                return Err(RepositoryError::Signing);
            }
            found = true;
            signing = true;
            armor.push_str(first);
            armor.push('\n');
        } else if signing && line.starts_with(' ') {
            armor.push_str(&line[1..]);
            armor.push('\n');
        } else if line.starts_with("gpgsig ") || line.starts_with("gpgsig-sha256 ") {
            return Err(RepositoryError::Signing);
        } else {
            signing = false;
            unsigned.push_str(line);
            unsigned.push('\n');
        }
    }
    if !found {
        return Err(RepositoryError::Signing);
    }
    validate_signature_armor(&armor, signature_format)?;
    unsigned.push('\n');
    unsigned.push_str(message);
    let mut bytes = Vector::new();
    bytes.extend(unsigned.bytes());
    Ok((bytes, armor))
}

fn append_multiline_header(contents: &mut Text, name: &str, value: &str) {
    for (index, line) in value.lines().enumerate() {
        if index == 0 {
            contents.push_str(name);
            contents.push(' ');
        } else {
            contents.push(' ');
        }
        contents.push_str(line);
        contents.push('\n');
    }
}

fn split_ml_dsa_commit_signature(contents: &[u8]) -> Result<(Vector<u8>, Text), RepositoryError> {
    let text = core::str::from_utf8(contents).map_err(|_| RepositoryError::Signing)?;
    let (headers, message) = text.split_once("\n\n").ok_or(RepositoryError::Signing)?;
    let mut unsigned = Text::new();
    let mut armor = Text::new();
    let mut signing = false;
    let mut found = false;
    for line in headers.split('\n') {
        if let Some(first) = line.strip_prefix("mrml-mldsa65 ") {
            if found {
                return Err(RepositoryError::Signing);
            }
            found = true;
            signing = true;
            armor.push_str(first);
            armor.push('\n');
        } else if signing && line.starts_with(' ') {
            armor.push_str(&line[1..]);
            armor.push('\n');
        } else {
            signing = false;
            unsigned.push_str(line);
            unsigned.push('\n');
        }
    }
    if !found {
        return Err(RepositoryError::Signing);
    }
    validate_ml_dsa_armor(&armor)?;
    unsigned.push('\n');
    unsigned.push_str(message);
    let mut bytes = Vector::new();
    bytes.extend(unsigned.bytes());
    Ok((bytes, armor))
}

fn validate_ml_dsa_armor(armor: &str) -> Result<(), RepositoryError> {
    const BEGIN: &str = "-----BEGIN MRML ML-DSA-65 SIGNATURE-----";
    const END: &str = "-----END MRML ML-DSA-65 SIGNATURE-----";
    const MAX_BYTES: usize = 8 * 1024;
    let mut lines = armor.lines();
    if armor.len() > MAX_BYTES
        || armor.contains(['\0', '\r'])
        || lines.next() != Some(BEGIN)
        || lines.next_back() != Some(END)
        || lines.clone().count() != 69
        || lines.enumerate().any(|(index, line)| {
            line.len() != if index == 68 { 60 } else { 64 }
                || !line
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        })
    {
        return Err(RepositoryError::Signing);
    }
    Ok(())
}

fn split_tag_signature(
    contents: &[u8],
    signature_format: GitSignatureFormat,
) -> Result<(&[u8], &str), RepositoryError> {
    let text = core::str::from_utf8(contents).map_err(|_| RepositoryError::Signing)?;
    let marker = signature_format.begin_marker();
    let offset = text.find(marker).ok_or(RepositoryError::Signing)?;
    if offset == 0 || text.as_bytes()[offset - 1] != b'\n' {
        return Err(RepositoryError::Signing);
    }
    let armor = &text[offset..];
    validate_signature_armor(armor, signature_format)?;
    Ok((&contents[..offset], armor))
}

fn validate_signature_armor(
    armor: &str,
    signature_format: GitSignatureFormat,
) -> Result<(), RepositoryError> {
    const MAX_SIGNATURE_BYTES: usize = 256 * 1024;
    const MAX_SIGNATURE_LINES: usize = 4096;
    let line_count = armor.lines().count();
    if armor.is_empty()
        || armor.len() > MAX_SIGNATURE_BYTES
        || armor.contains(['\0', '\r'])
        || !(3..=MAX_SIGNATURE_LINES).contains(&line_count)
    {
        return Err(RepositoryError::Signing);
    }
    let trimmed = armor.strip_suffix('\n').unwrap_or(armor);
    let mut lines = trimmed.lines();
    if lines.next() != Some(signature_format.begin_marker())
        || lines.next_back() != Some(signature_format.end_marker())
        || lines.any(|line| {
            line == signature_format.begin_marker() || line == signature_format.end_marker()
        })
    {
        return Err(RepositoryError::Signing);
    }
    Ok(())
}

fn remote_section(line: &str) -> Option<&str> {
    line.strip_prefix("[remote \"")?
        .strip_suffix("\"]")
        .filter(|name| validate_config_name(name).is_ok())
}

fn split_lines(text: &str) -> Vector<&str> {
    if text.is_empty() {
        Vector::new()
    } else {
        text.split_inclusive('\n').collect()
    }
}

fn line_mapping(child: &[&str], parent: &[&str]) -> Vector<Option<usize>> {
    const MAX_CELLS: usize = 4_000_000;
    let mut mapping = Vector::new();
    mapping.resize(child.len(), None);
    if child
        .len()
        .checked_mul(parent.len())
        .is_none_or(|cells| cells > MAX_CELLS)
    {
        return mapping;
    }
    let width = parent.len() + 1;
    let mut table = Vector::new();
    table.resize((child.len() + 1) * width, 0u32);
    for i in (0..child.len()).rev() {
        for j in (0..parent.len()).rev() {
            table[i * width + j] = if child[i] == parent[j] {
                table[(i + 1) * width + j + 1] + 1
            } else {
                table[(i + 1) * width + j].max(table[i * width + j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    while i < child.len() && j < parent.len() {
        if child[i] == parent[j] {
            mapping[i] = Some(j);
            i += 1;
            j += 1;
        } else if table[(i + 1) * width + j] >= table[i * width + j + 1] {
            i += 1;
        } else {
            j += 1;
        }
    }
    mapping
}

fn encode_remote_refs(
    format: ObjectFormat,
    refs: &[(Text, ObjectId)],
) -> Result<Vector<u8>, RepositoryError> {
    let mut text = mrml_runtime::mrml_format!(
        "MRML-REMOTE-REFS 1 {}\ncount {}\n",
        format.name(),
        refs.len()
    );
    for (name, id) in refs {
        text.push_str(&mrml_runtime::mrml_format!("{id} {name}\n"));
        if text.len() > MAX_REMOTE_REFS_BYTES - 128 {
            return Err(RepositoryError::FileTooLarge);
        }
    }
    let digest = ObjectId::blob_with_format(format, text.as_bytes());
    text.push_str(&mrml_runtime::mrml_format!("checksum {digest}\n"));
    if text.len() > MAX_REMOTE_REFS_BYTES {
        return Err(RepositoryError::FileTooLarge);
    }
    let mut bytes = Vector::new();
    bytes
        .try_extend_from_slice(text.as_bytes())
        .map_err(|_| RepositoryError::FileTooLarge)?;
    Ok(bytes)
}

fn parse_remote_refs(
    format: ObjectFormat,
    bytes: &[u8],
) -> Result<Vector<(Text, ObjectId)>, RepositoryError> {
    let text = core::str::from_utf8(bytes).map_err(|_| RepositoryError::InvalidReference)?;
    let checksum_marker = text
        .rfind("checksum ")
        .ok_or(RepositoryError::InvalidReference)?;
    if checksum_marker == 0 || !text.ends_with('\n') {
        return Err(RepositoryError::InvalidReference);
    }
    let authenticated = &text[..checksum_marker];
    let checksum = text[checksum_marker + "checksum ".len()..]
        .strip_suffix('\n')
        .and_then(|value| ObjectId::parse_for(format, value))
        .ok_or(RepositoryError::InvalidReference)?;
    if checksum != ObjectId::blob_with_format(format, authenticated.as_bytes()) {
        return Err(RepositoryError::InvalidReference);
    }
    let expected_header = mrml_runtime::mrml_format!("MRML-REMOTE-REFS 1 {}", format.name());
    let mut lines = authenticated.lines();
    if lines.next() != Some(expected_header.as_str()) {
        return Err(RepositoryError::InvalidReference);
    }
    let count = lines
        .next()
        .and_then(|line| line.strip_prefix("count "))
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| *count <= MAX_WORKTREE_ENTRIES)
        .ok_or(RepositoryError::InvalidReference)?;
    let mut refs: Vector<(Text, ObjectId)> = Vector::new();
    for line in lines {
        let (hex, name) = line
            .split_once(' ')
            .ok_or(RepositoryError::InvalidReference)?;
        validate_reference(&mrml_runtime::mrml_format!("refs/heads/{name}"))?;
        let id = ObjectId::parse_for(format, hex).ok_or(RepositoryError::InvalidReference)?;
        if refs
            .last()
            .is_some_and(|(previous, _)| previous.as_bytes() >= name.as_bytes())
        {
            return Err(RepositoryError::InvalidReference);
        }
        refs.push((name.into(), id));
    }
    if refs.len() != count {
        return Err(RepositoryError::InvalidReference);
    }
    Ok(refs)
}

impl From<FileError> for RepositoryError {
    fn from(value: FileError) -> Self {
        Self::File(value)
    }
}
impl From<IndexError> for RepositoryError {
    fn from(value: IndexError) -> Self {
        Self::Index(value)
    }
}
impl From<ObjectError> for RepositoryError {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}
impl From<PackError> for RepositoryError {
    fn from(value: PackError) -> Self {
        Self::Pack(value)
    }
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(error) => write!(formatter, "{error}"),
            Self::Index(error) => write!(formatter, "{error}"),
            Self::Object(error) => write!(formatter, "{error}"),
            Self::Pack(error) => write!(formatter, "{error}"),
            Self::WorktreeDirty => formatter.write_str("working tree is not clean"),
            Self::NoChanges => formatter.write_str("no staged changes to commit"),
            Self::MergeRequired => {
                formatter.write_str("non-fast-forward merge requires native three-way merge")
            }
            Self::Signing => formatter.write_str("Git signature is missing or invalid"),
            Self::UnsupportedObjectFormat => {
                formatter.write_str("unsupported or inconsistent Git repository object format")
            }
            Self::NotRepository => formatter.write_str("not an MRML Git repository"),
            Self::AlreadyExists => formatter.write_str("repository metadata already exists"),
            Self::UnsupportedLayout => {
                formatter.write_str("linked worktrees and gitdir files are not supported yet")
            }
            Self::InvalidHead => formatter.write_str("invalid HEAD"),
            Self::InvalidReference => formatter.write_str("unsafe or invalid reference"),
            Self::TooManyFiles => formatter.write_str("working tree contains too many files"),
            Self::TooDeep => formatter.write_str("working tree is too deeply nested"),
            Self::UnsupportedFileType => {
                formatter.write_str("symbolic links and special files are not supported yet")
            }
            Self::FileTooLarge => {
                formatter.write_str("working-tree file exceeds the native status limit")
            }
            Self::InvalidWorktreePath => formatter.write_str("unsafe or invalid working-tree path"),
            Self::ConflictedIndex => {
                formatter.write_str("cannot write a tree from an unmerged index")
            }
            Self::DetachedHead => formatter.write_str("native commit requires a branch HEAD"),
            Self::InvalidIdentity => formatter.write_str("invalid commit identity or message"),
            Self::ReferenceExists => formatter.write_str("reference already exists"),
            Self::ReferenceMissing => {
                formatter.write_str("reference or starting commit does not exist")
            }
            Self::CurrentBranch => formatter.write_str("cannot delete the current branch"),
        }
    }
}
impl core::error::Error for RepositoryError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sign_ml_dsa_65_git_payload, verify_ml_dsa_65_git_payload};
    use mrml_crypto::{ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, ml_dsa_65_keygen};
    use mrml_runtime::{process_id, remove_dir_all, temporary_directory};

    fn decode_hex(text: &str) -> Vector<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }
    fn signing_key() -> RsaPrivateKey {
        RsaPrivateKey::from_parts(
            RsaPublicKey {
                modulus: decode_hex(
                    "9eff1e540991fee9de7c7ed50d5da16508d610090a52c9aa4c41bc868e93e7cc03a6cc766fb2dab78ba91e4315f6524e355fda2c8a71b372f012d43460c2c425c2ae763d96a20584bc030e3595cc9f2352f51288f8db5d398d55efc566381707b4df848444641093fc5c48ca894db8397b252d00d5d606fe377b09f3609850fb",
                ),
                exponent: Vector::from([1, 0, 1]),
            },
            decode_hex(
                "2187d1e08d2821e736497102035094a1d70c35d3823ed552b9c43f3aed4499e4b77c6cb0297c418de5c123a5a8330b467d111ad4bbd9a0ab839fa4eaeae108364d4ad3f439916be8a244f8071922b1918cce92b27fe5f6ed24a328b15030b3fb3e300166c651f5f457daef746c4051a7a0f035379dcacf3a164fb4aedd284a11",
            ),
        )
        .unwrap()
    }

    fn root(name: &str) -> Text {
        join_path(
            &temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-git-{name}-{}", process_id()),
        )
    }

    #[test]
    fn initializes_and_discovers_without_a_git_process() {
        let path = root("init");
        let repository = Repository::init(&path).unwrap();
        assert_eq!(
            repository.current_branch().unwrap().as_deref(),
            Some("main")
        );
        assert_eq!(repository.head().unwrap(), None);
        let nested = join_path(&path, "src/deep");
        create_dir_all(&nested).unwrap();
        assert_eq!(Repository::discover(&nested).unwrap(), repository);
        remove_dir_all(&path).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_repository_objects_survive_ambient_replacement() {
        let path = root("retained-objects");
        let displaced = mrml_runtime::mrml_format!("{path}-displaced");
        let _ = remove_dir_all(&path);
        let _ = remove_dir_all(&displaced);
        create_dir_all(&path).unwrap();
        let capability = DirectoryCapability::open_root(&path).unwrap();
        let repository = Repository::initialize_sha256_capability(capability).unwrap();
        mrml_runtime::rename_file(&path, &displaced).unwrap();
        create_dir_all(&path).unwrap();

        let id = repository
            .write_object(ObjectKind::Blob, b"retained\n")
            .unwrap();
        assert_eq!(
            repository.read_object(id).unwrap().contents,
            &b"retained\n"[..]
        );
        let hex = id.to_hex();
        assert!(path_is_file(&join_path(
            &displaced,
            &mrml_runtime::mrml_format!(".git/objects/{}/{}", &hex[..2], &hex[2..])
        )));
        assert!(!path_exists(&join_path(&path, ".git")));

        let loose = join_path(
            &displaced,
            &mrml_runtime::mrml_format!(".git/objects/{}/{}", &hex[..2], &hex[2..]),
        );
        remove_file(&loose).unwrap();
        create_dir_all(&loose).unwrap();
        assert_eq!(
            repository.read_object(id),
            Err(RepositoryError::UnsupportedFileType)
        );

        drop(repository);
        remove_dir_all(&path).unwrap();
        remove_dir_all(&displaced).unwrap();
    }

    #[test]
    fn initializes_and_operates_sha256_repository_natively() {
        let path = root("init-sha256");
        let repository = Repository::init_with_format(&path, ObjectFormat::Sha256).unwrap();
        assert_eq!(repository.object_format(), ObjectFormat::Sha256);
        assert_eq!(
            Repository::discover(&path).unwrap().object_format(),
            ObjectFormat::Sha256
        );
        write_file(&join_path(&path, "tracked"), b"sha256").unwrap();
        repository
            .stage(&Vector::from([Text::from("tracked")]))
            .unwrap();
        assert_eq!(repository.index().unwrap().format, ObjectFormat::Sha256);
        let commit = repository
            .commit("sha256", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        assert_eq!(commit.format(), ObjectFormat::Sha256);
        assert_eq!(commit.to_hex().len(), 64);
        assert_eq!(repository.head().unwrap(), Some(commit));
        assert_eq!(repository.read_commit(commit).unwrap().message, "sha256\n");
        let packed = parse_pack_with_format(
            &repository.pack_reachable(commit).unwrap(),
            ObjectFormat::Sha256,
        )
        .unwrap();
        assert!(packed.iter().any(|object| object.id == commit));
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn validates_advertised_commit_tips_before_reference_updates() {
        let path = root("validate-advertised-tips");
        let repository = Repository::init_with_format(&path, ObjectFormat::Sha256).unwrap();
        write_file(&join_path(&path, "tracked"), b"tip").unwrap();
        repository
            .stage(&Vector::from([Text::from("tracked")]))
            .unwrap();
        let commit = repository
            .commit("tip", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        assert_eq!(repository.validate_commit_tips(&[commit]), Ok(()));

        let blob = repository
            .write_object(ObjectKind::Blob, b"not a commit")
            .unwrap();
        assert_eq!(
            repository.validate_commit_tips(&[blob]),
            Err(RepositoryError::InvalidReference)
        );
        let missing = ObjectId::parse_for(
            ObjectFormat::Sha256,
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        assert_eq!(
            repository.validate_commit_tips(&[missing]),
            Err(RepositoryError::ReferenceMissing)
        );
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn fetch_candidate_is_fully_traversed_before_objects_become_visible() {
        let source_path = root("validated-import-source");
        let source = Repository::init_with_format(&source_path, ObjectFormat::Sha256).unwrap();
        write_file(&join_path(&source_path, "tracked"), b"candidate").unwrap();
        source
            .stage(&Vector::from([Text::from("tracked")]))
            .unwrap();
        let commit = source
            .commit("candidate", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        let pack = source.pack_reachable(commit).unwrap();

        let destination_path = root("validated-import-destination");
        let destination =
            Repository::init_with_format(&destination_path, ObjectFormat::Sha256).unwrap();
        destination
            .import_pack_validated_commit_tips(&pack, &[commit])
            .unwrap();
        assert_eq!(
            destination.read_commit(commit).unwrap().message,
            "candidate\n"
        );

        let blob = source
            .write_object(ObjectKind::Blob, b"not a commit")
            .unwrap();
        let blob_pack = source.pack_reachable(blob).unwrap();
        let rejected_path = root("rejected-import-destination");
        let rejected = Repository::init_with_format(&rejected_path, ObjectFormat::Sha256).unwrap();
        assert_eq!(
            rejected.import_pack_validated_commit_tips(&blob_pack, &[blob]),
            Err(RepositoryError::InvalidReference)
        );
        assert_eq!(
            rejected.read_object(blob),
            Err(RepositoryError::ReferenceMissing)
        );

        remove_dir_all(&source_path).unwrap();
        remove_dir_all(&destination_path).unwrap();
        remove_dir_all(&rejected_path).unwrap();
    }

    #[test]
    fn streamed_fetch_pack_is_file_validated_before_object_installation() {
        let source_path = root("streamed-import-source");
        let source = Repository::init_with_format(&source_path, ObjectFormat::Sha256).unwrap();
        write_file(&join_path(&source_path, "tracked"), b"streamed candidate").unwrap();
        source
            .stage(&Vector::from([Text::from("tracked")]))
            .unwrap();
        let commit = source
            .commit("streamed", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        let pack = source.pack_reachable(commit).unwrap();

        let destination_path = root("streamed-import-destination");
        let destination =
            Repository::init_with_format(&destination_path, ObjectFormat::Sha256).unwrap();
        let candidate = join_path(&destination.git_dir, "fetch-candidate.pack");
        let scratch = join_path(&destination.git_dir, "fetch-candidate-objects");
        write_file(&candidate, &pack).unwrap();
        let installed = destination
            .import_pack_file_validated_commit_tips(
                &candidate,
                &scratch,
                &[commit],
                FetchPackLimits::production(pack.len() as u64).unwrap(),
            )
            .unwrap();
        assert!(installed.contains(&commit));
        assert_eq!(
            destination.read_commit(commit).unwrap().message,
            "streamed\n"
        );

        let rejected_path = root("streamed-import-rejected");
        let rejected = Repository::init_with_format(&rejected_path, ObjectFormat::Sha256).unwrap();
        let blob = source
            .write_object(ObjectKind::Blob, b"not a commit")
            .unwrap();
        let blob_pack = source.pack_reachable(blob).unwrap();
        let rejected_pack = join_path(&rejected.git_dir, "fetch-candidate.pack");
        let rejected_scratch = join_path(&rejected.git_dir, "fetch-candidate-objects");
        write_file(&rejected_pack, &blob_pack).unwrap();
        assert_eq!(
            rejected.import_pack_file_validated_commit_tips(
                &rejected_pack,
                &rejected_scratch,
                &[blob],
                FetchPackLimits::production(blob_pack.len() as u64).unwrap(),
            ),
            Err(RepositoryError::InvalidReference)
        );
        assert_eq!(
            rejected.read_object(blob),
            Err(RepositoryError::ReferenceMissing)
        );

        remove_dir_all(&source_path).unwrap();
        remove_dir_all(&destination_path).unwrap();
        remove_dir_all(&rejected_path).unwrap();
    }

    #[test]
    fn object_write_rereads_exact_bytes_before_returning_identity() {
        let path = root("object-write-reread");
        let repository = Repository::init_with_format(&path, ObjectFormat::Sha256).unwrap();
        let (id, _) = encode_loose_object_with_format(
            ObjectFormat::Sha256,
            ObjectKind::Blob,
            b"expected contents",
        );
        let hex = id.to_hex();
        let directory = join_path(&join_path(&repository.git_dir, "objects"), &hex[..2]);
        create_dir_all(&directory).unwrap();
        write_file(
            &join_path(&directory, &hex[2..]),
            b"corrupt preexisting object",
        )
        .unwrap();
        assert!(
            repository
                .write_object(ObjectKind::Blob, b"expected contents")
                .is_err()
        );
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn rejects_inconsistent_repository_object_format_configuration() {
        let path = root("invalid-object-format");
        let repository = Repository::init(&path).unwrap();
        write_file(
            &join_path(&repository.git_dir, "config"),
            b"[core]\n\trepositoryformatversion = 0\n[extensions]\n\tobjectformat = sha256\n",
        )
        .unwrap();
        assert_eq!(
            Repository::discover(&path),
            Err(RepositoryError::UnsupportedObjectFormat)
        );
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn rejects_malformed_or_unvalued_repository_format_configuration() {
        assert_eq!(
            parse_repository_object_format(
                "[core]\nrepositoryformatversion = 1\n[extensions]\nobjectformat\n"
            ),
            Err(RepositoryError::UnsupportedObjectFormat)
        );
        assert_eq!(
            parse_repository_object_format("[core]\nrepositoryformatversion\n"),
            Err(RepositoryError::UnsupportedObjectFormat)
        );
        assert_eq!(
            parse_repository_object_format("[core\nrepositoryformatversion = 1\n"),
            Err(RepositoryError::UnsupportedObjectFormat)
        );
        assert_eq!(
            parse_repository_object_format("[core]\nbare\nrepositoryformatversion = 0\n"),
            Ok(ObjectFormat::Sha1)
        );
    }

    #[test]
    fn repository_format_and_effective_config_parsing_match_git_basics() {
        assert_eq!(
            parse_repository_object_format(
                "[core]\nrepositoryFormatVersion = 1\n[extensions]\nobjectFormat = SHA1\n"
            ),
            Ok(ObjectFormat::Sha1)
        );
        assert_eq!(
            parse_repository_object_format("[core]\nrepositoryFormatVersion = 1\n"),
            Ok(ObjectFormat::Sha1)
        );
        assert_eq!(
            config_text_value("[tag]\ngpgSign = false\ngpgsign = true\n", "TAG", "GPGSIGN")
                .as_deref(),
            Some("true")
        );
        assert_eq!(
            config_text_value(
                "[gpg \"openpgp\"]\npublicKeyFile = current.asc\n",
                "gpg.openpgp",
                "publickeyfile"
            )
            .as_deref(),
            Some("current.asc")
        );
    }

    #[test]
    fn reports_untracked_files_natively() {
        let path = root("status");
        let repository = Repository::init(&path).unwrap();
        write_file(&join_path(&path, "hello.txt"), b"native").unwrap();
        assert_eq!(
            repository.changes().unwrap(),
            Vector::from([NativeChange {
                path: "hello.txt".into(),
                kind: NativeChangeKind::Untracked,
                staged: false,
                unstaged: true,
            }])
        );
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn excludes_root_gitignore_patterns_from_status_walk() {
        let path = root("ignored-status");
        let repository = Repository::init(&path).unwrap();
        write_file(
            &join_path(&path, ".gitignore"),
            b"target/\ntarget-*\n**/*.bak\n",
        )
        .unwrap();
        repository
            .stage(&Vector::from([Text::from(".gitignore")]))
            .unwrap();
        repository
            .commit("ignore", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        create_dir_all(&join_path(&path, "target/deep")).unwrap();
        create_dir_all(&join_path(&path, "target-debug")).unwrap();
        create_dir_all(&join_path(&path, "src")).unwrap();
        write_file(&join_path(&path, "target/deep/generated"), b"x").unwrap();
        write_file(&join_path(&path, "target-debug/generated"), b"x").unwrap();
        write_file(&join_path(&path, "src/temporary.bak"), b"x").unwrap();
        write_file(&join_path(&path, "visible"), b"x").unwrap();
        assert_eq!(
            repository.changes().unwrap(),
            Vector::from([NativeChange {
                path: "visible".into(),
                kind: NativeChangeKind::Untracked,
                staged: false,
                unstaged: true,
            }])
        );
        assert!(wildcard_match(b"target-*", b"target-debug"));
        assert!(ignore_pattern_matches("**/*.bak", "temporary.bak"));
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn applies_native_autocrlf_clean_and_smudge_filters() {
        let path = root("autocrlf");
        let repository = Repository::init(&path).unwrap();
        repository
            .set_config_value("core", "autocrlf", "true")
            .unwrap();
        let file = join_path(&path, "text.txt");
        write_file(&file, b"one\r\ntwo\r\n").unwrap();
        repository
            .stage(&Vector::from([Text::from("text.txt")]))
            .unwrap();
        assert_eq!(
            repository.index().unwrap().entry("text.txt").unwrap().id,
            ObjectId::blob(b"one\ntwo\n")
        );
        repository
            .commit("text", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        assert!(repository.changes().unwrap().is_empty());
        write_file(&file, b"different\r\n").unwrap();
        repository
            .restore(&Vector::from([Text::from("text.txt")]))
            .unwrap();
        assert_eq!(&*read_file_bounded(&file, 64).unwrap(), b"one\r\ntwo\r\n");
        assert_eq!(&*clean_worktree_bytes(b"a\r\nb\r\n", true), b"a\nb\n");
        assert_eq!(&*smudge_worktree_bytes(b"a\nb\n", true), b"a\r\nb\r\n");
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn stages_blob_and_updates_index_natively() {
        let path = root("stage");
        let repository = Repository::init(&path).unwrap();
        write_file(&join_path(&path, "hello.txt"), b"native").unwrap();
        repository
            .stage(&Vector::from([Text::from("hello.txt")]))
            .unwrap();
        assert_eq!(
            repository.index().unwrap().entry("hello.txt").unwrap().id,
            ObjectId::blob(b"native")
        );
        assert_eq!(
            repository.changes().unwrap(),
            Vector::from([NativeChange {
                path: "hello.txt".into(),
                kind: NativeChangeKind::Modified,
                staged: true,
                unstaged: false,
            }])
        );
        repository
            .commit("base", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        write_file(&join_path(&path, "hello.txt"), b"staged").unwrap();
        repository
            .stage(&Vector::from([Text::from("hello.txt")]))
            .unwrap();
        write_file(&join_path(&path, "hello.txt"), b"worktree").unwrap();
        assert_eq!(
            repository.changes().unwrap(),
            Vector::from([NativeChange {
                path: "hello.txt".into(),
                kind: NativeChangeKind::Modified,
                staged: true,
                unstaged: true,
            }])
        );
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn creates_tree_commit_and_branch_reference_natively() {
        let path = root("commit");
        let repository = Repository::init(&path).unwrap();
        create_dir_all(&join_path(&path, "src")).unwrap();
        write_file(&join_path(&path, "src/lib.rs"), b"pub fn native() {}\n").unwrap();
        repository
            .stage(&Vector::from([Text::from("src/lib.rs")]))
            .unwrap();
        let commit = repository
            .commit("initial", "MRML", "mrml@example.invalid", 1_700_000_000)
            .unwrap();
        assert_eq!(
            repository.commit("empty", "MRML", "mrml@example.invalid", 1_700_000_001),
            Err(RepositoryError::NoChanges)
        );
        assert_eq!(repository.head().unwrap(), Some(commit));
        assert!(path_is_file(&join_path(
            &repository.git_dir,
            &mrml_runtime::mrml_format!(
                "objects/{}/{}",
                &commit.to_hex()[..2],
                &commit.to_hex()[2..]
            )
        )));
        let packed = crate::parse_pack(&repository.pack_reachable(commit).unwrap()).unwrap();
        assert!(
            packed
                .iter()
                .any(|object| object.id == commit && object.kind == ObjectKind::Commit)
        );
        assert!(packed.iter().any(|object| object.kind == ObjectKind::Tree));
        assert!(packed.iter().any(|object| object.kind == ObjectKind::Blob));
        write_file(&join_path(&path, "src/lib.rs"), b"pub fn second() {}\n").unwrap();
        repository
            .stage(&Vector::from([Text::from("src/lib.rs")]))
            .unwrap();
        let second = repository
            .commit("second", "MRML", "mrml@example.invalid", 1_700_000_002)
            .unwrap();
        assert_eq!(repository.resolve_revision("HEAD~"), Ok(commit));
        assert_eq!(repository.resolve_revision("HEAD^1"), Ok(commit));
        assert_eq!(repository.resolve_revision("HEAD^0"), Ok(second));
        assert!(repository.resolve_revision("HEAD^2").is_err());
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn creates_and_verifies_signed_commit() {
        let path = root("signed-commit");
        let repository = Repository::init(&path).unwrap();
        write_file(&join_path(&path, "tracked"), b"signed").unwrap();
        repository
            .stage(&Vector::from([Text::from("tracked")]))
            .unwrap();
        let key = signing_key();
        let id = repository
            .commit_signed("signed", "Signer", "signer@example.invalid", 7, &key)
            .unwrap();
        repository
            .verify_commit_signature(id, key.public_key())
            .unwrap();
        let object = repository.read_object(id).unwrap();
        assert!(object.contents.windows(7).any(|part| part == b"gpgsig "));
        let tag = repository
            .create_signed_tag("v1", "release", "Signer", "signer@example.invalid", 8, &key)
            .unwrap();
        repository
            .verify_tag_signature(tag, key.public_key())
            .unwrap();
        assert_eq!(repository.resolve_revision("v1"), Ok(tag));
        let mut wrong = key.public_key().clone();
        wrong.exponent = Vector::from([3]);
        assert_eq!(
            repository.verify_commit_signature(id, &wrong),
            Err(RepositoryError::Signing)
        );
        assert_eq!(
            repository.verify_tag_signature(tag, &wrong),
            Err(RepositoryError::Signing)
        );
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn signature_verification_failure_never_updates_commit_or_tag_refs() {
        let path = root("signed-ref-verification-failure");
        let repository = Repository::init(&path).unwrap();
        write_file(&join_path(&path, "tracked"), b"base").unwrap();
        repository
            .stage(&Vector::from([Text::from("tracked")]))
            .unwrap();
        let base = repository
            .commit("base", "Signer", "signer@example.invalid", 6)
            .unwrap();
        write_file(&join_path(&path, "tracked"), b"changed").unwrap();
        repository
            .stage(&Vector::from([Text::from("tracked")]))
            .unwrap();
        let armor = "-----BEGIN PGP SIGNATURE-----\nZmFrZQ==\n-----END PGP SIGNATURE-----\n";
        assert_eq!(
            repository.commit_signed_with(
                "rejected",
                "Signer",
                "signer@example.invalid",
                7,
                GitSignatureFormat::OpenPgp,
                |_| Ok(armor.into()),
                |_, _| Err(RepositoryError::Signing),
            ),
            Err(RepositoryError::Signing)
        );
        assert_eq!(repository.head(), Ok(Some(base)));
        assert_eq!(
            repository.create_signed_tag_with(
                "rejected",
                "rejected",
                "Signer",
                "signer@example.invalid",
                8,
                GitSignatureFormat::OpenPgp,
                |_| Ok(armor.into()),
                |_, _| Err(RepositoryError::Signing),
            ),
            Err(RepositoryError::Signing)
        );
        assert_eq!(repository.read_reference("refs/tags/rejected"), Ok(None));
        assert_eq!(repository.head(), Ok(Some(base)));
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn sha256_commit_uses_gpgsig_sha256_and_generic_openpgp_payload() {
        let path = root("signed-sha256-commit");
        let repository = Repository::init_with_format(&path, ObjectFormat::Sha256).unwrap();
        write_file(&join_path(&path, "tracked"), b"signed").unwrap();
        repository
            .stage(&Vector::from([Text::from("tracked")]))
            .unwrap();
        let armor = "-----BEGIN PGP SIGNATURE-----\nZmFrZQ==\n-----END PGP SIGNATURE-----\n";
        let id = repository
            .commit_signed_with(
                "signed",
                "Signer",
                "signer@example.invalid",
                7,
                GitSignatureFormat::OpenPgp,
                |payload| {
                    assert!(payload.ends_with(b"\n\nsigned\n"));
                    Ok(armor.into())
                },
                |payload, found| {
                    assert!(payload.ends_with(b"\n\nsigned\n"));
                    assert_eq!(found, armor);
                    Ok(())
                },
            )
            .unwrap();
        let object = repository.read_object(id).unwrap();
        assert!(
            object
                .contents
                .windows(b"gpgsig-sha256 ".len())
                .any(|part| part == b"gpgsig-sha256 ")
        );
        assert!(
            !object
                .contents
                .windows(b"\ngpgsig ".len())
                .any(|part| part == b"\ngpgsig ")
        );
        repository
            .verify_commit_signature_with(id, GitSignatureFormat::OpenPgp, |payload, found| {
                assert!(payload.ends_with(b"\n\nsigned\n"));
                assert_eq!(found, armor);
                Ok(())
            })
            .unwrap();
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn hybrid_commit_nests_ml_dsa_under_openpgp_for_both_object_formats() {
        let mut public = [0u8; ML_DSA_65_PUBLIC_KEY_BYTES];
        let mut secret = [0u8; ML_DSA_65_SECRET_KEY_BYTES];
        ml_dsa_65_keygen(&[31u8; 32], &mut public, &mut secret).unwrap();
        let pgp = "-----BEGIN PGP SIGNATURE-----\nZmFrZQ==\n-----END PGP SIGNATURE-----\n";
        for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
            let path = root(match format {
                ObjectFormat::Sha1 => "hybrid-sha1",
                ObjectFormat::Sha256 => "hybrid-sha256",
            });
            let repository = Repository::init_with_format(&path, format).unwrap();
            write_file(&join_path(&path, "tracked"), b"hybrid").unwrap();
            repository.stage(&Vector::from(["tracked".into()])).unwrap();
            let id = repository
                .commit_hybrid_signed_with(
                    "hybrid",
                    "Signer",
                    "signer@example.invalid",
                    9,
                    |payload| {
                        sign_ml_dsa_65_git_payload(&secret, payload, &[37u8; 32])
                            .map_err(|_| RepositoryError::Signing)
                    },
                    |payload| {
                        assert!(
                            payload
                                .windows(b"mrml-mldsa65 ".len())
                                .any(|part| part == b"mrml-mldsa65 ")
                        );
                        Ok(pgp.into())
                    },
                    |payload, found| {
                        assert!(
                            payload
                                .windows(b"mrml-mldsa65 ".len())
                                .any(|part| part == b"mrml-mldsa65 ")
                        );
                        assert_eq!(found, pgp);
                        Ok(())
                    },
                    |payload, armor| {
                        verify_ml_dsa_65_git_payload(&public, payload, armor)
                            .map_err(|_| RepositoryError::Signing)
                    },
                )
                .unwrap();
            repository
                .verify_hybrid_commit_signature_with(
                    id,
                    |payload, found| {
                        assert!(
                            payload
                                .windows(b"mrml-mldsa65 ".len())
                                .any(|part| part == b"mrml-mldsa65 ")
                        );
                        assert_eq!(found, pgp);
                        Ok(())
                    },
                    |payload, armor| {
                        verify_ml_dsa_65_git_payload(&public, payload, armor)
                            .map_err(|_| RepositoryError::Signing)
                    },
                )
                .unwrap();
            write_file(&join_path(&path, "tracked"), b"hybrid-failed").unwrap();
            repository.stage(&Vector::from(["tracked".into()])).unwrap();
            assert_eq!(
                repository.commit_hybrid_signed_with(
                    "must not activate",
                    "Signer",
                    "signer@example.invalid",
                    10,
                    |payload| {
                        sign_ml_dsa_65_git_payload(&secret, payload, &[38u8; 32])
                            .map_err(|_| RepositoryError::Signing)
                    },
                    |_| Ok(pgp.into()),
                    |_, _| Err(RepositoryError::Signing),
                    |payload, armor| {
                        verify_ml_dsa_65_git_payload(&public, payload, armor)
                            .map_err(|_| RepositoryError::Signing)
                    },
                ),
                Err(RepositoryError::Signing)
            );
            assert_eq!(repository.head().unwrap(), Some(id));
            remove_dir_all(&path).unwrap();
        }
    }

    #[test]
    fn creates_lists_and_deletes_native_refs() {
        let path = root("refs");
        let repository = Repository::init(&path).unwrap();
        write_file(&join_path(&path, "tracked"), b"value").unwrap();
        repository
            .stage(&Vector::from([Text::from("tracked")]))
            .unwrap();
        let head = repository
            .commit("base", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        assert_eq!(
            repository.create_branch("topic/nested", false).unwrap(),
            head
        );
        assert!(
            repository
                .branches()
                .unwrap()
                .iter()
                .any(|(name, id)| name == "topic/nested" && *id == head)
        );
        repository.delete_branch("topic/nested").unwrap();
        assert!(
            !repository
                .branches()
                .unwrap()
                .iter()
                .any(|(name, _)| name == "topic/nested")
        );
        assert_eq!(repository.create_tag("v1").unwrap(), head);
        assert_eq!(repository.tags().unwrap()[0], (Text::from("v1"), head));
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn reads_packed_objects_and_references_after_gc_layout() {
        let source_path = root("pack-source");
        let source = Repository::init(&source_path).unwrap();
        write_file(&join_path(&source_path, "tracked"), b"packed").unwrap();
        source
            .stage(&Vector::from([Text::from("tracked")]))
            .unwrap();
        let head = source
            .commit("packed", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        let pack = source.pack_reachable(head).unwrap();

        let path = root("packed-layout");
        let repository = Repository::init(&path).unwrap();
        let pack_dir = join_path(&repository.git_dir, "objects/pack");
        create_dir_all(&pack_dir).unwrap();
        write_file(&join_path(&pack_dir, "pack-native.pack"), &pack).unwrap();
        write_file(
            &join_path(&repository.git_dir, "packed-refs"),
            mrml_runtime::mrml_format!(
                "# pack-refs with: peeled fully-peeled\n{head} refs/heads/main\n{head} refs/heads/topic\n{head} refs/tags/v1\n"
            )
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(repository.head().unwrap(), Some(head));
        assert_eq!(
            repository.read_commit(head).unwrap().message.trim(),
            "packed"
        );
        assert!(
            repository
                .branches()
                .unwrap()
                .iter()
                .any(|(name, _)| name == "topic")
        );
        assert_eq!(repository.resolve_revision("v1"), Ok(head));
        repository.delete_branch("topic").unwrap();
        assert!(
            !repository
                .branches()
                .unwrap()
                .iter()
                .any(|(name, _)| name == "topic")
        );
        remove_dir_all(&source_path).unwrap();
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn negotiated_pack_subtracts_complete_have_closure() {
        struct Sink {
            bytes: Vector<u8>,
            maximum_write: usize,
        }
        impl crate::PackStreamOutput for Sink {
            fn write(&mut self, bytes: &[u8]) -> Result<(), PackError> {
                self.maximum_write = self.maximum_write.max(bytes.len());
                self.bytes
                    .try_extend_from_slice(bytes)
                    .map_err(|_| PackError::TooLarge)
            }
        }
        let path = root("negotiated-pack");
        let repository = Repository::init_with_format(&path, ObjectFormat::Sha256).unwrap();
        let tracked = join_path(&path, "tracked");
        write_file(&tracked, b"first").unwrap();
        repository
            .stage(&Vector::from([Text::from("tracked")]))
            .unwrap();
        let first = repository
            .commit("first", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        write_file(&tracked, b"second").unwrap();
        repository
            .stage(&Vector::from([Text::from("tracked")]))
            .unwrap();
        let second = repository
            .commit("second", "MRML", "mrml@example.invalid", 2)
            .unwrap();

        let incremental = parse_pack_with_format(
            &repository.pack_negotiated(&[second], &[first]).unwrap(),
            ObjectFormat::Sha256,
        )
        .unwrap();
        assert!(incremental.iter().any(|object| object.id == second));
        assert!(!incremental.iter().any(|object| object.id == first));
        let mut streamed = Sink {
            bytes: Vector::new(),
            maximum_write: 0,
        };
        let streamed_count = repository
            .write_negotiated_pack(&[second], &[first], &mut streamed)
            .unwrap();
        let streamed_objects =
            parse_pack_with_format(&streamed.bytes, ObjectFormat::Sha256).unwrap();
        assert_eq!(streamed_count, streamed_objects.len());
        assert!(streamed_objects.iter().any(|object| object.id == second));
        assert!(!streamed_objects.iter().any(|object| object.id == first));
        assert!(streamed.maximum_write <= u16::MAX as usize);
        let empty = parse_pack_with_format(
            &repository.pack_negotiated(&[second], &[second]).unwrap(),
            ObjectFormat::Sha256,
        )
        .unwrap();
        assert!(empty.is_empty());
        remove_dir_all(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn six_concurrent_fetch_pack_generations_are_deterministic() {
        let path = root("concurrent-fetch-pack");
        let repository = Repository::init_with_format(&path, ObjectFormat::Sha256).unwrap();
        let tracked = join_path(&path, "tracked");
        write_file(&tracked, &[b'x'; 64 * 1024]).unwrap();
        repository
            .stage(&Vector::from([Text::from("tracked")]))
            .unwrap();
        let tip = repository
            .commit("concurrent", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        let expected = repository.pack_reachable(tip).unwrap();

        let mut workers = Vector::new();
        for _ in 0..6 {
            let worker_path = path.clone();
            let worker_expected = expected.clone();
            let worker = mrml_runtime::spawn_joinable(move || {
                let worker_repository = Repository::discover(&worker_path).unwrap();
                assert_eq!(
                    worker_repository.pack_reachable(tip).unwrap(),
                    worker_expected
                );
            })
            .unwrap_or_else(|_| panic!("failed to start fetch-pack generation worker"));
            workers.push(worker);
        }
        for worker in workers {
            assert!(worker.join());
        }
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn switches_branches_by_materializing_authenticated_tree() {
        let path = root("switch");
        let repository = Repository::init(&path).unwrap();
        let file = join_path(&path, "tracked");
        write_file(&file, b"main").unwrap();
        repository
            .stage(&Vector::from([Text::from("tracked")]))
            .unwrap();
        let main = repository
            .commit("main", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        repository.create_branch("topic", true).unwrap();
        write_file(&file, b"topic").unwrap();
        repository
            .stage(&Vector::from([Text::from("tracked")]))
            .unwrap();
        repository
            .commit("topic", "MRML", "mrml@example.invalid", 2)
            .unwrap();
        assert_eq!(repository.switch_branch("main").unwrap(), main);
        assert_eq!(&*read_file_bounded(&file, 16).unwrap(), b"main");
        assert_eq!(
            repository.current_branch().unwrap().as_deref(),
            Some("main")
        );
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn restores_worktree_and_unstages_to_head() {
        let path = root("restore");
        let repository = Repository::init(&path).unwrap();
        let file = join_path(&path, "tracked");
        write_file(&file, b"base").unwrap();
        let paths = Vector::from([Text::from("tracked")]);
        repository.stage(&paths).unwrap();
        repository
            .commit("base", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        write_file(&file, b"changed").unwrap();
        repository.stage(&paths).unwrap();
        repository.unstage(&paths).unwrap();
        assert_eq!(
            repository.index().unwrap().entry("tracked").unwrap().id,
            ObjectId::blob(b"base")
        );
        repository.restore(&paths).unwrap();
        assert_eq!(&*read_file_bounded(&file, 16).unwrap(), b"base");
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn adds_and_updates_remote_configuration_natively() {
        let path = root("remote");
        let repository = Repository::init(&path).unwrap();
        repository
            .set_remote("origin", "git@example.invalid:owner/repo.git", false)
            .unwrap();
        assert_eq!(
            repository.remotes().unwrap()[0],
            (
                Text::from("origin"),
                Text::from("git@example.invalid:owner/repo.git")
            )
        );
        repository
            .set_remote("origin", "ssh://git@example.invalid/other/repo.git", true)
            .unwrap();
        assert_eq!(
            repository.remotes().unwrap()[0].1,
            "ssh://git@example.invalid/other/repo.git"
        );
        assert!(
            repository
                .set_remote("missing", "git@example.invalid:x/y", true)
                .is_err()
        );
        let remote_id = ObjectId::blob(b"remote-tip");
        repository
            .update_remote_ref("origin", "refs/heads/main", remote_id)
            .unwrap();
        let remote_hex = remote_id.to_hex();
        assert_eq!(
            remote_hex,
            read_file_text_bounded(
                &join_path(&repository.git_dir, "refs/remotes/origin/main"),
                64
            )
            .unwrap()
            .trim()
        );
        repository
            .update_remote_ref("origin", "refs/heads/stale/topic", remote_id)
            .unwrap();
        assert_eq!(
            repository
                .prune_remote_refs("origin", &[Text::from("main")])
                .unwrap(),
            1
        );
        assert!(!path_exists(&join_path(
            &repository.git_dir,
            "refs/remotes/origin/stale/topic"
        )));
        assert_eq!(repository.prune_remote_refs("origin", &[]).unwrap(), 1);
        assert!(
            repository
                .update_remote_ref("../escape", "refs/heads/main", remote_id)
                .is_err()
        );
        assert!(
            repository
                .update_remote_ref("origin", "refs/tags/not-a-branch", remote_id)
                .is_err()
        );
        repository
            .set_config_value("ssh", "privateKey", "key.pem")
            .unwrap();
        repository
            .set_config_value("ssh", "hostKey", "host.pub")
            .unwrap();
        repository
            .set_config_value("ssh", "privateKey", "new.pem")
            .unwrap();
        assert_eq!(
            repository
                .config_value("ssh", "privateKey")
                .unwrap()
                .as_deref(),
            Some("new.pem")
        );
        assert_eq!(
            repository
                .config_value("ssh", "hostKey")
                .unwrap()
                .as_deref(),
            Some("host.pub")
        );
        assert!(repository.set_config_value("ssh", "bad key", "x").is_err());
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn remote_branch_set_activates_as_one_authenticated_manifest() {
        let path = root("atomic-remote-refs");
        let repository = Repository::init(&path).unwrap();
        let old = ObjectId::blob(b"old");
        let main = ObjectId::blob(b"main");
        let topic = ObjectId::blob(b"topic");
        repository
            .update_remote_ref("origin", "refs/heads/main", old)
            .unwrap();
        repository
            .update_remote_ref("origin", "refs/heads/stale", old)
            .unwrap();
        repository
            .activate_remote_refs_atomically(
                "origin",
                &[(Text::from("topic"), topic), (Text::from("main"), main)],
            )
            .unwrap();
        assert_eq!(
            repository
                .resolve_revision("refs/remotes/origin/main")
                .unwrap(),
            main
        );
        assert_eq!(
            repository
                .resolve_revision("refs/remotes/origin/topic")
                .unwrap(),
            topic
        );
        assert_eq!(
            repository.resolve_revision("refs/remotes/origin/stale"),
            Err(RepositoryError::ReferenceMissing)
        );
        let active = join_path(
            &join_path(&repository.git_dir, "mrml-remote-refs"),
            "origin.refs",
        );
        let mut tampered = read_file_bounded(&active, MAX_REMOTE_REFS_BYTES).unwrap();
        tampered[0] ^= 1;
        write_file(&active, &tampered).unwrap();
        assert!(repository.active_remote_refs("origin").is_err());
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn tracks_upstream_and_computes_native_divergence() {
        let path = root("upstream");
        let repository = Repository::init(&path).unwrap();
        let file = join_path(&path, "tracked");
        let paths = Vector::from([Text::from("tracked")]);
        write_file(&file, b"base").unwrap();
        repository.stage(&paths).unwrap();
        let base = repository
            .commit("base", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        repository
            .update_remote_ref("origin", "refs/heads/main", base)
            .unwrap();
        repository.set_upstream("origin/main").unwrap();
        assert_eq!(
            repository.upstream_status().unwrap(),
            Some((Text::from("origin/main"), 0, 0))
        );
        write_file(&file, b"local").unwrap();
        repository.stage(&paths).unwrap();
        repository
            .commit("local", "MRML", "mrml@example.invalid", 2)
            .unwrap();
        assert_eq!(
            repository.upstream_status().unwrap(),
            Some((Text::from("origin/main"), 1, 0))
        );
        assert!(repository.set_upstream("../escape").is_err());
        assert!(repository.set_upstream("origin/missing").is_err());
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn computes_staged_and_worktree_diffs_natively() {
        let path = root("diff");
        let repository = Repository::init(&path).unwrap();
        let file = join_path(&path, "tracked");
        let paths = Vector::from([Text::from("tracked")]);
        write_file(&file, b"base\n").unwrap();
        repository.stage(&paths).unwrap();
        repository
            .commit("base", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        write_file(&file, b"staged\n").unwrap();
        repository.stage(&paths).unwrap();
        assert_eq!(
            repository.diff(true, &[]).unwrap()[0].new.as_deref(),
            Some(&b"staged\n"[..])
        );
        write_file(&file, b"worktree\n").unwrap();
        assert_eq!(
            repository.diff(false, &[]).unwrap()[0].new.as_deref(),
            Some(&b"worktree\n"[..])
        );
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn filters_file_history_and_diffs_against_revision() {
        let path = root("file-history");
        let repository = Repository::init(&path).unwrap();
        let file = join_path(&path, "tracked");
        let paths = Vector::from([Text::from("tracked")]);
        write_file(&file, b"one\n").unwrap();
        repository.stage(&paths).unwrap();
        repository
            .commit("one", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        write_file(&file, b"two\n").unwrap();
        repository.stage(&paths).unwrap();
        repository
            .commit("two", "MRML", "mrml@example.invalid", 2)
            .unwrap();
        write_file(&file, b"three\n").unwrap();
        assert_eq!(repository.file_history("tracked", 10).unwrap().len(), 2);
        assert_eq!(
            repository.diff_revision("HEAD", &paths).unwrap()[0]
                .new
                .as_deref(),
            Some(&b"three\n"[..])
        );
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn attributes_lines_to_their_introducing_commits() {
        let path = root("blame");
        let repository = Repository::init(&path).unwrap();
        let file = join_path(&path, "tracked");
        let paths = Vector::from([Text::from("tracked")]);
        write_file(&file, b"old\n").unwrap();
        repository.stage(&paths).unwrap();
        let old = repository
            .commit("old", "Old", "old@example.invalid", 1)
            .unwrap();
        write_file(&file, b"old\nnew\n").unwrap();
        repository.stage(&paths).unwrap();
        let new = repository
            .commit("new", "New", "new@example.invalid", 2)
            .unwrap();
        let blame = repository.blame("tracked").unwrap();
        assert_eq!(blame[0].commit, old);
        assert_eq!(blame[1].commit, new);
        assert!(blame[0].author.starts_with("Old "));
        assert!(blame[1].author.starts_with("New "));
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn fast_forwards_current_branch_natively() {
        let path = root("merge-ff");
        let repository = Repository::init(&path).unwrap();
        let file = join_path(&path, "tracked");
        let paths = Vector::from([Text::from("tracked")]);
        write_file(&file, b"base").unwrap();
        repository.stage(&paths).unwrap();
        repository
            .commit("base", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        repository.create_branch("topic", true).unwrap();
        write_file(&file, b"topic").unwrap();
        repository.stage(&paths).unwrap();
        let topic = repository
            .commit("topic", "MRML", "mrml@example.invalid", 2)
            .unwrap();
        repository.switch_branch("main").unwrap();
        assert_eq!(
            repository.fast_forward("topic").unwrap(),
            MergeOutcome::FastForward(topic)
        );
        assert_eq!(&*read_file_bounded(&file, 16).unwrap(), b"topic");
        assert_eq!(repository.head().unwrap(), Some(topic));
        assert_eq!(
            repository.fast_forward("topic").unwrap(),
            MergeOutcome::UpToDate
        );
        assert_eq!(
            repository.checkout_branch_at("clone-tip", topic).unwrap(),
            topic
        );
        assert_eq!(
            repository.current_branch().unwrap().as_deref(),
            Some("clone-tip")
        );
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn checkout_branch_at_materializes_an_initial_clone_before_activating_its_ref() {
        let path = root("checkout-initial-clone");
        let repository = Repository::init(&path).unwrap();
        let file = join_path(&path, "tracked");
        write_file(&file, b"clone contents").unwrap();
        repository
            .stage(&Vector::from([Text::from("tracked")]))
            .unwrap();
        let tip = repository
            .commit("initial", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        mrml_runtime::remove_file(&file).unwrap();
        mrml_runtime::remove_file(&join_path(&repository.git_dir, "index")).unwrap();
        mrml_runtime::remove_file(&join_path(&repository.git_dir, "refs/heads/main")).unwrap();

        assert_eq!(repository.checkout_branch_at("main", tip).unwrap(), tip);
        assert_eq!(&*read_file_bounded(&file, 32).unwrap(), b"clone contents");
        assert!(repository.changes().unwrap().is_empty());
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn pushes_lists_and_pops_stash_objects() {
        let path = root("stash");
        let repository = Repository::init(&path).unwrap();
        let file = join_path(&path, "tracked");
        let paths = Vector::from([Text::from("tracked")]);
        write_file(&file, b"base").unwrap();
        repository.stage(&paths).unwrap();
        repository
            .commit("base", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        write_file(&file, b"saved").unwrap();
        let stash = repository
            .stash_push("checkpoint", "MRML", "mrml@example.invalid", 2)
            .unwrap();
        assert_eq!(&*read_file_bounded(&file, 16).unwrap(), b"base");
        assert_eq!(repository.stash_list(10).unwrap()[0].0, stash);
        assert_eq!(repository.stash_pop().unwrap(), stash);
        assert_eq!(&*read_file_bounded(&file, 16).unwrap(), b"saved");
        assert!(repository.stash_list(10).unwrap().is_empty());
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn creates_native_two_parent_three_way_merge() {
        let path = root("merge-three");
        let repository = Repository::init(&path).unwrap();
        let base_file = join_path(&path, "base");
        write_file(&base_file, b"base").unwrap();
        repository
            .stage(&Vector::from([Text::from("base")]))
            .unwrap();
        repository
            .commit("base", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        repository.create_branch("topic", true).unwrap();
        let topic_file = join_path(&path, "topic");
        write_file(&topic_file, b"topic").unwrap();
        repository
            .stage(&Vector::from([Text::from("topic")]))
            .unwrap();
        let topic = repository
            .commit("topic", "MRML", "mrml@example.invalid", 2)
            .unwrap();
        repository.switch_branch("main").unwrap();
        let main_file = join_path(&path, "main");
        write_file(&main_file, b"main").unwrap();
        repository
            .stage(&Vector::from([Text::from("main")]))
            .unwrap();
        let ours = repository
            .commit("main", "MRML", "mrml@example.invalid", 3)
            .unwrap();
        let merged = match repository
            .merge("topic", "MRML", "mrml@example.invalid", 4)
            .unwrap()
        {
            MergeOutcome::Merged(id) => id,
            other => panic!("unexpected {other:?}"),
        };
        let commit = repository.read_commit(merged).unwrap();
        assert_eq!(&commit.parents[..], &[ours, topic]);
        assert!(path_is_file(&topic_file));
        assert!(path_is_file(&main_file));
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn records_conflict_stages_and_aborts_merge() {
        let path = root("merge-conflict");
        let repository = Repository::init(&path).unwrap();
        let file = join_path(&path, "tracked");
        let paths = Vector::from([Text::from("tracked")]);
        write_file(&file, b"base\n").unwrap();
        repository.stage(&paths).unwrap();
        repository
            .commit("base", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        repository.create_branch("topic", true).unwrap();
        write_file(&file, b"theirs\n").unwrap();
        repository.stage(&paths).unwrap();
        repository
            .commit("theirs", "MRML", "mrml@example.invalid", 2)
            .unwrap();
        repository.switch_branch("main").unwrap();
        write_file(&file, b"ours\n").unwrap();
        repository.stage(&paths).unwrap();
        let ours = repository
            .commit("ours", "MRML", "mrml@example.invalid", 3)
            .unwrap();
        assert_eq!(
            repository
                .merge("topic", "MRML", "mrml@example.invalid", 4)
                .unwrap(),
            MergeOutcome::Conflicts(1)
        );
        assert_eq!(
            repository
                .index()
                .unwrap()
                .entries
                .iter()
                .filter(|entry| entry.path == "tracked")
                .count(),
            3
        );
        assert!(
            read_file_text_bounded(&file, 1024)
                .unwrap()
                .contains("<<<<<<< HEAD")
        );
        assert_eq!(repository.abort_merge().unwrap(), ours);
        assert_eq!(&*read_file_bounded(&file, 16).unwrap(), b"ours\n");
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn cherry_picks_commit_as_new_one_parent_commit() {
        let path = root("cherry");
        let repository = Repository::init(&path).unwrap();
        let base = join_path(&path, "base");
        write_file(&base, b"base").unwrap();
        repository
            .stage(&Vector::from([Text::from("base")]))
            .unwrap();
        repository
            .commit("base", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        repository.create_branch("topic", true).unwrap();
        let added = join_path(&path, "added");
        write_file(&added, b"picked").unwrap();
        repository
            .stage(&Vector::from([Text::from("added")]))
            .unwrap();
        let picked = repository
            .commit("picked", "Original", "original@example.invalid", 2)
            .unwrap();
        repository.switch_branch("main").unwrap();
        let own = join_path(&path, "own");
        write_file(&own, b"own").unwrap();
        repository
            .stage(&Vector::from([Text::from("own")]))
            .unwrap();
        let parent = repository
            .commit("own", "MRML", "mrml@example.invalid", 3)
            .unwrap();
        let id = match repository
            .cherry_pick(
                &picked.to_hex(),
                "Committer",
                "committer@example.invalid",
                4,
            )
            .unwrap()
        {
            MergeOutcome::Merged(id) => id,
            other => panic!("unexpected {other:?}"),
        };
        let commit = repository.read_commit(id).unwrap();
        assert_eq!(&commit.parents[..], &[parent]);
        assert!(commit.author.starts_with("Original "));
        assert!(path_is_file(&added));
        assert!(path_is_file(&own));
        remove_dir_all(&path).unwrap();
    }

    #[test]
    fn rebases_linear_commits_onto_target() {
        let path = root("rebase");
        let repository = Repository::init(&path).unwrap();
        let base = join_path(&path, "base");
        write_file(&base, b"base").unwrap();
        repository
            .stage(&Vector::from([Text::from("base")]))
            .unwrap();
        repository
            .commit("base", "MRML", "mrml@example.invalid", 1)
            .unwrap();
        repository.create_branch("topic", true).unwrap();
        let topic_file = join_path(&path, "topic");
        write_file(&topic_file, b"topic").unwrap();
        repository
            .stage(&Vector::from([Text::from("topic")]))
            .unwrap();
        let topic = repository
            .commit("topic", "Topic", "topic@example.invalid", 2)
            .unwrap();
        repository.switch_branch("main").unwrap();
        let main_file = join_path(&path, "main");
        write_file(&main_file, b"main").unwrap();
        repository
            .stage(&Vector::from([Text::from("main")]))
            .unwrap();
        let original = repository
            .commit("main", "Main", "main@example.invalid", 3)
            .unwrap();
        let head = match repository
            .rebase("topic", "Committer", "committer@example.invalid", 4)
            .unwrap()
        {
            RebaseOutcome::Rebased { count: 1, head } => head,
            other => panic!("unexpected {other:?}"),
        };
        assert_ne!(head, original);
        assert_eq!(repository.read_commit(head).unwrap().parents[0], topic);
        assert!(path_is_file(&topic_file));
        assert!(path_is_file(&main_file));
        remove_dir_all(&path).unwrap();
    }
}
