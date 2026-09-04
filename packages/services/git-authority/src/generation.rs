use mrml_crypto::Sha256;
use mrml_git::{RepositoryGeneration, RepositoryIdentity};
use mrml_runtime::{DirectoryCapability, File};
#[cfg(test)]
use std::fs;

const MAGIC: &[u8; 8] = b"MRAGEN01";
const DOMAIN: &[u8] = b"MRML git authority repository generation v1\0";
const LOCK_EXCLUSIVE_NONBLOCKING: i32 = 2 | 4;
const MAX_REPOSITORY_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationStoreError {
    Invalid,
    Stale,
    Unavailable,
}

pub trait AuthorityGenerationStore: Send {
    fn current(
        &self,
        repository: &RepositoryIdentity,
    ) -> Result<RepositoryGeneration, GenerationStoreError>;

    fn commit_next(
        &mut self,
        repository: &RepositoryIdentity,
        expected: RepositoryGeneration,
        next: RepositoryGeneration,
    ) -> Result<(), GenerationStoreError>;
}

pub struct MemoryAuthorityGenerationStore {
    repository: RepositoryIdentity,
    generation: RepositoryGeneration,
}

impl MemoryAuthorityGenerationStore {
    pub fn new(repository: RepositoryIdentity, generation: RepositoryGeneration) -> Self {
        Self {
            repository,
            generation,
        }
    }
}

impl AuthorityGenerationStore for MemoryAuthorityGenerationStore {
    fn current(
        &self,
        repository: &RepositoryIdentity,
    ) -> Result<RepositoryGeneration, GenerationStoreError> {
        (repository == &self.repository && self.generation.0 != 0)
            .then_some(self.generation)
            .ok_or(GenerationStoreError::Invalid)
    }

    fn commit_next(
        &mut self,
        repository: &RepositoryIdentity,
        expected: RepositoryGeneration,
        next: RepositoryGeneration,
    ) -> Result<(), GenerationStoreError> {
        if repository != &self.repository
            || self.generation != expected
            || expected.0.checked_add(1) != Some(next.0)
        {
            return Err(GenerationStoreError::Stale);
        }
        self.generation = next;
        Ok(())
    }
}

pub struct LinuxAuthorityGenerationStore {
    root: DirectoryCapability,
    owner_uid: u32,
    _lock: File,
}

impl LinuxAuthorityGenerationStore {
    pub fn open(
        root: &str,
        owner_uid: u32,
        repository: &RepositoryIdentity,
        bootstrap_generation: RepositoryGeneration,
    ) -> Result<Self, GenerationStoreError> {
        if owner_uid == 0 || bootstrap_generation.0 == 0 {
            return Err(GenerationStoreError::Invalid);
        }
        let root =
            DirectoryCapability::open_root(root).map_err(|_| GenerationStoreError::Unavailable)?;
        Self::open_capability(root, owner_uid, repository, bootstrap_generation)
    }

    pub fn open_capability(
        root: DirectoryCapability,
        owner_uid: u32,
        repository: &RepositoryIdentity,
        bootstrap_generation: RepositoryGeneration,
    ) -> Result<Self, GenerationStoreError> {
        if owner_uid == 0 || bootstrap_generation.0 == 0 {
            return Err(GenerationStoreError::Invalid);
        }
        validate_directory(&root, owner_uid)?;
        let lock = match root.create_new_file("catalog.lock", 0o600) {
            Ok(file) => file,
            Err(_) => root
                .open_regular("catalog.lock")
                .map_err(|_| GenerationStoreError::Unavailable)?,
        };
        validate_file(&lock, owner_uid, None)?;
        // SAFETY: `lock` owns a live file descriptor for the duration of this
        // call and `flock` neither retains nor dereferences a pointer.
        if unsafe { flock(lock.raw_fd(), LOCK_EXCLUSIVE_NONBLOCKING) } != 0 {
            return Err(GenerationStoreError::Unavailable);
        }
        let store = Self {
            root,
            owner_uid,
            _lock: lock,
        };
        let path = store.name(repository);
        let temporary = store.temporary_name(repository);
        if let Ok(file) = store.root.open_regular(&temporary) {
            validate_file(&file, owner_uid, None)?;
            store
                .root
                .remove_file(&temporary)
                .map_err(|_| GenerationStoreError::Unavailable)?;
            store.sync()?;
        }
        if store.root.open_regular(&path).is_err() {
            store.write_new(&path, repository, bootstrap_generation)?;
        }
        if store.current(repository)? != bootstrap_generation {
            // Bootstrap is an assertion on first deployment and a rollback
            // floor thereafter; an existing newer state is accepted.
            if store.current(repository)?.0 < bootstrap_generation.0 {
                return Err(GenerationStoreError::Stale);
            }
        }
        Ok(store)
    }

    fn name(&self, repository: &RepositoryIdentity) -> String {
        format!("{}.generation", repository_key(repository))
    }

    fn temporary_name(&self, repository: &RepositoryIdentity) -> String {
        format!("{}.generation.next", repository_key(repository))
    }

    fn write_new(
        &self,
        name: &str,
        repository: &RepositoryIdentity,
        generation: RepositoryGeneration,
    ) -> Result<(), GenerationStoreError> {
        let encoded = encode(repository, generation)?;
        let mut file = self
            .root
            .create_new_file(name, 0o600)
            .map_err(|_| GenerationStoreError::Unavailable)?;
        file.write_all(&encoded)
            .and_then(|_| file.sync())
            .map_err(|_| GenerationStoreError::Unavailable)?;
        validate_file(&file, self.owner_uid, Some(encoded.len() as u64))?;
        drop(file);
        self.sync()
    }

    fn sync(&self) -> Result<(), GenerationStoreError> {
        self.root
            .sync()
            .map_err(|_| GenerationStoreError::Unavailable)
    }
}

impl AuthorityGenerationStore for LinuxAuthorityGenerationStore {
    fn current(
        &self,
        repository: &RepositoryIdentity,
    ) -> Result<RepositoryGeneration, GenerationStoreError> {
        let name = self.name(repository);
        let mut file = self
            .root
            .open_regular(&name)
            .map_err(|_| GenerationStoreError::Unavailable)?;
        let length = file.len().map_err(|_| GenerationStoreError::Unavailable)?;
        validate_file(&file, self.owner_uid, Some(length))?;
        if length > (8 + 2 + MAX_REPOSITORY_BYTES + 8 + 32) as u64 {
            return Err(GenerationStoreError::Invalid);
        }
        let mut bytes = vec![0; length as usize];
        file.read_exact(&mut bytes)
            .map_err(|_| GenerationStoreError::Unavailable)?;
        decode(&bytes, repository)
    }

    fn commit_next(
        &mut self,
        repository: &RepositoryIdentity,
        expected: RepositoryGeneration,
        next: RepositoryGeneration,
    ) -> Result<(), GenerationStoreError> {
        if self.current(repository)? != expected || expected.0.checked_add(1) != Some(next.0) {
            return Err(GenerationStoreError::Stale);
        }
        let temporary = self.temporary_name(repository);
        if self.root.open_regular(&temporary).is_ok() {
            return Err(GenerationStoreError::Unavailable);
        }
        self.write_new(&temporary, repository, next)?;
        self.root
            .rename_child(&temporary, &self.name(repository))
            .map_err(|_| GenerationStoreError::Unavailable)?;
        self.sync()?;
        (self.current(repository)? == next)
            .then_some(())
            .ok_or(GenerationStoreError::Unavailable)
    }
}

fn encode(
    repository: &RepositoryIdentity,
    generation: RepositoryGeneration,
) -> Result<Vec<u8>, GenerationStoreError> {
    let name = repository.as_str().as_bytes();
    if name.is_empty() || name.len() > MAX_REPOSITORY_BYTES || generation.0 == 0 {
        return Err(GenerationStoreError::Invalid);
    }
    let mut output = Vec::with_capacity(8 + 2 + name.len() + 8 + 32);
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&(name.len() as u16).to_be_bytes());
    output.extend_from_slice(name);
    output.extend_from_slice(&generation.0.to_be_bytes());
    let checksum = checksum(&output);
    output.extend_from_slice(&checksum);
    Ok(output)
}

fn decode(
    input: &[u8],
    repository: &RepositoryIdentity,
) -> Result<RepositoryGeneration, GenerationStoreError> {
    if input.len() < 8 + 2 + 1 + 8 + 32 || !input.starts_with(MAGIC) {
        return Err(GenerationStoreError::Invalid);
    }
    let body_end = input.len() - 32;
    if checksum(&input[..body_end]) != input[body_end..] {
        return Err(GenerationStoreError::Invalid);
    }
    let name_len = u16::from_be_bytes(
        input[8..10]
            .try_into()
            .map_err(|_| GenerationStoreError::Invalid)?,
    ) as usize;
    let generation_offset = 10usize
        .checked_add(name_len)
        .ok_or(GenerationStoreError::Invalid)?;
    if name_len == 0
        || name_len > MAX_REPOSITORY_BYTES
        || generation_offset.checked_add(8) != Some(body_end)
        || &input[10..generation_offset] != repository.as_str().as_bytes()
    {
        return Err(GenerationStoreError::Invalid);
    }
    let generation = u64::from_be_bytes(
        input[generation_offset..body_end]
            .try_into()
            .map_err(|_| GenerationStoreError::Invalid)?,
    );
    (generation != 0)
        .then_some(RepositoryGeneration(generation))
        .ok_or(GenerationStoreError::Invalid)
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(bytes);
    digest.finalize()
}

fn repository_key(repository: &RepositoryIdentity) -> String {
    let mut digest = Sha256::new();
    digest.update(b"MRML authority repository catalog key v1\0");
    digest.update(repository.as_str().as_bytes());
    let digest = digest.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn validate_directory(
    directory: &DirectoryCapability,
    owner_uid: u32,
) -> Result<(), GenerationStoreError> {
    let metadata = directory
        .metadata()
        .map_err(|_| GenerationStoreError::Unavailable)?;
    if metadata.uid != owner_uid || metadata.mode & 0o022 != 0 || metadata.links < 2 {
        return Err(GenerationStoreError::Invalid);
    }
    Ok(())
}

fn validate_file(
    file: &File,
    owner_uid: u32,
    length: Option<u64>,
) -> Result<(), GenerationStoreError> {
    let metadata = file
        .metadata()
        .map_err(|_| GenerationStoreError::Unavailable)?;
    let actual_length = file.len().map_err(|_| GenerationStoreError::Unavailable)?;
    if metadata.links != 1
        || metadata.uid != owner_uid
        || metadata.mode & 0o777 != 0o600
        || length.is_some_and(|length| actual_length != length)
    {
        return Err(GenerationStoreError::Invalid);
    }
    Ok(())
}

unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn durable_catalog_advances_exactly_and_reopens() {
        let root =
            std::env::temp_dir().join(format!("mrml-authority-generation-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let owner = fs::metadata(&root).unwrap().uid();
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        {
            let mut store = LinuxAuthorityGenerationStore::open(
                root.to_str().unwrap(),
                owner,
                &repository,
                RepositoryGeneration(7),
            )
            .unwrap();
            store
                .commit_next(
                    &repository,
                    RepositoryGeneration(7),
                    RepositoryGeneration(8),
                )
                .unwrap();
            assert_eq!(
                store.commit_next(
                    &repository,
                    RepositoryGeneration(7),
                    RepositoryGeneration(8)
                ),
                Err(GenerationStoreError::Stale)
            );
        }
        let store = LinuxAuthorityGenerationStore::open(
            root.to_str().unwrap(),
            owner,
            &repository,
            RepositoryGeneration(7),
        )
        .unwrap();
        assert_eq!(store.current(&repository), Ok(RepositoryGeneration(8)));
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retained_generation_root_survives_ambient_replacement() {
        let root = std::env::temp_dir().join(format!(
            "mrml-authority-generation-retained-{}",
            std::process::id()
        ));
        let displaced = root.with_extension("displaced");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&displaced);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let owner = fs::metadata(&root).unwrap().uid();
        let repository = RepositoryIdentity::parse("owner/retained").unwrap();
        let capability = DirectoryCapability::open_root(root.to_str().unwrap()).unwrap();
        let mut store = LinuxAuthorityGenerationStore::open_capability(
            capability,
            owner,
            &repository,
            RepositoryGeneration(4),
        )
        .unwrap();
        fs::rename(&root, &displaced).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        store
            .commit_next(
                &repository,
                RepositoryGeneration(4),
                RepositoryGeneration(5),
            )
            .unwrap();
        assert_eq!(store.current(&repository), Ok(RepositoryGeneration(5)));
        let name = store.name(&repository);
        assert!(displaced.join(&name).is_file());
        assert!(!root.join(&name).exists());
        drop(store);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(displaced).unwrap();
    }
}
