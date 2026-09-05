use mrml_git::{
    AUTHORITY_GENERATION_RECORD_MAX_BYTES, RepositoryGeneration, RepositoryIdentity,
    authority_generation_record_name, encode_authority_generation_record,
    parse_authority_generation_record,
};
use mrml_runtime::{DirectoryCapability, File, Shared, Vector};
#[cfg(test)]
use std::fs;

const LOCK_EXCLUSIVE_NONBLOCKING: i32 = 2 | 4;

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
    repository: RepositoryIdentity,
    _lock: Shared<File>,
}

/// One process owns the durable catalog lock. Repository handles retain it,
/// without a shared operation mutex across verification or network I/O.
pub struct LinuxAuthorityGenerationCatalog {
    root: DirectoryCapability,
    owner_uid: u32,
    lock: Shared<File>,
    repositories: Vector<RepositoryIdentity>,
}

impl LinuxAuthorityGenerationCatalog {
    pub fn open_capability(
        root: DirectoryCapability,
        owner_uid: u32,
    ) -> Result<Self, GenerationStoreError> {
        if owner_uid == 0 {
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
        Ok(Self {
            root,
            owner_uid,
            lock: Shared::new(lock),
            repositories: Vector::new(),
        })
    }

    pub fn open_repository(
        &mut self,
        repository: &RepositoryIdentity,
        bootstrap_generation: RepositoryGeneration,
    ) -> Result<LinuxAuthorityGenerationStore, GenerationStoreError> {
        if bootstrap_generation.0 == 0 || self.repositories.len() >= 100_000 {
            return Err(GenerationStoreError::Invalid);
        }
        let index = match self.repositories.binary_search(repository) {
            Ok(_) => return Err(GenerationStoreError::Unavailable),
            Err(index) => index,
        };
        self.repositories
            .try_reserve(1)
            .map_err(|_| GenerationStoreError::Unavailable)?;
        let store = LinuxAuthorityGenerationStore {
            root: self
                .root
                .try_clone()
                .map_err(|_| GenerationStoreError::Unavailable)?,
            owner_uid: self.owner_uid,
            repository: repository.clone(),
            _lock: self.lock.clone(),
        };
        let path = store.name(repository);
        let temporary = store.temporary_name(repository);
        if let Ok(file) = store.root.open_regular(&temporary) {
            validate_file(&file, self.owner_uid, None)?;
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
        // Never issue two independently mutable handles for one repository,
        // even if the first handle is subsequently dropped.
        self.repositories
            .try_insert(index, repository.clone())
            .map_err(|_| GenerationStoreError::Unavailable)?;
        Ok(store)
    }
}

impl LinuxAuthorityGenerationStore {
    pub fn open(
        root: &str,
        owner_uid: u32,
        repository: &RepositoryIdentity,
        bootstrap_generation: RepositoryGeneration,
    ) -> Result<Self, GenerationStoreError> {
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
        LinuxAuthorityGenerationCatalog::open_capability(root, owner_uid)?
            .open_repository(repository, bootstrap_generation)
    }

    fn name(&self, repository: &RepositoryIdentity) -> String {
        authority_generation_record_name(repository).to_string()
    }

    fn temporary_name(&self, repository: &RepositoryIdentity) -> String {
        format!("{}.next", self.name(repository))
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
        if repository != &self.repository {
            return Err(GenerationStoreError::Invalid);
        }
        let name = self.name(repository);
        let mut file = self
            .root
            .open_regular(&name)
            .map_err(|_| GenerationStoreError::Unavailable)?;
        let length = file.len().map_err(|_| GenerationStoreError::Unavailable)?;
        validate_file(&file, self.owner_uid, Some(length))?;
        if length > AUTHORITY_GENERATION_RECORD_MAX_BYTES as u64 {
            return Err(GenerationStoreError::Invalid);
        }
        let mut bytes = vec![0; length as usize];
        file.read_exact(&mut bytes)
            .map_err(|_| GenerationStoreError::Unavailable)?;
        parse_authority_generation_record(&bytes, repository)
            .map_err(|_| GenerationStoreError::Invalid)
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
) -> Result<Vector<u8>, GenerationStoreError> {
    encode_authority_generation_record(repository, generation)
        .map_err(|_| GenerationStoreError::Invalid)
}

fn validate_directory(
    directory: &DirectoryCapability,
    owner_uid: u32,
) -> Result<(), GenerationStoreError> {
    let metadata = directory
        .metadata()
        .map_err(|_| GenerationStoreError::Unavailable)?;
    if metadata.uid != owner_uid || metadata.mode & 0o022 != 0 {
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

    fn catalog_fixture(name: &str) -> (std::path::PathBuf, u32) {
        let root = std::env::temp_dir().join(format!(
            "mrml-authority-catalog-{name}-{}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let owner = fs::metadata(&root).unwrap().uid();
        (root, owner)
    }

    fn open_catalog(root: &std::path::Path, owner: u32) -> LinuxAuthorityGenerationCatalog {
        LinuxAuthorityGenerationCatalog::open_capability(
            DirectoryCapability::open_root(root.to_str().unwrap()).unwrap(),
            owner,
        )
        .unwrap()
    }

    #[test]
    fn shared_catalog_keeps_repository_cas_and_reopen_independent() {
        let (root, owner) = catalog_fixture("independent");
        let first = RepositoryIdentity::parse("owner/first").unwrap();
        let second = RepositoryIdentity::parse("owner/second").unwrap();
        let mut catalog = open_catalog(&root, owner);
        let mut a = catalog
            .open_repository(&first, RepositoryGeneration(3))
            .unwrap();
        let mut b = catalog
            .open_repository(&second, RepositoryGeneration(9))
            .unwrap();
        assert!(matches!(
            catalog.open_repository(&first, RepositoryGeneration(3)),
            Err(GenerationStoreError::Unavailable)
        ));
        a.commit_next(&first, RepositoryGeneration(3), RepositoryGeneration(4))
            .unwrap();
        assert_eq!(b.current(&second), Ok(RepositoryGeneration(9)));
        assert_eq!(
            b.commit_next(&second, RepositoryGeneration(3), RepositoryGeneration(4)),
            Err(GenerationStoreError::Stale)
        );
        b.commit_next(&second, RepositoryGeneration(9), RepositoryGeneration(10))
            .unwrap();
        assert_eq!(a.current(&first), Ok(RepositoryGeneration(4)));
        assert_eq!(a.current(&second), Err(GenerationStoreError::Invalid));
        assert_eq!(
            a.commit_next(&second, RepositoryGeneration(10), RepositoryGeneration(11)),
            Err(GenerationStoreError::Invalid)
        );
        assert_eq!(b.current(&second), Ok(RepositoryGeneration(10)));
        drop(a);
        assert!(matches!(
            catalog.open_repository(&first, RepositoryGeneration(4)),
            Err(GenerationStoreError::Unavailable)
        ));
        drop(b);
        drop(catalog);
        let mut reopened = open_catalog(&root, owner);
        assert!(matches!(
            reopened.open_repository(&first, RepositoryGeneration(5)),
            Err(GenerationStoreError::Stale)
        ));
        let a = reopened
            .open_repository(&first, RepositoryGeneration(3))
            .unwrap();
        let b = reopened
            .open_repository(&second, RepositoryGeneration(9))
            .unwrap();
        assert_eq!(a.current(&first), Ok(RepositoryGeneration(4)));
        assert_eq!(b.current(&second), Ok(RepositoryGeneration(10)));
        drop((a, b, reopened));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn catalog_cleanup_removes_only_selected_repository_temporary() {
        let (root, owner) = catalog_fixture("cleanup");
        let first = RepositoryIdentity::parse("owner/first").unwrap();
        let second = RepositoryIdentity::parse("owner/second").unwrap();
        let first_next = format!("{}.next", authority_generation_record_name(&first));
        let second_next = format!("{}.next", authority_generation_record_name(&second));
        for (name, repository) in [(&first_next, &first), (&second_next, &second)] {
            fs::write(
                root.join(name),
                encode(repository, RepositoryGeneration(8)).unwrap(),
            )
            .unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let retained_second = fs::read(root.join(&second_next)).unwrap();
        let mut catalog = open_catalog(&root, owner);
        let a = catalog
            .open_repository(&first, RepositoryGeneration(7))
            .unwrap();
        assert!(!root.join(&first_next).exists());
        assert_eq!(fs::read(root.join(&second_next)).unwrap(), retained_second);
        assert_eq!(a.current(&first), Ok(RepositoryGeneration(7)));
        let b = catalog
            .open_repository(&second, RepositoryGeneration(7))
            .unwrap();
        assert!(!root.join(&second_next).exists());
        assert_eq!(b.current(&second), Ok(RepositoryGeneration(7)));
        drop((a, b, catalog));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "child process fixture invoked by catalog_lock_survives_builder_and_each_store"]
    fn catalog_writer_process_fixture() {
        let root = std::env::var("MRML_GENERATION_LOCK_PROBE_ROOT").unwrap();
        let expected = std::env::var("MRML_GENERATION_LOCK_PROBE_EXPECTED").unwrap();
        let owner = fs::metadata(&root).unwrap().uid();
        let result = LinuxAuthorityGenerationCatalog::open_capability(
            DirectoryCapability::open_root(&root).unwrap(),
            owner,
        );
        if expected == "locked" {
            assert!(matches!(result, Err(GenerationStoreError::Unavailable)));
        } else {
            assert_eq!(expected, "available");
            let mut catalog = result.unwrap();
            let repository = RepositoryIdentity::parse("owner/first").unwrap();
            let mut store = catalog
                .open_repository(&repository, RepositoryGeneration(3))
                .unwrap();
            store
                .commit_next(
                    &repository,
                    RepositoryGeneration(3),
                    RepositoryGeneration(4),
                )
                .unwrap();
        }
    }

    #[test]
    fn catalog_lock_survives_builder_and_each_store() {
        let (root, owner) = catalog_fixture("process-lock");
        let first = RepositoryIdentity::parse("owner/first").unwrap();
        let second = RepositoryIdentity::parse("owner/second").unwrap();
        let mut catalog = open_catalog(&root, owner);
        let a = catalog
            .open_repository(&first, RepositoryGeneration(3))
            .unwrap();
        let b = catalog
            .open_repository(&second, RepositoryGeneration(9))
            .unwrap();
        let probe = |expected: &str| {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "generation::tests::catalog_writer_process_fixture",
                    "--ignored",
                    "--nocapture",
                ])
                .env("MRML_GENERATION_LOCK_PROBE_ROOT", &root)
                .env("MRML_GENERATION_LOCK_PROBE_EXPECTED", expected)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        };
        probe("locked");
        drop(catalog);
        probe("locked");
        drop(a);
        probe("locked");
        drop(b);
        probe("available");
        let mut reopened = open_catalog(&root, owner);
        let a = reopened
            .open_repository(&first, RepositoryGeneration(3))
            .unwrap();
        let b = reopened
            .open_repository(&second, RepositoryGeneration(9))
            .unwrap();
        assert_eq!(a.current(&first), Ok(RepositoryGeneration(4)));
        assert_eq!(b.current(&second), Ok(RepositoryGeneration(9)));
        drop((a, b, reopened));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generation_store_cannot_access_another_repository() {
        let root = std::env::temp_dir().join(format!(
            "mrml-authority-generation-binding-{}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let owner = fs::metadata(&root).unwrap().uid();
        let first = RepositoryIdentity::parse("owner/first").unwrap();
        let second = RepositoryIdentity::parse("owner/second").unwrap();
        drop(
            LinuxAuthorityGenerationStore::open(
                root.to_str().unwrap(),
                owner,
                &second,
                RepositoryGeneration(9),
            )
            .unwrap(),
        );
        let mut store = LinuxAuthorityGenerationStore::open(
            root.to_str().unwrap(),
            owner,
            &first,
            RepositoryGeneration(3),
        )
        .unwrap();
        assert_eq!(store.current(&second), Err(GenerationStoreError::Invalid));
        assert!(
            store
                .commit_next(&second, RepositoryGeneration(9), RepositoryGeneration(10))
                .is_err()
        );
        assert_eq!(store.current(&first), Ok(RepositoryGeneration(3)));
        drop(store);
        let second_store = LinuxAuthorityGenerationStore::open(
            root.to_str().unwrap(),
            owner,
            &second,
            RepositoryGeneration(9),
        )
        .unwrap();
        assert_eq!(second_store.current(&second), Ok(RepositoryGeneration(9)));
        drop(second_store);
        fs::remove_dir_all(root).unwrap();
    }

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
