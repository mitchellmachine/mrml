use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use mrml_crypto::erase_secret_bytes;
use mrml_git::{BackupInventory, BackupStreamHeader, BackupVolume};
use mrml_gitd::{
    collect_backup_inventory, load_gitd_config, restore_backup_archive, verify_backup_archive,
    write_backup_archive,
};
use mrml_runtime::{DirectoryCapability, File, fill_random};

const CONFIG: &str = "/source/gitd-config/gitd.conf";
const BACKUP_ROOT: &str = "/backup";
const KEY_ROOT: &str = "/backup-key";
const KEY_NAME: &str = "git-backup.key";
const AUTHORITY_GENERATIONS: &str = "/source/authority-state/generations";
const RESTORE_CACHE: &str = "/restore/gitd-cache";
const CHUNK_BYTES: u32 = 1024 * 1024;
const SOURCE_ROOTS: [&str; 10] = [
    "/source/gitd-repos",
    "/source/gitd-state",
    "/source/gitd-quarantine",
    "/source/gitd-receipts",
    "/source/gitd-policies",
    "/source/gitd-secrets",
    "/source/gitd-config",
    "/source/authority-state",
    "/source/authority-secrets",
    "/source/authority-config",
];
const RESTORE_ROOTS: [&str; 10] = [
    "/restore/gitd-repos",
    "/restore/gitd-state",
    "/restore/gitd-quarantine",
    "/restore/gitd-receipts",
    "/restore/gitd-policies",
    "/restore/gitd-secrets",
    "/restore/gitd-config",
    "/restore/authority-state",
    "/restore/authority-secrets",
    "/restore/authority-config",
];

fn main() {
    if run().is_err() {
        eprintln!("mrml-git-backup: operation rejected");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ()> {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.as_slice() == [arguments[0].as_str(), "ensure-key"] {
        return ensure_backup_key();
    }
    let [_, command, generation] = arguments.as_slice() else {
        usage();
        return Err(());
    };
    let generation = parse_generation(generation)?;
    let mut key = read_backup_key()?;
    let result = match command.as_str() {
        "create" => create(generation, &key),
        "verify" => verify(generation, &key),
        "restore" => restore(generation, &key),
        _ => {
            usage();
            Err(())
        }
    };
    erase_secret_bytes(&mut key);
    result
}

fn ensure_backup_key() -> Result<(), ()> {
    let root = DirectoryCapability::open_root(KEY_ROOT).map_err(|_| ())?;
    validate_private_key_root(&root)?;
    if root.open_regular(KEY_NAME).is_ok() {
        let mut key = read_backup_key()?;
        erase_secret_bytes(&mut key);
        return Ok(());
    }
    let mut key = [0u8; 32];
    for _ in 0..8 {
        fill_random(&mut key).map_err(|_| ())?;
        if key != [0; 32] {
            break;
        }
    }
    if key == [0; 32] {
        return Err(());
    }
    let mut file = root.create_new_file(KEY_NAME, 0o400).map_err(|_| ())?;
    let result = file.write_all(&key).and_then(|()| file.sync());
    erase_secret_bytes(&mut key);
    result.map_err(|_| ())?;
    drop(file);
    root.sync().map_err(|_| ())?;
    let mut reread = read_backup_key()?;
    erase_secret_bytes(&mut reread);
    Ok(())
}

fn create(generation: u64, key: &[u8; 32]) -> Result<(), ()> {
    let config = source_config()?;
    let inventory =
        collect_backup_inventory(&config, generation, SOURCE_ROOTS, AUTHORITY_GENERATIONS)
            .map_err(|error| reject("inventory", error))?;
    let header = random_header(generation)?;
    let root = DirectoryCapability::open_root(BACKUP_ROOT).map_err(|_| ())?;
    validate_root(&root)?;
    let final_name = archive_name(generation);
    let temporary_name = format!("{final_name}.new");
    if root.open_regular(&final_name).is_ok() || root.open_regular(&temporary_name).is_ok() {
        return Err(());
    }
    let mut file = root
        .create_new_file(&temporary_name, 0o600)
        .map_err(|_| ())?;
    let result = (|| {
        let mut writer = RuntimeFile(&mut file);
        write_backup_archive(&mut writer, key, header, &inventory, SOURCE_ROOTS)
            .map_err(|error| reject("archive", error))?;
        drop(writer);
        file.sync().map_err(|_| ())?;
        validate_archive_file(&file)?;
        drop(file);
        root.rename_child(&temporary_name, &final_name)
            .map_err(|_| ())?;
        root.sync().map_err(|_| ())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = root.remove_file(&temporary_name);
        let _ = root.sync();
    }
    result?;
    verify(generation, key)
}

fn verify(generation: u64, key: &[u8; 32]) -> Result<(), ()> {
    let root = DirectoryCapability::open_root(BACKUP_ROOT).map_err(|_| ())?;
    validate_root(&root)?;
    let mut file = root
        .open_regular(&archive_name(generation))
        .map_err(|_| ())?;
    validate_archive_file(&file)?;
    let mut reader = RuntimeFile(&mut file);
    let inventory =
        verify_backup_archive(&mut reader, key).map_err(|error| reject("verification", error))?;
    (inventory.backup_generation == generation)
        .then_some(())
        .ok_or(())
}

fn restore(generation: u64, key: &[u8; 32]) -> Result<(), ()> {
    let root = DirectoryCapability::open_root(BACKUP_ROOT).map_err(|_| ())?;
    validate_root(&root)?;
    let mut file = root
        .open_regular(&archive_name(generation))
        .map_err(|_| ())?;
    validate_archive_file(&file)?;
    let mut archive = RuntimeFile(&mut file);
    let inventory = restore_backup_archive(&mut archive, key, RESTORE_ROOTS)
        .map_err(|error| reject("restore", error))?;
    if inventory.backup_generation != generation {
        return Err(());
    }
    initialize_restore_cache(&inventory)
}

fn initialize_restore_cache(inventory: &BackupInventory) -> Result<(), ()> {
    let root = DirectoryCapability::open_root(RESTORE_CACHE).map_err(|_| ())?;
    let metadata = root.metadata().map_err(|_| ())?;
    if metadata.mode & 0o170000 != 0o040000
        || root
            .read_directory()
            .map_err(|_| ())?
            .iter()
            .next()
            .is_some()
    {
        return Err(());
    }
    let repository_root = inventory
        .entries
        .iter()
        .find(|entry| entry.volume == BackupVolume::GitdRepositories && entry.path.as_str() == ".")
        .ok_or(())?;
    root.set_owner_mode(repository_root.uid, repository_root.gid, 0o700)
        .map_err(|_| ())?;
    let mut previous_owner = "";
    let mut owner_directory = None;
    for repository in &inventory.repositories {
        let (owner, name) = repository.repository.as_str().split_once('/').ok_or(())?;
        if owner != previous_owner {
            let directory = root.create_directory(owner, 0o700).map_err(|_| ())?;
            directory
                .set_owner_mode(repository_root.uid, repository_root.gid, 0o700)
                .map_err(|_| ())?;
            directory.sync().map_err(|_| ())?;
            previous_owner = owner;
            owner_directory = Some(directory);
        }
        let directory = owner_directory.as_ref().ok_or(())?;
        let repository_directory = directory.create_directory(name, 0o700).map_err(|_| ())?;
        repository_directory
            .set_owner_mode(repository_root.uid, repository_root.gid, 0o700)
            .and_then(|()| repository_directory.sync())
            .and_then(|()| directory.sync())
            .map_err(|_| ())?;
    }
    root.sync().map_err(|_| ())
}

fn source_config() -> Result<mrml_gitd::GitdConfig, ()> {
    let mut config = load_gitd_config(Path::new(CONFIG)).map_err(|_| ())?;
    config.repository_root = PathBuf::from(SOURCE_ROOTS[0]);
    config.state_root = PathBuf::from(SOURCE_ROOTS[1]);
    config.quarantine_root = PathBuf::from(SOURCE_ROOTS[2]);
    config.receipt_root = PathBuf::from(SOURCE_ROOTS[3]);
    config.policy_root = PathBuf::from(SOURCE_ROOTS[4]);
    config.repository_catalog = PathBuf::from(SOURCE_ROOTS[4]).join("repositories.v1");
    config.profile_catalog = PathBuf::from(SOURCE_ROOTS[4]).join("profiles.v1");
    Ok(config)
}

fn read_backup_key() -> Result<[u8; 32], ()> {
    let root = DirectoryCapability::open_root(KEY_ROOT).map_err(|_| ())?;
    validate_private_key_root(&root)?;
    let mut file = root.open_regular(KEY_NAME).map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if metadata.mode & 0o170000 != 0o100000
        || metadata.mode & 0o077 != 0
        || metadata.uid != 0
        || metadata.links != 1
        || file.len().map_err(|_| ())? != 32
    {
        return Err(());
    }
    let mut key = [0u8; 32];
    file.read_exact(&mut key).map_err(|_| ())?;
    if key == [0; 32] {
        erase_secret_bytes(&mut key);
        return Err(());
    }
    Ok(key)
}

fn validate_private_key_root(root: &DirectoryCapability) -> Result<(), ()> {
    let root_metadata = root.metadata().map_err(|_| ())?;
    if root_metadata.mode & 0o170000 != 0o040000
        || root_metadata.mode & 0o022 != 0
        || root_metadata.uid != 0
    {
        return Err(());
    }
    Ok(())
}

fn random_header(generation: u64) -> Result<BackupStreamHeader, ()> {
    for _ in 0..8 {
        let mut random = [0u8; 20];
        fill_random(&mut random).map_err(|_| ())?;
        let header = BackupStreamHeader {
            generation,
            chunk_bytes: CHUNK_BYTES,
            salt: random[..16].try_into().unwrap(),
            nonce_prefix: random[16..].try_into().unwrap(),
        };
        if header.salt != [0; 16] && header.nonce_prefix != [0; 4] {
            return Ok(header);
        }
    }
    Err(())
}

fn parse_generation(input: &str) -> Result<u64, ()> {
    if input.is_empty()
        || !input.bytes().all(|byte| byte.is_ascii_digit())
        || input.starts_with('0')
    {
        return Err(());
    }
    input.parse::<u64>().map_err(|_| ())
}

fn archive_name(generation: u64) -> String {
    format!("git-{generation}.mrb")
}

fn validate_root(root: &DirectoryCapability) -> Result<(), ()> {
    let metadata = root.metadata().map_err(|_| ())?;
    (metadata.mode & 0o170000 == 0o040000
        && metadata.mode & 0o777 == 0o700
        && metadata.uid == 0
        && metadata.gid == 0)
        .then_some(())
        .ok_or(())
}

fn validate_archive_file(file: &File) -> Result<(), ()> {
    let metadata = file.metadata().map_err(|_| ())?;
    (metadata.mode & 0o170000 == 0o100000
        && metadata.mode & 0o777 == 0o600
        && metadata.uid == 0
        && metadata.links == 1
        && file.len().map_err(|_| ())? > 0)
        .then_some(())
        .ok_or(())
}

fn usage() {
    eprintln!("usage: mrml-git-backup create|verify|restore GENERATION");
}

fn reject(stage: &str, error: impl core::fmt::Debug) {
    eprintln!("mrml-git-backup: {stage} rejected ({error:?})");
}

struct RuntimeFile<'a>(&'a mut File);

impl Read for RuntimeFile<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.0
            .read(buffer)
            .map_err(|_| std::io::Error::other("read rejected"))
    }
}

impl Write for RuntimeFile<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0
            .write_all(buffer)
            .map(|()| buffer.len())
            .map_err(|_| std::io::Error::other("write rejected"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0
            .sync()
            .map_err(|_| std::io::Error::other("sync rejected"))
    }
}

impl Seek for RuntimeFile<'_> {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let SeekFrom::Start(position) = position else {
            return Err(std::io::Error::other("unsupported seek"));
        };
        self.0
            .seek(position)
            .map(|()| position)
            .map_err(|_| std::io::Error::other("seek rejected"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_and_archive_names_are_canonical() {
        assert_eq!(parse_generation("1"), Ok(1));
        assert_eq!(parse_generation("18446744073709551615"), Ok(u64::MAX));
        for invalid in ["", "0", "01", "+1", " 1", "1\n", "18446744073709551616"] {
            assert!(parse_generation(invalid).is_err());
        }
        assert_eq!(archive_name(19), "git-19.mrb");
    }
}
