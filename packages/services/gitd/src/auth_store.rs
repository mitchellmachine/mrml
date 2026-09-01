use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use mrml_crypto::erase_secret_bytes;
use mrml_http::{
    GitdAuthentication, MAX_TOKEN_STORE_BYTES, RepositoryAccessPolicy, RepositoryIdentity,
    RepositoryProfile, TokenAuthority,
};
use mrml_runtime::Vector;

use crate::{DeploymentCatalog, DeploymentRepositoryProfile, GitdConfig};

const O_NOFOLLOW: i32 = 0x20_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationStoreError {
    Open,
    Metadata,
    Permissions,
    Size,
    Read,
    Decode,
    Catalog,
}

pub fn load_gitd_authentication(
    config: &GitdConfig,
    catalog: &DeploymentCatalog,
) -> Result<GitdAuthentication, AuthenticationStoreError> {
    let mut pepper = read_pepper(&config.token_pepper, config.gitd_uid)?;
    let authority = TokenAuthority::new(pepper).map_err(|_| AuthenticationStoreError::Decode);
    erase_secret_bytes(&mut pepper);
    let authority = authority?;
    let bytes = read_token_store(&config.token_records, config.gitd_uid)?;
    let records = authority
        .decode_records(&bytes)
        .map_err(|_| AuthenticationStoreError::Decode)?;
    let mut policies = Vector::new();
    policies
        .try_reserve_exact(catalog.repositories.len())
        .map_err(|_| AuthenticationStoreError::Size)?;
    for entry in &catalog.repositories {
        let repository = RepositoryIdentity::parse(entry.repository.as_str())
            .map_err(|_| AuthenticationStoreError::Catalog)?;
        let profile = match entry.profile.class {
            DeploymentRepositoryProfile::PublicRead => RepositoryProfile::PublicRead,
            DeploymentRepositoryProfile::Private => RepositoryProfile::Private,
            DeploymentRepositoryProfile::Protected => RepositoryProfile::Protected,
        };
        policies.push(RepositoryAccessPolicy {
            repository,
            profile,
            revocation_generation: entry.revocation_generation.0,
        });
    }
    GitdAuthentication::new(authority, policies, records)
        .map_err(|_| AuthenticationStoreError::Catalog)
}

fn read_pepper(path: &Path, gitd_uid: u32) -> Result<[u8; 32], AuthenticationStoreError> {
    let mut file = secure_file(path, gitd_uid, 32, 32)?;
    let mut pepper = [0u8; 32];
    file.read_exact(&mut pepper)
        .map_err(|_| AuthenticationStoreError::Read)?;
    if pepper == [0; 32] {
        erase_secret_bytes(&mut pepper);
        return Err(AuthenticationStoreError::Decode);
    }
    Ok(pepper)
}

fn read_token_store(path: &Path, gitd_uid: u32) -> Result<Vec<u8>, AuthenticationStoreError> {
    let mut file = secure_file(path, gitd_uid, 44, MAX_TOKEN_STORE_BYTES as u64)?;
    let length = usize::try_from(
        file.metadata()
            .map_err(|_| AuthenticationStoreError::Metadata)?
            .len(),
    )
    .map_err(|_| AuthenticationStoreError::Size)?;
    let mut bytes = vec![0u8; length];
    file.read_exact(&mut bytes)
        .map_err(|_| AuthenticationStoreError::Read)?;
    Ok(bytes)
}

fn secure_file(
    path: &Path,
    gitd_uid: u32,
    minimum: u64,
    maximum: u64,
) -> Result<std::fs::File, AuthenticationStoreError> {
    if !path.is_absolute() {
        return Err(AuthenticationStoreError::Open);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|_| AuthenticationStoreError::Open)?;
    let metadata = file
        .metadata()
        .map_err(|_| AuthenticationStoreError::Metadata)?;
    let mode = metadata.mode() & 0o777;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || (metadata.uid() != 0 && metadata.uid() != gitd_uid)
        || mode & 0o077 != 0
        || mode & 0o400 == 0
        || !(minimum..=maximum).contains(&metadata.len())
    {
        return Err(AuthenticationStoreError::Permissions);
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    #[test]
    fn hosted_store_requires_exact_private_files_and_authenticated_bytes() {
        let root =
            std::env::temp_dir().join(format!("mrml-gitd-auth-store-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let pepper_path = root.join("pepper");
        fs::write(&pepper_path, [0x41; 32]).unwrap();
        fs::set_permissions(&pepper_path, fs::Permissions::from_mode(0o400)).unwrap();
        let uid = fs::metadata(&pepper_path).unwrap().uid();
        let mut pepper = read_pepper(&pepper_path, uid).unwrap();
        let authority = TokenAuthority::new(pepper).unwrap();
        erase_secret_bytes(&mut pepper);
        let store_path = root.join("tokens.v1");
        let encoded = authority.encode_records(&[]).unwrap();
        fs::write(&store_path, &encoded).unwrap();
        fs::set_permissions(&store_path, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            &read_token_store(&store_path, uid).unwrap()[..],
            &encoded[..]
        );

        fs::set_permissions(&store_path, fs::Permissions::from_mode(0o440)).unwrap();
        assert_eq!(
            read_token_store(&store_path, uid),
            Err(AuthenticationStoreError::Permissions)
        );
        fs::set_permissions(&store_path, fs::Permissions::from_mode(0o400)).unwrap();
        let link = root.join("tokens-link");
        symlink(&store_path, &link).unwrap();
        assert_eq!(
            read_token_store(&link, uid),
            Err(AuthenticationStoreError::Open)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
