use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use mrml_crypto::erase_secret_bytes;
use mrml_http::{
    AccessScopes, GitdAuthentication, MAX_TOKEN_STORE_BYTES, OneTimeAccessToken,
    RepositoryAccessPolicy, RepositoryIdentity, RepositoryProfile, TokenAuthority, TokenRecord,
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

pub fn initialize_empty_token_store(
    path: &Path,
    pepper_path: &Path,
    gitd_uid: u32,
) -> Result<(), AuthenticationStoreError> {
    if !path.is_absolute() || path.exists() || path.file_name().is_none() {
        return Err(AuthenticationStoreError::Open);
    }
    let parent = path.parent().ok_or(AuthenticationStoreError::Open)?;
    let parent_metadata =
        std::fs::symlink_metadata(parent).map_err(|_| AuthenticationStoreError::Metadata)?;
    if !parent_metadata.is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != gitd_uid
        || parent_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(AuthenticationStoreError::Permissions);
    }
    let mut pepper = read_pepper(pepper_path, gitd_uid)?;
    let authority = TokenAuthority::new(pepper).map_err(|_| AuthenticationStoreError::Decode);
    erase_secret_bytes(&mut pepper);
    let bytes = authority?
        .encode_records(&[])
        .map_err(|_| AuthenticationStoreError::Decode)?;
    let temporary = parent.join(format!(".tokens.v1.initialize.{}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&temporary)
            .map_err(|_| AuthenticationStoreError::Open)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| AuthenticationStoreError::Read)?;
        std::fs::hard_link(&temporary, path).map_err(|_| AuthenticationStoreError::Open)?;
        std::fs::remove_file(&temporary).map_err(|_| AuthenticationStoreError::Open)?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| AuthenticationStoreError::Read)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

pub fn issue_access_token(
    path: &Path,
    pepper_path: &Path,
    gitd_uid: u32,
    repository: RepositoryIdentity,
    scopes: AccessScopes,
    valid_from: u64,
    expires_at: u64,
    revocation_generation: u64,
    label: &str,
) -> Result<OneTimeAccessToken, AuthenticationStoreError> {
    let (authority, mut records) = load_token_authority(path, pepper_path, gitd_uid)?;
    let (token, record) = authority
        .issue(
            repository,
            scopes,
            valid_from,
            expires_at,
            revocation_generation,
            label,
        )
        .map_err(|_| AuthenticationStoreError::Decode)?;
    records.push(record);
    replace_token_store(path, gitd_uid, &authority, &records)?;
    Ok(token)
}

pub fn revoke_access_token(
    path: &Path,
    pepper_path: &Path,
    gitd_uid: u32,
    encoded_token: &str,
) -> Result<bool, AuthenticationStoreError> {
    let (authority, mut records) = load_token_authority(path, pepper_path, gitd_uid)?;
    let removed = authority
        .revoke_encoded_token(&mut records, encoded_token)
        .map_err(|_| AuthenticationStoreError::Decode)?;
    if removed {
        replace_token_store(path, gitd_uid, &authority, &records)?;
    }
    Ok(removed)
}

fn load_token_authority(
    path: &Path,
    pepper_path: &Path,
    gitd_uid: u32,
) -> Result<(TokenAuthority, Vector<TokenRecord>), AuthenticationStoreError> {
    let mut pepper = read_pepper(pepper_path, gitd_uid)?;
    let authority = TokenAuthority::new(pepper).map_err(|_| AuthenticationStoreError::Decode);
    erase_secret_bytes(&mut pepper);
    let authority = authority?;
    let records = authority
        .decode_records(&read_token_store(path, gitd_uid)?)
        .map_err(|_| AuthenticationStoreError::Decode)?;
    Ok((authority, records))
}

fn replace_token_store(
    path: &Path,
    gitd_uid: u32,
    authority: &TokenAuthority,
    records: &[TokenRecord],
) -> Result<(), AuthenticationStoreError> {
    let _existing = secure_file(path, gitd_uid, 44, MAX_TOKEN_STORE_BYTES as u64)?;
    let parent = path.parent().ok_or(AuthenticationStoreError::Open)?;
    let bytes = authority
        .encode_records(records)
        .map_err(|_| AuthenticationStoreError::Decode)?;
    let temporary = parent.join(format!(".tokens.v1.replace.{}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&temporary)
            .map_err(|_| AuthenticationStoreError::Open)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| AuthenticationStoreError::Read)?;
        std::fs::rename(&temporary, path).map_err(|_| AuthenticationStoreError::Open)?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| AuthenticationStoreError::Read)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
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

    #[test]
    fn empty_store_initialization_is_authenticated_and_never_overwrites() {
        let root =
            std::env::temp_dir().join(format!("mrml-gitd-auth-initialize-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&root).unwrap().uid();
        let pepper_path = root.join("pepper");
        fs::write(&pepper_path, [0x52; 32]).unwrap();
        fs::set_permissions(&pepper_path, fs::Permissions::from_mode(0o400)).unwrap();
        let store_path = root.join("tokens.v1");
        assert_eq!(
            initialize_empty_token_store(&store_path, &pepper_path, uid),
            Ok(())
        );
        let mut pepper = read_pepper(&pepper_path, uid).unwrap();
        let authority = TokenAuthority::new(pepper).unwrap();
        erase_secret_bytes(&mut pepper);
        assert!(
            authority
                .decode_records(&fs::read(&store_path).unwrap())
                .unwrap()
                .is_empty()
        );
        let mut token = issue_access_token(
            &store_path,
            &pepper_path,
            uid,
            RepositoryIdentity::parse("owner/repository").unwrap(),
            AccessScopes::READ.union(AccessScopes::WRITE),
            10,
            20,
            3,
            "operator-issued",
        )
        .unwrap();
        let encoded = token
            .expose_once(|value| mrml_runtime::Text::from(value))
            .unwrap();
        assert_eq!(
            revoke_access_token(&store_path, &pepper_path, uid, &encoded),
            Ok(true)
        );
        assert_eq!(
            revoke_access_token(&store_path, &pepper_path, uid, &encoded),
            Ok(false)
        );
        assert_eq!(
            initialize_empty_token_store(&store_path, &pepper_path, uid),
            Err(AuthenticationStoreError::Open)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
