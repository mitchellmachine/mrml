use std::path::Path;

use mrml_crypto::Sha256;
use mrml_git::{
    FilesystemRepositoryView, RepositoryGeneration, RepositoryIdentity, RevocationGeneration,
    TrustGeneration,
};
use mrml_runtime::DirectoryCapability;

use crate::GitdConfig;

const MAX_CATALOG_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROFILES: usize = 4_096;
const MAX_REPOSITORIES: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentRepositoryProfile {
    PublicRead,
    Private,
    Protected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentProfile {
    pub name: String,
    pub class: DeploymentRepositoryProfile,
    pub max_object_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentRepository {
    pub repository: RepositoryIdentity,
    pub profile: DeploymentProfile,
    pub repository_generation: RepositoryGeneration,
    pub trust_generation: TrustGeneration,
    pub revocation_generation: RevocationGeneration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentCatalog {
    pub repositories: Vec<DeploymentRepository>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentCatalogError {
    Open,
    Metadata,
    Permissions,
    Size,
    Read,
    Digest,
    Encoding,
    Syntax,
    Order,
    Duplicate,
    UnknownProfile,
    InvalidValue,
}

pub fn verify_repository_admission(
    entry: &DeploymentRepository,
    view: &FilesystemRepositoryView,
) -> Result<(), DeploymentCatalogError> {
    let generations = view
        .authority_generations()
        .map_err(|_| DeploymentCatalogError::InvalidValue)?;
    if generations
        != (
            entry.repository_generation,
            entry.trust_generation,
            entry.revocation_generation,
        )
    {
        return Err(DeploymentCatalogError::InvalidValue);
    }
    Ok(())
}

pub fn load_deployment_catalog(
    config: &GitdConfig,
) -> Result<DeploymentCatalog, DeploymentCatalogError> {
    let profiles = read_authenticated(
        &config.profile_catalog,
        config.gitd_uid,
        config.profile_catalog_sha256,
    )?;
    let repositories = read_authenticated(
        &config.repository_catalog,
        config.gitd_uid,
        config.repository_catalog_sha256,
    )?;
    parse_deployment_catalog(&profiles, &repositories)
}

pub fn parse_deployment_catalog(
    profile_bytes: &[u8],
    repository_bytes: &[u8],
) -> Result<DeploymentCatalog, DeploymentCatalogError> {
    let profiles = parse_profiles(profile_bytes)?;
    let repositories = parse_repositories(repository_bytes, &profiles)?;
    Ok(DeploymentCatalog { repositories })
}

fn read_authenticated(
    path: &Path,
    gitd_uid: u32,
    expected_digest: [u8; 32],
) -> Result<Vec<u8>, DeploymentCatalogError> {
    if !path.is_absolute() {
        return Err(DeploymentCatalogError::Open);
    }
    let parent = path.parent().ok_or(DeploymentCatalogError::Open)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(DeploymentCatalogError::Open)?;
    let directory = DirectoryCapability::open_root(
        parent.to_str().ok_or(DeploymentCatalogError::Open)?,
    )
    .map_err(|_| DeploymentCatalogError::Open)?;
    read_authenticated_capability(&directory, name, gitd_uid, expected_digest)
}

fn read_authenticated_capability(
    directory: &DirectoryCapability,
    name: &str,
    gitd_uid: u32,
    expected_digest: [u8; 32],
) -> Result<Vec<u8>, DeploymentCatalogError> {
    let mut file = directory
        .open_regular(name)
        .map_err(|_| DeploymentCatalogError::Open)?;
    let metadata = file
        .metadata()
        .map_err(|_| DeploymentCatalogError::Metadata)?;
    let length = file
        .len()
        .map_err(|_| DeploymentCatalogError::Metadata)?;
    if metadata.links != 1
        || (metadata.uid != 0 && metadata.uid != gitd_uid)
        || metadata.mode & 0o022 != 0
        || metadata.mode & 0o444 == 0
        || length == 0
        || length > MAX_CATALOG_BYTES as u64
    {
        return Err(DeploymentCatalogError::Permissions);
    }
    let length = usize::try_from(length).map_err(|_| DeploymentCatalogError::Size)?;
    let mut bytes = vec![0u8; length];
    file.read_exact(&mut bytes)
        .map_err(|_| DeploymentCatalogError::Read)?;
    if Sha256::digest(&bytes) != expected_digest {
        return Err(DeploymentCatalogError::Digest);
    }
    Ok(bytes)
}

fn parse_profiles(input: &[u8]) -> Result<Vec<DeploymentProfile>, DeploymentCatalogError> {
    let text = canonical_text(input)?;
    let mut lines = text.lines();
    if lines.next() != Some("version=1") {
        return Err(DeploymentCatalogError::Syntax);
    }
    let mut profiles: Vec<DeploymentProfile> = Vec::new();
    for line in lines {
        let value = line
            .strip_prefix("profile=")
            .ok_or(DeploymentCatalogError::Syntax)?;
        let mut fields = value.split('|');
        let name = profile_name(fields.next().ok_or(DeploymentCatalogError::Syntax)?)?;
        let class = match fields.next().ok_or(DeploymentCatalogError::Syntax)? {
            "public-read" => DeploymentRepositoryProfile::PublicRead,
            "private" => DeploymentRepositoryProfile::Private,
            "protected" => DeploymentRepositoryProfile::Protected,
            _ => return Err(DeploymentCatalogError::InvalidValue),
        };
        let max_object_bytes = canonical_number(
            fields.next().ok_or(DeploymentCatalogError::Syntax)?,
            1_024,
            512 * 1024 * 1024,
        )?;
        if fields.next().is_some() {
            return Err(DeploymentCatalogError::Syntax);
        }
        if profiles.len() >= MAX_PROFILES {
            return Err(DeploymentCatalogError::Size);
        }
        if let Some(previous) = profiles.last() {
            if previous.name >= name {
                return Err(if previous.name == name {
                    DeploymentCatalogError::Duplicate
                } else {
                    DeploymentCatalogError::Order
                });
            }
        }
        profiles.push(DeploymentProfile {
            name,
            class,
            max_object_bytes,
        });
    }
    if profiles.is_empty() {
        return Err(DeploymentCatalogError::InvalidValue);
    }
    Ok(profiles)
}

fn parse_repositories(
    input: &[u8],
    profiles: &[DeploymentProfile],
) -> Result<Vec<DeploymentRepository>, DeploymentCatalogError> {
    let text = canonical_text(input)?;
    let mut lines = text.lines();
    if lines.next() != Some("version=1") {
        return Err(DeploymentCatalogError::Syntax);
    }
    let mut repositories: Vec<DeploymentRepository> = Vec::new();
    for line in lines {
        let value = line
            .strip_prefix("repository=")
            .ok_or(DeploymentCatalogError::Syntax)?;
        let mut fields = value.split('|');
        let identity_text = fields.next().ok_or(DeploymentCatalogError::Syntax)?;
        let repository = RepositoryIdentity::parse(identity_text)
            .map_err(|_| DeploymentCatalogError::InvalidValue)?;
        let profile_name = fields.next().ok_or(DeploymentCatalogError::Syntax)?;
        let profile = profiles
            .iter()
            .find(|profile| profile.name == profile_name)
            .cloned()
            .ok_or(DeploymentCatalogError::UnknownProfile)?;
        let repository_generation = RepositoryGeneration(canonical_number(
            fields.next().ok_or(DeploymentCatalogError::Syntax)?,
            1,
            u64::MAX,
        )?);
        let trust_generation = TrustGeneration(canonical_number(
            fields.next().ok_or(DeploymentCatalogError::Syntax)?,
            1,
            u64::MAX,
        )?);
        let revocation_generation = RevocationGeneration(canonical_number(
            fields.next().ok_or(DeploymentCatalogError::Syntax)?,
            1,
            u64::MAX,
        )?);
        if fields.next().is_some() {
            return Err(DeploymentCatalogError::Syntax);
        }
        if repositories.len() >= MAX_REPOSITORIES {
            return Err(DeploymentCatalogError::Size);
        }
        if let Some(previous) = repositories.last() {
            if previous.repository.as_str() >= repository.as_str() {
                return Err(if previous.repository == repository {
                    DeploymentCatalogError::Duplicate
                } else {
                    DeploymentCatalogError::Order
                });
            }
        }
        repositories.push(DeploymentRepository {
            repository,
            profile,
            repository_generation,
            trust_generation,
            revocation_generation,
        });
    }
    if repositories.is_empty() {
        return Err(DeploymentCatalogError::InvalidValue);
    }
    Ok(repositories)
}

fn canonical_text(input: &[u8]) -> Result<&str, DeploymentCatalogError> {
    if input.is_empty()
        || input.len() > MAX_CATALOG_BYTES
        || !input.ends_with(b"\n")
        || input.contains(&0)
        || input.contains(&b'\r')
    {
        return Err(DeploymentCatalogError::Size);
    }
    let text = core::str::from_utf8(input).map_err(|_| DeploymentCatalogError::Encoding)?;
    if text
        .lines()
        .any(|line| line.is_empty() || line.trim() != line)
    {
        return Err(DeploymentCatalogError::Syntax);
    }
    Ok(text)
}

fn profile_name(input: &str) -> Result<String, DeploymentCatalogError> {
    if input.is_empty()
        || input.len() > 64
        || !input.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(DeploymentCatalogError::InvalidValue);
    }
    Ok(input.to_owned())
}

fn canonical_number(
    input: &str,
    minimum: u64,
    maximum: u64,
) -> Result<u64, DeploymentCatalogError> {
    if input.is_empty()
        || !input.bytes().all(|byte| byte.is_ascii_digit())
        || (input.starts_with('0') && input.len() > 1)
    {
        return Err(DeploymentCatalogError::InvalidValue);
    }
    let value = input
        .parse::<u64>()
        .map_err(|_| DeploymentCatalogError::InvalidValue)?;
    if !(minimum..=maximum).contains(&value) {
        return Err(DeploymentCatalogError::InvalidValue);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_git::{
        ActiveRefFile, ActiveRefState, FullRefName, ObjectFormat, ObjectKind, PackGeneration,
        Repository,
    };
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    const PROFILES: &[u8] = b"version=1\nprofile=private|private|1048576\nprofile=protected|protected|268435456\nprofile=public|public-read|8388608\n";
    const REPOSITORIES: &[u8] = b"version=1\nrepository=owner/private|private|3|5|7\nrepository=owner/project|protected|4|6|8\nrepository=owner/public|public|2|4|6\n";

    #[test]
    fn canonical_catalog_resolves_exact_profiles_and_generations() {
        let catalog = parse_deployment_catalog(PROFILES, REPOSITORIES).unwrap();
        assert_eq!(catalog.repositories.len(), 3);
        assert_eq!(
            catalog.repositories[1].profile.class,
            DeploymentRepositoryProfile::Protected
        );
        assert_eq!(
            catalog.repositories[1].repository_generation,
            RepositoryGeneration(4)
        );
        assert_eq!(catalog.repositories[1].profile.max_object_bytes, 268435456);
    }

    #[test]
    fn unknown_profiles_order_aliases_and_malformed_identities_fail_closed() {
        assert_eq!(
            parse_deployment_catalog(
                PROFILES,
                b"version=1\nrepository=owner/project|missing|1|1|1\n"
            ),
            Err(DeploymentCatalogError::UnknownProfile)
        );
        assert_eq!(
            parse_deployment_catalog(
                b"version=1\nprofile=z|private|1024\nprofile=a|private|1024\n",
                b"version=1\nrepository=owner/project|a|1|1|1\n"
            ),
            Err(DeploymentCatalogError::Order)
        );
        assert_eq!(
            parse_deployment_catalog(
                PROFILES,
                b"version=1\nrepository=owner/project|protected|01|1|1\n"
            ),
            Err(DeploymentCatalogError::InvalidValue)
        );
        assert_eq!(
            parse_deployment_catalog(
                PROFILES,
                b"version=1\nrepository=owner//project|protected|1|1|1\n"
            ),
            Err(DeploymentCatalogError::InvalidValue)
        );
    }

    #[test]
    fn hosted_catalog_bytes_require_exact_digest_owner_mode_and_no_symlink() {
        let root =
            std::env::temp_dir().join(format!("mrml-gitd-catalog-loader-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let catalog = root.join("profiles.v1");
        fs::write(&catalog, PROFILES).unwrap();
        fs::set_permissions(&catalog, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = fs::metadata(&catalog).unwrap().uid();
        assert_eq!(
            read_authenticated(&catalog, uid, Sha256::digest(PROFILES)),
            Ok(PROFILES.to_vec())
        );
        assert_eq!(
            read_authenticated(&catalog, uid, [9; 32]),
            Err(DeploymentCatalogError::Digest)
        );
        let link = root.join("link.v1");
        symlink(&catalog, &link).unwrap();
        assert_eq!(
            read_authenticated(&link, uid, Sha256::digest(PROFILES)),
            Err(DeploymentCatalogError::Open)
        );
        fs::set_permissions(&catalog, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            read_authenticated(&catalog, uid, Sha256::digest(PROFILES)),
            Err(DeploymentCatalogError::Permissions)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn catalog_read_remains_bound_to_retained_parent_directory() {
        let root = std::env::temp_dir().join(format!(
            "mrml-gitd-catalog-retained-{}",
            std::process::id()
        ));
        let displaced = root.with_extension("displaced");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&displaced);
        fs::create_dir(&root).unwrap();
        let catalog = root.join("profiles.v1");
        fs::write(&catalog, PROFILES).unwrap();
        fs::set_permissions(&catalog, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = fs::metadata(&catalog).unwrap().uid();
        let retained = DirectoryCapability::open_root(root.to_str().unwrap()).unwrap();
        fs::rename(&root, &displaced).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(root.join("profiles.v1"), b"attacker-controlled").unwrap();

        assert_eq!(
            read_authenticated_capability(
                &retained,
                "profiles.v1",
                uid,
                Sha256::digest(PROFILES)
            ),
            Ok(PROFILES.to_vec())
        );

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(displaced).unwrap();
    }

    #[test]
    fn catalog_generations_exact_match_reopened_sha256_repository_state() {
        let root =
            std::env::temp_dir().join(format!("mrml-gitd-catalog-state-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let objects_path = root.join("objects");
        let refs_path = root.join("refs");
        let repository =
            Repository::init_with_format(objects_path.to_str().unwrap(), ObjectFormat::Sha256)
                .unwrap();
        let tip = repository.write_object(ObjectKind::Blob, b"tip").unwrap();
        let identity = RepositoryIdentity::parse("owner/project").unwrap();
        ActiveRefFile::initialize(
            refs_path.to_str().unwrap(),
            &ActiveRefState {
                repository: identity.clone(),
                repository_generation: RepositoryGeneration(4),
                trust_generation: TrustGeneration(6),
                revocation_generation: RevocationGeneration(8),
                pack_generation: PackGeneration(1),
                pack_set_digest: [1; 32],
                object_format: ObjectFormat::Sha256,
                default_branch: FullRefName::parse("refs/heads/main").unwrap(),
                refs: [(FullRefName::parse("refs/heads/main").unwrap(), tip)].into(),
            },
        )
        .unwrap();
        let view = FilesystemRepositoryView::open(
            identity,
            objects_path.to_str().unwrap(),
            refs_path.to_str().unwrap(),
        )
        .unwrap();
        let catalog = parse_deployment_catalog(PROFILES, REPOSITORIES).unwrap();
        assert_eq!(
            verify_repository_admission(&catalog.repositories[1], &view),
            Ok(())
        );
        assert_eq!(
            verify_repository_admission(&catalog.repositories[0], &view),
            Err(DeploymentCatalogError::InvalidValue)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
