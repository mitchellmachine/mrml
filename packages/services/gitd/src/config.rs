use std::path::{Component, Path, PathBuf};

use mrml_runtime::DirectoryCapability;

const MAX_CONFIG_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitdConfig {
    pub server_name: String,
    pub listen_port: u16,
    pub repository_root: PathBuf,
    pub state_root: PathBuf,
    pub quarantine_root: PathBuf,
    pub cache_root: PathBuf,
    pub receipt_root: PathBuf,
    pub policy_root: PathBuf,
    pub repository_catalog: PathBuf,
    pub repository_catalog_sha256: [u8; 32],
    pub profile_catalog: PathBuf,
    pub profile_catalog_sha256: [u8; 32],
    pub token_records: PathBuf,
    pub token_pepper: PathBuf,
    pub quic_retry_key: PathBuf,
    pub quic_retry_generation: u64,
    pub authority_socket: PathBuf,
    pub certd_socket: PathBuf,
    pub authority_capability: PathBuf,
    pub certd_capability: PathBuf,
    pub gitd_uid: u32,
    pub gitd_gid: u32,
    pub authority_uid: u32,
    pub authority_gid: u32,
    pub certd_uid: u32,
    pub certd_gid: u32,
    pub next_authority_request_id: u64,
    pub next_certd_request_id: u64,
    pub max_connections: u32,
    pub max_uploads: u32,
    pub max_receives: u32,
    pub max_body_bytes: u64,
    pub minimum_free_space_bytes: u64,
    pub drain_seconds: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitdConfigError {
    Open,
    Metadata,
    Permissions,
    Read,
    Size,
    Encoding,
    Syntax,
    UnknownField,
    DuplicateField,
    MissingField,
    InvalidValue,
}

pub fn load_gitd_config(path: &Path) -> Result<GitdConfig, GitdConfigError> {
    if !path.is_absolute() {
        return Err(GitdConfigError::InvalidValue);
    }
    let parent = path.parent().ok_or(GitdConfigError::Open)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(GitdConfigError::Open)?;
    let directory = DirectoryCapability::open_root(
        parent.to_str().ok_or(GitdConfigError::Open)?,
    )
    .map_err(|_| GitdConfigError::Open)?;
    load_gitd_config_capability(&directory, name)
}

fn load_gitd_config_capability(
    directory: &DirectoryCapability,
    name: &str,
) -> Result<GitdConfig, GitdConfigError> {
    let mut file = directory
        .open_regular(name)
        .map_err(|_| GitdConfigError::Open)?;
    let metadata = file.metadata().map_err(|_| GitdConfigError::Metadata)?;
    let length = file.len().map_err(|_| GitdConfigError::Metadata)?;
    let mode = metadata.mode & 0o777;
    if metadata.links != 1
        || mode & 0o022 != 0
        || mode & 0o444 == 0
        || length == 0
        || length > MAX_CONFIG_BYTES as u64
    {
        return Err(GitdConfigError::Permissions);
    }
    let length = usize::try_from(length).map_err(|_| GitdConfigError::Size)?;
    let mut input = vec![0u8; length];
    file.read_exact(&mut input)
        .map_err(|_| GitdConfigError::Read)?;
    let config = parse_gitd_config(&input)?;
    if metadata.uid != 0 && metadata.uid != config.gitd_uid {
        return Err(GitdConfigError::Permissions);
    }
    Ok(config)
}

pub fn parse_gitd_config(input: &[u8]) -> Result<GitdConfig, GitdConfigError> {
    if input.is_empty() || input.len() > MAX_CONFIG_BYTES || input.contains(&0) {
        return Err(GitdConfigError::Size);
    }
    let input = core::str::from_utf8(input).map_err(|_| GitdConfigError::Encoding)?;
    let mut version = None;
    let mut server_name = None;
    let mut listen_port = None;
    let mut repository_root = None;
    let mut state_root = None;
    let mut quarantine_root = None;
    let mut cache_root = None;
    let mut receipt_root = None;
    let mut policy_root = None;
    let mut repository_catalog = None;
    let mut repository_catalog_sha256 = None;
    let mut profile_catalog = None;
    let mut profile_catalog_sha256 = None;
    let mut token_records = None;
    let mut token_pepper = None;
    let mut quic_retry_key = None;
    let mut quic_retry_generation = None;
    let mut authority_socket = None;
    let mut certd_socket = None;
    let mut authority_capability = None;
    let mut certd_capability = None;
    let mut gitd_uid = None;
    let mut gitd_gid = None;
    let mut authority_uid = None;
    let mut authority_gid = None;
    let mut certd_uid = None;
    let mut certd_gid = None;
    let mut next_authority_request_id = None;
    let mut next_certd_request_id = None;
    let mut max_connections = None;
    let mut max_uploads = None;
    let mut max_receives = None;
    let mut max_body_bytes = None;
    let mut minimum_free_space_bytes = None;
    let mut drain_seconds = None;

    for line in input.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.trim() != line {
            return Err(GitdConfigError::Syntax);
        }
        let (key, value) = line.split_once('=').ok_or(GitdConfigError::Syntax)?;
        if key.is_empty() || value.is_empty() || value.contains('=') {
            return Err(GitdConfigError::Syntax);
        }
        macro_rules! set {
            ($slot:ident, $value:expr) => {{
                if $slot.is_some() {
                    return Err(GitdConfigError::DuplicateField);
                }
                $slot = Some($value);
            }};
        }
        match key {
            "version" => set!(version, number::<u16>(value)?),
            "server_name" => set!(server_name, parse_server_name(value)?),
            "listen_port" => set!(listen_port, nonzero_number::<u16>(value)?),
            "repository_root" => set!(repository_root, absolute_path(value)?),
            "state_root" => set!(state_root, absolute_path(value)?),
            "quarantine_root" => set!(quarantine_root, absolute_path(value)?),
            "cache_root" => set!(cache_root, absolute_path(value)?),
            "receipt_root" => set!(receipt_root, absolute_path(value)?),
            "policy_root" => set!(policy_root, absolute_path(value)?),
            "repository_catalog" => set!(repository_catalog, absolute_path(value)?),
            "repository_catalog_sha256" => {
                set!(repository_catalog_sha256, sha256_digest(value)?)
            }
            "profile_catalog" => set!(profile_catalog, absolute_path(value)?),
            "profile_catalog_sha256" => set!(profile_catalog_sha256, sha256_digest(value)?),
            "token_records" => set!(token_records, absolute_path(value)?),
            "token_pepper" => set!(token_pepper, absolute_path(value)?),
            "quic_retry_key" => set!(quic_retry_key, absolute_path(value)?),
            "quic_retry_generation" => {
                set!(quic_retry_generation, nonzero_number::<u64>(value)?)
            }
            "authority_socket" => set!(authority_socket, absolute_path(value)?),
            "certd_socket" => set!(certd_socket, absolute_path(value)?),
            "authority_capability" => set!(authority_capability, absolute_path(value)?),
            "certd_capability" => set!(certd_capability, absolute_path(value)?),
            "gitd_uid" => set!(gitd_uid, nonzero_number::<u32>(value)?),
            "gitd_gid" => set!(gitd_gid, nonzero_number::<u32>(value)?),
            "authority_uid" => set!(authority_uid, nonzero_number::<u32>(value)?),
            "authority_gid" => set!(authority_gid, nonzero_number::<u32>(value)?),
            "certd_uid" => set!(certd_uid, nonzero_number::<u32>(value)?),
            "certd_gid" => set!(certd_gid, nonzero_number::<u32>(value)?),
            "next_authority_request_id" => {
                set!(next_authority_request_id, nonzero_number::<u64>(value)?)
            }
            "next_certd_request_id" => {
                set!(next_certd_request_id, nonzero_number::<u64>(value)?)
            }
            "max_connections" => set!(max_connections, bounded_u32(value, 1, 1_000_000)?),
            "max_uploads" => set!(max_uploads, bounded_u32(value, 1, 65_536)?),
            "max_receives" => set!(max_receives, bounded_u32(value, 1, 4_096)?),
            "max_body_bytes" => set!(
                max_body_bytes,
                bounded_u64(value, 1024, 8 * 1024 * 1024 * 1024 * 1024)?
            ),
            "minimum_free_space_bytes" => set!(
                minimum_free_space_bytes,
                bounded_u64(value, 1024 * 1024 * 1024, 8 * 1024 * 1024 * 1024 * 1024)?
            ),
            "drain_seconds" => set!(drain_seconds, bounded_u32(value, 1, 300)?),
            _ => return Err(GitdConfigError::UnknownField),
        }
    }
    if version != Some(1) {
        return Err(GitdConfigError::InvalidValue);
    }
    macro_rules! required {
        ($slot:ident) => {
            $slot.ok_or(GitdConfigError::MissingField)?
        };
    }
    let config = GitdConfig {
        server_name: required!(server_name),
        listen_port: required!(listen_port),
        repository_root: required!(repository_root),
        state_root: required!(state_root),
        quarantine_root: required!(quarantine_root),
        cache_root: required!(cache_root),
        receipt_root: required!(receipt_root),
        policy_root: required!(policy_root),
        repository_catalog: required!(repository_catalog),
        repository_catalog_sha256: required!(repository_catalog_sha256),
        profile_catalog: required!(profile_catalog),
        profile_catalog_sha256: required!(profile_catalog_sha256),
        token_records: required!(token_records),
        token_pepper: required!(token_pepper),
        quic_retry_key: required!(quic_retry_key),
        quic_retry_generation: required!(quic_retry_generation),
        authority_socket: required!(authority_socket),
        certd_socket: required!(certd_socket),
        authority_capability: required!(authority_capability),
        certd_capability: required!(certd_capability),
        gitd_uid: required!(gitd_uid),
        gitd_gid: required!(gitd_gid),
        authority_uid: required!(authority_uid),
        authority_gid: required!(authority_gid),
        certd_uid: required!(certd_uid),
        certd_gid: required!(certd_gid),
        next_authority_request_id: required!(next_authority_request_id),
        next_certd_request_id: required!(next_certd_request_id),
        max_connections: required!(max_connections),
        max_uploads: required!(max_uploads),
        max_receives: required!(max_receives),
        max_body_bytes: required!(max_body_bytes),
        minimum_free_space_bytes: required!(minimum_free_space_bytes),
        drain_seconds: required!(drain_seconds),
    };
    let authoritative = [
        &config.repository_root,
        &config.state_root,
        &config.quarantine_root,
        &config.cache_root,
        &config.receipt_root,
        &config.policy_root,
    ];
    for left in 0..authoritative.len() {
        for right in left + 1..authoritative.len() {
            if authoritative[left] == authoritative[right]
                || authoritative[left].starts_with(authoritative[right])
                || authoritative[right].starts_with(authoritative[left])
            {
                return Err(GitdConfigError::InvalidValue);
            }
        }
    }
    if !is_direct_child(&config.repository_catalog, &config.policy_root)
        || !is_direct_child(&config.profile_catalog, &config.policy_root)
        || !is_direct_child(&config.token_records, &config.state_root)
        || config.token_pepper.parent() != Some(Path::new("/run/secrets"))
        || config.quic_retry_key.parent() != Some(Path::new("/run/secrets"))
        || config.repository_catalog == config.profile_catalog
        || config.token_pepper == config.authority_capability
        || config.token_pepper == config.certd_capability
        || config.quic_retry_key == config.token_pepper
        || config.quic_retry_key == config.authority_capability
        || config.quic_retry_key == config.certd_capability
    {
        return Err(GitdConfigError::InvalidValue);
    }
    Ok(config)
}

fn is_direct_child(path: &Path, parent: &Path) -> bool {
    path.parent() == Some(parent) && path.file_name().is_some()
}

fn sha256_digest(value: &str) -> Result<[u8; 32], GitdConfigError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(GitdConfigError::InvalidValue);
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        let high = hex_nibble(value.as_bytes()[index * 2])?;
        let low = hex_nibble(value.as_bytes()[index * 2 + 1])?;
        *byte = high << 4 | low;
    }
    if digest == [0; 32] {
        return Err(GitdConfigError::InvalidValue);
    }
    Ok(digest)
}

fn hex_nibble(value: u8) -> Result<u8, GitdConfigError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(GitdConfigError::InvalidValue),
    }
}

fn number<T: core::str::FromStr>(value: &str) -> Result<T, GitdConfigError> {
    if value.starts_with('+') || (value.starts_with('0') && value.len() > 1) {
        return Err(GitdConfigError::InvalidValue);
    }
    value.parse().map_err(|_| GitdConfigError::InvalidValue)
}

fn nonzero_number<T>(value: &str) -> Result<T, GitdConfigError>
where
    T: core::str::FromStr + Default + PartialEq,
{
    let parsed = number(value)?;
    if parsed == T::default() {
        return Err(GitdConfigError::InvalidValue);
    }
    Ok(parsed)
}

fn bounded_u32(value: &str, minimum: u32, maximum: u32) -> Result<u32, GitdConfigError> {
    let value = number(value)?;
    if !(minimum..=maximum).contains(&value) {
        return Err(GitdConfigError::InvalidValue);
    }
    Ok(value)
}

fn bounded_u64(value: &str, minimum: u64, maximum: u64) -> Result<u64, GitdConfigError> {
    let value = number(value)?;
    if !(minimum..=maximum).contains(&value) {
        return Err(GitdConfigError::InvalidValue);
    }
    Ok(value)
}

fn absolute_path(value: &str) -> Result<PathBuf, GitdConfigError> {
    if value.len() > 4096 || !value.is_ascii() {
        return Err(GitdConfigError::InvalidValue);
    }
    let path = Path::new(value);
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(GitdConfigError::InvalidValue);
    }
    Ok(path.to_path_buf())
}

fn parse_server_name(value: &str) -> Result<String, GitdConfigError> {
    if value.is_empty()
        || value.len() > 253
        || value.ends_with('.')
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(GitdConfigError::InvalidValue);
    }
    Ok(value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    const VALID: &str = "version=1\nserver_name=git.example.invalid\nlisten_port=8443\nrepository_root=/mnt/mrml/gitd/repos\nstate_root=/mnt/mrml/gitd/state\nquarantine_root=/mnt/mrml/gitd/quarantine\ncache_root=/mnt/mrml/gitd/cache\nreceipt_root=/mnt/mrml/gitd/receipts\npolicy_root=/mnt/mrml/gitd/policies\nrepository_catalog=/mnt/mrml/gitd/policies/repositories.v1\nrepository_catalog_sha256=1111111111111111111111111111111111111111111111111111111111111111\nprofile_catalog=/mnt/mrml/gitd/policies/profiles.v1\nprofile_catalog_sha256=2222222222222222222222222222222222222222222222222222222222222222\ntoken_records=/mnt/mrml/gitd/state/tokens.v1\ntoken_pepper=/run/secrets/gitd-token-pepper\nquic_retry_key=/run/secrets/gitd-quic-retry-key\nquic_retry_generation=1\nauthority_socket=/run/mrml/git-authority/authority.sock\ncertd_socket=/run/mrml/certd-gitd/certd.sock\nauthority_capability=/run/secrets/git-authority-channel\ncertd_capability=/run/secrets/certd-gitd-channel\ngitd_uid=21001\ngitd_gid=21001\nauthority_uid=21002\nauthority_gid=21002\ncertd_uid=21003\ncertd_gid=21003\nnext_authority_request_id=7\nnext_certd_request_id=11\nmax_connections=4096\nmax_uploads=128\nmax_receives=16\nmax_body_bytes=8589934592\nminimum_free_space_bytes=42949672960\ndrain_seconds=30\n";

    #[test]
    fn exact_v1_config_parses_with_production_defaults() {
        let config = parse_gitd_config(VALID.as_bytes()).unwrap();
        assert_eq!(config.gitd_uid, 21001);
        assert_eq!(config.authority_uid, 21002);
        assert_eq!(config.certd_uid, 21003);
        assert_eq!(config.listen_port, 8443);
        assert_eq!(config.minimum_free_space_bytes, 40 * 1024 * 1024 * 1024);
    }

    #[test]
    fn unknown_duplicate_missing_relative_and_overlapping_paths_fail() {
        assert_eq!(
            parse_gitd_config(format!("{VALID}unknown=value\n").as_bytes()),
            Err(GitdConfigError::UnknownField)
        );
        assert_eq!(
            parse_gitd_config(format!("{VALID}gitd_uid=21001\n").as_bytes()),
            Err(GitdConfigError::DuplicateField)
        );
        assert_eq!(
            parse_gitd_config(VALID.replace("version=1\n", "").as_bytes()),
            Err(GitdConfigError::InvalidValue)
        );
        assert_eq!(
            parse_gitd_config(
                VALID
                    .replace(
                        "repository_root=/mnt/mrml/gitd/repos",
                        "repository_root=repos"
                    )
                    .as_bytes()
            ),
            Err(GitdConfigError::InvalidValue)
        );
        assert_eq!(
            parse_gitd_config(
                VALID
                    .replace(
                        "repository_catalog_sha256=1111111111111111111111111111111111111111111111111111111111111111",
                        "repository_catalog_sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    )
                    .as_bytes()
            ),
            Err(GitdConfigError::InvalidValue)
        );
        assert_eq!(
            parse_gitd_config(
                VALID
                    .replace(
                        "repository_catalog=/mnt/mrml/gitd/policies/repositories.v1",
                        "repository_catalog=/mnt/mrml/gitd/state/repositories.v1"
                    )
                    .as_bytes()
            ),
            Err(GitdConfigError::InvalidValue)
        );
        assert_eq!(
            parse_gitd_config(
                VALID
                    .replace(
                        "token_records=/mnt/mrml/gitd/state/tokens.v1",
                        "token_records=/mnt/mrml/gitd/policies/tokens.v1"
                    )
                    .as_bytes()
            ),
            Err(GitdConfigError::InvalidValue)
        );
        assert_eq!(
            parse_gitd_config(
                VALID
                    .replace(
                        "state_root=/mnt/mrml/gitd/state",
                        "state_root=/mnt/mrml/gitd/repos/state"
                    )
                    .as_bytes()
            ),
            Err(GitdConfigError::InvalidValue)
        );
    }

    #[test]
    fn hosted_loader_rejects_symlinks_and_insecure_modes() {
        let root =
            std::env::temp_dir().join(format!("mrml-gitd-config-loader-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let config = root.join("gitd.conf");
        fs::write(&config, VALID).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        let owned = VALID.replace(
            "gitd_uid=21001",
            &format!(
                "gitd_uid={}",
                std::os::unix::fs::MetadataExt::uid(&fs::metadata(&config).unwrap())
            ),
        );
        fs::write(&config, owned).unwrap();
        assert!(load_gitd_config(&config).is_ok());

        let link = root.join("link.conf");
        symlink(&config, &link).unwrap();
        assert_eq!(load_gitd_config(&link), Err(GitdConfigError::Open));
        fs::set_permissions(&config, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(load_gitd_config(&config), Err(GitdConfigError::Permissions));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn config_load_remains_bound_to_retained_parent_directory() {
        let root =
            std::env::temp_dir().join(format!("mrml-gitd-config-retained-{}", std::process::id()));
        let displaced = root.with_extension("displaced");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&displaced);
        fs::create_dir(&root).unwrap();
        let config = root.join("gitd.conf");
        fs::write(&config, VALID).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = std::os::unix::fs::MetadataExt::uid(&fs::metadata(&config).unwrap());
        fs::write(
            &config,
            VALID.replace("gitd_uid=21001", &format!("gitd_uid={uid}")),
        )
        .unwrap();
        let retained = DirectoryCapability::open_root(root.to_str().unwrap()).unwrap();
        fs::rename(&root, &displaced).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(root.join("gitd.conf"), b"attacker-controlled").unwrap();

        assert!(load_gitd_config_capability(&retained, "gitd.conf").is_ok());

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(displaced).unwrap();
    }
}
