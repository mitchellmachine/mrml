use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use mrml_certificate::{CertdChannelCapability, CertdPeerIdentity};
use mrml_crypto::erase_secret_bytes;
use mrml_git_authority::{AuthorityCapability, AuthorityPeer};
use mrml_gitd::{
    GitAuthorityChannelClient, GitdCertdChannelClient, admit_catalog_repository,
    load_deployment_catalog, load_gitd_authentication, load_gitd_config, validate_storage_layout,
};

const O_NOFOLLOW: i32 = 0x20_000;

fn main() {
    if run().is_err() {
        eprintln!("mrml-gitd: health check failed closed");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ()> {
    let arguments: Vec<String> = std::env::args().collect();
    if let [_, command, config] = arguments.as_slice() {
        if command != "validate-config" {
            return Err(());
        }
        let config = load_gitd_config(Path::new(config)).map_err(|_| ())?;
        validate_storage_layout(&config).map_err(|_| ())?;
        let catalog = load_deployment_catalog(&config).map_err(|_| ())?;
        load_gitd_authentication(&config, &catalog).map_err(|_| ())?;
        for repository in &catalog.repositories {
            admit_catalog_repository(&config, repository).map_err(|_| ())?;
        }
        println!("valid");
        return Ok(());
    }
    if let [_, command, config_path, signer_identity] = arguments.as_slice() {
        if command != "dependencies-health" {
            return Err(());
        }
        let config = load_gitd_config(Path::new(config_path)).map_err(|_| ())?;
        validate_storage_layout(&config).map_err(|_| ())?;
        let catalog = load_deployment_catalog(&config).map_err(|_| ())?;
        load_gitd_authentication(&config, &catalog).map_err(|_| ())?;
        for repository in &catalog.repositories {
            admit_catalog_repository(&config, repository).map_err(|_| ())?;
        }
        let authority_capability =
            load_authority_capability(config.authority_capability.as_path(), config.authority_uid)?;
        let certd_capability =
            load_certd_capability(config.certd_capability.as_path(), config.certd_uid)?;
        let mut authority = GitAuthorityChannelClient::new(
            config.authority_socket.as_path(),
            authority_capability,
            AuthorityPeer {
                uid: config.gitd_uid,
                gid: config.gitd_gid,
            },
            AuthorityPeer {
                uid: config.authority_uid,
                gid: config.authority_gid,
            },
            parse_signer_identity(signer_identity)?,
            config.next_authority_request_id,
        )
        .map_err(|_| ())?;
        let mut certd = GitdCertdChannelClient::new(
            config.certd_socket.as_path(),
            certd_capability,
            CertdPeerIdentity {
                uid: config.gitd_uid,
                gid: config.gitd_gid,
            },
            CertdPeerIdentity {
                uid: config.certd_uid,
                gid: config.certd_gid,
            },
            config.next_certd_request_id,
        )
        .map_err(|_| ())?;
        authority.health().map_err(|_| ())?;
        certd.health().map_err(|_| ())?;
        println!("dependencies-ready");
        return Ok(());
    }
    let [
        _,
        command,
        socket,
        capability_path,
        own_uid,
        own_gid,
        authority_uid,
        authority_gid,
        signer_identity,
        request_id,
    ] = arguments.as_slice()
    else {
        eprintln!(
            "usage: mrml-gitd validate-config CONFIG | dependencies-health CONFIG SIGNER_IDENTITY_HEX | authority-health SOCKET CAPABILITY OWN_UID OWN_GID AUTHORITY_UID AUTHORITY_GID SIGNER_IDENTITY_HEX REQUEST_ID"
        );
        std::process::exit(64);
    };
    if command != "authority-health" {
        return Err(());
    }
    let authority_peer = parse_peer(authority_uid, authority_gid)?;
    let mut bytes = read_capability(capability_path, authority_peer.uid)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    erase_secret_bytes(&mut bytes);
    let capability = AuthorityCapability::new(key).map_err(|_| ())?;
    erase_secret_bytes(&mut key);
    let mut client = GitAuthorityChannelClient::new(
        Path::new(socket),
        capability,
        parse_peer(own_uid, own_gid)?,
        authority_peer,
        parse_signer_identity(signer_identity)?,
        request_id.parse().map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    client.health().map_err(|_| ())?;
    println!("ready");
    Ok(())
}

fn parse_peer(uid: &str, gid: &str) -> Result<AuthorityPeer, ()> {
    let peer = AuthorityPeer {
        uid: uid.parse().map_err(|_| ())?,
        gid: gid.parse().map_err(|_| ())?,
    };
    if peer.uid == 0 || peer.gid == 0 {
        return Err(());
    }
    Ok(peer)
}

fn parse_signer_identity(input: &str) -> Result<[u8; 64], ()> {
    if input.len() != 128 || !input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(());
    }
    let mut output = [0u8; 64];
    for (index, destination) in output.iter_mut().enumerate() {
        *destination =
            (hex(input.as_bytes()[index * 2])? << 4) | hex(input.as_bytes()[index * 2 + 1])?;
    }
    if output == [0; 64] {
        return Err(());
    }
    Ok(output)
}

fn hex(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(()),
    }
}

fn read_capability(path: &str, expected_owner: u32) -> Result<Vec<u8>, ()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    let mode = metadata.mode() & 0o777;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != expected_owner
        || !matches!(mode, 0o400 | 0o440 | 0o600)
        || metadata.len() != 32
    {
        return Err(());
    }
    let mut bytes = vec![0u8; 32];
    file.read_exact(&mut bytes).map_err(|_| ())?;
    Ok(bytes)
}

fn read_key(path: &Path, expected_owner: u32) -> Result<[u8; 32], ()> {
    let path = path.to_str().ok_or(())?;
    let mut bytes = read_capability(path, expected_owner)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    erase_secret_bytes(&mut bytes);
    Ok(key)
}

fn load_authority_capability(path: &Path, expected_owner: u32) -> Result<AuthorityCapability, ()> {
    let mut key = read_key(path, expected_owner)?;
    let capability = AuthorityCapability::new(key).map_err(|_| ());
    erase_secret_bytes(&mut key);
    capability
}

fn load_certd_capability(path: &Path, expected_owner: u32) -> Result<CertdChannelCapability, ()> {
    let mut key = read_key(path, expected_owner)?;
    let capability = CertdChannelCapability::new(key).map_err(|_| ());
    erase_secret_bytes(&mut key);
    capability
}
