use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use mrml_crypto::erase_secret_bytes;
use mrml_git_authority::{AuthorityCapability, AuthorityPeer};
use mrml_gitd::GitAuthorityChannelClient;

const O_NOFOLLOW: i32 = 0x20_000;

fn main() {
    if run().is_err() {
        eprintln!("mrml-gitd: health check failed closed");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ()> {
    let arguments: Vec<String> = std::env::args().collect();
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
            "usage: mrml-gitd authority-health SOCKET CAPABILITY OWN_UID OWN_GID AUTHORITY_UID AUTHORITY_GID SIGNER_IDENTITY_HEX REQUEST_ID"
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
