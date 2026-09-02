use mrml_certificate::{CertdChannelCapability, CertdPeerIdentity};
use mrml_crypto::erase_secret_bytes;
use mrml_gitd::{prove_identity_signing_route, validate_identity_snapshot, GitdCertdChannelClient};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const O_NOFOLLOW: i32 = 0x20_000;

fn main() {
    if run().is_err() {
        eprintln!("mrml-gitd-certd-test-probe: fixture protocol validation failed");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [socket, capability_file, client_uid, client_gid, fixture_uid, fixture_gid, owner_uid, server_name] =
        arguments.as_slice()
    else {
        return Err(());
    };
    let nonzero_u32 = |value: &str| {
        value
            .parse::<u32>()
            .ok()
            .filter(|value| *value != 0)
            .ok_or(())
    };
    let mut key = read_capability(Path::new(capability_file), nonzero_u32(owner_uid)?)?;
    let capability_result = CertdChannelCapability::new(key).map_err(|_| ());
    erase_secret_bytes(&mut key);
    let capability = capability_result?;
    let mut client = GitdCertdChannelClient::new(
        Path::new(socket),
        capability,
        CertdPeerIdentity {
            uid: nonzero_u32(client_uid)?,
            gid: nonzero_u32(client_gid)?,
        },
        CertdPeerIdentity {
            uid: nonzero_u32(fixture_uid)?,
            gid: nonzero_u32(fixture_gid)?,
        },
        1,
    )
    .map_err(|_| ())?;
    client.health().map_err(|_| ())?;
    let snapshot = client.get_identity_snapshot(server_name).map_err(|_| ())?;
    let generation = snapshot.identity_generation;
    let identity = validate_identity_snapshot(snapshot, None).map_err(|_| ())?;
    prove_identity_signing_route(&mut client, &identity, 1).map_err(|_| ())?;
    if client
        .wait_for_identity_generation(generation, 1)
        .map_err(|_| ())?
        .is_some()
    {
        return Err(());
    }
    println!("mrml-gitd-certd-test-probe PASS generation={generation}");
    Ok(())
}

fn read_capability(path: &Path, owner_uid: u32) -> Result<[u8; 32], ()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != owner_uid
        || !matches!(metadata.mode() & 0o777, 0o400 | 0o600)
        || metadata.len() != 32
    {
        return Err(());
    }
    let mut key = [0u8; 32];
    file.read_exact(&mut key).map_err(|_| ())?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    #[test]
    fn zero_numeric_identity_is_rejected() {
        assert!("0"
            .parse::<u32>()
            .ok()
            .filter(|value| *value != 0)
            .is_none());
    }
}
