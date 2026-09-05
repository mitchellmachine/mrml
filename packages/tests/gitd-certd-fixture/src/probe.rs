#![feature(peer_credentials_unix_socket)]
use mrml_certificate::{CertdChannelCapability, CertdPeerIdentity};
use mrml_crypto::erase_secret_bytes;
use mrml_gitd::{GitdCertdChannelClient, prove_identity_signing_route, validate_identity_snapshot};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

const O_NOFOLLOW: i32 = 0x20_000;
mod completion_fixture;
mod malformed_push;
mod measure_native;
mod real_enrollment;
mod response_loss;

fn main() {
    if run().is_err() {
        eprintln!("mrml-gitd-certd-test-probe: protocol validation failed");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments
        .first()
        .is_some_and(|command| command == "response-loss-proxy")
    {
        return response_loss::run(&arguments);
    }
    if arguments
        .first()
        .is_some_and(|command| command == "measure-native")
    {
        return measure_native::run(&arguments);
    }
    if arguments
        .first()
        .is_some_and(|command| command == "malformed-push")
    {
        return malformed_push::run(&arguments);
    }
    if arguments
        .first()
        .is_some_and(|command| command == "fixture-create")
    {
        return completion_fixture::run(&arguments);
    }
    if let [command, socket] = arguments.as_slice() {
        if command == "hold-partial-frame" {
            use std::io::Write;
            let mut stream = std::os::unix::net::UnixStream::connect(socket).map_err(|_| ())?;
            let peer = stream.peer_cred().map_err(|_| ())?;
            if peer.uid != 21003 || peer.gid != 21003 {
                return Err(());
            }
            stream.write_all(&[0]).map_err(|_| ())?;
            println!("partial frame connected");
            std::io::stdout().flush().map_err(|_| ())?;
            std::thread::sleep(std::time::Duration::from_secs(10));
            return Ok(());
        }
    }
    if arguments
        .first()
        .is_some_and(|command| command.starts_with("enroll-"))
    {
        return real_enrollment::run(&arguments);
    }
    if let [command, socket, owner_uid, socket_gid] = arguments.as_slice() {
        if command != "socket-health" {
            return Err(());
        }
        let metadata = std::fs::symlink_metadata(socket).map_err(|_| ())?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_socket()
            || metadata.uid() != owner_uid.parse::<u32>().map_err(|_| ())?
            || metadata.gid() != socket_gid.parse::<u32>().map_err(|_| ())?
            || metadata.mode() & 0o777 != 0o660
        {
            return Err(());
        }
        println!("ready");
        return Ok(());
    }
    let [
        socket,
        capability_file,
        client_uid,
        client_gid,
        fixture_uid,
        fixture_gid,
        owner_uid,
        server_name,
    ] = arguments.as_slice()
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
        std::env::var("MRML_TEST_CERTD_FIRST_REQUEST_ID")
            .ok()
            .map(|value| value.parse::<u64>().map_err(|_| ()))
            .transpose()?
            .unwrap_or(1),
    )
    .map_err(|_| ())?;
    client.health().map_err(|error| {
        eprintln!("Gitd health failed: {error:?}");
    })?;
    let snapshot = client.get_identity_snapshot(server_name).map_err(|error| {
        eprintln!("Gitd identity RPC failed: {error:?}");
    })?;
    let generation = snapshot.identity_generation;
    let identity = validate_identity_snapshot(snapshot, None).map_err(|error| {
        eprintln!("Gitd identity validation failed: {error:?}");
    })?;
    prove_identity_signing_route(&mut client, &identity, 1).map_err(|error| {
        eprintln!("Gitd signing proof failed: {error:?}");
    })?;
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
        assert!(
            "0".parse::<u32>()
                .ok()
                .filter(|value| *value != 0)
                .is_none()
        );
    }

    #[test]
    fn socket_health_requires_exact_arity() {
        let arguments = ["socket-health", "/tmp/certd.sock", "21003"];
        assert_ne!(arguments.len(), 4);
    }
}
