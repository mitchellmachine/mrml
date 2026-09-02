use mrml_crypto::erase_secret_bytes;
use mrml_git::{
    DurableDetachedCommitProofDirectory, LinuxDurableTrustPolicyStore, RepositoryIdentity,
};
use mrml_git_authority::{
    decode_frame, encode_frame, AuthorityCapability, AuthorityDispatchError, AuthorityFrame,
    AuthorityFrameKind, AuthorityListener, AuthorityOperation, AuthorityPeer,
    AuthorityReplayWindow, AuthoritySession, ProductionAuthority, AUTHORITY_CAPABILITY_BYTES,
    AUTHORITY_HEADER_BYTES, MAX_AUTHORITY_PAYLOAD_BYTES,
};
use mrml_openpgp::{parse_public_key_v6_ascii, MAX_OPENPGP_PUBLIC_KEY_BYTES};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const EX_USAGE: i32 = 64;
const EX_CONFIG: i32 = 78;
const O_NOFOLLOW: i32 = 0x20_000;
const STATUS_OK: u16 = 0;
const STATUS_UNAVAILABLE: u16 = 1;

fn main() {
    if run().is_err() {
        eprintln!("mrml-git-authority: operation failed closed");
        std::process::exit(EX_CONFIG);
    }
}

fn run() -> Result<(), ()> {
    let arguments: Vec<String> = std::env::args().collect();
    match arguments.as_slice() {
        [_, command, _socket, capability, peer_uid, peer_gid, own_uid, own_gid, policy, proofs, repository, openpgp, ml_dsa, receipt_key, validation_time, repository_generation]
            if matches!(command.as_str(), "check-config" | "describe-signer") =>
        {
            let _ = parse_peer(peer_uid, peer_gid)?;
            let authority_peer = parse_peer(own_uid, own_gid)?;
            let _capability = read_capability(capability, authority_peer.uid)?;
            let authority = load_authority(
                authority_peer.uid,
                policy,
                proofs,
                repository,
                openpgp,
                ml_dsa,
                receipt_key,
                validation_time.parse().map_err(|_| ())?,
                repository_generation.parse().map_err(|_| ())?,
            )?;
            if command == "describe-signer" {
                print_hex(&authority.signer_identity());
            } else {
                println!("valid");
            }
            Ok(())
        }
        [_, command, socket, capability, peer_uid, peer_gid, own_uid, own_gid, policy, proofs, repository, openpgp, ml_dsa, receipt_key, validation_time, repository_generation]
            if command == "serve" =>
        {
            serve(
                socket,
                capability,
                parse_peer(peer_uid, peer_gid)?,
                parse_peer(own_uid, own_gid)?,
                policy,
                proofs,
                repository,
                openpgp,
                ml_dsa,
                receipt_key,
                validation_time.parse().map_err(|_| ())?,
                repository_generation.parse().map_err(|_| ())?,
            )
        }
        [_, command, socket, capability, own_uid, own_gid, authority_uid, authority_gid]
            if command == "healthcheck" =>
        {
            healthcheck(
                socket,
                capability,
                parse_peer(own_uid, own_gid)?,
                parse_peer(authority_uid, authority_gid)?,
            )
        }
        [_, command, socket, own_uid, socket_gid] if command == "listener-health" => {
            listener_health(
                Path::new(socket),
                own_uid.parse().map_err(|_| ())?,
                socket_gid.parse().map_err(|_| ())?,
            )
        }
        _ => {
            eprintln!(
                "usage: mrml-git-authority serve SOCKET CAPABILITY PEER_UID PEER_GID OWN_UID OWN_GID POLICY_ROOT PROOF_ROOT REPOSITORY OPENPGP_PUBLIC ML_DSA_PUBLIC RECEIPT_KEY VALIDATION_TIME REPOSITORY_GENERATION\n       mrml-git-authority check-config SOCKET CAPABILITY PEER_UID PEER_GID OWN_UID OWN_GID POLICY_ROOT PROOF_ROOT REPOSITORY OPENPGP_PUBLIC ML_DSA_PUBLIC RECEIPT_KEY VALIDATION_TIME REPOSITORY_GENERATION\n       mrml-git-authority describe-signer SOCKET CAPABILITY PEER_UID PEER_GID OWN_UID OWN_GID POLICY_ROOT PROOF_ROOT REPOSITORY OPENPGP_PUBLIC ML_DSA_PUBLIC RECEIPT_KEY VALIDATION_TIME REPOSITORY_GENERATION\n       mrml-git-authority listener-health SOCKET OWN_UID SOCKET_GID\n       mrml-git-authority healthcheck SOCKET CAPABILITY OWN_UID OWN_GID AUTHORITY_UID AUTHORITY_GID"
            );
            std::process::exit(EX_USAGE);
        }
    }
}

fn print_hex(bytes: &[u8]) {
    println!("{}", lower_hex(bytes));
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn listener_health(socket: &Path, own_uid: u32, socket_gid: u32) -> Result<(), ()> {
    if own_uid == 0 || socket_gid == 0 {
        return Err(());
    }
    let metadata = std::fs::symlink_metadata(socket).map_err(|_| ())?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.uid() != own_uid
        || metadata.gid() != socket_gid
        || metadata.mode() & 0o777 != 0o660
    {
        return Err(());
    }
    println!("ready");
    Ok(())
}

fn serve(
    socket: &str,
    capability_path: &str,
    expected_gitd: AuthorityPeer,
    authority_peer: AuthorityPeer,
    policy_path: &str,
    proof_path: &str,
    repository: &str,
    openpgp_path: &str,
    ml_dsa_path: &str,
    receipt_key_path: &str,
    validation_time: u64,
    repository_generation: u64,
) -> Result<(), ()> {
    let termination_signals = TerminationSignals::block_current()?;
    let capability = read_capability(capability_path, authority_peer.uid)?;
    let mut authority = load_authority(
        authority_peer.uid,
        policy_path,
        proof_path,
        repository,
        openpgp_path,
        ml_dsa_path,
        receipt_key_path,
        validation_time,
        repository_generation,
    )?;
    let listener = AuthorityListener::bind(Path::new(socket), 0o660, expected_gitd)
        .and_then(|listener| listener.allow_health_peer(authority_peer))
        .map_err(|_| ())?;
    let mut replay = AuthorityReplayWindow::new();
    let mut health_replay = AuthorityReplayWindow::new();
    let terminating = Arc::new(AtomicBool::new(false));
    let signal_terminating = terminating.clone();
    let signal_socket = PathBuf::from(socket);
    let signal_worker = std::thread::spawn(move || {
        if termination_signals.wait().is_ok() {
            signal_terminating.store(true, Ordering::Release);
            let _ = std::os::unix::net::UnixStream::connect(signal_socket);
        }
    });
    loop {
        if terminating.load(Ordering::Acquire) {
            break;
        }
        let mut session = match listener.accept() {
            Ok(session) => session,
            Err(_) => continue,
        };
        if terminating.load(Ordering::Acquire) {
            break;
        }
        let mut encoded = vec![0u8; AUTHORITY_HEADER_BYTES + MAX_AUTHORITY_PAYLOAD_BYTES];
        let length = match session.read_frame(&mut encoded) {
            Ok(length) => length,
            Err(_) => continue,
        };
        let observed_peer = session.observed_peer();
        let request_replay = if observed_peer == expected_gitd {
            &mut replay
        } else {
            &mut health_replay
        };
        let request = match decode_frame(
            &encoded[..length],
            AuthorityFrameKind::Request,
            observed_peer,
            observed_peer,
            &capability,
            request_replay,
        ) {
            Ok(request) => request,
            Err(_) => continue,
        };
        if observed_peer != expected_gitd && request.operation != AuthorityOperation::Health {
            continue;
        }
        let result = mrml_runtime::unix_time_seconds()
            .ok_or(AuthorityDispatchError::Unavailable)
            .and_then(|now| authority.set_validation_time(now))
            .and_then(|()| authority.dispatch(request.operation, request.payload));
        let (status, payload) = match &result {
            Ok(payload) => (STATUS_OK, &payload[..]),
            Err(AuthorityDispatchError::Malformed) => (2, &[][..]),
            Err(AuthorityDispatchError::Unauthorized) => (3, &[][..]),
            Err(AuthorityDispatchError::Unavailable) => (STATUS_UNAVAILABLE, &[][..]),
            Err(AuthorityDispatchError::Resource) => (4, &[][..]),
        };
        let response = AuthorityFrame {
            kind: AuthorityFrameKind::Response,
            operation: request.operation,
            request_id: request.request_id,
            status,
            peer: authority_peer,
            payload,
        };
        let response_length = encode_frame(response, &capability, &mut encoded).map_err(|_| ())?;
        let _ = session.write_frame(&encoded[..response_length]);
    }
    signal_worker.join().map_err(|_| ())?;
    Ok(())
}

fn load_authority(
    authority_uid: u32,
    policy_path: &str,
    proof_path: &str,
    repository: &str,
    openpgp_path: &str,
    ml_dsa_path: &str,
    receipt_key_path: &str,
    validation_time: u64,
    repository_generation: u64,
) -> Result<ProductionAuthority, ()> {
    let (policy_path, proof_path) = authority_storage_paths(policy_path, proof_path, repository)?;
    let policy =
        LinuxDurableTrustPolicyStore::open(policy_path.to_str().ok_or(())?).map_err(|_| ())?;
    let proofs = DurableDetachedCommitProofDirectory::open(proof_path.to_str().ok_or(())?)
        .map_err(|_| ())?;
    let openpgp_bytes = read_regular(
        openpgp_path,
        1,
        MAX_OPENPGP_PUBLIC_KEY_BYTES,
        authority_uid,
        false,
    )?;
    let mut openpgp_scratch = vec![0u8; MAX_OPENPGP_PUBLIC_KEY_BYTES];
    let openpgp_key =
        parse_public_key_v6_ascii(&openpgp_bytes, &mut openpgp_scratch).map_err(|_| ())?;
    let ml_dsa_bytes = read_regular(
        ml_dsa_path,
        mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES,
        mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES,
        authority_uid,
        false,
    )?;
    let mut ml_dsa_key = [0u8; mrml_crypto::ML_DSA_65_PUBLIC_KEY_BYTES];
    ml_dsa_key.copy_from_slice(&ml_dsa_bytes);
    let mut receipt_bytes = read_regular(receipt_key_path, 32, 32, authority_uid, true)?;
    let mut receipt_key = [0u8; 32];
    receipt_key.copy_from_slice(&receipt_bytes);
    erase_secret_bytes(&mut receipt_bytes);
    let authority = ProductionAuthority::new(
        policy,
        proofs,
        openpgp_key,
        ml_dsa_key,
        receipt_key,
        validation_time,
        mrml_git::RepositoryGeneration(repository_generation),
    )
    .map_err(|_| ())?;
    erase_secret_bytes(&mut receipt_key);
    Ok(authority)
}

fn authority_storage_paths(
    policy_root: &str,
    proof_root: &str,
    repository: &str,
) -> Result<(PathBuf, PathBuf), ()> {
    let policy_root = Path::new(policy_root);
    let proof_root = Path::new(proof_root);
    if !policy_root.is_absolute() || !proof_root.is_absolute() {
        return Err(());
    }
    let repository = RepositoryIdentity::parse(repository).map_err(|_| ())?;
    Ok((
        policy_root.join(repository.as_str()),
        proof_root.join(repository.as_str()),
    ))
}

fn healthcheck(
    socket: &str,
    capability_path: &str,
    own_peer: AuthorityPeer,
    authority_peer: AuthorityPeer,
) -> Result<(), ()> {
    let capability = read_capability(capability_path, authority_peer.uid)?;
    let mut session = AuthoritySession::connect(Path::new(socket)).map_err(|_| ())?;
    let request_id = mrml_runtime::unix_time_seconds().ok_or(())?;
    let request = AuthorityFrame {
        kind: AuthorityFrameKind::Request,
        operation: AuthorityOperation::Health,
        request_id,
        status: 0,
        peer: own_peer,
        payload: &[],
    };
    let mut encoded = vec![0u8; AUTHORITY_HEADER_BYTES + MAX_AUTHORITY_PAYLOAD_BYTES];
    let length = encode_frame(request, &capability, &mut encoded).map_err(|_| ())?;
    session.write_frame(&encoded[..length]).map_err(|_| ())?;
    let length = session.read_frame(&mut encoded).map_err(|_| ())?;
    let response = decode_frame(
        &encoded[..length],
        AuthorityFrameKind::Response,
        session.observed_peer(),
        authority_peer,
        &capability,
        &mut AuthorityReplayWindow::new(),
    )
    .map_err(|_| ())?;
    if response.operation != AuthorityOperation::Health
        || response.request_id != request.request_id
        || response.status != STATUS_OK
        || response.payload != b"ready-v1"
    {
        return Err(());
    }
    println!("ready");
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeSignalSet {
    bits: [u64; 16],
}

struct TerminationSignals {
    set: NativeSignalSet,
}

impl TerminationSignals {
    fn block_current() -> Result<Self, ()> {
        const SIG_BLOCK: i32 = 0;
        const SIGINT: i32 = 2;
        const SIGTERM: i32 = 15;
        let mut set = NativeSignalSet { bits: [0; 16] };
        if unsafe { sigemptyset(&mut set) } != 0
            || unsafe { sigaddset(&mut set, SIGINT) } != 0
            || unsafe { sigaddset(&mut set, SIGTERM) } != 0
            || unsafe { pthread_sigmask(SIG_BLOCK, &set, core::ptr::null_mut()) } != 0
        {
            return Err(());
        }
        Ok(Self { set })
    }

    fn wait(self) -> Result<i32, ()> {
        let mut signal = 0;
        if unsafe { sigwait(&self.set, &mut signal) } == 0 && matches!(signal, 2 | 15) {
            Ok(signal)
        } else {
            Err(())
        }
    }
}

unsafe extern "C" {
    fn sigemptyset(set: *mut NativeSignalSet) -> i32;
    fn sigaddset(set: *mut NativeSignalSet, signal: i32) -> i32;
    fn pthread_sigmask(how: i32, set: *const NativeSignalSet, old: *mut NativeSignalSet) -> i32;
    fn sigwait(set: *const NativeSignalSet, signal: *mut i32) -> i32;
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

fn read_capability(path: &str, expected_owner: u32) -> Result<AuthorityCapability, ()> {
    let mut bytes = read_regular(
        path,
        AUTHORITY_CAPABILITY_BYTES,
        AUTHORITY_CAPABILITY_BYTES,
        expected_owner,
        true,
    )?;
    let mut key = [0u8; AUTHORITY_CAPABILITY_BYTES];
    key.copy_from_slice(&bytes);
    erase_secret_bytes(&mut bytes);
    let result = AuthorityCapability::new(key);
    erase_secret_bytes(&mut key);
    result.map_err(|_| ())
}

fn read_regular(
    path: &str,
    minimum: usize,
    maximum: usize,
    expected_owner: u32,
    secret: bool,
) -> Result<Vec<u8>, ()> {
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
        || (secret && !matches!(mode, 0o400 | 0o440 | 0o600))
        || (!secret && mode & 0o022 != 0)
        || metadata.len() < minimum as u64
        || metadata.len() > maximum as u64
    {
        return Err(());
    }
    let mut bytes = vec![0u8; metadata.len() as usize];
    file.read_exact(&mut bytes).map_err(|_| ())?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    #[test]
    fn listener_health_requires_exact_socket_identity_and_mode() {
        let root = std::env::temp_dir().join(format!(
            "mrml-authority-listener-health-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let socket = root.join("authority.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).unwrap();
        let metadata = std::fs::symlink_metadata(&socket).unwrap();
        assert!(listener_health(&socket, metadata.uid(), metadata.gid()).is_ok());
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(listener_health(&socket, metadata.uid(), metadata.gid()).is_err());
        drop(listener);
        std::fs::remove_file(socket).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn authority_paths_require_absolute_roots_and_canonical_repository_identity() {
        assert_eq!(
            authority_storage_paths("/policy", "/proof", "owner/project").unwrap(),
            (
                PathBuf::from("/policy/owner/project"),
                PathBuf::from("/proof/owner/project")
            )
        );
        for repository in [
            "../policy",
            "owner/../policy",
            "/owner/project",
            "owner//repo",
        ] {
            assert!(authority_storage_paths("/policy", "/proof", repository).is_err());
        }
        assert!(authority_storage_paths("policy", "/proof", "owner/project").is_err());
        assert!(authority_storage_paths("/policy", "proof", "owner/project").is_err());
    }

    #[test]
    fn signer_identity_encoding_is_exact_lowercase_hex() {
        assert_eq!(lower_hex(&[0x00, 0xab, 0xff]), "00abff");
    }
}
