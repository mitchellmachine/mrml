use mrml_crypto::erase_secret_bytes;
use mrml_git::{DurableDetachedCommitProofDirectory, LinuxDurableTrustPolicyStore};
use mrml_git_authority::{
    AUTHORITY_CAPABILITY_BYTES, AUTHORITY_HEADER_BYTES, AuthorityCapability,
    AuthorityDispatchError, AuthorityFrame, AuthorityFrameKind, AuthorityListener,
    AuthorityOperation, AuthorityPeer, AuthorityReplayWindow, AuthoritySession,
    MAX_AUTHORITY_PAYLOAD_BYTES, ProductionAuthority, decode_frame, encode_frame,
};
use mrml_openpgp::{MAX_OPENPGP_PUBLIC_KEY_BYTES, parse_public_key_v6_ascii};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

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
        [
            _,
            command,
            _socket,
            capability,
            peer_uid,
            peer_gid,
            own_uid,
            own_gid,
            policy,
            proofs,
            openpgp,
            ml_dsa,
            receipt_key,
            validation_time,
            repository_generation,
        ] if command == "check-config" => {
            let _ = parse_peer(peer_uid, peer_gid)?;
            let authority_peer = parse_peer(own_uid, own_gid)?;
            let _capability = read_capability(capability, authority_peer.uid)?;
            load_authority(
                authority_peer.uid,
                policy,
                proofs,
                openpgp,
                ml_dsa,
                receipt_key,
                validation_time.parse().map_err(|_| ())?,
                repository_generation.parse().map_err(|_| ())?,
            )?;
            println!("valid");
            Ok(())
        }
        [
            _,
            command,
            socket,
            capability,
            peer_uid,
            peer_gid,
            own_uid,
            own_gid,
            policy,
            proofs,
            openpgp,
            ml_dsa,
            receipt_key,
            validation_time,
            repository_generation,
        ] if command == "serve" => serve(
            socket,
            capability,
            parse_peer(peer_uid, peer_gid)?,
            parse_peer(own_uid, own_gid)?,
            policy,
            proofs,
            openpgp,
            ml_dsa,
            receipt_key,
            validation_time.parse().map_err(|_| ())?,
            repository_generation.parse().map_err(|_| ())?,
        ),
        [
            _,
            command,
            socket,
            capability,
            own_uid,
            own_gid,
            authority_uid,
            authority_gid,
        ] if command == "healthcheck" => healthcheck(
            socket,
            capability,
            parse_peer(own_uid, own_gid)?,
            parse_peer(authority_uid, authority_gid)?,
        ),
        _ => {
            eprintln!(
                "usage: mrml-git-authority serve SOCKET CAPABILITY PEER_UID PEER_GID OWN_UID OWN_GID POLICY_DIR PROOF_DIR OPENPGP_PUBLIC ML_DSA_PUBLIC RECEIPT_KEY VALIDATION_TIME REPOSITORY_GENERATION\n       mrml-git-authority check-config SOCKET CAPABILITY PEER_UID PEER_GID OWN_UID OWN_GID POLICY_DIR PROOF_DIR OPENPGP_PUBLIC ML_DSA_PUBLIC RECEIPT_KEY VALIDATION_TIME REPOSITORY_GENERATION\n       mrml-git-authority healthcheck SOCKET CAPABILITY OWN_UID OWN_GID AUTHORITY_UID AUTHORITY_GID"
            );
            std::process::exit(EX_USAGE);
        }
    }
}

fn serve(
    socket: &str,
    capability_path: &str,
    expected_gitd: AuthorityPeer,
    authority_peer: AuthorityPeer,
    policy_path: &str,
    proof_path: &str,
    openpgp_path: &str,
    ml_dsa_path: &str,
    receipt_key_path: &str,
    validation_time: u64,
    repository_generation: u64,
) -> Result<(), ()> {
    let capability = read_capability(capability_path, authority_peer.uid)?;
    let mut authority = load_authority(
        authority_peer.uid,
        policy_path,
        proof_path,
        openpgp_path,
        ml_dsa_path,
        receipt_key_path,
        validation_time,
        repository_generation,
    )?;
    let listener =
        AuthorityListener::bind(Path::new(socket), 0o660, expected_gitd).map_err(|_| ())?;
    let mut replay = AuthorityReplayWindow::new();
    loop {
        let mut session = match listener.accept() {
            Ok(session) => session,
            Err(_) => continue,
        };
        let mut encoded = vec![0u8; AUTHORITY_HEADER_BYTES + MAX_AUTHORITY_PAYLOAD_BYTES];
        let length = match session.read_frame(&mut encoded) {
            Ok(length) => length,
            Err(_) => continue,
        };
        let request = match decode_frame(
            &encoded[..length],
            AuthorityFrameKind::Request,
            session.observed_peer(),
            expected_gitd,
            &capability,
            &mut replay,
        ) {
            Ok(request) => request,
            Err(_) => continue,
        };
        let result = authority.dispatch(request.operation, request.payload);
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
}

fn load_authority(
    authority_uid: u32,
    policy_path: &str,
    proof_path: &str,
    openpgp_path: &str,
    ml_dsa_path: &str,
    receipt_key_path: &str,
    validation_time: u64,
    repository_generation: u64,
) -> Result<ProductionAuthority, ()> {
    let policy = LinuxDurableTrustPolicyStore::open(policy_path).map_err(|_| ())?;
    let proofs = DurableDetachedCommitProofDirectory::open(proof_path).map_err(|_| ())?;
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

fn healthcheck(
    socket: &str,
    capability_path: &str,
    own_peer: AuthorityPeer,
    authority_peer: AuthorityPeer,
) -> Result<(), ()> {
    let capability = read_capability(capability_path, authority_peer.uid)?;
    let mut session = AuthoritySession::connect(Path::new(socket)).map_err(|_| ())?;
    let request = AuthorityFrame {
        kind: AuthorityFrameKind::Request,
        operation: AuthorityOperation::Health,
        request_id: 1,
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
