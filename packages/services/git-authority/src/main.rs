use mrml_crypto::erase_secret_bytes;
use mrml_git_authority::{
    decode_frame, encode_frame, AuthorityCapability, AuthorityFrame, AuthorityFrameKind,
    AuthorityListener, AuthorityOperation, AuthorityPeer, AuthorityReplayWindow, AuthoritySession,
    AUTHORITY_CAPABILITY_BYTES, AUTHORITY_HEADER_BYTES, MAX_AUTHORITY_PAYLOAD_BYTES,
};
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
        [_, command, socket, capability, peer_uid, peer_gid, own_uid, own_gid]
            if command == "serve" =>
        {
            serve(
                socket,
                capability,
                parse_peer(peer_uid, peer_gid)?,
                parse_peer(own_uid, own_gid)?,
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
        _ => {
            eprintln!(
                "usage: mrml-git-authority serve SOCKET CAPABILITY PEER_UID PEER_GID OWN_UID OWN_GID\n       mrml-git-authority healthcheck SOCKET CAPABILITY OWN_UID OWN_GID AUTHORITY_UID AUTHORITY_GID"
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
) -> Result<(), ()> {
    let capability = read_capability(capability_path)?;
    let listener =
        AuthorityListener::bind(Path::new(socket), 0o660, expected_gitd).map_err(|_| ())?;
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
            &mut AuthorityReplayWindow::new(),
        ) {
            Ok(request) => request,
            Err(_) => continue,
        };
        let (status, payload): (u16, &[u8]) =
            if request.operation == AuthorityOperation::Health && request.payload.is_empty() {
                (STATUS_OK, b"ready-v1")
            } else {
                (STATUS_UNAVAILABLE, &[])
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

fn healthcheck(
    socket: &str,
    capability_path: &str,
    own_peer: AuthorityPeer,
    authority_peer: AuthorityPeer,
) -> Result<(), ()> {
    let capability = read_capability(capability_path)?;
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

fn read_capability(path: &str) -> Result<AuthorityCapability, ()> {
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
        || !matches!(mode, 0o400 | 0o440 | 0o600)
        || metadata.len() != AUTHORITY_CAPABILITY_BYTES as u64
    {
        return Err(());
    }
    let mut bytes = [0u8; AUTHORITY_CAPABILITY_BYTES];
    file.read_exact(&mut bytes).map_err(|_| ())?;
    let result = AuthorityCapability::new(bytes);
    erase_secret_bytes(&mut bytes);
    result.map_err(|_| ())
}
