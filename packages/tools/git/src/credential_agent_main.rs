#![feature(peer_credentials_unix_socket)]

use mrml_git::{
    CredentialAgentCapability, CredentialAgentRequest, CredentialAgentSession,
    HttpsCredentialAction, decode_credential_agent_request, encode_credential_agent_hello,
    encode_credential_agent_response,
};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_SECONDS: u64 = 5;
const MAX_FRAME_BYTES: usize = 1536;
const O_NOFOLLOW: i32 = 0o400000;
const O_CLOEXEC: i32 = 0o2000000;

unsafe extern "C" {
    fn chown(path: *const core::ffi::c_char, owner: u32, group: u32) -> i32;
}

struct Config {
    socket: PathBuf,
    capability_file: PathBuf,
    token_file: PathBuf,
    client_uid: u32,
    client_gid: u32,
    owner_uid: u32,
    socket_gid: u32,
    host: String,
    port: u16,
    repository_path: String,
    allow_read: bool,
    allow_write: bool,
    generation: u64,
}

struct Secret(Vec<u8>);

impl Drop for Secret {
    fn drop(&mut self) {
        erase(&mut self.0);
    }
}

fn main() {
    if run().is_err() {
        eprintln!(
            "component=mrml-git-credential-agent event=terminated category=configuration_or_runtime"
        );
        std::process::exit(1);
    }
}

fn run() -> Result<(), ()> {
    let config = parse_config(std::env::args().skip(1).collect())?;
    let mut capability_bytes = read_secret(&config.capability_file, 32, config.owner_uid)?;
    let mut capability_array = [0; 32];
    capability_array.copy_from_slice(&capability_bytes);
    erase(&mut capability_bytes);
    let capability = CredentialAgentCapability::new(capability_array).map_err(|_| ())?;
    erase(&mut capability_array);
    let mut token_bytes = read_secret(&config.token_file, 64, config.owner_uid)?;
    if token_bytes
        .iter()
        .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        erase(&mut token_bytes);
        return Err(());
    }
    let token = Secret(token_bytes);
    prepare_socket(&config)?;
    let listener = UnixListener::bind(&config.socket).map_err(|_| ())?;
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o660)).map_err(|_| ())?;
    set_owner(&config.socket, config.owner_uid, config.socket_gid)?;
    eprintln!(
        "component=mrml-git-credential-agent event=ready generation={}",
        config.generation
    );
    for incoming in listener.incoming() {
        let Ok(mut stream) = incoming else { continue };
        if handle(&mut stream, &config, &capability, &token.0).is_err() {
            eprintln!(
                "component=mrml-git-credential-agent event=request_rejected category=invalid_or_unauthorized"
            );
        }
    }
    Err(())
}

fn handle(
    stream: &mut UnixStream,
    config: &Config,
    capability: &CredentialAgentCapability,
    token: &[u8],
) -> Result<(), ()> {
    stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    let peer = stream.peer_cred().map_err(|_| ())?;
    if peer.uid != config.client_uid || peer.gid != config.client_gid {
        return Err(());
    }
    let now = mrml_runtime::unix_time_seconds().ok_or(())?;
    let mut session_id = [0; 32];
    mrml_runtime::fill_random(&mut session_id).map_err(|_| ())?;
    if session_id == [0; 32] {
        return Err(());
    }
    let session = CredentialAgentSession {
        id: session_id,
        expires_at: now.checked_add(SESSION_SECONDS).ok_or(())?,
    };
    write_frame(
        stream,
        &encode_credential_agent_hello(session, capability).map_err(|_| ())?,
    )?;
    let mut frame = read_frame(stream)?;
    let decoded = decode_credential_agent_request(&frame, session, capability).map_err(|_| ());
    erase(&mut frame);
    let request = decoded?;
    let current = mrml_runtime::unix_time_seconds().ok_or(())?;
    let allowed = current <= session.expires_at && request_matches(config, &request);
    let mut response = encode_credential_agent_response(
        &request,
        session.expires_at,
        allowed.then_some(token),
        capability,
    )
    .map_err(|_| ())?;
    let result = write_frame(stream, &response);
    erase(&mut response);
    result
}

fn request_matches(config: &Config, request: &CredentialAgentRequest) -> bool {
    request.credential_generation == config.generation
        && request.scope.host.as_str() == config.host
        && request.scope.port == config.port
        && request.scope.repository_path.as_str() == config.repository_path
        && match request.scope.action {
            HttpsCredentialAction::Read => config.allow_read,
            HttpsCredentialAction::Write => config.allow_write,
        }
}

fn parse_config(arguments: Vec<String>) -> Result<Config, ()> {
    if arguments.len() != 13 || arguments[0] != "serve" {
        return Err(());
    }
    let socket = absolute_path(&arguments[1])?;
    let capability_file = absolute_path(&arguments[2])?;
    let token_file = absolute_path(&arguments[3])?;
    let client_uid = nonzero(&arguments[4])?;
    let client_gid = nonzero(&arguments[5])?;
    let owner_uid = nonzero(&arguments[6])?;
    let socket_gid = nonzero(&arguments[7])?;
    let port = arguments[9]
        .parse()
        .ok()
        .filter(|value| *value != 0)
        .ok_or(())?;
    let (allow_read, allow_write) = match arguments[11].as_str() {
        "read" => (true, false),
        "write" => (false, true),
        "read-write" => (true, true),
        _ => return Err(()),
    };
    let generation = arguments[12]
        .parse()
        .ok()
        .filter(|value| *value != 0)
        .ok_or(())?;
    mrml_git::HttpsCredentialScope::new(
        &arguments[8],
        port,
        &arguments[10],
        HttpsCredentialAction::Read,
    )
    .map_err(|_| ())?;
    Ok(Config {
        socket,
        capability_file,
        token_file,
        client_uid,
        client_gid,
        owner_uid,
        socket_gid,
        host: arguments[8].clone(),
        port,
        repository_path: arguments[10].clone(),
        allow_read,
        allow_write,
        generation,
    })
}

fn absolute_path(value: &str) -> Result<PathBuf, ()> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || value.len() > 4096
        || value.as_bytes().contains(&0)
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(());
    }
    Ok(path)
}

fn nonzero(value: &str) -> Result<u32, ()> {
    value.parse().ok().filter(|value| *value != 0).ok_or(())
}

fn read_secret(path: &Path, exact: usize, owner: u32) -> Result<Vec<u8>, ()> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(O_NOFOLLOW | O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || !matches!(metadata.mode() & 0o777, 0o400 | 0o600)
        || metadata.len() != exact as u64
    {
        return Err(());
    }
    let mut output = vec![0; exact];
    file.read_exact(&mut output).map_err(|_| ())?;
    let mut trailing = [0; 1];
    if file.read(&mut trailing).map_err(|_| ())? != 0 {
        erase(&mut output);
        return Err(());
    }
    Ok(output)
}

fn prepare_socket(config: &Config) -> Result<(), ()> {
    let parent = config.socket.parent().ok_or(())?;
    let metadata = parent.metadata().map_err(|_| ())?;
    if !metadata.is_dir()
        || metadata.uid() != config.owner_uid
        || metadata.gid() != config.socket_gid
        || metadata.mode() & 0o7777 != 0o2770
    {
        return Err(());
    }
    match fs::symlink_metadata(&config.socket) {
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == config.owner_uid => {
            fs::remove_file(&config.socket).map_err(|_| ())?;
        }
        Ok(_) => return Err(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(()),
    }
    Ok(())
}

fn set_owner(path: &Path, uid: u32, gid: u32) -> Result<(), ()> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    let value = std::ffi::CString::new(bytes).map_err(|_| ())?;
    if unsafe { chown(value.as_ptr(), uid, gid) } == 0 {
        Ok(())
    } else {
        Err(())
    }
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, ()> {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).map_err(|_| ())?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(());
    }
    let mut frame = vec![0; length];
    stream.read_exact(&mut frame).map_err(|_| ())?;
    Ok(frame)
}

fn write_frame(stream: &mut UnixStream, frame: &[u8]) -> Result<(), ()> {
    let length = u32::try_from(frame.len()).map_err(|_| ())?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|_| stream.write_all(frame))
        .map_err(|_| ())
}

fn erase(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_git::{CredentialAgentPeer, HttpsCredentialProvider, UnixHttpsCredentialProvider};

    #[test]
    fn arguments_are_exact_and_policy_is_scope_bound() {
        let args = vec![
            "serve",
            "/run/agent/socket",
            "/keys/cap",
            "/keys/token",
            "21001",
            "21001",
            "21009",
            "21909",
            "git.example",
            "443",
            "/owner/repo.git",
            "read-write",
            "4",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let config = parse_config(args).unwrap();
        let scope = mrml_git::HttpsCredentialScope::new(
            "git.example",
            443,
            "/owner/repo.git",
            HttpsCredentialAction::Write,
        )
        .unwrap();
        let request = CredentialAgentRequest {
            session: CredentialAgentSession {
                id: [1; 32],
                expires_at: 2,
            },
            request_id: 1,
            credential_generation: 4,
            scope,
        };
        assert!(request_matches(&config, &request));
        let mut wrong = request;
        wrong.credential_generation = 3;
        assert!(!request_matches(&config, &wrong));
    }

    #[test]
    fn authenticated_unix_round_trip_returns_only_the_bound_use() {
        if std::env::var("MRML_CREDENTIAL_AGENT_SOCKET_TEST").as_deref() != Ok("1") {
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "mrml-credential-agent-round-trip-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let metadata = root.metadata().unwrap();
        let socket = root.join("agent.sock");
        let config = Config {
            socket: socket.clone(),
            capability_file: root.join("capability"),
            token_file: root.join("token"),
            client_uid: metadata.uid(),
            client_gid: metadata.gid(),
            owner_uid: metadata.uid(),
            socket_gid: metadata.gid(),
            host: "git.example".into(),
            port: 443,
            repository_path: "/owner/repo.git".into(),
            allow_read: true,
            allow_write: false,
            generation: 3,
        };
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let capability = CredentialAgentCapability::new([7; 32]).unwrap();
            handle(&mut stream, &config, &capability, &[b'a'; 64]).unwrap();
        });
        let mut provider = UnixHttpsCredentialProvider::new(
            socket.to_str().unwrap(),
            CredentialAgentPeer {
                uid: metadata.uid(),
                gid: metadata.gid(),
            },
            CredentialAgentCapability::new([7; 32]).unwrap(),
            3,
        )
        .unwrap();
        let scope = mrml_git::HttpsCredentialScope::new(
            "git.example",
            443,
            "/owner/repo.git",
            HttpsCredentialAction::Read,
        )
        .unwrap();
        let credential = provider.credential(&scope).unwrap();
        assert_eq!(
            format!("{credential:?}"),
            "ScopedBearerCredential(<redacted>)"
        );
        server.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
