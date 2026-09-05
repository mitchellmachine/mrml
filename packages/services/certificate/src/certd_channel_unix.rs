extern crate std;

use crate::{
    CERTD_CHANNEL_HEADER_BYTES, CertdChannelError, CertdChannelPolicy, CertdPeerIdentity,
    MAX_CERTD_CHANNEL_PAYLOAD_BYTES,
};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

pub const CERTD_CHANNEL_IO_TIMEOUT_MILLIS: u64 = 2_000;
pub const MAX_CERTD_CHANNEL_CONNECTIONS_PER_RUN: usize = 64;

#[derive(Debug)]
pub enum UnixCertdChannelError {
    InvalidPath,
    ExistingPath,
    BindFailed,
    PermissionFailed,
    AcceptFailed,
    WouldBlock,
    UnauthorizedPeer,
    IoFailed,
    Frame(CertdChannelError),
}

pub struct UnixCertdListener {
    listener: UnixListener,
    path: PathBuf,
    policy: CertdChannelPolicy,
    parent: fs::File,
    retained_path: PathBuf,
    socket_identity: (u64, u64),
}

impl UnixCertdListener {
    pub fn bind(
        path: &Path,
        socket_mode: u32,
        policy: CertdChannelPolicy,
    ) -> Result<Self, UnixCertdChannelError> {
        validate_socket_path(path)?;
        if !(socket_mode == 0o600 || socket_mode == 0o660) {
            return Err(UnixCertdChannelError::PermissionFailed);
        }
        let parent_path = path.parent().ok_or(UnixCertdChannelError::InvalidPath)?;
        // A local socket pair obtains our actual credentials without trusting
        // caller-selected directory metadata or the authorized remote peer.
        let (local, _) = UnixStream::pair().map_err(|_| UnixCertdChannelError::BindFailed)?;
        let owner = local
            .peer_cred()
            .map_err(|_| UnixCertdChannelError::PermissionFailed)?
            .uid;
        let parent = fs::OpenOptions::new()
            .read(true)
            .custom_flags(0o200000 | 0o400000) // O_DIRECTORY | O_NOFOLLOW, Linux.
            .open(parent_path)
            .map_err(|_| UnixCertdChannelError::InvalidPath)?;
        let metadata = parent
            .metadata()
            .map_err(|_| UnixCertdChannelError::InvalidPath)?;
        if metadata.uid() != owner
            || metadata.mode() & 0o700 != 0o700
            || metadata.mode() & 0o022 != 0
        {
            return Err(UnixCertdChannelError::PermissionFailed);
        }
        // Nonblocking directory flock is retained for the listener's lifetime.
        // There is no replaceable lock file and a second writer never waits.
        parent
            .try_lock()
            .map_err(|_| UnixCertdChannelError::ExistingPath)?;
        let retained_path = PathBuf::from(std::format!("/proc/self/fd/{}", parent.as_raw_fd()))
            .join(path.file_name().ok_or(UnixCertdChannelError::InvalidPath)?);
        match fs::symlink_metadata(&retained_path) {
            Ok(metadata) => {
                if !metadata.file_type().is_socket()
                    || metadata.uid() != owner
                    || metadata.mode() & 0o7777 != socket_mode
                    || metadata.nlink() != 1
                {
                    return Err(UnixCertdChannelError::ExistingPath);
                }
                // Only ECONNREFUSED proves this exact owned socket has no
                // listener. A successful connect, permissions failure, or any
                // ambiguous probe must leave the existing path intact.
                if !socket_is_refused(&retained_path)? {
                    return Err(UnixCertdChannelError::ExistingPath);
                }
                let current = fs::symlink_metadata(&retained_path)
                    .map_err(|_| UnixCertdChannelError::ExistingPath)?;
                if !same_socket(&current, (metadata.dev(), metadata.ino()))
                    || current.uid() != owner
                    || current.mode() & 0o7777 != socket_mode
                {
                    return Err(UnixCertdChannelError::ExistingPath);
                }
                fs::remove_file(&retained_path).map_err(|_| UnixCertdChannelError::BindFailed)?;
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(UnixCertdChannelError::BindFailed);
            }
            Err(_) => {}
        }
        let listener =
            UnixListener::bind(&retained_path).map_err(|_| UnixCertdChannelError::BindFailed)?;
        let metadata =
            fs::symlink_metadata(&retained_path).map_err(|_| UnixCertdChannelError::BindFailed)?;
        let identity = (metadata.dev(), metadata.ino());
        let result = Self {
            listener,
            path: path.to_path_buf(),
            policy,
            parent,
            retained_path,
            socket_identity: identity,
        };
        if !same_socket(&metadata, identity) || metadata.uid() != owner {
            return Err(UnixCertdChannelError::BindFailed);
        }
        fs::set_permissions(
            &result.retained_path,
            fs::Permissions::from_mode(socket_mode),
        )
        .map_err(|_| UnixCertdChannelError::PermissionFailed)?;
        result
            .listener
            .set_nonblocking(true)
            .map_err(|_| UnixCertdChannelError::BindFailed)?;
        Ok(result)
    }

    /// Compatibility blocking accept. Daemon shutdown loops should use
    /// `try_accept`, which distinguishes an empty queue from a rejected peer.
    pub fn accept(&self) -> Result<UnixCertdSession, UnixCertdChannelError> {
        loop {
            match self.try_accept() {
                Err(UnixCertdChannelError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                result => return result,
            }
        }
    }

    pub fn try_accept(&self) -> Result<UnixCertdSession, UnixCertdChannelError> {
        let (stream, _) = self.listener.accept().map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                UnixCertdChannelError::WouldBlock
            } else {
                UnixCertdChannelError::AcceptFailed
            }
        })?;
        configure_stream(&stream)?;
        let credentials = stream
            .peer_cred()
            .map_err(|_| UnixCertdChannelError::UnauthorizedPeer)?;
        let observed = CertdPeerIdentity {
            uid: credentials.uid,
            gid: credentials.gid,
        };
        if observed != self.policy.peer {
            return Err(UnixCertdChannelError::UnauthorizedPeer);
        }
        Ok(UnixCertdSession { stream, observed })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

// The stale probe must not block behind a live listener's full accept queue.
// Linux AF_UNIX nonblocking connect distinguishes ECONNREFUSED from every
// live, in-progress, permission-denied, or otherwise ambiguous outcome.
fn socket_is_refused(path: &Path) -> Result<bool, UnixCertdChannelError> {
    #[repr(C)]
    struct Address {
        family: u16,
        path: [u8; 108],
    }
    unsafe extern "C" {
        #[link_name = "socket"]
        fn linux_socket(domain: i32, kind: i32, protocol: i32) -> i32;
        #[link_name = "connect"]
        fn linux_connect(fd: i32, address: *const Address, length: u32) -> i32;
    }
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= 108 || bytes.contains(&0) {
        return Err(UnixCertdChannelError::InvalidPath);
    }
    let mut address = Address {
        family: 1,
        path: [0; 108],
    };
    address.path[..bytes.len()].copy_from_slice(bytes);
    // SAFETY: fixed Linux socket constants; a successful result is a newly
    // owned descriptor, transferred exactly once to OwnedFd for all exits.
    let raw = unsafe { linux_socket(1, 1 | 0o4000 | 0o2000000, 0) };
    if raw < 0 {
        return Err(UnixCertdChannelError::BindFailed);
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: initialized repr(C) sockaddr_un, bounded length including NUL,
    // and a live owned socket descriptor; connect does not retain the pointer.
    let result = unsafe {
        linux_connect(
            descriptor.as_raw_fd(),
            &address,
            (2 + bytes.len() + 1) as u32,
        )
    };
    Ok(result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(111))
}

fn same_socket(metadata: &fs::Metadata, identity: (u64, u64)) -> bool {
    metadata.file_type().is_socket()
        && metadata.nlink() == 1
        && (metadata.dev(), metadata.ino()) == identity
}

impl Drop for UnixCertdListener {
    fn drop(&mut self) {
        // Keep the directory lock through cleanup; never remove a replacement.
        let _keep_lock_alive = &self.parent;
        if fs::symlink_metadata(&self.retained_path)
            .is_ok_and(|metadata| same_socket(&metadata, self.socket_identity))
        {
            let _ = fs::remove_file(&self.retained_path);
        }
    }
}

pub struct UnixCertdSession {
    stream: UnixStream,
    observed: CertdPeerIdentity,
}

impl UnixCertdSession {
    pub fn connect(path: &Path) -> Result<Self, UnixCertdChannelError> {
        validate_socket_path(path)?;
        let stream = UnixStream::connect(path).map_err(|_| UnixCertdChannelError::IoFailed)?;
        configure_stream(&stream)?;
        let credentials = stream
            .peer_cred()
            .map_err(|_| UnixCertdChannelError::UnauthorizedPeer)?;
        Ok(Self {
            stream,
            observed: CertdPeerIdentity {
                uid: credentials.uid,
                gid: credentials.gid,
            },
        })
    }

    pub const fn observed_peer(&self) -> CertdPeerIdentity {
        self.observed
    }

    pub fn read_frame(&mut self, output: &mut [u8]) -> Result<usize, UnixCertdChannelError> {
        let deadline = Instant::now() + Duration::from_millis(CERTD_CHANNEL_IO_TIMEOUT_MILLIS);
        let mut prefix = [0u8; 4];
        read_until(&mut self.stream, &mut prefix, deadline)?;
        let length = u32::from_be_bytes(prefix) as usize;
        if !(CERTD_CHANNEL_HEADER_BYTES
            ..=CERTD_CHANNEL_HEADER_BYTES + MAX_CERTD_CHANNEL_PAYLOAD_BYTES)
            .contains(&length)
        {
            return Err(UnixCertdChannelError::Frame(
                CertdChannelError::PayloadLimit,
            ));
        }
        let destination = output
            .get_mut(..length)
            .ok_or(UnixCertdChannelError::Frame(
                CertdChannelError::OutputTooSmall,
            ))?;
        read_until(&mut self.stream, destination, deadline)?;
        Ok(length)
    }

    pub fn write_frame(&mut self, frame: &[u8]) -> Result<(), UnixCertdChannelError> {
        if !(CERTD_CHANNEL_HEADER_BYTES
            ..=CERTD_CHANNEL_HEADER_BYTES + MAX_CERTD_CHANNEL_PAYLOAD_BYTES)
            .contains(&frame.len())
        {
            return Err(UnixCertdChannelError::Frame(
                CertdChannelError::PayloadLimit,
            ));
        }
        let length = u32::try_from(frame.len())
            .map_err(|_| UnixCertdChannelError::Frame(CertdChannelError::PayloadLimit))?;
        let deadline = Instant::now() + Duration::from_millis(CERTD_CHANNEL_IO_TIMEOUT_MILLIS);
        write_until(&mut self.stream, &length.to_be_bytes(), deadline)?;
        write_until(&mut self.stream, frame, deadline)
    }
}

// One deadline covers both the length prefix and payload. Resetting an OS
// timeout after every successful byte would permit an indefinite slow sender.
fn remaining(deadline: Instant) -> Result<Duration, UnixCertdChannelError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(UnixCertdChannelError::IoFailed)
}
fn read_until(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), UnixCertdChannelError> {
    while !bytes.is_empty() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| UnixCertdChannelError::IoFailed)?;
        match stream.read(bytes) {
            Ok(0) => return Err(UnixCertdChannelError::IoFailed),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(UnixCertdChannelError::IoFailed),
        }
    }
    remaining(deadline).map(|_| ())
}
fn write_until(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), UnixCertdChannelError> {
    while !bytes.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|_| UnixCertdChannelError::IoFailed)?;
        match stream.write(bytes) {
            Ok(0) => return Err(UnixCertdChannelError::IoFailed),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(UnixCertdChannelError::IoFailed),
        }
    }
    remaining(deadline).map(|_| ())
}

fn configure_stream(stream: &UnixStream) -> Result<(), UnixCertdChannelError> {
    let timeout = Some(Duration::from_millis(CERTD_CHANNEL_IO_TIMEOUT_MILLIS));
    stream
        .set_read_timeout(timeout)
        .map_err(|_| UnixCertdChannelError::IoFailed)?;
    stream
        .set_write_timeout(timeout)
        .map_err(|_| UnixCertdChannelError::IoFailed)
}

fn validate_socket_path(path: &Path) -> Result<(), UnixCertdChannelError> {
    if !path.is_absolute()
        || path.as_os_str().as_bytes().len() >= 108
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(UnixCertdChannelError::InvalidPath);
    }
    let mut current = PathBuf::new();
    for component in path
        .parent()
        .ok_or(UnixCertdChannelError::InvalidPath)?
        .components()
    {
        current.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| UnixCertdChannelError::InvalidPath)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(UnixCertdChannelError::InvalidPath);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CertdChannelCapability, CertdChannelOperation, CertdChannelRequest, CertdChannelRole,
        CertdReplayWindow, decode_certd_channel_request, encode_certd_channel_request,
    };
    use std::os::unix::fs::MetadataExt;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new(label: &str) -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let root = std::env::temp_dir().join(std::format!(
                "mrml-certd-{}-{}-{}",
                label,
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
            Self(root)
        }
        fn socket(&self) -> PathBuf {
            self.0.join("channel.sock")
        }
        fn policy(&self) -> CertdChannelPolicy {
            let metadata = fs::metadata(&self.0).unwrap();
            CertdChannelPolicy {
                role: CertdChannelRole::Gitd,
                peer: CertdPeerIdentity {
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                },
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn restart_recovers_only_exact_owned_refused_socket() {
        let fixture = Fixture::new("restart");
        let stale = UnixListener::bind(fixture.socket()).unwrap();
        fs::set_permissions(fixture.socket(), fs::Permissions::from_mode(0o660)).unwrap();
        drop(stale); // A process exit leaves the same refused socket inode.
        let listener = UnixCertdListener::bind(&fixture.socket(), 0o660, fixture.policy()).unwrap();
        assert!(matches!(
            listener.try_accept(),
            Err(UnixCertdChannelError::WouldBlock)
        ));
        let client = UnixStream::connect(fixture.socket()).unwrap();
        assert!(listener.accept().is_ok());
        drop(client);
        drop(listener);
        assert!(!fixture.socket().exists());
        let restarted =
            UnixCertdListener::bind(&fixture.socket(), 0o660, fixture.policy()).unwrap();
        drop(restarted);
    }

    #[test]
    fn lifetime_directory_lock_rejects_second_writer_without_replacing_socket() {
        let fixture = Fixture::new("writer");
        let listener = UnixCertdListener::bind(&fixture.socket(), 0o600, fixture.policy()).unwrap();
        let identity = fs::symlink_metadata(fixture.socket()).unwrap().ino();
        assert!(matches!(
            UnixCertdListener::bind(&fixture.socket(), 0o600, fixture.policy()),
            Err(UnixCertdChannelError::ExistingPath)
        ));
        assert_eq!(
            fs::symlink_metadata(fixture.socket()).unwrap().ino(),
            identity
        );
        // Directory scope excludes another writer even under a different name.
        assert!(matches!(
            UnixCertdListener::bind(&fixture.0.join("other.sock"), 0o600, fixture.policy()),
            Err(UnixCertdChannelError::ExistingPath)
        ));
        drop(listener);
    }

    #[test]
    fn live_legacy_socket_and_wrong_mode_stale_socket_are_preserved() {
        let fixture = Fixture::new("legacy");
        let live = UnixListener::bind(fixture.socket()).unwrap();
        fs::set_permissions(fixture.socket(), fs::Permissions::from_mode(0o600)).unwrap();
        let identity = fs::symlink_metadata(fixture.socket()).unwrap().ino();
        assert!(matches!(
            UnixCertdListener::bind(&fixture.socket(), 0o600, fixture.policy()),
            Err(UnixCertdChannelError::ExistingPath)
        ));
        assert_eq!(
            fs::symlink_metadata(fixture.socket()).unwrap().ino(),
            identity
        );
        drop(live);
        assert!(matches!(
            UnixCertdListener::bind(&fixture.socket(), 0o660, fixture.policy()),
            Err(UnixCertdChannelError::ExistingPath)
        ));
        assert_eq!(
            fs::symlink_metadata(fixture.socket()).unwrap().ino(),
            identity
        );
    }

    #[test]
    fn socket_replacement_and_parent_replacement_are_not_unlinked() {
        let fixture = Fixture::new("replace");
        let listener = UnixCertdListener::bind(&fixture.socket(), 0o600, fixture.policy()).unwrap();
        fs::remove_file(fixture.socket()).unwrap();
        let replacement = UnixListener::bind(fixture.socket()).unwrap();
        let identity = fs::symlink_metadata(fixture.socket()).unwrap().ino();
        drop(listener);
        assert_eq!(
            fs::symlink_metadata(fixture.socket()).unwrap().ino(),
            identity
        );
        drop(replacement);
        fs::remove_file(fixture.socket()).unwrap();
        let listener = UnixCertdListener::bind(&fixture.socket(), 0o600, fixture.policy()).unwrap();
        let moved = fixture.0.with_extension("moved");
        fs::rename(&fixture.0, &moved).unwrap();
        fs::create_dir(&fixture.0).unwrap();
        fs::write(fixture.socket(), b"replacement parent sentinel").unwrap();
        drop(listener);
        assert_eq!(
            fs::read(fixture.socket()).unwrap(),
            b"replacement parent sentinel"
        );
        assert!(!moved.join("channel.sock").exists());
        fs::remove_dir(moved).unwrap();
    }

    #[test]
    fn symlink_and_peer_writable_parent_are_rejected() {
        let fixture = Fixture::new("unsafe");
        fs::write(fixture.0.join("sentinel"), b"preserve").unwrap();
        std::os::unix::fs::symlink("sentinel", fixture.socket()).unwrap();
        assert!(matches!(
            UnixCertdListener::bind(&fixture.socket(), 0o600, fixture.policy()),
            Err(UnixCertdChannelError::ExistingPath)
        ));
        assert_eq!(fs::read(fixture.0.join("sentinel")).unwrap(), b"preserve");
        fs::remove_file(fixture.socket()).unwrap();
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o2770)).unwrap();
        assert!(matches!(
            UnixCertdListener::bind(&fixture.socket(), 0o660, fixture.policy()),
            Err(UnixCertdChannelError::PermissionFailed)
        ));
        assert!(!fixture.socket().exists());
    }

    #[test]
    fn rejected_peer_does_not_poison_listener_and_idle_poll_is_bounded() {
        let fixture = Fixture::new("peer");
        let policy = fixture.policy();
        let mut wrong = policy;
        wrong.peer.uid = wrong.peer.uid.checked_add(1).unwrap();
        let mut listener = UnixCertdListener::bind(&fixture.socket(), 0o600, wrong).unwrap();
        let client = UnixStream::connect(fixture.socket()).unwrap();
        assert!(matches!(
            listener.accept(),
            Err(UnixCertdChannelError::UnauthorizedPeer)
        ));
        drop(client);
        assert!(matches!(
            listener.try_accept(),
            Err(UnixCertdChannelError::WouldBlock)
        ));
        listener.policy = policy;
        let client = UnixStream::connect(fixture.socket()).unwrap();
        assert_eq!(listener.accept().unwrap().observed_peer(), policy.peer);
        drop(client);
    }

    #[test]
    fn trickled_frame_cannot_extend_the_whole_frame_deadline() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let fixture = Fixture::new("trickle");
        let listener = UnixCertdListener::bind(&fixture.socket(), 0o600, fixture.policy()).unwrap();
        let mut client = UnixStream::connect(fixture.socket()).unwrap();
        let mut session = listener.accept().unwrap();
        let stopped = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let length = (CERTD_CHANNEL_HEADER_BYTES + 1024) as u32;
                client.write_all(&length.to_be_bytes()).unwrap();
                let watchdog = Instant::now() + Duration::from_secs(6);
                while !stopped.load(Ordering::Acquire) && Instant::now() < watchdog {
                    if client.write_all(&[0]).is_err() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                let _ = client.shutdown(std::net::Shutdown::Write);
            });
            let started = Instant::now();
            let result = session.read_frame(&mut [0; CERTD_CHANNEL_HEADER_BYTES + 1024]);
            stopped.store(true, Ordering::Release);
            assert!(matches!(result, Err(UnixCertdChannelError::IoFailed)));
            assert!(started.elapsed() < Duration::from_secs(5));
        });
    }

    #[test]
    fn real_socket_binds_peer_credentials_and_authenticated_frame() {
        let root =
            std::env::temp_dir().join(std::format!("mrml-certd-channel-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let metadata = fs::metadata(&root).unwrap();
        let peer = CertdPeerIdentity {
            uid: metadata.uid(),
            gid: metadata.gid(),
        };
        let policy = CertdChannelPolicy {
            role: CertdChannelRole::Gitd,
            peer,
        };
        let socket = root.join("certd.sock");
        let listener = UnixCertdListener::bind(&socket, 0o600, policy).unwrap();
        let capability = CertdChannelCapability::new([0x37; 32]).unwrap();
        let request = CertdChannelRequest {
            role: CertdChannelRole::Gitd,
            operation: CertdChannelOperation::Health,
            request_id: 1,
            peer,
            payload: b"health",
        };
        let mut encoded = [0u8; 256];
        let length = encode_certd_channel_request(request, &capability, &mut encoded).unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                UnixCertdSession::connect(&socket)
                    .unwrap()
                    .write_frame(&encoded[..length])
                    .unwrap()
            });
            let mut server = listener.accept().unwrap();
            let mut received = [0u8; 256];
            let received_length = server.read_frame(&mut received).unwrap();
            let decoded = decode_certd_channel_request(
                &received[..received_length],
                server.observed_peer(),
                policy,
                &capability,
                &mut CertdReplayWindow::new(),
            )
            .unwrap();
            assert_eq!(decoded, request);
        });
        drop(listener);
        assert!(!socket.exists());
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn existing_path_is_never_replaced() {
        let root =
            std::env::temp_dir().join(std::format!("mrml-certd-existing-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let socket = root.join("certd.sock");
        fs::write(&socket, b"do not replace").unwrap();
        let metadata = fs::metadata(&root).unwrap();
        let result = UnixCertdListener::bind(
            &socket,
            0o600,
            CertdChannelPolicy {
                role: CertdChannelRole::Gitd,
                peer: CertdPeerIdentity {
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                },
            },
        );
        assert!(matches!(result, Err(UnixCertdChannelError::ExistingPath)));
        assert_eq!(fs::read(&socket).unwrap(), b"do not replace");
        fs::remove_dir_all(root).unwrap();
    }
}
