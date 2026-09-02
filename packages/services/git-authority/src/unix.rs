extern crate std;

use crate::{AuthorityError, AuthorityPeer, AUTHORITY_HEADER_BYTES, MAX_AUTHORITY_PAYLOAD_BYTES};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum UnixAuthorityError {
    InvalidPath,
    ExistingPath,
    Bind,
    Permission,
    Accept,
    UnauthorizedPeer,
    Io,
    Frame(AuthorityError),
}

pub struct AuthorityListener {
    listener: UnixListener,
    path: PathBuf,
    socket_device: u64,
    socket_inode: u64,
    expected_peer: AuthorityPeer,
    health_peer: Option<AuthorityPeer>,
}

impl Drop for AuthorityListener {
    fn drop(&mut self) {
        let Ok(path) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if path.file_type().is_socket()
            && !path.file_type().is_symlink()
            && path.dev() == self.socket_device
            && path.ino() == self.socket_inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl AuthorityListener {
    pub fn bind(
        path: &Path,
        mode: u32,
        expected_peer: AuthorityPeer,
    ) -> Result<Self, UnixAuthorityError> {
        validate_path(path)?;
        if mode != 0o600 && mode != 0o660 {
            return Err(UnixAuthorityError::Permission);
        }
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(UnixAuthorityError::ExistingPath),
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(UnixAuthorityError::Bind)
            }
            Err(_) => {}
        }
        let listener = UnixListener::bind(path).map_err(|_| UnixAuthorityError::Bind)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|_| UnixAuthorityError::Permission)?;
        let metadata = fs::symlink_metadata(path).map_err(|_| UnixAuthorityError::Bind)?;
        if !metadata.file_type().is_socket() || metadata.file_type().is_symlink() {
            return Err(UnixAuthorityError::Bind);
        }
        Ok(Self {
            listener,
            path: path.to_path_buf(),
            socket_device: metadata.dev(),
            socket_inode: metadata.ino(),
            expected_peer,
            health_peer: None,
        })
    }

    pub fn allow_health_peer(mut self, peer: AuthorityPeer) -> Result<Self, UnixAuthorityError> {
        if peer == self.expected_peer {
            return Err(UnixAuthorityError::UnauthorizedPeer);
        }
        self.health_peer = Some(peer);
        Ok(self)
    }

    pub fn accept(&self) -> Result<AuthoritySession, UnixAuthorityError> {
        let (stream, _) = self
            .listener
            .accept()
            .map_err(|_| UnixAuthorityError::Accept)?;
        configure(&stream)?;
        let credentials = stream
            .peer_cred()
            .map_err(|_| UnixAuthorityError::UnauthorizedPeer)?;
        let observed = AuthorityPeer {
            uid: credentials.uid,
            gid: credentials.gid,
        };
        if observed != self.expected_peer && self.health_peer != Some(observed) {
            return Err(UnixAuthorityError::UnauthorizedPeer);
        }
        Ok(AuthoritySession { stream, observed })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub struct AuthoritySession {
    stream: UnixStream,
    observed: AuthorityPeer,
}

impl AuthoritySession {
    pub fn connect(path: &Path) -> Result<Self, UnixAuthorityError> {
        validate_path(path)?;
        let stream = UnixStream::connect(path).map_err(|_| UnixAuthorityError::Io)?;
        configure(&stream)?;
        let credentials = stream
            .peer_cred()
            .map_err(|_| UnixAuthorityError::UnauthorizedPeer)?;
        Ok(Self {
            stream,
            observed: AuthorityPeer {
                uid: credentials.uid,
                gid: credentials.gid,
            },
        })
    }
    pub const fn observed_peer(&self) -> AuthorityPeer {
        self.observed
    }
    pub fn read_frame(&mut self, output: &mut [u8]) -> Result<usize, UnixAuthorityError> {
        let mut prefix = [0u8; 4];
        self.stream
            .read_exact(&mut prefix)
            .map_err(|_| UnixAuthorityError::Io)?;
        let length = u32::from_be_bytes(prefix) as usize;
        if !(AUTHORITY_HEADER_BYTES..=AUTHORITY_HEADER_BYTES + MAX_AUTHORITY_PAYLOAD_BYTES)
            .contains(&length)
        {
            return Err(UnixAuthorityError::Frame(AuthorityError::PayloadLimit));
        }
        let destination = output
            .get_mut(..length)
            .ok_or(UnixAuthorityError::Frame(AuthorityError::OutputTooSmall))?;
        self.stream
            .read_exact(destination)
            .map_err(|_| UnixAuthorityError::Io)?;
        Ok(length)
    }
    pub fn write_frame(&mut self, frame: &[u8]) -> Result<(), UnixAuthorityError> {
        if !(AUTHORITY_HEADER_BYTES..=AUTHORITY_HEADER_BYTES + MAX_AUTHORITY_PAYLOAD_BYTES)
            .contains(&frame.len())
        {
            return Err(UnixAuthorityError::Frame(AuthorityError::PayloadLimit));
        }
        let length = u32::try_from(frame.len())
            .map_err(|_| UnixAuthorityError::Frame(AuthorityError::PayloadLimit))?;
        self.stream
            .write_all(&length.to_be_bytes())
            .and_then(|_| self.stream.write_all(frame))
            .map_err(|_| UnixAuthorityError::Io)
    }
}

fn configure(stream: &UnixStream) -> Result<(), UnixAuthorityError> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| UnixAuthorityError::Io)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| UnixAuthorityError::Io)
}

fn validate_path(path: &Path) -> Result<(), UnixAuthorityError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(UnixAuthorityError::InvalidPath);
    }
    let mut current = PathBuf::new();
    for component in path
        .parent()
        .ok_or(UnixAuthorityError::InvalidPath)?
        .components()
    {
        current.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| UnixAuthorityError::InvalidPath)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(UnixAuthorityError::InvalidPath);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        decode_frame, encode_frame, AuthorityCapability, AuthorityFrame, AuthorityFrameKind,
        AuthorityOperation, AuthorityReplayWindow,
    };
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn real_socket_binds_peer_credentials_and_authenticated_frame() {
        let root = std::env::temp_dir().join(std::format!(
            "mrml-git-authority-channel-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let metadata = fs::metadata(&root).unwrap();
        let peer = AuthorityPeer {
            uid: metadata.uid(),
            gid: metadata.gid(),
        };
        let socket = root.join("authority.sock");
        let listener = AuthorityListener::bind(&socket, 0o600, peer).unwrap();
        assert!(matches!(
            AuthorityListener::bind(&root.join("duplicate.sock"), 0o600, peer)
                .and_then(|listener| listener.allow_health_peer(peer)),
            Err(UnixAuthorityError::UnauthorizedPeer)
        ));
        let capability = AuthorityCapability::new([0x61; 32]).unwrap();
        let request = AuthorityFrame {
            kind: AuthorityFrameKind::Request,
            operation: AuthorityOperation::Health,
            request_id: 1,
            status: 0,
            peer,
            payload: b"health",
        };
        let mut encoded = [0u8; 256];
        let length = encode_frame(request, &capability, &mut encoded).unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                AuthoritySession::connect(&socket)
                    .unwrap()
                    .write_frame(&encoded[..length])
                    .unwrap()
            });
            let mut session = listener.accept().unwrap();
            let mut received = [0u8; 256];
            let received_length = session.read_frame(&mut received).unwrap();
            assert_eq!(
                decode_frame(
                    &received[..received_length],
                    AuthorityFrameKind::Request,
                    session.observed_peer(),
                    peer,
                    &capability,
                    &mut AuthorityReplayWindow::new()
                )
                .unwrap(),
                request
            );
        });
        drop(listener);
        assert!(!socket.exists());
        assert!(!root.join("duplicate.sock").exists());
        fs::remove_dir(root).unwrap();
    }
}
