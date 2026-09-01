extern crate std;

use crate::{
    CERTD_CHANNEL_HEADER_BYTES, CertdChannelError, CertdChannelPolicy, CertdPeerIdentity,
    MAX_CERTD_CHANNEL_PAYLOAD_BYTES,
};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

pub const CERTD_CHANNEL_IO_TIMEOUT_MILLIS: u64 = 2_000;
pub const MAX_CERTD_CHANNEL_CONNECTIONS_PER_RUN: usize = 64;

#[derive(Debug)]
pub enum UnixCertdChannelError {
    InvalidPath,
    ExistingPath,
    BindFailed,
    PermissionFailed,
    AcceptFailed,
    UnauthorizedPeer,
    IoFailed,
    Frame(CertdChannelError),
}

pub struct UnixCertdListener {
    listener: UnixListener,
    path: PathBuf,
    policy: CertdChannelPolicy,
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
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(UnixCertdChannelError::ExistingPath),
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(UnixCertdChannelError::BindFailed);
            }
            Err(_) => {}
        }
        let listener = UnixListener::bind(path).map_err(|_| UnixCertdChannelError::BindFailed)?;
        fs::set_permissions(path, fs::Permissions::from_mode(socket_mode))
            .map_err(|_| UnixCertdChannelError::PermissionFailed)?;
        let metadata = fs::symlink_metadata(path).map_err(|_| UnixCertdChannelError::BindFailed)?;
        if !metadata.file_type().is_socket() || metadata.file_type().is_symlink() {
            return Err(UnixCertdChannelError::BindFailed);
        }
        Ok(Self {
            listener,
            path: path.to_path_buf(),
            policy,
        })
    }

    pub fn accept(&self) -> Result<UnixCertdSession, UnixCertdChannelError> {
        let (stream, _) = self
            .listener
            .accept()
            .map_err(|_| UnixCertdChannelError::AcceptFailed)?;
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
        let mut prefix = [0u8; 4];
        self.stream
            .read_exact(&mut prefix)
            .map_err(|_| UnixCertdChannelError::IoFailed)?;
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
        self.stream
            .read_exact(destination)
            .map_err(|_| UnixCertdChannelError::IoFailed)?;
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
        self.stream
            .write_all(&length.to_be_bytes())
            .and_then(|_| self.stream.write_all(frame))
            .map_err(|_| UnixCertdChannelError::IoFailed)
    }
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
        fs::remove_file(socket).unwrap();
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
