use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use mrml_http::{
    GitdResourceController, QuicAdmissionController, QuicError, QuicRetryKey,
    QuicRetryTokenManager, QuicServerEndpoint,
};
use mrml_runtime::TcpListener;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitdListenerError {
    Limit,
    Tcp,
    Port,
    Udp,
    Secret,
}

pub struct GitdBoundListeners {
    tcp: TcpListener,
    quic: QuicServerEndpoint,
    port: u16,
}

impl GitdBoundListeners {
    pub fn bind(
        ip: [u8; 4],
        requested_port: u16,
        maximum_connections: u32,
    ) -> Result<Self, GitdListenerError> {
        let maximum_connections =
            usize::try_from(maximum_connections).map_err(|_| GitdListenerError::Limit)?;
        if maximum_connections == 0 || maximum_connections > 65_536 {
            return Err(GitdListenerError::Limit);
        }
        let maximum_retired_ids = maximum_connections
            .checked_mul(2)
            .unwrap_or(65_536)
            .min(65_536);
        let tcp = TcpListener::bind(ip, requested_port).map_err(|_| GitdListenerError::Tcp)?;
        let port = tcp.local_port().map_err(|_| GitdListenerError::Port)?;
        let quic = QuicServerEndpoint::bind(ip, port, maximum_connections, maximum_retired_ids)
            .map_err(map_quic)?;
        Ok(Self { tcp, quic, port })
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub const fn tcp(&self) -> &TcpListener {
        &self.tcp
    }

    pub const fn quic(&self) -> &QuicServerEndpoint {
        &self.quic
    }

    pub fn quic_mut(&mut self) -> &mut QuicServerEndpoint {
        &mut self.quic
    }

    pub fn configure_public_quic(
        &mut self,
        retry_key: [u8; 16],
        retry_generation: u64,
        maximum_connections: u32,
    ) -> Result<(), GitdListenerError> {
        if retry_key == [0; 16] || retry_generation == 0 {
            return Err(GitdListenerError::Secret);
        }
        let maximum = usize::try_from(maximum_connections).map_err(|_| GitdListenerError::Limit)?;
        let half_open = maximum.min(1024);
        let per_ip = half_open.min(32);
        let memory = u64::try_from(half_open)
            .ok()
            .and_then(|count| count.checked_mul(256 * 1024))
            .ok_or(GitdListenerError::Limit)?;
        let admission = QuicAdmissionController::new(
            half_open,
            per_ip,
            memory,
            30,
            half_open.saturating_div(2),
        )
        .map_err(map_quic)?;
        let tokens = QuicRetryTokenManager::new(
            QuicRetryKey {
                generation: retry_generation,
                key: retry_key,
            },
            30,
        )
        .map_err(map_quic)?;
        let resources =
            GitdResourceController::new(maximum.min(65_536)).ok_or(GitdListenerError::Limit)?;
        self.quic.configure_public_admission(admission, tokens);
        self.quic.configure_resource_controller(resources);
        Ok(())
    }
}

pub fn load_quic_retry_key(path: &Path, expected_uid: u32) -> Result<[u8; 16], GitdListenerError> {
    const O_NOFOLLOW: i32 = 0x20_000;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|_| GitdListenerError::Secret)?;
    let metadata = file.metadata().map_err(|_| GitdListenerError::Secret)?;
    let mode = metadata.mode() & 0o777;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
        || !matches!(mode, 0o400 | 0o600)
        || metadata.len() != 16
    {
        return Err(GitdListenerError::Secret);
    }
    let mut key = [0u8; 16];
    file.read_exact(&mut key)
        .map_err(|_| GitdListenerError::Secret)?;
    if key == [0; 16] {
        return Err(GitdListenerError::Secret);
    }
    Ok(key)
}

fn map_quic(error: QuicError) -> GitdListenerError {
    match error {
        QuicError::Limit => GitdListenerError::Limit,
        _ => GitdListenerError::Udp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn loopback_tcp_and_udp_own_one_exact_ephemeral_port() {
        let mut listeners = GitdBoundListeners::bind([127, 0, 0, 1], 0, 32).unwrap();
        assert_ne!(listeners.port(), 0);
        listeners.configure_public_quic([7; 16], 3, 32).unwrap();
        assert!(matches!(
            GitdBoundListeners::bind([127, 0, 0, 1], 0, 65_537),
            Err(GitdListenerError::Limit)
        ));
    }

    #[test]
    fn retry_key_requires_exact_private_regular_file() {
        let root = std::env::temp_dir().join(format!("mrml-gitd-quic-key-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let key_path = root.join("retry.key");
        fs::write(&key_path, [9u8; 16]).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o400)).unwrap();
        let uid = fs::metadata(&key_path).unwrap().uid();
        assert_eq!(load_quic_retry_key(&key_path, uid), Ok([9u8; 16]));
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o440)).unwrap();
        assert_eq!(
            load_quic_retry_key(&key_path, uid),
            Err(GitdListenerError::Secret)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
