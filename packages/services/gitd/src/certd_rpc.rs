use std::path::{Path, PathBuf};

use mrml_certificate::{
    CERTD_CHANNEL_HEADER_BYTES, CertdChannelCapability, CertdChannelOperation, CertdChannelPolicy,
    CertdChannelRequest, CertdChannelRole, CertdPeerIdentity, CertdReplayWindow,
    MAX_CERTD_CHANNEL_PAYLOAD_BYTES, UnixCertdSession, decode_certd_channel_request,
    encode_certd_channel_request,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitdCertdChannelError {
    InvalidConfiguration,
    SequenceExhausted,
    Connect,
    Encode,
    Write,
    Read,
    Authenticate,
    OutputLimit,
}

pub struct GitdCertdChannelClient {
    socket: PathBuf,
    capability: CertdChannelCapability,
    gitd_peer: CertdPeerIdentity,
    certd_peer: CertdPeerIdentity,
    next_request_id: u64,
}

impl GitdCertdChannelClient {
    pub fn new(
        socket: &Path,
        capability: CertdChannelCapability,
        gitd_peer: CertdPeerIdentity,
        certd_peer: CertdPeerIdentity,
        next_request_id: u64,
    ) -> Result<Self, GitdCertdChannelError> {
        if !socket.is_absolute()
            || gitd_peer.uid == 0
            || gitd_peer.gid == 0
            || certd_peer.uid == 0
            || certd_peer.gid == 0
            || next_request_id == 0
        {
            return Err(GitdCertdChannelError::InvalidConfiguration);
        }
        Ok(Self {
            socket: socket.to_path_buf(),
            capability,
            gitd_peer,
            certd_peer,
            next_request_id,
        })
    }

    pub fn health(&mut self) -> Result<(), GitdCertdChannelError> {
        let mut output = [0u8; 16];
        let written = self.exchange(CertdChannelOperation::Health, &[], &mut output)?;
        if &output[..written] != b"ready" {
            return Err(GitdCertdChannelError::Authenticate);
        }
        Ok(())
    }

    pub fn exchange(
        &mut self,
        operation: CertdChannelOperation,
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<usize, GitdCertdChannelError> {
        if !operation.allowed_for(CertdChannelRole::Gitd)
            || payload.len() > MAX_CERTD_CHANNEL_PAYLOAD_BYTES
        {
            return Err(GitdCertdChannelError::OutputLimit);
        }
        let request_id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(GitdCertdChannelError::SequenceExhausted)?;
        let mut frame = vec![0u8; CERTD_CHANNEL_HEADER_BYTES + MAX_CERTD_CHANNEL_PAYLOAD_BYTES];
        let written = encode_certd_channel_request(
            CertdChannelRequest {
                role: CertdChannelRole::Gitd,
                operation,
                request_id,
                peer: self.gitd_peer,
                payload,
            },
            &self.capability,
            &mut frame,
        )
        .map_err(|_| GitdCertdChannelError::Encode)?;
        let mut session =
            UnixCertdSession::connect(&self.socket).map_err(|_| GitdCertdChannelError::Connect)?;
        session
            .write_frame(&frame[..written])
            .map_err(|_| GitdCertdChannelError::Write)?;
        let received = session
            .read_frame(&mut frame)
            .map_err(|_| GitdCertdChannelError::Read)?;
        let response = decode_certd_channel_request(
            &frame[..received],
            session.observed_peer(),
            CertdChannelPolicy {
                role: CertdChannelRole::Gitd,
                peer: self.certd_peer,
            },
            &self.capability,
            &mut CertdReplayWindow::new(),
        )
        .map_err(|_| GitdCertdChannelError::Authenticate)?;
        if response.operation != operation
            || response.request_id != request_id
            || response.peer != self.certd_peer
        {
            return Err(GitdCertdChannelError::Authenticate);
        }
        let destination = output
            .get_mut(..response.payload.len())
            .ok_or(GitdCertdChannelError::OutputLimit)?;
        destination.copy_from_slice(response.payload);
        Ok(response.payload.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_certificate::UnixCertdListener;
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn real_channel_authenticates_exact_health_response() {
        let root =
            std::env::temp_dir().join(format!("mrml-gitd-certd-client-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let metadata = fs::metadata(&root).unwrap();
        let peer = CertdPeerIdentity {
            uid: metadata.uid(),
            gid: metadata.gid(),
        };
        let socket = root.join("certd.sock");
        let listener = UnixCertdListener::bind(
            &socket,
            0o600,
            CertdChannelPolicy {
                role: CertdChannelRole::Gitd,
                peer,
            },
        )
        .unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let mut session = listener.accept().unwrap();
                let capability = CertdChannelCapability::new([0x61; 32]).unwrap();
                let mut frame =
                    vec![0u8; CERTD_CHANNEL_HEADER_BYTES + MAX_CERTD_CHANNEL_PAYLOAD_BYTES];
                let received = session.read_frame(&mut frame).unwrap();
                let request = decode_certd_channel_request(
                    &frame[..received],
                    session.observed_peer(),
                    CertdChannelPolicy {
                        role: CertdChannelRole::Gitd,
                        peer,
                    },
                    &capability,
                    &mut CertdReplayWindow::new(),
                )
                .unwrap();
                assert_eq!(request.operation, CertdChannelOperation::Health);
                let written = encode_certd_channel_request(
                    CertdChannelRequest {
                        role: CertdChannelRole::Gitd,
                        operation: request.operation,
                        request_id: request.request_id,
                        peer,
                        payload: b"ready",
                    },
                    &capability,
                    &mut frame,
                )
                .unwrap();
                session.write_frame(&frame[..written]).unwrap();
            });
            let mut client = GitdCertdChannelClient::new(
                &socket,
                CertdChannelCapability::new([0x61; 32]).unwrap(),
                peer,
                peer,
                1,
            )
            .unwrap();
            assert_eq!(client.health(), Ok(()));
        });
        drop(listener);
        fs::remove_file(socket).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
