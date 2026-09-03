use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};

use mrml_git::ProtectedAuthorityRpc;
use mrml_git_authority::{
    AUTHORITY_HEADER_BYTES, AuthorityCapability, AuthorityFrame, AuthorityFrameKind,
    AuthorityOperation, AuthorityPeer, AuthorityReplayWindow, AuthoritySession,
    MAX_AUTHORITY_PAYLOAD_BYTES, decode_frame, encode_frame,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitAuthorityChannelError {
    InvalidConfiguration,
    SequenceExhausted,
    UnsupportedOperation,
    Connect,
    Encode,
    Write,
    Read,
    Authenticate,
    Denied,
    OutputLimit,
}

#[derive(Clone)]
pub struct GitAuthorityChannelClient {
    socket: PathBuf,
    capability: Arc<AuthorityCapability>,
    gitd_peer: AuthorityPeer,
    authority_peer: AuthorityPeer,
    signer_identity: [u8; 64],
    next_request_id: Arc<AtomicU64>,
    request_id_limit: u64,
}

impl GitAuthorityChannelClient {
    pub fn new(
        socket: &Path,
        capability: AuthorityCapability,
        gitd_peer: AuthorityPeer,
        authority_peer: AuthorityPeer,
        signer_identity: [u8; 64],
        next_request_id: u64,
    ) -> Result<Self, GitAuthorityChannelError> {
        if !socket.is_absolute()
            || signer_identity == [0; 64]
            || next_request_id == 0
            || gitd_peer.uid == 0
            || gitd_peer.gid == 0
            || authority_peer.uid == 0
            || authority_peer.gid == 0
        {
            return Err(GitAuthorityChannelError::InvalidConfiguration);
        }
        Ok(Self {
            socket: socket.to_path_buf(),
            capability: Arc::new(capability),
            gitd_peer,
            authority_peer,
            signer_identity,
            next_request_id: Arc::new(AtomicU64::new(next_request_id)),
            request_id_limit: u64::MAX,
        })
    }

    pub fn with_request_id_limit(
        mut self,
        request_id_limit: u64,
    ) -> Result<Self, GitAuthorityChannelError> {
        if request_id_limit <= self.next_request_id.load(Ordering::Relaxed) {
            return Err(GitAuthorityChannelError::InvalidConfiguration);
        }
        self.request_id_limit = request_id_limit;
        Ok(self)
    }

    pub fn health(&mut self) -> Result<(), GitAuthorityChannelError> {
        let mut response = [0u8; 16];
        let length = self.exchange(AuthorityOperation::Health, &[], &mut response)?;
        if &response[..length] != b"ready-v1" {
            return Err(GitAuthorityChannelError::Authenticate);
        }
        Ok(())
    }

    fn exchange(
        &mut self,
        operation: AuthorityOperation,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, GitAuthorityChannelError> {
        if request.len() > MAX_AUTHORITY_PAYLOAD_BYTES {
            return Err(GitAuthorityChannelError::OutputLimit);
        }
        let request_id = self.allocate_request_id()?;
        let mut session = AuthoritySession::connect(&self.socket)
            .map_err(|_| GitAuthorityChannelError::Connect)?;
        let mut frame = vec![0u8; AUTHORITY_HEADER_BYTES + MAX_AUTHORITY_PAYLOAD_BYTES];
        let request_length = encode_frame(
            AuthorityFrame {
                kind: AuthorityFrameKind::Request,
                operation,
                request_id,
                status: 0,
                peer: self.gitd_peer,
                payload: request,
            },
            &self.capability,
            &mut frame,
        )
        .map_err(|_| GitAuthorityChannelError::Encode)?;
        session
            .write_frame(&frame[..request_length])
            .map_err(|_| GitAuthorityChannelError::Write)?;
        let response_length = session
            .read_frame(&mut frame)
            .map_err(|_| GitAuthorityChannelError::Read)?;
        let decoded = decode_frame(
            &frame[..response_length],
            AuthorityFrameKind::Response,
            session.observed_peer(),
            self.authority_peer,
            &self.capability,
            &mut AuthorityReplayWindow::new(),
        )
        .map_err(|_| GitAuthorityChannelError::Authenticate)?;
        if decoded.operation != operation || decoded.request_id != request_id {
            return Err(GitAuthorityChannelError::Authenticate);
        }
        if decoded.status != 0 {
            eprintln!(
                "component=mrml-gitd event={}",
                authority_denied_event(operation)
            );
            return Err(GitAuthorityChannelError::Denied);
        }
        let destination = response
            .get_mut(..decoded.payload.len())
            .ok_or(GitAuthorityChannelError::OutputLimit)?;
        destination.copy_from_slice(decoded.payload);
        Ok(decoded.payload.len())
    }

    fn allocate_request_id(&self) -> Result<u64, GitAuthorityChannelError> {
        self.next_request_id
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                (current < self.request_id_limit).then(|| current + 1)
            })
            .map_err(|_| GitAuthorityChannelError::SequenceExhausted)
    }
}

const fn authority_denied_event(operation: AuthorityOperation) -> &'static str {
    match operation {
        AuthorityOperation::Health => "authority_health_denied",
        AuthorityOperation::AuthorizeReceive => "authority_receive_denied",
        AuthorityOperation::AuthorizeRefTransaction => "authority_transaction_denied",
        AuthorityOperation::VerifyCommit => "authority_commit_denied",
        AuthorityOperation::VerifyLegacyCommit => "authority_legacy_commit_denied",
        AuthorityOperation::SignReceipt => "authority_receipt_sign_denied",
        AuthorityOperation::VerifyReceipt => "authority_receipt_verify_denied",
        AuthorityOperation::InstallProof => "authority_proof_install_denied",
        AuthorityOperation::VerifyProof => "authority_proof_verify_denied",
        AuthorityOperation::InstallCandidateProof => "authority_candidate_proof_install_denied",
        AuthorityOperation::QueryCandidateById => "authority_candidate_lookup_denied",
        AuthorityOperation::BeginCandidate => "authority_candidate_begin_denied",
        AuthorityOperation::SealCandidateProofSet => "authority_candidate_seal_denied",
        AuthorityOperation::AuthorizeCandidate => "authority_candidate_authorize_denied",
        AuthorityOperation::StartCandidateActivation => "authority_candidate_start_denied",
        AuthorityOperation::CommitCandidate => "authority_candidate_commit_denied",
        AuthorityOperation::AbortCandidate => "authority_candidate_abort_denied",
        AuthorityOperation::QueryCandidate => "authority_candidate_query_denied",
        AuthorityOperation::PersistCandidateReceipt => "authority_candidate_receipt_denied",
        AuthorityOperation::CompleteCandidate => "authority_candidate_complete_denied",
    }
}

impl ProtectedAuthorityRpc for GitAuthorityChannelClient {
    fn call(&mut self, operation: u8, request: &[u8], response: &mut [u8]) -> Result<usize, ()> {
        let operation = AuthorityOperation::from_code(operation).ok_or(())?;
        self.exchange(operation, request, response).map_err(|_| ())
    }

    fn signer_identity(&self) -> [u8; 64] {
        self.signer_identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    use mrml_git_authority::AuthorityListener;

    #[test]
    fn request_id_limit_must_leave_a_nonempty_lease() {
        let peer = AuthorityPeer { uid: 1, gid: 1 };
        let client = GitAuthorityChannelClient::new(
            Path::new("/run/authority.sock"),
            AuthorityCapability::new([0x41; 32]).unwrap(),
            peer,
            peer,
            [0x42; 64],
            9,
        )
        .unwrap();
        assert!(matches!(
            client.with_request_id_limit(9),
            Err(GitAuthorityChannelError::InvalidConfiguration)
        ));
    }

    #[test]
    fn cloned_clients_share_one_monotonic_request_sequence() {
        let peer = AuthorityPeer { uid: 1, gid: 1 };
        let first = GitAuthorityChannelClient::new(
            Path::new("/run/authority.sock"),
            AuthorityCapability::new([0x41; 32]).unwrap(),
            peer,
            peer,
            [0x42; 64],
            41,
        )
        .unwrap()
        .with_request_id_limit(44)
        .unwrap();
        let second = first.clone();
        assert_eq!(first.allocate_request_id(), Ok(41));
        assert_eq!(second.allocate_request_id(), Ok(42));
        assert_eq!(first.allocate_request_id(), Ok(43));
        assert_eq!(
            second.allocate_request_id(),
            Err(GitAuthorityChannelError::SequenceExhausted)
        );
    }

    #[test]
    fn real_channel_authenticates_exact_health_response() {
        let root =
            std::env::temp_dir().join(format!("mrml-gitd-authority-client-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let metadata = fs::metadata(&root).unwrap();
        let peer = AuthorityPeer {
            uid: metadata.uid(),
            gid: metadata.gid(),
        };
        let socket = root.join("authority.sock");
        let listener = AuthorityListener::bind(&socket, 0o600, peer).unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let mut session = listener.accept().unwrap();
                let mut bytes = vec![0u8; AUTHORITY_HEADER_BYTES + MAX_AUTHORITY_PAYLOAD_BYTES];
                let length = session.read_frame(&mut bytes).unwrap();
                let request = decode_frame(
                    &bytes[..length],
                    AuthorityFrameKind::Request,
                    session.observed_peer(),
                    peer,
                    &AuthorityCapability::new([0x71; 32]).unwrap(),
                    &mut AuthorityReplayWindow::new(),
                )
                .unwrap();
                let length = encode_frame(
                    AuthorityFrame {
                        kind: AuthorityFrameKind::Response,
                        operation: request.operation,
                        request_id: request.request_id,
                        status: 0,
                        peer,
                        payload: b"ready-v1",
                    },
                    &AuthorityCapability::new([0x71; 32]).unwrap(),
                    &mut bytes,
                )
                .unwrap();
                session.write_frame(&bytes[..length]).unwrap();
            });
            let mut client = GitAuthorityChannelClient::new(
                &socket,
                AuthorityCapability::new([0x71; 32]).unwrap(),
                peer,
                peer,
                [0x72; 64],
                1,
            )
            .unwrap();
            assert_eq!(client.health(), Ok(()));
        });
        drop(listener);
        assert!(!socket.exists());
        fs::remove_dir(root).unwrap();
    }
}
